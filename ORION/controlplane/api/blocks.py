"""Endpoints de bloqueos automaticos generados por el WAF de mitmproxy.

Los bloqueos auto son reglas estandar de orion-rules con tres campos extra:
  auto_blocked = true        marcador para distinguirlos de las manuales
  expires_at   = iso8601     instante en el que el expirer los deshabilita
  reason       = string      texto del patron matcheado (ej. "union select")
  alert_type   = string      categoria (sqli, xss, rce, brute_force)
  source       = string      origen (waf-mitm, manual...)

El loader XDP solo mira enabled=true, asi que el expirer pasa enabled a false
y la regla deja de aplicarse en kernel pero se mantiene en el indice para que
la pestana "Bloqueos auto" muestre el historico con contador por IP.
"""

import ipaddress
import uuid
from datetime import datetime, timedelta, timezone

from flask import jsonify, request

from controlplane.api import api_bp
from controlplane.es_client import get_es

DEFAULT_TTL_SECONDS = 900   # 15 minutos. Tipico de fail2ban / firewalls comerciales.


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _pick_iface(src_ip: str) -> str:
    """Elige interfaz segun donde vive el atacante.

    10.0.2.0/24 = red interna del cliente -> enp6s0f0.
    Cualquier otra IP entra por eno1 (Internet o la propia LAN de ORION).
    """
    try:
        addr = ipaddress.IPv4Address(src_ip)
        if addr in ipaddress.IPv4Network("10.0.2.0/24"):
            return "enp6s0f0"
    except ValueError:
        pass
    return "eno1"


def _audit(rule_id, operation, old_state, new_state, user="waf-mitm"):
    """Misma auditoria que rules.py para tener una sola fuente de verdad."""
    es = get_es()
    es.index(index="orion-rules-history", document={
        "rule_id": rule_id,
        "operation": operation,
        "timestamp": _now_iso(),
        "user": user,
        "old_state": old_state,
        "new_state": new_state,
    })


@api_bp.route("/blocks/auto", methods=["POST"])
def create_auto_block():
    """Crea un bloqueo auto o lo extiende si ya hay uno activo para esa IP.

    Body esperado:
      {
        "source_ip":  "10.0.2.15",
        "reason":     "' OR 1=1 --",
        "alert_type": "sqli",
        "ttl":        900           # opcional, default 15 min
      }

    Comportamiento dedup: si ya hay un doc en orion-rules con
    auto_blocked=true, enabled=true, source_ip=X y expires_at>now,
    NO crea un duplicado. Reusa el existente:
      - reemplaza expires_at por now+ttl (extiende ventana)
      - incrementa hit_count
      - actualiza last_seen_reason/last_alert_type si el tipo cambia
    Devuelve 200 con status="extended". Si no hay, crea nueva regla y
    devuelve 201 con status="created".
    """
    payload = request.get_json(silent=True) or {}
    src_ip = (payload.get("source_ip") or "").strip()
    if not src_ip:
        return jsonify({"error": "source_ip requerido"}), 400
    try:
        ipaddress.IPv4Address(src_ip)
    except ValueError:
        return jsonify({"error": f"source_ip invalido: {src_ip}"}), 400

    ttl = int(payload.get("ttl") or DEFAULT_TTL_SECONDS)
    if ttl < 1 or ttl > 86400:
        return jsonify({"error": "ttl fuera de rango (1-86400)"}), 400

    reason     = (payload.get("reason") or "")[:200]
    alert_type = (payload.get("alert_type") or "unknown")[:32]
    iface      = payload.get("iface") or _pick_iface(src_ip)

    # Conteo de eventos. Dos modos:
    #   mode=increment (default): cada llamada suma +hits al hit_count.
    #     Usado por patrones regex y UA malicioso (1 deteccion = 1 evento).
    #   mode=max: hit_count = max(actual, hits). Usado por brute_force y
    #     fuzzing donde "hits" es el conteo agregado en la ventana de 60s,
    #     y queremos reflejar el pico de actividad, no la suma de ticks
    #     solapados.
    hits = int(payload.get("hits") or 1)
    if hits < 1: hits = 1
    mode = (payload.get("mode") or "increment").strip()
    if mode not in ("increment", "max"):
        mode = "increment"

    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl)
    es = get_es()

    # 1) Dedup: hay ya un bloqueo activo para esta IP?
    existing = es.search(index="orion-rules", body={
        "size": 1,
        "query": {
            "bool": {
                "must": [
                    {"term": {"auto_blocked": True}},
                    {"term": {"enabled": True}},
                    {"term": {"source_ip": src_ip}},
                    {"range": {"expires_at": {"gt": now.isoformat()}}},
                ]
            }
        },
        "sort": [{"created_at": "desc"}],
    })["hits"]["hits"]

    if existing:
        # Extender el existente, no crear nuevo.
        h = existing[0]
        rid = h["_id"]
        src = h["_source"]
        old = dict(src)
        current_hc = int(src.get("hit_count") or 1)
        if mode == "max":
            src["hit_count"] = max(current_hc, hits)
        else:
            src["hit_count"] = current_hc + hits
        src["expires_at"]  = expires.isoformat()
        src["last_reason"] = reason
        src["last_alert_type"] = alert_type
        src["updated_at"]  = now.isoformat()
        es.index(index="orion-rules", id=rid, document=src, refresh="wait_for")
        _audit(rid, "auto-extended", old, src)
        return jsonify({"id": rid, "status": "extended", **src}), 200

    # 2) No existe: crear nueva regla
    rule_id = f"auto-{uuid.uuid4().hex[:12]}"
    document = {
        "rule_id":      rule_id,
        "name":         f"auto: {alert_type} desde {src_ip}",
        "iface":        iface,
        "source_ip":    src_ip,
        "dest_ip":      None,
        "protocol":     "any",
        "source_port":  None,
        "dest_port":    None,
        "limit_pps":    None,
        "limit_bps":    None,
        "action":       "drop",
        "priority":     10,                 # alta para que tumbe antes que reglas manuales
        "comment":      f"WAF auto-block ({alert_type}): {reason}",
        "created_by":   "waf-mitm",
        "enabled":      True,
        "auto_blocked": True,
        "expires_at":   expires.isoformat(),
        "reason":       reason,
        "alert_type":   alert_type,
        "source":       "waf-mitm",
        "hit_count":    hits,
        "created_at":   now.isoformat(),
        "updated_at":   now.isoformat(),
    }

    es.index(index="orion-rules", id=rule_id, document=document, refresh="wait_for")
    _audit(rule_id, "auto-blocked", None, document)

    return jsonify({"id": rule_id, "status": "created", **document}), 201


@api_bp.route("/blocks/auto", methods=["GET"])
def list_auto_blocks():
    """Lista bloqueos auto + agregacion por IP con contador.

    Devuelve:
      active:   reglas con enabled=true y expires_at > now (lo que XDP esta tumbando)
      history:  todas las auto-blocked (incluye disabled) ordenadas por created_at desc
      by_ip:    [{ip, total_blocks, last_block_at, last_alert_type, currently_active}]
    """
    es = get_es()
    now_iso = _now_iso()

    # Activos: enabled=true AND expires_at>now
    active_q = {
        "size": 200,
        "query": {
            "bool": {
                "must": [
                    {"term": {"auto_blocked": True}},
                    {"term": {"enabled": True}},
                    {"range": {"expires_at": {"gt": now_iso}}},
                ]
            }
        },
        "sort": [{"created_at": "desc"}],
    }
    active_hits = es.search(index="orion-rules", body=active_q)["hits"]["hits"]
    active = [{"id": h["_id"], **h["_source"]} for h in active_hits]

    # Historico: todos los auto-blocked
    hist_q = {
        "size": 500,
        "query": {"term": {"auto_blocked": True}},
        "sort": [{"created_at": "desc"}],
    }
    hist_hits = es.search(index="orion-rules", body=hist_q)["hits"]["hits"]
    history = [{"id": h["_id"], **h["_source"]} for h in hist_hits]

    # Agregacion por IP: con dedup duro hay como mucho un doc activo por IP
    # pero history puede acumular varios docs (uno por "episodio" cuando
    # cada serie de detecciones expira y vuelve a empezar despues). El
    # contador real de detecciones se lleva en hit_count dentro del doc.
    by_ip = {}
    active_ips = {r["source_ip"] for r in active if r.get("source_ip")}
    for r in history:
        ip = r.get("source_ip")
        if not ip:
            continue
        hits = int(r.get("hit_count") or 1)
        if ip not in by_ip:
            by_ip[ip] = {
                "ip": ip,
                "total_blocks": 0,           # episodios (docs en history)
                "total_hits":   0,           # detecciones individuales
                "last_block_at": r["created_at"],
                "last_alert_type": r.get("last_alert_type") or r.get("alert_type", ""),
                "currently_active": ip in active_ips,
            }
        by_ip[ip]["total_blocks"] += 1
        by_ip[ip]["total_hits"]   += hits
    by_ip_list = sorted(by_ip.values(), key=lambda x: x["last_block_at"], reverse=True)

    return jsonify({
        "active": active,
        "history": history,
        "by_ip": by_ip_list,
        "total_active": len(active),
        "total_history": len(history),
        "unique_ips": len(by_ip_list),
    })


@api_bp.route("/blocks/auto/<rule_id>", methods=["DELETE"])
def release_auto_block(rule_id):
    """Libera un bloqueo auto manualmente (pone enabled=false antes del TTL)."""
    es = get_es()
    try:
        doc = es.get(index="orion-rules", id=rule_id)
    except Exception:
        return jsonify({"error": "not found"}), 404

    src = doc["_source"]
    if not src.get("auto_blocked"):
        return jsonify({"error": "no es un bloqueo auto"}), 400

    old = dict(src)
    src["enabled"] = False
    src["updated_at"] = _now_iso()
    es.index(index="orion-rules", id=rule_id, document=src, refresh="wait_for")
    _audit(rule_id, "manual-release", old, src, user="api")

    return jsonify({"id": rule_id, "status": "released"})


@api_bp.route("/blocks/auto/<rule_id>/promote", methods=["POST"])
def promote_auto_block(rule_id):
    """Promociona un bloqueo auto a regla permanente.

    Quita auto_blocked y expires_at, marca created_by=admin para que el
    expirer la ignore para siempre. La regla deja de aparecer en la
    pestana "Bloqueos auto" y empieza a verse en la pestana "Reglas"
    como una mas. XDP sigue tumbandola sin interrupcion (sigue enabled).
    """
    es = get_es()
    try:
        doc = es.get(index="orion-rules", id=rule_id)
    except Exception:
        return jsonify({"error": "not found"}), 404

    src = doc["_source"]
    if not src.get("auto_blocked"):
        return jsonify({"error": "no es un bloqueo auto"}), 400

    old = dict(src)

    # Promocion: quitar marcadores de auto-block, conservar action=drop + IP.
    src.pop("auto_blocked", None)
    src.pop("expires_at",   None)
    src["enabled"]    = True
    src["created_by"] = "admin"
    src["source"]     = "promoted-from-waf"
    src["comment"]    = (f"Promovida desde WAF (era {old.get('alert_type','?')}): "
                         f"{old.get('reason','')}")[:200]
    src["updated_at"] = _now_iso()

    es.index(index="orion-rules", id=rule_id, document=src, refresh="wait_for")
    _audit(rule_id, "promoted-to-permanent", old, src, user="api")

    return jsonify({"id": rule_id, "status": "promoted", **src})
