"""Endpoints para consultar el indice orion-threat-intel.

El indice lo rellena el script tools/abuseipdb_ingest.py (timer diario).
Cada doc tiene los campos:
  ip_or_cidr, type, source, category,
  abuse_confidence (0-100 porcentaje),
  country_code, last_reported_at,
  first_seen, last_seen, expires_at
"""

from flask import jsonify, request

from controlplane.api import api_bp
from controlplane.es_client import get_es


THREAT_INDEX = "orion-threat-intel"


@api_bp.route("/threat_intel/stats", methods=["GET"])
def threat_intel_stats():
    """Contadores agregados para los KPIs de la pestana Cyberinteligencia."""
    es = get_es()
    try:
        res = es.search(
            index=THREAT_INDEX,
            size=0,
            query={"match_all": {}},
            aggs={
                "sources":   {"terms": {"field": "source",       "size": 20}},
                "by_country":{"terms": {"field": "country_code", "size": 50}},
                "avg_score": {"avg":   {"field": "abuse_confidence"}},
                "high":      {"filter":{"range":{"abuse_confidence":{"gte":90}}}},
            },
        )
        total = res["hits"]["total"]["value"]
        sources    = {b["key"]: b["doc_count"] for b in res["aggregations"]["sources"]["buckets"]}
        by_country = {b["key"]: b["doc_count"] for b in res["aggregations"]["by_country"]["buckets"]}
        return jsonify({
            "total":      total,
            "sources":    sources,
            "by_country": by_country,
            "avg_score":  res["aggregations"]["avg_score"]["value"],
            "high_score": res["aggregations"]["high"]["doc_count"],
        })
    except Exception as e:
        return jsonify({
            "total": 0, "sources": {}, "by_country": {},
            "avg_score": None, "high_score": 0,
            "error": str(e),
        })


@api_bp.route("/threat_intel", methods=["GET"])
def threat_intel_list():
    """Lista paginada de IPs con reputacion, filtrable por score, pais y prefijo."""
    es = get_es()

    size      = min(int(request.args.get("size", 50)), 500)
    from_     = max(int(request.args.get("from", 0)), 0)
    min_score = int(request.args.get("min_score", 75))
    search    = request.args.get("search")
    country   = request.args.get("country")

    must = [{"range": {"abuse_confidence": {"gte": min_score}}}]
    if country:
        must.append({"term": {"country_code": country}})
    if search:
        must.append({"prefix": {"ip_or_cidr": search}})

    try:
        res = es.search(
            index=THREAT_INDEX,
            size=size,
            from_=from_,
            query={"bool": {"must": must}},
            sort=[{"abuse_confidence": {"order": "desc"}}],
        )
        items = []
        for h in res["hits"]["hits"]:
            src = h["_source"]
            items.append({
                "id":               h["_id"],
                "ip":               src.get("ip_or_cidr"),
                "abuse_confidence": src.get("abuse_confidence", 0),
                "country_code":     src.get("country_code", ""),
                "last_reported_at": src.get("last_reported_at"),
                "first_seen":       src.get("first_seen"),
                "source":           src.get("source", "abuseipdb"),
                "category":         src.get("category", ""),
            })
        return jsonify({
            "items": items,
            "total": res["hits"]["total"]["value"],
            "from":  from_,
            "size":  size,
        })
    except Exception as e:
        return jsonify({"items": [], "total": 0, "error": str(e)})


@api_bp.route("/threat_intel/check", methods=["GET"])
def threat_intel_check():
    """Lookup directo de una IP contra lo que ya tenemos indexado en ES."""
    es = get_es()
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "falta parametro ip"}), 400

    try:
        res = es.search(
            index=THREAT_INDEX,
            size=1,
            query={"term": {"ip_or_cidr": ip}},
        )
        hits = res["hits"]["hits"]
        if hits:
            src = hits[0]["_source"]
            return jsonify({
                "ip":               ip,
                "found":            True,
                "abuse_confidence": src.get("abuse_confidence", 0),
                "country_code":     src.get("country_code", ""),
                "last_reported_at": src.get("last_reported_at"),
                "source":           src.get("source", "abuseipdb"),
                "category":         src.get("category", ""),
            })
        return jsonify({"ip": ip, "found": False})
    except Exception as e:
        return jsonify({"ip": ip, "found": False, "error": str(e)})


@api_bp.route("/threat_intel/check_live", methods=["GET", "POST"])
def threat_intel_check_live():
    """Consulta en vivo a la API de AbuseIPDB y actualiza el indice.

    Consume una cuota del plan gratuito (1000 consultas al dia), por eso es
    una accion explicita del operador, no se llama automaticamente.
    """
    import sys
    sys.path.insert(0, "/home/minerva/Escritorio/TFG_Fabian/ORION")
    try:
        from tools.abuseipdb_ingest import (
            check_ip_live, upsert_check_result, get_api_key
        )
    except Exception as e:
        return jsonify({"error": f"no se pudo cargar ingest module: {e}"}), 500

    ip = (request.args.get("ip") or request.form.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "falta parametro ip"}), 400

    es = get_es()
    try:
        key = get_api_key()
    except SystemExit as e:
        return jsonify({"error": str(e)}), 500

    try:
        data = check_ip_live(key, ip)
    except RuntimeError as e:
        return jsonify({"ip": ip, "error": str(e)}), 502
    except Exception as e:
        return jsonify({"ip": ip, "error": f"error consultando API: {e}"}), 502

    # Guarda en orion-threat-intel (creando o actualizando)
    try:
        upsert_check_result(es, data)
        # Si la IP resulto maliciosa, ademas anadir una alerta de tipo "manual_check"
        # al indice orion-alerts (lo mira el dashboard de Cyberinteligencia)
        score = data.get("abuseConfidenceScore", 0)
        if score >= 50:
            import datetime as _dt, hashlib as _hl
            now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
            key = f"{ip}-manual-{now.strftime('%Y%m%d%H%M%S')}"
            _id = _hl.sha1(key.encode()).hexdigest()[:24]
            es.index(index="orion-alerts", id=_id, document={
                "@timestamp":       now.isoformat(),
                "ip":               ip,
                "abuse_confidence": score,
                "country_code":     data.get("countryCode", ""),
                "category":         "malicious",
                "isp":              data.get("isp", ""),
                "domain":           data.get("domain", ""),
                "connections":      0,
                "total_reports":    data.get("totalReports", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "detection_type":   "manual_check",
                "window":           "n/a",
            })
    except Exception as e:
        # No bloquea, devolvemos la info aunque la indexacion falle
        return jsonify({
            "ip":               ip,
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "country_code":     data.get("countryCode", ""),
            "isp":              data.get("isp", ""),
            "domain":           data.get("domain", ""),
            "total_reports":    data.get("totalReports", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "is_tor":           data.get("isTor", False),
            "indexed":          False,
            "index_error":      str(e),
        })

    return jsonify({
        "ip":               ip,
        "abuse_confidence": data.get("abuseConfidenceScore", 0),
        "country_code":     data.get("countryCode", ""),
        "isp":              data.get("isp", ""),
        "domain":           data.get("domain", ""),
        "total_reports":    data.get("totalReports", 0),
        "last_reported_at": data.get("lastReportedAt"),
        "is_tor":           data.get("isTor", False),
        "indexed":          True,
    })


@api_bp.route("/threat-intel/stats", methods=["GET"])
def _legacy_stats():
    """Alias con guion de threat_intel_stats para no romper enlaces externos."""
    return threat_intel_stats()


@api_bp.route("/threat-intel", methods=["GET"])
def _legacy_list():
    """Alias con guion de threat_intel_list para no romper enlaces externos."""
    return threat_intel_list()
