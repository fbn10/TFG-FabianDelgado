"""Endpoints CRUD de reglas.

Toca dos indices:
  - orion-rules:          fuente de verdad de las reglas activas.
  - orion-rules-history:  auditoria append-only de cada cambio.

Soft delete: borrar una regla equivale a poner enabled=false. Asi el
historial sigue trazable y se puede reactivar luego sin perder datos.
"""

import uuid
from datetime import datetime, timezone

from flask import jsonify, request

from controlplane.api import api_bp
from controlplane.es_client import get_es
from controlplane.validators import validate_rule


def _now_iso() -> str:
    """Timestamp actual en formato ISO 8601 con sufijo Z (UTC)."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _audit(rule_id: str, operation: str, old_state, new_state, user: str = "api"):
    """Apunta el cambio en orion-rules-history."""
    es = get_es()
    es.index(index="orion-rules-history", document={
        "rule_id": rule_id,
        "operation": operation,
        "timestamp": _now_iso(),
        "user": user,
        "old_state": old_state,
        "new_state": new_state,
    })


@api_bp.route("/rules", methods=["GET"])
def list_rules():
    """Devuelve todas las reglas activas (enabled=true)."""
    es = get_es()
    res = es.search(
        index="orion-rules",
        query={"term": {"enabled": True}},
        size=256,
    )
    rules = [{"id": h["_id"], **h["_source"]} for h in res["hits"]["hits"]]
    return jsonify({
        "rules": rules,
        "total": res["hits"]["total"]["value"],
    })


@api_bp.route("/rules/<rule_id>", methods=["GET"])
def get_rule(rule_id):
    """Devuelve una regla por id."""
    es = get_es()
    try:
        doc = es.get(index="orion-rules", id=rule_id)
        return jsonify({"id": doc["_id"], **doc["_source"]})
    except Exception:
        return jsonify({"error": "regla no encontrada"}), 404


@api_bp.route("/rules", methods=["POST"])
def create_rule():
    """Crea una regla nueva."""
    payload = request.get_json(silent=True) or {}

    try:
        clean = validate_rule(payload)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    rule_id = f"rule-{uuid.uuid4().hex[:12]}"
    now = _now_iso()
    document = {
        "rule_id": rule_id,
        **clean,
        "enabled": True,
        "created_at": now,
        "updated_at": now,
    }

    es = get_es()
    # refresh="wait_for" asegura que el doc es visible en busquedas
    # antes de devolver al cliente. Util para que un GET inmediato
    # despues de un POST vea la regla recien creada.
    es.index(
        index="orion-rules",
        id=rule_id,
        document=document,
        refresh="wait_for",
    )
    _audit(rule_id, "created", None, document)

    return jsonify({"id": rule_id, **document}), 201


@api_bp.route("/rules/<rule_id>", methods=["PUT"])
def update_rule(rule_id):
    """Modifica una regla existente.

    Conserva rule_id, created_at, created_by y enabled de la regla original.
    Sobrescribe todo lo demas con la nueva validacion. Indexa una entrada
    de auditoria con old_state y new_state.
    """
    payload = request.get_json(silent=True) or {}

    try:
        clean = validate_rule(payload)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    es = get_es()

    try:
        doc = es.get(index="orion-rules", id=rule_id)
    except Exception:
        return jsonify({"error": "regla no encontrada"}), 404

    old_state = doc["_source"]
    new_state = {
        **clean,
        "rule_id": rule_id,
        "enabled": old_state.get("enabled", True),
        "created_at": old_state.get("created_at"),
        "created_by": old_state.get("created_by", "api"),
        "updated_at": _now_iso(),
    }

    es.index(
        index="orion-rules",
        id=rule_id,
        document=new_state,
        refresh="wait_for",
    )
    _audit(rule_id, "updated", old_state, new_state)

    return jsonify({"id": rule_id, **new_state})


@api_bp.route("/rules/<rule_id>", methods=["DELETE"])
def disable_rule(rule_id):
    """Desactiva (soft delete) una regla cambiando enabled a false."""
    es = get_es()

    try:
        doc = es.get(index="orion-rules", id=rule_id)
    except Exception:
        return jsonify({"error": "regla no encontrada"}), 404

    old_state = doc["_source"]
    new_state = {**old_state, "enabled": False, "updated_at": _now_iso()}

    es.index(
        index="orion-rules",
        id=rule_id,
        document=new_state,
        refresh="wait_for",
    )
    _audit(rule_id, "disabled", old_state, new_state)

    return jsonify({"id": rule_id, "status": "disabled"})


@api_bp.route("/rules/history", methods=["GET"])
def list_rules_history():
    """Devuelve los cambios mas recientes del indice orion-rules-history.

    Aceptan: ?size=N (default 100) y ?rule_id=X para filtrar por una regla.
    Ordenado por timestamp descendente (mas reciente arriba).
    """
    es = get_es()

    size = min(int(request.args.get("size", 100)), 500)
    rule_id_filter = request.args.get("rule_id")

    query = {"match_all": {}}
    if rule_id_filter:
        query = {"term": {"rule_id": rule_id_filter}}

    try:
        res = es.search(
            index="orion-rules-history",
            query=query,
            size=size,
            sort=[{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
        )
        events = [{"id": h["_id"], **h["_source"]} for h in res["hits"]["hits"]]
        return jsonify({
            "events": events,
            "total": res["hits"]["total"]["value"],
        })
    except Exception as e:
        return jsonify({"events": [], "total": 0, "error": str(e)}), 200
