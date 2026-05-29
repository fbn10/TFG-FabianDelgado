"""Endpoints /api/mitm/*: trafico HTTPS interceptado y descifrado por mitmproxy.

Consulta el indice 'orion-mitm-traffic' que llena el addon tools/mitm_to_es.py.
"""

from flask import jsonify, request

from controlplane.api import api_bp
from controlplane.es_client import get_es

INDEX = "orion-mitm-traffic"


@api_bp.route("/mitm/sessions", methods=["GET"])
def mitm_sessions():
    """Lista de peticiones interceptadas, mas recientes primero.

    Parametros:
      window: rango de tiempo (default '15m')
      size:   max docs (default 100, max 500)
      method: filtrar por metodo HTTP (GET, POST, ...)
      only_security: si '1', devuelve solo peticiones con hallazgos de seguridad
    """
    es = get_es()

    window = request.args.get("window", "15m")
    size   = min(int(request.args.get("size", 100)), 500)
    method = request.args.get("method")
    only_security = request.args.get("only_security") == "1"

    must = [{"range": {"@timestamp": {"gte": f"now-{window}"}}}]
    if method:
        must.append({"term": {"http.method": method.upper()}})
    if only_security:
        must.append({"bool": {"should": [
            {"term": {"security.has_credentials": True}},
            {"term": {"security.has_jwt": True}},
        ]}})

    if not es.indices.exists(index=INDEX):
        return jsonify({"items": [], "total": 0, "note": f"indice {INDEX} aun no existe"})

    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
    }
    resp = es.search(index=INDEX, **body)
    hits = resp["hits"]["hits"]

    items = []
    for h in hits:
        src = h["_source"]
        http_ = src.get("http", {})
        sec   = src.get("security", {})
        items.append({
            "id":            h["_id"],
            "ts":            src.get("@timestamp"),
            "duration_ms":   src.get("duration_ms"),
            "client_ip":     src.get("client", {}).get("ip"),
            "server_host":   src.get("server", {}).get("hostname"),
            "method":        http_.get("method"),
            "path":          http_.get("path"),
            "url":           http_.get("url"),
            "status":        http_.get("response_status"),
            "req_ctype":     http_.get("request_content_type"),
            "resp_ctype":    http_.get("response_content_type"),
            "req_size":      http_.get("request_body_size"),
            "resp_size":     http_.get("response_body_size"),
            "has_credentials": sec.get("has_credentials", False),
            "has_jwt":         sec.get("has_jwt", False),
        })

    return jsonify({
        "items":  items,
        "total":  resp["hits"]["total"]["value"],
        "window": window,
    })


@api_bp.route("/mitm/sessions/<doc_id>", methods=["GET"])
def mitm_session_detail(doc_id):
    """Detalle completo de una peticion: headers, body completo, JWT decodificado."""
    es = get_es()
    if not es.indices.exists(index=INDEX):
        return jsonify({"error": "indice no existe"}), 404
    try:
        doc = es.get(index=INDEX, id=doc_id)
        return jsonify(doc["_source"])
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@api_bp.route("/mitm/stats", methods=["GET"])
def mitm_stats():
    """Estadisticas agregadas para tarjetas de la UI."""
    es = get_es()
    window = request.args.get("window", "15m")

    if not es.indices.exists(index=INDEX):
        return jsonify({
            "total": 0, "by_method": {}, "by_status": {}, "by_host": {},
            "with_credentials": 0, "with_jwt": 0, "window": window,
        })

    query = {"bool": {"must": [{"range": {"@timestamp": {"gte": f"now-{window}"}}}]}}

    body = {
        "size": 0,
        "query": query,
        "aggs": {
            "by_method":  {"terms": {"field": "http.method",          "size": 10}},
            "by_status":  {"terms": {"field": "http.response_status", "size": 10}},
            "by_host":    {"terms": {"field": "server.hostname",      "size": 10}},
            "with_credentials": {"filter": {"term": {"security.has_credentials": True}}},
            "with_jwt":         {"filter": {"term": {"security.has_jwt": True}}},
        },
    }
    resp = es.search(index=INDEX, **body)
    aggs = resp["aggregations"]

    def buckets_to_dict(agg):
        return {b["key"]: b["doc_count"] for b in agg["buckets"]}

    return jsonify({
        "total":             resp["hits"]["total"]["value"],
        "by_method":         buckets_to_dict(aggs["by_method"]),
        "by_status":         {str(k): v for k, v in buckets_to_dict(aggs["by_status"]).items()},
        "by_host":           buckets_to_dict(aggs["by_host"]),
        "with_credentials":  aggs["with_credentials"]["doc_count"],
        "with_jwt":          aggs["with_jwt"]["doc_count"],
        "window":            window,
    })
