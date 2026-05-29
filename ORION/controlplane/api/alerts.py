"""Endpoint /api/alerts: conexiones del cliente a IPs maliciosas (AbuseIPDB).

Hace cruce on-the-fly entre destination.ip observados por Packetbeat y la
blacklist de AbuseIPDB indexada en orion-threat-intel. Solo se considera
alerta una conexion cuya destination.ip tenga abuse_confidence >= min_score
(default 50).
"""

from flask import jsonify, request

from controlplane.api import api_bp
from controlplane.es_client import get_es

PACKETBEAT_INDEX = "packetbeat-*"
THREAT_INDEX     = "orion-threat-intel"


@api_bp.route("/alerts", methods=["GET"])
def alerts_list():
    """Devuelve conexiones a IPs con abuse_confidence >= min_score.

    Parametros:
      window:    ventana temporal (default '15m')
      min_score: umbral confidence AbuseIPDB (default 50)
      size:      maximo de alertas (default 100, max 500)
    """
    es = get_es()
    window    = request.args.get("window", "15m")
    min_score = int(request.args.get("min_score", 50))
    size      = min(int(request.args.get("size", 100)), 500)

    # 1) Top destination.ip vistas por Packetbeat
    try:
        traffic = es.search(
            index=PACKETBEAT_INDEX,
            size=0,
            query={"bool": {"must": [
                {"range":  {"@timestamp": {"gte": f"now-{window}"}}},
                {"exists": {"field": "destination.ip"}},
            ]}},
            aggs={"top_ips": {"terms": {"field": "destination.ip", "size": 500}}}
        )
    except Exception as e:
        return jsonify({"items": [], "total": 0, "error": str(e)})

    buckets = traffic["aggregations"]["top_ips"]["buckets"]
    if not buckets:
        return jsonify({"items": [], "total": 0, "window": window, "min_score": min_score})

    ips    = [b["key"] for b in buckets]
    counts = {b["key"]: b["doc_count"] for b in buckets}

    # 2) Cruce con orion-threat-intel (AbuseIPDB)
    if not es.indices.exists(index=THREAT_INDEX):
        return jsonify({"items": [], "total": 0, "note": "orion-threat-intel no existe"})

    threat = es.search(
        index=THREAT_INDEX,
        size=len(ips),
        query={"bool": {"filter": [
            {"terms": {"ip_or_cidr": ips}},
            {"range": {"abuse_confidence": {"gte": min_score}}},
        ]}}
    )

    threat_map = {h["_source"]["ip_or_cidr"]: h["_source"] for h in threat["hits"]["hits"]}

    items = []
    for ip in ips:
        ti = threat_map.get(ip)
        if not ti:
            continue
        items.append({
            "ip":               ip,
            "connections":      counts[ip],
            "abuse_confidence": ti.get("abuse_confidence", 0),
            "country_code":     ti.get("country_code", ""),
            "last_reported_at": ti.get("last_reported_at"),
            "source":           ti.get("source", "abuseipdb"),
            "category":         ti.get("category", ""),
        })

    items.sort(key=lambda x: (-x["abuse_confidence"], -x["connections"]))
    items = items[:size]

    return jsonify({
        "items":     items,
        "total":     len(items),
        "window":    window,
        "min_score": min_score,
    })


@api_bp.route("/alerts/stats", methods=["GET"])
def alerts_stats():
    """KPIs para la pestana Alertas."""
    es = get_es()
    window    = request.args.get("window", "15m")
    min_score = int(request.args.get("min_score", 50))

    try:
        traffic = es.search(
            index=PACKETBEAT_INDEX,
            size=0,
            query={"bool": {"must": [
                {"range":  {"@timestamp": {"gte": f"now-{window}"}}},
                {"exists": {"field": "destination.ip"}},
            ]}},
            aggs={"top_ips": {"terms": {"field": "destination.ip", "size": 500}}}
        )
    except Exception as e:
        return jsonify({"total": 0, "critical": 0, "avg_score": None,
                        "top_country": "--", "top_country_count": 0,
                        "total_connections": 0, "error": str(e)})

    buckets = traffic["aggregations"]["top_ips"]["buckets"]
    if not buckets:
        return jsonify({"total": 0, "critical": 0, "avg_score": None,
                        "top_country": "--", "top_country_count": 0,
                        "total_connections": 0, "window": window, "min_score": min_score})

    ips    = [b["key"] for b in buckets]
    counts = {b["key"]: b["doc_count"] for b in buckets}

    if not es.indices.exists(index=THREAT_INDEX):
        return jsonify({"total": 0, "critical": 0, "avg_score": None,
                        "top_country": "--", "top_country_count": 0,
                        "total_connections": 0})

    threat = es.search(
        index=THREAT_INDEX,
        size=len(ips),
        query={"bool": {"filter": [
            {"terms": {"ip_or_cidr": ips}},
            {"range": {"abuse_confidence": {"gte": min_score}}},
        ]}}
    )
    matched = [h["_source"] for h in threat["hits"]["hits"]]

    total              = len(matched)
    critical           = sum(1 for m in matched if m.get("abuse_confidence", 0) >= 90)
    avg_score          = (sum(m.get("abuse_confidence", 0) for m in matched) / total) if total else None
    countries          = {}
    total_connections  = 0
    for m in matched:
        c = m.get("country_code") or "?"
        countries[c] = countries.get(c, 0) + 1
        total_connections += counts.get(m["ip_or_cidr"], 0)

    top_country, top_count = ("--", 0)
    if countries:
        top_country, top_count = max(countries.items(), key=lambda x: x[1])

    return jsonify({
        "total":             total,
        "critical":          critical,
        "avg_score":         avg_score,
        "top_country":       top_country,
        "top_country_count": top_count,
        "total_connections": total_connections,
        "by_country":        countries,
        "window":            window,
        "min_score":         min_score,
    })
