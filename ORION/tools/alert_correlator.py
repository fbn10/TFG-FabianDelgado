#!/usr/bin/env python3
"""Correlador de alertas: cruza Packetbeat con orion-threat-intel.

Cada ejecucion:
  1. Lee las destination.ip vistas por Packetbeat en los ultimos 5 min.
  2. Cruza con orion-threat-intel (AbuseIPDB) con abuse_confidence >= 50.
  3. Para cada match, indexa un doc en orion-alerts con info enriquecida.

Diseno idempotente: el _id del doc es hash(ip + minuto truncado), asi que
relanzarlo en la misma ventana no duplica.

Se ejecuta cada minuto via systemd timer orion-alerts.timer.
"""

import datetime
import hashlib
import sys

from elasticsearch import Elasticsearch, helpers

ES_URL              = "http://localhost:9200"
PACKETBEAT_INDEX    = "packetbeat-*"
THREAT_INDEX        = "orion-threat-intel"
ALERTS_INDEX        = "orion-alerts"
LOOKBACK_MIN        = 5
MIN_CONFIDENCE      = 50

ALERTS_MAPPING = {
    "properties": {
        "@timestamp":       {"type": "date"},
        "ip":               {"type": "ip"},
        "abuse_confidence": {"type": "integer"},
        "country_code":     {"type": "keyword"},
        "category":         {"type": "keyword"},
        "isp":              {"type": "keyword"},
        "domain":           {"type": "keyword"},
        "connections":      {"type": "long"},
        "total_reports":    {"type": "long"},
        "last_reported_at": {"type": "date"},
        "detection_type":   {"type": "keyword"},  # "traffic" | "manual_check"
        "window":           {"type": "keyword"},
    }
}


def main():
    es = Elasticsearch(ES_URL, request_timeout=30)

    # Crear indice si no existe
    if not es.indices.exists(index=ALERTS_INDEX):
        es.indices.create(index=ALERTS_INDEX, mappings=ALERTS_MAPPING)
        print(f"[+] Indice {ALERTS_INDEX} creado")

    # 1. Top destination.ip en la ventana
    try:
        traffic = es.search(
            index=PACKETBEAT_INDEX,
            size=0,
            query={"bool": {"must": [
                {"range":  {"@timestamp": {"gte": f"now-{LOOKBACK_MIN}m"}}},
                {"exists": {"field": "destination.ip"}},
            ]}},
            aggs={"top_ips": {"terms": {"field": "destination.ip", "size": 1000}}}
        )
    except Exception as e:
        print(f"[!] Error consultando Packetbeat: {e}")
        return

    buckets = traffic["aggregations"]["top_ips"]["buckets"]
    if not buckets:
        print(f"[*] Sin trafico observado en ultimos {LOOKBACK_MIN} min")
        return

    counts = {b["key"]: b["doc_count"] for b in buckets}
    ips    = list(counts.keys())

    # 2. Cruzar con threat intel
    if not es.indices.exists(index=THREAT_INDEX):
        print(f"[!] {THREAT_INDEX} no existe, nada que correlar")
        return

    threat = es.search(
        index=THREAT_INDEX,
        size=len(ips),
        query={"bool": {"filter": [
            {"terms": {"ip_or_cidr": ips}},
            {"range": {"abuse_confidence": {"gte": MIN_CONFIDENCE}}},
        ]}}
    )
    matches = [h["_source"] for h in threat["hits"]["hits"]]

    if not matches:
        print(f"[*] 0 IPs maliciosas detectadas en {len(ips)} destinos observados")
        return

    # 3. Indexar alertas
    now = datetime.datetime.now(datetime.timezone.utc).replace(second=0, microsecond=0)
    docs = []
    for m in matches:
        ip = m.get("ip_or_cidr")
        if not ip:
            continue
        # _id estable por minuto: no duplica si correlamos dos veces el mismo minuto
        key = f"{ip}-{now.strftime('%Y%m%d%H%M')}"
        _id = hashlib.sha1(key.encode()).hexdigest()[:24]
        docs.append({
            "_op_type": "index",
            "_index":   ALERTS_INDEX,
            "_id":      _id,
            "_source": {
                "@timestamp":       now.isoformat(),
                "ip":               ip,
                "abuse_confidence": m.get("abuse_confidence", 0),
                "country_code":     m.get("country_code", ""),
                "category":         m.get("category", "malicious"),
                "isp":              m.get("isp", ""),
                "domain":           m.get("domain", ""),
                "connections":      counts.get(ip, 0),
                "total_reports":    m.get("total_reports", 0),
                "last_reported_at": m.get("last_reported_at"),
                "detection_type":   "traffic",
                "window":           f"{LOOKBACK_MIN}m",
            },
        })

    success, errors = helpers.bulk(es, docs, raise_on_error=False, raise_on_exception=False)
    print(f"[+] {success} alertas indexadas (de {len(matches)} matches en {len(ips)} destinos)")
    if errors:
        print(f"[!] {len(errors)} errores: {errors[:2]}")


if __name__ == "__main__":
    main()
