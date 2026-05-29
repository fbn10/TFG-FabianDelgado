#!/usr/bin/env python3
"""Expirer de bloqueos auto.

Se ejecuta periodicamente (systemd timer cada 5s). Busca en orion-rules las
reglas con auto_blocked=true, enabled=true y expires_at < now, y las pasa
a enabled=false. El loader XDP solo aplica reglas enabled=true, asi que el
paso a false equivale a quitar la entrada del mapa BPF.

No borra el documento: queda como historial en la pestana "Bloqueos auto"
con su estado "disabled" + el contador de cuantas veces se ha bloqueado esa
IP a lo largo del tiempo.
"""

import sys
from datetime import datetime, timezone

from elasticsearch import Elasticsearch

ES_URL = "http://localhost:9200"


def main():
    es = Elasticsearch(ES_URL, request_timeout=5)
    now_iso = datetime.now(timezone.utc).isoformat()

    query = {
        "size": 500,
        "query": {
            "bool": {
                "must": [
                    {"term": {"auto_blocked": True}},
                    {"term": {"enabled": True}},
                    {"range": {"expires_at": {"lt": now_iso}}},
                ]
            }
        },
    }

    try:
        hits = es.search(index="orion-rules", body=query)["hits"]["hits"]
    except Exception as e:
        print(f"[expirer] error consultando ES: {e}", file=sys.stderr)
        sys.exit(1)

    if not hits:
        return

    expired = 0
    for h in hits:
        rule_id = h["_id"]
        src = h["_source"]
        src["enabled"] = False
        src["updated_at"] = now_iso
        try:
            es.index(index="orion-rules", id=rule_id, document=src)
            es.index(index="orion-rules-history", document={
                "rule_id":   rule_id,
                "operation": "auto-expired",
                "timestamp": now_iso,
                "user":      "block-expirer",
                "old_state": h["_source"],
                "new_state": src,
            })
            expired += 1
        except Exception as e:
            print(f"[expirer] no se pudo expirar {rule_id}: {e}", file=sys.stderr)

    if expired:
        print(f"[expirer] expirados {expired} bloqueos")


if __name__ == "__main__":
    main()
