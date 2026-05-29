#!/usr/bin/env python3
"""Detector WAF desacoplado de mitmproxy.

Patron pipeline:
    mitmproxy --(orion-mitm-traffic)--> Elasticsearch
    waf_detector lee ES cada 5s -> regex + agregaciones -> /api/blocks/auto
    /api/blocks/auto crea regla en orion-rules
    Loader XDP propaga la regla al mapa BPF
    XDP dropea a wire-speed

Detecciones que dispara:

  1. User-Agent malicioso (sqlmap, nikto, gobuster, ...). Senal muy fiable.
  2. Patrones SQLi / XSS / RCE / LFI sobre URL + body de request, con
     URL-decoding doble para esquivar payloads tipo %27 / %2527.
  3. Fuerza bruta: >= 5 respuestas 401/403 desde misma IP en 60s.
  4. Fuzzing/enumeracion: >= 20 respuestas 404 desde misma IP en 60s.

Para no llenar orion-rules con duplicados durante un ataque sostenido, antes
de pedir el bloqueo consulta si ya hay una regla auto_blocked activa para
(source_ip, alert_type) creada en los ultimos DEDUPE_WINDOW_S segundos.
"""

import re
import sys
import time
import urllib.parse
import urllib.request
import json
from datetime import datetime, timedelta, timezone

from elasticsearch import Elasticsearch

ES_URL              = "http://localhost:9200"
TRAFFIC_INDEX       = "orion-mitm-traffic"
ALERT_INDEX         = "orion-alerts"
RULES_INDEX         = "orion-rules"
BLOCK_API_URL       = "http://localhost:5000/api/blocks/auto"
BLOCK_TTL_SECONDS   = 900   # 15 minutos. Lo puede prolongar manualmente desde la GUI ("Hacer permanente").

# Ventanas
SCAN_WINDOW_S       = 15          # cuanto hacia atras miramos cada tick
BRUTE_WINDOW_S      = 60
BRUTE_THRESHOLD     = 5
FUZZ_WINDOW_S       = 60
FUZZ_THRESHOLD      = 20
# Nota: la dedup (no crear duplicados) la aplica el endpoint /api/blocks/auto.
# Si la IP ya tiene un bloqueo activo, el endpoint extiende su TTL y
# incrementa hit_count en vez de crear otra regla.

# Patrones de ataque. Se aplican sobre URL+body URL-decodificados (incluyendo
# decode de '+' como espacio, propio de application/x-www-form-urlencoded).
WAF_PATTERNS = [
    ("sqli", re.compile(
        r"(?i)("
        r"\bunion\b\s+\bselect\b"                       # UNION SELECT
        r"|'\s*or\s*'?\d+'?\s*=\s*'?\d+"                # 'OR 1=1 (con comilla)
        r"|\bor\s+\d+\s*=\s*\d+\b"                      # OR 1=1 (sin comilla)
        r"|--(\s|$)"                                    # comentario SQL al final
        r"|;\s*(drop|delete|truncate|update|insert)\b"  # ; DROP / ; DELETE ...
        r"|\b(drop|delete|truncate)\s+(table|from)\b"   # DROP TABLE / DELETE FROM
        r"|\bselect\s+.+\s+from\b"                      # SELECT ... FROM
        r"|\bsleep\s*\("                                # sleep(
        r"|\bbenchmark\s*\("                            # benchmark(
        r"|\bwaitfor\s+delay\b"                         # WAITFOR DELAY (mssql)
        r")"
    )),
    ("xss",  re.compile(r"(?i)(<script[^>]*>|javascript:|onerror\s*=|onload\s*=|<iframe\b|<svg[^>]*/onload|document\.cookie|<img[^>]+onerror)")),
    ("rce",  re.compile(r"(?i)(;\s*(cat|ls|wget|curl|nc|bash|sh|id|whoami)\b|\$\([^)]+\)|`[^`]+`|&&\s*(cat|ls|wget|curl)|\|\s*(nc|sh|bash)\s)")),
    ("lfi",  re.compile(r"(?i)(\.\./|\.\.\\|/etc/(passwd|shadow|hosts)|/proc/self/|\\windows\\system32|file://|php://(filter|input))")),
]

MALICIOUS_UA_TOKENS = [
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirb", "dirbuster",
    "wfuzz", "ffuf", "acunetix", "nessus", "openvas", "metasploit",
    "havij", "jbrofuzz", "wpscan", "joomscan", "burpsuite",
]


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _double_urldecode(s: str) -> str:
    """Decodifica URL recursivamente hasta que la cadena se estabilice,
    con un tope de 4 pasadas. Cubre:
      - 1 pasada: encoding normal de form-urlencoded / URL (lo hace el
        navegador automaticamente al enviar un formulario).
      - 2 pasadas: double-encoding clasico del atacante (%2527 -> %27 -> ').
      - 3-4 pasadas: cuando el atacante teclea un payload ya codificado en
        un formulario HTML y el navegador anade otra capa encima.

    Usamos unquote_plus (no unquote) porque los bodies application/x-www-
    form-urlencoded codifican el espacio como '+'. Sin esto, un 'OR+1=1' no
    matchea con \\s* en la regex.
    """
    try:
        prev = s
        for _ in range(4):
            decoded = urllib.parse.unquote_plus(prev)
            if decoded == prev:
                break
            prev = decoded
        return prev
    except Exception:
        return s


def _fire_block(es, src_ip: str, alert_type: str, matched: str,
                hits: int = 1, mode: str = "increment",
                host: str = None, url: str = None):
    """Indexa alerta en orion-alerts + POST a /api/blocks/auto.

    hits/mode controlan como cuenta el endpoint:
      - increment (default): hit_count += hits. Patrones regex y UA atacante.
      - max: hit_count = max(actual, hits). Brute force y fuzzing (donde
        'hits' es el conteo agregado en ventana 60s, no eventos sueltos).

    No deduplica aqui: el endpoint /api/blocks/auto ya lo hace.
    """
    severity = ("high"   if alert_type in ("sqli", "rce", "lfi")
                else "medium" if alert_type in ("xss", "brute_force", "malicious_ua")
                else "low")

    try:
        es.index(index=ALERT_INDEX, document={
            "@timestamp":     _now_iso(),
            "detection_type": "waf-detector",
            "alert_type":     alert_type,
            "src_ip":         src_ip,
            "host":           host,
            "url":            url,
            "matched":        matched,
            "severity":       severity,
        })
    except Exception as e:
        print(f"[waf] no se pudo indexar alerta: {e}", file=sys.stderr)

    try:
        payload = json.dumps({
            "source_ip":  src_ip,
            "reason":     matched[:200],
            "alert_type": alert_type,
            "ttl":        BLOCK_TTL_SECONDS,
            "hits":       hits,
            "mode":       mode,
        }).encode("utf-8")
        req = urllib.request.Request(
            BLOCK_API_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2) as r:
            if 200 <= r.status < 300:
                body = json.loads(r.read().decode("utf-8"))
                status = body.get("status", "?")
                hc = body.get("hit_count")
                if status == "created":
                    print(f"[waf] BLOCK {src_ip} ({alert_type}, hit_count={hc}): {matched[:80]}")
                else:
                    print(f"[waf] EXTEND {src_ip} ({alert_type}, hit_count={hc})")
                return True
    except Exception as e:
        print(f"[waf] POST /api/blocks/auto fallo para {src_ip}: {e}", file=sys.stderr)
    return False


def scan_patterns(es):
    """Lee orion-mitm-traffic ultimos SCAN_WINDOW_S y aplica regex + UA-check."""
    since = (datetime.now(timezone.utc) - timedelta(seconds=SCAN_WINDOW_S)).isoformat()
    try:
        res = es.search(index=TRAFFIC_INDEX, body={
            "size": 500,
            "_source": [
                "@timestamp",
                "client.ip",
                "server.ip",
                "server.hostname",
                "http.url",
                "http.method",
                "http.request_body",
                "http.request_headers",
            ],
            "query": {"range": {"@timestamp": {"gte": since}}},
            "sort": [{"@timestamp": "desc"}],
        })
    except Exception as e:
        print(f"[waf] no se pudo leer {TRAFFIC_INDEX}: {e}", file=sys.stderr)
        return

    hits = res["hits"]["hits"]
    if hits:
        print(f"[waf] tick: {len(hits)} flows analizados (ventana {SCAN_WINDOW_S}s)")
    for h in hits:
        src  = h["_source"]
        client = src.get("client") or {}
        server = src.get("server") or {}
        http_o = src.get("http") or {}

        src_ip = client.get("ip")
        host   = server.get("hostname") or http_o.get("host")
        url    = http_o.get("url") or ""
        body   = http_o.get("request_body") or ""
        headers = http_o.get("request_headers") or {}

        if not src_ip:
            continue

        # 1) User-Agent malicioso
        ua = ""
        for k, v in headers.items():
            if k.lower() == "user-agent":
                ua = (v or "").lower()
                break
        if ua:
            for token in MALICIOUS_UA_TOKENS:
                if token in ua:
                    _fire_block(es, src_ip, "malicious_ua",
                                matched=f"User-Agent: {ua[:120]}",
                                host=host, url=url)
                    break

        # 2) Regex sobre url+body con double-decode
        haystack = _double_urldecode(f"{url}\n{body}")[:32_000]
        for alert_type, pattern in WAF_PATTERNS:
            m = pattern.search(haystack)
            if m:
                _fire_block(es, src_ip, alert_type,
                            matched=m.group(0)[:200],
                            host=host, url=url)
                break


def scan_brute_force(es):
    """Agrega por client.ip los flows con response_status 401 o 403 en BRUTE_WINDOW_S."""
    since = (datetime.now(timezone.utc) - timedelta(seconds=BRUTE_WINDOW_S)).isoformat()
    try:
        res = es.search(index=TRAFFIC_INDEX, body={
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": since}}},
                        {"terms": {"http.response_status": [401, 403]}},
                    ]
                }
            },
            "aggs": {
                "by_ip": {
                    "terms": {"field": "client.ip", "size": 50, "min_doc_count": BRUTE_THRESHOLD},
                }
            },
        })
    except Exception as e:
        print(f"[waf] brute force query fallo: {e}", file=sys.stderr)
        return

    buckets = res.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
    for b in buckets:
        ip = b["key"]
        count = b["doc_count"]
        _fire_block(es, ip, "brute_force",
                    matched=f"{count} respuestas 401/403 en {BRUTE_WINDOW_S}s",
                    hits=count, mode="max")


def scan_fuzzing(es):
    """Agrega por client.ip los flows con response_status 404 en FUZZ_WINDOW_S."""
    since = (datetime.now(timezone.utc) - timedelta(seconds=FUZZ_WINDOW_S)).isoformat()
    try:
        res = es.search(index=TRAFFIC_INDEX, body={
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": since}}},
                        {"term": {"http.response_status": 404}},
                    ]
                }
            },
            "aggs": {
                "by_ip": {
                    "terms": {"field": "client.ip", "size": 50, "min_doc_count": FUZZ_THRESHOLD},
                }
            },
        })
    except Exception as e:
        print(f"[waf] fuzzing query fallo: {e}", file=sys.stderr)
        return

    buckets = res.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
    for b in buckets:
        ip = b["key"]
        count = b["doc_count"]
        _fire_block(es, ip, "fuzzing",
                    matched=f"{count} respuestas 404 en {FUZZ_WINDOW_S}s",
                    hits=count, mode="max")


def main():
    es = Elasticsearch(ES_URL, request_timeout=5)
    # Tres pasadas independientes; un fallo en una no rompe las otras.
    scan_patterns(es)
    scan_brute_force(es)
    scan_fuzzing(es)


if __name__ == "__main__":
    main()
