#!/usr/bin/env python3
"""Ingesta de IPs maliciosas desde AbuseIPDB a Elasticsearch.

API: https://api.abuseipdb.com/api/v2/blacklist
Documentacion: https://docs.abuseipdb.com/

Cada IP devuelta tiene un campo `abuseConfidenceScore` (0-100) que es el
porcentaje de confianza en que la IP es maliciosa segun los reportes
acumulados. ORION almacena este score y lo expone en la GUI y dashboards.

Uso:
    # 1. Una API key en /etc/orion/abuseipdb.key o ENV var:
    export ABUSEIPDB_KEY="tu-api-key-aqui"
    # 2. Lanzar:
    python3 tools/abuseipdb_ingest.py

Lo lanzara automaticamente el timer systemd orion-threat-intel.timer (cada 24h).
"""

import datetime
import json
import os
import sys

import requests
from elasticsearch import Elasticsearch, helpers

# Configuracion
ES_URL          = "http://localhost:9200"
INDEX           = "orion-threat-intel"
API_URL         = "https://api.abuseipdb.com/api/v2/blacklist"
CHECK_URL       = "https://api.abuseipdb.com/api/v2/check"
KEY_FILE        = "/etc/orion/abuseipdb.key"
DEFAULT_LIMIT   = 10000   # gratuito permite hasta 10000 IPs
MIN_CONFIDENCE  = 50      # baja a 50 para reducir rotacion entre dias
LIVE_CHECK_DAYS = 90      # ventana de reportes para check on-demand


# Lectura de la API key
def get_api_key():
    """Lee la API key de ENV var ABUSEIPDB_KEY o de /etc/orion/abuseipdb.key."""
    key = os.environ.get("ABUSEIPDB_KEY")
    if key:
        return key.strip()
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            return f.read().strip()
    raise SystemExit(
        f"[!] Falta API key. Opciones:\n"
        f"    a) export ABUSEIPDB_KEY=tu-clave   (para uso interactivo)\n"
        f"    b) echo 'tu-clave' | sudo tee {KEY_FILE} > /dev/null && "
        f"sudo chmod 600 {KEY_FILE}  (para uso por systemd)"
    )


# Check puntual de UNA IP contra AbuseIPDB (consume 1 cuota del plan)
def check_ip_live(api_key, ip, max_age_days=LIVE_CHECK_DAYS):
    """Llama al endpoint /check para una IP concreta.

    Devuelve el dict del campo 'data' de AbuseIPDB con todos sus campos
    (abuseConfidenceScore, countryCode, isp, domain, totalReports, ...).
    Lanza RuntimeError en errores de la API.
    """
    headers = {"Key": api_key, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": max_age_days}
    r = requests.get(CHECK_URL, headers=headers, params=params, timeout=15)
    if r.status_code == 401:
        raise RuntimeError("API key invalida (401)")
    if r.status_code == 429:
        raise RuntimeError("Rate limit excedido (429). 1000 checks/dia en plan Free.")
    r.raise_for_status()
    return r.json().get("data", {})


def upsert_check_result(es, data):
    """Indexa/actualiza el resultado de un check en orion-threat-intel.

    Aprovecha el cache: si una IP ya estaba en la lista local, se actualiza
    con datos frescos. Si no estaba, se anade.
    Usa _id = abuseipdb-<ip> para evitar duplicados.
    """
    ip = data.get("ipAddress")
    if not ip:
        return None
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    expires = (datetime.datetime.now(datetime.timezone.utc)
               + datetime.timedelta(days=2)).isoformat()
    doc = {
        "ip_or_cidr":       ip,
        "type":             "ip",
        "source":           "abuseipdb",
        "ingest_type":      "manual",
        "category":         "malicious" if data.get("abuseConfidenceScore", 0) > 0 else "checked",
        "abuse_confidence": data.get("abuseConfidenceScore", 0),
        "country_code":     data.get("countryCode", ""),
        "isp":              data.get("isp", ""),
        "domain":           data.get("domain", ""),
        "total_reports":    data.get("totalReports", 0),
        "last_reported_at": data.get("lastReportedAt"),
        "first_seen":       now,
        "last_seen":        now,
        "expires_at":       expires,
    }
    es.index(index=INDEX, id=f"abuseipdb-{ip}", document=doc)
    return doc


# Descarga de la blacklist
def fetch_blacklist(api_key, limit=DEFAULT_LIMIT, confidence_min=MIN_CONFIDENCE):
    """Llama al endpoint /blacklist y devuelve el JSON con la lista."""
    headers = {"Key": api_key, "Accept": "application/json"}
    params  = {"confidenceMinimum": confidence_min, "limit": limit}
    print(f"[*] Descargando blacklist (confidence >= {confidence_min}, limit {limit})...")
    r = requests.get(API_URL, headers=headers, params=params, timeout=60)
    if r.status_code == 401:
        raise SystemExit("[!] API key invalida (401 Unauthorized)")
    if r.status_code == 429:
        raise SystemExit("[!] Rate limit excedido (429). El plan gratuito permite 1 blacklist/dia.")
    r.raise_for_status()
    return r.json()


# Mapping alineado con la documentacion del indice orion-threat-intel.
INDEX_MAPPING = {
    "properties": {
        "ip_or_cidr":          {"type": "ip"},
        "type":                {"type": "keyword"},
        "source":              {"type": "keyword"},
        "category":            {"type": "keyword"},
        "abuse_confidence":    {"type": "integer"},  # 0-100, el porcentaje
        "country_code":        {"type": "keyword"},
        "last_reported_at":    {"type": "date"},
        "first_seen":          {"type": "date"},
        "last_seen":           {"type": "date"},
        "expires_at":          {"type": "date"},
    }
}


def ensure_index(es):
    if not es.indices.exists(index=INDEX):
        es.indices.create(index=INDEX, mappings=INDEX_MAPPING)
        print(f"[+] Indice {INDEX} creado")


# Indexacion via bulk
def index_blacklist(es, blacklist_data):
    """Borra docs viejos del ingest masivo y mete los nuevos.
    NO toca las entradas con ingest_type=manual (verificaciones puntuales del
    operador), para que sobrevivan entre sincronizaciones.
    """
    ensure_index(es)

    print("[*] Borrando docs viejos de source=abuseipdb e ingest_type=blacklist...")
    es.delete_by_query(
        index=INDEX,
        body={"query": {"bool": {"must": [
            {"term": {"source":      "abuseipdb"}},
            {"term": {"ingest_type": "blacklist"}},
        ]}}},
        refresh=True,
    )

    now     = datetime.datetime.now(datetime.timezone.utc).isoformat()
    expires = (datetime.datetime.now(datetime.timezone.utc)
               + datetime.timedelta(days=2)).isoformat()

    docs = []
    for entry in blacklist_data.get("data", []):
        ip       = entry.get("ipAddress")
        score    = entry.get("abuseConfidenceScore", 0)
        last_rep = entry.get("lastReportedAt")
        country  = entry.get("countryCode", "")

        if not ip:
            continue

        docs.append({
            "_op_type": "index",
            "_index":   INDEX,
            "_id":      f"abuseipdb-{ip}",
            "_source": {
                "ip_or_cidr":       ip,
                "type":             "ip",
                "source":           "abuseipdb",
                "ingest_type":      "blacklist",
                "category":         "malicious",
                "abuse_confidence": score,
                "country_code":     country,
                "last_reported_at": last_rep,
                "first_seen":       now,
                "last_seen":        now,
                "expires_at":       expires,
            },
        })

    if not docs:
        print("[!] No hay docs para indexar")
        return 0

    print(f"[*] Indexando {len(docs)} docs en bulk...")
    success, errors = helpers.bulk(es, docs, raise_on_error=False, raise_on_exception=False)
    if errors:
        print(f"[!] {len(errors)} errores indexando (primeros 3): {errors[:3]}")
    print(f"[+] {success} docs indexados correctamente")
    return success


# Main
def main():
    print(f"[*] {datetime.datetime.now().isoformat()} - AbuseIPDB ingest")
    api_key = get_api_key()
    print(f"[*] API key cargada ({len(api_key)} caracteres)")

    blacklist = fetch_blacklist(api_key)
    print(f"[*] AbuseIPDB devolvio {len(blacklist.get('data', []))} IPs")

    es = Elasticsearch(ES_URL, request_timeout=30)
    n = index_blacklist(es, blacklist)

    print(f"[+] Hecho. Total IPs maliciosas en {INDEX}: {n}")


if __name__ == "__main__":
    main()
