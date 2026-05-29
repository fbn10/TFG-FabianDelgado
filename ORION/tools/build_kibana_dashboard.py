#!/usr/bin/env python3
"""Crea el dashboard 'ORION - Inspeccion de trafico' en Kibana via API.

Combina:
  - orion-mitm-traffic*  (HTTPS descifrado por mitmproxy)
  - packetbeat-*         (HTTP plano + metadata de red del propio ORION)

Usa visualizaciones clasicas (tipo 'visualization') en vez de Lens porque
en Kibana 8.x el schema de Lens via API es fragil; las clasicas son estables.

Idempotente. Borra el dashboard y las viz si ya existian.

Uso:
    python3 tools/build_kibana_dashboard.py
"""

import json
import sys

import requests

KIBANA          = "http://localhost:5601"

# Dashboard 1: inspeccion HTTPS (mitmproxy) + KPIs generales
DASHBOARD_TITLE = "ORION - Inspeccion de trafico"
DASHBOARD_ID    = "orion-inspeccion-trafico"

# Dashboard 2: cyberinteligencia AbuseIPDB
THREAT_DASHBOARD_TITLE = "ORION - Cyberinteligencia (AbuseIPDB)"
THREAT_DASHBOARD_ID    = "orion-cyberinteligencia"

MITM_DV_TITLE       = "orion-mitm-traffic*"
PACKETBEAT_DV_TITLE = "packetbeat-*"
THREAT_DV_TITLE     = "orion-threat-intel*"
ALERTS_DV_TITLE     = "orion-alerts*"

HEADERS = {"Content-Type": "application/json", "kbn-xsrf": "true"}


# Kibana API helpers
def kget(path):
    return requests.get(KIBANA + path, headers=HEADERS, timeout=60)


def kpost(path, payload):
    return requests.post(KIBANA + path, headers=HEADERS, json=payload, timeout=60)


def kdelete(path):
    return requests.delete(KIBANA + path, headers=HEADERS, timeout=60)


def find_data_view_id(title):
    r = kget("/api/data_views")
    for dv in r.json().get("data_view", []):
        if dv["title"] == title:
            return dv["id"]
    print(f"  [!] Data view '{title}' no existe. Crealo primero.")
    sys.exit(1)


def delete_if_exists(obj_type, obj_id):
    kdelete(f"/api/saved_objects/{obj_type}/{obj_id}?force=true")


# Constructores de visualizaciones clasicas (cada uno devuelve un dict listo para POSTear como saved object)
def _wrap_search_source(filter_kql=None):
    """Construye el searchSourceJSON con un filtro KQL opcional."""
    query = {"language": "kuery", "query": filter_kql or ""}
    return {
        "query": query,
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    }


def _save_obj(viz_id, title, vis_state, dv_id, filter_kql=None):
    return {
        "id": viz_id,
        "type": "visualization",
        "attributes": {
            "title": title,
            "description": "",
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(_wrap_search_source(filter_kql)),
            },
        },
        "references": [{
            "id": dv_id,
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern",
        }],
    }


def viz_metric(viz_id, title, dv_id, filter_kql=None):
    """Big-number con la cuenta de docs (filtrable con KQL)."""
    vs = {
        "title": title, "type": "metric",
        "aggs": [{
            "id": "1", "enabled": True, "type": "count",
            "schema": "metric", "params": {"customLabel": title},
        }],
        "params": {
            "addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {
                "percentageMode": False, "useRanges": False,
                "colorSchema": "Green to Red", "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000000}],
                "labels": {"show": True}, "invertColors": False,
                "style": {
                    "bgFill": "#000", "bgColor": False, "labelColor": False,
                    "subText": "", "fontSize": 48,
                },
            },
        },
    }
    return _save_obj(viz_id, title, vs, dv_id, filter_kql)


def viz_pie(viz_id, title, dv_id, field, size=10, filter_kql=None):
    """Donut con terms agg."""
    vs = {
        "title": title, "type": "pie",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count",
             "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms",
             "schema": "segment", "params": {
                 "field": field, "orderBy": "1", "order": "desc",
                 "size": size, "otherBucket": False, "missingBucket": False,
             }},
        ],
        "params": {
            "type": "pie", "addTooltip": True,
            "addLegend": True, "legendPosition": "right",
            "isDonut": True,
            "labels": {"show": False, "values": True, "last_level": True, "truncate": 100},
        },
    }
    return _save_obj(viz_id, title, vs, dv_id, filter_kql)


def viz_hbar(viz_id, title, dv_id, field, size=10, filter_kql=None):
    """Histograma vertical con terms agg (Kibana 8.x ya no soporta horizontal_bar
    como tipo independiente; usamos histogram, que renderiza bien)."""
    vs = {
        "title": title, "type": "histogram",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count",
             "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms",
             "schema": "segment", "params": {
                 "field": field, "orderBy": "1", "order": "desc",
                 "size": size, "otherBucket": False,
             }},
        ],
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False, "style": {"color": "#eee"}},
            "categoryAxes": [{
                "id": "CategoryAxis-1", "type": "category", "position": "bottom",
                "show": True, "style": {}, "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100, "rotate": 75},
                "title": {},
            }],
            "valueAxes": [{
                "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                "position": "left", "show": True, "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Count"},
            }],
            "seriesParams": [{
                "show": True, "type": "histogram", "mode": "stacked",
                "data": {"label": "Count", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True, "showCircles": True,
            }],
            "addTooltip": True, "addLegend": False, "legendPosition": "right",
            "times": [], "addTimeMarker": False, "labels": {},
            "palette": {"type": "palette", "name": "kibana_palette"},
            "isVislibVis": True, "detailedTooltip": True, "legendSize": "auto",
        },
    }
    return _save_obj(viz_id, title, vs, dv_id, filter_kql)


def viz_timeline(viz_id, title, dv_id, filter_kql=None):
    """Linea temporal con count over time."""
    vs = {
        "title": title, "type": "line",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count",
             "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "date_histogram",
             "schema": "segment", "params": {
                 "field": "@timestamp", "useNormalizedEsInterval": True,
                 "interval": "auto", "drop_partials": False,
                 "min_doc_count": 1, "extended_bounds": {},
             }},
        ],
        "params": {
            "type": "line",
            "grid": {"categoryLines": False},
            "categoryAxes": [{
                "id": "CategoryAxis-1", "type": "category", "position": "bottom",
                "show": True, "style": {}, "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100},
                "title": {},
            }],
            "valueAxes": [{
                "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                "position": "left", "show": True, "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Count"},
            }],
            "seriesParams": [{
                "show": True, "type": "line", "mode": "normal",
                "data": {"label": "Count", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True, "showCircles": True,
                "interpolate": "linear", "lineWidth": 2,
            }],
            "addTooltip": True, "addLegend": True, "legendPosition": "right",
            "times": [], "addTimeMarker": False,
        },
    }
    return _save_obj(viz_id, title, vs, dv_id, filter_kql)


def viz_table(viz_id, title, dv_id, fields, size=20, filter_kql=None):
    """Tabla con terms aggregations multiple."""
    aggs = [{"id": "1", "enabled": True, "type": "count",
             "schema": "metric", "params": {}}]
    for i, f in enumerate(fields, start=2):
        aggs.append({
            "id": str(i), "enabled": True, "type": "terms",
            "schema": "bucket", "params": {
                "field": f, "orderBy": "1", "order": "desc",
                "size": size, "otherBucket": False,
            },
        })
    vs = {
        "title": title, "type": "table",
        "aggs": aggs,
        "params": {
            "perPage": 10, "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "sort": {"columnIndex": None, "direction": None},
            "showTotal": False, "totalFunc": "sum",
        },
    }
    return _save_obj(viz_id, title, vs, dv_id, filter_kql)


def viz_hbar_sum(viz_id, title, dv_id, term_field, sum_field, size=10, filter_kql=None):
    """Histograma ordenado por SUMA de un campo (ej. dominios por bytes)."""
    vs = {
        "title": title, "type": "histogram",
        "aggs": [
            {"id": "1", "enabled": True, "type": "sum",
             "schema": "metric", "params": {"field": sum_field,
                                            "customLabel": f"sum({sum_field})"}},
            {"id": "2", "enabled": True, "type": "terms",
             "schema": "segment", "params": {
                 "field": term_field, "orderBy": "1", "order": "desc",
                 "size": size, "otherBucket": False,
             }},
        ],
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False, "style": {"color": "#eee"}},
            "categoryAxes": [{
                "id": "CategoryAxis-1", "type": "category", "position": "bottom",
                "show": True, "style": {}, "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100, "rotate": 75},
                "title": {},
            }],
            "valueAxes": [{
                "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                "position": "left", "show": True, "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": f"sum({sum_field})"},
            }],
            "seriesParams": [{
                "show": True, "type": "histogram", "mode": "stacked",
                "data": {"label": f"sum({sum_field})", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True, "showCircles": True,
            }],
            "addTooltip": True, "addLegend": False, "legendPosition": "right",
            "times": [], "addTimeMarker": False, "labels": {},
            "palette": {"type": "palette", "name": "kibana_palette"},
            "isVislibVis": True, "detailedTooltip": True, "legendSize": "auto",
        },
    }
    return _save_obj(viz_id, title, vs, dv_id, filter_kql)


def viz_metric_unique(viz_id, title, dv_id, field, filter_kql=None):
    """Big-number con cardinality (cuenta de valores UNICOS de un campo)."""
    vs = {
        "title": title, "type": "metric",
        "aggs": [{
            "id": "1", "enabled": True, "type": "cardinality",
            "schema": "metric", "params": {"field": field, "customLabel": title},
        }],
        "params": {
            "addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {
                "percentageMode": False, "useRanges": False,
                "colorSchema": "Green to Red", "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000000}],
                "labels": {"show": True}, "invertColors": False,
                "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                          "subText": "", "fontSize": 48},
            },
        },
    }
    return _save_obj(viz_id, title, vs, dv_id, filter_kql)


def viz_metric_sum(viz_id, title, dv_id, field, filter_kql=None):
    """Big-number con SUMA de un campo (ej. total de bytes)."""
    vs = {
        "title": title, "type": "metric",
        "aggs": [{
            "id": "1", "enabled": True, "type": "sum",
            "schema": "metric", "params": {"field": field, "customLabel": title},
        }],
        "params": {
            "addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {
                "percentageMode": False, "useRanges": False,
                "colorSchema": "Green to Red", "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000000000}],
                "labels": {"show": True}, "invertColors": False,
                "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                          "subText": "", "fontSize": 36},
            },
        },
    }
    return _save_obj(viz_id, title, vs, dv_id, filter_kql)


# Main
def main():
    print("[*] Conectando a Kibana...")
    r = kget("/api/status")
    if r.status_code != 200:
        print(f"  [!] Kibana no responde: {r.status_code}")
        sys.exit(1)
    print(f"  [+] Kibana {r.json().get('version',{}).get('number','?')} OK")

    mitm_dv = find_data_view_id(MITM_DV_TITLE)
    pkt_dv  = find_data_view_id(PACKETBEAT_DV_TITLE)
    print(f"  [+] DV mitm:       {mitm_dv}")
    print(f"  [+] DV packetbeat: {pkt_dv}")

    # Limpieza de visualizaciones Lens viejas que dieron error de schema (las recreamos como classic con los mismos ids)
    print("[*] Borrando dashboard y viz Lens viejos (si existen)...")
    for old_id in [
        "orion-viz-mitm-total", "orion-viz-mitm-creds", "orion-viz-mitm-jwt",
        "orion-viz-mitm-methods", "orion-viz-mitm-status",
        "orion-viz-mitm-hosts", "orion-viz-mitm-timeline", "orion-viz-mitm-paths",
        "orion-viz-pkt-dst-ips", "orion-viz-pkt-dst-ports", "orion-viz-pkt-timeline",
    ]:
        delete_if_exists("lens", old_id)
    delete_if_exists("dashboard", "orion-inspeccion-https")
    delete_if_exists("dashboard", DASHBOARD_ID)

    # Construir las visualizaciones nuevas (classic)
    print("[*] Construyendo visualizaciones clasicas...")
    vizzes = []

    # KPIs (3 metric tiles)
    vizzes.append(viz_metric("orion-v-total",
        "HTTPS interceptados", mitm_dv))
    vizzes.append(viz_metric("orion-v-creds",
        "Con credenciales", mitm_dv, "security.has_credentials: true"))
    vizzes.append(viz_metric("orion-v-jwt",
        "Con JWT", mitm_dv, "security.has_jwt: true"))

    # KPI extra para HTTP plano (cuenta de transacciones HTTP en Packetbeat)
    vizzes.append(viz_metric("orion-v-http-plain",
        "HTTP plano (sin cifrar)", pkt_dv, "event.dataset: http"))

    # Distribuciones
    vizzes.append(viz_pie("orion-v-methods",
        "Metodos HTTP (descifrado)", mitm_dv, "http.method", size=8))
    vizzes.append(viz_pie("orion-v-status",
        "Status codes (descifrado)", mitm_dv, "http.response_status", size=8))
    vizzes.append(viz_hbar("orion-v-hosts",
        "Top dominios accedidos (HTTPS)", mitm_dv, "server.hostname", size=10))

    # Timeline
    vizzes.append(viz_timeline("orion-v-timeline-mitm",
        "Peticiones HTTPS descifradas / tiempo", mitm_dv))

    # Top URLs (mitm). size alto para mostrar mas combinaciones de hosts y paths.
    vizzes.append(viz_table("orion-v-paths",
        "Top rutas HTTPS interceptadas", mitm_dv,
        ["http.method", "server.hostname", "http.path"], size=200))

    # Trafico observado por Packetbeat. Usamos destination.domain (que Packetbeat
    # rellena desde SNI/HTTP host) en lugar de destination.ip para ver
    # "google.com" en vez de "142.250.x.y".
    vizzes.append(viz_hbar("orion-v-pkt-dst-domains",
        "Top dominios destino (Packetbeat: SNI + HTTP host)",
        pkt_dv, "destination.domain", size=15))
    vizzes.append(viz_hbar("orion-v-pkt-dns-queries",
        "Top consultas DNS (dns.question.name)",
        pkt_dv, "dns.question.name", size=15, filter_kql="event.dataset: dns"))
    vizzes.append(viz_hbar("orion-v-pkt-dst-ports",
        "Top puertos destino", pkt_dv, "destination.port", size=10))
    vizzes.append(viz_hbar("orion-v-pkt-dst-ips",
        "Top IPs destino (con IP, sin DNS resuelto)",
        pkt_dv, "destination.ip", size=10,
        filter_kql="_exists_: destination.ip AND NOT _exists_: destination.domain"))
    vizzes.append(viz_timeline("orion-v-timeline-pkt",
        "Trafico de red total (paquetes/s)", pkt_dv))

    # Crear cada visualizacion
    for v in vizzes:
        delete_if_exists("visualization", v["id"])
        r = kpost(f"/api/saved_objects/visualization/{v['id']}", {
            "attributes": v["attributes"],
            "references": v["references"],
        })
        if r.status_code in (200, 201):
            print(f"  [+] {v['attributes']['title']}")
        else:
            print(f"  [!] {v['attributes']['title']}: {r.status_code}")
            print(f"      {r.text[:300]}")

    # Dashboard
    print("[*] Construyendo dashboard...")
    # Cada tupla es (y, x, ancho, alto, viz_id). El grid de Kibana tiene 48 columnas de ancho, asi que w=24 ocupa media fila.
    layout = [
        # KPIs en fila superior
        (0,  0,  12, 6,  "orion-v-total"),
        (0, 12,  12, 6,  "orion-v-creds"),
        (0, 24,  12, 6,  "orion-v-jwt"),
        (0, 36,  12, 6,  "orion-v-http-plain"),

        # HTTPS descifrado
        (6,  0,  24, 12, "orion-v-methods"),
        (6, 24,  24, 12, "orion-v-status"),
        (18, 0,  48, 14, "orion-v-hosts"),
        (32, 0,  48, 12, "orion-v-timeline-mitm"),
        (44, 0,  48, 16, "orion-v-paths"),

        # Trafico de red Packetbeat agregado por dominio
        (60, 0,  48, 14, "orion-v-pkt-dst-domains"),
        (74, 0,  48, 14, "orion-v-pkt-dns-queries"),

        # Detalle: puertos e IPs que no tienen dominio resuelto
        (88,  0, 24, 12, "orion-v-pkt-dst-ports"),
        (88, 24, 24, 12, "orion-v-pkt-dst-ips"),
        (100, 0, 48, 12, "orion-v-timeline-pkt"),
    ]

    panels = []
    refs   = []
    for i, (y, x, w, h, vid) in enumerate(layout):
        pid = f"panel_{i}"
        panels.append({
            "version": "8.19.0",
            "type": "visualization",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
            "panelIndex": pid,
            "embeddableConfig": {"enhancements": {}},
            "panelRefName": f"panel_{i}",
        })
        # Kibana espera name="panel_N" en references; el prefijo "{i}:" era erroneo
        # y hacia que el dashboard cargara las viz como vacias ("Invalid type '").
        refs.append({"id": vid, "name": f"panel_{i}", "type": "visualization"})

    dashboard_attrs = {
        "title": DASHBOARD_TITLE,
        "description": "Trafico HTTP/HTTPS descifrado por mitmproxy mas trafico de red propio observado por Packetbeat. Generado por tools/build_kibana_dashboard.py.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({
            "useMargins": True, "syncColors": False,
            "syncCursor": True, "syncTooltips": False,
            "hidePanelTitles": False,
        }),
        "version": 1, "timeRestore": False,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"query": "", "language": "kuery"},
                "filter": [],
            }),
        },
    }

    r = kpost(f"/api/saved_objects/dashboard/{DASHBOARD_ID}", {
        "attributes": dashboard_attrs,
        "references": refs,
    })

    if r.status_code in (200, 201):
        print(f"  [+] Dashboard creado: {DASHBOARD_TITLE}")
    else:
        print(f"  [!] Error al crear dashboard 1: {r.status_code}")
        print(f"      {r.text[:500]}")
        sys.exit(1)

    # Nota: el dashboard 2 ("Flujos por dominio") se eliminó porque Packetbeat
    # solo rellena destination.domain en docs TLS/HTTP/DNS y la mayoria del
    # trafico (ARP, broadcasts...) salia vacia. La info de dominios ya esta
    # cubierta por el dashboard 1 y las pestanas DNS/TLS de Packetbeat.

    # Dashboard 3: detecciones reales (orion-alerts), no la blacklist completa.
    # Lo alimentan tools/alert_correlator.py (cruce periodico contra Packetbeat)
    # y /api/threat_intel/check_live (verificacion puntual desde la GUI).
    print("[*] Construyendo Dashboard 3 (cyberinteligencia - detecciones reales)...")
    # Buscar/crear data view orion-alerts
    threat_dv = None
    try:
        threat_dv = find_data_view_id(ALERTS_DV_TITLE)
    except SystemExit:
        print(f"  [*] Creando data view {ALERTS_DV_TITLE}...")
        r = kpost("/api/data_views/data_view", {
            "data_view": {
                "title": ALERTS_DV_TITLE,
                "name": "Detecciones de IPs maliciosas",
                "timeFieldName": "@timestamp",
            }
        })
        if r.status_code in (200, 201):
            threat_dv = r.json()["data_view"]["id"]
            print(f"  [+] Data view creado: {threat_dv}")
        else:
            print(f"  [!] No se pudo crear data view: {r.status_code} {r.text[:200]}")
            threat_dv = None

    if threat_dv:
        threat_vizzes = []

        # KPIs
        threat_vizzes.append(viz_metric("orion-t-total",
            "Detecciones (alertas indexadas)", threat_dv))
        threat_vizzes.append(viz_metric_unique("orion-t-uniq-ips",
            "IPs maliciosas unicas vistas", threat_dv, "ip"))
        threat_vizzes.append(viz_metric("orion-t-critical",
            "Detecciones criticas (>=90%)", threat_dv,
            filter_kql="abuse_confidence >= 90"))
        threat_vizzes.append(viz_metric_unique("orion-t-countries",
            "Paises origen unicos", threat_dv, "country_code"))

        # Top paises desde donde se conectan IPs maliciosas
        threat_vizzes.append(viz_hbar("orion-t-by-country",
            "Top paises de IPs maliciosas detectadas",
            threat_dv, "country_code", size=15))

        # Distribucion por tipo de deteccion (traffic vs manual_check)
        threat_vizzes.append(viz_pie("orion-t-detection-type",
            "Tipo de deteccion (trafico vs verificacion manual)",
            threat_dv, "detection_type", size=5))

        # Top IPs detectadas (con score)
        threat_vizzes.append(viz_table("orion-t-top-ips",
            "Top IPs maliciosas detectadas",
            threat_dv, ["ip", "abuse_confidence", "country_code", "detection_type"], size=50))

        # Timeline de detecciones
        threat_vizzes.append(viz_timeline("orion-t-timeline",
            "Detecciones a lo largo del tiempo", threat_dv))

        # Crear viz
        for v in threat_vizzes:
            delete_if_exists("visualization", v["id"])
            r = kpost(f"/api/saved_objects/visualization/{v['id']}", {
                "attributes": v["attributes"],
                "references": v["references"],
            })
            if r.status_code in (200, 201):
                print(f"  [+] {v['attributes']['title']}")
            else:
                print(f"  [!] {v['attributes']['title']}: {r.status_code}")

        # Layout dashboard 3
        threat_layout = [
            # KPIs
            (0,  0, 12, 6,  "orion-t-total"),
            (0, 12, 12, 6,  "orion-t-uniq-ips"),
            (0, 24, 12, 6,  "orion-t-critical"),
            (0, 36, 12, 6,  "orion-t-countries"),

            # Distribuciones
            (6,  0, 24, 14, "orion-t-by-country"),
            (6, 24, 24, 14, "orion-t-detection-type"),

            # Tabla maestra
            (20, 0, 48, 20, "orion-t-top-ips"),

            # Timeline
            (40, 0, 48, 12, "orion-t-timeline"),
        ]

        t_panels = []
        t_refs   = []
        for i, (y, x, w, h, vid) in enumerate(threat_layout):
            pid = f"panel_{i}"
            t_panels.append({
                "version": "8.19.0",
                "type": "visualization",
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                "panelIndex": pid,
                "embeddableConfig": {"enhancements": {}},
                "panelRefName": f"panel_{i}",
            })
            t_refs.append({"id": vid, "name": f"panel_{i}", "type": "visualization"})

        t_attrs = {
            "title": THREAT_DASHBOARD_TITLE,
            "description": "IPs maliciosas de AbuseIPDB con confidence score. Generado por tools/build_kibana_dashboard.py.",
            "panelsJSON": json.dumps(t_panels),
            "optionsJSON": json.dumps({
                "useMargins": True, "syncColors": False,
                "syncCursor": True, "syncTooltips": False,
                "hidePanelTitles": False,
            }),
            "version": 1, "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": [],
                }),
            },
        }

        delete_if_exists("dashboard", THREAT_DASHBOARD_ID)
        r = kpost(f"/api/saved_objects/dashboard/{THREAT_DASHBOARD_ID}", {
            "attributes": t_attrs,
            "references": t_refs,
        })
        if r.status_code in (200, 201):
            print(f"  [+] Dashboard creado: {THREAT_DASHBOARD_TITLE}")
        else:
            print(f"  [!] Error en dashboard 3: {r.status_code} {r.text[:200]}")

    print()
    print("=" * 64)
    print(" Dashboards disponibles:")
    print(f"   {KIBANA}/app/dashboards#/view/{DASHBOARD_ID}")
    print(f"   {KIBANA}/app/dashboards#/view/{THREAT_DASHBOARD_ID}")
    print(" Via la GUI de ORION:")
    print("   http://localhost:5000/dashboards")
    print("=" * 64)


if __name__ == "__main__":
    main()
