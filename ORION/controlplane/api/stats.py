"""Endpoints de estadisticas que la UI consume.

Hacen de proxy entre el navegador y Elasticsearch para evitar problemas
de CORS y centralizar la logica de consulta.
"""

import subprocess

from flask import jsonify

from controlplane.api import api_bp
from controlplane.es_client import get_es


def _safe_count(index: str) -> int:
    """Devuelve count del indice, 0 si no existe o falla."""
    try:
        es = get_es()
        return es.count(index=index).get("count", 0)
    except Exception:
        return 0


def _check_xdp_attached() -> dict:
    """Verifica si hay un programa XDP atachado en alguna interfaz de ORION.

    Lee `ip link show <iface>` por cada interfaz (la version 'brief' con -br
    no muestra los markers de XDP, solo el formato completo lo hace).
    Devuelve un dict con el estado por interfaz y un boolean global.
    """
    interfaces = ("eno1", "enp6s0f0", "enp6s0f1")
    status = {}
    any_attached = False
    for iface in interfaces:
        try:
            result = subprocess.run(
                ["ip", "link", "show", iface],
                capture_output=True, text=True, timeout=2
            )
            # "xdp" o "xdpgeneric" en la primera linea cuando esta atachado
            has_xdp = "xdp" in result.stdout.lower()
            status[iface] = has_xdp
            if has_xdp:
                any_attached = True
        except Exception:
            status[iface] = False
    return {"any_attached": any_attached, "by_interface": status}


@api_bp.route("/stats/summary", methods=["GET"])
def stats_summary():
    """Resumen de contadores para el dashboard de inicio."""
    es = get_es()

    # Reglas activas
    try:
        res = es.count(index="orion-rules", query={"term": {"enabled": True}})
        rules_active = res.get("count", 0)
    except Exception:
        rules_active = 0

    return jsonify({
        "rules_active": rules_active,
        "nat_mappings": _safe_count("orion-nat-mappings"),
        "packetbeat_total": _safe_count("packetbeat-*"),
        "rules_history": _safe_count("orion-rules-history"),
        "xdp": _check_xdp_attached(),
    })
