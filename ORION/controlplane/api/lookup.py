"""Endpoint de consulta de prefijos BGP / ASN para una IP.

Usado por la pestana Reglas para ofrecer "averiguar rango" cuando el
operador quiere bloquear un CIDR entero en vez de una IP suelta.

Fuente: RIPE Stat (stat.ripe.net/data/network-info/data.json), API
publica de RIPE NCC sin auth ni rate-limit estricto.

Ejemplo de respuesta:
    GET /api/lookup/ip/8.8.8.8
    {
      "ip":       "8.8.8.8",
      "prefix":   "8.8.8.0/24",
      "asn":      "15169",
      "source":   "RIPE Stat"
    }
"""

import ipaddress
import json
import urllib.parse
import urllib.request

from flask import jsonify

from controlplane.api import api_bp

RIPE_URL = "https://stat.ripe.net/data/network-info/data.json"
USER_AGENT = "ORION-TFG/1.0 (UE Madrid - inspeccion de trafico)"
TIMEOUT_SEC = 4


@api_bp.route("/lookup/ip/<ip>", methods=["GET"])
def lookup_ip(ip):
    """Devuelve el prefijo BGP y ASN al que pertenece una IP."""
    # Validacion local antes de salir a Internet
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return jsonify({"error": f"ip invalida: {ip}"}), 400

    # IPs privadas no tienen prefijo BGP publico, RIPE Stat devuelve
    # vacio. Las cortocircuitamos con un mensaje claro.
    addr = ipaddress.IPv4Address(ip)
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return jsonify({
            "ip":     ip,
            "prefix": None,
            "asn":    None,
            "source": "local",
            "note":   "IP privada/local: no tiene prefijo BGP publico",
        })

    try:
        params = urllib.parse.urlencode({"resource": ip})
        req = urllib.request.Request(
            f"{RIPE_URL}?{params}",
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as r:
            body = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return jsonify({"error": f"no se pudo consultar RIPE Stat: {e}"}), 502

    data   = body.get("data") or {}
    prefix = data.get("prefix")
    asns   = data.get("asns") or []
    asn    = asns[0] if asns else None

    return jsonify({
        "ip":     ip,
        "prefix": prefix,
        "asn":    asn,
        "source": "RIPE Stat",
    })
