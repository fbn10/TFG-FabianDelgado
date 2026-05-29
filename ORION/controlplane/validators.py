"""Validacion de reglas antes de indexarlas en Elasticsearch.

Modelo de regla unificada: cada regla puede combinar varios criterios
(IP origen/destino, protocolo, puertos, rate-limit). Los criterios no
especificados actuan como wildcard. Una regla aplica si TODOS los
criterios presentes coinciden con el paquete.
"""

import ipaddress

# Interfaces validas: las del proyecto en el orden esperado por el loader
VALID_IFACES = {"enp6s0f0", "eno1", "enp6s0f1"}

# Protocolos soportados a nivel L3/L4
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "any"}

VALID_ACTIONS = {"allow", "drop"}


def _opt_str(d: dict, key: str) -> str | None:
    """Devuelve d[key] como string limpio o None si no esta o esta vacio."""
    v = d.get(key)
    if v is None:
        return None
    if isinstance(v, str):
        v = v.strip()
        return v or None
    return str(v)


def _opt_int(d: dict, key: str, lo: int | None = None, hi: int | None = None) -> int | None:
    """Devuelve d[key] como int validando rango. None si no esta presente."""
    v = d.get(key)
    if v is None or v == "":
        return None
    try:
        n = int(v)
    except (ValueError, TypeError):
        raise ValueError(f"{key} debe ser entero, recibido: {v!r}")
    if lo is not None and n < lo:
        raise ValueError(f"{key} debe ser >= {lo}, recibido: {n}")
    if hi is not None and n > hi:
        raise ValueError(f"{key} debe ser <= {hi}, recibido: {n}")
    return n


def _validate_ipv4(value: str, label: str) -> str:
    """Lanza ValueError si value no es una IPv4 valida."""
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError(f"{label} '{value}' no es una IPv4 valida")
    return value


def _validate_ipv4_or_cidr(value: str, label: str) -> str:
    """Acepta tanto IPv4 individual ('1.2.3.4') como CIDR ('1.2.3.0/24').

    Si es CIDR, valida que el prefijo este en [0,32] y normaliza la
    direccion de red (no permite host bits puestos: '1.2.3.5/24' se
    canonicaliza a '1.2.3.0/24' para que el LPM Trie matchee bien).
    """
    if "/" in value:
        try:
            net = ipaddress.IPv4Network(value, strict=False)
        except ValueError:
            raise ValueError(f"{label} '{value}' no es un CIDR IPv4 valido")
        return str(net)   # canonicalizado: '1.2.3.5/24' -> '1.2.3.0/24'
    # IP individual
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError(f"{label} '{value}' no es una IPv4 ni CIDR valido")
    return value


def validate_rule(data: dict) -> dict:
    """Valida un dict que representa una regla.

    Devuelve el dict ya saneado con todos los campos relevantes (los
    opcionales que no esten en el payload se incluyen como None).
    Lanza ValueError si algo no encaja.
    """
    if not isinstance(data, dict):
        raise ValueError("payload debe ser un objeto JSON")

    # iface obligatoria
    iface = _opt_str(data, "iface")
    if iface not in VALID_IFACES:
        raise ValueError(
            f"iface invalida. Permitidas: {sorted(VALID_IFACES)}"
        )

    # action obligatoria
    action = _opt_str(data, "action")
    if action not in VALID_ACTIONS:
        raise ValueError(
            f"action invalida. Permitidas: {sorted(VALID_ACTIONS)}"
        )

    # protocolo opcional, default 'any'
    protocol = (_opt_str(data, "protocol") or "any").lower()
    if protocol not in VALID_PROTOCOLS:
        raise ValueError(
            f"protocol invalido. Permitidos: {sorted(VALID_PROTOCOLS)}"
        )

    # IPs opcionales: aceptamos IP individual ('1.2.3.4') o CIDR ('1.2.3.0/24').
    # En el caso CIDR se canonicaliza al network base.
    source_ip = _opt_str(data, "source_ip")
    if source_ip:
        source_ip = _validate_ipv4_or_cidr(source_ip, "source_ip")
    dest_ip = _opt_str(data, "dest_ip")
    if dest_ip:
        dest_ip = _validate_ipv4_or_cidr(dest_ip, "dest_ip")

    # Puertos opcionales (1-65535). Un puerto solo existe en la capa L4
    # (TCP/UDP). Si se especifica un puerto sin protocolo concreto (o con
    # 'any'), asumimos TCP: es el caso abrumadoramente comun al filtrar
    # servicios (SSH 22, HTTP 80, HTTPS 443, RDP 3389...). Para filtrar un
    # puerto UDP (p.ej. DNS 53) hay que elegir UDP explicitamente. Para
    # cubrir TCP y UDP del mismo puerto se crean dos reglas separadas.
    source_port = _opt_int(data, "source_port", 1, 65535)
    dest_port = _opt_int(data, "dest_port", 1, 65535)
    if source_port is not None or dest_port is not None:
        if protocol == "any":
            protocol = "tcp"
        elif protocol == "icmp":
            raise ValueError("ICMP no tiene puertos; usa TCP o UDP")

    # Limits opcionales (>0 si se especifican)
    limit_pps = _opt_int(data, "limit_pps", 1)
    limit_bps = _opt_int(data, "limit_bps", 1)

    # Prioridad opcional, default 100. Menor valor = se evalua antes.
    priority = _opt_int(data, "priority", 0, 1_000_000) or 100

    # Coherencia: una regla tiene que tener al menos un criterio.
    # Si no, seria "matchea todo lo que entra a esta iface" y deberia
    # gestionarse como politica por defecto, no como regla individual.
    has_criteria = any([
        source_ip, dest_ip,
        protocol != "any",
        source_port is not None, dest_port is not None,
        limit_pps is not None, limit_bps is not None,
    ])
    if not has_criteria:
        raise ValueError(
            "la regla debe tener al menos un criterio "
            "(source_ip, dest_ip, protocol, puerto o rate-limit)"
        )

    out = {
        "name": _opt_str(data, "name") or "",
        "iface": iface,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "protocol": protocol,
        "source_port": source_port,
        "dest_port": dest_port,
        "limit_pps": limit_pps,
        "limit_bps": limit_bps,
        "action": action,
        "priority": priority,
        "comment": _opt_str(data, "comment") or "",
        "created_by": _opt_str(data, "created_by") or "api",
    }

    # Campos opcionales para reglas auto-generadas por el WAF de mitmproxy.
    # Si vienen, se conservan en el doc de orion-rules para que el expirer
    # y la pestana "Bloqueos auto" puedan recuperarlas.
    auto_blocked = bool(data.get("auto_blocked"))
    if auto_blocked:
        out["auto_blocked"] = True
        out["expires_at"]   = _opt_str(data, "expires_at")
        out["reason"]       = _opt_str(data, "reason") or ""
        out["alert_type"]   = _opt_str(data, "alert_type") or ""
        out["source"]       = _opt_str(data, "source") or "waf-mitm"

    return out
