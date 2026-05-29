"""Cargador del programa XDP de ORION en MODO RENDIMIENTO (NAT + REDIRECT).

Variante de xdp_nat.py que carga orion_xdp_redirect.c en lugar del .c
con XDP_PASS. La diferencia: tras NAT, emite el paquete por la NIC destino
con bpf_redirect (bypasea stack del kernel) -> ~10x mas pps.

TRADE-OFF: Packetbeat (AF_PACKET) y mitmproxy (netfilter) dejan de ver el
trafico de los flujos NAT. Para recuperar visibilidad, arrancar en paralelo:
    sudo -E python3 tools/flow_consumer.py
que consume el ring buffer del XDP e indexa en ES (orion-flows).

Uso (mata el otro loader si esta vivo - solo un XDP por NIC):
    sudo pkill -f xdp_nat.py
    sudo -E python3 tools/xdp_nat_redirect.py
"""

from bcc import BPF
from elasticsearch import Elasticsearch
import ctypes as ct
import socket
import time
import sys
import signal


# Indices logicos -> nombre de iface. El orden importa: cuadra con
# iface_indexes[] en orion_xdp.c (0=interna, 1=externa, 2=trex).
INTERFACES = ["enp6s0f0", "eno1", "enp6s0f1"]

ES_URL              = "http://localhost:9200"
ES_NAT_INDEX        = "orion-nat-mappings"
ES_RULES_INDEX      = "orion-rules"
RULES_REFRESH_SEC   = 5
MAX_RULES           = 16

# Mapeo iface -> indice logico
IFACE_TO_IDX = {name: idx for idx, name in enumerate(INTERFACES)}

# Mapeo de protocolo (texto -> numero IP)
PROTO_TO_NUM = {
    "any":  0,
    "icmp": socket.IPPROTO_ICMP,
    "tcp":  socket.IPPROTO_TCP,
    "udp":  socket.IPPROTO_UDP,
}


def ip_str_to_key(ip_str: str) -> int:
    """Convierte '10.0.2.10' al u32 que usa eBPF como clave (network order)."""
    return int.from_bytes(socket.inet_aton(ip_str), byteorder="little")


def port_to_be(port: int) -> int:
    """Convierte un puerto en host order al be16 que ve eBPF en el paquete."""
    # bytes en network order (BE) -> entero leido en LE para que coincida byte
    # a byte con la memoria que ve el verificador del kernel
    return int.from_bytes(port.to_bytes(2, byteorder="big"), byteorder="little")


def fetch_active_nat_mappings(es: Elasticsearch) -> list:
    """Devuelve la lista de mappings con enabled=true."""
    res = es.search(
        index=ES_NAT_INDEX,
        query={"term": {"enabled": True}},
        size=256,
    )
    return [hit["_source"] for hit in res["hits"]["hits"]]


def fetch_active_rules(es: Elasticsearch) -> list:
    """Devuelve la lista de reglas con enabled=true, ordenadas por prioridad ASC."""
    try:
        res = es.search(
            index=ES_RULES_INDEX,
            query={"term": {"enabled": True}},
            size=MAX_RULES,
            sort=[{"priority": {"order": "asc"}}, {"created_at": {"order": "asc"}}],
        )
        return [hit["_source"] for hit in res["hits"]["hits"]]
    except Exception as e:
        # Si el indice no existe todavia o el campo no tiene mapping, no
        # rompemos: devolvemos vacio y se reintenta en el siguiente tick.
        print(f"  WARN al leer reglas: {e}")
        return []


def _is_cidr(value: str) -> bool:
    """True si la cadena tiene notacion CIDR (contiene /)."""
    return isinstance(value, str) and "/" in value


def fill_cidr_map(b: BPF, rules_data: list) -> int:
    """Vuelca las reglas con source_ip en notacion CIDR al BPF_LPM_TRIE
    'blocked_cidrs'. Cualquier paquete con saddr dentro de uno de esos
    rangos se dropea de forma global, sin pasar por el bucle de reglas.

    Antes de poblar, vacia el mapa para que reflejar borrados es trivial
    (las claves que ya no estan dejan de existir).
    """
    cidr_map = b["blocked_cidrs"]
    Key = cidr_map.Key   # struct cidr_key

    # Limpiar entradas viejas (no hay clear() directo en LPM_TRIE: iterar).
    for k in list(cidr_map.keys()):
        del cidr_map[k]

    count = 0
    for data in rules_data:
        src = data.get("source_ip")
        if not _is_cidr(src):
            continue
        try:
            net_str, prefix_str = src.split("/", 1)
            prefix = int(prefix_str)
            if prefix < 0 or prefix > 32:
                continue
            octets = socket.inet_aton(net_str)
        except (ValueError, OSError):
            continue

        k = Key()
        k.prefixlen = prefix
        for i, octet in enumerate(octets):
            k.ip[i] = octet
        cidr_map[k] = ct.c_ubyte(1)
        count += 1

    return count


def fill_rules_map(b: BPF, rules_data: list) -> int:
    """Vuelca las reglas con source_ip individual (sin CIDR) al BPF_ARRAY
    'rules'. Las que tienen CIDR se procesan en fill_cidr_map().

    Las posiciones no usadas se llenan con enabled=0 para que el bucle de
    eBPF las ignore. Devuelve el numero de reglas activas cargadas.
    """
    rules_map = b["rules"]
    Rule = rules_map.Leaf  # ctypes Structure inferida de orion_xdp.c

    # Filtrar fuera las reglas CIDR (van en blocked_cidrs, no en rules).
    rules_data = [r for r in rules_data if not _is_cidr(r.get("source_ip"))]

    count = 0
    for i in range(MAX_RULES):
        r = Rule()  # ceros por defecto

        if i < len(rules_data):
            data = rules_data[i]
            iface_idx = IFACE_TO_IDX.get(data.get("iface"))
            if iface_idx is None:
                # Iface invalida en ES: marcamos disabled
                r.enabled = 0
            else:
                r.enabled    = 1
                r.iface_idx  = iface_idx
                r.protocol   = PROTO_TO_NUM.get((data.get("protocol") or "any").lower(), 0)
                r.action     = 1 if data.get("action") == "drop" else 0
                r.priority   = int(data.get("priority") or 100)

                src_ip = data.get("source_ip")
                dst_ip = data.get("dest_ip")
                if src_ip:
                    r.has_src_ip = 1
                    r.src_ip     = ip_str_to_key(src_ip)
                if dst_ip:
                    r.has_dst_ip = 1
                    r.dst_ip     = ip_str_to_key(dst_ip)

                src_port = data.get("source_port")
                dst_port = data.get("dest_port")
                if src_port:
                    r.has_src_port = 1
                    r.src_port     = port_to_be(int(src_port))
                if dst_port:
                    r.has_dst_port = 1
                    r.dst_port     = port_to_be(int(dst_port))

                r.limit_pps = int(data.get("limit_pps") or 0)
                r.limit_bps = int(data.get("limit_bps") or 0)
                count += 1
        else:
            r.enabled = 0

        rules_map[ct.c_uint(i)] = r

    return count


def fill_nat_maps(b: BPF, mappings: list):
    """Pobla nat_in2out / nat_out2in desde la lista de mapeos."""
    nat_in2out = b["nat_in2out"]
    nat_out2in = b["nat_out2in"]
    for m in mappings:
        ik = ct.c_uint(ip_str_to_key(m["internal_ip"]))
        ek = ct.c_uint(ip_str_to_key(m["external_ip"]))
        nat_in2out[ik] = ek
        nat_out2in[ek] = ik


def fill_iface_indexes(b: BPF):
    """Pobla iface_indexes con el ifindex real de cada iface logica."""
    iface_indexes = b["iface_indexes"]
    for i, iface in enumerate(INTERFACES):
        try:
            ifindex = socket.if_nametoindex(iface)
            iface_indexes[ct.c_uint(i)] = ct.c_uint(ifindex)
            print(f"  iface_indexes[{i}] = {ifindex}  ({iface})")
        except OSError:
            # Iface no presente: skip. eBPF ignorara ese indice.
            print(f"  iface_indexes[{i}]: '{iface}' no existe, ignorada")


# Arranque
print(f"Conectando a Elasticsearch en {ES_URL}...")
es = Elasticsearch(ES_URL)

mappings = fetch_active_nat_mappings(es)
if not mappings:
    print(f"ERROR: no hay mappings activos en {ES_NAT_INDEX}.")
    sys.exit(1)

print(f"Cargados {len(mappings)} mappings desde {ES_NAT_INDEX}:")
for m in mappings:
    print(f"  {m['internal_ip']:15} <-> {m['external_ip']:15}  ({m.get('client_label', '')})")


# Compilar y atachar
print("\nCompilando programa XDP (modo RENDIMIENTO: NAT + REDIRECT + ringbuf)...")
b = BPF(src_file="ebpf/orion_xdp_redirect.c")
fn = b.load_func("xdp_nat", BPF.XDP)

print("Atachando a interfaces...")
attached_ifaces = []
for iface in INTERFACES:
    try:
        b.attach_xdp(iface, fn, 0)
        attached_ifaces.append(iface)
        print(f"  XDP enganchado en {iface}")
    except Exception as e:
        print(f"  WARN no se pudo enganchar a {iface}: {e}")


# Rellenar mapas iniciales
fill_iface_indexes(b)
fill_nat_maps(b, mappings)
print(f"\n{len(mappings)} mappings cargados.")

initial_rules = fetch_active_rules(es)
active_rules  = fill_rules_map(b, initial_rules)
active_cidrs  = fill_cidr_map(b,  initial_rules)
print(f"{active_rules} reglas IP individuales cargadas.")
print(f"{active_cidrs} reglas CIDR (rangos) cargadas.")

print(f"\nXDP activo en MODO RENDIMIENTO (NAT + REDIRECT + ringbuf).")
print(f"  Refresco de reglas cada {RULES_REFRESH_SEC}s. Ctrl+C para parar.")
print(f"\n*** Para indexar el trafico redirigido en ES, arranca en otra terminal:")
print(f"      sudo -E python3 tools/flow_consumer.py")
print()


# Bucle principal: cada RULES_REFRESH_SEC vuelve a leer reglas y CIDRs de ES
# y reescribe los mapas BPF; el XDP queda atachado todo el tiempo.
stopped = False

def _stop(signum, frame):
    global stopped
    stopped = True

signal.signal(signal.SIGINT,  _stop)
signal.signal(signal.SIGTERM, _stop)

try:
    while not stopped:
        time.sleep(RULES_REFRESH_SEC)
        if stopped:
            break
        new_rules = fetch_active_rules(es)
        n = fill_rules_map(b, new_rules)
        c = fill_cidr_map(b,  new_rules)
        if n != active_rules:
            print(f"  reglas IP individuales: {active_rules} -> {n}")
            active_rules = n
        if c != active_cidrs:
            print(f"  reglas CIDR (rangos):    {active_cidrs} -> {c}")
            active_cidrs = c
finally:
    print("\nDesatachando XDP...")
    for iface in attached_ifaces:
        try:
            b.remove_xdp(iface, 0)
            print(f"  removido de {iface}")
        except Exception as e:
            print(f"  WARN al remover de {iface}: {e}")
    print("Limpio.")
