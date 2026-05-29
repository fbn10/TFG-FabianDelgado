#!/usr/bin/env python3
"""Consumer del BPF_RINGBUF de orion_xdp_redirect.

Lee eventos kernel->user-space emitidos por el XDP cuando hace REDIRECT y
los indexa en Elasticsearch (indice 'orion-flows'). Soluciona la perdida
de visibilidad del modo Rendimiento (XDP_REDIRECT bypassa el stack y por
tanto Packetbeat/AF_PACKET no ve el trafico).

Este script NO carga el XDP. Asume que xdp_nat_redirect.py ya lo tiene
cargado y el mapa 'flow_events' existe en el kernel. Lo localiza por
nombre (BPF_OBJ_GET via bpftool) y abre el ring.

Diseno:
  - Bulk a ES cada FLUSH_EVERY eventos o FLUSH_INTERVAL segundos.
  - Reporta cada PRINT_STATS_INTERVAL segundos: eventos procesados +
    eventos perdidos por overflow del ring (suma de ringbuf_lost en
    todas las CPUs).
  - Si ES no responde, encola hasta MAX_QUEUE y descarta los mas viejos.

Ejecucion:
    sudo -E python3 tools/flow_consumer.py
"""

import ctypes as ct
import socket
import sys
import time
from datetime import datetime, timezone

from bcc import BPF
from elasticsearch import Elasticsearch, helpers


# Configuracion
ES_URL              = "http://localhost:9200"
ES_INDEX            = "orion-flows"
FLUSH_EVERY         = 200    # n eventos antes de hacer bulk a ES
FLUSH_INTERVAL      = 2.0    # o segundos antes de bulk si no llega el N
POLL_TIMEOUT_MS     = 100    # cuanto bloquea cada llamada a ring_buffer_poll
PRINT_STATS_INTERVAL = 10.0  # cuantos seg entre cada log de "X eventos, Y perdidos"
MAX_QUEUE           = 5000   # tope antes de empezar a descartar


# Mapeo del struct flow_event (definido en ebpf/orion_xdp_redirect.c; cualquier cambio de orden o tamano en C tiene que reflejarse aqui)
class FlowEvent(ct.Structure):
    _fields_ = [
        ("ts_ns",       ct.c_uint64),
        ("saddr_orig",  ct.c_uint32),
        ("daddr_orig",  ct.c_uint32),
        ("saddr_post",  ct.c_uint32),
        ("daddr_post",  ct.c_uint32),
        ("sport",       ct.c_uint16),
        ("dport",       ct.c_uint16),
        ("proto",       ct.c_uint8),
        ("iface_idx",   ct.c_uint8),
        ("action",      ct.c_uint8),
        ("_pad",        ct.c_uint8),
        ("pkt_len",     ct.c_uint32),
    ]


IFACE_NAMES = {0: "enp6s0f0", 1: "eno1", 2: "enp6s0f1"}
PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}
ACTION_NAMES = {0: "PASS", 1: "DROP", 2: "REDIRECT"}


def be32_to_ip(be32_val: int) -> str:
    """Convierte un __be32 (en memoria) a 'a.b.c.d'."""
    return socket.inet_ntoa(ct.c_uint32(be32_val).value.to_bytes(4, "little"))


def be16_to_port(be16_val: int) -> int:
    """Convierte un __be16 a entero host."""
    return socket.ntohs(ct.c_uint16(be16_val).value)


# Buffer en memoria + flush a ES
class Sink:
    def __init__(self, es_url: str, index: str):
        self.es = Elasticsearch(es_url, request_timeout=5)
        self.index = index
        self.buffer = []
        self.last_flush = time.monotonic()
        self.total_indexed = 0
        self.dropped_overflow = 0

    def append(self, doc: dict):
        if len(self.buffer) >= MAX_QUEUE:
            # ES no responde, descartar el mas viejo
            self.buffer.pop(0)
            self.dropped_overflow += 1
        self.buffer.append(doc)
        if len(self.buffer) >= FLUSH_EVERY:
            self.flush()

    def maybe_flush(self):
        if self.buffer and (time.monotonic() - self.last_flush) >= FLUSH_INTERVAL:
            self.flush()

    def flush(self):
        if not self.buffer:
            return
        try:
            actions = [{"_index": self.index, "_source": d} for d in self.buffer]
            ok, errs = helpers.bulk(self.es, actions, raise_on_error=False)
            self.total_indexed += ok
        except Exception as e:
            print(f"[flow_consumer] error indexando {len(self.buffer)} docs: {e}",
                  file=sys.stderr)
        finally:
            self.buffer.clear()
            self.last_flush = time.monotonic()


# Cargar el programa XDP existente para acceder al mapa flow_events (BCC no expone abrir un map por pinned-name desde Python; recompilamos el .c, BCC lo cachea, y NO atachamos el programa: solo queremos el handle del objeto BPF)
print("Cargando programa XDP (solo para acceder al ring buffer)...")
b = BPF(src_file="ebpf/orion_xdp_redirect.c")


def on_event(cpu, data, size):
    ev = ct.cast(data, ct.POINTER(FlowEvent)).contents
    iso_ts = datetime.now(timezone.utc).isoformat()
    doc = {
        "@timestamp":  iso_ts,
        "ts_ns":       ev.ts_ns,
        "src_orig":    be32_to_ip(ev.saddr_orig),
        "dst_orig":    be32_to_ip(ev.daddr_orig),
        "src_post":    be32_to_ip(ev.saddr_post),
        "dst_post":    be32_to_ip(ev.daddr_post),
        "sport":       be16_to_port(ev.sport),
        "dport":       be16_to_port(ev.dport),
        "proto":       PROTO_NAMES.get(ev.proto, str(ev.proto)),
        "proto_num":   ev.proto,
        "iface":       IFACE_NAMES.get(ev.iface_idx, f"idx={ev.iface_idx}"),
        "action":      ACTION_NAMES.get(ev.action, str(ev.action)),
        "pkt_len":     ev.pkt_len,
        "natted":      ev.saddr_orig != ev.saddr_post or ev.daddr_orig != ev.daddr_post,
    }
    sink.append(doc)


def get_lost_count() -> int:
    """Suma los contadores PERCPU de ringbuf_lost."""
    try:
        arr = b["ringbuf_lost"]
        total = 0
        for v in arr[0]:  # PERCPU: iteramos todos los cores
            total += v
        return total
    except Exception:
        return 0


# Bucle principal
sink = Sink(ES_URL, ES_INDEX)
b["flow_events"].open_ring_buffer(on_event)

print(f"Consumer arrancado. Indexando en '{ES_INDEX}' cada {FLUSH_EVERY} eventos o {FLUSH_INTERVAL}s.")
print(f"Ctrl+C para parar.")

last_stats = time.monotonic()
last_lost = 0
try:
    while True:
        # Bloquea hasta POLL_TIMEOUT_MS o hasta que haya eventos.
        # Por cada evento se llama on_event() que llena el buffer.
        b.ring_buffer_poll(POLL_TIMEOUT_MS)

        # Flush periodico aunque no se llegue a FLUSH_EVERY
        sink.maybe_flush()

        # Log de stats cada 10s
        now = time.monotonic()
        if now - last_stats >= PRINT_STATS_INTERVAL:
            lost = get_lost_count()
            delta_lost = lost - last_lost
            last_lost = lost
            print(f"[flow_consumer] indexed={sink.total_indexed} "
                  f"queued={len(sink.buffer)} "
                  f"dropped_overflow={sink.dropped_overflow} "
                  f"ringbuf_lost_total={lost} (+{delta_lost} en {PRINT_STATS_INTERVAL}s)")
            last_stats = now

except KeyboardInterrupt:
    print("\nFlush final antes de salir...")
    sink.flush()
    print(f"Total indexado: {sink.total_indexed}")
    print(f"Ringbuf lost total: {get_lost_count()}")
