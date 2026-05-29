"""Cargador minimo de XDP. Cuenta paquetes entrantes en una interfaz.

Sirve para validar que BCC compila y carga programas eBPF en esta maquina,
antes de pasar al programa real con filtrado y NAT.

Uso (necesita sudo):
    sudo -E python3 tools/xdp_counter.py
"""

from bcc import BPF
import ctypes as ct
import time
import os
import sys

INTERFACE = "enp6s0f0"

# Compilar y cargar el programa eBPF
b = BPF(src_file="ebpf/counter.c")

# Obtener la funcion XDP del programa compilado
fn = b.load_func("xdp_counter", BPF.XDP)

# Atacharla a la interfaz fisica
b.attach_xdp(INTERFACE, fn, 0)
print(f"XDP cargado en {INTERFACE}. Genera trafico (ping 10.0.2.1) desde el cliente.")
print("Ctrl+C para parar y desatachar.")

key = ct.c_uint(0)
try:
    while True:
        time.sleep(1)
        try:
            count = b["packet_count"][key].value
        except KeyError:
            count = 0
        print(f"\rPaquetes vistos por XDP: {count}", end="", flush=True)
except KeyboardInterrupt:
    print("\nQuitando XDP de la interfaz...")
    b.remove_xdp(INTERFACE, 0)
    print("Listo.")
