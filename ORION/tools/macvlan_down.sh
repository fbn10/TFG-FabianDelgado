#!/bin/bash
# Solo quita el policy routing y sysctls. NO borra la interfaz, por si la
# quieres mantener viva para inspeccion manual.
IFACE="eno1.cliA"
EXT_IP="192.168.68.52"

ip rule del from "$EXT_IP" lookup 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true

echo "[+] Policy routing eliminado. La interfaz $IFACE sigue arriba."
