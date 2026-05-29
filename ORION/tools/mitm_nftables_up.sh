#!/bin/bash
# Aplica las reglas nftables que redirigen 80/443/8443 desde enp6s0f0 al
# proceso mitmproxy escuchando en :8888 (DNAT puro, sin TPROXY).
#
# Lo llama el servicio systemd orion-mitm-nftables.service al arrancar.
set -e

# 1. Modulos kernel necesarios
modprobe nf_nat        2>/dev/null || true
modprobe nf_conntrack  2>/dev/null || true

# 2. Limpieza de restos
nft delete table ip orion-mitm 2>/dev/null || true

# 3. Crear tabla y reglas REDIRECT
nft add table ip orion-mitm
nft 'add chain ip orion-mitm prerouting { type nat hook prerouting priority dstnat; policy accept; }'
nft 'add rule ip orion-mitm prerouting iifname enp6s0f0 tcp dport { 80, 443, 8443 } redirect to :8888'

# 4. Sysctls necesarios para que el redirect entregue al socket local
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/enp6s0f0/rp_filter

echo "[+] nftables orion-mitm aplicadas correctamente"
