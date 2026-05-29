#!/bin/bash
# Idempotente y dinamico:
# - Si eno1.cliA no existe, la crea + pide DHCP.
# - Lee la IP real que el DHCP le dio (puede ser .52, .55, .57... lo que Fortinet quiera).
# - Aplica policy routing usando esa IP dinamica.
set -e

IFACE="eno1.cliA"
PARENT="eno1"
MAC="02:11:22:33:44:01"
GW="192.168.68.1"
NAT_INDEX="orion-nat-mappings"
NAT_DOC_ID="cliente-a"

# 1. Asegurar interfaz
if ! ip link show "$IFACE" &>/dev/null; then
    echo "[*] Creando $IFACE..."
    ip link add "$IFACE" link "$PARENT" address "$MAC" type macvlan mode bridge
fi
ip link set "$IFACE" up

# 2. Asegurar IP via DHCP. Si ya tiene, no la toca.
if ! ip -4 addr show "$IFACE" | grep -q "inet "; then
    echo "[*] La interfaz no tiene IP, pidiendo DHCP..."
    dhclient -v "$IFACE" || true
fi

# 3. Leer la IP REAL que el DHCP ha asignado (dinamica)
EXT_IP=$(ip -4 -o addr show "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -1)
if [ -z "$EXT_IP" ]; then
    echo "[!] No se pudo obtener IP de $IFACE. Abortando."
    exit 1
fi
echo "[+] IP externa de la macvlan: $EXT_IP"

# 4. Quitar la default que dhclient haya metido en la tabla principal
ip route del default dev "$IFACE" 2>/dev/null || true

# 5. Sysctls
echo 2 > "/proc/sys/net/ipv4/conf/$IFACE/rp_filter"
echo 2 > "/proc/sys/net/ipv4/conf/$IFACE/arp_announce"
echo 1 > "/proc/sys/net/ipv4/conf/$IFACE/arp_ignore"

# 6. Policy routing tabla 100 con la IP dinamica
ip rule list | grep -E "lookup 100$" | awk '{print $3}' | while read src; do
    ip rule del from "$src" lookup 100 2>/dev/null || true
done
ip route flush table 100 2>/dev/null || true
ip route add default via "$GW" dev "$IFACE" src "$EXT_IP" table 100
ip rule add from "$EXT_IP" lookup 100

# 7. Actualizar el mapping en Elasticsearch si esta disponible
#    (no-op si ES esta caido, no rompemos el service por esto)
if curl -s -o /dev/null -w "%{http_code}" http://localhost:9200/ 2>/dev/null | grep -q "^200$"; then
    curl -s -X POST "http://localhost:9200/$NAT_INDEX/_update/$NAT_DOC_ID" \
        -H "Content-Type: application/json" \
        -d "{\"doc\":{\"external_ip\":\"$EXT_IP\",\"updated_at\":\"$(date -Iseconds)\"}}" > /dev/null
    echo "[+] Mapping ES actualizado: cliente-a -> $EXT_IP"
fi

# 8. Gratuitous ARP
arping -U -I "$IFACE" -c 3 "$EXT_IP" 2>/dev/null || true

echo "[+] $IFACE lista en $EXT_IP, policy routing aplicado"
