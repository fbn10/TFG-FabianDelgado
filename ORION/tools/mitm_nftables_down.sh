#!/bin/bash
# Quita las reglas nftables del servicio orion-mitm-nftables.
# Llamado por systemd al parar el servicio.
nft delete table ip orion-mitm 2>/dev/null || true
echo "[+] nftables orion-mitm eliminadas"
