#!/usr/bin/env bash
#
# ORION-Bank: lanzador. Verifica venv, dependencias y certificados TLS;
# arranca la app en https://0.0.0.0:8443/.
#
# Uso:
#   ./run.sh                # arranca en puerto 8443
#   ORION_BANK_PORT=9443 ./run.sh
#

set -e

cd "$(dirname "$0")"

# 1. venv: reutiliza el de ORION si existe, si no crea uno local
VENV="../../venv"
if [ ! -d "$VENV" ]; then
    VENV="./venv"
    if [ ! -d "$VENV" ]; then
        echo "[*] Creando venv local..."
        python3 -m venv "$VENV"
    fi
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

# 2. dependencias
python3 -c "import flask, jwt" 2>/dev/null || {
    echo "[*] Instalando dependencias (Flask, PyJWT)..."
    pip install -q -r requirements.txt
}

# 3. certificado TLS auto-firmado (se genera una vez)
CERT_DIR="./certs"
CA_KEY="$CERT_DIR/orion-bank-ca.key"
CA_CRT="$CERT_DIR/orion-bank-ca.crt"
CERT="$CERT_DIR/server.crt"
KEY="$CERT_DIR/server.key"

mkdir -p "$CERT_DIR"

# CA raiz local: se genera una vez, se instala en el navegador del cliente como Autoridad de confianza; cualquier cert firmado por ella sera valido sin warnings
if [ ! -f "$CA_CRT" ] || [ ! -f "$CA_KEY" ]; then
    echo "[*] Generando CA raiz local ORION-Bank-CA..."
    openssl genrsa -out "$CA_KEY" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
        -subj "/C=ES/ST=Madrid/L=Madrid/O=ORION-Bank-Demo/CN=ORION-Bank Demo Root CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$CA_CRT" 2>/dev/null
    chmod 600 "$CA_KEY"
    echo "[+] CA raiz generada en $CA_CRT (valida 10 anos)"
fi

# Cert servidor firmado por la CA: si lo borras, se regenera con la misma CA y el cliente sigue confiando sin reinstalar nada
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "[*] Generando cert servidor firmado por ORION-Bank-CA..."
    openssl genrsa -out "$KEY" 2048 2>/dev/null

    openssl req -new -key "$KEY" \
        -subj "/C=ES/ST=Madrid/L=Madrid/O=ORION-Bank-Demo/CN=demo-orion.local" \
        -out "$CERT_DIR/server.csr" 2>/dev/null

    cat > "$CERT_DIR/server.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:demo-orion.local,DNS:orion-bank.local,DNS:localhost,IP:127.0.0.1,IP:10.0.2.1,IP:192.168.68.51,IP:192.168.68.52
EOF

    openssl x509 -req -in "$CERT_DIR/server.csr" \
        -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
        -days 365 -sha256 \
        -extfile "$CERT_DIR/server.ext" \
        -out "$CERT" 2>/dev/null

    chmod 600 "$KEY"
    rm -f "$CERT_DIR/server.csr" "$CERT_DIR/server.ext"

    echo "[+] Cert servidor firmado por la CA: $CERT"
    echo "[+] Fingerprint CA:"
    openssl x509 -in "$CA_CRT" -noout -fingerprint -sha256 | sed 's/^/    /'
fi

# 4. arrancar
PORT="${ORION_BANK_PORT:-8443}"

echo ""
echo "============================================================"
echo " ORION-Bank arrancando en https://0.0.0.0:${PORT}/"
echo "------------------------------------------------------------"
echo " Local:        https://localhost:${PORT}/"
echo " Desde LAN:    https://<IP-de-ORION>:${PORT}/"
echo " Credenciales: fabian / Fabian1234"
echo "                admin / admin123"
echo "                demo / demo"
echo "============================================================"
echo ""

exec env \
    ORION_BANK_CERT="$CERT" \
    ORION_BANK_KEY="$KEY" \
    ORION_BANK_PORT="$PORT" \
    python3 app.py
