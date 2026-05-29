# ORION-Bank — Banco ficticio para demo TFG

Aplicacion web HTTPS desarrollada como **target** para demostrar la
interceptacion de trafico cifrado por el sistema ORION + mitmproxy.

**No es un banco real.** Datos ficticios, credenciales hardcoded,
unicamente uso pedagogico.

## Que demuestra

Sirve para enseñar — en una unica sesion — todos los tipos de contenido
HTTPS que ORION puede interceptar:

| Endpoint | Tipo capturable en mitmproxy |
|---|---|
| `POST /login` | Credenciales en form-data |
| `POST /api/login` | Credenciales en JSON |
| `GET /dashboard` | HTML autenticado (cookie JWT) |
| `GET /api/saldo` | JSON con saldo + IBAN |
| `GET /api/movimientos` | JSON con transacciones |
| `POST /api/transferencia` | JSON sensible (importe + IBAN destino) |
| `GET /comprobante.pdf` | Descarga binaria PDF |

Todos los endpoints autenticados usan **JWT firmado HS256** que viaja en
la cabecera `Authorization: Bearer ...` (o en la cookie `orion_bank_token`).
mitmproxy captura el token, lo decodifica y muestra el payload en claro.

## Arquitectura de la demo

```
Cliente PC (192.168.68.X)
    │
    │  HTTPS GET https://demo-orion.local:8443/...
    │  (CA de mitmproxy confiada por el cliente)
    │
    ▼
ORION
  ├── XDP NAT 1-a-1: SNAT src cliente -> 192.168.68.52
  ├── TPROXY        : redirige a mitmproxy :8080
  ├── mitmproxy     : descifra TLS, log de contenido, re-cifra
  └── ORION-Bank    : Flask + TLS auto-firmado en :8443
```

Las dos sesiones TLS (Cliente↔mitm y mitm↔Bank) son **reales y cifradas**.
Solo el proceso mitmproxy ve el plaintext.

## Arranque rapido

```bash
cd ORION/demo/orion_bank
chmod +x run.sh
./run.sh
```

Esto:
1. Activa el venv (reutiliza el de ORION si existe).
2. Instala Flask y PyJWT si faltan.
3. Genera certificado TLS auto-firmado en `certs/` si no existe.
4. Arranca Flask en `https://0.0.0.0:8443/`.

## Credenciales de prueba

| Usuario | Password | Saldo ficticio |
|---|---|---|
| `fabian` | `Fabian1234` | 4231.50 EUR |
| `admin` | `admin123` | 999999.99 EUR |
| `demo` | `demo` | 1500.00 EUR |

## Probar sin abrir navegador

```bash
# Login (ignoramos verificacion de cert con -k porque es auto-firmado)
TOKEN=$(curl -sk -X POST https://localhost:8443/api/login \
   -H "Content-Type: application/json" \
   -d '{"username":"fabian","password":"Fabian1234"}' | jq -r .token)

# Saldo
curl -sk https://localhost:8443/api/saldo \
   -H "Authorization: Bearer $TOKEN" | jq

# Movimientos
curl -sk https://localhost:8443/api/movimientos \
   -H "Authorization: Bearer $TOKEN" | jq

# Transferencia
curl -sk -X POST https://localhost:8443/api/transferencia \
   -H "Authorization: Bearer $TOKEN" \
   -H "Content-Type: application/json" \
   -d '{
     "destinatario_iban":"ES99 1111 2222 3333 4444 5555",
     "destinatario_nombre":"Pepe Perez",
     "importe": 250.00,
     "concepto": "Test TFG"
   }' | jq

# Comprobante PDF
curl -sk https://localhost:8443/comprobante.pdf \
   -H "Authorization: Bearer $TOKEN" -o /tmp/comp.pdf
file /tmp/comp.pdf
```

## Aviso legal

Este proyecto es codigo ficticio para fines academicos. No emula ningun
banco real. Las credenciales y datos financieros son inventados y
publicos. No introduzca informacion personal real.
