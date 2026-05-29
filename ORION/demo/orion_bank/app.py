"""ORION-Bank: aplicacion web ficticia para demostrar interceptacion TLS.

Esta aplicacion NO es un banco real. Es un mock pedagogico utilizado en el
TFG de ORION para demostrar que, con mitmproxy y la CA de ORION instalada en
el cliente, se puede inspeccionar trafico HTTPS extremo-a-extremo:

  Cliente <--TLS A--> mitmproxy <--TLS B--> ORION-Bank (este servidor)

Ambos tramos van cifrados con TLS reales. Solo mitmproxy ve el plaintext.

Rutas que demuestran cada tipo de contenido HTTP/HTTPS:

  GET  /                          HTML estatico
  GET  /login                     formulario HTML
  POST /login                     credenciales en form-data (capturables)
  POST /api/login                 credenciales en JSON (capturables)
  GET  /dashboard                 HTML autenticado por cookie JWT
  GET  /api/saldo                 JSON con datos financieros (capturable)
  GET  /api/movimientos           JSON con lista de transacciones
  POST /api/transferencia         POST con JSON sensible (importe, IBAN)
  GET  /comprobante.pdf           descarga binaria PDF (capturable)
  GET  /logout                    elimina cookie

Autenticacion: JWT firmado HS256. Token va en cookie y/o cabecera Bearer.
Datos: hardcoded, ficticios, sin conexion a sistemas reales.
"""

import datetime
import io
import os
from functools import wraps

import jwt
from flask import (Flask, jsonify, make_response, redirect, render_template,
                   request, send_file, url_for)

app = Flask(__name__)

# SECRET_KEY es ficticio aproposito para que mitmproxy pueda verificar el
# token capturado y la demo sea autocontenida.
app.config["SECRET_KEY"] = "orion-bank-demo-secret-key-NO-USAR-EN-PRODUCCION"
JWT_ALG = "HS256"
JWT_EXP_MIN = 30
JWT_ISSUER = "orion-bank-demo"

# Base de datos en memoria (mock). Datos completamente ficticios.
USERS = {
    "fabian": "Fabian1234",
    "admin":  "admin123",
    "demo":   "demo",
}

ACCOUNTS = {
    "fabian": {
        "cliente": "Fabian Delgado",
        "iban":    "ES76 0049 1500 0512 3456 7890",
        "saldo":   4231.50,
        "moneda":  "EUR",
        "tipo":    "Cuenta corriente",
    },
    "admin": {
        "cliente": "Administrador ORION-Bank",
        "iban":    "ES99 0000 0000 0000 0000 0001",
        "saldo":   999999.99,
        "moneda":  "EUR",
        "tipo":    "Cuenta de servicio",
    },
    "demo": {
        "cliente": "Usuario Demo",
        "iban":    "ES12 3456 7890 1234 5678 9012",
        "saldo":   1500.00,
        "moneda":  "EUR",
        "tipo":    "Cuenta corriente",
    },
}

MOVIMIENTOS = {
    "fabian": [
        {"fecha": "2026-05-09", "concepto": "Nomina IE Madrid",            "importe":  1850.00},
        {"fecha": "2026-05-08", "concepto": "Mercadona Pozuelo",           "importe":   -47.32},
        {"fecha": "2026-05-07", "concepto": "Devolucion Amazon",           "importe":    24.99},
        {"fecha": "2026-05-05", "concepto": "Restaurante La Tagliatella",  "importe":   -38.50},
        {"fecha": "2026-05-03", "concepto": "Transferencia recibida",      "importe":   200.00},
        {"fecha": "2026-05-01", "concepto": "Alquiler piso compartido",    "importe":  -450.00},
    ],
    "admin": [
        {"fecha": "2026-05-10", "concepto": "Auditoria interna",           "importe":    -1.00},
    ],
    "demo": [
        {"fecha": "2026-05-10", "concepto": "Saldo inicial",               "importe":  1500.00},
    ],
}

# Helpers de JWT
def make_token(username):
    now = datetime.datetime.utcnow()
    payload = {
        "sub":   username,
        "iat":   now,
        "exp":   now + datetime.timedelta(minutes=JWT_EXP_MIN),
        "iss":   JWT_ISSUER,
        "roles": ["admin", "customer"] if username == "admin" else ["customer"],
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm=JWT_ALG)


def extract_token():
    """Lee el JWT del header Authorization o de la cookie."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return request.cookies.get("orion_bank_token")


def require_jwt(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = extract_token()
        if not token:
            return jsonify({"error": "Falta token JWT"}), 401
        try:
            payload = jwt.decode(
                token,
                app.config["SECRET_KEY"],
                algorithms=[JWT_ALG],
                issuer=JWT_ISSUER,
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError as exc:
            return jsonify({"error": f"Token invalido: {exc}"}), 401
        request.user = payload["sub"]
        request.jwt_payload = payload
        return f(*args, **kwargs)
    return wrapper


# Rutas HTML
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_submit():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if USERS.get(username) != password:
        return render_template("login.html", error="Credenciales invalidas"), 401
    token = make_token(username)
    # 303 See Other: fuerza al cliente a seguir con GET tras el POST. Critico
    # para curl -L y tambien correcto por RFC 7231 §6.4.4.
    resp = make_response(redirect(url_for("dashboard"), code=303))
    resp.set_cookie(
        "orion_bank_token", token,
        max_age=JWT_EXP_MIN * 60,
        httponly=False, samesite="Lax",
    )
    return resp


@app.route("/dashboard")
def dashboard():
    token = extract_token()
    if not token:
        return redirect(url_for("login_page"))
    try:
        payload = jwt.decode(
            token, app.config["SECRET_KEY"],
            algorithms=[JWT_ALG], issuer=JWT_ISSUER,
        )
    except jwt.InvalidTokenError:
        return redirect(url_for("login_page"))
    return render_template(
        "dashboard.html",
        username=payload["sub"],
        roles=payload.get("roles", []),
        token=token,
        account=ACCOUNTS.get(payload["sub"], {}),
    )


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("orion_bank_token")
    return resp


# API JSON
@app.route("/api/login", methods=["POST"])
def api_login():
    """Login para clientes que prefieran JSON (cURL, apps moviles)."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if USERS.get(username) != password:
        return jsonify({"error": "Credenciales invalidas"}), 401
    return jsonify({
        "token": make_token(username),
        "token_type": "Bearer",
        "expires_in": JWT_EXP_MIN * 60,
        "user": username,
    })


@app.route("/api/saldo")
@require_jwt
def api_saldo():
    return jsonify(ACCOUNTS.get(request.user, {}))


@app.route("/api/movimientos")
@require_jwt
def api_movimientos():
    return jsonify({
        "cliente":     request.user,
        "movimientos": MOVIMIENTOS.get(request.user, []),
    })


@app.route("/api/transferencia", methods=["POST"])
@require_jwt
def api_transferencia():
    data = request.get_json(silent=True) or {}
    destinatario = data.get("destinatario_iban", "").strip()
    nombre       = data.get("destinatario_nombre", "").strip()
    importe      = float(data.get("importe", 0))
    concepto     = data.get("concepto", "").strip()

    if importe <= 0:
        return jsonify({"error": "Importe invalido"}), 400
    if not destinatario:
        return jsonify({"error": "Falta IBAN destinatario"}), 400

    acc = ACCOUNTS.get(request.user)
    if acc and importe > acc["saldo"]:
        return jsonify({"error": "Saldo insuficiente"}), 400

    return jsonify({
        "ok":               True,
        "id_transferencia": f"TRX-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
        "ordenante":        request.user,
        "destinatario": {
            "nombre": nombre or "(sin nombre)",
            "iban":   destinatario,
        },
        "importe":          importe,
        "moneda":           "EUR",
        "concepto":         concepto,
        "fecha":            datetime.datetime.utcnow().isoformat() + "Z",
        "estado":           "completada",
    })


# Descarga binaria: PDF generado al vuelo. Sirve para demostrar la captura
# de contenido binario por mitmproxy.
@app.route("/comprobante.pdf")
@require_jwt
def comprobante_pdf():
    """Genera un PDF minimal con datos de la cuenta. Demuestra captura
    de contenido binario por mitmproxy.
    """
    pdf_bytes = _build_minimal_pdf(
        titulo="Comprobante de operacion - ORION Bank",
        lineas=[
            f"Cliente: {ACCOUNTS.get(request.user, {}).get('cliente', request.user)}",
            f"IBAN:    {ACCOUNTS.get(request.user, {}).get('iban', '-')}",
            f"Saldo:   {ACCOUNTS.get(request.user, {}).get('saldo', 0)} EUR",
            f"Fecha:   {datetime.datetime.utcnow().isoformat()}Z",
            "",
            "Este documento es ficticio y se usa unicamente con fines",
            "didacticos en el TFG del sistema ORION.",
        ],
    )
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=False,
        download_name="comprobante.pdf",
    )


def _build_minimal_pdf(titulo, lineas):
    """Construye un PDF minimal valido sin dependencias externas.

    Suficiente para que cualquier visor lo abra y mitmproxy lo muestre como
    un descargable binario. No usamos fpdf/reportlab para evitar deps.
    """
    content_lines = [
        "BT",
        "/F1 16 Tf",
        "50 780 Td",
        f"({_pdf_escape(titulo)}) Tj",
        "0 -30 Td",
        "/F1 11 Tf",
    ]
    for ln in lineas:
        content_lines.append(f"({_pdf_escape(ln)}) Tj")
        content_lines.append("0 -16 Td")
    content_lines.append("ET")
    content = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects = []
    # 1: Catalog
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    # 2: Pages
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    # 3: Page
    objects.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
    )
    # 4: Contents stream
    objects.append(
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n"
        + content + b"\nendstream"
    )
    # 5: Font
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += f"{idx} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_pos = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n".encode()
    pdf += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        pdf += f"{off:010d} 00000 n \n".encode()
    pdf += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode()
    return bytes(pdf)


def _pdf_escape(s):
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


# Endpoints de diagnostico utiles durante la demo.
@app.route("/api/whoami")
@require_jwt
def whoami():
    return jsonify({
        "user":    request.user,
        "payload": {k: (v.isoformat() if hasattr(v, "isoformat") else v)
                    for k, v in request.jwt_payload.items()},
        "ip_origen":   request.remote_addr,
        "user_agent":  request.headers.get("User-Agent", ""),
    })


# Entry point
if __name__ == "__main__":
    cert = os.environ.get("ORION_BANK_CERT", "certs/server.crt")
    key  = os.environ.get("ORION_BANK_KEY",  "certs/server.key")
    port = int(os.environ.get("ORION_BANK_PORT", "8443"))

    if not (os.path.exists(cert) and os.path.exists(key)):
        raise SystemExit(
            f"[!] Faltan certificados TLS en {cert} / {key}.\n"
            f"    Ejecuta primero ./run.sh, que los genera automaticamente."
        )

    app.run(host="0.0.0.0", port=port, ssl_context=(cert, key), debug=False)
