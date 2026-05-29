"""Vistas HTML de ORION.

Cada ruta devuelve una pagina renderizada con Jinja2. Los datos los
piden las paginas via JavaScript a la API en /api/*, asi separamos la
presentacion de los datos.
"""

from flask import render_template, redirect, url_for

from controlplane.web import web_bp


@web_bp.route("/")
def home():
    """Pantalla de presentacion con logo, radar y olas."""
    return render_template("home.html", current="home")


@web_bp.route("/resumen")
def resumen_page():
    """Resumen con tarjetas de metricas (lo que antes era la home)."""
    return render_template("resumen.html", current="resumen")


@web_bp.route("/reglas")
def rules_page():
    """Tabla de reglas con boton para anadir y borrar."""
    return render_template("rules.html", current="rules")


@web_bp.route("/estado")
def health_page():
    """Antigua pestana 'Estado', ahora fusionada con Resumen."""
    return redirect(url_for("web.resumen_page"))


@web_bp.route("/dashboards")
def dashboards_page():
    """Visualizaciones de Kibana embebidas."""
    return render_template("dashboards.html", current="dashboards")


@web_bp.route("/inteligencia")
def threat_intel_page():
    """Listas publicas de IPs/CIDRs maliciosas (FireHOL, Spamhaus)."""
    return render_template("inteligencia.html", current="inteligencia")


@web_bp.route("/alertas")
def alerts_page():
    """Conexiones recientes detectadas como maliciosas (threat.matched=true)."""
    return render_template("alertas.html", current="alertas")


@web_bp.route("/mitm")
def mitm_page():
    """Trafico HTTPS interceptado y descifrado por mitmproxy."""
    return render_template("mitm.html", current="mitm")


@web_bp.route("/bloqueos")
def blocks_page():
    """IPs bloqueadas automaticamente por el WAF (auto-blocks con TTL)."""
    return render_template("blocks.html", current="blocks")
