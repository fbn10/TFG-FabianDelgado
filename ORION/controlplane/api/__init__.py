"""Blueprint que agrupa todos los endpoints HTTP de la API."""

from flask import Blueprint

api_bp = Blueprint("api", __name__, url_prefix="/api")

# Importar los modulos para que registren sus rutas en api_bp.
from controlplane.api import health, rules, stats, threat_intel, alerts, mitm, blocks, lookup  # noqa: E402, F401
