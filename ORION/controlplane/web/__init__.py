"""Blueprint que sirve las paginas HTML."""

from flask import Blueprint

web_bp = Blueprint("web", __name__)

# Importar las vistas para registrar las rutas en el blueprint.
from controlplane.web import views  # noqa: E402, F401
