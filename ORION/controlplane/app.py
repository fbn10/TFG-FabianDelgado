"""Factory de la app Flask de ORION.

Patron application factory: la app se crea via funcion create_app() en
lugar de declararla a nivel de modulo. Asi se pueden lanzar varias
instancias (util en tests) y se mantiene la configuracion encapsulada.
"""

import os

from flask import Flask

# Ruta absoluta al directorio raiz del proyecto (un nivel por encima de
# controlplane/). Sirve para apuntar a frontend/templates y frontend/static
# sin depender del directorio actual desde el que se lance python.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, "frontend", "templates"),
        static_folder=os.path.join(BASE_DIR, "frontend", "static"),
        static_url_path="/static",
    )

    # Registrar los blueprints. Imports dentro de la funcion para evitar
    # ciclos de importacion al cargar el paquete controlplane.
    from controlplane.api import api_bp
    from controlplane.web import web_bp

    app.register_blueprint(api_bp)
    app.register_blueprint(web_bp)

    return app
