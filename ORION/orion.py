"""Punto de entrada de ORION (control plane).

Uso:
    source venv/bin/activate
    python orion.py
"""

from controlplane.app import create_app

app = create_app()


if __name__ == "__main__":
    # debug=True activa autoreload al cambiar codigo y muestra trazas
    # detalladas en errores. Se desactiva en produccion.
    app.run(host="127.0.0.1", port=5000, debug=True)
