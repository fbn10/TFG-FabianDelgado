"""Endpoint de salud: confirma que Flask y Elasticsearch responden."""

from flask import jsonify

from controlplane.api import api_bp
from controlplane.es_client import get_es


@api_bp.route("/health", methods=["GET"])
def health():
    try:
        es = get_es()
        info = es.info()
        return jsonify({
            "status": "ok",
            "flask": "ok",
            "es_cluster": info.get("cluster_name"),
            "es_version": info.get("version", {}).get("number"),
        })
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 503
