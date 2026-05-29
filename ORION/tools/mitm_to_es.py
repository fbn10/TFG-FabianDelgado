"""Addon de mitmproxy: vuelca cada peticion/respuesta descifrada a Elasticsearch.

Se carga con:
    sudo mitmweb --mode transparent --listen-host 0.0.0.0 --listen-port 8888 \\
                 --ssl-insecure --showhost \\
                 --set web_open_browser=false \\
                 --web-host 0.0.0.0 --web-port 8081 \\
                 -s /home/minerva/Escritorio/TFG_Fabian/ORION/tools/mitm_to_es.py

Cada par request+response genera un documento en el indice 'orion-mitm-traffic'.
Detecta credenciales en form-data o JSON y tokens JWT, marcandolos como hallazgos.
"""

import json
import time
import urllib.parse
from datetime import datetime, timezone

from elasticsearch import Elasticsearch
from mitmproxy import ctx, http

# Config
ES_URL          = "http://localhost:9200"
INDEX_NAME      = "orion-mitm-traffic"
MAX_BODY_BYTES  = 64 * 1024
SENSITIVE_KEYS  = {
    "password", "passwd", "pass", "pwd",
    "username", "user", "usuario", "login",
    "email", "mail",
    "secret", "token", "apikey", "api_key",
    "iban", "tarjeta", "card", "cvv", "cvc", "pan",
}
BINARY_CTYPES = ("image/", "application/octet-stream", "application/pdf",
                 "application/zip", "video/", "audio/")

# Nota: la deteccion WAF (patrones, fuerza bruta, fuzzing, UA atacante) NO se
# hace aqui. Vive en tools/waf_detector.py, un worker independiente que lee
# este mismo indice (orion-mitm-traffic) cada pocos segundos y dispara
# bloqueos via /api/blocks/auto. Asi este addon hace una sola cosa (indexar)
# y un crash del detector no rompe la captura.


class MitmToES:
    def __init__(self):
        self.es = None

    def load(self, loader):
        try:
            self.es = Elasticsearch(ES_URL, request_timeout=2)
            ctx.log.info(f"[mitm_to_es] conectado a {ES_URL}, indice {INDEX_NAME}")
            self._ensure_index()
        except Exception as e:
            ctx.log.error(f"[mitm_to_es] no se pudo conectar a ES: {e}")

    def _ensure_index(self):
        """Crea mapping minimo si el indice no existe."""
        if not self.es:
            return
        try:
            if self.es.indices.exists(index=INDEX_NAME):
                return
            self.es.indices.create(index=INDEX_NAME, mappings={
                "properties": {
                    "@timestamp":   {"type": "date"},
                    "duration_ms":  {"type": "long"},
                    "client":       {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
                    "server":       {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"},
                                                    "hostname": {"type": "keyword"}}},
                    "tls":          {"properties": {"version": {"type": "keyword"}, "cipher": {"type": "keyword"}}},
                    "http": {
                        "properties": {
                            "method":              {"type": "keyword"},
                            "path":                {"type": "keyword"},
                            "host":                {"type": "keyword"},
                            "url":                 {"type": "keyword"},
                            "version":             {"type": "keyword"},
                            "request_headers":     {"type": "object", "enabled": True},
                            "request_body_size":   {"type": "long"},
                            "request_body":        {"type": "text"},
                            "request_content_type":{"type": "keyword"},
                            "response_status":     {"type": "integer"},
                            "response_status_text":{"type": "keyword"},
                            "response_headers":    {"type": "object", "enabled": True},
                            "response_body_size":  {"type": "long"},
                            "response_body":       {"type": "text"},
                            "response_content_type":{"type": "keyword"},
                        }
                    },
                    "security": {
                        "properties": {
                            "credentials": {"type": "object", "enabled": True},
                            "jwt_token":   {"type": "text"},
                            "jwt_payload": {"type": "object", "enabled": True},
                            "has_credentials": {"type": "boolean"},
                            "has_jwt": {"type": "boolean"},
                        }
                    },
                }
            })
            ctx.log.info(f"[mitm_to_es] indice {INDEX_NAME} creado")
        except Exception as e:
            ctx.log.warn(f"[mitm_to_es] no se pudo crear indice: {e}")

    def response(self, flow: http.HTTPFlow):
        """Hook principal de mitmproxy: se dispara con la respuesta completa en memoria."""
        if not self.es or not flow.response:
            return
        try:
            doc = self._build_doc(flow)
            self.es.index(index=INDEX_NAME, document=doc)
        except Exception as e:
            ctx.log.error(f"[mitm_to_es] error indexando: {e}")

    def _build_doc(self, flow: http.HTTPFlow) -> dict:
        """Construye el documento que se indexa por cada par request+response."""
        req  = flow.request
        resp = flow.response

        client_ip   = client_port = None
        if flow.client_conn and flow.client_conn.peername:
            client_ip, client_port = flow.client_conn.peername[0], flow.client_conn.peername[1]

        server_ip   = server_port = None
        if flow.server_conn and flow.server_conn.address:
            server_ip, server_port = flow.server_conn.address[0], flow.server_conn.address[1]

        tls_version = None
        if flow.server_conn and getattr(flow.server_conn, "tls_version", None):
            tls_version = flow.server_conn.tls_version

        req_ctype  = req.headers.get("content-type", "")
        resp_ctype = resp.headers.get("content-type", "")

        doc = {
            "@timestamp":  datetime.now(timezone.utc).isoformat(),
            "duration_ms": self._duration_ms(req, resp),
            "client": {"ip": client_ip, "port": client_port},
            "server": {"ip": server_ip, "port": server_port, "hostname": req.host},
            "tls":    {"version": tls_version},
            "http": {
                "method":               req.method,
                "path":                 req.path,
                "host":                 req.host,
                "url":                  req.pretty_url,
                "version":              req.http_version,
                "request_headers":      self._safe_headers(req.headers),
                "request_body_size":    len(req.content or b""),
                "request_body":         self._preview_body(req.content, req_ctype),
                "request_content_type": req_ctype.split(";")[0].strip() if req_ctype else None,
                "response_status":      resp.status_code,
                "response_status_text": resp.reason,
                "response_headers":     self._safe_headers(resp.headers),
                "response_body_size":   len(resp.content or b""),
                "response_body":        self._preview_body(resp.content, resp_ctype),
                "response_content_type":resp_ctype.split(";")[0].strip() if resp_ctype else None,
            },
        }

        # Hallazgos de seguridad
        creds = self._detect_credentials(req)
        jwt_token, jwt_payload = self._detect_jwt(req)
        sec = {}
        if creds:
            sec["credentials"] = creds
            sec["has_credentials"] = True
        if jwt_token:
            sec["jwt_token"] = jwt_token
            sec["jwt_payload"] = jwt_payload
            sec["has_jwt"] = True
        if sec:
            doc["security"] = sec

        return doc

    def _safe_headers(self, headers):
        """Convierte mitmproxy Headers en dict simple para ES."""
        return {k: v for k, v in headers.items(multi=False)}

    def _preview_body(self, content, content_type):
        if not content:
            return None
        ct = (content_type or "").lower()
        if any(b in ct for b in BINARY_CTYPES):
            return f"<binary content_type={ct} size={len(content)}>"
        try:
            text = content[:MAX_BODY_BYTES].decode("utf-8", errors="replace")
            if len(content) > MAX_BODY_BYTES:
                text += f"\n... [truncado, total {len(content)} bytes]"
            return text
        except Exception:
            return f"<binary size={len(content)}>"

    def _duration_ms(self, req, resp):
        try:
            return int((resp.timestamp_end - req.timestamp_start) * 1000)
        except Exception:
            return None

    def _detect_credentials(self, req: http.Request):
        """Extrae claves sensibles del body si viene como form-encoded o JSON."""
        if not req.content:
            return None
        ctype = (req.headers.get("content-type", "") or "").lower()

        try:
            body = req.content.decode("utf-8", errors="replace")
        except Exception:
            return None

        # x-www-form-urlencoded
        if "application/x-www-form-urlencoded" in ctype:
            return self._dict_pick(urllib.parse.parse_qs(body), flatten=True)

        # JSON
        if "application/json" in ctype:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    return self._dict_pick(data, flatten=False)
            except Exception:
                return None

        return None

    def _dict_pick(self, d, flatten=False):
        """Devuelve solo las claves sensibles del dict."""
        out = {}
        for k, v in d.items():
            if k.lower() in SENSITIVE_KEYS:
                if flatten and isinstance(v, list):
                    v = v[0] if v else ""
                out[k] = v
        return out or None

    def _detect_jwt(self, req: http.Request):
        """Busca un JWT en Authorization Bearer o en cookies tipo 'token'/'jwt'."""
        auth = req.headers.get("authorization", "")
        token = None
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()
        else:
            # buscar en cookies tipica clave 'token' o '*jwt*'
            cookie_header = req.headers.get("cookie", "")
            for piece in cookie_header.split(";"):
                if "=" in piece:
                    k, v = piece.strip().split("=", 1)
                    if "jwt" in k.lower() or "token" in k.lower():
                        token = v.strip()
                        break
        if not token or token.count(".") != 2:
            return None, None

        # Decodificar payload SIN verificar firma (es solo para visualizacion)
        try:
            import base64
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception:
            payload = None
        return token, payload


addons = [MitmToES()]
