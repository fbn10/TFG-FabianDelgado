"""Cliente Elasticsearch reutilizable.

Mantiene una unica instancia abierta durante la vida del proceso.
Cualquier modulo que necesite ES debe llamar a get_es().
"""

from elasticsearch import Elasticsearch

ES_URL = "http://localhost:9200"

_es: Elasticsearch | None = None


def get_es() -> Elasticsearch:
    global _es
    if _es is None:
        _es = Elasticsearch(ES_URL)
    return _es
