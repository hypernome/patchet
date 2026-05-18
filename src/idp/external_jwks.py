"""
JWKS fetch + key resolution via PyJWT's PyJWKClient.
Handles caching, kid-based key selection, and TLS redirects automatically.
"""

from jwt import PyJWKClient

_clients: dict[str, PyJWKClient] = {}


def get_jwks_client(jwks_uri: str) -> PyJWKClient:
    if jwks_uri not in _clients:
        _clients[jwks_uri] = PyJWKClient(jwks_uri, cache_keys=True, lifespan=600)
    return _clients[jwks_uri]
