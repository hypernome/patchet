"""
Fetch + cache external JWKS, used to verify subject_token JWTs from
trusted issuers during token exchange.

Cache TTL: 10 min. Keys rotate, so we refresh occasionally.
"""

import time
import httpx
from typing import Dict, Any

_cache: Dict[str, tuple[float, Dict[str, Any]]] = {}
_CACHE_TTL_S = 600


async def fetch_jwks(jwks_uri: str) -> Dict[str, Any]:
    cached = _cache.get(jwks_uri)
    if cached and cached[0] > time.time():
        return cached[1]
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
        res = await client.get(jwks_uri)
        res.raise_for_status()
        keys = res.json()
    _cache[jwks_uri] = (time.time() + _CACHE_TTL_S, keys)
    return keys
