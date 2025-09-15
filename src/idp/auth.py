from __future__ import annotations
import os, time, asyncio
from typing import Dict, Iterable, Optional, Callable
import httpx
from fastapi import HTTPException, Request, Depends, FastAPI
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from jose.utils import base64url_decode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from util.environment import EnvVars

# ---------- JWKS cache (shared) ----------
def _jwk_to_pem(jwk: Dict[str,str]) -> bytes:
    n = int.from_bytes(base64url_decode(jwk["n"].encode()), "big")
    e = int.from_bytes(base64url_decode(jwk["e"].encode()), "big")
    pub = rsa.RSAPublicNumbers(e, n).public_key()
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

class _JWKSCache:
    def __init__(self, jwks_url: str, ttl_seconds: int = 600):
        self.jwks_url = jwks_url
        self.ttl = ttl_seconds
        self._kid_to_pem: Dict[str, bytes] = {}
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    async def get(self, kid: str) -> bytes:
        now = time.time()
        async with self._lock:
            if not self._kid_to_pem or now >= self._expires_at or kid not in self._kid_to_pem:
                await self._refresh()
            if kid not in self._kid_to_pem:
                await self._refresh()
            key = self._kid_to_pem.get(kid)
            if not isinstance(key, (bytes, bytearray)):
                raise HTTPException(500, f"JWKSCache bug: expected bytes, got {type(key).__name__}")
            return key

    async def _refresh(self):
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(self.jwks_url)
            r.raise_for_status()
            data = r.json()
        kid_map = {}
        for k in data.get("keys", []):
            if k.get("kty") == "RSA" and "n" in k and "e" in k and "kid" in k:
                kid_map[k["kid"]] = _jwk_to_pem(k)
        if not kid_map:
            raise HTTPException(502, "Empty/invalid JWKS")
        self._kid_to_pem = kid_map
        self._expires_at = time.time() + self.ttl

# ---------- 1) Thin middleware: verify sig/iss/exp and stash claims ----------
class JWTSignatureMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        jwks_url: str,
        issuer: str,
        algorithms: Optional[list[str]] = None,
        clock_skew_seconds: int = 60,
        exempt_paths: Optional[list[str]] = None,
    ):
        super().__init__(app)
        self.issuer = issuer
        self.algorithms = algorithms or ["RS256"]
        self.clock_skew = clock_skew_seconds
        self.exempt = set(exempt_paths or [
            "/health", 
            "/docs", 
            "/openapi.json", 
            "/oauth/token", 
            "/oauth/.well-known/jwks.json", 
            "/oauth/introspect", 
            "/oauth/whoami"
        ])
        self.jwks = _JWKSCache(jwks_url, ttl_seconds=int(os.getenv("JWKS_TTL", "600")))

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        path = request.url.path
        if path in self.exempt or any(path.startswith(p + "/") for p in self.exempt):
            return await call_next(request)

        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        if not auth or not auth.lower().startswith("bearer "):
            return JSONResponse({"error": "Missing bearer token"}, status_code=401)
        token = auth.split(" ", 1)[1].strip()

        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if not kid:
                return JSONResponse({"error": "Missing kid"}, status_code=401)
            key_pem = await self.jwks.get(kid)

            # Only verify signature/iss/exp/nbf here. Audience & scopes are per-endpoint.
            claims = jwt.decode(
                token,
                key_pem,
                algorithms=self.algorithms,
                issuer=self.issuer,
                options={"verify_aud": False}
            )
            request.state.claims = claims
            request.state.token = token

        except ExpiredSignatureError:
            return JSONResponse({"error": f"Token expired"}, status_code=401)
        except JWTClaimsError as e:
            return JSONResponse({"error": f"Invalid claims: {e}"}, status_code=401)
        except JWTError as e:
            return JSONResponse({"error": f"Invalid token: {e}"}, status_code=401)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, f"Auth error: {e}")

        return await call_next(request)

def install_signature_middleware(app: FastAPI):
    idp_url: str = os.getenv(EnvVars.IDP_URL.value, "http://idp.localhost")
    exempt_paths = os.getenv("AUTH_EXEMPT_PATHS", None)
    app.add_middleware(
        JWTSignatureMiddleware,
        jwks_url=f"{idp_url}/oauth/.well-known/jwks.json",
        issuer=os.getenv(EnvVars.EXPECTED_ISS.value, "http://idp.localhost"),
        clock_skew_seconds=int(os.getenv("CLOCK_SKEW_SECONDS","60")),
        exempt_paths=(exempt_paths.split(",") if exempt_paths else None),
    )

# ---------- 2) Per-endpoint dependency enforcing audience + scopes ----------
def _claim_scopes(claims: dict) -> set[str]:
    raw = claims.get("scope") or claims.get("scp") or []
    if isinstance(raw, str): 
        return set(s for s in raw.split() if s)
    if isinstance(raw, list): 
        return set(raw)
    return set()

def require_auth(scopes: Iterable[str] | str = (), audience: Optional[str] = None):
    req_scopes = scopes.split() if isinstance(scopes, str) else list(scopes or [])
    need = set(req_scopes)

    async def _dep(request: Request):
        claims = getattr(request.state, "claims", None)
        if not claims:
            raise HTTPException(401, "Unauthenticated")

        # Audience check (if provided)
        if audience is not None:
            aud = claims.get("aud")
            if isinstance(aud, str):
                ok = (audience == aud)
            elif isinstance(aud, list):
                ok = (audience in aud)
            else:
                ok = False
            if not ok:
                raise HTTPException(403, f"Invalid audience: need '{audience}'")

        # Scope check (if any required)
        if need:
            have = _claim_scopes(claims)
            missing = [s for s in need if s not in have]
            if missing:
                raise HTTPException(403, f"Missing required scope(s): {', '.join(missing)}")

        # Optionally expose convenience fields
        request.state.subject = claims.get("sub")

    return _dep