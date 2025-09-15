from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import json, uuid, os

from fastapi import APIRouter, HTTPException, Depends, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from jose import jwt
from jose.utils import base64url_encode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

ISSUER = os.getenv("ISSUER")
if not ISSUER: 
    ISSUER = "http://idp.localhost"
ALG = "RS256"

# --- In-memory clients ---
CLIENTS: Dict[str, Dict] = {
    "planner": {
        "client_secret": "planner-secret",
        "scopes": ["classify", "plan", "read:repo", "read:sbom", "write:sbom"],
        "audiences": ["api.localhost.github", "api.localhost.osv"],
        "tenant": "org:hypernome"
    },
    "patcher": {
        "client_secret": "executor-secret",
        "scopes": ["patch", "write:repo", "create:pr"],
        "audiences": ["api.localhost.github"],
        "tenant": "org:hypernome"
    },
    "intent_registration_admin": {
        "client_secret": "intent-secret",
        "scopes": ["register:intent", "register:workflow"],
        "audiences": ["idp.localhost"],
        "tenant": "org:hypernome"    
    },
    # Add an intentionally over-scoped client for threat reproduction:
    "admin": {
        "client_secret": "too-much",
        "scopes": ["classify","plan","patch","write:repo","create:pr","read:repo","read:sbom"],
        "audiences": ["api.localhost.github", "api.localhost.osv"],
        "tenant": "org:hypernome"
    }
}

# --- Generate ephemeral RSA keypair (in-memory) ---
_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
priv_pem = _key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
pub = _key.public_key()
pub_numbers = pub.public_numbers()
n = base64url_encode(pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")).decode()
e = base64url_encode(pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")).decode()
KID = str(uuid.uuid4())

JWKS = {
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "kid": KID,
        "alg": ALG,
        "n": n,
        "e": e
    }]
}

oauth_router = APIRouter(prefix="/oauth")

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: Optional[str] = None

class IntrospectResponse(BaseModel):
    active: bool
    sub: Optional[str] = None
    scope: Optional[str] = None
    client_id: Optional[str] = None
    exp: Optional[int] = None
    aud: Optional[List[str]] = None
    iss: Optional[str] = None
    jti: Optional[str] = None

def issue_jwt(client_id: str, scopes: List[str], audience: List[str], extra: Dict) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=30)  # make short for replay tests
    claims = {
        "iss": ISSUER,
        "sub": f"client:{client_id}",
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid.uuid4()),
        "scope": " ".join(scopes),
        **extra,
    }
    return jwt.encode(
        claims,
        priv_pem,
        algorithm=ALG,
        headers={"kid": KID}
    )

@oauth_router.get("/.well-known/jwks.json")
def jwks():
    return JSONResponse(JWKS)

@oauth_router.post("/token", response_model=TokenResponse)
def token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: str = Form(default=""),
    audience: str = Form(default="")  # space-delimited
):
    if grant_type != "client_credentials":
        raise HTTPException(400, "unsupported_grant_type")

    client = CLIENTS.get(client_id)
    if not client or client.get("client_secret") != client_secret:
        raise HTTPException(401, "invalid_client")

    requested_scopes = [s for s in scope.split() if s] if scope else client["scopes"]
    # Enforce subset-of allowed scopes (for “normal” OAuth)
    for s in requested_scopes:
        if s not in client["scopes"]:
            raise HTTPException(400, f"invalid_scope: {s}")

    requested_aud = [a for a in audience.split() if a] if audience else client["audiences"]
    # Enforce subset-of allowed audiences
    for a in requested_aud:
        if a not in client["audiences"]:
            raise HTTPException(400, f"invalid_audience: {a}")

    token = issue_jwt(
        client_id,
        requested_scopes,
        requested_aud,
        extra={
            "tenant": client["tenant"],
            # Put a repo selector here to simulate cross-repo (or omit for over-scoped):
            # "repo_id": "gh:hypernome/patchet-public#<sha>"
        }
    )
    return TokenResponse(access_token=token, expires_in=30, scope=" ".join(requested_scopes))

@oauth_router.post("/introspect", response_model=IntrospectResponse)
def introspect(token: str = Form(...)):
    try:
        claims = jwt.get_unverified_claims(token)
        # This is a minimal check; Resource Server (API) should verify signature & aud with JWKS
        return IntrospectResponse(
            active=True,
            sub=claims.get("sub"),
            scope=claims.get("scope"),
            client_id=claims.get("sub"),
            exp=claims.get("exp"),
            aud=claims.get("aud"),
            iss=claims.get("iss"),
            jti=claims.get("jti"),
        )
    except Exception:
        return IntrospectResponse(active=False)

# Sample protected resource to test verification.
from fastapi import Header
from jose import jwk
from jose.utils import base64url_decode

def verify_jwt(auth_header: Optional[str]) -> Dict:
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer")
    token = auth_header.split(" ", 1)[1]
    # verify signature with local JWKS (in a real API, you’d fetch from /.well-known/jwks.json)
    headers = jwt.get_unverified_header(token)
    if headers.get("kid") != KID:
        raise HTTPException(401, "kid mismatch")
    try:
        claims = jwt.decode(token, priv_pem, algorithms=[ALG], audience=None, issuer=ISSUER)
        return claims
    except Exception as e:
        raise HTTPException(401, f"invalid token: {e}")

@oauth_router.get("/whoami")
def whoami(authorization: Optional[str] = Header(default=None)):
    claims = verify_jwt(authorization)
    return {"sub": claims["sub"], "scope": claims.get("scope"), "aud": claims.get("aud"), "tenant": claims.get("tenant")}