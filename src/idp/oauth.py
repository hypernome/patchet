from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import json, uuid, os

from fastapi import APIRouter, HTTPException, Depends, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from jose import jwt
import jwt as pyjwt
from jwt.exceptions import InvalidTokenError, PyJWKClientError
from jose.utils import base64url_encode
from jose.exceptions import JWTError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from idp.trusted_issuers import TRUSTED_ISSUERS
from idp.external_jwks import get_jwks_client

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"

ISSUER = os.getenv("ISSUER")
if not ISSUER:
    ISSUER = "http://idp.localhost"
ALG = "RS256"

# --- In-memory clients ---
CLIENTS: Dict[str, Dict] = {
    "planner": {
        "client_secret": "planner-secret",
        "scopes": [
            "classify",
            "plan",
            "read:repo",
            "read:sbom",
            "write:sbom",
            "write:deployment",
            "approve:deployment",
            "read:file:config.json",
            "payment:initiate",
            "sr:start",
            "sr:approve",
            "agent:metadata:read",
        ],
        "audiences": [
            "api.localhost.github",
            "api.localhost.osv",
            "api.localhost.deploy",
            "api.localhost.files",
            "api.localhost.payment",
            "api.localhost.sr",
            "api.localhost.data",
        ],
        "tenant": "org:hypernome",
    },
    "patcher": {
        "client_secret": "executor-secret",
        "scopes": [
            "patch",
            "write:repo",
            "create:pr",
            "deploy:production",
            "write:files:all",
            "payment:initiate",
            "payment:execute",
            "sr:execute",
            "data:process",
        ],
        "audiences": [
            "api.localhost.github",
            "api.localhost.osv",
            "api.localhost.deploy",
            "api.localhost.files",
            "api.localhost.payment",
            "api.localhost.sr",
            "api.localhost.data",
        ],
        "tenant": "org:hypernome",
    },
    "intent_registration_admin": {
        "client_secret": "intent-secret",
        "scopes": ["register:intent", "register:workflow"],
        "audiences": ["idp.localhost"],
        "tenant": "org:hypernome",
    },
    "building_admin": {
        "client_secret": "greentech123",
        "scopes": [
            "read:sensors",
            "write:hvac",
            "write:lighting",
            "read:data",
            "read:agents",
        ],
        "audiences": ["api.localhost.building"],
        "tenant": "org:hypernome",
    },
    "building_hvac": {
        "client_secret": "greentech123",
        "scopes": [
            "write:hvac",
            "read:data",
            "read:agents",
        ],
        "audiences": ["api.localhost.building"],
        "tenant": "org:hypernome",
    },
    "building_lighting": {
        "client_secret": "greentech123",
        "scopes": [
            "write:lighting",
            "read:data",
            "read:agents",
        ],
        "audiences": ["api.localhost.building"],
        "tenant": "org:hypernome",
    },
    "building_sensors": {
        "client_secret": "greentech123",
        "scopes": [
            "read:sensors",
            "read:data",
            "read:agents",
        ],
        "audiences": ["api.localhost.building"],
        "tenant": "org:hypernome",
    },
    # Add an intentionally over-scoped client for threat reproduction:
    "admin": {
        "client_secret": "too-much",
        "scopes": [
            "classify",
            "plan",
            "patch",
            "write:repo",
            "create:pr",
            "read:repo",
            "read:sbom, read:agents",
        ],
        "audiences": ["api.localhost.github", "api.localhost.osv"],
        "tenant": "org:hypernome",
    },
    "patchet": {
        "client_secret": "patchet-admin",
        "scopes": ["read:agents", "generate:intent-token"],
        "audiences": ["idp.localhost"],
        "tenant": "org:hypernome",
    },
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
n = base64url_encode(
    pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")
).decode()
e = base64url_encode(
    pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")
).decode()
KID = str(uuid.uuid4())

JWKS = {"keys": [{"kty": "RSA", "use": "sig", "kid": KID, "alg": ALG, "n": n, "e": e}]}

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


def issue_jwt(
    client_id: str, scopes: List[str], audience: List[str], extra: Dict
) -> str:
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
    return jwt.encode(claims, priv_pem, algorithm=ALG, headers={"kid": KID})


@oauth_router.get("/.well-known/jwks.json")
def jwks():
    return JSONResponse(JWKS)


@oauth_router.get("/.well-known/openid-configuration")
def jwks():
    return JSONResponse(JWKS)


# ── Root-level discovery aliases (public, no auth) ─────────────────────────
# OIDC/OAuth discovery is conventionally served at the ISSUER ROOT:
#   {issuer}/.well-known/jwks.json
#   {issuer}/.well-known/openid-configuration
# External verifiers, resource servers, and client libraries fetch JWKS from
# the root well-known path to verify our tokens — they cannot guess a /oauth
# prefix. These aliases serve the same content as the /oauth/.well-known/*
# routes above. Kept additive: the /oauth/.well-known/* paths still work, so
# the in-process JWKS cache and the api resource server are unaffected.
discovery_router = APIRouter()


@discovery_router.get("/.well-known/jwks.json")
def root_jwks():
    return JSONResponse(JWKS)


@discovery_router.get("/.well-known/openid-configuration")
def root_openid_configuration():
    return JSONResponse(JWKS)


@oauth_router.post("/token", response_model=TokenResponse)
async def token(
    grant_type: str = Form(...),
    client_id: str = Form(default=None),
    client_secret: str = Form(default=None),
    subject_token: str = Form(default=None),
    subject_token_type: str = Form(default=None),
    scope: str = Form(default=""),
    audience: str = Form(default=""),  # space-delimited
):
    if grant_type == TOKEN_EXCHANGE_GRANT:
        return await _handle_token_exchange(
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            audience=audience,
            scope=scope,
        )

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

    requested_aud = (
        [a for a in audience.split() if a] if audience else client["audiences"]
    )
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
        },
    )
    return TokenResponse(
        access_token=token, expires_in=30, scope=" ".join(requested_scopes)
    )


async def _handle_token_exchange(
    subject_token: str | None,
    subject_token_type: str | None,
    audience: str,
    scope: str,
):
    if not subject_token:
        raise HTTPException(400, "missing subject_token")
    if (
        subject_token_type
        and subject_token_type != "urn:ietf:params:oauth:token-type:jwt"
    ):
        raise HTTPException(400, "unsupported subject_token_type")

    # Peek at the iss claim to look up trust config (signature unverified yet)
    try:
        unverified = pyjwt.decode(subject_token, options={"verify_signature": False})
    except InvalidTokenError as e:
        raise HTTPException(400, f"malformed subject_token: {e}")

    issuer = unverified.get("iss")
    if not issuer or issuer not in TRUSTED_ISSUERS:
        raise HTTPException(401, f"untrusted issuer: {issuer}")

    trusted = TRUSTED_ISSUERS[issuer]

    # Fetch issuer JWKS, resolve key by kid
    try:
        jwks_client = get_jwks_client(trusted.jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(subject_token)
    except PyJWKClientError as e:
        raise HTTPException(401, f"jwks lookup failed: {e}")

    # Verify signature + claims
    try:
        claims = pyjwt.decode(
            subject_token,
            signing_key.key,
            algorithms=["EdDSA"],
            audience=trusted.expected_audience,
            issuer=trusted.issuer,
        )
    except InvalidTokenError as e:
        raise HTTPException(401, f"subject_token verification failed: {e}")

    user_sub = claims.get("sub")
    user_email = claims.get("email")
    if not user_sub:
        raise HTTPException(400, "subject_token missing sub claim")

    requested_scopes = [s for s in scope.split() if s] or trusted.default_scopes
    granted_scopes = [s for s in requested_scopes if s in trusted.default_scopes]
    if not granted_scopes:
        raise HTTPException(403, "no requested scopes are permitted for this issuer")

    requested_audiences = [
        a for a in audience.split() if a
    ] or trusted.default_authority_audiences
    granted_audiences = [
        a for a in requested_audiences if a in trusted.default_authority_audiences
    ]
    if not granted_audiences:
        raise HTTPException(403, "no requested audiences are permitted for this issuer")

    access_token = _mint_internal_token(
        sub=f"federated:{issuer}:{user_sub}",
        email=user_email,
        scopes=granted_scopes,
        audiences=granted_audiences,
        federated_issuer=issuer,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=1800,
        scope=" ".join(granted_scopes),
    )


def _mint_internal_token(sub, email, scopes, audiences, federated_issuer):
    """
    Mint an Authority access token bound to a federated user.

    Signed identically to issue_jwt() — same python-jose encoder, same RSA
    private key (priv_pem), same algorithm (ALG) and key id (KID), same
    issuer (ISSUER) — so these tokens verify against the IDP's published
    JWKS exactly like client_credentials tokens do.

    Extra claims `federated_iss` and `email` are carried so audit logs
    capture which external identity actually acted.
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=1800)
    claims = {
        "iss": ISSUER,
        "sub": sub,
        "email": email,
        "aud": audiences,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid.uuid4()),
        "scope": " ".join(scopes),
        "federated_iss": federated_issuer,
    }
    return jwt.encode(claims, priv_pem, algorithm=ALG, headers={"kid": KID})


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
        claims = jwt.decode(
            token, priv_pem, algorithms=[ALG], audience=None, issuer=ISSUER
        )
        return claims
    except Exception as e:
        raise HTTPException(401, f"invalid token: {e}")


@oauth_router.get("/whoami")
def whoami(authorization: Optional[str] = Header(default=None)):
    claims = verify_jwt(authorization)
    return {
        "sub": claims["sub"],
        "scope": claims.get("scope"),
        "aud": claims.get("aud"),
        "tenant": claims.get("tenant"),
    }
