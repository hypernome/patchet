"""
Trusted external issuers whose subject_token JWTs the Authority will
accept for OAuth 2.0 Token Exchange (RFC 8693).

Each entry maps an issuer URL to:
  - jwks_uri:   where to fetch its public keys
  - audience:   the `aud` claim we expect on tokens from this issuer
  - role_map:   user-claim -> Authority scopes & audiences
"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class TrustedIssuer:
    issuer: str
    jwks_uri: str
    expected_audience: str
    default_scopes: List[str]
    default_authority_audiences: List[str]


TRUSTED_ISSUERS: Dict[str, TrustedIssuer] = {
    "https://auth51.com": TrustedIssuer(
        issuer="https://auth51.com",
        jwks_uri="https://auth51.com/api/jwks.json",
        expected_audience="idp.localhost",  # Authority's own audience
        default_scopes=[
            "read:agents",
            "generate:intent-token",
        ],
        default_authority_audiences=[
            "idp.localhost",
        ],
    ),
}
