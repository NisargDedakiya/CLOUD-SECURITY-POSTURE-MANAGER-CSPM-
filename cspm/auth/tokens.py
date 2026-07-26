"""OIDC / JWT verification (Okta, Azure AD, Auth0, Cognito, ...).

Supports two modes, chosen by config:
- ``jwks``   : verify RS256 tokens against the IdP's JWKS endpoint (production).
- ``secret`` : verify HS256 tokens with a shared secret (dev / internal tokens).

The verified claims are returned; the caller maps ``sub``/``org``/``roles`` onto
an :class:`~cspm.shared.deps.OrgContext`.
"""

from __future__ import annotations

import time

import jwt
from jwt import PyJWKClient

from cspm.config import get_settings

_settings = get_settings()
_jwks_client: PyJWKClient | None = None


class TokenError(Exception):
    """Raised when a bearer token is missing/invalid/expired."""


def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        if not _settings.oidc_jwks_url:
            raise TokenError("OIDC JWKS URL not configured.")
        _jwks_client = PyJWKClient(_settings.oidc_jwks_url)
    return _jwks_client


def verify_token(token: str) -> dict:
    """Verify a bearer token and return its claims."""
    if not token:
        raise TokenError("Empty token.")
    try:
        if _settings.auth_mode == "jwks":
            signing_key = _get_jwks_client().get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=_settings.oidc_audience or None,
                issuer=_settings.oidc_issuer or None,
                options={"verify_aud": bool(_settings.oidc_audience)},
            )
        else:  # secret / HS256
            if not _settings.jwt_secret:
                raise TokenError("JWT secret not configured.")
            claims = jwt.decode(
                token,
                _settings.jwt_secret,
                algorithms=["HS256"],
                audience=_settings.oidc_audience or None,
                options={"verify_aud": bool(_settings.oidc_audience)},
            )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token expired.") from exc
    except jwt.PyJWTError as exc:
        raise TokenError(f"Invalid token: {exc}") from exc

    if "exp" in claims and claims["exp"] < time.time():
        raise TokenError("Token expired.")
    return claims


def issue_dev_token(sub: str, org: str, roles: list[str], ttl: int = 3600) -> str:
    """Mint an HS256 token for local/dev/testing (not for production issuance)."""
    if not _settings.jwt_secret:
        raise TokenError("JWT secret not configured.")
    payload = {
        "sub": sub,
        "org": org,
        "roles": roles,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl,
    }
    if _settings.oidc_audience:
        payload["aud"] = _settings.oidc_audience
    return jwt.encode(payload, _settings.jwt_secret, algorithm="HS256")
