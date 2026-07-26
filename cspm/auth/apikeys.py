"""API keys for programmatic access.

A key is shown once at creation as ``cspm_<prefix>_<secret>``; only its SHA-256
hash is stored. Lookups are by prefix then constant-time hash comparison.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from cspm.shared.models import ApiKey

_PREFIX_LEN = 8


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def create_api_key(
    db: Session, org_id: str, name: str, role: str = "analyst"
) -> tuple[ApiKey, str]:
    """Create a key; returns (record, plaintext). Plaintext is never stored."""
    prefix = secrets.token_hex(_PREFIX_LEN // 2)
    secret = secrets.token_urlsafe(32)
    plaintext = f"cspm_{prefix}_{secret}"
    record = ApiKey(
        org_id=org_id,
        name=name,
        prefix=prefix,
        key_hash=_hash(plaintext),
        role=role,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record, plaintext


def verify_api_key(db: Session, plaintext: str) -> ApiKey | None:
    """Return the matching, non-revoked ApiKey or None."""
    parts = plaintext.split("_")
    if len(parts) < 3 or parts[0] != "cspm":
        return None
    prefix = parts[1]
    candidate = (
        db.query(ApiKey).filter_by(prefix=prefix, revoked=False).one_or_none()
    )
    if candidate is None:
        return None
    if not hmac.compare_digest(candidate.key_hash, _hash(plaintext)):
        return None
    candidate.last_used_at = datetime.now(UTC)
    db.commit()
    return candidate
