"""Tamper-evident audit log (shared table).

Each entry stores the hash of the previous entry (per org) plus a hash of its
own content, forming a hash chain. Any edit/deletion of a historical row breaks
the chain, which :func:`verify_chain` detects — giving WORM-like integrity even
on ordinary storage.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy.orm import Session

from cspm.logging_config import get_logger
from cspm.shared.models import AuditLogEntry

_log = get_logger("cspm.audit")


def _entry_hash(entry: AuditLogEntry, prev_hash: str) -> str:
    payload = json.dumps(
        {
            "prev": prev_hash,
            "seq": entry.seq,
            "org_id": entry.org_id,
            "user_id": entry.user_id,
            "action": entry.action,
            "resource": entry.resource,
            "meta": entry.meta,
            "ip_addr": entry.ip_addr,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def record_action(
    db: Session,
    *,
    org_id: str | None,
    user_id: str | None,
    action: str,
    resource: str | None = None,
    meta: dict | None = None,
    ip_addr: str | None = None,
) -> None:
    """Append a hash-chained audit entry. Best-effort: never breaks the request."""
    try:
        prev = (
            db.query(AuditLogEntry)
            .filter_by(org_id=org_id)
            .order_by(AuditLogEntry.seq.desc())
            .first()
        )
        prev_hash = prev.entry_hash if prev and prev.entry_hash else "genesis"
        entry = AuditLogEntry(
            org_id=org_id,
            user_id=user_id,
            action=action,
            resource=resource,
            meta=meta,
            ip_addr=ip_addr,
            seq=(prev.seq + 1) if prev else 1,
        )
        db.add(entry)
        db.flush()  # assign ts default
        entry.prev_hash = prev_hash
        entry.entry_hash = _entry_hash(entry, prev_hash)
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        _log.exception("failed to write audit log for action=%s", action)


def verify_chain(db: Session, org_id: str) -> bool:
    """Recompute the chain for an org; return True if intact."""
    prev_hash = "genesis"
    entries = (
        db.query(AuditLogEntry)
        .filter_by(org_id=org_id)
        .order_by(AuditLogEntry.seq.asc())
        .all()
    )
    for e in entries:
        if e.prev_hash != prev_hash:
            return False
        if e.entry_hash != _entry_hash(e, prev_hash):
            return False
        prev_hash = e.entry_hash
    return True
