"""Helper to write immutable audit-log entries (shared table)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from cspm.logging_config import get_logger
from cspm.shared.models import AuditLogEntry

_log = get_logger("cspm.audit")


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
    """Append an audit entry. Best-effort: never breaks the request path."""
    try:
        db.add(
            AuditLogEntry(
                org_id=org_id,
                user_id=user_id,
                action=action,
                resource=resource,
                meta=meta,
                ip_addr=ip_addr,
            )
        )
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        _log.exception("failed to write audit log for action=%s", action)
