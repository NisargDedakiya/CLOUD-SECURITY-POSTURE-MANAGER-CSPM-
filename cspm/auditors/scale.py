"""Scale helpers: AWS Organizations discovery + throttling backoff.

Lets one connected management account fan out to every member account in an AWS
Organization, with an explicit concurrency cap and exponential backoff so large
multi-account audits don't trip API throttling.
"""

from __future__ import annotations

import time

from cspm.config import get_settings
from cspm.logging_config import get_logger

_log = get_logger("cspm.scale")
_settings = get_settings()


def boto_config():  # pragma: no cover - requires botocore
    """A botocore Config with adaptive retries (throttling backoff)."""
    from botocore.config import Config

    return Config(
        retries={"max_attempts": _settings.scan_max_retries, "mode": "adaptive"},
        max_pool_connections=_settings.audit_concurrency,
    )


def with_backoff(fn, *args, **kwargs):
    """Call ``fn`` retrying on throttling with exponential backoff."""
    from botocore.exceptions import ClientError

    attempts = _settings.scan_max_retries
    for i in range(attempts):
        try:
            return fn(*args, **kwargs)
        except ClientError as exc:  # pragma: no cover - needs AWS
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"Throttling", "ThrottlingException", "RequestLimitExceeded"} and i < attempts - 1:
                delay = _settings.scan_backoff_base ** i
                _log.warning("throttled (%s); backing off %.1fs", code, delay)
                time.sleep(delay)
                continue
            raise


def discover_org_accounts(session) -> list[dict]:  # pragma: no cover - needs AWS
    """List all ACTIVE accounts in the organization of the given session."""
    org = session.client("organizations", config=boto_config())
    accounts: list[dict] = []
    paginator = org.get_paginator("list_accounts")
    for page in paginator.paginate():
        for acct in page.get("Accounts", []):
            if acct.get("Status") == "ACTIVE":
                accounts.append({"id": acct["Id"], "name": acct.get("Name", "")})
    return accounts


def member_role_arn(account_id: str, role_name: str = "Track2CSPMAuditRole") -> str:
    """Standard cross-account role ARN convention for member-account auditing."""
    return f"arn:aws:iam::{account_id}:role/{role_name}"
