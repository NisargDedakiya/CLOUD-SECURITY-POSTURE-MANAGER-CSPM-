"""CSPM ORM models — mirrors the DB schema in spec Section 4.

Portable across Postgres and SQLite: UUIDs are stored as strings and JSONB as
the SQLAlchemy ``JSON`` type (which maps to JSONB on Postgres).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cspm.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Provider(str, enum.Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class CloudAccount(Base):
    """cspm_cloud_accounts — a connected AWS/GCP/Azure account (Module 6.1)."""

    __tablename__ = "cspm_cloud_accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organisations.id", ondelete="CASCADE")
    )
    provider: Mapped[str] = mapped_column(String(20), nullable=False)
    label: Mapped[str | None] = mapped_column(String(255))

    # AWS
    role_arn: Mapped[str | None] = mapped_column(Text)
    external_id: Mapped[str | None] = mapped_column(String(100))
    # GCP (AES-256 encrypted service-account JSON)
    gcp_sa_key_enc: Mapped[str | None] = mapped_column(Text)
    # Azure
    azure_tenant_id: Mapped[str | None] = mapped_column(String(100))
    azure_client_id: Mapped[str | None] = mapped_column(String(100))
    azure_secret_enc: Mapped[str | None] = mapped_column(Text)

    status: Mapped[str] = mapped_column(String(20), default="pending")
    last_validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scan_runs: Mapped[list["ScanRun"]] = relationship(
        back_populates="cloud_account", cascade="all, delete-orphan"
    )


class ScanRun(Base):
    """cspm_scan_runs — one audit execution against a cloud account."""

    __tablename__ = "cspm_scan_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    cloud_account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cspm_cloud_accounts.id", ondelete="CASCADE")
    )
    status: Mapped[str] = mapped_column(String(20), default="queued")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    checks_run: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    cloud_account: Mapped[CloudAccount] = relationship(back_populates="scan_runs")
    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="scan_run", cascade="all, delete-orphan"
    )


class FindingRecord(Base):
    """cspm_findings — a single misconfiguration finding."""

    __tablename__ = "cspm_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id"))
    cloud_account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cspm_cloud_accounts.id")
    )
    scan_run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("cspm_scan_runs.id"), nullable=True
    )
    check_id: Mapped[str] = mapped_column(String(100))
    resource: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    description: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="open")
    dedup_hash: Mapped[str] = mapped_column(String(64), unique=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan_run: Mapped[ScanRun] = relationship(back_populates="findings")


class ComplianceMapping(Base):
    """compliance_mappings — static seed: check_id → framework → control_id."""

    __tablename__ = "compliance_mappings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    check_id: Mapped[str] = mapped_column(String(100), nullable=False)
    framework: Mapped[str] = mapped_column(String(50), nullable=False)
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)


class Baseline(Base):
    """cspm_baselines — approved config snapshot per resource (Module 6.4)."""

    __tablename__ = "cspm_baselines"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    cloud_account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cspm_cloud_accounts.id", ondelete="CASCADE")
    )
    resource_type: Mapped[str | None] = mapped_column(String(100))
    resource_id: Mapped[str | None] = mapped_column(Text)
    config_snapshot: Mapped[dict] = mapped_column(JSON)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class DriftEvent(Base):
    """cspm_drift_events — a detected configuration change (Module 6.4)."""

    __tablename__ = "cspm_drift_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id"))
    cloud_account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cspm_cloud_accounts.id")
    )
    resource_type: Mapped[str | None] = mapped_column(String(100))
    resource_id: Mapped[str | None] = mapped_column(Text)
    drift_type: Mapped[str] = mapped_column(String(30))
    before_state: Mapped[dict | None] = mapped_column(JSON)
    after_state: Mapped[dict | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="pending_review")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
