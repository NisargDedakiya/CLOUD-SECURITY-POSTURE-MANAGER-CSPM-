"""CSPM & CNAPP ORM models — mirrors the enterprise DB schema.

Includes CSPM, CIEM, Attack Path Analysis, Multi-Cloud Asset Inventory,
Kubernetes Security, IaC Scanning, DevSecOps integrations, and MSSP management.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
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
    return datetime.now(UTC)


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
    K8S = "kubernetes"


class CloudAccount(Base):
    """cspm_cloud_accounts — a connected AWS/GCP/Azure/K8s account."""

    __tablename__ = "cspm_cloud_accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organisations.id", ondelete="CASCADE")
    )
    environment_id: Mapped[str | None] = mapped_column(String(36))
    provider: Mapped[str] = mapped_column(String(20), nullable=False)
    label: Mapped[str | None] = mapped_column(String(255))
    environment_name: Mapped[str] = mapped_column(String(50), default="production")  # production, staging, development

    # AWS
    role_arn: Mapped[str | None] = mapped_column(Text)
    external_id: Mapped[str | None] = mapped_column(String(100))
    # GCP (AES-256 encrypted service-account JSON)
    gcp_sa_key_enc: Mapped[str | None] = mapped_column(Text)
    # Azure
    azure_tenant_id: Mapped[str | None] = mapped_column(String(100))
    azure_client_id: Mapped[str | None] = mapped_column(String(100))
    azure_secret_enc: Mapped[str | None] = mapped_column(Text)
    azure_subscription_id: Mapped[str | None] = mapped_column(String(100))

    status: Mapped[str] = mapped_column(String(20), default="pending")
    last_validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scan_runs: Mapped[list[ScanRun]] = relationship(
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
    findings: Mapped[list[FindingRecord]] = relationship(
        back_populates="scan_run", cascade="all, delete-orphan"
    )


class FindingRecord(Base):
    """cspm_findings — a single misconfiguration or security finding."""

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
    resource_type: Mapped[str | None] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20))
    description: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="open")
    dedup_hash: Mapped[str] = mapped_column(String(64), unique=True)

    # AI Security Copilot Fields
    ai_explanation: Mapped[str | None] = mapped_column(Text)
    ai_root_cause: Mapped[str | None] = mapped_column(Text)
    ai_cli_fix: Mapped[str | None] = mapped_column(Text)
    ai_console_fix: Mapped[str | None] = mapped_column(Text)
    ai_terraform_fix: Mapped[str | None] = mapped_column(Text)
    ai_estimated_effort: Mapped[str | None] = mapped_column(String(50))
    exploitability_score: Mapped[float] = mapped_column(Float, default=0.0)

    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan_run: Mapped[ScanRun] = relationship(back_populates="findings")


class AssetRecord(Base):
    """cspm_assets — unified cloud asset inventory item."""

    __tablename__ = "cspm_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"), index=True)
    cloud_account_id: Mapped[str] = mapped_column(String(36), index=True)
    provider: Mapped[str] = mapped_column(String(20))  # aws, gcp, azure, k8s
    category: Mapped[str] = mapped_column(String(50))  # compute, storage, database, iam, network, container, serverless, k8s
    resource_id: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(String(255))
    region: Mapped[str | None] = mapped_column(String(50))
    environment: Mapped[str] = mapped_column(String(50), default="production")
    owner: Mapped[str | None] = mapped_column(String(255))
    business_unit: Mapped[str | None] = mapped_column(String(255))
    criticality: Mapped[str] = mapped_column(String(20), default="medium")  # high, medium, low, critical
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=True)
    tags: Mapped[dict | None] = mapped_column(JSON)
    metadata_info: Mapped[dict | None] = mapped_column(JSON)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AttackPathChain(Base):
    """cspm_attack_paths — graph of exploitable attack chains."""

    __tablename__ = "cspm_attack_paths"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    entry_point: Mapped[str] = mapped_column(String(255))
    target_resource: Mapped[str] = mapped_column(String(255))
    risk_score: Mapped[float] = mapped_column(Float, default=9.0)
    steps: Mapped[list] = mapped_column(JSON)  # list of node step dicts
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CIEMRecord(Base):
    """cspm_ciem_records — CIEM entitlement & identity risk findings."""

    __tablename__ = "cspm_ciem_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"))
    cloud_account_id: Mapped[str] = mapped_column(String(36))
    identity_name: Mapped[str] = mapped_column(String(255))
    identity_type: Mapped[str] = mapped_column(String(50))  # role, user, service_account
    risk_type: Mapped[str] = mapped_column(String(100))  # privilege_escalation, excessive_permissions, unused_role, dormant_account, risky_trust
    risk_score: Mapped[float] = mapped_column(Float, default=7.5)
    details: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="open")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class IaCScanResult(Base):
    """cspm_iac_scans — Infrastructure as Code static scan result."""

    __tablename__ = "cspm_iac_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"))
    repository: Mapped[str | None] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(String(500))
    iac_type: Mapped[str] = mapped_column(String(50))  # terraform, cloudformation, bicep, pulumi
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    issues: Mapped[list] = mapped_column(JSON)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class K8sClusterScan(Base):
    """cspm_k8s_scans — Kubernetes cluster posture scan."""

    __tablename__ = "cspm_k8s_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"))
    cluster_name: Mapped[str] = mapped_column(String(255))
    distro: Mapped[str] = mapped_column(String(50))  # eks, aks, gke, custom
    score: Mapped[float] = mapped_column(Float, default=100.0)
    privileged_pods: Mapped[int] = mapped_column(Integer, default=0)
    rbac_violations: Mapped[int] = mapped_column(Integer, default=0)
    missing_net_policies: Mapped[int] = mapped_column(Integer, default=0)
    exposed_secrets: Mapped[int] = mapped_column(Integer, default=0)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class TicketIntegration(Base):
    """cspm_ticket_integrations — Jira / ServiceNow / Linear / Azure Boards."""

    __tablename__ = "cspm_ticket_integrations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(50))  # jira, servicenow, linear, azure_boards
    config: Mapped[dict] = mapped_column(JSON)
    auto_sync: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ComplianceMapping(Base):
    """compliance_mappings — static seed: check_id → framework → control_id."""

    __tablename__ = "compliance_mappings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    check_id: Mapped[str] = mapped_column(String(100), nullable=False)
    framework: Mapped[str] = mapped_column(String(50), nullable=False)
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)


class Baseline(Base):
    """cspm_baselines — approved config snapshot per resource."""

    __tablename__ = "cspm_baselines"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    cloud_account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cspm_cloud_accounts.id", ondelete="CASCADE")
    )
    resource_type: Mapped[str | None] = mapped_column(String(100))
    resource_id: Mapped[str | None] = mapped_column(Text)
    config_snapshot: Mapped[dict] = mapped_column(JSON)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Subscription(Base):
    """cspm_subscriptions — an org's plan + Stripe/Razorpay linkage."""

    __tablename__ = "cspm_subscriptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organisations.id", ondelete="CASCADE"), unique=True
    )
    plan: Mapped[str] = mapped_column(String(50), default="starter")  # free, starter, pro, business, enterprise, mssp
    billing_cycle: Mapped[str] = mapped_column(String(20), default="monthly")  # monthly, annual
    status: Mapped[str] = mapped_column(String(30), default="active")
    stripe_customer_id: Mapped[str | None] = mapped_column(String(255))
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(255))
    razorpay_customer_id: Mapped[str | None] = mapped_column(String(255))
    razorpay_subscription_id: Mapped[str | None] = mapped_column(String(255))
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trial_used: Mapped[bool] = mapped_column(default=False)
    coupon_code: Mapped[str | None] = mapped_column(String(50))
    seats: Mapped[int] = mapped_column(Integer, default=5)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ComplianceSnapshot(Base):
    """cspm_compliance_snapshots — per-scan framework score."""

    __tablename__ = "cspm_compliance_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    cloud_account_id: Mapped[str] = mapped_column(String(36))
    scan_run_id: Mapped[str | None] = mapped_column(String(36))
    framework: Mapped[str] = mapped_column(String(50))
    score: Mapped[float] = mapped_column()
    checks_passed: Mapped[int] = mapped_column(Integer, default=0)
    checks_applicable: Mapped[int] = mapped_column(Integer, default=0)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class DriftEvent(Base):
    """cspm_drift_events — detected configuration changes."""

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
    rollback_cli: Mapped[str | None] = mapped_column(Text)
    rollback_terraform: Mapped[str | None] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class MSSPClientMapping(Base):
    """cspm_mssp_clients — Agency portal customer mappings."""

    __tablename__ = "cspm_mssp_clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    mssp_org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"))
    client_org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"))
    client_name: Mapped[str] = mapped_column(String(255), nullable=False)
    branding_logo: Mapped[str | None] = mapped_column(String(500))
    branding_color: Mapped[str | None] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class InvoiceRecord(Base):
    """cspm_invoices — generated PDF/JSON invoices."""

    __tablename__ = "cspm_invoices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"))
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    currency: Mapped[str] = mapped_column(String(10), default="USD")
    tax_amount: Mapped[float] = mapped_column(Float, default=0.0)
    tax_type: Mapped[str | None] = mapped_column(String(20))  # GST, VAT
    status: Mapped[str] = mapped_column(String(20), default="paid")
    pdf_url: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AlertPolicy(Base):
    """cspm_alert_policies — custom alert rules."""

    __tablename__ = "cspm_alert_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    channel: Mapped[str] = mapped_column(String(50))  # email, slack, teams, discord, pagerduty, opsgenie, webhook
    min_severity: Mapped[str] = mapped_column(String(20), default="high")
    condition: Mapped[str] = mapped_column(String(50), default="critical_only")  # critical_only, compliance_failures, daily_summary, weekly_summary
    target_destination: Mapped[str] = mapped_column(String(500))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
