"""Minimal shared-schema tables CSPM references via foreign key.

Includes Multi-Tenant SaaS workspace models, SCIM, SSO, Team Members, and Tamper-Evident Audit Log.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cspm.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class Organisation(Base):
    __tablename__ = "organisations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    plan: Mapped[str] = mapped_column(String(50), default="starter")
    seats: Mapped[int] = mapped_column(Integer, default=5)
    logo_url: Mapped[str | None] = mapped_column(String(500))
    custom_domain: Mapped[str | None] = mapped_column(String(255))
    is_mssp: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    projects: Mapped[list[Project]] = relationship(back_populates="organisation", cascade="all, delete-orphan")


class Project(Base):
    """Projects within an organization."""

    __tablename__ = "cspm_projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    organisation: Mapped[Organisation] = relationship(back_populates="projects")
    environments: Mapped[list[Environment]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Environment(Base):
    """Environments (prod, staging, dev) within a project."""

    __tablename__ = "cspm_environments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("cspm_projects.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(50), nullable=False)  # prod, staging, dev
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped[Project] = relationship(back_populates="environments")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255))
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class OrgMembership(Base):
    """org_memberships — user↔org role binding."""

    __tablename__ = "org_memberships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="viewer")  # admin, analyst, viewer, auditor


class ApiKey(Base):
    """API keys for programmatic access. Only the hash is stored."""

    __tablename__ = "cspm_api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), nullable=False)
    name: Mapped[str] = mapped_column(String(255))
    prefix: Mapped[str] = mapped_column(String(12), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    role: Mapped[str] = mapped_column(String(50), default="analyst")
    rate_limit: Mapped[int] = mapped_column(Integer, default=1000)  # requests/hr
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(default=False)


class SSOConfig(Base):
    """Enterprise SSO Configuration (SAML 2.0 / Entra / Okta / Auth0)."""

    __tablename__ = "cspm_sso_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"), unique=True)
    provider_type: Mapped[str] = mapped_column(String(50), nullable=False)  # saml, entra, okta, auth0, google
    idp_entity_id: Mapped[str | None] = mapped_column(Text)
    sso_url: Mapped[str | None] = mapped_column(Text)
    certificate_pem: Mapped[str | None] = mapped_column(Text)
    domain: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class SCIMUser(Base):
    """SCIM provisioned users."""

    __tablename__ = "cspm_scim_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organisations.id", ondelete="CASCADE"))
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    user_name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuditLogEntry(Base):
    """audit_log — immutable record of user actions with SHA-256 tamper-evident hash chaining."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str | None] = mapped_column(String(36))
    user_id: Mapped[str | None] = mapped_column(String(36))
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource: Mapped[str | None] = mapped_column(String(255))
    meta: Mapped[dict | None] = mapped_column(JSON)
    ip_addr: Mapped[str | None] = mapped_column(String(64))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    seq: Mapped[int] = mapped_column(Integer, default=0, index=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str | None] = mapped_column(String(64))

    def compute_hash(self, prev: str | None = None) -> str:
        prev_str = prev or self.prev_hash or "GENESIS"
        payload = f"{self.id}:{self.org_id}:{self.user_id}:{self.action}:{self.resource}:{self.ts.isoformat()}:{prev_str}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
