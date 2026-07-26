"""Pydantic request/response models for the CSPM API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AWSConnectRequest(BaseModel):
    provider: str = Field("aws", pattern="^aws$")
    label: str | None = None
    role_arn: str
    external_id: str | None = None


class GCPConnectRequest(BaseModel):
    provider: str = Field("gcp", pattern="^gcp$")
    label: str | None = None
    service_account_json: str


class AzureConnectRequest(BaseModel):
    provider: str = Field("azure", pattern="^azure$")
    label: str | None = None
    tenant_id: str
    client_id: str
    client_secret: str


class CloudAccountOut(BaseModel):
    """Cloud account — NEVER exposes secret fields."""

    id: str
    provider: str
    label: str | None
    status: str
    account_identifier: str | None = None
    last_validated_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanRunOut(BaseModel):
    id: str
    cloud_account_id: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    checks_run: int
    findings_count: int

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: str
    check_id: str
    resource: str | None
    severity: str
    description: str | None
    remediation: str | None
    status: str
    discovered_at: datetime

    model_config = {"from_attributes": True}


class FindingStatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|accepted_risk|resolved)$")


class DriftEventOut(BaseModel):
    id: str
    resource_type: str | None
    resource_id: str | None
    drift_type: str
    status: str
    detected_at: datetime

    model_config = {"from_attributes": True}
