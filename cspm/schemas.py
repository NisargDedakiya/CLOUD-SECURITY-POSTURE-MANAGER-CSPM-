"""Pydantic request/response models for the CSPM & CNAPP API."""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


class AWSConnectRequest(BaseModel):
    provider: str = Field("aws", pattern="^aws$")
    label: str | None = None
    role_arn: str
    external_id: str | None = None
    environment_name: str = "production"


class GCPConnectRequest(BaseModel):
    provider: str = Field("gcp", pattern="^gcp$")
    label: str | None = None
    service_account_json: str
    environment_name: str = "production"


class AzureConnectRequest(BaseModel):
    provider: str = Field("azure", pattern="^azure$")
    label: str | None = None
    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str
    environment_name: str = "production"


class CloudAccountOut(BaseModel):
    """Cloud account — NEVER exposes secret fields."""

    id: str
    provider: str
    label: str | None
    status: str
    environment_name: str = "production"
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
    resource_type: str | None = None
    severity: str
    description: str | None
    remediation: str | None
    status: str
    ai_explanation: str | None = None
    ai_root_cause: str | None = None
    ai_cli_fix: str | None = None
    ai_console_fix: str | None = None
    ai_terraform_fix: str | None = None
    ai_estimated_effort: str | None = None
    exploitability_score: float = 0.0
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
    rollback_cli: str | None = None
    rollback_terraform: str | None = None
    detected_at: datetime

    model_config = {"from_attributes": True}


class AssetOut(BaseModel):
    id: str
    cloud_account_id: str
    provider: str
    category: str
    resource_id: str
    name: str
    region: str | None
    environment: str
    owner: str | None
    business_unit: str | None
    criticality: str
    is_internet_facing: bool
    is_encrypted: bool
    tags: dict | None = None
    metadata_info: dict | None = None

    model_config = {"from_attributes": True}


class AttackPathOut(BaseModel):
    id: str
    title: str
    entry_point: str
    target_resource: str
    risk_score: float
    steps: list

    model_config = {"from_attributes": True}


class CIEMRecordOut(BaseModel):
    id: str
    identity_name: str
    identity_type: str
    risk_type: str
    risk_score: float
    details: dict
    status: str

    model_config = {"from_attributes": True}


class IaCScanRequest(BaseModel):
    repository: str | None = "main-repo"
    file_path: str
    iac_type: str  # terraform, cloudformation, bicep, pulumi
    content: str


class K8sScanRequest(BaseModel):
    cluster_name: str
    distro: str = "eks"  # eks, aks, gke, custom
    manifests: list[dict] = []


class SSOConfigCreate(BaseModel):
    provider_type: str = Field(pattern="^(saml|entra|okta|auth0|google)$")
    idp_entity_id: str
    sso_url: str
    certificate_pem: str | None = None
    domain: str | None = None


class TicketIntegrationCreate(BaseModel):
    provider: str = Field(pattern="^(jira|servicenow|linear|azure_boards)$")
    config: dict
    auto_sync: bool = True
