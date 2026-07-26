"""Subscription plans, features, and quotas.

The plan catalog is the single source of truth for what each tier can do.
Feature gating and usage limits everywhere else read from here.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

UNLIMITED = -1  # sentinel for "no limit"


class Feature(str, enum.Enum):
    MULTI_CLOUD = "multi_cloud"          # connect GCP/Azure (AWS always allowed)
    DRIFT = "drift"                      # continuous drift detection
    INTEGRATIONS = "integrations"        # Slack/webhook/PagerDuty
    EVIDENCE_EXPORT = "evidence_export"  # auditor evidence
    TRENDS = "trends"                    # compliance trend history
    API_KEYS = "api_keys"               # programmatic access
    SSO_SCIM = "sso_scim"               # OIDC/SAML + SCIM provisioning
    PROWLER = "prowler"                 # Prowler check breadth
    AUTO_REMEDIATION = "auto_remediation"
    PRIORITY_SUPPORT = "priority_support"


@dataclass(frozen=True)
class Plan:
    id: str
    name: str
    price_usd_month: int
    blurb: str
    max_accounts: int
    max_scans_per_month: int
    max_api_keys: int
    frameworks: tuple[str, ...]          # ("all",) means every framework
    features: frozenset[Feature] = field(default_factory=frozenset)

    def has(self, feature: Feature) -> bool:
        return feature in self.features

    def allows_framework(self, framework: str) -> bool:
        return "all" in self.frameworks or framework in self.frameworks


_ALL = (
    Feature.MULTI_CLOUD, Feature.DRIFT, Feature.INTEGRATIONS, Feature.EVIDENCE_EXPORT,
    Feature.TRENDS, Feature.API_KEYS, Feature.SSO_SCIM, Feature.PROWLER,
    Feature.AUTO_REMEDIATION, Feature.PRIORITY_SUPPORT,
)

PLANS: dict[str, Plan] = {
    "free": Plan(
        id="free", name="Free", price_usd_month=0,
        blurb="Kick the tyres on one AWS account.",
        max_accounts=1, max_scans_per_month=10, max_api_keys=0,
        frameworks=("cis_aws_v2",), features=frozenset(),
    ),
    "starter": Plan(
        id="starter", name="Starter", price_usd_month=49,
        blurb="For small teams securing a few accounts.",
        max_accounts=3, max_scans_per_month=100, max_api_keys=2,
        frameworks=("cis_aws_v2", "soc2"),
        features=frozenset({Feature.DRIFT, Feature.API_KEYS}),
    ),
    "pro": Plan(
        id="pro", name="Pro", price_usd_month=299,
        blurb="Multi-cloud posture + compliance for growing orgs.",
        max_accounts=15, max_scans_per_month=1000, max_api_keys=10,
        frameworks=("all",),
        features=frozenset({
            Feature.MULTI_CLOUD, Feature.DRIFT, Feature.INTEGRATIONS,
            Feature.EVIDENCE_EXPORT, Feature.TRENDS, Feature.API_KEYS, Feature.PROWLER,
        }),
    ),
    "enterprise": Plan(
        id="enterprise", name="Enterprise", price_usd_month=0,  # custom / contact sales
        blurb="SSO, unlimited scale, and dedicated support.",
        max_accounts=UNLIMITED, max_scans_per_month=UNLIMITED, max_api_keys=UNLIMITED,
        frameworks=("all",), features=frozenset(_ALL),
    ),
}

DEFAULT_PLAN = "free"


def get_plan(plan_id: str | None) -> Plan:
    return PLANS.get(plan_id or DEFAULT_PLAN, PLANS[DEFAULT_PLAN])


def plan_public(plan: Plan) -> dict:
    """Serialize a plan for the pricing page."""
    return {
        "id": plan.id,
        "name": plan.name,
        "price_usd_month": plan.price_usd_month,
        "blurb": plan.blurb,
        "custom_pricing": plan.id == "enterprise",
        "limits": {
            "max_accounts": plan.max_accounts,
            "max_scans_per_month": plan.max_scans_per_month,
            "max_api_keys": plan.max_api_keys,
            "frameworks": list(plan.frameworks),
        },
        "features": [f.value for f in _ALL if f in plan.features],
    }
