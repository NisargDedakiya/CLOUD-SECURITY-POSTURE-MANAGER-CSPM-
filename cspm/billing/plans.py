"""Subscription plans, features, and quotas for Aegis CNAPP.

Defines the 6 pricing tiers: Community (Free), Starter ($49), Professional ($299),
Business ($999), Enterprise (Custom), and MSSP (Custom).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

UNLIMITED = -1


class Feature(str, enum.Enum):
    MULTI_CLOUD = "multi_cloud"          # connect AWS/GCP/Azure/K8s
    DRIFT = "drift"                      # continuous drift detection & rollback
    INTEGRATIONS = "integrations"        # Slack/Teams/Discord/PagerDuty/Opsgenie
    EVIDENCE_EXPORT = "evidence_export"  # auditor evidence & multi-format reports
    TRENDS = "trends"                    # compliance trend history
    API_KEYS = "api_keys"               # programmatic REST & GraphQL access
    SSO_SCIM = "sso_scim"               # SAML 2.0/Entra/Okta/Auth0 + SCIM
    PROWLER = "prowler"                 # deep check breadth
    AUTO_REMEDIATION = "auto_remediation"
    PRIORITY_SUPPORT = "priority_support"
    CIEM = "ciem"                       # Cloud Infrastructure Entitlement Management
    ATTACK_PATH = "attack_path"         # Attack Path Analysis
    IAC_SCANNING = "iac_scanning"       # Infrastructure as Code Static Analysis
    K8S_SECURITY = "k8s_security"       # Kubernetes Pod Security & RBAC
    AI_COPILOT = "ai_copilot"           # AI Security Copilot Remediation & NL Search
    MSSP_PORTAL = "mssp_portal"         # Multi-client Agency Portal & White-labeling


@dataclass(frozen=True)
class Plan:
    id: str
    name: str
    price_usd_month: int
    price_usd_annual: int
    blurb: str
    target_audience: str
    max_accounts: int
    max_scans_per_month: int
    max_api_keys: int
    max_seats: int
    frameworks: tuple[str, ...]
    features: frozenset[Feature] = field(default_factory=frozenset)

    def has(self, feature: Feature) -> bool:
        return feature in self.features

    def allows_framework(self, framework: str) -> bool:
        return "all" in self.frameworks or framework in self.frameworks


_ALL = tuple(Feature)

PLANS: dict[str, Plan] = {
    "free": Plan(
        id="free", name="Community", price_usd_month=0, price_usd_annual=0,
        blurb="Learning & Open Source cloud security posture check.",
        target_audience="Learning & Open Source",
        max_accounts=1, max_scans_per_month=10, max_api_keys=0, max_seats=2,
        frameworks=("cis_aws_v2",), features=frozenset(),
    ),
    "starter": Plan(
        id="starter", name="Starter", price_usd_month=49, price_usd_annual=470,
        blurb="For small startups securing core cloud assets.",
        target_audience="Small startups",
        max_accounts=3, max_scans_per_month=100, max_api_keys=3, max_seats=5,
        frameworks=("cis_aws_v2", "soc2"),
        features=frozenset({Feature.DRIFT, Feature.API_KEYS, Feature.IAC_SCANNING}),
    ),
    "pro": Plan(
        id="pro", name="Professional", price_usd_month=299, price_usd_annual=2870,
        blurb="Multi-cloud posture + compliance for growing SaaS teams.",
        target_audience="Growing SaaS companies",
        max_accounts=15, max_scans_per_month=1000, max_api_keys=10, max_seats=15,
        frameworks=("all",),
        features=frozenset({
            Feature.MULTI_CLOUD, Feature.DRIFT, Feature.INTEGRATIONS,
            Feature.EVIDENCE_EXPORT, Feature.TRENDS, Feature.API_KEYS, Feature.PROWLER,
            Feature.IAC_SCANNING, Feature.K8S_SECURITY, Feature.AI_COPILOT,
        }),
    ),
    "business": Plan(
        id="business", name="Business", price_usd_month=999, price_usd_annual=9590,
        blurb="Full CNAPP platform with CIEM and Attack Path Analysis.",
        target_audience="Mid-market organizations",
        max_accounts=50, max_scans_per_month=5000, max_api_keys=25, max_seats=50,
        frameworks=("all",),
        features=frozenset({
            Feature.MULTI_CLOUD, Feature.DRIFT, Feature.INTEGRATIONS,
            Feature.EVIDENCE_EXPORT, Feature.TRENDS, Feature.API_KEYS, Feature.PROWLER,
            Feature.AUTO_REMEDIATION, Feature.SSO_SCIM, Feature.CIEM, Feature.ATTACK_PATH,
            Feature.IAC_SCANNING, Feature.K8S_SECURITY, Feature.AI_COPILOT,
        }),
    ),
    "enterprise": Plan(
        id="enterprise", name="Enterprise", price_usd_month=0, price_usd_annual=0,
        blurb="Unlimited scale, dedicated support, custom SLAs.",
        target_audience="Large enterprises",
        max_accounts=UNLIMITED, max_scans_per_month=UNLIMITED, max_api_keys=UNLIMITED, max_seats=UNLIMITED,
        frameworks=("all",), features=frozenset(_ALL),
    ),
    "mssp": Plan(
        id="mssp", name="MSSP Partner", price_usd_month=0, price_usd_annual=0,
        blurb="Dedicated agency portal, white-labeling, client management.",
        target_audience="Managed security providers",
        max_accounts=UNLIMITED, max_scans_per_month=UNLIMITED, max_api_keys=UNLIMITED, max_seats=UNLIMITED,
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
        "price_usd_annual": plan.price_usd_annual,
        "blurb": plan.blurb,
        "target_audience": plan.target_audience,
        "custom_pricing": plan.id in ("enterprise", "mssp"),
        "limits": {
            "max_accounts": plan.max_accounts,
            "max_scans_per_month": plan.max_scans_per_month,
            "max_api_keys": plan.max_api_keys,
            "max_seats": plan.max_seats,
            "frameworks": list(plan.frameworks),
        },
        "features": [f.value for f in _ALL if f in plan.features],
    }
