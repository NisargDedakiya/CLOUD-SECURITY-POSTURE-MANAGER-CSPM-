"""GCP Security Audit Engine (follow-on to AWS, spec Step 5).

Mirrors the AWS class-based ``check_*`` pattern. A collector object may be
injected for testing; in production it wraps google-cloud client libraries
authenticated from the stored service-account key.
"""

from __future__ import annotations

from datetime import UTC

from cspm.auditors.base import BaseAuditor
from cspm.auditors.findings import Finding


class GCPAuditor(BaseAuditor):
    provider = "gcp"

    def __init__(self, service_account_json: str | None = None, collector=None) -> None:
        self.service_account_json = service_account_json
        # collector exposes: buckets(), firewalls(), instances(), service_accounts()
        self.collector = collector or _LiveGCPCollector(service_account_json)

    def check_bucket_public_access(self) -> list[Finding]:
        findings = []
        for b in self.collector.buckets():
            members = set(b.get("iam_members", []))
            if members & {"allUsers", "allAuthenticatedUsers"}:
                findings.append(
                    Finding(
                        resource=b["name"],
                        check="Cloud Storage bucket is publicly accessible",
                        check_id="gcp_bucket_public",
                        severity="critical",
                        remediation="Remove allUsers/allAuthenticatedUsers from the bucket IAM policy.",
                    )
                )
        return findings

    def check_bucket_uniform_access(self) -> list[Finding]:
        findings = []
        for b in self.collector.buckets():
            if not b.get("uniform_bucket_level_access"):
                findings.append(
                    Finding(
                        resource=b["name"],
                        check="Bucket does not enforce uniform bucket-level access",
                        check_id="gcp_bucket_ubla",
                        severity="medium",
                        remediation="Enable uniform bucket-level access to disable ACLs.",
                    )
                )
        return findings

    def check_firewall_open_ingress(self) -> list[Finding]:
        findings = []
        for fw in self.collector.firewalls():
            if fw.get("direction", "INGRESS") != "INGRESS":
                continue
            if "0.0.0.0/0" not in fw.get("source_ranges", []):
                continue
            ports = {p for a in fw.get("allowed", []) for p in a.get("ports", [])}
            if {"22", "3389"} & ports or not ports:
                findings.append(
                    Finding(
                        resource=fw["name"],
                        check="Firewall allows 0.0.0.0/0 to management ports",
                        check_id="gcp_firewall_open",
                        severity="high",
                        remediation="Restrict source ranges for SSH/RDP to trusted networks.",
                    )
                )
        return findings

    def check_instance_public_ip(self) -> list[Finding]:
        findings = []
        for inst in self.collector.instances():
            if inst.get("has_public_ip"):
                findings.append(
                    Finding(
                        resource=inst["name"],
                        check="Compute instance has an external IP",
                        check_id="gcp_instance_public_ip",
                        severity="medium",
                        remediation="Remove the external IP; use Cloud NAT / IAP instead.",
                    )
                )
        return findings

    def check_sa_key_rotation(self) -> list[Finding]:
        findings = []
        for sa in self.collector.service_accounts():
            max_age = max((k.get("age_days", 0) for k in sa.get("keys", [])), default=0)
            if max_age >= 90:
                findings.append(
                    Finding(
                        resource=sa["email"],
                        check="Service account key older than 90 days",
                        check_id="gcp_sa_key_age",
                        severity="medium",
                        remediation="Rotate and delete service-account keys older than 90 days.",
                    )
                )
        return findings

    def check_sql_public_ip(self) -> list[Finding]:
        findings = []
        for inst in self.collector.sql_instances():
            if inst.get("public_ip"):
                findings.append(
                    Finding(
                        resource=inst["name"],
                        check="Cloud SQL instance has a public IP",
                        check_id="gcp_sql_public_ip",
                        severity="high",
                        remediation="Disable the public IP; use Private Service Connect / private IP.",
                    )
                )
        return findings

    def check_audit_logging(self) -> list[Finding]:
        cfg = self.collector.audit_config()
        if not cfg.get("all_services_data_access"):
            return [
                Finding(
                    resource=f"project/{cfg.get('project', 'unknown')}",
                    check="Project audit logging not fully enabled",
                    check_id="gcp_audit_logging",
                    severity="medium",
                    remediation="Enable Data Access audit logs for all services in the IAM policy.",
                )
            ]
        return []

    def resource_snapshots(self) -> dict[str, dict]:
        snaps: dict[str, dict] = {}
        for b in self.collector.buckets():
            snaps[f"gcs:{b['name']}"] = {"type": "storage_bucket", **b}
        for fw in self.collector.firewalls():
            snaps[f"fw:{fw['name']}"] = {"type": "firewall_rule", **fw}
        return snaps


class _LiveGCPCollector:  # pragma: no cover - requires google-cloud + creds
    """Live GCP collector backed by google-cloud-storage + the discovery API.

    Install with ``pip install -e ".[gcp]"``. Credentials are built from the
    connected service-account JSON; only read-only scopes are requested.
    """

    _SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]

    def __init__(self, service_account_json: str | None) -> None:
        if not service_account_json:
            raise ValueError("service_account_json required for live GCP auditing.")
        import json

        from google.oauth2 import service_account

        self._info = json.loads(service_account_json)
        self.project = self._info["project_id"]
        self._creds = service_account.Credentials.from_service_account_info(
            self._info, scopes=self._SCOPES
        )

    def _compute(self):
        from googleapiclient.discovery import build

        return build("compute", "v1", credentials=self._creds, cache_discovery=False)

    def _iam(self):
        from googleapiclient.discovery import build

        return build("iam", "v1", credentials=self._creds, cache_discovery=False)

    def buckets(self) -> list[dict]:
        from google.cloud import storage

        client = storage.Client(project=self.project, credentials=self._creds)
        out = []
        for bucket in client.list_buckets():
            policy = bucket.get_iam_policy(requested_policy_version=3)
            members: set[str] = set()
            for binding in policy.bindings:
                members |= set(binding.get("members", []))
            ubla = bool(
                getattr(bucket.iam_configuration, "uniform_bucket_level_access_enabled", False)
            )
            out.append(
                {"name": bucket.name, "iam_members": list(members), "uniform_bucket_level_access": ubla}
            )
        return out

    def firewalls(self) -> list[dict]:
        svc = self._compute()
        out = []
        req = svc.firewalls().list(project=self.project)
        while req is not None:
            resp = req.execute()
            for fw in resp.get("items", []):
                out.append(
                    {
                        "name": fw["name"],
                        "direction": fw.get("direction", "INGRESS"),
                        "source_ranges": fw.get("sourceRanges", []),
                        "allowed": fw.get("allowed", []),
                    }
                )
            req = svc.firewalls().list_next(req, resp)
        return out

    def instances(self) -> list[dict]:
        svc = self._compute()
        out = []
        req = svc.instances().aggregatedList(project=self.project)
        while req is not None:
            resp = req.execute()
            for _zone, scoped in resp.get("items", {}).items():
                for inst in scoped.get("instances", []):
                    has_public = any(
                        ac.get("natIP")
                        for nic in inst.get("networkInterfaces", [])
                        for ac in nic.get("accessConfigs", [])
                    )
                    out.append({"name": inst["name"], "has_public_ip": has_public})
            req = svc.instances().aggregatedList_next(req, resp)
        return out

    def service_accounts(self) -> list[dict]:
        from datetime import datetime

        iam = self._iam()
        out = []
        resp = (
            iam.projects()
            .serviceAccounts()
            .list(name=f"projects/{self.project}")
            .execute()
        )
        for sa in resp.get("accounts", []):
            keys_resp = (
                iam.projects()
                .serviceAccounts()
                .keys()
                .list(name=sa["name"], keyTypes="USER_MANAGED")
                .execute()
            )
            keys = []
            for k in keys_resp.get("keys", []):
                valid = k.get("validAfterTime")
                age = 0
                if valid:
                    created = datetime.fromisoformat(valid.replace("Z", "+00:00"))
                    age = (datetime.now(UTC) - created).days
                keys.append({"age_days": age})
            out.append({"email": sa["email"], "keys": keys})
        return out

    def sql_instances(self) -> list[dict]:
        from googleapiclient.discovery import build

        svc = build("sqladmin", "v1beta4", credentials=self._creds, cache_discovery=False)
        out = []
        for inst in svc.instances().list(project=self.project).execute().get("items", []):
            ip_cfg = inst.get("settings", {}).get("ipConfiguration", {})
            out.append({"name": inst["name"], "public_ip": ip_cfg.get("ipv4Enabled", False)})
        return out

    def audit_config(self) -> dict:
        from googleapiclient.discovery import build

        crm = build("cloudresourcemanager", "v1", credentials=self._creds, cache_discovery=False)
        policy = crm.projects().getIamPolicy(resource=self.project, body={}).execute()
        all_svcs = any(
            a.get("service") == "allServices"
            and any(c.get("logType") == "DATA_READ" for c in a.get("auditLogConfigs", []))
            for a in policy.get("auditConfigs", [])
        )
        return {"project": self.project, "all_services_data_access": all_svcs}
