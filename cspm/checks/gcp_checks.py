"""GCP security posture checks."""

from __future__ import annotations

from cspm.checks.base import Check
from cspm.models import Cloud, Resource, Severity


class StorageBucketPublicCheck(Check):
    check_id = "GCP_BUCKET_PUBLIC"
    title = "Cloud Storage bucket is not public"
    cloud = Cloud.GCP
    resource_type = "storage_bucket"
    severity = Severity.CRITICAL
    description = "Cloud Storage buckets must not grant access to allUsers/allAuthenticatedUsers."
    remediation = "Remove 'allUsers' and 'allAuthenticatedUsers' from the bucket IAM policy."

    def evaluate(self, resource: Resource) -> bool:
        members = resource.properties.get("iam_members", [])
        public = {"allUsers", "allAuthenticatedUsers"}
        return not public.intersection(members)


class StorageBucketUBLACheck(Check):
    check_id = "GCP_BUCKET_UBLA"
    title = "Bucket enforces uniform bucket-level access"
    cloud = Cloud.GCP
    resource_type = "storage_bucket"
    severity = Severity.MEDIUM
    description = "Buckets should enforce uniform bucket-level access to disable ACLs."
    remediation = "Enable uniform bucket-level access on the bucket."

    def evaluate(self, resource: Resource) -> bool:
        return bool(resource.properties.get("uniform_bucket_level_access"))


class FirewallOpenRDPCheck(Check):
    check_id = "GCP_FIREWALL_OPEN_RDP"
    title = "Firewall does not allow 0.0.0.0/0 to RDP"
    cloud = Cloud.GCP
    resource_type = "firewall_rule"
    severity = Severity.HIGH
    description = "Firewall rules must not expose port 3389 (RDP) to the internet."
    remediation = "Restrict source ranges for port 3389 to trusted networks."

    def evaluate(self, resource: Resource) -> bool:
        if resource.properties.get("direction", "INGRESS") != "INGRESS":
            return True
        source_ranges = resource.properties.get("source_ranges", [])
        if "0.0.0.0/0" not in source_ranges:
            return True
        for allowed in resource.properties.get("allowed", []):
            ports = allowed.get("ports", [])
            if "3389" in ports or not ports:
                return False
        return True


class ComputeInstancePublicIPCheck(Check):
    check_id = "GCP_INSTANCE_PUBLIC_IP"
    title = "Compute instance has no public IP"
    cloud = Cloud.GCP
    resource_type = "compute_instance"
    severity = Severity.MEDIUM
    description = "Compute instances should not have external (public) IP addresses."
    remediation = "Remove the external IP; use Cloud NAT or a bastion for egress/access."

    def evaluate(self, resource: Resource) -> bool:
        return not resource.properties.get("has_public_ip", False)


class ServiceAccountKeyRotationCheck(Check):
    check_id = "GCP_SA_KEY_AGE"
    title = "Service account keys are rotated"
    cloud = Cloud.GCP
    resource_type = "service_account"
    severity = Severity.MEDIUM
    description = "User-managed service account keys must be younger than 90 days."
    remediation = "Rotate service account keys and delete keys older than 90 days."

    def evaluate(self, resource: Resource) -> bool:
        max_age = max(
            (k.get("age_days", 0) for k in resource.properties.get("keys", [])),
            default=0,
        )
        return max_age < 90
