# Cloud Security Posture Manager (CSPM)

A multi-cloud (**AWS**, **GCP**, **Azure**) security posture scanner. It collects
normalized cloud resources, runs a set of Python-coded security checks against
them, and reports misconfigurations with severity and remediation guidance —
via a REST API, a web dashboard, and a CLI.

Out of the box it runs in **mock mode** with realistic sample resources, so you
can try the whole pipeline without any cloud credentials.

## Architecture

```
cspm/
  models.py          Resource, Finding, Severity, ScanResult
  checks/            Python-coded checks (one class per check, auto-registered)
    base.py            Check base class + registry
    aws_checks.py      GCP/Azure equivalents alongside
  providers/         Resource collectors per cloud (mock + live stubs)
  engine.py          ScanEngine: collect resources -> run applicable checks
  api/app.py         FastAPI REST API + dashboard host
  cli.py             Command-line scanner
web/                 Static dashboard (HTML/CSS/JS)
tests/               pytest unit + integration tests
```

**Flow:** a `Provider` collects `Resource` objects → the `ScanEngine` matches
each resource to applicable `Check`s → each check returns a `Finding`
(pass/fail with severity + remediation) → results are aggregated into a
`ScanResult` with a posture score.

## Quick start

```bash
pip install -e ".[dev]"

# CLI scan (mock data)
cspm --format table                 # all clouds
cspm --cloud aws --cloud gcp        # subset
cspm --format json                  # machine-readable
cspm --fail-on high                 # non-zero exit for CI gating

# Web dashboard + API
uvicorn cspm.api.app:app --reload
# open http://127.0.0.1:8000
```

## API endpoints

| Method | Path           | Description                                  |
|--------|----------------|----------------------------------------------|
| GET    | `/api/health`  | Health/version                               |
| GET    | `/api/checks`  | List all registered checks                   |
| GET    | `/api/scan`    | Run a scan. Query: `cloud=aws&live=false`    |
| GET    | `/`            | Web dashboard                                |

## Built-in checks

**AWS:** S3 public access, S3 encryption, security-group open SSH, IAM user MFA,
RDS encryption.
**GCP:** public storage bucket, uniform bucket-level access, firewall open RDP,
instance public IP, service-account key rotation.
**Azure:** storage HTTPS-only, public blob access, NSG open management ports,
SQL auditing, VM disk encryption.

## Adding a check

Subclass `Check`, set the class attributes, and implement `evaluate` (return
`True` when compliant). Registration is automatic on import.

```python
from cspm.checks.base import Check
from cspm.models import Cloud, Resource, Severity

class MyCheck(Check):
    check_id = "AWS_MY_CHECK"
    title = "..."
    cloud = Cloud.AWS
    resource_type = "s3_bucket"
    severity = Severity.HIGH
    description = "..."
    remediation = "..."

    def evaluate(self, resource: Resource) -> bool:
        return resource.properties.get("something") is True
```

## Going live

Each provider ships a `_collect_live()` stub. Implement it with the relevant
cloud SDK (boto3 / google-cloud / azure-mgmt) to normalize real resources into
`Resource` objects, then run with `--live` (CLI) or `?live=true` (API).

## Tests

```bash
pytest -q
```
