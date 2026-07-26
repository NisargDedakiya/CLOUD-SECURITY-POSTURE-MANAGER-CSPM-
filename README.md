# Tool 6 — Cloud Security Posture Manager (CSPM)

Continuously audits a customer's **AWS, GCP, and Azure** accounts against CIS
Benchmarks and security best practices, finding misconfigurations before
attackers exploit them. Read-only and non-intrusive — it never modifies customer
cloud resources.

Built to the Track 2 SaaS platform spec: CSPM is **not standalone**, it mounts as
a router at `/api/v1/cspm/` on the shared FastAPI backend (auth, orgs, billing,
audit log, reports). The shared foundation is represented here by lightweight,
swappable stubs in `cspm/shared/`.

## Modules (spec build order)

| # | Module | Package | What it does |
|---|--------|---------|--------------|
| 6.1 | Cloud Account Connector | `cspm/connectors/` | Connect AWS (STS AssumeRole + external id), GCP (SA key), Azure (SP) with least-privilege, read-only creds. Validates then stores secrets AES-256 encrypted. |
| 6.2 | AWS Security Audit Engine | `cspm/auditors/` | `AWSAuditor` class with independently-testable `check_*` methods (IAM, S3, EC2/VPC, RDS, CloudTrail, KMS, GuardDuty). |
| 6.3 | Compliance Mapping Engine | `cspm/compliance/` | Maps checks → CIS AWS v2 / SOC 2 / ISO 27001 / PCI DSS v4 controls; per-framework score; evidence export; remediation priority. |
| 6.4 | Drift Detection | `cspm/drift/` | Baseline snapshot (JSONB) + `deepdiff` structural comparison; approval workflow; security-sensitive changes flagged. |

## Architecture

```
cspm/
  config.py         env-driven settings
  db.py             SQLAlchemy engine/session/Base
  models.py         ORM for cspm_* tables (spec Section 4)
  schemas.py        Pydantic request/response (secrets never serialized)
  security/crypto.py AES-256-GCM field encryption
  shared/           stubs for the shared platform (orgs, users, auth deps)
  connectors/       Module 6.1
  auditors/         Module 6.2  (+ Finding value object)
  compliance/       Module 6.3  (mappings seed + scoring/evidence)
  drift/            Module 6.4  (deepdiff detector)
  service.py        orchestration shared by API + Celery
  celery_app.py     shared Celery app (4 queues) reference
  tasks.py          run_aws_audit (high queue), run_drift_check (default)
  api/router.py     /api/v1/cspm/ endpoints (spec Section 6)
  api/app.py        standalone FastAPI app + dashboard
  cli.py            AWS audit CLI (--demo for no-credential run)
  fakes.py          in-memory fake AWS session for demos/tests
web/                dashboard
migrations/         001_cspm_schema.sql (Postgres)
tests/              39 tests
```

## Quick start (no cloud credentials)

```bash
pip install -e ".[dev]"

# CLI: full audit against an in-memory fake AWS account
cspm --demo                 # table with findings + compliance scores
cspm --demo --format json

# API + dashboard
uvicorn cspm.api.app:app --reload
#   open http://127.0.0.1:8000  (set an Org id, connect an account, scan)
```

Every API request is org-scoped via the `X-Org-Id` header (the seam where the
shared JWT/RBAC auth is wired in).

## API surface (`/api/v1/cspm/`)

```
POST   /accounts                        Connect a cloud account
GET    /accounts                        List connected accounts
POST   /accounts/{id}/validate          Re-validate credentials
DELETE /accounts/{id}                   Disconnect
POST   /accounts/{id}/scan              Trigger an audit
GET    /scans/{scan_run_id}             Scan run status
GET    /findings                        List findings (severity/status/account)
PATCH  /findings/{id}                   Update finding status
GET    /compliance/{framework}          Compliance score + detail
GET    /compliance/{framework}/evidence Evidence export
GET    /drift                           List drift events
POST   /drift/{id}/approve              Approve drift (updates baseline)
POST   /drift/{id}/reject               Mark as violation (creates finding)
```

## Security notes (per spec 6.1)

- AWS uses **STS AssumeRole with an external id** (per-org secret) to prevent the
  confused-deputy problem.
- Cloud secrets (AWS secret keys, GCP SA JSON, Azure client secrets) are
  **AES-256-GCM encrypted** at rest and **never returned to the frontend** —
  `CloudAccountOut` has no secret fields.
- Validation runs the cheapest read-only call per provider
  (`sts.get_caller_identity()` for AWS).

## Production hardening

- **Config guards** (`CSPM_ENV=production`): fails fast unless `CSPM_ENCRYPTION_KEY`
  is set, `CSPM_DATABASE_URL` is Postgres, and `CSPM_EAGER_TASKS=false`. See
  `.env.example`.
- **Observability**: structured JSON logging, per-request `X-Request-Id`
  propagation, a global 500 handler, and immutable `audit_log` writes on every
  mutation.
- **RBAC**: `viewer` / `analyst` / `admin` (via `X-Role`, the JWT/RBAC seam).
  Connect/scan/patch/drift require analyst+, disconnect requires admin.
- **Bounded lists**: every list endpoint takes `limit`/`offset` and returns
  `X-Total-Count`.
- **Async scans**: with `CSPM_EAGER_TASKS=false`, `POST /accounts/{id}/scan`
  persists a queued run and enqueues `cspm.run_aws_audit` on the `high` queue;
  poll `GET /scans/{id}`. Security-sensitive drift re-routes an alert to `critical`.
- **Health/readiness**: `/api/v1/cspm/health` and `/api/v1/cspm/ready` (DB ping).

## Deployment

```bash
# One-command local stack: Postgres + Redis + API + Celery worker
export CSPM_ENCRYPTION_KEY=$(python -c "from cspm.security.crypto import generate_key; print(generate_key())")
docker compose up --build
# API on http://localhost:8000 ; migrations run automatically (alembic upgrade head)
```

- **Migrations**: `alembic upgrade head` (or the raw `migrations/001_cspm_schema.sql`).
- **Live cloud**: `pip install -e ".[gcp,azure]"`; AWS uses bundled boto3.
- **CI**: `.github/workflows/ci.yml` runs `ruff` + `pytest` on every push/PR.

## Tests & lint

```bash
pytest -q              # 49 tests across every module
ruff check cspm tests  # lint
```
