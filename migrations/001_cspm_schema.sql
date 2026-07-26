-- CSPM schema (spec Section 4). Postgres 15+. Run after the shared schema
-- (organisations, users, ...) exists. In production this is an Alembic migration.

CREATE TABLE IF NOT EXISTS cspm_cloud_accounts (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id         UUID REFERENCES organisations(id) ON DELETE CASCADE,
  provider       VARCHAR(20) NOT NULL,          -- aws/gcp/azure
  label          VARCHAR(255),
  role_arn       TEXT,                           -- AWS only
  external_id    VARCHAR(100),                   -- AWS only, per-org secret
  gcp_sa_key_enc TEXT,                           -- GCP only, AES-256 encrypted
  azure_tenant_id VARCHAR(100),                  -- Azure only
  azure_client_id VARCHAR(100),                  -- Azure only
  azure_secret_enc TEXT,                         -- Azure only, AES-256 encrypted
  status         VARCHAR(20) DEFAULT 'pending',  -- pending/active/error
  last_validated_at TIMESTAMPTZ,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cspm_scan_runs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cloud_account_id UUID REFERENCES cspm_cloud_accounts(id) ON DELETE CASCADE,
  status          VARCHAR(20) DEFAULT 'queued',  -- queued/running/completed/failed
  started_at      TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ,
  checks_run      INTEGER DEFAULT 0,
  findings_count  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cspm_findings (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          UUID REFERENCES organisations(id),
  cloud_account_id UUID REFERENCES cspm_cloud_accounts(id),
  scan_run_id     UUID REFERENCES cspm_scan_runs(id),
  check_id        VARCHAR(100),
  resource        TEXT,
  severity        VARCHAR(20),
  description     TEXT,
  remediation     TEXT,
  status          VARCHAR(30) DEFAULT 'open',    -- open/accepted_risk/resolved
  dedup_hash      VARCHAR(64) UNIQUE,
  discovered_at   TIMESTAMPTZ DEFAULT NOW(),
  resolved_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS compliance_mappings (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  check_id     VARCHAR(100) NOT NULL,
  framework    VARCHAR(50) NOT NULL,             -- cis_aws_v2/soc2/iso27001/pci_dss_v4
  control_id   VARCHAR(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS cspm_baselines (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cloud_account_id UUID REFERENCES cspm_cloud_accounts(id) ON DELETE CASCADE,
  resource_type   VARCHAR(100),
  resource_id     TEXT,
  config_snapshot JSONB,
  approved_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cspm_drift_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          UUID REFERENCES organisations(id),
  cloud_account_id UUID REFERENCES cspm_cloud_accounts(id),
  resource_type   VARCHAR(100),
  resource_id     TEXT,
  drift_type      VARCHAR(30),                   -- created/deleted/changed/permission_changed
  before_state    JSONB,
  after_state     JSONB,
  status          VARCHAR(20) DEFAULT 'pending_review', -- pending_review/approved/violation
  detected_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cspm_findings_org ON cspm_findings(org_id, status);
CREATE INDEX IF NOT EXISTS idx_cspm_drift_org ON cspm_drift_events(org_id, status);
CREATE INDEX IF NOT EXISTS idx_compliance_check ON compliance_mappings(check_id, framework);
