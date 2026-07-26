# Security Policy

Aegis (Cloud Security Posture Manager) is a security product, so we hold our own
posture to a high bar. This page describes how we build securely and how to
report issues.

## Reporting a vulnerability

- **Email:** security@aegis.example (PGP key on request)
- Please include steps to reproduce, impact, and affected version/commit.
- We aim to acknowledge within **2 business days** and to triage within **5**.
- Please practice responsible disclosure — give us reasonable time to fix before
  public disclosure. We do not pursue legal action against good-faith research.

> Do **not** open public GitHub issues for security reports.

## Our security posture (how the product is built)

**Least privilege & read-only**
- Cloud access is read-only (AWS `SecurityAudit`, GCP Security Reviewer, Azure
  Reader). Aegis never modifies customer resources.
- AWS uses STS AssumeRole with a per-org **external ID** (confused-deputy defense).

**Secrets**
- Customer cloud credentials are encrypted at rest with **AES-256-GCM** using
  envelope encryption (KMS/Vault-backed keys supported) and are **never**
  returned to the frontend.
- App secrets come from the environment / a secrets manager; none are committed.

**Tenant isolation**
- Every query is org-scoped, backed by **PostgreSQL Row-Level Security** so a
  code-path bug cannot leak cross-tenant data.

**AuthN / AuthZ**
- OIDC/JWT SSO (Okta, Azure AD), SCIM provisioning, API keys (hashed at rest),
  and role-based access control (viewer / analyst / admin).

**Auditability**
- All mutating actions are written to a **tamper-evident, hash-chained audit
  log**; integrity is verifiable via `GET /audit/verify`.

**Supply chain & CI**
- Dependency updates via Dependabot; **Trivy** vulnerability/secret/misconfig
  scanning and a **CycloneDX SBOM** run in CI; linting (ruff) and tests gate merges.

**Hardening**
- Non-root containers, read-only root filesystem, dropped capabilities.
- Structured logging with request-id tracing; Prometheus metrics; rate limiting.

## Supported versions
The latest released `0.x` line receives security fixes. Pre-1.0 software: pin a
version and watch releases.

## Compliance
Aegis's own SOC 2 program is **in progress** (see `docs/legal/soc2-readiness.md`).
This page describes controls that are implemented in code; a SOC 2 report is a
separate third-party attestation and is not yet available.
