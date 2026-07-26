# SOC 2 Readiness Checklist

> SOC 2 is a **third-party attestation** by a licensed CPA firm — it cannot be
> self-issued. This checklist gets you audit-ready. Typical path: pick a
> compliance automation vendor (Vanta/Drata/Secureframe) → 3-month observation
> window (Type II) → auditor engagement.

## Trust Services Criteria coverage

### Security (required)
- [x] RBAC with least privilege (viewer/analyst/admin) — *in product*
- [x] Encryption at rest (AES-256) and in transit (TLS)
- [x] Tamper-evident audit logging
- [x] Vulnerability scanning + SBOM in CI (Trivy, CycloneDX)
- [x] Secrets management (KMS/Vault providers)
- [ ] Formal access reviews (quarterly) — *process*
- [ ] Endpoint security / MDM for staff laptops — *process*
- [ ] Background checks for employees — *process*
- [ ] Security awareness training — *process*

### Availability
- [x] Health/readiness probes, autoscaling (HPA), metrics
- [ ] Documented SLA + uptime monitoring / status page — *see docs/ops/sla.md*
- [ ] Backup & disaster-recovery runbook with tested restores — *process*

### Confidentiality
- [x] Tenant isolation (Postgres RLS)
- [x] Data-retention controls (configurable purge)
- [ ] Data classification policy — *doc*

### Processing Integrity / Privacy (if in scope)
- [ ] Privacy policy published (draft in `web/legal/privacy.html`)
- [ ] DPA + sub-processor list — *doc*

## Company-level policies to author
- [ ] Information Security Policy
- [ ] Incident Response Plan (see `docs/ops/runbook.md` for the technical half)
- [ ] Change Management Policy (CI gates already enforce much of this)
- [ ] Vendor/Sub-processor Management
- [ ] Business Continuity / DR
- [ ] Acceptable Use & Onboarding/Offboarding

## Sequence
1. Adopt a compliance automation platform; connect GitHub/cloud/HR.
2. Author policies (templates from the platform).
3. Remediate gaps flagged above.
4. Run the Type I audit, then a Type II observation window.
5. Publish the report under NDA to prospects; add a trust page.
