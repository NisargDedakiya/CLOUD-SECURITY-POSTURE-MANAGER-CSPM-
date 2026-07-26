# Operations — Deployment, Runbook, SLA

## Deployment (production)

**Recommended:** Kubernetes via the Helm chart in `deploy/helm/cspm`.

```bash
# 1. Secrets (never in values.yaml)
kubectl create secret generic cspm-secrets \
  --from-literal=CSPM_DATABASE_URL='postgresql+psycopg://...' \
  --from-literal=CSPM_REDIS_URL='redis://...' \
  --from-literal=CSPM_ENCRYPTION_KEY='...' \
  --from-literal=CSPM_OIDC_JWKS_URL='...' \
  --from-literal=CSPM_STRIPE_SECRET_KEY='...'

# 2. Install (API w/ HPA + worker + beat)
helm install cspm deploy/helm/cspm -f prod-values.yaml

# 3. Migrate
kubectl exec deploy/cspm-api -- alembic upgrade head
```

Prerequisites: managed **PostgreSQL 15+** and **Redis 7+**, a TLS-terminating
ingress/CDN (add HSTS/CSP headers there), and `CSPM_ENV=production` (fails fast if
misconfigured).

## Monitoring & alerting
- **Metrics:** Prometheus scrapes `/metrics` (request rate/latency, scans, findings).
- **Health:** liveness `/api/v1/cspm/health`, readiness `/api/v1/cspm/ready`.
- **Errors:** set `CSPM_SENTRY_DSN` for exception tracking.
- **Suggested alerts:** 5xx rate > 1% (5m); p95 latency > 1s; readiness failing;
  Celery queue depth growing; DB connections saturated; cert expiry < 14d.

## On-call runbook (technical incident response)
1. **Acknowledge** the page; check `/ready` and the metrics dashboard.
2. **Triage:** API down? DB/Redis reachable? Recent deploy? Check Sentry + logs
   (filter by `request_id`).
3. **Mitigate:** roll back the last release (`helm rollback cspm`), scale API
   replicas, or fail over the DB as appropriate.
4. **Data-affecting?** For any suspected tenant-data issue, run
   `GET /audit/verify` per affected org and preserve logs.
5. **Communicate:** update the status page; notify affected customers per SLA.
6. **Post-incident:** blameless write-up within 3 business days; track fixes.

## SLA (template — commit only what you can meet)
| Tier | Uptime | Support response |
|---|---|---|
| Free | best-effort | community |
| Starter/Pro | 99.5% | 1 business day |
| Enterprise | 99.9% | 1 hour (critical), 24×7 |

- Measure uptime with an external monitor; publish a status page.
- Define maintenance windows; exclude them from SLA math.
- Back up Postgres (PITR) and **test restores** quarterly; document RPO/RTO.

## Backups & DR
- Automated daily DB snapshots + WAL/PITR.
- Encryption keys backed up in KMS/Vault (rotation supported by the key provider).
- Quarterly restore drill; record RTO/RPO actuals.
