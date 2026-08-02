# Aegis Enterprise CNAPP Platform — Production Deployment Guide

## 1. Kubernetes Deployment
Deploy using standard Kubernetes manifests in `deploy/k8s/`:
```bash
kubectl apply -f deploy/k8s/deployment.yaml
```

## 2. Helm Chart Deployment
```bash
helm upgrade --install aegis deploy/helm/ --namespace aegis-security --create-namespace
```

## 3. Terraform Cloud Infrastructure
Provision PostgreSQL HA, Redis Cluster, and AWS VPC:
```bash
cd deploy/terraform
terraform init
terraform apply -auto-approve
```

## 4. Production Environment Variables
- `CSPM_AUTH_MODE`: Set to `token` or `headers` (for local dev).
- `DATABASE_URL`: PostgreSQL connection string (`postgresql+psycopg://user:pass@host:5432/aegis`).
- `REDIS_URL`: Redis cluster URL (`redis://redis-host:6379/0`).
- `SECRET_KEY`: AES-256 master key for service account credential encryption.
