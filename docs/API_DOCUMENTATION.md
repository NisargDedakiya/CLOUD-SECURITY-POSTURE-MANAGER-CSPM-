# Aegis Enterprise CNAPP Platform — API Reference Manual

All endpoints accept authentication via Bearer Token (`Authorization: Bearer <jwt_or_apikey>`) or Tenant Header (`X-Org-Id: <org_id>`).

## REST API Endpoints

### 1. Security Overview & Dashboard
- `GET /api/v1/cspm/overview`: Basic CSPM summary.
- `GET /api/v1/cspm/dashboard/metrics`: CISO executive metrics (scores, MTTR, posture timeline, scheduled scans).

### 2. Knowledge Graph & Attack Paths
- `GET /api/v1/cspm/knowledge-graph`: Returns directed graph nodes, edges, and blast-radius calculations.
- `GET /api/v1/cspm/attack-paths`: Visual graph of exploitable attack chains.
- `GET /api/v1/cspm/asset-hierarchy`: Returns tree: Org → Provider → Account → VPC → Resources.

### 3. CIEM & IAM Explorer
- `GET /api/v1/cspm/ciem`: Privilege escalation vectors, excessive permissions, dormant roles.
- `GET /api/v1/cspm/iam-explorer`: Detailed IAM users, roles, policies, and cross-account trust matrix.

### 4. DevSecOps & Runtime Security
- `POST /api/v1/cspm/iac/scan`: Static IaC analysis (Terraform, CloudFormation, Bicep, Pulumi).
- `POST /api/v1/cspm/k8s/scan`: Kubernetes security audit (EKS/AKS/GKE).
- `GET /api/v1/cspm/runtime/events`: Real-time container runtime threats and anomalous cloud API calls.
- `POST /api/v1/cspm/siem/export`: Stream findings to Splunk HEC, Sentinel, Elastic, Datadog.

### 5. GraphQL API
- `POST /api/v1/graphql`: Standard GraphQL schema query endpoint.
