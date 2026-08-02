# Aegis Enterprise CNAPP Platform — Developer & Setup Guide

## 1. Local Development Setup

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm 9+
- Docker & Docker Compose

### Setup Environment
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev,deploy,billing,gcp,azure]"
```

### Running Backend & Web Server
```bash
python -m uvicorn cspm.api.app:app --host 127.0.0.1 --port 8000 --reload
```

### Running Test Suite
```bash
pytest
```

## 2. Code Structure
- `cspm/api/`: FastAPI routers (REST, GraphQL, SCIM, Billing, MSSP, Dashboard).
- `cspm/engine/`: Core CNAPP engines (CIEM, Attack Path, Knowledge Graph, Inventory, IaC Scanner, Runtime CDR).
- `cspm/auditors/`: Multi-cloud auditors (AWS, GCP, Azure, K8s).
- `cspm/ai/`: AI Security Copilot (Remediation, Prioritization, NL Search, Summary).
- `web/`: Modern single-page enterprise frontend web app.
