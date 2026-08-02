# Aegis Enterprise CNAPP Platform — Architecture & Design Guide

## 1. System Overview

Aegis is an enterprise Cloud-Native Application Protection Platform (CNAPP) integrating Cloud Security Posture Management (CSPM), Cloud Infrastructure Entitlement Management (CIEM), Visual Attack Path Analysis, Cloud Security Knowledge Graph, Kubernetes Security (EKS/AKS/GKE), Infrastructure as Code (IaC) Static Analysis, Runtime Security (CDR), and AI Security Copilot into a multi-tenant SaaS platform.

```
                  +-----------------------------------+
                  |   Enterprise Web SPA & Mobile     |
                  +-----------------------------------+
                                    |
                                REST / GraphQL
                                    v
                  +-----------------------------------+
                  |  FastAPI Platform Gateway (v1)    |
                  +-----------------------------------+
                  | Rate Limit | Auth (JWT/SSO/SCIM) |
                  +-----------------------------------+
                                    |
            +-----------------------+-----------------------+
            |                       |                       |
            v                       v                       v
  +------------------+    +-------------------+    +------------------+
  |  Security Engine |    |  Knowledge Graph  |    |  AI Copilot      |
  |  (CSPM/CIEM/K8s) |    |  & Attack Paths   |    |  Remediation     |
  +------------------+    +-------------------+    +------------------+
            |                       |                       |
            +-----------------------+-----------------------+
                                    |
                                    v
                     +-----------------------------+
                     |  PostgreSQL HA & Redis DB   |
                     +-----------------------------+
```

## 2. Core Architectural Pillars
- **Multi-Tenant Isolation**: Row-Level Security (RLS) and monotonic sequence hash-chaining (`AuditLogEntry.compute_hash()`).
- **Cloud Security Knowledge Graph**: Graph model calculating blast radius impact across connected AWS, GCP, Azure, and K8s resources.
- **Enterprise SSO & SCIM 2.0**: SAML 2.0, Entra ID, Okta, Auth0, Google Workspace integration with zero-downtime SCIM user provisioning.
- **Multi-Gateway Billing**: Stripe & Razorpay dual-gateway engine with annual/monthly billing, trial licenses, GST/VAT tax calculator, and PDF/JSON invoices.
- **Observability**: Prometheus metrics (`/metrics`), OpenTelemetry distributed tracing, and Grafana dashboard templates.
