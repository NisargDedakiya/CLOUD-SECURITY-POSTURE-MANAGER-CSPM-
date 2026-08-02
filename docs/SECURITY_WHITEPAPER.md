# Aegis Enterprise Security & Compliance Whitepaper

## 1. Security Architecture & Threat Model
- **Tenant Isolation**: Strict Row-Level Security (RLS) enforcement via mandatory `X-Org-Id` filter context on all database queries.
- **Data Encryption**: All connected cloud credentials (GCP Service Account JSONs, Azure Client Secrets) are stored with AES-256-GCM envelope encryption.
- **Tamper-Evident Audit Logging**: Each user action is chained to the previous audit log entry using cryptographic SHA-256 hashes (`entry_hash = sha256(payload + prev_hash)`).
- **Vulnerability Disclosure**: Security disclosures governed via standard `.well-known/security.txt`.
