# Aegis Enterprise CNAPP Platform — Administrator Guide

## 1. Organization & Member Management
- **Role Permissions**: Admin (Full Access), Analyst (Write Access), Auditor (Compliance Read Only), Viewer (Read Only).
- **Enterprise SSO Setup**: Configure SAML 2.0 or OIDC endpoints for Okta, Microsoft Entra ID (Azure AD), Auth0, or Google Workspace under **Organization Settings**.
- **SCIM 2.0 User Provisioning**: Connect SCIM provisioning endpoint at `/api/v1/scim/v2/Users`.
- **Tamper-Evident Audit Trail**: Verify SHA-256 hash chains under **Audit Logs**.
