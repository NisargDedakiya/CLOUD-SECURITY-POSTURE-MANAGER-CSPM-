# Connect your AWS account to Aegis (one click)

Aegis audits your account **read-only** — it assumes a role you create, using an
**External ID** so only your Aegis org can use it. It never modifies resources.

## Option A — One-click (CloudFormation)

Use a **Launch Stack** URL. Host `aws-role.yaml` at a public HTTPS URL (e.g. an
S3 bucket or your website) and build the link below — the console pre-fills the
template and parameters; the customer just clicks *Create stack*.

```
https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review
  ?templateURL=https://<YOUR-BUCKET>.s3.amazonaws.com/aegis/aws-role.yaml
  &stackName=Aegis-CSPM-Audit-Role
  &param_AegisAccountId=<YOUR_AEGIS_ACCOUNT_ID>
  &param_ExternalId=<CUSTOMER_EXTERNAL_ID>
```

> Render this button in the app's "Connect AWS" dialog, injecting the org's
> External ID automatically. After the stack finishes, the customer copies the
> **RoleArn** output back into Aegis.

### Steps shown to the customer
1. Click **Launch stack** (opens their AWS console, already filled in).
2. Tick *"I acknowledge that AWS CloudFormation might create IAM resources with custom names"*.
3. Click **Create stack** → wait ~1 minute.
4. Open the stack's **Outputs** tab → copy **RoleArn**.
5. Paste it into Aegis and click **Validate & connect**.

## Option B — Terraform

For IaC-driven customers, ship `aws-role.tf`:

```bash
terraform apply \
  -var aegis_account_id=<YOUR_AEGIS_ACCOUNT_ID> \
  -var external_id=<CUSTOMER_EXTERNAL_ID>
# then paste the `role_arn` output into Aegis
```

## What the role grants
- Trust: only `arn:aws:iam::<AegisAccountId>:root` **with the matching External ID**.
- Permissions: AWS-managed **`SecurityAudit`** + **`ViewOnlyAccess`** (read-only).
- Session: 1 hour max.

## Multi-account (AWS Organizations)
Deploy the same template as a **CloudFormation StackSet** across the org (or all
member OUs) using the same role name; Aegis then fans out via
`organizations:ListAccounts` and assumes `AegisCSPMAuditRole` in each member
account. See `cspm/auditors/scale.py`.
