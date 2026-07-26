# Connect GCP & Azure to Aegis (read-only)

Aegis needs least-privilege, read-only access. Below are copy-paste setups.

## GCP — service account (Security Reviewer)

```bash
# Run in the project you want Aegis to audit
export PROJECT_ID=your-project
gcloud iam service-accounts create aegis-cspm \
  --project="$PROJECT_ID" --display-name="Aegis CSPM (read-only)"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:aegis-cspm@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/iam.securityReviewer"

# Create a key and paste its JSON into the Aegis "Connect GCP" dialog
gcloud iam service-accounts keys create aegis-key.json \
  --iam-account="aegis-cspm@$PROJECT_ID.iam.gserviceaccount.com"
```

> Rotate/delete the key after 90 days — Aegis flags stale keys anyway.
> For org-wide, grant `roles/iam.securityReviewer` at the folder/org level instead.

### Terraform (GCP)
```hcl
resource "google_service_account" "aegis" {
  account_id   = "aegis-cspm"
  display_name = "Aegis CSPM (read-only)"
}
resource "google_project_iam_member" "aegis" {
  project = var.project_id
  role    = "roles/iam.securityReviewer"
  member  = "serviceAccount:${google_service_account.aegis.email}"
}
resource "google_service_account_key" "aegis" {
  service_account_id = google_service_account.aegis.name
}
output "sa_key_json" {
  value     = base64decode(google_service_account_key.aegis.private_key)
  sensitive = true
}
```

## Azure — service principal (Reader)

```bash
SUB=$(az account show --query id -o tsv)
az ad sp create-for-rbac --name "aegis-cspm" \
  --role "Reader" --scopes "/subscriptions/$SUB"
# Output gives: appId (client_id), password (client_secret), tenant (tenant_id)
# Paste those + the subscription id into the Aegis "Connect Azure" dialog.
```

### Terraform (Azure)
```hcl
data "azurerm_subscription" "current" {}
resource "azuread_application" "aegis" { display_name = "aegis-cspm" }
resource "azuread_service_principal" "aegis" { client_id = azuread_application.aegis.client_id }
resource "azuread_service_principal_password" "aegis" {
  service_principal_id = azuread_service_principal.aegis.id
}
resource "azurerm_role_assignment" "aegis" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.aegis.object_id
}
```

Provide to Aegis: **tenant_id**, **client_id**, **client_secret**, **subscription_id**.
