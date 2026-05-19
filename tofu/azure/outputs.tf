output "container_app_url" {
  description = "Public URL of the protosource-auth Container App. Visit this after the first image push for the login page."
  value       = "https://${module.app.container_app_fqdn}"
}

output "acr_login_server" {
  description = "ACR login-server hostname (e.g. <name>.azurecr.io). Tag images against this value and `docker push` to it. For `az acr login`, strip the suffix and pass just the registry name: `az acr login --name $(tofu output -raw acr_login_server | cut -d. -f1)`."
  value       = module.app.acr_login_server
}

output "cosmos_endpoint" {
  description = "Cosmos account endpoint. Used by the mgr CLI for `ensure-tables` / `bootstrap` against this env."
  value       = module.cosmos.endpoint
}

output "cosmos_database_name" {
  description = "Cosmos database id. Pass as PROTOSOURCE_AUTH_COSMOS_DATABASE when running the mgr CLI."
  value       = module.cosmos.database_name
}

output "key_vault_uri" {
  description = "Key Vault DNS name (https://<vault>.vault.azure.net/)."
  value       = azurerm_key_vault.this.vault_uri
}

output "master_key_ref" {
  description = "Version-pinned Key Vault key identifier URL — the value of PROTOSOURCE_AUTH_MASTER_KEY_REF. The Container App reads this through its env; surfaced here for mgr CLI invocations and debugging. Version-pinned because the resolver persists this value on each Key aggregate at wrap time and Decrypt must target the exact version that produced the ciphertext. KEK rotation requires a tofu apply (to pick up the new version) plus a re-wrap or retirement of signing keys still pinned to the previous version."
  value       = azurerm_key_vault_key.kek.id
}

output "managed_identity_client_id" {
  description = "Client ID of the Container App's user-assigned Managed Identity. Already wired into the container as AZURE_CLIENT_ID; surfaced here for cross-stack consumers."
  value       = module.app.client_id
}

output "custom_domain_verification_id" {
  description = "Value for the asuid.<host> TXT record at your DNS provider. Stable per Container App — does not change across applies. Wrapped in nonsensitive() because the azurerm provider marks this field sensitive by default, but the value is one we explicitly need to publish at the DNS provider — it is not a secret."
  value       = nonsensitive(data.azurerm_container_app.this.custom_domain_verification_id)
}

output "dns_records" {
  description = "DNS records to create at your DNS provider (e.g. Route53) before the second apply binds the custom domain. When custom_domain is empty the value is a placeholder reminding you to populate it."
  value       = var.custom_domain == "" ? "Set -var custom_domain=<hostname> on the next apply and create the records this output will then print." : <<-EOT
    Create the following records at your DNS provider for ${var.custom_domain}:

      CNAME  ${var.custom_domain}        →  ${module.app.container_app_fqdn}
      TXT    asuid.${var.custom_domain}  →  ${nonsensitive(data.azurerm_container_app.this.custom_domain_verification_id)}

    After both records propagate, re-run `tofu apply` to issue the managed
    certificate. Then bind the cert to the custom domain (one-time, via
    portal or `az containerapp hostname bind`) — azurerm cannot do this
    in one apply because the cert and the binding are mutually dependent.
  EOT
}
