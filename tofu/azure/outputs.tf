output "container_app_url" {
  description = "Public URL of the protosource-auth Container App. Visit this after the first image push for the login page."
  value       = "https://${module.app.container_app_fqdn}"
}

output "acr_login_server" {
  description = "ACR login server hostname. Use with `az acr login --name <prefix>` then `docker push`."
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
  description = "Versionless Key Vault key identifier URL — the value of PROTOSOURCE_AUTH_MASTER_KEY_REF. The Container App reads this through its env; surfaced here for mgr CLI invocations and debugging. Versionless so KEK rotation (creating a new version of the same key) takes effect without a tofu apply."
  value       = azurerm_key_vault_key.kek.versionless_id
}

output "managed_identity_client_id" {
  description = "Client ID of the Container App's user-assigned Managed Identity. Already wired into the container as AZURE_CLIENT_ID; surfaced here for cross-stack consumers."
  value       = module.app.client_id
}
