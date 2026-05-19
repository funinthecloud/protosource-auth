output "resource_group_name" {
  description = "Resource group holding the tfstate storage account. Pass as -backend-config=resource_group_name=... to `tofu init` in tofu/azure."
  value       = azurerm_resource_group.tfstate.name
}

output "storage_account_name" {
  description = "Storage account holding the tfstate container. Pass as -backend-config=storage_account_name=... to `tofu init` in tofu/azure."
  value       = azurerm_storage_account.tfstate.name
}

output "container_name" {
  description = "Blob container holding tfstate files. Pass as -backend-config=container_name=... to `tofu init` in tofu/azure."
  value       = azurerm_storage_container.tfstate.name
}
