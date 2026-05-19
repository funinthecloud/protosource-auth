terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.20"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      # Premium Key Vault has soft-delete on by default and cannot be
      # turned off. The destroy / recover policy is variable-driven so
      # dev stacks can iterate quickly (purge + auto-recover) while
      # prod keeps the safer default (preserve soft-deleted state,
      # require manual recovery). See key_vault_destroy_safety in
      # variables.tf for the full tradeoff.
      purge_soft_delete_on_destroy    = !var.key_vault_destroy_safety
      recover_soft_deleted_key_vaults = !var.key_vault_destroy_safety
    }
  }
  subscription_id = var.subscription_id
}
