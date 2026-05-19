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
      # turned off. When `tofu destroy` removes the vault, allow the
      # provider to purge soft-deleted state too so a re-apply with
      # the same name doesn't conflict.
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
  subscription_id = var.subscription_id
}
