# ─────────────────────────────────────────────────────────────────────────
# Bootstrap module: provisions the resource group + storage account that
# the tofu/azure env stack uses for its remote tfstate. Apply this once
# per subscription. Subsequent `tofu init` in tofu/azure points its
# backend at the outputs here.
#
# Cold-start:
#   az login
#   az account set --subscription <your-subscription-id>
#   az provider register --namespace Microsoft.Storage
#   cd tofu/azure-bootstrap
#   tofu init && tofu apply
# ─────────────────────────────────────────────────────────────────────────

locals {
  # Globally-unique storage account name (3-24 chars, alphanumeric only).
  # Hash of subscription + prefix keeps it stable across operators.
  suffix       = substr(md5("${var.subscription_id}-${var.name_prefix}-tfstate"), 0, 6)
  storage_name = "${replace(var.name_prefix, "-", "")}tfs${local.suffix}"
}

resource "azurerm_resource_group" "tfstate" {
  name     = "${var.name_prefix}-tfstate-rg"
  location = var.location
}

resource "azurerm_storage_account" "tfstate" {
  name                     = local.storage_name
  resource_group_name      = azurerm_resource_group.tfstate.name
  location                 = azurerm_resource_group.tfstate.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # State files contain sensitive material (tokens, keys) when not
  # using sensitive=true everywhere — disable public blob access and
  # require TLS.
  allow_nested_items_to_be_public = false
  min_tls_version                 = "TLS1_2"

  blob_properties {
    versioning_enabled = true
  }
}

resource "azurerm_storage_container" "tfstate" {
  name                  = "tfstate"
  storage_account_id    = azurerm_storage_account.tfstate.id
  container_access_type = "private"
}
