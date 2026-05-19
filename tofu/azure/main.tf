# ─────────────────────────────────────────────────────────────────────────
# Azure env stack for protosource-auth.
#
# Stack contents:
#   • Resource group + tags
#   • Cosmos DB (NoSQL API) account, database, and 2 containers via the
#     upstream cosmos-eventstore module
#   • Container App + ACR + Managed Identity + Log Analytics via the
#     upstream container-app-service module
#   • Premium Key Vault with RBAC mode + HSM-backed RSA KEK
#   • Role assignment granting the Container App MI Key Vault Crypto User
#     on the KEK (least privilege)
#
# Public endpoints everywhere — see README for the private-endpoint
# follow-up plan when a compliance driver appears.
#
# Cold-start sequence (assumes tofu/azure-bootstrap is already applied):
#
#   az login
#   az account set --subscription <id>
#   for ns in Microsoft.App Microsoft.OperationalInsights \
#             Microsoft.ContainerRegistry Microsoft.ManagedIdentity \
#             Microsoft.DocumentDB Microsoft.KeyVault; do
#     az provider register --namespace $ns
#   done
#
#   tofu init \
#     -backend-config="resource_group_name=<bootstrap rg>" \
#     -backend-config="storage_account_name=<bootstrap sa>" \
#     -backend-config="container_name=tfstate"
#
#   tofu apply -var subscription_id=<id> -var issuer_iss=https://auth.example.com
#
# After the first apply, push the image to the new ACR (see
# acr_login_server output) and re-apply with -var image=<acr-fqdn>/protosource-auth:<tag>.
# ─────────────────────────────────────────────────────────────────────────

data "azurerm_client_config" "current" {}

locals {
  # Globally-unique suffix derived from subscription + prefix so two
  # operators applying with the same vars don't collide on Cosmos /
  # ACR / Key Vault name uniqueness checks.
  suffix              = substr(md5("${var.subscription_id}-${var.name_prefix}"), 0, 6)
  cosmos_account_name = "${var.name_prefix}-cosmos-${local.suffix}"
  acr_name            = "${replace(var.name_prefix, "-", "")}acr${local.suffix}"
  # Key Vault names are 3-24 chars, must start with a letter, must
  # end with a letter or digit (no trailing -). Compose
  # "<prefix>-kv-<suffix>" and pre-truncate the prefix portion to 14
  # chars so the final string is 14 + 4 ("-kv-") + 6 = 24 chars
  # exactly, always within the limit. trimsuffix guards against the
  # prefix being cut on a hyphen boundary (e.g. a 15-char prefix
  # ending its 14th char with "-"). name_prefix validation requires a
  # leading letter, so the first character is always a letter.
  key_vault_name = "${trimsuffix(substr(var.name_prefix, 0, 14), "-")}-kv-${local.suffix}"
}

resource "azurerm_resource_group" "this" {
  name     = "${var.name_prefix}-rg"
  location = var.location
  tags     = var.tags
}

# Container App + identity + ACR + log analytics. Standing it up first
# gives us the principal_id that cosmos-eventstore and the Key Vault
# role assignment need to grant data-plane access to.
module "app" {
  source = "git::https://github.com/funinthecloud/protosource.git//deploy/modules/container-app-service?ref=v0.4.0"

  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  name_prefix         = var.name_prefix
  acr_name            = local.acr_name
  image               = var.image
  target_port         = 8080
  min_replicas        = var.min_replicas
  max_replicas        = var.max_replicas
  cpu                 = var.container_cpu
  memory              = var.container_memory

  env = {
    # Storage backend selection + Cosmos wiring.
    PROTOSOURCE_AUTH_STORE_BACKEND                 = "cosmosdb"
    PROTOSOURCE_AUTH_COSMOS_ENDPOINT               = module.cosmos.endpoint
    PROTOSOURCE_AUTH_COSMOS_USE_DEFAULT_CREDENTIAL = "1"
    PROTOSOURCE_AUTH_COSMOS_DATABASE               = module.cosmos.database_name
    PROTOSOURCE_AUTH_EVENTS_CONTAINER              = module.cosmos.events_container_name
    PROTOSOURCE_AUTH_AGGREGATES_CONTAINER          = module.cosmos.aggregates_container_name

    # Key provider selection + Key Vault KEK reference.
    PROTOSOURCE_AUTH_KEY_PROVIDER   = "azurekeyvault"
    PROTOSOURCE_AUTH_MASTER_KEY_REF = azurerm_key_vault_key.kek.id

    # Issuer / token config.
    PROTOSOURCE_AUTH_ISSUER_ISS          = var.issuer_iss
    PROTOSOURCE_AUTH_ISSUER_ID           = var.issuer_id
    PROTOSOURCE_AUTH_ISSUER_DISPLAY_NAME = var.issuer_display_name
    PROTOSOURCE_AUTH_TOKEN_TTL           = var.token_ttl

    PROTOSOURCE_AUTH_CORS_ORIGIN = var.cors_origin

    # AZURE_CLIENT_ID is set inside the container-app-service module
    # itself (see its app.tf:local.managed_env) so DefaultAzureCredential
    # disambiguates which user-assigned identity to request — passing
    # it here would create a self-reference cycle.
  }

  tags = var.tags
}

# Cosmos account + DB + 2 containers + data-plane RBAC granted to the
# Container App's Managed Identity.
module "cosmos" {
  source = "git::https://github.com/funinthecloud/protosource.git//deploy/modules/cosmos-eventstore?ref=v0.4.0"

  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  account_name        = local.cosmos_account_name
  database_name       = var.cosmos_database
  serverless          = var.cosmos_serverless

  data_contributor_principal_ids = [module.app.principal_id]

  tags = var.tags
}

# Premium Key Vault with RBAC authorization. Premium tier is required
# for HSM-backed keys; RBAC mode (vs. access policies) is required so
# the role assignment below actually grants crypto access.
resource "azurerm_key_vault" "this" {
  name                = local.key_vault_name
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tenant_id           = data.azurerm_client_config.current.tenant_id

  sku_name                   = "premium"
  rbac_authorization_enabled = true

  # Soft-delete is mandatory on Key Vault. Purge protection prevents
  # accidental destruction of HSM key material — leave on for prod,
  # but the dev stack disables it so `tofu destroy` is clean.
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  tags = var.tags
}

# Grant the caller (whoever ran `tofu apply`) Key Vault Crypto Officer
# at the vault scope so they can create + manage the KEK. Without
# this, the azurerm_key_vault_key resource below fails with 403 even
# though the caller has Owner on the subscription, because RBAC mode
# replaces the implicit data-plane access of access-policy mode.
resource "azurerm_role_assignment" "deployer_crypto_officer" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# HSM-backed RSA KEK. The KeyProvider wraps signing-key material with
# RSA-OAEP-256 against this key; the private half never leaves the
# HSM boundary.
resource "azurerm_key_vault_key" "kek" {
  name         = var.key_vault_kek_name
  key_vault_id = azurerm_key_vault.this.id
  key_type     = "RSA-HSM"
  key_size     = var.key_vault_kek_size

  key_opts = [
    "encrypt",
    "decrypt",
    "wrapKey",
    "unwrapKey",
  ]

  tags = var.tags

  depends_on = [azurerm_role_assignment.deployer_crypto_officer]
}

# Grant the Container App's Managed Identity Key Vault Crypto User on
# the KEK only (not the whole vault). Crypto User is the least-
# privilege role that allows Encrypt + Decrypt without Create / Delete
# / Rotate, matching what the KeyProvider needs.
resource "azurerm_role_assignment" "app_crypto_user" {
  scope                = azurerm_key_vault_key.kek.resource_versionless_id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = module.app.principal_id
}
