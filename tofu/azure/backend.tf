terraform {
  backend "azurerm" {
    # Pass concrete values via `-backend-config` at `tofu init` time:
    #   tofu init \
    #     -backend-config="resource_group_name=<bootstrap rg>" \
    #     -backend-config="storage_account_name=<bootstrap sa>" \
    #     -backend-config="container_name=tfstate"
    key = "protosource-auth.tfstate"
  }
}
