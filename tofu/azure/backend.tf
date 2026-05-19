terraform {
  backend "azurerm" {
    key                  = "protosource-auth.tfstate"
    resource_group_name  = "protosrctf-tfstate-rg"
    storage_account_name = "protosrctfstate"
    container_name       = "tfstate"
  }
}
