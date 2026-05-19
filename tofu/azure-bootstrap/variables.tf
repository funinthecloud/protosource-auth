variable "subscription_id" {
  description = "Azure subscription ID. Required so the bootstrap doesn't accidentally target whichever subscription `az account show` returns."
  type        = string
}

variable "location" {
  description = "Azure region for the tfstate storage account."
  type        = string
  default     = "eastus"
}

variable "name_prefix" {
  description = "Short lowercase prefix for resource names (3-20 chars)."
  type        = string
  default     = "protosrc-auth"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,20}$", var.name_prefix))
    error_message = "name_prefix must be 3-20 chars of lowercase letters, digits, or hyphens."
  }
}
