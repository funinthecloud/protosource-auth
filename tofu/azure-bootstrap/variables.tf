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
  description = "Short lowercase prefix for resource names (3-20 chars). Must start with a letter so the derived storage account name (hyphens stripped) is valid (storage account names must start with a letter or digit but Azure docs recommend a leading letter; we hold the line at letters to also satisfy the env stack's stricter rules)."
  type        = string
  default     = "protosrc-auth"

  validation {
    condition = (
      can(regex("^[a-z][a-z0-9-]*[a-z0-9]$", var.name_prefix))
      && !can(regex("--", var.name_prefix))
      && length(var.name_prefix) >= 3
      && length(var.name_prefix) <= 20
    )
    error_message = "name_prefix must be 3-20 chars, start with a lowercase letter, end with a lowercase letter or digit, and contain only lowercase letters, digits, and single (non-trailing, non-consecutive) hyphens."
  }
}
