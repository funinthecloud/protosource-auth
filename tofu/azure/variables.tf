variable "subscription_id" {
  description = "Azure subscription ID to deploy into. Required so the env doesn't accidentally target whichever subscription `az account show` returns."
  type        = string
}

variable "location" {
  description = "Azure region for the env."
  type        = string
  default     = "eastus"
}

variable "name_prefix" {
  description = "Lowercase prefix for resource names (3-20 chars). Used to derive globally-unique names (ACR, Cosmos account, Key Vault) with a deterministic hash suffix."
  type        = string
  default     = "protosrc-auth"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,20}$", var.name_prefix))
    error_message = "name_prefix must be 3-20 chars of lowercase letters, digits, or hyphens."
  }
}

variable "image" {
  description = "Container image to run. Stays on the Microsoft quickstart until you push your own protosource-auth image to the ACR this stack creates."
  type        = string
  default     = "mcr.microsoft.com/k8se/quickstart:latest"
}

variable "issuer_iss" {
  description = "JWT `iss` claim value advertised by the default issuer. Required."
  type        = string
}

variable "issuer_id" {
  description = "Default issuer aggregate id."
  type        = string
  default     = "default"
}

variable "issuer_display_name" {
  description = "Human-readable default issuer name."
  type        = string
  default     = "protosource-auth"
}

variable "token_ttl" {
  description = "Lifetime for issued shadow tokens, as a Go time.Duration string (e.g. \"10h\") or integer seconds."
  type        = string
  default     = "10h"
}

variable "cors_origin" {
  description = "Allowed CORS origin(s) for the admin frontend (comma-separated). Empty disables CORS."
  type        = string
  default     = ""
}

variable "cosmos_serverless" {
  description = "Run Cosmos under the Serverless capability. Recommended for dev and low-traffic workloads."
  type        = bool
  default     = true
}

variable "cosmos_database" {
  description = "Cosmos SQL database id."
  type        = string
  default     = "protosource-auth"
}

variable "key_vault_kek_name" {
  description = "Name of the HSM-backed RSA key in Key Vault that wraps signing-key material."
  type        = string
  default     = "protosource-auth-kek"
}

variable "key_vault_kek_size" {
  description = "RSA key size for the KEK. 3072 is the cheapest HSM size that passes most compliance baselines; 4096 adds future-proofing at marginal cost."
  type        = number
  default     = 3072

  validation {
    condition     = contains([2048, 3072, 4096], var.key_vault_kek_size)
    error_message = "key_vault_kek_size must be 2048, 3072, or 4096."
  }
}

variable "min_replicas" {
  description = "Minimum Container App replicas. 0 enables scale-to-zero."
  type        = number
  default     = 0
}

variable "max_replicas" {
  description = "Maximum Container App replicas."
  type        = number
  default     = 3
}

variable "container_cpu" {
  description = "vCPU per Container App replica. Must pair with container_memory per the Container Apps matrix."
  type        = number
  default     = 0.5
}

variable "container_memory" {
  description = "Memory per Container App replica."
  type        = string
  default     = "1Gi"
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default = {
    project   = "protosource-auth"
    managedBy = "tofu"
  }
}
