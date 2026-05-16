variable "region" {
  type    = string
  default = "us-east-1"
}

variable "stack_name" {
  type        = string
  description = "Resource name prefix."
  default     = "protosource-auth"
}

variable "events_table_name" {
  type    = string
  default = "events"
}

variable "aggregates_table_name" {
  type    = string
  default = "aggregates"
}

variable "kms_key_arn" {
  type        = string
  description = "Full KMS key ARN used by the service for envelope encryption of signing keys."
}

variable "domain_name" {
  type        = string
  description = "Custom domain for the auth API (e.g. auth.example.com)."
}

variable "certificate_arn" {
  type        = string
  description = "ACM certificate ARN for the API domain (regional, same region as API)."
}

variable "hosted_zone_id" {
  type        = string
  description = "Route53 hosted zone ID for the API domain."
}

variable "cors_origin" {
  type        = string
  default     = ""
  description = "Allowed CORS origin(s) for the admin frontend. Comma-separated."
}

variable "admin_domain_name" {
  type        = string
  default     = ""
  description = "Custom domain for admin SPA. Empty disables admin infra."
}

variable "admin_certificate_arn" {
  type        = string
  default     = ""
  description = "ACM certificate ARN for admin domain (must be in us-east-1 for CloudFront)."
}

variable "admin_hosted_zone_id" {
  type        = string
  default     = ""
  description = "Route53 hosted zone ID for admin domain."
}

variable "lambda_source_dir" {
  type        = string
  description = "Path to the lambda Go package (relative to this module)."
  default     = "../../cmd/protosource-auth-lambda"
}

variable "lambda_timeout" {
  type    = number
  default = 10
}

variable "lambda_memory_mb" {
  type    = number
  default = 256
}
