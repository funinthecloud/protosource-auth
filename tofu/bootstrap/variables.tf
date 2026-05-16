variable "region" {
  type        = string
  description = "AWS region for the state bucket and lock table."
  default     = "us-east-1"
}

variable "state_bucket_name" {
  type        = string
  description = "Globally-unique S3 bucket name for tofu remote state."
}

variable "lock_table_name" {
  type        = string
  description = "DynamoDB table name for tofu state locking."
  default     = "protosource-auth-tofu-locks"
}
