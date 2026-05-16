data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  has_admin = var.admin_domain_name != "" && var.admin_certificate_arn != "" && var.admin_hosted_zone_id != ""

  events_table_arn     = "arn:aws:dynamodb:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/${var.events_table_name}"
  aggregates_table_arn = "arn:aws:dynamodb:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/${var.aggregates_table_name}"

  build_dir = "${path.module}/.build"
  zip_path  = "${path.module}/.build/lambda.zip"
}
