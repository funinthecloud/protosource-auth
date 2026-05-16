output "api_url" {
  value = "https://${aws_api_gateway_rest_api.auth.id}.execute-api.${data.aws_region.current.name}.amazonaws.com/${aws_api_gateway_stage.prod.stage_name}/"
}

output "custom_domain_url" {
  value = "https://${var.domain_name}/"
}

output "auth_function_arn" {
  value = aws_lambda_function.auth.arn
}

output "admin_url" {
  value = local.has_admin ? "https://${var.admin_domain_name}/" : null
}

output "admin_bucket_name" {
  value = local.has_admin ? aws_s3_bucket.admin[0].id : null
}

output "admin_distribution_id" {
  value = local.has_admin ? aws_cloudfront_distribution.admin[0].id : null
}
