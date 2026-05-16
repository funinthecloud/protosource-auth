output "state_bucket" {
  value = aws_s3_bucket.state.id
}

output "lock_table" {
  value = aws_dynamodb_table.locks.name
}

output "backend_config_snippet" {
  description = "Paste this into tofu/aws/backend.tf bucket/dynamodb_table fields, or pass via -backend-config."
  value = <<-EOT
    bucket         = "${aws_s3_bucket.state.id}"
    key            = "aws/protosource-auth.tfstate"
    region         = "${var.region}"
    dynamodb_table = "${aws_dynamodb_table.locks.name}"
    encrypt        = true
  EOT
}
