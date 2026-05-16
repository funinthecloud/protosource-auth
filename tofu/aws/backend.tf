# Configure via `tofu init -backend-config=...` using the output from tofu/bootstrap.
# Example:
#   tofu init \
#     -backend-config="bucket=<from-bootstrap>" \
#     -backend-config="key=aws/protosource-auth.tfstate" \
#     -backend-config="region=us-east-1" \
#     -backend-config="dynamodb_table=<from-bootstrap>" \
#     -backend-config="encrypt=true"
terraform {
  backend "s3" {}
}
