# tofu

OpenTofu modules that replace the (removed) AWS SAM deployment.

Layout:
- `bootstrap/` — one-shot: creates the S3 state bucket + DynamoDB lock table.
- `aws/` — the live stack: Lambda + API Gateway + custom domain + admin SPA (S3/CloudFront).

The DynamoDB *data* tables (`events`, `aggregates`), the KMS key, ACM certs, and Route53 zones are **not** managed here — same as under SAM. Create the data tables with `protosource-authmgr ensure-tables` before applying.

## One-time: bootstrap remote state

```bash
cd tofu/bootstrap
tofu init
tofu apply -var state_bucket_name=protosource-auth-tfstate-<accountid>
tofu output backend_config_snippet
```

## Deploy AWS stack

```bash
cd tofu/aws
cp terraform.tfvars.example terraform.tfvars   # edit values
tofu init -backend-config=backend.hcl
tofu apply
```

The lambda binary is built by `tofu apply` via `go build` against `./cmd/protosource-auth-lambda` — `go` must be on PATH.

## Azure

Pending. Handled as a separate step.
