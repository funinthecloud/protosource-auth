# Build the Go lambda binary. The hash covers every .go file the build could
# pull in (lambda main + every in-repo package it can import) plus go.sum.
# Cheaper than getting it wrong -- go build itself is incremental, so re-running
# when nothing changed costs ~ms but a missed rebuild ships stale code.
resource "null_resource" "build_lambda" {
  triggers = {
    source_hash = sha256(join("", [
      for f in fileset("${path.module}/../..", "**/*.go") :
      filesha256("${path.module}/../../${f}")
    ]))
    go_sum = filesha256("${path.module}/../../go.sum")
  }

  provisioner "local-exec" {
    working_dir = "${path.module}/../.."
    command     = <<-EOT
      set -euo pipefail
      mkdir -p "${abspath(local.build_dir)}"
      GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
        go build -trimpath -ldflags='-s -w' \
          -o "${abspath(local.build_dir)}/bootstrap" \
          ./cmd/protosource-auth-lambda
    EOT
  }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = local.zip_path
  source_file = "${local.build_dir}/bootstrap"
  depends_on  = [null_resource.build_lambda]
}

# ── IAM ──

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.stack_name}-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "lambda_inline" {
  statement {
    sid    = "DynamoDBCrud"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:BatchGetItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:ConditionCheckItem",
      "dynamodb:DescribeTable",
    ]
    resources = [
      local.events_table_arn,
      "${local.events_table_arn}/index/*",
      local.aggregates_table_arn,
      "${local.aggregates_table_arn}/index/*",
    ]
  }

  statement {
    sid       = "KMS"
    effect    = "Allow"
    actions   = ["kms:Encrypt", "kms:Decrypt"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "lambda_inline" {
  name   = "${var.stack_name}-lambda-inline"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_inline.json
}

# ── Function ──

resource "aws_lambda_function" "auth" {
  function_name    = "${var.stack_name}-auth"
  role             = aws_iam_role.lambda.arn
  handler          = "bootstrap"
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_mb

  environment {
    variables = {
      PROTOSOURCE_AUTH_EVENTS_TABLE     = var.events_table_name
      PROTOSOURCE_AUTH_AGGREGATES_TABLE = var.aggregates_table_name
      PROTOSOURCE_AUTH_KMS_KEY_ARN      = var.kms_key_arn
      PROTOSOURCE_AUTH_CORS_ORIGIN      = var.cors_origin
    }
  }
}
