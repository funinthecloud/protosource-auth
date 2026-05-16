# Admin SPA: S3 (private) + CloudFront w/ OAC + Route53 alias.
# Mirrors the SAM `HasAdminDomain` condition.

resource "aws_s3_bucket" "admin" {
  count         = local.has_admin ? 1 : 0
  bucket_prefix = "${var.stack_name}-admin-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "admin" {
  count                   = local.has_admin ? 1 : 0
  bucket                  = aws_s3_bucket.admin[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudfront_origin_access_control" "admin" {
  count                             = local.has_admin ? 1 : 0
  name                              = "${var.admin_domain_name}-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "admin" {
  count   = local.has_admin ? 1 : 0
  enabled = true
  aliases = [var.admin_domain_name]

  default_root_object = "index.html"

  origin {
    origin_id                = "S3Origin"
    domain_name              = aws_s3_bucket.admin[0].bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.admin[0].id
  }

  default_cache_behavior {
    target_origin_id       = "S3Origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = "658327ea-f89d-4fab-a63d-7e88639e58f6" # CachingOptimized
    compress               = true
  }

  custom_error_response {
    error_code         = 403
    response_code      = 200
    response_page_path = "/index.html"
  }

  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  viewer_certificate {
    acm_certificate_arn      = var.admin_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}

data "aws_iam_policy_document" "admin_bucket" {
  count = local.has_admin ? 1 : 0
  statement {
    sid     = "AllowCloudFrontRead"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.admin[0].arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.admin[0].arn]
    }
  }
}

resource "aws_s3_bucket_policy" "admin" {
  count  = local.has_admin ? 1 : 0
  bucket = aws_s3_bucket.admin[0].id
  policy = data.aws_iam_policy_document.admin_bucket[0].json
}

resource "aws_route53_record" "admin" {
  count   = local.has_admin ? 1 : 0
  zone_id = var.admin_hosted_zone_id
  name    = var.admin_domain_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.admin[0].domain_name
    zone_id                = "Z2FDTNDATAQYW2" # CloudFront global hosted zone
    evaluate_target_health = false
  }
}
