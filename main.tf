# =========================================================
# 1. CENTRAL S3 LOG ARCHIVE
# =========================================================

resource "aws_s3_bucket" "log_archive" {
  bucket = var.log_bucket_name

  tags = {
    Name        = var.log_bucket_name
    Project     = var.project_name
    Environment = var.environment
    Owner       = "Person-1"
    Purpose     = "Security-Log-Archive"
  }
}

resource "aws_s3_bucket_public_access_block" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  versioning_configuration {
    status = "Enabled"
  }
}


# =========================================================
# 2. KMS ENCRYPTION
# =========================================================

resource "aws_kms_key" "log_encryption" {
  description             = "KMS key for AWS IR security logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = {
    Name    = "aws-ir-log-encryption"
    Project = var.project_name
    Owner   = "Person-1"
  }
}

resource "aws_kms_alias" "log_encryption" {
  name          = "alias/aws-ir-log-encryption"
  target_key_id = aws_kms_key.log_encryption.key_id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.log_encryption.arn
    }

    bucket_key_enabled = true
  }
}


# =========================================================
# 3. AWS ACCOUNT INFORMATION
# =========================================================

data "aws_caller_identity" "current" {}


# =========================================================
# 4. S3 BUCKET POLICY
# CLOUDTRAIL + AWS CONFIG
# =========================================================

resource "aws_s3_bucket_policy" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [

      # CloudTrail bucket permission check
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"

        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.log_archive.arn

        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${var.project_name}-${var.environment}-trail"
          }
        }
      },

      # CloudTrail write permission
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"

        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.log_archive.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"

        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${var.project_name}-${var.environment}-trail"
          }
        }
      },

      # AWS Config bucket permission check
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"

        Principal = {
          Service = "config.amazonaws.com"
        }

        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.log_archive.arn

        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },

      # AWS Config write permission
      {
        Sid    = "AWSConfigWrite"
        Effect = "Allow"

        Principal = {
          Service = "config.amazonaws.com"
        }

        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.log_archive.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"

        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}


# =========================================================
# 5. KMS KEY POLICY
# CLOUDTRAIL + AWS CONFIG
# =========================================================

resource "aws_kms_key_policy" "log_encryption" {
  key_id = aws_kms_key.log_encryption.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [

      # Account administrator permissions
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"

        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }

        Action   = "kms:*"
        Resource = "*"
      },

      # CloudTrail encryption permissions
      {
        Sid    = "AllowCloudTrailEncryption"
        Effect = "Allow"

        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]

        Resource = "*"

        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${var.project_name}-${var.environment}-trail"
          }
        }
      },

      # AWS Config encryption permissions
      {
        Sid    = "AllowAWSConfigEncryption"
        Effect = "Allow"

        Principal = {
          Service = "config.amazonaws.com"
        }

        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]

        Resource = "*"

        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}


# =========================================================
# 6. CLOUDTRAIL MULTI-REGION
# =========================================================

resource "aws_cloudtrail" "main" {
  name           = "${var.project_name}-${var.environment}-trail"
  s3_bucket_name = aws_s3_bucket.log_archive.id

  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.log_encryption.arn

  depends_on = [
    aws_s3_bucket_policy.log_archive,
    aws_kms_key_policy.log_encryption
  ]

  tags = {
    Name    = "${var.project_name}-${var.environment}-trail"
    Project = var.project_name
    Owner   = "Person-1"
  }

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    dynamic "data_resource" {
      for_each = length(var.sensitive_s3_bucket_arns) > 0 ? [1] : []

      content {
        type   = "AWS::S3::Object"
        values = var.sensitive_s3_bucket_arns
      }
    }
  }
}


# =========================================================
# 7. S3 LOG RETENTION
# =========================================================

resource "aws_s3_bucket_lifecycle_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    id     = "security-logs-retention"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.log_archive
  ]
}


# =========================================================
# 8. AWS CONFIG IAM ROLE
# =========================================================

resource "aws_iam_role" "config_role" {
  name = "${var.project_name}-${var.environment}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "config.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name    = "${var.project_name}-config-role"
    Project = var.project_name
    Owner   = "Person-1"
  }
}

resource "aws_iam_role_policy_attachment" "config_role" {
  role = aws_iam_role.config_role.name

  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}


# =========================================================
# 9. AWS CONFIG CONFIGURATION RECORDER
# =========================================================

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project_name}-${var.environment}-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.config_role
  ]
}


# =========================================================
# 10. AWS CONFIG DELIVERY CHANNEL
# =========================================================

resource "aws_config_delivery_channel" "main" {
  name           = "${var.project_name}-${var.environment}-delivery"
  s3_bucket_name = aws_s3_bucket.log_archive.bucket

  depends_on = [
    aws_s3_bucket_policy.log_archive,
    aws_kms_key_policy.log_encryption
  ]
}


# =========================================================
# 11. START AWS CONFIG RECORDING
# =========================================================

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [
    aws_config_delivery_channel.main
  ]
}