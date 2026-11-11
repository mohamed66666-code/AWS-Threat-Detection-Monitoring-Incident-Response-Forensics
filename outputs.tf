# S3 Log Archive Outputs

output "log_archive_bucket_name" {
  description = "Name of the central log archive bucket"
  value       = aws_s3_bucket.log_archive.bucket
}

output "log_archive_bucket_arn" {
  description = "ARN of the central log archive bucket"
  value       = aws_s3_bucket.log_archive.arn
}

output "log_archive_bucket_region" {
  description = "AWS region of the log archive bucket"
  value       = var.aws_region
}


# KMS Encryption Outputs

output "kms_key_arn" {
  description = "ARN of the security logs encryption key"
  value       = aws_kms_key.log_encryption.arn
}


# CloudTrail Outputs

output "cloudtrail_name" {
  description = "Name of the multi-region CloudTrail"
  value       = aws_cloudtrail.main.name
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail"
  value       = aws_cloudtrail.main.arn
}


# AWS Config Outputs

output "config_recorder_name" {
  description = "AWS Config configuration recorder name"
  value       = aws_config_configuration_recorder.main.name
}

output "config_delivery_channel_name" {
  description = "AWS Config delivery channel name"
  value       = aws_config_delivery_channel.main.name
}