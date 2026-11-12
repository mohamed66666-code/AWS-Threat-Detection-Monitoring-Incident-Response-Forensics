output "central_logs_bucket_id" {
  value = aws_s3_bucket.central_logs.id
}

output "central_logs_bucket_arn" {
  value = aws_s3_bucket.central_logs.arn
}