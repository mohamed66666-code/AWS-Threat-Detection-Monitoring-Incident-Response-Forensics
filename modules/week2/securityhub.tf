resource "aws_securityhub_account" "main" {
  enable_default_standards = true
}

# Enable AWS Foundational Security Best Practices standard
resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}