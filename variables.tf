variable "aws_region" {
  description = "AWS region for the project"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "aws-ir"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "lab"
}

variable "log_bucket_name" {
  description = "Globally unique S3 bucket name for storing security logs"
  type        = string

  validation {
    condition = (
      length(var.log_bucket_name) >= 3 &&
      length(var.log_bucket_name) <= 63 &&
      can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.log_bucket_name)) &&
      !strcontains(var.log_bucket_name, "..")
    )

    error_message = "The S3 bucket name must be 3-63 characters, lowercase, and use valid S3 bucket naming characters."
  }
}

variable "sensitive_s3_bucket_arns" {
  description = "S3 bucket ARNs to monitor for data events"
  type        = list(string)
  default     = []
}