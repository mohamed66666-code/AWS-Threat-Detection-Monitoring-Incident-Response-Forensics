data "aws_vpc" "selected" {
  default = true
}

# 1. Quarantine / Isolation Security Group (Deny All Traffic)
resource "aws_security_group" "isolation_sg" {
  name        = "soar-quarantine-isolation-sg"
  description = "Zero-trust isolation security group for compromised instances"
  vpc_id      = data.aws_vpc.selected.id
  # No ingress and no egress rules = complete network isolation
}

# 2. IAM Role for Remediation Lambda
resource "aws_iam_role" "soar_lambda_role" {
  name = "soar-ec2-isolation-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "soar_lambda_policy" {
  name = "soar-ec2-isolation-policy"
  role = aws_iam_role.soar_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceAttribute",
          "ec2:DescribeInstances",
          "ec2:CreateSnapshot"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Zip the Python script automatically
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_remediation.py"
  output_path = "${path.module}/lambda_remediation.zip"
}

# 3. Remediation Lambda Function
resource "aws_lambda_function" "isolate_ec2" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "soar-isolate-compromised-ec2"
  role             = aws_iam_role.soar_lambda_role.arn
  handler          = "lambda_remediation.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 30

  environment {
    variables = {
      ISOLATION_SG_ID = aws_security_group.isolation_sg.id
    }
  }
}

# 4. Security Hub Custom Action (SOAR Trigger from Console)
resource "aws_securityhub_action_target" "isolate_action" {
  name        = "IsolateEC2Instance"
  identifier  = "IsolateEC2Action"
  description = "Triggers SOAR Lambda to isolate a compromised EC2 instance"
}

# 5. EventBridge Rule listening to Security Hub Custom Action
resource "aws_cloudwatch_event_rule" "securityhub_custom_action_rule" {
  name        = "soar-securityhub-isolate-ec2-rule"
  description = "Routes Security Hub IsolateEC2Action to Lambda"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Custom Action"]
    resources   = [aws_securityhub_action_target.isolate_action.arn]
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.securityhub_custom_action_rule.name
  target_id = "IsolateEC2LambdaTarget"
  arn       = aws_lambda_function.isolate_ec2.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.isolate_ec2.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub_custom_action_rule.arn
}