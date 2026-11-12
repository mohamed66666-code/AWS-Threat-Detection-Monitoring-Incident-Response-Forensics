output "isolation_sg_id" {
  value = aws_security_group.isolation_sg.id
}

output "remediation_lambda_arn" {
  value = aws_lambda_function.isolate_ec2.arn
}

output "securityhub_custom_action_arn" {
  value = aws_securityhub_action_target.isolate_action.arn
}

output "ssm_runbook_name" {
  value = aws_ssm_document.forensic_runbook.name
}