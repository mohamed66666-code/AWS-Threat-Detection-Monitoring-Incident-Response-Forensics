resource "aws_ssm_document" "forensic_runbook" {
  name            = "SOAR-Forensic-Evidence-Collection"
  document_type   = "Automation"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '0.3'
description: 'Automated Forensic Runbook to snapshot EBS volume of an instance'
parameters:
  VolumeId:
    type: String
    description: 'The EBS Volume ID to snapshot'
mainSteps:
  - name: CreateForensicSnapshot
    action: 'aws:executeAwsApi'
    inputs:
      Service: ec2
      Api: CreateSnapshot
      VolumeId: '{{ VolumeId }}'
      Description: 'Automated SOAR Forensic Snapshot'
DOC
}