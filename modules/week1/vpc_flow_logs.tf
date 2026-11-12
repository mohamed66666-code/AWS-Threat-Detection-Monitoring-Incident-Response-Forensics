# Get default VPC to enable flow logs on it
data "aws_vpc" "selected" {
  default = true
}

resource "aws_flow_log" "vpc_flow_log" {
  log_destination      = "${aws_s3_bucket.central_logs.arn}/vpc-flow-logs"
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = data.aws_vpc.selected.id
}