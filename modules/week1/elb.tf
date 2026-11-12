data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.selected.id]
  }
}

resource "aws_security_group" "alb_sg" {
  name        = "threat-detection-alb-sg"
  description = "Security group for test ALB"
  vpc_id      = data.aws_vpc.selected.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "test_alb" {
  name               = "audit-test-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = data.aws_subnets.default.ids

  access_logs {
    bucket  = aws_s3_bucket.central_logs.id
    prefix  = "elb-logs"
    enabled = true
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_bucket_policy]
}