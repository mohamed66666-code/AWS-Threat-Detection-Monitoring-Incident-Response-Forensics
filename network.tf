resource "aws_vpc" "Vpc_Test" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "My-Vpc_Test"
  }
}