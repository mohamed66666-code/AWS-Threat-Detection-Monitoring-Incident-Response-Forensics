output "target_instance_id" {
  value = aws_instance.target_instance.id
}

output "target_instance_ip" {
  value = aws_instance.target_instance.public_ip
}