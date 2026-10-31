terraform {
  backend "s3" {
    bucket       = "terraform-state-403659231312"
    key          = "dev/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}