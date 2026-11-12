locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

module "week1_logging" {
  source      = "./modules/week1"
  aws_region  = var.aws_region
  project_name = var.project_name
  environment  = var.environment
}

module "week2_threat_detection" {
  source       = "./modules/week2"
  aws_region   = var.aws_region
  project_name = var.project_name
  environment  = var.environment

  depends_on = [module.week1_logging]
}

module "week3_incident_response" {
  source       = "./modules/week3"
  aws_region   = var.aws_region
  project_name = var.project_name
  environment  = var.environment

  depends_on = [module.week2_threat_detection]
}
module "week4_automation" {
  source       = "./modules/week4"
  aws_region   = var.aws_region
  project_name = var.project_name
  environment  = var.environment

  depends_on = [module.week3_incident_response]
}