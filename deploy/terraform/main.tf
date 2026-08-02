# Terraform Production Infrastructure configuration for Aegis Enterprise CNAPP

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "us-east-1"
}

resource "aws_vpc" "aegis_vpc" {
  cidr_block           = "10.100.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "aegis-cnapp-vpc"
    Environment = "production"
  }
}

resource "aws_db_instance" "postgres_ha" {
  allocated_storage       = 100
  engine                  = "postgres"
  engine_version          = "15.4"
  instance_class          = "db.r6g.xlarge"
  multi_az                = true
  db_name                 = "aegis_prod"
  username                = "aegis_admin"
  password                = "SecureRandomPassword2026!"
  storage_encrypted       = true
  skip_final_snapshot     = true
  publicly_accessible     = false
}
