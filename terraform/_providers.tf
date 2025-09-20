terraform {
  required_version = ">= 1.13.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.12"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  backend "s3" {
    # Configuration provided via backend-config
    # bucket = "your-terraform-state-bucket"
    # key    = "lambda-python-template/terraform.tfstate"
    # region = "us-east-1"
  }
}

provider "aws" {
  region = local.aws_region

  default_tags {
    tags = {
      Project     = local.project_name
      Environment = local.environment
      ManagedBy   = "terraform"
    }
  }
}

# Get current AWS account information
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}