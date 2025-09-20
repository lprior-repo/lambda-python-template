# TFLint Configuration for Python Lambda Template
# This configuration enforces AWS security best practices and ThoughtWorks quality standards

config {
  # Enable module inspection
  module = true

  # Force return zero exit code even when issues are found
  force = false

  # Disable color output for CI/CD environments
  disabled_by_default = false
}

# AWS Provider Plugin
plugin "aws" {
  enabled = true
  version = "0.30.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

# Terraform Core Rules
plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

# AWS Lambda Security Rules
rule "aws_lambda_function_dead_letter_config" {
  enabled = true
}

rule "aws_lambda_function_tracing_config" {
  enabled = true
}

rule "aws_lambda_permission_wildcard_principal" {
  enabled = true
}

# IAM Security Rules
rule "aws_iam_policy_document_gov_friendly_arns" {
  enabled = true
}

rule "aws_iam_role_policy_attachment_policy_arn" {
  enabled = true
}

rule "aws_iam_policy_gov_friendly_arns" {
  enabled = true
}

# API Gateway Security Rules
rule "aws_api_gateway_domain_name_invalid_certificate_arn" {
  enabled = true
}

rule "aws_api_gateway_model_invalid_name" {
  enabled = true
}

# DynamoDB Security Rules
rule "aws_dynamodb_table_invalid_stream_view_type" {
  enabled = true
}

rule "aws_dynamodb_table_invalid_index" {
  enabled = true
}

# CloudWatch Security Rules
rule "aws_cloudwatch_log_group_invalid_retention_in_days" {
  enabled = true
}

# S3 Security Rules
rule "aws_s3_bucket_public_access_block" {
  enabled = true
}

rule "aws_s3_bucket_public_read" {
  enabled = true
}

rule "aws_s3_bucket_public_write" {
  enabled = true
}

# Security Group Rules
rule "aws_security_group_rule_invalid_protocol" {
  enabled = true
}

rule "aws_db_instance_invalid_type" {
  enabled = true
}

# Naming Convention Rules
rule "terraform_naming_convention" {
  enabled = true

  # Custom naming patterns
  resource "aws_lambda_function" {
    format = "snake_case"
  }

  resource "aws_iam_role" {
    format = "snake_case"
  }

  resource "aws_dynamodb_table" {
    format = "snake_case"
  }
}

# Required Labels/Tags
rule "terraform_required_labels" {
  enabled = true

  # Ensure all resources have required tags
  labels = [
    "Environment",
    "Project",
    "Team",
    "Cost-Center"
  ]
}

# Documentation Requirements
rule "terraform_documented_outputs" {
  enabled = true
}

rule "terraform_documented_variables" {
  enabled = true
}

# Type Constraints
rule "terraform_typed_variables" {
  enabled = true
}

# Standard Formatting
rule "terraform_standard_module_structure" {
  enabled = true
}