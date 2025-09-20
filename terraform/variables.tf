variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "function_name" {
  description = "Base name for Lambda functions"
  type        = string
  default     = "python-lambda"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "namespace" {
  description = "Namespace for resource naming (enables ephemeral infrastructure)"
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^[a-z0-9-]*$", var.namespace))
    error_message = "Namespace must contain only lowercase letters, numbers, and hyphens."
  }
}

