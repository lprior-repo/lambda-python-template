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

# ========================================
# API Gateway Configuration
# ========================================

variable "api_throttling_rate_limit" {
  description = "API Gateway throttling rate limit (requests per second)"
  type        = number
  default     = 1000
  validation {
    condition     = var.api_throttling_rate_limit >= 1 && var.api_throttling_rate_limit <= 10000
    error_message = "API throttling rate limit must be between 1 and 10000."
  }
}

variable "api_throttling_burst_limit" {
  description = "API Gateway throttling burst limit"
  type        = number
  default     = 2000
  validation {
    condition     = var.api_throttling_burst_limit >= 1 && var.api_throttling_burst_limit <= 10000
    error_message = "API throttling burst limit must be between 1 and 10000."
  }
}

variable "api_domain_name" {
  description = "Custom domain name for API Gateway (leave empty to skip)"
  type        = string
  default     = ""
}

variable "api_certificate_arn" {
  description = "ARN of SSL certificate for custom domain (required if domain_name is set)"
  type        = string
  default     = ""
}

# ========================================
# Security Configuration
# ========================================

variable "enable_waf" {
  description = "Enable WAF for API Gateway"
  type        = bool
  default     = false
}

variable "allowed_ips" {
  description = "List of allowed IP addresses/CIDR blocks"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# ========================================
# Lambda Configuration
# ========================================

variable "lambda_memory_size" {
  description = "Memory size for Lambda functions (MB)"
  type        = number
  default     = 512
  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory size must be between 128 and 10240 MB."
  }
}

variable "lambda_timeout" {
  description = "Timeout for Lambda functions (seconds)"
  type        = number
  default     = 30
  validation {
    condition     = var.lambda_timeout >= 1 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 1 and 900 seconds."
  }
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrency for Lambda functions (0 = no limit)"
  type        = number
  default     = 0
  validation {
    condition     = var.lambda_reserved_concurrency >= 0
    error_message = "Lambda reserved concurrency must be non-negative."
  }
}

# ========================================
# DynamoDB Configuration
# ========================================

variable "dynamodb_billing_mode" {
  description = "DynamoDB billing mode"
  type        = string
  default     = "PAY_PER_REQUEST"
  validation {
    condition     = contains(["PAY_PER_REQUEST", "PROVISIONED"], var.dynamodb_billing_mode)
    error_message = "DynamoDB billing mode must be either PAY_PER_REQUEST or PROVISIONED."
  }
}

variable "dynamodb_read_capacity" {
  description = "DynamoDB read capacity units (only used with PROVISIONED billing)"
  type        = number
  default     = 5
}

variable "dynamodb_write_capacity" {
  description = "DynamoDB write capacity units (only used with PROVISIONED billing)"
  type        = number
  default     = 5
}

variable "enable_point_in_time_recovery" {
  description = "Enable point-in-time recovery for DynamoDB tables"
  type        = bool
  default     = true
}

# ========================================
# Monitoring and Logging
# ========================================

variable "log_retention_in_days" {
  description = "CloudWatch logs retention period (days)"
  type        = number
  default     = 14
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_in_days)
    error_message = "Log retention must be a valid CloudWatch value."
  }
}

variable "enable_xray_tracing" {
  description = "Enable X-Ray tracing for Lambda functions"
  type        = bool
  default     = true
}

variable "enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring features"
  type        = bool
  default     = true
}

# ========================================
# Tags
# ========================================

variable "additional_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# ========================================
# Monitoring and Alerting
# ========================================

variable "monthly_budget_limit" {
  description = "Monthly budget limit for cost monitoring (USD)"
  type        = string
  default     = "100"
  validation {
    condition     = can(tonumber(var.monthly_budget_limit)) && tonumber(var.monthly_budget_limit) > 0
    error_message = "Monthly budget limit must be a positive number."
  }
}

variable "budget_notification_emails" {
  description = "List of email addresses for budget notifications"
  type        = list(string)
  default     = []
  validation {
    condition = length(var.budget_notification_emails) == 0 || alltrue([
      for email in var.budget_notification_emails : can(regex("^[\\w\\.-]+@[\\w\\.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "All budget notification emails must be valid email addresses."
  }
}

variable "alert_email_address" {
  description = "Email address for critical alerts (optional)"
  type        = string
  default     = ""
  validation {
    condition     = var.alert_email_address == "" || can(regex("^[\\w\\.-]+@[\\w\\.-]+\\.[a-zA-Z]{2,}$", var.alert_email_address))
    error_message = "Alert email address must be a valid email address or empty."
  }
}

variable "powertools_service_name" {
  description = "Service name for Lambda Powertools metrics namespace"
  type        = string
  default     = "lambda-python-template"
}

variable "enable_business_metrics_dashboard" {
  description = "Enable CloudWatch dashboard for business metrics"
  type        = bool
  default     = true
}

variable "alarm_evaluation_periods" {
  description = "Number of evaluation periods for CloudWatch alarms"
  type        = number
  default     = 2
  validation {
    condition     = var.alarm_evaluation_periods >= 1 && var.alarm_evaluation_periods <= 5
    error_message = "Alarm evaluation periods must be between 1 and 5."
  }
}

variable "lambda_error_threshold" {
  description = "Error count threshold for Lambda function alarms"
  type        = number
  default     = 5
  validation {
    condition     = var.lambda_error_threshold >= 1
    error_message = "Lambda error threshold must be at least 1."
  }
}

variable "api_gateway_error_threshold" {
  description = "Error count threshold for API Gateway alarms"
  type        = number
  default     = 10
  validation {
    condition     = var.api_gateway_error_threshold >= 1
    error_message = "API Gateway error threshold must be at least 1."
  }
}

variable "lambda_duration_threshold_ms" {
  description = "Duration threshold in milliseconds for Lambda function alarms"
  type        = number
  default     = 10000
  validation {
    condition     = var.lambda_duration_threshold_ms >= 1000
    error_message = "Lambda duration threshold must be at least 1000ms."
  }
}

# ========================================
# Kinesis Configuration
# ========================================

variable "kinesis_shard_count" {
  description = "Number of shards for Kinesis streams"
  type        = number
  default     = 1
  validation {
    condition     = var.kinesis_shard_count >= 1 && var.kinesis_shard_count <= 1000
    error_message = "Kinesis shard count must be between 1 and 1000."
  }
}

variable "kinesis_retention_hours" {
  description = "Data retention period for Kinesis streams (hours)"
  type        = number
  default     = 24
  validation {
    condition     = var.kinesis_retention_hours >= 24 && var.kinesis_retention_hours <= 8760
    error_message = "Kinesis retention period must be between 24 hours and 365 days (8760 hours)."
  }
}

variable "enable_kinesis_analytics" {
  description = "Enable Kinesis Data Analytics for real-time processing"
  type        = bool
  default     = true
}

variable "enable_dynamodb_streams" {
  description = "Enable DynamoDB streams for change data capture"
  type        = bool
  default     = true
}

variable "kinesis_encryption_enabled" {
  description = "Enable server-side encryption for Kinesis streams"
  type        = bool
  default     = true
}

# ========================================
# Security Configuration
# ========================================

variable "enable_waf" {
  description = "Enable AWS WAF v2 for API Gateway protection"
  type        = bool
  default     = false
}

variable "waf_rate_limit" {
  description = "Rate limit for WAF (requests per 5 minutes)"
  type        = number
  default     = 2000
  validation {
    condition     = var.waf_rate_limit >= 100 && var.waf_rate_limit <= 20000000
    error_message = "WAF rate limit must be between 100 and 20,000,000."
  }
}

variable "waf_blocked_requests_threshold" {
  description = "Threshold for WAF blocked requests alarm"
  type        = number
  default     = 100
}

variable "enable_waf_logging" {
  description = "Enable WAF logging to CloudWatch"
  type        = bool
  default     = true
}

variable "blocked_ips" {
  description = "List of IP addresses/CIDR blocks to block"
  type        = list(string)
  default     = []
}

variable "blocked_countries" {
  description = "List of country codes to block (ISO 3166-1 alpha-2)"
  type        = list(string)
  default     = []
}

variable "cors_allowed_origins" {
  description = "List of allowed CORS origins"
  type        = list(string)
  default     = ["*"]
}

# ========================================
# Secrets Manager Configuration
# ========================================

variable "secret_recovery_window_days" {
  description = "Recovery window for deleted secrets (days)"
  type        = number
  default     = 7
  validation {
    condition     = var.secret_recovery_window_days >= 7 && var.secret_recovery_window_days <= 30
    error_message = "Secret recovery window must be between 7 and 30 days."
  }
}

variable "backup_region" {
  description = "Backup region for secret replication"
  type        = string
  default     = "us-west-2"
}

# Database credentials (use secure input methods in production)
variable "database_username" {
  description = "Database username"
  type        = string
  default     = "postgres"
  sensitive   = true
}

variable "database_password" {
  description = "Database password"
  type        = string
  default     = "changeme"
  sensitive   = true
}

variable "database_host" {
  description = "Database host"
  type        = string
  default     = "localhost"
}

variable "database_port" {
  description = "Database port"
  type        = number
  default     = 5432
}

variable "database_name" {
  description = "Database name"
  type        = string
  default     = "app_db"
}

# External API keys (use secure input methods in production)
variable "stripe_secret_key" {
  description = "Stripe secret key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "sendgrid_api_key" {
  description = "SendGrid API key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_webhook_url" {
  description = "Slack webhook URL"
  type        = string
  default     = ""
  sensitive   = true
}

variable "datadog_api_key" {
  description = "Datadog API key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "jwt_signing_key" {
  description = "JWT signing key"
  type        = string
  default     = "your-super-secret-jwt-key-change-in-production"
  sensitive   = true
}

variable "encryption_key" {
  description = "Application encryption key"
  type        = string
  default     = "your-32-char-encryption-key-here"
  sensitive   = true
}

variable "jwt_access_secret" {
  description = "JWT access token secret"
  type        = string
  default     = "access-token-secret-change-me"
  sensitive   = true
}

variable "jwt_refresh_secret" {
  description = "JWT refresh token secret"
  type        = string
  default     = "refresh-token-secret-change-me"
  sensitive   = true
}

# ========================================
# Parameter Store Configuration
# ========================================

variable "app_config_parameters" {
  description = "Application configuration parameters"
  type = map(object({
    value = string
    type  = string
    tier  = string
  }))
  default = {
    max_connections = {
      value = "100"
      type  = "String"
      tier  = "Standard"
    }
    cache_size = {
      value = "1000"
      type  = "String"
      tier  = "Standard"
    }
    api_version = {
      value = "v1"
      type  = "String"
      tier  = "Standard"
    }
  }
}

variable "feature_flag_parameters" {
  description = "Feature flag parameters"
  type        = map(string)
  default = {
    enable_advanced_logging = "true"
    enable_caching         = "true"
    enable_metrics         = "true"
    enable_auth_validation = "true"
    enable_rate_limiting   = "true"
  }
}

# ========================================
# VPC Configuration
# ========================================

variable "enable_vpc_endpoints" {
  description = "Enable VPC endpoints for secure service communication"
  type        = bool
  default     = false
}

variable "vpc_id" {
  description = "VPC ID for VPC endpoints"
  type        = string
  default     = ""
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for VPC endpoints"
  type        = list(string)
  default     = []
}

variable "route_table_ids" {
  description = "Route table IDs for VPC endpoints"
  type        = list(string)
  default     = []
}

# ========================================
# Performance Optimization Configuration
# ========================================

variable "enable_provisioned_concurrency" {
  description = "Enable Lambda provisioned concurrency to eliminate cold starts"
  type        = bool
  default     = false
}

variable "health_lambda_provisioned_concurrency" {
  description = "Provisioned concurrency for health Lambda function"
  type        = number
  default     = 5
  validation {
    condition     = var.health_lambda_provisioned_concurrency >= 1
    error_message = "Provisioned concurrency must be at least 1."
  }
}

variable "users_lambda_provisioned_concurrency" {
  description = "Provisioned concurrency for users Lambda function"
  type        = number
  default     = 10
  validation {
    condition     = var.users_lambda_provisioned_concurrency >= 1
    error_message = "Provisioned concurrency must be at least 1."
  }
}

variable "orders_lambda_provisioned_concurrency" {
  description = "Provisioned concurrency for orders Lambda function"
  type        = number
  default     = 10
  validation {
    condition     = var.orders_lambda_provisioned_concurrency >= 1
    error_message = "Provisioned concurrency must be at least 1."
  }
}

variable "enable_lambda_autoscaling" {
  description = "Enable auto-scaling for Lambda provisioned concurrency"
  type        = bool
  default     = false
}

variable "lambda_min_provisioned_concurrency" {
  description = "Minimum provisioned concurrency for auto-scaling"
  type        = number
  default     = 5
}

variable "lambda_max_provisioned_concurrency" {
  description = "Maximum provisioned concurrency for auto-scaling"
  type        = number
  default     = 100
  validation {
    condition     = var.lambda_max_provisioned_concurrency >= var.lambda_min_provisioned_concurrency
    error_message = "Maximum provisioned concurrency must be greater than or equal to minimum."
  }
}

variable "cold_start_duration_threshold" {
  description = "Cold start duration threshold in milliseconds for alarms"
  type        = number
  default     = 3000
}

# ========================================
# DynamoDB Auto-scaling Configuration
# ========================================

variable "dynamodb_min_read_capacity" {
  description = "Minimum read capacity units for DynamoDB auto-scaling"
  type        = number
  default     = 5
  validation {
    condition     = var.dynamodb_min_read_capacity >= 1
    error_message = "Minimum read capacity must be at least 1."
  }
}

variable "dynamodb_max_read_capacity" {
  description = "Maximum read capacity units for DynamoDB auto-scaling"
  type        = number
  default     = 40000
  validation {
    condition     = var.dynamodb_max_read_capacity >= var.dynamodb_min_read_capacity
    error_message = "Maximum read capacity must be greater than or equal to minimum."
  }
}

variable "dynamodb_min_write_capacity" {
  description = "Minimum write capacity units for DynamoDB auto-scaling"
  type        = number
  default     = 5
  validation {
    condition     = var.dynamodb_min_write_capacity >= 1
    error_message = "Minimum write capacity must be at least 1."
  }
}

variable "dynamodb_max_write_capacity" {
  description = "Maximum write capacity units for DynamoDB auto-scaling"
  type        = number
  default     = 40000
  validation {
    condition     = var.dynamodb_max_write_capacity >= var.dynamodb_min_write_capacity
    error_message = "Maximum write capacity must be greater than or equal to minimum."
  }
}

variable "dynamodb_unused_capacity_threshold" {
  description = "Threshold for unused DynamoDB capacity alarm"
  type        = number
  default     = 20
}

# ========================================
# ElastiCache Configuration
# ========================================

variable "enable_elasticache" {
  description = "Enable ElastiCache Redis for caching"
  type        = bool
  default     = false
}

variable "elasticache_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.micro"
  validation {
    condition = contains([
      "cache.t3.micro", "cache.t3.small", "cache.t3.medium",
      "cache.r6g.large", "cache.r6g.xlarge", "cache.r6g.2xlarge"
    ], var.elasticache_node_type)
    error_message = "ElastiCache node type must be a valid cache instance type."
  }
}

variable "elasticache_num_cache_clusters" {
  description = "Number of cache clusters for ElastiCache"
  type        = number
  default     = 2
  validation {
    condition     = var.elasticache_num_cache_clusters >= 1 && var.elasticache_num_cache_clusters <= 6
    error_message = "Number of cache clusters must be between 1 and 6."
  }
}

variable "elasticache_automatic_failover" {
  description = "Enable automatic failover for ElastiCache"
  type        = bool
  default     = true
}

variable "elasticache_multi_az" {
  description = "Enable Multi-AZ for ElastiCache"
  type        = bool
  default     = true
}

variable "elasticache_snapshot_retention" {
  description = "Number of days to retain ElastiCache snapshots"
  type        = number
  default     = 5
  validation {
    condition     = var.elasticache_snapshot_retention >= 0 && var.elasticache_snapshot_retention <= 35
    error_message = "Snapshot retention must be between 0 and 35 days."
  }
}

variable "elasticache_cpu_threshold" {
  description = "CPU utilization threshold for ElastiCache alarms (%)"
  type        = number
  default     = 80
  validation {
    condition     = var.elasticache_cpu_threshold >= 1 && var.elasticache_cpu_threshold <= 100
    error_message = "CPU threshold must be between 1 and 100."
  }
}

variable "elasticache_memory_threshold" {
  description = "Memory utilization threshold for ElastiCache alarms (%)"
  type        = number
  default     = 80
  validation {
    condition     = var.elasticache_memory_threshold >= 1 && var.elasticache_memory_threshold <= 100
    error_message = "Memory threshold must be between 1 and 100."
  }
}

variable "redis_auth_token" {
  description = "Auth token for Redis ElastiCache cluster"
  type        = string
  default     = ""
  sensitive   = true
}

# ========================================
# Connection Pooling Configuration
# ========================================

variable "enable_connection_pooling" {
  description = "Enable connection pooling layer for Lambda functions"
  type        = bool
  default     = true
}

variable "connection_pool_size" {
  description = "Maximum number of connections in the pool"
  type        = number
  default     = 10
  validation {
    condition     = var.connection_pool_size >= 1 && var.connection_pool_size <= 100
    error_message = "Connection pool size must be between 1 and 100."
  }
}

variable "connection_timeout_seconds" {
  description = "Connection timeout in seconds"
  type        = number
  default     = 30
  validation {
    condition     = var.connection_timeout_seconds >= 1 && var.connection_timeout_seconds <= 300
    error_message = "Connection timeout must be between 1 and 300 seconds."
  }
}
