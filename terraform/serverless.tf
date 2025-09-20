# Serverless Infrastructure - Python Lambda Template
# Clean, modular serverless architecture with DynamoDB, EventBridge, and API Gateway

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Local values for consistent naming and tagging
locals {
  namespace_prefix = var.namespace != "" ? "${var.namespace}-" : ""
  function_name    = "${local.namespace_prefix}${var.function_name}"

  common_tags = {
    Project     = "lambda-python-template"
    Environment = var.environment
    ManagedBy   = "terraform"
    Namespace   = var.namespace
  }
}

# ========================================
# DYNAMODB TABLES
# ========================================

# Users table for CRUD operations
resource "aws_dynamodb_table" "users" {
  name         = "${local.function_name}-users"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "email"
    type = "S"
  }

  global_secondary_index {
    name            = "email-index"
    hash_key        = "email"
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-users"
  })
}

# Posts table for CRUD operations
resource "aws_dynamodb_table" "posts" {
  name         = "${local.function_name}-posts"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  range_key    = "created_at"

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "S"
  }

  attribute {
    name = "user_id"
    type = "S"
  }

  global_secondary_index {
    name            = "user-posts-index"
    hash_key        = "user_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-posts"
  })
}

# Audit logs table for EventBridge events
resource "aws_dynamodb_table" "audit_logs" {
  name         = "${local.function_name}-audit-logs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"
  range_key    = "timestamp"

  attribute {
    name = "event_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-audit"
  })
}

# Idempotency table for Lambda Powertools
resource "aws_dynamodb_table" "idempotency" {
  name         = "${local.function_name}-idempotency"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  ttl {
    attribute_name = "expiration"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-idempotency"
  })
}

# Event Store table for event sourcing
resource "aws_dynamodb_table" "event_store" {
  name         = "${local.function_name}-event-store"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "stream_id"
  range_key    = "version"

  attribute {
    name = "stream_id"
    type = "S"
  }

  attribute {
    name = "version"
    type = "N"
  }

  attribute {
    name = "event_type"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  global_secondary_index {
    name     = "event-type-index"
    hash_key = "event_type"
    range_key = "timestamp"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-event-store"
  })
}

# Event Store Streams metadata table
resource "aws_dynamodb_table" "event_store_streams" {
  name         = "${local.function_name}-event-store-streams"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "stream_id"

  attribute {
    name = "stream_id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-event-store-streams"
  })
}

# Event Snapshots table
resource "aws_dynamodb_table" "event_snapshots" {
  name         = "${local.function_name}-event-snapshots"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "stream_id"
  range_key    = "version"

  attribute {
    name = "stream_id"
    type = "S"
  }

  attribute {
    name = "version"
    type = "N"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-event-snapshots"
  })
}

# Projection Checkpoints table
resource "aws_dynamodb_table" "projection_checkpoints" {
  name         = "${local.function_name}-projection-checkpoints"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "stream_id"

  attribute {
    name = "stream_id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-projection-checkpoints"
  })
}

# Rate Limiting table
resource "aws_dynamodb_table" "rate_limits" {
  name         = "${local.function_name}-rate-limits"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-rate-limits"
  })
}

# API Keys table for authentication
resource "aws_dynamodb_table" "api_keys" {
  name         = "${local.function_name}-api-keys"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "api_key_hash"

  attribute {
    name = "api_key_hash"
    type = "S"
  }

  attribute {
    name = "user_id"
    type = "S"
  }

  global_secondary_index {
    name     = "user-id-index"
    hash_key = "user_id"
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-api-keys"
  })
}

# Event Dead Letter Queue table
resource "aws_dynamodb_table" "event_dlq" {
  name         = "${local.function_name}-event-dlq"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-event-dlq"
  })
}

# Projections tables for CQRS
resource "aws_dynamodb_table" "order_summaries" {
  name         = "${local.function_name}-order-summaries"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  global_secondary_index {
    name     = "user-id-index"
    hash_key = "user_id"
  }

  global_secondary_index {
    name     = "status-index"
    hash_key = "status"
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-order-summaries"
  })
}

resource "aws_dynamodb_table" "user_activity" {
  name         = "${local.function_name}-user-activity"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Resource = "dynamodb-user-activity"
  })
}

# ========================================
# EVENTBRIDGE
# ========================================

# Custom event bus for application events
resource "aws_cloudwatch_event_bus" "app_events" {
  name = "${local.function_name}-events"

  tags = merge(local.common_tags, {
    Resource = "eventbridge-bus"
  })
}

# Event rules for capturing CRUD operations
resource "aws_cloudwatch_event_rule" "crud_events" {
  name           = "${local.function_name}-crud-events"
  description    = "Capture all CRUD events for audit logging"
  event_bus_name = aws_cloudwatch_event_bus.app_events.name

  event_pattern = jsonencode({
    source = ["lambda.${local.function_name}"]
    detail-type = [
      "User Created", "User Updated", "User Deleted",
      "Post Created", "Post Updated", "Post Deleted"
    ]
  })

  tags = local.common_tags
}

# ========================================
# AWS APPCONFIG - FEATURE FLAGGING & CONFIGURATION
# ========================================

# AppConfig Application
resource "aws_appconfig_application" "main" {
  name        = "${local.function_name}-config"
  description = "Feature flags and configuration for ${local.function_name}"
  tags = merge(local.common_tags, {
    Resource = "appconfig-application"
  })
}

# Feature Flags Configuration Profile
resource "aws_appconfig_configuration_profile" "feature_flags" {
  application_id = aws_appconfig_application.main.id
  name           = "feature-flags"
  description    = "Feature flags configuration"
  location_uri   = "hosted"
  type           = "AWS.AppConfig.FeatureFlags"

  tags = local.common_tags
}

# Application Configuration Profile
resource "aws_appconfig_configuration_profile" "app_config" {
  application_id = aws_appconfig_application.main.id
  name           = "app-config"
  description    = "Application configuration settings"
  location_uri   = "hosted"

  validator {
    content = jsonencode({
      "$schema" = "http://json-schema.org/draft-07/schema#"
      type      = "object"
      properties = {
        database = {
          type = "object"
          properties = {
            readCapacityUnits  = { type = "integer", minimum = 1 }
            writeCapacityUnits = { type = "integer", minimum = 1 }
            ttl                = { type = "integer", minimum = 3600 }
          }
          required = ["readCapacityUnits", "writeCapacityUnits", "ttl"]
        }
        api = {
          type = "object"
          properties = {
            timeoutMs  = { type = "integer", minimum = 1000 }
            maxRetries = { type = "integer", minimum = 0 }
            enableCors = { type = "boolean" }
          }
          required = ["timeoutMs", "maxRetries", "enableCors"]
        }
        features = {
          type = "object"
          properties = {
            enableAdvancedLogging = { type = "boolean" }
            enableMetrics         = { type = "boolean" }
            maintenanceMode       = { type = "boolean" }
          }
          required = ["enableAdvancedLogging", "enableMetrics", "maintenanceMode"]
        }
      }
      required = ["database", "api", "features"]
    })
    type = "JSON_SCHEMA"
  }

  tags = local.common_tags
}

# Ephemeral Environment (based on namespace)
resource "aws_appconfig_environment" "ephemeral" {
  count          = var.namespace != "" ? 1 : 0
  name           = var.namespace
  description    = "Ephemeral environment configuration for ${var.namespace}"
  application_id = aws_appconfig_application.main.id

  monitor {
    alarm_arn      = aws_cloudwatch_metric_alarm.lambda_error_rate.arn
    alarm_role_arn = aws_iam_role.appconfig_monitor.arn
  }

  tags = local.common_tags
}

# Production Environment
resource "aws_appconfig_environment" "production" {
  name           = "production"
  description    = "Production environment configuration"
  application_id = aws_appconfig_application.main.id

  monitor {
    alarm_arn      = aws_cloudwatch_metric_alarm.lambda_error_rate.arn
    alarm_role_arn = aws_iam_role.appconfig_monitor.arn
  }

  tags = local.common_tags
}

# Deployment Strategy - Canary
resource "aws_appconfig_deployment_strategy" "canary" {
  name                           = "${local.function_name}-canary"
  description                    = "Canary deployment strategy for safe rollouts"
  deployment_duration_in_minutes = 10
  final_bake_time_in_minutes     = 10
  growth_factor                  = 20
  growth_type                    = "EXPONENTIAL"
  replicate_to                   = "NONE"

  tags = local.common_tags
}

# IAM Role for AppConfig Monitoring
resource "aws_iam_role" "appconfig_monitor" {
  name = "${local.function_name}-appconfig-monitor"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "appconfig.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "appconfig_monitor" {
  name = "${local.function_name}-appconfig-monitor"
  role = aws_iam_role.appconfig_monitor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:DescribeAlarms"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Alarm for Error Rate Monitoring
resource "aws_cloudwatch_metric_alarm" "lambda_error_rate" {
  alarm_name          = "${local.function_name}-lambda-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors lambda error rate"

  dimensions = {
    FunctionName = "${local.function_name}-users"
  }

  tags = local.common_tags
}

# Initial Feature Flags Configuration
resource "aws_appconfig_hosted_configuration_version" "feature_flags_initial" {
  application_id           = aws_appconfig_application.main.id
  configuration_profile_id = aws_appconfig_configuration_profile.feature_flags.configuration_profile_id
  description              = "Initial feature flags configuration"
  content_type             = "application/json"

  content = jsonencode({
    flags = {
      enableNewUserFlow = {
        enabled = false
      }
      enableAdvancedSearch = {
        enabled = false
      }
      maintenanceMode = {
        enabled = false
      }
    }
    values = {
      enableNewUserFlow = {
        enabled = false
      }
      enableAdvancedSearch = {
        enabled = false
      }
      maintenanceMode = {
        enabled = false
      }
    }
    version = "1"
  })
}

# Initial Application Configuration
resource "aws_appconfig_hosted_configuration_version" "app_config_initial" {
  application_id           = aws_appconfig_application.main.id
  configuration_profile_id = aws_appconfig_configuration_profile.app_config.configuration_profile_id
  description              = "Initial application configuration"
  content_type             = "application/json"

  content = jsonencode({
    database = {
      readCapacityUnits  = 5
      writeCapacityUnits = 5
      ttl                = 86400
    }
    api = {
      timeoutMs  = 30000
      maxRetries = 3
      enableCors = true
    }
    features = {
      enableAdvancedLogging = false
      enableMetrics         = true
      maintenanceMode       = false
    }
  })
}

# ========================================
# LAMBDA FUNCTIONS
# ========================================
# All Lambda functions are configured with AWS Lambda PowerTools for Python:
# - Structured logging with configurable log levels
# - Custom metrics with automatic cold start tracking
# - Distributed tracing with request/response capture
# - Environment-specific configuration (INFO logs in prod, DEBUG in dev)
# - IAM permissions for CloudWatch metrics publishing

# Health check Lambda
module "health_lambda" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.1.0"

  function_name = "${local.function_name}-health"
  description   = "Health check endpoint"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 15

  create_package         = false
  local_existing_package = "../build/health.zip"

  tracing_mode = "Active"

  environment_variables = {
    ENVIRONMENT              = var.environment
    PYTHONPATH               = "/var/runtime"
    APPCONFIG_APPLICATION_ID = aws_appconfig_application.main.id
    APPCONFIG_ENVIRONMENT    = var.namespace != "" ? var.namespace : "production"
    APPCONFIG_FEATURE_FLAGS  = aws_appconfig_configuration_profile.feature_flags.name
    APPCONFIG_APP_CONFIG     = aws_appconfig_configuration_profile.app_config.name
    IDEMPOTENCY_TABLE_NAME   = aws_dynamodb_table.idempotency.name

    # Event Sourcing Tables
    EVENT_STORE_TABLE_NAME           = aws_dynamodb_table.event_store.name
    EVENT_SNAPSHOTS_TABLE_NAME       = aws_dynamodb_table.event_snapshots.name
    PROJECTION_CHECKPOINTS_TABLE     = aws_dynamodb_table.projection_checkpoints.name
    ORDER_SUMMARIES_TABLE_NAME       = aws_dynamodb_table.order_summaries.name
    USER_ACTIVITY_TABLE_NAME         = aws_dynamodb_table.user_activity.name

    # Security Tables
    RATE_LIMITS_TABLE_NAME = aws_dynamodb_table.rate_limits.name
    API_KEYS_TABLE_NAME    = aws_dynamodb_table.api_keys.name

    # Event Processing
    EVENT_DLQ_TABLE_NAME = aws_dynamodb_table.event_dlq.name
    EVENT_BUS_NAME       = aws_cloudwatch_event_bus.app_events.name

    # AWS Lambda PowerTools for Python
    POWERTOOLS_SERVICE_NAME               = "${local.function_name}-health"
    POWERTOOLS_METRICS_NAMESPACE          = local.function_name
    POWERTOOLS_LOG_LEVEL                  = var.environment == "production" ? "INFO" : "DEBUG"
    POWERTOOLS_LOGGER_SAMPLE_RATE         = var.environment == "production" ? "0.1" : "1"
    POWERTOOLS_TRACE_ENABLED              = "true"
    POWERTOOLS_TRACER_CAPTURE_RESPONSE    = "true"
    POWERTOOLS_TRACER_CAPTURE_ERROR       = "true"
    POWERTOOLS_METRICS_CAPTURE_COLD_START = "true"
  }

  attach_cloudwatch_logs_policy     = true
  attach_tracing_policy             = true
  cloudwatch_logs_retention_in_days = 14

  attach_policy_statements = true
  policy_statements = {
    appconfig = {
      effect = "Allow"
      actions = [
        "appconfig:StartConfigurationSession",
        "appconfig:GetConfiguration"
      ]
      resources = ["*"]
    }
    powertools_metrics = {
      effect = "Allow"
      actions = [
        "cloudwatch:PutMetricData"
      ]
      resources = ["*"]
      condition = {
        test     = "StringEquals"
        variable = "cloudwatch:namespace"
        values   = [local.function_name]
      }
    }
  }

  tags = local.common_tags
}

# Users CRUD Lambda
module "users_lambda" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.1.0"

  function_name = "${local.function_name}-users"
  description   = "Users CRUD API"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  architectures = ["arm64"]
  memory_size   = 512
  timeout       = 30

  create_package         = false
  local_existing_package = "../build/users.zip"

  tracing_mode = "Active"

  environment_variables = {
    ENVIRONMENT              = var.environment
    PYTHONPATH               = "/var/runtime"
    USERS_TABLE_NAME         = aws_dynamodb_table.users.name
    EVENT_BUS_NAME           = aws_cloudwatch_event_bus.app_events.name
    APPCONFIG_APPLICATION_ID = aws_appconfig_application.main.id
    APPCONFIG_ENVIRONMENT    = var.namespace != "" ? var.namespace : "production"
    APPCONFIG_FEATURE_FLAGS  = aws_appconfig_configuration_profile.feature_flags.name
    APPCONFIG_APP_CONFIG     = aws_appconfig_configuration_profile.app_config.name
    IDEMPOTENCY_TABLE_NAME   = aws_dynamodb_table.idempotency.name

    # Event Sourcing Tables
    EVENT_STORE_TABLE_NAME           = aws_dynamodb_table.event_store.name
    EVENT_SNAPSHOTS_TABLE_NAME       = aws_dynamodb_table.event_snapshots.name
    PROJECTION_CHECKPOINTS_TABLE     = aws_dynamodb_table.projection_checkpoints.name
    ORDER_SUMMARIES_TABLE_NAME       = aws_dynamodb_table.order_summaries.name
    USER_ACTIVITY_TABLE_NAME         = aws_dynamodb_table.user_activity.name

    # Security Tables
    RATE_LIMITS_TABLE_NAME = aws_dynamodb_table.rate_limits.name
    API_KEYS_TABLE_NAME    = aws_dynamodb_table.api_keys.name

    # Event Processing
    EVENT_DLQ_TABLE_NAME = aws_dynamodb_table.event_dlq.name

    # AWS Lambda PowerTools for Python
    POWERTOOLS_SERVICE_NAME               = "${local.function_name}-users"
    POWERTOOLS_METRICS_NAMESPACE          = local.function_name
    POWERTOOLS_LOG_LEVEL                  = var.environment == "production" ? "INFO" : "DEBUG"
    POWERTOOLS_LOGGER_SAMPLE_RATE         = var.environment == "production" ? "0.1" : "1"
    POWERTOOLS_TRACE_ENABLED              = "true"
    POWERTOOLS_TRACER_CAPTURE_RESPONSE    = "true"
    POWERTOOLS_TRACER_CAPTURE_ERROR       = "true"
    POWERTOOLS_METRICS_CAPTURE_COLD_START = "true"
  }

  attach_cloudwatch_logs_policy     = true
  attach_tracing_policy             = true
  cloudwatch_logs_retention_in_days = 14

  attach_policy_statements = true
  policy_statements = {
    dynamodb = {
      effect = "Allow"
      actions = [
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
        "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"
      ]
      resources = [
        aws_dynamodb_table.users.arn,
        "${aws_dynamodb_table.users.arn}/*",
        aws_dynamodb_table.event_store.arn,
        "${aws_dynamodb_table.event_store.arn}/*",
        aws_dynamodb_table.event_snapshots.arn,
        "${aws_dynamodb_table.event_snapshots.arn}/*",
        aws_dynamodb_table.projection_checkpoints.arn,
        aws_dynamodb_table.user_activity.arn,
        aws_dynamodb_table.rate_limits.arn,
        aws_dynamodb_table.api_keys.arn,
        "${aws_dynamodb_table.api_keys.arn}/*",
        aws_dynamodb_table.event_dlq.arn,
        aws_dynamodb_table.idempotency.arn
      ]
    }
    eventbridge = {
      effect    = "Allow"
      actions   = ["events:PutEvents"]
      ]
      resources = [aws_cloudwatch_event_bus.app_events.arn]
    }
    idempotency = {
      effect = "Allow"
      actions = [
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"
      ]
      resources = [aws_dynamodb_table.idempotency.arn]
    }
    appconfig = {
      effect = "Allow"
      actions = [
        "appconfig:StartConfigurationSession",
        "appconfig:GetConfiguration"
      ]
      resources = ["*"]
    }
    powertools_metrics = {
      effect = "Allow"
      actions = [
        "cloudwatch:PutMetricData"
      ]
      resources = ["*"]
      condition = {
        test     = "StringEquals"
        variable = "cloudwatch:namespace"
        values   = [local.function_name]
      }
    }
  }

  tags = local.common_tags
}

# Posts CRUD Lambda
module "posts_lambda" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.1.0"

  function_name = "${local.function_name}-posts"
  description   = "Posts CRUD API"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  architectures = ["arm64"]
  memory_size   = 512
  timeout       = 30

  create_package         = false
  local_existing_package = "../build/posts.zip"

  tracing_mode = "Active"

  environment_variables = {
    ENVIRONMENT              = var.environment
    PYTHONPATH               = "/var/runtime"
    POSTS_TABLE_NAME         = aws_dynamodb_table.posts.name
    USERS_TABLE_NAME         = aws_dynamodb_table.users.name
    EVENT_BUS_NAME           = aws_cloudwatch_event_bus.app_events.name
    APPCONFIG_APPLICATION_ID = aws_appconfig_application.main.id
    APPCONFIG_ENVIRONMENT    = var.namespace != "" ? var.namespace : "production"
    APPCONFIG_FEATURE_FLAGS  = aws_appconfig_configuration_profile.feature_flags.name
    APPCONFIG_APP_CONFIG     = aws_appconfig_configuration_profile.app_config.name
    IDEMPOTENCY_TABLE_NAME   = aws_dynamodb_table.idempotency.name

    # Event Sourcing Tables
    EVENT_STORE_TABLE_NAME           = aws_dynamodb_table.event_store.name
    EVENT_SNAPSHOTS_TABLE_NAME       = aws_dynamodb_table.event_snapshots.name
    PROJECTION_CHECKPOINTS_TABLE     = aws_dynamodb_table.projection_checkpoints.name
    ORDER_SUMMARIES_TABLE_NAME       = aws_dynamodb_table.order_summaries.name
    USER_ACTIVITY_TABLE_NAME         = aws_dynamodb_table.user_activity.name

    # Security Tables
    RATE_LIMITS_TABLE_NAME = aws_dynamodb_table.rate_limits.name
    API_KEYS_TABLE_NAME    = aws_dynamodb_table.api_keys.name

    # Event Processing
    EVENT_DLQ_TABLE_NAME = aws_dynamodb_table.event_dlq.name

    # AWS Lambda PowerTools for Python
    POWERTOOLS_SERVICE_NAME               = "${local.function_name}-posts"
    POWERTOOLS_METRICS_NAMESPACE          = local.function_name
    POWERTOOLS_LOG_LEVEL                  = var.environment == "production" ? "INFO" : "DEBUG"
    POWERTOOLS_LOGGER_SAMPLE_RATE         = var.environment == "production" ? "0.1" : "1"
    POWERTOOLS_TRACE_ENABLED              = "true"
    POWERTOOLS_TRACER_CAPTURE_RESPONSE    = "true"
    POWERTOOLS_TRACER_CAPTURE_ERROR       = "true"
    POWERTOOLS_METRICS_CAPTURE_COLD_START = "true"
  }

  attach_cloudwatch_logs_policy     = true
  attach_tracing_policy             = true
  cloudwatch_logs_retention_in_days = 14

  attach_policy_statements = true
  policy_statements = {
    dynamodb = {
      effect = "Allow"
      actions = [
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
        "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"
      ]
      resources = [
        aws_dynamodb_table.posts.arn, "${aws_dynamodb_table.posts.arn}/*",
        aws_dynamodb_table.users.arn, "${aws_dynamodb_table.users.arn}/*",
        aws_dynamodb_table.event_store.arn, "${aws_dynamodb_table.event_store.arn}/*",
        aws_dynamodb_table.event_snapshots.arn, "${aws_dynamodb_table.event_snapshots.arn}/*",
        aws_dynamodb_table.projection_checkpoints.arn,
        aws_dynamodb_table.order_summaries.arn, "${aws_dynamodb_table.order_summaries.arn}/*",
        aws_dynamodb_table.user_activity.arn,
        aws_dynamodb_table.rate_limits.arn,
        aws_dynamodb_table.api_keys.arn, "${aws_dynamodb_table.api_keys.arn}/*",
        aws_dynamodb_table.event_dlq.arn,
        aws_dynamodb_table.idempotency.arn
      ]
    }
    eventbridge = {
      effect    = "Allow"
      actions   = ["events:PutEvents"]
      resources = [aws_cloudwatch_event_bus.app_events.arn]
    }
    appconfig = {
      effect = "Allow"
      actions = [
        "appconfig:StartConfigurationSession",
        "appconfig:GetConfiguration"
      ]
      resources = ["*"]
    }
    powertools_metrics = {
      effect = "Allow"
      actions = [
        "cloudwatch:PutMetricData"
      ]
      resources = ["*"]
      condition = {
        test     = "StringEquals"
        variable = "cloudwatch:namespace"
        values   = [local.function_name]
      }
    }
  }

  tags = local.common_tags
}

# Event processor Lambda for audit logging
module "event_processor_lambda" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.1.0"

  function_name = "${local.function_name}-event-processor"
  description   = "Process EventBridge events for audit logging"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 30

  create_package         = false
  local_existing_package = "../build/event-processor.zip"

  tracing_mode = "Active"

  environment_variables = {
    ENVIRONMENT              = var.environment
    PYTHONPATH               = "/var/runtime"
    AUDIT_TABLE_NAME         = aws_dynamodb_table.audit_logs.name
    APPCONFIG_APPLICATION_ID = aws_appconfig_application.main.id
    APPCONFIG_ENVIRONMENT    = var.namespace != "" ? var.namespace : "production"
    APPCONFIG_FEATURE_FLAGS  = aws_appconfig_configuration_profile.feature_flags.name
    APPCONFIG_APP_CONFIG     = aws_appconfig_configuration_profile.app_config.name

    # AWS Lambda PowerTools for Python
    POWERTOOLS_SERVICE_NAME               = "${local.function_name}-event-processor"
    POWERTOOLS_METRICS_NAMESPACE          = local.function_name
    POWERTOOLS_LOG_LEVEL                  = var.environment == "production" ? "INFO" : "DEBUG"
    POWERTOOLS_LOGGER_SAMPLE_RATE         = var.environment == "production" ? "0.1" : "1"
    POWERTOOLS_TRACE_ENABLED              = "true"
    POWERTOOLS_TRACER_CAPTURE_RESPONSE    = "true"
    POWERTOOLS_TRACER_CAPTURE_ERROR       = "true"
    POWERTOOLS_METRICS_CAPTURE_COLD_START = "true"
  }

  attach_cloudwatch_logs_policy     = true
  attach_tracing_policy             = true
  cloudwatch_logs_retention_in_days = 14

  attach_policy_statements = true
  policy_statements = {
    dynamodb = {
      effect    = "Allow"
      actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
      resources = [aws_dynamodb_table.audit_logs.arn]
    }
    appconfig = {
      effect = "Allow"
      actions = [
        "appconfig:StartConfigurationSession",
        "appconfig:GetConfiguration"
      ]
      resources = ["*"]
    }
    powertools_metrics = {
      effect = "Allow"
      actions = [
        "cloudwatch:PutMetricData"
      ]
      resources = ["*"]
      condition = {
        test     = "StringEquals"
        variable = "cloudwatch:namespace"
        values   = [local.function_name]
      }
    }
  }

  tags = local.common_tags
}

# Orders Events Processor Lambda (Event Sourcing Demo)
module "orders_events_lambda" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.1.0"

  function_name = "${local.function_name}-orders-events"
  description   = "Orders Event Processor - Event Sourcing and CQRS patterns"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  architectures = ["arm64"]
  memory_size   = 512
  timeout       = 30

  create_package         = false
  local_existing_package = "../orders-events-handler.zip"

  tracing_mode = "Active"

  environment_variables = {
    ENVIRONMENT              = var.environment
    PYTHONPATH               = "/var/runtime"
    EVENT_BUS_NAME           = aws_cloudwatch_event_bus.app_events.name
    APPCONFIG_APPLICATION_ID = aws_appconfig_application.main.id
    APPCONFIG_ENVIRONMENT    = var.namespace != "" ? var.namespace : "production"
    APPCONFIG_FEATURE_FLAGS  = aws_appconfig_configuration_profile.feature_flags.name
    APPCONFIG_APP_CONFIG     = aws_appconfig_configuration_profile.app_config.name
    IDEMPOTENCY_TABLE_NAME   = aws_dynamodb_table.idempotency.name

    # Event Sourcing Tables
    EVENT_STORE_TABLE_NAME           = aws_dynamodb_table.event_store.name
    EVENT_SNAPSHOTS_TABLE_NAME       = aws_dynamodb_table.event_snapshots.name
    PROJECTION_CHECKPOINTS_TABLE     = aws_dynamodb_table.projection_checkpoints.name
    ORDER_SUMMARIES_TABLE_NAME       = aws_dynamodb_table.order_summaries.name
    USER_ACTIVITY_TABLE_NAME         = aws_dynamodb_table.user_activity.name

    # Security Tables
    RATE_LIMITS_TABLE_NAME = aws_dynamodb_table.rate_limits.name
    API_KEYS_TABLE_NAME    = aws_dynamodb_table.api_keys.name

    # Event Processing
    EVENT_DLQ_TABLE_NAME = aws_dynamodb_table.event_dlq.name

    # AWS Lambda PowerTools for Python
    POWERTOOLS_SERVICE_NAME               = "${local.function_name}-orders-events"
    POWERTOOLS_METRICS_NAMESPACE          = local.function_name
    POWERTOOLS_LOG_LEVEL                  = var.environment == "production" ? "INFO" : "DEBUG"
    POWERTOOLS_LOGGER_SAMPLE_RATE         = var.environment == "production" ? "0.1" : "1"
    POWERTOOLS_TRACE_ENABLED              = "true"
    POWERTOOLS_TRACER_CAPTURE_RESPONSE    = "true"
    POWERTOOLS_TRACER_CAPTURE_ERROR       = "true"
    POWERTOOLS_METRICS_CAPTURE_COLD_START = "true"
  }

  attach_cloudwatch_logs_policy     = true
  attach_tracing_policy             = true
  cloudwatch_logs_retention_in_days = 14

  attach_policy_statements = true
  policy_statements = {
    dynamodb = {
      effect = "Allow"
      actions = [
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
        "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"
      ]
      resources = [
        aws_dynamodb_table.event_store.arn,
        "${aws_dynamodb_table.event_store.arn}/*",
        aws_dynamodb_table.event_snapshots.arn,
        "${aws_dynamodb_table.event_snapshots.arn}/*",
        aws_dynamodb_table.projection_checkpoints.arn,
        aws_dynamodb_table.order_summaries.arn,
        "${aws_dynamodb_table.order_summaries.arn}/*",
        aws_dynamodb_table.user_activity.arn,
        aws_dynamodb_table.rate_limits.arn,
        aws_dynamodb_table.api_keys.arn,
        "${aws_dynamodb_table.api_keys.arn}/*",
        aws_dynamodb_table.event_dlq.arn,
        aws_dynamodb_table.idempotency.arn
      ]
    }
    eventbridge = {
      effect    = "Allow"
      actions   = ["events:PutEvents"]
      resources = [aws_cloudwatch_event_bus.app_events.arn]
    }
    appconfig = {
      effect = "Allow"
      actions = [
        "appconfig:StartConfigurationSession",
        "appconfig:GetConfiguration"
      ]
      resources = ["*"]
    }
    powertools_metrics = {
      effect = "Allow"
      actions = [
        "cloudwatch:PutMetricData"
      ]
      resources = ["*"]
      condition = {
        test     = "StringEquals"
        variable = "cloudwatch:namespace"
        values   = [local.function_name]
      }
    }
  }

  tags = local.common_tags
}

# ========================================
# API GATEWAY
# ========================================

module "api_gateway" {
  source  = "terraform-aws-modules/apigateway-v2/aws"
  version = "5.3.1"

  name          = "${local.function_name}-api"
  description   = "Serverless CRUD API"
  protocol_type = "HTTP"

  create_domain_name    = false
  create_domain_records = false
  create_certificate    = false

  cors_configuration = {
    allow_headers     = ["content-type", "authorization", "x-api-key"]
    allow_methods     = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allow_origins     = ["https://localhost:3000", "https://example.com"]
    expose_headers    = ["date", "keep-alive"]
    max_age           = 300
    allow_credentials = false
  }

  routes = {
    # Health check
    "GET /health" = {
      integration = {
        uri                    = module.health_lambda.lambda_function_arn
        payload_format_version = "2.0"
        timeout_milliseconds   = 12000
      }
    }

    # Users CRUD
    "GET /users"         = { integration = { uri = module.users_lambda.lambda_function_arn, payload_format_version = "2.0" } }
    "GET /users/{id}"    = { integration = { uri = module.users_lambda.lambda_function_arn, payload_format_version = "2.0" } }
    "POST /users"        = { integration = { uri = module.users_lambda.lambda_function_arn, payload_format_version = "2.0" } }
    "PUT /users/{id}"    = { integration = { uri = module.users_lambda.lambda_function_arn, payload_format_version = "2.0" } }
    "DELETE /users/{id}" = { integration = { uri = module.users_lambda.lambda_function_arn, payload_format_version = "2.0" } }

    # Posts CRUD
    "GET /posts"         = { integration = { uri = module.posts_lambda.lambda_function_arn, payload_format_version = "2.0" } }
    "GET /posts/{id}"    = { integration = { uri = module.posts_lambda.lambda_function_arn, payload_format_version = "2.0" } }
    "POST /posts"        = { integration = { uri = module.posts_lambda.lambda_function_arn, payload_format_version = "2.0" } }
    "PUT /posts/{id}"    = { integration = { uri = module.posts_lambda.lambda_function_arn, payload_format_version = "2.0" } }
    "DELETE /posts/{id}" = { integration = { uri = module.posts_lambda.lambda_function_arn, payload_format_version = "2.0" } }
  }

  tags = local.common_tags
}

# ========================================
# LAMBDA PERMISSIONS
# ========================================

# API Gateway permissions
# Lambda permissions for API Gateway
resource "aws_lambda_permission" "api_gateway_health" {
  statement_id  = "AllowAPIGatewayInvokeHealth"
  action        = "lambda:InvokeFunction"
  function_name = module.health_lambda.lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${module.api_gateway.api_execution_arn}/*/*"
}

resource "aws_lambda_permission" "api_gateway_users" {
  statement_id  = "AllowAPIGatewayInvokeUsers"
  action        = "lambda:InvokeFunction"
  function_name = module.users_lambda.lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${module.api_gateway.api_execution_arn}/*/*"
}

resource "aws_lambda_permission" "api_gateway_posts" {
  statement_id  = "AllowAPIGatewayInvokePosts"
  action        = "lambda:InvokeFunction"
  function_name = module.posts_lambda.lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${module.api_gateway.api_execution_arn}/*/*"
}

# EventBridge permissions
resource "aws_cloudwatch_event_target" "audit_target" {
  rule           = aws_cloudwatch_event_rule.crud_events.name
  event_bus_name = aws_cloudwatch_event_bus.app_events.name
  target_id      = "AuditProcessor"
  arn            = module.event_processor_lambda.lambda_function_arn
}

resource "aws_cloudwatch_event_target" "orders_events_target" {
  rule           = aws_cloudwatch_event_rule.crud_events.name
  event_bus_name = aws_cloudwatch_event_bus.app_events.name
  target_id      = "OrdersEventsProcessor"
  arn            = module.orders_events_lambda.lambda_function_arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = module.event_processor_lambda.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.crud_events.arn
}

resource "aws_lambda_permission" "allow_eventbridge_orders_events" {
  statement_id  = "AllowExecutionFromEventBridgeOrdersEvents"
  action        = "lambda:InvokeFunction"
  function_name = module.orders_events_lambda.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.crud_events.arn
}
