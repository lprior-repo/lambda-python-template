# ========================================
# ENHANCED SECURITY INFRASTRUCTURE
# ========================================
# Enterprise-grade security setup with:
# - AWS WAF v2 for application firewall protection
# - AWS Secrets Manager for secure credential management
# - AWS Parameter Store for hierarchical configuration
# - Enhanced API Gateway security policies
# - VPC endpoints for secure service communication
# - Security monitoring and alerting

# ========================================
# AWS WAF V2 CONFIGURATION
# ========================================

# WAF Web ACL for API Gateway protection
resource "aws_wafv2_web_acl" "api_protection" {
  count = var.enable_waf ? 1 : 0

  name  = "${local.function_name}-api-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rate limiting rule
  rule {
    name     = "RateLimitRule"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "RateLimitRule"
      sampled_requests_enabled    = true
    }
  }

  # AWS Managed Rules - Core Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        # Exclude specific rules if needed
        rule_action_override {
          action_to_use {
            count {}
          }
          name = "SizeRestrictions_BODY"
        }

        rule_action_override {
          action_to_use {
            count {}
          }
          name = "GenericRFI_BODY"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled    = true
    }
  }

  # AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled    = true
    }
  }

  # IP allowlist/blocklist rule
  rule {
    name     = "IPAllowlistRule"
    priority = 4

    action {
      dynamic "allow" {
        for_each = length(var.allowed_ips) > 0 ? [1] : []
        content {}
      }
      dynamic "block" {
        for_each = length(var.blocked_ips) > 0 ? [1] : []
        content {}
      }
    }

    statement {
      dynamic "ip_set_reference_statement" {
        for_each = length(var.allowed_ips) > 0 || length(var.blocked_ips) > 0 ? [1] : []
        content {
          arn = length(var.allowed_ips) > 0 ? aws_wafv2_ip_set.allowed_ips[0].arn : aws_wafv2_ip_set.blocked_ips[0].arn
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "IPAllowlistRule"
      sampled_requests_enabled    = true
    }
  }

  # Geo-blocking rule
  rule {
    name     = "GeoBlockingRule"
    priority = 5

    action {
      block {}
    }

    statement {
      geo_match_statement {
        country_codes = var.blocked_countries
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "GeoBlockingRule"
      sampled_requests_enabled    = true
    }
  }

  # SQL injection protection
  rule {
    name     = "SQLInjectionRule"
    priority = 6

    action {
      block {}
    }

    statement {
      sqli_match_statement {
        field_to_match {
          body {
            oversize_handling = "CONTINUE"
          }
        }

        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }

        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "SQLInjectionRule"
      sampled_requests_enabled    = true
    }
  }

  # XSS protection
  rule {
    name     = "XSSRule"
    priority = 7

    action {
      block {}
    }

    statement {
      xss_match_statement {
        field_to_match {
          body {
            oversize_handling = "CONTINUE"
          }
        }

        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }

        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "XSSRule"
      sampled_requests_enabled    = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                 = "ApiProtectionWebACL"
    sampled_requests_enabled    = true
  }

  tags = local.common_tags
}

# IP sets for allowlist/blocklist
resource "aws_wafv2_ip_set" "allowed_ips" {
  count = var.enable_waf && length(var.allowed_ips) > 0 ? 1 : 0

  name               = "${local.function_name}-allowed-ips"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.allowed_ips

  tags = local.common_tags
}

resource "aws_wafv2_ip_set" "blocked_ips" {
  count = var.enable_waf && length(var.blocked_ips) > 0 ? 1 : 0

  name               = "${local.function_name}-blocked-ips"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.blocked_ips

  tags = local.common_tags
}

# WAF logging configuration
resource "aws_wafv2_web_acl_logging_configuration" "api_protection_logging" {
  count = var.enable_waf && var.enable_waf_logging ? 1 : 0

  resource_arn            = aws_wafv2_web_acl.api_protection[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_logs[0].arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "x-api-key"
    }
  }
}

# CloudWatch log group for WAF logs
resource "aws_cloudwatch_log_group" "waf_logs" {
  count = var.enable_waf && var.enable_waf_logging ? 1 : 0

  name              = "/aws/wafv2/${local.function_name}"
  retention_in_days = var.log_retention_in_days

  tags = local.common_tags
}

# ========================================
# AWS SECRETS MANAGER
# ========================================

# Database credentials secret
resource "aws_secretsmanager_secret" "database_credentials" {
  name                    = "${local.function_name}/database/credentials"
  description             = "Database credentials for ${local.function_name}"
  recovery_window_in_days = var.secret_recovery_window_days

  replica {
    region = var.backup_region
  }

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "database_credentials" {
  secret_id = aws_secretsmanager_secret.database_credentials.id
  secret_string = jsonencode({
    username = var.database_username
    password = var.database_password
    engine   = "postgres"
    host     = var.database_host
    port     = var.database_port
    dbname   = var.database_name
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# API keys secret
resource "aws_secretsmanager_secret" "api_keys" {
  name                    = "${local.function_name}/api/keys"
  description             = "External API keys for ${local.function_name}"
  recovery_window_in_days = var.secret_recovery_window_days

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "api_keys" {
  secret_id = aws_secretsmanager_secret.api_keys.id
  secret_string = jsonencode({
    stripe_secret_key     = var.stripe_secret_key
    sendgrid_api_key      = var.sendgrid_api_key
    slack_webhook_url     = var.slack_webhook_url
    datadog_api_key       = var.datadog_api_key
    jwt_signing_key       = var.jwt_signing_key
    encryption_key        = var.encryption_key
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# JWT signing secrets
resource "aws_secretsmanager_secret" "jwt_secrets" {
  name                    = "${local.function_name}/jwt/signing"
  description             = "JWT signing secrets for ${local.function_name}"
  recovery_window_in_days = var.secret_recovery_window_days

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "jwt_secrets" {
  secret_id = aws_secretsmanager_secret.jwt_secrets.id
  secret_string = jsonencode({
    access_token_secret   = var.jwt_access_secret
    refresh_token_secret  = var.jwt_refresh_secret
    algorithm             = "HS256"
    access_token_ttl      = 3600
    refresh_token_ttl     = 604800
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ========================================
# AWS SYSTEMS MANAGER PARAMETER STORE
# ========================================

# Application configuration parameters
resource "aws_ssm_parameter" "app_config" {
  for_each = var.app_config_parameters

  name  = "/${local.function_name}/config/${each.key}"
  type  = each.value.type
  value = each.value.value
  tier  = each.value.tier

  tags = local.common_tags
}

# Feature flags parameters
resource "aws_ssm_parameter" "feature_flags" {
  for_each = var.feature_flag_parameters

  name  = "/${local.function_name}/features/${each.key}"
  type  = "String"
  value = each.value

  tags = local.common_tags
}

# Environment-specific parameters
resource "aws_ssm_parameter" "environment_config" {
  for_each = {
    log_level                = var.environment == "prod" ? "INFO" : "DEBUG"
    api_timeout_seconds      = "30"
    database_timeout_seconds = "10"
    cache_ttl_seconds        = "300"
    max_retry_attempts       = "3"
    rate_limit_requests      = "1000"
    rate_limit_window        = "3600"
  }

  name  = "/${local.function_name}/env/${var.environment}/${each.key}"
  type  = "String"
  value = each.value

  tags = local.common_tags
}

# Security configuration parameters
resource "aws_ssm_parameter" "security_config" {
  for_each = {
    password_min_length      = "12"
    session_timeout_minutes  = "30"
    max_login_attempts       = "5"
    account_lockout_minutes  = "15"
    require_mfa              = "true"
    allowed_cors_origins     = jsonencode(var.cors_allowed_origins)
    security_headers_enabled = "true"
  }

  name  = "/${local.function_name}/security/${each.key}"
  type  = "String"
  value = each.value

  tags = local.common_tags
}

# ========================================
# VPC ENDPOINTS FOR SECURE COMMUNICATION
# ========================================

# VPC endpoint for DynamoDB
resource "aws_vpc_endpoint" "dynamodb" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id       = var.vpc_id
  service_name = "com.amazonaws.${var.aws_region}.dynamodb"

  route_table_ids = var.route_table_ids

  tags = merge(local.common_tags, {
    Name = "${local.function_name}-dynamodb-endpoint"
  })
}

# VPC endpoint for S3
resource "aws_vpc_endpoint" "s3" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id       = var.vpc_id
  service_name = "com.amazonaws.${var.aws_region}.s3"

  route_table_ids = var.route_table_ids

  tags = merge(local.common_tags, {
    Name = "${local.function_name}-s3-endpoint"
  })
}

# VPC endpoint for Secrets Manager
resource "aws_vpc_endpoint" "secretsmanager" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.vpc_endpoints[0].id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.database_credentials.arn,
          aws_secretsmanager_secret.api_keys.arn,
          aws_secretsmanager_secret.jwt_secrets.arn
        ]
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.function_name}-secretsmanager-endpoint"
  })
}

# Security group for VPC endpoints
resource "aws_security_group" "vpc_endpoints" {
  count = var.enable_vpc_endpoints ? 1 : 0

  name_prefix = "${local.function_name}-vpc-endpoints-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.function_name}-vpc-endpoints-sg"
  })
}

# ========================================
# IAM ROLES FOR SECRETS ACCESS
# ========================================

# IAM role for Lambda functions to access secrets
resource "aws_iam_role" "secrets_access" {
  name = "${local.function_name}-secrets-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# IAM policy for secrets access
resource "aws_iam_role_policy" "secrets_access" {
  name = "${local.function_name}-secrets-access-policy"
  role = aws_iam_role.secrets_access.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.database_credentials.arn,
          aws_secretsmanager_secret.api_keys.arn,
          aws_secretsmanager_secret.jwt_secrets.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = [
          "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/${local.function_name}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = [
          "arn:aws:kms:${var.aws_region}:${data.aws_caller_identity.current.account_id}:key/*"
        ]
        Condition = {
          StringEquals = {
            "kms:ViaService" = [
              "secretsmanager.${var.aws_region}.amazonaws.com",
              "ssm.${var.aws_region}.amazonaws.com"
            ]
          }
        }
      }
    ]
  })
}

# ========================================
# SECURITY MONITORING AND ALERTING
# ========================================

# CloudWatch alarm for WAF blocked requests
resource "aws_cloudwatch_metric_alarm" "waf_blocked_requests" {
  count = var.enable_waf ? 1 : 0

  alarm_name          = "${local.function_name}-waf-blocked-requests"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.waf_blocked_requests_threshold
  alarm_description   = "High number of blocked requests by WAF"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    WebACL = aws_wafv2_web_acl.api_protection[0].name
    Region = var.aws_region
  }

  tags = local.common_tags
}

# SNS topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  name         = "${local.function_name}-security-alerts"
  display_name = "Security Alerts - ${var.environment}"

  tags = local.common_tags
}

# CloudWatch log metric filter for security events
resource "aws_cloudwatch_log_metric_filter" "security_events" {
  name           = "${local.function_name}-security-events"
  log_group_name = "/aws/lambda/${module.users_lambda.lambda_function_name}"
  pattern        = "[timestamp, uuid, level=\"ERROR\", message=\"SECURITY*\"]"

  metric_transformation {
    name      = "SecurityEvents"
    namespace = var.powertools_service_name
    value     = "1"
  }
}

# Alarm for security events
resource "aws_cloudwatch_metric_alarm" "security_events" {
  alarm_name          = "${local.function_name}-security-events"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "SecurityEvents"
  namespace           = var.powertools_service_name
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Security events detected in application logs"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = local.common_tags
}

# ========================================
# OUTPUTS
# ========================================

output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = var.enable_waf ? aws_wafv2_web_acl.api_protection[0].arn : null
}

output "secrets_manager_arns" {
  description = "ARNs of Secrets Manager secrets"
  value = {
    database_credentials = aws_secretsmanager_secret.database_credentials.arn
    api_keys            = aws_secretsmanager_secret.api_keys.arn
    jwt_secrets         = aws_secretsmanager_secret.jwt_secrets.arn
  }
}

output "security_alerts_topic_arn" {
  description = "ARN of the security alerts SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}

output "vpc_endpoints" {
  description = "VPC endpoints created for secure communication"
  value = var.enable_vpc_endpoints ? {
    dynamodb       = aws_vpc_endpoint.dynamodb[0].id
    s3             = aws_vpc_endpoint.s3[0].id
    secretsmanager = aws_vpc_endpoint.secretsmanager[0].id
  } : {}
}
