# ========================================
# ADVANCED MONITORING & OBSERVABILITY
# ========================================
# Enterprise-grade monitoring setup with:
# - Custom CloudWatch dashboards with business KPIs
# - Comprehensive alarms for all Lambda functions and DynamoDB tables
# - Multi-channel alerting via SNS
# - Cost monitoring and optimization alerts
# - Performance and security monitoring

# ========================================
# SNS TOPICS FOR ALERTING
# ========================================

# Critical alerts (errors, outages, security issues)
resource "aws_sns_topic" "critical_alerts" {
  name         = "${local.function_name}-critical-alerts"
  display_name = "Critical Alerts - ${var.environment}"

  tags = local.common_tags
}

# Warning alerts (performance degradation, cost thresholds)
resource "aws_sns_topic" "warning_alerts" {
  name         = "${local.function_name}-warning-alerts"
  display_name = "Warning Alerts - ${var.environment}"

  tags = local.common_tags
}

# Info alerts (deployment notifications, scaling events)
resource "aws_sns_topic" "info_alerts" {
  name         = "${local.function_name}-info-alerts"
  display_name = "Info Alerts - ${var.environment}"

  tags = local.common_tags
}

# SNS topic policies to allow CloudWatch to publish
resource "aws_sns_topic_policy" "critical_alerts_policy" {
  arn = aws_sns_topic.critical_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.critical_alerts.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic_policy" "warning_alerts_policy" {
  arn = aws_sns_topic.warning_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.warning_alerts.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Example email subscription (uncomment and configure for production)
# resource "aws_sns_topic_subscription" "critical_email" {
#   topic_arn = aws_sns_topic.critical_alerts.arn
#   protocol  = "email"
#   endpoint  = var.alert_email_address
# }

# ========================================
# LAMBDA FUNCTION ALARMS
# ========================================

# Health Lambda alarms
resource "aws_cloudwatch_metric_alarm" "health_lambda_errors" {
  alarm_name          = "${local.function_name}-health-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Health Lambda function error rate is too high"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]
  ok_actions          = [aws_sns_topic.info_alerts.arn]

  dimensions = {
    FunctionName = module.health_lambda.lambda_function_name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "health_lambda_duration" {
  alarm_name          = "${local.function_name}-health-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "5000"
  alarm_description   = "Health Lambda function duration is too high"
  alarm_actions       = [aws_sns_topic.warning_alerts.arn]

  dimensions = {
    FunctionName = module.health_lambda.lambda_function_name
  }

  tags = local.common_tags
}

# Users Lambda alarms
resource "aws_cloudwatch_metric_alarm" "users_lambda_errors" {
  alarm_name          = "${local.function_name}-users-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "Users Lambda function error rate is too high"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]

  dimensions = {
    FunctionName = module.users_lambda.lambda_function_name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "users_lambda_duration" {
  alarm_name          = "${local.function_name}-users-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "10000"
  alarm_description   = "Users Lambda function duration is too high"
  alarm_actions       = [aws_sns_topic.warning_alerts.arn]

  dimensions = {
    FunctionName = module.users_lambda.lambda_function_name
  }

  tags = local.common_tags
}

# Orders Lambda alarms
resource "aws_cloudwatch_metric_alarm" "orders_lambda_errors" {
  alarm_name          = "${local.function_name}-orders-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "Orders Lambda function error rate is too high"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]

  dimensions = {
    FunctionName = module.posts_lambda.lambda_function_name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "orders_lambda_throttles" {
  alarm_name          = "${local.function_name}-orders-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Orders Lambda function is being throttled"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]

  dimensions = {
    FunctionName = module.posts_lambda.lambda_function_name
  }

  tags = local.common_tags
}

# Event Processor Lambda alarms
resource "aws_cloudwatch_metric_alarm" "event_processor_errors" {
  alarm_name          = "${local.function_name}-event-processor-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Event Processor Lambda function error rate is too high"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]

  dimensions = {
    FunctionName = module.event_processor_lambda.lambda_function_name
  }

  tags = local.common_tags
}

# ========================================
# DYNAMODB ALARMS
# ========================================

# Users table alarms
resource "aws_cloudwatch_metric_alarm" "users_table_throttles" {
  alarm_name          = "${local.function_name}-users-table-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "UserErrorsThrottledRequests"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Users DynamoDB table is being throttled"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]

  dimensions = {
    TableName = aws_dynamodb_table.users.name
  }

  tags = local.common_tags
}

# Event Store table alarms
resource "aws_cloudwatch_metric_alarm" "event_store_consumed_read_capacity" {
  alarm_name          = "${local.function_name}-event-store-read-capacity"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ConsumedReadCapacityUnits"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "80"
  alarm_description   = "Event Store table read capacity is high"
  alarm_actions       = [aws_sns_topic.warning_alerts.arn]

  dimensions = {
    TableName = aws_dynamodb_table.event_store.name
  }

  tags = local.common_tags
}

# ========================================
# API GATEWAY ALARMS
# ========================================

resource "aws_cloudwatch_metric_alarm" "api_gateway_4xx_errors" {
  alarm_name          = "${local.function_name}-api-4xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "4XXError"
  namespace           = "AWS/ApiGateway"
  period              = "300"
  statistic           = "Sum"
  threshold           = "50"
  alarm_description   = "API Gateway 4XX error rate is too high"
  alarm_actions       = [aws_sns_topic.warning_alerts.arn]

  dimensions = {
    ApiName = "${local.function_name}-api"
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "api_gateway_5xx_errors" {
  alarm_name          = "${local.function_name}-api-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "5XXError"
  namespace           = "AWS/ApiGateway"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "API Gateway 5XX error rate is too high"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]

  dimensions = {
    ApiName = "${local.function_name}-api"
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "api_gateway_latency" {
  alarm_name          = "${local.function_name}-api-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "Latency"
  namespace           = "AWS/ApiGateway"
  period              = "300"
  statistic           = "Average"
  threshold           = "5000"
  alarm_description   = "API Gateway latency is too high"
  alarm_actions       = [aws_sns_topic.warning_alerts.arn]

  dimensions = {
    ApiName = "${local.function_name}-api"
  }

  tags = local.common_tags
}

# ========================================
# COST MONITORING
# ========================================

# Budget for Lambda costs
resource "aws_budgets_budget" "lambda_costs" {
  name         = "${local.function_name}-lambda-budget"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_limit
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  time_period_start = "2024-01-01_00:00"

  cost_filters = {
    Service = ["Amazon Elastic Compute Cloud - Compute", "AWS Lambda"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_email_addresses = var.budget_notification_emails
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.budget_notification_emails
  }

  tags = local.common_tags
}

# ========================================
# CLOUDWATCH DASHBOARD
# ========================================

resource "aws_cloudwatch_dashboard" "main_dashboard" {
  dashboard_name = "${local.function_name}-overview"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", module.health_lambda.lambda_function_name],
            [".", "Errors", ".", "."],
            [".", "Duration", ".", "."],
            ["AWS/Lambda", "Invocations", "FunctionName", module.users_lambda.lambda_function_name],
            [".", "Errors", ".", "."],
            [".", "Duration", ".", "."],
            ["AWS/Lambda", "Invocations", "FunctionName", module.posts_lambda.lambda_function_name],
            [".", "Errors", ".", "."],
            [".", "Duration", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          period  = 300
          title   = "Lambda Function Metrics"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", aws_dynamodb_table.users.name],
            [".", "ConsumedWriteCapacityUnits", ".", "."],
            [".", "ConsumedReadCapacityUnits", "TableName", aws_dynamodb_table.event_store.name],
            [".", "ConsumedWriteCapacityUnits", ".", "."],
            [".", "ConsumedReadCapacityUnits", "TableName", aws_dynamodb_table.order_summaries.name],
            [".", "ConsumedWriteCapacityUnits", ".", "."]
          ]
          view   = "timeSeries"
          stacked = false
          region = var.aws_region
          period = 300
          title  = "DynamoDB Capacity Usage"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ApiGateway", "Count", "ApiName", "${local.function_name}-api"],
            [".", "4XXError", ".", "."],
            [".", "5XXError", ".", "."],
            [".", "Latency", ".", "."]
          ]
          view   = "timeSeries"
          stacked = false
          region = var.aws_region
          period = 300
          title  = "API Gateway Metrics"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["CWLogs", "IncomingLogEvents", "LogGroupName", "/aws/lambda/${module.health_lambda.lambda_function_name}"],
            [".", ".", ".", "/aws/lambda/${module.users_lambda.lambda_function_name}"],
            [".", ".", ".", "/aws/lambda/${module.posts_lambda.lambda_function_name}"],
            [".", ".", ".", "/aws/lambda/${module.event_processor_lambda.lambda_function_name}"]
          ]
          view   = "timeSeries"
          stacked = false
          region = var.aws_region
          period = 300
          title  = "Log Volume"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 12
        width  = 24
        height = 6

        properties = {
          query = "SOURCE '/aws/lambda/${module.health_lambda.lambda_function_name}' | SOURCE '/aws/lambda/${module.users_lambda.lambda_function_name}' | SOURCE '/aws/lambda/${module.posts_lambda.lambda_function_name}'\n| fields @timestamp, @message\n| filter @message like /ERROR/\n| sort @timestamp desc\n| limit 20"
          region = var.aws_region
          title  = "Recent Errors"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Business metrics dashboard
resource "aws_cloudwatch_dashboard" "business_metrics" {
  dashboard_name = "${local.function_name}-business-metrics"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["${var.powertools_service_name}", "OrdersCreated"],
            [".", "OrdersUpdated"],
            [".", "OrdersCancelled"],
            [".", "OrderProcessingTime"]
          ]
          view   = "timeSeries"
          stacked = false
          region = var.aws_region
          period = 300
          title  = "Order Processing Metrics"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 0
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["${var.powertools_service_name}", "AuthenticationSuccessful"],
            [".", "AuthenticationFailed"],
            [".", "RateLimitExceeded"],
            [".", "SecurityViolations"]
          ]
          view   = "timeSeries"
          stacked = false
          region = var.aws_region
          period = 300
          title  = "Security Metrics"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 0
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["${var.powertools_service_name}", "ActiveUsers"],
            [".", "UserRegistrations"],
            [".", "UserActivities"],
            [".", "FeatureFlagEvaluations"]
          ]
          view   = "timeSeries"
          stacked = false
          region = var.aws_region
          period = 300
          title  = "User Activity Metrics"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# ========================================
# DATA SOURCES
# ========================================

data "aws_caller_identity" "current" {}
