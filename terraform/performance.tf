# ========================================
# PERFORMANCE OPTIMIZATION INFRASTRUCTURE
# ========================================
# Enterprise-grade performance setup with:
# - Lambda provisioned concurrency for cold start elimination
# - DynamoDB auto-scaling for automatic capacity management
# - ElastiCache for high-performance caching
# - Connection pooling and optimization
# - Performance monitoring and alerting
# - Cost optimization recommendations

# ========================================
# LAMBDA PROVISIONED CONCURRENCY
# ========================================

# Provisioned concurrency for critical Lambda functions
resource "aws_lambda_provisioned_concurrency_config" "health_lambda" {
  count = var.enable_provisioned_concurrency ? 1 : 0

  function_name                     = module.health_lambda.lambda_function_name
  provisioned_concurrent_executions = var.health_lambda_provisioned_concurrency
  qualifier                         = module.health_lambda.lambda_function_version

  lifecycle {
    ignore_changes = [qualifier]
  }

  depends_on = [module.health_lambda]
}

resource "aws_lambda_provisioned_concurrency_config" "users_lambda" {
  count = var.enable_provisioned_concurrency ? 1 : 0

  function_name                     = module.users_lambda.lambda_function_name
  provisioned_concurrent_executions = var.users_lambda_provisioned_concurrency
  qualifier                         = module.users_lambda.lambda_function_version

  lifecycle {
    ignore_changes = [qualifier]
  }

  depends_on = [module.users_lambda]
}

resource "aws_lambda_provisioned_concurrency_config" "orders_lambda" {
  count = var.enable_provisioned_concurrency ? 1 : 0

  function_name                     = module.posts_lambda.lambda_function_name
  provisioned_concurrent_executions = var.orders_lambda_provisioned_concurrency
  qualifier                         = module.posts_lambda.lambda_function_version

  lifecycle {
    ignore_changes = [qualifier]
  }

  depends_on = [module.posts_lambda]
}

# Application Auto Scaling target for Lambda provisioned concurrency
resource "aws_appautoscaling_target" "lambda_concurrency" {
  count = var.enable_provisioned_concurrency && var.enable_lambda_autoscaling ? 1 : 0

  max_capacity       = var.lambda_max_provisioned_concurrency
  min_capacity       = var.lambda_min_provisioned_concurrency
  resource_id        = "function:${module.users_lambda.lambda_function_name}:provisioned"
  scalable_dimension = "lambda:function:ProvisionedConcurrency"
  service_namespace  = "lambda"

  depends_on = [aws_lambda_provisioned_concurrency_config.users_lambda]
}

# Auto scaling policy for Lambda concurrency
resource "aws_appautoscaling_policy" "lambda_concurrency_up" {
  count = var.enable_provisioned_concurrency && var.enable_lambda_autoscaling ? 1 : 0

  name               = "${local.function_name}-lambda-scale-up"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.lambda_concurrency[0].resource_id
  scalable_dimension = aws_appautoscaling_target.lambda_concurrency[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.lambda_concurrency[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "LambdaProvisionedConcurrencyUtilization"
    }
    target_value = 70.0
  }
}

# ========================================
# DYNAMODB AUTO-SCALING
# ========================================

# Auto-scaling for Users table
resource "aws_appautoscaling_target" "users_table_read" {
  count = var.dynamodb_billing_mode == "PROVISIONED" ? 1 : 0

  max_capacity       = var.dynamodb_max_read_capacity
  min_capacity       = var.dynamodb_min_read_capacity
  resource_id        = "table/${aws_dynamodb_table.users.name}"
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_target" "users_table_write" {
  count = var.dynamodb_billing_mode == "PROVISIONED" ? 1 : 0

  max_capacity       = var.dynamodb_max_write_capacity
  min_capacity       = var.dynamodb_min_write_capacity
  resource_id        = "table/${aws_dynamodb_table.users.name}"
  scalable_dimension = "dynamodb:table:WriteCapacityUnits"
  service_namespace  = "dynamodb"
}

# Auto-scaling policies for Users table
resource "aws_appautoscaling_policy" "users_table_read_policy" {
  count = var.dynamodb_billing_mode == "PROVISIONED" ? 1 : 0

  name               = "${local.function_name}-users-read-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.users_table_read[0].resource_id
  scalable_dimension = aws_appautoscaling_target.users_table_read[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.users_table_read[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBReadCapacityUtilization"
    }
    target_value = 70.0
  }
}

resource "aws_appautoscaling_policy" "users_table_write_policy" {
  count = var.dynamodb_billing_mode == "PROVISIONED" ? 1 : 0

  name               = "${local.function_name}-users-write-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.users_table_write[0].resource_id
  scalable_dimension = aws_appautoscaling_target.users_table_write[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.users_table_write[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBWriteCapacityUtilization"
    }
    target_value = 70.0
  }
}

# Auto-scaling for Event Store table
resource "aws_appautoscaling_target" "event_store_read" {
  count = var.dynamodb_billing_mode == "PROVISIONED" ? 1 : 0

  max_capacity       = var.dynamodb_max_read_capacity
  min_capacity       = var.dynamodb_min_read_capacity
  resource_id        = "table/${aws_dynamodb_table.event_store.name}"
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_target" "event_store_write" {
  count = var.dynamodb_billing_mode == "PROVISIONED" ? 1 : 0

  max_capacity       = var.dynamodb_max_write_capacity
  min_capacity       = var.dynamodb_min_write_capacity
  resource_id        = "table/${aws_dynamodb_table.event_store.name}"
  scalable_dimension = "dynamodb:table:WriteCapacityUnits"
  service_namespace  = "dynamodb"
}

# ========================================
# ELASTICACHE FOR CACHING
# ========================================

# ElastiCache subnet group
resource "aws_elasticache_subnet_group" "main" {
  count = var.enable_elasticache ? 1 : 0

  name       = "${local.function_name}-cache-subnet"
  subnet_ids = var.private_subnet_ids

  tags = local.common_tags
}

# ElastiCache security group
resource "aws_security_group" "elasticache" {
  count = var.enable_elasticache ? 1 : 0

  name_prefix = "${local.function_name}-elasticache-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 6379
    to_port     = 6379
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
    Name = "${local.function_name}-elasticache-sg"
  })
}

# ElastiCache parameter group
resource "aws_elasticache_parameter_group" "redis" {
  count = var.enable_elasticache ? 1 : 0

  family = "redis7"
  name   = "${local.function_name}-redis-params"

  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }

  parameter {
    name  = "timeout"
    value = "300"
  }

  parameter {
    name  = "tcp-keepalive"
    value = "60"
  }

  tags = local.common_tags
}

# ElastiCache Redis cluster
resource "aws_elasticache_replication_group" "redis" {
  count = var.enable_elasticache ? 1 : 0

  replication_group_id         = "${local.function_name}-redis"
  description                  = "Redis cluster for ${local.function_name}"

  node_type                    = var.elasticache_node_type
  port                         = 6379
  parameter_group_name         = aws_elasticache_parameter_group.redis[0].name
  subnet_group_name            = aws_elasticache_subnet_group.main[0].name
  security_group_ids           = [aws_security_group.elasticache[0].id]

  num_cache_clusters           = var.elasticache_num_cache_clusters

  # Multi-AZ and backup configuration
  automatic_failover_enabled   = var.elasticache_automatic_failover
  multi_az_enabled             = var.elasticache_multi_az
  snapshot_retention_limit     = var.elasticache_snapshot_retention
  snapshot_window              = "03:00-05:00"
  maintenance_window           = "sun:05:00-sun:07:00"

  # Encryption
  at_rest_encryption_enabled   = true
  transit_encryption_enabled   = true
  auth_token                   = var.redis_auth_token

  # Performance and monitoring
  apply_immediately            = false
  auto_minor_version_upgrade   = true

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.elasticache_slow[0].name
    destination_type = "cloudwatch-logs"
    log_format       = "text"
    log_type         = "slow-log"
  }

  tags = local.common_tags
}

# CloudWatch log group for ElastiCache slow logs
resource "aws_cloudwatch_log_group" "elasticache_slow" {
  count = var.enable_elasticache ? 1 : 0

  name              = "/aws/elasticache/${local.function_name}/slow-log"
  retention_in_days = var.log_retention_in_days

  tags = local.common_tags
}

# ========================================
# CONNECTION POOLING CONFIGURATION
# ========================================

# Lambda layer for connection pooling libraries
resource "aws_lambda_layer_version" "connection_pool" {
  count = var.enable_connection_pooling ? 1 : 0

  filename            = "../build/connection-pool-layer.zip"
  layer_name          = "${local.function_name}-connection-pool"
  description         = "Connection pooling libraries for ${local.function_name}"

  compatible_runtimes = ["python3.13"]
  compatible_architectures = ["arm64"]

  source_code_hash = filebase64sha256("../build/connection-pool-layer.zip")

  lifecycle {
    ignore_changes = [source_code_hash]
  }
}

# ========================================
# PERFORMANCE MONITORING
# ========================================

# Custom CloudWatch dashboard for performance metrics
resource "aws_cloudwatch_dashboard" "performance_metrics" {
  dashboard_name = "${local.function_name}-performance"

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
            ["AWS/Lambda", "Duration", "FunctionName", module.health_lambda.lambda_function_name, { "stat": "Average" }],
            [".", ".", ".", ".", { "stat": "p99" }],
            [".", "Duration", "FunctionName", module.users_lambda.lambda_function_name, { "stat": "Average" }],
            [".", ".", ".", ".", { "stat": "p99" }],
            [".", "Duration", "FunctionName", module.posts_lambda.lambda_function_name, { "stat": "Average" }],
            [".", ".", ".", ".", { "stat": "p99" }]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          period  = 300
          title   = "Lambda Function Duration (Average vs P99)"
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
            ["AWS/Lambda", "ConcurrentExecutions", "FunctionName", module.users_lambda.lambda_function_name],
            ["AWS/Lambda", "ProvisionedConcurrencyUtilization", "FunctionName", module.users_lambda.lambda_function_name],
            ["AWS/Lambda", "ProvisionedConcurrencyInvocations", "FunctionName", module.users_lambda.lambda_function_name]
          ]
          view   = "timeSeries"
          stacked = false
          region = var.aws_region
          period = 300
          title  = "Lambda Concurrency Metrics"
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
          metrics = var.enable_elasticache ? [
            ["AWS/ElastiCache", "CPUUtilization", "CacheClusterId", "${aws_elasticache_replication_group.redis[0].replication_group_id}-001"],
            [".", "DatabaseMemoryUsagePercentage", ".", "."],
            [".", "NetworkBytesIn", ".", "."],
            [".", "NetworkBytesOut", ".", "."]
          ] : []
          view   = "timeSeries"
          stacked = false
          region = var.aws_region
          period = 300
          title  = "ElastiCache Performance Metrics"
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
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", aws_dynamodb_table.users.name],
            [".", "ConsumedWriteCapacityUnits", ".", "."],
            [".", "SuccessfulRequestLatency", ".", ".", "Operation", "GetItem"],
            [".", "SuccessfulRequestLatency", ".", ".", "Operation", "PutItem"],
            [".", "SuccessfulRequestLatency", ".", ".", "Operation", "Query"]
          ]
          view   = "timeSeries"
          stacked = false
          region = var.aws_region
          period = 300
          title  = "DynamoDB Performance Metrics"
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
# PERFORMANCE ALARMS
# ========================================

# Lambda cold start alarm
resource "aws_cloudwatch_metric_alarm" "lambda_cold_starts" {
  count = var.enable_provisioned_concurrency ? 0 : 1

  alarm_name          = "${local.function_name}-cold-starts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Maximum"
  threshold           = var.cold_start_duration_threshold
  alarm_description   = "Lambda function experiencing cold starts"
  alarm_actions       = [aws_sns_topic.warning_alerts.arn]

  dimensions = {
    FunctionName = module.users_lambda.lambda_function_name
  }

  tags = local.common_tags
}

# DynamoDB throttling alarm
resource "aws_cloudwatch_metric_alarm" "dynamodb_throttling" {
  alarm_name          = "${local.function_name}-dynamodb-throttling"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "UserErrorsThrottledRequests"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "DynamoDB requests are being throttled"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]

  dimensions = {
    TableName = aws_dynamodb_table.users.name
  }

  tags = local.common_tags
}

# ElastiCache high CPU alarm
resource "aws_cloudwatch_metric_alarm" "elasticache_cpu" {
  count = var.enable_elasticache ? 1 : 0

  alarm_name          = "${local.function_name}-elasticache-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = var.elasticache_cpu_threshold
  alarm_description   = "ElastiCache CPU utilization is high"
  alarm_actions       = [aws_sns_topic.warning_alerts.arn]

  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.redis[0].replication_group_id}-001"
  }

  tags = local.common_tags
}

# ElastiCache memory usage alarm
resource "aws_cloudwatch_metric_alarm" "elasticache_memory" {
  count = var.enable_elasticache ? 1 : 0

  alarm_name          = "${local.function_name}-elasticache-memory"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseMemoryUsagePercentage"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = var.elasticache_memory_threshold
  alarm_description   = "ElastiCache memory utilization is high"
  alarm_actions       = [aws_sns_topic.warning_alerts.arn]

  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.redis[0].replication_group_id}-001"
  }

  tags = local.common_tags
}

# ========================================
# COST OPTIMIZATION
# ========================================

# Lambda function right-sizing recommendations
resource "aws_cloudwatch_log_metric_filter" "lambda_memory_utilization" {
  name           = "${local.function_name}-memory-utilization"
  log_group_name = "/aws/lambda/${module.users_lambda.lambda_function_name}"
  pattern        = "[timestamp, uuid, level, message=\"REPORT*\", ...]"

  metric_transformation {
    name      = "LambdaMemoryUtilization"
    namespace = var.powertools_service_name
    value     = "1"
  }
}

# DynamoDB unused capacity alarm
resource "aws_cloudwatch_metric_alarm" "dynamodb_unused_capacity" {
  count = var.dynamodb_billing_mode == "PROVISIONED" ? 1 : 0

  alarm_name          = "${local.function_name}-dynamodb-unused-capacity"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "ConsumedReadCapacityUnits"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Average"
  threshold           = var.dynamodb_unused_capacity_threshold
  alarm_description   = "DynamoDB has significant unused capacity"
  alarm_actions       = [aws_sns_topic.info_alerts.arn]

  dimensions = {
    TableName = aws_dynamodb_table.users.name
  }

  tags = local.common_tags
}

# ========================================
# OUTPUTS
# ========================================

output "elasticache_endpoint" {
  description = "ElastiCache Redis endpoint"
  value       = var.enable_elasticache ? aws_elasticache_replication_group.redis[0].primary_endpoint_address : null
}

output "performance_dashboard_url" {
  description = "CloudWatch dashboard URL for performance metrics"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.performance_metrics.dashboard_name}"
}

output "provisioned_concurrency_configs" {
  description = "Provisioned concurrency configurations"
  value = var.enable_provisioned_concurrency ? {
    health_lambda = var.health_lambda_provisioned_concurrency
    users_lambda  = var.users_lambda_provisioned_concurrency
    orders_lambda = var.orders_lambda_provisioned_concurrency
  } : {}
}

output "cache_configuration" {
  description = "Cache configuration details"
  value = var.enable_elasticache ? {
    node_type     = var.elasticache_node_type
    num_clusters  = var.elasticache_num_cache_clusters
    multi_az      = var.elasticache_multi_az
    endpoint      = aws_elasticache_replication_group.redis[0].primary_endpoint_address
  } : {}
}
