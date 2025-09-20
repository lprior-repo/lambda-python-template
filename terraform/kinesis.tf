# ========================================
# KINESIS INTEGRATION FOR REAL-TIME EVENT STREAMING
# ========================================
# Enterprise-grade real-time data processing with:
# - Kinesis Data Streams for high-throughput event ingestion
# - DynamoDB Streams integration for change data capture
# - Kinesis Data Analytics for real-time analytics
# - Lambda consumers for stream processing
# - Dead letter queues for failed processing

# ========================================
# KINESIS DATA STREAMS
# ========================================

# Main event stream for real-time order processing
resource "aws_kinesis_stream" "order_events" {
  name             = "${local.function_name}-order-events"
  shard_count      = var.kinesis_shard_count
  retention_period = var.kinesis_retention_hours

  shard_level_metrics = [
    "IncomingRecords",
    "OutgoingRecords",
    "WriteProvisionedThroughputExceeded",
    "ReadProvisionedThroughputExceeded",
    "IncomingBytes",
    "OutgoingBytes"
  ]

  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.kinesis_encryption.arn

  tags = merge(local.common_tags, {
    Purpose = "Real-time order event processing"
  })
}

# User activity stream for real-time analytics
resource "aws_kinesis_stream" "user_activity" {
  name             = "${local.function_name}-user-activity"
  shard_count      = var.kinesis_shard_count
  retention_period = var.kinesis_retention_hours

  shard_level_metrics = [
    "IncomingRecords",
    "OutgoingRecords"
  ]

  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.kinesis_encryption.arn

  tags = merge(local.common_tags, {
    Purpose = "Real-time user activity tracking"
  })
}

# Security events stream for monitoring and alerting
resource "aws_kinesis_stream" "security_events" {
  name             = "${local.function_name}-security-events"
  shard_count      = 1
  retention_period = 168 # 7 days for security events

  shard_level_metrics = [
    "IncomingRecords",
    "OutgoingRecords"
  ]

  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.kinesis_encryption.arn

  tags = merge(local.common_tags, {
    Purpose = "Security event monitoring"
  })
}

# ========================================
# KMS KEY FOR KINESIS ENCRYPTION
# ========================================

resource "aws_kms_key" "kinesis_encryption" {
  description             = "KMS key for Kinesis streams encryption"
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Kinesis Service"
        Effect = "Allow"
        Principal = {
          Service = "kinesis.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Lambda Service"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "kinesis_encryption" {
  name          = "alias/${local.function_name}-kinesis"
  target_key_id = aws_kms_key.kinesis_encryption.key_id
}

# ========================================
# DYNAMODB STREAMS INTEGRATION
# ========================================

# Enable DynamoDB streams on core tables for change data capture
resource "aws_dynamodb_table" "users_with_stream" {
  name         = "${local.function_name}-users-stream"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = var.enable_point_in_time_recovery
  }

  tags = merge(local.common_tags, {
    Purpose = "Users table with DynamoDB streams"
  })
}

resource "aws_dynamodb_table" "orders_with_stream" {
  name         = "${local.function_name}-orders-stream"
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

  global_secondary_index {
    name     = "UserOrdersIndex"
    hash_key = "user_id"
  }

  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = var.enable_point_in_time_recovery
  }

  tags = merge(local.common_tags, {
    Purpose = "Orders table with DynamoDB streams"
  })
}

# ========================================
# KINESIS DATA ANALYTICS
# ========================================

# Real-time analytics application for order processing
resource "aws_kinesis_analytics_application" "order_analytics" {
  name = "${local.function_name}-order-analytics"

  code = file("${path.module}/sql/order_analytics.sql")

  inputs {
    name_prefix = "ORDER_STREAM"

    kinesis_stream {
      resource_arn = aws_kinesis_stream.order_events.arn
      role_arn     = aws_iam_role.kinesis_analytics.arn
    }

    schema {
      record_columns {
        name     = "event_id"
        sql_type = "VARCHAR(64)"
        mapping  = "$.event_id"
      }

      record_columns {
        name     = "event_type"
        sql_type = "VARCHAR(32)"
        mapping  = "$.event_type"
      }

      record_columns {
        name     = "order_id"
        sql_type = "VARCHAR(64)"
        mapping  = "$.order_id"
      }

      record_columns {
        name     = "user_id"
        sql_type = "VARCHAR(64)"
        mapping  = "$.user_id"
      }

      record_columns {
        name     = "amount"
        sql_type = "DECIMAL(10,2)"
        mapping  = "$.amount"
      }

      record_columns {
        name     = "timestamp"
        sql_type = "TIMESTAMP"
        mapping  = "$.timestamp"
      }

      record_format {
        record_format_type = "JSON"

        mapping_parameters {
          json_mapping_parameters {
            record_row_path = "$"
          }
        }
      }
    }
  }

  outputs {
    name = "ORDER_METRICS_STREAM"

    kinesis_stream {
      resource_arn = aws_kinesis_stream.analytics_output.arn
      role_arn     = aws_iam_role.kinesis_analytics.arn
    }

    schema {
      record_format_type = "JSON"
    }
  }

  tags = local.common_tags
}

# Output stream for analytics results
resource "aws_kinesis_stream" "analytics_output" {
  name             = "${local.function_name}-analytics-output"
  shard_count      = 1
  retention_period = 24

  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.kinesis_encryption.arn

  tags = merge(local.common_tags, {
    Purpose = "Analytics output stream"
  })
}

# ========================================
# LAMBDA STREAM PROCESSORS
# ========================================

# Order events stream processor
module "order_stream_processor" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.1.0"

  function_name = "${local.function_name}-order-stream-processor"
  description   = "Process order events from Kinesis stream"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  architectures = ["arm64"]
  memory_size   = var.lambda_memory_size
  timeout       = 60

  create_package         = false
  local_existing_package = "../build/order-stream-processor.zip"

  tracing_mode = var.enable_xray_tracing ? "Active" : "PassThrough"

  environment_variables = {
    POWERTOOLS_SERVICE_NAME      = var.powertools_service_name
    POWERTOOLS_METRICS_NAMESPACE = var.powertools_service_name
    LOG_LEVEL                    = var.environment == "prod" ? "INFO" : "DEBUG"
    ENVIRONMENT                  = var.environment
    ORDER_EVENTS_STREAM_NAME     = aws_kinesis_stream.order_events.name
    USER_ACTIVITY_STREAM_NAME    = aws_kinesis_stream.user_activity.name
    SECURITY_EVENTS_STREAM_NAME  = aws_kinesis_stream.security_events.name
  }

  attach_cloudwatch_logs_policy     = true
  attach_tracing_policy             = var.enable_xray_tracing
  cloudwatch_logs_retention_in_days = var.log_retention_in_days

  attach_policy_statements = true
  policy_statements = {
    kinesis_read = {
      effect = "Allow"
      actions = [
        "kinesis:DescribeStream",
        "kinesis:GetShardIterator",
        "kinesis:GetRecords",
        "kinesis:ListShards"
      ]
      resources = [
        aws_kinesis_stream.order_events.arn,
        aws_kinesis_stream.user_activity.arn,
        aws_kinesis_stream.security_events.arn
      ]
    }
    kinesis_write = {
      effect = "Allow"
      actions = [
        "kinesis:PutRecord",
        "kinesis:PutRecords"
      ]
      resources = [
        aws_kinesis_stream.user_activity.arn,
        aws_kinesis_stream.security_events.arn
      ]
    }
    kms_decrypt = {
      effect = "Allow"
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey"
      ]
      resources = [aws_kms_key.kinesis_encryption.arn]
    }
    dynamodb_read_write = {
      effect = "Allow"
      actions = [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query",
        "dynamodb:Scan"
      ]
      resources = [
        aws_dynamodb_table.order_summaries.arn,
        aws_dynamodb_table.user_activity.arn,
        "${aws_dynamodb_table.order_summaries.arn}/*",
        "${aws_dynamodb_table.user_activity.arn}/*"
      ]
    }
  }

  event_source_mapping = {
    kinesis = {
      event_source_arn                   = aws_kinesis_stream.order_events.arn
      starting_position                  = "LATEST"
      batch_size                         = 100
      maximum_batching_window_in_seconds = 5
      parallelization_factor             = 2
      bisect_batch_on_function_error     = true
      maximum_retry_attempts             = 3

      destination_config {
        on_failure {
          destination_arn = aws_sqs_queue.stream_processing_dlq.arn
        }
      }
    }
  }

  tags = local.common_tags
}

# DynamoDB streams processor
module "dynamodb_stream_processor" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.1.0"

  function_name = "${local.function_name}-dynamodb-stream-processor"
  description   = "Process DynamoDB stream events for change data capture"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  architectures = ["arm64"]
  memory_size   = var.lambda_memory_size
  timeout       = 60

  create_package         = false
  local_existing_package = "../build/dynamodb-stream-processor.zip"

  tracing_mode = var.enable_xray_tracing ? "Active" : "PassThrough"

  environment_variables = {
    POWERTOOLS_SERVICE_NAME      = var.powertools_service_name
    POWERTOOLS_METRICS_NAMESPACE = var.powertools_service_name
    LOG_LEVEL                    = var.environment == "prod" ? "INFO" : "DEBUG"
    ENVIRONMENT                  = var.environment
    ORDER_EVENTS_STREAM_NAME     = aws_kinesis_stream.order_events.name
    USER_ACTIVITY_STREAM_NAME    = aws_kinesis_stream.user_activity.name
  }

  attach_cloudwatch_logs_policy     = true
  attach_tracing_policy             = var.enable_xray_tracing
  cloudwatch_logs_retention_in_days = var.log_retention_in_days

  attach_policy_statements = true
  policy_statements = {
    dynamodb_stream_read = {
      effect = "Allow"
      actions = [
        "dynamodb:DescribeStream",
        "dynamodb:GetRecords",
        "dynamodb:GetShardIterator",
        "dynamodb:ListStreams"
      ]
      resources = [
        "${aws_dynamodb_table.users_with_stream.arn}/stream/*",
        "${aws_dynamodb_table.orders_with_stream.arn}/stream/*"
      ]
    }
    kinesis_write = {
      effect = "Allow"
      actions = [
        "kinesis:PutRecord",
        "kinesis:PutRecords"
      ]
      resources = [
        aws_kinesis_stream.order_events.arn,
        aws_kinesis_stream.user_activity.arn
      ]
    }
    kms_encrypt_decrypt = {
      effect = "Allow"
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]
      resources = [aws_kms_key.kinesis_encryption.arn]
    }
  }

  event_source_mapping = {
    users_stream = {
      event_source_arn                   = aws_dynamodb_table.users_with_stream.stream_arn
      starting_position                  = "LATEST"
      batch_size                         = 10
      maximum_batching_window_in_seconds = 5
      bisect_batch_on_function_error     = true
      maximum_retry_attempts             = 3

      destination_config {
        on_failure {
          destination_arn = aws_sqs_queue.stream_processing_dlq.arn
        }
      }
    }

    orders_stream = {
      event_source_arn                   = aws_dynamodb_table.orders_with_stream.stream_arn
      starting_position                  = "LATEST"
      batch_size                         = 10
      maximum_batching_window_in_seconds = 5
      bisect_batch_on_function_error     = true
      maximum_retry_attempts             = 3

      destination_config {
        on_failure {
          destination_arn = aws_sqs_queue.stream_processing_dlq.arn
        }
      }
    }
  }

  tags = local.common_tags
}

# ========================================
# DEAD LETTER QUEUE FOR STREAM PROCESSING
# ========================================

resource "aws_sqs_queue" "stream_processing_dlq" {
  name                       = "${local.function_name}-stream-processing-dlq"
  message_retention_seconds  = 1209600 # 14 days
  visibility_timeout_seconds = 300

  kms_master_key_id                 = "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = 300

  tags = merge(local.common_tags, {
    Purpose = "Dead letter queue for stream processing failures"
  })
}

# DLQ alarm for monitoring failed messages
resource "aws_cloudwatch_metric_alarm" "stream_processing_dlq_messages" {
  alarm_name          = "${local.function_name}-stream-dlq-messages"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ApproximateNumberOfVisibleMessages"
  namespace           = "AWS/SQS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Messages in stream processing DLQ"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]

  dimensions = {
    QueueName = aws_sqs_queue.stream_processing_dlq.name
  }

  tags = local.common_tags
}

# ========================================
# IAM ROLES AND POLICIES
# ========================================

# IAM role for Kinesis Analytics
resource "aws_iam_role" "kinesis_analytics" {
  name = "${local.function_name}-kinesis-analytics-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "kinesisanalytics.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "kinesis_analytics" {
  name = "${local.function_name}-kinesis-analytics-policy"
  role = aws_iam_role.kinesis_analytics.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kinesis:DescribeStream",
          "kinesis:GetShardIterator",
          "kinesis:GetRecords",
          "kinesis:ListShards"
        ]
        Resource = [
          aws_kinesis_stream.order_events.arn,
          aws_kinesis_stream.user_activity.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kinesis:PutRecord",
          "kinesis:PutRecords"
        ]
        Resource = aws_kinesis_stream.analytics_output.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.kinesis_encryption.arn
      }
    ]
  })
}

# ========================================
# KINESIS MONITORING
# ========================================

# Kinesis stream monitoring alarms
resource "aws_cloudwatch_metric_alarm" "kinesis_incoming_records" {
  count = length([
    aws_kinesis_stream.order_events.name,
    aws_kinesis_stream.user_activity.name,
    aws_kinesis_stream.security_events.name
  ])

  alarm_name          = "${local.function_name}-kinesis-${element([
    "order-events",
    "user-activity",
    "security-events"
  ], count.index)}-incoming-records"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "IncomingRecords"
  namespace           = "AWS/Kinesis"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Kinesis stream has no incoming records"
  alarm_actions       = [aws_sns_topic.warning_alerts.arn]

  dimensions = {
    StreamName = element([
      aws_kinesis_stream.order_events.name,
      aws_kinesis_stream.user_activity.name,
      aws_kinesis_stream.security_events.name
    ], count.index)
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "kinesis_write_provisioned_throughput_exceeded" {
  count = length([
    aws_kinesis_stream.order_events.name,
    aws_kinesis_stream.user_activity.name,
    aws_kinesis_stream.security_events.name
  ])

  alarm_name          = "${local.function_name}-kinesis-${element([
    "order-events",
    "user-activity",
    "security-events"
  ], count.index)}-write-throttled"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "WriteProvisionedThroughputExceeded"
  namespace           = "AWS/Kinesis"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Kinesis stream write throughput exceeded"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]

  dimensions = {
    StreamName = element([
      aws_kinesis_stream.order_events.name,
      aws_kinesis_stream.user_activity.name,
      aws_kinesis_stream.security_events.name
    ], count.index)
  }

  tags = local.common_tags
}
