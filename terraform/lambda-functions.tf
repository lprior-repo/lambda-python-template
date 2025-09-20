# Lambda function modules for each endpoint
module "lambda_functions" {
  source   = "terraform-aws-modules/lambda/aws"
  version  = "~> 8.1"
  for_each = { for k, v in local.lambda_functions : k => v if length(v.routes) > 0 }

  function_name = each.value.name
  description   = "Serverless function for ${each.key} endpoint"
  handler       = each.value.handler
  runtime       = each.value.runtime
  architectures = ["arm64"]

  create_package         = false
  local_existing_package = each.value.source_dir

  timeout     = 30
  memory_size = 512

  environment_variables = {
    ENVIRONMENT      = local.environment
    NODE_ENV         = "production"
    LOG_LEVEL        = "INFO"
    USERS_TABLE_NAME = aws_dynamodb_table.users.name
    POSTS_TABLE_NAME = aws_dynamodb_table.posts.name
    AUDIT_TABLE_NAME = aws_dynamodb_table.audit_logs.name
    EVENT_BUS_NAME   = aws_cloudwatch_event_bus.app_events.name
    AWS_REGION       = local.aws_region
  }

  # CloudWatch Logs
  attach_cloudwatch_logs_policy     = true
  cloudwatch_logs_retention_in_days = 14

  # X-Ray tracing
  tracing_mode          = "Active"
  attach_tracing_policy = true

  # DynamoDB permissions
  attach_policy_statements = true
  policy_statements = {
    dynamodb = {
      effect = "Allow"
      actions = [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:Scan"
      ]
      resources = [
        aws_dynamodb_table.users.arn,
        "${aws_dynamodb_table.users.arn}/*",
        aws_dynamodb_table.posts.arn,
        "${aws_dynamodb_table.posts.arn}/*",
        aws_dynamodb_table.audit_logs.arn,
        "${aws_dynamodb_table.audit_logs.arn}/*"
      ]
    }
    eventbridge = {
      effect    = "Allow"
      actions   = ["events:PutEvents"]
      resources = [aws_cloudwatch_event_bus.app_events.arn]
    }
  }

  tags = local.common_tags
}

# Authorizer Lambda (separate module since it doesn't need routes)
module "api_key_authorizer" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 8.1"

  function_name = local.lambda_functions.authorizer.name
  description   = "API Key authorizer for API Gateway"
  handler       = local.lambda_functions.authorizer.handler
  runtime       = local.lambda_functions.authorizer.runtime
  architectures = ["arm64"]

  create_package         = false
  local_existing_package = local.lambda_functions.authorizer.source_dir

  timeout     = 30
  memory_size = 256

  environment_variables = {
    ENVIRONMENT = local.environment
    NODE_ENV    = "production"
    LOG_LEVEL   = "INFO"
    AWS_REGION  = local.aws_region
  }

  # CloudWatch Logs
  attach_cloudwatch_logs_policy     = true
  cloudwatch_logs_retention_in_days = 14

  tags = local.common_tags
}

# Event Processor Lambda (for EventBridge)
module "event_processor" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 8.1"

  function_name = local.lambda_functions.event_processor.name
  description   = "Process EventBridge events for audit logging"
  handler       = local.lambda_functions.event_processor.handler
  runtime       = local.lambda_functions.event_processor.runtime
  architectures = ["arm64"]

  create_package         = false
  local_existing_package = local.lambda_functions.event_processor.source_dir

  timeout     = 30
  memory_size = 256

  environment_variables = {
    ENVIRONMENT      = local.environment
    NODE_ENV         = "production"
    LOG_LEVEL        = "INFO"
    AUDIT_TABLE_NAME = aws_dynamodb_table.audit_logs.name
    AWS_REGION       = local.aws_region
  }

  # CloudWatch Logs
  attach_cloudwatch_logs_policy     = true
  cloudwatch_logs_retention_in_days = 14

  # DynamoDB permissions for audit logs
  attach_policy_statements = true
  policy_statements = {
    dynamodb = {
      effect    = "Allow"
      actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
      resources = [aws_dynamodb_table.audit_logs.arn]
    }
  }

  tags = local.common_tags
}

# Lambda permissions for API Gateway
resource "aws_lambda_permission" "api_gateway_lambda" {
  for_each = { for k, v in local.lambda_functions : k => v if length(v.routes) > 0 }

  statement_id  = "AllowExecutionFromAPIGateway-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_functions[each.key].lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/*/*"
}

# Lambda permission for authorizer
resource "aws_lambda_permission" "authorizer" {
  statement_id  = "AllowExecutionFromAPIGateway-authorizer"
  action        = "lambda:InvokeFunction"
  function_name = module.api_key_authorizer.lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/*/*"
}