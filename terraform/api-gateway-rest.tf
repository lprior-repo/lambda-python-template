# ========================================
# API GATEWAY REST API
# ========================================
# Complete REST API setup with proper resource structure, CORS, validation,
# request/response mapping, and comprehensive monitoring

# API Gateway REST API
resource "aws_api_gateway_rest_api" "orders_api" {
  name        = "${local.function_name}-orders-api"
  description = "Orders management REST API with comprehensive features"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  # Enable request validation
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = "execute-api:Invoke"
        Resource = "*"
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ips
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Resource = "api-gateway-rest"
  })
}

# ========================================
# API GATEWAY MODELS
# ========================================

# Request validation models
resource "aws_api_gateway_model" "create_order_request" {
  rest_api_id  = aws_api_gateway_rest_api.orders_api.id
  name         = "CreateOrderRequest"
  content_type = "application/json"

  schema = jsonencode({
    "$schema" = "http://json-schema.org/draft-04/schema#"
    title     = "Create Order Request"
    type      = "object"
    properties = {
      customer_name = {
        type      = "string"
        minLength = 1
        maxLength = 50
        pattern   = "^[a-zA-Z\\s]+$"
      }
      customer_email = {
        type    = "string"
        pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
      }
      order_item_count = {
        type    = "integer"
        minimum = 1
        maximum = 100
      }
      notes = {
        type      = "string"
        maxLength = 500
      }
    }
    required = ["customer_name", "customer_email", "order_item_count"]
  })
}

resource "aws_api_gateway_model" "update_order_request" {
  rest_api_id  = aws_api_gateway_rest_api.orders_api.id
  name         = "UpdateOrderRequest"
  content_type = "application/json"

  schema = jsonencode({
    "$schema" = "http://json-schema.org/draft-04/schema#"
    title     = "Update Order Request"
    type      = "object"
    properties = {
      order_item_count = {
        type    = "integer"
        minimum = 1
        maximum = 100
      }
      notes = {
        type      = "string"
        maxLength = 500
      }
    }
  })
}

resource "aws_api_gateway_model" "error_response" {
  rest_api_id  = aws_api_gateway_rest_api.orders_api.id
  name         = "ErrorResponse"
  content_type = "application/json"

  schema = jsonencode({
    "$schema" = "http://json-schema.org/draft-04/schema#"
    title     = "Error Response"
    type      = "object"
    properties = {
      error = {
        type = "object"
        properties = {
          code         = { type = "string" }
          message      = { type = "string" }
          error_id     = { type = "string" }
          timestamp    = { type = "string" }
          details      = { type = "object" }
          field_errors = { type = "array" }
        }
        required = ["code", "message", "error_id", "timestamp"]
      }
      retry_after = { type = "integer" }
    }
    required = ["error"]
  })
}

# ========================================
# REQUEST VALIDATORS
# ========================================

resource "aws_api_gateway_request_validator" "body_validator" {
  name                        = "${local.function_name}-body-validator"
  rest_api_id                 = aws_api_gateway_rest_api.orders_api.id
  validate_request_body       = true
  validate_request_parameters = false
}

resource "aws_api_gateway_request_validator" "params_validator" {
  name                        = "${local.function_name}-params-validator"
  rest_api_id                 = aws_api_gateway_rest_api.orders_api.id
  validate_request_body       = false
  validate_request_parameters = true
}

resource "aws_api_gateway_request_validator" "body_and_params_validator" {
  name                        = "${local.function_name}-body-and-params-validator"
  rest_api_id                 = aws_api_gateway_rest_api.orders_api.id
  validate_request_body       = true
  validate_request_parameters = true
}

# ========================================
# API RESOURCES STRUCTURE
# ========================================

# /api resource
resource "aws_api_gateway_resource" "api" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  parent_id   = aws_api_gateway_rest_api.orders_api.root_resource_id
  path_part   = "api"
}

# /api/v1 resource
resource "aws_api_gateway_resource" "api_v1" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  parent_id   = aws_api_gateway_resource.api.id
  path_part   = "v1"
}

# /api/v1/health resource
resource "aws_api_gateway_resource" "health" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  parent_id   = aws_api_gateway_resource.api_v1.id
  path_part   = "health"
}

# /api/v1/orders resource
resource "aws_api_gateway_resource" "orders" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  parent_id   = aws_api_gateway_resource.api_v1.id
  path_part   = "orders"
}

# /api/v1/orders/{order_id} resource
resource "aws_api_gateway_resource" "order_by_id" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  parent_id   = aws_api_gateway_resource.orders.id
  path_part   = "{order_id}"
}

# /api/v1/orders/statistics resource
resource "aws_api_gateway_resource" "order_statistics" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  parent_id   = aws_api_gateway_resource.orders.id
  path_part   = "statistics"
}

# ========================================
# CORS OPTIONS METHODS
# ========================================

# CORS for /health
resource "aws_api_gateway_method" "health_options" {
  rest_api_id   = aws_api_gateway_rest_api.orders_api.id
  resource_id   = aws_api_gateway_resource.health.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "health_options" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.health_options.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = jsonencode({
      statusCode = 200
    })
  }
}

resource "aws_api_gateway_method_response" "health_options" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.health_options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "health_options" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.health_options.http_method
  status_code = aws_api_gateway_method_response.health_options.status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "method.response.header.Access-Control-Allow-Methods" = "'GET,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }
}

# CORS for /orders
resource "aws_api_gateway_method" "orders_options" {
  rest_api_id   = aws_api_gateway_rest_api.orders_api.id
  resource_id   = aws_api_gateway_resource.orders.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "orders_options" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.orders.id
  http_method = aws_api_gateway_method.orders_options.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = jsonencode({
      statusCode = 200
    })
  }
}

resource "aws_api_gateway_method_response" "orders_options" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.orders.id
  http_method = aws_api_gateway_method.orders_options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "orders_options" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.orders.id
  http_method = aws_api_gateway_method.orders_options.http_method
  status_code = aws_api_gateway_method_response.orders_options.status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "method.response.header.Access-Control-Allow-Methods" = "'GET,POST,PUT,DELETE,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }
}

# CORS for /orders/{order_id}
resource "aws_api_gateway_method" "order_by_id_options" {
  rest_api_id   = aws_api_gateway_rest_api.orders_api.id
  resource_id   = aws_api_gateway_resource.order_by_id.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "order_by_id_options" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.order_by_id.id
  http_method = aws_api_gateway_method.order_by_id_options.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = jsonencode({
      statusCode = 200
    })
  }
}

resource "aws_api_gateway_method_response" "order_by_id_options" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.order_by_id.id
  http_method = aws_api_gateway_method.order_by_id_options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "order_by_id_options" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.order_by_id.id
  http_method = aws_api_gateway_method.order_by_id_options.http_method
  status_code = aws_api_gateway_method_response.order_by_id_options.status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "method.response.header.Access-Control-Allow-Methods" = "'GET,PUT,DELETE,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }
}

# ========================================
# LAMBDA INTEGRATIONS
# ========================================

# Health Check - GET /api/v1/health
resource "aws_api_gateway_method" "get_health" {
  rest_api_id   = aws_api_gateway_rest_api.orders_api.id
  resource_id   = aws_api_gateway_resource.health.id
  http_method   = "GET"
  authorization = "NONE"

  request_validator_id = aws_api_gateway_request_validator.params_validator.id
}

resource "aws_api_gateway_integration" "get_health" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.get_health.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.health_lambda.lambda_function_invoke_arn
}

resource "aws_lambda_permission" "allow_health_api_gateway" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = module.health_lambda.lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.orders_api.execution_arn}/*/*"
}

# Orders Collection - GET /api/v1/orders
resource "aws_api_gateway_method" "get_orders" {
  rest_api_id   = aws_api_gateway_rest_api.orders_api.id
  resource_id   = aws_api_gateway_resource.orders.id
  http_method   = "GET"
  authorization = "NONE"

  request_validator_id = aws_api_gateway_request_validator.params_validator.id

  request_parameters = {
    "method.request.querystring.customer_email"     = false
    "method.request.querystring.status"             = false
    "method.request.querystring.limit"              = false
    "method.request.querystring.last_evaluated_key" = false
  }
}

resource "aws_api_gateway_integration" "get_orders" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.orders.id
  http_method = aws_api_gateway_method.get_orders.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.orders_lambda.lambda_function_invoke_arn
}

# Orders Collection - POST /api/v1/orders
resource "aws_api_gateway_method" "post_orders" {
  rest_api_id   = aws_api_gateway_rest_api.orders_api.id
  resource_id   = aws_api_gateway_resource.orders.id
  http_method   = "POST"
  authorization = "NONE"

  request_validator_id = aws_api_gateway_request_validator.body_validator.id

  request_models = {
    "application/json" = aws_api_gateway_model.create_order_request.name
  }
}

resource "aws_api_gateway_integration" "post_orders" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.orders.id
  http_method = aws_api_gateway_method.post_orders.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.orders_lambda.lambda_function_invoke_arn
}

# Order by ID - GET /api/v1/orders/{order_id}
resource "aws_api_gateway_method" "get_order_by_id" {
  rest_api_id   = aws_api_gateway_rest_api.orders_api.id
  resource_id   = aws_api_gateway_resource.order_by_id.id
  http_method   = "GET"
  authorization = "NONE"

  request_validator_id = aws_api_gateway_request_validator.params_validator.id

  request_parameters = {
    "method.request.path.order_id" = true
  }
}

resource "aws_api_gateway_integration" "get_order_by_id" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.order_by_id.id
  http_method = aws_api_gateway_method.get_order_by_id.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.orders_lambda.lambda_function_invoke_arn
}

# Order by ID - PUT /api/v1/orders/{order_id}
resource "aws_api_gateway_method" "put_order_by_id" {
  rest_api_id   = aws_api_gateway_rest_api.orders_api.id
  resource_id   = aws_api_gateway_resource.order_by_id.id
  http_method   = "PUT"
  authorization = "NONE"

  request_validator_id = aws_api_gateway_request_validator.body_and_params_validator.id

  request_parameters = {
    "method.request.path.order_id" = true
  }

  request_models = {
    "application/json" = aws_api_gateway_model.update_order_request.name
  }
}

resource "aws_api_gateway_integration" "put_order_by_id" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.order_by_id.id
  http_method = aws_api_gateway_method.put_order_by_id.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.orders_lambda.lambda_function_invoke_arn
}

# Order by ID - DELETE /api/v1/orders/{order_id}
resource "aws_api_gateway_method" "delete_order_by_id" {
  rest_api_id   = aws_api_gateway_rest_api.orders_api.id
  resource_id   = aws_api_gateway_resource.order_by_id.id
  http_method   = "DELETE"
  authorization = "NONE"

  request_validator_id = aws_api_gateway_request_validator.params_validator.id

  request_parameters = {
    "method.request.path.order_id"      = true
    "method.request.querystring.reason" = false
  }
}

resource "aws_api_gateway_integration" "delete_order_by_id" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.order_by_id.id
  http_method = aws_api_gateway_method.delete_order_by_id.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.orders_lambda.lambda_function_invoke_arn
}

# Order Statistics - GET /api/v1/orders/statistics
resource "aws_api_gateway_method" "get_order_statistics" {
  rest_api_id   = aws_api_gateway_rest_api.orders_api.id
  resource_id   = aws_api_gateway_resource.order_statistics.id
  http_method   = "GET"
  authorization = "NONE"

  request_validator_id = aws_api_gateway_request_validator.params_validator.id
}

resource "aws_api_gateway_integration" "get_order_statistics" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  resource_id = aws_api_gateway_resource.order_statistics.id
  http_method = aws_api_gateway_method.get_order_statistics.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.orders_lambda.lambda_function_invoke_arn
}

# Lambda permissions for orders API
resource "aws_lambda_permission" "allow_orders_api_gateway" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = module.orders_lambda.lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.orders_api.execution_arn}/*/*"
}

# ========================================
# API GATEWAY DEPLOYMENT
# ========================================

resource "aws_api_gateway_deployment" "orders_api" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.api.id,
      aws_api_gateway_resource.api_v1.id,
      aws_api_gateway_resource.health.id,
      aws_api_gateway_resource.orders.id,
      aws_api_gateway_resource.order_by_id.id,
      aws_api_gateway_resource.order_statistics.id,
      aws_api_gateway_method.get_health.id,
      aws_api_gateway_method.get_orders.id,
      aws_api_gateway_method.post_orders.id,
      aws_api_gateway_method.get_order_by_id.id,
      aws_api_gateway_method.put_order_by_id.id,
      aws_api_gateway_method.delete_order_by_id.id,
      aws_api_gateway_method.get_order_statistics.id,
      aws_api_gateway_integration.get_health.id,
      aws_api_gateway_integration.get_orders.id,
      aws_api_gateway_integration.post_orders.id,
      aws_api_gateway_integration.get_order_by_id.id,
      aws_api_gateway_integration.put_order_by_id.id,
      aws_api_gateway_integration.delete_order_by_id.id,
      aws_api_gateway_integration.get_order_statistics.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ========================================
# API GATEWAY STAGE
# ========================================

resource "aws_api_gateway_stage" "orders_api" {
  deployment_id = aws_api_gateway_deployment.orders_api.id
  rest_api_id   = aws_api_gateway_rest_api.orders_api.id
  stage_name    = var.environment

  # Enable detailed CloudWatch metrics
  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway_access_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      caller         = "$context.identity.caller"
      user           = "$context.identity.user"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      requestTime    = "$context.requestTime"
      responseTime   = "$context.responseTime"
      error          = "$context.error.message"
      errorType      = "$context.error.messageString"
    })
  }

  tags = local.common_tags
}

# ========================================
# CLOUDWATCH RESOURCES
# ========================================

# CloudWatch Log Group for API Gateway Access Logs
resource "aws_cloudwatch_log_group" "api_gateway_access_logs" {
  name              = "/aws/apigateway/${local.function_name}-orders-api"
  retention_in_days = 14

  tags = merge(local.common_tags, {
    Resource = "cloudwatch-logs-api-gateway"
  })
}

# CloudWatch Log Group for API Gateway Execution Logs
resource "aws_cloudwatch_log_group" "api_gateway_execution_logs" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.orders_api.id}/${var.environment}"
  retention_in_days = 14

  tags = merge(local.common_tags, {
    Resource = "cloudwatch-logs-api-gateway-execution"
  })
}

# ========================================
# API GATEWAY METHOD SETTINGS
# ========================================

resource "aws_api_gateway_method_settings" "orders_api" {
  rest_api_id = aws_api_gateway_rest_api.orders_api.id
  stage_name  = aws_api_gateway_stage.orders_api.stage_name
  method_path = "*/*"

  settings {
    # Enable detailed CloudWatch metrics
    metrics_enabled = true
    data_trace_enabled = var.environment != "production"
    logging_level = var.environment == "production" ? "ERROR" : "INFO"

    # Throttling settings
    throttling_rate_limit  = var.api_throttling_rate_limit
    throttling_burst_limit = var.api_throttling_burst_limit

    # Caching settings (disabled by default)
    caching_enabled = false
    cache_ttl_in_seconds = 300
    cache_key_parameters = []

    # Request/Response settings
    require_authorization_for_cache_control = false
    unauthorized_cache_control_header_strategy = "SUCCEED_WITH_RESPONSE_HEADER"
  }
}

# ========================================
# WAF INTEGRATION (OPTIONAL)
# ========================================

# Web ACL for API Gateway (optional security layer)
resource "aws_wafv2_web_acl" "api_gateway_waf" {
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

    override_action {
      none {}
    }

    statement {
      rate_based_statement {
        limit          = 2000
        aggregate_key_type = "IP"

        scope_down_statement {
          geo_match_statement {
            country_codes = ["US", "CA", "GB", "DE", "FR", "AU", "JP"]
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
      sampled_requests_enabled   = true
    }

    action {
      block {}
    }
  }

  # Block common attack patterns
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
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  tags = merge(local.common_tags, {
    Resource = "waf-web-acl"
  })
}

# Associate WAF with API Gateway stage
resource "aws_wafv2_web_acl_association" "api_gateway_waf" {
  count = var.enable_waf ? 1 : 0

  resource_arn = aws_api_gateway_stage.orders_api.arn
  web_acl_arn  = aws_wafv2_web_acl.api_gateway_waf[0].arn
}

# ========================================
# API GATEWAY DOMAIN NAME (OPTIONAL)
# ========================================

# Custom domain name for API Gateway (if certificate is provided)
resource "aws_api_gateway_domain_name" "orders_api" {
  count = var.api_domain_name != "" ? 1 : 0

  domain_name              = var.api_domain_name
  regional_certificate_arn = var.api_certificate_arn

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = merge(local.common_tags, {
    Resource = "api-gateway-domain"
  })
}

resource "aws_api_gateway_base_path_mapping" "orders_api" {
  count = var.api_domain_name != "" ? 1 : 0

  api_id      = aws_api_gateway_rest_api.orders_api.id
  stage_name  = aws_api_gateway_stage.orders_api.stage_name
  domain_name = aws_api_gateway_domain_name.orders_api[0].domain_name
  base_path   = "api"
}

# ========================================
# OUTPUTS
# ========================================

output "api_gateway_rest_api_id" {
  description = "ID of the API Gateway REST API"
  value       = aws_api_gateway_rest_api.orders_api.id
}

output "api_gateway_stage_arn" {
  description = "ARN of the API Gateway stage"
  value       = aws_api_gateway_stage.orders_api.arn
}

output "api_gateway_stage_invoke_url" {
  description = "Invoke URL of the API Gateway stage"
  value       = aws_api_gateway_stage.orders_api.invoke_url
}

output "api_base_url" {
  description = "Base URL for the API"
  value       = "${aws_api_gateway_stage.orders_api.invoke_url}/api/v1"
}

output "api_custom_domain_url" {
  description = "Custom domain URL for the API (if configured)"
  value       = var.api_domain_name != "" ? "https://${var.api_domain_name}/api" : null
}
