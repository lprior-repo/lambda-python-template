# API Gateway v2 (HTTP API)
resource "aws_apigatewayv2_api" "api" {
  name          = "${local.function_base_name}-api"
  description   = "Serverless HTTP API Gateway for ${var.project_name}"
  protocol_type = "HTTP"

  cors_configuration {
    allow_credentials = false
    allow_headers     = ["authorization", "content-type", "x-amz-date", "x-amz-security-token", "x-amz-user-agent", "x-api-key", "x-request-id"]
    allow_methods     = ["DELETE", "GET", "OPTIONS", "POST", "PUT"]
    allow_origins     = ["*"]
    expose_headers    = ["x-request-id", "x-service", "x-version"]
    max_age           = 86400
  }

  tags = local.common_tags
}

# API Gateway Stage
resource "aws_apigatewayv2_stage" "api" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "prod"
  auto_deploy = true

  tags = local.common_tags
}

# API Gateway Authorizer
resource "aws_apigatewayv2_authorizer" "api_key" {
  api_id                            = aws_apigatewayv2_api.api.id
  authorizer_type                   = "REQUEST"
  authorizer_uri                    = module.api_key_authorizer.lambda_function_invoke_arn
  identity_sources                  = ["$request.header.x-api-key"]
  name                              = "${local.function_base_name}-api-key-authorizer"
  authorizer_payload_format_version = "2.0"
  authorizer_result_ttl_in_seconds  = 300
  enable_simple_responses           = true
}

# Lambda Integrations and Routes
resource "aws_apigatewayv2_integration" "lambda" {
  for_each = { for k, v in local.lambda_functions : k => v if length(v.routes) > 0 }

  api_id             = aws_apigatewayv2_api.api.id
  integration_type   = "AWS_PROXY"
  integration_method = "POST"
  integration_uri    = module.lambda_functions[each.key].lambda_function_invoke_arn

  payload_format_version = "2.0"
  timeout_milliseconds   = 30000
}

resource "aws_apigatewayv2_route" "lambda" {
  for_each = {
    for route in flatten([
      for func_key, func_config in local.lambda_functions : [
        for route in func_config.routes : {
          key      = "${route.method} ${route.path}"
          func_key = func_key
          method   = route.method
          path     = route.path
          auth     = route.auth
        }
      ]
    ]) : route.key => route
  }

  api_id    = aws_apigatewayv2_api.api.id
  route_key = each.value.key
  target    = "integrations/${aws_apigatewayv2_integration.lambda[each.value.func_key].id}"

  authorization_type = each.value.auth ? "CUSTOM" : "NONE"
  authorizer_id      = each.value.auth ? aws_apigatewayv2_authorizer.api_key.id : null
}