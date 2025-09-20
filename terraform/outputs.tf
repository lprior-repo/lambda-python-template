output "health_lambda_function_arn" {
  description = "ARN of the Health Lambda function"
  value       = module.health_lambda.lambda_function_arn
}

output "users_lambda_function_arn" {
  description = "ARN of the Users Lambda function"
  value       = module.users_lambda.lambda_function_arn
}

output "posts_lambda_function_arn" {
  description = "ARN of the Posts Lambda function"
  value       = module.posts_lambda.lambda_function_arn
}

output "event_processor_lambda_function_arn" {
  description = "ARN of the Event Processor Lambda function"
  value       = module.event_processor_lambda.lambda_function_arn
}

output "api_gateway_url" {
  description = "URL of the API Gateway"
  value       = module.api_gateway.api_endpoint
}

output "health_endpoint" {
  description = "Health endpoint URL"
  value       = "${module.api_gateway.api_endpoint}/health"
}

output "users_endpoint" {
  description = "Users endpoint URL"
  value       = "${module.api_gateway.api_endpoint}/users"
}

output "posts_endpoint" {
  description = "Posts endpoint URL"
  value       = "${module.api_gateway.api_endpoint}/posts"
}

output "users_table_name" {
  description = "Name of the Users DynamoDB table"
  value       = aws_dynamodb_table.users.name
}

output "posts_table_name" {
  description = "Name of the Posts DynamoDB table"
  value       = aws_dynamodb_table.posts.name
}

output "audit_logs_table_name" {
  description = "Name of the Audit Logs DynamoDB table"
  value       = aws_dynamodb_table.audit_logs.name
}

output "event_bus_name" {
  description = "Name of the custom EventBridge bus"
  value       = aws_cloudwatch_event_bus.app_events.name
}