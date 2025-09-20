# EventBridge Custom Bus
resource "aws_cloudwatch_event_bus" "app_events" {
  name = "${local.function_base_name}-events"

  tags = local.common_tags
}

# Event rules for capturing CRUD operations
resource "aws_cloudwatch_event_rule" "crud_events" {
  name           = "${local.function_base_name}-crud-events"
  description    = "Capture all CRUD events for audit logging"
  event_bus_name = aws_cloudwatch_event_bus.app_events.name

  event_pattern = jsonencode({
    source = ["lambda.${local.function_base_name}"]
    detail-type = [
      "User Created", "User Updated", "User Deleted",
      "Post Created", "Post Updated", "Post Deleted"
    ]
  })

  tags = local.common_tags
}

# EventBridge target for audit processing
resource "aws_cloudwatch_event_target" "audit_target" {
  rule           = aws_cloudwatch_event_rule.crud_events.name
  event_bus_name = aws_cloudwatch_event_bus.app_events.name
  target_id      = "AuditProcessor"
  arn            = module.event_processor.lambda_function_arn
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = module.event_processor.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.crud_events.arn
}