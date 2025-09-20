# DynamoDB Tables
resource "aws_dynamodb_table" "users" {
  name         = "${local.function_base_name}-users"
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

  tags = local.common_tags
}

resource "aws_dynamodb_table" "posts" {
  name         = "${local.function_base_name}-posts"
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

  tags = local.common_tags
}

resource "aws_dynamodb_table" "audit_logs" {
  name         = "${local.function_base_name}-audit-logs"
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

  tags = local.common_tags
}