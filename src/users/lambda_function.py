import json
import time
from datetime import datetime
from typing import Dict, Any, List

from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.logging import correlation_paths

# Initialize AWS Powertools
logger = Logger(service="users-service")
tracer = Tracer(service="users-service")
metrics = Metrics(namespace="LambdaTemplate/Users", service="users-service")


@tracer.capture_method
def get_users_from_database() -> List[Dict[str, str]]:
    """Simulate fetching users from database (DynamoDB)."""

    # Mock users data - in real implementation, you'd fetch from DynamoDB
    users: List[Dict[str, str]] = [
        {
            "id": "1",
            "name": "John Doe",
            "email": "john@example.com",
            "createdAt": "2024-01-15T10:30:00Z",
        },
        {
            "id": "2",
            "name": "Jane Smith",
            "email": "jane@example.com",
            "createdAt": "2024-01-16T14:45:00Z",
        },
        {
            "id": "3",
            "name": "Alice Johnson",
            "email": "alice@example.com",
            "createdAt": "2024-01-17T09:15:00Z",
        },
    ]

    # Simulate database latency
    time.sleep(0.05)

    logger.info("Users retrieved from database", extra={"user_count": len(users)})
    tracer.put_annotation("user_count", str(len(users)))

    return users


@tracer.capture_method
def process_users_request(event: Dict[str, Any]) -> Dict[str, Any]:
    """Process the users request with business logic."""

    # Add trace annotations and metadata
    tracer.put_annotation("path", event.get("path", "/users"))
    tracer.put_metadata("event", event)

    logger.info(
        "Processing users request",
        extra={
            "path": event.get("path"),
            "http_method": event.get("httpMethod"),
            "user_agent": event.get("headers", {}).get("User-Agent"),
        },
    )

    # Fetch users data
    users = get_users_from_database()

    response_data = {
        "users": users,
        "count": len(users),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "request_id": event.get("requestContext", {}).get("requestId", "unknown"),
    }

    logger.info(
        "Users request processed successfully",
        extra={"user_count": len(users), "request_id": response_data["request_id"]},
    )

    return response_data


@metrics.log_metrics(capture_cold_start_metric=True)
@tracer.capture_lambda_handler
@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Users Lambda function handler with AWS Powertools

    Args:
        event: Lambda event payload
        context: Lambda context object

    Returns:
        API Gateway response with users data
    """

    # Add correlation ID for tracing
    tracer.put_annotation("correlation_id", context.aws_request_id)

    try:
        logger.info(
            "Lambda invocation started",
            extra={
                "request_id": context.aws_request_id,
                "function_name": context.function_name,
                "function_version": context.function_version,
                "remaining_time_ms": context.get_remaining_time_in_millis(),
            },
        )

        # Add custom metrics
        metrics.add_metric(name="RequestCount", unit=MetricUnit.Count, value=1)

        # Process the request
        response_data = process_users_request(event)

        # Add business metrics
        metrics.add_metric(name="SuccessCount", unit=MetricUnit.Count, value=1)
        metrics.add_metric(
            name="UserCount", unit=MetricUnit.Count, value=response_data["count"]
        )

        response = {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": (
                    "Content-Type,X-Amz-Date,Authorization,X-Api-Key,"
                    "X-Amz-Security-Token"
                ),
                "Access-Control-Allow-Methods": "OPTIONS,POST,GET",
                "X-Request-ID": context.aws_request_id,
                "Cache-Control": "max-age=300",  # Cache for 5 minutes
            },
            "body": json.dumps(response_data, indent=2),
        }

        logger.info("Lambda invocation completed successfully")
        return response

    except Exception as e:
        logger.exception(
            "Lambda invocation failed",
            extra={"error": str(e), "request_id": context.aws_request_id},
        )

        # Add error metrics
        metrics.add_metric(name="ErrorCount", unit=MetricUnit.Count, value=1)

        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "X-Request-ID": context.aws_request_id,
            },
            "body": json.dumps(
                {
                    "message": "Internal server error",
                    "request_id": context.aws_request_id,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                }
            ),
        }
