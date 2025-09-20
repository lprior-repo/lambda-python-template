import json
import os
from datetime import datetime
from typing import Dict, Any

from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools.event_handler import APIGatewayRestResolver

# Initialize AWS Powertools
logger = Logger(service="hello-service")
tracer = Tracer(service="hello-service")
metrics = Metrics(namespace="LambdaTemplate/Hello", service="hello-service")

# Optional: API Gateway event handler (alternative to manual parsing)
app = APIGatewayRestResolver()


@tracer.capture_method
def get_app_version() -> str:
    """Get application version from SSM parameter or environment variable."""
    try:
        # Try to get from SSM parameter (optional)
        # return get_parameter("/lambda-template/version", max_age=300)
        return os.environ.get("APP_VERSION", "v1.0.0")
    except Exception as e:
        logger.warning("Could not retrieve version parameter", extra={"error": str(e)})
        return "v1.0.0"


@tracer.capture_method
def process_hello_request(event: Dict[str, Any]) -> Dict[str, Any]:
    """Process the hello request with business logic."""

    # Add trace annotations and metadata
    tracer.put_annotation("path", event.get("path", "/hello"))
    tracer.put_metadata("event", event)

    logger.info(
        "Processing hello request",
        extra={
            "path": event.get("path"),
            "http_method": event.get("httpMethod"),
            "user_agent": event.get("headers", {}).get("User-Agent"),
        },
    )

    app_version = get_app_version()

    response_data = {
        "message": "Hello from Python Lambda with Powertools!",
        "path": event.get("path", "/hello"),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "request_id": event.get("requestContext", {}).get("requestId", "unknown"),
        "version": app_version,
    }

    logger.info(
        "Hello request processed successfully", extra={"response": response_data}
    )
    return response_data


@metrics.log_metrics(capture_cold_start_metric=True)
@tracer.capture_lambda_handler
@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Hello Lambda function handler with AWS Powertools

    Args:
        event: Lambda event payload
        context: Lambda context object

    Returns:
        API Gateway response
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
        response_data = process_hello_request(event)

        # Add success metrics
        metrics.add_metric(name="SuccessCount", unit=MetricUnit.Count, value=1)

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


# Alternative: Using APIGatewayRestResolver for cleaner route handling
@app.get("/hello")
@tracer.capture_method
def hello_route():
    """Alternative route handler using Powertools event resolver."""
    metrics.add_metric(name="HelloRouteCount", unit=MetricUnit.Count, value=1)

    return {
        "message": "Hello from route handler!",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": get_app_version(),
    }


# Uncomment to use the route-based approach instead
# @metrics.log_metrics
# @tracer.capture_lambda_handler
# @logger.inject_lambda_context
# def lambda_handler(event, context):
#     return app.resolve(event, context)
