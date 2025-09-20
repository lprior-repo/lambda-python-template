"""
Orders Handler - Lambda function for order management API.

This module implements the handler layer for order operations,
following the three-layer architecture pattern from the aws-lambda-handler-cookbook
with comprehensive error handling, validation, and observability.
"""

import json
import os
from typing import Any, Dict, Optional

from aws_lambda_powertools import Logger, Metrics, Tracer
from aws_lambda_powertools.event_handler import APIGatewayRestResolver, CORSConfig
from aws_lambda_powertools.event_handler.exceptions import (
    BadRequestError,
    InternalServerError,
    NotFoundError,
    UnauthorizedError,
)
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.utilities.validation import envelopes, validator
from pydantic import ValidationError

from service.dal.dynamodb_handler import DynamoDBHandler
from service.handlers.utils.dynamic_configuration import (
    get_configuration_value,
    is_maintenance_mode,
    parse_configuration,
)
from service.handlers.utils.idempotency import (
    BaseServiceError,
    BusinessLogicError,
    ErrorCategory,
    ErrorSeverity,
    ResourceNotFoundError,
    ValidationError as ServiceValidationError,
    create_api_response,
    create_error_context,
    format_error_response,
    get_http_status_code,
    get_idempotency_manager,
    handle_idempotency_errors,
    log_error_metrics,
)
from service.handlers.utils.observability import logger, metrics, tracer
from service.logic.order_service import OrderNotFoundError, OrderService, OrderStateError, OrderValidationError
from service.models.input import CreateOrderRequest, UpdateOrderRequest
from service.models.order import OrderStatus
from service.models.output import (
    CreateOrderResponse,
    ErrorResponse,
    GetOrderResponse,
    HealthCheckResponse,
    UpdateOrderResponse,
)

# Configure CORS
cors_config = CORSConfig(
    allow_origin="*",
    max_age=600,
    expose_headers=["x-custom-header"],
    allow_headers=["content-type", "x-custom-header", "authorization"],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)

# Initialize API Gateway resolver
app = APIGatewayRestResolver(cors=cors_config, enable_validation=True)

# Initialize service dependencies
orders_table_name = os.environ.get('ORDERS_TABLE_NAME', 'orders-table')
orders_dal = DynamoDBHandler(
    table_name=orders_table_name,
    endpoint_url=os.environ.get('DYNAMODB_ENDPOINT'),  # For local testing
)
order_service = OrderService(orders_table_handler=orders_dal)

# Initialize idempotency manager
idempotency_manager = get_idempotency_manager()


def handle_service_errors(func):
    """Decorator to handle service errors and convert to HTTP responses."""

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except BaseServiceError as e:
            # Log error metrics
            log_error_metrics(e)

            # Get appropriate HTTP status code
            status_code = get_http_status_code(e)

            # Format error response
            error_response = format_error_response(
                error=e,
                include_details=get_configuration_value('debug_mode', default_value=False),
            )

            # Return structured error response
            return create_api_response(
                status_code=status_code,
                body=json.dumps(error_response),
                headers={"Retry-After": str(e.retry_after)} if e.retry_after else None,
            )

        except ValidationError as e:
            # Handle Pydantic validation errors
            logger.error("Request validation failed", extra={
                "validation_errors": str(e),
                "error_count": e.error_count(),
            })

            metrics.add_metric(name="ValidationError", unit=MetricUnit.Count, value=1)

            field_errors = [
                {"field": error["loc"][-1], "message": error["msg"]}
                for error in e.errors()
            ]

            validation_error = ServiceValidationError(
                message="Request validation failed",
                field_errors=field_errors,
            )

            error_response = format_error_response(validation_error)

            return create_api_response(
                status_code=400,
                body=json.dumps(error_response),
            )

        except Exception as e:
            # Handle unexpected errors
            logger.exception("Unexpected error in handler", extra={
                "error": str(e),
                "function_name": func.__name__,
            })

            metrics.add_metric(name="UnexpectedError", unit=MetricUnit.Count, value=1)

            unexpected_error = BaseServiceError(
                message="An unexpected error occurred",
                error_code="INTERNAL_SERVER_ERROR",
                severity=ErrorSeverity.CRITICAL,
                category=ErrorCategory.INFRASTRUCTURE,
            )

            error_response = format_error_response(unexpected_error)

            return create_api_response(
                status_code=500,
                body=json.dumps(error_response),
            )

    return wrapper


@app.middleware_stack.before
def check_maintenance_mode():
    """Check if the application is in maintenance mode."""
    if is_maintenance_mode():
        logger.warning("Request rejected - application in maintenance mode")
        metrics.add_metric(name="MaintenanceModeRequest", unit=MetricUnit.Count, value=1)

        maintenance_error = BaseServiceError(
            message="Application is temporarily unavailable for maintenance",
            error_code="MAINTENANCE_MODE",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.INFRASTRUCTURE,
            retry_after=300,
            user_message="The service is temporarily unavailable for maintenance. Please try again in a few minutes.",
        )

        error_response = format_error_response(maintenance_error)

        return create_api_response(
            status_code=503,
            body=json.dumps(error_response),
            headers={"Retry-After": "300"},
        )


@app.middleware_stack.after
def add_security_headers(response: Dict[str, Any]) -> Dict[str, Any]:
    """Add security headers to all responses."""
    if 'headers' not in response:
        response['headers'] = {}

    response['headers'].update({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
    })

    return response


@app.get("/health")
@tracer.capture_method
@handle_service_errors
def health_check() -> Dict[str, Any]:
    """
    Health check endpoint.

    Returns:
        Health status information
    """
    logger.info("Health check requested")

    # Get request context
    request_context = app.current_event.request_context
    request_id = request_context.request_id if request_context else "unknown"

    context = create_error_context(
        request_id=request_id,
        operation="health_check",
    )

    # Perform health checks
    health_status = {
        "status": "healthy",
        "timestamp": "",
        "version": os.environ.get("SERVICE_VERSION", "unknown"),
        "environment": os.environ.get("ENVIRONMENT", "unknown"),
        "checks": {}
    }

    try:
        # Check DynamoDB connectivity
        db_health = orders_dal.health_check()
        health_status["checks"]["database"] = db_health

        # Overall status based on component health
        if db_health.get("status") != "healthy":
            health_status["status"] = "unhealthy"

        health_status["timestamp"] = db_health.get("timestamp", "")

    except Exception as e:
        logger.error("Health check failed", extra={"error": str(e)})
        health_status.update({
            "status": "unhealthy",
            "checks": {"database": {"status": "unhealthy", "error": str(e)}}
        })

    # Add metrics
    if health_status["status"] == "healthy":
        metrics.add_metric(name="HealthCheckSuccess", unit=MetricUnit.Count, value=1)
    else:
        metrics.add_metric(name="HealthCheckFailure", unit=MetricUnit.Count, value=1)

    response = HealthCheckResponse(**health_status)

    return create_api_response(
        status_code=200 if health_status["status"] == "healthy" else 503,
        body=response.model_dump_json(),
    )


@app.post("/orders")
@tracer.capture_method
@handle_service_errors
@handle_idempotency_errors
@idempotency_manager.make_handler_idempotent
def create_order() -> Dict[str, Any]:
    """
    Create a new order.

    Returns:
        Created order information
    """
    logger.info("Create order request received")

    # Get request context
    request_context = app.current_event.request_context
    request_id = request_context.request_id if request_context else "unknown"

    context = create_error_context(
        request_id=request_id,
        operation="create_order",
    )

    # Parse and validate request
    try:
        request_body = json.loads(app.current_event.body or "{}")
        create_request = CreateOrderRequest.model_validate(request_body)
    except json.JSONDecodeError as e:
        raise ServiceValidationError(
            message="Invalid JSON in request body",
            context=context,
        )
    except ValidationError as e:
        # Re-raise to be handled by decorator
        raise e

    # Add trace annotations
    tracer.put_annotation("customer_email", create_request.customer_email)
    tracer.put_annotation("order_item_count", create_request.order_item_count)

    # Create order through service layer
    response = order_service.create_order(
        request=create_request,
        context=context,
    )

    logger.info("Order created successfully", extra={
        "order_id": response.order_id,
        "customer_email": create_request.customer_email,
    })

    return create_api_response(
        status_code=201,
        body=response.model_dump_json(),
        headers={"Location": f"/orders/{response.order_id}"},
    )


@app.get("/orders/<order_id>")
@tracer.capture_method
@handle_service_errors
def get_order(order_id: str) -> Dict[str, Any]:
    """
    Get an order by ID.

    Args:
        order_id: Order identifier

    Returns:
        Order information
    """
    logger.info("Get order request received", extra={"order_id": order_id})

    # Get request context
    request_context = app.current_event.request_context
    request_id = request_context.request_id if request_context else "unknown"

    context = create_error_context(
        request_id=request_id,
        operation="get_order",
        resource_id=order_id,
    )

    # Add trace annotations
    tracer.put_annotation("order_id", order_id)

    # Get order through service layer
    response = order_service.get_order(
        order_id=order_id,
        context=context,
    )

    logger.info("Order retrieved successfully", extra={
        "order_id": order_id,
        "status": response.order.status.value,
    })

    return create_api_response(
        status_code=200,
        body=response.model_dump_json(),
    )


@app.put("/orders/<order_id>")
@tracer.capture_method
@handle_service_errors
@handle_idempotency_errors
@idempotency_manager.make_handler_idempotent
def update_order(order_id: str) -> Dict[str, Any]:
    """
    Update an existing order.

    Args:
        order_id: Order identifier

    Returns:
        Updated order information
    """
    logger.info("Update order request received", extra={"order_id": order_id})

    # Get request context
    request_context = app.current_event.request_context
    request_id = request_context.request_id if request_context else "unknown"

    context = create_error_context(
        request_id=request_id,
        operation="update_order",
        resource_id=order_id,
    )

    # Parse and validate request
    try:
        request_body = json.loads(app.current_event.body or "{}")
        update_request = UpdateOrderRequest.model_validate(request_body)
    except json.JSONDecodeError as e:
        raise ServiceValidationError(
            message="Invalid JSON in request body",
            context=context,
        )
    except ValidationError as e:
        # Re-raise to be handled by decorator
        raise e

    # Add trace annotations
    tracer.put_annotation("order_id", order_id)
    if update_request.order_item_count is not None:
        tracer.put_annotation("new_item_count", update_request.order_item_count)

    # Update order through service layer
    response = order_service.update_order(
        order_id=order_id,
        request=update_request,
        context=context,
    )

    logger.info("Order updated successfully", extra={
        "order_id": order_id,
        "new_item_count": response.order.order_item_count,
    })

    return create_api_response(
        status_code=200,
        body=response.model_dump_json(),
    )


@app.delete("/orders/<order_id>")
@tracer.capture_method
@handle_service_errors
def cancel_order(order_id: str) -> Dict[str, Any]:
    """
    Cancel an order.

    Args:
        order_id: Order identifier

    Returns:
        Cancelled order information
    """
    logger.info("Cancel order request received", extra={"order_id": order_id})

    # Get request context
    request_context = app.current_event.request_context
    request_id = request_context.request_id if request_context else "unknown"

    context = create_error_context(
        request_id=request_id,
        operation="cancel_order",
        resource_id=order_id,
    )

    # Get cancellation reason from query parameters
    query_params = app.current_event.query_string_parameters or {}
    reason = query_params.get('reason', 'Customer requested cancellation')

    # Add trace annotations
    tracer.put_annotation("order_id", order_id)
    tracer.put_annotation("cancellation_reason", reason)

    # Cancel order through service layer
    response = order_service.cancel_order(
        order_id=order_id,
        reason=reason,
        context=context,
    )

    logger.info("Order cancelled successfully", extra={
        "order_id": order_id,
        "reason": reason,
    })

    return create_api_response(
        status_code=200,
        body=response.model_dump_json(),
    )


@app.get("/orders")
@tracer.capture_method
@handle_service_errors
def list_orders() -> Dict[str, Any]:
    """
    List orders with optional filtering.

    Returns:
        List of orders with pagination
    """
    logger.info("List orders request received")

    # Get request context
    request_context = app.current_event.request_context
    request_id = request_context.request_id if request_context else "unknown"

    context = create_error_context(
        request_id=request_id,
        operation="list_orders",
    )

    # Parse query parameters
    query_params = app.current_event.query_string_parameters or {}

    customer_email = query_params.get('customer_email')
    status_str = query_params.get('status')
    limit = int(query_params.get('limit', '50'))
    last_evaluated_key_str = query_params.get('last_evaluated_key')

    # Validate and parse parameters
    status = None
    if status_str:
        try:
            status = OrderStatus(status_str.upper())
        except ValueError:
            raise ServiceValidationError(
                message=f"Invalid status value: {status_str}",
                context=context,
            )

    last_evaluated_key = None
    if last_evaluated_key_str:
        try:
            last_evaluated_key = json.loads(last_evaluated_key_str)
        except json.JSONDecodeError:
            raise ServiceValidationError(
                message="Invalid last_evaluated_key format",
                context=context,
            )

    # Validate limit
    if limit > 100:
        limit = 100
    elif limit < 1:
        limit = 1

    # Add trace annotations
    tracer.put_annotation("customer_email", customer_email or "all")
    tracer.put_annotation("status_filter", status.value if status else "all")
    tracer.put_annotation("limit", limit)

    # List orders through service layer
    response = order_service.list_orders(
        customer_email=customer_email,
        status=status,
        limit=limit,
        last_evaluated_key=last_evaluated_key,
        context=context,
    )

    # Convert orders to serializable format
    serializable_response = {
        "orders": [order.model_dump() for order in response["orders"]],
        "count": response["count"],
        "scanned_count": response.get("scanned_count", 0),
    }

    if "last_evaluated_key" in response:
        serializable_response["last_evaluated_key"] = response["last_evaluated_key"]

    logger.info("Orders listed successfully", extra={
        "orders_count": response["count"],
        "customer_email_filter": customer_email,
        "status_filter": status.value if status else None,
    })

    return create_api_response(
        status_code=200,
        body=json.dumps(serializable_response),
    )


@app.get("/orders/statistics")
@tracer.capture_method
@handle_service_errors
def get_order_statistics() -> Dict[str, Any]:
    """
    Get order statistics for monitoring and reporting.

    Returns:
        Order statistics
    """
    logger.info("Order statistics request received")

    # Get request context
    request_context = app.current_event.request_context
    request_id = request_context.request_id if request_context else "unknown"

    context = create_error_context(
        request_id=request_id,
        operation="get_order_statistics",
    )

    # Get statistics through service layer
    statistics = order_service.get_order_statistics(context=context)

    logger.info("Order statistics generated successfully", extra={
        "total_orders": statistics["total_orders"],
        "total_revenue": statistics["total_revenue"],
    })

    return create_api_response(
        status_code=200,
        body=json.dumps(statistics),
    )


@tracer.capture_lambda_handler
@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
@metrics.log_metrics(capture_cold_start_metric=True)
def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """
    Main Lambda handler function.

    Args:
        event: Lambda event payload
        context: Lambda context object

    Returns:
        API Gateway response
    """
    try:
        # Add global metrics
        metrics.add_metric(name="RequestCount", unit=MetricUnit.Count, value=1)

        # Add trace annotations
        tracer.put_annotation("service", "orders-api")
        tracer.put_annotation("environment", os.environ.get("ENVIRONMENT", "unknown"))

        # Process request through API Gateway resolver
        response = app.resolve(event, context)

        # Add success metrics
        metrics.add_metric(name="RequestSuccess", unit=MetricUnit.Count, value=1)

        return response

    except Exception as e:
        # Add error metrics
        metrics.add_metric(name="RequestError", unit=MetricUnit.Count, value=1)

        logger.exception("Unhandled error in lambda handler", extra={
            "error": str(e),
            "event": event,
        })

        # Return generic error response
        error_response = {
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "error_id": context.aws_request_id,
            }
        }

        return create_api_response(
            status_code=500,
            body=json.dumps(error_response),
        )
