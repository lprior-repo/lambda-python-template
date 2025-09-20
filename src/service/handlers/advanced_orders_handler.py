"""
Advanced Orders Handler - Enhanced Lambda function demonstrating modern serverless patterns.

This module implements an advanced order management handler showcasing:
- Event sourcing with event store
- CQRS patterns with read model projections
- JWT/API key authentication
- Rate limiting with multiple algorithms
- Advanced security patterns
- Comprehensive error handling and observability

This serves as a comprehensive example of enterprise serverless patterns.
"""

import json
import os
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

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

# Import new patterns
from service.events import (
    EventPublisher,
    EventStore,
    EventStreamProcessor,
    OrderCreatedEvent,
    OrderUpdatedEvent,
    OrderCancelledEvent,
    EventType,
    EventSource,
    BaseEvent,
    OrderSummaryProjection,
    UserActivityProjection,
)

from service.security import (
    JWTAuthenticator,
    APIKeyAuthenticator,
    DynamoDBRateLimiter,
    RateLimitConfig,
    RateLimitAlgorithm,
    SecurityValidator,
    add_security_headers,
    extract_token_from_event,
    create_rate_limit_key,
)

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
    get_idempotency_manager,
)
from service.handlers.utils.observability import logger, metrics, tracer
from service.logic.order_service import OrderService
from service.models.input import CreateOrderRequest, UpdateOrderRequest
from service.models.output import (
    CreateOrderResponse,
    GetOrderResponse,
    UpdateOrderResponse,
    ErrorResponse,
)

# Configure CORS with enhanced security
cors_config = CORSConfig(
    allow_origin=os.environ.get('CORS_ALLOWED_ORIGINS', '*'),
    max_age=600,
    expose_headers=["x-custom-header", "x-ratelimit-limit", "x-ratelimit-remaining"],
    allow_headers=["content-type", "authorization", "x-api-key"],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)

# Initialize API Gateway resolver
app = APIGatewayRestResolver(cors=cors_config, enable_validation=True)

# Initialize event sourcing components
event_publisher = EventPublisher(
    event_bus_name=os.environ.get('EVENT_BUS_NAME', 'default'),
    dlq_table_name=os.environ.get('EVENT_DLQ_TABLE_NAME')
)

event_store = EventStore(
    table_name=os.environ.get('EVENT_STORE_TABLE_NAME', 'event-store'),
    snapshot_table_name=os.environ.get('EVENT_SNAPSHOTS_TABLE_NAME', 'event-snapshots')
)

# Initialize projections for CQRS
order_projection = OrderSummaryProjection(
    table_name=os.environ.get('ORDER_SUMMARIES_TABLE_NAME', 'order-summaries')
)

user_activity_projection = UserActivityProjection(
    table_name=os.environ.get('USER_ACTIVITY_TABLE_NAME', 'user-activity')
)

# Initialize security components
jwt_authenticator = JWTAuthenticator(
    jwks_url=os.environ.get('JWT_JWKS_URL'),
    issuer=os.environ.get('JWT_ISSUER'),
    audience=os.environ.get('JWT_AUDIENCE'),
    algorithm='RS256'
)

api_key_authenticator = APIKeyAuthenticator(
    dynamodb_table=os.environ.get('API_KEYS_TABLE_NAME'),
    cache_results=True,
    cache_ttl=300
)

# Initialize rate limiter
rate_limiter = DynamoDBRateLimiter(
    table_name=os.environ.get('RATE_LIMITS_TABLE_NAME', 'rate-limits')
)

# Rate limit configurations for different user types
RATE_LIMIT_CONFIGS = {
    'premium': RateLimitConfig(
        requests_per_window=1000,
        window_size_seconds=3600,
        algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
        burst_size=1500
    ),
    'standard': RateLimitConfig(
        requests_per_window=100,
        window_size_seconds=3600,
        algorithm=RateLimitAlgorithm.SLIDING_WINDOW
    ),
    'basic': RateLimitConfig(
        requests_per_window=10,
        window_size_seconds=3600,
        algorithm=RateLimitAlgorithm.FIXED_WINDOW
    )
}

# Security validator
security_validator = SecurityValidator()

# Initialize order service
order_service = OrderService()
idempotency_manager = get_idempotency_manager()


def authenticate_request(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Authenticate incoming request using JWT or API key."""
    try:
        token = extract_token_from_event(event)

        if not token:
            return None

        # Try JWT authentication first
        if token.startswith('eyJ'):  # JWT tokens typically start with this
            auth_result = jwt_authenticator.authenticate(token)
            if auth_result.authenticated:
                return {
                    'user_claims': auth_result.user_claims,
                    'auth_type': 'jwt'
                }

        # Try API key authentication
        auth_result = api_key_authenticator.authenticate(token)
        if auth_result.authenticated:
            return {
                'user_claims': auth_result.user_claims,
                'auth_type': 'api_key'
            }

        return None

    except Exception as e:
        logger.error(f"Authentication failed: {str(e)}")
        return None


def check_rate_limit(event: Dict[str, Any], user_tier: str = 'basic') -> bool:
    """Check rate limit for the request."""
    try:
        # Create rate limit key from multiple identifiers
        rate_limit_key = create_rate_limit_key(
            user_id=event.get('user_claims', {}).get('user_id'),
            ip_address=event.get('requestContext', {}).get('identity', {}).get('sourceIp'),
            endpoint=event.get('path')
        )

        # Get rate limit config for user tier
        config = RATE_LIMIT_CONFIGS.get(user_tier, RATE_LIMIT_CONFIGS['basic'])

        # Check rate limit
        result = rate_limiter.check_rate_limit(rate_limit_key, config)

        # Add rate limit headers to response (will be added by middleware)
        event['rate_limit_headers'] = result.to_headers()

        return result.allowed

    except Exception as e:
        logger.error(f"Rate limit check failed: {str(e)}")
        # Fail open - allow request if rate limiter fails
        return True


def validate_input_security(data: Dict[str, Any]) -> None:
    """Validate input for security issues."""
    try:
        security_validator.validate_input(data)
    except Exception as e:
        logger.warning(f"Security validation warning: {str(e)}")
        metrics.add_metric(name="SecurityValidationWarning", unit=MetricUnit.Count, value=1)


@app.middleware_stack.before
def security_middleware():
    """Comprehensive security middleware."""
    event = app.current_event.raw_event

    # 1. Authentication
    auth_info = authenticate_request(event)
    if not auth_info:
        logger.warning("Unauthenticated request", extra={'path': event.get('path')})
        metrics.add_metric(name="UnauthenticatedRequest", unit=MetricUnit.Count, value=1)
        raise UnauthorizedError("Authentication required")

    # Store auth info for handlers
    event['auth_info'] = auth_info
    user_tier = auth_info['user_claims'].roles[0] if auth_info['user_claims'].roles else 'basic'

    # 2. Rate limiting
    if not check_rate_limit(event, user_tier):
        logger.warning("Rate limit exceeded", extra={
            'user_id': auth_info['user_claims'].user_id,
            'tier': user_tier
        })
        metrics.add_metric(name="RateLimitExceeded", unit=MetricUnit.Count, value=1)

        from aws_lambda_powertools.event_handler.exceptions import TooManyRequestsError
        raise TooManyRequestsError("Rate limit exceeded")

    # 3. Input validation security
    if event.get('body'):
        try:
            body_data = json.loads(event['body'])
            validate_input_security(body_data)
        except json.JSONDecodeError:
            pass  # Will be handled by request validation

    # 4. Maintenance mode check
    if is_maintenance_mode():
        logger.warning("Request rejected - maintenance mode")
        metrics.add_metric(name="MaintenanceModeRequest", unit=MetricUnit.Count, value=1)
        raise InternalServerError("Service temporarily unavailable")


@app.middleware_stack.after
def security_headers_middleware(response: Dict[str, Any]) -> Dict[str, Any]:
    """Add security headers and rate limit headers."""
    response = add_security_headers(response)

    # Add rate limit headers if available
    event = app.current_event.raw_event
    if 'rate_limit_headers' in event:
        if 'headers' not in response:
            response['headers'] = {}
        response['headers'].update(event['rate_limit_headers'])

    return response


@app.post("/orders")
@tracer.capture_method
@handle_idempotency_errors
def create_order(request: CreateOrderRequest) -> CreateOrderResponse:
    """
    Create a new order using event sourcing patterns.

    This endpoint demonstrates:
    - Event sourcing with event store
    - Command validation and processing
    - Event publishing for downstream services
    - Idempotency handling
    """
    logger.info("Creating new order", extra={"request": request.dict()})

    # Get user info from middleware
    auth_info = app.current_event.raw_event.get('auth_info', {})
    user_claims = auth_info.get('user_claims')

    try:
        # Validate business rules
        if request.total_amount <= 0:
            raise BadRequestError("Order total must be positive")

        if not request.items:
            raise BadRequestError("Order must contain at least one item")

        # Use idempotency for reliable processing
        with idempotency_manager:
            # Generate order ID
            order_id = f"order-{datetime.utcnow().strftime('%Y%m%d')}-{request.user_id}-{hash(str(request.dict())) % 10000:04d}"

            # Create order created event
            order_created_event = OrderCreatedEvent.create(
                order_data={
                    'order_id': order_id,
                    'user_id': request.user_id,
                    'status': 'created',
                    'total_amount': request.total_amount,
                    'currency': request.currency,
                    'items': [item.dict() for item in request.items],
                    'shipping_address': request.shipping_address.dict() if request.shipping_address else None,
                    'created_by': user_claims.user_id if user_claims else 'system'
                }
            )

            # Store event in event store
            stream_id = f"order-{order_id}"
            event_records = event_store.append_events(
                stream_id=stream_id,
                events=[order_created_event]
            )

            # Update read model projections
            for record in event_records:
                order_projection.handle_event(record)
                user_activity_projection.handle_event(record)

            # Publish event for downstream services
            event_publisher.publish_event(order_created_event)

            # Create additional events for business processes
            downstream_events = []

            # Inventory reservation event
            inventory_event = BaseEvent(
                source=EventSource.INVENTORY,
                event_type=EventType.INVENTORY_UPDATED,
                data={
                    'order_id': order_id,
                    'action': 'reserve',
                    'items': [{'product_id': item.product_id, 'quantity': item.quantity} for item in request.items]
                }
            )
            downstream_events.append(inventory_event)

            # Payment processing event
            payment_event = BaseEvent(
                source=EventSource.PAYMENTS,
                event_type=EventType.PAYMENT_INITIATED,
                data={
                    'order_id': order_id,
                    'amount': request.total_amount,
                    'currency': request.currency,
                    'user_id': request.user_id,
                    'payment_method': request.payment_method
                }
            )
            downstream_events.append(payment_event)

            # Publish downstream events
            event_publisher.publish_events(downstream_events)

            # Record metrics
            metrics.add_metric(name="OrderCreated", unit=MetricUnit.Count, value=1)
            metrics.add_metric(name="OrderValue", unit=MetricUnit.Count, value=request.total_amount)

            logger.info("Order created successfully", extra={
                "order_id": order_id,
                "stream_id": stream_id,
                "events_published": len(downstream_events) + 1
            })

            return CreateOrderResponse(
                order_id=order_id,
                status='created',
                total_amount=request.total_amount,
                currency=request.currency,
                estimated_delivery=datetime.utcnow() + timedelta(days=3),
                tracking_number=f"TRK-{order_id[-8:]}"
            )

    except Exception as e:
        logger.error(f"Failed to create order: {str(e)}")
        metrics.add_metric(name="OrderCreationError", unit=MetricUnit.Count, value=1)
        raise


@app.get("/orders/<order_id>")
@tracer.capture_method
def get_order(order_id: str) -> GetOrderResponse:
    """
    Get order details from read model projection.

    This demonstrates CQRS query patterns using projections
    instead of rebuilding from events for performance.
    """
    logger.info("Retrieving order", extra={"order_id": order_id})

    try:
        # Get order from read model projection
        order_summary = order_projection.get_state(order_id)

        if not order_summary:
            logger.warning("Order not found in projection", extra={"order_id": order_id})

            # Fallback: rebuild from event store
            stream_id = f"order-{order_id}"
            events = event_store.get_events(stream_id)

            if not events:
                raise NotFoundError(f"Order {order_id} not found")

            # Rebuild order state from events
            order_state = {}
            for event_record in events:
                if event_record.event_type == "OrderCreated":
                    order_state.update(event_record.event_data)
                elif event_record.event_type == "OrderUpdated":
                    order_state.update(event_record.event_data)
                elif event_record.event_type == "OrderCancelled":
                    order_state["status"] = "cancelled"
                    order_state["cancelled_at"] = event_record.timestamp.isoformat()

            order_summary = order_state

        # Record metrics
        metrics.add_metric(name="OrderRetrieved", unit=MetricUnit.Count, value=1)

        return GetOrderResponse(
            order_id=order_summary['order_id'],
            user_id=order_summary['user_id'],
            status=order_summary['status'],
            total_amount=order_summary['total_amount'],
            currency=order_summary.get('currency', 'USD'),
            created_at=order_summary.get('created_at'),
            updated_at=order_summary.get('updated_at')
        )

    except Exception as e:
        logger.error(f"Failed to retrieve order: {str(e)}")
        metrics.add_metric(name="OrderRetrievalError", unit=MetricUnit.Count, value=1)
        raise


@app.put("/orders/<order_id>")
@tracer.capture_method
@handle_idempotency_errors
def update_order(order_id: str, request: UpdateOrderRequest) -> UpdateOrderResponse:
    """
    Update order using event sourcing with optimistic concurrency control.
    """
    logger.info("Updating order", extra={"order_id": order_id, "updates": request.dict()})

    # Get user info from middleware
    auth_info = app.current_event.raw_event.get('auth_info', {})
    user_claims = auth_info.get('user_claims')

    try:
        stream_id = f"order-{order_id}"

        # Get current stream version for optimistic concurrency
        stream_info = event_store.get_stream_info(stream_id)
        if not stream_info:
            raise NotFoundError(f"Order {order_id} not found")

        expected_version = stream_info.version

        # Create order updated event
        update_data = request.dict(exclude_unset=True)
        update_data['order_id'] = order_id
        update_data['updated_by'] = user_claims.user_id if user_claims else 'system'
        update_data['updated_at'] = datetime.utcnow().isoformat()

        order_updated_event = OrderUpdatedEvent.create(
            order_data=update_data
        )

        # Store event with version check (optimistic concurrency)
        with idempotency_manager:
            event_records = event_store.append_events(
                stream_id=stream_id,
                events=[order_updated_event],
                expected_version=expected_version
            )

            # Update projections
            for record in event_records:
                order_projection.handle_event(record)
                user_activity_projection.handle_event(record)

            # Publish event
            event_publisher.publish_event(order_updated_event)

            # Handle status transitions
            if request.status and request.status == 'completed':
                completion_event = BaseEvent(
                    source=EventSource.ORDERS,
                    event_type=EventType.ORDER_COMPLETED,
                    data={
                        'order_id': order_id,
                        'completed_at': datetime.utcnow().isoformat()
                    }
                )
                event_publisher.publish_event(completion_event)

            metrics.add_metric(name="OrderUpdated", unit=MetricUnit.Count, value=1)

            logger.info("Order updated successfully", extra={
                "order_id": order_id,
                "new_version": expected_version + 1
            })

            return UpdateOrderResponse(
                order_id=order_id,
                status=request.status or 'updated',
                updated_at=datetime.utcnow(),
                version=expected_version + 1
            )

    except Exception as e:
        logger.error(f"Failed to update order: {str(e)}")
        metrics.add_metric(name="OrderUpdateError", unit=MetricUnit.Count, value=1)
        raise


@app.delete("/orders/<order_id>")
@tracer.capture_method
@handle_idempotency_errors
def cancel_order(order_id: str) -> Dict[str, Any]:
    """
    Cancel order using saga pattern for distributed transaction coordination.
    """
    logger.info("Cancelling order", extra={"order_id": order_id})

    # Get user info from middleware
    auth_info = app.current_event.raw_event.get('auth_info', {})
    user_claims = auth_info.get('user_claims')

    try:
        stream_id = f"order-{order_id}"

        # Verify order exists and get current state
        order_summary = order_projection.get_state(order_id)
        if not order_summary:
            raise NotFoundError(f"Order {order_id} not found")

        if order_summary.get('status') in ['cancelled', 'completed']:
            raise BadRequestError(f"Cannot cancel order in {order_summary['status']} status")

        # Create cancellation event
        cancellation_data = {
            'order_id': order_id,
            'reason': 'user_requested',
            'cancelled_by': user_claims.user_id if user_claims else 'system',
            'cancelled_at': datetime.utcnow().isoformat(),
            'original_status': order_summary.get('status'),
            'total_amount': order_summary.get('total_amount'),
            'user_id': order_summary.get('user_id'),
            'items': order_summary.get('items', [])
        }

        # Check if payment was processed
        user_activity = user_activity_projection.get_state(order_summary['user_id'])
        cancellation_data['payment_status'] = 'processed' if user_activity else 'pending'

        order_cancelled_event = OrderCancelledEvent.create(
            order_id=order_id,
            reason='user_requested',
            metadata={'cancelled_by': user_claims.user_id if user_claims else 'system'}
        )
        order_cancelled_event.data = cancellation_data

        with idempotency_manager:
            # Store cancellation event
            event_records = event_store.append_events(
                stream_id=stream_id,
                events=[order_cancelled_event]
            )

            # Update projections
            for record in event_records:
                order_projection.handle_event(record)
                user_activity_projection.handle_event(record)

            # Publish cancellation event
            event_publisher.publish_event(order_cancelled_event)

            metrics.add_metric(name="OrderCancelled", unit=MetricUnit.Count, value=1)

            logger.info("Order cancelled successfully", extra={
                "order_id": order_id,
                "compensation_required": cancellation_data['payment_status'] == 'processed'
            })

            return {
                "order_id": order_id,
                "status": "cancelled",
                "cancelled_at": cancellation_data['cancelled_at'],
                "message": "Order cancelled successfully"
            }

    except Exception as e:
        logger.error(f"Failed to cancel order: {str(e)}")
        metrics.add_metric(name="OrderCancellationError", unit=MetricUnit.Count, value=1)
        raise


@app.get("/orders/user/<user_id>")
@tracer.capture_method
def get_user_orders(user_id: str) -> Dict[str, Any]:
    """Get orders for a specific user from read model."""
    logger.info("Retrieving user orders", extra={"user_id": user_id})

    try:
        # Get user activity from projection (includes order count, etc.)
        user_activity = user_activity_projection.get_state(user_id)

        # This is a simplified example - in practice, you'd have a dedicated
        # orders-by-user projection or GSI
        orders = []  # Would query order projection with user_id GSI

        metrics.add_metric(name="UserOrdersRetrieved", unit=MetricUnit.Count, value=1)

        return {
            "user_id": user_id,
            "orders": orders,
            "total_orders": user_activity.get('total_orders', 0) if user_activity else 0,
            "total_spent": user_activity.get('total_spent', 0.0) if user_activity else 0.0,
            "last_activity": user_activity.get('last_activity') if user_activity else None
        }

    except Exception as e:
        logger.error(f"Failed to retrieve user orders: {str(e)}")
        metrics.add_metric(name="UserOrdersRetrievalError", unit=MetricUnit.Count, value=1)
        raise


@app.post("/orders/<order_id>/replay")
@tracer.capture_method
def replay_order_events(order_id: str) -> Dict[str, Any]:
    """
    Replay events for an order stream (admin function).
    Useful for rebuilding projections or debugging.
    """
    logger.info("Replaying order events", extra={"order_id": order_id})

    # Check admin permissions
    auth_info = app.current_event.raw_event.get('auth_info', {})
    user_claims = auth_info.get('user_claims')

    if not user_claims or 'admin' not in user_claims.roles:
        raise UnauthorizedError("Admin access required")

    try:
        stream_id = f"order-{order_id}"

        # Initialize stream processor for single stream
        stream_processor = EventStreamProcessor(
            event_store=event_store,
            projections=[order_projection, user_activity_projection]
        )

        # Replay events
        events_processed = stream_processor.process_stream(stream_id, from_version=0)

        metrics.add_metric(name="OrderEventsReplayed", unit=MetricUnit.Count, value=events_processed)

        logger.info("Order events replayed successfully", extra={
            "order_id": order_id,
            "events_processed": events_processed
        })

        return {
            "order_id": order_id,
            "stream_id": stream_id,
            "events_processed": events_processed,
            "status": "completed"
        }

    except Exception as e:
        logger.error(f"Failed to replay order events: {str(e)}")
        metrics.add_metric(name="OrderReplayError", unit=MetricUnit.Count, value=1)
        raise


@tracer.capture_lambda_handler
@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST, log_event=True)
@metrics.log_metrics(capture_cold_start_metric=True)
def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """
    Enhanced Lambda handler with comprehensive patterns.

    Features demonstrated:
    - Event sourcing and CQRS
    - JWT and API key authentication
    - Rate limiting with multiple algorithms
    - Security validation and headers
    - Comprehensive error handling
    - Advanced observability
    """
    return app.resolve(event, context)
