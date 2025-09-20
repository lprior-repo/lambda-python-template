"""
Business Logic Layer for Order Management.

This module contains the core business logic for order processing,
following patterns from the aws-lambda-handler-cookbook with proper
validation, error handling, and business rule enforcement.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import boto3
from aws_lambda_powertools.metrics import MetricUnit
from boto3.dynamodb.conditions import Key

from service.dal.dynamodb_handler import DynamoDBHandler
from service.handlers.utils.idempotency import (
    BaseServiceError,
    BusinessLogicError,
    ErrorCategory,
    ErrorContext,
    ErrorSeverity,
    ResourceNotFoundError,
    ValidationError,
    create_error_context,
)
from service.handlers.utils.observability import logger, metrics, tracer
from service.models.input import CreateOrderRequest, UpdateOrderRequest
from service.models.order import Order, OrderStatus
from service.models.output import CreateOrderResponse, GetOrderResponse, UpdateOrderResponse


class OrderValidationError(ValidationError):
    """Raised when order validation fails."""
    pass


class OrderNotFoundError(ResourceNotFoundError):
    """Raised when an order is not found."""

    def __init__(self, order_id: str, context: Optional[ErrorContext] = None):
        super().__init__(
            resource_type="Order",
            resource_id=order_id,
            context=context,
        )


class OrderStateError(BusinessLogicError):
    """Raised when order state transition is invalid."""

    def __init__(
        self,
        message: str,
        current_status: OrderStatus,
        attempted_status: OrderStatus,
        context: Optional[ErrorContext] = None,
    ):
        super().__init__(
            message=message,
            error_code="INVALID_ORDER_STATE_TRANSITION",
            context=context,
            user_message=f"Cannot change order from {current_status.value} to {attempted_status.value}",
        )
        self.current_status = current_status
        self.attempted_status = attempted_status


class OrderService:
    """Business logic service for order management."""

    def __init__(
        self,
        orders_table_handler: DynamoDBHandler,
        eventbridge_client: Optional[Any] = None,
        max_order_items: int = 100,
        max_order_value: float = 10000.0,
    ):
        """
        Initialize order service.

        Args:
            orders_table_handler: DynamoDB handler for orders table
            eventbridge_client: EventBridge client for publishing events
            max_order_items: Maximum number of items allowed per order
            max_order_value: Maximum order value allowed
        """
        self.orders_dal = orders_table_handler
        self.eventbridge_client = eventbridge_client or boto3.client('events')
        self.max_order_items = max_order_items
        self.max_order_value = max_order_value

        logger.info("Order service initialized", extra={
            "max_order_items": max_order_items,
            "max_order_value": max_order_value,
        })

    @tracer.capture_method
    def _validate_order_business_rules(
        self,
        order_data: Dict[str, Any],
        context: ErrorContext,
    ) -> None:
        """
        Validate business rules for orders.

        Args:
            order_data: Order data to validate
            context: Error context for tracing

        Raises:
            OrderValidationError: If validation fails
        """
        order_item_count = order_data.get('order_item_count', 0)

        # Validate item count limits
        if order_item_count > self.max_order_items:
            raise OrderValidationError(
                message=f"Order exceeds maximum item limit of {self.max_order_items}",
                context=context,
            )

        # Calculate estimated order value (simplified business logic)
        estimated_value = order_item_count * 50.0  # $50 per item average
        if estimated_value > self.max_order_value:
            raise OrderValidationError(
                message=f"Order value ${estimated_value:.2f} exceeds maximum limit of ${self.max_order_value:.2f}",
                context=context,
            )

        # Validate customer email domain (business rule example)
        customer_email = order_data.get('customer_email', '')
        blocked_domains = ['spam.com', 'fake.com', 'test.invalid']
        email_domain = customer_email.split('@')[-1] if '@' in customer_email else ''

        if email_domain.lower() in blocked_domains:
            raise OrderValidationError(
                message=f"Orders from domain '{email_domain}' are not allowed",
                context=context,
            )

        logger.debug("Order business rules validation passed", extra={
            "order_item_count": order_item_count,
            "estimated_value": estimated_value,
            "customer_email_domain": email_domain,
        })

    @tracer.capture_method
    def _can_transition_order_status(
        self,
        current_status: OrderStatus,
        new_status: OrderStatus,
    ) -> bool:
        """
        Check if order status transition is valid.

        Args:
            current_status: Current order status
            new_status: Desired new status

        Returns:
            True if transition is valid, False otherwise
        """
        # Define valid status transitions
        valid_transitions = {
            OrderStatus.PENDING: [OrderStatus.CONFIRMED, OrderStatus.CANCELLED],
            OrderStatus.CONFIRMED: [OrderStatus.PROCESSING, OrderStatus.CANCELLED],
            OrderStatus.PROCESSING: [OrderStatus.SHIPPED, OrderStatus.CANCELLED],
            OrderStatus.SHIPPED: [OrderStatus.DELIVERED],
            OrderStatus.DELIVERED: [],  # Final state
            OrderStatus.CANCELLED: [],  # Final state
        }

        allowed_statuses = valid_transitions.get(current_status, [])
        return new_status in allowed_statuses

    @tracer.capture_method
    def _publish_order_event(
        self,
        event_type: str,
        order: Order,
        context: ErrorContext,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Publish order event to EventBridge.

        Args:
            event_type: Type of event (Created, Updated, Cancelled, etc.)
            order: Order object
            context: Error context for tracing
            additional_data: Additional event data
        """
        try:
            event_data = {
                'order_id': order.id,
                'customer_email': order.customer_email,
                'order_status': order.status.value,
                'order_item_count': order.order_item_count,
                'total_amount': order.total_amount,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'request_id': context.request_id,
            }

            if additional_data:
                event_data.update(additional_data)

            self.eventbridge_client.put_events(
                Entries=[
                    {
                        'Source': 'lambda.order-service',
                        'DetailType': f'Order {event_type}',
                        'Detail': json.dumps(event_data),
                        'Time': datetime.now(timezone.utc),
                    }
                ]
            )

            metrics.add_metric(name="OrderEventPublished", unit=MetricUnit.Count, value=1)
            metrics.add_metric(name=f"Order{event_type}EventPublished", unit=MetricUnit.Count, value=1)

            logger.info(f"Order {event_type.lower()} event published", extra={
                "order_id": order.id,
                "event_type": event_type,
                "customer_email": order.customer_email,
            })

        except Exception as e:
            logger.error(f"Failed to publish order {event_type.lower()} event", extra={
                "order_id": order.id,
                "event_type": event_type,
                "error": str(e),
            })
            # Don't fail the operation if event publishing fails
            metrics.add_metric(name="OrderEventPublishFailure", unit=MetricUnit.Count, value=1)

    @tracer.capture_method
    def create_order(
        self,
        request: CreateOrderRequest,
        context: ErrorContext,
    ) -> CreateOrderResponse:
        """
        Create a new order.

        Args:
            request: Create order request data
            context: Error context for tracing

        Returns:
            Created order response

        Raises:
            OrderValidationError: If order validation fails
            DALError: If database operation fails
        """
        logger.info("Creating new order", extra={
            "customer_name": request.customer_name,
            "customer_email": request.customer_email,
            "order_item_count": request.order_item_count,
            "request_id": context.request_id,
        })

        # Generate order ID
        order_id = str(uuid4())

        # Calculate total amount (simplified pricing logic)
        item_price = 50.0  # $50 per item
        total_amount = float(request.order_item_count) * item_price

        # Create order object
        order_data = {
            'id': order_id,
            'customer_name': request.customer_name,
            'customer_email': request.customer_email,
            'order_item_count': request.order_item_count,
            'notes': request.notes,
            'status': OrderStatus.PENDING.value,
            'total_amount': total_amount,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'updated_at': datetime.now(timezone.utc).isoformat(),
        }

        # Validate business rules
        self._validate_order_business_rules(order_data, context)

        # Store order in database
        stored_order_data = self.orders_dal.put_item(
            item=order_data,
            context=context,
        )

        # Create order object from stored data
        order = Order.model_validate(stored_order_data)

        # Publish order created event
        self._publish_order_event("Created", order, context)

        # Add business metrics
        metrics.add_metric(name="OrderCreated", unit=MetricUnit.Count, value=1)
        metrics.add_metric(name="OrderValue", unit=MetricUnit.None, value=total_amount)
        metrics.add_metric(name="OrderItemCount", unit=MetricUnit.Count, value=request.order_item_count)

        logger.info("Order created successfully", extra={
            "order_id": order_id,
            "total_amount": total_amount,
            "customer_email": request.customer_email,
        })

        return CreateOrderResponse(
            order_id=order_id,
            status=order.status,
            total_amount=total_amount,
            created_at=order.created_at,
            message="Order created successfully",
        )

    @tracer.capture_method
    def get_order(
        self,
        order_id: str,
        context: ErrorContext,
    ) -> GetOrderResponse:
        """
        Get an order by ID.

        Args:
            order_id: Order identifier
            context: Error context for tracing

        Returns:
            Order details

        Raises:
            OrderNotFoundError: If order is not found
            DALError: If database operation fails
        """
        logger.info("Retrieving order", extra={
            "order_id": order_id,
            "request_id": context.request_id,
        })

        # Get order from database
        order_data = self.orders_dal.get_item(
            key={'id': order_id},
            context=context,
        )

        if not order_data:
            raise OrderNotFoundError(order_id=order_id, context=context)

        # Create order object
        order = Order.model_validate(order_data)

        # Add metrics
        metrics.add_metric(name="OrderRetrieved", unit=MetricUnit.Count, value=1)

        logger.info("Order retrieved successfully", extra={
            "order_id": order_id,
            "status": order.status.value,
            "customer_email": order.customer_email,
        })

        return GetOrderResponse(order=order)

    @tracer.capture_method
    def update_order(
        self,
        order_id: str,
        request: UpdateOrderRequest,
        context: ErrorContext,
    ) -> UpdateOrderResponse:
        """
        Update an existing order.

        Args:
            order_id: Order identifier
            request: Update order request data
            context: Error context for tracing

        Returns:
            Updated order response

        Raises:
            OrderNotFoundError: If order is not found
            OrderStateError: If order cannot be updated in current state
            OrderValidationError: If update validation fails
            DALError: If database operation fails
        """
        logger.info("Updating order", extra={
            "order_id": order_id,
            "request_id": context.request_id,
        })

        # Get existing order
        existing_order_data = self.orders_dal.get_item(
            key={'id': order_id},
            context=context,
        )

        if not existing_order_data:
            raise OrderNotFoundError(order_id=order_id, context=context)

        existing_order = Order.model_validate(existing_order_data)

        # Check if order can be updated (business rule)
        if existing_order.status in [OrderStatus.SHIPPED, OrderStatus.DELIVERED, OrderStatus.CANCELLED]:
            raise OrderStateError(
                message=f"Cannot update order in {existing_order.status.value} status",
                current_status=existing_order.status,
                attempted_status=existing_order.status,  # Not changing status, but using for error
                context=context,
            )

        # Build update expression
        update_parts = []
        expression_values = {}

        if request.order_item_count is not None:
            # Validate new item count
            temp_order_data = existing_order_data.copy()
            temp_order_data['order_item_count'] = request.order_item_count
            self._validate_order_business_rules(temp_order_data, context)

            # Recalculate total amount
            item_price = 50.0
            new_total_amount = float(request.order_item_count) * item_price

            update_parts.extend([
                "order_item_count = :order_item_count",
                "total_amount = :total_amount"
            ])
            expression_values[':order_item_count'] = request.order_item_count
            expression_values[':total_amount'] = new_total_amount

        if request.notes is not None:
            update_parts.append("notes = :notes")
            expression_values[':notes'] = request.notes

        if not update_parts:
            # No updates requested, return current order
            return UpdateOrderResponse(
                order=existing_order,
                message="No changes requested",
            )

        # Perform update
        update_expression = "SET " + ", ".join(update_parts)

        updated_order_data = self.orders_dal.update_item(
            key={'id': order_id},
            update_expression=update_expression,
            expression_attribute_values=expression_values,
            # Ensure order still exists and hasn't been deleted
            condition_expression=Key('id').exists(),
            context=context,
        )

        # Create updated order object
        updated_order = Order.model_validate(updated_order_data)

        # Publish order updated event
        self._publish_order_event("Updated", updated_order, context, {
            'previous_item_count': existing_order.order_item_count,
            'new_item_count': updated_order.order_item_count,
        })

        # Add metrics
        metrics.add_metric(name="OrderUpdated", unit=MetricUnit.Count, value=1)

        logger.info("Order updated successfully", extra={
            "order_id": order_id,
            "previous_item_count": existing_order.order_item_count,
            "new_item_count": updated_order.order_item_count,
            "new_total_amount": updated_order.total_amount,
        })

        return UpdateOrderResponse(
            order=updated_order,
            message="Order updated successfully",
        )

    @tracer.capture_method
    def cancel_order(
        self,
        order_id: str,
        reason: str,
        context: ErrorContext,
    ) -> UpdateOrderResponse:
        """
        Cancel an order.

        Args:
            order_id: Order identifier
            reason: Cancellation reason
            context: Error context for tracing

        Returns:
            Cancelled order response

        Raises:
            OrderNotFoundError: If order is not found
            OrderStateError: If order cannot be cancelled in current state
            DALError: If database operation fails
        """
        logger.info("Cancelling order", extra={
            "order_id": order_id,
            "reason": reason,
            "request_id": context.request_id,
        })

        # Get existing order
        existing_order_data = self.orders_dal.get_item(
            key={'id': order_id},
            context=context,
        )

        if not existing_order_data:
            raise OrderNotFoundError(order_id=order_id, context=context)

        existing_order = Order.model_validate(existing_order_data)

        # Check if order can be cancelled
        if not self._can_transition_order_status(existing_order.status, OrderStatus.CANCELLED):
            raise OrderStateError(
                message=f"Cannot cancel order in {existing_order.status.value} status",
                current_status=existing_order.status,
                attempted_status=OrderStatus.CANCELLED,
                context=context,
            )

        # Update order status to cancelled
        updated_order_data = self.orders_dal.update_item(
            key={'id': order_id},
            update_expression="SET #status = :status, cancellation_reason = :reason",
            expression_attribute_names={'#status': 'status'},
            expression_attribute_values={
                ':status': OrderStatus.CANCELLED.value,
                ':reason': reason,
            },
            condition_expression=Key('id').exists(),
            context=context,
        )

        # Create updated order object
        cancelled_order = Order.model_validate(updated_order_data)

        # Publish order cancelled event
        self._publish_order_event("Cancelled", cancelled_order, context, {
            'cancellation_reason': reason,
            'previous_status': existing_order.status.value,
        })

        # Add metrics
        metrics.add_metric(name="OrderCancelled", unit=MetricUnit.Count, value=1)

        logger.info("Order cancelled successfully", extra={
            "order_id": order_id,
            "previous_status": existing_order.status.value,
            "cancellation_reason": reason,
        })

        return UpdateOrderResponse(
            order=cancelled_order,
            message=f"Order cancelled: {reason}",
        )

    @tracer.capture_method
    def list_orders(
        self,
        customer_email: Optional[str] = None,
        status: Optional[OrderStatus] = None,
        limit: int = 50,
        last_evaluated_key: Optional[Dict[str, Any]] = None,
        context: Optional[ErrorContext] = None,
    ) -> Dict[str, Any]:
        """
        List orders with optional filtering.

        Args:
            customer_email: Filter by customer email
            status: Filter by order status
            limit: Maximum number of orders to return
            last_evaluated_key: Pagination token
            context: Error context for tracing

        Returns:
            Dictionary with orders list and pagination info

        Raises:
            DALError: If database operation fails
        """
        logger.info("Listing orders", extra={
            "customer_email": customer_email,
            "status": status.value if status else None,
            "limit": limit,
            "has_pagination_token": last_evaluated_key is not None,
        })

        # Build filter expression
        filter_expression = None
        if customer_email and status:
            filter_expression = Key('customer_email').eq(customer_email) & Key('status').eq(status.value)
        elif customer_email:
            filter_expression = Key('customer_email').eq(customer_email)
        elif status:
            filter_expression = Key('status').eq(status.value)

        # Scan or query based on filters
        if customer_email:
            # Use GSI for customer email queries (if exists)
            result = self.orders_dal.scan_items(
                filter_expression=filter_expression,
                limit=limit,
                exclusive_start_key=last_evaluated_key,
                context=context,
            )
        else:
            # Full table scan
            result = self.orders_dal.scan_items(
                filter_expression=filter_expression,
                limit=limit,
                exclusive_start_key=last_evaluated_key,
                context=context,
            )

        # Convert to Order objects
        orders = [Order.model_validate(item) for item in result['items']]

        # Add metrics
        metrics.add_metric(name="OrdersListed", unit=MetricUnit.Count, value=len(orders))

        response = {
            'orders': orders,
            'count': len(orders),
            'scanned_count': result.get('scanned_count', 0),
        }

        if 'last_evaluated_key' in result:
            response['last_evaluated_key'] = result['last_evaluated_key']

        logger.info("Orders listed successfully", extra={
            "orders_count": len(orders),
            "scanned_count": result.get('scanned_count', 0),
            "has_more_results": 'last_evaluated_key' in response,
        })

        return response

    @tracer.capture_method
    def get_order_statistics(
        self,
        context: ErrorContext,
    ) -> Dict[str, Any]:
        """
        Get order statistics for monitoring and reporting.

        Args:
            context: Error context for tracing

        Returns:
            Dictionary with order statistics

        Raises:
            DALError: If database operation fails
        """
        logger.info("Generating order statistics", extra={
            "request_id": context.request_id,
        })

        # Get all orders (in production, you'd want to use aggregation queries)
        result = self.orders_dal.scan_items(context=context)
        orders = [Order.model_validate(item) for item in result['items']]

        # Calculate statistics
        total_orders = len(orders)
        total_revenue = sum(order.total_amount for order in orders)

        status_counts = {}
        for status in OrderStatus:
            status_counts[status.value] = sum(1 for order in orders if order.status == status)

        average_order_value = total_revenue / total_orders if total_orders > 0 else 0
        average_items_per_order = sum(order.order_item_count for order in orders) / total_orders if total_orders > 0 else 0

        statistics = {
            'total_orders': total_orders,
            'total_revenue': round(total_revenue, 2),
            'average_order_value': round(average_order_value, 2),
            'average_items_per_order': round(average_items_per_order, 1),
            'status_distribution': status_counts,
            'generated_at': datetime.now(timezone.utc).isoformat(),
        }

        logger.info("Order statistics generated", extra=statistics)

        return statistics
