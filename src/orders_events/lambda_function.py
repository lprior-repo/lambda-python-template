"""
Orders Event Processor Lambda Function.

This Lambda function demonstrates advanced event sourcing and CQRS patterns
with EventBridge integration, event store management, and projection updates.
"""

import json
import os
import sys
from typing import Any, Dict

# Add the service module to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.utilities.data_classes import EventBridgeEvent

from service.events import (
    EventHandler,
    event_handler,
    EventType,
    EventSource,
    BaseEvent,
    OrderCreatedEvent,
    OrderUpdatedEvent,
    OrderCancelledEvent,
    EventPublisher,
    EventStore,
    EventStreamProcessor,
    OrderSummaryProjection,
    UserActivityProjection,
)

logger = Logger()
tracer = Tracer()
metrics = Metrics()

# Initialize event components
event_publisher = EventPublisher(
    event_bus_name=os.environ.get('EVENT_BUS_NAME', 'default'),
    dlq_table_name=os.environ.get('EVENT_DLQ_TABLE_NAME')
)

event_store = EventStore(
    table_name=os.environ.get('EVENT_STORE_TABLE_NAME', 'event-store'),
    snapshot_table_name=os.environ.get('EVENT_SNAPSHOTS_TABLE_NAME', 'event-snapshots')
)

# Initialize projections
order_projection = OrderSummaryProjection(
    table_name=os.environ.get('ORDER_SUMMARIES_TABLE_NAME', 'order-summaries')
)

user_activity_projection = UserActivityProjection(
    table_name=os.environ.get('USER_ACTIVITY_TABLE_NAME', 'user-activity')
)

# Initialize stream processor
stream_processor = EventStreamProcessor(
    event_store=event_store,
    projections=[order_projection, user_activity_projection],
    checkpoint_table=os.environ.get('PROJECTION_CHECKPOINTS_TABLE', 'projection-checkpoints')
)


@event_handler(EventType.ORDER_CREATED, EventSource.ORDERS)
@tracer.capture_method
def handle_order_created(event: BaseEvent, context: LambdaContext) -> Dict[str, Any]:
    """Handle order created events with event sourcing."""
    logger.info("Processing order created event", extra={"event_id": event.id})

    try:
        # Store event in event store
        order_id = event.data.get('order_id')
        stream_id = f"order-{order_id}"

        event_records = event_store.append_events(
            stream_id=stream_id,
            events=[event]
        )

        # Update projections
        for record in event_records:
            order_projection.handle_event(record)
            user_activity_projection.handle_event(record)

        # Publish downstream events
        user_registered_event = BaseEvent(
            source=EventSource.NOTIFICATIONS,
            event_type=EventType.NOTIFICATION_SENT,
            data={
                "notification_id": f"order-created-{order_id}",
                "recipient_id": event.data.get('user_id'),
                "channel": "email",
                "message": f"Order {order_id} has been created successfully!",
                "template_id": "order_confirmation"
            }
        )

        event_publisher.publish_event(user_registered_event)

        metrics.add_metric(name="OrderCreatedProcessed", unit=MetricUnit.Count, value=1)

        logger.info(
            "Order created event processed successfully",
            extra={
                "order_id": order_id,
                "stream_id": stream_id,
                "events_stored": len(event_records)
            }
        )

        return {
            "status": "processed",
            "order_id": order_id,
            "stream_id": stream_id,
            "events_stored": len(event_records)
        }

    except Exception as e:
        logger.error(f"Failed to process order created event: {str(e)}")
        metrics.add_metric(name="OrderCreatedProcessingError", unit=MetricUnit.Count, value=1)
        raise


@event_handler(EventType.ORDER_UPDATED, EventSource.ORDERS)
@tracer.capture_method
def handle_order_updated(event: BaseEvent, context: LambdaContext) -> Dict[str, Any]:
    """Handle order updated events with optimistic concurrency."""
    logger.info("Processing order updated event", extra={"event_id": event.id})

    try:
        order_id = event.data.get('order_id')
        stream_id = f"order-{order_id}"

        # Get current stream version for optimistic concurrency
        stream_info = event_store.get_stream_info(stream_id)
        expected_version = stream_info.version if stream_info else 0

        # Store event with version check
        event_records = event_store.append_events(
            stream_id=stream_id,
            events=[event],
            expected_version=expected_version
        )

        # Update projections
        for record in event_records:
            order_projection.handle_event(record)
            user_activity_projection.handle_event(record)

        # Check if status changed to completed
        if event.data.get('status') == 'completed':
            completion_event = BaseEvent(
                source=EventSource.ORDERS,
                event_type=EventType.ORDER_COMPLETED,
                data={
                    "order_id": order_id,
                    "completion_time": event.timestamp.isoformat(),
                    "user_id": event.data.get('user_id')
                }
            )

            event_publisher.publish_event(completion_event)

        metrics.add_metric(name="OrderUpdatedProcessed", unit=MetricUnit.Count, value=1)

        return {
            "status": "processed",
            "order_id": order_id,
            "new_version": expected_version + 1
        }

    except Exception as e:
        logger.error(f"Failed to process order updated event: {str(e)}")
        metrics.add_metric(name="OrderUpdatedProcessingError", unit=MetricUnit.Count, value=1)
        raise


@event_handler(EventType.ORDER_CANCELLED, EventSource.ORDERS)
@tracer.capture_method
def handle_order_cancelled(event: BaseEvent, context: LambdaContext) -> Dict[str, Any]:
    """Handle order cancelled events with compensation logic."""
    logger.info("Processing order cancelled event", extra={"event_id": event.id})

    try:
        order_id = event.data.get('order_id')
        stream_id = f"order-{order_id}"

        # Store cancellation event
        event_records = event_store.append_events(
            stream_id=stream_id,
            events=[event]
        )

        # Update projections
        for record in event_records:
            order_projection.handle_event(record)
            user_activity_projection.handle_event(record)

        # Publish compensation events
        compensation_events = []

        # Inventory restoration event
        inventory_event = BaseEvent(
            source=EventSource.INVENTORY,
            event_type=EventType.INVENTORY_UPDATED,
            data={
                "order_id": order_id,
                "action": "restore",
                "items": event.data.get('items', []),
                "reason": "order_cancelled"
            }
        )
        compensation_events.append(inventory_event)

        # Payment refund event (if payment was processed)
        if event.data.get('payment_status') == 'processed':
            refund_event = BaseEvent(
                source=EventSource.PAYMENTS,
                event_type=EventType.PAYMENT_REFUNDED,
                data={
                    "order_id": order_id,
                    "refund_amount": event.data.get('total_amount', 0),
                    "refund_reason": event.data.get('reason', 'order_cancelled'),
                    "user_id": event.data.get('user_id')
                }
            )
            compensation_events.append(refund_event)

        # Notification event
        notification_event = BaseEvent(
            source=EventSource.NOTIFICATIONS,
            event_type=EventType.NOTIFICATION_SENT,
            data={
                "notification_id": f"order-cancelled-{order_id}",
                "recipient_id": event.data.get('user_id'),
                "channel": "email",
                "message": f"Order {order_id} has been cancelled.",
                "template_id": "order_cancellation"
            }
        )
        compensation_events.append(notification_event)

        # Publish all compensation events
        event_publisher.publish_events(compensation_events)

        metrics.add_metric(name="OrderCancelledProcessed", unit=MetricUnit.Count, value=1)
        metrics.add_metric(name="CompensationEventsPublished", unit=MetricUnit.Count, value=len(compensation_events))

        return {
            "status": "processed",
            "order_id": order_id,
            "compensation_events": len(compensation_events)
        }

    except Exception as e:
        logger.error(f"Failed to process order cancelled event: {str(e)}")
        metrics.add_metric(name="OrderCancelledProcessingError", unit=MetricUnit.Count, value=1)
        raise


@event_handler()  # Global handler for auditing
@tracer.capture_method
def audit_event_handler(event: BaseEvent, context: LambdaContext) -> Dict[str, Any]:
    """Global event handler for audit logging."""
    try:
        # Create audit event
        audit_event = BaseEvent(
            source=EventSource.AUDIT,
            event_type=EventType.AUDIT_LOG_CREATED,
            data={
                "original_event_id": event.id,
                "event_type": event.event_type.value,
                "event_source": event.source.value,
                "timestamp": event.timestamp.isoformat(),
                "correlation_id": event.metadata.correlation_id,
                "lambda_request_id": context.aws_request_id,
                "lambda_function_name": context.function_name
            }
        )

        # Store audit event in separate stream
        audit_stream_id = f"audit-{event.timestamp.strftime('%Y-%m-%d')}"
        event_store.append_events(
            stream_id=audit_stream_id,
            events=[audit_event]
        )

        metrics.add_metric(name="EventAudited", unit=MetricUnit.Count, value=1)

        return {"audited": True, "audit_stream": audit_stream_id}

    except Exception as e:
        logger.error(f"Failed to audit event: {str(e)}")
        # Don't fail the main processing for audit errors
        return {"audited": False, "error": str(e)}


@tracer.capture_lambda_handler
@metrics.log_metrics(capture_cold_start_metric=True)
def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """
    Main Lambda handler for order events processing.

    This handler demonstrates:
    - Event sourcing with event store
    - CQRS with read model projections
    - Saga pattern for distributed transactions
    - Event-driven architecture with EventBridge
    - Comprehensive error handling and monitoring
    """
    logger.info("Orders event processor invoked", extra={"event": event})

    try:
        # Create event handler and process the event
        handler = EventHandler()
        result = handler.handle_event(event, context)

        # Record success metrics
        metrics.add_metric(name="EventProcessingSuccess", unit=MetricUnit.Count, value=1)

        logger.info(
            "Event processing completed successfully",
            extra={
                "result": result,
                "function_name": context.function_name,
                "remaining_time": context.get_remaining_time_in_millis()
            }
        )

        return result

    except Exception as e:
        # Record error metrics
        metrics.add_metric(name="EventProcessingError", unit=MetricUnit.Count, value=1)

        logger.error(
            f"Event processing failed: {str(e)}",
            extra={
                "error": str(e),
                "event": event,
                "function_name": context.function_name
            }
        )

        # Re-raise to trigger Lambda error handling
        raise


# Additional utility functions for event replay and projection rebuilding
@tracer.capture_method
def replay_events_for_stream(stream_id: str, from_version: int = 0) -> Dict[str, Any]:
    """Replay events for a specific stream to rebuild projections."""
    try:
        events_processed = stream_processor.process_stream(
            stream_id=stream_id,
            from_version=from_version
        )

        logger.info(f"Replayed {events_processed} events for stream {stream_id}")

        return {
            "stream_id": stream_id,
            "events_processed": events_processed,
            "status": "completed"
        }

    except Exception as e:
        logger.error(f"Failed to replay events for stream {stream_id}: {str(e)}")
        raise


@tracer.capture_method
def create_snapshot_for_stream(stream_id: str) -> Dict[str, Any]:
    """Create a snapshot for an event stream."""
    try:
        # Get all events for the stream
        events = event_store.get_events(stream_id)

        if not events:
            return {"stream_id": stream_id, "snapshot_created": False, "reason": "no_events"}

        # Build aggregate state from events
        aggregate_state = {}
        for event_record in events:
            # Apply event to state (simplified example)
            if event_record.event_type == "OrderCreated":
                aggregate_state.update(event_record.event_data)
                aggregate_state["status"] = "created"
            elif event_record.event_type == "OrderUpdated":
                aggregate_state.update(event_record.event_data)
            elif event_record.event_type == "OrderCancelled":
                aggregate_state["status"] = "cancelled"

        # Create and save snapshot
        from service.events.event_sourcing import Snapshot
        from datetime import datetime

        snapshot = Snapshot(
            stream_id=stream_id,
            version=events[-1].version,
            data=aggregate_state,
            timestamp=datetime.utcnow(),
            aggregate_type="Order"
        )

        success = event_store.save_snapshot(snapshot)

        logger.info(f"Created snapshot for stream {stream_id}, version {snapshot.version}")

        return {
            "stream_id": stream_id,
            "snapshot_created": success,
            "version": snapshot.version,
            "aggregate_type": snapshot.aggregate_type
        }

    except Exception as e:
        logger.error(f"Failed to create snapshot for stream {stream_id}: {str(e)}")
        raise
