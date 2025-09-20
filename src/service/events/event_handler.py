"""
Event Handler Patterns for Lambda Event Processing.

This module provides decorators and patterns for handling events in a Lambda
environment with features like routing, validation, error handling, and metrics.
"""

import json
import functools
from typing import Any, Callable, Dict, List, Optional, Type, Union
from dataclasses import dataclass
from enum import Enum

from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.utilities.data_classes import EventBridgeEvent
from aws_lambda_powertools.utilities.typing import LambdaContext
from pydantic import BaseModel, ValidationError

from .event_schemas import BaseEvent, EventType, EventSource, EVENT_REGISTRY

logger = Logger()
tracer = Tracer()
metrics = Metrics()


class EventProcessingError(Exception):
    """Exception raised during event processing."""

    def __init__(self, message: str, event_data: Optional[Dict[str, Any]] = None,
                 original_error: Optional[Exception] = None):
        super().__init__(message)
        self.event_data = event_data
        self.original_error = original_error


class EventHandlerNotFoundError(EventProcessingError):
    """Exception raised when no handler is found for an event."""
    pass


class EventValidationFailedError(EventProcessingError):
    """Exception raised when event validation fails."""
    pass


@dataclass
class HandlerConfig:
    """Configuration for event handlers."""

    validate_input: bool = True
    validate_output: bool = False
    capture_metrics: bool = True
    capture_traces: bool = True
    retry_on_error: bool = False
    max_retries: int = 3
    dead_letter_queue: Optional[str] = None


class HandlerRegistry:
    """Registry for event handlers."""

    def __init__(self):
        self._handlers: Dict[str, Dict[str, Callable]] = {}
        self._global_handlers: List[Callable] = []

    def register(self, event_type: Union[EventType, str],
                 event_source: Union[EventSource, str],
                 handler: Callable,
                 config: Optional[HandlerConfig] = None):
        """Register an event handler."""
        key = self._make_key(event_type, event_source)

        if key not in self._handlers:
            self._handlers[key] = {}

        self._handlers[key]['handler'] = handler
        self._handlers[key]['config'] = config or HandlerConfig()

        logger.debug(f"Registered handler for {key}")

    def register_global(self, handler: Callable):
        """Register a global handler that processes all events."""
        self._global_handlers.append(handler)
        logger.debug("Registered global handler")

    def get_handler(self, event_type: Union[EventType, str],
                   event_source: Union[EventSource, str]) -> Optional[Dict[str, Any]]:
        """Get handler for event type and source."""
        key = self._make_key(event_type, event_source)
        return self._handlers.get(key)

    def get_global_handlers(self) -> List[Callable]:
        """Get all global handlers."""
        return self._global_handlers.copy()

    def list_handlers(self) -> Dict[str, Dict[str, Any]]:
        """List all registered handlers."""
        return self._handlers.copy()

    def _make_key(self, event_type: Union[EventType, str],
                  event_source: Union[EventSource, str]) -> str:
        """Create a key for handler registration."""
        type_str = event_type.value if isinstance(event_type, EventType) else str(event_type)
        source_str = event_source.value if isinstance(event_source, EventSource) else str(event_source)
        return f"{source_str}:{type_str}"


# Global handler registry
_handler_registry = HandlerRegistry()


def event_handler(
    event_type: Union[EventType, str, List[Union[EventType, str]]] = None,
    event_source: Union[EventSource, str, List[Union[EventSource, str]]] = None,
    config: Optional[HandlerConfig] = None
):
    """
    Decorator to register event handlers.

    Args:
        event_type: Event type(s) to handle
        event_source: Event source(s) to handle
        config: Handler configuration

    Example:
        @event_handler(EventType.ORDER_CREATED, EventSource.ORDERS)
        def handle_order_created(event: OrderCreatedEvent, context: LambdaContext):
            # Process order created event
            pass
    """
    def decorator(func: Callable) -> Callable:
        # Handle multiple event types/sources
        event_types = event_type if isinstance(event_type, list) else [event_type]
        event_sources = event_source if isinstance(event_source, list) else [event_source]

        # Register for all combinations
        for e_type in event_types:
            for e_source in event_sources:
                if e_type is None or e_source is None:
                    # Global handler
                    _handler_registry.register_global(func)
                else:
                    _handler_registry.register(e_type, e_source, func, config)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        return wrapper

    return decorator


class EventHandler:
    """
    Main event handler class for processing Lambda events.

    Features:
    - Event routing based on type and source
    - Input/output validation
    - Error handling and retries
    - Metrics and tracing
    - Dead letter queue support
    """

    def __init__(self, registry: Optional[HandlerRegistry] = None):
        self.registry = registry or _handler_registry

    @tracer.capture_method
    @metrics.log_metrics(capture_cold_start_metric=True)
    def handle_event(self, event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
        """
        Main entry point for handling Lambda events.

        Args:
            event: Lambda event payload
            context: Lambda context

        Returns:
            Response dictionary
        """
        start_time = tracer.current_span().start_time

        try:
            # Parse event
            parsed_event = self._parse_event(event)

            # Find and execute handlers
            result = self._execute_handlers(parsed_event, context)

            # Record success metrics
            self._record_success_metrics(parsed_event)

            logger.info(
                "Event processed successfully",
                extra={
                    "event_type": parsed_event.event_type,
                    "event_source": parsed_event.source,
                    "event_id": parsed_event.id
                }
            )

            return result

        except Exception as e:
            # Record error metrics
            self._record_error_metrics(event, e)

            logger.error(
                f"Event processing failed: {str(e)}",
                extra={"event": event, "error": str(e)}
            )

            # Re-raise for Lambda runtime to handle
            raise

    def _parse_event(self, event: Dict[str, Any]) -> BaseEvent:
        """Parse Lambda event into BaseEvent."""
        try:
            # Handle EventBridge events
            if 'source' in event and 'detail-type' in event:
                return self._parse_eventbridge_event(event)

            # Handle direct event payload
            elif 'event_type' in event or 'eventType' in event:
                return self._parse_direct_event(event)

            # Handle SQS events
            elif 'Records' in event and event['Records']:
                return self._parse_sqs_event(event)

            else:
                # Fallback - treat as raw event data
                return BaseEvent(
                    source=EventSource.SYSTEM,
                    event_type=EventType.SYSTEM_ERROR,
                    data=event
                )

        except Exception as e:
            raise EventValidationFailedError(
                f"Failed to parse event: {str(e)}",
                event_data=event,
                original_error=e
            )

    def _parse_eventbridge_event(self, event: Dict[str, Any]) -> BaseEvent:
        """Parse EventBridge event."""
        try:
            eventbridge_event = EventBridgeEvent(event)
            detail = eventbridge_event.detail

            # Extract event information
            event_source = EventSource(eventbridge_event.source)
            event_type = EventType(eventbridge_event.detail_type)

            # Create BaseEvent
            return BaseEvent(
                id=detail.get('id', eventbridge_event.id),
                source=event_source,
                event_type=event_type,
                timestamp=eventbridge_event.time,
                data=detail.get('data', detail),
                metadata=detail.get('metadata', {})
            )

        except (ValueError, KeyError) as e:
            raise EventValidationFailedError(
                f"Invalid EventBridge event: {str(e)}",
                event_data=event,
                original_error=e
            )

    def _parse_direct_event(self, event: Dict[str, Any]) -> BaseEvent:
        """Parse direct event payload."""
        try:
            # Try to create BaseEvent directly
            return BaseEvent(**event)

        except ValidationError as e:
            # Try with different field mappings
            mapped_event = {
                'source': event.get('source') or event.get('eventSource', EventSource.SYSTEM),
                'event_type': event.get('event_type') or event.get('eventType', EventType.SYSTEM_ERROR),
                'data': event.get('data', event),
                'metadata': event.get('metadata', {})
            }

            if 'id' in event:
                mapped_event['id'] = event['id']
            if 'timestamp' in event:
                mapped_event['timestamp'] = event['timestamp']

            return BaseEvent(**mapped_event)

    def _parse_sqs_event(self, event: Dict[str, Any]) -> BaseEvent:
        """Parse SQS event record."""
        try:
            # Take the first record
            record = event['Records'][0]
            body = json.loads(record['body'])

            # If body contains EventBridge message, parse it
            if 'Message' in body:
                message = json.loads(body['Message'])
                return self._parse_eventbridge_event(message)
            else:
                return self._parse_direct_event(body)

        except (json.JSONDecodeError, KeyError, IndexError) as e:
            raise EventValidationFailedError(
                f"Invalid SQS event: {str(e)}",
                event_data=event,
                original_error=e
            )

    def _execute_handlers(self, event: BaseEvent, context: LambdaContext) -> Dict[str, Any]:
        """Execute registered handlers for the event."""
        results = []

        # Execute specific handlers
        handler_info = self.registry.get_handler(event.event_type, event.source)
        if handler_info:
            result = self._execute_single_handler(
                handler_info['handler'],
                handler_info['config'],
                event,
                context
            )
            results.append(result)

        # Execute global handlers
        for global_handler in self.registry.get_global_handlers():
            result = self._execute_single_handler(
                global_handler,
                HandlerConfig(),
                event,
                context
            )
            results.append(result)

        # If no handlers found, raise error
        if not results:
            raise EventHandlerNotFoundError(
                f"No handler found for event {event.event_type} from {event.source}",
                event_data=event.dict()
            )

        # Return combined results
        return {
            'processed': True,
            'results': results,
            'event_id': event.id,
            'handlers_executed': len(results)
        }

    def _execute_single_handler(
        self,
        handler: Callable,
        config: HandlerConfig,
        event: BaseEvent,
        context: LambdaContext
    ) -> Any:
        """Execute a single event handler."""
        handler_name = handler.__name__

        try:
            # Add tracing if enabled
            if config.capture_traces:
                with tracer.subsegment(f"handler_{handler_name}"):
                    result = self._call_handler_with_retry(handler, config, event, context)
            else:
                result = self._call_handler_with_retry(handler, config, event, context)

            # Record handler metrics
            if config.capture_metrics:
                metrics.add_metric(
                    name=f"HandlerSuccess_{handler_name}",
                    unit=MetricUnit.Count,
                    value=1
                )

            logger.debug(f"Handler {handler_name} executed successfully")

            return result

        except Exception as e:
            # Record error metrics
            if config.capture_metrics:
                metrics.add_metric(
                    name=f"HandlerError_{handler_name}",
                    unit=MetricUnit.Count,
                    value=1
                )

            logger.error(f"Handler {handler_name} failed: {str(e)}")

            # Send to DLQ if configured
            if config.dead_letter_queue:
                self._send_to_dlq(event, e, config.dead_letter_queue)

            raise EventProcessingError(
                f"Handler {handler_name} failed: {str(e)}",
                event_data=event.dict(),
                original_error=e
            )

    def _call_handler_with_retry(
        self,
        handler: Callable,
        config: HandlerConfig,
        event: BaseEvent,
        context: LambdaContext
    ) -> Any:
        """Call handler with retry logic."""
        last_exception = None

        max_attempts = config.max_retries + 1 if config.retry_on_error else 1

        for attempt in range(max_attempts):
            try:
                # Call handler with appropriate arguments
                if self._handler_accepts_context(handler):
                    return handler(event, context)
                else:
                    return handler(event)

            except Exception as e:
                last_exception = e

                if attempt < max_attempts - 1:
                    logger.warning(
                        f"Handler attempt {attempt + 1} failed, retrying: {str(e)}"
                    )
                    # Simple retry without backoff - could be enhanced
                    continue
                else:
                    break

        # All attempts failed
        raise last_exception

    def _handler_accepts_context(self, handler: Callable) -> bool:
        """Check if handler accepts context parameter."""
        import inspect
        sig = inspect.signature(handler)
        return len(sig.parameters) > 1

    def _record_success_metrics(self, event: BaseEvent):
        """Record success metrics."""
        metrics.add_metric(name="EventProcessed", unit=MetricUnit.Count, value=1)
        metrics.add_metric(
            name=f"EventProcessed_{event.event_type.value}",
            unit=MetricUnit.Count,
            value=1
        )

    def _record_error_metrics(self, event: Dict[str, Any], error: Exception):
        """Record error metrics."""
        metrics.add_metric(name="EventProcessingError", unit=MetricUnit.Count, value=1)
        metrics.add_metric(
            name=f"EventProcessingError_{type(error).__name__}",
            unit=MetricUnit.Count,
            value=1
        )

    def _send_to_dlq(self, event: BaseEvent, error: Exception, dlq_name: str):
        """Send failed event to dead letter queue."""
        try:
            import boto3
            sqs = boto3.client('sqs')

            dlq_message = {
                'event': event.dict(),
                'error': str(error),
                'error_type': type(error).__name__,
                'timestamp': event.timestamp.isoformat()
            }

            sqs.send_message(
                QueueUrl=dlq_name,
                MessageBody=json.dumps(dlq_message, default=str)
            )

            logger.info(f"Event sent to DLQ: {dlq_name}")

        except Exception as dlq_error:
            logger.error(f"Failed to send to DLQ: {str(dlq_error)}")


# Convenience function for Lambda handlers
def create_event_handler(registry: Optional[HandlerRegistry] = None) -> Callable:
    """
    Create a Lambda handler function for event processing.

    Returns:
        Lambda handler function
    """
    handler = EventHandler(registry)

    def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
        return handler.handle_event(event, context)

    return lambda_handler


# Example usage patterns
if __name__ == "__main__":
    # Example handler registrations

    @event_handler(EventType.ORDER_CREATED, EventSource.ORDERS)
    def handle_order_created(event: BaseEvent, context: LambdaContext):
        """Handle order created events."""
        logger.info(f"Processing order: {event.data}")
        # Business logic here
        return {"status": "processed", "order_id": event.data.get("order_id")}

    @event_handler(EventType.USER_REGISTERED, EventSource.USERS)
    def handle_user_registered(event: BaseEvent):
        """Handle user registration events."""
        logger.info(f"New user registered: {event.data}")
        # Send welcome email, setup user preferences, etc.
        return {"status": "processed", "user_id": event.data.get("user_id")}

    @event_handler()  # Global handler
    def handle_all_events(event: BaseEvent, context: LambdaContext):
        """Handle all events for auditing."""
        logger.info(f"Audit: {event.event_type} from {event.source}")
        # Audit logging logic
        return {"audited": True}

    # Create Lambda handler
    lambda_handler = create_event_handler()
