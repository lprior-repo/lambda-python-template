"""
Event Schemas and Patterns for EventBridge Integration.

This module provides comprehensive event handling patterns for AWS EventBridge,
including schema validation, event sourcing, and structured event publishing.
"""

from .event_schemas import (
    BaseEvent,
    OrderCreatedEvent,
    OrderUpdatedEvent,
    OrderCancelledEvent,
    UserRegisteredEvent,
    PaymentProcessedEvent,
    InventoryUpdatedEvent,
    NotificationEvent,
    AuditEvent,
    EventType,
    EventSource,
)

from .event_publisher import (
    EventPublisher,
    EventPublishError,
    EventValidationError,
)

from .event_handler import (
    EventHandler,
    event_handler,
    EventProcessingError,
)

from .event_sourcing import (
    EventStore,
    EventStreamProcessor,
    EventProjection,
    Snapshot,
)

__all__ = [
    # Event Schemas
    'BaseEvent',
    'OrderCreatedEvent',
    'OrderUpdatedEvent',
    'OrderCancelledEvent',
    'UserRegisteredEvent',
    'PaymentProcessedEvent',
    'InventoryUpdatedEvent',
    'NotificationEvent',
    'AuditEvent',
    'EventType',
    'EventSource',

    # Event Publisher
    'EventPublisher',
    'EventPublishError',
    'EventValidationError',

    # Event Handler
    'EventHandler',
    'event_handler',
    'EventProcessingError',

    # Event Sourcing
    'EventStore',
    'EventStreamProcessor',
    'EventProjection',
    'Snapshot',
]
