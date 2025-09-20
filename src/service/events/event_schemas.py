"""
Event Schemas for EventBridge Integration.

This module defines comprehensive event schemas using Pydantic for validation,
supporting event-driven architecture patterns with type safety and serialization.
"""

import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator
from aws_lambda_powertools import Logger

logger = Logger()


class EventSource(str, Enum):
    """Standard event sources in the system."""

    ORDERS = "orders.service"
    USERS = "users.service"
    PAYMENTS = "payments.service"
    INVENTORY = "inventory.service"
    NOTIFICATIONS = "notifications.service"
    AUDIT = "audit.service"
    SYSTEM = "system"


class EventType(str, Enum):
    """Standard event types following domain-driven design."""

    # Order Events
    ORDER_CREATED = "OrderCreated"
    ORDER_UPDATED = "OrderUpdated"
    ORDER_CANCELLED = "OrderCancelled"
    ORDER_COMPLETED = "OrderCompleted"
    ORDER_FAILED = "OrderFailed"

    # User Events
    USER_REGISTERED = "UserRegistered"
    USER_UPDATED = "UserUpdated"
    USER_DELETED = "UserDeleted"
    USER_LOGIN = "UserLogin"

    # Payment Events
    PAYMENT_INITIATED = "PaymentInitiated"
    PAYMENT_PROCESSED = "PaymentProcessed"
    PAYMENT_FAILED = "PaymentFailed"
    PAYMENT_REFUNDED = "PaymentRefunded"

    # Inventory Events
    INVENTORY_UPDATED = "InventoryUpdated"
    INVENTORY_LOW_STOCK = "InventoryLowStock"
    INVENTORY_OUT_OF_STOCK = "InventoryOutOfStock"

    # Notification Events
    NOTIFICATION_SENT = "NotificationSent"
    NOTIFICATION_FAILED = "NotificationFailed"

    # System Events
    SYSTEM_HEALTH_CHECK = "SystemHealthCheck"
    SYSTEM_ERROR = "SystemError"

    # Audit Events
    AUDIT_LOG_CREATED = "AuditLogCreated"


class EventMetadata(BaseModel):
    """Standard metadata for all events."""

    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    causation_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    version: str = Field(default="1.0")

    class Config:
        frozen = True


class BaseEvent(BaseModel):
    """Base event schema with common fields."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    source: EventSource
    event_type: EventType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: EventMetadata = Field(default_factory=EventMetadata)
    data: Dict[str, Any] = Field(default_factory=dict)

    @validator('timestamp', pre=True)
    def parse_timestamp(cls, v):
        """Parse timestamp from various formats."""
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except ValueError:
                return datetime.utcnow()
        return v

    def to_eventbridge_entry(self, event_bus_name: str = "default") -> Dict[str, Any]:
        """Convert to EventBridge PutEvents entry format."""
        return {
            "Source": self.source.value,
            "DetailType": self.event_type.value,
            "Detail": json.dumps(self.dict(), default=str),
            "EventBusName": event_bus_name,
            "Time": self.timestamp,
            "Resources": []
        }

    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: str
        }


# Order Events
class OrderData(BaseModel):
    """Order data schema."""

    order_id: str
    user_id: str
    status: str
    total_amount: float
    currency: str = "USD"
    items: List[Dict[str, Any]] = Field(default_factory=list)
    shipping_address: Optional[Dict[str, Any]] = None
    billing_address: Optional[Dict[str, Any]] = None


class OrderCreatedEvent(BaseEvent):
    """Event published when an order is created."""

    source: EventSource = EventSource.ORDERS
    event_type: EventType = EventType.ORDER_CREATED
    data: OrderData

    @classmethod
    def create(cls, order_data: OrderData, metadata: Optional[EventMetadata] = None):
        """Factory method to create OrderCreatedEvent."""
        return cls(
            data=order_data,
            metadata=metadata or EventMetadata()
        )


class OrderUpdatedEvent(BaseEvent):
    """Event published when an order is updated."""

    source: EventSource = EventSource.ORDERS
    event_type: EventType = EventType.ORDER_UPDATED
    data: OrderData
    previous_data: Optional[OrderData] = None

    @classmethod
    def create(cls, order_data: OrderData, previous_data: Optional[OrderData] = None,
               metadata: Optional[EventMetadata] = None):
        """Factory method to create OrderUpdatedEvent."""
        return cls(
            data=order_data,
            previous_data=previous_data,
            metadata=metadata or EventMetadata()
        )


class OrderCancelledEvent(BaseEvent):
    """Event published when an order is cancelled."""

    source: EventSource = EventSource.ORDERS
    event_type: EventType = EventType.ORDER_CANCELLED
    data: Dict[str, Any]
    reason: str

    @classmethod
    def create(cls, order_id: str, reason: str, metadata: Optional[EventMetadata] = None):
        """Factory method to create OrderCancelledEvent."""
        return cls(
            data={"order_id": order_id, "reason": reason},
            reason=reason,
            metadata=metadata or EventMetadata()
        )


# User Events
class UserData(BaseModel):
    """User data schema."""

    user_id: str
    email: str
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    status: str = "active"
    preferences: Dict[str, Any] = Field(default_factory=dict)


class UserRegisteredEvent(BaseEvent):
    """Event published when a user registers."""

    source: EventSource = EventSource.USERS
    event_type: EventType = EventType.USER_REGISTERED
    data: UserData

    @classmethod
    def create(cls, user_data: UserData, metadata: Optional[EventMetadata] = None):
        """Factory method to create UserRegisteredEvent."""
        return cls(
            data=user_data,
            metadata=metadata or EventMetadata()
        )


# Payment Events
class PaymentData(BaseModel):
    """Payment data schema."""

    payment_id: str
    order_id: str
    user_id: str
    amount: float
    currency: str = "USD"
    status: str
    payment_method: str
    transaction_id: Optional[str] = None


class PaymentProcessedEvent(BaseEvent):
    """Event published when a payment is processed."""

    source: EventSource = EventSource.PAYMENTS
    event_type: EventType = EventType.PAYMENT_PROCESSED
    data: PaymentData

    @classmethod
    def create(cls, payment_data: PaymentData, metadata: Optional[EventMetadata] = None):
        """Factory method to create PaymentProcessedEvent."""
        return cls(
            data=payment_data,
            metadata=metadata or EventMetadata()
        )


# Inventory Events
class InventoryData(BaseModel):
    """Inventory data schema."""

    product_id: str
    sku: str
    quantity: int
    reserved_quantity: int = 0
    available_quantity: int
    location: Optional[str] = None
    supplier: Optional[str] = None


class InventoryUpdatedEvent(BaseEvent):
    """Event published when inventory is updated."""

    source: EventSource = EventSource.INVENTORY
    event_type: EventType = EventType.INVENTORY_UPDATED
    data: InventoryData

    @classmethod
    def create(cls, inventory_data: InventoryData, metadata: Optional[EventMetadata] = None):
        """Factory method to create InventoryUpdatedEvent."""
        return cls(
            data=inventory_data,
            metadata=metadata or EventMetadata()
        )


# Notification Events
class NotificationData(BaseModel):
    """Notification data schema."""

    notification_id: str
    recipient_id: str
    channel: str  # email, sms, push, in-app
    subject: Optional[str] = None
    message: str
    template_id: Optional[str] = None
    template_data: Dict[str, Any] = Field(default_factory=dict)
    scheduled_for: Optional[datetime] = None


class NotificationEvent(BaseEvent):
    """Event for notification requests."""

    source: EventSource = EventSource.NOTIFICATIONS
    event_type: EventType = EventType.NOTIFICATION_SENT
    data: NotificationData

    @classmethod
    def create(cls, notification_data: NotificationData, metadata: Optional[EventMetadata] = None):
        """Factory method to create NotificationEvent."""
        return cls(
            data=notification_data,
            metadata=metadata or EventMetadata()
        )


# Audit Events
class AuditData(BaseModel):
    """Audit data schema."""

    entity_type: str
    entity_id: str
    action: str
    actor_id: Optional[str] = None
    actor_type: str = "user"
    before_state: Optional[Dict[str, Any]] = None
    after_state: Optional[Dict[str, Any]] = None
    changes: List[Dict[str, Any]] = Field(default_factory=list)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class AuditEvent(BaseEvent):
    """Event for audit logging."""

    source: EventSource = EventSource.AUDIT
    event_type: EventType = EventType.AUDIT_LOG_CREATED
    data: AuditData

    @classmethod
    def create(cls, audit_data: AuditData, metadata: Optional[EventMetadata] = None):
        """Factory method to create AuditEvent."""
        return cls(
            data=audit_data,
            metadata=metadata or EventMetadata()
        )


# Event Registry for dynamic event creation
EVENT_REGISTRY = {
    EventType.ORDER_CREATED: OrderCreatedEvent,
    EventType.ORDER_UPDATED: OrderUpdatedEvent,
    EventType.ORDER_CANCELLED: OrderCancelledEvent,
    EventType.USER_REGISTERED: UserRegisteredEvent,
    EventType.PAYMENT_PROCESSED: PaymentProcessedEvent,
    EventType.INVENTORY_UPDATED: InventoryUpdatedEvent,
    EventType.NOTIFICATION_SENT: NotificationEvent,
    EventType.AUDIT_LOG_CREATED: AuditEvent,
}


def create_event_from_type(event_type: EventType, data: Dict[str, Any],
                          metadata: Optional[EventMetadata] = None) -> BaseEvent:
    """Factory function to create events dynamically from type."""
    event_class = EVENT_REGISTRY.get(event_type, BaseEvent)

    if event_class == BaseEvent:
        logger.warning(f"Unknown event type: {event_type}, using BaseEvent")
        return BaseEvent(
            source=EventSource.SYSTEM,
            event_type=event_type,
            data=data,
            metadata=metadata or EventMetadata()
        )

    return event_class(data=data, metadata=metadata)


def validate_event_schema(event_data: Dict[str, Any]) -> bool:
    """Validate event data against schema."""
    try:
        BaseEvent(**event_data)
        return True
    except Exception as e:
        logger.error(f"Event schema validation failed: {e}")
        return False
