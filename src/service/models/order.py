"""
Order domain model for the business logic layer.

This module defines the core Order entity used throughout the application,
following domain-driven design patterns from the aws-lambda-handler-cookbook.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class OrderStatus(str, Enum):
    """Order status enumeration."""

    PENDING = 'pending'
    CONFIRMED = 'confirmed'
    PROCESSING = 'processing'
    SHIPPED = 'shipped'
    DELIVERED = 'delivered'
    CANCELLED = 'cancelled'
    REFUNDED = 'refunded'


class Order(BaseModel):
    """Core Order domain model."""

    id: Annotated[str, Field(
        description='Unique identifier for the order',
        examples=['ord_1234567890abcdef']
    )]

    customer_name: Annotated[str, Field(
        min_length=1,
        max_length=50,
        description='Customer name for the order',
        examples=['John Doe']
    )]

    customer_email: Annotated[str, Field(
        description='Customer email address',
        examples=['john.doe@example.com']
    )]

    order_item_count: Annotated[int, Field(
        gt=0,
        le=100,
        description='Number of items in the order',
        examples=[5]
    )]

    status: Annotated[OrderStatus, Field(
        default=OrderStatus.PENDING,
        description='Current status of the order'
    )] = OrderStatus.PENDING

    notes: Annotated[Optional[str], Field(
        default=None,
        max_length=500,
        description='Optional notes for the order'
    )] = None

    created_at: Annotated[str, Field(
        description='ISO timestamp when the order was created'
    )]

    updated_at: Annotated[str, Field(
        description='ISO timestamp when the order was last updated'
    )]

    estimated_delivery: Annotated[Optional[str], Field(
        default=None,
        description='Estimated delivery ISO timestamp'
    )] = None

    total_amount: Annotated[float, Field(
        ge=0,
        description='Total order amount',
        examples=[29.99]
    )]

    cancellation_reason: Annotated[Optional[str], Field(
        default=None,
        max_length=200,
        description='Reason for cancellation if cancelled'
    )] = None

    @field_validator('customer_email')
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        """Validate email format."""
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, v):
            raise ValueError('Invalid email format')
        return v.lower()

    @classmethod
    def create(
        cls,
        customer_name: str,
        customer_email: str,
        order_item_count: int,
        notes: Optional[str] = None,
        total_amount: Optional[float] = None
    ) -> 'Order':
        """
        Create a new order with generated ID and timestamps.

        Args:
            customer_name: Name of the customer placing the order
            customer_email: Email address of the customer
            order_item_count: Number of items in the order
            notes: Optional notes for the order
            total_amount: Total order amount (calculated if not provided)

        Returns:
            New Order instance with generated fields
        """
        now = datetime.now(timezone.utc).isoformat()
        order_id = str(uuid4())

        # Calculate order total if not provided (simple example)
        if total_amount is None:
            base_price = 50.0  # $50 per item
            total_amount = round(order_item_count * base_price, 2)

        return cls(
            id=order_id,
            customer_name=customer_name,
            customer_email=customer_email,
            order_item_count=order_item_count,
            status=OrderStatus.PENDING,
            notes=notes,
            created_at=now,
            updated_at=now,
            total_amount=total_amount
        )

    def update_item_count(self, new_count: int) -> None:
        """
        Update the item count and recalculate total.

        Args:
            new_count: New number of items
        """
        if new_count <= 0:
            raise ValueError("Item count must be greater than 0")
        if new_count > 100:
            raise ValueError("Item count cannot exceed 100")

        self.order_item_count = new_count
        self.updated_at = datetime.now(timezone.utc).isoformat()

        # Recalculate order total
        base_price = 50.0
        self.total_amount = round(new_count * base_price, 2)

    def update_status(self, new_status: OrderStatus) -> None:
        """
        Update the order status.

        Args:
            new_status: New status for the order
        """
        self.status = new_status
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_notes(self, additional_notes: str) -> None:
        """
        Add or update notes for the order.

        Args:
            additional_notes: Notes to add or replace existing notes
        """
        if len(additional_notes) > 500:
            raise ValueError("Notes cannot exceed 500 characters")

        self.notes = additional_notes
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def can_be_cancelled(self) -> bool:
        """
        Check if the order can be cancelled.

        Returns:
            True if the order can be cancelled, False otherwise
        """
        return self.status in [
            OrderStatus.PENDING,
            OrderStatus.CONFIRMED,
            OrderStatus.PROCESSING
        ]

    def cancel(self, reason: str) -> None:
        """
        Cancel the order if it's in a cancellable state.

        Args:
            reason: Reason for cancellation

        Raises:
            ValueError: If the order cannot be cancelled
        """
        if not self.can_be_cancelled():
            raise ValueError(f"Cannot cancel order with status: {self.status}")

        self.status = OrderStatus.CANCELLED
        self.cancellation_reason = reason
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def can_transition_to(self, new_status: OrderStatus) -> bool:
        """
        Check if the order can transition to a new status.

        Args:
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
            OrderStatus.DELIVERED: [OrderStatus.REFUNDED],
            OrderStatus.CANCELLED: [],  # Final state
            OrderStatus.REFUNDED: [],  # Final state
        }

        allowed_statuses = valid_transitions.get(self.status, [])
        return new_status in allowed_statuses

    def is_final_status(self) -> bool:
        """
        Check if the order is in a final status (no further transitions allowed).

        Returns:
            True if in final status, False otherwise
        """
        return self.status in [OrderStatus.DELIVERED, OrderStatus.CANCELLED, OrderStatus.REFUNDED]

    def get_days_since_created(self) -> int:
        """
        Get the number of days since the order was created.

        Returns:
            Number of days since creation
        """
        created_datetime = datetime.fromisoformat(self.created_at.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        return (now - created_datetime).days

    def to_dict(self) -> dict:
        """
        Convert the order to a dictionary for storage.

        Returns:
            Dictionary representation of the order
        """
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_email': self.customer_email,
            'order_item_count': self.order_item_count,
            'status': self.status.value,
            'notes': self.notes,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'estimated_delivery': self.estimated_delivery,
            'total_amount': self.total_amount,
            'cancellation_reason': self.cancellation_reason
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Order':
        """
        Create an Order instance from a dictionary.

        Args:
            data: Dictionary containing order data

        Returns:
            Order instance created from the dictionary
        """
        return cls(
            id=data['id'],
            customer_name=data['customer_name'],
            customer_email=data['customer_email'],
            order_item_count=data['order_item_count'],
            status=OrderStatus(data['status']),
            notes=data.get('notes'),
            created_at=data['created_at'],
            updated_at=data['updated_at'],
            estimated_delivery=data.get('estimated_delivery'),
            total_amount=data['total_amount'],
            cancellation_reason=data.get('cancellation_reason')
        )

    class Config:
        """Pydantic configuration."""

        # Enable JSON schema generation
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "customer_name": "John Doe",
                "customer_email": "john.doe@example.com",
                "order_item_count": 5,
                "status": "pending",
                "notes": "Please deliver after 5 PM",
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:30:00Z",
                "estimated_delivery": "2024-01-18T15:00:00Z",
                "total_amount": 250.0,
                "cancellation_reason": None
            }
        }
