"""
Input models for request validation using Pydantic.

This module defines all input models used for validating incoming requests
to the Lambda functions, following patterns from the aws-lambda-handler-cookbook.
"""

from typing import Annotated

from pydantic import BaseModel, Field, field_validator


class CreateOrderRequest(BaseModel):
    """Request model for creating a new order."""

    customer_name: Annotated[str, Field(
        min_length=1,
        max_length=50,
        description='Customer name for the order',
        examples=['John Doe', 'Jane Smith']
    )]

    order_item_count: Annotated[int, Field(
        strict=True,
        description='Number of items in the order',
        examples=[1, 5, 10]
    )]

    customer_email: Annotated[str, Field(
        description='Customer email address',
        examples=['john.doe@example.com']
    )]

    notes: Annotated[str | None, Field(
        default=None,
        max_length=500,
        description='Optional notes for the order',
        examples=['Please deliver after 5 PM']
    )] = None

    @field_validator('order_item_count')
    @classmethod
    def validate_order_item_count(cls, v: int) -> int:
        """Validate that order item count is positive."""
        # We don't use Field(gt=0) because pydantic exports it incorrectly to OpenAPI doc
        # See https://github.com/tiangolo/fastapi/issues/240
        if v <= 0:
            raise ValueError('order_item_count must be greater than 0')
        if v > 100:
            raise ValueError('order_item_count cannot exceed 100 items')
        return v

    @field_validator('customer_email')
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        """Validate email format."""
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, v):
            raise ValueError('Invalid email format')
        return v.lower()


class UpdateOrderRequest(BaseModel):
    """Request model for updating an existing order."""

    order_item_count: Annotated[int | None, Field(
        default=None,
        strict=True,
        description='Updated number of items in the order',
        examples=[1, 5, 10]
    )] = None

    notes: Annotated[str | None, Field(
        default=None,
        max_length=500,
        description='Updated notes for the order'
    )] = None

    @field_validator('order_item_count')
    @classmethod
    def validate_order_item_count(cls, v: int | None) -> int | None:
        """Validate that order item count is positive if provided."""
        if v is not None:
            if v <= 0:
                raise ValueError('order_item_count must be greater than 0')
            if v > 100:
                raise ValueError('order_item_count cannot exceed 100 items')
        return v


class HealthCheckRequest(BaseModel):
    """Request model for health check endpoint."""

    include_details: Annotated[bool, Field(
        default=False,
        description='Whether to include detailed health information'
    )] = False
