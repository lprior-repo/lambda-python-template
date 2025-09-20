"""
Output models for API responses using Pydantic.

This module defines all output models used for structuring responses
from the Lambda functions, following patterns from the aws-lambda-handler-cookbook.
"""

from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, Field


class CreateOrderOutput(BaseModel):
    """Response model for successful order creation."""

    id: Annotated[str, Field(
        description='Unique identifier for the created order',
        examples=['ord_1234567890abcdef']
    )]

    customer_name: Annotated[str, Field(
        description='Customer name for the order',
        examples=['John Doe']
    )]

    customer_email: Annotated[str, Field(
        description='Customer email address',
        examples=['john.doe@example.com']
    )]

    item_count: Annotated[int, Field(
        description='Number of items in the order',
        examples=[5]
    )]

    status: Annotated[str, Field(
        description='Current status of the order',
        examples=['pending', 'confirmed', 'processing']
    )]

    notes: Annotated[str | None, Field(
        default=None,
        description='Optional notes for the order'
    )] = None

    created_at: Annotated[datetime, Field(
        description='Timestamp when the order was created'
    )]

    estimated_delivery: Annotated[datetime | None, Field(
        default=None,
        description='Estimated delivery timestamp'
    )] = None

    order_total: Annotated[float, Field(
        description='Total order amount',
        examples=[29.99]
    )]


class GetOrderOutput(BaseModel):
    """Response model for retrieving an order."""

    id: Annotated[str, Field(
        description='Unique identifier for the order',
        examples=['ord_1234567890abcdef']
    )]

    customer_name: Annotated[str, Field(
        description='Customer name for the order',
        examples=['John Doe']
    )]

    customer_email: Annotated[str, Field(
        description='Customer email address',
        examples=['john.doe@example.com']
    )]

    item_count: Annotated[int, Field(
        description='Number of items in the order',
        examples=[5]
    )]

    status: Annotated[str, Field(
        description='Current status of the order',
        examples=['pending', 'confirmed', 'processing', 'shipped', 'delivered']
    )]

    notes: Annotated[str | None, Field(
        default=None,
        description='Optional notes for the order'
    )] = None

    created_at: Annotated[datetime, Field(
        description='Timestamp when the order was created'
    )]

    updated_at: Annotated[datetime, Field(
        description='Timestamp when the order was last updated'
    )]

    estimated_delivery: Annotated[datetime | None, Field(
        default=None,
        description='Estimated delivery timestamp'
    )] = None

    order_total: Annotated[float, Field(
        description='Total order amount',
        examples=[29.99]
    )]


class UpdateOrderOutput(BaseModel):
    """Response model for successful order update."""

    id: Annotated[str, Field(
        description='Unique identifier for the updated order',
        examples=['ord_1234567890abcdef']
    )]

    customer_name: Annotated[str, Field(
        description='Customer name for the order',
        examples=['John Doe']
    )]

    item_count: Annotated[int, Field(
        description='Updated number of items in the order',
        examples=[7]
    )]

    status: Annotated[str, Field(
        description='Current status of the order',
        examples=['pending', 'confirmed', 'processing']
    )]

    notes: Annotated[str | None, Field(
        default=None,
        description='Updated notes for the order'
    )] = None

    updated_at: Annotated[datetime, Field(
        description='Timestamp when the order was updated'
    )]

    order_total: Annotated[float, Field(
        description='Updated total order amount',
        examples=[34.99]
    )]


class HealthCheckOutput(BaseModel):
    """Response model for health check endpoint."""

    status: Annotated[str, Field(
        description='Health status of the service',
        examples=['healthy', 'degraded', 'unhealthy']
    )]

    timestamp: Annotated[datetime, Field(
        description='Timestamp of the health check'
    )]

    version: Annotated[str, Field(
        description='Application version',
        examples=['1.0.0']
    )]

    service: Annotated[str, Field(
        description='Service name',
        examples=['lambda-python-template']
    )]

    environment: Annotated[str, Field(
        description='Deployment environment',
        examples=['dev', 'staging', 'prod']
    )]

    request_id: Annotated[str, Field(
        description='Request correlation ID',
        examples=['req_1234567890abcdef']
    )]

    checks: Annotated[dict[str, Any] | None, Field(
        default=None,
        description='Detailed health check results when requested'
    )] = None


class ErrorOutput(BaseModel):
    """Standard error response model."""

    error: Annotated[str, Field(
        description='Error type or code',
        examples=['ValidationError', 'NotFound', 'InternalServerError']
    )]

    message: Annotated[str, Field(
        description='Human-readable error message',
        examples=['Invalid input provided', 'Order not found', 'Internal server error occurred']
    )]

    details: Annotated[dict[str, Any] | None, Field(
        default=None,
        description='Additional error details'
    )] = None

    timestamp: Annotated[datetime, Field(
        description='Timestamp when the error occurred'
    )]

    request_id: Annotated[str, Field(
        description='Request correlation ID for debugging',
        examples=['req_1234567890abcdef']
    )]

    trace_id: Annotated[str | None, Field(
        default=None,
        description='X-Ray trace ID for distributed tracing'
    )] = None


class InternalServerErrorOutput(BaseModel):
    """Response model for internal server errors (5xx)."""

    error: Annotated[str, Field(
        default='InternalServerError',
        description='Error type'
    )] = 'InternalServerError'

    message: Annotated[str, Field(
        default='An internal server error occurred',
        description='Error message'
    )] = 'An internal server error occurred'

    timestamp: Annotated[datetime, Field(
        description='Timestamp when the error occurred'
    )]

    request_id: Annotated[str, Field(
        description='Request correlation ID for debugging'
    )]

    trace_id: Annotated[str | None, Field(
        default=None,
        description='X-Ray trace ID for distributed tracing'
    )] = None


class ValidationErrorOutput(BaseModel):
    """Response model for validation errors (4xx)."""

    error: Annotated[str, Field(
        default='ValidationError',
        description='Error type'
    )] = 'ValidationError'

    message: Annotated[str, Field(
        description='Validation error message',
        examples=['Invalid input provided']
    )]

    validation_errors: Annotated[list[dict[str, Any]], Field(
        description='Detailed validation error information',
        examples=[[{
            'field': 'customer_name',
            'message': 'Field required',
            'type': 'missing'
        }]]
    )]

    timestamp: Annotated[datetime, Field(
        description='Timestamp when the error occurred'
    )]

    request_id: Annotated[str, Field(
        description='Request correlation ID for debugging'
    )]


class NotFoundErrorOutput(BaseModel):
    """Response model for not found errors (404)."""

    error: Annotated[str, Field(
        default='NotFound',
        description='Error type'
    )] = 'NotFound'

    message: Annotated[str, Field(
        description='Not found error message',
        examples=['Order not found']
    )]

    resource_type: Annotated[str, Field(
        description='Type of resource that was not found',
        examples=['order', 'customer']
    )]

    resource_id: Annotated[str, Field(
        description='ID of the resource that was not found',
        examples=['ord_1234567890abcdef']
    )]

    timestamp: Annotated[datetime, Field(
        description='Timestamp when the error occurred'
    )]

    request_id: Annotated[str, Field(
        description='Request correlation ID for debugging'
    )]
