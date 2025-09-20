"""
Service Models Package

This package contains all Pydantic models used throughout the service,
including input validation models, output response models, and domain models.
"""

from .input import CreateOrderRequest, UpdateOrderRequest, HealthCheckRequest
from .output import (
    CreateOrderOutput,
    GetOrderOutput,
    UpdateOrderOutput,
    HealthCheckOutput,
    ErrorOutput,
    InternalServerErrorOutput,
    ValidationErrorOutput,
    NotFoundErrorOutput
)
from .order import Order, OrderStatus

__all__ = [
    # Input models
    "CreateOrderRequest",
    "UpdateOrderRequest",
    "HealthCheckRequest",

    # Output models
    "CreateOrderOutput",
    "GetOrderOutput",
    "UpdateOrderOutput",
    "HealthCheckOutput",
    "ErrorOutput",
    "InternalServerErrorOutput",
    "ValidationErrorOutput",
    "NotFoundErrorOutput",

    # Domain models
    "Order",
    "OrderStatus"
]
