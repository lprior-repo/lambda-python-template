"""
AWS Lambda Python Template Service Module.

This package contains the core service implementation following the three-layer
architecture pattern from the aws-lambda-handler-cookbook:

- handlers: API handlers and entry points
- logic: Business logic and domain operations
- dal: Data access layer for persistence
- models: Data models and schemas

The service is designed with serverless best practices including:
- Comprehensive observability with AWS Lambda Powertools
- Input validation with Pydantic models
- Dynamic configuration with AWS AppConfig
- Error handling and resilience patterns
- Performance optimization for Lambda cold starts
"""

__version__ = "1.0.0"
__author__ = "Your Organization"
__description__ = "AWS Lambda Python Template with Advanced Patterns"

# Re-export commonly used classes for convenience
from service.models.order import Order, OrderStatus
from service.models.input import CreateOrderRequest, UpdateOrderRequest
from service.models.output import CreateOrderOutput, GetOrderOutput
from service.handlers.utils.observability import logger, tracer, metrics

__all__ = [
    "Order",
    "OrderStatus",
    "CreateOrderRequest",
    "UpdateOrderRequest",
    "CreateOrderOutput",
    "GetOrderOutput",
    "logger",
    "tracer",
    "metrics",
]
