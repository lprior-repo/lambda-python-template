"""
AWS Lambda Handlers Module.

This module contains the Lambda function handlers that serve as entry points
for the serverless application. Each handler implements the three-layer
architecture pattern:

1. Handler Layer (this module): Request/response handling, validation, routing
2. Logic Layer: Business logic and domain operations
3. Data Access Layer: Persistence and external service integration

The handlers use AWS Lambda Powertools for:
- Structured logging with correlation IDs
- Distributed tracing with X-Ray
- Custom metrics collection
- Input validation and serialization
- OpenAPI documentation generation

Handler Types:
- REST API handlers: Process HTTP requests via API Gateway
- Event handlers: Process AWS service events (SQS, SNS, etc.)
- Scheduled handlers: Process CloudWatch Events/EventBridge triggers
"""

__version__ = "1.0.0"

# Re-export handler utilities for convenience
from service.handlers.utils.observability import logger, tracer, metrics
from service.handlers.utils.rest_api_resolver import app, ORDERS_PATH, HEALTH_PATH

__all__ = [
    "logger",
    "tracer",
    "metrics",
    "app",
    "ORDERS_PATH",
    "HEALTH_PATH",
]
