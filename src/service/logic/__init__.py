"""
Business Logic Layer Module.

This module contains the core business logic and domain operations for the
AWS Lambda Python Template service. It implements the middle layer of the
three-layer architecture pattern from the aws-lambda-handler-cookbook.

The logic layer is responsible for:
- Implementing business rules and domain logic
- Coordinating between handlers and data access layers
- Managing feature flags and dynamic configuration
- Handling idempotency for API operations
- Implementing business workflows and processes
- Validating business constraints beyond input validation

Key Patterns Implemented:
- Domain-driven design principles
- Command/Query separation
- Idempotent operations using AWS Lambda Powertools
- Feature flag evaluation for A/B testing and gradual rollouts
- Business rule validation and enforcement
- Audit logging for business operations

Architecture Benefits:
- Separation of concerns: Business logic isolated from infrastructure
- Testability: Pure functions that are easy to unit test
- Reusability: Logic can be shared across different handlers
- Maintainability: Business rules centralized in one layer
- Extensibility: Easy to add new business operations
"""

__version__ = "1.0.0"

# Re-export commonly used business logic functions for convenience
try:
    from service.logic.create_order import create_order
    from service.logic.update_order import update_order
    from service.logic.get_order import get_order
    from service.logic.health_check import health_check

    __all__ = [
        "create_order",
        "update_order",
        "get_order",
        "health_check",
    ]
except ImportError:
    # Business logic modules may not be implemented yet
    __all__ = []
