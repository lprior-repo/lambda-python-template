"""
Idempotency and error handling utilities for AWS Lambda handlers.

This module provides utilities for implementing idempotency patterns and
enhanced error handling, following patterns from the aws-lambda-handler-cookbook.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from aws_lambda_powertools.utilities.idempotency import (
    DynamoDBPersistenceLayer,
    IdempotencyConfig,
    idempotent,
    idempotent_function,
)
from aws_lambda_powertools.utilities.idempotency.exceptions import (
    IdempotencyAlreadyInProgressError,
    IdempotencyInconsistentStateError,
    IdempotencyItemAlreadyExistsError,
    IdempotencyKeyError,
    IdempotencyPersistenceLayerError,
    IdempotencyValidationError,
)
from pydantic import BaseModel, Field

from service.handlers.utils.observability import logger, metrics, tracer


class ErrorSeverity(str, Enum):
    """Error severity levels for classification."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ErrorCategory(str, Enum):
    """Error categories for classification."""
    VALIDATION = "VALIDATION"
    BUSINESS_LOGIC = "BUSINESS_LOGIC"
    EXTERNAL_SERVICE = "EXTERNAL_SERVICE"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    SECURITY = "SECURITY"
    TIMEOUT = "TIMEOUT"
    RATE_LIMIT = "RATE_LIMIT"


class ErrorContext(BaseModel):
    """Context information for errors."""

    request_id: str = Field(description="Unique request identifier")
    user_id: Optional[str] = Field(default=None, description="User identifier if available")
    operation: str = Field(description="Operation being performed")
    resource_id: Optional[str] = Field(default=None, description="Resource identifier")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    additional_data: Dict[str, Any] = Field(default_factory=dict)


class BaseServiceError(Exception):
    """Base exception class for service errors."""

    def __init__(
        self,
        message: str,
        error_code: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.BUSINESS_LOGIC,
        context: Optional[ErrorContext] = None,
        retry_after: Optional[int] = None,
        user_message: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.severity = severity
        self.category = category
        self.context = context
        self.retry_after = retry_after
        self.user_message = user_message or "An error occurred while processing your request."
        self.error_id = str(uuid.uuid4())

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for logging and response."""
        return {
            "error_id": self.error_id,
            "error_code": self.error_code,
            "message": self.message,
            "user_message": self.user_message,
            "severity": self.severity.value,
            "category": self.category.value,
            "retry_after": self.retry_after,
            "context": self.context.model_dump() if self.context else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class ValidationError(BaseServiceError):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str,
        field_errors: Optional[List[Dict[str, str]]] = None,
        context: Optional[ErrorContext] = None,
    ):
        super().__init__(
            message=message,
            error_code="VALIDATION_ERROR",
            severity=ErrorSeverity.LOW,
            category=ErrorCategory.VALIDATION,
            context=context,
            user_message="Invalid input provided. Please check your request and try again.",
        )
        self.field_errors = field_errors or []


class BusinessLogicError(BaseServiceError):
    """Raised when business logic validation fails."""

    def __init__(
        self,
        message: str,
        error_code: str = "BUSINESS_LOGIC_ERROR",
        context: Optional[ErrorContext] = None,
        user_message: Optional[str] = None,
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.BUSINESS_LOGIC,
            context=context,
            user_message=user_message,
        )


class ExternalServiceError(BaseServiceError):
    """Raised when external service calls fail."""

    def __init__(
        self,
        message: str,
        service_name: str,
        error_code: str = "EXTERNAL_SERVICE_ERROR",
        retry_after: Optional[int] = None,
        context: Optional[ErrorContext] = None,
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.EXTERNAL_SERVICE,
            context=context,
            retry_after=retry_after,
            user_message="A required service is temporarily unavailable. Please try again later.",
        )
        self.service_name = service_name


class ResourceNotFoundError(BaseServiceError):
    """Raised when a requested resource is not found."""

    def __init__(
        self,
        resource_type: str,
        resource_id: str,
        context: Optional[ErrorContext] = None,
    ):
        message = f"{resource_type} with ID '{resource_id}' not found"
        super().__init__(
            message=message,
            error_code="RESOURCE_NOT_FOUND",
            severity=ErrorSeverity.LOW,
            category=ErrorCategory.BUSINESS_LOGIC,
            context=context,
            user_message=f"The requested {resource_type.lower()} was not found.",
        )
        self.resource_type = resource_type
        self.resource_id = resource_id


class RateLimitError(BaseServiceError):
    """Raised when rate limits are exceeded."""

    def __init__(
        self,
        limit: int,
        window_seconds: int,
        retry_after: int,
        context: Optional[ErrorContext] = None,
    ):
        message = f"Rate limit exceeded: {limit} requests per {window_seconds} seconds"
        super().__init__(
            message=message,
            error_code="RATE_LIMIT_EXCEEDED",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.RATE_LIMIT,
            context=context,
            retry_after=retry_after,
            user_message=f"Too many requests. Please try again in {retry_after} seconds.",
        )
        self.limit = limit
        self.window_seconds = window_seconds


class IdempotencyManager:
    """Manager for handling idempotency patterns."""

    def __init__(
        self,
        table_name: str,
        event_key_jmespath: str = "[body, queryStringParameters]",
        payload_validation_jmespath: str = "body",
        expires_after_seconds: int = 3600,  # 1 hour
        use_local_cache: bool = True,
        local_cache_max_items: int = 1000,
        hash_function: str = "md5",
    ):
        """
        Initialize idempotency manager.

        Args:
            table_name: DynamoDB table name for persistence
            event_key_jmespath: JMESPath to extract idempotency key from event
            payload_validation_jmespath: JMESPath to extract payload for validation
            expires_after_seconds: How long to keep idempotency records
            use_local_cache: Whether to use local caching
            local_cache_max_items: Maximum items in local cache
            hash_function: Hash function for generating keys
        """
        self.persistence_layer = DynamoDBPersistenceLayer(table_name=table_name)

        self.config = IdempotencyConfig(
            event_key_jmespath=event_key_jmespath,
            payload_validation_jmespath=payload_validation_jmespath,
            expires_after_seconds=expires_after_seconds,
            use_local_cache=use_local_cache,
            local_cache_max_items=local_cache_max_items,
            hash_function=hash_function,
        )

    def make_idempotent(self, func):
        """Decorator to make a function idempotent."""
        return idempotent_function(
            data_keyword_argument="event",
            persistence_store=self.persistence_layer,
            config=self.config,
        )(func)

    def make_handler_idempotent(self, func):
        """Decorator to make a Lambda handler idempotent."""
        return idempotent(
            persistence_store=self.persistence_layer,
            config=self.config,
        )(func)


def create_error_context(
    request_id: str,
    operation: str,
    user_id: Optional[str] = None,
    resource_id: Optional[str] = None,
    **additional_data: Any,
) -> ErrorContext:
    """Create an error context for consistent error handling."""
    return ErrorContext(
        request_id=request_id,
        user_id=user_id,
        operation=operation,
        resource_id=resource_id,
        additional_data=additional_data,
    )


def handle_idempotency_errors(func):
    """Decorator to handle idempotency-related errors gracefully."""

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)

        except IdempotencyAlreadyInProgressError as e:
            logger.warning("Idempotency collision detected - request already in progress", extra={
                "idempotency_key": e.idempotency_key,
                "function_name": func.__name__,
            })
            raise BusinessLogicError(
                message="Request is already being processed",
                error_code="REQUEST_IN_PROGRESS",
                user_message="Your request is already being processed. Please wait for completion.",
            )

        except IdempotencyItemAlreadyExistsError as e:
            logger.info("Returning cached idempotent response", extra={
                "idempotency_key": e.idempotency_key,
                "function_name": func.__name__,
            })
            # This should return the cached response - handled by powertools
            raise

        except IdempotencyKeyError as e:
            logger.error("Invalid idempotency key", extra={
                "error": str(e),
                "function_name": func.__name__,
            })
            raise ValidationError(
                message="Unable to generate idempotency key from request",
                context=create_error_context(
                    request_id=str(uuid.uuid4()),
                    operation=func.__name__,
                    error_details=str(e),
                ),
            )

        except IdempotencyValidationError as e:
            logger.error("Idempotency validation failed", extra={
                "error": str(e),
                "function_name": func.__name__,
            })
            raise ValidationError(
                message="Request payload validation failed for idempotency",
                context=create_error_context(
                    request_id=str(uuid.uuid4()),
                    operation=func.__name__,
                    error_details=str(e),
                ),
            )

        except IdempotencyInconsistentStateError as e:
            logger.error("Idempotency state inconsistency detected", extra={
                "error": str(e),
                "function_name": func.__name__,
            })
            raise BaseServiceError(
                message="Idempotency state inconsistency detected",
                error_code="IDEMPOTENCY_INCONSISTENT_STATE",
                severity=ErrorSeverity.HIGH,
                category=ErrorCategory.INFRASTRUCTURE,
                context=create_error_context(
                    request_id=str(uuid.uuid4()),
                    operation=func.__name__,
                    error_details=str(e),
                ),
            )

        except IdempotencyPersistenceLayerError as e:
            logger.error("Idempotency persistence layer error", extra={
                "error": str(e),
                "function_name": func.__name__,
            })
            raise BaseServiceError(
                message="Idempotency service temporarily unavailable",
                error_code="IDEMPOTENCY_SERVICE_ERROR",
                severity=ErrorSeverity.HIGH,
                category=ErrorCategory.INFRASTRUCTURE,
                context=create_error_context(
                    request_id=str(uuid.uuid4()),
                    operation=func.__name__,
                    error_details=str(e),
                ),
                retry_after=30,
            )

    return wrapper


@tracer.capture_method
def log_error_metrics(error: BaseServiceError) -> None:
    """Log error metrics for monitoring and alerting."""

    # Add error metrics
    metrics.add_metric(name="ErrorCount", unit="Count", value=1)
    metrics.add_metric(name=f"Error{error.category.value}Count", unit="Count", value=1)
    metrics.add_metric(name=f"Error{error.severity.value}Count", unit="Count", value=1)

    # Add trace annotations
    tracer.put_annotation("error_code", error.error_code)
    tracer.put_annotation("error_severity", error.severity.value)
    tracer.put_annotation("error_category", error.category.value)

    # Add trace metadata
    tracer.put_metadata("error_details", error.to_dict())

    # Log structured error
    logger.error(
        "Service error occurred",
        extra={
            "error_id": error.error_id,
            "error_code": error.error_code,
            "error_severity": error.severity.value,
            "error_category": error.category.value,
            "error_message": error.message,
            "user_message": error.user_message,
            "context": error.context.model_dump() if error.context else None,
        }
    )


def format_error_response(
    error: BaseServiceError,
    include_details: bool = False,
) -> Dict[str, Any]:
    """Format error for API response."""

    response = {
        "error": {
            "code": error.error_code,
            "message": error.user_message,
            "error_id": error.error_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    }

    if error.retry_after:
        response["retry_after"] = error.retry_after

    if include_details and error.context:
        response["error"]["details"] = {
            "operation": error.context.operation,
            "resource_id": error.context.resource_id,
        }

    # Add field errors for validation errors
    if isinstance(error, ValidationError) and error.field_errors:
        response["error"]["field_errors"] = error.field_errors

    return response


def get_http_status_code(error: BaseServiceError) -> int:
    """Get appropriate HTTP status code for error."""

    status_mapping = {
        "VALIDATION_ERROR": 400,
        "RESOURCE_NOT_FOUND": 404,
        "BUSINESS_LOGIC_ERROR": 422,
        "RATE_LIMIT_EXCEEDED": 429,
        "EXTERNAL_SERVICE_ERROR": 502,
        "REQUEST_IN_PROGRESS": 409,
        "IDEMPOTENCY_INCONSISTENT_STATE": 500,
        "IDEMPOTENCY_SERVICE_ERROR": 503,
    }

    return status_mapping.get(error.error_code, 500)


# Global idempotency manager instance
# This will be configured by the handler based on environment variables
idempotency_manager: Optional[IdempotencyManager] = None


def get_idempotency_manager() -> IdempotencyManager:
    """Get or create the global idempotency manager instance."""
    global idempotency_manager

    if idempotency_manager is None:
        import os
        table_name = os.environ.get("IDEMPOTENCY_TABLE_NAME", "idempotency-table")
        idempotency_manager = IdempotencyManager(table_name=table_name)

    return idempotency_manager


def create_api_response(
    status_code: int,
    body: Any,
    headers: Optional[Dict[str, str]] = None,
    cors_enabled: bool = True,
) -> Dict[str, Any]:
    """Create standardized API Gateway response."""

    default_headers = {
        "Content-Type": "application/json",
        "X-Request-ID": str(uuid.uuid4()),
    }

    if cors_enabled:
        default_headers.update({
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE",
        })

    if headers:
        default_headers.update(headers)

    return {
        "statusCode": status_code,
        "headers": default_headers,
        "body": body if isinstance(body, str) else str(body),
    }
