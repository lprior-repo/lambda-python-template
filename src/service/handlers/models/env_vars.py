"""
Environment variable models for type-safe configuration.

This module defines Pydantic models for environment variables used by Lambda handlers,
providing type safety and validation following patterns from the aws-lambda-handler-cookbook.
"""

from typing import Annotated

from aws_lambda_env_modeler import BaseEnvModel, get_environment_variables
from pydantic import Field


class MyHandlerEnvVars(BaseEnvModel):
    """Environment variables for Lambda handlers."""

    # DynamoDB table name for storing orders
    TABLE_NAME: Annotated[str, Field(
        description='DynamoDB table name for order storage',
        min_length=1
    )]

    # AWS region
    AWS_REGION: Annotated[str, Field(
        default='us-east-1',
        description='AWS region for service deployment'
    )] = 'us-east-1'

    # Environment name (dev, staging, prod)
    ENVIRONMENT: Annotated[str, Field(
        default='dev',
        description='Deployment environment name',
        pattern=r'^(dev|staging|prod)$'
    )] = 'dev'

    # Application version
    APP_VERSION: Annotated[str, Field(
        default='1.0.0',
        description='Application version string'
    )] = '1.0.0'

    # Service name for observability
    POWERTOOLS_SERVICE_NAME: Annotated[str, Field(
        default='lambda-python-template',
        description='Service name for AWS Powertools'
    )] = 'lambda-python-template'

    # Metrics namespace
    POWERTOOLS_METRICS_NAMESPACE: Annotated[str, Field(
        default='LambdaTemplate',
        description='Namespace for CloudWatch metrics'
    )] = 'LambdaTemplate'

    # Log level for AWS Powertools Logger
    LOG_LEVEL: Annotated[str, Field(
        default='INFO',
        description='Log level for application logging',
        pattern=r'^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$'
    )] = 'INFO'

    # Enable/disable X-Ray tracing
    POWERTOOLS_TRACE_DISABLED: Annotated[str, Field(
        default='false',
        description='Disable X-Ray tracing (true/false)',
        pattern=r'^(true|false)$'
    )] = 'false'

    # Feature flags configuration
    CONFIGURATION_NAME: Annotated[str, Field(
        default='lambda-python-template-config',
        description='AWS AppConfig configuration name for feature flags'
    )] = 'lambda-python-template-config'

    CONFIGURATION_MAX_AGE_MINUTES: Annotated[int, Field(
        default=5,
        description='Maximum age in minutes for cached configuration',
        ge=1,
        le=60
    )] = 5

    # Database connection settings
    DB_CONNECTION_TIMEOUT: Annotated[int, Field(
        default=30,
        description='Database connection timeout in seconds',
        ge=1,
        le=300
    )] = 30

    DB_MAX_RETRIES: Annotated[int, Field(
        default=3,
        description='Maximum number of database operation retries',
        ge=0,
        le=10
    )] = 3

    # API Gateway settings
    CORS_ALLOW_ORIGIN: Annotated[str, Field(
        default='*',
        description='CORS allowed origins for API responses'
    )] = '*'

    CORS_ALLOW_HEADERS: Annotated[str, Field(
        default='Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        description='CORS allowed headers for API requests'
    )] = 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'

    CORS_ALLOW_METHODS: Annotated[str, Field(
        default='GET,POST,PUT,DELETE,OPTIONS',
        description='CORS allowed HTTP methods'
    )] = 'GET,POST,PUT,DELETE,OPTIONS'

    # Security settings
    ENABLE_REQUEST_VALIDATION: Annotated[str, Field(
        default='true',
        description='Enable request validation (true/false)',
        pattern=r'^(true|false)$'
    )] = 'true'

    MAX_REQUEST_SIZE_KB: Annotated[int, Field(
        default=1024,
        description='Maximum request size in kilobytes',
        ge=1,
        le=10240
    )] = 1024

    # Performance settings
    LAMBDA_TIMEOUT_SECONDS: Annotated[int, Field(
        default=30,
        description='Lambda function timeout in seconds',
        ge=1,
        le=900
    )] = 30

    LAMBDA_MEMORY_MB: Annotated[int, Field(
        default=512,
        description='Lambda function memory allocation in MB',
        ge=128,
        le=10240
    )] = 512

    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.ENVIRONMENT == 'dev'

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.ENVIRONMENT == 'prod'

    @property
    def tracing_enabled(self) -> bool:
        """Check if X-Ray tracing is enabled."""
        return self.POWERTOOLS_TRACE_DISABLED.lower() == 'false'

    @property
    def request_validation_enabled(self) -> bool:
        """Check if request validation is enabled."""
        return self.ENABLE_REQUEST_VALIDATION.lower() == 'true'


# Utility function to get typed environment variables
def get_handler_env_vars() -> MyHandlerEnvVars:
    """
    Get typed environment variables for Lambda handlers.

    Returns:
        Validated environment variables model instance
    """
    return get_environment_variables(model=MyHandlerEnvVars)
