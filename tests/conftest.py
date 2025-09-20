"""
Pytest configuration and shared fixtures for the Lambda Python Template.

This module provides common test fixtures and configuration used across
unit, integration, and end-to-end tests.
"""

import os
import pytest
from datetime import datetime
from typing import Generator, Dict, Any
from unittest.mock import Mock, patch

import boto3
from moto import mock_dynamodb

from service.models.order import Order, OrderStatus


# Test environment configuration
@pytest.fixture(scope="session", autouse=True)
def test_environment():
    """Set up test environment variables."""
    os.environ.update({
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_ACCESS_KEY_ID": "test",
        "AWS_SECRET_ACCESS_KEY": "test",
        "TABLE_NAME": "test-orders-table",
        "ENVIRONMENT": "test",
        "APP_VERSION": "test-1.0.0",
        "POWERTOOLS_SERVICE_NAME": "test-lambda-python-template",
        "POWERTOOLS_METRICS_NAMESPACE": "TestLambdaTemplate",
        "LOG_LEVEL": "DEBUG",
        "POWERTOOLS_TRACE_DISABLED": "true",  # Disable X-Ray in tests
        "CONFIGURATION_NAME": "test-config",
        "CONFIGURATION_MAX_AGE_MINUTES": "1",
    })


# DynamoDB fixtures
@pytest.fixture
def dynamodb_table():
    """Create a mock DynamoDB table for testing."""
    with mock_dynamodb():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

        # Create table with proper schema
        table = dynamodb.create_table(
            TableName="test-orders-table",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "gsi1pk", "AttributeType": "S"},
                {"AttributeName": "gsi1sk", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "gsi1pk", "KeyType": "HASH"},
                        {"AttributeName": "gsi1sk", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 5,
                        "WriteCapacityUnits": 5,
                    },
                }
            ],
            BillingMode="PROVISIONED",
            ProvisionedThroughput={
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            },
        )

        # Wait for table to be created
        table.wait_until_exists()
        yield table


# Sample data fixtures
@pytest.fixture
def sample_order() -> Order:
    """Create a sample order for testing."""
    return Order.create(
        customer_name="John Doe",
        customer_email="john.doe@example.com",
        item_count=3,
        notes="Test order for unit testing"
    )


@pytest.fixture
def sample_order_data() -> Dict[str, Any]:
    """Sample order data for request testing."""
    return {
        "customer_name": "Jane Smith",
        "customer_email": "jane.smith@example.com",
        "order_item_count": 5,
        "notes": "Integration test order"
    }


@pytest.fixture
def api_gateway_event() -> Dict[str, Any]:
    """Create a sample API Gateway event for testing."""
    return {
        "httpMethod": "POST",
        "path": "/api/orders",
        "headers": {
            "Content-Type": "application/json",
            "User-Agent": "test-agent/1.0",
        },
        "body": '{"customer_name": "Test User", "customer_email": "test@example.com", "order_item_count": 2}',
        "requestContext": {
            "requestId": "test-request-id-123",
            "accountId": "123456789012",
            "stage": "test",
            "httpMethod": "POST",
            "path": "/api/orders",
            "protocol": "HTTP/1.1",
            "requestTime": "2024-01-01T12:00:00.000Z",
            "requestTimeEpoch": 1704110400000,
            "identity": {
                "sourceIp": "127.0.0.1",
                "userAgent": "test-agent/1.0",
            },
        },
        "pathParameters": None,
        "queryStringParameters": None,
        "multiValueQueryStringParameters": None,
        "stageVariables": None,
        "isBase64Encoded": False,
    }


@pytest.fixture
def lambda_context():
    """Create a mock Lambda context for testing."""
    context = Mock()
    context.function_name = "test-lambda-function"
    context.function_version = "1"
    context.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-lambda-function"
    context.memory_limit_in_mb = "512"
    context.remaining_time_in_millis = lambda: 30000
    context.aws_request_id = "test-request-id-123"
    context.log_group_name = "/aws/lambda/test-lambda-function"
    context.log_stream_name = "2024/01/01/[$LATEST]test123"
    return context


# Mock fixtures for external services
@pytest.fixture
def mock_app_config():
    """Mock AWS AppConfig for testing."""
    with patch("service.handlers.utils.dynamic_configuration.get_app_config") as mock:
        mock.return_value = {
            "campaign_config": {
                "discount_percentage": 15.0,
                "min_order_amount": 30.0,
                "max_discount_amount": 75.0,
                "campaign_message": "Test discount applied!"
            },
            "premium_config": {
                "free_shipping_threshold": 0.0,
                "priority_processing": True,
                "extended_return_period_days": 90,
                "premium_support_enabled": True
            },
            "performance_config": {
                "cache_ttl_seconds": 600,
                "max_concurrent_requests": 200,
                "request_timeout_seconds": 45,
                "enable_compression": True
            },
            "debug_mode": True,
            "maintenance_mode": False,
            "rate_limit_requests_per_minute": 2000
        }
        yield mock


@pytest.fixture
def mock_feature_flags():
    """Mock feature flag evaluations for testing."""
    flags = {
        "ten_percent_campaign": True,
        "premium_user_features": True,
        "enable_caching": True,
        "enhanced_logging": True,
        "order_validation_v2": False,
        "customer_notifications": True,
    }

    def mock_evaluate(name, context=None, default=False):
        return flags.get(name, default)

    with patch("service.handlers.utils.dynamic_configuration.get_configuration_store") as mock_store:
        mock_store.return_value.evaluate = mock_evaluate
        yield mock_store


# Test data helpers
@pytest.fixture
def populated_table(dynamodb_table, sample_order):
    """Create a DynamoDB table with sample data."""
    from service.dal.db_handler import DynamoDbHandler

    dal = DynamoDbHandler("test-orders-table")

    # Create multiple orders for testing
    orders = [
        dal.create_order_in_db("Alice Johnson", "alice@example.com", 2, "First test order"),
        dal.create_order_in_db("Bob Wilson", "bob@example.com", 7, "Second test order"),
        dal.create_order_in_db("Alice Johnson", "alice@example.com", 1, "Third test order"),
    ]

    yield dynamodb_table, orders


# Performance testing fixtures
@pytest.fixture
def performance_timer():
    """Timer fixture for performance testing."""
    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def start(self):
            self.start_time = datetime.utcnow()

        def stop(self):
            self.end_time = datetime.utcnow()

        @property
        def elapsed_ms(self) -> float:
            if self.start_time and self.end_time:
                return (self.end_time - self.start_time).total_seconds() * 1000
            return 0.0

    return Timer()


# Integration test fixtures
@pytest.fixture
def integration_client():
    """HTTP client for integration testing."""
    import httpx

    base_url = os.environ.get("API_BASE_URL", "http://localhost:3000")

    with httpx.Client(base_url=base_url, timeout=30.0) as client:
        yield client


# Error simulation fixtures
@pytest.fixture
def mock_dynamodb_error():
    """Mock DynamoDB errors for testing error handling."""
    from botocore.exceptions import ClientError

    def create_error(error_code: str, message: str = "Test error"):
        return ClientError(
            error_response={
                "Error": {
                    "Code": error_code,
                    "Message": message,
                }
            },
            operation_name="TestOperation"
        )

    return create_error


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "slow: Slow running tests")
    config.addinivalue_line("markers", "benchmark: Performance benchmark tests")


def pytest_collection_modifyitems(config, items):
    """Automatically mark tests based on their location."""
    for item in items:
        # Add markers based on test location
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)
        elif "benchmark" in str(item.fspath):
            item.add_marker(pytest.mark.benchmark)


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset any singleton instances between tests."""
    # Clear any cached configuration
    from service.handlers.utils.dynamic_configuration import _config_cache
    _config_cache.clear()
    yield
    _config_cache.clear()


# Async fixtures for async testing
@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
