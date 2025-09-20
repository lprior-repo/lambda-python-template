"""
Unit tests for Pydantic models.

This module tests the validation, serialization, and business logic
of the Pydantic models used throughout the application.
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

from service.models.input import CreateOrderRequest, UpdateOrderRequest, HealthCheckRequest
from service.models.output import (
    CreateOrderOutput, GetOrderOutput, UpdateOrderOutput, HealthCheckOutput,
    ErrorOutput, InternalServerErrorOutput, ValidationErrorOutput, NotFoundErrorOutput
)
from service.models.order import Order, OrderStatus


class TestCreateOrderRequest:
    """Test cases for CreateOrderRequest model."""

    def test_valid_create_order_request(self):
        """Test creating a valid order request."""
        request = CreateOrderRequest(
            customer_name="John Doe",
            customer_email="john.doe@example.com",
            order_item_count=5,
            notes="Please deliver after 5 PM"
        )

        assert request.customer_name == "John Doe"
        assert request.customer_email == "john.doe@example.com"
        assert request.order_item_count == 5
        assert request.notes == "Please deliver after 5 PM"

    def test_minimal_valid_request(self):
        """Test creating a request with minimal required fields."""
        request = CreateOrderRequest(
            customer_name="Jane",
            customer_email="jane@test.com",
            order_item_count=1
        )

        assert request.customer_name == "Jane"
        assert request.customer_email == "jane@test.com"
        assert request.order_item_count == 1
        assert request.notes is None

    def test_email_normalization(self):
        """Test that email addresses are normalized to lowercase."""
        request = CreateOrderRequest(
            customer_name="Test User",
            customer_email="TEST.USER@EXAMPLE.COM",
            order_item_count=3
        )

        assert request.customer_email == "test.user@example.com"

    def test_invalid_email_format(self):
        """Test validation of invalid email formats."""
        with pytest.raises(ValidationError) as exc_info:
            CreateOrderRequest(
                customer_name="Test User",
                customer_email="invalid-email",
                order_item_count=1
            )

        error = exc_info.value.errors()[0]
        assert "Invalid email format" in str(error["ctx"])

    def test_invalid_order_item_count_zero(self):
        """Test validation of zero item count."""
        with pytest.raises(ValidationError) as exc_info:
            CreateOrderRequest(
                customer_name="Test User",
                customer_email="test@example.com",
                order_item_count=0
            )

        error = exc_info.value.errors()[0]
        assert "order_item_count must be greater than 0" in str(error["ctx"])

    def test_invalid_order_item_count_negative(self):
        """Test validation of negative item count."""
        with pytest.raises(ValidationError) as exc_info:
            CreateOrderRequest(
                customer_name="Test User",
                customer_email="test@example.com",
                order_item_count=-5
            )

        error = exc_info.value.errors()[0]
        assert "order_item_count must be greater than 0" in str(error["ctx"])

    def test_invalid_order_item_count_too_large(self):
        """Test validation of excessively large item count."""
        with pytest.raises(ValidationError) as exc_info:
            CreateOrderRequest(
                customer_name="Test User",
                customer_email="test@example.com",
                order_item_count=150
            )

        error = exc_info.value.errors()[0]
        assert "order_item_count cannot exceed 100 items" in str(error["ctx"])

    def test_customer_name_too_short(self):
        """Test validation of customer name that's too short."""
        with pytest.raises(ValidationError):
            CreateOrderRequest(
                customer_name="",
                customer_email="test@example.com",
                order_item_count=1
            )

    def test_customer_name_too_long(self):
        """Test validation of customer name that's too long."""
        with pytest.raises(ValidationError):
            CreateOrderRequest(
                customer_name="A" * 60,  # 60 characters, exceeds 50 limit
                customer_email="test@example.com",
                order_item_count=1
            )

    def test_notes_too_long(self):
        """Test validation of notes that exceed length limit."""
        with pytest.raises(ValidationError):
            CreateOrderRequest(
                customer_name="Test User",
                customer_email="test@example.com",
                order_item_count=1,
                notes="A" * 600  # Exceeds 500 character limit
            )


class TestUpdateOrderRequest:
    """Test cases for UpdateOrderRequest model."""

    def test_valid_update_request(self):
        """Test creating a valid update request."""
        request = UpdateOrderRequest(
            order_item_count=10,
            notes="Updated notes"
        )

        assert request.order_item_count == 10
        assert request.notes == "Updated notes"

    def test_empty_update_request(self):
        """Test creating an update request with no changes."""
        request = UpdateOrderRequest()

        assert request.order_item_count is None
        assert request.notes is None

    def test_partial_update_request(self):
        """Test creating an update request with only some fields."""
        request = UpdateOrderRequest(order_item_count=7)

        assert request.order_item_count == 7
        assert request.notes is None

    def test_invalid_item_count_validation(self):
        """Test validation of invalid item count in update request."""
        with pytest.raises(ValidationError):
            UpdateOrderRequest(order_item_count=0)


class TestOrder:
    """Test cases for Order domain model."""

    def test_create_order(self):
        """Test creating a new order."""
        order = Order.create(
            customer_name="Alice Johnson",
            customer_email="alice@example.com",
            item_count=3,
            notes="Test order"
        )

        assert order.customer_name == "Alice Johnson"
        assert order.customer_email == "alice@example.com"
        assert order.item_count == 3
        assert order.notes == "Test order"
        assert order.status == OrderStatus.PENDING
        assert order.id.startswith("ord_")
        assert isinstance(order.created_at, datetime)
        assert isinstance(order.updated_at, datetime)
        assert order.order_total > 0

    def test_create_order_with_custom_total(self):
        """Test creating an order with a custom total."""
        order = Order.create(
            customer_name="Bob Wilson",
            customer_email="bob@example.com",
            item_count=2,
            order_total=29.99
        )

        assert order.order_total == 29.99

    def test_update_item_count(self):
        """Test updating the item count of an order."""
        order = Order.create(
            customer_name="Test User",
            customer_email="test@example.com",
            item_count=5
        )

        original_updated_at = order.updated_at
        original_total = order.order_total

        order.update_item_count(10)

        assert order.item_count == 10
        assert order.updated_at > original_updated_at
        assert order.order_total != original_total

    def test_update_item_count_invalid(self):
        """Test updating item count with invalid values."""
        order = Order.create(
            customer_name="Test User",
            customer_email="test@example.com",
            item_count=5
        )

        with pytest.raises(ValueError, match="Item count must be greater than 0"):
            order.update_item_count(0)

        with pytest.raises(ValueError, match="Item count cannot exceed 100"):
            order.update_item_count(150)

    def test_update_status(self):
        """Test updating the order status."""
        order = Order.create(
            customer_name="Test User",
            customer_email="test@example.com",
            item_count=3
        )

        original_updated_at = order.updated_at

        order.update_status(OrderStatus.CONFIRMED)

        assert order.status == OrderStatus.CONFIRMED
        assert order.updated_at > original_updated_at

    def test_add_notes(self):
        """Test adding notes to an order."""
        order = Order.create(
            customer_name="Test User",
            customer_email="test@example.com",
            item_count=3
        )

        order.add_notes("Special delivery instructions")

        assert order.notes == "Special delivery instructions"

    def test_add_notes_too_long(self):
        """Test adding notes that exceed the length limit."""
        order = Order.create(
            customer_name="Test User",
            customer_email="test@example.com",
            item_count=3
        )

        with pytest.raises(ValueError, match="Notes cannot exceed 500 characters"):
            order.add_notes("A" * 600)

    def test_can_be_cancelled(self):
        """Test checking if an order can be cancelled."""
        order = Order.create(
            customer_name="Test User",
            customer_email="test@example.com",
            item_count=3
        )

        # Pending orders can be cancelled
        assert order.can_be_cancelled() is True

        # Confirmed orders can be cancelled
        order.update_status(OrderStatus.CONFIRMED)
        assert order.can_be_cancelled() is True

        # Shipped orders cannot be cancelled
        order.update_status(OrderStatus.SHIPPED)
        assert order.can_be_cancelled() is False

    def test_cancel_order(self):
        """Test cancelling an order."""
        order = Order.create(
            customer_name="Test User",
            customer_email="test@example.com",
            item_count=3
        )

        order.cancel()

        assert order.status == OrderStatus.CANCELLED

    def test_cancel_order_invalid_status(self):
        """Test cancelling an order with invalid status."""
        order = Order.create(
            customer_name="Test User",
            customer_email="test@example.com",
            item_count=3
        )

        order.update_status(OrderStatus.DELIVERED)

        with pytest.raises(ValueError, match="Cannot cancel order with status"):
            order.cancel()

    def test_to_dict(self):
        """Test converting order to dictionary."""
        order = Order.create(
            customer_name="Test User",
            customer_email="test@example.com",
            item_count=3,
            notes="Test notes"
        )

        order_dict = order.to_dict()

        assert order_dict["id"] == order.id
        assert order_dict["customer_name"] == "Test User"
        assert order_dict["customer_email"] == "test@example.com"
        assert order_dict["item_count"] == 3
        assert order_dict["status"] == "pending"
        assert order_dict["notes"] == "Test notes"
        assert "created_at" in order_dict
        assert "updated_at" in order_dict

    def test_from_dict(self):
        """Test creating order from dictionary."""
        order_data = {
            "id": "ord_test123",
            "customer_name": "Test User",
            "customer_email": "test@example.com",
            "item_count": 5,
            "status": "confirmed",
            "notes": "Test order",
            "created_at": "2024-01-01T12:00:00",
            "updated_at": "2024-01-01T12:05:00",
            "estimated_delivery": None,
            "order_total": 29.95
        }

        order = Order.from_dict(order_data)

        assert order.id == "ord_test123"
        assert order.customer_name == "Test User"
        assert order.customer_email == "test@example.com"
        assert order.item_count == 5
        assert order.status == OrderStatus.CONFIRMED
        assert order.notes == "Test order"
        assert order.order_total == 29.95


class TestOutputModels:
    """Test cases for output models."""

    def test_create_order_output(self):
        """Test CreateOrderOutput model."""
        now = datetime.utcnow()
        output = CreateOrderOutput(
            id="ord_123",
            customer_name="John Doe",
            customer_email="john@example.com",
            item_count=3,
            status="pending",
            created_at=now,
            order_total=17.97
        )

        assert output.id == "ord_123"
        assert output.customer_name == "John Doe"
        assert output.item_count == 3
        assert output.status == "pending"
        assert output.order_total == 17.97

    def test_error_output(self):
        """Test ErrorOutput model."""
        now = datetime.utcnow()
        error = ErrorOutput(
            error="ValidationError",
            message="Invalid input provided",
            timestamp=now,
            request_id="req_123"
        )

        assert error.error == "ValidationError"
        assert error.message == "Invalid input provided"
        assert error.request_id == "req_123"

    def test_validation_error_output(self):
        """Test ValidationErrorOutput model."""
        now = datetime.utcnow()
        validation_error = ValidationErrorOutput(
            message="Validation failed",
            validation_errors=[{
                "field": "customer_name",
                "message": "Field required",
                "type": "missing"
            }],
            timestamp=now,
            request_id="req_123"
        )

        assert validation_error.error == "ValidationError"
        assert len(validation_error.validation_errors) == 1
        assert validation_error.validation_errors[0]["field"] == "customer_name"

    def test_health_check_output(self):
        """Test HealthCheckOutput model."""
        now = datetime.utcnow()
        health = HealthCheckOutput(
            status="healthy",
            timestamp=now,
            version="1.0.0",
            service="lambda-python-template",
            environment="test",
            request_id="req_123"
        )

        assert health.status == "healthy"
        assert health.version == "1.0.0"
        assert health.service == "lambda-python-template"
        assert health.environment == "test"


class TestHealthCheckRequest:
    """Test cases for HealthCheckRequest model."""

    def test_basic_health_check_request(self):
        """Test basic health check request."""
        request = HealthCheckRequest()
        assert request.include_details is False

    def test_detailed_health_check_request(self):
        """Test health check request with details."""
        request = HealthCheckRequest(include_details=True)
        assert request.include_details is True
