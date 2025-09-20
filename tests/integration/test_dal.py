"""
Integration tests for the Data Access Layer (DAL).

This module tests the DynamoDB implementation of the DAL with real AWS services
(mocked with moto) to ensure proper integration between components.
"""

import pytest
from datetime import datetime
from botocore.exceptions import ClientError

from service.dal.db_handler import DynamoDbHandler
from service.models.order import Order, OrderStatus


@pytest.mark.integration
class TestDynamoDbHandler:
    """Integration tests for DynamoDB handler."""

    def test_create_order_success(self, dynamodb_table):
        """Test successful order creation in DynamoDB."""
        dal = DynamoDbHandler("test-orders-table")

        order = dal.create_order_in_db(
            customer_name="Alice Johnson",
            customer_email="alice@example.com",
            order_item_count=3,
            notes="Integration test order"
        )

        assert order.id.startswith("ord_")
        assert order.customer_name == "Alice Johnson"
        assert order.customer_email == "alice@example.com"
        assert order.item_count == 3
        assert order.notes == "Integration test order"
        assert order.status == OrderStatus.PENDING
        assert isinstance(order.created_at, datetime)
        assert order.order_total > 0

    def test_get_order_by_id_success(self, dynamodb_table):
        """Test successful order retrieval by ID."""
        dal = DynamoDbHandler("test-orders-table")

        # Create an order first
        created_order = dal.create_order_in_db(
            customer_name="Bob Wilson",
            customer_email="bob@example.com",
            order_item_count=5
        )

        # Retrieve the order
        retrieved_order = dal.get_order_by_id(created_order.id)

        assert retrieved_order is not None
        assert retrieved_order.id == created_order.id
        assert retrieved_order.customer_name == "Bob Wilson"
        assert retrieved_order.customer_email == "bob@example.com"
        assert retrieved_order.item_count == 5

    def test_get_order_by_id_not_found(self, dynamodb_table):
        """Test order retrieval when order doesn't exist."""
        dal = DynamoDbHandler("test-orders-table")

        result = dal.get_order_by_id("ord_nonexistent")

        assert result is None

    def test_update_order_success(self, dynamodb_table):
        """Test successful order update."""
        dal = DynamoDbHandler("test-orders-table")

        # Create an order first
        order = dal.create_order_in_db(
            customer_name="Charlie Brown",
            customer_email="charlie@example.com",
            order_item_count=2
        )

        # Update the order
        order.update_item_count(7)
        order.add_notes("Updated during integration test")

        updated_order = dal.update_order_in_db(order)

        assert updated_order.item_count == 7
        assert updated_order.notes == "Updated during integration test"
        assert updated_order.updated_at > updated_order.created_at

    def test_update_nonexistent_order(self, dynamodb_table):
        """Test updating an order that doesn't exist."""
        dal = DynamoDbHandler("test-orders-table")

        # Create an order object that doesn't exist in DB
        fake_order = Order.create(
            customer_name="Fake User",
            customer_email="fake@example.com",
            item_count=1
        )
        fake_order.id = "ord_nonexistent"

        with pytest.raises(ClientError) as exc_info:
            dal.update_order_in_db(fake_order)

        assert exc_info.value.response['Error']['Code'] == 'ConditionalCheckFailedException'

    def test_delete_order_success(self, dynamodb_table):
        """Test successful order deletion."""
        dal = DynamoDbHandler("test-orders-table")

        # Create an order first
        order = dal.create_order_in_db(
            customer_name="David Smith",
            customer_email="david@example.com",
            order_item_count=4
        )

        # Delete the order
        result = dal.delete_order_by_id(order.id)

        assert result is True

        # Verify order is deleted
        retrieved_order = dal.get_order_by_id(order.id)
        assert retrieved_order is None

    def test_delete_nonexistent_order(self, dynamodb_table):
        """Test deleting an order that doesn't exist."""
        dal = DynamoDbHandler("test-orders-table")

        result = dal.delete_order_by_id("ord_nonexistent")

        assert result is False

    def test_list_orders_by_customer(self, dynamodb_table):
        """Test listing orders for a specific customer."""
        dal = DynamoDbHandler("test-orders-table")
        customer_email = "emma@example.com"

        # Create multiple orders for the same customer
        order1 = dal.create_order_in_db(
            customer_name="Emma Davis",
            customer_email=customer_email,
            order_item_count=2
        )

        order2 = dal.create_order_in_db(
            customer_name="Emma Davis",
            customer_email=customer_email,
            order_item_count=5
        )

        # Create an order for a different customer
        dal.create_order_in_db(
            customer_name="Frank Miller",
            customer_email="frank@example.com",
            order_item_count=3
        )

        # List orders for Emma
        orders = dal.list_orders_by_customer(customer_email)

        assert len(orders) == 2
        assert all(order.customer_email == customer_email for order in orders)

        # Orders should be sorted by creation time (most recent first)
        assert orders[0].created_at >= orders[1].created_at

    def test_list_orders_by_customer_empty(self, dynamodb_table):
        """Test listing orders for a customer with no orders."""
        dal = DynamoDbHandler("test-orders-table")

        orders = dal.list_orders_by_customer("nonexistent@example.com")

        assert len(orders) == 0

    def test_list_orders_with_limit(self, dynamodb_table):
        """Test listing orders with a limit."""
        dal = DynamoDbHandler("test-orders-table")
        customer_email = "grace@example.com"

        # Create multiple orders
        for i in range(5):
            dal.create_order_in_db(
                customer_name="Grace Wilson",
                customer_email=customer_email,
                order_item_count=i + 1
            )

        # List with limit
        orders = dal.list_orders_by_customer(customer_email, limit=3)

        assert len(orders) == 3

    def test_health_check_success(self, dynamodb_table):
        """Test successful health check."""
        dal = DynamoDbHandler("test-orders-table")

        result = dal.health_check()

        assert result["status"] == "healthy"
        assert result["table"] == "test-orders-table"
        assert "timestamp" in result

    def test_duplicate_order_prevention(self, dynamodb_table):
        """Test that duplicate orders with same ID are prevented."""
        dal = DynamoDbHandler("test-orders-table")

        # Create first order
        order1 = dal.create_order_in_db(
            customer_name="Henry Clark",
            customer_email="henry@example.com",
            order_item_count=2
        )

        # Try to create another order with same ID (this shouldn't happen in practice)
        # We'll manually insert to test the condition
        item = dal._order_to_dynamodb_item(order1)
        item.update({
            'pk': f"ORDER#{order1.id}",
            'sk': f"ORDER#{order1.id}",
            'gsi1pk': f"CUSTOMER#{order1.customer_email}",
            'gsi1sk': f"ORDER#{order1.created_at.isoformat()}",
            'entity_type': 'order'
        })

        with pytest.raises(ClientError) as exc_info:
            dal.table.put_item(
                Item=item,
                ConditionExpression='attribute_not_exists(pk)'
            )

        assert exc_info.value.response['Error']['Code'] == 'ConditionalCheckFailedException'

    def test_order_conversion_methods(self, dynamodb_table):
        """Test order conversion to/from DynamoDB format."""
        dal = DynamoDbHandler("test-orders-table")

        # Create an order
        original_order = Order.create(
            customer_name="Ivy Green",
            customer_email="ivy@example.com",
            item_count=3,
            notes="Test conversion"
        )

        # Convert to DynamoDB item
        item = dal._order_to_dynamodb_item(original_order)

        assert item["id"] == original_order.id
        assert item["customer_name"] == "Ivy Green"
        assert item["customer_email"] == "ivy@example.com"
        assert item["item_count"] == 3
        assert item["status"] == "pending"
        assert item["notes"] == "Test conversion"

        # Convert back to Order
        converted_order = dal._dynamodb_item_to_order(item)

        assert converted_order.id == original_order.id
        assert converted_order.customer_name == original_order.customer_name
        assert converted_order.customer_email == original_order.customer_email
        assert converted_order.item_count == original_order.item_count
        assert converted_order.status == original_order.status
        assert converted_order.notes == original_order.notes

    def test_invalid_item_conversion(self, dynamodb_table):
        """Test handling of invalid DynamoDB items during conversion."""
        dal = DynamoDbHandler("test-orders-table")

        # Invalid item missing required fields
        invalid_item = {
            "id": "ord_invalid",
            "customer_name": "Invalid User"
            # Missing required fields
        }

        with pytest.raises(ValueError, match="Invalid order data in database"):
            dal._dynamodb_item_to_order(invalid_item)

    def test_concurrent_operations(self, dynamodb_table):
        """Test concurrent operations on the same order."""
        dal = DynamoDbHandler("test-orders-table")

        # Create an order
        order = dal.create_order_in_db(
            customer_name="Jack Thompson",
            customer_email="jack@example.com",
            order_item_count=2
        )

        # Simulate concurrent updates by getting the same order twice
        order1 = dal.get_order_by_id(order.id)
        order2 = dal.get_order_by_id(order.id)

        # Update both versions
        order1.update_item_count(5)
        order2.update_item_count(8)

        # First update should succeed
        dal.update_order_in_db(order1)

        # Second update should also succeed (last write wins)
        dal.update_order_in_db(order2)

        # Verify final state
        final_order = dal.get_order_by_id(order.id)
        assert final_order.item_count == 8
