"""
Performance benchmark tests for the Lambda Python Template.

This module contains benchmark tests to monitor performance characteristics
and detect regressions in critical paths of the application.
"""

import pytest
import time
from datetime import datetime
from typing import Dict, Any

from service.models.order import Order, OrderStatus
from service.models.input import CreateOrderRequest
from service.dal.db_handler import DynamoDbHandler


@pytest.mark.benchmark
class TestOrderPerformance:
    """Performance benchmark tests for order operations."""

    def test_order_creation_performance(self, benchmark, dynamodb_table):
        """Benchmark order creation performance."""
        dal = DynamoDbHandler("test-orders-table")

        def create_order():
            return dal.create_order_in_db(
                customer_name="Performance Test User",
                customer_email="perf@example.com",
                order_item_count=5,
                notes="Performance benchmark order"
            )

        # Run benchmark
        result = benchmark(create_order)

        # Assertions
        assert result.id.startswith("ord_")
        assert result.customer_name == "Performance Test User"
        assert result.item_count == 5

        # Performance assertions (adjust based on your requirements)
        assert benchmark.stats['mean'] < 0.1  # Average should be under 100ms
        assert benchmark.stats['max'] < 0.5   # Max should be under 500ms

    def test_order_retrieval_performance(self, benchmark, dynamodb_table):
        """Benchmark order retrieval performance."""
        dal = DynamoDbHandler("test-orders-table")

        # Setup: Create an order first
        order = dal.create_order_in_db(
            customer_name="Retrieval Test User",
            customer_email="retrieve@example.com",
            order_item_count=3
        )

        def get_order():
            return dal.get_order_by_id(order.id)

        # Run benchmark
        result = benchmark(get_order)

        # Assertions
        assert result is not None
        assert result.id == order.id
        assert result.customer_name == "Retrieval Test User"

        # Performance assertions
        assert benchmark.stats['mean'] < 0.05  # Average should be under 50ms
        assert benchmark.stats['max'] < 0.2    # Max should be under 200ms

    def test_order_update_performance(self, benchmark, dynamodb_table):
        """Benchmark order update performance."""
        dal = DynamoDbHandler("test-orders-table")

        # Setup: Create an order first
        order = dal.create_order_in_db(
            customer_name="Update Test User",
            customer_email="update@example.com",
            order_item_count=2
        )

        def update_order():
            order.update_item_count(7)
            order.add_notes("Updated during benchmark")
            return dal.update_order_in_db(order)

        # Run benchmark
        result = benchmark(update_order)

        # Assertions
        assert result.item_count == 7
        assert result.notes == "Updated during benchmark"

        # Performance assertions
        assert benchmark.stats['mean'] < 0.1  # Average should be under 100ms
        assert benchmark.stats['max'] < 0.3   # Max should be under 300ms

    def test_bulk_order_operations_performance(self, benchmark, dynamodb_table):
        """Benchmark bulk order operations."""
        dal = DynamoDbHandler("test-orders-table")

        def bulk_operations():
            orders = []
            # Create multiple orders
            for i in range(10):
                order = dal.create_order_in_db(
                    customer_name=f"Bulk User {i}",
                    customer_email=f"bulk{i}@example.com",
                    order_item_count=i + 1
                )
                orders.append(order)

            # Retrieve all orders
            retrieved_orders = []
            for order in orders:
                retrieved = dal.get_order_by_id(order.id)
                retrieved_orders.append(retrieved)

            return retrieved_orders

        # Run benchmark
        result = benchmark(bulk_operations)

        # Assertions
        assert len(result) == 10
        assert all(order is not None for order in result)

        # Performance assertions for bulk operations
        assert benchmark.stats['mean'] < 2.0  # Average should be under 2 seconds
        assert benchmark.stats['max'] < 5.0   # Max should be under 5 seconds

    def test_order_model_performance(self, benchmark):
        """Benchmark order model operations."""

        def model_operations():
            # Create order
            order = Order.create(
                customer_name="Model Test User",
                customer_email="model@example.com",
                item_count=5,
                notes="Model performance test"
            )

            # Perform various operations
            order.update_item_count(10)
            order.update_status(OrderStatus.CONFIRMED)
            order.add_notes("Updated notes")

            # Convert to/from dict
            order_dict = order.to_dict()
            recreated_order = Order.from_dict(order_dict)

            return recreated_order

        # Run benchmark
        result = benchmark(model_operations)

        # Assertions
        assert result.item_count == 10
        assert result.status == OrderStatus.CONFIRMED
        assert "Updated notes" in result.notes

        # Performance assertions (model operations should be very fast)
        assert benchmark.stats['mean'] < 0.001  # Average should be under 1ms
        assert benchmark.stats['max'] < 0.01    # Max should be under 10ms

    def test_validation_performance(self, benchmark):
        """Benchmark input validation performance."""

        def validation_operations():
            # Valid request
            valid_request = CreateOrderRequest(
                customer_name="Validation Test",
                customer_email="validation@example.com",
                order_item_count=3,
                notes="Validation performance test"
            )

            # Multiple validation operations
            requests = []
            for i in range(100):
                request = CreateOrderRequest(
                    customer_name=f"User {i}",
                    customer_email=f"user{i}@example.com",
                    order_item_count=(i % 10) + 1
                )
                requests.append(request)

            return requests

        # Run benchmark
        result = benchmark(validation_operations)

        # Assertions
        assert len(result) == 100
        assert all(req.customer_name.startswith("User") for req in result)

        # Performance assertions
        assert benchmark.stats['mean'] < 0.01  # Average should be under 10ms
        assert benchmark.stats['max'] < 0.05   # Max should be under 50ms

    @pytest.mark.slow
    def test_memory_usage_performance(self, benchmark, dynamodb_table):
        """Benchmark memory usage during operations."""
        import psutil
        import os

        dal = DynamoDbHandler("test-orders-table")
        process = psutil.Process(os.getpid())

        def memory_intensive_operations():
            initial_memory = process.memory_info().rss

            # Create many orders
            orders = []
            for i in range(50):
                order = dal.create_order_in_db(
                    customer_name=f"Memory User {i}",
                    customer_email=f"memory{i}@example.com",
                    order_item_count=(i % 20) + 1
                )
                orders.append(order)

            final_memory = process.memory_info().rss
            memory_increase = final_memory - initial_memory

            # Clean up by deleting orders
            for order in orders:
                dal.delete_order_by_id(order.id)

            return memory_increase

        # Run benchmark
        memory_increase = benchmark(memory_intensive_operations)

        # Performance assertions
        # Memory increase should be reasonable (adjust based on your requirements)
        assert memory_increase < 50 * 1024 * 1024  # Less than 50MB increase
        assert benchmark.stats['mean'] < 5.0       # Should complete within 5 seconds

    def test_concurrent_operations_simulation(self, benchmark, dynamodb_table):
        """Simulate concurrent operations performance."""
        dal = DynamoDbHandler("test-orders-table")

        def simulate_concurrent_load():
            import concurrent.futures
            import threading

            results = []

            def create_order_worker(worker_id):
                try:
                    order = dal.create_order_in_db(
                        customer_name=f"Concurrent User {worker_id}",
                        customer_email=f"concurrent{worker_id}@example.com",
                        order_item_count=(worker_id % 10) + 1
                    )
                    return order.id
                except Exception as e:
                    return f"Error: {str(e)}"

            # Simulate 10 concurrent operations
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(create_order_worker, i) for i in range(10)]
                results = [future.result() for future in concurrent.futures.as_completed(futures)]

            return results

        # Run benchmark
        result = benchmark(simulate_concurrent_load)

        # Assertions
        assert len(result) == 10
        successful_orders = [r for r in result if r.startswith("ord_")]
        assert len(successful_orders) >= 8  # At least 80% success rate

        # Performance assertions
        assert benchmark.stats['mean'] < 3.0  # Should complete within 3 seconds
        assert benchmark.stats['max'] < 10.0  # Max should be under 10 seconds


@pytest.mark.benchmark
class TestColdStartPerformance:
    """Benchmark tests for Lambda cold start simulation."""

    def test_module_import_performance(self, benchmark):
        """Benchmark module import times (simulates cold start)."""

        def import_modules():
            # Simulate fresh imports (in real Lambda, these happen during cold start)
            import importlib
            import sys

            # Remove modules from cache to simulate cold start
            modules_to_reload = [
                'service.models.order',
                'service.models.input',
                'service.models.output',
                'service.dal.db_handler',
            ]

            for module in modules_to_reload:
                if module in sys.modules:
                    del sys.modules[module]

            # Re-import modules
            from service.models.order import Order
            from service.models.input import CreateOrderRequest
            from service.models.output import CreateOrderOutput
            from service.dal.db_handler import DynamoDbHandler

            return True

        # Run benchmark
        result = benchmark(import_modules)

        # Assertions
        assert result is True

        # Cold start performance is critical for Lambda
        assert benchmark.stats['mean'] < 0.1   # Should import within 100ms
        assert benchmark.stats['max'] < 0.5    # Max should be under 500ms

    def test_initialization_performance(self, benchmark, dynamodb_table):
        """Benchmark service initialization performance."""

        def initialize_service():
            # Simulate service initialization
            from service.handlers.utils.observability import logger, tracer, metrics
            from service.dal.db_handler import DynamoDbHandler
            from service.handlers.utils.rest_api_resolver import app

            # Initialize DAL
            dal = DynamoDbHandler("test-orders-table")

            # Test health check (common initialization operation)
            health_result = dal.health_check()

            return health_result

        # Run benchmark
        result = benchmark(initialize_service)

        # Assertions
        assert result["status"] == "healthy"

        # Initialization should be fast
        assert benchmark.stats['mean'] < 0.2   # Should initialize within 200ms
        assert benchmark.stats['max'] < 1.0    # Max should be under 1 second


@pytest.mark.benchmark
@pytest.mark.parametrize("order_count", [1, 10, 50, 100])
def test_scalability_performance(benchmark, dynamodb_table, order_count):
    """Test performance characteristics with different loads."""
    dal = DynamoDbHandler("test-orders-table")

    def create_multiple_orders():
        orders = []
        for i in range(order_count):
            order = dal.create_order_in_db(
                customer_name=f"Scale User {i}",
                customer_email=f"scale{i}@example.com",
                order_item_count=(i % 20) + 1
            )
            orders.append(order)
        return orders

    # Run benchmark
    result = benchmark(create_multiple_orders)

    # Assertions
    assert len(result) == order_count
    assert all(order.id.startswith("ord_") for order in result)

    # Performance should scale reasonably
    expected_max_time = order_count * 0.1  # 100ms per order max
    assert benchmark.stats['mean'] < expected_max_time
