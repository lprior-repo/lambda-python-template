"""
Performance benchmark tests for the Lambda Python Template.

This module contains performance benchmarks to ensure the service meets
performance requirements and to detect performance regressions.
"""

import pytest
import time
from typing import Dict, Any

from service.models.order import Order
from service.dal.db_handler import DynamoDbHandler


@pytest.mark.benchmark
class TestOrderCreationPerformance:
    """Benchmark tests for order creation operations."""

    def test_order_model_creation_performance(self, benchmark):
        """Benchmark Order domain model creation."""
        def create_order():
            return Order.create(
                customer_name="Performance Test User",
                customer_email="perf@example.com",
                item_count=5,
                notes="Performance benchmark test order"
            )

        result = benchmark(create_order)

        # Verify the order was created correctly
        assert result.customer_name == "Performance Test User"
        assert result.item_count == 5

    def test_order_serialization_performance(self, benchmark, sample_order):
        """Benchmark order serialization to dictionary."""
        result = benchmark(sample_order.to_dict)

        # Verify serialization worked
        assert isinstance(result, dict)
        assert result["customer_name"] == sample_order.customer_name

    def test_order_validation_performance(self, benchmark):
        """Benchmark Pydantic model validation."""
        from service.models.input import CreateOrderRequest

        def validate_order_request():
            return CreateOrderRequest(
                customer_name="Validation Test",
                customer_email="validation@example.com",
                order_item_count=3
            )

        result = benchmark(validate_order_request)

        # Verify validation worked
        assert result.customer_name == "Validation Test"
        assert result.order_item_count == 3


@pytest.mark.benchmark
class TestDatabasePerformance:
    """Benchmark tests for database operations."""

    def test_database_order_creation_performance(self, benchmark, dynamodb_table):
        """Benchmark database order creation."""
        dal = DynamoDbHandler("test-orders-table")

        def create_order_in_db():
            return dal.create_order_in_db(
                customer_name="DB Perf Test",
                customer_email="dbperf@example.com",
                order_item_count=3
            )

        result = benchmark(create_order_in_db)

        # Verify the order was created
        assert result.customer_name == "DB Perf Test"
        assert result.id.startswith("ord_")

    def test_database_order_retrieval_performance(self, benchmark, populated_table):
        """Benchmark database order retrieval."""
        table, orders = populated_table
        dal = DynamoDbHandler("test-orders-table")

        # Get the first order ID for testing
        test_order_id = orders[0].id

        def get_order_from_db():
            return dal.get_order_by_id(test_order_id)

        result = benchmark(get_order_from_db)

        # Verify the order was retrieved
        assert result is not None
        assert result.id == test_order_id

    def test_database_order_list_performance(self, benchmark, populated_table):
        """Benchmark database order listing."""
        table, orders = populated_table
        dal = DynamoDbHandler("test-orders-table")

        # Use the first order's customer email
        customer_email = orders[0].customer_email

        def list_customer_orders():
            return dal.list_orders_by_customer(customer_email)

        result = benchmark(list_customer_orders)

        # Verify orders were retrieved
        assert isinstance(result, list)
        assert len(result) > 0


@pytest.mark.benchmark
@pytest.mark.slow
class TestConcurrencyPerformance:
    """Benchmark tests for concurrent operations."""

    def test_concurrent_order_creation(self, dynamodb_table):
        """Test performance under concurrent order creation load."""
        import asyncio
        import concurrent.futures
        from threading import Thread

        dal = DynamoDbHandler("test-orders-table")
        results = []
        errors = []

        def create_order(index: int):
            try:
                start_time = time.time()
                order = dal.create_order_in_db(
                    customer_name=f"Concurrent User {index}",
                    customer_email=f"user{index}@concurrent.com",
                    order_item_count=1
                )
                end_time = time.time()
                results.append({
                    'index': index,
                    'order_id': order.id,
                    'duration': end_time - start_time
                })
            except Exception as e:
                errors.append({'index': index, 'error': str(e)})

        # Create multiple orders concurrently
        num_threads = 10
        threads = []

        start_time = time.time()

        for i in range(num_threads):
            thread = Thread(target=create_order, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        end_time = time.time()
        total_duration = end_time - start_time

        # Verify results
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == num_threads

        # Performance assertions
        avg_duration = sum(r['duration'] for r in results) / len(results)
        max_duration = max(r['duration'] for r in results)

        print(f"Concurrent operation stats:")
        print(f"  Total time: {total_duration:.3f}s")
        print(f"  Average per operation: {avg_duration:.3f}s")
        print(f"  Max operation time: {max_duration:.3f}s")
        print(f"  Operations per second: {num_threads / total_duration:.2f}")

        # Performance thresholds
        assert avg_duration < 2.0, f"Average operation time too high: {avg_duration:.3f}s"
        assert max_duration < 5.0, f"Max operation time too high: {max_duration:.3f}s"


@pytest.mark.benchmark
class TestMemoryPerformance:
    """Benchmark tests for memory usage."""

    def test_memory_usage_order_creation(self):
        """Test memory usage during order creation."""
        import psutil
        import os

        process = psutil.Process(os.getpid())

        # Measure initial memory
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Create many orders
        orders = []
        for i in range(1000):
            order = Order.create(
                customer_name=f"Memory Test User {i}",
                customer_email=f"memory{i}@example.com",
                item_count=1
            )
            orders.append(order)

        # Measure final memory
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory

        print(f"Memory usage stats:")
        print(f"  Initial memory: {initial_memory:.2f} MB")
        print(f"  Final memory: {final_memory:.2f} MB")
        print(f"  Memory increase: {memory_increase:.2f} MB")
        print(f"  Memory per order: {memory_increase / 1000 * 1024:.2f} KB")

        # Memory usage should be reasonable
        assert memory_increase < 100, f"Memory increase too high: {memory_increase:.2f} MB"

        # Clean up
        del orders


@pytest.mark.benchmark
class TestResponseTimeRequirements:
    """Benchmark tests to verify response time requirements."""

    def test_order_creation_response_time(self, dynamodb_table):
        """Test that order creation meets response time requirements."""
        dal = DynamoDbHandler("test-orders-table")

        response_times = []

        for i in range(10):
            start_time = time.time()

            order = dal.create_order_in_db(
                customer_name=f"Response Time Test {i}",
                customer_email=f"response{i}@example.com",
                order_item_count=1
            )

            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to ms
            response_times.append(response_time)

        avg_response_time = sum(response_times) / len(response_times)
        p95_response_time = sorted(response_times)[int(0.95 * len(response_times))]
        max_response_time = max(response_times)

        print(f"Response time stats:")
        print(f"  Average: {avg_response_time:.2f} ms")
        print(f"  95th percentile: {p95_response_time:.2f} ms")
        print(f"  Maximum: {max_response_time:.2f} ms")

        # Response time requirements
        assert avg_response_time < 500, f"Average response time too high: {avg_response_time:.2f} ms"
        assert p95_response_time < 1000, f"95th percentile response time too high: {p95_response_time:.2f} ms"
        assert max_response_time < 2000, f"Max response time too high: {max_response_time:.2f} ms"

    def test_health_check_response_time(self, dynamodb_table):
        """Test that health check meets fast response requirements."""
        dal = DynamoDbHandler("test-orders-table")

        response_times = []

        for i in range(20):
            start_time = time.time()

            health_result = dal.health_check()

            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to ms
            response_times.append(response_time)

            # Verify health check worked
            assert health_result["status"] == "healthy"

        avg_response_time = sum(response_times) / len(response_times)
        max_response_time = max(response_times)

        print(f"Health check response time stats:")
        print(f"  Average: {avg_response_time:.2f} ms")
        print(f"  Maximum: {max_response_time:.2f} ms")

        # Health checks should be very fast
        assert avg_response_time < 100, f"Health check average response time too high: {avg_response_time:.2f} ms"
        assert max_response_time < 500, f"Health check max response time too high: {max_response_time:.2f} ms"
