"""
End-to-end tests for the Lambda Python Template API.

This module tests the complete API functionality from HTTP request to response,
including all middleware, validation, business logic, and data persistence.
"""

import pytest
import json
from typing import Dict, Any

import httpx


@pytest.mark.e2e
class TestOrdersAPI:
    """End-to-end tests for the Orders API."""

    def test_create_order_success(self, integration_client: httpx.Client):
        """Test successful order creation via API."""
        order_data = {
            "customer_name": "John Doe",
            "customer_email": "john.doe@example.com",
            "order_item_count": 3,
            "notes": "E2E test order"
        }

        response = integration_client.post("/api/orders", json=order_data)

        assert response.status_code == 200

        result = response.json()
        assert result["customer_name"] == "John Doe"
        assert result["customer_email"] == "john.doe@example.com"
        assert result["item_count"] == 3
        assert result["notes"] == "E2E test order"
        assert result["status"] == "pending"
        assert "id" in result
        assert "created_at" in result
        assert "order_total" in result

    def test_create_order_validation_error(self, integration_client: httpx.Client):
        """Test order creation with validation errors."""
        invalid_data = {
            "customer_name": "",  # Invalid: empty name
            "customer_email": "invalid-email",  # Invalid: malformed email
            "order_item_count": 0,  # Invalid: zero items
        }

        response = integration_client.post("/api/orders", json=invalid_data)

        assert response.status_code == 422

        result = response.json()
        assert result["error"] == "ValidationError"
        assert "validation_errors" in result

    def test_create_order_minimal_data(self, integration_client: httpx.Client):
        """Test order creation with minimal required data."""
        minimal_data = {
            "customer_name": "Jane Smith",
            "customer_email": "jane@example.com",
            "order_item_count": 1
        }

        response = integration_client.post("/api/orders", json=minimal_data)

        assert response.status_code == 200

        result = response.json()
        assert result["customer_name"] == "Jane Smith"
        assert result["customer_email"] == "jane@example.com"
        assert result["item_count"] == 1
        assert result["notes"] is None

    def test_create_order_large_count(self, integration_client: httpx.Client):
        """Test order creation with maximum allowed item count."""
        large_order = {
            "customer_name": "Bob Wilson",
            "customer_email": "bob@example.com",
            "order_item_count": 100  # Maximum allowed
        }

        response = integration_client.post("/api/orders", json=large_order)

        assert response.status_code == 200

        result = response.json()
        assert result["item_count"] == 100

    def test_create_order_excessive_count(self, integration_client: httpx.Client):
        """Test order creation with item count exceeding limit."""
        excessive_order = {
            "customer_name": "Test User",
            "customer_email": "test@example.com",
            "order_item_count": 150  # Exceeds limit
        }

        response = integration_client.post("/api/orders", json=excessive_order)

        assert response.status_code == 422

        result = response.json()
        assert result["error"] == "ValidationError"

    def test_create_order_missing_content_type(self, integration_client: httpx.Client):
        """Test order creation without proper content type."""
        order_data = {
            "customer_name": "Test User",
            "customer_email": "test@example.com",
            "order_item_count": 2
        }

        response = integration_client.post(
            "/api/orders",
            content=json.dumps(order_data),
            headers={"Content-Type": "text/plain"}
        )

        assert response.status_code == 415  # Unsupported Media Type

    def test_invalid_http_method(self, integration_client: httpx.Client):
        """Test using invalid HTTP method on orders endpoint."""
        response = integration_client.put("/api/orders")

        assert response.status_code == 405  # Method Not Allowed

    def test_malformed_json_request(self, integration_client: httpx.Client):
        """Test sending malformed JSON in request body."""
        response = integration_client.post(
            "/api/orders",
            content="{ invalid json }",
            headers={"Content-Type": "application/json"}
        )

        assert response.status_code == 400  # Bad Request


@pytest.mark.e2e
class TestHealthAPI:
    """End-to-end tests for the Health Check API."""

    def test_health_check_basic(self, integration_client: httpx.Client):
        """Test basic health check endpoint."""
        response = integration_client.get("/health")

        assert response.status_code == 200

        result = response.json()
        assert result["status"] in ["healthy", "degraded", "unhealthy"]
        assert "timestamp" in result
        assert "version" in result
        assert "service" in result
        assert "environment" in result
        assert "request_id" in result

    def test_health_check_with_details(self, integration_client: httpx.Client):
        """Test health check with detailed information."""
        response = integration_client.get("/health?include_details=true")

        assert response.status_code == 200

        result = response.json()
        assert result["status"] in ["healthy", "degraded", "unhealthy"]
        if "checks" in result:
            assert isinstance(result["checks"], dict)


@pytest.mark.e2e
class TestCORSHeaders:
    """End-to-end tests for CORS headers."""

    def test_cors_preflight_request(self, integration_client: httpx.Client):
        """Test CORS preflight request."""
        response = integration_client.options(
            "/api/orders",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            }
        )

        assert response.status_code == 200
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers
        assert "Access-Control-Allow-Headers" in response.headers

    def test_cors_actual_request(self, integration_client: httpx.Client):
        """Test CORS headers on actual API request."""
        order_data = {
            "customer_name": "CORS Test",
            "customer_email": "cors@example.com",
            "order_item_count": 1
        }

        response = integration_client.post(
            "/api/orders",
            json=order_data,
            headers={"Origin": "https://example.com"}
        )

        assert response.status_code == 200
        assert "Access-Control-Allow-Origin" in response.headers


@pytest.mark.e2e
class TestAPIDocumentation:
    """End-to-end tests for API documentation endpoints."""

    def test_swagger_documentation(self, integration_client: httpx.Client):
        """Test Swagger/OpenAPI documentation endpoint."""
        response = integration_client.get("/swagger")

        # Should either return the documentation or redirect
        assert response.status_code in [200, 302, 404]  # 404 if not implemented yet

    def test_openapi_spec(self, integration_client: httpx.Client):
        """Test OpenAPI specification endpoint."""
        response = integration_client.get("/openapi.json")

        # Should either return the spec or 404 if not implemented
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            spec = response.json()
            assert "openapi" in spec
            assert "info" in spec
            assert "paths" in spec


@pytest.mark.e2e
@pytest.mark.slow
class TestPerformanceBasics:
    """Basic performance tests for the API."""

    def test_response_time_threshold(self, integration_client: httpx.Client):
        """Test that API responses are within acceptable time limits."""
        import time

        order_data = {
            "customer_name": "Performance Test",
            "customer_email": "perf@example.com",
            "order_item_count": 1
        }

        start_time = time.time()
        response = integration_client.post("/api/orders", json=order_data)
        end_time = time.time()

        assert response.status_code == 200

        response_time = (end_time - start_time) * 1000  # Convert to milliseconds
        assert response_time < 2000  # Should respond within 2 seconds

    def test_concurrent_requests(self, integration_client: httpx.Client):
        """Test handling of concurrent requests."""
        import asyncio
        import httpx

        async def create_order(client: httpx.AsyncClient, index: int):
            order_data = {
                "customer_name": f"Concurrent User {index}",
                "customer_email": f"user{index}@example.com",
                "order_item_count": 1
            }

            response = await client.post("/api/orders", json=order_data)
            return response.status_code

        async def run_concurrent_test():
            async with httpx.AsyncClient(
                base_url=integration_client.base_url,
                timeout=30.0
            ) as async_client:
                tasks = [create_order(async_client, i) for i in range(5)]
                results = await asyncio.gather(*tasks)
                return results

        # Run the test
        results = asyncio.run(run_concurrent_test())

        # All requests should succeed
        assert all(status_code == 200 for status_code in results)


@pytest.mark.e2e
class TestErrorHandling:
    """End-to-end tests for error handling scenarios."""

    def test_internal_server_error_handling(self, integration_client: httpx.Client):
        """Test handling of internal server errors."""
        # This test would need a way to trigger an internal error
        # For now, we'll just test that non-existent endpoints return proper errors
        response = integration_client.get("/api/nonexistent")

        assert response.status_code == 404

        result = response.json()
        assert "error" in result
        assert "message" in result
        assert "request_id" in result

    def test_request_timeout_handling(self, integration_client: httpx.Client):
        """Test handling of request timeouts."""
        # This would need a way to simulate slow processing
        # For now, we'll test with a very short timeout
        with httpx.Client(
            base_url=integration_client.base_url,
            timeout=0.001  # Very short timeout
        ) as timeout_client:
            try:
                response = timeout_client.get("/health")
                # If it succeeds, the service is very fast
                assert response.status_code == 200
            except httpx.TimeoutException:
                # Expected for very short timeout
                pass

    def test_large_payload_handling(self, integration_client: httpx.Client):
        """Test handling of large request payloads."""
        large_notes = "A" * 1000  # Large but valid notes

        order_data = {
            "customer_name": "Large Payload Test",
            "customer_email": "large@example.com",
            "order_item_count": 1,
            "notes": large_notes
        }

        response = integration_client.post("/api/orders", json=order_data)

        # Should be rejected due to notes length validation
        assert response.status_code == 422


@pytest.mark.e2e
class TestSecurityHeaders:
    """End-to-end tests for security headers and practices."""

    def test_security_headers_present(self, integration_client: httpx.Client):
        """Test that security headers are present in responses."""
        response = integration_client.get("/health")

        assert response.status_code == 200

        # Check for basic security headers
        headers = response.headers

        # X-Request-ID should be present for tracing
        assert "X-Request-ID" in headers or "x-request-id" in headers

    def test_no_sensitive_headers_exposed(self, integration_client: httpx.Client):
        """Test that sensitive headers are not exposed."""
        response = integration_client.get("/health")

        headers = response.headers

        # Should not expose internal AWS headers
        sensitive_headers = [
            "x-amzn-trace-id",
            "x-amzn-requestid",
            "server"  # Should not expose server information
        ]

        for header in sensitive_headers:
            assert header.lower() not in [h.lower() for h in headers.keys()]
