import json
import pytest
from unittest.mock import Mock, patch
from lambda_function import (
    lambda_handler,
    process_users_request,
    get_users_from_database,
)


class TestGetUsersFromDatabase:
    """Test cases for get_users_from_database function."""

    def test_get_users_returns_expected_data(self):
        """Test that get_users_from_database returns expected user data."""
        users = get_users_from_database()

        assert isinstance(users, list)
        assert len(users) == 3

        # Verify first user
        assert users[0]["id"] == "1"
        assert users[0]["name"] == "John Doe"
        assert users[0]["email"] == "john@example.com"
        assert users[0]["createdAt"] == "2024-01-15T10:30:00Z"

        # Verify user structure
        for user in users:
            assert "id" in user
            assert "name" in user
            assert "email" in user
            assert "createdAt" in user

    def test_get_users_consistent_data(self):
        """Test that get_users_from_database returns consistent data across calls."""
        users1 = get_users_from_database()
        users2 = get_users_from_database()

        assert users1 == users2
        assert len(users1) == len(users2)

    @patch("lambda_function.time.sleep")
    def test_get_users_database_simulation(self, mock_sleep):
        """Test that database latency simulation is called."""
        get_users_from_database()
        mock_sleep.assert_called_once_with(0.05)


class TestProcessUsersRequest:
    """Test cases for process_users_request function."""

    def test_process_users_request_with_valid_event(self):
        """Test processing users request with valid API Gateway event."""
        event = {
            "path": "/users",
            "httpMethod": "GET",
            "headers": {"User-Agent": "test-agent"},
            "requestContext": {"requestId": "test-request-id"},
        }

        result = process_users_request(event)

        assert "users" in result
        assert "count" in result
        assert "timestamp" in result
        assert "request_id" in result

        assert result["count"] == 3
        assert result["request_id"] == "test-request-id"
        assert len(result["users"]) == 3

    def test_process_users_request_with_minimal_event(self):
        """Test processing users request with minimal event data."""
        event = {}

        result = process_users_request(event)

        assert result["count"] == 3
        assert result["request_id"] == "unknown"
        assert len(result["users"]) == 3

    def test_process_users_request_users_data_structure(self):
        """Test that users data structure is properly formatted."""
        event = {"requestContext": {"requestId": "structure-test"}}

        result = process_users_request(event)

        users = result["users"]
        assert isinstance(users, list)

        for user in users:
            assert isinstance(user, dict)
            assert "id" in user
            assert "name" in user
            assert "email" in user
            assert "createdAt" in user

    def test_process_users_request_with_different_path(self):
        """Test processing users request with different path."""
        event = {
            "path": "/api/v1/users",
            "requestContext": {"requestId": "path-test-123"},
        }

        result = process_users_request(event)

        assert result["request_id"] == "path-test-123"
        assert result["count"] == 3


class TestLambdaHandler:
    """Test cases for lambda_handler function."""

    def test_lambda_handler_success(self):
        """Test successful lambda handler execution."""
        event = {
            "path": "/users",
            "httpMethod": "GET",
            "headers": {"User-Agent": "test-agent"},
            "requestContext": {"requestId": "test-request-id"},
        }

        context = Mock()
        context.aws_request_id = "lambda-request-id"
        context.function_name = "users-function"
        context.function_version = "$LATEST"
        context.get_remaining_time_in_millis.return_value = 30000

        response = lambda_handler(event, context)

        assert response["statusCode"] == 200
        assert response["headers"]["Content-Type"] == "application/json"
        assert response["headers"]["X-Request-ID"] == "lambda-request-id"
        assert response["headers"]["Cache-Control"] == "max-age=300"
        assert "Access-Control-Allow-Origin" in response["headers"]

        body = json.loads(response["body"])
        assert body["count"] == 3
        assert body["request_id"] == "test-request-id"
        assert len(body["users"]) == 3

    def test_lambda_handler_with_exception(self):
        """Test lambda handler when an exception occurs."""
        event = {"path": "/users"}
        context = Mock()
        context.aws_request_id = "error-request-id"
        context.function_name = "users-function"
        context.function_version = "$LATEST"
        context.get_remaining_time_in_millis.return_value = 30000

        with patch(
            "lambda_function.process_users_request",
            side_effect=Exception("Database error"),
        ):
            response = lambda_handler(event, context)

        assert response["statusCode"] == 500
        assert response["headers"]["Content-Type"] == "application/json"
        assert response["headers"]["X-Request-ID"] == "error-request-id"

        body = json.loads(response["body"])
        assert body["message"] == "Internal server error"
        assert body["request_id"] == "error-request-id"
        assert "timestamp" in body

    def test_lambda_handler_cors_headers(self):
        """Test that CORS headers are properly set."""
        event = {"path": "/users"}
        context = Mock()
        context.aws_request_id = "cors-test-id"
        context.function_name = "users-function"
        context.function_version = "$LATEST"
        context.get_remaining_time_in_millis.return_value = 30000

        response = lambda_handler(event, context)

        headers = response["headers"]
        assert headers["Access-Control-Allow-Origin"] == "*"
        assert "Access-Control-Allow-Headers" in headers
        assert "Access-Control-Allow-Methods" in headers

    def test_lambda_handler_cache_headers(self):
        """Test that cache headers are properly set."""
        event = {"path": "/users"}
        context = Mock()
        context.aws_request_id = "cache-test-id"
        context.function_name = "users-function"
        context.function_version = "$LATEST"
        context.get_remaining_time_in_millis.return_value = 30000

        response = lambda_handler(event, context)

        assert response["headers"]["Cache-Control"] == "max-age=300"

    def test_lambda_handler_empty_event(self):
        """Test lambda handler with empty event."""
        event = {}
        context = Mock()
        context.aws_request_id = "empty-event-id"
        context.function_name = "users-function"
        context.function_version = "$LATEST"
        context.get_remaining_time_in_millis.return_value = 30000

        response = lambda_handler(event, context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["count"] == 3
        assert body["request_id"] == "unknown"

    @patch("lambda_function.get_users_from_database")
    def test_lambda_handler_with_mocked_database(self, mock_get_users):
        """Test lambda handler with mocked database call."""
        mock_users = [
            {
                "id": "1",
                "name": "Test User",
                "email": "test@example.com",
                "createdAt": "2024-01-01T00:00:00Z",
            }
        ]
        mock_get_users.return_value = mock_users

        event = {"requestContext": {"requestId": "mock-test"}}
        context = Mock()
        context.aws_request_id = "mock-lambda-id"
        context.function_name = "users-function"
        context.function_version = "$LATEST"
        context.get_remaining_time_in_millis.return_value = 30000

        response = lambda_handler(event, context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["count"] == 1
        assert body["users"] == mock_users
        mock_get_users.assert_called_once()


@pytest.fixture
def sample_api_gateway_event():
    """Fixture providing a sample API Gateway event for users endpoint."""
    return {
        "resource": "/users",
        "path": "/users",
        "httpMethod": "GET",
        "headers": {"Accept": "application/json", "User-Agent": "pytest/test-agent"},
        "multiValueHeaders": {},
        "queryStringParameters": None,
        "multiValueQueryStringParameters": None,
        "pathParameters": None,
        "stageVariables": None,
        "requestContext": {
            "requestId": "users-request-12345",
            "stage": "prod",
            "resourceId": "def456",
            "resourcePath": "/users",
            "httpMethod": "GET",
            "apiId": "testapi123",
            "accountId": "123456789012",
            "requestTime": "20/Sep/2024:12:05:00 +0000",
            "requestTimeEpoch": 1726833900,
        },
        "body": None,
        "isBase64Encoded": False,
    }


@pytest.fixture
def lambda_context():
    """Fixture providing a mock Lambda context."""
    context = Mock()
    context.aws_request_id = "test-lambda-users-context-id"
    context.function_name = "users-lambda-function"
    context.function_version = "$LATEST"
    context.invoked_function_arn = (
        "arn:aws:lambda:us-east-1:123456789012:function:users-lambda-function"
    )
    context.memory_limit_in_mb = 256
    context.get_remaining_time_in_millis.return_value = 25000
    return context


class TestUserDataValidation:
    """Test cases for user data validation and structure."""

    def test_user_data_has_required_fields(self):
        """Test that each user has all required fields."""
        users = get_users_from_database()

        required_fields = ["id", "name", "email", "createdAt"]

        for user in users:
            for field in required_fields:
                assert field in user, f"User missing required field: {field}"

    def test_user_data_types(self):
        """Test that user data fields have correct types."""
        users = get_users_from_database()

        for user in users:
            assert isinstance(user["id"], str), "User ID should be string"
            assert isinstance(user["name"], str), "User name should be string"
            assert isinstance(user["email"], str), "User email should be string"
            assert isinstance(user["createdAt"], str), "User createdAt should be string"

    def test_user_email_format(self):
        """Test that user emails contain @ symbol (basic validation)."""
        users = get_users_from_database()

        for user in users:
            assert "@" in user["email"], f"Invalid email format: {user['email']}"

    def test_user_id_uniqueness(self):
        """Test that user IDs are unique."""
        users = get_users_from_database()
        user_ids = [user["id"] for user in users]

        assert len(user_ids) == len(set(user_ids)), "User IDs should be unique"


class TestIntegration:
    """Integration tests using fixtures."""

    def test_integration_with_fixtures(self, sample_api_gateway_event, lambda_context):
        """Test integration with realistic API Gateway event and Lambda context."""
        response = lambda_handler(sample_api_gateway_event, lambda_context)

        assert response["statusCode"] == 200
        assert response["headers"]["X-Request-ID"] == "test-lambda-users-context-id"

        body = json.loads(response["body"])
        assert body["request_id"] == "users-request-12345"
        assert body["count"] == 3
        assert len(body["users"]) == 3

    def test_performance_characteristics(
        self, sample_api_gateway_event, lambda_context
    ):
        """Test basic performance characteristics."""
        import time

        start_time = time.time()
        response = lambda_handler(sample_api_gateway_event, lambda_context)
        end_time = time.time()

        execution_time = end_time - start_time

        # Should complete within reasonable time (less than 1 second for mock data)
        assert execution_time < 1.0, f"Function took too long: {execution_time}s"
        assert response["statusCode"] == 200


if __name__ == "__main__":
    pytest.main([__file__])
