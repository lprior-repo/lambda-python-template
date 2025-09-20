import json
import pytest
from unittest.mock import Mock, patch
from lambda_function import lambda_handler, process_hello_request, get_app_version


class TestGetAppVersion:
    """Test cases for get_app_version function."""

    def test_get_app_version_from_env(self):
        """Test getting app version from environment variable."""
        with patch.dict("os.environ", {"APP_VERSION": "v2.0.0"}):
            version = get_app_version()
            assert version == "v2.0.0"

    def test_get_app_version_default(self):
        """Test getting default app version when env var is not set."""
        with patch.dict("os.environ", {}, clear=True):
            version = get_app_version()
            assert version == "v1.0.0"

    @patch("lambda_function.get_parameter")
    def test_get_app_version_from_ssm_parameter(self, mock_get_parameter):
        """Test getting app version from SSM parameter."""
        # Note: This test is for future SSM implementation
        # Currently the SSM code is commented out
        mock_get_parameter.return_value = "v3.0.0"
        version = get_app_version()
        # Should still return env var or default since SSM is commented out
        assert version == "v1.0.0"


class TestProcessHelloRequest:
    """Test cases for process_hello_request function."""

    def test_process_hello_request_with_valid_event(self):
        """Test processing hello request with valid API Gateway event."""
        event = {
            "path": "/hello",
            "httpMethod": "GET",
            "headers": {"User-Agent": "test-agent"},
            "requestContext": {"requestId": "test-request-id"},
        }

        with patch("lambda_function.get_app_version", return_value="v1.0.0"):
            result = process_hello_request(event)

        assert result["message"] == "Hello from Python Lambda with Powertools!"
        assert result["path"] == "/hello"
        assert result["request_id"] == "test-request-id"
        assert result["version"] == "v1.0.0"
        assert "timestamp" in result

    def test_process_hello_request_with_minimal_event(self):
        """Test processing hello request with minimal event data."""
        event = {}

        with patch("lambda_function.get_app_version", return_value="v1.0.0"):
            result = process_hello_request(event)

        assert result["message"] == "Hello from Python Lambda with Powertools!"
        assert result["path"] == "/hello"
        assert result["request_id"] == "unknown"
        assert result["version"] == "v1.0.0"
        assert "timestamp" in result

    def test_process_hello_request_with_different_path(self):
        """Test processing hello request with different path."""
        event = {"path": "/hello/world", "requestContext": {"requestId": "test-123"}}

        with patch("lambda_function.get_app_version", return_value="v2.0.0"):
            result = process_hello_request(event)

        assert result["path"] == "/hello/world"
        assert result["request_id"] == "test-123"
        assert result["version"] == "v2.0.0"


class TestLambdaHandler:
    """Test cases for lambda_handler function."""

    def test_lambda_handler_success(self):
        """Test successful lambda handler execution."""
        event = {
            "path": "/hello",
            "httpMethod": "GET",
            "headers": {"User-Agent": "test-agent"},
            "requestContext": {"requestId": "test-request-id"},
        }

        context = Mock()
        context.aws_request_id = "lambda-request-id"
        context.function_name = "hello-function"
        context.function_version = "$LATEST"
        context.get_remaining_time_in_millis.return_value = 30000

        with patch("lambda_function.get_app_version", return_value="v1.0.0"):
            response = lambda_handler(event, context)

        assert response["statusCode"] == 200
        assert response["headers"]["Content-Type"] == "application/json"
        assert response["headers"]["X-Request-ID"] == "lambda-request-id"
        assert "Access-Control-Allow-Origin" in response["headers"]

        body = json.loads(response["body"])
        assert body["message"] == "Hello from Python Lambda with Powertools!"
        assert body["request_id"] == "test-request-id"
        assert body["version"] == "v1.0.0"

    def test_lambda_handler_with_exception(self):
        """Test lambda handler when an exception occurs."""
        event = {"path": "/hello"}
        context = Mock()
        context.aws_request_id = "error-request-id"
        context.function_name = "hello-function"
        context.function_version = "$LATEST"
        context.get_remaining_time_in_millis.return_value = 30000

        with patch(
            "lambda_function.process_hello_request", side_effect=Exception("Test error")
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
        event = {"path": "/hello"}
        context = Mock()
        context.aws_request_id = "cors-test-id"
        context.function_name = "hello-function"
        context.function_version = "$LATEST"
        context.get_remaining_time_in_millis.return_value = 30000

        response = lambda_handler(event, context)

        headers = response["headers"]
        assert headers["Access-Control-Allow-Origin"] == "*"
        assert "Access-Control-Allow-Headers" in headers
        assert "Access-Control-Allow-Methods" in headers

    def test_lambda_handler_empty_event(self):
        """Test lambda handler with empty event."""
        event = {}
        context = Mock()
        context.aws_request_id = "empty-event-id"
        context.function_name = "hello-function"
        context.function_version = "$LATEST"
        context.get_remaining_time_in_millis.return_value = 30000

        response = lambda_handler(event, context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["path"] == "/hello"
        assert body["request_id"] == "unknown"


@pytest.fixture
def sample_api_gateway_event():
    """Fixture providing a sample API Gateway event."""
    return {
        "resource": "/hello",
        "path": "/hello",
        "httpMethod": "GET",
        "headers": {"Accept": "application/json", "User-Agent": "pytest/test-agent"},
        "multiValueHeaders": {},
        "queryStringParameters": None,
        "multiValueQueryStringParameters": None,
        "pathParameters": None,
        "stageVariables": None,
        "requestContext": {
            "requestId": "test-request-12345",
            "stage": "prod",
            "resourceId": "abc123",
            "resourcePath": "/hello",
            "httpMethod": "GET",
            "apiId": "testapi123",
            "accountId": "123456789012",
            "requestTime": "20/Sep/2024:12:00:00 +0000",
            "requestTimeEpoch": 1726833600,
        },
        "body": None,
        "isBase64Encoded": False,
    }


@pytest.fixture
def lambda_context():
    """Fixture providing a mock Lambda context."""
    context = Mock()
    context.aws_request_id = "test-lambda-context-id"
    context.function_name = "hello-lambda-function"
    context.function_version = "$LATEST"
    context.invoked_function_arn = (
        "arn:aws:lambda:us-east-1:123456789012:function:hello-lambda-function"
    )
    context.memory_limit_in_mb = 128
    context.get_remaining_time_in_millis.return_value = 30000
    return context


class TestIntegration:
    """Integration tests using fixtures."""

    def test_integration_with_fixtures(self, sample_api_gateway_event, lambda_context):
        """Test integration with realistic API Gateway event and Lambda context."""
        with patch("lambda_function.get_app_version", return_value="v1.0.0"):
            response = lambda_handler(sample_api_gateway_event, lambda_context)

        assert response["statusCode"] == 200
        assert response["headers"]["X-Request-ID"] == "test-lambda-context-id"

        body = json.loads(response["body"])
        assert body["request_id"] == "test-request-12345"
        assert body["path"] == "/hello"
        assert body["version"] == "v1.0.0"


if __name__ == "__main__":
    pytest.main([__file__])
