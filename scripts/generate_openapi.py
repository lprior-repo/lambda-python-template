#!/usr/bin/env python3
"""
OpenAPI specification generator for the Lambda Python Template.

This script generates OpenAPI 3.0 specification from the AWS Lambda Powertools
event handler decorators and Pydantic models, following patterns from the
aws-lambda-handler-cookbook.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import yaml
from pydantic import BaseModel


def get_openapi_spec() -> Dict[str, Any]:
    """
    Generate OpenAPI specification from the application.

    Returns:
        OpenAPI specification dictionary
    """
    # Import here to avoid circular imports and ensure app is configured
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

    try:
        from service.handlers.utils.rest_api_resolver import app
        from service.models.input import CreateOrderRequest, UpdateOrderRequest, HealthCheckRequest
        from service.models.output import (
            CreateOrderOutput, GetOrderOutput, UpdateOrderOutput, HealthCheckOutput,
            ErrorOutput, InternalServerErrorOutput, ValidationErrorOutput, NotFoundErrorOutput
        )

        # Enable OpenAPI generation
        openapi_spec = app.get_openapi_schema()

        # Enhance the basic specification
        enhanced_spec = enhance_openapi_spec(openapi_spec)

        return enhanced_spec

    except ImportError as e:
        print(f"Error importing application modules: {e}")
        return create_fallback_spec()


def enhance_openapi_spec(spec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhance the OpenAPI specification with additional metadata and examples.

    Args:
        spec: Base OpenAPI specification

    Returns:
        Enhanced OpenAPI specification
    """
    # Update info section
    spec["info"].update({
        "title": "AWS Lambda Python Template API",
        "description": """
        A production-ready AWS Lambda Python service template implementing serverless best practices.

        This API provides order management functionality with comprehensive validation,
        observability, feature flags, and error handling following the patterns from
        the aws-lambda-handler-cookbook.

        ## Features

        - **Comprehensive Validation**: Input validation using Pydantic models
        - **Observability**: Structured logging, distributed tracing, and metrics
        - **Feature Flags**: Dynamic configuration via AWS AppConfig
        - **Error Handling**: Standardized error responses with correlation IDs
        - **Security**: CORS support and input sanitization
        - **Performance**: Optimized for serverless environments

        ## Authentication

        This API uses AWS IAM for authentication when deployed. For local development,
        authentication may be disabled.

        ## Rate Limiting

        API requests are subject to rate limiting. Current limits:
        - 1000 requests per minute per client
        - Burst capacity of 2000 requests

        ## Error Codes

        The API uses standard HTTP status codes:
        - `200` - Success
        - `400` - Bad Request (malformed JSON, etc.)
        - `422` - Validation Error (invalid input data)
        - `404` - Resource Not Found
        - `429` - Rate Limit Exceeded
        - `500` - Internal Server Error
        """,
        "version": "1.0.0",
        "contact": {
            "name": "API Support",
            "email": "support@example.com",
            "url": "https://github.com/your-org/lambda-python-template"
        },
        "license": {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT"
        },
        "termsOfService": "https://example.com/terms"
    })

    # Add servers
    spec["servers"] = [
        {
            "url": "https://api.example.com",
            "description": "Production server"
        },
        {
            "url": "https://staging-api.example.com",
            "description": "Staging server"
        },
        {
            "url": "https://dev-api.example.com",
            "description": "Development server"
        },
        {
            "url": "http://localhost:3000",
            "description": "Local development server"
        }
    ]

    # Add security schemes
    spec["components"]["securitySchemes"] = {
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key for authentication"
        },
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT token authentication"
        }
    }

    # Add global security
    spec["security"] = [
        {"ApiKeyAuth": []},
        {"BearerAuth": []}
    ]

    # Add tags with descriptions
    spec["tags"] = [
        {
            "name": "Orders",
            "description": "Order management operations",
            "externalDocs": {
                "description": "Find out more about orders",
                "url": "https://docs.example.com/orders"
            }
        },
        {
            "name": "Health",
            "description": "Health check and monitoring operations",
            "externalDocs": {
                "description": "Monitoring guide",
                "url": "https://docs.example.com/monitoring"
            }
        }
    ]

    # Enhance path descriptions and examples
    enhance_paths(spec)

    # Add additional schemas
    add_additional_schemas(spec)

    return spec


def enhance_paths(spec: Dict[str, Any]) -> None:
    """
    Enhance path definitions with better descriptions and examples.

    Args:
        spec: OpenAPI specification to enhance
    """
    paths = spec.get("paths", {})

    # Enhance orders endpoints
    if "/api/orders" in paths:
        orders_path = paths["/api/orders"]

        if "post" in orders_path:
            post_op = orders_path["post"]
            post_op.update({
                "summary": "Create a new order",
                "description": """
                Create a new order with the provided customer information and items.

                The order will be created with a unique ID and initial status of 'pending'.
                The order total will be calculated automatically based on the item count.

                **Business Rules:**
                - Customer email must be valid and unique per order
                - Item count must be between 1 and 100
                - Notes are optional but limited to 500 characters

                **Feature Flags:**
                - Premium customers may receive additional benefits
                - Campaign discounts may be applied automatically
                """,
                "operationId": "createOrder",
                "tags": ["Orders"]
            })

            # Add examples to request body
            if "requestBody" in post_op:
                request_body = post_op["requestBody"]
                if "content" in request_body:
                    content = request_body["content"]
                    if "application/json" in content:
                        json_content = content["application/json"]
                        json_content["examples"] = {
                            "basic_order": {
                                "summary": "Basic Order",
                                "description": "A simple order with required fields only",
                                "value": {
                                    "customer_name": "John Doe",
                                    "customer_email": "john.doe@example.com",
                                    "order_item_count": 3
                                }
                            },
                            "detailed_order": {
                                "summary": "Detailed Order",
                                "description": "An order with all optional fields included",
                                "value": {
                                    "customer_name": "Jane Smith",
                                    "customer_email": "jane.smith@example.com",
                                    "order_item_count": 5,
                                    "notes": "Please deliver after 5 PM on weekdays"
                                }
                            },
                            "bulk_order": {
                                "summary": "Bulk Order",
                                "description": "A large order with maximum item count",
                                "value": {
                                    "customer_name": "Business Customer",
                                    "customer_email": "procurement@company.com",
                                    "order_item_count": 100,
                                    "notes": "Corporate bulk order for office supplies"
                                }
                            }
                        }

    # Enhance health check endpoint
    if "/health" in paths:
        health_path = paths["/health"]

        if "get" in health_path:
            get_op = health_path["get"]
            get_op.update({
                "summary": "Health check endpoint",
                "description": """
                Returns the health status of the service and its dependencies.

                This endpoint is used by load balancers and monitoring systems
                to determine if the service is healthy and ready to receive traffic.

                **Health Status Levels:**
                - `healthy` - All systems operational
                - `degraded` - Some non-critical issues detected
                - `unhealthy` - Critical issues affecting functionality

                **Checks Performed:**
                - Database connectivity
                - External service availability
                - Memory and CPU usage
                - Configuration validity
                """,
                "operationId": "healthCheck",
                "tags": ["Health"]
            })


def add_additional_schemas(spec: Dict[str, Any]) -> None:
    """
    Add additional schemas that might not be automatically detected.

    Args:
        spec: OpenAPI specification to enhance
    """
    components = spec.setdefault("components", {})
    schemas = components.setdefault("schemas", {})

    # Add common error response schemas
    schemas.update({
        "ProblemDetails": {
            "type": "object",
            "description": "RFC 7807 Problem Details for HTTP APIs",
            "properties": {
                "type": {
                    "type": "string",
                    "format": "uri",
                    "description": "A URI that identifies the problem type"
                },
                "title": {
                    "type": "string",
                    "description": "A short, human-readable summary of the problem"
                },
                "status": {
                    "type": "integer",
                    "description": "The HTTP status code"
                },
                "detail": {
                    "type": "string",
                    "description": "A human-readable explanation specific to this occurrence"
                },
                "instance": {
                    "type": "string",
                    "format": "uri",
                    "description": "A URI that identifies the specific occurrence of the problem"
                }
            },
            "required": ["type", "title"]
        },
        "HealthStatus": {
            "type": "string",
            "enum": ["healthy", "degraded", "unhealthy"],
            "description": "The health status of the service"
        },
        "OrderStatus": {
            "type": "string",
            "enum": ["pending", "confirmed", "processing", "shipped", "delivered", "cancelled", "refunded"],
            "description": "The current status of an order"
        }
    })


def create_fallback_spec() -> Dict[str, Any]:
    """
    Create a basic fallback OpenAPI specification when the app can't be imported.

    Returns:
        Basic OpenAPI specification
    """
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "AWS Lambda Python Template API",
            "description": "A serverless API template with best practices",
            "version": "1.0.0",
            "contact": {
                "name": "API Support",
                "email": "support@example.com"
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT"
            }
        },
        "servers": [
            {
                "url": "https://api.example.com",
                "description": "Production server"
            }
        ],
        "paths": {
            "/health": {
                "get": {
                    "summary": "Health check",
                    "description": "Returns the health status of the service",
                    "responses": {
                        "200": {
                            "description": "Service is healthy",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {"type": "string"},
                                            "timestamp": {"type": "string", "format": "date-time"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {}
        }
    }


def validate_openapi_spec(spec: Dict[str, Any]) -> bool:
    """
    Validate the OpenAPI specification.

    Args:
        spec: OpenAPI specification to validate

    Returns:
        True if valid, False otherwise
    """
    try:
        # Basic structural validation
        required_fields = ["openapi", "info", "paths"]
        for field in required_fields:
            if field not in spec:
                print(f"Error: Missing required field '{field}' in OpenAPI spec")
                return False

        # Validate info section
        info = spec["info"]
        required_info_fields = ["title", "version"]
        for field in required_info_fields:
            if field not in info:
                print(f"Error: Missing required field 'info.{field}' in OpenAPI spec")
                return False

        # Validate OpenAPI version
        openapi_version = spec["openapi"]
        if not openapi_version.startswith("3."):
            print(f"Warning: OpenAPI version '{openapi_version}' is not 3.x")

        print("✅ OpenAPI specification validation passed")
        return True

    except Exception as e:
        print(f"Error validating OpenAPI spec: {e}")
        return False


def main():
    """Main function for the OpenAPI generator script."""
    parser = argparse.ArgumentParser(
        description="Generate OpenAPI specification for Lambda Python Template"
    )
    parser.add_argument(
        "--format",
        choices=["json", "yaml"],
        default="yaml",
        help="Output format (default: yaml)"
    )
    parser.add_argument(
        "--out-destination",
        default=".",
        help="Output directory (default: current directory)"
    )
    parser.add_argument(
        "--out-filename",
        help="Output filename (default: openapi.{format})"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate the generated specification"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty print the output"
    )

    args = parser.parse_args()

    # Generate OpenAPI specification
    print("🔄 Generating OpenAPI specification...")
    spec = get_openapi_spec()

    # Add generation metadata
    spec["info"]["x-generated"] = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "generator": "aws-lambda-python-template/openapi-generator",
        "version": "1.0.0"
    }

    # Validate if requested
    if args.validate:
        print("🔍 Validating OpenAPI specification...")
        if not validate_openapi_spec(spec):
            sys.exit(1)

    # Determine output filename
    if args.out_filename:
        filename = args.out_filename
    else:
        filename = f"openapi.{args.format}"

    # Prepare output path
    output_dir = Path(args.out_destination)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / filename

    # Write specification to file
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            if args.format == "json":
                if args.pretty:
                    json.dump(spec, f, indent=2, ensure_ascii=False)
                else:
                    json.dump(spec, f, ensure_ascii=False)
            else:  # yaml
                yaml.dump(
                    spec,
                    f,
                    default_flow_style=False,
                    allow_unicode=True,
                    sort_keys=False
                )

        print(f"✅ OpenAPI specification written to: {output_path}")
        print(f"📊 Specification contains {len(spec.get('paths', {}))} paths")
        print(f"🔧 Format: {args.format.upper()}")

        # Display some statistics
        paths = spec.get("paths", {})
        total_operations = sum(
            len([k for k in path_obj.keys() if k in ["get", "post", "put", "patch", "delete"]])
            for path_obj in paths.values()
        )
        print(f"📈 Total operations: {total_operations}")

        schemas = spec.get("components", {}).get("schemas", {})
        print(f"📋 Schema definitions: {len(schemas)}")

    except Exception as e:
        print(f"❌ Error writing OpenAPI specification: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
