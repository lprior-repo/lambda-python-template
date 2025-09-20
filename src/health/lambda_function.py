"""
Health Check Lambda Function - Dedicated health monitoring endpoint.

This module provides a comprehensive health check for the serverless application,
including database connectivity, external service status, and system metrics.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict

# Add the service module to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from aws_lambda_powertools import Logger, Metrics, Tracer
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.utilities.typing import LambdaContext

from service.dal.dynamodb_handler import DynamoDBHandler
from service.handlers.utils.dynamic_configuration import (
    get_configuration_value,
    is_maintenance_mode,
)
from service.handlers.utils.idempotency import create_api_response

# Initialize AWS Powertools
logger = Logger(service="health-check")
tracer = Tracer(service="health-check")
metrics = Metrics(namespace="LambdaTemplate/Health", service="health-check")


@tracer.capture_method
def check_dynamodb_health() -> Dict[str, Any]:
    """
    Check DynamoDB connectivity and performance.

    Returns:
        Health check results for DynamoDB
    """
    try:
        start_time = time.time()

        # Initialize DynamoDB handler for orders table
        orders_table_name = os.environ.get('ORDERS_TABLE_NAME', 'orders-table')
        orders_dal = DynamoDBHandler(
            table_name=orders_table_name,
            endpoint_url=os.environ.get('DYNAMODB_ENDPOINT'),
        )

        # Perform health check
        health_result = orders_dal.health_check()

        # Calculate response time
        response_time = (time.time() - start_time) * 1000

        # Add metrics
        metrics.add_metric(name="DatabaseHealthCheckDuration", unit=MetricUnit.Milliseconds, value=response_time)

        if health_result.get("status") == "healthy":
            metrics.add_metric(name="DatabaseHealthCheckSuccess", unit=MetricUnit.Count, value=1)
        else:
            metrics.add_metric(name="DatabaseHealthCheckFailure", unit=MetricUnit.Count, value=1)

        return {
            "component": "dynamodb",
            "status": health_result.get("status", "unknown"),
            "response_time_ms": round(response_time, 2),
            "table_name": orders_table_name,
            "table_status": health_result.get("table_status", "unknown"),
            "details": {
                "endpoint": os.environ.get('DYNAMODB_ENDPOINT', 'default'),
                "region": os.environ.get('AWS_REGION', 'unknown'),
            }
        }

    except Exception as e:
        logger.error("DynamoDB health check failed", extra={"error": str(e)})
        metrics.add_metric(name="DatabaseHealthCheckFailure", unit=MetricUnit.Count, value=1)

        return {
            "component": "dynamodb",
            "status": "unhealthy",
            "error": str(e),
            "response_time_ms": 0,
            "table_name": orders_table_name,
        }


@tracer.capture_method
def check_appconfig_health() -> Dict[str, Any]:
    """
    Check AWS AppConfig connectivity and configuration retrieval.

    Returns:
        Health check results for AppConfig
    """
    try:
        start_time = time.time()

        # Test configuration retrieval
        maintenance_mode = is_maintenance_mode()
        api_version = get_configuration_value('api_version', default_value='unknown')

        response_time = (time.time() - start_time) * 1000

        # Add metrics
        metrics.add_metric(name="AppConfigHealthCheckDuration", unit=MetricUnit.Milliseconds, value=response_time)
        metrics.add_metric(name="AppConfigHealthCheckSuccess", unit=MetricUnit.Count, value=1)

        return {
            "component": "appconfig",
            "status": "healthy",
            "response_time_ms": round(response_time, 2),
            "details": {
                "maintenance_mode": maintenance_mode,
                "api_version": api_version,
                "application_id": os.environ.get('APPCONFIG_APPLICATION_ID', 'unknown'),
                "environment": os.environ.get('APPCONFIG_ENVIRONMENT', 'unknown'),
            }
        }

    except Exception as e:
        logger.error("AppConfig health check failed", extra={"error": str(e)})
        metrics.add_metric(name="AppConfigHealthCheckFailure", unit=MetricUnit.Count, value=1)

        return {
            "component": "appconfig",
            "status": "unhealthy",
            "error": str(e),
            "response_time_ms": 0,
        }


@tracer.capture_method
def check_lambda_environment() -> Dict[str, Any]:
    """
    Check Lambda environment and configuration.

    Returns:
        Health check results for Lambda environment
    """
    try:
        # Check memory usage and execution environment
        memory_limit = int(os.environ.get('AWS_LAMBDA_FUNCTION_MEMORY_SIZE', '0'))
        timeout = int(os.environ.get('AWS_LAMBDA_FUNCTION_TIMEOUT', '0'))

        # Check critical environment variables
        required_env_vars = [
            'ORDERS_TABLE_NAME',
            'APPCONFIG_APPLICATION_ID',
            'POWERTOOLS_SERVICE_NAME'
        ]

        missing_vars = [var for var in required_env_vars if not os.environ.get(var)]

        status = "healthy" if not missing_vars else "degraded"

        return {
            "component": "lambda_environment",
            "status": status,
            "details": {
                "function_name": os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown'),
                "function_version": os.environ.get('AWS_LAMBDA_FUNCTION_VERSION', 'unknown'),
                "memory_limit_mb": memory_limit,
                "timeout_seconds": timeout,
                "runtime": os.environ.get('AWS_EXECUTION_ENV', 'unknown'),
                "environment": os.environ.get('ENVIRONMENT', 'unknown'),
                "missing_env_vars": missing_vars,
            }
        }

    except Exception as e:
        logger.error("Lambda environment health check failed", extra={"error": str(e)})

        return {
            "component": "lambda_environment",
            "status": "unhealthy",
            "error": str(e),
        }


@tracer.capture_method
def get_system_metrics() -> Dict[str, Any]:
    """
    Get basic system metrics for monitoring.

    Returns:
        System metrics and performance indicators
    """
    try:
        import psutil

        # Get memory usage (if psutil is available)
        memory_info = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent(interval=0.1)

        return {
            "memory_usage_percent": memory_info.percent,
            "available_memory_mb": round(memory_info.available / 1024 / 1024, 2),
            "cpu_usage_percent": cpu_percent,
        }
    except ImportError:
        # psutil not available in Lambda by default
        return {
            "memory_usage_percent": 0,
            "available_memory_mb": 0,
            "cpu_usage_percent": 0,
            "note": "psutil not available - basic metrics only"
        }
    except Exception as e:
        logger.warning("Failed to get system metrics", extra={"error": str(e)})
        return {
            "memory_usage_percent": 0,
            "available_memory_mb": 0,
            "cpu_usage_percent": 0,
            "error": str(e)
        }


@tracer.capture_lambda_handler
@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
@metrics.log_metrics(capture_cold_start_metric=True)
def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """
    Lambda handler for health check endpoint.

    Performs comprehensive health checks across all system components
    and returns detailed status information for monitoring purposes.

    Args:
        event: Lambda event payload (API Gateway event)
        context: Lambda context object

    Returns:
        API Gateway response with health check results
    """
    start_time = time.time()

    # Add global metrics
    metrics.add_metric(name="HealthCheckRequestCount", unit=MetricUnit.Count, value=1)

    # Add trace annotations
    tracer.put_annotation("service", "health-check")
    tracer.put_annotation("environment", os.environ.get("ENVIRONMENT", "unknown"))
    tracer.put_annotation("function_version", context.function_version)

    try:
        logger.info("Health check started", extra={
            "request_id": context.aws_request_id,
            "function_name": context.function_name,
            "remaining_time_ms": context.get_remaining_time_in_millis(),
        })

        # Determine if detailed checks are requested
        query_params = event.get('queryStringParameters') or {}
        include_details = query_params.get('include_details', 'false').lower() == 'true'

        # Perform health checks
        health_checks = []

        # Always check DynamoDB
        db_health = check_dynamodb_health()
        health_checks.append(db_health)

        # Check AppConfig
        config_health = check_appconfig_health()
        health_checks.append(config_health)

        # Check Lambda environment
        env_health = check_lambda_environment()
        health_checks.append(env_health)

        # Determine overall health status
        unhealthy_components = [check for check in health_checks if check.get("status") == "unhealthy"]
        degraded_components = [check for check in health_checks if check.get("status") == "degraded"]

        if unhealthy_components:
            overall_status = "unhealthy"
            status_code = 503
        elif degraded_components:
            overall_status = "degraded"
            status_code = 200
        else:
            overall_status = "healthy"
            status_code = 200

        # Calculate total response time
        total_response_time = (time.time() - start_time) * 1000

        # Build response
        health_response = {
            "status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": os.environ.get("SERVICE_VERSION", "unknown"),
            "environment": os.environ.get("ENVIRONMENT", "unknown"),
            "function_name": context.function_name,
            "request_id": context.aws_request_id,
            "response_time_ms": round(total_response_time, 2),
            "checks": {
                "total": len(health_checks),
                "healthy": len([c for c in health_checks if c.get("status") == "healthy"]),
                "degraded": len(degraded_components),
                "unhealthy": len(unhealthy_components),
            }
        }

        # Add detailed information if requested
        if include_details:
            health_response["details"] = {
                "components": health_checks,
                "system_metrics": get_system_metrics(),
                "maintenance_mode": is_maintenance_mode(),
                "configuration": {
                    "memory_limit_mb": int(os.environ.get('AWS_LAMBDA_FUNCTION_MEMORY_SIZE', '0')),
                    "timeout_seconds": int(os.environ.get('AWS_LAMBDA_FUNCTION_TIMEOUT', '0')),
                    "powertools_version": "3.7.0",  # Should match requirements.txt
                    "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                }
            }

        # Add success metrics
        metrics.add_metric(name="HealthCheckSuccess", unit=MetricUnit.Count, value=1)
        metrics.add_metric(name="HealthCheckDuration", unit=MetricUnit.Milliseconds, value=total_response_time)

        # Add status-specific metrics
        if overall_status == "healthy":
            metrics.add_metric(name="HealthCheckHealthy", unit=MetricUnit.Count, value=1)
        elif overall_status == "degraded":
            metrics.add_metric(name="HealthCheckDegraded", unit=MetricUnit.Count, value=1)
        else:
            metrics.add_metric(name="HealthCheckUnhealthy", unit=MetricUnit.Count, value=1)

        logger.info("Health check completed", extra={
            "overall_status": overall_status,
            "response_time_ms": total_response_time,
            "unhealthy_components": len(unhealthy_components),
            "degraded_components": len(degraded_components),
        })

        return create_api_response(
            status_code=status_code,
            body=json.dumps(health_response, indent=2),
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            }
        )

    except Exception as e:
        # Add error metrics
        metrics.add_metric(name="HealthCheckError", unit=MetricUnit.Count, value=1)

        logger.exception("Health check failed with unexpected error", extra={
            "error": str(e),
            "request_id": context.aws_request_id,
        })

        # Return error response
        error_response = {
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": {
                "code": "HEALTH_CHECK_FAILED",
                "message": "Health check encountered an unexpected error",
                "error_id": context.aws_request_id,
            },
            "request_id": context.aws_request_id,
        }

        return create_api_response(
            status_code=503,
            body=json.dumps(error_response),
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            }
        )
