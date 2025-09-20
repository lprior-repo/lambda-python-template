"""
Centralized observability utilities for AWS Lambda handlers.

This module provides configured instances of AWS Lambda Powertools for logging,
tracing, and metrics collection following best practices from the cookbook.
"""

from aws_lambda_powertools.logging import Logger
from aws_lambda_powertools.metrics import Metrics
from aws_lambda_powertools.tracing import Tracer

# Metrics namespace for business KPIs
METRICS_NAMESPACE = 'LambdaTemplate'

# JSON output format, service name can be set by environment variable "POWERTOOLS_SERVICE_NAME"
logger: Logger = Logger()

# Service name can be set by environment variable "POWERTOOLS_SERVICE_NAME"
# Disabled by setting POWERTOOLS_TRACE_DISABLED to "True"
tracer: Tracer = Tracer()

# Namespace and service name can be set by environment variables:
# - POWERTOOLS_METRICS_NAMESPACE
# - POWERTOOLS_SERVICE_NAME
metrics = Metrics(namespace=METRICS_NAMESPACE)
