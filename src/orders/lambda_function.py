"""
Orders Lambda Function - Entry point for orders API.

This module serves as the Lambda function entry point that delegates to the
enhanced orders handler using the three-layer architecture pattern.
"""

import os
import sys
from typing import Any, Dict

# Add the service module to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from aws_lambda_powertools.utilities.typing import LambdaContext
from service.handlers.orders_handler import lambda_handler as orders_handler


def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """
    Lambda function entry point for orders API.

    This function delegates to the enhanced orders handler which implements
    the three-layer architecture with comprehensive error handling,
    validation, observability, and business logic.

    Args:
        event: Lambda event payload (API Gateway event)
        context: Lambda context object

    Returns:
        API Gateway response dictionary
    """
    return orders_handler(event, context)
