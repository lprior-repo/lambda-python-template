"""
REST API resolver utility for AWS Lambda handlers.

This module provides a configured API Gateway REST resolver with OpenAPI documentation
support, following patterns from the aws-lambda-handler-cookbook.
"""

from aws_lambda_powertools.event_handler import APIGatewayRestResolver
from aws_lambda_powertools.event_handler.openapi.models import Tag

# API path constants
ORDERS_PATH = '/api/orders'
HEALTH_PATH = '/health'

# OpenAPI tags for documentation
ORDERS_TAG = Tag(name='Orders', description='Order management operations')
HEALTH_TAG = Tag(name='Health', description='Health check operations')

# Configure API Gateway REST resolver with OpenAPI support
app = APIGatewayRestResolver(
    enable_validation=True,
    debug=False,
)

# Configure OpenAPI documentation
app.enable_swagger(
    path='/swagger',
    title='Lambda Python Template API',
    version='1.0.0',
    description='AWS Lambda Python template with advanced patterns and best practices',
    contact={
        'name': 'API Support',
        'email': 'support@example.com',
    },
    license_info={
        'name': 'MIT',
        'url': 'https://opensource.org/licenses/MIT',
    },
    servers=[
        {
            'url': 'https://api.example.com',
            'description': 'Production server',
        },
        {
            'url': 'https://staging-api.example.com',
            'description': 'Staging server',
        },
    ],
    tags=[ORDERS_TAG, HEALTH_TAG],
)
