"""
Security Module for Lambda Applications.

This module provides comprehensive security patterns for serverless applications
including authentication, authorization, rate limiting, input validation, and
security monitoring.
"""

from .auth import (
    JWTAuthenticator,
    APIKeyAuthenticator,
    CognitoAuthenticator,
    AuthenticationError,
    AuthorizationError,
    TokenExpiredError,
    InvalidTokenError,
)

from .rate_limiter import (
    RateLimiter,
    DynamoDBRateLimiter,
    RateLimitExceeded,
    RateLimitConfig,
    RateLimitResult,
)

from .input_validator import (
    InputValidator,
    SecurityValidator,
    ValidationError,
    SQLInjectionDetector,
    XSSDetector,
    PathTraversalDetector,
)

from .security_headers import (
    SecurityHeadersMiddleware,
    CSPPolicy,
    SecurityConfig,
    add_security_headers,
)

from .secrets_manager import (
    SecretsManager,
    AWSSecretsManager,
    SecretNotFoundError,
    SecretDecryptionError,
)

__all__ = [
    # Authentication
    'JWTAuthenticator',
    'APIKeyAuthenticator',
    'CognitoAuthenticator',
    'AuthenticationError',
    'AuthorizationError',
    'TokenExpiredError',
    'InvalidTokenError',

    # Rate Limiting
    'RateLimiter',
    'DynamoDBRateLimiter',
    'RateLimitExceeded',
    'RateLimitConfig',
    'RateLimitResult',

    # Input Validation
    'InputValidator',
    'SecurityValidator',
    'ValidationError',
    'SQLInjectionDetector',
    'XSSDetector',
    'PathTraversalDetector',

    # Security Headers
    'SecurityHeadersMiddleware',
    'CSPPolicy',
    'SecurityConfig',
    'add_security_headers',

    # Secrets Management
    'SecretsManager',
    'AWSSecretsManager',
    'SecretNotFoundError',
    'SecretDecryptionError',
]
