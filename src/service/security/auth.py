"""
Authentication Patterns for Lambda Applications.

This module provides comprehensive authentication and authorization patterns
including JWT validation, API key authentication, and AWS Cognito integration.
"""

import json
import time
import base64
import hashlib
import hmac
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlencode
from urllib.request import urlopen

import boto3
from botocore.exceptions import ClientError
from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError as JWTInvalidTokenError
from pydantic import BaseModel, Field, validator

logger = Logger()
tracer = Tracer()
metrics = Metrics()


class AuthenticationError(Exception):
    """Base authentication error."""
    pass


class AuthorizationError(Exception):
    """Authorization error - user authenticated but not authorized."""
    pass


class TokenExpiredError(AuthenticationError):
    """Token has expired."""
    pass


class InvalidTokenError(AuthenticationError):
    """Token is invalid or malformed."""
    pass


class InsufficientPermissionsError(AuthorizationError):
    """User lacks required permissions."""
    pass


@dataclass
class UserClaims:
    """User claims from authentication token."""

    user_id: str
    username: Optional[str] = None
    email: Optional[str] = None
    roles: List[str] = None
    permissions: List[str] = None
    groups: List[str] = None
    custom_claims: Dict[str, Any] = None
    token_type: str = "Bearer"
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    def __post_init__(self):
        if self.roles is None:
            self.roles = []
        if self.permissions is None:
            self.permissions = []
        if self.groups is None:
            self.groups = []
        if self.custom_claims is None:
            self.custom_claims = {}

    def has_role(self, role: str) -> bool:
        """Check if user has specific role."""
        return role in self.roles

    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        return permission in self.permissions

    def has_any_role(self, roles: List[str]) -> bool:
        """Check if user has any of the specified roles."""
        return any(role in self.roles for role in roles)

    def has_all_roles(self, roles: List[str]) -> bool:
        """Check if user has all specified roles."""
        return all(role in self.roles for role in roles)

    def is_in_group(self, group: str) -> bool:
        """Check if user is in specific group."""
        return group in self.groups


class AuthenticationResult(BaseModel):
    """Result of authentication operation."""

    authenticated: bool
    user_claims: Optional[UserClaims] = None
    error_message: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: Optional[int] = None


class Authenticator(ABC):
    """Base authenticator interface."""

    @abstractmethod
    def authenticate(self, token: str) -> AuthenticationResult:
        """Authenticate a token and return user claims."""
        pass

    @abstractmethod
    def authorize(self, user_claims: UserClaims, required_permissions: List[str]) -> bool:
        """Check if user has required permissions."""
        pass


class JWTAuthenticator(Authenticator):
    """
    JWT-based authenticator with support for various JWT providers.

    Features:
    - JWT signature validation
    - Token expiration checking
    - Key rotation support
    - Custom claim validation
    - Performance optimizations with caching
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        algorithm: str = "HS256",
        public_key: Optional[str] = None,
        jwks_url: Optional[str] = None,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        leeway: int = 10,
        cache_keys: bool = True,
        cache_ttl: int = 3600
    ):
        """
        Initialize JWT authenticator.

        Args:
            secret_key: Secret key for HMAC algorithms
            algorithm: JWT algorithm (HS256, RS256, etc.)
            public_key: Public key for RSA algorithms
            jwks_url: URL to fetch JSON Web Key Set
            issuer: Expected token issuer
            audience: Expected token audience
            leeway: Time leeway for token validation (seconds)
            cache_keys: Whether to cache JWKS keys
            cache_ttl: Cache TTL in seconds
        """
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.public_key = public_key
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self.cache_keys = cache_keys
        self.cache_ttl = cache_ttl

        # Key cache
        self._key_cache: Dict[str, Any] = {}
        self._cache_timestamps: Dict[str, float] = {}

        logger.info(
            "JWT Authenticator initialized",
            extra={
                "algorithm": algorithm,
                "has_secret": bool(secret_key),
                "has_public_key": bool(public_key),
                "jwks_url": jwks_url,
                "issuer": issuer
            }
        )

    @tracer.capture_method
    def authenticate(self, token: str) -> AuthenticationResult:
        """Authenticate JWT token."""
        start_time = time.time()

        try:
            # Remove Bearer prefix if present
            if token.startswith("Bearer "):
                token = token[7:]

            # Decode token header to get key ID
            header = jwt.get_unverified_header(token)
            key_id = header.get('kid')

            # Get verification key
            verification_key = self._get_verification_key(key_id)

            # Decode and verify token
            payload = jwt.decode(
                token,
                verification_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway
            )

            # Extract user claims
            user_claims = self._extract_user_claims(payload)

            duration_ms = (time.time() - start_time) * 1000

            # Record metrics
            metrics.add_metric(name="AuthenticationSuccess", unit=MetricUnit.Count, value=1)
            metrics.add_metric(name="AuthenticationDuration", unit=MetricUnit.Milliseconds, value=duration_ms)

            logger.info(
                "JWT authentication successful",
                extra={
                    "user_id": user_claims.user_id,
                    "username": user_claims.username,
                    "duration_ms": duration_ms
                }
            )

            return AuthenticationResult(
                authenticated=True,
                user_claims=user_claims,
                token_type="Bearer",
                expires_in=self._get_token_ttl(payload)
            )

        except ExpiredSignatureError:
            metrics.add_metric(name="AuthenticationTokenExpired", unit=MetricUnit.Count, value=1)
            logger.warning("JWT token expired")
            return AuthenticationResult(
                authenticated=False,
                error_message="Token has expired"
            )

        except JWTInvalidTokenError as e:
            metrics.add_metric(name="AuthenticationInvalidToken", unit=MetricUnit.Count, value=1)
            logger.warning(f"Invalid JWT token: {str(e)}")
            return AuthenticationResult(
                authenticated=False,
                error_message=f"Invalid token: {str(e)}"
            )

        except Exception as e:
            metrics.add_metric(name="AuthenticationError", unit=MetricUnit.Count, value=1)
            logger.error(f"JWT authentication failed: {str(e)}")
            return AuthenticationResult(
                authenticated=False,
                error_message="Authentication failed"
            )

    def authorize(self, user_claims: UserClaims, required_permissions: List[str]) -> bool:
        """Check if user has required permissions."""
        if not required_permissions:
            return True

        # Check if user has all required permissions
        has_permissions = all(
            user_claims.has_permission(perm) for perm in required_permissions
        )

        if has_permissions:
            metrics.add_metric(name="AuthorizationSuccess", unit=MetricUnit.Count, value=1)
        else:
            metrics.add_metric(name="AuthorizationDenied", unit=MetricUnit.Count, value=1)
            logger.warning(
                "Authorization denied",
                extra={
                    "user_id": user_claims.user_id,
                    "required_permissions": required_permissions,
                    "user_permissions": user_claims.permissions
                }
            )

        return has_permissions

    def _get_verification_key(self, key_id: Optional[str] = None) -> str:
        """Get key for JWT verification."""
        if self.secret_key:
            return self.secret_key

        if self.public_key:
            return self.public_key

        if self.jwks_url and key_id:
            return self._get_jwks_key(key_id)

        raise InvalidTokenError("No verification key available")

    def _get_jwks_key(self, key_id: str) -> str:
        """Get key from JWKS endpoint."""
        # Check cache first
        if self.cache_keys and key_id in self._key_cache:
            cache_time = self._cache_timestamps.get(key_id, 0)
            if time.time() - cache_time < self.cache_ttl:
                return self._key_cache[key_id]

        try:
            # Fetch JWKS
            with urlopen(self.jwks_url) as response:
                jwks = json.loads(response.read())

            # Find matching key
            for key in jwks.get('keys', []):
                if key.get('kid') == key_id:
                    # Convert to PEM format for RSA keys
                    if key.get('kty') == 'RSA':
                        public_key = self._jwk_to_pem(key)

                        # Cache the key
                        if self.cache_keys:
                            self._key_cache[key_id] = public_key
                            self._cache_timestamps[key_id] = time.time()

                        return public_key

            raise InvalidTokenError(f"Key ID {key_id} not found in JWKS")

        except Exception as e:
            logger.error(f"Failed to fetch JWKS key: {str(e)}")
            raise InvalidTokenError(f"Failed to fetch verification key: {str(e)}")

    def _jwk_to_pem(self, jwk: Dict[str, Any]) -> str:
        """Convert JWK to PEM format."""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend

            # Decode the modulus and exponent
            n = int.from_bytes(
                base64.urlsafe_b64decode(jwk['n'] + '=='),
                byteorder='big'
            )
            e = int.from_bytes(
                base64.urlsafe_b64decode(jwk['e'] + '=='),
                byteorder='big'
            )

            # Create RSA public key
            public_numbers = rsa.RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key(backend=default_backend())

            # Convert to PEM
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            return pem.decode('utf-8')

        except Exception as e:
            logger.error(f"Failed to convert JWK to PEM: {str(e)}")
            raise InvalidTokenError("Failed to process verification key")

    def _extract_user_claims(self, payload: Dict[str, Any]) -> UserClaims:
        """Extract user claims from JWT payload."""
        # Standard claims
        user_id = payload.get('sub') or payload.get('user_id') or payload.get('uid')
        username = payload.get('username') or payload.get('preferred_username')
        email = payload.get('email')

        # Extract roles and permissions
        roles = payload.get('roles', [])
        permissions = payload.get('permissions', [])
        groups = payload.get('groups', [])

        # Handle Cognito-style claims
        if 'cognito:groups' in payload:
            groups.extend(payload['cognito:groups'])

        # Extract timestamps
        issued_at = None
        expires_at = None

        if 'iat' in payload:
            issued_at = datetime.fromtimestamp(payload['iat'])
        if 'exp' in payload:
            expires_at = datetime.fromtimestamp(payload['exp'])

        # Custom claims (exclude standard claims)
        standard_claims = {
            'sub', 'iss', 'aud', 'exp', 'iat', 'nbf', 'jti',
            'user_id', 'username', 'email', 'roles', 'permissions', 'groups'
        }
        custom_claims = {
            k: v for k, v in payload.items()
            if k not in standard_claims and not k.startswith('cognito:')
        }

        return UserClaims(
            user_id=user_id,
            username=username,
            email=email,
            roles=roles,
            permissions=permissions,
            groups=groups,
            custom_claims=custom_claims,
            issued_at=issued_at,
            expires_at=expires_at
        )

    def _get_token_ttl(self, payload: Dict[str, Any]) -> Optional[int]:
        """Get token TTL in seconds."""
        if 'exp' in payload:
            return max(0, payload['exp'] - int(time.time()))
        return None


class APIKeyAuthenticator(Authenticator):
    """
    API Key-based authenticator with support for multiple key sources.
    """

    def __init__(
        self,
        api_keys: Optional[Dict[str, Dict[str, Any]]] = None,
        dynamodb_table: Optional[str] = None,
        hash_keys: bool = True,
        cache_results: bool = True,
        cache_ttl: int = 300
    ):
        """
        Initialize API Key authenticator.

        Args:
            api_keys: Static API keys mapping
            dynamodb_table: DynamoDB table for API keys
            hash_keys: Whether to hash keys for comparison
            cache_results: Whether to cache validation results
            cache_ttl: Cache TTL in seconds
        """
        self.api_keys = api_keys or {}
        self.dynamodb_table = dynamodb_table
        self.hash_keys = hash_keys
        self.cache_results = cache_results
        self.cache_ttl = cache_ttl

        # Cache for validation results
        self._validation_cache: Dict[str, tuple] = {}

        # Initialize DynamoDB client if table is specified
        if dynamodb_table:
            self.dynamodb = boto3.client('dynamodb')

        logger.info(
            "API Key Authenticator initialized",
            extra={
                "static_keys_count": len(self.api_keys),
                "dynamodb_table": dynamodb_table,
                "hash_keys": hash_keys
            }
        )

    @tracer.capture_method
    def authenticate(self, api_key: str) -> AuthenticationResult:
        """Authenticate API key."""
        start_time = time.time()

        try:
            # Check cache first
            if self.cache_results:
                cached_result = self._get_cached_result(api_key)
                if cached_result:
                    return cached_result

            # Validate API key
            key_info = self._validate_api_key(api_key)

            if not key_info:
                metrics.add_metric(name="APIKeyAuthenticationFailed", unit=MetricUnit.Count, value=1)
                result = AuthenticationResult(
                    authenticated=False,
                    error_message="Invalid API key"
                )
            else:
                # Create user claims from key info
                user_claims = UserClaims(
                    user_id=key_info.get('user_id', 'api_key_user'),
                    username=key_info.get('username'),
                    email=key_info.get('email'),
                    roles=key_info.get('roles', []),
                    permissions=key_info.get('permissions', []),
                    custom_claims=key_info.get('custom_claims', {})
                )

                metrics.add_metric(name="APIKeyAuthenticationSuccess", unit=MetricUnit.Count, value=1)
                result = AuthenticationResult(
                    authenticated=True,
                    user_claims=user_claims,
                    token_type="ApiKey"
                )

            # Cache result
            if self.cache_results:
                self._cache_result(api_key, result)

            duration_ms = (time.time() - start_time) * 1000
            metrics.add_metric(name="APIKeyAuthenticationDuration", unit=MetricUnit.Milliseconds, value=duration_ms)

            return result

        except Exception as e:
            metrics.add_metric(name="APIKeyAuthenticationError", unit=MetricUnit.Count, value=1)
            logger.error(f"API key authentication failed: {str(e)}")
            return AuthenticationResult(
                authenticated=False,
                error_message="Authentication failed"
            )

    def authorize(self, user_claims: UserClaims, required_permissions: List[str]) -> bool:
        """Check if API key has required permissions."""
        if not required_permissions:
            return True

        return all(user_claims.has_permission(perm) for perm in required_permissions)

    def _validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key against configured sources."""
        # Check static keys first
        key_hash = self._hash_key(api_key) if self.hash_keys else api_key

        if key_hash in self.api_keys:
            return self.api_keys[key_hash]

        # Check DynamoDB if configured
        if self.dynamodb_table:
            return self._validate_dynamodb_key(key_hash)

        return None

    def _validate_dynamodb_key(self, key_hash: str) -> Optional[Dict[str, Any]]:
        """Validate API key against DynamoDB table."""
        try:
            response = self.dynamodb.get_item(
                TableName=self.dynamodb_table,
                Key={'api_key_hash': {'S': key_hash}}
            )

            if 'Item' not in response:
                return None

            item = response['Item']

            # Check if key is active
            if not item.get('active', {}).get('BOOL', True):
                return None

            # Check expiration
            if 'expires_at' in item:
                expires_at = int(item['expires_at']['N'])
                if time.time() > expires_at:
                    return None

            # Extract key information
            return {
                'user_id': item.get('user_id', {}).get('S'),
                'username': item.get('username', {}).get('S'),
                'email': item.get('email', {}).get('S'),
                'roles': json.loads(item.get('roles', {}).get('S', '[]')),
                'permissions': json.loads(item.get('permissions', {}).get('S', '[]')),
                'custom_claims': json.loads(item.get('custom_claims', {}).get('S', '{}'))
            }

        except Exception as e:
            logger.error(f"Failed to validate DynamoDB API key: {str(e)}")
            return None

    def _hash_key(self, api_key: str) -> str:
        """Hash API key for secure storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()

    def _get_cached_result(self, api_key: str) -> Optional[AuthenticationResult]:
        """Get cached validation result."""
        key_hash = hashlib.md5(api_key.encode()).hexdigest()

        if key_hash in self._validation_cache:
            result, timestamp = self._validation_cache[key_hash]
            if time.time() - timestamp < self.cache_ttl:
                return result
            else:
                # Remove expired cache entry
                del self._validation_cache[key_hash]

        return None

    def _cache_result(self, api_key: str, result: AuthenticationResult):
        """Cache validation result."""
        key_hash = hashlib.md5(api_key.encode()).hexdigest()
        self._validation_cache[key_hash] = (result, time.time())


class CognitoAuthenticator(Authenticator):
    """
    AWS Cognito-based authenticator with JWT validation.
    """

    def __init__(
        self,
        user_pool_id: str,
        app_client_id: str,
        region: str = "us-east-1"
    ):
        """
        Initialize Cognito authenticator.

        Args:
            user_pool_id: Cognito User Pool ID
            app_client_id: App Client ID
            region: AWS region
        """
        self.user_pool_id = user_pool_id
        self.app_client_id = app_client_id
        self.region = region

        # Construct JWKS URL
        jwks_url = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"

        # Initialize JWT authenticator with Cognito settings
        self.jwt_authenticator = JWTAuthenticator(
            algorithm="RS256",
            jwks_url=jwks_url,
            audience=app_client_id,
            issuer=f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
        )

        logger.info(
            "Cognito Authenticator initialized",
            extra={
                "user_pool_id": user_pool_id,
                "app_client_id": app_client_id,
                "region": region
            }
        )

    def authenticate(self, token: str) -> AuthenticationResult:
        """Authenticate Cognito JWT token."""
        return self.jwt_authenticator.authenticate(token)

    def authorize(self, user_claims: UserClaims, required_permissions: List[str]) -> bool:
        """Check authorization with Cognito groups/permissions."""
        return self.jwt_authenticator.authorize(user_claims, required_permissions)


def extract_token_from_event(event: Dict[str, Any]) -> Optional[str]:
    """Extract authentication token from Lambda event."""
    # Check Authorization header
    headers = event.get('headers', {})

    # Handle both cases (API Gateway v1 and v2)
    auth_header = headers.get('Authorization') or headers.get('authorization')

    if auth_header:
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
        elif auth_header.startswith('ApiKey '):
            return auth_header[7:]
        else:
            return auth_header

    # Check query parameters
    query_params = event.get('queryStringParameters', {}) or {}
    if 'token' in query_params:
        return query_params['token']
    if 'api_key' in query_params:
        return query_params['api_key']

    # Check request context (for custom authorizers)
    request_context = event.get('requestContext', {})
    authorizer = request_context.get('authorizer', {})

    if 'token' in authorizer:
        return authorizer['token']

    return None


def require_auth(
    authenticator: Authenticator,
    required_permissions: Optional[List[str]] = None
):
    """
    Decorator for Lambda functions that require authentication.

    Args:
        authenticator: Authenticator instance
        required_permissions: List of required permissions
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(event, context):
            # Extract token
            token = extract_token_from_event(event)

            if not token:
                return {
                    'statusCode': 401,
                    'body': json.dumps({'error': 'Missing authentication token'}),
                    'headers': {'Content-Type': 'application/json'}
                }

            # Authenticate
            auth_result = authenticator.authenticate(token)

            if not auth_result.authenticated:
                return {
                    'statusCode': 401,
                    'body': json.dumps({'error': auth_result.error_message or 'Authentication failed'}),
                    'headers': {'Content-Type': 'application/json'}
                }

            # Authorize
            if required_permissions:
                if not authenticator.authorize(auth_result.user_claims, required_permissions):
                    return {
                        'statusCode': 403,
                        'body': json.dumps({'error': 'Insufficient permissions'}),
                        'headers': {'Content-Type': 'application/json'}
                    }

            # Add user claims to event
            event['user_claims'] = auth_result.user_claims

            # Call original function
            return func(event, context)

        return wrapper
    return decorator
