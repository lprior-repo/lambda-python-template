"""
Rate Limiting Patterns for Lambda Applications.

This module provides comprehensive rate limiting capabilities with DynamoDB backend,
supporting various algorithms like token bucket, sliding window, and fixed window.
"""

import time
import json
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from enum import Enum

import boto3
from botocore.exceptions import ClientError
from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from pydantic import BaseModel, Field, validator

logger = Logger()
tracer = Tracer()
metrics = Metrics()


class RateLimitAlgorithm(str, Enum):
    """Rate limiting algorithms."""

    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    SLIDING_LOG = "sliding_log"


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""

    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message)
        self.retry_after = retry_after


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""

    requests_per_window: int
    window_size_seconds: int
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.TOKEN_BUCKET
    burst_size: Optional[int] = None
    key_prefix: str = "rate_limit"

    def __post_init__(self):
        if self.burst_size is None:
            self.burst_size = self.requests_per_window * 2


@dataclass
class RateLimitResult:
    """Result of rate limit check."""

    allowed: bool
    remaining: int
    reset_time: int
    retry_after: Optional[int] = None
    current_usage: int = 0

    def to_headers(self) -> Dict[str, str]:
        """Convert to HTTP headers."""
        headers = {
            'X-RateLimit-Limit': str(self.remaining + self.current_usage),
            'X-RateLimit-Remaining': str(self.remaining),
            'X-RateLimit-Reset': str(self.reset_time)
        }

        if self.retry_after is not None:
            headers['Retry-After'] = str(self.retry_after)

        return headers


class RateLimiter(ABC):
    """Base rate limiter interface."""

    @abstractmethod
    def check_rate_limit(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Check if request is within rate limit."""
        pass

    @abstractmethod
    def reset_rate_limit(self, key: str, config: RateLimitConfig) -> bool:
        """Reset rate limit for a key."""
        pass


class DynamoDBRateLimiter(RateLimiter):
    """
    DynamoDB-based rate limiter supporting multiple algorithms.

    Features:
    - Token bucket algorithm
    - Sliding window algorithm
    - Fixed window algorithm
    - Atomic operations with DynamoDB
    - TTL-based cleanup
    - Multi-tier rate limiting
    """

    def __init__(
        self,
        table_name: str = "rate-limits",
        region_name: str = "us-east-1",
        enable_metrics: bool = True
    ):
        """
        Initialize DynamoDB rate limiter.

        Args:
            table_name: DynamoDB table name
            region_name: AWS region
            enable_metrics: Whether to emit CloudWatch metrics
        """
        self.table_name = table_name
        self.enable_metrics = enable_metrics

        self.dynamodb = boto3.client('dynamodb', region_name=region_name)

        logger.info(
            "DynamoDB Rate Limiter initialized",
            extra={
                "table_name": table_name,
                "region": region_name,
                "enable_metrics": enable_metrics
            }
        )

    @tracer.capture_method
    def check_rate_limit(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Check rate limit using configured algorithm."""
        start_time = time.time()

        try:
            # Choose algorithm
            if config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
                result = self._check_token_bucket(key, config)
            elif config.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
                result = self._check_sliding_window(key, config)
            elif config.algorithm == RateLimitAlgorithm.FIXED_WINDOW:
                result = self._check_fixed_window(key, config)
            elif config.algorithm == RateLimitAlgorithm.SLIDING_LOG:
                result = self._check_sliding_log(key, config)
            else:
                raise ValueError(f"Unsupported algorithm: {config.algorithm}")

            # Record metrics
            if self.enable_metrics:
                duration_ms = (time.time() - start_time) * 1000
                metrics.add_metric(
                    name="RateLimitCheckDuration",
                    unit=MetricUnit.Milliseconds,
                    value=duration_ms
                )

                if result.allowed:
                    metrics.add_metric(name="RateLimitAllowed", unit=MetricUnit.Count, value=1)
                else:
                    metrics.add_metric(name="RateLimitExceeded", unit=MetricUnit.Count, value=1)

            logger.debug(
                "Rate limit check completed",
                extra={
                    "key": key,
                    "algorithm": config.algorithm,
                    "allowed": result.allowed,
                    "remaining": result.remaining
                }
            )

            return result

        except Exception as e:
            if self.enable_metrics:
                metrics.add_metric(name="RateLimitError", unit=MetricUnit.Count, value=1)

            logger.error(f"Rate limit check failed: {str(e)}", extra={"key": key})

            # Fail open - allow request if rate limiter fails
            return RateLimitResult(
                allowed=True,
                remaining=config.requests_per_window,
                reset_time=int(time.time() + config.window_size_seconds)
            )

    def _check_token_bucket(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Implement token bucket algorithm."""
        current_time = time.time()
        item_key = f"{config.key_prefix}:tb:{key}"

        try:
            # Try to get existing bucket
            response = self.dynamodb.get_item(
                TableName=self.table_name,
                Key={'id': {'S': item_key}}
            )

            if 'Item' in response:
                item = response['Item']
                last_refill = float(item['last_refill']['N'])
                tokens = float(item['tokens']['N'])
            else:
                # Initialize new bucket
                last_refill = current_time
                tokens = config.burst_size

            # Calculate tokens to add
            time_passed = current_time - last_refill
            tokens_to_add = time_passed * (config.requests_per_window / config.window_size_seconds)
            tokens = min(config.burst_size, tokens + tokens_to_add)

            # Check if request is allowed
            if tokens >= 1:
                tokens -= 1
                allowed = True
                remaining = int(tokens)
            else:
                allowed = False
                remaining = 0

            # Update bucket
            ttl = int(current_time + config.window_size_seconds * 2)

            self.dynamodb.put_item(
                TableName=self.table_name,
                Item={
                    'id': {'S': item_key},
                    'tokens': {'N': str(tokens)},
                    'last_refill': {'N': str(current_time)},
                    'ttl': {'N': str(ttl)},
                    'algorithm': {'S': config.algorithm.value}
                }
            )

            reset_time = int(current_time + (1 - tokens) / (config.requests_per_window / config.window_size_seconds))
            retry_after = None if allowed else max(1, int(1 / (config.requests_per_window / config.window_size_seconds)))

            return RateLimitResult(
                allowed=allowed,
                remaining=remaining,
                reset_time=reset_time,
                retry_after=retry_after,
                current_usage=config.burst_size - remaining
            )

        except Exception as e:
            logger.error(f"Token bucket check failed: {str(e)}")
            raise

    def _check_sliding_window(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Implement sliding window algorithm."""
        current_time = time.time()
        window_start = current_time - config.window_size_seconds
        item_key = f"{config.key_prefix}:sw:{key}"

        try:
            # Get current window data
            response = self.dynamodb.get_item(
                TableName=self.table_name,
                Key={'id': {'S': item_key}}
            )

            if 'Item' in response:
                item = response['Item']
                requests = json.loads(item.get('requests', {}).get('S', '[]'))
            else:
                requests = []

            # Filter requests within current window
            valid_requests = [req for req in requests if req > window_start]

            # Check if request is allowed
            if len(valid_requests) < config.requests_per_window:
                valid_requests.append(current_time)
                allowed = True
                remaining = config.requests_per_window - len(valid_requests)
            else:
                allowed = False
                remaining = 0

            # Update window data
            ttl = int(current_time + config.window_size_seconds * 2)

            self.dynamodb.put_item(
                TableName=self.table_name,
                Item={
                    'id': {'S': item_key},
                    'requests': {'S': json.dumps(valid_requests[-config.requests_per_window:])},
                    'window_start': {'N': str(window_start)},
                    'ttl': {'N': str(ttl)},
                    'algorithm': {'S': config.algorithm.value}
                }
            )

            # Calculate reset time
            if valid_requests:
                oldest_request = min(valid_requests)
                reset_time = int(oldest_request + config.window_size_seconds)
            else:
                reset_time = int(current_time + config.window_size_seconds)

            retry_after = None if allowed else max(1, reset_time - int(current_time))

            return RateLimitResult(
                allowed=allowed,
                remaining=remaining,
                reset_time=reset_time,
                retry_after=retry_after,
                current_usage=len(valid_requests)
            )

        except Exception as e:
            logger.error(f"Sliding window check failed: {str(e)}")
            raise

    def _check_fixed_window(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Implement fixed window algorithm."""
        current_time = time.time()
        window_start = int(current_time // config.window_size_seconds) * config.window_size_seconds
        item_key = f"{config.key_prefix}:fw:{key}:{window_start}"

        try:
            # Try to increment counter atomically
            try:
                response = self.dynamodb.update_item(
                    TableName=self.table_name,
                    Key={'id': {'S': item_key}},
                    UpdateExpression='ADD request_count :inc SET window_start = :start, ttl = :ttl, algorithm = :alg',
                    ExpressionAttributeValues={
                        ':inc': {'N': '1'},
                        ':start': {'N': str(window_start)},
                        ':ttl': {'N': str(int(current_time + config.window_size_seconds * 2))},
                        ':alg': {'S': config.algorithm.value}
                    },
                    ConditionExpression='attribute_not_exists(request_count) OR request_count < :limit',
                    ExpressionAttributeValues={
                        **{':inc': {'N': '1'}, ':start': {'N': str(window_start)},
                           ':ttl': {'N': str(int(current_time + config.window_size_seconds * 2))},
                           ':alg': {'S': config.algorithm.value}},
                        ':limit': {'N': str(config.requests_per_window)}
                    },
                    ReturnValues='ALL_NEW'
                )

                # Request allowed
                current_count = int(response['Attributes']['request_count']['N'])
                remaining = max(0, config.requests_per_window - current_count)

                return RateLimitResult(
                    allowed=True,
                    remaining=remaining,
                    reset_time=int(window_start + config.window_size_seconds),
                    current_usage=current_count
                )

            except ClientError as e:
                if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                    # Rate limit exceeded
                    # Get current count
                    response = self.dynamodb.get_item(
                        TableName=self.table_name,
                        Key={'id': {'S': item_key}}
                    )

                    current_count = 0
                    if 'Item' in response:
                        current_count = int(response['Item'].get('request_count', {}).get('N', '0'))

                    reset_time = int(window_start + config.window_size_seconds)
                    retry_after = max(1, reset_time - int(current_time))

                    return RateLimitResult(
                        allowed=False,
                        remaining=0,
                        reset_time=reset_time,
                        retry_after=retry_after,
                        current_usage=current_count
                    )
                else:
                    raise

        except Exception as e:
            logger.error(f"Fixed window check failed: {str(e)}")
            raise

    def _check_sliding_log(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Implement sliding log algorithm (most accurate but memory intensive)."""
        current_time = time.time()
        window_start = current_time - config.window_size_seconds
        item_key = f"{config.key_prefix}:sl:{key}"

        try:
            # Get current log
            response = self.dynamodb.get_item(
                TableName=self.table_name,
                Key={'id': {'S': item_key}}
            )

            if 'Item' in response:
                item = response['Item']
                log_entries = json.loads(item.get('log_entries', {}).get('S', '[]'))
            else:
                log_entries = []

            # Filter entries within current window
            valid_entries = [entry for entry in log_entries if entry > window_start]

            # Check if request is allowed
            if len(valid_entries) < config.requests_per_window:
                valid_entries.append(current_time)
                allowed = True
                remaining = config.requests_per_window - len(valid_entries)
            else:
                allowed = False
                remaining = 0

            # Keep only recent entries to prevent unbounded growth
            max_entries = config.requests_per_window * 2
            if len(valid_entries) > max_entries:
                valid_entries = valid_entries[-max_entries:]

            # Update log
            ttl = int(current_time + config.window_size_seconds * 2)

            self.dynamodb.put_item(
                TableName=self.table_name,
                Item={
                    'id': {'S': item_key},
                    'log_entries': {'S': json.dumps(valid_entries)},
                    'window_start': {'N': str(window_start)},
                    'ttl': {'N': str(ttl)},
                    'algorithm': {'S': config.algorithm.value}
                }
            )

            # Calculate reset time (when oldest entry expires)
            if valid_entries:
                oldest_entry = min(valid_entries)
                reset_time = int(oldest_entry + config.window_size_seconds)
            else:
                reset_time = int(current_time + config.window_size_seconds)

            retry_after = None if allowed else max(1, reset_time - int(current_time))

            return RateLimitResult(
                allowed=allowed,
                remaining=remaining,
                reset_time=reset_time,
                retry_after=retry_after,
                current_usage=len(valid_entries)
            )

        except Exception as e:
            logger.error(f"Sliding log check failed: {str(e)}")
            raise

    @tracer.capture_method
    def reset_rate_limit(self, key: str, config: RateLimitConfig) -> bool:
        """Reset rate limit for a key."""
        try:
            item_key = f"{config.key_prefix}:{config.algorithm.value[:2]}:{key}"

            self.dynamodb.delete_item(
                TableName=self.table_name,
                Key={'id': {'S': item_key}}
            )

            logger.info(f"Rate limit reset for key: {key}")

            if self.enable_metrics:
                metrics.add_metric(name="RateLimitReset", unit=MetricUnit.Count, value=1)

            return True

        except Exception as e:
            logger.error(f"Failed to reset rate limit: {str(e)}")

            if self.enable_metrics:
                metrics.add_metric(name="RateLimitResetError", unit=MetricUnit.Count, value=1)

            return False

    def get_rate_limit_status(self, key: str, config: RateLimitConfig) -> Dict[str, Any]:
        """Get current rate limit status without consuming quota."""
        try:
            item_key = f"{config.key_prefix}:{config.algorithm.value[:2]}:{key}"

            response = self.dynamodb.get_item(
                TableName=self.table_name,
                Key={'id': {'S': item_key}}
            )

            if 'Item' not in response:
                return {
                    'exists': False,
                    'remaining': config.requests_per_window,
                    'reset_time': int(time.time() + config.window_size_seconds)
                }

            item = response['Item']
            current_time = time.time()

            if config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
                last_refill = float(item['last_refill']['N'])
                tokens = float(item['tokens']['N'])

                # Calculate current tokens
                time_passed = current_time - last_refill
                tokens_to_add = time_passed * (config.requests_per_window / config.window_size_seconds)
                current_tokens = min(config.burst_size, tokens + tokens_to_add)

                return {
                    'exists': True,
                    'remaining': int(current_tokens),
                    'reset_time': int(current_time + (config.burst_size - current_tokens) /
                                    (config.requests_per_window / config.window_size_seconds)),
                    'algorithm': config.algorithm.value,
                    'current_tokens': current_tokens
                }

            elif config.algorithm == RateLimitAlgorithm.FIXED_WINDOW:
                window_start = float(item.get('window_start', {}).get('N', current_time))
                request_count = int(item.get('request_count', {}).get('N', '0'))

                return {
                    'exists': True,
                    'remaining': max(0, config.requests_per_window - request_count),
                    'reset_time': int(window_start + config.window_size_seconds),
                    'algorithm': config.algorithm.value,
                    'current_usage': request_count
                }

            else:
                # For sliding window algorithms, do a non-consuming check
                return {
                    'exists': True,
                    'algorithm': config.algorithm.value,
                    'note': 'Status check requires full algorithm execution for sliding windows'
                }

        except Exception as e:
            logger.error(f"Failed to get rate limit status: {str(e)}")
            return {'error': str(e)}


class MultiTierRateLimiter:
    """
    Multi-tier rate limiter supporting different limits for different user types.
    """

    def __init__(self, base_limiter: RateLimiter):
        self.base_limiter = base_limiter
        self.tier_configs: Dict[str, RateLimitConfig] = {}

    def add_tier(self, tier_name: str, config: RateLimitConfig):
        """Add a rate limit tier."""
        self.tier_configs[tier_name] = config
        logger.info(f"Added rate limit tier: {tier_name}")

    def check_rate_limit(self, key: str, user_tier: str = "default") -> RateLimitResult:
        """Check rate limit based on user tier."""
        config = self.tier_configs.get(user_tier)

        if not config:
            raise ValueError(f"Unknown tier: {user_tier}")

        # Use tier-specific key
        tier_key = f"{user_tier}:{key}"

        return self.base_limiter.check_rate_limit(tier_key, config)


def create_rate_limit_key(
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    api_key: Optional[str] = None,
    endpoint: Optional[str] = None
) -> str:
    """Create a rate limit key from various identifiers."""
    parts = []

    if user_id:
        parts.append(f"user:{user_id}")
    if ip_address:
        parts.append(f"ip:{ip_address}")
    if api_key:
        # Hash API key for privacy
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
        parts.append(f"key:{api_key_hash}")
    if endpoint:
        parts.append(f"endpoint:{endpoint}")

    if not parts:
        raise ValueError("At least one identifier must be provided")

    return ":".join(parts)


def rate_limit_decorator(
    limiter: RateLimiter,
    config: RateLimitConfig,
    key_extractor: callable = None
):
    """
    Decorator for Lambda functions to apply rate limiting.

    Args:
        limiter: Rate limiter instance
        config: Rate limit configuration
        key_extractor: Function to extract rate limit key from event
    """
    def decorator(func):
        def wrapper(event, context):
            # Extract rate limit key
            if key_extractor:
                key = key_extractor(event)
            else:
                # Default key extraction
                key = create_rate_limit_key(
                    ip_address=event.get('requestContext', {}).get('identity', {}).get('sourceIp'),
                    endpoint=event.get('path')
                )

            # Check rate limit
            result = limiter.check_rate_limit(key, config)

            if not result.allowed:
                return {
                    'statusCode': 429,
                    'headers': {
                        **result.to_headers(),
                        'Content-Type': 'application/json'
                    },
                    'body': json.dumps({
                        'error': 'Rate limit exceeded',
                        'retry_after': result.retry_after
                    })
                }

            # Add rate limit headers to successful responses
            response = func(event, context)

            if isinstance(response, dict) and 'headers' in response:
                response['headers'].update(result.to_headers())

            return response

        return wrapper
    return decorator
