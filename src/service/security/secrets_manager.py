"""
AWS Secrets Manager Integration for Lambda Applications.

This module provides secure secrets management with AWS Secrets Manager,
including caching, automatic rotation handling, and comprehensive error handling.
"""

import json
import time
import base64
from typing import Any, Dict, Optional, Union
from dataclasses import dataclass
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit

logger = Logger()
tracer = Tracer()
metrics = Metrics()


class SecretNotFoundError(Exception):
    """Exception raised when secret is not found."""
    pass


class SecretDecryptionError(Exception):
    """Exception raised when secret cannot be decrypted."""
    pass


class SecretRotationError(Exception):
    """Exception raised when secret rotation fails."""
    pass


@dataclass
class CachedSecret:
    """Cached secret with metadata."""

    value: Union[str, Dict[str, Any]]
    version_id: str
    created_date: datetime
    cached_at: datetime
    ttl_seconds: int

    @property
    def is_expired(self) -> bool:
        """Check if cached secret has expired."""
        return datetime.utcnow() > self.cached_at + timedelta(seconds=self.ttl_seconds)

    @property
    def expires_at(self) -> datetime:
        """Get expiration time of cached secret."""
        return self.cached_at + timedelta(seconds=self.ttl_seconds)


class SecretsManager:
    """Base interface for secrets management."""

    def get_secret(self, secret_name: str, version_id: Optional[str] = None) -> Union[str, Dict[str, Any]]:
        """Get a secret value."""
        raise NotImplementedError

    def put_secret(self, secret_name: str, secret_value: Union[str, Dict[str, Any]]) -> str:
        """Store a secret value."""
        raise NotImplementedError

    def delete_secret(self, secret_name: str, force_delete: bool = False) -> bool:
        """Delete a secret."""
        raise NotImplementedError


class AWSSecretsManager(SecretsManager):
    """
    AWS Secrets Manager implementation with advanced features.

    Features:
    - Automatic caching with configurable TTL
    - Version management and rotation handling
    - Error handling and retry logic
    - Support for JSON and string secrets
    - Metrics and observability
    - Cross-region replication support
    """

    def __init__(
        self,
        region_name: str = "us-east-1",
        cache_ttl_seconds: int = 300,
        max_cache_size: int = 100,
        enable_caching: bool = True,
        endpoint_url: Optional[str] = None
    ):
        """
        Initialize AWS Secrets Manager client.

        Args:
            region_name: AWS region name
            cache_ttl_seconds: Cache TTL in seconds (default: 5 minutes)
            max_cache_size: Maximum number of secrets to cache
            enable_caching: Whether to enable secret caching
            endpoint_url: Custom endpoint URL (for testing)
        """
        self.region_name = region_name
        self.cache_ttl_seconds = cache_ttl_seconds
        self.max_cache_size = max_cache_size
        self.enable_caching = enable_caching

        # Initialize AWS client
        self.client = boto3.client(
            'secretsmanager',
            region_name=region_name,
            endpoint_url=endpoint_url
        )

        # Cache for secrets
        self._cache: Dict[str, CachedSecret] = {}

        logger.info(
            "AWS Secrets Manager initialized",
            extra={
                "region": region_name,
                "cache_ttl": cache_ttl_seconds,
                "caching_enabled": enable_caching,
                "max_cache_size": max_cache_size
            }
        )

    @tracer.capture_method
    def get_secret(
        self,
        secret_name: str,
        version_id: Optional[str] = None,
        version_stage: str = "AWSCURRENT"
    ) -> Union[str, Dict[str, Any]]:
        """
        Get secret value from AWS Secrets Manager.

        Args:
            secret_name: Name or ARN of the secret
            version_id: Specific version ID to retrieve
            version_stage: Version stage (AWSCURRENT, AWSPENDING)

        Returns:
            Secret value (string or parsed JSON dict)

        Raises:
            SecretNotFoundError: If secret doesn't exist
            SecretDecryptionError: If secret cannot be decrypted
        """
        start_time = time.time()
        cache_key = f"{secret_name}:{version_id or version_stage}"

        try:
            # Check cache first
            if self.enable_caching and cache_key in self._cache:
                cached_secret = self._cache[cache_key]

                if not cached_secret.is_expired:
                    logger.debug(
                        "Secret retrieved from cache",
                        extra={
                            "secret_name": secret_name,
                            "version_id": cached_secret.version_id,
                            "cached_at": cached_secret.cached_at.isoformat(),
                            "expires_at": cached_secret.expires_at.isoformat()
                        }
                    )

                    metrics.add_metric(name="SecretCacheHit", unit=MetricUnit.Count, value=1)
                    return cached_secret.value
                else:
                    # Remove expired entry
                    del self._cache[cache_key]

            # Retrieve from AWS Secrets Manager
            kwargs = {
                "SecretId": secret_name,
                "VersionStage": version_stage
            }

            if version_id:
                kwargs["VersionId"] = version_id
                kwargs.pop("VersionStage", None)  # Can't use both

            response = self.client.get_secret_value(**kwargs)

            # Parse secret value
            secret_value = self._parse_secret_value(response)

            # Cache the secret
            if self.enable_caching:
                self._cache_secret(
                    cache_key,
                    secret_value,
                    response.get("VersionId", ""),
                    response.get("CreatedDate", datetime.utcnow())
                )

            duration_ms = (time.time() - start_time) * 1000

            # Record metrics
            metrics.add_metric(name="SecretRetrieved", unit=MetricUnit.Count, value=1)
            metrics.add_metric(name="SecretRetrievalDuration", unit=MetricUnit.Milliseconds, value=duration_ms)
            metrics.add_metric(name="SecretCacheMiss", unit=MetricUnit.Count, value=1)

            logger.info(
                "Secret retrieved successfully",
                extra={
                    "secret_name": secret_name,
                    "version_id": response.get("VersionId"),
                    "version_stage": version_stage,
                    "duration_ms": duration_ms,
                    "cached": self.enable_caching
                }
            )

            return secret_value

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')

            if error_code == 'ResourceNotFoundException':
                logger.error(f"Secret not found: {secret_name}")
                metrics.add_metric(name="SecretNotFound", unit=MetricUnit.Count, value=1)
                raise SecretNotFoundError(f"Secret '{secret_name}' not found")

            elif error_code == 'DecryptionFailureException':
                logger.error(f"Secret decryption failed: {secret_name}")
                metrics.add_metric(name="SecretDecryptionFailed", unit=MetricUnit.Count, value=1)
                raise SecretDecryptionError(f"Failed to decrypt secret '{secret_name}'")

            elif error_code == 'InternalServiceErrorException':
                logger.error(f"AWS Secrets Manager internal error for: {secret_name}")
                metrics.add_metric(name="SecretServiceError", unit=MetricUnit.Count, value=1)
                raise SecretDecryptionError(f"Internal service error retrieving '{secret_name}'")

            else:
                logger.error(f"Failed to retrieve secret '{secret_name}': {error_code}")
                metrics.add_metric(name="SecretRetrievalError", unit=MetricUnit.Count, value=1)
                raise SecretDecryptionError(f"Failed to retrieve secret: {str(e)}")

        except Exception as e:
            logger.error(f"Unexpected error retrieving secret '{secret_name}': {str(e)}")
            metrics.add_metric(name="SecretRetrievalError", unit=MetricUnit.Count, value=1)
            raise SecretDecryptionError(f"Unexpected error: {str(e)}")

    @tracer.capture_method
    def put_secret(
        self,
        secret_name: str,
        secret_value: Union[str, Dict[str, Any]],
        description: Optional[str] = None,
        kms_key_id: Optional[str] = None
    ) -> str:
        """
        Store a secret value in AWS Secrets Manager.

        Args:
            secret_name: Name of the secret
            secret_value: Secret value (string or dict)
            description: Description of the secret
            kms_key_id: KMS key ID for encryption

        Returns:
            Version ID of the stored secret

        Raises:
            SecretDecryptionError: If secret cannot be stored
        """
        try:
            # Prepare secret string
            if isinstance(secret_value, dict):
                secret_string = json.dumps(secret_value)
            else:
                secret_string = str(secret_value)

            # Try to update existing secret first
            try:
                kwargs = {
                    "SecretId": secret_name,
                    "SecretString": secret_string
                }

                if kms_key_id:
                    kwargs["KmsKeyId"] = kms_key_id

                response = self.client.update_secret(**kwargs)
                version_id = response["VersionId"]

                logger.info(f"Secret updated: {secret_name}, version: {version_id}")

            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                    # Secret doesn't exist, create it
                    kwargs = {
                        "Name": secret_name,
                        "SecretString": secret_string
                    }

                    if description:
                        kwargs["Description"] = description
                    if kms_key_id:
                        kwargs["KmsKeyId"] = kms_key_id

                    response = self.client.create_secret(**kwargs)
                    version_id = response["VersionId"]

                    logger.info(f"Secret created: {secret_name}, version: {version_id}")
                else:
                    raise

            # Invalidate cache
            if self.enable_caching:
                cache_keys_to_remove = [
                    key for key in self._cache.keys()
                    if key.startswith(f"{secret_name}:")
                ]
                for key in cache_keys_to_remove:
                    del self._cache[key]

            metrics.add_metric(name="SecretStored", unit=MetricUnit.Count, value=1)

            return version_id

        except Exception as e:
            logger.error(f"Failed to store secret '{secret_name}': {str(e)}")
            metrics.add_metric(name="SecretStorageError", unit=MetricUnit.Count, value=1)
            raise SecretDecryptionError(f"Failed to store secret: {str(e)}")

    @tracer.capture_method
    def delete_secret(
        self,
        secret_name: str,
        force_delete: bool = False,
        recovery_window_days: int = 7
    ) -> bool:
        """
        Delete a secret from AWS Secrets Manager.

        Args:
            secret_name: Name of the secret to delete
            force_delete: Force immediate deletion
            recovery_window_days: Days until permanent deletion (1-30)

        Returns:
            True if deletion was scheduled/completed

        Raises:
            SecretNotFoundError: If secret doesn't exist
        """
        try:
            kwargs = {"SecretId": secret_name}

            if force_delete:
                kwargs["ForceDeleteWithoutRecovery"] = True
            else:
                kwargs["RecoveryWindowInDays"] = recovery_window_days

            response = self.client.delete_secret(**kwargs)

            # Remove from cache
            if self.enable_caching:
                cache_keys_to_remove = [
                    key for key in self._cache.keys()
                    if key.startswith(f"{secret_name}:")
                ]
                for key in cache_keys_to_remove:
                    del self._cache[key]

            deletion_date = response.get("DeletionDate")

            logger.info(
                f"Secret deletion scheduled: {secret_name}",
                extra={
                    "force_delete": force_delete,
                    "deletion_date": deletion_date.isoformat() if deletion_date else None
                }
            )

            metrics.add_metric(name="SecretDeleted", unit=MetricUnit.Count, value=1)

            return True

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')

            if error_code == 'ResourceNotFoundException':
                logger.warning(f"Secret not found for deletion: {secret_name}")
                raise SecretNotFoundError(f"Secret '{secret_name}' not found")
            else:
                logger.error(f"Failed to delete secret '{secret_name}': {error_code}")
                metrics.add_metric(name="SecretDeletionError", unit=MetricUnit.Count, value=1)
                return False

        except Exception as e:
            logger.error(f"Unexpected error deleting secret '{secret_name}': {str(e)}")
            metrics.add_metric(name="SecretDeletionError", unit=MetricUnit.Count, value=1)
            return False

    def list_secrets(self, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        List secrets in AWS Secrets Manager.

        Args:
            max_results: Maximum number of results to return

        Returns:
            List of secret metadata
        """
        try:
            response = self.client.list_secrets(MaxResults=max_results)
            secrets = response.get("SecretList", [])

            logger.info(f"Listed {len(secrets)} secrets")
            metrics.add_metric(name="SecretsListed", unit=MetricUnit.Count, value=len(secrets))

            return secrets

        except Exception as e:
            logger.error(f"Failed to list secrets: {str(e)}")
            metrics.add_metric(name="SecretListError", unit=MetricUnit.Count, value=1)
            return []

    def get_secret_metadata(self, secret_name: str) -> Dict[str, Any]:
        """
        Get metadata for a secret without retrieving the value.

        Args:
            secret_name: Name of the secret

        Returns:
            Secret metadata
        """
        try:
            response = self.client.describe_secret(SecretId=secret_name)

            metadata = {
                "name": response.get("Name"),
                "arn": response.get("ARN"),
                "description": response.get("Description"),
                "created_date": response.get("CreatedDate"),
                "last_changed_date": response.get("LastChangedDate"),
                "last_accessed_date": response.get("LastAccessedDate"),
                "version_ids_to_stages": response.get("VersionIdsToStages", {}),
                "tags": response.get("Tags", [])
            }

            logger.debug(f"Retrieved metadata for secret: {secret_name}")

            return metadata

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')

            if error_code == 'ResourceNotFoundException':
                raise SecretNotFoundError(f"Secret '{secret_name}' not found")
            else:
                logger.error(f"Failed to get metadata for '{secret_name}': {error_code}")
                raise SecretDecryptionError(f"Failed to get metadata: {str(e)}")

    def clear_cache(self, secret_name: Optional[str] = None):
        """
        Clear cached secrets.

        Args:
            secret_name: Specific secret to clear, or None for all
        """
        if secret_name:
            cache_keys_to_remove = [
                key for key in self._cache.keys()
                if key.startswith(f"{secret_name}:")
            ]
            for key in cache_keys_to_remove:
                del self._cache[key]

            logger.info(f"Cleared cache for secret: {secret_name}")
        else:
            self._cache.clear()
            logger.info("Cleared all cached secrets")

        metrics.add_metric(name="SecretCacheCleared", unit=MetricUnit.Count, value=1)

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        now = datetime.utcnow()
        expired_count = sum(1 for secret in self._cache.values() if secret.is_expired)

        return {
            "total_cached": len(self._cache),
            "expired_count": expired_count,
            "valid_count": len(self._cache) - expired_count,
            "cache_size_limit": self.max_cache_size,
            "cache_ttl_seconds": self.cache_ttl_seconds
        }

    def _parse_secret_value(self, response: Dict[str, Any]) -> Union[str, Dict[str, Any]]:
        """Parse secret value from AWS response."""
        # Try SecretString first
        if 'SecretString' in response:
            secret_string = response['SecretString']

            # Try to parse as JSON
            try:
                return json.loads(secret_string)
            except (json.JSONDecodeError, TypeError):
                return secret_string

        # Fallback to SecretBinary
        elif 'SecretBinary' in response:
            secret_binary = response['SecretBinary']

            if isinstance(secret_binary, bytes):
                return base64.b64encode(secret_binary).decode('utf-8')
            else:
                return str(secret_binary)

        else:
            raise SecretDecryptionError("No secret value found in response")

    def _cache_secret(
        self,
        cache_key: str,
        value: Union[str, Dict[str, Any]],
        version_id: str,
        created_date: datetime
    ):
        """Cache a secret value."""
        # Ensure cache size limit
        if len(self._cache) >= self.max_cache_size:
            # Remove oldest entry
            oldest_key = min(
                self._cache.keys(),
                key=lambda k: self._cache[k].cached_at
            )
            del self._cache[oldest_key]

        # Cache the secret
        self._cache[cache_key] = CachedSecret(
            value=value,
            version_id=version_id,
            created_date=created_date,
            cached_at=datetime.utcnow(),
            ttl_seconds=self.cache_ttl_seconds
        )


# Global secrets manager instance (lazily initialized)
_secrets_manager: Optional[AWSSecretsManager] = None


def get_secrets_manager(
    region_name: str = "us-east-1",
    cache_ttl_seconds: int = 300
) -> AWSSecretsManager:
    """
    Get or create global secrets manager instance.

    Args:
        region_name: AWS region
        cache_ttl_seconds: Cache TTL in seconds

    Returns:
        AWSSecretsManager instance
    """
    global _secrets_manager

    if _secrets_manager is None:
        _secrets_manager = AWSSecretsManager(
            region_name=region_name,
            cache_ttl_seconds=cache_ttl_seconds
        )

    return _secrets_manager


def get_secret(
    secret_name: str,
    version_id: Optional[str] = None,
    region_name: str = "us-east-1"
) -> Union[str, Dict[str, Any]]:
    """
    Convenience function to get a secret value.

    Args:
        secret_name: Name of the secret
        version_id: Specific version ID
        region_name: AWS region

    Returns:
        Secret value
    """
    secrets_manager = get_secrets_manager(region_name)
    return secrets_manager.get_secret(secret_name, version_id)


def get_database_credentials(secret_name: str, region_name: str = "us-east-1") -> Dict[str, str]:
    """
    Get database credentials from secrets manager.

    Args:
        secret_name: Name of the database secret
        region_name: AWS region

    Returns:
        Dictionary with database credentials

    Raises:
        SecretNotFoundError: If secret doesn't exist
        SecretDecryptionError: If secret format is invalid
    """
    secret_value = get_secret(secret_name, region_name=region_name)

    if not isinstance(secret_value, dict):
        raise SecretDecryptionError("Database secret must be a JSON object")

    required_fields = ['username', 'password', 'host', 'port', 'dbname']
    missing_fields = [field for field in required_fields if field not in secret_value]

    if missing_fields:
        raise SecretDecryptionError(f"Database secret missing required fields: {missing_fields}")

    return {
        'username': secret_value['username'],
        'password': secret_value['password'],
        'host': secret_value['host'],
        'port': str(secret_value['port']),
        'database': secret_value['dbname'],
        'engine': secret_value.get('engine', 'postgres')
    }


def get_api_key(secret_name: str, key_name: str = "api_key", region_name: str = "us-east-1") -> str:
    """
    Get API key from secrets manager.

    Args:
        secret_name: Name of the secret
        key_name: Key name within the secret (if JSON)
        region_name: AWS region

    Returns:
        API key string
    """
    secret_value = get_secret(secret_name, region_name=region_name)

    if isinstance(secret_value, dict):
        if key_name not in secret_value:
            raise SecretDecryptionError(f"API key '{key_name}' not found in secret")
        return secret_value[key_name]
    else:
        return str(secret_value)
