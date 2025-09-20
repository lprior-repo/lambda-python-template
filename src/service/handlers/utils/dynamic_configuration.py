"""
Dynamic configuration utility for AWS AppConfig integration.

This module provides utilities for fetching and caching dynamic configuration
from AWS AppConfig, following patterns from the aws-lambda-handler-cookbook.
"""

import json
from typing import Any, Type, TypeVar

from aws_lambda_powertools.utilities.parameters import AppConfigProvider, get_app_config
from cachetools import TTLCache
from pydantic import BaseModel, ValidationError

from service.handlers.models.dynamic_configuration import MyConfiguration
from service.handlers.utils.observability import logger

T = TypeVar('T', bound=BaseModel)

# Global cache for configuration data
_config_cache = TTLCache(maxsize=100, ttl=300)  # 5-minute TTL
_app_config_provider: AppConfigProvider | None = None


def get_configuration_store() -> AppConfigProvider:
    """
    Get the AWS AppConfig provider instance.

    Returns:
        Configured AppConfig provider
    """
    global _app_config_provider

    if _app_config_provider is None:
        _app_config_provider = AppConfigProvider(
            environment='production',  # AppConfig environment
            application='lambda-python-template',  # AppConfig application name
        )
        logger.debug('AppConfig provider initialized')

    return _app_config_provider


def parse_configuration(model: Type[T], force_refresh: bool = False) -> T:
    """
    Parse dynamic configuration from AWS AppConfig using Pydantic model.

    Args:
        model: Pydantic model class to parse configuration into
        force_refresh: Whether to force refresh the configuration cache

    Returns:
        Parsed configuration model instance

    Raises:
        ValidationError: If configuration data doesn't match the model schema
        Exception: If configuration cannot be fetched from AppConfig
    """
    cache_key = f"config_{model.__name__}"

    # Check cache first unless forced refresh
    if not force_refresh and cache_key in _config_cache:
        logger.debug(f'Using cached configuration for {model.__name__}')
        return _config_cache[cache_key]

    try:
        # Fetch configuration from AppConfig
        config_data = get_app_config(
            name='feature_flags',  # Configuration profile name
            environment='production',
            application='lambda-python-template',
            max_age=300,  # Cache for 5 minutes
        )

        logger.debug(f'Fetched configuration from AppConfig: {config_data}')

        # Parse JSON if it's a string
        if isinstance(config_data, str):
            config_data = json.loads(config_data)

        # Parse into Pydantic model
        parsed_config = model.model_validate(config_data)

        # Cache the parsed configuration
        _config_cache[cache_key] = parsed_config

        logger.info(f'Successfully parsed configuration for {model.__name__}')
        return parsed_config

    except ValidationError as e:
        logger.error(f'Configuration validation error for {model.__name__}: {e}')
        # Return default configuration on validation error
        default_config = model()
        _config_cache[cache_key] = default_config
        return default_config

    except Exception as e:
        logger.error(f'Failed to fetch configuration from AppConfig: {e}')
        # Return default configuration on any error
        default_config = model()
        _config_cache[cache_key] = default_config
        return default_config


def get_feature_flag(
    flag_name: str,
    context: dict[str, Any] | None = None,
    default_value: bool = False
) -> bool:
    """
    Get a feature flag value from AWS AppConfig.

    Args:
        flag_name: Name of the feature flag
        context: Context for feature flag evaluation (user attributes, etc.)
        default_value: Default value if flag cannot be retrieved

    Returns:
        Feature flag value
    """
    try:
        config_store = get_configuration_store()

        # Evaluate feature flag with context
        flag_value = config_store.evaluate(
            name=flag_name,
            context=context or {},
            default=default_value,
        )

        logger.debug(f'Feature flag {flag_name}: {flag_value}', extra={
            'flag_name': flag_name,
            'flag_value': flag_value,
            'context': context
        })

        return flag_value

    except Exception as e:
        logger.warning(f'Failed to evaluate feature flag {flag_name}: {e}')
        return default_value


def get_configuration_value(
    key: str,
    default_value: Any = None,
    value_type: Type = str
) -> Any:
    """
    Get a specific configuration value from the cached configuration.

    Args:
        key: Configuration key (dot notation supported, e.g., 'campaign_config.discount_percentage')
        default_value: Default value if key is not found
        value_type: Expected type of the value

    Returns:
        Configuration value cast to the specified type
    """
    try:
        config = parse_configuration(MyConfiguration)

        # Support dot notation for nested keys
        value = config
        for part in key.split('.'):
            if hasattr(value, part):
                value = getattr(value, part)
            else:
                logger.warning(f'Configuration key not found: {key}')
                return default_value

        # Type casting
        if value_type and not isinstance(value, value_type):
            try:
                value = value_type(value)
            except (ValueError, TypeError) as e:
                logger.warning(f'Failed to cast configuration value to {value_type}: {e}')
                return default_value

        return value

    except Exception as e:
        logger.error(f'Failed to get configuration value for key {key}: {e}')
        return default_value


def refresh_configuration() -> None:
    """
    Force refresh of all cached configuration data.

    This function clears the configuration cache, forcing the next
    configuration request to fetch fresh data from AppConfig.
    """
    global _config_cache
    _config_cache.clear()
    logger.info('Configuration cache cleared, next request will fetch fresh data')


def is_maintenance_mode() -> bool:
    """
    Check if the application is in maintenance mode.

    Returns:
        True if maintenance mode is enabled, False otherwise
    """
    return get_configuration_value('maintenance_mode', default_value=False, value_type=bool)


def get_rate_limit() -> int:
    """
    Get the current rate limit configuration.

    Returns:
        Rate limit requests per minute
    """
    return get_configuration_value(
        'rate_limit_requests_per_minute',
        default_value=1000,
        value_type=int
    )


def is_debug_mode() -> bool:
    """
    Check if debug mode is enabled.

    Returns:
        True if debug mode is enabled, False otherwise
    """
    return get_configuration_value('debug_mode', default_value=False, value_type=bool)


def get_cache_ttl() -> int:
    """
    Get the cache TTL configuration.

    Returns:
        Cache TTL in seconds
    """
    try:
        config = parse_configuration(MyConfiguration)
        return config.get_cache_ttl()
    except Exception as e:
        logger.error(f'Failed to get cache TTL: {e}')
        return 300  # Default 5 minutes


def should_apply_discount(order_amount: float) -> bool:
    """
    Check if campaign discount should be applied based on current configuration.

    Args:
        order_amount: Total order amount

    Returns:
        True if discount should be applied, False otherwise
    """
    try:
        config = parse_configuration(MyConfiguration)
        return config.should_apply_campaign_discount(order_amount)
    except Exception as e:
        logger.error(f'Failed to check discount eligibility: {e}')
        return False
