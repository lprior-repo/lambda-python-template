"""
Dynamic configuration models for feature flags and app configuration.

This module defines models for AWS AppConfig-based feature flags and dynamic configuration,
following patterns from the aws-lambda-handler-cookbook for runtime configuration management.
"""

from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, Field


class FeatureFlagsNames(str, Enum):
    """Feature flag names enumeration."""

    # Campaign and promotional features
    TEN_PERCENT_CAMPAIGN = 'ten_percent_campaign'
    PREMIUM_USER_FEATURES = 'premium_user_features'
    SEASONAL_DISCOUNTS = 'seasonal_discounts'

    # API and performance features
    ENABLE_CACHING = 'enable_caching'
    ENHANCED_LOGGING = 'enhanced_logging'
    RATE_LIMITING = 'rate_limiting'

    # Business logic features
    ORDER_VALIDATION_V2 = 'order_validation_v2'
    CUSTOMER_NOTIFICATIONS = 'customer_notifications'
    INVENTORY_TRACKING = 'inventory_tracking'

    # Experimental features
    ML_RECOMMENDATIONS = 'ml_recommendations'
    REAL_TIME_ANALYTICS = 'real_time_analytics'
    ADVANCED_SEARCH = 'advanced_search'


class CampaignConfiguration(BaseModel):
    """Configuration for campaign-related features."""

    discount_percentage: Annotated[float, Field(
        default=10.0,
        description='Discount percentage for campaigns',
        ge=0.0,
        le=100.0
    )] = 10.0

    min_order_amount: Annotated[float, Field(
        default=25.0,
        description='Minimum order amount to qualify for discount',
        ge=0.0
    )] = 25.0

    max_discount_amount: Annotated[float, Field(
        default=50.0,
        description='Maximum discount amount per order',
        ge=0.0
    )] = 50.0

    campaign_message: Annotated[str, Field(
        default='Special discount applied!',
        description='Message to display when campaign is active'
    )] = 'Special discount applied!'


class PremiumConfiguration(BaseModel):
    """Configuration for premium user features."""

    free_shipping_threshold: Annotated[float, Field(
        default=0.0,
        description='Minimum order amount for free shipping (0 = always free)',
        ge=0.0
    )] = 0.0

    priority_processing: Annotated[bool, Field(
        default=True,
        description='Enable priority order processing for premium users'
    )] = True

    extended_return_period_days: Annotated[int, Field(
        default=60,
        description='Extended return period in days for premium users',
        ge=0,
        le=365
    )] = 60

    premium_support_enabled: Annotated[bool, Field(
        default=True,
        description='Enable premium customer support'
    )] = True


class PerformanceConfiguration(BaseModel):
    """Configuration for performance-related features."""

    cache_ttl_seconds: Annotated[int, Field(
        default=300,
        description='Cache time-to-live in seconds',
        ge=0,
        le=3600
    )] = 300

    max_concurrent_requests: Annotated[int, Field(
        default=100,
        description='Maximum concurrent requests allowed',
        ge=1,
        le=1000
    )] = 100

    request_timeout_seconds: Annotated[int, Field(
        default=30,
        description='Request timeout in seconds',
        ge=1,
        le=300
    )] = 30

    enable_compression: Annotated[bool, Field(
        default=True,
        description='Enable response compression'
    )] = True


class NotificationConfiguration(BaseModel):
    """Configuration for customer notification features."""

    email_notifications_enabled: Annotated[bool, Field(
        default=True,
        description='Enable email notifications'
    )] = True

    sms_notifications_enabled: Annotated[bool, Field(
        default=False,
        description='Enable SMS notifications'
    )] = False

    order_confirmation_template: Annotated[str, Field(
        default='order_confirmation_v1',
        description='Email template for order confirmations'
    )] = 'order_confirmation_v1'

    shipping_notification_template: Annotated[str, Field(
        default='shipping_notification_v1',
        description='Email template for shipping notifications'
    )] = 'shipping_notification_v1'

    notification_retry_attempts: Annotated[int, Field(
        default=3,
        description='Number of retry attempts for failed notifications',
        ge=0,
        le=10
    )] = 3


class ValidationConfiguration(BaseModel):
    """Configuration for validation features."""

    strict_email_validation: Annotated[bool, Field(
        default=True,
        description='Enable strict email format validation'
    )] = True

    require_phone_validation: Annotated[bool, Field(
        default=False,
        description='Require phone number validation'
    )] = False

    max_order_items: Annotated[int, Field(
        default=100,
        description='Maximum number of items per order',
        ge=1,
        le=1000
    )] = 100

    min_customer_name_length: Annotated[int, Field(
        default=2,
        description='Minimum customer name length',
        ge=1,
        le=10
    )] = 2

    max_customer_name_length: Annotated[int, Field(
        default=50,
        description='Maximum customer name length',
        ge=10,
        le=100
    )] = 50


class MyConfiguration(BaseModel):
    """Main configuration model containing all feature configurations."""

    # Feature flag configurations
    campaign_config: Annotated[CampaignConfiguration, Field(
        default_factory=CampaignConfiguration,
        description='Campaign and discount configuration'
    )] = CampaignConfiguration()

    premium_config: Annotated[PremiumConfiguration, Field(
        default_factory=PremiumConfiguration,
        description='Premium user features configuration'
    )] = PremiumConfiguration()

    performance_config: Annotated[PerformanceConfiguration, Field(
        default_factory=PerformanceConfiguration,
        description='Performance and caching configuration'
    )] = PerformanceConfiguration()

    notification_config: Annotated[NotificationConfiguration, Field(
        default_factory=NotificationConfiguration,
        description='Customer notification configuration'
    )] = NotificationConfiguration()

    validation_config: Annotated[ValidationConfiguration, Field(
        default_factory=ValidationConfiguration,
        description='Input validation configuration'
    )] = ValidationConfiguration()

    # Global configuration settings
    api_version: Annotated[str, Field(
        default='v1',
        description='API version identifier'
    )] = 'v1'

    debug_mode: Annotated[bool, Field(
        default=False,
        description='Enable debug mode with enhanced logging'
    )] = False

    maintenance_mode: Annotated[bool, Field(
        default=False,
        description='Enable maintenance mode (blocks most operations)'
    )] = False

    rate_limit_requests_per_minute: Annotated[int, Field(
        default=1000,
        description='Rate limit: requests per minute per client',
        ge=1,
        le=10000
    )] = 1000

    experimental_features_enabled: Annotated[bool, Field(
        default=False,
        description='Enable experimental features (use with caution)'
    )] = False

    # External service configurations
    external_services: Annotated[dict[str, Any], Field(
        default_factory=dict,
        description='Configuration for external service integrations'
    )] = {}

    # Custom application-specific settings
    custom_settings: Annotated[dict[str, Any], Field(
        default_factory=dict,
        description='Custom application-specific configuration'
    )] = {}

    def is_feature_enabled(self, feature_name: str) -> bool:
        """
        Check if a specific feature is enabled.

        Args:
            feature_name: Name of the feature to check

        Returns:
            True if the feature is enabled, False otherwise
        """
        feature_mapping = {
            'campaign': not self.maintenance_mode,
            'premium': not self.maintenance_mode,
            'notifications': self.notification_config.email_notifications_enabled,
            'caching': self.performance_config.cache_ttl_seconds > 0,
            'debug': self.debug_mode,
            'experimental': self.experimental_features_enabled,
        }

        return feature_mapping.get(feature_name, False)

    def get_rate_limit(self) -> int:
        """Get the current rate limit setting."""
        if self.maintenance_mode:
            return 10  # Very restrictive during maintenance
        return self.rate_limit_requests_per_minute

    def should_apply_campaign_discount(self, order_amount: float) -> bool:
        """
        Check if campaign discount should be applied to an order.

        Args:
            order_amount: Total order amount

        Returns:
            True if discount should be applied, False otherwise
        """
        if self.maintenance_mode:
            return False

        return (
            order_amount >= self.campaign_config.min_order_amount and
            not self.maintenance_mode
        )

    def get_cache_ttl(self) -> int:
        """Get the appropriate cache TTL based on current configuration."""
        if self.debug_mode:
            return 0  # No caching in debug mode
        if self.maintenance_mode:
            return 60  # Short cache during maintenance
        return self.performance_config.cache_ttl_seconds
