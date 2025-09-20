"""
Security Headers Middleware for Lambda Applications.

This module provides comprehensive security headers middleware that adds
OWASP-recommended security headers to HTTP responses, including Content
Security Policy (CSP), HSTS, and other security-related headers.
"""

import json
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum

from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit

logger = Logger()
tracer = Tracer()
metrics = Metrics()


class CSPDirective(str, Enum):
    """Content Security Policy directive names."""

    DEFAULT_SRC = "default-src"
    SCRIPT_SRC = "script-src"
    STYLE_SRC = "style-src"
    IMG_SRC = "img-src"
    CONNECT_SRC = "connect-src"
    FONT_SRC = "font-src"
    OBJECT_SRC = "object-src"
    MEDIA_SRC = "media-src"
    FRAME_SRC = "frame-src"
    CHILD_SRC = "child-src"
    WORKER_SRC = "worker-src"
    MANIFEST_SRC = "manifest-src"
    BASE_URI = "base-uri"
    FORM_ACTION = "form-action"
    FRAME_ANCESTORS = "frame-ancestors"
    PLUGIN_TYPES = "plugin-types"
    SANDBOX = "sandbox"
    UPGRADE_INSECURE_REQUESTS = "upgrade-insecure-requests"
    BLOCK_ALL_MIXED_CONTENT = "block-all-mixed-content"
    REQUIRE_SRI_FOR = "require-sri-for"
    REPORT_URI = "report-uri"
    REPORT_TO = "report-to"


class CSPSource(str, Enum):
    """Common CSP source values."""

    SELF = "'self'"
    NONE = "'none'"
    UNSAFE_INLINE = "'unsafe-inline'"
    UNSAFE_EVAL = "'unsafe-eval'"
    STRICT_DYNAMIC = "'strict-dynamic'"
    UNSAFE_HASHES = "'unsafe-hashes'"
    DATA = "data:"
    BLOB = "blob:"
    FILESYSTEM = "filesystem:"
    HTTPS = "https:"
    WSS = "wss:"


@dataclass
class CSPPolicy:
    """Content Security Policy configuration."""

    # Core directives
    default_src: List[str] = field(default_factory=lambda: [CSPSource.SELF])
    script_src: List[str] = field(default_factory=lambda: [CSPSource.SELF])
    style_src: List[str] = field(default_factory=lambda: [CSPSource.SELF])
    img_src: List[str] = field(default_factory=lambda: [CSPSource.SELF, CSPSource.DATA])
    connect_src: List[str] = field(default_factory=lambda: [CSPSource.SELF])
    font_src: List[str] = field(default_factory=lambda: [CSPSource.SELF])

    # Restrictive directives
    object_src: List[str] = field(default_factory=lambda: [CSPSource.NONE])
    media_src: List[str] = field(default_factory=lambda: [CSPSource.SELF])
    frame_src: List[str] = field(default_factory=lambda: [CSPSource.NONE])
    child_src: List[str] = field(default_factory=lambda: [CSPSource.SELF])
    worker_src: List[str] = field(default_factory=lambda: [CSPSource.SELF])
    manifest_src: List[str] = field(default_factory=lambda: [CSPSource.SELF])

    # Navigation directives
    base_uri: List[str] = field(default_factory=lambda: [CSPSource.SELF])
    form_action: List[str] = field(default_factory=lambda: [CSPSource.SELF])
    frame_ancestors: List[str] = field(default_factory=lambda: [CSPSource.NONE])

    # Other directives
    upgrade_insecure_requests: bool = True
    block_all_mixed_content: bool = True

    # Reporting
    report_uri: Optional[str] = None
    report_to: Optional[str] = None

    # Policy mode
    report_only: bool = False

    def to_header_value(self) -> str:
        """Convert CSP policy to header value string."""
        directives = []

        # Add source-based directives
        directive_map = {
            CSPDirective.DEFAULT_SRC: self.default_src,
            CSPDirective.SCRIPT_SRC: self.script_src,
            CSPDirective.STYLE_SRC: self.style_src,
            CSPDirective.IMG_SRC: self.img_src,
            CSPDirective.CONNECT_SRC: self.connect_src,
            CSPDirective.FONT_SRC: self.font_src,
            CSPDirective.OBJECT_SRC: self.object_src,
            CSPDirective.MEDIA_SRC: self.media_src,
            CSPDirective.FRAME_SRC: self.frame_src,
            CSPDirective.CHILD_SRC: self.child_src,
            CSPDirective.WORKER_SRC: self.worker_src,
            CSPDirective.MANIFEST_SRC: self.manifest_src,
            CSPDirective.BASE_URI: self.base_uri,
            CSPDirective.FORM_ACTION: self.form_action,
            CSPDirective.FRAME_ANCESTORS: self.frame_ancestors,
        }

        for directive, sources in directive_map.items():
            if sources:
                directives.append(f"{directive.value} {' '.join(sources)}")

        # Add boolean directives
        if self.upgrade_insecure_requests:
            directives.append(CSPDirective.UPGRADE_INSECURE_REQUESTS.value)

        if self.block_all_mixed_content:
            directives.append(CSPDirective.BLOCK_ALL_MIXED_CONTENT.value)

        # Add reporting directives
        if self.report_uri:
            directives.append(f"{CSPDirective.REPORT_URI.value} {self.report_uri}")

        if self.report_to:
            directives.append(f"{CSPDirective.REPORT_TO.value} {self.report_to}")

        return "; ".join(directives)

    def get_header_name(self) -> str:
        """Get the appropriate CSP header name."""
        return "Content-Security-Policy-Report-Only" if self.report_only else "Content-Security-Policy"

    @classmethod
    def strict_policy(cls) -> 'CSPPolicy':
        """Create a strict CSP policy for high-security applications."""
        return cls(
            default_src=[CSPSource.NONE],
            script_src=[CSPSource.SELF],
            style_src=[CSPSource.SELF],
            img_src=[CSPSource.SELF],
            connect_src=[CSPSource.SELF],
            font_src=[CSPSource.SELF],
            object_src=[CSPSource.NONE],
            media_src=[CSPSource.NONE],
            frame_src=[CSPSource.NONE],
            child_src=[CSPSource.NONE],
            worker_src=[CSPSource.NONE],
            manifest_src=[CSPSource.SELF],
            base_uri=[CSPSource.SELF],
            form_action=[CSPSource.SELF],
            frame_ancestors=[CSPSource.NONE],
            upgrade_insecure_requests=True,
            block_all_mixed_content=True
        )

    @classmethod
    def relaxed_policy(cls) -> 'CSPPolicy':
        """Create a relaxed CSP policy for development or legacy applications."""
        return cls(
            default_src=[CSPSource.SELF],
            script_src=[CSPSource.SELF, CSPSource.UNSAFE_INLINE],
            style_src=[CSPSource.SELF, CSPSource.UNSAFE_INLINE],
            img_src=[CSPSource.SELF, CSPSource.DATA, CSPSource.HTTPS],
            connect_src=[CSPSource.SELF],
            font_src=[CSPSource.SELF, CSPSource.DATA],
            object_src=[CSPSource.NONE],
            media_src=[CSPSource.SELF],
            frame_src=[CSPSource.SELF],
            child_src=[CSPSource.SELF],
            worker_src=[CSPSource.SELF],
            manifest_src=[CSPSource.SELF],
            base_uri=[CSPSource.SELF],
            form_action=[CSPSource.SELF],
            frame_ancestors=[CSPSource.SELF],
            upgrade_insecure_requests=False,
            block_all_mixed_content=False
        )

    @classmethod
    def api_policy(cls) -> 'CSPPolicy':
        """Create a CSP policy optimized for API endpoints."""
        return cls(
            default_src=[CSPSource.NONE],
            script_src=[CSPSource.NONE],
            style_src=[CSPSource.NONE],
            img_src=[CSPSource.NONE],
            connect_src=[CSPSource.SELF],
            font_src=[CSPSource.NONE],
            object_src=[CSPSource.NONE],
            media_src=[CSPSource.NONE],
            frame_src=[CSPSource.NONE],
            child_src=[CSPSource.NONE],
            worker_src=[CSPSource.NONE],
            manifest_src=[CSPSource.NONE],
            base_uri=[CSPSource.NONE],
            form_action=[CSPSource.NONE],
            frame_ancestors=[CSPSource.NONE],
            upgrade_insecure_requests=True,
            block_all_mixed_content=True
        )


@dataclass
class SecurityConfig:
    """Configuration for security headers."""

    # Content Security Policy
    csp_policy: Optional[CSPPolicy] = None

    # HSTS (HTTP Strict Transport Security)
    hsts_max_age: int = 31536000  # 1 year
    hsts_include_subdomains: bool = True
    hsts_preload: bool = False

    # X-Frame-Options
    x_frame_options: str = "DENY"  # DENY, SAMEORIGIN, or ALLOW-FROM uri

    # X-Content-Type-Options
    x_content_type_options: str = "nosniff"

    # X-XSS-Protection (deprecated but still useful for older browsers)
    x_xss_protection: str = "1; mode=block"

    # Referrer-Policy
    referrer_policy: str = "strict-origin-when-cross-origin"

    # Permissions-Policy (formerly Feature-Policy)
    permissions_policy: Dict[str, List[str]] = field(default_factory=lambda: {
        "geolocation": ["()"],
        "microphone": ["()"],
        "camera": ["()"],
        "payment": ["()"],
        "usb": ["()"],
        "magnetometer": ["()"],
        "gyroscope": ["()"],
        "speaker": ["()"]
    })

    # Cross-Origin policies
    cross_origin_embedder_policy: str = "require-corp"
    cross_origin_opener_policy: str = "same-origin"
    cross_origin_resource_policy: str = "same-site"

    # Cache control for security-sensitive responses
    cache_control: str = "no-store, no-cache, must-revalidate, proxy-revalidate"
    pragma: str = "no-cache"
    expires: str = "0"

    # Server identification
    server_header: Optional[str] = None  # Remove server identification
    x_powered_by: Optional[str] = None  # Remove X-Powered-By header

    # Custom headers
    custom_headers: Dict[str, str] = field(default_factory=dict)

    # Environment-specific settings
    enforce_https: bool = True
    add_cache_headers: bool = False

    def get_permissions_policy_value(self) -> str:
        """Convert permissions policy to header value."""
        policies = []
        for feature, allowlist in self.permissions_policy.items():
            if allowlist:
                allowlist_str = " ".join(allowlist)
                policies.append(f"{feature}={allowlist_str}")
            else:
                policies.append(f"{feature}=()")

        return ", ".join(policies)


class SecurityHeadersMiddleware:
    """
    Middleware for adding comprehensive security headers to HTTP responses.

    This middleware follows OWASP security guidelines and adds protection
    against common web vulnerabilities including XSS, clickjacking,
    MIME-type sniffing, and information disclosure.
    """

    def __init__(self, config: Optional[SecurityConfig] = None):
        """
        Initialize security headers middleware.

        Args:
            config: Security configuration. If None, uses secure defaults.
        """
        self.config = config or SecurityConfig()

        # Set default CSP policy if none provided
        if self.config.csp_policy is None:
            self.config.csp_policy = CSPPolicy.api_policy()

        logger.info(
            "Security headers middleware initialized",
            extra={
                "hsts_max_age": self.config.hsts_max_age,
                "csp_enabled": self.config.csp_policy is not None,
                "enforce_https": self.config.enforce_https
            }
        )

    @tracer.capture_method
    def add_security_headers(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add security headers to HTTP response.

        Args:
            response: HTTP response dictionary

        Returns:
            Modified response with security headers
        """
        if 'headers' not in response:
            response['headers'] = {}

        headers = response['headers']

        try:
            # Content Security Policy
            if self.config.csp_policy:
                csp_header = self.config.csp_policy.get_header_name()
                csp_value = self.config.csp_policy.to_header_value()
                headers[csp_header] = csp_value

            # HTTP Strict Transport Security
            if self.config.enforce_https:
                hsts_value = f"max-age={self.config.hsts_max_age}"
                if self.config.hsts_include_subdomains:
                    hsts_value += "; includeSubDomains"
                if self.config.hsts_preload:
                    hsts_value += "; preload"
                headers["Strict-Transport-Security"] = hsts_value

            # X-Frame-Options
            headers["X-Frame-Options"] = self.config.x_frame_options

            # X-Content-Type-Options
            headers["X-Content-Type-Options"] = self.config.x_content_type_options

            # X-XSS-Protection (for older browsers)
            headers["X-XSS-Protection"] = self.config.x_xss_protection

            # Referrer-Policy
            headers["Referrer-Policy"] = self.config.referrer_policy

            # Permissions-Policy
            if self.config.permissions_policy:
                headers["Permissions-Policy"] = self.config.get_permissions_policy_value()

            # Cross-Origin policies
            headers["Cross-Origin-Embedder-Policy"] = self.config.cross_origin_embedder_policy
            headers["Cross-Origin-Opener-Policy"] = self.config.cross_origin_opener_policy
            headers["Cross-Origin-Resource-Policy"] = self.config.cross_origin_resource_policy

            # Cache control headers (for sensitive responses)
            if self.config.add_cache_headers:
                headers["Cache-Control"] = self.config.cache_control
                headers["Pragma"] = self.config.pragma
                headers["Expires"] = self.config.expires

            # Remove server identification headers
            if self.config.server_header is None:
                headers.pop("Server", None)
            elif self.config.server_header:
                headers["Server"] = self.config.server_header

            if self.config.x_powered_by is None:
                headers.pop("X-Powered-By", None)
            elif self.config.x_powered_by:
                headers["X-Powered-By"] = self.config.x_powered_by

            # Add custom headers
            headers.update(self.config.custom_headers)

            # Record metrics
            metrics.add_metric(name="SecurityHeadersAdded", unit=MetricUnit.Count, value=1)
            metrics.add_metric(name="SecurityHeadersCount", unit=MetricUnit.Count, value=len(headers))

            logger.debug(
                "Security headers added to response",
                extra={
                    "headers_count": len(headers),
                    "csp_enabled": "Content-Security-Policy" in headers or "Content-Security-Policy-Report-Only" in headers,
                    "hsts_enabled": "Strict-Transport-Security" in headers
                }
            )

        except Exception as e:
            logger.error(f"Failed to add security headers: {str(e)}")
            metrics.add_metric(name="SecurityHeadersError", unit=MetricUnit.Count, value=1)
            # Don't fail the request, just log the error

        return response

    def __call__(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Make the middleware callable."""
        return self.add_security_headers(response)


def add_security_headers(response: Dict[str, Any],
                        config: Optional[SecurityConfig] = None) -> Dict[str, Any]:
    """
    Convenience function to add security headers to a response.

    Args:
        response: HTTP response dictionary
        config: Security configuration (optional)

    Returns:
        Response with security headers added
    """
    middleware = SecurityHeadersMiddleware(config)
    return middleware.add_security_headers(response)


def create_api_security_config(
    strict: bool = True,
    report_csp_violations: bool = False,
    csp_report_uri: Optional[str] = None
) -> SecurityConfig:
    """
    Create security configuration optimized for API endpoints.

    Args:
        strict: Use strict security settings
        report_csp_violations: Enable CSP violation reporting
        csp_report_uri: URI for CSP violation reports

    Returns:
        SecurityConfig instance
    """
    # Choose CSP policy based on strictness
    if strict:
        csp_policy = CSPPolicy.strict_policy()
    else:
        csp_policy = CSPPolicy.api_policy()

    # Configure CSP reporting
    if report_csp_violations and csp_report_uri:
        csp_policy.report_uri = csp_report_uri
        csp_policy.report_only = False  # Enforce policy, but also report

    return SecurityConfig(
        csp_policy=csp_policy,
        hsts_max_age=31536000 if strict else 300,
        hsts_include_subdomains=strict,
        hsts_preload=False,  # Don't auto-enable preload
        x_frame_options="DENY",
        referrer_policy="strict-origin-when-cross-origin" if strict else "origin-when-cross-origin",
        permissions_policy={
            "geolocation": ["()"],
            "microphone": ["()"],
            "camera": ["()"],
            "payment": ["()"],
            "usb": ["()"],
            "interest-cohort": ["()"]  # Disable FLoC
        } if strict else {},
        cross_origin_embedder_policy="require-corp" if strict else "unsafe-none",
        cross_origin_opener_policy="same-origin",
        cross_origin_resource_policy="same-site",
        enforce_https=True,
        add_cache_headers=True,
        server_header=None,  # Remove server identification
        x_powered_by=None   # Remove X-Powered-By
    )


def create_web_app_security_config(
    cdn_domains: List[str] = None,
    api_domains: List[str] = None,
    analytics_domains: List[str] = None
) -> SecurityConfig:
    """
    Create security configuration for web applications.

    Args:
        cdn_domains: List of CDN domains for assets
        api_domains: List of API domains for connections
        analytics_domains: List of analytics domains

    Returns:
        SecurityConfig instance
    """
    cdn_domains = cdn_domains or []
    api_domains = api_domains or []
    analytics_domains = analytics_domains or []

    # Build CSP sources
    script_src = [CSPSource.SELF] + cdn_domains
    style_src = [CSPSource.SELF, CSPSource.UNSAFE_INLINE] + cdn_domains
    img_src = [CSPSource.SELF, CSPSource.DATA] + cdn_domains + analytics_domains
    connect_src = [CSPSource.SELF] + api_domains + analytics_domains
    font_src = [CSPSource.SELF] + cdn_domains

    csp_policy = CSPPolicy(
        default_src=[CSPSource.SELF],
        script_src=script_src,
        style_src=style_src,
        img_src=img_src,
        connect_src=connect_src,
        font_src=font_src,
        object_src=[CSPSource.NONE],
        media_src=[CSPSource.SELF],
        frame_src=[CSPSource.NONE],
        child_src=[CSPSource.SELF],
        worker_src=[CSPSource.SELF],
        manifest_src=[CSPSource.SELF],
        base_uri=[CSPSource.SELF],
        form_action=[CSPSource.SELF],
        frame_ancestors=[CSPSource.NONE],
        upgrade_insecure_requests=True,
        block_all_mixed_content=True
    )

    return SecurityConfig(
        csp_policy=csp_policy,
        hsts_max_age=31536000,
        hsts_include_subdomains=True,
        x_frame_options="DENY",
        referrer_policy="strict-origin-when-cross-origin",
        permissions_policy={
            "geolocation": ["self"],
            "microphone": ["()"],
            "camera": ["()"],
            "payment": ["self"],
            "usb": ["()"],
            "interest-cohort": ["()"]
        },
        enforce_https=True,
        add_cache_headers=False  # Let CDN handle caching
    )


# Pre-configured middleware instances
STRICT_API_MIDDLEWARE = SecurityHeadersMiddleware(create_api_security_config(strict=True))
RELAXED_API_MIDDLEWARE = SecurityHeadersMiddleware(create_api_security_config(strict=False))
