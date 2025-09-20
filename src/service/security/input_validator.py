"""
Input Validation and Security Patterns for Lambda Applications.

This module provides comprehensive input validation and security scanning
to protect against common web vulnerabilities like XSS, SQL injection,
and path traversal attacks.
"""

import re
import html
import urllib.parse
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum

from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from pydantic import BaseModel, validator

logger = Logger()
tracer = Tracer()
metrics = Metrics()


class SecurityThreatLevel(str, Enum):
    """Security threat levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationError(Exception):
    """Base validation error."""

    def __init__(self, message: str, field: Optional[str] = None,
                 threat_level: SecurityThreatLevel = SecurityThreatLevel.MEDIUM):
        super().__init__(message)
        self.field = field
        self.threat_level = threat_level


class SecurityViolation(ValidationError):
    """Security violation detected."""

    def __init__(self, message: str, violation_type: str, field: Optional[str] = None,
                 threat_level: SecurityThreatLevel = SecurityThreatLevel.HIGH):
        super().__init__(message, field, threat_level)
        self.violation_type = violation_type


@dataclass
class ValidationResult:
    """Result of security validation."""

    is_valid: bool
    violations: List[SecurityViolation]
    sanitized_data: Optional[Dict[str, Any]] = None
    risk_score: int = 0

    def add_violation(self, violation: SecurityViolation):
        """Add a security violation."""
        self.violations.append(violation)
        self.is_valid = False

        # Increase risk score based on threat level
        threat_scores = {
            SecurityThreatLevel.LOW: 1,
            SecurityThreatLevel.MEDIUM: 5,
            SecurityThreatLevel.HIGH: 15,
            SecurityThreatLevel.CRITICAL: 50
        }
        self.risk_score += threat_scores.get(violation.threat_level, 5)


class SQLInjectionDetector:
    """Detector for SQL injection attacks."""

    def __init__(self):
        # Common SQL injection patterns
        self.sql_patterns = [
            # Basic SQL keywords
            r"\b(union\s+select|select\s+\*|drop\s+table|delete\s+from)\b",
            r"\b(insert\s+into|update\s+set|create\s+table|alter\s+table)\b",

            # SQL comments
            r"(--|#|/\*|\*/)",

            # SQL injection techniques
            r"(\bor\b\s+\d+\s*=\s*\d+|\band\b\s+\d+\s*=\s*\d+)",
            r"(\'\s*or\s*\'|\"\s*or\s*\")",
            r"(\'\s*;\s*|\"\s*;\s*)",

            # UNION-based attacks
            r"\bunion\b.*\bselect\b",

            # Boolean-based blind SQL injection
            r"\b(true|false)\s*=\s*\b(true|false)",

            # Time-based blind SQL injection
            r"\b(waitfor\s+delay|sleep\s*\(|benchmark\s*\()",

            # Error-based SQL injection
            r"\b(extractvalue\s*\(|updatexml\s*\(|exp\s*\()",

            # SQL functions that shouldn't be in user input
            r"\b(concat\s*\(|char\s*\(|ascii\s*\(|substring\s*\()",

            # Stacked queries
            r";\s*(select|insert|update|delete|drop|create|alter)",
        ]

        # Compile patterns for performance
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in self.sql_patterns
        ]

    @tracer.capture_method
    def detect(self, value: str, field_name: str = None) -> List[SecurityViolation]:
        """Detect SQL injection attempts."""
        violations = []

        if not isinstance(value, str):
            return violations

        # URL decode the value to catch encoded attacks
        try:
            decoded_value = urllib.parse.unquote_plus(value)
        except Exception:
            decoded_value = value

        # Check against SQL injection patterns
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(decoded_value):
                violation = SecurityViolation(
                    message=f"Potential SQL injection detected in {field_name or 'input'}",
                    violation_type="sql_injection",
                    field=field_name,
                    threat_level=SecurityThreatLevel.HIGH
                )
                violations.append(violation)

                logger.warning(
                    "SQL injection attempt detected",
                    extra={
                        "field": field_name,
                        "pattern_index": i,
                        "value_length": len(value),
                        "detected_pattern": self.sql_patterns[i][:50]
                    }
                )

                metrics.add_metric(name="SQLInjectionDetected", unit=MetricUnit.Count, value=1)
                break  # One detection is enough

        return violations

    def sanitize(self, value: str) -> str:
        """Sanitize input by removing/escaping SQL injection patterns."""
        if not isinstance(value, str):
            return value

        # URL decode first
        try:
            sanitized = urllib.parse.unquote_plus(value)
        except Exception:
            sanitized = value

        # Remove dangerous SQL keywords and patterns
        dangerous_patterns = [
            r"(--|#|/\*|\*/)",  # SQL comments
            r";\s*(select|insert|update|delete|drop|create|alter)",  # Stacked queries
            r"\bunion\b.*\bselect\b",  # UNION attacks
        ]

        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)

        # Escape single quotes
        sanitized = sanitized.replace("'", "''")

        return sanitized.strip()


class XSSDetector:
    """Detector for Cross-Site Scripting (XSS) attacks."""

    def __init__(self):
        # XSS patterns
        self.xss_patterns = [
            # Script tags
            r"<\s*script[^>]*>.*?</\s*script\s*>",
            r"<\s*script[^>]*>",

            # Event handlers
            r"\bon\w+\s*=",
            r"\bon(load|error|click|mouseover|focus|blur)\s*=",

            # JavaScript URLs
            r"javascript\s*:",
            r"vbscript\s*:",
            r"data\s*:",

            # Common XSS vectors
            r"<\s*iframe[^>]*>",
            r"<\s*object[^>]*>",
            r"<\s*embed[^>]*>",
            r"<\s*link[^>]*>",
            r"<\s*meta[^>]*>",

            # Expression() attacks (IE)
            r"expression\s*\(",

            # Style-based XSS
            r"<\s*style[^>]*>.*?</\s*style\s*>",
            r"style\s*=.*?(expression|javascript|vbscript)",

            # Base64 encoded attacks
            r"data:text/html;base64,",

            # SVG-based XSS
            r"<\s*svg[^>]*>.*?</\s*svg\s*>",

            # Form-based XSS
            r"<\s*form[^>]*action\s*=",

            # Import statements
            r"@import",

            # HTML entities that could be XSS
            r"&#x?[0-9a-f]+;?",
        ]

        # Compile patterns
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            for pattern in self.xss_patterns
        ]

    @tracer.capture_method
    def detect(self, value: str, field_name: str = None) -> List[SecurityViolation]:
        """Detect XSS attempts."""
        violations = []

        if not isinstance(value, str):
            return violations

        # URL decode the value
        try:
            decoded_value = urllib.parse.unquote_plus(value)
        except Exception:
            decoded_value = value

        # HTML decode to catch encoded attacks
        try:
            html_decoded_value = html.unescape(decoded_value)
        except Exception:
            html_decoded_value = decoded_value

        # Check against XSS patterns
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(html_decoded_value):
                violation = SecurityViolation(
                    message=f"Potential XSS attack detected in {field_name or 'input'}",
                    violation_type="xss",
                    field=field_name,
                    threat_level=SecurityThreatLevel.HIGH
                )
                violations.append(violation)

                logger.warning(
                    "XSS attempt detected",
                    extra={
                        "field": field_name,
                        "pattern_index": i,
                        "value_length": len(value),
                        "detected_pattern": self.xss_patterns[i][:50]
                    }
                )

                metrics.add_metric(name="XSSDetected", unit=MetricUnit.Count, value=1)
                break  # One detection is enough

        return violations

    def sanitize(self, value: str) -> str:
        """Sanitize input by HTML escaping and removing dangerous patterns."""
        if not isinstance(value, str):
            return value

        # HTML escape the entire string
        sanitized = html.escape(value, quote=True)

        # Remove script tags and event handlers
        dangerous_patterns = [
            r"<\s*script[^>]*>.*?</\s*script\s*>",
            r"<\s*script[^>]*>",
            r"\bon\w+\s*=\s*['\"][^'\"]*['\"]",
            r"javascript\s*:",
            r"vbscript\s*:",
        ]

        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE | re.DOTALL)

        return sanitized.strip()


class PathTraversalDetector:
    """Detector for path traversal attacks."""

    def __init__(self):
        self.path_patterns = [
            r"\.\./",  # Directory traversal
            r"\.\.\w",  # Variant without slash
            r"%2e%2e%2f",  # URL encoded ../
            r"\.\.\\",  # Windows path traversal
            r"%2e%2e%5c",  # URL encoded ..\
            r"/etc/passwd",  # Unix system files
            r"/proc/",  # Unix process files
            r"c:\\",  # Windows system paths
            r"\\windows\\",  # Windows directories
            r"/root/",  # Unix root directory
            r"/home/",  # Unix home directories
        ]

        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.path_patterns
        ]

    @tracer.capture_method
    def detect(self, value: str, field_name: str = None) -> List[SecurityViolation]:
        """Detect path traversal attempts."""
        violations = []

        if not isinstance(value, str):
            return violations

        # URL decode the value
        try:
            decoded_value = urllib.parse.unquote_plus(value)
        except Exception:
            decoded_value = value

        # Check against path traversal patterns
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(decoded_value):
                violation = SecurityViolation(
                    message=f"Potential path traversal detected in {field_name or 'input'}",
                    violation_type="path_traversal",
                    field=field_name,
                    threat_level=SecurityThreatLevel.MEDIUM
                )
                violations.append(violation)

                logger.warning(
                    "Path traversal attempt detected",
                    extra={
                        "field": field_name,
                        "pattern_index": i,
                        "value_length": len(value),
                        "detected_pattern": self.path_patterns[i]
                    }
                )

                metrics.add_metric(name="PathTraversalDetected", unit=MetricUnit.Count, value=1)
                break

        return violations

    def sanitize(self, value: str) -> str:
        """Sanitize path input by removing traversal sequences."""
        if not isinstance(value, str):
            return value

        # Remove common path traversal patterns
        sanitized = value

        dangerous_patterns = [
            r"\.\.+[/\\]",  # Any number of dots followed by slash
            r"[/\\]\.\.+",  # Slash followed by dots
            r"%2e",  # URL encoded dots
            r"%2f",  # URL encoded forward slash
            r"%5c",  # URL encoded backslash
        ]

        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)

        # Remove absolute path indicators
        sanitized = re.sub(r"^[/\\]+", "", sanitized)
        sanitized = re.sub(r"^[a-zA-Z]:\\", "", sanitized)

        return sanitized.strip()


class SecurityValidator:
    """Main security validator that combines all detectors."""

    def __init__(self, enable_sanitization: bool = True):
        self.enable_sanitization = enable_sanitization
        self.sql_detector = SQLInjectionDetector()
        self.xss_detector = XSSDetector()
        self.path_detector = PathTraversalDetector()

        # Configuration
        self.max_string_length = 10000
        self.max_nesting_depth = 10

    @tracer.capture_method
    def validate_input(self, data: Union[Dict[str, Any], str, List[Any]],
                      field_prefix: str = "") -> ValidationResult:
        """Validate input data for security issues."""
        result = ValidationResult(is_valid=True, violations=[])

        if self.enable_sanitization:
            result.sanitized_data = {}

        try:
            self._validate_recursive(data, result, field_prefix, depth=0)

            # Log validation results
            if result.violations:
                logger.warning(
                    "Security violations detected",
                    extra={
                        "violation_count": len(result.violations),
                        "risk_score": result.risk_score,
                        "violations": [v.violation_type for v in result.violations]
                    }
                )

                metrics.add_metric(name="SecurityValidationViolations",
                                 unit=MetricUnit.Count, value=len(result.violations))
                metrics.add_metric(name="SecurityRiskScore",
                                 unit=MetricUnit.Count, value=result.risk_score)

            return result

        except Exception as e:
            logger.error(f"Security validation failed: {str(e)}")
            # In case of validation failure, assume unsafe
            result.is_valid = False
            result.add_violation(SecurityViolation(
                message="Security validation failed",
                violation_type="validation_error",
                threat_level=SecurityThreatLevel.MEDIUM
            ))
            return result

    def _validate_recursive(self, data: Any, result: ValidationResult,
                          field_prefix: str, depth: int):
        """Recursively validate data structure."""
        if depth > self.max_nesting_depth:
            result.add_violation(SecurityViolation(
                message=f"Maximum nesting depth exceeded: {depth}",
                violation_type="depth_limit",
                field=field_prefix,
                threat_level=SecurityThreatLevel.MEDIUM
            ))
            return

        if isinstance(data, dict):
            sanitized_dict = {} if self.enable_sanitization else None

            for key, value in data.items():
                field_name = f"{field_prefix}.{key}" if field_prefix else key

                # Validate the key itself
                if isinstance(key, str):
                    self._validate_string(key, result, f"{field_name}[key]")

                # Validate the value
                self._validate_recursive(value, result, field_name, depth + 1)

                # Add to sanitized data if enabled
                if self.enable_sanitization and sanitized_dict is not None:
                    sanitized_key = self._sanitize_string(key) if isinstance(key, str) else key
                    sanitized_value = self._get_sanitized_value(value)
                    sanitized_dict[sanitized_key] = sanitized_value

            if self.enable_sanitization and result.sanitized_data is not None:
                if field_prefix:
                    # Handle nested dicts
                    keys = field_prefix.split('.')
                    current = result.sanitized_data
                    for i, k in enumerate(keys[:-1]):
                        if k not in current:
                            current[k] = {}
                        current = current[k]
                    current[keys[-1]] = sanitized_dict
                else:
                    result.sanitized_data = sanitized_dict

        elif isinstance(data, list):
            sanitized_list = [] if self.enable_sanitization else None

            for i, item in enumerate(data):
                field_name = f"{field_prefix}[{i}]"
                self._validate_recursive(item, result, field_name, depth + 1)

                if self.enable_sanitization and sanitized_list is not None:
                    sanitized_list.append(self._get_sanitized_value(item))

            if self.enable_sanitization and result.sanitized_data is not None and sanitized_list is not None:
                # Store sanitized list (implementation depends on structure)
                pass

        elif isinstance(data, str):
            self._validate_string(data, result, field_prefix)

    def _validate_string(self, value: str, result: ValidationResult, field_name: str):
        """Validate a string value."""
        # Check length
        if len(value) > self.max_string_length:
            result.add_violation(SecurityViolation(
                message=f"String length exceeds maximum: {len(value)} > {self.max_string_length}",
                violation_type="length_limit",
                field=field_name,
                threat_level=SecurityThreatLevel.LOW
            ))

        # Run security detectors
        violations = []
        violations.extend(self.sql_detector.detect(value, field_name))
        violations.extend(self.xss_detector.detect(value, field_name))
        violations.extend(self.path_detector.detect(value, field_name))

        for violation in violations:
            result.add_violation(violation)

    def _sanitize_string(self, value: str) -> str:
        """Sanitize a string value."""
        if not isinstance(value, str):
            return value

        # Apply all sanitization methods
        sanitized = value
        sanitized = self.sql_detector.sanitize(sanitized)
        sanitized = self.xss_detector.sanitize(sanitized)
        sanitized = self.path_detector.sanitize(sanitized)

        # Truncate if too long
        if len(sanitized) > self.max_string_length:
            sanitized = sanitized[:self.max_string_length]

        return sanitized

    def _get_sanitized_value(self, value: Any) -> Any:
        """Get sanitized version of a value."""
        if isinstance(value, str):
            return self._sanitize_string(value)
        elif isinstance(value, dict):
            return {k: self._get_sanitized_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._get_sanitized_value(item) for item in value]
        else:
            return value


def validate_and_sanitize(data: Any, strict: bool = False) -> ValidationResult:
    """
    Convenience function to validate and sanitize input data.

    Args:
        data: Input data to validate
        strict: If True, raises exception on any security violation

    Returns:
        ValidationResult with validation status and sanitized data
    """
    validator = SecurityValidator(enable_sanitization=True)
    result = validator.validate_input(data)

    if strict and not result.is_valid:
        raise SecurityViolation(
            f"Security validation failed with {len(result.violations)} violations",
            violation_type="validation_failed"
        )

    return result


def sanitize_html_input(html_content: str) -> str:
    """
    Sanitize HTML content for safe display.

    Args:
        html_content: Raw HTML content

    Returns:
        Sanitized HTML content
    """
    if not isinstance(html_content, str):
        return html_content

    xss_detector = XSSDetector()
    return xss_detector.sanitize(html_content)


def validate_file_path(file_path: str, allowed_extensions: List[str] = None) -> bool:
    """
    Validate file path for security issues.

    Args:
        file_path: File path to validate
        allowed_extensions: List of allowed file extensions

    Returns:
        True if path is safe, False otherwise
    """
    if not isinstance(file_path, str):
        return False

    path_detector = PathTraversalDetector()
    violations = path_detector.detect(file_path)

    if violations:
        return False

    if allowed_extensions:
        extension = file_path.lower().split('.')[-1] if '.' in file_path else ''
        if extension not in [ext.lower().lstrip('.') for ext in allowed_extensions]:
            return False

    return True
