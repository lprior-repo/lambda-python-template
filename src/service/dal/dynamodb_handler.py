"""
Data Access Layer (DAL) for DynamoDB operations.

This module provides a comprehensive data access layer for DynamoDB operations,
following patterns from the aws-lambda-handler-cookbook with proper error handling,
retry logic, and observability.
"""

import json
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type, TypeVar, Union
from uuid import uuid4

import boto3
from aws_lambda_powertools.metrics import MetricUnit
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError, BotoCoreError
from pydantic import BaseModel, ValidationError

from service.handlers.utils.idempotency import (
    BaseServiceError,
    ErrorCategory,
    ErrorContext,
    ErrorSeverity,
    ExternalServiceError,
    ResourceNotFoundError,
    create_error_context,
)
from service.handlers.utils.observability import logger, metrics, tracer

T = TypeVar('T', bound=BaseModel)


class DALError(BaseServiceError):
    """Base exception for Data Access Layer errors."""

    def __init__(
        self,
        message: str,
        operation: str,
        table_name: str,
        error_code: str = "DAL_ERROR",
        severity: ErrorSeverity = ErrorSeverity.HIGH,
        context: Optional[ErrorContext] = None,
        retry_after: Optional[int] = None,
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            severity=severity,
            category=ErrorCategory.INFRASTRUCTURE,
            context=context,
            retry_after=retry_after,
            user_message="A database error occurred. Please try again later.",
        )
        self.operation = operation
        self.table_name = table_name


class ItemNotFoundError(ResourceNotFoundError):
    """Raised when a DynamoDB item is not found."""

    def __init__(
        self,
        table_name: str,
        key: Dict[str, Any],
        context: Optional[ErrorContext] = None,
    ):
        self.table_name = table_name
        self.key = key
        super().__init__(
            resource_type="Item",
            resource_id=str(key),
            context=context,
        )


class ConditionalCheckFailedError(DALError):
    """Raised when a conditional check fails in DynamoDB."""

    def __init__(
        self,
        table_name: str,
        condition: str,
        context: Optional[ErrorContext] = None,
    ):
        super().__init__(
            message=f"Conditional check failed: {condition}",
            operation="conditional_write",
            table_name=table_name,
            error_code="CONDITIONAL_CHECK_FAILED",
            severity=ErrorSeverity.MEDIUM,
            context=context,
        )
        self.condition = condition


class BaseDAL(ABC):
    """Abstract base class for Data Access Layer implementations."""

    @abstractmethod
    def get_item(self, key: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get a single item by key."""
        pass

    @abstractmethod
    def put_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update an item."""
        pass

    @abstractmethod
    def delete_item(self, key: Dict[str, Any]) -> bool:
        """Delete an item by key."""
        pass

    @abstractmethod
    def query_items(
        self,
        key_condition: Any,
        filter_expression: Optional[Any] = None,
        limit: Optional[int] = None,
        scan_index_forward: bool = True,
        exclusive_start_key: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Query items with pagination support."""
        pass

    @abstractmethod
    def scan_items(
        self,
        filter_expression: Optional[Any] = None,
        limit: Optional[int] = None,
        exclusive_start_key: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Scan items with pagination support."""
        pass


class DynamoDBHandler(BaseDAL):
    """Enhanced DynamoDB handler with comprehensive error handling and observability."""

    def __init__(
        self,
        table_name: str,
        region_name: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        max_retries: int = 3,
        retry_backoff_base: float = 0.1,
    ):
        """
        Initialize DynamoDB handler.

        Args:
            table_name: Name of the DynamoDB table
            region_name: AWS region name
            endpoint_url: DynamoDB endpoint URL (for local testing)
            max_retries: Maximum number of retries for failed operations
            retry_backoff_base: Base delay for exponential backoff
        """
        self.table_name = table_name
        self.max_retries = max_retries
        self.retry_backoff_base = retry_backoff_base

        # Initialize DynamoDB resource
        session_config = {}
        if region_name:
            session_config['region_name'] = region_name

        self.dynamodb = boto3.resource('dynamodb', **session_config)
        if endpoint_url:
            self.dynamodb = boto3.resource('dynamodb', endpoint_url=endpoint_url, **session_config)

        self.table = self.dynamodb.Table(table_name)

        logger.info("DynamoDB handler initialized", extra={
            "table_name": table_name,
            "region_name": region_name,
            "endpoint_url": endpoint_url,
        })

    @tracer.capture_method
    def _handle_dynamodb_errors(self, operation: str, context: Optional[ErrorContext] = None):
        """Decorator to handle DynamoDB errors consistently."""

        def decorator(func):
            def wrapper(*args, **kwargs):
                operation_start = time.time()

                try:
                    # Add operation metrics
                    metrics.add_metric(name=f"DynamoDB{operation}Count", unit=MetricUnit.Count, value=1)

                    result = func(*args, **kwargs)

                    # Add success metrics
                    operation_duration = (time.time() - operation_start) * 1000
                    metrics.add_metric(name=f"DynamoDB{operation}Duration", unit=MetricUnit.Milliseconds, value=operation_duration)
                    metrics.add_metric(name=f"DynamoDB{operation}Success", unit=MetricUnit.Count, value=1)

                    tracer.put_annotation("dynamodb_operation", operation)
                    tracer.put_annotation("table_name", self.table_name)

                    return result

                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    error_message = e.response['Error']['Message']

                    # Add error metrics
                    metrics.add_metric(name=f"DynamoDB{operation}Error", unit=MetricUnit.Count, value=1)
                    metrics.add_metric(name=f"DynamoDB{error_code}Error", unit=MetricUnit.Count, value=1)

                    logger.error(f"DynamoDB {operation} error", extra={
                        "error_code": error_code,
                        "error_message": error_message,
                        "table_name": self.table_name,
                        "operation": operation,
                    })

                    # Handle specific error types
                    if error_code == 'ResourceNotFoundException':
                        raise DALError(
                            message=f"Table {self.table_name} not found",
                            operation=operation,
                            table_name=self.table_name,
                            error_code="TABLE_NOT_FOUND",
                            context=context,
                        )
                    elif error_code == 'ConditionalCheckFailedException':
                        raise ConditionalCheckFailedError(
                            table_name=self.table_name,
                            condition="Item condition check failed",
                            context=context,
                        )
                    elif error_code == 'ProvisionedThroughputExceededException':
                        raise DALError(
                            message="DynamoDB throughput exceeded",
                            operation=operation,
                            table_name=self.table_name,
                            error_code="THROUGHPUT_EXCEEDED",
                            severity=ErrorSeverity.HIGH,
                            context=context,
                            retry_after=60,
                        )
                    elif error_code == 'ThrottlingException':
                        raise DALError(
                            message="DynamoDB throttling detected",
                            operation=operation,
                            table_name=self.table_name,
                            error_code="THROTTLING_ERROR",
                            severity=ErrorSeverity.HIGH,
                            context=context,
                            retry_after=30,
                        )
                    else:
                        raise DALError(
                            message=f"DynamoDB error: {error_message}",
                            operation=operation,
                            table_name=self.table_name,
                            error_code=f"DYNAMODB_{error_code}",
                            context=context,
                        )

                except BotoCoreError as e:
                    metrics.add_metric(name=f"DynamoDB{operation}Error", unit=MetricUnit.Count, value=1)
                    logger.error(f"DynamoDB connection error during {operation}", extra={
                        "error": str(e),
                        "table_name": self.table_name,
                    })
                    raise ExternalServiceError(
                        message=f"Database connection error: {str(e)}",
                        service_name="DynamoDB",
                        error_code="DATABASE_CONNECTION_ERROR",
                        context=context,
                    )

                except Exception as e:
                    metrics.add_metric(name=f"DynamoDB{operation}Error", unit=MetricUnit.Count, value=1)
                    logger.error(f"Unexpected error during {operation}", extra={
                        "error": str(e),
                        "table_name": self.table_name,
                    })
                    raise DALError(
                        message=f"Unexpected database error: {str(e)}",
                        operation=operation,
                        table_name=self.table_name,
                        error_code="UNEXPECTED_DATABASE_ERROR",
                        context=context,
                    )

            return wrapper
        return decorator

    @tracer.capture_method
    def get_item(
        self,
        key: Dict[str, Any],
        consistent_read: bool = False,
        attributes_to_get: Optional[List[str]] = None,
        context: Optional[ErrorContext] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Get a single item from DynamoDB.

        Args:
            key: Primary key of the item to retrieve
            consistent_read: Whether to use strongly consistent read
            attributes_to_get: Specific attributes to retrieve
            context: Error context for tracing

        Returns:
            Item data or None if not found

        Raises:
            DALError: If DynamoDB operation fails
        """

        @self._handle_dynamodb_errors("GetItem", context)
        def _get_item():
            get_item_kwargs = {
                'Key': key,
                'ConsistentRead': consistent_read,
            }

            if attributes_to_get:
                get_item_kwargs['ProjectionExpression'] = ', '.join(attributes_to_get)

            response = self.table.get_item(**get_item_kwargs)
            item = response.get('Item')

            if item:
                logger.debug("Item retrieved successfully", extra={
                    "table_name": self.table_name,
                    "key": key,
                    "item_size": len(json.dumps(item, default=str)),
                })

            return item

        return _get_item()

    @tracer.capture_method
    def put_item(
        self,
        item: Dict[str, Any],
        condition_expression: Optional[Any] = None,
        context: Optional[ErrorContext] = None,
    ) -> Dict[str, Any]:
        """
        Put an item into DynamoDB.

        Args:
            item: Item data to store
            condition_expression: Conditional expression for the put operation
            context: Error context for tracing

        Returns:
            The stored item data

        Raises:
            DALError: If DynamoDB operation fails
            ConditionalCheckFailedError: If condition check fails
        """

        @self._handle_dynamodb_errors("PutItem", context)
        def _put_item():
            # Add timestamps
            now = datetime.now(timezone.utc).isoformat()
            if 'created_at' not in item:
                item['created_at'] = now
            item['updated_at'] = now

            put_item_kwargs = {'Item': item}
            if condition_expression:
                put_item_kwargs['ConditionExpression'] = condition_expression

            self.table.put_item(**put_item_kwargs)

            logger.info("Item stored successfully", extra={
                "table_name": self.table_name,
                "item_id": item.get('id', 'unknown'),
                "item_size": len(json.dumps(item, default=str)),
            })

            return item

        return _put_item()

    @tracer.capture_method
    def update_item(
        self,
        key: Dict[str, Any],
        update_expression: str,
        expression_attribute_values: Optional[Dict[str, Any]] = None,
        expression_attribute_names: Optional[Dict[str, str]] = None,
        condition_expression: Optional[Any] = None,
        return_values: str = "ALL_NEW",
        context: Optional[ErrorContext] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Update an item in DynamoDB.

        Args:
            key: Primary key of the item to update
            update_expression: Update expression
            expression_attribute_values: Expression attribute values
            expression_attribute_names: Expression attribute names
            condition_expression: Conditional expression for the update
            return_values: What values to return after update
            context: Error context for tracing

        Returns:
            Updated item data or None

        Raises:
            DALError: If DynamoDB operation fails
            ConditionalCheckFailedError: If condition check fails
        """

        @self._handle_dynamodb_errors("UpdateItem", context)
        def _update_item():
            # Add updated timestamp
            if expression_attribute_values is None:
                expression_attribute_values = {}

            expression_attribute_values[':updated_at'] = datetime.now(timezone.utc).isoformat()

            # Ensure update expression includes updated_at
            if 'updated_at' not in update_expression:
                if update_expression.strip().startswith('SET'):
                    update_expression += ', updated_at = :updated_at'
                else:
                    update_expression = f'SET updated_at = :updated_at, {update_expression}'

            update_kwargs = {
                'Key': key,
                'UpdateExpression': update_expression,
                'ReturnValues': return_values,
            }

            if expression_attribute_values:
                update_kwargs['ExpressionAttributeValues'] = expression_attribute_values

            if expression_attribute_names:
                update_kwargs['ExpressionAttributeNames'] = expression_attribute_names

            if condition_expression:
                update_kwargs['ConditionExpression'] = condition_expression

            response = self.table.update_item(**update_kwargs)
            updated_item = response.get('Attributes')

            logger.info("Item updated successfully", extra={
                "table_name": self.table_name,
                "key": key,
                "return_values": return_values,
            })

            return updated_item

        return _update_item()

    @tracer.capture_method
    def delete_item(
        self,
        key: Dict[str, Any],
        condition_expression: Optional[Any] = None,
        context: Optional[ErrorContext] = None,
    ) -> bool:
        """
        Delete an item from DynamoDB.

        Args:
            key: Primary key of the item to delete
            condition_expression: Conditional expression for the delete
            context: Error context for tracing

        Returns:
            True if item was deleted, False if not found

        Raises:
            DALError: If DynamoDB operation fails
            ConditionalCheckFailedError: If condition check fails
        """

        @self._handle_dynamodb_errors("DeleteItem", context)
        def _delete_item():
            delete_kwargs = {
                'Key': key,
                'ReturnValues': 'ALL_OLD',
            }

            if condition_expression:
                delete_kwargs['ConditionExpression'] = condition_expression

            response = self.table.delete_item(**delete_kwargs)
            deleted_item = response.get('Attributes')

            if deleted_item:
                logger.info("Item deleted successfully", extra={
                    "table_name": self.table_name,
                    "key": key,
                })
                return True
            else:
                logger.warning("Item not found for deletion", extra={
                    "table_name": self.table_name,
                    "key": key,
                })
                return False

        return _delete_item()

    @tracer.capture_method
    def query_items(
        self,
        key_condition: Any,
        filter_expression: Optional[Any] = None,
        limit: Optional[int] = None,
        scan_index_forward: bool = True,
        exclusive_start_key: Optional[Dict[str, Any]] = None,
        index_name: Optional[str] = None,
        projection_expression: Optional[str] = None,
        context: Optional[ErrorContext] = None,
    ) -> Dict[str, Any]:
        """
        Query items from DynamoDB.

        Args:
            key_condition: Key condition expression
            filter_expression: Filter expression
            limit: Maximum number of items to return
            scan_index_forward: Sort order (True for ascending)
            exclusive_start_key: Pagination token
            index_name: Global secondary index name
            projection_expression: Attributes to retrieve
            context: Error context for tracing

        Returns:
            Dictionary with 'items' and optional 'last_evaluated_key'

        Raises:
            DALError: If DynamoDB operation fails
        """

        @self._handle_dynamodb_errors("Query", context)
        def _query_items():
            query_kwargs = {
                'KeyConditionExpression': key_condition,
                'ScanIndexForward': scan_index_forward,
            }

            if filter_expression:
                query_kwargs['FilterExpression'] = filter_expression

            if limit:
                query_kwargs['Limit'] = limit

            if exclusive_start_key:
                query_kwargs['ExclusiveStartKey'] = exclusive_start_key

            if index_name:
                query_kwargs['IndexName'] = index_name

            if projection_expression:
                query_kwargs['ProjectionExpression'] = projection_expression

            response = self.table.query(**query_kwargs)

            result = {
                'items': response.get('Items', []),
                'count': response.get('Count', 0),
                'scanned_count': response.get('ScannedCount', 0),
            }

            if 'LastEvaluatedKey' in response:
                result['last_evaluated_key'] = response['LastEvaluatedKey']

            logger.info("Query completed successfully", extra={
                "table_name": self.table_name,
                "items_count": result['count'],
                "scanned_count": result['scanned_count'],
                "has_more_results": 'last_evaluated_key' in result,
            })

            return result

        return _query_items()

    @tracer.capture_method
    def scan_items(
        self,
        filter_expression: Optional[Any] = None,
        limit: Optional[int] = None,
        exclusive_start_key: Optional[Dict[str, Any]] = None,
        projection_expression: Optional[str] = None,
        index_name: Optional[str] = None,
        context: Optional[ErrorContext] = None,
    ) -> Dict[str, Any]:
        """
        Scan items from DynamoDB.

        Args:
            filter_expression: Filter expression
            limit: Maximum number of items to return
            exclusive_start_key: Pagination token
            projection_expression: Attributes to retrieve
            index_name: Global secondary index name
            context: Error context for tracing

        Returns:
            Dictionary with 'items' and optional 'last_evaluated_key'

        Raises:
            DALError: If DynamoDB operation fails
        """

        @self._handle_dynamodb_errors("Scan", context)
        def _scan_items():
            scan_kwargs = {}

            if filter_expression:
                scan_kwargs['FilterExpression'] = filter_expression

            if limit:
                scan_kwargs['Limit'] = limit

            if exclusive_start_key:
                scan_kwargs['ExclusiveStartKey'] = exclusive_start_key

            if projection_expression:
                scan_kwargs['ProjectionExpression'] = projection_expression

            if index_name:
                scan_kwargs['IndexName'] = index_name

            response = self.table.scan(**scan_kwargs)

            result = {
                'items': response.get('Items', []),
                'count': response.get('Count', 0),
                'scanned_count': response.get('ScannedCount', 0),
            }

            if 'LastEvaluatedKey' in response:
                result['last_evaluated_key'] = response['LastEvaluatedKey']

            logger.info("Scan completed successfully", extra={
                "table_name": self.table_name,
                "items_count": result['count'],
                "scanned_count": result['scanned_count'],
                "has_more_results": 'last_evaluated_key' in result,
            })

            return result

        return _scan_items()

    @tracer.capture_method
    def batch_get_items(
        self,
        keys: List[Dict[str, Any]],
        consistent_read: bool = False,
        attributes_to_get: Optional[List[str]] = None,
        context: Optional[ErrorContext] = None,
    ) -> List[Dict[str, Any]]:
        """
        Batch get multiple items from DynamoDB.

        Args:
            keys: List of primary keys to retrieve
            consistent_read: Whether to use strongly consistent read
            attributes_to_get: Specific attributes to retrieve
            context: Error context for tracing

        Returns:
            List of retrieved items

        Raises:
            DALError: If DynamoDB operation fails
        """

        @self._handle_dynamodb_errors("BatchGetItem", context)
        def _batch_get_items():
            if not keys:
                return []

            request_items = {
                self.table_name: {
                    'Keys': keys,
                    'ConsistentRead': consistent_read,
                }
            }

            if attributes_to_get:
                request_items[self.table_name]['ProjectionExpression'] = ', '.join(attributes_to_get)

            response = self.dynamodb.batch_get_item(RequestItems=request_items)
            items = response.get('Responses', {}).get(self.table_name, [])

            logger.info("Batch get completed successfully", extra={
                "table_name": self.table_name,
                "requested_keys": len(keys),
                "retrieved_items": len(items),
            })

            return items

        return _batch_get_items()

    @tracer.capture_method
    def batch_write_items(
        self,
        put_requests: Optional[List[Dict[str, Any]]] = None,
        delete_requests: Optional[List[Dict[str, Any]]] = None,
        context: Optional[ErrorContext] = None,
    ) -> Dict[str, Any]:
        """
        Batch write (put/delete) multiple items to DynamoDB.

        Args:
            put_requests: List of items to put
            delete_requests: List of keys to delete
            context: Error context for tracing

        Returns:
            Dictionary with unprocessed items if any

        Raises:
            DALError: If DynamoDB operation fails
        """

        @self._handle_dynamodb_errors("BatchWriteItem", context)
        def _batch_write_items():
            if not put_requests and not delete_requests:
                return {'unprocessed_items': []}

            request_items = {self.table_name: []}

            if put_requests:
                for item in put_requests:
                    # Add timestamps
                    now = datetime.now(timezone.utc).isoformat()
                    if 'created_at' not in item:
                        item['created_at'] = now
                    item['updated_at'] = now

                    request_items[self.table_name].append({
                        'PutRequest': {'Item': item}
                    })

            if delete_requests:
                for key in delete_requests:
                    request_items[self.table_name].append({
                        'DeleteRequest': {'Key': key}
                    })

            response = self.dynamodb.batch_write_item(RequestItems=request_items)
            unprocessed_items = response.get('UnprocessedItems', {}).get(self.table_name, [])

            logger.info("Batch write completed successfully", extra={
                "table_name": self.table_name,
                "put_requests": len(put_requests) if put_requests else 0,
                "delete_requests": len(delete_requests) if delete_requests else 0,
                "unprocessed_items": len(unprocessed_items),
            })

            return {'unprocessed_items': unprocessed_items}

        return _batch_write_items()

    @tracer.capture_method
    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on the DynamoDB table.

        Returns:
            Health check results

        Raises:
            DALError: If health check fails
        """
        try:
            start_time = time.time()

            # Test basic table access
            response = self.table.describe()
            table_status = response.get('Table', {}).get('TableStatus', 'UNKNOWN')

            # Test read operation
            test_key = {'id': f'health-check-{uuid4()}'}
            self.table.get_item(Key=test_key)

            duration_ms = (time.time() - start_time) * 1000

            health_data = {
                'status': 'healthy' if table_status == 'ACTIVE' else 'unhealthy',
                'table_name': self.table_name,
                'table_status': table_status,
                'response_time_ms': round(duration_ms, 2),
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }

            logger.info("Health check completed", extra=health_data)
            return health_data

        except Exception as e:
            error_data = {
                'status': 'unhealthy',
                'table_name': self.table_name,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }

            logger.error("Health check failed", extra=error_data)
            return error_data
