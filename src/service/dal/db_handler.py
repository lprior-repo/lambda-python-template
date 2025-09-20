"""
DynamoDB implementation of the Data Access Layer (DAL).

This module provides a concrete implementation of the DAL interface using Amazon DynamoDB,
following patterns from the aws-lambda-handler-cookbook for robust database operations.
"""

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from datetime import datetime
from typing import Any, Dict, List, Optional

from service.dal import BaseDalHandler
from service.handlers.utils.observability import logger, tracer
from service.models.order import Order, OrderStatus


class DynamoDbHandler(BaseDalHandler):
    """DynamoDB implementation of the data access layer."""

    def __init__(self, table_name: str) -> None:
        """
        Initialize the DynamoDB handler.

        Args:
            table_name: Name of the DynamoDB table
        """
        super().__init__(table_name)
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(table_name)
        logger.debug(f'DynamoDB handler initialized for table: {table_name}')

    @tracer.capture_method
    def create_order_in_db(
        self,
        customer_name: str,
        customer_email: str,
        order_item_count: int,
        notes: Optional[str] = None
    ) -> Order:
        """
        Create a new order in DynamoDB.

        Args:
            customer_name: Name of the customer
            customer_email: Email address of the customer
            order_item_count: Number of items in the order
            notes: Optional notes for the order

        Returns:
            Created Order instance

        Raises:
            ClientError: If DynamoDB operation fails
        """
        try:
            # Create order domain object
            order = Order.create(
                customer_name=customer_name,
                customer_email=customer_email,
                item_count=order_item_count,
                notes=notes
            )

            # Convert to DynamoDB item format
            item = self._order_to_dynamodb_item(order)

            # Add metadata for DynamoDB
            item['pk'] = f"ORDER#{order.id}"
            item['sk'] = f"ORDER#{order.id}"
            item['gsi1pk'] = f"CUSTOMER#{customer_email}"
            item['gsi1sk'] = f"ORDER#{order.created_at.isoformat()}"
            item['entity_type'] = 'order'

            # Write to DynamoDB
            self.table.put_item(
                Item=item,
                ConditionExpression='attribute_not_exists(pk)'  # Ensure no duplicates
            )

            logger.info(f'Successfully created order in database: {order.id}')
            tracer.put_annotation('order_created', order.id)
            tracer.put_metadata('order_details', {
                'customer_email': customer_email,
                'item_count': order_item_count
            })

            return order

        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(f'DynamoDB error creating order: {error_code}', extra={
                'error': str(e),
                'customer_email': customer_email
            })
            raise
        except Exception as e:
            logger.error(f'Unexpected error creating order: {e}')
            raise

    @tracer.capture_method
    def get_order_by_id(self, order_id: str) -> Optional[Order]:
        """
        Retrieve an order by its ID from DynamoDB.

        Args:
            order_id: Unique identifier of the order

        Returns:
            Order instance if found, None otherwise

        Raises:
            ClientError: If DynamoDB operation fails
        """
        try:
            response = self.table.get_item(
                Key={
                    'pk': f"ORDER#{order_id}",
                    'sk': f"ORDER#{order_id}"
                }
            )

            item = response.get('Item')
            if not item:
                logger.info(f'Order not found: {order_id}')
                return None

            order = self._dynamodb_item_to_order(item)
            logger.debug(f'Successfully retrieved order: {order_id}')
            tracer.put_annotation('order_retrieved', order_id)

            return order

        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(f'DynamoDB error retrieving order {order_id}: {error_code}')
            raise
        except Exception as e:
            logger.error(f'Unexpected error retrieving order {order_id}: {e}')
            raise

    @tracer.capture_method
    def update_order_in_db(self, order: Order) -> Order:
        """
        Update an existing order in DynamoDB.

        Args:
            order: Order instance with updated data

        Returns:
            Updated Order instance

        Raises:
            ClientError: If DynamoDB operation fails
        """
        try:
            # Update the timestamp
            order.updated_at = datetime.utcnow()

            # Convert to DynamoDB item format
            item = self._order_to_dynamodb_item(order)

            # Update the item in DynamoDB
            self.table.put_item(
                Item={
                    **item,
                    'pk': f"ORDER#{order.id}",
                    'sk': f"ORDER#{order.id}",
                    'gsi1pk': f"CUSTOMER#{order.customer_email}",
                    'gsi1sk': f"ORDER#{order.created_at.isoformat()}",
                    'entity_type': 'order'
                },
                ConditionExpression='attribute_exists(pk)'  # Ensure order exists
            )

            logger.info(f'Successfully updated order: {order.id}')
            tracer.put_annotation('order_updated', order.id)

            return order

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ConditionalCheckFailedException':
                logger.error(f'Order not found for update: {order.id}')
            else:
                logger.error(f'DynamoDB error updating order {order.id}: {error_code}')
            raise
        except Exception as e:
            logger.error(f'Unexpected error updating order {order.id}: {e}')
            raise

    @tracer.capture_method
    def delete_order_by_id(self, order_id: str) -> bool:
        """
        Delete an order by its ID from DynamoDB.

        Args:
            order_id: Unique identifier of the order

        Returns:
            True if order was deleted, False if not found

        Raises:
            ClientError: If DynamoDB operation fails
        """
        try:
            response = self.table.delete_item(
                Key={
                    'pk': f"ORDER#{order_id}",
                    'sk': f"ORDER#{order_id}"
                },
                ConditionExpression='attribute_exists(pk)',
                ReturnValues='ALL_OLD'
            )

            deleted_item = response.get('Attributes')
            if deleted_item:
                logger.info(f'Successfully deleted order: {order_id}')
                tracer.put_annotation('order_deleted', order_id)
                return True
            else:
                logger.info(f'Order not found for deletion: {order_id}')
                return False

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ConditionalCheckFailedException':
                logger.info(f'Order not found for deletion: {order_id}')
                return False
            else:
                logger.error(f'DynamoDB error deleting order {order_id}: {error_code}')
                raise
        except Exception as e:
            logger.error(f'Unexpected error deleting order {order_id}: {e}')
            raise

    @tracer.capture_method
    def list_orders_by_customer(self, customer_email: str, limit: int = 50) -> List[Order]:
        """
        List orders for a specific customer from DynamoDB.

        Args:
            customer_email: Customer's email address
            limit: Maximum number of orders to return

        Returns:
            List of Order instances

        Raises:
            ClientError: If DynamoDB operation fails
        """
        try:
            response = self.table.query(
                IndexName='GSI1',  # Global Secondary Index for customer queries
                KeyConditionExpression=Key('gsi1pk').eq(f"CUSTOMER#{customer_email}"),
                ScanIndexForward=False,  # Most recent first
                Limit=limit
            )

            orders = []
            for item in response.get('Items', []):
                try:
                    order = self._dynamodb_item_to_order(item)
                    orders.append(order)
                except Exception as e:
                    logger.warning(f'Failed to parse order item: {e}', extra={'item': item})

            logger.info(f'Retrieved {len(orders)} orders for customer: {customer_email}')
            tracer.put_annotation('orders_listed', len(orders))
            tracer.put_metadata('customer_query', {'email': customer_email, 'count': len(orders)})

            return orders

        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(f'DynamoDB error listing orders for {customer_email}: {error_code}')
            raise
        except Exception as e:
            logger.error(f'Unexpected error listing orders for {customer_email}: {e}')
            raise

    @tracer.capture_method
    def health_check(self) -> Dict[str, str]:
        """
        Perform a health check on the DynamoDB table.

        Returns:
            Dictionary with health check results

        Raises:
            ClientError: If DynamoDB operation fails
        """
        try:
            # Simple operation to test connectivity
            self.table.describe()

            logger.debug('DynamoDB health check passed')
            return {
                'status': 'healthy',
                'table': self.table_name,
                'timestamp': datetime.utcnow().isoformat()
            }

        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(f'DynamoDB health check failed: {error_code}')
            return {
                'status': 'unhealthy',
                'table': self.table_name,
                'error': error_code,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f'Unexpected error in health check: {e}')
            return {
                'status': 'unhealthy',
                'table': self.table_name,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }

    def _order_to_dynamodb_item(self, order: Order) -> Dict[str, Any]:
        """
        Convert Order domain object to DynamoDB item format.

        Args:
            order: Order instance to convert

        Returns:
            Dictionary suitable for DynamoDB storage
        """
        return {
            'id': order.id,
            'customer_name': order.customer_name,
            'customer_email': order.customer_email,
            'item_count': order.item_count,
            'status': order.status.value,
            'notes': order.notes,
            'created_at': order.created_at.isoformat(),
            'updated_at': order.updated_at.isoformat(),
            'estimated_delivery': order.estimated_delivery.isoformat() if order.estimated_delivery else None,
            'order_total': str(order.order_total)  # Store as string to avoid precision issues
        }

    def _dynamodb_item_to_order(self, item: Dict[str, Any]) -> Order:
        """
        Convert DynamoDB item to Order domain object.

        Args:
            item: DynamoDB item dictionary

        Returns:
            Order instance

        Raises:
            ValueError: If item data is invalid
        """
        try:
            return Order(
                id=item['id'],
                customer_name=item['customer_name'],
                customer_email=item['customer_email'],
                item_count=int(item['item_count']),
                status=OrderStatus(item['status']),
                notes=item.get('notes'),
                created_at=datetime.fromisoformat(item['created_at']),
                updated_at=datetime.fromisoformat(item['updated_at']),
                estimated_delivery=datetime.fromisoformat(item['estimated_delivery']) if item.get('estimated_delivery') else None,
                order_total=float(item['order_total'])
            )
        except (KeyError, ValueError, TypeError) as e:
            logger.error(f'Failed to convert DynamoDB item to Order: {e}', extra={'item': item})
            raise ValueError(f"Invalid order data in database: {e}")
