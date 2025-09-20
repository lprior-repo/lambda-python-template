"""
Data Access Layer (DAL) for AWS Lambda Python Template.

This module provides the data access layer interfaces and factory functions
for database operations, following patterns from the aws-lambda-handler-cookbook.
"""

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from service.models.order import Order


@runtime_checkable
class DalHandler(Protocol):
    """Protocol defining the data access layer interface."""

    def create_order_in_db(self, customer_name: str, customer_email: str, order_item_count: int, notes: str | None = None) -> Order:
        """Create a new order in the database."""
        ...

    def get_order_by_id(self, order_id: str) -> Order | None:
        """Retrieve an order by its ID."""
        ...

    def update_order_in_db(self, order: Order) -> Order:
        """Update an existing order in the database."""
        ...

    def delete_order_by_id(self, order_id: str) -> bool:
        """Delete an order by its ID."""
        ...

    def list_orders_by_customer(self, customer_email: str, limit: int = 50) -> list[Order]:
        """List orders for a specific customer."""
        ...


class BaseDalHandler(ABC):
    """Abstract base class for data access layer implementations."""

    def __init__(self, table_name: str) -> None:
        """
        Initialize the DAL handler.

        Args:
            table_name: Name of the database table/collection
        """
        self.table_name = table_name

    @abstractmethod
    def create_order_in_db(self, customer_name: str, customer_email: str, order_item_count: int, notes: str | None = None) -> Order:
        """Create a new order in the database."""
        pass

    @abstractmethod
    def get_order_by_id(self, order_id: str) -> Order | None:
        """Retrieve an order by its ID."""
        pass

    @abstractmethod
    def update_order_in_db(self, order: Order) -> Order:
        """Update an existing order in the database."""
        pass

    @abstractmethod
    def delete_order_by_id(self, order_id: str) -> bool:
        """Delete an order by its ID."""
        pass

    @abstractmethod
    def list_orders_by_customer(self, customer_email: str, limit: int = 50) -> list[Order]:
        """List orders for a specific customer."""
        pass

    @abstractmethod
    def health_check(self) -> dict[str, str]:
        """Perform a health check on the data store."""
        pass


def get_dal_handler(table_name: str) -> DalHandler:
    """
    Factory function to get the appropriate DAL handler.

    Args:
        table_name: Name of the database table

    Returns:
        DAL handler instance
    """
    # Import here to avoid circular imports
    from service.dal.db_handler import DynamoDbHandler

    return DynamoDbHandler(table_name)


__all__ = [
    'DalHandler',
    'BaseDalHandler',
    'get_dal_handler'
]
