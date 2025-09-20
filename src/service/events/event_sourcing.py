"""
Event Sourcing Patterns for Lambda Applications.

This module provides comprehensive event sourcing capabilities including
event store, projections, snapshots, and stream processing for CQRS patterns.
"""

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Type, Union, Iterator
from uuid import UUID, uuid4

import boto3
from botocore.exceptions import ClientError
from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from pydantic import BaseModel, Field, validator

from .event_schemas import BaseEvent, EventType, EventSource

logger = Logger()
tracer = Tracer()
metrics = Metrics()


class EventStoreError(Exception):
    """Base exception for event store operations."""
    pass


class StreamNotFoundError(EventStoreError):
    """Exception raised when stream is not found."""
    pass


class ConcurrencyError(EventStoreError):
    """Exception raised when concurrent modification is detected."""
    pass


class ProjectionError(Exception):
    """Exception raised during projection operations."""
    pass


@dataclass
class EventRecord:
    """Represents a stored event with metadata."""

    stream_id: str
    event_id: str
    event_type: str
    event_data: Dict[str, Any]
    metadata: Dict[str, Any]
    version: int
    timestamp: datetime
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None

    def to_event(self) -> BaseEvent:
        """Convert EventRecord back to BaseEvent."""
        return BaseEvent(
            id=self.event_id,
            source=EventSource(self.metadata.get('source', EventSource.SYSTEM)),
            event_type=EventType(self.event_type),
            timestamp=self.timestamp,
            data=self.event_data,
            metadata=self.metadata
        )


@dataclass
class StreamInfo:
    """Information about an event stream."""

    stream_id: str
    version: int
    created_at: datetime
    updated_at: datetime
    event_count: int
    last_event_id: Optional[str] = None


@dataclass
class Snapshot:
    """Represents an aggregate snapshot."""

    stream_id: str
    version: int
    data: Dict[str, Any]
    timestamp: datetime
    aggregate_type: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert snapshot to dictionary for storage."""
        return {
            'stream_id': self.stream_id,
            'version': self.version,
            'data': self.data,
            'timestamp': self.timestamp.isoformat(),
            'aggregate_type': self.aggregate_type
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Snapshot':
        """Create snapshot from dictionary."""
        return cls(
            stream_id=data['stream_id'],
            version=data['version'],
            data=data['data'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            aggregate_type=data['aggregate_type']
        )


class EventStore:
    """
    DynamoDB-based event store with advanced features.

    Features:
    - Optimistic concurrency control
    - Event ordering and versioning
    - Stream-based event storage
    - Snapshot support
    - Query capabilities
    """

    def __init__(
        self,
        table_name: str = "event-store",
        snapshot_table_name: str = "event-snapshots",
        region_name: str = "us-east-1",
        snapshot_frequency: int = 100
    ):
        """
        Initialize event store.

        Args:
            table_name: DynamoDB table for events
            snapshot_table_name: DynamoDB table for snapshots
            region_name: AWS region
            snapshot_frequency: Take snapshot every N events
        """
        self.table_name = table_name
        self.snapshot_table_name = snapshot_table_name
        self.snapshot_frequency = snapshot_frequency

        self.dynamodb = boto3.client('dynamodb', region_name=region_name)

        logger.info(
            "EventStore initialized",
            extra={
                "table_name": table_name,
                "snapshot_table_name": snapshot_table_name,
                "snapshot_frequency": snapshot_frequency
            }
        )

    @tracer.capture_method
    def append_events(
        self,
        stream_id: str,
        events: List[BaseEvent],
        expected_version: Optional[int] = None
    ) -> List[EventRecord]:
        """
        Append events to a stream with optimistic concurrency control.

        Args:
            stream_id: Unique identifier for the event stream
            events: List of events to append
            expected_version: Expected current version (for concurrency control)

        Returns:
            List of stored event records

        Raises:
            ConcurrencyError: If expected version doesn't match current version
        """
        if not events:
            return []

        start_time = time.time()

        try:
            # Get current stream version
            current_version = self._get_stream_version(stream_id)

            # Check expected version for concurrency control
            if expected_version is not None and current_version != expected_version:
                raise ConcurrencyError(
                    f"Expected version {expected_version}, but current version is {current_version}"
                )

            # Prepare event records
            event_records = []
            for i, event in enumerate(events):
                version = current_version + i + 1

                event_record = EventRecord(
                    stream_id=stream_id,
                    event_id=event.id,
                    event_type=event.event_type.value,
                    event_data=event.data,
                    metadata=event.metadata.dict(),
                    version=version,
                    timestamp=event.timestamp,
                    correlation_id=event.metadata.correlation_id,
                    causation_id=event.metadata.causation_id
                )

                event_records.append(event_record)

            # Store events in batch
            self._store_events_batch(event_records)

            # Update stream info
            self._update_stream_info(stream_id, current_version + len(events), event_records[-1].event_id)

            # Check if snapshot is needed
            if (current_version + len(events)) % self.snapshot_frequency == 0:
                self._trigger_snapshot(stream_id, current_version + len(events))

            duration_ms = (time.time() - start_time) * 1000

            metrics.add_metric(name="EventsAppended", unit=MetricUnit.Count, value=len(events))
            metrics.add_metric(name="AppendDuration", unit=MetricUnit.Milliseconds, value=duration_ms)

            logger.info(
                "Events appended successfully",
                extra={
                    "stream_id": stream_id,
                    "event_count": len(events),
                    "new_version": current_version + len(events),
                    "duration_ms": duration_ms
                }
            )

            return event_records

        except Exception as e:
            logger.error(f"Failed to append events: {e}", extra={"stream_id": stream_id})
            metrics.add_metric(name="AppendError", unit=MetricUnit.Count, value=1)
            raise EventStoreError(f"Failed to append events: {e}") from e

    @tracer.capture_method
    def get_events(
        self,
        stream_id: str,
        from_version: int = 0,
        to_version: Optional[int] = None,
        limit: Optional[int] = None
    ) -> List[EventRecord]:
        """
        Get events from a stream.

        Args:
            stream_id: Stream identifier
            from_version: Starting version (inclusive)
            to_version: Ending version (inclusive)
            limit: Maximum number of events to return

        Returns:
            List of event records
        """
        try:
            # Build query parameters
            key_condition = {
                'stream_id': {'S': stream_id}
            }

            if from_version > 0:
                key_condition['version'] = {'N': str(from_version)}

            query_params = {
                'TableName': self.table_name,
                'KeyConditionExpression': 'stream_id = :stream_id',
                'ExpressionAttributeValues': {
                    ':stream_id': {'S': stream_id}
                },
                'ScanIndexForward': True  # Sort by version ascending
            }

            if from_version > 0:
                query_params['KeyConditionExpression'] += ' AND version >= :from_version'
                query_params['ExpressionAttributeValues'][':from_version'] = {'N': str(from_version)}

            if to_version is not None:
                query_params['KeyConditionExpression'] += ' AND version <= :to_version'
                query_params['ExpressionAttributeValues'][':to_version'] = {'N': str(to_version)}

            if limit:
                query_params['Limit'] = limit

            # Execute query
            response = self.dynamodb.query(**query_params)

            # Convert to EventRecord objects
            events = []
            for item in response.get('Items', []):
                event_record = self._item_to_event_record(item)
                events.append(event_record)

            logger.info(
                "Events retrieved",
                extra={
                    "stream_id": stream_id,
                    "from_version": from_version,
                    "to_version": to_version,
                    "event_count": len(events)
                }
            )

            return events

        except Exception as e:
            logger.error(f"Failed to get events: {e}", extra={"stream_id": stream_id})
            raise EventStoreError(f"Failed to get events: {e}") from e

    @tracer.capture_method
    def get_stream_info(self, stream_id: str) -> Optional[StreamInfo]:
        """Get information about an event stream."""
        try:
            response = self.dynamodb.get_item(
                TableName=f"{self.table_name}-streams",
                Key={'stream_id': {'S': stream_id}}
            )

            if 'Item' not in response:
                return None

            item = response['Item']
            return StreamInfo(
                stream_id=stream_id,
                version=int(item['version']['N']),
                created_at=datetime.fromisoformat(item['created_at']['S']),
                updated_at=datetime.fromisoformat(item['updated_at']['S']),
                event_count=int(item['event_count']['N']),
                last_event_id=item.get('last_event_id', {}).get('S')
            )

        except Exception as e:
            logger.error(f"Failed to get stream info: {e}", extra={"stream_id": stream_id})
            return None

    @tracer.capture_method
    def save_snapshot(self, snapshot: Snapshot) -> bool:
        """Save an aggregate snapshot."""
        try:
            item = {
                'stream_id': {'S': snapshot.stream_id},
                'version': {'N': str(snapshot.version)},
                'data': {'S': json.dumps(snapshot.data)},
                'timestamp': {'S': snapshot.timestamp.isoformat()},
                'aggregate_type': {'S': snapshot.aggregate_type},
                'ttl': {'N': str(int((datetime.utcnow() + timedelta(days=90)).timestamp()))}
            }

            self.dynamodb.put_item(
                TableName=self.snapshot_table_name,
                Item=item
            )

            logger.info(
                "Snapshot saved",
                extra={
                    "stream_id": snapshot.stream_id,
                    "version": snapshot.version,
                    "aggregate_type": snapshot.aggregate_type
                }
            )

            return True

        except Exception as e:
            logger.error(f"Failed to save snapshot: {e}", extra={"stream_id": snapshot.stream_id})
            return False

    @tracer.capture_method
    def get_latest_snapshot(self, stream_id: str) -> Optional[Snapshot]:
        """Get the latest snapshot for a stream."""
        try:
            response = self.dynamodb.query(
                TableName=self.snapshot_table_name,
                KeyConditionExpression='stream_id = :stream_id',
                ExpressionAttributeValues={
                    ':stream_id': {'S': stream_id}
                },
                ScanIndexForward=False,  # Sort by version descending
                Limit=1
            )

            items = response.get('Items', [])
            if not items:
                return None

            item = items[0]
            return Snapshot(
                stream_id=stream_id,
                version=int(item['version']['N']),
                data=json.loads(item['data']['S']),
                timestamp=datetime.fromisoformat(item['timestamp']['S']),
                aggregate_type=item['aggregate_type']['S']
            )

        except Exception as e:
            logger.error(f"Failed to get snapshot: {e}", extra={"stream_id": stream_id})
            return None

    def _get_stream_version(self, stream_id: str) -> int:
        """Get current version of a stream."""
        stream_info = self.get_stream_info(stream_id)
        return stream_info.version if stream_info else 0

    def _store_events_batch(self, event_records: List[EventRecord]):
        """Store multiple events in a batch."""
        # DynamoDB batch write (max 25 items)
        batch_size = 25

        for i in range(0, len(event_records), batch_size):
            batch = event_records[i:i + batch_size]

            request_items = {
                self.table_name: [
                    {
                        'PutRequest': {
                            'Item': {
                                'stream_id': {'S': record.stream_id},
                                'version': {'N': str(record.version)},
                                'event_id': {'S': record.event_id},
                                'event_type': {'S': record.event_type},
                                'event_data': {'S': json.dumps(record.event_data)},
                                'metadata': {'S': json.dumps(record.metadata)},
                                'timestamp': {'S': record.timestamp.isoformat()},
                                'correlation_id': {'S': record.correlation_id or ''},
                                'causation_id': {'S': record.causation_id or ''}
                            }
                        }
                    }
                    for record in batch
                ]
            }

            self.dynamodb.batch_write_item(RequestItems=request_items)

    def _update_stream_info(self, stream_id: str, new_version: int, last_event_id: str):
        """Update stream information."""
        now = datetime.utcnow().isoformat()

        try:
            # Try to update existing stream info
            self.dynamodb.update_item(
                TableName=f"{self.table_name}-streams",
                Key={'stream_id': {'S': stream_id}},
                UpdateExpression='SET version = :version, updated_at = :updated_at, last_event_id = :last_event_id ADD event_count :inc',
                ExpressionAttributeValues={
                    ':version': {'N': str(new_version)},
                    ':updated_at': {'S': now},
                    ':last_event_id': {'S': last_event_id},
                    ':inc': {'N': '1'}
                }
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'ValidationException':
                # Stream doesn't exist, create it
                self.dynamodb.put_item(
                    TableName=f"{self.table_name}-streams",
                    Item={
                        'stream_id': {'S': stream_id},
                        'version': {'N': str(new_version)},
                        'created_at': {'S': now},
                        'updated_at': {'S': now},
                        'event_count': {'N': str(new_version)},
                        'last_event_id': {'S': last_event_id}
                    }
                )
            else:
                raise

    def _trigger_snapshot(self, stream_id: str, version: int):
        """Trigger snapshot creation (placeholder for async processing)."""
        logger.info(
            "Snapshot triggered",
            extra={"stream_id": stream_id, "version": version}
        )
        # In a real implementation, this would trigger an async process
        # to create snapshots, possibly using SQS or EventBridge

    def _item_to_event_record(self, item: Dict[str, Any]) -> EventRecord:
        """Convert DynamoDB item to EventRecord."""
        return EventRecord(
            stream_id=item['stream_id']['S'],
            event_id=item['event_id']['S'],
            event_type=item['event_type']['S'],
            event_data=json.loads(item['event_data']['S']),
            metadata=json.loads(item['metadata']['S']),
            version=int(item['version']['N']),
            timestamp=datetime.fromisoformat(item['timestamp']['S']),
            correlation_id=item.get('correlation_id', {}).get('S'),
            causation_id=item.get('causation_id', {}).get('S')
        )


class EventProjection(ABC):
    """Base class for event projections."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def handle_event(self, event: EventRecord) -> None:
        """Handle a single event and update projection."""
        pass

    @abstractmethod
    def get_state(self, key: str) -> Optional[Dict[str, Any]]:
        """Get current state for a key."""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset projection state."""
        pass


class DynamoDBProjection(EventProjection):
    """DynamoDB-based event projection."""

    def __init__(
        self,
        name: str,
        table_name: str,
        region_name: str = "us-east-1"
    ):
        super().__init__(name)
        self.table_name = table_name
        self.dynamodb = boto3.client('dynamodb', region_name=region_name)

    def handle_event(self, event: EventRecord) -> None:
        """Handle event and update projection."""
        try:
            # This is a base implementation - override in subclasses
            projection_data = self._process_event(event)

            if projection_data:
                self._update_projection(projection_data)

        except Exception as e:
            logger.error(f"Projection {self.name} failed to handle event: {e}")
            raise ProjectionError(f"Failed to handle event: {e}") from e

    def get_state(self, key: str) -> Optional[Dict[str, Any]]:
        """Get projection state for a key."""
        try:
            response = self.dynamodb.get_item(
                TableName=self.table_name,
                Key={'id': {'S': key}}
            )

            if 'Item' not in response:
                return None

            # Convert DynamoDB item to dict
            return self._item_to_dict(response['Item'])

        except Exception as e:
            logger.error(f"Failed to get projection state: {e}")
            return None

    def reset(self) -> None:
        """Reset projection by truncating table."""
        # WARNING: This deletes all data
        logger.warning(f"Resetting projection {self.name}")
        # Implementation would scan and delete all items

    def _process_event(self, event: EventRecord) -> Optional[Dict[str, Any]]:
        """Process event and return projection data (override in subclasses)."""
        return {
            'id': event.stream_id,
            'last_event_id': event.event_id,
            'last_updated': event.timestamp.isoformat(),
            'version': event.version
        }

    def _update_projection(self, data: Dict[str, Any]):
        """Update projection with new data."""
        # Convert dict to DynamoDB item
        item = self._dict_to_item(data)

        self.dynamodb.put_item(
            TableName=self.table_name,
            Item=item
        )

    def _dict_to_item(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert dict to DynamoDB item format."""
        item = {}
        for key, value in data.items():
            if isinstance(value, str):
                item[key] = {'S': value}
            elif isinstance(value, (int, float)):
                item[key] = {'N': str(value)}
            elif isinstance(value, bool):
                item[key] = {'BOOL': value}
            elif isinstance(value, dict):
                item[key] = {'S': json.dumps(value)}
            elif isinstance(value, list):
                item[key] = {'S': json.dumps(value)}
            else:
                item[key] = {'S': str(value)}
        return item

    def _item_to_dict(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Convert DynamoDB item to dict."""
        result = {}
        for key, value in item.items():
            if 'S' in value:
                try:
                    # Try to parse as JSON first
                    result[key] = json.loads(value['S'])
                except (json.JSONDecodeError, TypeError):
                    result[key] = value['S']
            elif 'N' in value:
                try:
                    result[key] = int(value['N'])
                except ValueError:
                    result[key] = float(value['N'])
            elif 'BOOL' in value:
                result[key] = value['BOOL']
            else:
                result[key] = value
        return result


class EventStreamProcessor:
    """
    Event stream processor for building projections.

    Features:
    - Process events from event store
    - Build and maintain projections
    - Handle replay scenarios
    - Checkpoint management
    """

    def __init__(
        self,
        event_store: EventStore,
        projections: List[EventProjection],
        checkpoint_table: str = "projection-checkpoints"
    ):
        self.event_store = event_store
        self.projections = projections
        self.checkpoint_table = checkpoint_table
        self.dynamodb = boto3.client('dynamodb')

    @tracer.capture_method
    def process_stream(
        self,
        stream_id: str,
        from_version: Optional[int] = None,
        batch_size: int = 100
    ) -> int:
        """
        Process events from a stream and update projections.

        Args:
            stream_id: Stream to process
            from_version: Start from this version (uses checkpoint if None)
            batch_size: Number of events to process in each batch

        Returns:
            Number of events processed
        """
        start_time = time.time()
        total_processed = 0

        try:
            # Get starting position
            start_version = from_version or self._get_checkpoint(stream_id)

            logger.info(
                "Starting stream processing",
                extra={
                    "stream_id": stream_id,
                    "start_version": start_version,
                    "projections": [p.name for p in self.projections]
                }
            )

            # Process events in batches
            current_version = start_version

            while True:
                events = self.event_store.get_events(
                    stream_id=stream_id,
                    from_version=current_version + 1,
                    limit=batch_size
                )

                if not events:
                    break

                # Process batch
                for event in events:
                    self._process_event(event)
                    current_version = event.version
                    total_processed += 1

                # Update checkpoint
                self._save_checkpoint(stream_id, current_version)

                logger.debug(
                    f"Processed batch: {len(events)} events, version {current_version}"
                )

            duration_ms = (time.time() - start_time) * 1000

            metrics.add_metric(name="StreamProcessed", unit=MetricUnit.Count, value=total_processed)
            metrics.add_metric(name="ProcessingDuration", unit=MetricUnit.Milliseconds, value=duration_ms)

            logger.info(
                "Stream processing completed",
                extra={
                    "stream_id": stream_id,
                    "events_processed": total_processed,
                    "final_version": current_version,
                    "duration_ms": duration_ms
                }
            )

            return total_processed

        except Exception as e:
            logger.error(f"Stream processing failed: {e}", extra={"stream_id": stream_id})
            metrics.add_metric(name="ProcessingError", unit=MetricUnit.Count, value=1)
            raise

    def _process_event(self, event: EventRecord):
        """Process a single event through all projections."""
        for projection in self.projections:
            try:
                projection.handle_event(event)
            except Exception as e:
                logger.error(
                    f"Projection {projection.name} failed to process event",
                    extra={"event_id": event.event_id, "error": str(e)}
                )
                # Continue with other projections

    def _get_checkpoint(self, stream_id: str) -> int:
        """Get last processed version for a stream."""
        try:
            response = self.dynamodb.get_item(
                TableName=self.checkpoint_table,
                Key={'stream_id': {'S': stream_id}}
            )

            if 'Item' in response:
                return int(response['Item']['version']['N'])

            return 0

        except Exception as e:
            logger.error(f"Failed to get checkpoint: {e}")
            return 0

    def _save_checkpoint(self, stream_id: str, version: int):
        """Save checkpoint for a stream."""
        try:
            self.dynamodb.put_item(
                TableName=self.checkpoint_table,
                Item={
                    'stream_id': {'S': stream_id},
                    'version': {'N': str(version)},
                    'updated_at': {'S': datetime.utcnow().isoformat()}
                }
            )
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")


# Example projection implementations
class OrderSummaryProjection(DynamoDBProjection):
    """Example projection for order summaries."""

    def __init__(self, table_name: str = "order-summaries"):
        super().__init__("OrderSummary", table_name)

    def _process_event(self, event: EventRecord) -> Optional[Dict[str, Any]]:
        """Process order-related events."""
        if event.event_type == "OrderCreated":
            return {
                'id': event.event_data['order_id'],
                'user_id': event.event_data['user_id'],
                'status': event.event_data['status'],
                'total_amount': event.event_data['total_amount'],
                'created_at': event.timestamp.isoformat(),
                'updated_at': event.timestamp.isoformat(),
                'version': event.version
            }
        elif event.event_type == "OrderUpdated":
            # Get existing order and update
            existing = self.get_state(event.event_data['order_id'])
            if existing:
                existing.update({
                    'status': event.event_data.get('status', existing['status']),
                    'updated_at': event.timestamp.isoformat(),
                    'version': event.version
                })
                return existing

        return None


class UserActivityProjection(DynamoDBProjection):
    """Example projection for user activity tracking."""

    def __init__(self, table_name: str = "user-activity"):
        super().__init__("UserActivity", table_name)

    def _process_event(self, event: EventRecord) -> Optional[Dict[str, Any]]:
        """Process user-related events."""
        if 'user_id' in event.event_data:
            user_id = event.event_data['user_id']

            # Get existing activity
            existing = self.get_state(user_id) or {
                'id': user_id,
                'total_orders': 0,
                'total_spent': 0.0,
                'last_activity': None,
                'events_count': 0
            }

            # Update based on event type
            if event.event_type == "OrderCreated":
                existing['total_orders'] += 1
                existing['total_spent'] += event.event_data.get('total_amount', 0)

            existing['last_activity'] = event.timestamp.isoformat()
            existing['events_count'] += 1
            existing['version'] = event.version

            return existing

        return None
