"""
EventBridge Publisher with Advanced Patterns.

This module provides a robust event publisher for AWS EventBridge with features like
batching, retry logic, dead letter queues, and comprehensive error handling.
"""

import json
import time
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.utilities.batch import BatchProcessor, EventType as BatchEventType
from aws_lambda_powertools.utilities.data_classes import EventBridgeEvent
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from pydantic import ValidationError

from .event_schemas import BaseEvent, EventMetadata, EventType, EventSource

logger = Logger()
tracer = Tracer()
metrics = Metrics()


class EventPublishError(Exception):
    """Exception raised when event publishing fails."""

    def __init__(self, message: str, event_data: Optional[Dict[str, Any]] = None,
                 original_error: Optional[Exception] = None):
        super().__init__(message)
        self.event_data = event_data
        self.original_error = original_error


class EventValidationError(EventPublishError):
    """Exception raised when event validation fails."""
    pass


class EventBatchError(EventPublishError):
    """Exception raised when batch processing fails."""

    def __init__(self, message: str, failed_events: List[Dict[str, Any]] = None,
                 successful_count: int = 0):
        super().__init__(message)
        self.failed_events = failed_events or []
        self.successful_count = successful_count


@dataclass
class PublishResult:
    """Result of event publishing operation."""

    success: bool
    event_id: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    duration_ms: float = 0.0
    event_data: Optional[Dict[str, Any]] = None


@dataclass
class BatchPublishResult:
    """Result of batch event publishing operation."""

    total_events: int
    successful_events: int
    failed_events: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_ms: float = 0.0


class EventPublisher:
    """
    Advanced EventBridge event publisher with enterprise features.

    Features:
    - Event validation and schema enforcement
    - Automatic batching for performance
    - Retry logic with exponential backoff
    - Dead letter queue support
    - Comprehensive metrics and tracing
    - Parallel processing for large batches
    """

    def __init__(
        self,
        event_bus_name: str = "default",
        region_name: str = "us-east-1",
        max_batch_size: int = 10,
        max_retries: int = 3,
        retry_backoff: float = 1.0,
        enable_dlq: bool = True,
        dlq_table_name: Optional[str] = None,
        parallel_workers: int = 4
    ):
        """
        Initialize EventBridge publisher.

        Args:
            event_bus_name: Name of the EventBridge bus
            region_name: AWS region
            max_batch_size: Maximum events per batch (EventBridge limit is 10)
            max_retries: Maximum retry attempts
            retry_backoff: Initial backoff time in seconds
            enable_dlq: Enable dead letter queue for failed events
            dlq_table_name: DynamoDB table name for DLQ
            parallel_workers: Number of parallel workers for batch processing
        """
        self.event_bus_name = event_bus_name
        self.max_batch_size = min(max_batch_size, 10)  # EventBridge limit
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self.enable_dlq = enable_dlq
        self.dlq_table_name = dlq_table_name or f"event-dlq-{event_bus_name}"
        self.parallel_workers = parallel_workers

        # Initialize AWS clients
        self.eventbridge = boto3.client('events', region_name=region_name)
        self.dynamodb = boto3.client('dynamodb', region_name=region_name) if enable_dlq else None

        logger.info(
            "EventPublisher initialized",
            extra={
                "event_bus_name": event_bus_name,
                "max_batch_size": self.max_batch_size,
                "max_retries": max_retries,
                "enable_dlq": enable_dlq
            }
        )

    @tracer.capture_method
    @metrics.log_metrics(capture_cold_start_metric=True)
    def publish_event(
        self,
        event: Union[BaseEvent, Dict[str, Any]],
        validate_schema: bool = True
    ) -> PublishResult:
        """
        Publish a single event to EventBridge.

        Args:
            event: Event to publish (BaseEvent instance or dict)
            validate_schema: Whether to validate event schema

        Returns:
            PublishResult with operation details
        """
        start_time = time.time()

        try:
            # Convert to BaseEvent if needed and validate
            if isinstance(event, dict):
                if validate_schema:
                    try:
                        event = BaseEvent(**event)
                    except ValidationError as e:
                        raise EventValidationError(f"Event validation failed: {e}", event)
                else:
                    # Create minimal BaseEvent for dict input
                    event = BaseEvent(
                        source=event.get('source', EventSource.SYSTEM),
                        event_type=event.get('event_type', EventType.SYSTEM_ERROR),
                        data=event.get('data', event)
                    )

            # Convert to EventBridge format
            entry = event.to_eventbridge_entry(self.event_bus_name)

            # Publish with retry logic
            result = self._publish_with_retry([entry])

            duration_ms = (time.time() - start_time) * 1000

            if result.get('FailedEntryCount', 0) > 0:
                failed_entry = result.get('Entries', [{}])[0]
                error_message = failed_entry.get('ErrorMessage', 'Unknown error')

                # Send to DLQ if enabled
                if self.enable_dlq:
                    self._send_to_dlq(entry, error_message)

                metrics.add_metric(name="EventPublishFailed", unit=MetricUnit.Count, value=1)

                return PublishResult(
                    success=False,
                    error_message=error_message,
                    duration_ms=duration_ms,
                    event_data=entry
                )

            metrics.add_metric(name="EventPublishSuccess", unit=MetricUnit.Count, value=1)
            metrics.add_metric(name="EventPublishDuration", unit=MetricUnit.Milliseconds, value=duration_ms)

            return PublishResult(
                success=True,
                event_id=event.id,
                duration_ms=duration_ms,
                event_data=entry
            )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            error_message = f"Failed to publish event: {str(e)}"

            logger.error(error_message, extra={"error": str(e), "event": event})
            metrics.add_metric(name="EventPublishError", unit=MetricUnit.Count, value=1)

            # Send to DLQ if enabled
            if self.enable_dlq and isinstance(event, BaseEvent):
                self._send_to_dlq(event.to_eventbridge_entry(self.event_bus_name), error_message)

            return PublishResult(
                success=False,
                error_message=error_message,
                duration_ms=duration_ms
            )

    @tracer.capture_method
    def publish_events(
        self,
        events: List[Union[BaseEvent, Dict[str, Any]]],
        validate_schema: bool = True,
        use_parallel: bool = True
    ) -> BatchPublishResult:
        """
        Publish multiple events to EventBridge with batching.

        Args:
            events: List of events to publish
            validate_schema: Whether to validate event schemas
            use_parallel: Whether to use parallel processing for large batches

        Returns:
            BatchPublishResult with operation details
        """
        start_time = time.time()

        if not events:
            return BatchPublishResult(
                total_events=0,
                successful_events=0,
                duration_ms=0.0
            )

        logger.info(f"Publishing {len(events)} events in batches")

        # Prepare events and create batches
        try:
            prepared_events = self._prepare_events(events, validate_schema)
            batches = self._create_batches(prepared_events)

            # Process batches
            if use_parallel and len(batches) > 1:
                result = self._process_batches_parallel(batches)
            else:
                result = self._process_batches_sequential(batches)

            duration_ms = (time.time() - start_time) * 1000
            result.duration_ms = duration_ms

            # Log metrics
            metrics.add_metric(name="EventBatchSize", unit=MetricUnit.Count, value=len(events))
            metrics.add_metric(name="EventBatchSuccess", unit=MetricUnit.Count, value=result.successful_events)
            metrics.add_metric(name="EventBatchFailed", unit=MetricUnit.Count, value=len(result.failed_events))
            metrics.add_metric(name="EventBatchDuration", unit=MetricUnit.Milliseconds, value=duration_ms)

            logger.info(
                "Batch publish completed",
                extra={
                    "total_events": result.total_events,
                    "successful_events": result.successful_events,
                    "failed_events": len(result.failed_events),
                    "duration_ms": duration_ms
                }
            )

            return result

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            error_message = f"Batch publish failed: {str(e)}"

            logger.error(error_message, extra={"error": str(e), "event_count": len(events)})
            metrics.add_metric(name="EventBatchError", unit=MetricUnit.Count, value=1)

            return BatchPublishResult(
                total_events=len(events),
                successful_events=0,
                failed_events=[{"error": error_message, "events": events}],
                errors=[error_message],
                duration_ms=duration_ms
            )

    def _prepare_events(
        self,
        events: List[Union[BaseEvent, Dict[str, Any]]],
        validate_schema: bool
    ) -> List[Dict[str, Any]]:
        """Prepare events for publishing."""
        prepared = []

        for event in events:
            try:
                if isinstance(event, dict):
                    if validate_schema:
                        event = BaseEvent(**event)
                    else:
                        event = BaseEvent(
                            source=event.get('source', EventSource.SYSTEM),
                            event_type=event.get('event_type', EventType.SYSTEM_ERROR),
                            data=event.get('data', event)
                        )

                prepared.append(event.to_eventbridge_entry(self.event_bus_name))

            except ValidationError as e:
                logger.error(f"Event validation failed: {e}", extra={"event": event})
                if self.enable_dlq:
                    self._send_to_dlq(event, f"Validation error: {e}")

        return prepared

    def _create_batches(self, events: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Create batches from events list."""
        return [
            events[i:i + self.max_batch_size]
            for i in range(0, len(events), self.max_batch_size)
        ]

    def _process_batches_sequential(self, batches: List[List[Dict[str, Any]]]) -> BatchPublishResult:
        """Process batches sequentially."""
        total_events = sum(len(batch) for batch in batches)
        successful_events = 0
        failed_events = []
        errors = []

        for batch in batches:
            try:
                result = self._publish_with_retry(batch)
                batch_successful = len(batch) - result.get('FailedEntryCount', 0)
                successful_events += batch_successful

                # Handle failed entries
                if result.get('FailedEntryCount', 0) > 0:
                    for i, entry_result in enumerate(result.get('Entries', [])):
                        if 'ErrorCode' in entry_result:
                            failed_event = batch[i]
                            error_message = entry_result.get('ErrorMessage', 'Unknown error')
                            failed_events.append(failed_event)
                            errors.append(error_message)

                            # Send to DLQ
                            if self.enable_dlq:
                                self._send_to_dlq(failed_event, error_message)

            except Exception as e:
                error_message = f"Batch processing failed: {str(e)}"
                errors.append(error_message)
                failed_events.extend(batch)
                logger.error(error_message, extra={"batch_size": len(batch)})

        return BatchPublishResult(
            total_events=total_events,
            successful_events=successful_events,
            failed_events=failed_events,
            errors=errors
        )

    def _process_batches_parallel(self, batches: List[List[Dict[str, Any]]]) -> BatchPublishResult:
        """Process batches in parallel."""
        total_events = sum(len(batch) for batch in batches)
        successful_events = 0
        failed_events = []
        errors = []

        with ThreadPoolExecutor(max_workers=self.parallel_workers) as executor:
            # Submit all batches
            future_to_batch = {
                executor.submit(self._publish_with_retry, batch): batch
                for batch in batches
            }

            # Process completed futures
            for future in as_completed(future_to_batch):
                batch = future_to_batch[future]

                try:
                    result = future.result()
                    batch_successful = len(batch) - result.get('FailedEntryCount', 0)
                    successful_events += batch_successful

                    # Handle failed entries
                    if result.get('FailedEntryCount', 0) > 0:
                        for i, entry_result in enumerate(result.get('Entries', [])):
                            if 'ErrorCode' in entry_result:
                                failed_event = batch[i]
                                error_message = entry_result.get('ErrorMessage', 'Unknown error')
                                failed_events.append(failed_event)
                                errors.append(error_message)

                                # Send to DLQ
                                if self.enable_dlq:
                                    self._send_to_dlq(failed_event, error_message)

                except Exception as e:
                    error_message = f"Parallel batch processing failed: {str(e)}"
                    errors.append(error_message)
                    failed_events.extend(batch)
                    logger.error(error_message, extra={"batch_size": len(batch)})

        return BatchPublishResult(
            total_events=total_events,
            successful_events=successful_events,
            failed_events=failed_events,
            errors=errors
        )

    @tracer.capture_method
    def _publish_with_retry(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Publish events with retry logic."""
        last_exception = None

        for attempt in range(self.max_retries + 1):
            try:
                response = self.eventbridge.put_events(Entries=entries)

                # Log successful attempt
                if attempt > 0:
                    logger.info(f"Event published successfully on attempt {attempt + 1}")

                return response

            except (ClientError, BotoCoreError) as e:
                last_exception = e
                error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', 'Unknown')

                logger.warning(
                    f"Event publish attempt {attempt + 1} failed: {error_code}",
                    extra={"error": str(e), "attempt": attempt + 1}
                )

                # Don't retry on certain errors
                if error_code in ['ValidationException', 'InvalidParameterValue']:
                    break

                # Wait before retry (exponential backoff)
                if attempt < self.max_retries:
                    wait_time = self.retry_backoff * (2 ** attempt)
                    time.sleep(wait_time)

        # All retries failed
        raise EventPublishError(
            f"Failed to publish events after {self.max_retries + 1} attempts",
            original_error=last_exception
        )

    def _send_to_dlq(self, event_data: Union[Dict[str, Any], Any], error_message: str):
        """Send failed event to dead letter queue."""
        if not self.enable_dlq or not self.dynamodb:
            return

        try:
            dlq_item = {
                'id': {'S': str(time.time_ns())},
                'event_data': {'S': json.dumps(event_data, default=str)},
                'error_message': {'S': error_message},
                'timestamp': {'S': str(int(time.time()))},
                'retry_count': {'N': '0'},
                'ttl': {'N': str(int(time.time()) + 7 * 24 * 3600)}  # 7 days TTL
            }

            self.dynamodb.put_item(
                TableName=self.dlq_table_name,
                Item=dlq_item
            )

            logger.info("Event sent to DLQ", extra={"dlq_table": self.dlq_table_name})

        except Exception as e:
            logger.error(f"Failed to send event to DLQ: {e}")

    @tracer.capture_method
    def get_dlq_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve events from dead letter queue."""
        if not self.enable_dlq or not self.dynamodb:
            return []

        try:
            response = self.dynamodb.scan(
                TableName=self.dlq_table_name,
                Limit=limit
            )

            events = []
            for item in response.get('Items', []):
                events.append({
                    'id': item['id']['S'],
                    'event_data': json.loads(item['event_data']['S']),
                    'error_message': item['error_message']['S'],
                    'timestamp': int(item['timestamp']['S']),
                    'retry_count': int(item['retry_count']['N'])
                })

            return events

        except Exception as e:
            logger.error(f"Failed to retrieve DLQ events: {e}")
            return []

    @tracer.capture_method
    def retry_dlq_events(self, event_ids: Optional[List[str]] = None) -> BatchPublishResult:
        """Retry events from dead letter queue."""
        if not self.enable_dlq:
            return BatchPublishResult(total_events=0, successful_events=0)

        try:
            # Get events to retry
            dlq_events = self.get_dlq_events()

            if event_ids:
                dlq_events = [e for e in dlq_events if e['id'] in event_ids]

            if not dlq_events:
                return BatchPublishResult(total_events=0, successful_events=0)

            # Extract event data and retry
            events_to_retry = [event['event_data'] for event in dlq_events]
            result = self.publish_events(events_to_retry, validate_schema=False)

            # Remove successful events from DLQ
            if result.successful_events > 0:
                self._remove_from_dlq([e['id'] for e in dlq_events[:result.successful_events]])

            logger.info(
                f"DLQ retry completed: {result.successful_events}/{len(dlq_events)} events successful"
            )

            return result

        except Exception as e:
            logger.error(f"DLQ retry failed: {e}")
            return BatchPublishResult(
                total_events=len(dlq_events) if 'dlq_events' in locals() else 0,
                successful_events=0,
                errors=[str(e)]
            )

    def _remove_from_dlq(self, event_ids: List[str]):
        """Remove events from DLQ after successful retry."""
        if not self.enable_dlq or not self.dynamodb:
            return

        for event_id in event_ids:
            try:
                self.dynamodb.delete_item(
                    TableName=self.dlq_table_name,
                    Key={'id': {'S': event_id}}
                )
            except Exception as e:
                logger.error(f"Failed to remove event {event_id} from DLQ: {e}")
