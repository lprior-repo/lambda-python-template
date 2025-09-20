-- ========================================
-- KINESIS ANALYTICS SQL FOR ORDER PROCESSING
-- ========================================
-- Real-time analytics for order events with:
-- - Order volume and revenue metrics
-- - User activity aggregations
-- - Event type distributions
-- - Time-based windowing for trending analysis
-- - Anomaly detection patterns

-- Create in-application streams for processing
CREATE OR REPLACE STREAM "order_volume_stream" (
    window_start TIMESTAMP,
    window_end TIMESTAMP,
    total_orders BIGINT,
    total_revenue DECIMAL(12,2),
    avg_order_value DECIMAL(10,2),
    unique_users BIGINT
);

CREATE OR REPLACE STREAM "event_type_metrics" (
    window_start TIMESTAMP,
    window_end TIMESTAMP,
    event_type VARCHAR(32),
    event_count BIGINT,
    total_amount DECIMAL(12,2)
);

CREATE OR REPLACE STREAM "user_activity_metrics" (
    window_start TIMESTAMP,
    window_end TIMESTAMP,
    user_id VARCHAR(64),
    order_count BIGINT,
    total_spent DECIMAL(12,2),
    avg_order_value DECIMAL(10,2)
);

CREATE OR REPLACE STREAM "hourly_trends" (
    hour_start TIMESTAMP,
    total_orders BIGINT,
    total_revenue DECIMAL(12,2),
    unique_users BIGINT,
    orders_per_minute DECIMAL(8,2)
);

-- ========================================
-- ORDER VOLUME AND REVENUE ANALYTICS
-- ========================================

-- 5-minute sliding window for order volume and revenue
CREATE OR REPLACE PUMP "order_volume_pump" AS INSERT INTO "order_volume_stream"
SELECT STREAM
    ROWTIME_TO_TIMESTAMP(window_start) as window_start,
    ROWTIME_TO_TIMESTAMP(window_end) as window_end,
    COUNT(*) as total_orders,
    COALESCE(SUM(amount), 0.00) as total_revenue,
    COALESCE(AVG(amount), 0.00) as avg_order_value,
    COUNT(DISTINCT user_id) as unique_users
FROM TABLE(
    TUMBLE(
        CURSOR(SELECT STREAM * FROM "SOURCE_SQL_STREAM_001" WHERE event_type = 'ORDER_CREATED'),
        INTERVAL '5' MINUTE
    )
)
GROUP BY
    ROWTIME_TO_TIMESTAMP(window_start),
    ROWTIME_TO_TIMESTAMP(window_end);

-- ========================================
-- EVENT TYPE DISTRIBUTION ANALYTICS
-- ========================================

-- Track distribution of different event types
CREATE OR REPLACE PUMP "event_type_pump" AS INSERT INTO "event_type_metrics"
SELECT STREAM
    ROWTIME_TO_TIMESTAMP(window_start) as window_start,
    ROWTIME_TO_TIMESTAMP(window_end) as window_end,
    event_type,
    COUNT(*) as event_count,
    COALESCE(SUM(amount), 0.00) as total_amount
FROM TABLE(
    TUMBLE(
        CURSOR(SELECT STREAM * FROM "SOURCE_SQL_STREAM_001"),
        INTERVAL '1' MINUTE
    )
)
GROUP BY
    ROWTIME_TO_TIMESTAMP(window_start),
    ROWTIME_TO_TIMESTAMP(window_end),
    event_type;

-- ========================================
-- USER ACTIVITY ANALYTICS
-- ========================================

-- 15-minute window for user activity patterns
CREATE OR REPLACE PUMP "user_activity_pump" AS INSERT INTO "user_activity_metrics"
SELECT STREAM
    ROWTIME_TO_TIMESTAMP(window_start) as window_start,
    ROWTIME_TO_TIMESTAMP(window_end) as window_end,
    user_id,
    COUNT(*) as order_count,
    COALESCE(SUM(amount), 0.00) as total_spent,
    COALESCE(AVG(amount), 0.00) as avg_order_value
FROM TABLE(
    TUMBLE(
        CURSOR(SELECT STREAM * FROM "SOURCE_SQL_STREAM_001" WHERE event_type IN ('ORDER_CREATED', 'ORDER_UPDATED')),
        INTERVAL '15' MINUTE
    )
)
GROUP BY
    ROWTIME_TO_TIMESTAMP(window_start),
    ROWTIME_TO_TIMESTAMP(window_end),
    user_id
HAVING COUNT(*) > 0;

-- ========================================
-- HOURLY TREND ANALYTICS
-- ========================================

-- Hourly aggregations for trend analysis
CREATE OR REPLACE PUMP "hourly_trends_pump" AS INSERT INTO "hourly_trends"
SELECT STREAM
    ROWTIME_TO_TIMESTAMP(window_start) as hour_start,
    COUNT(*) as total_orders,
    COALESCE(SUM(amount), 0.00) as total_revenue,
    COUNT(DISTINCT user_id) as unique_users,
    CAST(COUNT(*) AS DECIMAL(8,2)) / 60.0 as orders_per_minute
FROM TABLE(
    TUMBLE(
        CURSOR(SELECT STREAM * FROM "SOURCE_SQL_STREAM_001" WHERE event_type = 'ORDER_CREATED'),
        INTERVAL '1' HOUR
    )
)
GROUP BY
    ROWTIME_TO_TIMESTAMP(window_start);

-- ========================================
-- ANOMALY DETECTION PATTERNS
-- ========================================

-- Create stream for anomaly detection (high-value orders)
CREATE OR REPLACE STREAM "anomaly_alerts" (
    event_time TIMESTAMP,
    event_id VARCHAR(64),
    order_id VARCHAR(64),
    user_id VARCHAR(64),
    amount DECIMAL(10,2),
    anomaly_type VARCHAR(32),
    confidence_score DECIMAL(5,2)
);

-- Detect unusually high-value orders (above 95th percentile)
CREATE OR REPLACE PUMP "high_value_anomaly_pump" AS INSERT INTO "anomaly_alerts"
SELECT STREAM
    timestamp as event_time,
    event_id,
    order_id,
    user_id,
    amount,
    'HIGH_VALUE_ORDER' as anomaly_type,
    95.0 as confidence_score
FROM "SOURCE_SQL_STREAM_001"
WHERE event_type = 'ORDER_CREATED'
AND amount > (
    SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY amount)
    FROM TABLE(
        RANGE_WINDOW(
            CURSOR(SELECT STREAM amount FROM "SOURCE_SQL_STREAM_001" WHERE event_type = 'ORDER_CREATED'),
            INTERVAL '1' HOUR PRECEDING
        )
    )
);

-- ========================================
-- REAL-TIME METRICS OUTPUT
-- ========================================

-- Combine all metrics into a single output stream
CREATE OR REPLACE STREAM "DESTINATION_SQL_STREAM" (
    metric_type VARCHAR(32),
    timestamp TIMESTAMP,
    metric_name VARCHAR(64),
    metric_value DECIMAL(12,2),
    dimensions VARCHAR(256)
);

-- Output order volume metrics
CREATE OR REPLACE PUMP "output_order_volume" AS INSERT INTO "DESTINATION_SQL_STREAM"
SELECT STREAM
    'ORDER_VOLUME' as metric_type,
    window_end as timestamp,
    'total_orders' as metric_name,
    CAST(total_orders AS DECIMAL(12,2)) as metric_value,
    CONCAT('window_minutes=5') as dimensions
FROM "order_volume_stream"
UNION ALL
SELECT STREAM
    'ORDER_REVENUE' as metric_type,
    window_end as timestamp,
    'total_revenue' as metric_name,
    total_revenue as metric_value,
    CONCAT('window_minutes=5') as dimensions
FROM "order_volume_stream"
UNION ALL
SELECT STREAM
    'ORDER_METRICS' as metric_type,
    window_end as timestamp,
    'avg_order_value' as metric_name,
    avg_order_value as metric_value,
    CONCAT('window_minutes=5') as dimensions
FROM "order_volume_stream";

-- Output event type metrics
CREATE OR REPLACE PUMP "output_event_types" AS INSERT INTO "DESTINATION_SQL_STREAM"
SELECT STREAM
    'EVENT_DISTRIBUTION' as metric_type,
    window_end as timestamp,
    'event_count' as metric_name,
    CAST(event_count AS DECIMAL(12,2)) as metric_value,
    CONCAT('event_type=', event_type, ',window_minutes=1') as dimensions
FROM "event_type_metrics";

-- Output hourly trends
CREATE OR REPLACE PUMP "output_hourly_trends" AS INSERT INTO "DESTINATION_SQL_STREAM"
SELECT STREAM
    'HOURLY_TRENDS' as metric_type,
    hour_start as timestamp,
    'orders_per_minute' as metric_name,
    orders_per_minute as metric_value,
    CONCAT('window_hours=1') as dimensions
FROM "hourly_trends";

-- Output anomaly alerts
CREATE OR REPLACE PUMP "output_anomalies" AS INSERT INTO "DESTINATION_SQL_STREAM"
SELECT STREAM
    'ANOMALY_ALERT' as metric_type,
    event_time as timestamp,
    anomaly_type as metric_name,
    amount as metric_value,
    CONCAT('user_id=', user_id, ',order_id=', order_id, ',confidence=', CAST(confidence_score AS VARCHAR(10))) as dimensions
FROM "anomaly_alerts";
