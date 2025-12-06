#!/usr/bin/env python
# Tenable to Cribl collector - Common utilities
import os
import sys
import logging
import time
import threading
from collections import defaultdict
import http_event_collector as hec


# Required environment variables
REQUIRED_ENV_VARS = [
    ('TENABLE_ACCESS_KEY', 'Tenable.io API access key'),
    ('TENABLE_SECRET_KEY', 'Tenable.io API secret key'),
    ('CRIBL_HEC_HOST', 'Cribl/Splunk HEC hostname or IP'),
    ('CRIBL_HEC_TOKEN', 'Cribl/Splunk HEC authentication token'),
]


def validate_environment():
    """
    Validate that all required environment variables are set.
    Raises EnvironmentError with helpful message if any are missing.
    """
    missing = []
    for var_name, description in REQUIRED_ENV_VARS:
        if not os.getenv(var_name):
            missing.append((var_name, description))

    if missing:
        error_lines = ["Missing required environment variables:"]
        for var_name, description in missing:
            error_lines.append("  - {0}: {1}".format(var_name, description))
        error_lines.append("")
        error_lines.append("Set these in your .env file or export them as environment variables.")
        raise EnvironmentError('\n'.join(error_lines))


class CollectorMetrics:
    """
    Thread-safe metrics collection for monitoring collector health.
    Tracks events processed, errors, and timing per feed.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        """Reset all metrics for a new collection run."""
        with self._lock:
            self.start_time = time.time()
            self.feeds_processed = 0
            self.total_events = 0
            self.total_errors = 0
            self.hec_retries = 0
            self.feed_stats = defaultdict(lambda: {
                'events': 0,
                'errors': 0,
                'duration': 0.0
            })
            self.error_messages = []

    def record_feed(self, feed_name, event_count, duration):
        """Record metrics for a completed feed."""
        with self._lock:
            self.feeds_processed += 1
            self.total_events += event_count
            self.feed_stats[feed_name]['events'] = event_count
            self.feed_stats[feed_name]['duration'] = duration

    def record_error(self, feed_name, error_message):
        """Record an error for a feed."""
        with self._lock:
            self.total_errors += 1
            self.feed_stats[feed_name]['errors'] += 1
            self.error_messages.append({
                'feed': feed_name,
                'error': error_message,
                'timestamp': time.time()
            })

    def record_hec_retry(self):
        """Record an HEC retry attempt."""
        with self._lock:
            self.hec_retries += 1

    def get_summary(self):
        """Get a summary dict of all metrics."""
        with self._lock:
            elapsed = time.time() - self.start_time
            return {
                'elapsed_seconds': round(elapsed, 2),
                'feeds_processed': self.feeds_processed,
                'total_events': self.total_events,
                'total_errors': self.total_errors,
                'hec_retries': self.hec_retries,
                'events_per_second': round(self.total_events / max(elapsed, 0.001), 2),
                'feed_stats': dict(self.feed_stats),
                'recent_errors': self.error_messages[-10:]  # Last 10 errors
            }

    def log_summary(self, logger, run_duration=None):
        """Log a summary of metrics."""
        summary = self.get_summary()
        logger.info("-" * 40)
        logger.info("METRICS SUMMARY:")
        logger.info("  Feeds processed: {0}".format(summary['feeds_processed']))
        logger.info("  Total events: {0}".format(summary['total_events']))
        logger.info("  Total errors: {0}".format(summary['total_errors']))
        logger.info("  HEC retries: {0}".format(summary['hec_retries']))
        if run_duration and run_duration > 0:
            logger.info("  Run duration: {0:.2f}s".format(run_duration))
            logger.info("  Throughput: {0:.2f} events/sec".format(
                summary['total_events'] / max(run_duration, 0.001)))
        logger.info("-" * 40)


class CriblHECHandler:
    # Handles sending events to Cribl via HTTP Event Collector

    def __init__(self, host, port, token, index,
                 sourcetype, source, ssl_verify=True,
                 ssl_ca_cert=None,
                 max_retries=None, backoff_factor=None,
                 pool_connections=None, pool_maxsize=None):
        # Initialize HEC client with connection parameters
        self.hec_handler = hec.http_event_collector(
            token=token,
            http_event_server=host,
            http_event_port=str(port),
            http_event_server_ssl=ssl_verify,
            ssl_ca_cert=ssl_ca_cert,
            index=index,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize
        )
        self.sourcetype = sourcetype
        self.source = source
        self.index = index
        ssl_info = "CA cert: {}".format(ssl_ca_cert) if ssl_ca_cert else "SSL: {}".format(ssl_verify)
        logging.info("Initialized Cribl HEC: {0}:{1} ({2})".format(host, port, ssl_info))

    def send_event(self, event_data, timestamp=None,
                   sourcetype=None, source=None):
        # Send a single event to Cribl HEC
        try:
            # Build HEC payload with event data and metadata
            payload = {}
            payload['event'] = event_data
            payload['sourcetype'] = sourcetype or self.sourcetype
            payload['source'] = source or self.source
            payload['index'] = self.index

            # Add timestamp if provided
            if timestamp:
                payload['time'] = timestamp

            self.hec_handler.sendEvent(payload)
            return True
        except Exception as e:
            logging.error("Failed to send event to Cribl: {0}".format(e))
            return False

    def send_batch(
            self,
            events,
            sourcetype=None,
            feed_type=None,
            feed_name=None):
        # Send multiple events in batch mode for better performance
        if not events:
            return 0

        success_count = 0
        batch_sourcetype = sourcetype or self.sourcetype

        # Add each event to the batch buffer
        for event in events:
            try:
                # Build HEC payload
                payload = {}
                payload['event'] = event
                payload['sourcetype'] = batch_sourcetype
                payload['source'] = self.source
                payload['index'] = self.index

                # Add feed classification as HEC fields for easy filtering
                if feed_type:
                    payload['fields'] = {
                        'feed_type': feed_type,
                        'feed_name': feed_name or ''
                    }

                self.hec_handler.sendEvent(payload)
                success_count += 1
            except Exception as e:
                logging.error("Failed to add event to batch: {0}".format(e))

        # Flush the batch to send all buffered events
        try:
            self.hec_handler.flushBatch()
            logging.info(
                "HEC batch sent: {0} events | feed_type={1} | feed_name={2}".format(
                    success_count,
                    feed_type or 'n/a',
                    feed_name or 'n/a'))
        except Exception as e:
            logging.error("Error flushing batch: {0}".format(e))

        return success_count

    def flush(self):
        """Flush any pending events in the HEC buffer."""
        try:
            self.hec_handler.flushBatch()
        except Exception as e:
            logging.error("Error flushing HEC batch: {0}".format(e))


def setup_logging(log_level='INFO', log_file='tenable_integration.log'):
    # Configure logging to both console and file
    # Ensure logs directory exists
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Prepend logs/ directory to log file path
    log_path = os.path.join(log_dir, log_file)

    # Set up dual logging (console + file)
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),  # Console output
            logging.FileHandler(log_path)  # File output
        ]
    )
