#!/usr/bin/env python3
# Main Tenable to Cribl collector
import os
import argparse
import logging
import time
import sys
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from tenable.io import TenableIO
from checkpoint_manager import FileCheckpoint
from tenable_common import CriblHECHandler, setup_logging, validate_environment, CollectorMetrics
from feeds.assets import (AssetFeedProcessor, AssetSelfScanProcessor,
                          DeletedAssetProcessor, TerminatedAssetProcessor)
from feeds.vulnerabilities import (
    VulnerabilityFeedProcessor,
    VulnerabilityNoInfoProcessor,
    VulnerabilitySelfScanProcessor,
    FixedVulnerabilityProcessor)
from feeds.plugins import (PluginFeedProcessor, ComplianceFeedProcessor)


# Global shutdown event for graceful termination
_shutdown_event = threading.Event()


class TenableIntegration:
    # Main integration orchestrator for all Tenable feeds

    def __init__(self):
        # Load environment variables from .env file
        load_dotenv()

        # Validate required environment variables (fail fast)
        validate_environment()

        # Set up logging
        log_level = os.getenv('LOG_LEVEL', 'INFO')
        setup_logging(log_level, 'tenable_integration.log')
        self.logger = logging.getLogger(__name__)

        # Initialize metrics tracker
        self.metrics = CollectorMetrics()

        # Reference to global shutdown event
        self._shutdown_event = _shutdown_event

        # Initialize Tenable.io API client
        self.tenable = TenableIO(
            access_key=os.getenv('TENABLE_ACCESS_KEY'),
            secret_key=os.getenv('TENABLE_SECRET_KEY'),
            url=os.getenv('TENABLE_URL', 'https://cloud.tenable.com')
        )
        self.logger.info("Initialized Tenable.io client")

        # Initialize Cribl HEC handler with retry and pool settings
        # Get CA cert path (None if not set or empty)
        ca_cert_path = os.getenv('CRIBL_HEC_CA_CERT', '').strip() or None
        
        self.cribl = CriblHECHandler(
            host=os.getenv('CRIBL_HEC_HOST'),
            port=int(os.getenv('CRIBL_HEC_PORT', 8088)),
            token=os.getenv('CRIBL_HEC_TOKEN'),
            index='', sourcetype='', source='',
            ssl_verify=os.getenv(
                'CRIBL_HEC_SSL_VERIFY',
                'true').lower() == 'true',
            ssl_ca_cert=ca_cert_path,
            max_retries=int(os.getenv('HEC_MAX_RETRIES', 3)),
            backoff_factor=float(os.getenv('HEC_BACKOFF_FACTOR', 1.0)),
            pool_connections=int(os.getenv('HEC_POOL_CONNECTIONS', 10)),
            pool_maxsize=int(os.getenv('HEC_POOL_MAXSIZE', 10))
        )

        # Initialize checkpoint manager for deduplication
        self.checkpoint = FileCheckpoint(
            checkpoint_dir=os.getenv('CHECKPOINT_DIR', 'checkpoints'),
            key_prefix='tenable',
            max_ids=int(os.getenv('CHECKPOINT_MAX_IDS', 100000)),
            retention_days=int(os.getenv('CHECKPOINT_RETENTION_DAYS', 30))
        )
        self.logger.info("Initialized file-based checkpointing")

        # Configure batch size for HEC sends
        self.batch_size = int(os.getenv('HEC_BATCH_SIZE', 10000))
        self.logger.info(
            "Batch size configured: {0} events".format(
                self.batch_size))

        # Configure max events per feed (0 = unlimited)
        self.max_events = int(os.getenv('MAX_EVENTS_PER_FEED', 0))
        if self.max_events > 0:
            self.logger.info(
                "Max events per feed: {0}".format(
                    self.max_events))
        else:
            self.logger.info("Max events per feed: unlimited")

        # Configure concurrent workers (0 = auto-tune, 1+ = explicit)
        self.max_workers = int(os.getenv('MAX_CONCURRENT_FEEDS', 0))
        # Note: if 0, will auto-tune to min(10, feed_count) at runtime
        if self.max_workers > 0:
            self.logger.info(
                "Concurrent execution: {0} workers (explicit)".format(
                    self.max_workers))
        else:
            self.logger.info("Concurrent execution: auto-tune (up to 10 workers)")

        # Cache for feed processors (lazy initialization)
        self._feed_processors = {}

    def _get_processor(self, feed_name):
        if feed_name in self._feed_processors:
            return self._feed_processors[feed_name]

        processor_map = {
            'tenableio_asset': AssetFeedProcessor,
            'tenableio_asset_self_scan': AssetSelfScanProcessor,
            'tenableio_deleted_asset': DeletedAssetProcessor,
            'tenableio_terminated_asset': TerminatedAssetProcessor,
            'tenableio_vulnerability': VulnerabilityFeedProcessor,
            'tenableio_vulnerability_no_info': VulnerabilityNoInfoProcessor,
            'tenableio_vulnerability_self_scan': VulnerabilitySelfScanProcessor,
            'tenableio_fixed_vulnerability': FixedVulnerabilityProcessor,
            'tenableio_plugin': PluginFeedProcessor,
            'tenableio_compliance': ComplianceFeedProcessor}

        processor_class = processor_map.get(feed_name)
        if not processor_class:
            raise ValueError("Unknown feed type: {0}".format(feed_name))

        processor = processor_class(
            self.tenable,
            self.checkpoint,
            self.cribl,
            self.batch_size,
            self.max_events)
        self._feed_processors[feed_name] = processor
        return processor

    def _process_feed(self, feed_name):
        # Process a single feed (thread-safe for concurrent execution)
        # Check for shutdown before processing
        if self._shutdown_event.is_set():
            self.logger.warning("Shutdown requested, skipping feed: {0}".format(feed_name))
            return 0

        try:
            start_time = time.time()
            processor = self._get_processor(feed_name)
            event_count = processor.process()

            # Track metrics
            elapsed = time.time() - start_time
            self.metrics.record_feed(feed_name, event_count, elapsed)

            # Flush checkpoint after processing
            self.checkpoint.flush_all()
            return event_count
        except Exception as e:
            self.metrics.record_error(feed_name, str(e))
            self.logger.error(
                "Error processing feed {0}: {1}".format(
                    feed_name, str(e)), exc_info=True)
            return 0

    def run_once(self, data_types):
        # Run collection once for specified feed types
        # Note: No process lock needed - each feed uses separate checkpoint
        # files
        try:
            # Reset metrics for this run
            self.metrics.reset()
            run_start = time.time()

            self.logger.info("=" * 80)
            self.logger.info("STARTING TENABLE TO CRIBL INTEGRATION")
            self.logger.info("=" * 80)
            self.logger.info(
                "Selected feeds: {0}".format(
                    ', '.join(data_types)))
            self.logger.info("Batch size: {0} events".format(self.batch_size))
            self.logger.info(
                "Timestamp: {0}".format(
                    time.strftime('%Y-%m-%d %H:%M:%S')))
            self.logger.info("=" * 80)

            # All available feed types
            all_feeds = [
                'tenableio_asset',
                'tenableio_asset_self_scan',
                'tenableio_compliance',
                'tenableio_deleted_asset',
                'tenableio_fixed_vulnerability',
                'tenableio_plugin',
                'tenableio_terminated_asset',
                'tenableio_vulnerability',
                'tenableio_vulnerability_no_info',
                'tenableio_vulnerability_self_scan']

            # Determine which feeds to process
            feeds_to_process = all_feeds if 'all' in data_types else [
                f for f in data_types if f in all_feeds]
            total_events = 0
            feed_results = {}

            # Auto-tune workers if not explicitly set
            effective_workers = self.max_workers
            if effective_workers == 0:
                # Auto-tune: use min(10, feed_count) for optimal parallelism
                effective_workers = min(10, len(feeds_to_process))

            # Process feeds concurrently with auto-tuned or explicit workers
            self.logger.info(
                "CONCURRENT MODE: Processing {0} feeds with {1} workers".format(
                    len(feeds_to_process), effective_workers))
            self.logger.info(
                "Feeds queued: {0}".format(
                    ', '.join(feeds_to_process)))

            with ThreadPoolExecutor(max_workers=effective_workers) as executor:
                # Submit all feed processing jobs
                future_to_feed = {
                    executor.submit(self._process_feed, feed_name): feed_name
                    for feed_name in feeds_to_process
                }

                self.logger.info(
                    "All {0} feeds submitted to thread pool".format(len(feeds_to_process)))
                completed = 0

                # Collect results as they complete
                for future in as_completed(future_to_feed):
                    feed_name = future_to_feed[future]
                    completed += 1
                    try:
                        event_count = future.result()
                        total_events += event_count
                        feed_results[feed_name] = event_count
                        self.logger.info(
                            "Feed {0} completed: {1} events ({2}/{3} done)".format(
                                feed_name, event_count, completed, len(feeds_to_process)))
                    except Exception as e:
                        self.logger.error("Feed {0} FAILED: {1} ({2}/{3} done)".format(
                            feed_name, str(e), completed, len(feeds_to_process)), exc_info=True)
                        feed_results[feed_name] = 0

            self.logger.info("=" * 80)
            self.logger.info("INTEGRATION COMPLETED SUCCESSFULLY")
            self.logger.info("=" * 80)
            self.logger.info("Feed Collection Summary:")
            for feed_name in feeds_to_process:
                event_count = feed_results.get(feed_name, 0)
                self.logger.info(
                    "  {0}: {1} events".format(
                        feed_name, event_count))
            self.logger.info("-" * 80)
            self.logger.info(
                "Total events sent to Cribl: {0}".format(total_events))

            # Log metrics summary
            run_elapsed = time.time() - run_start
            self.metrics.log_summary(self.logger, run_elapsed)
            self.logger.info("=" * 80)

            # CRITICAL: Flush all checkpoints to disk to prevent duplicates
            self.logger.info("Flushing checkpoints to disk...")
            self.checkpoint.flush_all()
            self.logger.info("Checkpoints saved successfully")
        except Exception as e:
            self.logger.error(
                "ERROR during integration run: {0}".format(
                    str(e)), exc_info=True)
            raise
        finally:
            # Always try to flush checkpoints, even on error
            try:
                self.checkpoint.flush_all()
            except Exception:
                pass

    def run_daemon(self, data_types, interval=3600):
        self.logger.info(
            "Starting daemon mode (interval: {0}s)...".format(interval))
        while not self._shutdown_event.is_set():
            try:
                self.run_once(data_types)
                self.logger.info(
                    "Sleeping for {0} seconds (Ctrl+C to stop)...".format(interval))
                # Use event wait instead of sleep for responsive shutdown
                if self._shutdown_event.wait(timeout=interval):
                    self.logger.info("Shutdown event received during sleep")
                    break
            except Exception as e:
                self.logger.error(
                    "Error in daemon loop: {0}".format(
                        str(e)), exc_info=True)
                self.logger.info(
                    "Waiting {0} seconds before retry...".format(interval))
                if self._shutdown_event.wait(timeout=interval):
                    break

        self.logger.info("Daemon mode exiting, performing cleanup...")
        self._graceful_shutdown()

    def _graceful_shutdown(self):
        """Perform graceful shutdown: flush checkpoints and log final metrics."""
        self.logger.info("Initiating graceful shutdown...")
        try:
            # Flush all pending checkpoints
            self.checkpoint.flush_all()
            self.logger.info("Checkpoints flushed successfully")
        except Exception as e:
            self.logger.error("Error flushing checkpoints: {0}".format(e))

        try:
            # Flush any pending HEC events
            self.cribl.flush()
            self.logger.info("HEC buffer flushed successfully")
        except Exception as e:
            self.logger.error("Error flushing HEC buffer: {0}".format(e))

        # Log final metrics
        self.metrics.log_summary(self.logger, 0)
        self.logger.info("Graceful shutdown complete")


def _signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    sig_name = signal.Signals(signum).name
    logging.getLogger(__name__).info(
        "Received signal {0}, initiating graceful shutdown...".format(sig_name))
    _shutdown_event.set()


def main():
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    parser = argparse.ArgumentParser(
        description='Tenable to Cribl Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Feed Types:
  tenableio_asset                   Asset inventory
  tenableio_asset_self_scan         Agent-based assets
  tenableio_compliance              Compliance findings
  tenableio_deleted_asset           Deleted assets
  tenableio_fixed_vulnerability     Fixed vulnerabilities
  tenableio_plugin                  Plugin metadata
  tenableio_terminated_asset        Terminated assets
  tenableio_vulnerability           Active vulnerabilities
  tenableio_vulnerability_no_info   Info-level vulnerabilities
  tenableio_vulnerability_self_scan Agent-based vulnerabilities
  all                               All feeds

Examples:
  python tenable_collector.py --feed all
  python tenable_collector.py --feed tenableio_asset tenableio_vulnerability
  python tenable_collector.py --feed all --daemon --interval 3600
        """
    )

    parser.add_argument(
        '--feed',
        nargs='+',
        default=['all'],
        dest='types',
        choices=[
            'all',
            'tenableio_asset',
            'tenableio_asset_self_scan',
            'tenableio_compliance',
            'tenableio_deleted_asset',
            'tenableio_fixed_vulnerability',
            'tenableio_plugin',
            'tenableio_terminated_asset',
            'tenableio_vulnerability',
            'tenableio_vulnerability_no_info',
            'tenableio_vulnerability_self_scan'],
        help='Feed types to collect (default: all)')

    parser.add_argument('--daemon', action='store_true',
                        help='Run in daemon mode (continuous collection)')

    parser.add_argument(
        '--interval',
        type=int,
        default=3600,
        help='Seconds between runs in daemon mode (default: 3600)')

    args = parser.parse_args()
    integration = TenableIntegration()

    if args.daemon:
        integration.run_daemon(args.types, args.interval)
    else:
        integration.run_once(args.types)


if __name__ == '__main__':
    main()
