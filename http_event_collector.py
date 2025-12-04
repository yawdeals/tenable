#!/usr/bin/env python
"""
Splunk/Cribl HTTP Event Collector (HEC) Python Library
Based on georgestarcher's Splunk-Class-httpevent
https://github.com/georgestarcher/Splunk-Class-httpevent

Enhanced with:
- Exponential backoff retry logic
- Connection pool tuning
- Better error handling
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
import time
import socket
import logging


class http_event_collector:
    """
    Splunk/Cribl HTTP Event Collector class for sending events
    """

    # Default retry configuration
    DEFAULT_MAX_RETRIES = 3
    DEFAULT_BACKOFF_FACTOR = 1.0
    DEFAULT_RETRY_STATUS_CODES = [429, 500, 502, 503, 504]

    # Default connection pool configuration
    DEFAULT_POOL_CONNECTIONS = 10
    DEFAULT_POOL_MAXSIZE = 10

    def __init__(
            self,
            token,
            http_event_server,
            host="",
            http_event_port='8088',
            http_event_server_ssl=True,
            max_bytes=1048576,
            index="",
            max_retries=None,
            backoff_factor=None,
            pool_connections=None,
            pool_maxsize=None):
        """
        Initialize HEC event collector

        Args:
            token: HEC token from Splunk/Cribl
            http_event_server: Server hostname/IP
            host: Host field for events (default: current hostname)
            http_event_port: HEC port (default: 8088)
            http_event_server_ssl: Use SSL/TLS (default: True)
            max_bytes: Maximum batch size in bytes (default: 1MB)
            index: Default index
            max_retries: Maximum retry attempts (default: 3)
            backoff_factor: Exponential backoff factor in seconds (default: 1.0)
            pool_connections: Number of connection pools (default: 10)
            pool_maxsize: Max connections per pool (default: 10)
        """
        self.token = token
        self.batchEvents = []
        self.maxByteLength = max_bytes
        self.currentByteLength = 0

        # Retry configuration
        self.max_retries = max_retries if max_retries is not None else self.DEFAULT_MAX_RETRIES
        self.backoff_factor = backoff_factor if backoff_factor is not None else self.DEFAULT_BACKOFF_FACTOR

        # Connection pool configuration
        self.pool_connections = pool_connections if pool_connections is not None else self.DEFAULT_POOL_CONNECTIONS
        self.pool_maxsize = pool_maxsize if pool_maxsize is not None else self.DEFAULT_POOL_MAXSIZE

        # Metrics tracking
        self.retry_count = 0
        self.send_count = 0
        self.error_count = 0

        # Set server protocol
        protocol = 'https' if http_event_server_ssl else 'http'

        # Build server URI
        self.server_uri = f'{protocol}://{http_event_server}:{http_event_port}/services/collector/event'

        # Set default host if not provided
        self.host = host if host else socket.gethostname()
        self.index = index

        # Logger for this module
        self.logger = logging.getLogger(__name__)

        # Create persistent session with connection pooling and retry logic
        self._session = self._create_session(http_event_server_ssl)

    def _create_session(self, ssl_enabled):
        """Create a requests session with connection pooling and retry strategy."""
        session = requests.Session()

        # Configure retry strategy with exponential backoff
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=self.DEFAULT_RETRY_STATUS_CODES,
            allowed_methods=["POST"],
            raise_on_status=False
        )

        # Configure HTTP adapter with connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.pool_connections,
            pool_maxsize=self.pool_maxsize
        )

        # Mount adapter for both http and https
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Disable SSL warnings if not verifying
        if not ssl_enabled:
            requests.packages.urllib3.disable_warnings()

        return session

    def sendEvent(self, payload, eventtime=""):
        """
        Send a single event or add to batch

        Args:
            payload: Event payload dictionary
            eventtime: Optional event time (epoch or formatted string)
        """
        # Add metadata to payload
        if 'host' not in payload:
            payload['host'] = self.host

        if 'index' not in payload and self.index:
            payload['index'] = self.index

        # Handle event time
        if eventtime:
            payload['time'] = eventtime
        elif 'time' not in payload:
            payload['time'] = str(int(time.time()))

        # Convert payload to JSON
        payloadString = json.dumps(payload)
        payloadLength = len(payloadString)

        # Check if adding this event would exceed max batch size
        if (self.currentByteLength + payloadLength) > self.maxByteLength:
            self.flushBatch()

        # Add event to batch
        self.batchEvents.append(payloadString)
        self.currentByteLength += payloadLength

    def flushBatch(self):
        """Flush the current batch of events with retry logic."""
        if len(self.batchEvents) == 0:
            return

        # Combine all events with newlines
        payload = '\n'.join(self.batchEvents)
        event_count = len(self.batchEvents)

        # Prepare headers
        headers = {
            'Authorization': f'Splunk {self.token}',
            'Content-Type': 'application/json'
        }

        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self._session.post(
                    self.server_uri,
                    data=payload,
                    headers=headers,
                    verify=False,
                    proxies={'http': None, 'https': None},
                    timeout=30
                )

                if response.status_code == 200:
                    self.send_count += event_count
                    self.batchEvents = []
                    self.currentByteLength = 0
                    return response

                if response.status_code in self.DEFAULT_RETRY_STATUS_CODES:
                    self.retry_count += 1
                    wait_time = self.backoff_factor * (2 ** attempt)
                    self.logger.warning(
                        f"HEC returned {response.status_code}, retrying in {wait_time:.1f}s "
                        f"(attempt {attempt + 1}/{self.max_retries + 1})"
                    )
                    time.sleep(wait_time)
                    continue

                # Non-retryable error
                self.error_count += 1
                self.logger.error(f"HEC error: {response.status_code} - {response.text}")
                self.batchEvents = []
                self.currentByteLength = 0
                return response

            except requests.exceptions.Timeout:
                self.retry_count += 1
                last_error = "Request timeout"
                wait_time = self.backoff_factor * (2 ** attempt)
                self.logger.warning(f"HEC timeout, retrying in {wait_time:.1f}s")
                time.sleep(wait_time)

            except requests.exceptions.ConnectionError as e:
                self.retry_count += 1
                last_error = str(e)
                wait_time = self.backoff_factor * (2 ** attempt)
                self.logger.warning(f"HEC connection error, retrying in {wait_time:.1f}s: {e}")
                time.sleep(wait_time)

            except Exception as e:
                self.error_count += 1
                self.logger.error(f"HEC exception: {e}")
                self.batchEvents = []
                self.currentByteLength = 0
                raise

        # All retries exhausted
        self.error_count += 1
        self.logger.error(f"HEC failed after {self.max_retries + 1} attempts: {last_error}")
        self.batchEvents = []
        self.currentByteLength = 0

    def get_metrics(self):
        """Get current metrics for monitoring."""
        return {
            'send_count': self.send_count,
            'retry_count': self.retry_count,
            'error_count': self.error_count
        }

    def __del__(self):
        """Destructor - flush any remaining events"""
        try:
            self.flushBatch()
        except Exception:
            pass
