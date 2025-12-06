#!/usr/bin/env python
"""
Splunk HTTP Event Collector (HEC) Python Library
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
import os
import logging
from datetime import datetime


class http_event_collector:
    """
    Splunk HTTP Event Collector class for sending events to Splunk
    """

    # Default retry configuration
    DEFAULT_MAX_RETRIES = 3
    DEFAULT_BACKOFF_FACTOR = 1.0  # 1s, 2s, 4s with exponential backoff
    DEFAULT_RETRY_STATUS_CODES = [429, 500, 502, 503, 504]

    # Default connection pool configuration
    DEFAULT_POOL_CONNECTIONS = 3
    DEFAULT_POOL_MAXSIZE = 3

    # Rate limiting defaults (to prevent overwhelming HEC)
    DEFAULT_BATCH_DELAY = 0.2  # 200ms delay between batches
    DEFAULT_REQUEST_TIMEOUT = 90  # Increased timeout for large batches

    def __init__(
            self,
            token,
            http_event_server,
            host="",
            http_event_port='8088',
            http_event_server_ssl=True,
            ssl_ca_cert=None,
            max_bytes=1048576,
            index="",
            max_retries=None,
            backoff_factor=None,
            pool_connections=None,
            pool_maxsize=None,
            batch_delay=None,
            request_timeout=None):
        """
        Initialize HEC event collector

        Args:
            token: HEC token from Splunk
            http_event_server: Splunk server hostname/IP
            host: Host field for events (default: current hostname)
            http_event_port: HEC port (default: 8088)
            http_event_server_ssl: Use SSL/TLS (default: True)
            max_bytes: Maximum batch size in bytes (default: 1MB)
            index: Default Splunk index
            max_retries: Maximum retry attempts (default: 3)
            backoff_factor: Exponential backoff factor in seconds (default: 1.0)
            pool_connections: Number of connection pools (default: 5)
            pool_maxsize: Max connections per pool (default: 5)
            ssl_ca_cert: Path to CA certificate file for SSL verification (default: None)
            batch_delay: Delay between batches in seconds (default: 0.1)
            request_timeout: Request timeout in seconds (default: 60)
        """
        self.token = token
        self.ssl_ca_cert = ssl_ca_cert
        self.ssl_verify = http_event_server_ssl
        self.batchEvents = []
        self.maxByteLength = max_bytes
        self.currentByteLength = 0
        self.server_uri = []

        # Retry configuration
        self.max_retries = max_retries if max_retries is not None else self.DEFAULT_MAX_RETRIES
        self.backoff_factor = backoff_factor if backoff_factor is not None else self.DEFAULT_BACKOFF_FACTOR

        # Connection pool configuration
        self.pool_connections = pool_connections if pool_connections is not None else self.DEFAULT_POOL_CONNECTIONS
        self.pool_maxsize = pool_maxsize if pool_maxsize is not None else self.DEFAULT_POOL_MAXSIZE

        # Rate limiting configuration
        self.batch_delay = batch_delay if batch_delay is not None else self.DEFAULT_BATCH_DELAY
        self.request_timeout = request_timeout if request_timeout is not None else self.DEFAULT_REQUEST_TIMEOUT

        # Metrics tracking
        self.retry_count = 0
        self.send_count = 0
        self.error_count = 0

        # Set server protocol
        if http_event_server_ssl:
            protocol = 'https'
        else:
            protocol = 'http'

        # Build server URI
        self.server_uri = f'{protocol}://{http_event_server}:{http_event_port}/services/collector/event'

        # Set default host if not provided
        if host:
            self.host = host
        else:
            self.host = socket.gethostname()

        self.index = index

        # Logger for this module
        self.logger = logging.getLogger(__name__)

        # Create persistent session with connection pooling and retry logic
        self._session = self._create_session(http_event_server_ssl)

    def _create_session(self, ssl_enabled):
        """
        Create a requests session with connection pooling and retry strategy.

        Args:
            ssl_enabled: Whether SSL is enabled (for warning suppression)

        Returns:
            Configured requests.Session object
        """
        session = requests.Session()

        # Configure retry strategy with exponential backoff
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=self.DEFAULT_RETRY_STATUS_CODES,
            allowed_methods=["POST"],  # Only retry POST requests
            raise_on_status=False  # Don't raise, we handle status ourselves
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
        else:
            if 'time' not in payload:
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
        """
        Flush the current batch of events to Splunk with retry logic.
        """
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

        # Send via persistent session with connection pooling
        # Retry strategy is built into the session adapter
        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                # Determine SSL verification setting
                if self.ssl_verify:
                    verify_param = self.ssl_ca_cert if self.ssl_ca_cert else True
                else:
                    verify_param = False

                response = self._session.post(
                    self.server_uri,
                    data=payload,
                    headers=headers,
                    verify=verify_param,
                    proxies={'http': None, 'https': None},
                    timeout=self.request_timeout
                )

                # Check response
                if response.status_code == 200:
                    self.send_count += event_count
                    # Reset batch on success
                    self.batchEvents = []
                    self.currentByteLength = 0
                    # Rate limiting: small delay between batches to avoid overwhelming HEC
                    if self.batch_delay > 0:
                        time.sleep(self.batch_delay)
                    return response

                # Handle specific error codes
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
                self.logger.error(
                    f"HEC Event Collector error: {response.status_code} - {response.text}")
                # Reset batch even on error to prevent stuck data
                self.batchEvents = []
                self.currentByteLength = 0
                return response

            except requests.exceptions.Timeout:
                self.retry_count += 1
                last_error = "Request timeout"
                wait_time = self.backoff_factor * (2 ** attempt)
                self.logger.warning(
                    f"HEC request timeout, retrying in {wait_time:.1f}s "
                    f"(attempt {attempt + 1}/{self.max_retries + 1})"
                )
                time.sleep(wait_time)

            except requests.exceptions.ConnectionError as e:
                self.retry_count += 1
                last_error = str(e)
                wait_time = self.backoff_factor * (2 ** attempt)
                self.logger.warning(
                    f"HEC connection error, retrying in {wait_time:.1f}s "
                    f"(attempt {attempt + 1}/{self.max_retries + 1}): {e}"
                )
                time.sleep(wait_time)

            except Exception as e:
                self.error_count += 1
                self.logger.error(f"HEC Event Collector exception: {e}")
                # Reset batch on exception
                self.batchEvents = []
                self.currentByteLength = 0
                raise

        # All retries exhausted
        self.error_count += 1
        self.logger.error(
            f"HEC request failed after {self.max_retries + 1} attempts: {last_error}")
        # Reset batch to prevent stuck state
        self.batchEvents = []
        self.currentByteLength = 0

    def __del__(self):
        """
        Destructor - flush any remaining events
        """
        try:
            self.flushBatch()
        except BaseException:
            pass

    def get_metrics(self):
        """
        Get current metrics for monitoring.

        Returns:
            dict with send_count, retry_count, error_count
        """
        return {
            'send_count': self.send_count,
            'retry_count': self.retry_count,
            'error_count': self.error_count
        }


class http_event_collector_raw:
    """
    Splunk HTTP Event Collector class for raw endpoint
    """

    def __init__(self, token, http_event_server, http_event_port='8088',
                 http_event_server_ssl=True, channel=""):
        """
        Initialize HEC raw event collector

        Args:
            token: HEC token from Splunk
            http_event_server: Splunk server hostname/IP
            http_event_port: HEC port (default: 8088)
            http_event_server_ssl: Use SSL/TLS (default: True)
            channel: HEC channel GUID
        """
        self.token = token
        self.channel = channel

        # Set server protocol
        if http_event_server_ssl:
            protocol = 'https'
        else:
            protocol = 'http'

        # Build server URI
        self.server_uri = f'{protocol}://{http_event_server}:{http_event_port}/services/collector/raw'

        # Disable SSL warnings if not verifying
        if not http_event_server_ssl:
            requests.packages.urllib3.disable_warnings()

    def sendEvent(self, payload, source="", sourcetype="", index="", host=""):
        """
        Send raw event to Splunk

        Args:
            payload: Raw event data
            source: Event source
            sourcetype: Event sourcetype
            index: Splunk index
            host: Event host
        """
        # Prepare headers
        headers = {
            'Authorization': f'Splunk {self.token}'
        }

        if self.channel:
            headers['X-Splunk-Request-Channel'] = self.channel

        # Prepare query parameters
        params = {}
        if source:
            params['source'] = source
        if sourcetype:
            params['sourcetype'] = sourcetype
        if index:
            params['index'] = index
        if host:
            params['host'] = host

        # Send to Splunk
        try:
            response = requests.post(
                self.server_uri,
                params=params,
                data=payload,
                headers=headers,
                verify=False  # Consider making this configurable
            )

            # Check response
            if response.status_code != 200:
                print(
                    f"HEC Raw Event Collector error: {response.status_code} - {response.text}")

            return response

        except Exception as e:
            print(f"HEC Raw Event Collector exception: {e}")
            raise
