#!/usr/bin/env python3
"""
Test script for HEC library
Usage: python test_script.py
"""

import os
from dotenv import load_dotenv
from http_event_collector import http_event_collector

# Load .env file
load_dotenv()

def main():
    # Initialize HEC client
    hec = http_event_collector(
        token=os.getenv('HEC_TOKEN'),
        http_event_server=os.getenv('HEC_HOST'),
        http_event_port=os.getenv('HEC_PORT', '8088'),
        http_event_server_ssl=os.getenv('HEC_SSL_VERIFY', 'true').lower() == 'true',
        index=os.getenv('HEC_INDEX', 'main'),
        max_retries=int(os.getenv('HEC_MAX_RETRIES', 3)),
        backoff_factor=float(os.getenv('HEC_BACKOFF_FACTOR', 1.0))
    )

    print("Sending test events to HEC...")

    # Test 1: Single event
    hec.sendEvent({
        "event": {"message": "Test event 1", "severity": "info"},
        "sourcetype": "hec:test",
        "source": "test_script"
    })

    # Test 2: Batch of events
    for i in range(10):
        hec.sendEvent({
            "event": {"counter": i, "type": "batch_test"},
            "sourcetype": "hec:test",
            "source": "test_script"
        })

    # Flush remaining events
    hec.flushBatch()

    # Print metrics
    metrics = hec.get_metrics()
    print(f"Events sent: {metrics['send_count']}")
    print(f"Retries: {metrics['retry_count']}")
    print(f"Errors: {metrics['error_count']}")

    if metrics['error_count'] == 0:
        print("SUCCESS: All events sent successfully!")
    else:
        print("WARNING: Some events failed to send")

if __name__ == "__main__":
    main()
