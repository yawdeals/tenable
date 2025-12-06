#!/usr/bin/env python3
# Vulnerability feed processors with unique severity/state filters for
# concurrent execution
import time
from feeds.base import BaseFeedProcessor
from feeds.assets import _safe_export_with_retry


def _safe_get(obj, key, default=None):
    """Safely get a value from a dict or Box object."""
    if obj is None:
        return default
    if hasattr(obj, 'get'):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _safe_nested_get(obj, *keys, default=None):
    """Safely get a nested value from a dict or Box object chain."""
    current = obj
    for key in keys:
        current = _safe_get(current, key)
        if current is None:
            return default
    return current if current is not None else default


class VulnerabilityFeedProcessor(BaseFeedProcessor):

    def __init__(self, tenable_client, checkpoint_mgr,
                 hec_handler, batch_size=5000, max_events=0):
        super(
            VulnerabilityFeedProcessor,
            self).__init__(
            tenable_client,
            checkpoint_mgr,
            hec_handler,
            "Active Vulnerabilities",
            "tenableio_vulnerability",
            "tenable:io:vulnerability",
            "vulnerability",
            batch_size,
            max_events)

    def process(self):
        self.log_start()
        event_count = 0

        try:
            self.logger.info(
                "Initiating vulnerability export (severity: medium, high, critical)...")
            self.logger.info(
                "(This may take several minutes for large environments)")

            for vuln in _safe_export_with_retry(
                lambda: self.tenable.exports.vulns(
                    severity=[
                        'medium',
                        'high',
                        'critical']),
                    "Active Vulnerabilities"):
                # Use safe helpers for pytenable 1.9.0+ Box object compatibility
                vuln_key = "{0}_{1}_{2}_{3}".format(
                    _safe_nested_get(vuln, 'asset', 'uuid', default='unknown'),
                    _safe_nested_get(vuln, 'plugin', 'id', default='unknown'),
                    _safe_nested_get(vuln, 'port', 'port', default='0'),
                    _safe_nested_get(vuln, 'port', 'protocol', default='tcp')
                )

                if self.is_processed(vuln_key):
                    continue

                if self.send_event(vuln, item_id=vuln_key):
                    event_count += 1
                    self.log_progress(event_count)

                if self.should_stop(event_count):
                    break

            self.flush_events()
            self.log_completion(event_count)
        except Exception as e:
            self.logger.error(
                "Error processing vulnerability feed: {0}".format(
                    str(e)))

        return event_count


class VulnerabilityNoInfoProcessor(BaseFeedProcessor):

    def __init__(self, tenable_client, checkpoint_mgr,
                 hec_handler, batch_size=5000, max_events=0):
        super(
            VulnerabilityNoInfoProcessor,
            self).__init__(
            tenable_client,
            checkpoint_mgr,
            hec_handler,
            "Informational Vulnerabilities",
            "tenableio_vulnerability_no_info",
            "tenable:io:vulnerability:info",
            "vulnerability_info",
            batch_size,
            max_events)

    def process(self):
        self.log_start()
        event_count = 0

        try:
            self.logger.info(
                "Initiating informational vulnerability export (severity: info)...")
            for vuln in _safe_export_with_retry(
                lambda: self.tenable.exports.vulns(severity=['info']),
                "Informational Vulnerabilities"
            ):
                # Use safe helpers for pytenable 1.9.0+ Box object compatibility
                vuln_key = "{0}_{1}_{2}_{3}".format(
                    _safe_nested_get(vuln, 'asset', 'uuid', default='unknown'),
                    _safe_nested_get(vuln, 'plugin', 'id', default='unknown'),
                    _safe_nested_get(vuln, 'port', 'port', default='0'),
                    _safe_nested_get(vuln, 'port', 'protocol', default='tcp')
                )

                if self.is_processed(vuln_key):
                    continue

                if self.send_event(vuln, item_id=vuln_key):
                    event_count += 1
                    self.log_progress(event_count)

                if self.should_stop(event_count):
                    break

            self.flush_events()
            self.log_completion(event_count)
        except Exception as e:
            self.logger.error(
                "Error processing informational vulnerability feed: {0}".format(
                    str(e)))

        return event_count


class VulnerabilitySelfScanProcessor(BaseFeedProcessor):

    def __init__(self, tenable_client, checkpoint_mgr,
                 hec_handler, batch_size=5000, max_events=0):
        super(
            VulnerabilitySelfScanProcessor,
            self).__init__(
            tenable_client,
            checkpoint_mgr,
            hec_handler,
            "Agent-Based Vulnerabilities",
            "tenableio_vulnerability_self_scan",
            "tenable:io:vulnerability:self_scan",
            "vulnerability_self_scan",
            batch_size,
            max_events)

    def process(self):
        self.log_start()
        event_count = 0

        try:
            self.logger.info("Initiating agent-based vulnerability export...")
            # Use state=['OPEN'] to differentiate this export from others
            # pytenable 1.9.0+ requires state to be a list, not a string
            # Note: We still filter by has_agent locally since API doesn't
            # support that filter
            for vuln in _safe_export_with_retry(
                lambda: self.tenable.exports.vulns(state=['OPEN']),
                "Agent-Based Vulnerabilities"
            ):
                # Use safe helpers for pytenable 1.9.0+ Box object compatibility
                asset_info = _safe_get(vuln, 'asset', {})
                if not _safe_get(asset_info, 'has_agent', False):
                    continue

                vuln_key = "{0}_{1}_{2}_{3}".format(
                    _safe_get(asset_info, 'uuid', 'unknown'),
                    _safe_nested_get(vuln, 'plugin', 'id', default='unknown'),
                    _safe_nested_get(vuln, 'port', 'port', default='0'),
                    _safe_nested_get(vuln, 'port', 'protocol', default='tcp')
                )

                if self.is_processed(vuln_key):
                    continue

                if self.send_event(vuln, item_id=vuln_key):
                    event_count += 1
                    self.log_progress(event_count)

                if self.should_stop(event_count):
                    break

            self.flush_events()
            self.log_completion(event_count)
        except Exception as e:
            self.logger.error(
                "Error processing agent-based vulnerability feed: {0}".format(str(e)))

        return event_count


class FixedVulnerabilityProcessor(BaseFeedProcessor):

    def __init__(self, tenable_client, checkpoint_mgr,
                 hec_handler, batch_size=5000, max_events=0):
        super(
            FixedVulnerabilityProcessor,
            self).__init__(
            tenable_client,
            checkpoint_mgr,
            hec_handler,
            "Fixed Vulnerabilities",
            "tenableio_fixed_vulnerability",
            "tenable:io:vulnerability:fixed",
            "fixed_vulnerability",
            batch_size,
            max_events)

    def process(self):
        self.log_start()
        event_count = 0

        try:
            previous_vulns = self.get_processed_ids()
            self.logger.info(
                "Found {0} vulnerabilities in previous checkpoint".format(
                    len(previous_vulns)))

            current_vulns = set()
            self.logger.info(
                "Fetching current vulnerabilities from Tenable...")
            self.logger.info(
                "(This may take several minutes for large environments)")

            # Use state=['FIXED'] to get fixed vulnerabilities directly
            # pytenable 1.9.0 removed num_findings parameter
            for vuln in _safe_export_with_retry(
                lambda: self.tenable.exports.vulns(state=['FIXED']),
                "Fixed Vulnerabilities"
            ):
                # Use safe helpers for pytenable 1.9.0+ Box object compatibility
                vuln_key = "{0}_{1}_{2}_{3}".format(
                    _safe_nested_get(vuln, 'asset', 'uuid', default='unknown'),
                    _safe_nested_get(vuln, 'plugin', 'id', default='unknown'),
                    _safe_nested_get(vuln, 'port', 'port', default='0'),
                    _safe_nested_get(vuln, 'port', 'protocol', default='tcp')
                )
                current_vulns.add(vuln_key)

            self.logger.info(
                "Found {0} current vulnerabilities".format(
                    len(current_vulns)))
            fixed_vulns = previous_vulns - current_vulns

            if fixed_vulns:
                self.logger.info(
                    "Detected {0} fixed vulnerabilities".format(
                        len(fixed_vulns)))
                for vuln_key in fixed_vulns:
                    parts = vuln_key.split('_')
                    fix_event = {
                        'vulnerability_key': vuln_key,
                        'asset_uuid': parts[0] if len(parts) > 0 else 'unknown',
                        'plugin_id': parts[1] if len(parts) > 1 else 'unknown',
                        'port': parts[2] if len(parts) > 2 else '0',
                        'protocol': parts[3] if len(parts) > 3 else 'tcp',
                        'event_type': 'vulnerability_fixed',
                        'detected_at': int(
                            time.time())}
                    if self.send_event(fix_event):
                        event_count += 1
                        self.log_progress(event_count)

                    if self.should_stop(event_count):
                        break
            else:
                self.logger.info("No fixed vulnerabilities detected")

            for vuln_key in current_vulns:
                self.mark_processed(vuln_key)

            self.flush_events()
            self.log_completion(event_count)
        except Exception as e:
            self.logger.error(
                "Error processing fixed vulnerability feed: {0}".format(
                    str(e)))

        return event_count
