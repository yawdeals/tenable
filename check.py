#!/usr/bin/env python3
# File-based checkpoint manager for deduplication and state tracking
import os
import json
import logging
import time
import tempfile
import shutil
import threading
from typing import Optional, Set, Dict


class FileCheckpoint:
    # Manages checkpoints with in-memory caching and periodic disk writes
    # Thread-safe for concurrent feed processing

    def __init__(self, checkpoint_dir="checkpoints", key_prefix="tenable",
                 max_ids=100000, retention_days=30, flush_interval=100):
        # Initialize checkpoint manager with configuration
        self.checkpoint_dir = checkpoint_dir
        self.key_prefix = key_prefix
        self.max_ids = max_ids  # Max IDs to track per feed
        self.retention_seconds = retention_days * 86400  # Convert days to seconds
        self.flush_interval = flush_interval  # Auto-flush after N IDs

        # Thread lock for safe concurrent access
        self._lock = threading.Lock()

        # In-memory cache for performance (reduces disk I/O)
        self._cache: Dict[str, Dict] = {}  # Cached checkpoint data
        # Keys that need to be written to disk
        self._dirty_keys: Set[str] = set()
        # Count of pending writes per key
        self._pending_count: Dict[str, int] = {}

        # Global timestamp counter to ensure monotonic timestamps across
        # batches
        self._last_timestamp: float = 0.0

        # Create checkpoint directory if it doesn't exist
        if not os.path.exists(self.checkpoint_dir):
            os.makedirs(self.checkpoint_dir)
            logging.info(
                "Created checkpoint directory: {}".format(
                    self.checkpoint_dir))

    def _get_checkpoint_file(self, key):
        filename = "{}_{}.json".format(self.key_prefix, key)
        return os.path.join(self.checkpoint_dir, filename)

    def _load_checkpoint(self, key):
        # Load checkpoint from disk into memory cache (lazy loading)
        # Note: caller must hold self._lock
        if key in self._cache:
            return  # Already loaded

        filepath = self._get_checkpoint_file(key)
        # Default empty checkpoint structure
        data = {
            'id_tracking': {},  # ID -> timestamp mapping
            'last_timestamp': None,  # Last processed timestamp
            'last_cleanup': None,  # Last cleanup time
            'total_tracked': 0  # Total IDs tracked
        }

        try:
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    loaded_data = json.load(f)
                    data.update(loaded_data)

                    # Migrate old format if needed (backward compatibility)
                    if 'processed_ids' in loaded_data and 'id_tracking' not in loaded_data:
                        current_time = int(time.time())
                        data['id_tracking'] = {
                            str(pid): current_time
                            for pid in loaded_data.get('processed_ids', [])
                        }
        except Exception as e:
            logging.error(
                "Error loading checkpoint {}: {}".format(
                    filepath, e))

        # Store in cache
        self._cache[key] = data
        self._pending_count[key] = 0

    def _atomic_write(self, filepath, data):
        # Write to temp file first
        dir_name = os.path.dirname(filepath)
        fd, temp_path = tempfile.mkstemp(dir=dir_name, suffix='.tmp')

        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(data, f, indent=2)

            # Atomic rename (on POSIX systems)
            shutil.move(temp_path, filepath)
        except Exception as e:
            # Clean up temp file on error
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise e

    def flush(self, key=None):
        # Write cached checkpoint data to disk
        with self._lock:
            keys_to_flush = [key] if key else list(self._dirty_keys)

            for k in keys_to_flush:
                if k not in self._cache:
                    continue

                filepath = self._get_checkpoint_file(k)
                data = self._cache[k]

                try:
                    # Apply retention and size limits before write
                    current_time = int(time.time())
                    cutoff_time = current_time - self.retention_seconds
                    id_tracking = data.get('id_tracking', {})

                    # Remove expired IDs (older than retention period)
                    id_tracking = {
                        id_key: ts for id_key, ts in id_tracking.items()
                        if ts > cutoff_time
                    }

                    # Enforce max size limit (keep most recent IDs)
                    if len(id_tracking) > self.max_ids:
                        sorted_ids = sorted(
                            id_tracking.items(), key=lambda x: x[1], reverse=True)
                        id_tracking = dict(sorted_ids[:self.max_ids])
                        logging.warning(
                            "Checkpoint {} trimmed to {} IDs".format(
                                k, self.max_ids))

                    # Update cache and prepare for write
                    data['id_tracking'] = id_tracking
                    data['processed_ids'] = list(id_tracking.keys())
                    data['last_cleanup'] = current_time
                    data['total_tracked'] = len(id_tracking)

                    # Write to disk atomically (prevents corruption)
                    self._atomic_write(filepath, data)
                    self._dirty_keys.discard(k)
                    self._pending_count[k] = 0

                    logging.debug(
                        "Flushed checkpoint {}: {} IDs".format(
                            k, len(id_tracking)))
                except Exception as e:
                    logging.error("Error flushing checkpoint {}: {}".format(k, e))

    def flush_all(self):
        self.flush()

    def get_last_timestamp(self, key):
        with self._lock:
            self._load_checkpoint(key)
            # Return 0 if no timestamp exists to allow numeric comparisons
            return self._cache[key].get('last_timestamp', 0)

    def set_last_timestamp(self, key, timestamp):
        with self._lock:
            self._load_checkpoint(key)
            self._cache[key]['last_timestamp'] = timestamp
            self._dirty_keys.add(key)
        # Timestamps are important - flush immediately
        self.flush(key)

    def get_processed_ids(self, key):
        with self._lock:
            self._load_checkpoint(key)

            current_time = int(time.time())
            cutoff_time = current_time - self.retention_seconds
            id_tracking = self._cache[key].get('id_tracking', {})

            # Return only non-expired IDs
            return {
                id_key for id_key, ts in id_tracking.items()
                if ts > cutoff_time
            }

    def add_processed_id(self, key, item_id):
        with self._lock:
            self._load_checkpoint(key)

            # Add to in-memory cache
            current_time = int(time.time())
            self._cache[key].setdefault('id_tracking', {})[
                str(item_id)] = current_time
            self._dirty_keys.add(key)
            self._pending_count[key] = self._pending_count.get(key, 0) + 1

            # Check if auto-flush needed
            should_flush = self._pending_count[key] >= self.flush_interval

        # Auto-flush after flush_interval IDs (outside lock)
        if should_flush:
            self.flush(key)

    def add_processed_ids_batch(self, key, item_ids):
        if not item_ids:
            return

        with self._lock:
            self._load_checkpoint(key)

            current_time = time.time()
            id_tracking = self._cache[key].setdefault('id_tracking', {})

            # Ensure timestamps are monotonically increasing across all batches
            # This prevents the same timestamp range from being reused in
            # subsequent batches
            if current_time <= self._last_timestamp:
                current_time = self._last_timestamp + 0.000001

            # Use incrementing microsecond timestamps to preserve order
            # This ensures trimming keeps the most recently added IDs
            for i, item_id in enumerate(item_ids):
                # Add microseconds to ensure uniqueness and preserve order
                timestamp = current_time + (i / 1000000.0)
                id_tracking[str(item_id)] = timestamp
                self._last_timestamp = timestamp  # Track globally across all batches

            self._dirty_keys.add(key)
            self._pending_count[key] = self._pending_count.get(
                key, 0) + len(item_ids)

        # Always flush after batch add (outside lock)
        self.flush(key)

    def is_processed(self, key, item_id):
        with self._lock:
            self._load_checkpoint(key)

            id_tracking = self._cache[key].get('id_tracking', {})
            str_id = str(item_id)

            if str_id not in id_tracking:
                return False

            # Check if expired
            current_time = int(time.time())
            cutoff_time = current_time - self.retention_seconds
            return id_tracking[str_id] > cutoff_time

    def clear_checkpoint(self, key):
        filepath = self._get_checkpoint_file(key)

        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                logging.info("Cleared checkpoint: {}".format(key))
        except Exception as e:
            logging.error(
                "Error clearing checkpoint {}: {}".format(
                    filepath, e))

    def get_all_checkpoints(self):
        checkpoints = []

        try:
            for filename in os.listdir(self.checkpoint_dir):
                if filename.startswith(
                        self.key_prefix) and filename.endswith('.json'):
                    # Extract key from filename
                    key = filename.replace(
                        self.key_prefix + '_',
                        '').replace(
                        '.json',
                        '')
                    checkpoints.append(key)
        except Exception as e:
            logging.error("Error listing checkpoints: {}".format(e))

        return checkpoints

    def get_checkpoint_stats(self, key):
        self._load_checkpoint(key)
        filepath = self._get_checkpoint_file(key)

        stats = {
            'exists': False,
            'file_size_bytes': 0,
            'total_ids': 0,
            'cached_ids': 0,
            'pending_writes': 0,
            'last_cleanup': None,
            'last_timestamp': None
        }

        try:
            if os.path.exists(filepath):
                stats['exists'] = True
                stats['file_size_bytes'] = os.path.getsize(filepath)

            data = self._cache.get(key, {})
            stats['total_ids'] = len(data.get('id_tracking', {}))
            stats['cached_ids'] = stats['total_ids']
            stats['pending_writes'] = self._pending_count.get(key, 0)
            stats['last_cleanup'] = data.get('last_cleanup')
            stats['last_timestamp'] = data.get('last_timestamp')
        except Exception as e:
            logging.error(
                "Error getting checkpoint stats for {}: {}".format(
                    key, e))

        return stats

    def cleanup_all_checkpoints(self):
        for key in self.get_all_checkpoints():
            try:
                self._load_checkpoint(key)
                self._dirty_keys.add(key)
                self.flush(key)
                processed_ids = self.get_processed_ids(key)
                logging.info(
                    "Cleaned checkpoint {}: {} active IDs".format(
                        key, len(processed_ids)))
            except Exception as e:
                logging.error(
                    "Error cleaning checkpoint {}: {}".format(
                        key, e))

    def __del__(self):
        try:
            self.flush_all()
        except Exception:
            pass  # Ignore errors during cleanup
