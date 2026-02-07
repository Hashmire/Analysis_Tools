#!/usr/bin/env python3
"""
CPE Cache Management System (Sharded Implementation)

Hash-based sharded cache with lazy loading and run-boundary eviction for improved
memory management and scalability. Addresses monolithic cache file issues.

Key Features:
- MD5 hash-based shard distribution (16 shards)
- Lazy loading - only load shards containing requested CPE strings
- Run-boundary eviction - clear memory between dataset processing runs
- Auto-save every N entries for data safety
- Global singleton pattern for cross-run performance
"""

import hashlib
import time
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import orjson
from ..logging.workflow_logger import get_logger

# Get logger instance
logger = get_logger()

class ShardedCPECache:
    """
    Hash-based sharded CPE cache with lazy loading and memory eviction.
    
    Provides memory-efficient caching for NVD CPE API responses through
    shard-based storage architecture.
    """
    
    def __init__(self, config: Dict[str, Any], num_shards: int = 16):
        """
        Initialize sharded cache.
        
        Args:
            config: Cache configuration dict from config.json
            num_shards: Number of shards to distribute cache across (default: 16)
        """
        self.config = config
        self.disabled = config.get('disabled', False)
        self.num_shards = num_shards
        
        # Use project root cache directory
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent.parent 
        self.cache_dir = project_root / "cache" / "cpe_base_strings"
        self.metadata_file = project_root / "cache" / 'cache_metadata.json'
        
        # Loaded shards {shard_index: cache_data_dict}
        self.loaded_shards = {}
        
        # Track unsaved changes per shard {shard_index: count}
        self.unsaved_changes = {}
        
        # Session statistics
        self.session_stats = {
            'hits': 0,
            'misses': 0,
            'expired': 0,
            'new_entries': 0,
            'api_calls_saved': 0,
            'auto_saves': 0
        }
        
        # Auto-save configuration
        self.auto_save_threshold = config.get('auto_save_threshold', 50)
        
        # Metadata for compatibility
        self.cpe_metadata = {
            'created': datetime.now(timezone.utc).isoformat(),
            'description': 'NVD CPE API responses with per-entry expiration (sharded)',
            'sharding_enabled': True,
            'num_shards': num_shards,
            'last_updated': datetime.now(timezone.utc).isoformat(),
            'total_entries': 0
        }
        
        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing metadata
        if not self.disabled:
            self._load_metadata()
        else:
            logger.info("CPE cache disabled - skipping cache initialization", group="cpe_queries")
    
    def _get_shard_index(self, cpe_string: str) -> int:
        """
        Determine shard index for a CPE string using MD5 hash.
        
        Args:
            cpe_string: CPE match string
            
        Returns:
            Shard index (0 to num_shards-1)
        """
        hash_digest = hashlib.md5(cpe_string.encode('utf-8')).hexdigest()
        return int(hash_digest[:8], 16) % self.num_shards
    
    def _get_shard_filename(self, shard_index: int) -> str:
        """Get filename for specific shard."""
        return f"cpe_cache_shard_{shard_index:02d}.json"
    
    @staticmethod
    def load_shard_from_disk(shard_path: Path) -> Dict[str, Any]:
        """Load a shard file from disk.
        
        Prevention logic in put() ensures data is validated before caching,
        so corruption should not occur. If a shard is corrupted, fail loudly
        to surface the real issue rather than masking it.
        
        Args:
            shard_path: Path to shard file
            
        Returns:
            Dict of cache entries, or empty dict if file doesn't exist
            
        Raises:
            Exception: If shard file is corrupted (indicates unexpected issue)
        """
        if not shard_path.exists():
            return {}
        
        try:
            with open(shard_path, 'rb') as f:
                return orjson.loads(f.read())
        except Exception as e:
            # Fail fast - corruption should not happen due to prevention logic
            error_type = type(e).__name__
            error_msg = str(e)[:200]
            
            logger.error(
                f"CPE cache shard corrupted: {shard_path.name}",
                group="cpe_queries"
            )
            logger.error(
                f"  Error: {error_type} - {error_msg}",
                group="cpe_queries"
            )
            logger.error(
                f"  This should not happen due to put() validation.",
                group="cpe_queries"
            )
            logger.error(
                f"  Manual action: Delete corrupted file to rebuild: {shard_path}",
                group="cpe_queries"
            )
            raise
    
    @staticmethod
    def save_shard_to_disk(shard_path: Path, shard_data: Dict[str, Any]) -> None:
        """Save a shard file to disk using atomic write with compact JSON.
        
        Uses atomic write pattern (temp file + rename) to prevent corruption from
        partial writes. Prevention logic in put() validates all data before caching,
        so serialization should never fail.
        
        Args:
            shard_path: Path to shard file
            shard_data: Dict of cache entries to save
            
        Note:
            Logs warning on failure but does not raise - allows cache to continue
            building in memory and retry save on next attempt.
        """
        try:
            # Ensure parent directory exists
            shard_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Serialize - put() validation ensures this will succeed
            json_bytes = orjson.dumps(shard_data)
            
            # Atomic write: temp file in same directory + rename
            # Using same directory ensures atomic rename on same filesystem
            temp_fd, temp_path = tempfile.mkstemp(
                dir=shard_path.parent,
                prefix=f".tmp_{shard_path.name}_",
                suffix=".json"
            )
            
            try:
                # Write to temp file
                with open(temp_fd, 'wb') as f:
                    f.write(json_bytes)
                    f.flush()  # Ensure data written to OS buffer
                    # os.fsync(temp_fd) could be added here for extra safety
                
                # Atomic rename (replaces existing file if present)
                temp_path_obj = Path(temp_path)
                temp_path_obj.replace(shard_path)
                
            except Exception as write_error:
                # Cleanup temp file on failure
                try:
                    Path(temp_path).unlink(missing_ok=True)
                except:
                    pass
                raise write_error
                
        except Exception as e:
            logger.warning(
                f"Failed to save shard {shard_path.name}: {e} - will retry on next save",
                group="cpe_queries"
            )
    
    def _load_shard(self, shard_index: int) -> Dict[str, Any]:
        """Lazy load a single shard into memory with proactive eviction."""
        if shard_index in self.loaded_shards:
            return self.loaded_shards[shard_index]
        
        # PROACTIVE EVICTION: Enforce memory limit BEFORE loading new shard
        max_loaded_shards = self.config.get('max_loaded_shards', 4)
        if len(self.loaded_shards) >= max_loaded_shards:
            # Need to make room - save and evict oldest shard
            oldest_shard_idx = list(self.loaded_shards.keys())[0]
            
            # Save if it has changes
            if oldest_shard_idx in self.unsaved_changes and self.unsaved_changes[oldest_shard_idx] > 0:
                self._save_shard(oldest_shard_idx)
                self.unsaved_changes[oldest_shard_idx] = 0
            
            # Evict from memory
            del self.loaded_shards[oldest_shard_idx]
            logger.debug(
                f"Proactive eviction: Shard {oldest_shard_idx} saved and evicted to load shard {shard_index}",
                group="cpe_queries"
            )
        
        shard_path = self.cache_dir / self._get_shard_filename(shard_index)
        
        start_time = time.time()
        self.loaded_shards[shard_index] = self.load_shard_from_disk(shard_path)
        
        if self.loaded_shards[shard_index]:
            load_time = time.time() - start_time
            logger.debug(
                f"Loaded shard {shard_index}: {len(self.loaded_shards[shard_index])} entries in {load_time:.3f}s",
                group="cpe_queries"
            )
        else:
            logger.debug(f"Shard {shard_index} does not exist - created empty shard", group="cpe_queries")
        
        return self.loaded_shards[shard_index]
    
    def _save_shard(self, shard_index: int) -> None:
        """Save a single shard to disk using compact JSON."""
        if shard_index not in self.loaded_shards:
            return
        
        shard_path = self.cache_dir / self._get_shard_filename(shard_index)
        shard_data = self.loaded_shards[shard_index]
        
        start_time = time.time()
        self.save_shard_to_disk(shard_path, shard_data)
        save_time = time.time() - start_time
        logger.debug(
            f"Saved shard {shard_index}: {len(shard_data)} entries in {save_time:.3f}s",
            group="cpe_queries"
        )
    
    def _load_metadata(self) -> None:
        """Load cache metadata from unified metadata file."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'rb') as f:
                    stored_metadata = orjson.loads(f.read())
                    if 'datasets' in stored_metadata and 'cpe_cache' in stored_metadata['datasets']:
                        cpe_data = stored_metadata['datasets']['cpe_cache']
                        self.cpe_metadata.update(cpe_data)
                        logger.debug("Loaded CPE cache metadata", group="cpe_queries")
            except Exception as e:
                logger.warning(f"Failed to load cache metadata: {e}", group="cpe_queries")
    
    def _save_metadata(self) -> None:
        """Save cache metadata to unified metadata file."""
        try:
            # Update total entries count from loaded shards
            total_entries = sum(len(shard) for shard in self.loaded_shards.values())
            
            # Scan all shard files to get accurate total
            total_entries_on_disk = 0
            shard_details = {}
            for shard_index in range(self.num_shards):
                shard_path = self.cache_dir / self._get_shard_filename(shard_index)
                if shard_path.exists():
                    try:
                        with open(shard_path, 'rb') as f:
                            shard_data = orjson.loads(f.read())
                        entry_count = len(shard_data)
                        total_entries_on_disk += entry_count
                        
                        # Get file modification time for last_updated
                        file_stat = shard_path.stat()
                        file_mtime = datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc)
                        
                        shard_details[f"shard_{shard_index:02d}"] = {
                            'filename': shard_path.name,
                            'entry_count': entry_count,
                            'file_size_mb': round(file_stat.st_size / (1024 * 1024), 2),
                            'last_updated': file_mtime.isoformat()
                        }
                    except Exception:
                        pass
            
            self.cpe_metadata['total_entries'] = total_entries_on_disk
            self.cpe_metadata['directory_path'] = 'cache/cpe_base_strings'
            self.cpe_metadata['shards'] = shard_details
            
            # Remove cache-level last_updated (now tracked per-shard)
            self.cpe_metadata.pop('last_updated', None)
            
            # Load existing metadata or create new
            unified_metadata = {}
            if self.metadata_file.exists():
                try:
                    with open(self.metadata_file, 'rb') as f:
                        unified_metadata = orjson.loads(f.read())
                except Exception as e:
                    # Metadata file exists but can't be loaded - log but continue with empty dict
                    # This is non-critical (only affects statistics, not actual cache data)
                    logger.warning(f"Metadata file exists but failed to load: {e} - using empty metadata", group="cpe_queries")
            
            # Update CPE cache section
            if 'datasets' not in unified_metadata:
                unified_metadata['datasets'] = {}
            unified_metadata['datasets']['cpe_cache'] = self.cpe_metadata
            unified_metadata['last_updated'] = datetime.now(timezone.utc).isoformat()
            
            # Save updated metadata
            with open(self.metadata_file, 'wb') as f:
                f.write(orjson.dumps(unified_metadata, option=orjson.OPT_INDENT_2))
            
            logger.debug("Saved CPE cache metadata", group="cpe_queries")
        except Exception as e:
            logger.error(f"Failed to save cache metadata: {e}", group="cpe_queries")
    
    @staticmethod
    def parse_cache_entry_timestamp(entry: Dict[str, Any]) -> datetime:
        """Parse timestamp from cache entry (static utility for external use).
        
        Args:
            entry: Cache entry dict with 'last_queried' field
            
        Returns:
            Timezone-aware datetime object
        """
        timestamp_str = entry.get('last_queried')
        parsed_timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        
        # Ensure timezone-aware
        if parsed_timestamp.tzinfo is None:
            parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)
        
        return parsed_timestamp
    
    def _get_entry_timestamp(self, entry: Dict[str, Any]) -> datetime:
        """Get timestamp from cache entry (delegates to static method)."""
        return self.parse_cache_entry_timestamp(entry)
    
    def _is_expired(self, entry: Dict[str, Any]) -> bool:
        """Check if a cache entry has expired."""
        refresh_strategy = self.config.get('refresh_strategy', {})
        max_age_hours = refresh_strategy.get('notify_age_hours', 12)
        if max_age_hours <= 0:
            return False  # Never expire
        
        last_queried = self._get_entry_timestamp(entry)
        expiry_date = last_queried + timedelta(hours=max_age_hours)
        return datetime.now(timezone.utc) > expiry_date
    
    def get(self, cpe_string: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """
        Retrieve cached CPE data for a given CPE string.
        
        Automatically loads the appropriate shard if not already loaded.
        
        Args:
            cpe_string: The CPE match string to look up
            
        Returns:
            Tuple of (Cached API response data or None, status)
            Status can be: 'hit', 'miss', 'expired', 'disabled'
        """
        if self.disabled or not self.config.get('enabled', True):
            return None, 'disabled'
        
        # Determine which shard contains this CPE
        shard_index = self._get_shard_index(cpe_string)
        shard_data = self._load_shard(shard_index)
        
        # Check if entry exists
        if cpe_string not in shard_data:
            self.session_stats['misses'] += 1
            
            # Record cache miss for dashboard tracking
            try:
                from ..reporting.dataset_contents_collector import record_cache_activity
                record_cache_activity('miss', cache_size=self._get_total_entries())
            except ImportError:
                pass
            
            return None, 'miss'
        
        entry = shard_data[cpe_string]
        
        # Check if entry is expired
        if self._is_expired(entry):
            del shard_data[cpe_string]
            self.session_stats['expired'] += 1
            
            # Mark shard as having unsaved changes (deletion)
            self.unsaved_changes[shard_index] = self.unsaved_changes.get(shard_index, 0) + 1
            
            # Record cache expiration for dashboard tracking
            try:
                from ..reporting.dataset_contents_collector import record_cache_activity
                record_cache_activity('expired', cache_size=self._get_total_entries())
            except ImportError:
                pass
            
            return None, 'expired'
        
        # Cache hit
        self.session_stats['hits'] += 1
        self.session_stats['api_calls_saved'] += 1
        
        # Record cache hit for dashboard tracking
        try:
            from ..reporting.dataset_contents_collector import record_cache_activity
            record_cache_activity('hit', cache_size=self._get_total_entries(), api_calls_saved=1)
        except ImportError:
            pass
        
        # Log cache hit
        result_count = entry['query_response'].get('totalResults', 0)
        logger.debug(
            f"Cache hit for CPE: {cpe_string} - NVD CPE API call avoided ({result_count} results)",
            group="cpe_queries"
        )
        
        return entry['query_response'], 'hit'
    
    def put(self, cpe_string: str, api_response: Dict[str, Any]) -> None:
        """
        Store CPE API response in cache with data validation.
        
        Validates that response data can be serialized before caching to prevent
        corruption. Rejects responses containing invalid UTF-8 surrogates or
        other non-serializable data from NVD API.
        
        Args:
            cpe_string: The CPE match string used as key
            api_response: The full API response to cache
        """
        if self.disabled or not self.config.get('enabled', True):
            return
                # VALIDATION: Ensure data is serializable before caching to prevent corruption
        # Test serialization with strict UTF-8 enforcement
        try:
            test_serialization = orjson.dumps(api_response)
            # Successfully serialized - data is clean
        except (orjson.JSONEncodeError, TypeError, ValueError) as e:
            # Data contains invalid UTF-8 surrogates or non-serializable types
            error_type = type(e).__name__
            error_msg = str(e)[:200]  # Capture more context
            
            logger.warning(
                f"CPE cache rejection - corrupt NVD API response detected:",
                group="cpe_queries"
            )
            logger.warning(
                f"  CPE: {cpe_string}",
                group="cpe_queries"
            )
            logger.warning(
                f"  Error: {error_type} - {error_msg}",
                group="cpe_queries"
            )
            logger.info(
                f"Data not cached - future queries for this CPE will retry the API call",
                group="cpe_queries"
            )
            
            # Track rejection statistics
            if not hasattr(self, '_rejection_stats'):
                self._rejection_stats = {'count': 0, 'cpes': []}
            self._rejection_stats['count'] += 1
            self._rejection_stats['cpes'].append(cpe_string)
            
            # Do not cache - let future queries retry the API call instead
            return
                # Determine which shard should contain this CPE
        shard_index = self._get_shard_index(cpe_string)
        shard_data = self._load_shard(shard_index)
        
        # Create cache entry
        entry = {
            'query_response': api_response,
            'last_queried': datetime.now(timezone.utc).isoformat(),
            'query_count': 1,
            'total_results': api_response.get('totalResults', 0)
        }
        
        # Update existing entry or create new one
        is_new = cpe_string not in shard_data
        if is_new:
            self.session_stats['new_entries'] += 1
        else:
            existing = shard_data[cpe_string]
            entry['query_count'] = existing.get('query_count', 0) + 1
        
        shard_data[cpe_string] = entry
        
        # Track unsaved changes for this shard
        if is_new:
            self.unsaved_changes[shard_index] = self.unsaved_changes.get(shard_index, 0) + 1
        
        # Check if auto-save threshold reached (across all shards)
        total_unsaved = sum(self.unsaved_changes.values())
        if self.auto_save_threshold > 0 and total_unsaved >= self.auto_save_threshold:
            self._auto_save()
    
    def _auto_save(self) -> None:
        """Perform automatic incremental save with memory-spike prevention."""
        self.session_stats['auto_saves'] += 1
        total_unsaved = sum(self.unsaved_changes.values())
        logger.debug(f"CPE cache auto-save triggered ({total_unsaved} new entries)", group="cpe_queries")
        
        # INCREMENTAL SAVE-AND-EVICT: Process one shard at a time to prevent memory spikes
        max_loaded_shards = self.config.get('max_loaded_shards', 4)
        shards_to_process = list(self.loaded_shards.keys())
        shards_saved = 0
        shards_evicted = 0
        
        for shard_idx in shards_to_process:
            # Save if has changes
            if shard_idx in self.unsaved_changes and self.unsaved_changes[shard_idx] > 0:
                self._save_shard(shard_idx)  # Saves, then releases serialized data immediately
                self.unsaved_changes[shard_idx] = 0
                shards_saved += 1
            
            # Evict if we're over limit (keep newest shards)
            if len(self.loaded_shards) > max_loaded_shards:
                # Evict this shard after saving (process from oldest to newest)
                if shard_idx in self.loaded_shards:
                    del self.loaded_shards[shard_idx]
                    shards_evicted += 1
        
        self.unsaved_changes.clear()
        
        if shards_evicted > 0:
            logger.debug(
                f"Auto-save: Saved {shards_saved} shards, evicted {shards_evicted} shards ({len(self.loaded_shards)} retained)",
                group="cpe_queries"
            )
        else:
            logger.debug(
                f"Auto-save: Saved {shards_saved} shards, no eviction needed",
                group="cpe_queries"
            )
    
    def _get_total_entries(self) -> int:
        """Get total number of entries across all loaded shards."""
        return sum(len(shard) for shard in self.loaded_shards.values())
    
    def save_all_shards(self) -> None:
        """Save all loaded shards to disk using compact JSON."""
        if self.disabled or not self.config.get('enabled', True):
            logger.debug("Cache disabled - skipping save operation", group="cpe_queries")
            return
        
        start_time = time.time()
        shards_saved = 0
        
        # Only save shards that have unsaved changes (memory efficient)
        for shard_index in list(self.loaded_shards.keys()):
            # Skip shards with no changes unless forced
            if shard_index not in self.unsaved_changes or self.unsaved_changes[shard_index] == 0:
                continue
            self._save_shard(shard_index)
            shards_saved += 1
        
        # Save metadata
        self._save_metadata()
        
        save_time = time.time() - start_time
        total_entries = self._get_total_entries()
        logger.debug(
            f"CPE Base String Cache saved: {total_entries} entries across {shards_saved} shards in {save_time:.2f}s",
            group="cpe_queries"
        )
        
        # Update dashboard collector with cache statistics
        try:
            from ..reporting.dataset_contents_collector import update_cache_file_size
            # Report total size across all shard files
            total_size = sum(
                (self.cache_dir / self._get_shard_filename(i)).stat().st_size 
                for i in range(self.num_shards)
                if (self.cache_dir / self._get_shard_filename(i)).exists()
            )
            update_cache_file_size(str(self.cache_dir / "cpe_cache_shard_*.json"))
        except (ImportError, Exception):
            pass
    
    def save_changed_shards_only(self) -> None:
        """Save only shards with unsaved changes (memory-efficient operation)."""
        if self.disabled or not self.config.get('enabled', True):
            return
        
        if not self.unsaved_changes:
            logger.debug("No unsaved changes - skipping save", group="cpe_queries")
            return
        
        start_time = time.time()
        for shard_index in list(self.unsaved_changes.keys()):
            if shard_index in self.loaded_shards:
                self._save_shard(shard_index)
        
        save_time = time.time() - start_time
        logger.debug(
            f"Saved {len(self.unsaved_changes)} changed shards in {save_time:.2f}s",
            group="cpe_queries"
        )
        self.unsaved_changes.clear()
    
    def save_changed_shards_only(self) -> None:
        """Save only shards with unsaved changes (memory-efficient operation)."""
        if self.disabled or not self.config.get('enabled', True):
            return
        
        if not self.unsaved_changes:
            logger.debug("No unsaved changes - skipping save", group="cpe_queries")
            return
        
        start_time = time.time()
        for shard_index in list(self.unsaved_changes.keys()):
            if shard_index in self.loaded_shards:
                self._save_shard(shard_index)
        
        save_time = time.time() - start_time
        logger.debug(
            f"Saved {len(self.unsaved_changes)} changed shards in {save_time:.2f}s",
            group="cpe_queries"
        )
        self.unsaved_changes.clear()
    
    def evict_all_shards(self) -> None:
        """
        Clear all shards from memory (run-boundary eviction).
        
        Singleton instance stays alive but loaded shard data is freed.
        Should be called after save_all_shards() at dataset run completion.
        """
        shards_evicted = len(self.loaded_shards)
        self.loaded_shards.clear()
        self.unsaved_changes.clear()
        logger.info(
            f"CPE cache shards evicted: {shards_evicted} shards cleared from memory",
            group="cpe_queries"
        )
    
    def cleanup_expired(self) -> None:
        """Remove expired entries from all loaded shards."""
        total_expired = 0
        
        for shard_index, shard_data in self.loaded_shards.items():
            expired_keys = []
            for key, entry in shard_data.items():
                if self._is_expired(entry):
                    expired_keys.append(key)
            
            for key in expired_keys:
                del shard_data[key]
            
            if expired_keys:
                total_expired += len(expired_keys)
                self.unsaved_changes[shard_index] = self.unsaved_changes.get(shard_index, 0) + len(expired_keys)
        
        if total_expired > 0:
            logger.info(
                f"Cache cleanup: removed {total_expired} expired entries",
                group="cpe_queries"
            )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        # Calculate most recent shard update from shards
        shard_updates = [
            shard_info.get('last_updated', '')
            for shard_info in self.cpe_metadata.get('shards', {}).values()
        ]
        most_recent_update = max(shard_updates) if shard_updates else 'unknown'
        
        stats = {
            'total_entries': self._get_total_entries(),
            'loaded_shards': len(self.loaded_shards),
            'session_hits': self.session_stats['hits'],
            'session_misses': self.session_stats['misses'],
            'session_expired': self.session_stats['expired'],
            'session_new_entries': self.session_stats['new_entries'],
            'session_auto_saves': self.session_stats['auto_saves'],
            'unsaved_changes': sum(self.unsaved_changes.values()),
            'session_api_calls_saved': self.session_stats['api_calls_saved'],
            'cache_created': self.cpe_metadata['created'],
            'last_updated': most_recent_update,
            'sharding_enabled': True,
            'num_shards': self.num_shards
        }
        
        # Include corruption event statistics if any occurred
        if hasattr(self, '_rejection_stats'):
            stats['session_rejections'] = self._rejection_stats['count']
            stats['rejected_cpes'] = self._rejection_stats['cpes']  # All rejected CPEs, not a sample
        
        return stats
    
    def log_session_stats(self) -> None:
        """Log cache performance for current session."""
        stats = self.get_stats()
        session_total = stats['session_hits'] + stats['session_misses'] + stats['session_expired']
        session_hit_rate = (stats['session_hits'] / session_total * 100) if session_total > 0 else 0
        
        logger.info(
            f"Cache session performance: {stats['session_hits']} hits, "
            f"{stats['session_misses']} misses, "
            f"{stats['session_expired']} expired, "
            f"{round(session_hit_rate, 1)}% hit rate, "
            f"{stats['session_new_entries']} new entries, "
            f"{stats['session_auto_saves']} auto-saves, "
            f"{stats['loaded_shards']}/{self.num_shards} shards loaded",
            group="cpe_queries"
        )
        
        if stats['session_api_calls_saved'] > 0:
            logger.info(
                f"Cache session saved {stats['session_api_calls_saved']} API calls this run",
                group="cpe_queries"
            )
        
        # Log corruption events if any occurred
        if 'session_rejections' in stats and stats['session_rejections'] > 0:
            logger.warning(
                f"Cache session rejected {stats['session_rejections']} corrupt API responses",
                group="cpe_queries"
            )
            rejected_cpes = stats.get('rejected_cpes', [])
            if rejected_cpes:
                logger.warning(
                    f"All rejected CPEs ({len(rejected_cpes)}): {', '.join(rejected_cpes)}",
                    group="cpe_queries"
                )
    
    def flush(self) -> None:
        """Save all loaded shards to disk and reset unsaved counter."""
        self.save_all_shards()
        self.unsaved_changes.clear()
    
    def clear(self) -> None:
        """Clear all cache data from memory and reset statistics."""
        self.loaded_shards.clear()
        self.unsaved_changes.clear()
        self.session_stats = {
            'hits': 0,
            'misses': 0,
            'expired': 0,
            'new_entries': 0,
            'api_calls_saved': 0,
            'auto_saves': 0
        }
        logger.info("Cache cleared", group="cpe_queries")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - save cache."""
        try:
            self.log_session_stats()
            self.flush()
        except Exception as e:
            logger.warning(f"Failed to save cache during context manager exit: {e}", group="cpe_queries")
            # Don't raise - cache remains in memory for retry on next save
            return False

# Global cache manager instance
_global_cache_instance = None

class GlobalCPECacheManager:
    """Global CPE cache manager that loads once and persists across all CVE processing runs"""
    
    def __init__(self):
        self._cache_instance = None
        self._config = None
    
    def initialize(self, config: Dict[str, Any]):
        """Initialize the global cache with configuration (sharded cache only)"""
        if self._cache_instance is None:
            logger.info("Initializing CPE Base String cache (once per session, large files may load slowly)", group="cpe_queries")
            self._config = config
            
            # Use sharded cache implementation
            num_shards = config.get('sharding', {}).get('num_shards', 16)
            self._cache_instance = ShardedCPECache(config, num_shards=num_shards)
            logger.info(f"Using sharded CPE cache with {num_shards} shards", group="cpe_queries")
            
            # Initialize the cache context manager
            self._cache_instance.__enter__()
        return self._cache_instance
    
    def get_cache(self):
        """Get the cached instance"""
        if self._cache_instance is None:
            raise RuntimeError("Global CPE cache not initialized. Call initialize() first.")
        return self._cache_instance
    
    def is_initialized(self):
        """Check if cache is already initialized"""
        return self._cache_instance is not None
    
    def save_and_cleanup(self):
        """Save cache and cleanup on shutdown (memory-efficient strategy)"""
        if self._cache_instance:
            try:
                # Save only changed shards first (memory efficient)
                self._cache_instance.save_changed_shards_only()
                # Then evict all from memory
                self._cache_instance.evict_all_shards()
                logger.info("Global CPE cache saved and cleaned up", group="cpe_queries")
            except Exception as e:
                logger.warning(f"Error during cache cleanup: {e}", group="cpe_queries")
            finally:
                self._cache_instance = None
    
    def save_all_shards(self):
        """Save all loaded shards to disk (sharded cache only)"""
        if self._cache_instance:
            try:
                self._cache_instance.save_all_shards()
            except Exception as e:
                logger.warning(f"Error during cache save: {e}", group="cpe_queries")
    
    def evict_all_shards(self):
        """Evict all shards from memory (sharded cache only)"""
        if self._cache_instance:
            try:
                self._cache_instance.evict_all_shards()
            except Exception as e:
                logger.warning(f"Error during cache eviction: {e}", group="cpe_queries")

def get_global_cache_manager():
    """Get the global cache manager instance"""
    global _global_cache_instance
    if _global_cache_instance is None:
        _global_cache_instance = GlobalCPECacheManager()
    return _global_cache_instance
