#!/usr/bin/env python3
"""
CPE Cache Management System (Optimized)

This module provides high-performance caching functionality for NVD CPE API responses 
to reduce redundant API calls during large dataset processing.

Key optimizations:
- Uses orjson for 5-10x faster JSON serialization/deserialization
- Optimized save/load operations for large datasets
- Efficient in-memory data structures
"""

import os
import json
import gzip
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from workflow_logger import get_logger

# Try to use orjson for much better performance, fall back to standard json
try:
    import orjson
    HAS_ORJSON = True
except ImportError:
    HAS_ORJSON = False

# Get logger instance
logger = get_logger()

class CPECache:
    """Manages local caching of NVD CPE API responses with optimized performance"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cache_dir = Path(os.path.dirname(__file__)) / config.get('directory', 'cache')
        self.cache_file = self.cache_dir / 'cpe_cache.json'
        self.metadata_file = self.cache_dir / 'cache_metadata.json'
        self.cache_data = {}
        self.metadata = {
            'created': datetime.now().isoformat(),
            'last_updated': datetime.now().isoformat(),
            'cache_version': '1.0',
            'total_entries': 0,
            'hit_count': 0,
            'miss_count': 0,
            'api_calls_saved': 0
        }
        self.session_stats = {
            'hits': 0,
            'misses': 0,
            'expired': 0,
            'new_entries': 0,
            'api_calls_saved': 0
        }
        
        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing cache
        self._load_cache()
        
    def _load_cache(self):
        """Load existing cache data from disk with optimized performance"""
        start_time = time.time()
        try:
            if self.cache_file.exists():
                if self.config.get('compression', False) and str(self.cache_file).endswith('.gz'):
                    with gzip.open(self.cache_file, 'rt', encoding='utf-8') as f:
                        if HAS_ORJSON:
                            content = f.read()
                            self.cache_data = orjson.loads(content)
                        else:
                            self.cache_data = json.load(f)
                else:
                    if HAS_ORJSON:
                        with open(self.cache_file, 'rb') as f:
                            self.cache_data = orjson.loads(f.read())
                    else:
                        with open(self.cache_file, 'r', encoding='utf-8') as f:
                            self.cache_data = json.load(f)
                
                load_time = time.time() - start_time
                logger.info(f"/cpes/ cache loaded: {len(self.cache_data)} entries in {load_time:.2f}s", group="cpe_queries")
            else:
                logger.info("No existing /cpes/ cache found - starting fresh cache", group="cpe_queries")
                
            # Load metadata
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    stored_metadata = json.load(f)
                    self.metadata.update(stored_metadata)
                    
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.warning(f"Cache load error: {e} - starting with empty cache", group="cpe_queries")
            self.cache_data = {}
        except Exception as e:
            if HAS_ORJSON:
                try:
                    # Try orjson decode error
                    logger.warning(f"orjson decode error: {e} - starting with empty cache", group="cpe_queries")
                except:
                    logger.warning(f"Cache load error: {e} - starting with empty cache", group="cpe_queries")
            else:
                logger.warning(f"Cache load error: {e} - starting with empty cache", group="cpe_queries")
            self.cache_data = {}
            
    def _save_cache(self):
        """Save cache data to disk with optimized performance using orjson"""
        start_time = time.time()
        try:
            # Update metadata
            self.metadata['last_updated'] = datetime.now().isoformat()
            self.metadata['total_entries'] = len(self.cache_data)
            
            # Save main cache using orjson for much better performance
            if self.config.get('compression', False):
                cache_file_gz = str(self.cache_file) + '.gz'
                with gzip.open(cache_file_gz, 'wt', encoding='utf-8') as f:
                    if HAS_ORJSON:
                        # orjson produces bytes, decode for text mode
                        f.write(orjson.dumps(self.cache_data).decode('utf-8'))
                    else:
                        json.dump(self.cache_data, f, separators=(',', ':'))
            else:
                if HAS_ORJSON:
                    # orjson is much faster - write as binary
                    with open(self.cache_file, 'wb') as f:
                        f.write(orjson.dumps(self.cache_data))
                else:
                    # Fallback to standard json
                    with open(self.cache_file, 'w', encoding='utf-8') as f:
                        json.dump(self.cache_data, f, separators=(',', ':'))
                    
            # Save metadata (small file, can keep readable)
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(self.metadata, f, indent=2)
            
            save_time = time.time() - start_time
            
            logger.debug(f"/cpes/ cache saved: {len(self.cache_data)} entries in {save_time:.2f}s", group="cpe_queries")
            
        except Exception as e:
            logger.error(f"/cpes/ cache save error: {e}", group="cpe_queries")
            
    def get(self, cpe_string: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """
        Retrieve cached CPE data for a given CPE string
        
        Args:
            cpe_string: The CPE match string to look up
            
        Returns:
            Tuple of (Cached API response data or None if not found/expired, status)
            Status can be: 'hit', 'miss', 'expired'
        """
        if not self.config.get('enabled', True):
            return None, 'disabled'
            
        if cpe_string not in self.cache_data:
            self.session_stats['misses'] += 1
            self.metadata['miss_count'] += 1
            return None, 'miss'
            
        entry = self.cache_data[cpe_string]
        
        # Check if entry is expired
        if self._is_expired(entry):
            del self.cache_data[cpe_string]
            self.session_stats['expired'] += 1
            self.metadata['miss_count'] += 1
            return None, 'expired'
            
        # Cache hit
        self.session_stats['hits'] += 1
        self.session_stats['api_calls_saved'] += 1
        self.metadata['hit_count'] += 1
        self.metadata['api_calls_saved'] += 1
        
        # Log cache hit with result count for dashboard tracking
        result_count = entry['query_response'].get('totalResults', 0)
        logger.debug(f"Cache hit for CPE: {cpe_string} - NVD CPE API call avoided ({result_count} results)", group="cpe_queries")
        
        return entry['query_response'], 'hit'
        
    def put(self, cpe_string: str, api_response: Dict[str, Any]):
        """
        Store CPE API response in cache
        
        Args:
            cpe_string: The CPE match string used as key
            api_response: The full API response to cache
        """
        if not self.config.get('enabled', True):
            return
            
        entry = {
            'query_response': api_response,
            'last_queried': datetime.now().isoformat(),
            'query_count': 1,
            'total_results': api_response.get('totalResults', 0),
            'cache_version': '1.0'
        }
        
        # Update existing entry or create new one
        if cpe_string in self.cache_data:
            existing = self.cache_data[cpe_string]
            entry['query_count'] = existing.get('query_count', 0) + 1
        else:
            self.session_stats['new_entries'] += 1
            
        self.cache_data[cpe_string] = entry
        
    def _is_expired(self, entry: Dict[str, Any]) -> bool:
        """Check if a cache entry has expired (older than 12 hours)"""
        max_age_hours = self.config.get('max_age_hours', 12)
        if max_age_hours <= 0:
            return False  # Never expire if max_age_hours is 0 or negative
            
        last_queried = datetime.fromisoformat(entry['last_queried'].replace('Z', '+00:00'))
        expiry_date = last_queried + timedelta(hours=max_age_hours)
        return datetime.now() > expiry_date
        
    def cleanup_expired(self):
        """Remove expired entries from cache (older than 12 hours)"""
        expired_keys = []
        for key, entry in self.cache_data.items():
            if self._is_expired(entry):
                expired_keys.append(key)
                
        for key in expired_keys:
            del self.cache_data[key]
            
        if expired_keys:
            logger.info(f"Cache cleanup: removed {len(expired_keys)} entries older than 12 hours", group="cpe_queries")
            
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_queries = self.metadata['hit_count'] + self.metadata['miss_count']
        hit_rate = (self.metadata['hit_count'] / total_queries * 100) if total_queries > 0 else 0
        
        return {
            'total_entries': len(self.cache_data),
            'session_hits': self.session_stats['hits'],
            'session_misses': self.session_stats['misses'],
            'session_expired': self.session_stats['expired'],
            'session_new_entries': self.session_stats['new_entries'],
            'session_api_calls_saved': self.session_stats['api_calls_saved'],
            'lifetime_hits': self.metadata['hit_count'],
            'lifetime_misses': self.metadata['miss_count'],
            'lifetime_hit_rate': round(hit_rate, 1),
            'lifetime_api_calls_saved': self.metadata['api_calls_saved'],
            'cache_created': self.metadata['created'],
            'last_updated': self.metadata['last_updated']
        }
        
    def log_session_stats(self):
        """Log cache performance for current session"""
        stats = self.get_stats()
        session_total = stats['session_hits'] + stats['session_misses'] + stats['session_expired']
        session_hit_rate = (stats['session_hits'] / session_total * 100) if session_total > 0 else 0
        
        logger.info(
            f"Cache session performance: {stats['session_hits']} hits, "
            f"{stats['session_misses']} misses, "
            f"{stats['session_expired']} expired, "
            f"{round(session_hit_rate, 1)}% hit rate, "
            f"{stats['session_new_entries']} new entries",
            group="cpe_queries"
        )
        
        # Report session-specific API calls saved, not lifetime
        if stats['session_api_calls_saved'] > 0:
            logger.info(
                f"Cache session saved {stats['session_api_calls_saved']} API calls this run",
                group="cpe_queries"
            )
        
    def flush(self):
        """Save cache to disk"""
        self._save_cache()
        
    def clear(self):
        """Clear all cache data"""
        self.cache_data = {}
        self.session_stats = {'hits': 0, 'misses': 0, 'expired': 0, 'new_entries': 0, 'api_calls_saved': 0}
        logger.info("Cache cleared", group="cpe_queries")
        
    def __enter__(self):
        """Context manager entry"""
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - save cache"""
        self.log_session_stats()
        self.flush()

# Global cache manager instance
_global_cache_instance = None

class GlobalCPECacheManager:
    """Global CPE cache manager that loads once and persists across all CVE processing runs"""
    
    def __init__(self):
        self._cache_instance = None
        self._config = None
    
    def initialize(self, config: Dict[str, Any]):
        """Initialize the global cache with configuration"""
        if self._cache_instance is None:
            logger.info("Initializing global CPE cache - this will happen once per session", group="cpe_queries")
            self._config = config
            self._cache_instance = CPECache(config)
            # Force load the cache data
            self._cache_instance.__enter__()  # Initialize the cache
            logger.info("Global CPE cache initialized and ready for use", group="cpe_queries")
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
        """Save cache and cleanup on shutdown"""
        if self._cache_instance:
            try:
                self._cache_instance.__exit__(None, None, None)  # Trigger save
                logger.info("Global CPE cache saved and cleaned up", group="cpe_queries")
            except Exception as e:
                logger.warning(f"Error during cache cleanup: {e}", group="cpe_queries")
            finally:
                self._cache_instance = None

def get_global_cache_manager():
    """Get the global cache manager instance"""
    global _global_cache_instance
    if _global_cache_instance is None:
        _global_cache_instance = GlobalCPECacheManager()
    return _global_cache_instance
