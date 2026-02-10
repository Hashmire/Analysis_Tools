#!/usr/bin/env python3
"""
CPE Cache Refresh - NVD change-based refresh strategy

This standalone utility refreshes expired CPE cache entries by querying NVD's
change tracking APIs to identify which CPE data has actually changed, avoiding
unnecessary API calls for unchanged entries.

Features:
- Phase 1: Discovery - Scan shards to find oldest entries, query NVD for changes
- Phase 2: Selective Refresh - Only refresh CPE base strings that changed at NVD
- Phase 3: Finalize - Save updates and generate statistics report

Architecture:
- Works directly with shard files
- Loads shards sequentially to minimize memory usage
- Uses hash-based routing matching ShardedCPECache implementation
- Respects NVD API 180-day query limit
Configuration:
- Queries from oldest cache entry timestamp (not notify_age_hours)
- This is a manual refresh tool - runs independently of main cache expiration
- Main cache uses notify_age_hours for automatic expiration during runtime
- This script refreshes based on NVD changes, not age-based expiration
Usage:
    python -m utilities.refresh_cpe_cache
"""

import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
import requests

from src.analysis_tool.logging.workflow_logger import get_logger
from src.analysis_tool.storage.run_organization import get_analysis_tools_root
from src.analysis_tool.storage.cpe_cache import ShardedCPECache
from src.analysis_tool.core.analysis_tool import load_config
from src.analysis_tool.core.gatherData import query_nvd_cpematch_page, gatherNVDCPEData

logger = get_logger()

# API Configuration constants
RESULTS_PER_PAGE = 500  # NVD cpematch API max per page
REQUEST_DELAY = 0.6  # 600ms between requests for API rate limiting

# Create minimal cache instance for utility methods (filename generation)
# Using __new__ to bypass __init__ and avoid initialization logging
_cache_utils = ShardedCPECache.__new__(ShardedCPECache)
_cache_utils.num_shards = 16  # Default, can be overridden


class CPECacheRefreshStats:
    """Track refresh operation statistics"""
    
    def __init__(self):
        self.oldest_entry_timestamp: Optional[datetime] = None
        self.query_start_date: Optional[datetime] = None
        self.query_limited_by_api: bool = False
        self.changed_matches_found: int = 0
        self.unique_cpe_bases: int = 0
        self.entries_refreshed: int = 0
        self.api_calls_made: int = 0
        self.shards_updated: int = 0
        self.auto_saves_triggered: int = 0
        self.start_time: float = time.time()
        self.errors: List[str] = []
    
    def report(self) -> str:
        """Generate human-readable statistics report"""
        elapsed = time.time() - self.start_time
        
        lines = [
            "\n" + "="*80,
            "CPE CACHE REFRESH SUMMARY",
            "="*80,
            f"Oldest cache entry:        {self.oldest_entry_timestamp}",
            f"Query start date:          {self.query_start_date}",
            f"Limited by 180-day API:    {'YES' if self.query_limited_by_api else 'NO'}",
            f"Changed CPE matches found: {self.changed_matches_found:,}",
            f"Unique CPE base strings:   {self.unique_cpe_bases:,}",
            f"Entries refreshed:         {self.entries_refreshed:,}",
            f"API calls made:            {self.api_calls_made:,}",
            f"Shards updated:            {self.shards_updated:,}",
            f"Auto-saves triggered:      {self.auto_saves_triggered:,}",
            f"Elapsed time:              {elapsed:.1f}s",
        ]
        
        if self.errors:
            lines.append(f"\nErrors encountered:        {len(self.errors)}")
            for error in self.errors[:5]:  # Show first 5 errors
                lines.append(f"  - {error}")
            if len(self.errors) > 5:
                lines.append(f"  ... and {len(self.errors) - 5} more")
        
        lines.append("="*80 + "\n")
        return "\n".join(lines)


def diagnose_shard_corruption(shard_path: Path, error: Exception) -> Dict[str, Any]:
    """
    Diagnose the source and type of cache shard corruption.
    
    Provides detailed feedback about corruption to aid debugging and
    identify systemic issues (e.g., network errors, disk failures).
    
    Args:
        shard_path: Path to corrupted shard file
        error: Exception that was raised during load attempt
    
    Returns:
        Dict with diagnostic information
    """
    diagnostics = {
        'error_type': type(error).__name__,
        'error_message': str(error)[:200],
        'file_size': 0,
        'corruption_category': 'UNKNOWN',
        'first_bytes': '',
        'recommendations': []
    }
    
    try:
        # Get file size
        diagnostics['file_size'] = shard_path.stat().st_size
        
        # Read first 200 bytes for analysis
        with open(shard_path, 'rb') as f:
            first_bytes = f.read(200)
            diagnostics['first_bytes'] = repr(first_bytes[:100])
        
        # Check for null bytes (should be prevented by validation)
        has_null_bytes = b'\x00' in first_bytes
        
        # Check for surrogate pairs in UTF-8 byte sequence
        # Surrogates in UTF-8: 0xED 0xA0-0xBF (high) or 0xED 0xB0-0xBF (low)
        has_surrogates = False
        for i in range(len(first_bytes) - 2):
            if first_bytes[i] == 0xED and 0xA0 <= first_bytes[i+1] <= 0xBF:
                has_surrogates = True
                break
        
        # Categorize corruption type aligned with prevention mechanisms
        if diagnostics['file_size'] == 0:
            diagnostics['corruption_category'] = 'DISK_FAILURE - Empty File'
            diagnostics['recommendations'].append('Complete write failure or interruption during atomic save operation')
            diagnostics['recommendations'].append('Likely cause: Disk full, power loss, or process termination during write')
        
        elif first_bytes.startswith(b'{') and diagnostics['file_size'] < 100:
            diagnostics['corruption_category'] = 'DISK_FAILURE - Truncated Write'
            diagnostics['recommendations'].append('Partial write detected - file starts valid but incomplete')
            diagnostics['recommendations'].append('Likely cause: Disk full, process killed, or temp file not fully written')
        
        elif not first_bytes.startswith(b'{'):
            diagnostics['corruption_category'] = 'DISK_CORRUPTION - Invalid Format'
            diagnostics['recommendations'].append('File does not contain valid JSON structure')
            diagnostics['recommendations'].append('Likely cause: Bit flips, disk corruption, or external file modification')
        
        elif 'JSONDecodeError' in diagnostics['error_type']:
            # Distinguish between orjson-specific, general JSON, and NVD garbage issues
            if first_bytes.startswith(b'<!DOCTYPE') or first_bytes.startswith(b'<html'):
                diagnostics['corruption_category'] = 'NVD_GARBAGE - HTML Error Page'
                diagnostics['recommendations'].append('NVD API returned HTML error page instead of JSON')
                diagnostics['recommendations'].append('Should be caught during HTTP response validation before caching')
                diagnostics['recommendations'].append('Indicates validation bypass or API rate limiting/error response')
            
            elif has_null_bytes:
                diagnostics['corruption_category'] = 'VALIDATION_BYPASS - Null Bytes (JSON-level)'
                diagnostics['recommendations'].append('Null bytes in JSON content (invalid for both JSON and orjson)')
                diagnostics['recommendations'].append('Should be blocked by validate_string_content() layer')
                diagnostics['recommendations'].append('Possible causes: Validation skipped, disk corruption post-write, or manual file edit')
            
            elif has_surrogates:
                diagnostics['corruption_category'] = 'ORJSON_SPECIFIC - UTF-8 Surrogate Pairs'
                diagnostics['recommendations'].append('UTF-8 surrogate pairs detected (orjson strictness - standard json may accept)')
                diagnostics['recommendations'].append('Should be blocked by orjson roundtrip test in validate_orjson_serializable()')
                diagnostics['recommendations'].append('Possible causes: Validation skipped, NVD data corruption, or post-write disk corruption')
            
            else:
                # Generic JSON syntax error - check error message for clues
                error_lower = diagnostics['error_message'].lower()
                if 'unexpected character' in error_lower or 'unexpected end' in error_lower:
                    diagnostics['corruption_category'] = 'JSON_SYNTAX_ERROR - Malformed Structure'
                    diagnostics['recommendations'].append('General JSON syntax error (missing braces, invalid escapes, etc.)')
                    diagnostics['recommendations'].append('Likely cause: Incomplete write, disk corruption during save, or power loss')
                else:
                    diagnostics['corruption_category'] = 'JSON_PARSE_ERROR - Unknown Issue'
                    diagnostics['recommendations'].append('orjson parsing failed with unrecognized error pattern')
                    diagnostics['recommendations'].append('Check error message for details - may be encoding or syntax issue')
        
        else:
            diagnostics['corruption_category'] = 'UNKNOWN'
            diagnostics['recommendations'].append('Unrecognized corruption pattern - see error details for investigation')
    
    except Exception as diag_error:
        diagnostics['recommendations'].append(f'Diagnostic scan failed: {diag_error}')
    
    return diagnostics


def log_corruption_diagnostics(shard_index: int, shard_path: Path, error: Exception) -> None:
    """
    Log detailed corruption diagnostics before auto-recovery.
    
    Args:
        shard_index: Shard index number
        shard_path: Path to corrupted shard file
        error: Exception that was raised
    """
    diag = diagnose_shard_corruption(shard_path, error)
    
    logger.error(
        f"Shard {shard_index:02d} corruption detected - detailed diagnostics:",
        group="CACHE_REFRESH"
    )
    logger.error(f"  File: {shard_path}", group="CACHE_REFRESH")
    logger.error(f"  Size: {diag['file_size']:,} bytes", group="CACHE_REFRESH")
    logger.error(f"  Category: {diag['corruption_category']}", group="CACHE_REFRESH")
    logger.error(f"  Error Type: {diag['error_type']}", group="CACHE_REFRESH")
    logger.error(f"  Error Message: {diag['error_message']}", group="CACHE_REFRESH")
    logger.error(f"  First Bytes: {diag['first_bytes']}", group="CACHE_REFRESH")
    
    for rec in diag['recommendations']:
        logger.error(f"  -> {rec}", group="CACHE_REFRESH")


def get_shard_index(cpe_string: str, num_shards: int = 16) -> int:
    """
    Hash CPE string to shard index (delegates to ShardedCPECache implementation).
    
    Args:
        cpe_string: CPE match string
        num_shards: Number of shards (default: 16)
    
    Returns:
        Shard index (0 to num_shards-1)
    """
    # Use temporary instance just for hash calculation (instance methods only)
    # Create with minimal config to avoid unnecessary logging
    temp_cache = ShardedCPECache.__new__(ShardedCPECache)
    temp_cache.num_shards = num_shards
    return temp_cache._get_shard_index(cpe_string)


def find_oldest_cache_entry(cache_dir: Path, num_shards: int = 16) -> datetime:
    """
    Scan shard files sequentially to find oldest last_queried timestamp.
    
    Loads each shard file (cpe_cache_shard_XX.json) in sequence, processes it,
    then frees memory before loading the next. This minimizes memory usage during
    the discovery phase.
    
    Args:
        cache_dir: Path to cache/cpe_base_strings directory
        num_shards: Number of shards to scan (default: 16)
    
    Returns:
        Oldest last_queried timestamp found across all loaded shards
    """
    oldest = datetime.now(timezone.utc)
    total_entries = 0
    
    logger.info(f"Scanning {num_shards} shard files for oldest cache entry...", group="CACHE_REFRESH")
    
    # Set num_shards on utility instance if different from default
    if num_shards != 16:
        _cache_utils.num_shards = num_shards
    
    for shard_index in range(num_shards):
        shard_path = cache_dir / _cache_utils._get_shard_filename(shard_index)
        if not shard_path.exists():
            logger.debug(f"Shard {shard_index:02d} does not exist - skipping", group="CACHE_REFRESH")
            continue
        
        # Load shard - auto-recover if corrupted
        try:
            shard_data = ShardedCPECache.load_shard_from_disk(shard_path)
        except Exception as e:
            # Diagnose corruption before deletion
            log_corruption_diagnostics(shard_index, shard_path, e)
            
            logger.error(
                f"Auto-recovering: Deleting corrupted shard to allow rebuild",
                group="CACHE_REFRESH"
            )
            shard_path.unlink()  # Delete corrupted file - will rebuild naturally
            logger.info(f"Shard {shard_index:02d} deleted - will rebuild on next CPE lookup", group="CACHE_REFRESH")
            continue  # Skip this shard in current refresh cycle
        
        shard_entries = len(shard_data)
        total_entries += shard_entries
        
        for entry_data in shard_data.values():
            last_queried_str = entry_data.get('last_queried')
            if not last_queried_str:
                continue
            
            # Use ShardedCPECache static method for timestamp parsing
            last_queried = ShardedCPECache.parse_cache_entry_timestamp(entry_data)
            
            if last_queried < oldest:
                oldest = last_queried
        
        logger.debug(
            f"Shard {shard_index:02d}: {shard_entries:,} entries scanned",
            group="CACHE_REFRESH"
        )
        
        del shard_data  # Free memory before next shard
    
    logger.info(
        f"Scanned {total_entries:,} total cache entries across {num_shards} shards",
        group="CACHE_REFRESH"
    )
    
    return oldest


def get_query_start_date(oldest_entry: datetime) -> Tuple[datetime, bool]:
    """
    Determine query start date respecting NVD 180-day API limit.
    
    Args:
        oldest_entry: Oldest cache entry timestamp found
    
    Returns:
        Tuple of (query_start_date, limited_by_api)
    """
    now = datetime.now(timezone.utc)
    max_lookback = now - timedelta(days=180)
    
    if oldest_entry < max_lookback:
        logger.warning(
            f"Oldest cache entry ({oldest_entry.date()}) exceeds NVD API 180-day limit. "
            f"Query will start from {max_lookback.date()} instead. "
            f"Cache entries older than 180 days cannot be validated via change detection.",
            group="CACHE_REFRESH"
        )
        return max_lookback, True  # Limited by API
    
    return oldest_entry, False  # Can query full range


def query_cpematch_changes(
    api_key: str,
    start_date: datetime,
    end_date: datetime,
    stats: CPECacheRefreshStats,
    nvd_cpematch_api: str
) -> List[str]:
    """
    Query NVD /cpematch/ API for CPE changes in date range (DISCOVERY PHASE).
    
    This API provides PARTIAL metadata - just enough to identify which CPE base
    strings need refreshing. Full CPE metadata is obtained in Phase 2 via /cpes/ API.
    
    Filters out match criteria with empty 'matches' arrays (CPEs not in dictionary).
    
    Args:
        api_key: NVD API key
        start_date: Start of query range
        end_date: End of query range (typically now)
        stats: Statistics tracker
        nvd_cpematch_api: NVD CPE Match API endpoint URL
    
    Returns:
        List of CPE criteria strings (filtered to only those with CPE dictionary entries)
    """
    all_matches = []
    start_index = 0
    
    # Format dates for NVD API (ISO 8601 with timezone)
    start_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000+00:00')
    end_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000+00:00')
    
    logger.info(
        f"Querying NVD /cpematch/ API for changes between {start_date.date()} and {end_date.date()}...",
        group="CACHE_REFRESH"
    )
    
    while True:
        params = {
            'lastModStartDate': start_str,
            'lastModEndDate': end_str,
            'resultsPerPage': RESULTS_PER_PAGE,
            'startIndex': start_index
        }
        
        headers = {'apiKey': api_key} if api_key else {}
        
        # Build URL with query parameters
        from urllib.parse import urlencode
        url = f"{nvd_cpematch_api}?{urlencode(params)}"
        logger.info(f"Query: {url}", group="CACHE_REFRESH")
        
        # Use centralized API query function
        data = query_nvd_cpematch_page(url, headers, f"NVD CPE Match API (startIndex={start_index})")
        
        if data is None:
            error_msg = f"Failed to query /cpematch/ API (startIndex={start_index})"
            logger.error(error_msg, group="CACHE_REFRESH")
            stats.errors.append(error_msg)
            break
        
        stats.api_calls_made += 1
        
        try:
            matches = data.get('matchStrings', [])
            
            if not matches:
                break
            
            # Extract CPE match strings that have actual CPE dictionary entries
            for match_obj in matches:
                match_string_data = match_obj.get('matchString', {})
                
                # Check if this match has actual CPE dictionary entries
                cpe_matches = match_string_data.get('matches', [])
                if not cpe_matches:
                    # Skip - this criteria doesn't have any CPE dictionary entries
                    continue
                
                # Extract the 'criteria' field which contains the actual CPE string
                cpe_match_string = match_string_data.get('criteria')
                if cpe_match_string:
                    all_matches.append(cpe_match_string)
            
            logger.debug(
                f"Retrieved {len(matches)} match strings (startIndex={start_index})",
                group="CACHE_REFRESH"
            )
            
            # Check if more pages available
            total_results = data.get('totalResults', 0)
            if start_index + RESULTS_PER_PAGE >= total_results:
                break
            
            start_index += RESULTS_PER_PAGE
            time.sleep(REQUEST_DELAY)  # Rate limiting
            
        except Exception as e:
            error_msg = f"Failed to process /cpematch/ API response (startIndex={start_index}): {e}"
            logger.error(error_msg, group="CACHE_REFRESH")
            stats.errors.append(error_msg)
            break
    
    logger.info(
        f"Found {len(all_matches):,} changed CPE match strings from NVD",
        group="CACHE_REFRESH"
    )
    
    return all_matches


def extract_unique_cpe_bases(match_strings: List[str]) -> Set[str]:
    """
    Extract unique CPE base strings from match criteria (remove version/update components).
    
    CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    Base string: All components except version (pos 5) and update (pos 6) - replace with '*'
    
    NOTE: Input match_strings are already filtered (Phase 1) to only include CPEs that
    have dictionary entries. This deduplicates them into unique base strings for Phase 2 queries.
    
    Args:
        match_strings: List of CPE criteria strings (pre-filtered to have dictionary entries)
    
    Returns:
        Set of unique CPE base strings (all attributes except version/update)
    """
    bases = set()
    
    for match in match_strings:
        parts = match.split(':')
        if len(parts) >= 13:
            # Replace version and update (positions 5-6) with '*'
            base_parts = parts[:5] + ['*', '*'] + parts[7:]
            base = ':'.join(base_parts)
            bases.add(base)
        elif len(parts) >= 5:
            # Handle shorter CPE strings - replace version/update with '*'
            base_parts = parts[:5] + ['*', '*']
            # Pad to standard 13-component format if needed
            while len(base_parts) < 13:
                base_parts.append('*')
            base = ':'.join(base_parts)
            bases.add(base)
    
    logger.info(
        f"Extracted {len(bases):,} unique CPE base strings from {len(match_strings):,} match strings",
        group="CACHE_REFRESH"
    )
    
    return bases


def query_nvd_cpes_api(api_key: str, cpe_base: str, stats: CPECacheRefreshStats, nvd_cpe_api: str) -> Optional[Dict[str, Any]]:
    """
    Query NVD /cpes/ API for specific CPE base string (REFRESH PHASE).
    
    This API provides COMPLETE CPE metadata including all dictionary entries,
    titles, references, deprecation status, etc. This is the full data cached
    for use by the main analysis tool.
    
    Args:
        api_key: NVD API key
        cpe_base: CPE base string to query (identified in Phase 1)
        stats: Statistics tracker
        nvd_cpe_api: NVD CPE API endpoint URL (not used - kept for backward compatibility)
    
    Returns:
        Full API response dict with complete CPE metadata, or None on error
    """
    # Use centralized gatherNVDCPEData function from gatherData.py
    data = gatherNVDCPEData(api_key, 'cpeMatchString', cpe_base)
    
    if data is None:
        error_msg = f"Failed to query /cpes/ API for {cpe_base}"
        logger.warning(error_msg, group="CACHE_REFRESH")
        stats.errors.append(error_msg)
        return None
    
    # Track API call in stats
    stats.api_calls_made += 1
    
    result_count = data.get('totalResults', 0)
    logger.info(f"Refreshing CPE cache: {cpe_base} ({result_count} results)", group="CACHE_REFRESH")
    return data


def flush_staged_updates(staged: Dict[int, Dict[str, Any]], cache_dir: Path, stats: CPECacheRefreshStats, num_shards: int = 16) -> int:
    """
    Flush staged updates to shard files (save to disk).
    
    For each shard with pending updates:
    1. Load existing shard file (cpe_cache_shard_XX.json) if it exists
    2. Merge updates (preserving existing query_count values)
    3. Save shard back to disk using compact JSON (no indentation)
    
    This mirrors the ShardedCPECache.save_shard() behavior but operates
    on shard files directly without using the singleton cache manager.
    
    Args:
        staged: Dict of {shard_index: {cpe_base: cache_entry}}
        cache_dir: Path to cache/cpe_base_strings directory
        stats: Statistics tracker
    
    Returns:
        Number of entries flushed to shard files
    """
    total_flushed = 0
    
    # Set num_shards on utility instance if different from default
    if num_shards != 16:
        _cache_utils.num_shards = num_shards
    
    for shard_index, updates in staged.items():
        if not updates:
            continue
        
        shard_path = cache_dir / _cache_utils._get_shard_filename(shard_index)
        
        # Load shard - auto-recover if corrupted
        try:
            shard_data = ShardedCPECache.load_shard_from_disk(shard_path)
        except Exception as e:
            # Diagnose corruption before deletion
            log_corruption_diagnostics(shard_index, shard_path, e)
            
            logger.error(
                f"Auto-recovering: Deleting corrupted shard to rebuild with fresh updates",
                group="CACHE_REFRESH"
            )
            shard_path.unlink()  # Delete corrupted file
            logger.info(f"Shard {shard_index:02d} deleted - starting fresh with updates", group="CACHE_REFRESH")
            shard_data = {}  # Start with empty shard, apply updates
        
        # Merge updates (preserve query_count if entry exists)
        # This maintains cache statistics across refreshes
        for cpe_base, new_entry in updates.items():
            if cpe_base in shard_data:
                # Preserve query_count from existing entry (don't reset to 1)
                existing_count = shard_data[cpe_base].get('query_count', 1)
                new_entry['query_count'] = existing_count
        
        shard_data.update(updates)
        
        # Save shard using ShardedCPECache static method (compact JSON)
        ShardedCPECache.save_shard_to_disk(shard_path, shard_data)
        
        logger.debug(
            f"Flushed {len(updates)} updates to shard {shard_index:02d}",
            group="CACHE_REFRESH"
        )
        
        total_flushed += len(updates)
        updates.clear()
        stats.shards_updated += 1
    
    return total_flushed


def smart_refresh(
    api_key: str,
    cache_dir: Path,
    nvd_cpematch_api: str,
    nvd_cpe_api: str,
    num_shards: int = 16
) -> CPECacheRefreshStats:
    """
    Execute smart refresh using NVD change detection.
    
    Args:
        api_key: NVD API key
        cache_dir: Path to cache/cpe_base_strings directory
        nvd_cpematch_api: NVD CPE Match API endpoint URL
        nvd_cpe_api: NVD CPE API endpoint URL
        num_shards: Number of shards
    
    Returns:
        Statistics object with refresh results
    """
    stats = CPECacheRefreshStats()
    
    logger.info("="*80, group="CACHE_REFRESH")
    logger.info("Starting CPE Cache Smart Refresh", group="CACHE_REFRESH")
    logger.info("="*80, group="CACHE_REFRESH")
    
    # Phase 1: Discovery
    logger.info("\n--- PHASE 1: DISCOVERY ---", group="CACHE_REFRESH")
    
    oldest_entry = find_oldest_cache_entry(cache_dir, num_shards)
    stats.oldest_entry_timestamp = oldest_entry
    logger.info(f"Oldest cache entry timestamp: {oldest_entry}", group="CACHE_REFRESH")
    
    # Check 180-day API limit
    query_start, limited = get_query_start_date(oldest_entry)
    query_end = datetime.now(timezone.utc)
    stats.query_start_date = query_start
    stats.query_limited_by_api = limited
    
    if limited:
        logger.warning(
            "Smart refresh limited to 180-day window. "
            "Cache entries older than this cannot be validated.",
            group="CACHE_REFRESH"
        )
    
    # Query NVD for changes
    changed_matches = query_cpematch_changes(
        api_key, query_start, query_end, stats, nvd_cpematch_api
    )
    stats.changed_matches_found = len(changed_matches)
    
    # Extract unique CPE base strings
    unique_bases = extract_unique_cpe_bases(changed_matches)
    stats.unique_cpe_bases = len(unique_bases)
    
    if not unique_bases:
        logger.info("No CPE base strings need refreshing - cache is up to date!", group="CACHE_REFRESH")
        return stats
    
    # Phase 2: Selective Refresh
    logger.info(f"\n--- PHASE 2: SELECTIVE REFRESH ({len(unique_bases):,} entries) ---", group="CACHE_REFRESH")
    
    staged_updates = {i: {} for i in range(num_shards)}
    refreshed = 0
    
    for cpe_base in unique_bases:
        # Query NVD for updated CPE data
        api_response = query_nvd_cpes_api(api_key, cpe_base, stats, nvd_cpe_api)
        
        if api_response is None:
            continue  # Error already logged
        
        # Build cache entry matching ShardedCPECache.put() format
        now = datetime.now(timezone.utc).isoformat()
        total_results = api_response.get('totalResults', 0)
        cache_entry = {
            'query_response': api_response,
            'last_queried': now,
            'query_count': 1,  # Will be updated during flush if entry exists
            'total_results': total_results
        }
        
        # Route to correct shard using hash-based distribution (mirrors ShardedCPECache._get_shard_index)
        shard_idx = get_shard_index(cpe_base, num_shards)
        staged_updates[shard_idx][cpe_base] = cache_entry
        refreshed += 1
        stats.entries_refreshed += 1
        
        # Periodic flush (every 50 entries) - save staged updates to shard files
        if refreshed % 50 == 0:
            flushed = flush_staged_updates(staged_updates, cache_dir, stats, num_shards)
            logger.info(
                f"Progress: {refreshed}/{len(unique_bases)} refreshed, {flushed} entries saved to shards",
                group="CACHE_REFRESH"
            )
            stats.auto_saves_triggered += 1
            time.sleep(REQUEST_DELAY)  # Rate limiting
        else:
            time.sleep(REQUEST_DELAY)  # Rate limiting between API calls
    
    # Phase 3: Finalize - save remaining staged updates to shard files
    logger.info("\n--- PHASE 3: FINALIZE ---", group="CACHE_REFRESH")
    
    flushed = flush_staged_updates(staged_updates, cache_dir, stats, num_shards)
    logger.info(f"Final flush: {flushed} updates saved to shard files", group="CACHE_REFRESH")
    
    logger.info(stats.report(), group="CACHE_REFRESH")
    
    return stats


def main():
    """Main entry point for cache refresh script"""
    
    # Load configuration
    config = load_config()
    
    # Get API key from config
    api_key = config.get('defaults', {}).get('default_api_key')
    if not api_key or api_key == 'CONFIG_DEFAULT':
        logger.error(
            "No NVD API key configured. Please set 'default_api_key' in src/analysis_tool/config.json",
            group="CACHE_REFRESH"
        )
        return 1
    
    # Get API endpoints from config
    api_endpoints = config.get('api', {}).get('endpoints', {})
    nvd_cpematch_api = api_endpoints.get('nvd_cpematch')
    nvd_cpe_api = api_endpoints.get('nvd_cpes')
    
    if not nvd_cpematch_api:
        logger.error(
            "Missing 'nvd_cpematch' endpoint in config.json api.endpoints section",
            group="CACHE_REFRESH"
        )
        return 1
    
    if not nvd_cpe_api:
        logger.error(
            "Missing 'nvd_cpes' endpoint in config.json api.endpoints section",
            group="CACHE_REFRESH"
        )
        return 1
    
    # Get cache settings
    cache_config = config.get('cache_settings', {}).get('cpe_cache', {})
    num_shards = cache_config.get('sharding', {}).get('num_shards', 16)
    
    # Determine cache directory using same logic as ShardedCPECache
    cache_dir = get_analysis_tools_root() / "cache" / "cpe_base_strings"
    
    if not cache_dir.exists():
        logger.error(f"Cache directory does not exist: {cache_dir}", group="CACHE_REFRESH")
        return 1
    
    logger.info(f"Using cache directory: {cache_dir}", group="CACHE_REFRESH")
    logger.info(f"Number of shards: {num_shards}", group="CACHE_REFRESH")
    
    # Execute smart refresh
    try:
        stats = smart_refresh(
            api_key=api_key,
            cache_dir=cache_dir,
            nvd_cpematch_api=nvd_cpematch_api,
            nvd_cpe_api=nvd_cpe_api,
            num_shards=num_shards
        )
        
        if stats.errors:
            logger.warning(
                f"Refresh completed with {len(stats.errors)} errors",
                group="CACHE_REFRESH"
            )
            return 1
        
        logger.info("Cache refresh completed successfully!", group="CACHE_REFRESH")
        return 0
        
    except Exception as e:
        logger.error(f"Fatal error during cache refresh: {e}", group="CACHE_REFRESH")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
