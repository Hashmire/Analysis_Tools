#!/usr/bin/env python3
"""
NVD CVE Cache Refresh Utility

Refreshes NVD CVE cache by querying for records modified since the last update.
Uses 3-phase approach: Discovery → Validation & Update → Finalize.

Usage:
    # Auto-detect from cache metadata (recommended)
    python -m utilities.refresh_nvd_cache
    
    # Manual date range (testing/recovery)
    python -m utilities.refresh_nvd_cache --days 7
    python -m utilities.refresh_nvd_cache --start-date 2024-01-01 --end-date 2024-01-31
"""

import sys
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from src.analysis_tool.logging.workflow_logger import get_logger
from src.analysis_tool.storage.run_organization import get_analysis_tools_root
from src.analysis_tool.core.analysis_tool import load_config
from src.analysis_tool.core.gatherData import (
    _save_nvd_cve_to_local_file,
    _get_cached_config,
    _update_cache_metadata,
    _update_manual_refresh_timestamp,
    _get_cache_metadata_last_update,
    _transform_nvd_vulnerability_to_response,
    load_schema,
    query_nvd_cves_by_modified_date,
    query_nvd_cves_all,
    query_nvd_cves_by_modified_date_concurrent,
    query_nvd_cves_all_concurrent,
    TOOLNAME,
    VERSION,
    config
)

logger = get_logger()


class NVDCacheRefreshStats:
    """Track refresh operation statistics"""
    
    def __init__(self):
        self.start_time = datetime.now(timezone.utc)
        self.date_range_start: Optional[datetime] = None
        self.date_range_end: Optional[datetime] = None
        self.total_cves_found: int = 0
        self.cves_processed: int = 0
        self.cves_cached: int = 0
        self.cves_updated: int = 0
        self.cves_current: int = 0
        self.validation_failures: int = 0
        self.cache_failures: int = 0
        self.api_calls: int = 0
        self.batches_processed: int = 0
        self.errors: List[str] = []
    
    def report(self) -> str:
        """Generate human-readable statistics report"""
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        
        lines = [
            "\n" + "="*80,
            "NVD CVE CACHE REFRESH SUMMARY",
            "="*80,
            f"Date range:                {self.date_range_start.strftime('%Y-%m-%d') if self.date_range_start else 'FULL REFRESH'} to {self.date_range_end.strftime('%Y-%m-%d') if self.date_range_end else 'FULL REFRESH'}",
            f"Total CVEs found:          {self.total_cves_found:,}",
            f"CVEs processed:            {self.cves_processed:,}",
            f"  - Cached (new):          {self.cves_cached:,}",
            f"  - Updated:               {self.cves_updated:,}",
            f"  - Current:               {self.cves_current:,}",
            f"  - Failed:                {self.cache_failures:,}",
            f"API calls made:            {self.api_calls:,}",
            f"Batches processed:         {self.batches_processed:,}",
            f"Elapsed time:              {minutes}m {seconds}s",
        ]
        
        if self.errors:
            lines.append(f"\nErrors encountered:        {len(self.errors)}")
            for error in self.errors[:5]:  # Show first 5 errors
                lines.append(f"  - {error}")
            if len(self.errors) > 5:
                lines.append(f"  ... and {len(self.errors) - 5} more")
        
        lines.append("="*80 + "\n")
        return "\n".join(lines)


def determine_date_range(args) -> Optional[tuple[Optional[datetime], Optional[datetime]]]:
    """
    Determine refresh date range from CLI arguments or cache metadata.
    
    Args:
        args: Parsed command-line arguments
    
    Returns:
        Tuple of (start_date, end_date), (None, None) for full refresh, or None on failure
    """
    now = datetime.now(timezone.utc)
    
    # Full database refresh (no date filters)
    if args.full_refresh:
        logger.warning("FULL REFRESH MODE: Will query entire NVD dataset", group="CACHE_REFRESH")
        logger.warning("This operation will take 30-60 minutes to complete", group="CACHE_REFRESH")
        return (None, None)  # Signal for full refresh
    
    # Auto-detect from cache metadata (default behavior)
    if args.auto or (not args.days and not args.start_date and not args.full_refresh):
        last_update = _get_cache_metadata_last_update('nvd_2_0_cve')
        if last_update:
            logger.info(f"Cache metadata shows last update: {last_update.strftime('%Y-%m-%d %H:%M:%S %Z')}", group="CACHE_REFRESH")
            logger.info(f"Query range: {last_update.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')} (from cache metadata)", group="CACHE_REFRESH")
            return last_update, now
        else:
            logger.warning("Auto-detection failed - no cache metadata found", group="CACHE_REFRESH")
            logger.error("Cannot proceed without date range. Use --days N or --start-date/--end-date", group="CACHE_REFRESH")
            return None
    
    # Manual date range specified (testing/recovery)
    if args.start_date and args.end_date:
        start = datetime.strptime(args.start_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
        end = datetime.strptime(args.end_date, '%Y-%m-%d').replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
        logger.info(f"Query range: {start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')} (manual)", group="CACHE_REFRESH")
        return start, end
    
    # Days back specified (testing/recovery)
    if args.days:
        start = now - timedelta(days=args.days)
        logger.info(f"Query range: {start.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')} (last {args.days} days)", group="CACHE_REFRESH")
        return start, now
    
    return None


def _process_single_cve(vuln_record: Dict[str, Any], nvd_schema: Any) -> Tuple[Optional[str], str, Optional[str]]:
    """
    Process a single CVE record (thread-safe worker function).
    
    Args:
        vuln_record: Single vulnerability record from NVD API
        nvd_schema: Pre-loaded NVD CVE 2.0 schema for validation
    
    Returns:
        Tuple of (cve_id, status, error_message)
    """
    try:
        # Extract CVE ID
        cve_id = vuln_record.get('cve', {}).get('id')
        if not cve_id:
            return None, "failed", "Missing CVE ID in vulnerability record"
        
        # Transform to single-CVE response format
        nvd_response = _transform_nvd_vulnerability_to_response(vuln_record, cve_id)
        
        # Cache NVD record with metadata updates disabled (bulk update in Phase 3)
        status = _save_nvd_cve_to_local_file(cve_id, nvd_response, cve_schema=nvd_schema, update_metadata=False)
        
        return cve_id, status, None
    except Exception as e:
        cve_id = vuln_record.get('cve', {}).get('id', 'UNKNOWN')
        return cve_id, "failed", f"Processing error: {str(e)[:100]}"


def process_api_page(vulnerabilities: List[Dict[str, Any]], nvd_schema: Any, stats: NVDCacheRefreshStats, page_num: int, total_pages: int, max_workers: int = 20):
    """
    Process CVE records with validation and caching using parallel workers.
    
    Args:
        vulnerabilities: List of vulnerability records from NVD API
        nvd_schema: Pre-loaded NVD CVE 2.0 schema for validation
        stats: Statistics tracker
        page_num: Current page number (1-indexed)
        total_pages: Total number of pages
        max_workers: Number of parallel workers (default: 20)
    """
    logger.info(f"Processing API page {page_num}/{total_pages} ({len(vulnerabilities)} CVEs) with {max_workers} workers", group="CACHE_REFRESH")
    
    # Thread-safe lock for stats updates
    stats_lock = threading.Lock()
    
    # Process CVEs in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all CVEs to worker pool
        futures = {executor.submit(_process_single_cve, vuln, nvd_schema): vuln for vuln in vulnerabilities}
        
        # Collect results as they complete
        for future in as_completed(futures):
            cve_id, status, error = future.result()
            
            # Thread-safe stats update
            with stats_lock:
                stats.cves_processed += 1
                
                # Track and log status
                if status == "cached":
                    stats.cves_cached += 1
                    logger.info(f"[{stats.cves_processed:>4}/{stats.total_cves_found}] {cve_id:<20} CACHED", group="CACHE_REFRESH")
                elif status == "updated":
                    stats.cves_updated += 1
                    logger.info(f"[{stats.cves_processed:>4}/{stats.total_cves_found}] {cve_id:<20} UPDATED", group="CACHE_REFRESH")
                elif status == "skipped":
                    stats.cves_current += 1
                    logger.info(f"[{stats.cves_processed:>4}/{stats.total_cves_found}] {cve_id:<20} CURRENT", group="CACHE_REFRESH")
                else:  # failed
                    stats.cache_failures += 1
                    logger.info(f"[{stats.cves_processed:>4}/{stats.total_cves_found}] {cve_id:<20} FAILED", group="CACHE_REFRESH")
                    if error:
                        stats.errors.append(error)
    
    stats.batches_processed += 1


def smart_refresh(api_key: Optional[str], args=None, max_workers: int = 20, api_workers: int = 15):
    """
    Main refresh orchestration: discover changes, validate, update.
    
    Phase 1: Discovery - Query NVD for modified CVEs (concurrent)
    Phase 2: Validation & Update - Validate and cache records (parallel)
    Phase 3: Finalize - Update metadata
    
    Args:
        api_key: NVD API key (optional, recommended for better rate limits)
        args: Parsed command-line arguments
        max_workers: Number of parallel workers for CVE processing (default: 20)
        api_workers: Number of concurrent API requests (default: 15)
    
    Returns:
        NVDCacheRefreshStats object with operation results
    """
    stats = NVDCacheRefreshStats()
    
    # Determine date range
    date_range = determine_date_range(args)
    if date_range is None:
        logger.error("Failed to determine date range - cannot proceed", group="CACHE_REFRESH")
        return stats
    
    start_date, end_date = date_range
    stats.date_range_start = start_date
    stats.date_range_end = end_date
    
    # Phase 1: Query NVD for CVEs (CONCURRENT)
    logger.info("\n--- PHASE 1: DISCOVERY (CONCURRENT) ---", group="CACHE_REFRESH")
    
    # Full refresh or incremental refresh?
    if start_date is None and end_date is None:
        logger.info(f"Querying NVD for ALL CVEs with {api_workers} concurrent workers", group="CACHE_REFRESH")
        vulnerabilities = query_nvd_cves_all_concurrent(api_key, max_workers=api_workers)
    else:
        logger.info(f"Querying NVD for CVEs modified since {start_date.strftime('%Y-%m-%d')} with {api_workers} concurrent workers", group="CACHE_REFRESH")
        vulnerabilities = query_nvd_cves_by_modified_date_concurrent(start_date, end_date, api_key, max_workers=api_workers)
    stats.total_cves_found = len(vulnerabilities)
    stats.api_calls = (len(vulnerabilities) + 1999) // 2000 if vulnerabilities else 1
    
    if not vulnerabilities:
        if stats.total_cves_found == 0:
            logger.info("Cache is up to date - no changes detected", group="CACHE_REFRESH")
        else:
            logger.warning("No CVE records retrieved - check errors", group="CACHE_REFRESH")
        return stats
    
    # Phase 2: Pre-load schema and process CVEs
    logger.info("\n--- PHASE 2: VALIDATION & UPDATE ---", group="CACHE_REFRESH")
    logger.info("Pre-loading NVD CVE 2.0 schema for batch validation", group="CACHE_REFRESH")
    try:
        nvd_schema = load_schema('nvd_cves_2_0')
        logger.info("Schema loaded - will validate all CVEs before caching", group="CACHE_REFRESH")
    except Exception as e:
        logger.error(f"Failed to load schema: {e} - Proceeding without validation", group="CACHE_REFRESH")
        nvd_schema = None
        stats.errors.append(f"Schema load failed: {str(e)[:100]}")
    
    logger.info(f"Processing {len(vulnerabilities):,} CVEs", group="CACHE_REFRESH")
    process_api_page(vulnerabilities, nvd_schema, stats, page_num=1, total_pages=1, max_workers=max_workers)
    
    # Phase 3: Finalize
    logger.info("\n--- PHASE 3: FINALIZE ---", group="CACHE_REFRESH")
    try:
        nvd_config = _get_cached_config('nvd_2_0_cve')
        nvd_repo_path = nvd_config.get('path', 'cache/nvd_2.0_cves')
        _update_cache_metadata('nvd_2_0_cve', nvd_repo_path)
        logger.info("Cache metadata updated with refresh timestamp", group="CACHE_REFRESH")
    except Exception as e:
        logger.warning(f"Failed to update cache metadata: {e}", group="CACHE_REFRESH")
        stats.errors.append(f"Metadata update failed: {str(e)[:100]}")
    
    # Update lastManualUpdate timestamp for manual refresh tracking
    try:
        _update_manual_refresh_timestamp('nvd_2_0_cve')
        logger.info("NVD CVE cache lastManualUpdate timestamp updated", group="CACHE_REFRESH")
    except Exception as e:
        logger.warning(f"Failed to update lastManualUpdate timestamp: {e}", group="CACHE_REFRESH")
        stats.errors.append(f"Manual timestamp update failed: {str(e)[:100]}")
    
    return stats


def main():
    """Entry point for NVD CVE cache refresh utility"""
    parser = argparse.ArgumentParser(
        description='Refresh NVD CVE cache based on detected changes (recommended: use --auto)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect from cache metadata (RECOMMENDED - default)
  python -m utilities.refresh_nvd_cves_2_0_cache
  python -m utilities.refresh_nvd_cves_2_0_cache --auto
  
  # Complete database refresh (proactive cache population)
  python -m utilities.refresh_nvd_cves_2_0_cache --full-refresh
  
  # Manual date range for testing/recovery
  python -m utilities.refresh_nvd_cves_2_0_cache --days 30
  python -m utilities.refresh_nvd_cves_2_0_cache --start-date 2024-01-01 --end-date 2024-01-31

Note: Default behavior is --auto (query from last cache update).
      Use --full-refresh for complete proactive cache population.
      Manual ranges (--days or --start-date/--end-date) are for testing/recovery only.
        """
    )
    
    # Date range options (mutually exclusive)
    date_group = parser.add_mutually_exclusive_group()
    date_group.add_argument(
        '--auto',
        action='store_true',
        help='Auto-detect from cache metadata (DEFAULT - refresh since last update)'
    )
    date_group.add_argument(
        '--days',
        type=int,
        metavar='N',
        help='Refresh CVEs modified in last N days (testing/recovery)'
    )
    date_group.add_argument(
        '--full-refresh',
        action='store_true',
        help='Query entire NVD dataset - complete cache population'
    )
    
    # Manual date range (both required if either specified)
    parser.add_argument(
        '--start-date',
        metavar='YYYY-MM-DD',
        help='Start date for refresh (requires --end-date, testing/recovery)'
    )
    parser.add_argument(
        '--end-date',
        metavar='YYYY-MM-DD',
        help='End date for refresh (requires --start-date, testing/recovery)'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=20,
        metavar='N',
        help='Number of parallel workers for processing CVEs (default: 20, range: 1-100)'
    )
    parser.add_argument(
        '--api-workers',
        type=int,
        default=15,
        metavar='N',
        help='Number of concurrent API requests (default: 15, range: 1-25)'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if (args.start_date and not args.end_date) or (args.end_date and not args.start_date):
        parser.error("--start-date and --end-date must be specified together")
    
    # Validate workers range
    if args.workers < 1 or args.workers > 100:
        parser.error("--workers must be between 1 and 100")
    
    # Validate api-workers range
    if args.api_workers < 1 or args.api_workers > 25:
        parser.error("--api-workers must be between 1 and 25")
    
    # Get API key from config
    config = load_config()
    api_key = config.get('defaults', {}).get('default_api_key')
    if not api_key or api_key == "CONFIG_DEFAULT":
        api_key = None
        logger.warning("No API key configured - refresh will be slower", group="CACHE_REFRESH")
    
    # Execute refresh
    try:
        logger.info("Starting NVD CVE cache refresh", group="CACHE_REFRESH")
        stats = smart_refresh(api_key, args, max_workers=args.workers, api_workers=args.api_workers)
        
        # Print final report
        print(stats.report())
        
        # Return exit code based on results
        if stats.errors and stats.cves_cached == 0:
            logger.error("Refresh failed - no CVEs were cached", group="CACHE_REFRESH")
            return 1
        elif stats.errors:
            logger.warning(f"Refresh completed with {len(stats.errors)} errors", group="CACHE_REFRESH")
            return 0  # Partial success
        else:
            logger.info("Cache refresh completed successfully", group="CACHE_REFRESH")
            return 0
        
    except KeyboardInterrupt:
        logger.warning("\nRefresh interrupted by user", group="CACHE_REFRESH")
        return 1
    except Exception as e:
        logger.error(f"Refresh failed: {e}", group="CACHE_REFRESH")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
