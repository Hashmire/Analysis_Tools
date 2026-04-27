#!/usr/bin/env python3
"""
CVE List V5 Cache Refresh Utility

Refreshes CVE List V5 cache by querying GitHub deltaLog.json for recent changes.
Uses CVE Project's change tracking to efficiently identify and refresh only modified CVEs.

Usage:
    # Auto-detect from cache metadata (recommended)
    python -m utilities.refresh_cve_cvelist_5_2_cache
    
    # Force refresh of last N days regardless of cache state
    python -m utilities.refresh_cve_cvelist_5_2_cache --days 7
"""

import sys
import argparse
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from src.analysis_tool.logging.workflow_logger import get_logger
from src.analysis_tool.storage.run_organization import get_analysis_tools_root
from src.analysis_tool.core.gatherData import (
    _update_cache_metadata,
    _update_manual_refresh_timestamp,
    _resolve_cve_cache_file_path,
    _refresh_cvelist_from_mitre_api,
    load_schema,
    TOOLNAME,
    VERSION,
    config
)

logger = get_logger()

# CVE Project deltaLog.json URL
DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/deltaLog.json"


class CVEListRefreshStats:
    """Track refresh operation statistics"""
    
    def __init__(self):
        self.start_time = datetime.now(timezone.utc)
        self.cutoff_date: Optional[datetime] = None
        self.delta_log_entries: int = 0
        self.cves_in_range: int = 0
        self.cves_checked: int = 0
        self.cves_current: int = 0
        self.cves_added: int = 0
        self.cves_updated: int = 0
        self.error_count: int = 0
        self.errors: List[str] = []
    
    def report(self) -> str:
        """Generate human-readable statistics report"""
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        
        lines = [
            "\n" + "="*80,
            "CVE LIST V5 CACHE REFRESH SUMMARY",
            "="*80,
            f"Cutoff date:               {self.cutoff_date.strftime('%Y-%m-%d %H:%M:%S %Z') if self.cutoff_date else 'N/A'}",
            f"DeltaLog entries found:    {self.delta_log_entries:,}",
            f"CVEs in date range:        {self.cves_in_range:,}",
            f"CVEs processed:              {self.cves_checked:,}",
            f"  - Errors:                    {self.error_count:,}",
            f"  - Added:                {self.cves_added:,}",
            f"  - Updated:              {self.cves_updated:,}",
            f"  - Current:              {self.cves_current:,}",
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


def fetch_delta_log() -> Optional[Dict[str, Any]]:
    """
    Fetch deltaLog.json from CVE Project GitHub repository.
    
    Returns:
        Parsed deltaLog.json data or None on failure
    """
    try:
        logger.info(f"Fetching deltaLog.json from CVE Project repository...", group="CACHE_MANAGEMENT")
        headers = {
            "Accept": "application/json",
            "User-Agent": f"{TOOLNAME}/{VERSION}"
        }
        
        response = requests.get(DELTA_LOG_URL, headers=headers, timeout=30)
        response.raise_for_status()
        
        delta_log = response.json()
        logger.info(f"Successfully fetched deltaLog.json", group="CACHE_MANAGEMENT")
        return delta_log
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch deltaLog.json: {e}", group="CACHE_MANAGEMENT")
        return None
    except Exception as e:
        logger.error(f"Error parsing deltaLog.json: {e}", group="CACHE_MANAGEMENT")
        return None


def determine_cutoff_date(args) -> Optional[datetime]:
    """
    Determine refresh cutoff date from CLI arguments or cache metadata.
    
    Args:
        args: Parsed command-line arguments
    
    Returns:
        Cutoff datetime (only refresh CVEs changed after this) or None on failure
    """
    now = datetime.now(timezone.utc)
    
    # Manual days override
    if args.days:
        cutoff = now - timedelta(days=args.days)
        logger.info(f"Cutoff date: {cutoff.strftime('%Y-%m-%d %H:%M:%S %Z')} (last {args.days} days)", group="CACHE_MANAGEMENT")
        return cutoff
    
    # Auto-detect from config.json last_manual_update (default behavior)
    cve_config = config['cache_settings']['cve_list_v5']
    last_manual_update_str = cve_config.get('refresh_strategy', {}).get('last_manual_update')
    if last_manual_update_str:
        try:
            if 'Z' in last_manual_update_str:
                last_manual_update_str = last_manual_update_str.replace('Z', '+00:00')
            elif '+' not in last_manual_update_str and last_manual_update_str.count(':') >= 2:
                last_manual_update_str = last_manual_update_str + '+00:00'
            last_update = datetime.fromisoformat(last_manual_update_str)
            logger.info(f"Config last_manual_update: {last_update.strftime('%Y-%m-%d %H:%M:%S %Z')}", group="CACHE_MANAGEMENT")
            logger.info(f"Cutoff date: {last_update.strftime('%Y-%m-%d %H:%M:%S %Z')} (from config.json)", group="CACHE_MANAGEMENT")
            return last_update
        except ValueError as e:
            logger.warning(f"Could not parse last_manual_update from config: {e}", group="CACHE_MANAGEMENT")
    
    # No valid timestamp in config — default to last 30 days
    cutoff = now - timedelta(days=30)
    logger.warning(f"No last_manual_update in config — defaulting to last 30 days. Run: python -m utilities.refresh_cve_cvelist_5_2_cache --days N to establish a baseline.", group="CACHE_MANAGEMENT")
    logger.info(f"Cutoff date: {cutoff.strftime('%Y-%m-%d %H:%M:%S %Z')} (default 30 days)", group="CACHE_MANAGEMENT")
    return cutoff


def parse_delta_log_for_changes(delta_log: Dict[str, Any], cutoff_date: datetime, stats: CVEListRefreshStats) -> List[str]:
    """
    Parse deltaLog.json to find CVEs changed after cutoff date.
    
    Args:
        delta_log: Parsed deltaLog.json data
        cutoff_date: Only include CVEs changed after this date
        stats: Statistics tracker
    
    Returns:
        List of CVE IDs that need refreshing
    """
    cves_to_refresh = set()

    # DeltaLog structure: Array of batch records, each with:
    #   {fetchTime, numberOfChanges, new: [{cveId, dateUpdated, ...}], updated: [...], error: [...]}
    delta_batches = delta_log if isinstance(delta_log, list) else delta_log.get('cves', [])
    stats.delta_log_entries = len(delta_batches)

    logger.info(f"Parsing {len(delta_batches):,} deltaLog batches...", group="CACHE_MANAGEMENT")

    for batch in delta_batches:
        try:
            fetch_time_str = batch.get('fetchTime')
            if not fetch_time_str:
                continue

            # Batch-level time filter: skip batches entirely older than cutoff
            try:
                ft_str = fetch_time_str.replace('Z', '+00:00') if 'Z' in fetch_time_str else fetch_time_str
                if '+' not in ft_str:
                    ft_str = ft_str + '+00:00'
                fetch_time = datetime.fromisoformat(ft_str)
                if fetch_time <= cutoff_date:
                    continue
            except ValueError:
                continue

            # Process individual CVE entries within this batch
            for cve_entry in batch.get('new', []) + batch.get('updated', []):
                try:
                    cve_id = cve_entry.get('cveId')
                    date_updated = cve_entry.get('dateUpdated')

                    if not cve_id or not date_updated:
                        continue

                    try:
                        date_str = date_updated.replace('Z', '+00:00') if 'Z' in date_updated else date_updated
                        if '+' not in date_str:
                            date_str = date_str + '+00:00'
                        update_datetime = datetime.fromisoformat(date_str)

                        if update_datetime > cutoff_date:
                            cves_to_refresh.add(cve_id)

                    except ValueError as parse_error:
                        logger.debug(f"Failed to parse dateUpdated for {cve_id}: {date_updated}", group="CACHE_MANAGEMENT")
                        continue

                except Exception as cve_error:
                    logger.debug(f"Error parsing CVE entry in deltaLog batch: {cve_error}", group="CACHE_MANAGEMENT")
                    continue

        except Exception as batch_error:
            logger.debug(f"Error parsing deltaLog batch: {batch_error}", group="CACHE_MANAGEMENT")
            continue

    stats.cves_in_range = len(cves_to_refresh)
    logger.info(f"Found {len(cves_to_refresh):,} CVEs modified since cutoff date", group="CACHE_MANAGEMENT")

    return sorted(cves_to_refresh)


def _process_single_cve_v5(
    cve_id: str,
    cve_repo_path: str,
    cache_ttl_hours: float,
    cve_schema: Any
) -> Tuple[str, str]:
    """
    Process a single CVE record (thread-safe worker function).

    Returns (cve_id, status) where status is one of:
        'current'  — within TTL, no refresh needed
        'added'    — new file written
        'updated'  — existing file refreshed
        'error'    — path resolution failed or refresh failed (logged inside refresh function)
    """
    try:
        cve_file_path = _resolve_cve_cache_file_path(cve_id, cve_repo_path)
        if not cve_file_path:
            return cve_id, "error"

        file_existed = cve_file_path.exists()

        if file_existed:
            file_age_hours = (
                datetime.now(timezone.utc)
                - datetime.fromtimestamp(cve_file_path.stat().st_mtime, tz=timezone.utc)
            ).total_seconds() / 3600
            if file_age_hours < cache_ttl_hours:
                return cve_id, "current"

        success = _refresh_cvelist_from_mitre_api(
            cve_id,
            cve_file_path,
            refresh_reason="deltaLog change detected",
            cve_schema=cve_schema,
            update_metadata=False,
        )
        if not success:
            return cve_id, "error"
        return cve_id, "updated" if file_existed else "added"
    except Exception as e:
        logger.warning(f"CVE 5.x  {cve_id:<20} ERROR (unexpected: {str(e)[:80]})", group="CACHE_MANAGEMENT")
        return cve_id, "error"


def smart_refresh(args=None, max_workers: int = 20):
    """
    Main refresh orchestration: fetch deltaLog, identify changes, refresh stale caches.

    Phase 1: Discovery - Fetch deltaLog and identify changed CVEs
    Phase 2: Validation & Update - Check staleness and refresh as needed (TTL-based, parallel)
    Phase 3: Finalize - Update metadata

    Args:
        args: Parsed command-line arguments
        max_workers: Number of parallel workers for CVE fetching (default: 20)

    Returns:
        CVEListRefreshStats object with operation results
    """
    stats = CVEListRefreshStats()
    
    # Get CVE List V5 config
    cve_config = config['cache_settings']['cve_list_v5']
    if not cve_config:
        logger.error("Failed to load CVE List V5 config - cannot proceed", group="CACHE_MANAGEMENT")
        return stats

    cve_repo_path = cve_config.get('path')
    if not cve_repo_path:
        logger.error("CVE List V5 config missing required 'path' key - cannot proceed", group="CACHE_MANAGEMENT")
        return stats

    refresh_strategy = cve_config.get('refresh_strategy', {})
    cache_ttl_hours = refresh_strategy.get('notify_age_hours')
    if cache_ttl_hours is None:
        logger.error("CVE List V5 config missing required 'refresh_strategy.notify_age_hours' key - cannot proceed", group="CACHE_MANAGEMENT")
        return stats
    
    # Determine cutoff date
    cutoff_date = determine_cutoff_date(args)
    if not cutoff_date:
        logger.error("Failed to determine cutoff date - cannot proceed", group="CACHE_MANAGEMENT")
        return stats
    
    stats.cutoff_date = cutoff_date
    
    # Phase 1: Fetch deltaLog and identify changed CVEs
    logger.info("\n--- PHASE 1: DISCOVERY ---", group="CACHE_MANAGEMENT")
    delta_log = fetch_delta_log()
    if not delta_log:
        logger.error("Failed to fetch deltaLog.json - cannot proceed", group="CACHE_MANAGEMENT")
        return stats
    
    cves_to_check = parse_delta_log_for_changes(delta_log, cutoff_date, stats)
    if not cves_to_check:
        logger.info("No CVE changes detected since cutoff date - cache is up to date", group="CACHE_MANAGEMENT")
        return stats
    
    # Phase 2: Check staleness and refresh as needed
    logger.info("\n--- PHASE 2: VALIDATION & UPDATE ---", group="CACHE_MANAGEMENT")
    logger.info("Pre-loading CVE List V5 schema for batch validation", group="CACHE_MANAGEMENT")
    try:
        cve_schema = load_schema('cve_cve_5_2')
        logger.info("Schema loaded - will validate all CVEs before caching", group="CACHE_MANAGEMENT")
    except Exception as e:
        logger.error(f"Failed to load schema: {e} - Proceeding without validation", group="CACHE_MANAGEMENT")
        cve_schema = None
        stats.errors.append(f"Schema load failed: {str(e)[:100]}")
    
    logger.info(f"{len(cves_to_check)} CVE List v5 records require cache operations", group="CACHE_MANAGEMENT")

    stats_lock = threading.Lock()

    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        futures = {
            executor.submit(_process_single_cve_v5, cve_id, cve_repo_path, cache_ttl_hours, cve_schema): cve_id
            for cve_id in cves_to_check
        }

        for future in as_completed(futures):
            try:
                cve_id, status = future.result()
                with stats_lock:
                    stats.cves_checked += 1
                    if status == "current":
                        stats.cves_current += 1
                    elif status == "added":
                        stats.cves_added += 1
                    elif status == "updated":
                        stats.cves_updated += 1
                    else:  # error
                        stats.error_count += 1
                        stats.errors.append(f"Refresh failed for {cve_id}")
            except Exception as e:
                cve_id = futures[future]
                with stats_lock:
                    stats.cves_checked += 1
                    stats.error_count += 1
                    stats.errors.append(f"Processing error for {cve_id}: {str(e)[:100]}")
                logger.warning(f"CVE 5.x  {cve_id:<20} ERROR (unexpected: {str(e)[:80]})", group="CACHE_MANAGEMENT")
    except KeyboardInterrupt:
        logger.warning("Interrupt received — cancelling pending CVE workers...", group="CACHE_MANAGEMENT")
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        executor.shutdown(wait=False)
    
    # Phase 3: Finalize
    logger.info("\n--- PHASE 3: FINALIZE ---", group="CACHE_MANAGEMENT")
    
    # Update cache metadata
    if stats.cves_added + stats.cves_updated > 0:
        try:
            _update_cache_metadata('cve_list_v5', cve_repo_path)
            logger.info("Cache metadata updated with refresh timestamp", group="CACHE_MANAGEMENT")
        except Exception as e:
            logger.warning(f"Failed to update cache metadata: {e}", group="CACHE_MANAGEMENT")
            stats.errors.append(f"Metadata update failed: {str(e)[:100]}")
        
        # Update lastManualUpdate timestamp for manual refresh tracking
        try:
            _update_manual_refresh_timestamp('cve_list_v5')
            logger.info("CVE List V5 cache lastManualUpdate timestamp updated", group="CACHE_MANAGEMENT")
        except Exception as e:
            logger.warning(f"Failed to update lastManualUpdate timestamp: {e}", group="CACHE_MANAGEMENT")
            stats.errors.append(f"Manual timestamp update failed: {str(e)[:100]}")
    else:
        logger.info("No CVEs refreshed - metadata unchanged", group="CACHE_MANAGEMENT")
    
    return stats


def main():
    """Entry point for CVE List V5 cache refresh utility"""
    parser = argparse.ArgumentParser(
        description='Refresh CVE List V5 cache using GitHub deltaLog.json change tracking',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect from cache metadata (RECOMMENDED - default)
  python -m utilities.refresh_cve_cvelist_5_2_cache
  
  # Force refresh of last N days regardless of cache state
  python -m utilities.refresh_cve_cvelist_5_2_cache --days 30

Note: Default behavior queries deltaLog.json for changes since last manual update,
      then checks cache staleness (TTL) before refreshing individual CVEs.
      This ensures efficient refresh of only truly stale data.
        """
    )
    
    parser.add_argument(
        '--days',
        type=int,
        metavar='N',
        help='Force refresh of CVEs changed in last N days (overrides cache metadata)'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=20,
        metavar='N',
        help='Number of parallel workers for CVE fetching (default: 20)'
    )

    args = parser.parse_args()
    
    # Display banner
    logger.info("="*80, group="CACHE_MANAGEMENT")
    logger.info("CVE List V5 Cache Refresh Utility", group="CACHE_MANAGEMENT")
    logger.info("="*80, group="CACHE_MANAGEMENT")
    
    # Run refresh
    stats = smart_refresh(args, max_workers=args.workers)
    
    # Display results
    print(stats.report())
    
    # Exit with appropriate code
    if stats.error_count > 0 and stats.cves_added == 0 and stats.cves_updated == 0:
        logger.error("Refresh failed - no CVEs were successfully updated", group="CACHE_MANAGEMENT")
        return 1
    elif stats.error_count > 0:
        logger.warning(f"Refresh completed with {stats.error_count} errors", group="CACHE_MANAGEMENT")
        return 0  # Partial success
    else:
        logger.info("Refresh completed successfully", group="CACHE_MANAGEMENT")
        return 0


if __name__ == "__main__":
    sys.exit(main())
