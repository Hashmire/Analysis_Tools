#!/usr/bin/env python3
"""
CVE List V5 Cache Refresh Utility

Refreshes CVE List V5 cache by querying GitHub deltaLog.json for recent changes.
Uses CVE Project's change tracking to efficiently identify and refresh only modified CVEs.

Usage:
    # Auto-detect from cache metadata (recommended)
    python -m utilities.refresh_cve_list_v5_cache
    
    # Force refresh of last N days regardless of cache state
    python -m utilities.refresh_cve_list_v5_cache --days 7
"""

import sys
import argparse
import requests
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.analysis_tool.logging.workflow_logger import get_logger
from src.analysis_tool.storage.run_organization import get_analysis_tools_root
from src.analysis_tool.core.analysis_tool import load_config
from src.analysis_tool.core.gatherData import (
    _get_cached_config,
    _update_cache_metadata,
    _update_manual_refresh_timestamp,
    _get_cache_metadata_last_update,
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
        self.cves_skipped_fresh: int = 0
        self.cves_refreshed: int = 0
        self.refresh_failures: int = 0
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
            f"CVEs checked:              {self.cves_checked:,}",
            f"CVEs skipped (fresh):      {self.cves_skipped_fresh:,}",
            f"CVEs refreshed:            {self.cves_refreshed:,}",
            f"Refresh failures:          {self.refresh_failures:,}",
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
        logger.info(f"Fetching deltaLog.json from CVE Project repository...", group="CACHE_REFRESH")
        headers = {
            "Accept": "application/json",
            "User-Agent": f"{TOOLNAME}/{VERSION}"
        }
        
        response = requests.get(DELTA_LOG_URL, headers=headers, timeout=30)
        response.raise_for_status()
        
        delta_log = response.json()
        logger.info(f"Successfully fetched deltaLog.json", group="CACHE_REFRESH")
        return delta_log
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch deltaLog.json: {e}", group="CACHE_REFRESH")
        return None
    except Exception as e:
        logger.error(f"Error parsing deltaLog.json: {e}", group="CACHE_REFRESH")
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
        logger.info(f"Cutoff date: {cutoff.strftime('%Y-%m-%d %H:%M:%S %Z')} (last {args.days} days)", group="CACHE_REFRESH")
        return cutoff
    
    # Auto-detect from cache metadata (default behavior)
    last_update = _get_cache_metadata_last_update('cve_list_v5')
    if last_update:
        logger.info(f"Cache metadata shows last update: {last_update.strftime('%Y-%m-%d %H:%M:%S %Z')}", group="CACHE_REFRESH")
        logger.info(f"Cutoff date: {last_update.strftime('%Y-%m-%d %H:%M:%S %Z')} (from cache metadata)", group="CACHE_REFRESH")
        return last_update
    else:
        # No cache metadata - default to last 30 days
        cutoff = now - timedelta(days=30)
        logger.warning(f"No cache metadata found - defaulting to last 30 days", group="CACHE_REFRESH")
        logger.info(f"Cutoff date: {cutoff.strftime('%Y-%m-%d %H:%M:%S %Z')} (default 30 days)", group="CACHE_REFRESH")
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
    
    # DeltaLog structure: Array of objects with {cveId, state, dateUpdated, dateReserved, ...}
    delta_entries = delta_log if isinstance(delta_log, list) else delta_log.get('cves', [])
    stats.delta_log_entries = len(delta_entries)
    
    logger.info(f"Parsing {len(delta_entries):,} deltaLog entries...", group="CACHE_REFRESH")
    
    for entry in delta_entries:
        try:
            cve_id = entry.get('cveId')
            date_updated = entry.get('dateUpdated')
            
            if not cve_id or not date_updated:
                continue
            
            # Parse dateUpdated timestamp
            try:
                if 'Z' in date_updated:
                    date_str = date_updated.replace('Z', '+00:00')
                elif '+' not in date_updated:
                    date_str = date_updated + '+00:00'
                else:
                    date_str = date_updated
                
                update_datetime = datetime.fromisoformat(date_str)
                
                # Check if updated after cutoff
                if update_datetime > cutoff_date:
                    cves_to_refresh.add(cve_id)
                    
            except ValueError as parse_error:
                logger.debug(f"Failed to parse dateUpdated for {cve_id}: {date_updated}", group="CACHE_REFRESH")
                continue
                
        except Exception as entry_error:
            logger.debug(f"Error parsing deltaLog entry: {entry_error}", group="CACHE_REFRESH")
            continue
    
    stats.cves_in_range = len(cves_to_refresh)
    logger.info(f"Found {len(cves_to_refresh):,} CVEs modified since cutoff date", group="CACHE_REFRESH")
    
    return sorted(cves_to_refresh)


def smart_refresh(args=None):
    """
    Main refresh orchestration: fetch deltaLog, identify changes, refresh stale caches.
    
    Phase 1: Discovery - Fetch deltaLog and identify changed CVEs
    Phase 2: Validation & Update - Check staleness and refresh as needed (TTL-based)
    Phase 3: Finalize - Update metadata
    
    Args:
        args: Parsed command-line arguments
    
    Returns:
        CVEListRefreshStats object with operation results
    """
    stats = CVEListRefreshStats()
    
    # Get CVE List V5 config
    cve_config = _get_cached_config('cve_list_v5')
    if not cve_config.get('enabled', False):
        logger.warning("CVE List V5 cache is disabled in config - exiting", group="CACHE_REFRESH")
        return stats
    
    if cve_config.get('manual_sync_only', False):
        logger.warning("CVE List V5 is set to manual_sync_only - this refresh script is the manual sync", group="CACHE_REFRESH")
    
    cve_repo_path = cve_config.get('path', 'cache/cve_list_v5')
    cache_ttl_hours = cve_config.get('refresh_strategy', {}).get('notify_age_hours', 720)
    
    # Determine cutoff date
    cutoff_date = determine_cutoff_date(args)
    if not cutoff_date:
        logger.error("Failed to determine cutoff date - cannot proceed", group="CACHE_REFRESH")
        return stats
    
    stats.cutoff_date = cutoff_date
    
    # Phase 1: Fetch deltaLog and identify changed CVEs
    logger.info("\n--- PHASE 1: DISCOVERY ---", group="CACHE_REFRESH")
    delta_log = fetch_delta_log()
    if not delta_log:
        logger.error("Failed to fetch deltaLog.json - cannot proceed", group="CACHE_REFRESH")
        return stats
    
    cves_to_check = parse_delta_log_for_changes(delta_log, cutoff_date, stats)
    if not cves_to_check:
        logger.info("No CVE changes detected since cutoff date - cache is up to date", group="CACHE_REFRESH")
        return stats
    
    # Phase 2: Check staleness and refresh as needed
    logger.info("\n--- PHASE 2: VALIDATION & UPDATE ---", group="CACHE_REFRESH")
    logger.info("Pre-loading CVE List V5 schema for batch validation", group="CACHE_REFRESH")
    try:
        cve_schema = load_schema('cve_cve_5_2')
        logger.info("Schema loaded - will validate all CVEs before caching", group="CACHE_REFRESH")
    except Exception as e:
        logger.error(f"Failed to load schema: {e} - Proceeding without validation", group="CACHE_REFRESH")
        cve_schema = None
        stats.errors.append(f"Schema load failed: {str(e)[:100]}")
    
    logger.info(f"Checking {len(cves_to_check):,} CVEs for staleness (TTL: {cache_ttl_hours}h)", group="CACHE_REFRESH")
    
    for cve_id in cves_to_check:
        try:
            stats.cves_checked += 1
            
            # Resolve cache file path
            cve_file_path = _resolve_cve_cache_file_path(cve_id, cve_repo_path)
            if not cve_file_path:
                logger.debug(f"Path resolution failed for {cve_id} - skipping", group="CACHE_REFRESH")
                continue
            
            should_refresh = False
            
            if cve_file_path.exists():
                # TTL-based staleness check
                file_modified_time = datetime.fromtimestamp(cve_file_path.stat().st_mtime, tz=timezone.utc)
                file_age_hours = (datetime.now(timezone.utc) - file_modified_time).total_seconds() / 3600
                
                if file_age_hours < cache_ttl_hours:
                    # Fresh cache - skip refresh
                    stats.cves_skipped_fresh += 1
                    if stats.cves_skipped_fresh % 100 == 0:
                        logger.info(f"Progress: {stats.cves_checked}/{len(cves_to_check)} checked, {stats.cves_skipped_fresh} fresh, {stats.cves_refreshed} refreshed", group="CACHE_REFRESH")
                    continue
                else:
                    should_refresh = True
            else:
                # Missing cache file
                should_refresh = True
            
            # Refresh from MITRE API
            if should_refresh:
                try:
                    _refresh_cvelist_from_mitre_api(
                        cve_id,
                        cve_file_path,
                        refresh_reason="deltaLog change detected",
                        cve_schema=cve_schema,
                        update_metadata=False  # Disable per-file updates, will update once at end
                    )
                    stats.cves_refreshed += 1
                    
                    if stats.cves_refreshed % 50 == 0:
                        logger.info(f"Progress: {stats.cves_checked}/{len(cves_to_check)} checked, {stats.cves_refreshed} refreshed", group="CACHE_REFRESH")
                        
                except Exception as refresh_error:
                    stats.refresh_failures += 1
                    logger.warning(f"Refresh failed for {cve_id}: {refresh_error}", group="CACHE_REFRESH")
                    stats.errors.append(f"Refresh failed for {cve_id}: {str(refresh_error)[:100]}")
                    
        except Exception as e:
            logger.debug(f"Error processing {cve_id}: {e}", group="CACHE_REFRESH")
            stats.errors.append(f"Processing error for {cve_id}: {str(e)[:100]}")
    
    # Phase 3: Finalize
    logger.info("\n--- PHASE 3: FINALIZE ---", group="CACHE_REFRESH")
    
    # Update cache metadata
    if stats.cves_refreshed > 0:
        try:
            _update_cache_metadata('cve_list_v5', cve_repo_path)
            logger.info("Cache metadata updated with refresh timestamp", group="CACHE_REFRESH")
        except Exception as e:
            logger.warning(f"Failed to update cache metadata: {e}", group="CACHE_REFRESH")
            stats.errors.append(f"Metadata update failed: {str(e)[:100]}")
        
        # Update lastManualUpdate timestamp for manual refresh tracking
        try:
            _update_manual_refresh_timestamp('cve_list_v5')
            logger.info("CVE List V5 cache lastManualUpdate timestamp updated", group="CACHE_REFRESH")
        except Exception as e:
            logger.warning(f"Failed to update lastManualUpdate timestamp: {e}", group="CACHE_REFRESH")
            stats.errors.append(f"Manual timestamp update failed: {str(e)[:100]}")
    else:
        logger.info("No CVEs refreshed - metadata unchanged", group="CACHE_REFRESH")
    
    return stats


def main():
    """Entry point for CVE List V5 cache refresh utility"""
    parser = argparse.ArgumentParser(
        description='Refresh CVE List V5 cache using GitHub deltaLog.json change tracking',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect from cache metadata (RECOMMENDED - default)
  python -m utilities.refresh_cve_list_v5_cache
  
  # Force refresh of last N days regardless of cache state
  python -m utilities.refresh_cve_list_v5_cache --days 30

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
    
    args = parser.parse_args()
    
    # Display banner
    logger.info("="*80, group="CACHE_REFRESH")
    logger.info("CVE List V5 Cache Refresh Utility", group="CACHE_REFRESH")
    logger.info("="*80, group="CACHE_REFRESH")
    
    # Run refresh
    stats = smart_refresh(args)
    
    # Display results
    print(stats.report())
    
    # Exit with appropriate code
    if stats.refresh_failures > 0 and stats.cves_refreshed == 0:
        logger.error("Refresh failed - no CVEs were successfully updated", group="CACHE_REFRESH")
        return 1
    elif stats.refresh_failures > 0:
        logger.warning(f"Refresh completed with {stats.refresh_failures} failures", group="CACHE_REFRESH")
        return 0  # Partial success
    else:
        logger.info("Refresh completed successfully", group="CACHE_REFRESH")
        return 0


if __name__ == "__main__":
    sys.exit(main())
