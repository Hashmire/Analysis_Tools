#!/usr/bin/env python3
"""
NVD CVE Dataset Generator
This script queries the NVD API for CVEs with specific vulnerability statuses
and generates a file with one CVE ID per line for use with analysis_tool.py

Enhanced with tracking capabilities and integration with the enhanced dataset generator.
"""

import requests
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from time import sleep
import argparse
from pathlib import Path
import uuid
from src.analysis_tool.logging.workflow_logger import get_logger

def get_analysis_tools_root():
    """Get the absolute path to the Analysis_Tools project root"""
    current_file = Path(__file__).resolve()
    # Navigate up from generate_dataset.py to Analysis_Tools/
    return current_file.parent

def validate_uuid(uuid_string):
    """Validate that a string is a proper UUID format"""
    try:
        uuid.UUID(uuid_string)
        return True
    except ValueError:
        return False

def resolve_output_path(output_file, run_directory=None):
    """Resolve output file path - write to run directory if provided, otherwise use absolute path"""
    if os.path.isabs(output_file):
        return Path(output_file)
    elif run_directory:
        # Write directly to logs directory (consolidated storage)
        logs_dir = run_directory / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        return logs_dir / output_file
    else:
        # No run directory provided - fail fast
        raise RuntimeError("Run directory required for dataset generation - standalone usage not supported")

# Load configuration
def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'src', 'analysis_tool', 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)

config = load_config()
VERSION = config['application']['version']
TOOLNAME = config['application']['toolname']

# Get global logger instance (shared with analysis_tool)
logger = get_logger()

# Global batch processing for cache updates
_cache_batch = {
    'nvd_updates': [],
    'cve_list_updates': [],
    'batch_size': 100
}

# Cache for config lookups (loaded once per session)
_config_cache = {}

def _get_cached_config(cache_type):
    """Get cache config with session-level caching to avoid repeated file reads"""
    if cache_type not in _config_cache:
        from src.analysis_tool.core.gatherData import get_cache_config
        _config_cache[cache_type] = get_cache_config(cache_type)
    return _config_cache[cache_type]

def _flush_cache_batches():
    """Process all pending cache updates in batches"""
    _flush_nvd_cache_batch()
    _flush_cve_list_cache_batch()

def _flush_cve_list_cache_batch():
    """Process queued CVE List V5 cache updates in batch"""
    if not _cache_batch['cve_list_updates']:
        return
    
    from src.analysis_tool.core.gatherData import _update_cache_metadata
    import requests
    
    batch = _cache_batch['cve_list_updates']
    _cache_batch['cve_list_updates'] = []
    
    repo_paths = set()
    
    for item in batch:
        try:
            # Fetch CVE List V5 record from MITRE API
            cve_org_url = config['api']['endpoints']['cve_list']
            simple_cve_request_url = cve_org_url + item['cve_id']
            
            response = requests.get(simple_cve_request_url, timeout=config['api']['timeouts']['cve_org'])
            response.raise_for_status()
            cve_record_data = response.json()
            
            # Ensure directory exists
            item['file_path'].parent.mkdir(parents=True, exist_ok=True)
            
            # Write with pretty formatting
            with open(item['file_path'], 'w', encoding='utf-8') as f:
                json.dump(cve_record_data, f, indent=2)
            
            repo_paths.add(item['repo_path'])
            logger.debug(f"CVE List v5 local cache updated for {item['cve_id']}", group="CACHE_MANAGEMENT")
            
        except Exception as e:
            logger.debug(f"CVE List v5 local cache update failed for {item['cve_id']}: {e}", group="CACHE_MANAGEMENT")
    
    # Update metadata once per batch
    for repo_path in repo_paths:
        try:
            _update_cache_metadata('cve_list_v5', repo_path)
        except Exception as e:
            logger.debug(f"Cache metadata update failed (CVE List v5): {e}", group="CACHE_MANAGEMENT")
    
    if batch:
        logger.info(f"Batch processed {len(batch)} CVE List v5 local cache updates", group="CACHE_MANAGEMENT")

def _flush_nvd_cache_batch():
    """Process queued NVD cache updates in batch"""
    if not _cache_batch['nvd_updates']:
        return
    
    from src.analysis_tool.core.gatherData import _update_cache_metadata
    from datetime import datetime
    
    batch = _cache_batch['nvd_updates']
    _cache_batch['nvd_updates'] = []
    
    repo_paths = set()
    
    for item in batch:
        try:
            # Ensure directory exists
            item['file_path'].parent.mkdir(parents=True, exist_ok=True)
            
            # Create NVD API response format
            nvd_response_data = {
                "resultsPerPage": 1,
                "startIndex": 0,
                "totalResults": 1,
                "format": "NVD_CVE", 
                "version": "2.0",
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "vulnerabilities": [item['vulnerability_record']]
            }
            
            # Write with pretty formatting
            with open(item['file_path'], 'w', encoding='utf-8') as f:
                json.dump(nvd_response_data, f, indent=2)
            
            repo_paths.add(item['repo_path'])
            logger.debug(f"NVD 2.0 local cache updated for {item['cve_id']}", group="CACHE_MANAGEMENT")
            
        except Exception as e:
            logger.debug(f"NVD 2.0 local cache update failed for {item['cve_id']}: {e}", group="CACHE_MANAGEMENT")
    
    # Update metadata once per batch
    for repo_path in repo_paths:
        try:
            _update_cache_metadata('nvd_2_0_cve', repo_path)
        except Exception as e:
            logger.debug(f"Cache metadata update failed (NVD 2.0): {e}", group="CACHE_MANAGEMENT")
    
    if batch:
        logger.info(f"Batch processed {len(batch)} NVD 2.0 local cache updates", group="CACHE_MANAGEMENT")

def _save_nvd_cve_to_cache_during_bulk_generation(cve_id, vulnerability_record):
    """
    Queue NVD CVE record for batch cache update during bulk dataset generation.
    Only updates cache if API data is newer than existing cached data.
    """
    try:
        # Import cache functions (delayed import to avoid circular dependencies)
        from src.analysis_tool.core.gatherData import _resolve_cve_cache_file_path
        from datetime import datetime
        
        nvd_config = _get_cached_config('nvd_2_0_cve')
        if not nvd_config.get('enabled', False):
            return False
            
        # Use 'cache/nvd_2.0_cves' as default path (parallel to cve_list_v5)
        nvd_repo_path = nvd_config.get('path', 'cache/nvd_2.0_cves')
        
        nvd_file_path = _resolve_cve_cache_file_path(cve_id, nvd_repo_path)
        if not nvd_file_path:
            return False
        
        # Extract API lastModified timestamp
        api_last_modified = vulnerability_record.get('cve', {}).get('lastModified')
        if not api_last_modified:
            logger.warning(f"NVD 2.0 local cache missing lastModified for {cve_id} - No Action", group="CACHE_MANAGEMENT")
            return False
        
        # Parse API timestamp
        try:
            if 'Z' in api_last_modified:
                api_datetime_str = api_last_modified.replace('Z', '+00:00')
            elif '+' not in api_last_modified and api_last_modified.count(':') >= 2:
                api_datetime_str = api_last_modified + '+00:00'
            else:
                api_datetime_str = api_last_modified
            api_datetime = datetime.fromisoformat(api_datetime_str)
        except ValueError:
            logger.warning(f"NVD 2.0 local cache timestamp parse failed for {cve_id}: {api_last_modified} - No Action", group="CACHE_MANAGEMENT")
            return False
            
        # Check if file exists and compare timestamps
        if nvd_file_path.exists():
            try:
                with open(nvd_file_path, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                
                # Extract cached lastModified timestamp
                cached_vulns = cached_data.get('vulnerabilities', [])
                if cached_vulns:
                    cached_last_modified = cached_vulns[0].get('cve', {}).get('lastModified')
                    if cached_last_modified:
                        # Parse cached timestamp
                        if 'Z' in cached_last_modified:
                            cached_datetime_str = cached_last_modified.replace('Z', '+00:00')
                        elif '+' not in cached_last_modified and cached_last_modified.count(':') >= 2:
                            cached_datetime_str = cached_last_modified + '+00:00'
                        else:
                            cached_datetime_str = cached_last_modified
                        cached_datetime = datetime.fromisoformat(cached_datetime_str)
                        
                        # Compare timestamps - only update if API data is newer
                        if api_datetime <= cached_datetime:
                            logger.debug(f"NVD 2.0 local cache file up-to-date for {cve_id} - No Action", group="CACHE_MANAGEMENT")
                            return False
                        
                        logger.debug(f"NVD 2.0 local cache file stale for {cve_id} - Queued for Update", group="CACHE_MANAGEMENT")
                        
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"NVD 2.0 local cache file corrupted for {cve_id}: {e} - Queued for Update", group="CACHE_MANAGEMENT")
        
        # Queue for batch processing instead of immediate write
        _cache_batch['nvd_updates'].append({
            'cve_id': cve_id,
            'file_path': nvd_file_path,
            'vulnerability_record': vulnerability_record,
            'repo_path': nvd_repo_path
        })
        
        # Process batch if it reaches target size
        if len(_cache_batch['nvd_updates']) >= _cache_batch['batch_size']:
            _flush_nvd_cache_batch()
        
        return True
        
    except Exception as e:
        logger.warning(f"NVD 2.0 local cache update queue failed for {cve_id}: {e}", group="CACHE_MANAGEMENT")
        return False

def _save_cve_list_v5_to_cache_during_bulk_generation(cve_id, nvd_last_modified):
    """
    Queue CVE List V5 record for batch cache update during bulk dataset generation.
    Uses configurable sync behavior - can be disabled via manual_sync_only flag.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-12345")
        nvd_last_modified: lastModified timestamp from NVD API response (used for logging only)
    """
    try:
        # Import cache functions (delayed import to avoid circular dependencies)
        from src.analysis_tool.core.gatherData import _resolve_cve_cache_file_path
        
        cve_config = _get_cached_config('cve_list_v5')
        if not cve_config.get('enabled', False):
            return False
        
        # Check if automatic sync is disabled
        if cve_config.get('manual_sync_only', False):
            logger.debug(f"CVE List v5 local cache automatic sync disabled for {cve_id}  - No Action (Refer to  configuration file `manual_sync_only=true`)", group="CACHE_MANAGEMENT")
            return False
            
        # Use 'cache/cve_list_v5' as default path
        cve_repo_path = cve_config.get('path', 'cache/cve_list_v5')
        
        cve_file_path = _resolve_cve_cache_file_path(cve_id, cve_repo_path)
        if not cve_file_path:
            return False
        
        # Use file modification time + TTL approach (avoids cross-source timestamp comparison issues)
        # Use configured notify_age_hours from cache settings
        cache_ttl_hours = cve_config.get('refresh_strategy', {}).get('notify_age_hours', 168)  # Default to 168 hours (7 days)
        
        if cve_file_path.exists():
            # Check file modification time vs TTL
            file_modified_time = datetime.fromtimestamp(cve_file_path.stat().st_mtime, tz=timezone.utc)
            file_age_hours = (datetime.now(timezone.utc) - file_modified_time).total_seconds() / 3600
            
            if file_age_hours < cache_ttl_hours:
                # File is within TTL - no update needed
                logger.debug(f"CVE List v5 local cache file up-to-date for {cve_id} (age: {file_age_hours:.1f}h < {cache_ttl_hours}h TTL) - No Action", group="CACHE_MANAGEMENT")
                return False
            
            # File is older than TTL - queue for update
            logger.debug(f"CVE List v5 local cache file stale (age: {file_age_hours:.1f}h > {cache_ttl_hours}h TTL) for {cve_id} - Queued for Update", group="CACHE_MANAGEMENT")
        else:
            # File doesn't exist - queue for creation
            logger.debug(f"CVE List v5 local cache file not found for {cve_id} - Queued for Update", group="CACHE_MANAGEMENT")
        
        # Queue for batch processing instead of immediate API call
        _cache_batch['cve_list_updates'].append({
            'cve_id': cve_id,
            'file_path': cve_file_path,
            'repo_path': cve_repo_path
        })
        
        # Process batch if it reaches target size
        if len(_cache_batch['cve_list_updates']) >= _cache_batch['batch_size']:
            _flush_cve_list_cache_batch()
        
        return True
        
    except Exception as e:
        logger.debug(f"CVE List v5 local cache update queue failed for {cve_id}: {e}", group="CACHE_MANAGEMENT")
        return False

def query_nvd_cves_by_status(api_key=None, target_statuses=None, output_file="cve_dataset.txt", run_directory=None, source_uuid=None, statuses_explicitly_provided=False):
    """
    Query NVD API for CVEs with specific vulnerability statuses
    
    Args:
        api_key (str): NVD API key (required for reasonable performance)
        target_statuses (list): List of vulnerability statuses to filter by
                               ['Received', 'Awaiting Analysis', 'Undergoing Analysis']
        output_file (str): Output file path
        run_directory (Path): Run directory where dataset should be written
        source_uuid (str): Optional UUID to filter CVEs by sourceIdentifier (server-side filtering)
        statuses_explicitly_provided (bool): Whether user explicitly provided status filters
    """
    if target_statuses is None:
        target_statuses = ['Received', 'Awaiting Analysis', 'Undergoing Analysis']
    
    logger.info("Starting CVE dataset generation...", group="DATASET")
    if source_uuid and not statuses_explicitly_provided:
        logger.info("Target vulnerability statuses: ALL (inclusive mode with UUID filtering)", group="DATASET")
    else:
        logger.info(f"Target vulnerability statuses: {', '.join(target_statuses)}", group="DATASET")
    if source_uuid:
        logger.info(f"Source UUID filter (server-side): {source_uuid}", group="DATASET")
    logger.info(f"Output file: {output_file}", group="DATASET")
    logger.info(f"Using API key: {'Yes' if api_key else 'No'}", group="DATASET")
    
    # Initialize dataset contents collector
    from src.analysis_tool.logging.dataset_contents_collector import (
        initialize_dataset_contents_report, start_collection_phase, 
        record_api_call, record_output_file, update_cve_discovery_progress
    )
    
    # Initialize collector with run's logs directory
    if run_directory:
        logs_dir = run_directory / "logs"
        logs_dir.mkdir(exist_ok=True)
        initialize_dataset_contents_report(str(logs_dir))
        logger.info("=== CVE Record Cache Preparation ===", group="DATASET")
        start_collection_phase("cache_preparation", "nvd_api")
    
    base_url = config['api']['endpoints']['nvd_cves']
    headers = {
        "Accept": "application/json",
        "User-Agent": f"{TOOLNAME}/{VERSION}"
    }
    
    # Add API key if provided
    if api_key:
        headers["apiKey"] = api_key
    
    # Results per page (max 2000)
    results_per_page = 2000
    start_index = 0
    total_results = 0
    matching_cves = []
    
    logger.info("Starting CVE collection...", group="CVE_QUERY")
    
    while True:
        # Construct URL with pagination and optional UUID filtering
        url = f"{base_url}?resultsPerPage={results_per_page}&startIndex={start_index}"
        if source_uuid:
            url += f"&sourceIdentifier={source_uuid}"
        
        logger.info(f"Processing CVE dataset queries: Starting at index {start_index}...", group="CVE_QUERY")
        
        max_retries = config['api']['retry']['max_attempts_nvd']
        page_data = None
        
        # Retry logic for API calls
        rate_limited = False
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers, timeout=config['api']['timeouts']['nvd_api'])
                response.raise_for_status()
                page_data = response.json()
                break
                
            except requests.exceptions.RequestException as e:
                logger.error(f"NVD CVE data API request failed: Unable to fetch dataset at index {start_index} (Attempt {attempt + 1}/{max_retries}) - {e}", group="data_processing")
                
                if hasattr(e, 'response') and e.response is not None:
                    if 'message' in e.response.headers:                        logger.error(f"NVD API Message: {e.response.headers['message']}", group="data_processing")
                    logger.error(f"Response status code: {e.response.status_code}", group="data_processing")
                    
                    # Check for rate limiting
                    if e.response.status_code == 429:
                        rate_limited = True
                
                if attempt < max_retries - 1:
                    wait_time = config['api']['retry']['delay_without_key'] if not api_key else config['api']['retry']['delay_with_key']
                    logger.info(f"Waiting {wait_time} seconds before retry...", group="CVE_QUERY")
                    sleep(wait_time)
                else:
                    logger.error(f"Dataset generation failed: Maximum retry attempts ({max_retries}) reached for current page - stopping data collection", group="data_processing")
                    # Record failed API call in unified tracking
                    if run_directory:
                        record_api_call(0, rate_limited)
                        # Also record in unified dashboard tracking
                        try:
                            from src.analysis_tool.logging.dataset_contents_collector import record_api_call_unified
                            record_api_call_unified("NVD CVE API", success=False)
                        except ImportError:
                            pass
                    break
        
        if page_data is None:
            logger.error("Dataset generation failed: Unable to retrieve page data after all retry attempts - stopping data collection", group="data_processing")
            break
        
        # Record successful API call
        vulnerabilities = page_data.get('vulnerabilities', [])
        if run_directory:
            record_api_call(len(vulnerabilities), rate_limited)
            # Also record in unified dashboard tracking
            try:
                from src.analysis_tool.logging.dataset_contents_collector import record_api_call_unified
                record_api_call_unified("NVD CVE API", success=True)
            except ImportError:
                pass
        
        if not vulnerabilities:
            logger.info("No more vulnerabilities found. Collection complete.", group="CVE_QUERY")
            break
        
        logger.info(f"Processing {len(vulnerabilities)} CVEs from this page...", group="CVE_QUERY")
        
        for vuln in vulnerabilities:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', '')
            vuln_status = cve_data.get('vulnStatus', '')
            
            # Determine if we should apply status filtering
            should_include = False
            if source_uuid and not statuses_explicitly_provided:
                # UUID filtering with default statuses - include all CVEs from this source
                should_include = True
                matching_cves.append(cve_id)
                logger.info(f"MATCH: {cve_id} - Status: {vuln_status}, UUID: {source_uuid} (all statuses)", group="CVE_QUERY")
            elif vuln_status in target_statuses:
                # Either traditional status filtering or UUID + explicit status filtering
                should_include = True
                matching_cves.append(cve_id)
                status_desc = f", UUID: {source_uuid}" if source_uuid else ""
                logger.info(f"MATCH: {cve_id} - Status: {vuln_status}{status_desc}", group="CVE_QUERY")
            
            # OPTIMIZATION: Cache both NVD and CVE List V5 records now to avoid re-fetching later
            if should_include and cve_id:
                # Extract NVD 2.0 API lastModified for timestamp comparisons
                nvd_last_modified = cve_data.get('lastModified', '')
                
                # Cache NVD CVE record
                _save_nvd_cve_to_cache_during_bulk_generation(cve_id, vuln)
                
                # Cache CVE List V5 record (only if we have NVD timestamp for comparison)
                if nvd_last_modified:
                    _save_cve_list_v5_to_cache_during_bulk_generation(cve_id, nvd_last_modified)
                else:
                    logger.warning(f"NVD 2.0 API response missing required lastModified field for {cve_id} - skipping CVE List V5 cache (malformed API response)", group="CACHE_MANAGEMENT")
        
        # Check if we have more pages
        total_results = page_data.get('totalResults', 0)
        current_end = start_index + len(vulnerabilities)
        progress_pct = (current_end / total_results * 100) if total_results > 0 else 0
        logger.info(f"Processing CVE dataset generation: {current_end}/{total_results} ({progress_pct:.1f}%) - {len(matching_cves)} matching CVE records found", group="CVE_QUERY")
        
        # Update dashboard progress
        if run_directory:
            update_cve_discovery_progress(current_end, total_results, len(matching_cves))
        
        if current_end >= total_results:
            logger.info("Reached end of available CVEs.", group="CVE_QUERY")
            break
        
        # Move to next page
        start_index += results_per_page
        
        # Rate limiting - wait between pages
        if not api_key:
            wait_time = config['api']['retry']['page_delay_without_key']
            logger.info(f"Waiting {wait_time} seconds before next page (rate limiting)...", group="CVE_QUERY")
            sleep(wait_time)
        else:
            wait_time = config['api']['retry']['page_delay_with_key']
            if wait_time > 0:
                logger.info(f"Waiting {wait_time} seconds before next page...", group="CVE_QUERY")
                sleep(wait_time)
    
    # Flush any remaining cache updates
    _flush_cache_batches()
    
    logger.info("=== END CVE Record Cache Preparation ===", group="DATASET")
    
    # Write results to file
    output_file_resolved = resolve_output_path(output_file, run_directory)
    
    logger.info(f"Writing {len(matching_cves)} CVE IDs to {output_file_resolved}...", group="DATASET")
    
    try:
        with open(output_file_resolved, 'w') as f:
            for cve_id in matching_cves:
                f.write(f"{cve_id}\n")
        
        logger.info("Dataset generated successfully!", group="DATASET")
        logger.info(f"Collected {len(matching_cves)} CVE records", group="DATASET")
        logger.info(f"File saved: {output_file_resolved}", group="DATASET")
        
        logger.info(f"You can now run: python -m src.analysis_tool.core.analysis_tool --file {output_file_resolved}", group="DATASET")
        
        # Record output file in dataset contents collector
        if run_directory:
            record_output_file(output_file, str(output_file_resolved), len(matching_cves))
        
    except Exception as e:
        logger.error(f"Dataset file creation failed: Unable to write dataset output to '{output_file_resolved}' - {e}", group="data_processing")
        return False
    
    return True

def generate_last_days(days, api_key=None, output_file="cve_recent_dataset.txt", run_directory=None, source_uuid=None):
    """Generate dataset for CVEs modified in the last N days"""
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    
    # Limit to 120 days max
    if days > 120:
        logger.error("Cannot query more than 120 days (NVD API limit)", group="DATASET")
        return False
    
    logger.info(f"Generating dataset for CVEs modified in the last {days} days", group="DATASET")
    
    return query_nvd_cves_by_date_range(
        start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
        end_date.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
        api_key, output_file, run_directory, source_uuid
    )


def generate_date_range(start_date_str, end_date_str, api_key=None, output_file="cve_range_dataset.txt", run_directory=None, source_uuid=None):
    """Generate dataset for CVEs modified in a specific date range"""
    try:
        # Parse dates
        if 'T' not in start_date_str:
            start_date_str += 'T00:00:00.000Z'
        if 'T' not in end_date_str:
            end_date_str += 'T23:59:59.000Z'
        
        start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
        end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
        
        # Validate range
        if (end_date - start_date).days > 120:
            logger.error("Date range cannot exceed 120 days (NVD API limit)", group="DATASET")
            return False
        
        logger.info(f"Generating dataset for date range: {start_date_str} to {end_date_str}", group="DATASET")
        
        return query_nvd_cves_by_date_range(start_date_str, end_date_str, api_key, output_file, run_directory, source_uuid)
        
    except ValueError as e:
        logger.error(f"Invalid date format: {e}", group="DATASET")
        return False


def query_nvd_cves_by_date_range(start_date, end_date, api_key=None, output_file="cve_dataset.txt", run_directory=None, source_uuid=None):
    """Query NVD API for CVEs modified within a date range"""
    logger.info(f"Querying CVEs modified between {start_date} and {end_date}", group="DATASET")
    if source_uuid:
        logger.info(f"Source UUID filter (server-side): {source_uuid}", group="DATASET")
    
    # Initialize dataset contents collector for date range queries
    from src.analysis_tool.logging.dataset_contents_collector import (
        initialize_dataset_contents_report, start_collection_phase, 
        record_api_call, record_output_file, update_cve_discovery_progress
    )
    
    # Initialize collector with run's logs directory
    if run_directory:
        logs_dir = run_directory / "logs"
        logs_dir.mkdir(exist_ok=True)
        initialize_dataset_contents_report(str(logs_dir))
        
    logger.info("=== END Generate Dataset Initialization Phase ===", group="DATASET")
    logger.info("=== CVE Record Cache Preparation ===", group="DATASET")
    
    if run_directory:
        start_collection_phase("cache_preparation", "nvd_api")
    
    base_url = config['api']['endpoints']['nvd_cves']
    headers = {
        "Accept": "application/json",
        "User-Agent": f"{TOOLNAME}/{VERSION}"
    }
    
    if api_key:
        headers["apiKey"] = api_key
    
    results_per_page = 2000
    start_index = 0
    matching_cves = []
    
    # URL encode dates
    start_date_encoded = start_date.replace('+', '%2B')
    end_date_encoded = end_date.replace('+', '%2B')
    
    while True:
        url = (f"{base_url}?"
               f"lastModStartDate={start_date_encoded}&"
               f"lastModEndDate={end_date_encoded}&"
               f"resultsPerPage={results_per_page}&"
               f"startIndex={start_index}")
        if source_uuid:
            url += f"&sourceIdentifier={source_uuid}"
        
        logger.info(f"Querying CVEs modified in date range: Starting at index {start_index}...", group="CVE_QUERY")
        
        max_retries = config['api']['retry']['max_attempts_nvd']
        page_data = None
        rate_limited = False
        
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers, timeout=config['api']['timeouts']['nvd_api'])
                response.raise_for_status()
                page_data = response.json()
                break
            except requests.exceptions.RequestException as e:
                logger.error(f"NVD API request failed: {e} (Attempt {attempt + 1}/{max_retries})", group="data_processing")
                
                # Check for rate limiting
                if hasattr(e, 'response') and e.response is not None and e.response.status_code == 429:
                    rate_limited = True
                
                if attempt < max_retries - 1:
                    wait_time = config['api']['retry']['delay_without_key'] if not api_key else config['api']['retry']['delay_with_key']
                    sleep(wait_time)
                else:
                    # Record failed API call
                    if run_directory:
                        record_api_call(0, rate_limited)
        
        if page_data is None:
            logger.error("Failed to retrieve page data", group="data_processing")
            break
        
        # Record successful API call
        vulnerabilities = page_data.get('vulnerabilities', [])
        if run_directory:
            record_api_call(len(vulnerabilities), rate_limited)
        if not vulnerabilities:
            logger.info("No more vulnerabilities found. Collection complete.", group="CVE_QUERY")
            break
        
        logger.info(f"Processing {len(vulnerabilities)} CVEs from this page...", group="CVE_QUERY")
        
        for vuln in vulnerabilities:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', '')
            if cve_id:
                matching_cves.append(cve_id)
                
                # OPTIMIZATION: Cache both NVD and CVE List V5 records now to avoid re-fetching later
                # Extract NVD 2.0 API lastModified for timestamp comparisons
                nvd_last_modified = cve_data.get('lastModified', '')
                
                # Cache NVD CVE record
                _save_nvd_cve_to_cache_during_bulk_generation(cve_id, vuln)
                
                # Cache CVE List V5 record (only if we have NVD timestamp for comparison)
                if nvd_last_modified:
                    _save_cve_list_v5_to_cache_during_bulk_generation(cve_id, nvd_last_modified)
                else:
                    logger.warning(f"NVD 2.0 API response missing required lastModified field for {cve_id} - skipping CVE List V5 cached record creation (malformed API response)", group="CACHE_MANAGEMENT")
        
        total_results = page_data.get('totalResults', 0)
        current_end = start_index + len(vulnerabilities)
        progress_pct = (current_end / total_results * 100) if total_results > 0 else 0
        logger.info(f"Progress: {current_end}/{total_results} ({progress_pct:.1f}%) - {len(matching_cves)} CVEs found", group="CVE_QUERY")
        
        # Update dashboard progress
        if run_directory:
            update_cve_discovery_progress(current_end, total_results, len(matching_cves))
        
        if current_end >= total_results:
            break
        
        start_index += results_per_page
        
        # Rate limiting
        wait_time = config['api']['retry']['page_delay_without_key'] if not api_key else config['api']['retry']['page_delay_with_key']
        if wait_time > 0:
            sleep(wait_time)
    
    # Flush any remaining cache updates
    _flush_cache_batches()
    
    logger.info("=== END CVE Record Cache Preparation ===", group="DATASET")
    
    # Write results
    output_file_resolved = resolve_output_path(output_file, run_directory)
    try:
        with open(output_file_resolved, 'w') as f:
            for cve_id in matching_cves:
                f.write(f"{cve_id}\n")
        
        # Record output file in dataset contents collector (logs silently)
        if run_directory:
            record_output_file(output_file, str(output_file_resolved), len(matching_cves))
        
        return True
    except Exception as e:
        logger.error(f"Failed to write output file: {e}", group="data_processing")
        return False
        return False

def main():
    """Main function with command line argument parsing"""
    parser = argparse.ArgumentParser(description='Generate CVE dataset from NVD API')
    
    # Group 1: Tool Output - What analysis outputs to generate
    output_group = parser.add_argument_group('Tool Output', 'Select which analysis outputs to generate')
    output_group.add_argument("--nvd-ish-only", nargs='?', const='true', choices=['true', 'false'], default='false',
                             help="Generate complete NVD-ish enriched records without report files or HTML (ignores other output flags)")
    output_group.add_argument('--sdc-report', nargs='?', const='true', choices=['true', 'false'], default='false',
                             help='Generate Source Data Concerns report (default: false, true if flag provided without value)')
    output_group.add_argument('--cpe-suggestions', nargs='?', const='true', choices=['true', 'false'], default='false', 
                             help='Generate CPE suggestions via NVD CPE API calls (default: false, true if flag provided without value)')
    output_group.add_argument('--alias-report', nargs='?', const='true', choices=['true', 'false'], default='false',
                             help='Generate alias report via curator features (default: false, true if flag provided without value)')
    output_group.add_argument('--cpe-as-generator', nargs='?', const='true', choices=['true', 'false'], default='false',
                             help='Generate CPE Applicability Statements as interactive HTML pages (default: false, true if flag provided without value)')
    
    # Group 2: Data Input/Sources - Specify what data to process and where to get it
    input_group = parser.add_argument_group('Data Input/Sources', 'Specify input data and data sources')
    input_group.add_argument('--api-key', nargs='?', const='CONFIG_DEFAULT', help='NVD API key. Use without value to use config default, or provide explicit key')
    
    # Group 3: Processing Control - Control how processing is performed and output is presented
    control_group = parser.add_argument_group('Processing Control', 'Control processing behavior and output presentation')
    control_group.add_argument('--external-assets', action='store_true',
                              help='Enable external assets in analysis (passed through to analysis tool)')
    
    # Group 4: Dataset Generation - Control what CVE data is included in the dataset
    dataset_group = parser.add_argument_group('Dataset Generation', 'Control CVE data selection and dataset creation')
    dataset_group.add_argument('--source-uuid', type=str,
                              help='Filter CVEs by sourceIdentifier (CNA/ADP providerMetadata.orgId) - must be valid UUID format. When used without --statuses, includes all vulnerability statuses.')
    dataset_group.add_argument('--statuses', nargs='+', 
                              default=['Received', 'Awaiting Analysis', 'Undergoing Analysis'],
                              help='Vulnerability statuses to include (default when no UUID: Received, Awaiting Analysis, Undergoing Analysis; default with UUID: all statuses)')
    dataset_group.add_argument('--last-days', type=int,
                              help='Generate dataset for CVEs modified in the last N days')
    dataset_group.add_argument('--start-date', type=str,
                              help='Start date for lastModified filter (YYYY-MM-DD or ISO format)')
    dataset_group.add_argument('--end-date', type=str,
                              help='End date for lastModified filter (YYYY-MM-DD or ISO format)')
    
    # Group 5: Run Organization - Control directory structure for multi-run orchestration
    run_org_group = parser.add_argument_group('Run Organization', 'Control run directory hierarchy')
    run_org_group.add_argument('--parent-run-dir', type=str,
                              help='Parent run directory path - creates this run as child within parent (used by harvest script)')
    
    args = parser.parse_args()
    
    logger.info("=" * 80, group="DATASET")
    logger.info("NVD CVE Dataset Generator", group="DATASET")
    logger.info("=" * 80, group="DATASET")
    
    # Validate UUID if provided
    if args.source_uuid and not validate_uuid(args.source_uuid):
        logger.error(f"Invalid UUID format: {args.source_uuid}", group="DATASET")
        logger.error("Source UUID must be a valid UUID format", group="DATASET")
        return 1
    
    # Detect if statuses were explicitly provided (not using defaults)
    import sys
    statuses_explicitly_provided = '--statuses' in sys.argv
    
    # Resolve API key from command line, config, or default to None
    api_key_source = None
    if args.api_key == 'CONFIG_DEFAULT':
        resolved_api_key = config['defaults']['default_api_key']
        api_key_source = "Configuration"
        logger.info("NVD API key detected | Source: Configuration", group="DATASET")
    elif args.api_key:
        resolved_api_key = args.api_key
        api_key_source = "Direct Input"
        logger.info("NVD API key detected | Source: Direct Input", group="DATASET")
    else:
        # No --api-key flag provided, fall back to config
        resolved_api_key = config['defaults']['default_api_key'] or None
        if resolved_api_key:
            api_key_source = "Configuration"
            logger.info("NVD API key detected | Source: Configuration", group="DATASET")
    
    if not resolved_api_key:
        logger.error("API key is required for dataset generation", group="DATASET")
        logger.error("Either use --api-key parameter or set default_api_key in config.json", group="DATASET")
        logger.error("NVD API without a key has severe rate limits that make dataset generation impractical", group="DATASET")
        return 1
    
    logger.info("Using API key for enhanced rate limits", group="DATASET")
    if args.source_uuid:
        logger.info(f"UUID filtering enabled: {args.source_uuid}", group="DATASET")
    
    # Create run directory first - ALL dataset generation creates runs
    from src.analysis_tool.storage.run_organization import create_run_directory
    
    # Convert string boolean arguments to actual booleans
    sdc_report = args.sdc_report.lower() == 'true'
    cpe_suggestions = args.cpe_suggestions.lower() == 'true'
    alias_report = args.alias_report.lower() == 'true'
    cpe_as_generator = args.cpe_as_generator.lower() == 'true'
    nvd_ish_only = args.nvd_ish_only.lower() == 'true'
    external_assets = args.external_assets
    
    # Handle --nvd-ish-only flag processing (override behavior)
    if nvd_ish_only:
        # Override other output flags (ignore their values)
        sdc_report = False
        cpe_suggestions = False
        alias_report = False
        cpe_as_generator = False
        
        print("NVD-ish only mode enabled: generating complete enriched records without report files or HTML")
        print("Other output flags ignored in NVD-ish only mode")
    
    # Validate feature combinations
    if alias_report and not args.source_uuid:
        print("ERROR: --alias-report requires --source-uuid to determine the appropriate confirmed mappings file")
        print("Example usage:")
        print("  python generate_dataset.py --last-days 7 --alias-report --source-uuid your-uuid-here")
        return
    
    # Validate that at least one feature is enabled (or nvd-ish-only mode)
    if not any([sdc_report, cpe_suggestions, alias_report, cpe_as_generator, nvd_ish_only]):
        print("ERROR: At least one feature must be enabled for dataset generation!")
        print("Available features:")
        print("  --sdc-report               : Generate Source Data Concerns report")
        print("  --cpe-suggestions          : Generate CPE suggestions via NVD CPE API calls")
        print("  --alias-report             : Generate alias report via curator features")
        print("  --cpe-as-generator         : Generate CPE Applicability Statements as interactive HTML pages")
        print("  --nvd-ish-only             : Generate complete NVD-ish enriched records without report files or HTML")
        print("")
        print("Example usage:")
        print("  python generate_dataset.py --last-days 7 --sdc-report")
        print("  python generate_dataset.py --last-days 7 --cpe-suggestions --cpe-as-generator")
        return 1
    
    # Generate initial run context with source shortname resolution
    source_suffix = ""
    if args.source_uuid:
        # Resolve source shortname for better human readability in directory names
        import sys
        from pathlib import Path
        
        # Add src to path if not already there
        project_root = Path(__file__).parent
        src_path = project_root / "src"
        if str(src_path) not in sys.path:
            sys.path.insert(0, str(src_path))
        
        from analysis_tool.core.gatherData import gatherNVDSourceData
        from analysis_tool.storage.nvd_source_manager import get_global_source_manager
        
        # Initialize NVD source manager with cache-aware fallback logic
        source_manager = get_global_source_manager()
        
        if source_manager.is_initialized():
            logger.info("NVD source manager already initialized", group="DATASET")
            logger.info(f"Using existing source data with {source_manager.get_source_count()} entries", group="DATASET")
        else:
            # Try to load from cache first
            from analysis_tool.storage.nvd_source_manager import try_load_from_environment_cache
            
            if try_load_from_environment_cache():
                # Check if cache is too old (more than 24 hours)
                try:
                    from pathlib import Path
                    import json
                    current_file = Path(__file__).resolve()
                    project_root = current_file.parent
                    cache_metadata_path = project_root / "cache" / "cache_metadata.json"
                    
                    if cache_metadata_path.exists():
                        with open(cache_metadata_path, 'r') as f:
                            metadata = json.load(f)
                        
                        if 'datasets' in metadata and 'nvd_source_data' in metadata['datasets']:
                            last_updated = datetime.fromisoformat(metadata['datasets']['nvd_source_data']['last_updated'])
                            # Ensure timezone-aware comparison
                            if last_updated.tzinfo is None:
                                last_updated = last_updated.replace(tzinfo=timezone.utc)
                            age_hours = (datetime.now(timezone.utc) - last_updated).total_seconds() / 3600
                            
                            from analysis_tool.storage.nvd_source_manager import is_cache_stale, get_cache_age_threshold
                            if is_cache_stale(age_hours):
                                threshold = get_cache_age_threshold()
                                logger.warning(f"NVD source cache is {age_hours:.1f} hours old (threshold: {threshold}h) - refreshing from API", group="DATASET")
                                # Refresh the cache
                                nvd_source_data = gatherNVDSourceData(resolved_api_key)
                                source_manager.initialize(nvd_source_data)
                                source_manager.create_localized_cache()
                                logger.info(f"NVD source cache refreshed with {source_manager.get_source_count()} entries", group="DATASET")
                            else:
                                logger.info(f"NVD source manager loaded from cache with {source_manager.get_source_count()} entries (age: {age_hours:.1f}h)", group="DATASET")
                        else:
                            logger.info(f"NVD source manager loaded from cache with {source_manager.get_source_count()} entries", group="DATASET")
                    else:
                        logger.info(f"NVD source manager loaded from cache with {source_manager.get_source_count()} entries", group="DATASET")
                except Exception as e:
                    logger.warning(f"Could not check cache age: {e}", group="DATASET")
                    logger.info(f"NVD source manager loaded from cache with {source_manager.get_source_count()} entries", group="DATASET")
            else:
                logger.warning("NVD source cache not found - creating fresh cache", group="DATASET")
                
                # Fallback: Load NVD source data as fallback for standalone execution
                logger.info("Gathering NVD source data from API for standalone dataset generation", group="DATASET")
                nvd_source_data = gatherNVDSourceData(resolved_api_key)
                source_manager.initialize(nvd_source_data)
                
                # Create cache for future use
                try:
                    cache_path = source_manager.create_localized_cache()
                    logger.info(f"Created NVD source cache for future use: {cache_path}", group="DATASET")
                except Exception as e:
                    logger.warning(f"Could not create source cache: {e}", group="DATASET")
                
                logger.info(f"NVD source manager initialized from API with {source_manager.get_source_count()} entries", group="DATASET")
        
        # Get human-readable shortname (capped to 7-8 characters)
        full_shortname = source_manager.get_source_shortname(args.source_uuid)
        source_shortname = full_shortname[:8] if len(full_shortname) > 8 else full_shortname
        source_suffix = f"_{source_shortname}"
        
        logger.info(f"Resolved source UUID {args.source_uuid[:8]}... to shortname: '{source_shortname}'", group="DATASET")
    else:
        # No source UUID provided - use default shortname
        source_shortname = None
    
    # Prepare enhanced naming parameters
    execution_type = "dataset"
    
    # Determine range specification
    range_spec = None
    if args.last_days:
        range_spec = f"last_{args.last_days}_days"
    elif args.start_date and args.end_date:
        range_spec = f"range_{args.start_date}_to_{args.end_date}"
    
    # Prepare tool flags (only include those that are true)
    tool_flags = {}
    if nvd_ish_only:
        tool_flags['nvd-ish'] = True
    if sdc_report:
        tool_flags['sdc'] = True
    if cpe_suggestions:
        tool_flags['cpe-sug'] = True
    if alias_report:
        tool_flags['alias'] = True
    if cpe_as_generator:
        tool_flags['cpe-as-gen'] = True
    
    # Create run directory using enhanced naming
    # If parent_run_dir provided, create this run as child within parent hierarchy
    from pathlib import Path
    parent_run_path = Path(args.parent_run_dir) if args.parent_run_dir else None
    
    # Determine subdirectories based on nvd-ish-only mode
    # nvd-ish-only doesn't need generated_pages (only produces JSON enriched records)
    subdirs = ["logs"] if nvd_ish_only else ["generated_pages", "logs"]
    
    # Check if we're in a test environment to enable consolidated test run handling
    is_test = os.environ.get('CONSOLIDATED_TEST_RUN') == '1'
    
    run_directory, run_id = create_run_directory(
        execution_type=execution_type,
        source_shortname=source_shortname,
        range_spec=range_spec,
        status_list=args.statuses if args.statuses else None,
        tool_flags=tool_flags if tool_flags else None,
        parent_run_dir=parent_run_path,
        subdirs=subdirs,
        is_test=is_test
    )
    logger.info(f"Created dataset generation run: {run_id}", group="DATASET")
    logger.info(f"Run directory: {run_directory}", group="DATASET")
    
    # Configure file logging to write to run-specific logs directory
    logs_dir = run_directory / "logs"
    logger.set_run_logs_directory(str(logs_dir))
    logger.start_file_logging("cve_dataset")
    
    logger.info("=== Generate Dataset Initialization Phase ===", group="DATASET")
    if api_key_source:
        logger.info(f"NVD API key detected | Source: {api_key_source}", group="DATASET")
    if args.source_uuid:
        logger.info(f"Source UUID filter active: {args.source_uuid}", group="DATASET")
    
    # Generate dataset directly in run directory
    success = False
    output_file = "cve_dataset.txt"  # Fixed filename for dataset generation
    
    # Determine which mode to use - all write directly to run directory
    if args.last_days:
        success = generate_last_days(args.last_days, resolved_api_key, output_file, run_directory, args.source_uuid)
    elif args.start_date and args.end_date:
        success = generate_date_range(args.start_date, args.end_date, resolved_api_key, output_file, run_directory, args.source_uuid)
    else:
        # Traditional status-based generation
        success = query_nvd_cves_by_status(
            api_key=resolved_api_key,
            target_statuses=args.statuses,
            output_file=output_file,
            run_directory=run_directory,
            source_uuid=args.source_uuid,
            statuses_explicitly_provided=statuses_explicitly_provided
        )
    
    if success:
        # Handoff phase between dataset generation and integrated analysis
        dataset_path = run_directory / "logs" / output_file
        
        logger.info("=== Generate Dataset Handoff Phase ===", group="DATASET")
        
        # Count CVEs for reporting
        try:
            cve_count = sum(1 for line in open(dataset_path) if line.strip())
            logger.info(f"CVE Record List Generated: {cve_count} CVEs | /logs/{output_file}", group="DATASET")
        except Exception as e:
            logger.error(f"Failed to read dataset file: {e}", group="data_processing")
            cve_count = 0
        
        # Run analysis tool with existing run context
        success = run_analysis_tool(output_file, resolved_api_key, run_directory, run_id, external_assets, sdc_report, cpe_suggestions, alias_report, cpe_as_generator, nvd_ish_only, args.source_uuid)
        if not success:
            logger.error("Analysis tool execution failed", group="data_processing")
            return 1
    else:
        logger.error("Dataset generation process failed: Unable to complete CVE data collection and processing", group="data_processing")
        return 1
    
    return 0


def run_analysis_tool(dataset_file, api_key=None, run_directory=None, run_id=None, external_assets=False, sdc_report=False, cpe_suggestions=False, alias_report=False, cpe_as_generator=False, nvd_ish_only=False, source_uuid=None):
    """Run the analysis tool on the generated dataset within an existing run context (direct integration)"""
    
    try:
        # If we have a run directory context, the dataset should be in that run
        if not run_directory:
            raise RuntimeError("Run directory required for integrated analysis - legacy behavior removed")
            
        dataset_path = run_directory / "logs" / Path(dataset_file).name
        if not dataset_path.exists():
            raise FileNotFoundError(f"Dataset file not found in run directory: {dataset_path}")
        
        # Report handoff parameters - only show what's enabled
        if run_directory:
            logger.info(f"Run directory: {run_directory}", group="DATASET")
        
        # Report enabled analysis features for handoff
        enabled_features = []
        
        if nvd_ish_only:
            enabled_features.append("NVD-ish Enriched Records")
            # NVD-ish mode enables these sub-features automatically
            enabled_features.append("Source Data Concerns")
            enabled_features.append("CPE Suggestions")
            enabled_features.append("CPE-AS Generator")
        else:
            if sdc_report:
                enabled_features.append("Source Data Concerns")
            if cpe_suggestions:
                enabled_features.append("CPE Suggestions")
            if alias_report:
                enabled_features.append("Alias Report")
            if cpe_as_generator:
                enabled_features.append("CPE-AS Generator")
        
        if enabled_features:
            logger.info(f"Enabled features: {', '.join(enabled_features)}", group="DATASET")
        else:
            logger.info("No optional features enabled", group="DATASET")
        
        if source_uuid:
            logger.info(f"Source UUID filter: {source_uuid}", group="DATASET")
        
        logger.info("=== END Generate Dataset Handoff Phase ===", group="DATASET")
        
        # Direct import from analysis_tool
        from src.analysis_tool.core.analysis_tool import main
        
        # Temporarily replace sys.argv to pass parameters to main()
        original_argv = sys.argv[:]
        try:
            # Build argument list for analysis tool
            sys.argv = ["analysis_tool.py", "--file", str(dataset_path)]
            
            # Add run context if available - pass full run directory path as run-id
            if run_directory:
                sys.argv.extend(["--run-id", str(run_directory)])
            
            if api_key:
                sys.argv.extend(["--api-key", api_key])
            
            if external_assets:
                sys.argv.append("--external-assets")
            
            # Add feature flags
            sys.argv.extend(["--nvd-ish-only", "true" if nvd_ish_only else "false"])
            sys.argv.extend(["--sdc-report", "true" if sdc_report else "false"])
            sys.argv.extend(["--cpe-suggestions", "true" if cpe_suggestions else "false"])
            sys.argv.extend(["--alias-report", "true" if alias_report else "false"])
            sys.argv.extend(["--cpe-as-generator", "true" if cpe_as_generator else "false"])
            
            if source_uuid:
                sys.argv.extend(["--source-uuid", source_uuid])
            
            # Execute analysis tool main function
            exit_code = main()
            
            # Analysis tool returns 0 for success, non-zero for failure
            if exit_code == 0:
                logger.info("-" * 60, group="DATASET")
                logger.info("Analysis tool completed successfully", group="INIT")
                if run_directory:
                    logger.info(f"Results available in: {run_directory}", group="INIT")
                    
                    # Finalize dataset contents report after integrated analysis completes
                    from src.analysis_tool.logging.dataset_contents_collector import finalize_dataset_contents_report
                    finalize_dataset_contents_report()
                    
                return True
            else:
                logger.error(f"Analysis tool failed with exit code {exit_code}", group="INIT")
                return False
            
        finally:
            # Restore original sys.argv
            sys.argv = original_argv
            
    except Exception as e:
        logger.error(f"Failed to run analysis tool: {e}", group="INIT")
        return False

if __name__ == "__main__":
    exit(main())
