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
import datetime
from time import sleep
import argparse
from pathlib import Path
import uuid
from src.analysis_tool.logging.workflow_logger import WorkflowLogger

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

# Initialize logger
logger = WorkflowLogger()

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
    
    logger.info("Starting CVE dataset generation...", group="initialization")
    if source_uuid and not statuses_explicitly_provided:
        logger.info("Target vulnerability statuses: ALL (inclusive mode with UUID filtering)", group="initialization")
    else:
        logger.info(f"Target vulnerability statuses: {', '.join(target_statuses)}", group="initialization")
    if source_uuid:
        logger.info(f"Source UUID filter (server-side): {source_uuid}", group="initialization")
    logger.info(f"Output file: {output_file}", group="initialization")
    logger.info(f"Using API key: {'Yes' if api_key else 'No'}", group="initialization")
    
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
        start_collection_phase("cve_list_generation", "nvd_api")
    
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
        
        logger.info(f"Processing CVE dataset queries: Starting at index {start_index}...", group="cve_queries")
        
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
                    logger.info(f"Waiting {wait_time} seconds before retry...", group="cve_queries")
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
            logger.info("No more vulnerabilities found. Collection complete.", group="cve_queries")
            break
        
        logger.info(f"Processing {len(vulnerabilities)} CVEs from this page...", group="cve_queries")
        
        for vuln in vulnerabilities:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', '')
            vuln_status = cve_data.get('vulnStatus', '')
            
            # Determine if we should apply status filtering
            if source_uuid and not statuses_explicitly_provided:
                # UUID filtering with default statuses - include all CVEs from this source
                matching_cves.append(cve_id)
                logger.info(f"MATCH: {cve_id} - Status: {vuln_status}, UUID: {source_uuid} (all statuses)", group="cve_queries")
            elif vuln_status in target_statuses:
                # Either traditional status filtering or UUID + explicit status filtering
                matching_cves.append(cve_id)
                status_desc = f", UUID: {source_uuid}" if source_uuid else ""
                logger.info(f"MATCH: {cve_id} - Status: {vuln_status}{status_desc}", group="cve_queries")
        
        # Check if we have more pages
        total_results = page_data.get('totalResults', 0)
        current_end = start_index + len(vulnerabilities)
        progress_pct = (current_end / total_results * 100) if total_results > 0 else 0
        logger.info(f"Processing CVE dataset generation: {current_end}/{total_results} ({progress_pct:.1f}%) - {len(matching_cves)} matching CVE records found", group="cve_queries")
        
        # Update dashboard progress
        if run_directory:
            update_cve_discovery_progress(current_end, total_results, len(matching_cves))
        
        if current_end >= total_results:
            logger.info("Reached end of available CVEs.", group="cve_queries")
            break
        
        # Move to next page
        start_index += results_per_page
        
        # Rate limiting - wait between pages
        if not api_key:
            wait_time = config['api']['retry']['page_delay_without_key']
            logger.info(f"Waiting {wait_time} seconds before next page (rate limiting)...", group="cve_queries")
            sleep(wait_time)
        else:
            wait_time = config['api']['retry']['page_delay_with_key']
            if wait_time > 0:
                logger.info(f"Waiting {wait_time} seconds before next page...", group="cve_queries")
                sleep(wait_time)
    
    # Write results to file
    output_file_resolved = resolve_output_path(output_file, run_directory)
    
    logger.info(f"Writing {len(matching_cves)} CVE IDs to {output_file_resolved}...", group="initialization")
    
    try:
        with open(output_file_resolved, 'w') as f:
            for cve_id in matching_cves:
                f.write(f"{cve_id}\n")
        
        logger.info("Dataset generated successfully!", group="initialization")
        logger.info(f"Collected {len(matching_cves)} CVE records", group="initialization")
        logger.info(f"File saved: {output_file_resolved}", group="initialization")
        logger.info(f"You can now run: python -m src.analysis_tool.core.analysis_tool --file {output_file_resolved}", group="initialization")
        
        # Record output file in dataset contents collector
        if run_directory:
            record_output_file(output_file, str(output_file_resolved), len(matching_cves))
        
    except Exception as e:
        logger.error(f"Dataset file creation failed: Unable to write dataset output to '{output_file_resolved}' - {e}", group="data_processing")
        return False
    
    # Finalize dataset contents report
    if run_directory:
        from src.analysis_tool.logging.dataset_contents_collector import finalize_dataset_contents_report
        report_path = finalize_dataset_contents_report()
        if report_path:
            logger.info(f"Dataset generation report finalized: {report_path}", group="completion")
    
    return True

def generate_last_days(days, api_key=None, output_file="cve_recent_dataset.txt", run_directory=None, source_uuid=None):
    """Generate dataset for CVEs modified in the last N days"""
    end_date = datetime.datetime.now()
    start_date = end_date - datetime.timedelta(days=days)
    
    # Limit to 120 days max
    if days > 120:
        logger.error("Cannot query more than 120 days (NVD API limit)", group="initialization")
        return False
    
    logger.info(f"Generating dataset for CVEs modified in the last {days} days", group="initialization")
    
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
        
        start_date = datetime.datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
        end_date = datetime.datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
        
        # Validate range
        if (end_date - start_date).days > 120:
            logger.error("Date range cannot exceed 120 days (NVD API limit)", group="initialization")
            return False
        
        logger.info(f"Generating dataset for date range: {start_date_str} to {end_date_str}", group="initialization")
        
        return query_nvd_cves_by_date_range(start_date_str, end_date_str, api_key, output_file, run_directory, source_uuid)
        
    except ValueError as e:
        logger.error(f"Invalid date format: {e}", group="initialization")
        return False


def query_nvd_cves_by_date_range(start_date, end_date, api_key=None, output_file="cve_dataset.txt", run_directory=None, source_uuid=None):
    """Query NVD API for CVEs modified within a date range"""
    logger.info(f"Querying CVEs modified between {start_date} and {end_date}", group="initialization")
    if source_uuid:
        logger.info(f"Source UUID filter (server-side): {source_uuid}", group="initialization")
    
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
        start_collection_phase("cve_list_generation", "nvd_api")
    
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
        
        logger.info(f"Querying CVEs modified in date range: Starting at index {start_index}...", group="cve_queries")
        
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
            logger.info("No more vulnerabilities found. Collection complete.", group="cve_queries")
            break
        
        logger.info(f"Processing {len(vulnerabilities)} CVEs from this page...", group="cve_queries")
        
        for vuln in vulnerabilities:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', '')
            if cve_id:
                matching_cves.append(cve_id)
                if source_uuid:
                    logger.info(f"FOUND: {cve_id} - UUID: {source_uuid}", group="cve_queries")
                else:
                    logger.info(f"FOUND: {cve_id}", group="cve_queries")
        
        total_results = page_data.get('totalResults', 0)
        current_end = start_index + len(vulnerabilities)
        progress_pct = (current_end / total_results * 100) if total_results > 0 else 0
        logger.info(f"Progress: {current_end}/{total_results} ({progress_pct:.1f}%) - {len(matching_cves)} CVEs found", group="cve_queries")
        
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
    
    # Write results
    output_file_resolved = resolve_output_path(output_file, run_directory)
    try:
        with open(output_file_resolved, 'w') as f:
            for cve_id in matching_cves:
                f.write(f"{cve_id}\n")
        
        logger.info(f"Dataset generated successfully: {len(matching_cves)} CVEs", group="initialization")
        logger.info(f"File saved: {output_file_resolved}", group="initialization")
        
        # Record output file in dataset contents collector
        if run_directory:
            record_output_file(output_file, str(output_file_resolved), len(matching_cves))
        
        # Finalize dataset contents report
        if run_directory:
            from src.analysis_tool.logging.dataset_contents_collector import finalize_dataset_contents_report
            report_path = finalize_dataset_contents_report()
            if report_path:
                logger.info(f"Dataset generation report finalized: {report_path}", group="completion")
        
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
    input_group.add_argument('--local-cve-repo', type=str, nargs='?', const='CONFIG_DEFAULT',
                            help='Path to local CVE repository for integrated analysis. Use without value to use config default, or provide explicit path (e.g., /path/to/cvelistV5/cves)')
    
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
    
    args = parser.parse_args()
    
    logger.info("=" * 80, group="initialization")
    logger.info("NVD CVE Dataset Generator", group="initialization")
    logger.info("=" * 80, group="initialization")
    
    # Validate UUID if provided
    if args.source_uuid and not validate_uuid(args.source_uuid):
        logger.error(f"Invalid UUID format: {args.source_uuid}", group="initialization")
        logger.error("Source UUID must be a valid UUID format", group="initialization")
        return 1
    
    # Detect if statuses were explicitly provided (not using defaults)
    import sys
    statuses_explicitly_provided = '--statuses' in sys.argv
    
    # Resolve API key from command line, config, or default to None
    if args.api_key == 'CONFIG_DEFAULT':
        resolved_api_key = config['defaults']['default_api_key']
        logger.info("Using default NVD API key from config for faster processing", group="initialization")
    elif args.api_key:
        resolved_api_key = args.api_key
        logger.info("Using provided NVD API key for faster processing", group="initialization")
    else:
        resolved_api_key = config['defaults']['default_api_key'] or None
    
    if not resolved_api_key:
        logger.error("API key is required for dataset generation", group="initialization")
        logger.error("Either use --api-key parameter or set default_api_key in config.json", group="initialization")
        logger.error("NVD API without a key has severe rate limits that make dataset generation impractical", group="initialization")
        return 1
    
    logger.info("Using API key for enhanced rate limits", group="initialization")
    if args.source_uuid:
        logger.info(f"UUID filtering enabled: {args.source_uuid}", group="initialization")
    
    # Resolve local CVE repository path from config if needed
    if args.local_cve_repo == 'CONFIG_DEFAULT':
        local_cve_config = config.get('local_cve_repository', {})
        if local_cve_config.get('enabled', False):
            args.local_cve_repo = local_cve_config.get('default_path')
            logger.info(f"Using configured local CVE repository: {args.local_cve_repo}", group="initialization")
        else:
            args.local_cve_repo = None
            logger.info("Local CVE repository disabled in config, using API only", group="initialization")
    elif args.local_cve_repo:
        logger.info(f"Using specified local CVE repository: {args.local_cve_repo}", group="initialization")
    
    # Create run directory first - ALL dataset generation creates runs
    from src.analysis_tool.storage.run_organization import create_run_directory
    
    # Convert string boolean arguments to actual booleans
    sdc_report = args.sdc_report.lower() == 'true'
    cpe_suggestions = args.cpe_suggestions.lower() == 'true'
    alias_report = args.alias_report.lower() == 'true'
    cpe_as_generator = args.cpe_as_generator.lower() == 'true'
    
    # Validate feature combinations
    if alias_report and not args.source_uuid:
        print("ERROR: --alias-report requires --source-uuid to determine the appropriate confirmed mappings file")
        print("Example usage:")
        print("  python generate_dataset.py --last-days 7 --alias-report --source-uuid your-uuid-here")
        return
    
    # Validate that at least one feature is enabled
    if not any([sdc_report, cpe_suggestions, alias_report, cpe_as_generator]):
        print("ERROR: At least one feature must be enabled for dataset generation!")
        print("Available features:")
        print("  --sdc-report               : Generate Source Data Concerns report")
        print("  --cpe-suggestions          : Generate CPE suggestions via NVD CPE API calls")
        print("  --alias-report             : Generate alias report via curator features")
        print("  --cpe-as-generator         : Generate CPE Applicability Statements as interactive HTML pages")
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
            logger.info("NVD source manager already initialized", group="initialization")
            logger.info(f"Using existing source data with {source_manager.get_source_count()} entries", group="initialization")
        else:
            # Try to load from cache first
            from analysis_tool.storage.nvd_source_manager import try_load_from_environment_cache
            
            if try_load_from_environment_cache():
                # Check if cache is too old (more than 24 hours)
                from datetime import datetime, timedelta
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
                            age_hours = (datetime.now() - last_updated).total_seconds() / 3600
                            
                            if age_hours > 24:
                                logger.warning(f"NVD source cache is {age_hours:.1f} hours old - refreshing from API", group="initialization")
                                # Refresh the cache
                                nvd_source_data = gatherNVDSourceData(resolved_api_key)
                                source_manager.initialize(nvd_source_data)
                                source_manager.create_localized_cache()
                                logger.info(f"NVD source cache refreshed with {source_manager.get_source_count()} entries", group="initialization")
                            else:
                                logger.info(f"NVD source manager loaded from cache with {source_manager.get_source_count()} entries (age: {age_hours:.1f}h)", group="initialization")
                        else:
                            logger.info(f"NVD source manager loaded from cache with {source_manager.get_source_count()} entries", group="initialization")
                    else:
                        logger.info(f"NVD source manager loaded from cache with {source_manager.get_source_count()} entries", group="initialization")
                except Exception as e:
                    logger.warning(f"Could not check cache age: {e}", group="initialization")
                    logger.info(f"NVD source manager loaded from cache with {source_manager.get_source_count()} entries", group="initialization")
            else:
                logger.warning("NVD source cache not found - creating fresh cache", group="initialization")
                
                # Fallback: Load NVD source data as fallback for standalone execution
                logger.info("Gathering NVD source data from API for standalone dataset generation", group="initialization")
                nvd_source_data = gatherNVDSourceData(resolved_api_key)
                source_manager.initialize(nvd_source_data)
                
                # Create cache for future use
                try:
                    cache_path = source_manager.create_localized_cache()
                    logger.info(f"Created NVD source cache for future use: {cache_path}", group="initialization")
                except Exception as e:
                    logger.warning(f"Could not create source cache: {e}", group="initialization")
                
                logger.info(f"NVD source manager initialized from API with {source_manager.get_source_count()} entries", group="initialization")
        
        # Get human-readable shortname (capped to 7-8 characters)
        full_shortname = source_manager.get_source_shortname(args.source_uuid)
        source_shortname = full_shortname[:8] if len(full_shortname) > 8 else full_shortname
        source_suffix = f"_{source_shortname}"
        
        logger.info(f"Resolved source UUID {args.source_uuid[:8]}... to shortname: '{source_shortname}'", group="initialization")
    
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
    if sdc_report:
        tool_flags['sdc'] = True
    if cpe_suggestions:
        tool_flags['cpe-sug'] = True
    if alias_report:
        tool_flags['alias'] = True
    if cpe_as_generator:
        tool_flags['cpe-as-gen'] = True
    
    # Create run directory using enhanced naming
    run_directory, run_id = create_run_directory(
        execution_type=execution_type,
        source_shortname=source_shortname,
        range_spec=range_spec,
        status_list=args.statuses if args.statuses else None,
        tool_flags=tool_flags if tool_flags else None
    )
    logger.info(f"Created dataset generation run: {run_id}", group="initialization")
    logger.info(f"Run directory: {run_directory}", group="initialization")
    
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
        logger.info("Dataset generation completed successfully!", group="initialization")
        
        # Always run analysis tool after dataset generation
        logger.info("Starting integrated analysis run...", group="initialization")
        

        dataset_path = run_directory / "logs" / Path(output_file).name
        
        # Run analysis tool with existing run context
        success = run_analysis_tool(output_file, resolved_api_key, run_directory, run_id, args.external_assets, sdc_report, cpe_suggestions, alias_report, cpe_as_generator, args.source_uuid, args.local_cve_repo)
        if not success:
            logger.error("Analysis tool execution failed", group="data_processing")
            return 1
    else:
        logger.error("Dataset generation process failed: Unable to complete CVE data collection and processing", group="data_processing")
        return 1
    
    return 0


def run_analysis_tool(dataset_file, api_key=None, run_directory=None, run_id=None, external_assets=False, sdc_report=False, cpe_suggestions=False, alias_report=False, cpe_as_generator=False, source_uuid=None, local_cve_repo=None):
    """Run the analysis tool on the generated dataset within an existing run context (direct integration)"""
    
    try:
        # If we have a run directory context, the dataset should be in that run
        if not run_directory:
            raise RuntimeError("Run directory required for integrated analysis - legacy behavior removed")
            
        dataset_path = run_directory / "logs" / Path(dataset_file).name
        if not dataset_path.exists():
            raise FileNotFoundError(f"Dataset file not found in run directory: {dataset_path}")
        
        # Check dataset size for smart batch handling
        try:
            cve_count = sum(1 for line in open(dataset_path) if line.strip())
            logger.info(f"Dataset contains {cve_count:,} CVE entries", group="initialization")
        except Exception as e:
            logger.error(f"Failed to count CVEs in dataset: {e}", group="data_processing")
            cve_count = 0
        
        # Comprehensive feature flag auditing for integrated analysis
        logger.info("=== INTEGRATED ANALYSIS FEATURE FLAG AUDIT ===", group="initialization")
        logger.info(f"SDC Report: {'ENABLED' if sdc_report else 'DISABLED'}", group="initialization")
        logger.info(f"CPE Suggestions: {'ENABLED' if cpe_suggestions else 'DISABLED'}", group="initialization")
        logger.info(f"Alias Report: {'ENABLED' if alias_report else 'DISABLED'}", group="initialization")
        logger.info(f"CPE-AS Generator: {'ENABLED' if cpe_as_generator else 'DISABLED'}", group="initialization")
        
        # Log enabled features summary
        enabled_features = []
        if sdc_report:
            enabled_features.append("Source Data Concerns")
        if cpe_suggestions:
            enabled_features.append("CPE Suggestions")
        if alias_report:
            enabled_features.append("Alias Report")
        if cpe_as_generator:
            enabled_features.append("CPE as Generator")
        logger.info(f"Enabled features: {', '.join(enabled_features) if enabled_features else 'None'}", group="initialization")
        logger.info("=== END INTEGRATED ANALYSIS AUDIT ===", group="initialization")
        
        if run_id:
            logger.info(f"Continuing analysis within existing run: {run_id}", group="initialization")
        
        if source_uuid:
            logger.info(f"Source UUID filter will be applied during analysis: {source_uuid}", group="initialization")
        
        if local_cve_repo:
            logger.info(f"Local CVE repository will be used with API fallback: {local_cve_repo}", group="initialization")
        
        if run_directory:
            logger.info(f"Analysis will continue in run directory: {run_directory}", group="initialization")
        else:
            logger.info(f"Analysis will create new run directory", group="initialization")
        
        # Import and run analysis tool directly (eliminates subprocess overhead)
        logger.info("Executing analysis tool via direct integration:", group="initialization")
        logger.info("-" * 60, group="initialization")
        
        # Direct import from analysis_tool
        from src.analysis_tool.core.analysis_tool import main
        
        # Temporarily replace sys.argv to pass parameters to main()
        original_argv = sys.argv[:]
        try:
            # Build argument list for analysis tool
            sys.argv = ["analysis_tool.py", "--file", str(dataset_path)]
            
            # Add run context if available
            if run_id:
                sys.argv.extend(["--run-id", run_id])
            
            if api_key:
                sys.argv.extend(["--api-key", api_key])
            
            if external_assets:
                sys.argv.append("--external-assets")
            
            # Add feature flags
            sys.argv.extend(["--sdc-report", "true" if sdc_report else "false"])
            sys.argv.extend(["--cpe-suggestions", "true" if cpe_suggestions else "false"])
            sys.argv.extend(["--alias-report", "true" if alias_report else "false"])
            sys.argv.extend(["--cpe-as-generator", "true" if cpe_as_generator else "false"])
            
            if source_uuid:
                sys.argv.extend(["--source-uuid", source_uuid])
            
            if local_cve_repo:
                sys.argv.extend(["--local-cve-repo", local_cve_repo])
            
            # Execute analysis tool main function
            main()
            
            logger.info("-" * 60, group="initialization")
            logger.info("Analysis tool completed successfully", group="initialization")
            if run_directory:
                logger.info(f"Results available in: {run_directory}", group="initialization")
            return True
            
        finally:
            # Restore original sys.argv
            sys.argv = original_argv
            
    except Exception as e:
        logger.error(f"Failed to run analysis tool: {e}", group="data_processing")
        return False

if __name__ == "__main__":
    exit(main())
