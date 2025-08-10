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
import datetime
from time import sleep
import argparse
from pathlib import Path
from src.analysis_tool.logging.workflow_logger import WorkflowLogger

def get_analysis_tools_root():
    """Get the absolute path to the Analysis_Tools project root"""
    current_file = Path(__file__).resolve()
    # Navigate up from generate_dataset.py to Analysis_Tools/
    return current_file.parent

def resolve_output_path(output_file, run_directory=None):
    """Resolve output file path - write to run directory if provided, otherwise use absolute path"""
    if os.path.isabs(output_file):
        return Path(output_file)
    elif run_directory:
        # Write directly to run directory
        datasets_dir = run_directory / "datasets"
        datasets_dir.mkdir(parents=True, exist_ok=True)
        return datasets_dir / output_file
    else:
        # No run directory provided - fail fast
        raise RuntimeError("Run directory required for dataset generation - standalone usage not supported")

def record_dataset_run(output_file, cve_count, run_directory, run_type="status_based"):
    """Record this dataset generation run in the run-specific tracking system"""
    try:
        # Write tracking data directly to run directory (unified runs structure)
        run_datasets_dir = run_directory / "datasets"
        run_datasets_dir.mkdir(exist_ok=True)
        tracker_file = run_datasets_dir / "dataset_tracker.json"
        
        # Load existing tracking data from run directory if it exists
        if tracker_file.exists():
            with open(tracker_file, 'r') as f:
                tracker_data = json.load(f)
        else:
            tracker_data = {
                "last_full_pull": None,
                "last_differential_pull": None,
                "run_history": [],
                "cve_history": {},
                "metadata": {
                    "version": "1.0",
                    "created": datetime.datetime.now().isoformat()
                }
            }
        
        # Generate descriptive run ID and context
        timestamp_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        dataset_name = Path(output_file).stem
        run_context = f"{dataset_name}_{cve_count}CVEs" if cve_count > 0 else dataset_name
        
        # Add new run record with enhanced context
        run_record = {
            "run_id": f"{run_type}_{timestamp_str}",
            "run_type": run_type,
            "timestamp": datetime.datetime.now().isoformat(),
            "cve_count": cve_count,
            "output_file": str(output_file),
            "run_context": run_context,  # For integration with run-based structure
            "size_category": "large" if cve_count > 10000 else "medium" if cve_count > 1000 else "small"
        }
        
        tracker_data["run_history"].append(run_record)
        
        # Update last full pull timestamp for status-based runs
        if run_type == "status_based":
            tracker_data["last_full_pull"] = datetime.datetime.now().isoformat()
        
        # Save updated tracking data to run directory only
        with open(tracker_file, 'w') as f:
            json.dump(tracker_data, f, indent=2, default=str)
            
        logger.info(f"Run recorded in tracking system: {run_record['run_id']}", group="initialization")
        logger.info(f"Dataset prepared for analysis context: {run_context}", group="initialization")
        
    except Exception as e:
        logger.error(f"Failed to record run in tracking system: {e}", group="data_processing")

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

def query_nvd_cves_by_status(api_key=None, target_statuses=None, output_file="cve_dataset.txt", run_directory=None):
    """
    Query NVD API for CVEs with specific vulnerability statuses
    
    Args:
        api_key (str): NVD API key (required for reasonable performance)
        target_statuses (list): List of vulnerability statuses to filter by
                               ['Received', 'Awaiting Analysis', 'Undergoing Analysis']
        output_file (str): Output file path
        run_directory (Path): Run directory where dataset should be written
    """
    if target_statuses is None:
        target_statuses = ['Received', 'Awaiting Analysis', 'Undergoing Analysis']
    
    logger.info("Starting CVE dataset generation...", group="initialization")
    logger.info(f"Target vulnerability statuses: {', '.join(target_statuses)}", group="initialization")
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
        # Construct URL with pagination
        url = f"{base_url}?resultsPerPage={results_per_page}&startIndex={start_index}"
        
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
                            record_api_call_unified("NVD CVE Dataset API", success=False)
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
                record_api_call_unified("NVD CVE Dataset API", success=True)
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
            
            if vuln_status in target_statuses:
                matching_cves.append(cve_id)
                logger.info(f"MATCH: {cve_id} - Status: {vuln_status}", group="cve_queries")
        
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
        logger.info(f"You can now run: python run_tools.py --file {output_file_resolved}", group="initialization")
        
        # Record output file in dataset contents collector
        if run_directory:
            record_output_file(output_file, str(output_file_resolved), len(matching_cves))
        
        # Record this run in the tracking system
        record_dataset_run(output_file_resolved, len(matching_cves), run_directory, "status_based")
        
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

def show_last_run_info():
    """Show information about the last dataset generation run"""
    try:
        # TODO: Update to read from latest run directory instead of global tracker
        logger.info("Last run info currently requires manual inspection of runs/ directory", group="initialization")
        logger.info("This feature will be updated to work with the unified runs structure", group="initialization")
        return
        
    except Exception as e:
        logger.error(f"Failed to show last run info: {e}", group="data_processing")


def generate_last_days(days, api_key=None, output_file="cve_recent_dataset.txt", run_directory=None):
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
        api_key, output_file, run_directory
    )


def generate_since_last_run(api_key=None, output_file="cve_differential_dataset.txt", run_directory=None):
    """Generate dataset for CVEs modified since the last run"""
    try:
        # TODO: Update to find latest run from runs/ directory structure
        logger.error("Differential dataset generation temporarily disabled", group="initialization")
        logger.error("This feature will be updated to work with the unified runs structure", group="initialization")
        return False
        
    except Exception as e:
        logger.error(f"Failed to generate differential dataset: {e}", group="data_processing")
        return False


def generate_date_range(start_date_str, end_date_str, api_key=None, output_file="cve_range_dataset.txt", run_directory=None):
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
        
        return query_nvd_cves_by_date_range(start_date_str, end_date_str, api_key, output_file, run_directory)
        
    except ValueError as e:
        logger.error(f"Invalid date format: {e}", group="initialization")
        return False


def query_nvd_cves_by_date_range(start_date, end_date, api_key=None, output_file="cve_dataset.txt", run_directory=None):
    """Query NVD API for CVEs modified within a date range"""
    logger.info(f"Querying CVEs modified between {start_date} and {end_date}", group="initialization")
    
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
        
        # Record this run
        record_dataset_run(output_file_resolved, len(matching_cves), run_directory, "date_range")
        
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
    parser.add_argument('--api-key', type=str, help='NVD API key (optional but recommended)')
    parser.add_argument('--output', type=str, default='cve_dataset.txt', 
                       help='Output file path (default: cve_dataset.txt)')
    
    # Traditional status-based options
    parser.add_argument('--statuses', nargs='+', 
                       default=['Received', 'Awaiting Analysis', 'Undergoing Analysis'],
                       help='Vulnerability statuses to include (default: Received, Awaiting Analysis, Undergoing Analysis)')
    
    # New date-based options
    parser.add_argument('--last-days', type=int,
                       help='Generate dataset for CVEs modified in the last N days')
    parser.add_argument('--start-date', type=str,
                       help='Start date for lastModified filter (YYYY-MM-DD or ISO format)')
    parser.add_argument('--end-date', type=str,
                       help='End date for lastModified filter (YYYY-MM-DD or ISO format)')
    parser.add_argument('--since-last-run', action='store_true',
                       help='Generate dataset for CVEs modified since last run')
    
    # Processing options
    parser.add_argument('--run-analysis', action='store_true', default=True,
                       help='Automatically run analysis tool after dataset generation (default: True)')
    parser.add_argument('--no-analysis', action='store_true',
                       help='Skip running analysis tool after dataset generation')
    parser.add_argument('--external-assets', action='store_true',
                       help='Enable external assets in analysis (passed through to run_tools.py)')
    parser.add_argument('--show-last-run', action='store_true',
                       help='Show when the last dataset generation occurred')
    
    args = parser.parse_args()
    
    logger.info("=" * 80, group="initialization")
    logger.info("NVD CVE Dataset Generator", group="initialization")
    logger.info("=" * 80, group="initialization")
    
    # Handle info requests
    if args.show_last_run:
        show_last_run_info()
        return 0
    
    # Resolve API key from command line, config, or default to None
    resolved_api_key = args.api_key or config['defaults']['default_api_key'] or None
    
    if not resolved_api_key:
        logger.error("API key is required for dataset generation", group="initialization")
        logger.error("Either use --api-key parameter or set default_api_key in config.json", group="initialization")
        logger.error("NVD API without a key has severe rate limits that make dataset generation impractical", group="initialization")
        return 1
    
    logger.info("Using API key for enhanced rate limits", group="initialization")
    
    # Create run directory first - ALL dataset generation creates runs
    from src.analysis_tool.storage.run_organization import create_run_directory
    
    # Generate initial run context
    if args.since_last_run:
        initial_context = "differential_dataset"
    elif args.last_days:
        initial_context = f"last_{args.last_days}_days_dataset"
    elif args.start_date and args.end_date:
        initial_context = f"range_{args.start_date}_to_{args.end_date}_dataset"
    else:
        initial_context = "status_based_dataset"
    
    # Create run directory
    run_directory, run_id = create_run_directory(initial_context)
    logger.info(f"Created dataset generation run: {run_id}", group="initialization")
    logger.info(f"Run directory: {run_directory}", group="initialization")
    
    # Generate dataset directly in run directory
    success = False
    
    # Determine which mode to use - all write directly to run directory
    if args.since_last_run:
        success = generate_since_last_run(resolved_api_key, args.output, run_directory)
    elif args.last_days:
        success = generate_last_days(args.last_days, resolved_api_key, args.output, run_directory)
    elif args.start_date and args.end_date:
        success = generate_date_range(args.start_date, args.end_date, resolved_api_key, args.output, run_directory)
    else:
        # Traditional status-based generation
        success = query_nvd_cves_by_status(
            api_key=resolved_api_key,
            target_statuses=args.statuses,
            output_file=args.output,
            run_directory=run_directory
        )
    
    if success:
        logger.info("Dataset generation completed successfully!", group="initialization")
        
        # Run analysis tool by default unless --no-analysis is specified
        should_run_analysis = args.run_analysis and not args.no_analysis
        
        if should_run_analysis:
            logger.info("Starting integrated analysis run...", group="initialization")
            
            # Dataset was already written to run directory, so just run analysis
            # The run directory already contains the dataset in datasets/ subdirectory
            dataset_path = run_directory / "datasets" / Path(args.output).name
            
            # Run analysis tool with existing run context
            success = run_analysis_tool(args.output, resolved_api_key, run_directory, run_id, args.external_assets)
            if not success:
                logger.error("Analysis tool execution failed", group="data_processing")
                return 1
        else:
            logger.info("Skipping analysis tool execution (--no-analysis specified)", group="initialization")
    else:
        logger.error("Dataset generation process failed: Unable to complete CVE data collection and processing", group="data_processing")
        return 1
    
    return 0


def run_analysis_tool(dataset_file, api_key=None, run_directory=None, run_id=None, external_assets=False):
    """Run the analysis tool on the generated dataset within an existing run context"""
    import subprocess
    
    try:
        # Get paths
        root_path = get_analysis_tools_root()
        run_tools_path = root_path / "run_tools.py"
        
        if not run_tools_path.exists():
            logger.error(f"run_tools.py not found at {run_tools_path}", group="data_processing")
            return False

        # If we have a run directory context, the dataset should be in that run
        if not run_directory:
            raise RuntimeError("Run directory required for integrated analysis - legacy behavior removed")
            
        dataset_path = run_directory / "datasets" / Path(dataset_file).name
        if not dataset_path.exists():
            raise FileNotFoundError(f"Dataset file not found in run directory: {dataset_path}")
        
        # Check dataset size for smart batch handling
        try:
            cve_count = sum(1 for line in open(dataset_path) if line.strip())
            logger.info(f"Dataset contains {cve_count:,} CVE entries", group="initialization")
        except Exception as e:
            logger.error(f"Failed to count CVEs in dataset: {e}", group="data_processing")
            cve_count = 0
        
        # Build command with run context integration
        cmd = [
            "python", str(run_tools_path),
            "--file", str(dataset_path)
        ]
        
        # Add run context if available
        if run_id:
            cmd.extend(["--run-id", run_id])
            logger.info(f"Continuing analysis within existing run: {run_id}", group="initialization")
        
        
        if api_key:
            cmd.extend(["--api-key", api_key])
        
        if external_assets:
            cmd.append("--external-assets")
        
        logger.info(f"Executing: {' '.join(cmd)}", group="initialization")
        
        if run_directory:
            logger.info(f"Analysis will continue in run directory: {run_directory}", group="initialization")
        else:
            logger.info(f"Analysis will create new run directory", group="initialization")
        
        # Run the analysis tool with live output
        logger.info("Handing off to analysis tool - live output will follow:", group="initialization")
        logger.info("-" * 60, group="initialization")
        
        result = subprocess.run(
            cmd,
            cwd=str(root_path)
        )
        
        logger.info("-" * 60, group="initialization")
        if result.returncode == 0:
            logger.info("Analysis tool completed successfully", group="initialization")
            if run_directory:
                logger.info(f"Results available in: {run_directory}", group="initialization")
            return True
        else:
            logger.error(f"Analysis tool failed with return code {result.returncode}", 
                        group="data_processing")
            return False
            
    except FileNotFoundError:
        logger.error("Python interpreter not found", group="data_processing")
        return False
    except Exception as e:
        logger.error(f"Failed to run analysis tool: {e}", group="data_processing")
        return False

if __name__ == "__main__":
    exit(main())
