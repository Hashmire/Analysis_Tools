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
from ..workflow_logger import WorkflowLogger

def get_analysis_tools_root():
    """Get the absolute path to the Analysis_Tools project root"""
    current_file = Path(__file__).resolve()
    # Navigate up from src/analysis_tool/utilities/generate_dataset.py to Analysis_Tools/
    return current_file.parent.parent.parent.parent

def ensure_datasets_directory():
    """Ensure the datasets directory exists and return its path"""
    datasets_dir = get_analysis_tools_root() / "datasets"
    datasets_dir.mkdir(parents=True, exist_ok=True)
    return datasets_dir

def resolve_output_path(output_file):
    """Resolve output file path - if relative, put in datasets directory"""
    if os.path.isabs(output_file):
        return Path(output_file)
    else:
        return ensure_datasets_directory() / output_file

def record_dataset_run(output_file, cve_count, run_type="status_based"):
    """Record this dataset generation run in the tracking system"""
    try:
        tracker_file = ensure_datasets_directory() / "dataset_tracker.json"
        
        # Load existing tracking data
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
        
        # Add new run record
        run_record = {
            "run_id": f"{run_type}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "run_type": run_type,
            "timestamp": datetime.datetime.now().isoformat(),
            "cve_count": cve_count,
            "output_file": str(output_file)
        }
        
        tracker_data["run_history"].append(run_record)
        
        # Update last full pull timestamp for status-based runs
        if run_type == "status_based":
            tracker_data["last_full_pull"] = datetime.datetime.now().isoformat()
        
        # Save updated tracking data
        with open(tracker_file, 'w') as f:
            json.dump(tracker_data, f, indent=2, default=str)
            
        logger.info(f"Run recorded in tracking system: {run_record['run_id']}", group="initialization")
        
    except Exception as e:
        logger.error(f"Failed to record run in tracking system: {e}", group="data_processing")

# Load configuration
def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)

config = load_config()
VERSION = config['application']['version']
TOOLNAME = config['application']['toolname']

# Initialize logger
logger = WorkflowLogger()

def query_nvd_cves_by_status(api_key=None, target_statuses=None, output_file="cve_dataset.txt", test_limit=None):
    """
    Query NVD API for CVEs with specific vulnerability statuses
    
    Args:
        api_key (str): NVD API key (optional but recommended for higher rate limits)
        target_statuses (list): List of vulnerability statuses to filter by
                               ['Received', 'Awaiting Analysis', 'Undergoing Analysis']
        output_file (str): Output file path
        test_limit (int): Limit number of matching CVEs for testing (None for no limit)
    """
    if target_statuses is None:
        target_statuses = ['Received', 'Awaiting Analysis', 'Undergoing Analysis']
    
    logger.info("Starting CVE dataset generation...", group="initialization")
    logger.info(f"Target vulnerability statuses: {', '.join(target_statuses)}", group="initialization")
    logger.info(f"Output file: {output_file}", group="initialization")
    logger.info(f"Using API key: {'Yes' if api_key else 'No'}", group="initialization")
    if test_limit:
        logger.info(f"Test mode enabled - limiting to {test_limit} CVEs", group="initialization")
    
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
                
                if attempt < max_retries - 1:
                    wait_time = config['api']['retry']['delay_without_key'] if not api_key else config['api']['retry']['delay_with_key']
                    logger.info(f"Waiting {wait_time} seconds before retry...", group="cve_queries")
                    sleep(wait_time)
                else:
                    logger.error(f"Dataset generation failed: Maximum retry attempts ({max_retries}) reached for current page - stopping data collection", group="data_processing")
                    break
        
        if page_data is None:
            logger.error("Dataset generation failed: Unable to retrieve page data after all retry attempts - stopping data collection", group="data_processing")
            break
        
        # Process CVEs in this page
        vulnerabilities = page_data.get('vulnerabilities', [])
        
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
                
                # Check test limit
                if test_limit and len(matching_cves) >= test_limit:
                    logger.info(f"Reached test limit of {test_limit} CVEs. Stopping.", group="cve_queries")
                    break
        
        # Check if we hit test limit and break outer loop
        if test_limit and len(matching_cves) >= test_limit:
            break
        
        # Check if we have more pages
        total_results = page_data.get('totalResults', 0)
        current_end = start_index + len(vulnerabilities)
        progress_pct = (current_end / total_results * 100) if total_results > 0 else 0
        logger.info(f"Processing CVE dataset generation: {current_end}/{total_results} ({progress_pct:.1f}%) - {len(matching_cves)} matching CVE records found", group="cve_queries")
        
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
    output_file_resolved = resolve_output_path(output_file)
    
    logger.info(f"Writing {len(matching_cves)} CVE IDs to {output_file_resolved}...", group="initialization")
    
    try:
        with open(output_file_resolved, 'w') as f:
            for cve_id in matching_cves:
                f.write(f"{cve_id}\n")
        
        logger.info("Dataset generated successfully!", group="initialization")
        logger.info(f"Collected {len(matching_cves)} CVE records", group="initialization")
        logger.info(f"File saved: {output_file_resolved}", group="initialization")
        logger.info(f"You can now run: python run_tools.py --file {output_file_resolved}", group="initialization")
        
        # Record this run in the tracking system
        record_dataset_run(output_file_resolved, len(matching_cves), "status_based")
        
    except Exception as e:
        logger.error(f"Dataset file creation failed: Unable to write dataset output to '{output_file_resolved}' - {e}", group="data_processing")
        return False
    
    return True

def show_last_run_info():
    """Show information about the last dataset generation run"""
    try:
        tracker_file = ensure_datasets_directory() / "dataset_tracker.json"
        if not tracker_file.exists():
            print("No previous runs found.")
            return
        
        with open(tracker_file, 'r') as f:
            tracker_data = json.load(f)
        
        if not tracker_data.get("run_history"):
            print("No previous runs found.")
            return
        
        last_run = tracker_data["run_history"][-1]
        timestamp = datetime.datetime.fromisoformat(last_run["timestamp"])
        
        print(f"Last run: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Type: {last_run['run_type']}")
        print(f"CVE count: {last_run['cve_count']}")
        print(f"Output file: {last_run['output_file']}")
        
    except Exception as e:
        logger.error(f"Failed to show last run info: {e}", group="data_processing")


def generate_last_days(days, api_key=None, output_file="cve_recent_dataset.txt", test_limit=None):
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
        api_key, output_file, test_limit
    )


def generate_since_last_run(api_key=None, output_file="cve_differential_dataset.txt", test_limit=None):
    """Generate dataset for CVEs modified since the last run"""
    try:
        tracker_file = ensure_datasets_directory() / "dataset_tracker.json"
        if not tracker_file.exists():
            logger.error("No previous runs found. Cannot generate differential dataset.", group="initialization")
            return False
        
        with open(tracker_file, 'r') as f:
            tracker_data = json.load(f)
        
        if not tracker_data.get("run_history"):
            logger.error("No previous runs found. Cannot generate differential dataset.", group="initialization")
            return False
        
        last_run = tracker_data["run_history"][-1]
        start_date = datetime.datetime.fromisoformat(last_run["timestamp"])
        end_date = datetime.datetime.now()
        
        # Check if range exceeds 120 days
        if (end_date - start_date).days > 120:
            start_date = end_date - datetime.timedelta(days=120)
            logger.info("Last run was more than 120 days ago. Limiting to last 120 days.", group="initialization")
        
        logger.info(f"Generating differential dataset since {start_date.strftime('%Y-%m-%d %H:%M:%S')}", group="initialization")
        
        return query_nvd_cves_by_date_range(
            start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            end_date.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            api_key, output_file, test_limit
        )
        
    except Exception as e:
        logger.error(f"Failed to generate differential dataset: {e}", group="data_processing")
        return False


def generate_date_range(start_date_str, end_date_str, api_key=None, output_file="cve_range_dataset.txt", test_limit=None):
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
        
        return query_nvd_cves_by_date_range(start_date_str, end_date_str, api_key, output_file, test_limit)
        
    except ValueError as e:
        logger.error(f"Invalid date format: {e}", group="initialization")
        return False


def query_nvd_cves_by_date_range(start_date, end_date, api_key=None, output_file="cve_dataset.txt", test_limit=None):
    """Query NVD API for CVEs modified within a date range"""
    logger.info(f"Querying CVEs modified between {start_date} and {end_date}", group="initialization")
    
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
        
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers, timeout=config['api']['timeouts']['nvd_api'])
                response.raise_for_status()
                page_data = response.json()
                break
            except requests.exceptions.RequestException as e:
                logger.error(f"NVD API request failed: {e} (Attempt {attempt + 1}/{max_retries})", group="data_processing")
                if attempt < max_retries - 1:
                    wait_time = config['api']['retry']['delay_without_key'] if not api_key else config['api']['retry']['delay_with_key']
                    sleep(wait_time)
        
        if page_data is None:
            logger.error("Failed to retrieve page data", group="data_processing")
            break
        
        vulnerabilities = page_data.get('vulnerabilities', [])
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
                
                if test_limit and len(matching_cves) >= test_limit:
                    logger.info(f"Reached test limit of {test_limit} CVEs. Stopping.", group="cve_queries")
                    break
        
        if test_limit and len(matching_cves) >= test_limit:
            break
        
        total_results = page_data.get('totalResults', 0)
        current_end = start_index + len(vulnerabilities)
        progress_pct = (current_end / total_results * 100) if total_results > 0 else 0
        logger.info(f"Progress: {current_end}/{total_results} ({progress_pct:.1f}%) - {len(matching_cves)} CVEs found", group="cve_queries")
        
        if current_end >= total_results:
            break
        
        start_index += results_per_page
        
        # Rate limiting
        wait_time = config['api']['retry']['page_delay_without_key'] if not api_key else config['api']['retry']['page_delay_with_key']
        if wait_time > 0:
            sleep(wait_time)
    
    # Write results
    output_file_resolved = resolve_output_path(output_file)
    try:
        with open(output_file_resolved, 'w') as f:
            for cve_id in matching_cves:
                f.write(f"{cve_id}\n")
        
        logger.info(f"Dataset generated successfully: {len(matching_cves)} CVEs", group="initialization")
        logger.info(f"File saved: {output_file_resolved}", group="initialization")
        
        # Record this run
        record_dataset_run(output_file_resolved, len(matching_cves), "date_range")
        
        return True
    except Exception as e:
        logger.error(f"Failed to write output file: {e}", group="data_processing")
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
    parser.add_argument('--test-mode', action='store_true',
                       help='Enable test mode to limit to first 100 matching CVEs for testing')
    parser.add_argument('--run-analysis', action='store_true',
                       help='Automatically run analysis tool after dataset generation')
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
    
    # Set test limit if in test mode
    test_limit = 100 if args.test_mode else None
    success = False
    
    # Determine which mode to use
    if args.since_last_run:
        success = generate_since_last_run(args.api_key, args.output, test_limit)
    elif args.last_days:
        success = generate_last_days(args.last_days, args.api_key, args.output, test_limit)
    elif args.start_date and args.end_date:
        success = generate_date_range(args.start_date, args.end_date, args.api_key, args.output, test_limit)
    else:
        # Traditional status-based generation
        success = query_nvd_cves_by_status(
            api_key=args.api_key,
            target_statuses=args.statuses,
            output_file=args.output,
            test_limit=test_limit
        )
    
    if success:
        logger.info("Dataset generation completed successfully!", group="initialization")
        
        # Optionally run analysis tool
        if args.run_analysis:
            logger.info("Starting analysis tool processing...", group="initialization")
            success = run_analysis_tool(args.output, args.api_key)
            if not success:
                logger.error("Analysis tool execution failed", group="data_processing")
                return 1
    else:
        logger.error("Dataset generation process failed: Unable to complete CVE data collection and processing", group="data_processing")
        return 1
    
    return 0


def run_analysis_tool(dataset_file, api_key=None):
    """Run the analysis tool on the generated dataset"""
    import subprocess
    
    try:
        # Get paths
        root_path = get_analysis_tools_root()
        run_tools_path = root_path / "run_tools.py"
        dataset_path = resolve_output_path(dataset_file)
        
        if not run_tools_path.exists():
            logger.error(f"run_tools.py not found at {run_tools_path}", group="data_processing")
            return False
        
        if not dataset_path.exists():
            logger.error(f"Dataset file not found at {dataset_path}", group="data_processing")
            return False
        
        # Build command
        cmd = [
            "python", str(run_tools_path),
            "--file", str(dataset_path)
        ]
        
        if api_key:
            cmd.extend(["--api-key", api_key])
        
        logger.info(f"Executing: {' '.join(cmd)}", group="initialization")
        
        # Run the analysis tool
        result = subprocess.run(
            cmd,
            cwd=str(root_path),
            capture_output=True,
            text=True,
            timeout=7200  # 2 hour timeout
        )
        
        if result.returncode == 0:
            logger.info("Analysis tool completed successfully", group="initialization")
            return True
        else:
            logger.error(f"Analysis tool failed with return code {result.returncode}", 
                        group="data_processing")
            logger.error(f"Error output: {result.stderr}", group="data_processing")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error("Analysis tool timed out after 2 hours", group="data_processing")
        return False
    except FileNotFoundError:
        logger.error("Python interpreter not found", group="data_processing")
        return False
    except Exception as e:
        logger.error(f"Failed to run analysis tool: {e}", group="data_processing")
        return False

if __name__ == "__main__":
    exit(main())
