#!/usr/bin/env python3
"""
NVD CVE Dataset Generator
This script queries the NVD API for CVEs with specific vulnerability statuses
and generates a file with one CVE ID per line for use with analysis_tool.py
"""

import requests
import json
import os
import datetime
from time import sleep
import argparse
from pathlib import Path
from .workflow_logger import WorkflowLogger

def get_analysis_tools_root():
    """Get the absolute path to the Analysis_Tools project root"""
    current_file = Path(__file__).resolve()
    # Navigate up from src/analysis_tool/generate_dataset.py to Analysis_Tools/
    return current_file.parent.parent.parent

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

# Load configuration
def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
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
        logger.info(f"You can now run: python analysis_tool.py --file {output_file_resolved}", group="initialization")
        
    except Exception as e:
        logger.error(f"Dataset file creation failed: Unable to write dataset output to '{output_file_resolved}' - {e}", group="data_processing")
        return False
    
    return True

def main():
    """Main function with command line argument parsing"""
    parser = argparse.ArgumentParser(description='Generate CVE dataset from NVD API')
    parser.add_argument('--api-key', type=str, help='NVD API key (optional but recommended)')
    parser.add_argument('--output', type=str, default='cve_dataset.txt', 
                       help='Output file path (default: cve_dataset.txt)')
    parser.add_argument('--statuses', nargs='+', 
                       default=['Received', 'Awaiting Analysis', 'Undergoing Analysis'],
                       help='Vulnerability statuses to include (default: Received, Awaiting Analysis, Undergoing Analysis)')
    parser.add_argument('--test-mode', action='store_true',                       help='Enable test mode to limit to first 100 matching CVEs for testing')
    
    args = parser.parse_args()
    
    logger.info("=" * 80, group="initialization")
    logger.info("NVD CVE Dataset Generator", group="initialization")
    logger.info("=" * 80, group="initialization")
    
    # Set test limit if in test mode
    test_limit = 100 if args.test_mode else None
    
    success = query_nvd_cves_by_status(
        api_key=args.api_key,
        target_statuses=args.statuses,
        output_file=args.output,
        test_limit=test_limit    )
    
    if success:
        logger.info("Dataset generation completed successfully!", group="initialization")
    else:
        logger.error("Dataset generation process failed: Unable to complete CVE data collection and processing", group="data_processing")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
