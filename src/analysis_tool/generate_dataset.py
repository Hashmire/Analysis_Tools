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

# Load configuration
def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)

config = load_config()
VERSION = config['application']['version']
TOOLNAME = config['application']['toolname']

def get_utc_timestamp():
    """Get current UTC timestamp in ISO format."""
    return datetime.datetime.utcnow().isoformat() + " UTC"

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
    
    print(f"[INFO] Starting CVE dataset generation...")
    print(f"[INFO] Target vulnerability statuses: {', '.join(target_statuses)}")
    print(f"[INFO] Output file: {output_file}")
    print(f"[INFO] Using API key: {'Yes' if api_key else 'No'}")
    if test_limit:
        print(f"[INFO] Test mode enabled - limiting to {test_limit} CVEs")
    
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
    
    print(f"[INFO] {get_utc_timestamp()} - Starting CVE collection...")
    
    while True:
        # Construct URL with pagination
        url = f"{base_url}?resultsPerPage={results_per_page}&startIndex={start_index}"
        
        print(f"[INFO] Querying page starting at index {start_index}...")
        
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
                timestamp = get_utc_timestamp()
                print(f"[ERROR] {timestamp} - Error fetching CVE data (Attempt {attempt + 1}/{max_retries}): {e}")
                
                if hasattr(e, 'response') and e.response is not None:
                    if 'message' in e.response.headers:
                        print(f"[ERROR] NVD API Message: {e.response.headers['message']}")
                    print(f"[ERROR] Response status code: {e.response.status_code}")
                
                if attempt < max_retries - 1:
                    wait_time = config['api']['retry']['delay_without_key'] if not api_key else config['api']['retry']['delay_with_key']
                    print(f"Waiting {wait_time} seconds before retry...")
                    sleep(wait_time)
                else:
                    print("Max retries reached for this page. Stopping.")
                    break
        
        if page_data is None:
            print("[ERROR] Failed to retrieve data for current page. Stopping.")
            break
        
        # Process CVEs in this page
        vulnerabilities = page_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            print("[INFO] No more vulnerabilities found. Collection complete.")
            break
        
        print(f"[INFO] Processing {len(vulnerabilities)} CVEs from this page...")
        
        for vuln in vulnerabilities:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', '')
            vuln_status = cve_data.get('vulnStatus', '')
            
            if vuln_status in target_statuses:
                matching_cves.append(cve_id)
                print(f"[MATCH] {cve_id} - Status: {vuln_status}")
                
                # Check test limit
                if test_limit and len(matching_cves) >= test_limit:
                    print(f"[INFO] Reached test limit of {test_limit} CVEs. Stopping.")
                    break
        
        # Check if we hit test limit and break outer loop
        if test_limit and len(matching_cves) >= test_limit:
            break
        
        # Check if we have more pages
        total_results = page_data.get('totalResults', 0)
        current_end = start_index + len(vulnerabilities)
        
        print(f"[INFO] Processed {current_end} of {total_results} total CVEs")
        print(f"[INFO] Found {len(matching_cves)} matching CVEs so far")
        
        if current_end >= total_results:
            print("[INFO] Reached end of available CVEs.")
            break
        
        # Move to next page
        start_index += results_per_page
        
        # Rate limiting - wait between pages
        if not api_key:
            wait_time = config['api']['retry']['page_delay_without_key']
            print(f"[INFO] Waiting {wait_time} seconds before next page (rate limiting)...")
            sleep(wait_time)
        else:
            wait_time = config['api']['retry']['page_delay_with_key']
            if wait_time > 0:
                print(f"[INFO] Waiting {wait_time} seconds before next page...")
                sleep(wait_time)
    
    # Write results to file
    print(f"\n[INFO] Writing {len(matching_cves)} CVE IDs to {output_file}...")
    
    try:
        with open(output_file, 'w') as f:
            for cve_id in matching_cves:
                f.write(f"{cve_id}\n")
        
        print(f"[SUCCESS] Dataset generated successfully!")
        print(f"[INFO] Total CVEs found: {len(matching_cves)}")
        print(f"[INFO] File saved: {output_file}")
        print(f"[INFO] You can now run: python analysis_tool.py --file {output_file}")
        
    except Exception as e:
        print(f"[ERROR] Failed to write output file: {e}")
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
    parser.add_argument('--test-mode', action='store_true', 
                       help='Enable test mode to limit to first 100 matching CVEs for testing')
    
    args = parser.parse_args()
    
    print("="*80)
    print("NVD CVE Dataset Generator")
    print("="*80)
    
    # Set test limit if in test mode
    test_limit = 100 if args.test_mode else None
    
    success = query_nvd_cves_by_status(
        api_key=args.api_key,
        target_statuses=args.statuses,
        output_file=args.output,
        test_limit=test_limit
    )
    
    if success:
        print("\n[INFO] Dataset generation completed successfully!")
    else:
        print("\n[ERROR] Dataset generation failed!")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
