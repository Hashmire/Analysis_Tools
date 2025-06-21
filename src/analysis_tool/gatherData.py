# Import Python dependencies
import requests
import pandas as pd
import os
import json
from time import sleep
import datetime
import requests

# Import Analysis Tool 
import processData

# Import the new logging system
from workflow_logger import get_logger, LogGroup

# Get logger instance
logger = get_logger()

# Load configuration
def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)

config = load_config()
VERSION = config['application']['version']
TOOLNAME = config['application']['toolname']



def get_public_ip():
    """Get the current public IP address being used by the tool."""
    try:
        response = requests.get(config['api']['endpoints']['public_ip'], 
                              timeout=config['api']['timeouts']['public_ip'])
        return response.text if response.status_code == 200 else "Unknown"
    except Exception as e:
        return f"Could not retrieve IP: {str(e)}"

# Helper function to get current UTC timestamp
def get_utc_timestamp():
    """Get current UTC timestamp in ISO format."""
    return datetime.datetime.utcnow().isoformat() + " UTC"

# Update gatherCVEListRecord function
def gatherCVEListRecord(targetCve):
    # Set the API Endpoint target
    cveOrgJSON = config['api']['endpoints']['cve_list']
    # create the simple URL using user input ID and expected URL
    simpleCveRequestUrl = cveOrgJSON + targetCve
    
    logger.api_call("MITRE CVE API", {"cve_id": targetCve}, group="cve_queries")
    
    try:
        r = requests.get(simpleCveRequestUrl, timeout=config['api']['timeouts']['cve_org'])
        r.raise_for_status()  
        cveRecordDict = r.json()

        processData.integrityCheckCVE("cveIdMatch", targetCve, cveRecordDict)
        processData.integrityCheckCVE("cveStatusCheck", "REJECTED", cveRecordDict)
        
        logger.api_response("MITRE CVE API", "Success", group="cve_queries")
        return cveRecordDict
    except requests.exceptions.RequestException as e:
        public_ip = get_public_ip()
        timestamp = get_utc_timestamp()
        logger.error(f"{timestamp} - Error fetching CVE List data for {targetCve}: {e}", group="error_handling")
        logger.info(f"Current public IP address: {public_ip}", group="error_handling")
        return None

# Using provided CVE-ID, get the CVE data from the NVD API 
def gatherNVDCVERecord(apiKey, targetCve):
    logger.api_call("NVD CVE API", {"cve_id": targetCve}, group="cve_queries")
   
    url = config['api']['endpoints']['nvd_cves'] + "?cveId=" + targetCve
    headers = {
        "Accept": "application/json",
        "User-Agent": f"{TOOLNAME}/{VERSION}"
    }
      # Only add API key to headers if one was provided
    if apiKey:
        headers["apiKey"] = apiKey
   
    max_retries = config['api']['retry']['max_attempts_nvd']
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, timeout=config['api']['timeouts']['nvd_api'])
            response.raise_for_status()
            logger.api_response("NVD CVE API", "Success", group="cve_queries")
            return response.json()
        except requests.exceptions.RequestException as e:
            public_ip = get_public_ip()
            timestamp = get_utc_timestamp()
            logger.error(f"{timestamp} - Error fetching NVD CVE record data (Attempt {attempt + 1}/{max_retries}): {e}", group="error_handling")
            logger.info(f"Current public IP address: {public_ip}", group="cve_queries")
            
            if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                logger.error(f"NVD API Message: {e.response.headers['message']}", group="error_handling")
            
            if attempt < max_retries - 1:
                wait_time = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                logger.info(f"Waiting {wait_time} seconds before retry...", group="cve_queries")
                sleep(wait_time)
            else:
                logger.info("Max retries reached. Giving up.", group="error_handling")
                return None
    
# Query NVD /source/ API for data and return a dataframe of the response content
def gatherNVDSourceData(apiKey):
    logger.info("Querying NVD /source/ API to get source mappings...", group="cve_queries")
    
    def fetch_nvd_data():
        url = config['api']['endpoints']['nvd_sources']
        headers = {
            "Accept": "application/json",
            "User-Agent": f"{TOOLNAME}/{VERSION}"
        }
        
        # Only add API key to headers if one was provided
        if apiKey:
            headers["apiKey"] = apiKey
       
        max_retries = config['api']['retry']['max_attempts_nvd']
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:                
                public_ip = get_public_ip()
                timestamp = get_utc_timestamp()
                logger.error(f"{timestamp} - Error fetching source data (Attempt {attempt + 1}/{max_retries}): {e}", group="error_handling")
                logger.info(f"Current public IP address: {public_ip}", group="cve_queries")
    
                if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                    logger.error(f"NVD API Message: {e.response.headers['message']}", group="error_handling")                
                if attempt < max_retries - 1:
                    wait_time = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                    logger.info(f"Waiting {wait_time} seconds before retry...", group="cve_queries")
                    sleep(wait_time)
                else:
                    logger.info("Max retries reached. Giving up.", group="error_handling")
                    return None
    
    def create_dataframe():
        data = fetch_nvd_data()
       
        if not data or 'sources' not in data:
            return None
       
        # Create DataFrame directly from the sources list
        df = pd.DataFrame(data['sources'])
       
        return df
   
    return create_dataframe()

# Query the NVD /cpes/ API for information Supported parameters:  cpeMatchString
def gatherNVDCPEData(apiKey, case, query_string):
    match case:
        case 'cpeMatchString':
            nvd_cpes_url = config['api']['endpoints']['nvd_cpes']
            headers = {"user-agent": f"{TOOLNAME}/{VERSION}"}
            
            # Only add API key to headers if one was provided
            if apiKey:
                headers["apiKey"] = apiKey
           
            max_retries = config['api']['retry']['max_attempts_cpe']
            for attempt in range(max_retries):
                try:
                    # Initial request to get total results
                    initial_params = {
                        "cpeMatchString": query_string,
                        "startIndex": 0
                    }
                   
                    response = requests.get(nvd_cpes_url, params=initial_params, headers=headers)
                    response.raise_for_status()
                    
                    initial_data = response.json()
                   
                    total_results = initial_data.get("totalResults", 0)
                    results_per_page = initial_data.get("resultsPerPage", 0)
                   
                    # If we already have all results, return initial response
                    if total_results <= results_per_page:
                        return initial_data
                   
                    # Initialize consolidated results with first batch
                    consolidated_data = initial_data.copy()
                    consolidated_data["products"] = initial_data.get("products", []).copy()
                     # Calculate number of additional requests needed
                    remaining_results = total_results - results_per_page
                    current_index = results_per_page                    
                    logger.info(f"Found {total_results} total results for {query_string}. Collecting all pages...", group="cpe_queries")
                   
                    # Collect remaining pages
                    while remaining_results > 0:
                        for page_attempt in range(max_retries):
                            try:                                # Add delay to respect rate limits
                                if not headers.get("apiKey"):
                                    sleep(config['api']['retry']['page_delay_without_key'])  # Conservative approach without API key
                                else:
                                    sleep(config['api']['retry']['page_delay_with_key'])  # More aggressive with API key
                               
                                params = {
                                    "cpeMatchString": query_string,
                                    "startIndex": current_index
                                }
                               
                                response = requests.get(nvd_cpes_url, params=params, headers=headers)
                                response.raise_for_status()
                                
                                page_data = response.json()
                               
                                # Add products from this page to consolidated results
                                if "products" in page_data:
                                    consolidated_data["products"].extend(page_data["products"])
                                 # Update counters
                                results_this_page = len(page_data.get("products", []))
                                remaining_results -= results_this_page
                                current_index += results_per_page
                                 
                                logger.info(f"Collected {len(consolidated_data['products'])} of {total_results} results...", group="cpe_queries")
                                break
                            except requests.exceptions.RequestException as e:
                                public_ip = get_public_ip()
                                timestamp = get_utc_timestamp()
                                logger.error(f"{timestamp} - Error fetching page data (Attempt {page_attempt + 1}/{max_retries}): {e}", group="error_handling")
                                logger.info(f"Current public IP address: {public_ip}", group="cpe_queries")
                                  # Check for message header and display if present - error response
                                if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                                    error_message = e.response.headers['message']
                                    logger.error(f"NVD API Message: {error_message}", group="error_handling")
                                    
                                    # Don't retry for "Invalid cpeMatchstring parameter" errors
                                    if "Invalid cpeMatchstring parameter" in error_message:
                                        logger.warning(f"Invalid CPE match string detected, skipping: {query_string}", group="cpe_queries")
                                        # Return what we've collected so far
                                        consolidated_data["startIndex"] = 0
                                        consolidated_data["resultsPerPage"] = len(consolidated_data["products"])
                                        consolidated_data["error"] = error_message
                                        consolidated_data["status"] = "invalid_cpe"
                                        return consolidated_data
                                
                                if page_attempt < max_retries - 1:
                                    logger.info("Waiting 6 seconds before retry...", group="cpe_queries")
                                    sleep(6)
                                else:
                                    logger.info("Max retries reached for page data. Giving up.", group="error_handling")
                                    return None
                   
                    # Update final counts
                    consolidated_data["startIndex"] = 0
                    consolidated_data["resultsPerPage"] = len(consolidated_data["products"])
                   
                    return consolidated_data
                   
                except requests.exceptions.RequestException as e:
                    public_ip = get_public_ip()
                    timestamp = get_utc_timestamp()
                    logger.error(f"{timestamp} - Error fetching data (Attempt {attempt + 1}/{max_retries}): {e}", group="error_handling")
                    logger.info(f"Current public IP address: {public_ip}", group="cpe_queries")
                    
                    # Check for message header and display if present - error response
                    if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                        error_message = e.response.headers['message']
                        logger.error(f"NVD API Message: {error_message}", group="error_handling")
                        
                        # Don't retry for "Invalid cpeMatchstring parameter" errors
                        if "Invalid cpeMatchstring parameter" in error_message:
                            logger.warning(f"Invalid CPE match string detected, skipping: {query_string}", group="cpe_queries")
                            # Return empty result structure instead of None
                            return {
                                "totalResults": 0,
                                "resultsPerPage": 0,
                                "startIndex": 0,
                                "products": [],
                                "error": error_message,
                                "status": "invalid_cpe"
                            }
                    
                    if attempt < max_retries - 1:
                        logger.info("Waiting 6 seconds before retry...", group="cpe_queries")
                        sleep(6)
                    else:
                        logger.info("Max retries reached. Giving up.", group="error_handling")
                        return None
        
        case _:
            return None

# Creates the primary dataframe to be referenced and modified as needed throughout the process
def gatherPrimaryDataframe():
    data = {
        'sourceID': '',
        'sourceRole': '',
        'rawPlatformData': [],
        'rawCPEsQueryData': [],
        'sortedCPEsQueryData': [],
        'trimmedCPEsQueryData': [],
        }

    # Create DataFrame
    return pd.DataFrame(data)

# Using the provided CVE-ID, gathers relevant VDB information from known, publicly available sources
# def gatherVDBIntel(targetCve):
#    # This currently references another file, we should bring that file into here and break it out into the appropriate Gather/Process/Generate groupings
#    try:
#        vdbIntelHtml = vdb_checker.gatherVDBCheckerData(targetCve)
#        return (vdbIntelHtml)
#   except:
#        print("[ERROR]  Failed to run vdb_checker!")

def gatherAllCVEIDs(apiKey):
    """
    Gather all CVE IDs from the NVD API with proper retry mechanism.
    
    Args:
        apiKey: NVD API key for authentication
        
    Returns:
        List of all CVE IDs
    """    
    
    base_url = config['api']['endpoints']['nvd_cves']
    headers = {
        "Accept": "application/json",
        "User-Agent": f"{TOOLNAME}/{VERSION}"
    }
    
    # Add API key to headers if provided
    if apiKey:
        headers["apiKey"] = apiKey
    
    params = {
        "startIndex": 0,
    }
    all_cves = []
    total_results = None
    results_per_page = 2000  # Default NVD API page size
    start_index = 0
    
    # Define retry parameters
    max_retries = config['api']['retry']['max_attempts_nvd']
    
    while total_results is None or start_index < total_results:
        params["startIndex"] = start_index
        
        for attempt in range(max_retries):
            try:
                current_page = start_index // results_per_page + 1
                pages_estimate = total_results // results_per_page + 1 if total_results else "?"
                
                if total_results:
                    progress = min(start_index, total_results) / total_results * 100
                    logger.info(f"Querying CVEs [Page {current_page}/{pages_estimate}] - {progress:.1f}% complete ({len(all_cves)} CVEs collected so far)", group="cve_queries")
                else:
                    logger.info(f"Querying CVEs [Page {current_page}/?] - Determining total count...", group="cve_queries")
                
                response = requests.get(base_url, params=params, headers=headers)
                response.raise_for_status()
                
                data = response.json()
                
               
                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    logger.info(f"Found {total_results} total CVEs", group="cve_queries")
                
                # Extract CVE IDs from current page
                for vuln in data.get("vulnerabilities", []):
                    if "cve" in vuln and "id" in vuln["cve"]:
                        all_cves.append(vuln["cve"]["id"])
                
                # Move to next page
                start_index += results_per_page
                
                # Rate limiting
                if not headers.get("apiKey"):
                    sleep(1)  
                else:
                    sleep(0)  
                    
                break
                
            except requests.exceptions.RequestException as e:
                public_ip = get_public_ip()
                timestamp = get_utc_timestamp()
                logger.error(f"{timestamp} - Error fetching CVE list (Attempt {attempt + 1}/{max_retries}): {e}", group="error_handling")
                logger.info(f"Current public IP address: {public_ip}", group="cve_queries")
                
                # Check for message header and display if present
                if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                    error_message = e.response.headers['message']
                    logger.error(f"NVD API Message: {error_message}", group="error_handling")
                
                if attempt < max_retries - 1:
                    logger.info("Waiting 6 seconds before retry...", group="cve_queries")
                    sleep(6)
                else:
                    logger.info("Max retries reached for this page. Moving to next page.", group="error_handling")
                    # Move to next page even if failed
                    start_index += results_per_page
    
    logger.info(f"Total CVEs gathered: {len(all_cves)}", group="cve_queries")
    return all_cves
