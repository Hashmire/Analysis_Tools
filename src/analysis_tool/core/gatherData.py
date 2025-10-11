# Import Python dependencies
import requests
import pandas as pd
import os
import json
from time import sleep
from pathlib import Path

# Import Analysis Tool 
from . import processData

# Import the new logging system
from ..logging.workflow_logger import get_logger, LogGroup

# Get logger instance
logger = get_logger()

# Load configuration
def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
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
    except Exception as e:        return f"Could not retrieve IP: {str(e)}"

def _resolve_cve_file_path(cve_id, repo_base_path):
    """
    Convert CVE ID to local repository file path.
    CVE-2024-12345 → {repo_base_path}/2024/12xxx/CVE-2024-12345.json
    """
    try:
        parts = cve_id.split('-')
        if len(parts) != 3:
            return None
            
        year = parts[1]
        number = parts[2]
        
        # Determine directory based on number ranges
        if len(number) == 4:
            dir_name = f"{number[0]}xxx"
        elif len(number) == 5:
            dir_name = f"{number[:2]}xxx"
        elif len(number) >= 6:
            dir_name = f"{number[:3]}xxx"
        else:
            return None
            
        return Path(repo_base_path) / year / dir_name / f"{cve_id}.json"
    except (IndexError, ValueError):
        return None

def _load_cve_from_local_file(cve_file_path):
    """
    Load CVE record from local JSON file.
    Returns CVE data dict or None if file doesn't exist or is invalid.
    """
    try:
        if not cve_file_path.exists():
            return None
            
        with open(cve_file_path, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
            
        # Validate basic CVE structure
        if 'cveMetadata' in cve_data and 'cveId' in cve_data['cveMetadata']:
            return cve_data
        else:
            logger.warning(f"Invalid CVE structure in local file: {cve_file_path}", group="cve_queries")
            return None
            
    except (json.JSONDecodeError, IOError, UnicodeDecodeError) as e:
        logger.warning(f"Cannot read local CVE file {cve_file_path}: {e}", group="cve_queries")
        return None

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
        logger.error(f"MITRE CVE API request failed: Unable to fetch CVE record for {targetCve} - {e}", group="cve_queries")
        logger.debug(f"Current public IP address: {public_ip}", group="cve_queries")
        
        # Record failed API call in unified dashboard tracking
        try:
            from ..logging.dataset_contents_collector import record_api_call_unified
            record_api_call_unified("MITRE CVE API", success=False)
        except ImportError:
            pass  # Fallback for testing environments
        
        return None

def gatherCVEListRecordLocal(targetCve, local_repo_path=None):
    """
    Load CVE record from local repository with API fallback.
    Always audits when API fallback is used.
    
    Args:
        targetCve: CVE ID to load (e.g., "CVE-2024-12345")
        local_repo_path: Path to local CVE repository base directory
        
    Returns:
        CVE record dict or None if loading fails
    """
    # Attempt local loading first if path provided
    if local_repo_path:
        logger.debug(f"Attempting local CVE load: {targetCve} from {local_repo_path}", group="cve_queries")
        
        cve_file_path = _resolve_cve_file_path(targetCve, local_repo_path)
        if cve_file_path:
            local_data = _load_cve_from_local_file(cve_file_path)
            if local_data:
                logger.info(f"Successfully loaded CVE from local repository: {targetCve}", group="cve_queries")
                return local_data
        
        # Local loading failed - fall back to API
        logger.warning(f"Local CVE load failed for {targetCve} - falling back to MITRE API", group="cve_queries")
    
    # Always attempt API fallback
    logger.info(f"Using MITRE API for CVE: {targetCve}", group="cve_queries")
    return gatherCVEListRecord(targetCve)

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
            logger.error(f"NVD CVE API request failed: Unable to fetch CVE record for {targetCve} (Attempt {attempt + 1}/{max_retries}) - {e}", group="cve_queries")
            logger.debug(f"Current public IP address: {public_ip}", group="cve_queries")            
            if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                logger.error(f"NVD API Message: {e.response.headers['message']}", group="cve_queries")
            
            # Record failed API call in unified dashboard tracking (only once per final failure)
            if attempt == max_retries - 1:  # Only on final attempt
                try:
                    from ..logging.dataset_contents_collector import record_api_call_unified
                    record_api_call_unified("NVD CVE API", success=False)
                except ImportError:
                    pass  # Fallback for testing environments
            
            if attempt < max_retries - 1:
                wait_time = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                logger.warning(f"Waiting {wait_time} seconds before retry...", group="cve_queries")
                sleep(wait_time)
            else:
                logger.error(f"NVD CVE API request failed: Maximum retry attempts ({max_retries}) reached for CVE {targetCve}", group="cve_queries")
                return None
    
# Query NVD /source/ API for data and return a dataframe of the response content
def gatherNVDSourceData(apiKey):
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
                logger.error(f"NVD Sources API request failed: Unable to fetch source entries (Attempt {attempt + 1}/{max_retries}) - {e}", group="cve_queries")
                logger.debug(f"Current public IP address: {public_ip}", group="cve_queries")
                
                if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                    logger.error(f"NVD API Message: {e.response.headers['message']}", group="cve_queries")                
                if attempt < max_retries - 1:
                    wait_time = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                    logger.warning(f"Waiting {wait_time} seconds before retry...", group="cve_queries")
                    sleep(wait_time)
                else:
                    logger.error(f"NVD Sources API request failed: Maximum retry attempts ({max_retries}) reached", group="cve_queries")
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
                   
                    # Log the API call before making the request
                    logger.api_call("NVD CPE API", {"cpe_match_string": query_string, "start_index": 0}, group="cpe_queries")
                   
                    response = requests.get(nvd_cpes_url, params=initial_params, headers=headers)
                    response.raise_for_status()
                    
                    initial_data = response.json()
                   
                    total_results = initial_data.get("totalResults", 0)
                    results_per_page = initial_data.get("resultsPerPage", 0)
                   
                    # Log the API response with result count
                    logger.api_response("NVD CPE API", "Success", count=total_results, group="cpe_queries")
                   
                    # If we already have all results, return initial response
                    if total_results <= results_per_page:
                        logger.debug(f"Single page CPE query completed: {total_results} results for {query_string}", group="cpe_queries")
                        return initial_data
                   
                    # Initialize consolidated results with first batch
                    consolidated_data = initial_data.copy()
                    consolidated_data["products"] = initial_data.get("products", []).copy()
                     # Calculate number of additional requests needed
                    remaining_results = total_results - results_per_page
                    current_index = results_per_page                    
                    logger.info(f"Processing CPE collections: Found {total_results} total results - Collecting all pages...", group="cpe_queries")
                   
                    # Collect remaining pages
                    additional_api_calls = 0
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
                               
                                # Log the paginated API call
                                logger.api_call("NVD CPE API", {"cpe_match_string": query_string, "start_index": current_index}, group="cpe_queries")
                                additional_api_calls += 1
                               
                                response = requests.get(nvd_cpes_url, params=params, headers=headers)
                                response.raise_for_status()
                                
                                page_data = response.json()
                               
                                # Log the paginated API response
                                page_results = len(page_data.get("products", []))
                                logger.api_response("NVD CPE API", "Success", count=page_results, group="cpe_queries")
                               
                                # Add products from this page to consolidated results
                                if "products" in page_data:
                                    consolidated_data["products"].extend(page_data["products"])
                                 
                                # Update counters
                                results_this_page = len(page_data.get("products", []))
                                remaining_results -= results_this_page
                                current_index += results_per_page
                                 
                                logger.debug(f"Collected {len(consolidated_data['products'])} of {total_results} CPE names...", group="cpe_queries")
                                break
                            except requests.exceptions.RequestException as e:
                                public_ip = get_public_ip()
                                logger.error(f"NVD CPE API paginated request failed: Unable to fetch page data for '{query_string}' (Attempt {page_attempt + 1}/{max_retries}) - {e}", group="cve_queries")
                                logger.debug(f"Current public IP address: {public_ip}", group="cpe_queries")
                                
                                # Log the failed API response
                                logger.api_response("NVD CPE API", "Failed", group="cpe_queries")
                                
                                # Record failed paginated API call in unified dashboard tracking
                                try:
                                    from ..logging.dataset_contents_collector import record_api_call_unified
                                    record_api_call_unified("NVD CPE API", success=False)
                                except ImportError:
                                    pass  # Fallback for testing environments
                                
                                  # Check for message header and display if present - error response
                                if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                                    error_message = e.response.headers['message']
                                    logger.error(f"NVD API Message: {error_message}", group="cve_queries")
                                    
                                    # Don't retry for "Invalid cpeMatchstring parameter" errors
                                    if "Invalid cpeMatchstring parameter" in error_message:
                                        # Note: This should be rare due to early validation in deriveCPEMatchStringList
                                        logger.warning(f"API rejected CPE string (bypassed early validation): {query_string}", group="cpe_queries")
                                        # Return what we've collected so far
                                        consolidated_data["startIndex"] = 0
                                        consolidated_data["resultsPerPage"] = len(consolidated_data["products"])
                                        consolidated_data["error"] = error_message
                                        consolidated_data["status"] = "invalid_cpe"
                                        return consolidated_data
                                
                                if page_attempt < max_retries - 1:
                                    wait_time = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                                    logger.warning(f"Waiting {wait_time} seconds before retry...", group="cpe_queries")
                                    sleep(wait_time)
                                else:
                                    logger.error(f"NVD CPE API paginated request failed: Maximum retry attempts ({max_retries}) reached for page data", group="cve_queries")
                                    return None
                   
                    # Update final counts
                    consolidated_data["startIndex"] = 0
                    consolidated_data["resultsPerPage"] = len(consolidated_data["products"])
                   
                    # Log completion summary for multi-page requests
                    total_api_calls = 1 + additional_api_calls  # Initial call + additional pages
                    logger.info(f"Multi-page CPE query completed: {total_results} results across {total_api_calls} API calls for {query_string}", group="cpe_queries")
                   
                    return consolidated_data
                   
                except requests.exceptions.RequestException as e:
                    public_ip = get_public_ip()
                    logger.error(f"NVD CPE API request failed: Unable to fetch CPE data for '{query_string}' (Attempt {attempt + 1}/{max_retries}) - {e}", group="cve_queries")
                    logger.debug(f"Current public IP address: {public_ip}", group="cpe_queries")
                    
                    # Log the failed API response
                    logger.api_response("NVD CPE API", "Failed", group="cpe_queries")
                    
                    # Record failed API call in unified dashboard tracking
                    try:
                        from ..logging.dataset_contents_collector import record_api_call_unified
                        record_api_call_unified("NVD CPE API", success=False)
                    except ImportError:
                        pass  # Fallback for testing environments
                    
                    # Check for message header and display if present - error response
                    if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                        error_message = e.response.headers['message']
                        logger.error(f"NVD API Message: {error_message}", group="cve_queries")
                        
                        # Don't retry for "Invalid cpeMatchstring parameter" errors
                        if "Invalid cpeMatchstring parameter" in error_message:
                            # Note: This should be rare due to early validation in deriveCPEMatchStringList
                            logger.warning(f"API rejected CPE string (bypassed early validation): {query_string}", group="cpe_queries")
                            # Return empty result structure instead of None
                            return {
                                "totalResults": 0,
                                "resultsPerPage": 0,
                                "startIndex": 0,
                                "products": [],
                                "error": error_message,
                                "status": "invalid_cpe"                            }
                    
                    if attempt < max_retries - 1:
                        wait_time = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                        logger.warning(f"Waiting {wait_time} seconds before retry...", group="cpe_queries")
                        sleep(wait_time)
                    else:
                        logger.error(f"NVD CPE API request failed: Maximum retry attempts ({max_retries}) reached", group="cve_queries")
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
                    logger.info(f"Processing CVE queries: Page {current_page}/{pages_estimate} ({progress:.1f}%) - {len(all_cves)} CVE records collected so far", group="cve_queries")
                else:
                    logger.info(f"Processing CVE queries: Page {current_page}/? - Determining total count...", group="cve_queries")
                
                response = requests.get(base_url, params=params, headers=headers)
                response.raise_for_status()
                
                data = response.json()
                
                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    logger.info(f"Found {total_results} total results in NVD database", group="cve_queries")
                
                # Extract CVE IDs from current page
                for vuln in data.get("vulnerabilities", []):
                    if "cve" in vuln and "id" in vuln["cve"]:
                        all_cves.append(vuln["cve"]["id"])
                
                # Move to next page
                start_index += results_per_page
                  # Rate limiting
                if not headers.get("apiKey"):
                    sleep(1)  
                else:                    sleep(0)  
                    
                break
                
            except requests.exceptions.RequestException as e:
                public_ip = get_public_ip()
                logger.error(f"NVD CVE list API request failed: Unable to fetch CVE list page {current_page} (Attempt {attempt + 1}/{max_retries}) - {e}", group="cve_queries")
                logger.debug(f"Current public IP address: {public_ip}", group="cve_queries")
                
                # Check for message header and display if present
                if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                    error_message = e.response.headers['message']
                    logger.error(f"NVD API Message: {error_message}", group="cve_queries")
                
                if attempt < max_retries - 1:
                    wait_time = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                    logger.warning(f"Waiting {wait_time} seconds before retry...", group="cve_queries")
                    sleep(wait_time)
                else:
                    logger.warning(f"NVD CVE list API request failed: Maximum retry attempts ({max_retries}) reached for page {current_page} - skipping to next page", group="cve_queries")
                    # Move to next page even if failed
                    start_index += results_per_page
    
    logger.info(f"Processing CVE collection completed: {len(all_cves)} CVE records collected", group="cve_queries")
    return all_cves


def load_confirmed_mappings_for_uuid(target_uuid):
    """
    Load confirmed mappings file for the specified target UUID.
    
    Args:
        target_uuid (str): The target UUID to search for in confirmed mapping files
        
    Returns:
        list: List of confirmed mappings, or empty list if none found
        
    Note:
        This function searches the mappings directory for JSON files containing
        the specified cnaId and returns the confirmedMappings array.
    """
    try:
        # Get the mappings directory from config
        config = load_config()
        mappings_dir = Path(__file__).parent.parent / config['confirmed_mappings']['mappings_directory']
        
        if not mappings_dir.exists():
            logger.debug(f"Mappings directory not found: {mappings_dir}", group="data_proc")
            return []
        
        # Search for JSON files containing the target UUID
        for mapping_file in mappings_dir.glob("*.json"):
            try:
                with open(mapping_file, 'r', encoding='utf-8') as f:
                    mapping_data = json.load(f)
                    
                if mapping_data.get('cnaId') == target_uuid:
                    confirmed_mappings = mapping_data.get('confirmedMappings', [])
                    logger.info(f"Found confirmed mappings file: {mapping_file.name} with {len(confirmed_mappings)} mappings", group="data_proc")
                    return confirmed_mappings
                    
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not read mapping file {mapping_file}: {e}", group="data_proc")
                continue
                
        logger.debug(f"No confirmed mappings file found for UUID: {target_uuid}", group="data_proc")
        return []
        
    except Exception as e:
        logger.error(f"Error loading confirmed mappings for UUID {target_uuid}: {e}", group="data_proc")
        return []
