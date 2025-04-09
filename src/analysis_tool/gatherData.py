# Import Python dependencies
import requests
import pandas as pd
from build_info import VERSION, TOOLNAME
from time import sleep
import datetime

# Import Analysis Tool 
import processData
import vdb_checker    

# Update get_public_ip function to include timestamp
def get_public_ip():
    """Get the current public IP address being used by the tool."""
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
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
    cveOrgJSON = "https://cveawg.mitre.org/api/cve/"
    # create the simple URL using user input ID and expected URL
    simpleCveRequestUrl = cveOrgJSON + targetCve
    
    try:
        # Do GET Request to API and convert response to Python datatypes
        r = requests.get(simpleCveRequestUrl)
        r.raise_for_status()  # Raise exception for HTTP errors
        cveRecordDict = r.json()

        processData.integrityCheckCVE("cveIdMatch", targetCve, cveRecordDict)
        processData.integrityCheckCVE("cveStatusCheck", "REJECTED", cveRecordDict)
        return cveRecordDict
    except requests.exceptions.RequestException as e:
        public_ip = get_public_ip()
        timestamp = get_utc_timestamp()
        print(f"[ERROR] {timestamp} - Error fetching CVE List data for {targetCve}: {e}")
        print(f"Current public IP address: {public_ip}")
        return None

# Using provided CVE-ID, get the CVE data from the NVD API 
def gatherNVDCVERecord(apiKey, targetCve):
    print(f"[INFO]  Querying NVD /cves/ API to get NVD Dataset Information...")
   
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?cveId=" + targetCve
    headers = {
        "Accept": "application/json",
        "User-Agent": f"{TOOLNAME}/{VERSION}"
    }
    
    # Only add API key to headers if one was provided
    if apiKey:
        headers["apiKey"] = apiKey
   
    max_retries = 100
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            public_ip = get_public_ip()
            timestamp = get_utc_timestamp()
            print(f"[ERROR] {timestamp} - Error fetching NVD CVE record data (Attempt {attempt + 1}/{max_retries}): {e}")
            print(f"Current public IP address: {public_ip}")
            
            if attempt < max_retries - 1:
                print(f"Waiting 6 seconds before retry...")
                sleep(6)
            else:
                print("Max retries reached. Giving up.")
                return None
    
# Query NVD /source/ API for data and return a dataframe of the response content
def gatherNVDSourceData(apiKey):
    print(f"[INFO]  Querying NVD /source/ API to get source mappings...")
    
    def fetch_nvd_data():
        url = "https://services.nvd.nist.gov/rest/json/source/2.0/"
        headers = {
            "Accept": "application/json",
            "User-Agent": f"{TOOLNAME}/{VERSION}"
        }
        
        # Only add API key to headers if one was provided
        if apiKey:
            headers["apiKey"] = apiKey
       
        max_retries = 100
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                public_ip = get_public_ip()
                timestamp = get_utc_timestamp()
                print(f"[ERROR] {timestamp} - Error fetching source data (Attempt {attempt + 1}/{max_retries}): {e}")
                print(f"Current public IP address: {public_ip}")
                
                if attempt < max_retries - 1:
                    print(f"Waiting 6 seconds before retry...")
                    sleep(6)
                else:
                    print("Max retries reached. Giving up.")
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
            nvd_cpes_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
            headers = {"user-agent": f"{TOOLNAME}/{VERSION}"}
            
            # Only add API key to headers if one was provided
            if apiKey:
                headers["apiKey"] = apiKey
           
            max_retries = 100
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
                   
                    print(f"\n[INFO] Found {total_results} total results for {query_string}. Collecting all pages...")
                   
                    # Collect remaining pages
                    while remaining_results > 0:
                        for page_attempt in range(max_retries):
                            try:
                                # Add delay to respect rate limits (non-API Key)
                                sleep(0.6)
                               
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
                               
                                print(f"[INFO] Collected {len(consolidated_data['products'])} of {total_results} results...")
                                break
                            except requests.exceptions.RequestException as e:
                                public_ip = get_public_ip()
                                timestamp = get_utc_timestamp()
                                print(f"[ERROR] {timestamp} - Error fetching page data (Attempt {page_attempt + 1}/{max_retries}): {e}")
                                print(f"Current public IP address: {public_ip}")
                                
                                if page_attempt < max_retries - 1:
                                    print(f"Waiting 6 seconds before retry...")
                                    sleep(6)
                                else:
                                    print("Max retries reached for page data. Giving up.")
                                    return None
                   
                    # Update final counts
                    consolidated_data["startIndex"] = 0
                    consolidated_data["resultsPerPage"] = len(consolidated_data["products"])
                   
                    return consolidated_data
                   
                except requests.exceptions.RequestException as e:
                    public_ip = get_public_ip()
                    timestamp = get_utc_timestamp()
                    print(f"[ERROR] {timestamp} - Error fetching data (Attempt {attempt + 1}/{max_retries}): {e}")
                    print(f"Current public IP address: {public_ip}")
                    
                    if attempt < max_retries - 1:
                        print(f"Waiting 6 seconds before retry...")
                        sleep(6)
                    else:
                        print("Max retries reached. Giving up.")
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
def gatherVDBIntel(targetCve):
    # This currently references another file, we should bring that file into here and break it out into the appropriate Gather/Process/Generate groupings
    try:
        vdbIntelHtml = vdb_checker.gatherVDBCheckerData(targetCve)
        return (vdbIntelHtml)
    except:
        print("[ERROR]  Failed to run vdb_checker!")
