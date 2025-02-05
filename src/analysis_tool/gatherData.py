# Import Python dependencies
import requests
import pandas as pd
from build_info import VERSION, TOOLNAME
from time import sleep

# Import Analysis Tool 
import processData
import vdb_checker    

# Using provided CVE-ID, get the CVE data from CVE Program API 
def gatherCVEListRecord(targetCve):
    # Set the API Endpoint target
    cveOrgJSON = "https://cveawg.mitre.org/api/cve/"
    # create the simple URL using user input ID and expected URL
    simpleCveRequestUrl = cveOrgJSON + targetCve
    # Do GET Request to API and convert response to Python datatypes
    r = requests.get(simpleCveRequestUrl)
    # We can avoid any error handling around missing required fields if we perform schema validation prior to processing sections.
    # integrityCheckCVE(DO SCHEMA VALIDATION CASE HERE)
    cveRecordDict = r.json()

    processData.integrityCheckCVE("cveIdMatch", targetCve, cveRecordDict)
    processData.integrityCheckCVE("cveStatusCheck", "REJECTED", cveRecordDict)
    return (cveRecordDict)

# Using provided CVE-ID, get the CVE data from the NVD API 
def gatherNVDCVERecord(apiKey, targetCve):
    print(f"[INFO]  Querying NVD /cves/ API to get NVD Dataset Information...")
   
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?cveId=" + targetCve
    headers = {
        "Accept": "application/json",
        "User-Agent": "{TOOLNAME}{VERSION}",
        "apiKey": f"{apiKey}"
    }
   
    max_retries = 10
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching NVD CVE record data (Attempt {attempt + 1}/{max_retries}): {e}")
            
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
            "User-Agent": "{TOOLNAME}/{VERSION}",
            "apiKey": f"{apiKey}"
        }
       
        max_retries = 10
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                print(f"Error fetching data (Attempt {attempt + 1}/{max_retries}): {e}")
                
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
            headers = {"user-agent": f"{TOOLNAME}/{VERSION}", "apiKey": f"{apiKey}"}
           
            max_retries = 10
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
                   
                    # Update final counts
                    consolidated_data["startIndex"] = 0
                    consolidated_data["resultsPerPage"] = len(consolidated_data["products"])
                   
                    return consolidated_data
                   
                except requests.exceptions.RequestException as e:
                    print(f"\nError fetching data (Attempt {attempt + 1}/{max_retries}): {e}")
                    
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
        'dataSource': [],
        'sourceID': [],
        'sourceRole': [],
        'platformFormatType': [], 
        'hasCPEArray': [],
        'rawPlatformData': [],
        'cpeBaseStrings': [],
        'cpeVersionChecks': [],
        'cpesQueryData': []
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
