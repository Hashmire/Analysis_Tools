# Import Python dependencies
import re
import pandas as pd
from tqdm import tqdm
from sys import exit
from typing import List, Dict, Any, Union
from collections import defaultdict

# Import Analysis Tool 
import gatherData
import generateHTML

########################
###  Data Processing ###
########################   
# 
# 
# Takes the processed data from the /cpes/ API and reduces to the top 10 base strings that appear most relevant to the platform entry
## We have already sorted each set of results for each individual base string search, this function is responsible for aggregating
## the results for each of those searches and performing additional sorting to determine the top 10 most relevant base strings. 

def getNVDSourceDataByUUID(uuid: str, nvdSourceData: pd.DataFrame) -> dict:
    for index, row in nvdSourceData.iterrows():
        if uuid in row.get('sourceIdentifiers', []):
            return {
                "name": row.get('name'),
                "contactEmail": row.get('contactEmail'),
                "sourceIdentifiers": row.get('sourceIdentifiers')
            }
    return {}

def sort_cpes_query_data(rawDataset: pd.DataFrame):

    tempDataset = rawDataset.copy()

    for index, row in tempDataset.iterrows():
        cpes_query_data = row['rawCPEsQueryData']
        # Convert cpes_query_data to a list of dictionaries for sorting
        cpes_query_data_list = [{key: value} for key, value in cpes_query_data.items()]
        
        # Sort the list of dictionaries using sort_broad_entries and sort_base_strings
        sorted_cpes_query_data = sort_broad_entries(cpes_query_data_list)
        
        # Convert the sorted list of dictionaries back to a dictionary
        sorted_cpes_query_data_dict = {list(entry.keys())[0]: list(entry.values())[0] for entry in sorted_cpes_query_data}
        
        # Update the row with the sorted cpes_query_data
        tempDataset.at[index, 'sortedCPEsQueryData'] = sorted_cpes_query_data_dict
    
    return tempDataset
#
def sort_broad_entries(data):
    # Sort the list of dictionaries based on 'matches_found' in descending order
    sorted_data = sorted(data, key=lambda x: list(x.values())[0].get('matches_found', 0), reverse=True)
    return sorted_data
#                    ,
def sort_base_strings(unique_base_strings: dict) -> dict:
    sorted_base_strings = dict(sorted(
        unique_base_strings.items(), 
        key=lambda x: (
            # Primary sort: depFalseCount (items with depFalseCount of 0 are moved to the bottom)
            x[1].get('depFalseCount', 0) == 0,
            # Secondary sort: searchCount
            -x[1].get('searchCount', 0),
            # Tertiary sort: Total items in versions_found
            -x[1].get('versionsFound', 0),
            # Quaternary sort: depTrueCount + depFalseCount
            -(x[1].get('depFalseCount', 0) + x[1].get('depTrueCount', 0)),
            # Quinary sort: depFalseCount
            -x[1].get('depFalseCount', 0)
        )
    ))
    return sorted_base_strings
#
def reduceToTop10(workingDataset: pd.DataFrame) -> pd.DataFrame:
    
    trimmedDataset = workingDataset.copy()
    top_10_base_strings_dict = {}

    def consolidateBaseStrings(data, unique_base_strings, duplicate_keys):
        for key, value in data.items():
            if isinstance(value, dict):
                cpe_breakout = breakoutCPEComponents(key)
                recorded_keys = {k: v for k, v in cpe_breakout.items() if v != '*' and k not in ['cpePrefix', 'cpeVersion']}
                recorded_keys_str = "".join(recorded_keys.keys())
                if 'base_strings' in value:
                    base_strings = value['base_strings']
                    for base_key, base_value in base_strings.items():
                        if base_key in unique_base_strings:
                            duplicate_keys[base_key] = duplicate_keys.get(base_key, 1) + 1
                            unique_base_strings[base_key]['searchCount'] += 1
                            unique_base_strings[base_key]['searchSource' + recorded_keys_str] = key
                        else:
                            unique_base_strings[base_key] = base_value
                            unique_base_strings[base_key]['searchCount'] = 1
                            unique_base_strings[base_key]['searchSource' + recorded_keys_str] = key
                else:
                    consolidateBaseStrings(value, unique_base_strings, duplicate_keys)
            elif isinstance(value, list):
                for item in value:
                    consolidateBaseStrings(item, unique_base_strings, duplicate_keys)

    def compare_versions(base_strings, cpe_version_checks):
        for base_key, base_value in base_strings.items():
            versions_found_content = base_value.get('versionsFoundContent', [])
            matched_versions = []
            unique_versions = set()
            for version_entry in versions_found_content:
                for check in cpe_version_checks:
                    for key, value in check.items():
                        if key in version_entry:
                            cpe_value = version_entry[key]
                            cpe_breakout = breakoutCPEComponents(cpe_value)
                            if cpe_breakout['version'] == value:
                                version_pair = (key, cpe_value)
                                if version_pair not in unique_versions:
                                    matched_versions.append({key: cpe_value})
                                    unique_versions.add(version_pair)
                                    base_value['matched'] = True
                                break
            # Ensure uniqueness in versionsFoundContent
            base_value['versionsFoundContent'].extend(matched_versions)
            base_value['versionsFoundContent'] = list({frozenset(item.items()): item for item in base_value['versionsFoundContent']}.values())
            base_value['versionsFound'] = len(base_value['versionsFoundContent'])

    for index, row in workingDataset.iterrows():
        unique_base_strings = {}  
        duplicate_keys = {} 
        sorted_cpes_query_data = row['sortedCPEsQueryData']
        cpe_version_checks = row['cpeVersionChecks']
        consolidateBaseStrings(sorted_cpes_query_data, unique_base_strings, duplicate_keys)

        compare_versions(unique_base_strings, cpe_version_checks)
        sorted_base_strings = sort_base_strings(unique_base_strings)

        top_10_base_strings = dict(list(sorted_base_strings.items())[:10])

        # Store the top_10_base_strings in the dictionary
        top_10_base_strings_dict[index] = top_10_base_strings

        # Ensure that only the current row is updated
        trimmedDataset.at[index, 'trimmedCPEsQueryData'] = top_10_base_strings

    return trimmedDataset
    
# Processes the mapping of /cpes/ API results with the baseStrings derived from external data
def populateRawCPEsQueryData(rawDataSet: pd.DataFrame, cpeQueryData: List[Dict[str, Any]]):
    # Create a copy of the dataframe to avoid modifying the original
    updated_df = rawDataSet.copy()
    
    # Iterate through each row in the DataFrame
    for index, row in updated_df.iterrows():
        # Initialize a dictionary to store the matched values
        matchedValues = {}
        
        # Get the cpeBaseStrings for the current row
        cpeBaseStringsList = row.get('cpeBaseStrings', [])
        
        # Handle non-iterable values
        if not isinstance(cpeBaseStringsList, (list, tuple, set)):
            if pd.isna(cpeBaseStringsList) or cpeBaseStringsList is None:
                cpeBaseStringsList = []
            else:
                cpeBaseStringsList = [str(cpeBaseStringsList)]
        
        # Compare each cpeBaseString with the keys
        for cpeBaseString in cpeBaseStringsList:
            for entry in cpeQueryData:
                for key, value in entry.items():
                    if cpeBaseString == key:
                        matchedValues[key] = value
        
        # Update the content of the 'rawCPEsQueryData' field with the dictionary of matched values
        updated_df.at[index, 'rawCPEsQueryData'] = matchedValues
    
    return updated_df
#
# Generates a list of unique cpeMatchStrings based on the contents of cpeBaseStrings
def deriveCPEMatchStringList(rawDataSet):
    distinct_values = set()

    # Iterate through each row in the DataFrame
    for index, row in rawDataSet.iterrows():
        if 'cpeBaseStrings' in row:
            cpe_base_strings = row['cpeBaseStrings']
            # Check if cpe_base_strings is iterable
            if isinstance(cpe_base_strings, (list, tuple, set)):
                for cpe_string in cpe_base_strings:
                    if cpe_string:  # Skip empty strings
                        distinct_values.add(cpe_string)
            elif cpe_base_strings:  # If it's a single non-empty value
                distinct_values.add(cpe_base_strings)

    # Convert the set to a list to get distinct values
    distinct_values_list = list(distinct_values)
    return distinct_values_list
#
# Generates a list of CPE Base Strings and relevant contextual information about each
def suggestCPEData(apiKey, rawDataset, case):
    match case:
        # Case 1 CVE List
        case 1:

            # Iterate through each row in the DataFrame to generate cpeBaseString suggestions
            for index, row in rawDataset.iterrows():
                # Initialize lists to store the extracted values for the current row
                cpe_values = []
                # Initialize a list to store the dictionaries for each row
                cpeBaseStrings = []

                # Check if platformFormatType is cveAffectsVersionSingle or cveAffectsVersionRange
                if 'platformFormatType' in row and row['platformFormatType'] in ['cveAffectsVersionSingle', 'cveAffectsVersionRange']:
                    
                    if 'rawPlatformData' in row:
                        platform_data = row['rawPlatformData']
                        
                    # Generate CPE Match Strings based on available content
                    if 'vendor' in platform_data:
                        if platform_data['vendor'] == "n\\/a":
                            print("[DEBUG]  Placeholder values detected when gathering Vendor search strings ")
                        else:
                            cpeValidstring = formatFor23CPE(platform_data['vendor'])
                            culledString = curateCPEAttributes('vendor', cpeValidstring, True)
                            
                            part = "*"
                            vendor = culledString
                            product = "*"                     
                            version = "*"
                            update = "*"
                            edition = "*"
                            lang = "*"
                            swEdition = "*"
                            targetSW = "*"
                            targetHW = "*"
                            other = "*"

                            # Build a CPE Search String from supported elements
                            rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update  + ":" + edition  + ":" + lang  + ":" + swEdition + ":" + targetSW + ":" + targetHW  + ":" + other
                            scratchSearchStringBreakout = breakoutCPEComponents(rawMatchString)
                            scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                            cpeBaseStrings.append(scratchMatchString)

                    # Generate CPE Match Strings based on available content for 'product'
                    if 'product' in platform_data:
                        if platform_data['product'] == "n\\/a":
                            print("[DEBUG]  Placeholder values detected when gathering Product search strings ")
                        else:
                            cpeValidstring = formatFor23CPE(platform_data['product'])
                            culledString = curateCPEAttributes('product', cpeValidstring, True)
                            
                            part = "*"
                            vendor = "*"
                            product = culledString
                            version = "*"
                            update = "*"
                            edition = "*"
                            lang = "*"
                            swEdition = "*"
                            targetSW = "*"
                            targetHW = "*"
                            other = "*"

                            # Build a CPE Search String from supported elements
                            rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update  + ":" + edition  + ":" + lang  + ":" + swEdition + ":" + targetSW + ":" + targetHW  + ":" + other
                            scratchSearchStringBreakout = breakoutCPEComponents(rawMatchString)
                            scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                            cpeBaseStrings.append(scratchMatchString)

                    # Generate CPE Match Strings based on available content for 'platform'
                    if 'platform' in platform_data:
                        cpeValidstring = formatFor23CPE(platform_data['platform'])
                        
                        part = "*"
                        vendor = "*"
                        product = "*"
                        version = "*"
                        update = "*"
                        edition = "*"
                        lang = "*"
                        swEdition = "*"
                        targetSW = "*"
                        targetHW = culledString
                        other = "*"

                        # Build a CPE Search String from supported elements
                        rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update  + ":" + edition  + ":" + lang  + ":" + swEdition + ":" + targetSW + ":" + targetHW  + ":" + other
                        scratchSearchStringBreakout = breakoutCPEComponents(rawMatchString)
                        scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                        cpeBaseStrings.append(scratchMatchString)

                    # Generate CPE Match Strings based on available content for 'packageName'
                    if 'packageName' in platform_data:
                        cpeValidstring = formatFor23CPE(platform_data['packageName'])
                        culledString = curateCPEAttributes('product', cpeValidstring, True)
                        
                        part = "*"
                        vendor = "*"
                        product = culledString
                        version = "*"
                        update = "*"
                        edition = "*"
                        lang = "*"
                        swEdition = "*"
                        targetSW = "*"
                        targetHW = "*"
                        other = "*"

                        # Build a CPE Search String from supported elements
                        rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update  + ":" + edition  + ":" + lang  + ":" + swEdition + ":" + targetSW + ":" + targetHW  + ":" + other
                        scratchSearchStringBreakout = breakoutCPEComponents(rawMatchString)
                        scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                        cpeBaseStrings.append(scratchMatchString)

                    # Generate CPE Match Strings based on available content for 'vendor' and 'product'
                    if 'vendor' in platform_data and 'product' in platform_data:
                        cpeValidstringVendor = formatFor23CPE(platform_data['vendor'])
                        cpeValidstringProduct = formatFor23CPE(platform_data['product'])
                        culledStringVendor = curateCPEAttributes('vendor', cpeValidstringVendor, True)
                        culledStringProduct = curateCPEAttributes('vendorProduct', culledStringVendor, cpeValidstringProduct)
                        
                        part = "*"
                        vendor = culledStringVendor
                        product = culledStringProduct
                        version = "*"
                        update = "*"
                        edition = "*"
                        lang = "*"
                        swEdition = "*"
                        targetSW = "*"
                        targetHW = "*"
                        other = "*"

                        # Build a CPE Search String from supported elements
                        rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update  + ":" + edition  + ":" + lang  + ":" + swEdition + ":" + targetSW + ":" + targetHW  + ":" + other
                        scratchSearchStringBreakout = breakoutCPEComponents(rawMatchString)
                        scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                        cpeBaseStrings.append(scratchMatchString)

                    # Generate CPE Match Strings based on available content for 'vendor' and 'packageName'
                    if 'vendor' in platform_data and 'packageName' in platform_data:
                        cpeValidstringVendor = formatFor23CPE(platform_data['vendor'])
                        cpeValidstringPackageName = formatFor23CPE(platform_data['packageName'])
                        culledStringVendor = curateCPEAttributes('vendor', cpeValidstringVendor, True)
                        culledStringProduct = curateCPEAttributes('vendorProduct', culledStringVendor, cpeValidstringPackageName)
                        
                        part = "*"
                        vendor = culledStringVendor
                        product = cpeValidstringPackageName
                        version = "*"
                        update = "*"
                        edition = "*"
                        lang = "*"
                        swEdition = "*"
                        targetSW = "*"
                        targetHW = "*"
                        other = "*"

                        # Build a CPE Search String from supported elements
                        rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update  + ":" + edition  + ":" + lang  + ":" + swEdition + ":" + targetSW + ":" + targetHW  + ":" + other
                        scratchSearchStringBreakout = breakoutCPEComponents(rawMatchString)
                        scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                        cpeBaseStrings.append(scratchMatchString)           

                    # Extract cpe array values
                    if 'cpes' in platform_data:
                        cpe_values.append(platform_data['cpes'])

                # Add the cpeBaseStrings list to the cpeBaseStrings column of primaryDataframe
                rawDataset.at[index, 'cpeBaseStrings'] = cpeBaseStrings
                uniqueStringList = deriveCPEMatchStringList(rawDataset)
            
            rawCPEsQueryData = bulkQueryandProcessNVDCPEs(apiKey, rawDataset, uniqueStringList)
           
            ## Map the relevant, raw rawCPEsQueryData back into the rows of the primaryDataframe
            mappedDataset = populateRawCPEsQueryData(rawDataset, rawCPEsQueryData)

            # Update the query data results so the most relevant cpeBaseStrings are listed first.
            sortedDataset = sort_cpes_query_data(mappedDataset)
            trimmedDataset = reduceToTop10(sortedDataset)

            return trimmedDataset
        # Case 2 covers the CPE Search mode
        case 2:
            # Set up for consolidating CPE Suggestions
            allCpeMappings = {}
            uniqueStringList = ["Placeholder (n/a) detected - API calls skipped"]
            allCpeCheck = set()
            # Consolidate all of the string queries we think will be useful for this CVE Record
            print ("[INFO]  Gathering search strings for API query...")
            
            return ()
#
# Calls for NVD API Query and processes statistics and other useful data based on the results
def bulkQueryandProcessNVDCPEs(apiKey, rawDataSet, query_list: List[str]) -> List[Dict[str, Any]]:
    bulk_results = []
    
    print(f"[INFO]  Querying NVD /cpes/ API to get CPE Dictionary information...")
    for query_string in tqdm(query_list):
        # Skip empty queries
        if not query_string:
            continue
        
        json_response = gatherData.gatherNVDCPEData(apiKey, "cpeMatchString", query_string)
        
        if 'totalResults' in json_response:

            # General statistics
            stats = {
                "matches_found": json_response['totalResults'],
                "is_truncated": json_response["resultsPerPage"] < json_response["totalResults"],
            }
            
            # Additional Stats if content is found
            if "products" in json_response:
                base_string_stats = analyzeBaseStrings(rawDataSet['cpeVersionChecks'], json_response)
                stats.update({
                    "unique_base_count": base_string_stats["unique_base_count"],
                    "base_strings": base_string_stats["base_strings"]
                })
            
        else:
            stats = {
                "matches_found": 0,
                "status": "error",
                "error_message": str(json_response)
            }
        
        # Store results for this query
        bulk_results.append({query_string: stats})
    
    return bulk_results
#
# Processes statistics based on /cpes/ response data
def analyzeBaseStrings(cpeVersionChecks, json_response: Dict[str, Any]) -> Dict[str, Any]:
    # Initialize some data collection variables
    base_strings = defaultdict(lambda: {"depTrueCount": 0, "depFalseCount": 0, "versionsFound": 0, "versionsFoundContent": []})
    total_deprecated = 0
    total_active = 0
    
    for product in json_response["products"]:
        cpe_name = product["cpe"]["cpeName"]
        cpe_components = breakoutCPEComponents(cpe_name) 
        cpe_version_value = cpe_components['version']
        base_cpe_name = constructSearchString(cpe_components, "base")

        # Populate versions_found based on comparisons to query results
        versions_found = base_strings[base_cpe_name]['versionsFoundContent']
        unique_versions = set()
        
        for check in cpeVersionChecks:
            for item in check:
                # Compare the version value with cpe_version_value
                if 'version' in item and item['version'] == cpe_version_value:
                    version_pair = ('version', item['version'])
                    if version_pair not in unique_versions:
                        versions_found.append({'version': cpe_name})
                        unique_versions.add(version_pair)
                if 'lessThan' in item and item['lessThan'] == cpe_version_value:
                    less_than_pair = ('lessThan', item['lessThan'])
                    if less_than_pair not in unique_versions:
                        versions_found.append({'lessThan': cpe_name})
                        unique_versions.add(less_than_pair)
                if 'lessThanOrEqual' in item and item['lessThanOrEqual'] == cpe_version_value:
                    less_than_or_equal_pair = ('lessThanOrEqual', item['lessThanOrEqual'])
                    if less_than_or_equal_pair not in unique_versions:
                        versions_found.append({'lessThanOrEqual': cpe_name})
                        unique_versions.add(less_than_or_equal_pair)

        # Update the base_strings dictionary
        base_strings[base_cpe_name]['versionsFoundContent'] = versions_found
        base_strings[base_cpe_name]['versionsFound'] = len(versions_found)
        
        # Update the deprecated and active counts
        if product["cpe"]["deprecated"]:
            base_strings[base_cpe_name]["depTrueCount"] += 1
            total_deprecated += 1
        else:
            base_strings[base_cpe_name]["depFalseCount"] += 1
            total_active += 1

    return {
        "base_strings": base_strings,
        "total_deprecated": total_deprecated,
        "total_active": total_active,
        "unique_base_count": len(base_strings)
    }


def processCVEData(dataframe, cveRecordData):
    """Process CVE Record Data to extract platform-related information"""
    result_df = dataframe.copy()
    
    # Track products already processed to avoid duplicates
    processed_products = set()
    
    if 'containers' in cveRecordData:
        # Process CNA container
        if 'cna' in cveRecordData['containers']:
            container = cveRecordData['containers']['cna']
            source_id = container.get('providerMetadata', {}).get('orgId', 'Unknown')
            source_role = 'CNA'
            
            # Handle affected entries
            if 'affected' in container:
                for affected in container['affected']:
                    vendor = affected.get('vendor', '')
                    product = affected.get('product', '')
                    
                    # Create a unique key for this vendor-product combo
                    product_key = create_product_key(affected, source_id)
                    
                    # Skip if we've already processed this product from this source
                    if product_key in processed_products:
                        continue
                        
                    processed_products.add(product_key)
                    
                    # Safely handle versions
                    versions_checks = []
                    if affected.get('versions') and isinstance(affected.get('versions'), list):
                        versions_checks = affected.get('versions', [])
                    
                    # Create a new row in the dataframe
                    new_row = {
                        'dataSource': 'CVEAPI',
                        'sourceID': source_id,
                        'sourceRole': source_role,
                        'platformFormatType': 'cveAffectsVersionRange' if affected.get('versions') else 'affected',
                        'hasCPEArray': 'cpes' in affected,
                        'rawPlatformData': affected,
                        'cpeBaseStrings': [],
                        'cpeVersionChecks': versions_checks,
                        'rawCPEsQueryData': [],
                        'sortedCPEsQueryData': [],
                        'trimmedCPEsQueryData': []
                    }
                    
                    # Append to dataframe 
                    result_df = pd.concat([result_df, pd.DataFrame([new_row])], ignore_index=True)
        
        # Process ADP containers
        if 'adp' in cveRecordData.get('containers', {}):
            for adp_container in cveRecordData['containers']['adp']:
                source_id = adp_container.get('providerMetadata', {}).get('orgId', 'Unknown')
                source_role = "ADP"
                
                # Handle affected entries in ADP container
                if 'affected' in adp_container:
                    for affected in adp_container['affected']:
                        vendor = affected.get('vendor', '')
                        product = affected.get('product', '')
                        
                        # Create a unique key for this vendor-product-source combo
                        product_key = create_product_key(affected, source_id)
                        
                        # Skip if we've already processed this product from this source
                        if product_key in processed_products:
                            continue
                            
                        processed_products.add(product_key)
                        
                        # Safely handle versions
                        versions_checks = []
                        if affected.get('versions') and isinstance(affected.get('versions'), list):
                            versions_checks = affected.get('versions', [])
                        
                        # Create a new row in the dataframe
                        new_row = {
                            'dataSource': 'CVEAPI',
                            'sourceID': source_id,
                            'sourceRole': source_role,
                            'platformFormatType': 'cveAffectsVersionRange' if affected.get('versions') else 'affected',
                            'hasCPEArray': 'cpes' in affected,
                            'rawPlatformData': affected,
                            'cpeBaseStrings': [],
                            'cpeVersionChecks': versions_checks,
                            'rawCPEsQueryData': [],
                            'sortedCPEsQueryData': [],
                            'trimmedCPEsQueryData': []
                        }
                        
                        # Append to dataframe
                        result_df = pd.concat([result_df, pd.DataFrame([new_row])], ignore_index=True)
    
    return result_df

def processNVDRecordData(dataframe, nvdRecordData):
    """Process NVD Record Data to extract platform-related information"""
    result_df = dataframe.copy()
    
    try:
        # Process NVD vulnerabilities
        if 'vulnerabilities' in nvdRecordData:
            for vuln in nvdRecordData['vulnerabilities']:
                if 'cve' in vuln and 'configurations' in vuln['cve']:
                    source_id = 'nvd@nist.gov'
                    source_role = 'NVD'
                    
                    # Process each configuration as a single row
                    for config in vuln['cve'].get('configurations', []):
                        # Create a unique identifier for this config
                        config_key = f"config_{hash(str(config))}"
                        
                        # Extract some sample information for display/filtering
                        sample_cpe = None
                        sample_vendor = None
                        sample_product = None
                        cpe_base_strings = []
                        
                        # Extract CPEs from the configuration for base strings
                        if 'nodes' in config:
                            for node in config['nodes']:
                                if 'cpeMatch' in node:
                                    for cpe_match in node['cpeMatch']:
                                        if 'criteria' in cpe_match:
                                            cpe_base_strings.append(cpe_match['criteria'])
                                            
                                            # Use the first CPE as a sample
                                            if not sample_cpe:
                                                sample_cpe = cpe_match['criteria']
                                                # Extract vendor/product from the sample CPE
                                                cpe_parts = breakoutCPEComponents(sample_cpe)
                                                sample_vendor = cpe_parts.get('vendor', '')
                                                sample_product = cpe_parts.get('product', '')
                        
                        # Create a new row with the complete configuration
                        new_row = {
                            'dataSource': 'NVDAPI',
                            'sourceID': source_id,
                            'sourceRole': source_role,
                            'platformFormatType': 'nvdConfiguration',
                            'hasCPEArray': True,
                            'rawPlatformData': {
                                'vendor': sample_vendor,
                                'product': sample_product
                            },
                            'rawConfigData': config,  # Store the complete configuration object
                            'cpeBaseStrings': cpe_base_strings,
                            'cpeVersionChecks': [],  # Not applicable for full configurations
                            'rawCPEsQueryData': [],
                            'sortedCPEsQueryData': [],
                            'trimmedCPEsQueryData': []
                        }
                        
                        # Append to dataframe
                        result_df = pd.concat([result_df, pd.DataFrame([new_row])], ignore_index=True)
    except Exception as e:
        print(f"[ERROR] Error processing NVD record data: {e}")
    
    return result_df

#########################

########################
###    CPE Helpers   ###
########################
#
# Takes any string and returns it formatted per CPE 2.3 specification attribute value requirements
def formatFor23CPE(rawAttribute):
    
    # Mapping of chars to replace with escaped characters
    cpeEscape = {
        " ": "_", 
        "\\": "\\\\",
        "!": "\\!",
        "\"": "\\\"",
        "#": "\\#",
        "$": "\\$",
        "&": "\\&",
        "\'": "\\\'",
        "(": "\\(",
        ")": "\\)",
        #"*": "\*", Not supported yet, need to build in logic for this case to not cause issues.
        "+": "\\+",
        "/": "\\/",
        ":": "\\:",
        ";": "\\;",
        "<": "\\<",
        "=": "\\=",
        ">": "\\>",
        "?": "\\?",
        "@": "\\@",
        "[": "\\[",
        "]":"\\]",
        "^": "\\^",
        "`": "\\`",
        "{": "\\{",
        "|": "\\|",
        "}": "\\}",
        "~": "\\~",
        ",": "\\,"
    }
    
    # Lowercase the string
    rawAttribute = rawAttribute.lower()

    return ''.join([cpeEscape.get(x, x) for x in rawAttribute])
#
# Removes/replaces problematic text from vendor and product attribute values
def curateCPEAttributes(case, attributeString1, attributeString2):

    match case:
        case 'vendor':

            # Vendor Aliases
            if ("apache_software_foundation") in attributeString1:
                attributeString1 = attributeString1.replace("apache_software_foundation", "apache")

            return (attributeString1)

        case 'product':
            
            # General Trimming
            if ("apache_") in attributeString1:
                attributeString1 = attributeString1.replace("apache_", "")

            if ("_software") in attributeString1:
                attributeString1 = attributeString1.replace("_software", "")

            if ("_version") in attributeString1:
                attributeString1 = attributeString1.replace("_version", "")

            if ("_plugin") in attributeString1:
                attributeString1 = attributeString1.replace("_plugin", "")

            return (attributeString1)      
        
        case 'vendorProduct':
            # Remove the vendor name if it is duplicated in the product
            productVCullValue = formatFor23CPE(attributeString1 + "_")          
            if productVCullValue in attributeString2:
                attributeString2 = attributeString2.replace(productVCullValue, "")
            
            # General Trimming
            if ("apache_") in attributeString2:
                attributeString2 = attributeString2.replace("apache_", "")

            if ("_software") in attributeString2:
                attributeString2 = attributeString2.replace("_software", "")

            if ("_version") in attributeString2:
                attributeString2 = attributeString2.replace("_version", "")

            if ("_plugin") in attributeString2:
                attributeString2 = attributeString2.replace("_plugin", "")

            return attributeString2
            
# Build a CPE Search string from a cpeBreakout based on type desired
def constructSearchString(rawBreakout, constructType):
    cpeStringResult = ""
    match constructType:
        case "baseQuery":
            # Replace unwanted component values with ANY ("*")
            rawBreakout["version"] = "*"
            rawBreakout["update"] = "*"
            for item in rawBreakout:
                # We give product some wildcards before and after to cast a wider net
                if item == "product" and rawBreakout[item] != "*":
                    cpeStringResult = cpeStringResult + "*" + str(rawBreakout[item]) + "*:"
                else:
                    cpeStringResult = cpeStringResult + str(rawBreakout[item]) + ":"
                        
            cpeStringResult = cpeStringResult.rstrip(":")
            return cpeStringResult
        case "base":
            # Replace unwanted component values with ANY ("*")
            rawBreakout["version"] = "*"
            rawBreakout["update"] = "*"
            for item in rawBreakout:
                # We give product some wildcards before and after to cast a wider net
                if item == "product":
                    cpeStringResult = cpeStringResult +  str(rawBreakout[item] + ":")
                else:
                    cpeStringResult = cpeStringResult + str(rawBreakout[item] + ":")
                        
            cpeStringResult = cpeStringResult.rstrip(cpeStringResult[-1])
            return(cpeStringResult)
        case _:
            print("[WARNING] unexpected constructType:  " + constructType)
#
# Identify if CPE 2.3/2.2 provided and breakout into component based dictionary
def breakoutCPEComponents(cpeMatchString):
    # using ":" as a delimeter will work in 99% of cases today. 
    cpeBreakOut = cpeMatchString.split(":")
    
    # Handle empty or malformed CPE strings
    if len(cpeBreakOut) < 2:
        print(f"[WARNING] Malformed CPE string: {cpeMatchString}")
        return {"cpePrefix": "", "cpeVersion": "unknown", "part": "*", "vendor": "*", "product": "*", 
                "version": "*", "update": "*", "edition": "*", "lang": "*", 
                "swEdition": "*", "targetSW": "*", "targetHW": "*", "other": "*"}
    
    cpeVersion = cpeBreakOut[1]
    
    if cpeVersion == "2.3":
        cpeDict = {
                "cpePrefix": cpeBreakOut[0],
                "cpeVersion": cpeBreakOut[1],
                "part": cpeBreakOut[2] if len(cpeBreakOut) > 2 else "*",
                "vendor": cpeBreakOut[3] if len(cpeBreakOut) > 3 else "*",
                "product": cpeBreakOut[4] if len(cpeBreakOut) > 4 else "*",
                "version": cpeBreakOut[5] if len(cpeBreakOut) > 5 else "*",
                "update": cpeBreakOut[6] if len(cpeBreakOut) > 6 else "*",
                "edition": cpeBreakOut[7] if len(cpeBreakOut) > 7 else "*",
                "lang": cpeBreakOut[8] if len(cpeBreakOut) > 8 else "*",
                "swEdition": cpeBreakOut[9] if len(cpeBreakOut) > 9 else "*",
                "targetSW": cpeBreakOut[10] if len(cpeBreakOut) > 10 else "*",
                "targetHW": cpeBreakOut[11] if len(cpeBreakOut) > 11 else "*",
                "other": cpeBreakOut[12] if len(cpeBreakOut) > 12 else "*"
                }
        return cpeDict
    # FIX: Use 'in' operator for the comparison instead of OR
    elif cpeVersion in ["/a", "/o", "/h"]:
        cpeDict = {
                "cpePrefix": cpeBreakOut[0],
                "cpeVersion": "2.3",
                "part": "*",
                "vendor": cpeBreakOut[2] if len(cpeBreakOut) > 2 else "*",
                "product": cpeBreakOut[3] if len(cpeBreakOut) > 3 else "*",
                "version": cpeBreakOut[4] if len(cpeBreakOut) > 4 else "*",
                "update": "*",
                "edition": "*",
                "lang": "*",
                "swEdition": "*",
                "targetSW": "*",
                "targetHW": "*",
                "other": "*"
                }
        return cpeDict
    else: 
        print(f"[WARNING] CPE type check error! {cpeVersion}")
        return {"cpePrefix": "", "cpeVersion": "unknown", "part": "*", "vendor": "*", "product": "*", 
                "version": "*", "update": "*", "edition": "*", "lang": "*", 
                "swEdition": "*", "targetSW": "*", "targetHW": "*", "other": "*"}
#
######################## 

########################
# Integrity Check Dump #
########################
# CVE List related sanity checks
def integrityCheckCVE(checkType, checkValue, checkDataSet=False):
    match checkType:
        case "cveIdMatch":
            # Confirm that ID returned by the API is the one entered
            if checkValue == checkDataSet["cveMetadata"]["cveId"]:
                print("[INFO]  Getting " + checkValue +" from CVE Program services...")
            else:
                print("[FAULT]  CVE Services CVE ID check failed! CVE-ID from Services returned as ", checkDataSet["cveMetadata"]["cveId"], "...Exiting")
                exit()
        
        case "cveStatusCheck":
            # Confirm the CVE ID is not REJECTED
            if checkDataSet["cveMetadata"]["state"] == checkValue:
                print("[FAULT]  CVE record is in the " + checkDataSet["cveMetadata"]["state"] + " state!")
                exit()
            else:
                checkValue == True
                
        case "cveIdFormat":
            # Confirm that the CVE ID entered is a valid CVE ID
            pattern = re.compile("^CVE-[0-9]{4}-[0-9]{4,19}$")
            if re.fullmatch(pattern, checkValue):
                checkValue == True
            else:
                print("[FAULT]  CVE ID Format check failed! \"", checkValue, "\"...Exiting")
                exit()
        case _:
            print("[FAULT]  Unexpected Case for Integrity Check! ...Exiting")
            exit()

# More sophisticated product_key to handle edge cases
def create_product_key(affected, source_id):
    """Create a unique key for a product to prevent duplicate rows"""
    # Handle None or non-dictionary affected
    if affected is None or not isinstance(affected, dict):
        return f"unknown:{source_id}"
    
    vendor = affected.get('vendor', '').lower().strip()
    product = affected.get('product', '').lower().strip()
    
    # Include CPEs in the key if available
    cpes = []
    if affected.get('cpes') and isinstance(affected.get('cpes'), list):
        cpes = sorted(affected.get('cpes', []))
    cpes_string = "-".join(cpes)
    
    # Include version information in the key
    versions_info = ""
    if affected.get('versions') and isinstance(affected.get('versions'), list):
        # Create a hash of version information to identify unique version sets
        for v in affected.get('versions', []):
            if isinstance(v, dict):
                if v.get('version'):
                    versions_info += f"{v.get('version')}:"
                if v.get('lessThan'):
                    versions_info += f"lt{v.get('lessThan')}:"
                if v.get('lessThanOrEqual'):
                    versions_info += f"lte{v.get('lessThanOrEqual')}:"
    
    # Generate the complete key
    return f"{vendor}:{product}:{source_id}:{cpes_string}:{versions_info}"