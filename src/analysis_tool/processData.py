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
            for version_entry in versions_found_content:
                for check in cpe_version_checks:
                    for key, value in check.items():
                        if key in version_entry:
                            cpe_value = version_entry[key]
                            cpe_breakout = breakoutCPEComponents(cpe_value)
                            if cpe_breakout['version'] == value:
                                matched_versions.append({key: cpe_value})
                                base_value['matched'] = True
                                break
            base_value['versionsFoundContent'] = matched_versions
            base_value['versionsFound'] = len(matched_versions)

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
def populateRawCPEsQueryData(rawDataSet: pd.DataFrame, cpeQueryData: List[Dict[str, Any]],):
    # Create a copy of the dataframe to avoid modifying the original
    updated_df = rawDataSet.copy()
    
    # Iterate through each row in the DataFrame
    for index, row in updated_df.iterrows():
        # Initialize a dictionary to store the matched values
        matchedValues = {}
        
        # Get the cpeBaseStrings for the current row
        cpeBaseStringsList = row['cpeBaseStrings']
        
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
            for cpe_string in cpe_base_strings:
                distinct_values.add(cpe_string)

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
            
            # Gather data from the NVD API based on a derived list of unique CPE Match Strings
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

# Consolidated function to process CVE record data and ensure a single row per affected array entry
def processCVEData(df, cve_data):
    def processCVEAffectedEntry(entry, source_id, source_role):
        rows = []
        # Case 1: version and status exist
        if 'versions' in entry:
            versions_info = []
            for version in entry['versions']:
                if 'version' in version and 'status' in version and 'versionType' not in version:
                    versions_info.append({'version': version['version'], 'status': version['status']})
            if versions_info:
                rows.append({
                    'dataSource': 'CVEAPI',
                    'sourceID': source_id,
                    'sourceRole': source_role,
                    'platformFormatType': 'cveAffectsVersionSingle',
                    'hasCPEArray': entry.get('cpes', []),  # Extract the 'cpes' array
                    'rawPlatformData': entry,
                    'cpeBaseStrings': '',
                    'cpeVersionChecks': versions_info,
                    'rawCPEsQueryData': [],
                    'sortedCPEsQueryData': [],
                    'trimmedCPEsQueryData': [],
                    'platformStatistics': []
                })
        
        # Case 2: version and versionType exist
        if 'versions' in entry:
            versions_info = []
            for version in entry['versions']:
                if 'version' in version and 'versionType' in version:
                    if 'lessThan' in version:
                        versions_info.append({'version': version['version'], 'status': version['status']})
                        versions_info.append({'lessThan': version['lessThan'], 'status': version['status']})
                        rows.append({
                            'dataSource': 'CVEAPI',
                            'sourceID': source_id,
                            'sourceRole': source_role,
                            'platformFormatType': 'cveAffectsVersionRange',
                            'hasCPEArray': entry.get('cpes', []),  # Extract the 'cpes' array
                            'rawPlatformData': entry,
                            'cpeBaseStrings': '',
                            'cpeVersionChecks': versions_info,
                            'rawCPEsQueryData': [],
                            'sortedCPEsQueryData': [],
                            'trimmedCPEsQueryData': [],
                            'platformStatistics': []
                        })
                    elif 'lessThanOrEqual' in version:
                        versions_info.append({'version': version['version'], 'status': version['status']})
                        versions_info.append({'lessThanOrEqual': version['lessThanOrEqual'], 'status': version['status']})
                        rows.append({
                            'dataSource': 'CVEAPI',
                            'sourceID': source_id,
                            'sourceRole': source_role,
                            'platformFormatType': 'cveAffectsVersionRange',
                            'hasCPEArray': entry.get('cpes', []),  # Extract the 'cpes' array
                            'rawPlatformData': entry,
                            'cpeBaseStrings': '',
                            'cpeVersionChecks': versions_info,
                            'rawCPEsQueryData': [],
                            'sortedCPEsQueryData': [],
                            'trimmedCPEsQueryData': [],
                            'platformStatistics': []
                        })
                    else:  # 'version' lone wolf:
                        versions_info.append({'version': version['version'], 'status': version['status']})
                        rows.append({
                            'dataSource': 'CVEAPI',
                            'sourceID': source_id,
                            'sourceRole': source_role,
                            'platformFormatType': 'cveAffectsVersionSingle',
                            'hasCPEArray': entry.get('cpes', []),  # Extract the 'cpes' array
                            'rawPlatformData': entry,
                            'cpeBaseStrings': '',
                            'cpeVersionChecks': versions_info,
                            'rawCPEsQueryData': [],
                            'sortedCPEsQueryData': [],
                            'trimmedCPEsQueryData': [],
                            'platformStatistics': []
                        })
        
        return rows

    if 'containers' in cve_data:
        rows = []
        for container in cve_data['containers'].get('cna', []):
            source_id = cve_data['containers'].get('cna', {}).get('providerMetadata', {}).get('orgId')
            
            # Process affected section
            if 'affected' in container:
                
                affected_entries = cve_data['containers'].get('cna', {}).get('affected')
                print('CVE List CNA Affected Section Found: ', len(affected_entries), ' entries...')
                
                for entry in affected_entries:
                    rows.extend(processCVEAffectedEntry(entry, source_id, 'CNA'))
            
            # Process cpeApplicability section
            if 'cpeApplicability' in container:
                print('CVE List CNA CPE Applicability Section Found: (Stored, but not leveraged yet)')
                rows.append({
                    'dataSource': 'CVEAPI',
                    'sourceID': source_id,
                    'sourceRole': 'CNA',
                    'platformFormatType': 'cpeApplicability',
                    'rawPlatformData': cve_data['containers'].get('cna', {}).get('cpeApplicability'),
                    'cpeBaseStrings': '',
                    'cpeVersionChecks': [],
                    'rawCPEsQueryData': [],
                    'sortedCPEsQueryData': [],
                    'trimmedCPEsQueryData': [],
                    'platformStatistics': []
                })

        # Process ADP entries
        for container in cve_data['containers'].get('adp', []):
            source_id = container.get('providerMetadata', {}).get('orgId')
            
            # Process affected section
            if 'affected' in container:
                
                affected_entries = container.get('affected', [])
                print('CVE List ADP Affected Section Found: ', len(affected_entries), ' entries...')
                for entry in affected_entries:
                    rows.extend(processCVEAffectedEntry(entry, source_id, 'ADP'))
            
            # Process cpeApplicability section
            if 'cpeApplicability' in container:
                print('CVE List ADP CPE Applicability Section Found: (Stored, but not leveraged yet)')
                rows.append({
                    'dataSource': 'CVEAPI',
                    'sourceID': source_id,
                    'sourceRole': 'ADP',
                    'platformFormatType': 'cpeApplicability',
                    'rawPlatformData': container.get('cpeApplicability'),
                    'cpeBaseStrings': '',
                    'cpeVersionChecks': [],
                    'rawCPEsQueryData': [],
                    'sortedCPEsQueryData': [],
                    'trimmedCPEsQueryData': [],
                    'platformStatistics': []
                })
        if rows:
            df = pd.concat([df, pd.DataFrame(rows)], ignore_index=True)
    
    return df

# Determines platformFormatType for data, populates dataSource, sourceID, sourceRole, and rawPlatformData
def processNVDRecordData(df, nvd_data):
    if 'vulnerabilities' in nvd_data:
        for vuln in nvd_data['vulnerabilities']:
            if 'configurations' in vuln['cve']:
                new_row = {
                    'dataSource': 'NVDAPI',
                    'sourceID': 'nvd@nist.gov',
                    'sourceRole': 'NVD',
                    'platformFormatType': 'cpeApplicability',
                    'rawPlatformData': vuln['cve'].get('configurations', []),
                    'cpeBaseStrings': '',
                    'cpeVersionChecks': [],
                    'rawCPEsQueryData': [],
                    #'filteredCPEsQueryData': [],
                    'sortedCPEsQueryData': [],
                    'platformStatistics': []
                }
                print('NVD Configurations Section Found...')
                df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    
    return df


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
    # need to add support for "\:" present in a component to avoid improper breakout. 
    cpeBreakOut = cpeMatchString.split(":")
    cpeVersion = cpeBreakOut[1]
    
    if cpeVersion == "2.3":
        cpeDict = {
                "cpePrefix": cpeBreakOut[0],
                "cpeVersion": cpeBreakOut[1],
                "part": cpeBreakOut[2],
                "vendor": cpeBreakOut[3],
                "product": cpeBreakOut[4],
                "version":cpeBreakOut[5],
                "update": cpeBreakOut[6],
                "edition": cpeBreakOut[7],
                "lang": cpeBreakOut[8],
                "swEdition": cpeBreakOut[9],
                "targetSW": cpeBreakOut[10],
                "targetHW": cpeBreakOut[11],
                "other": cpeBreakOut[12]
                }
        return (cpeDict)
    elif cpeVersion == "/a" or "/o" or "/h":
        cpeDict = {
                "cpePrefix": cpeBreakOut[0],
                "cpeVersion": "2.3",
                "part": "*",
                "vendor": cpeBreakOut[2],
                "product": cpeBreakOut[3],
                "version":cpeBreakOut[4],
                "update": "*",
                "edition": "*",
                "lang": "*",
                "swEdition": "*",
                "targetSW": "*",
                "targetHW": "*",
                "other": "*"
                }
        return (cpeDict)
    else: 
        print("[WARNING] CPE type check error! " + str(cpeDict["cpeVersion"]))
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
########################
