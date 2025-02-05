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

def sort_broad_entries(data):
    # Sort the list of dictionaries based on 'matches_found' in descending order
    sorted_data = sorted(data, key=lambda x: list(x.values())[0].get('matches_found', 0), reverse=True)
    return sorted_data

def sort_base_strings(sorted_data):
    for entry in sorted_data:
        for broad_key, broad_value in entry.items():
            sorted_base_strings = dict(sorted(
                broad_value['base_strings'].items(), 
                key=lambda x: (
                    # Primary sort: Total items in versions_found
                    len(x[1].get('versionsFound', [])),
                    # Secondary sort: Total dependency count
                    x[1].get('depFalseCount', 0) + x[1].get('depTrueCount', 0),
                    # Tertiary sort: depFalseCount
                    x[1].get('depFalseCount', 0)
                ),
                reverse=True
            ))
            broad_value['base_strings'] = sorted_base_strings
    
    return sorted_data

# Processes statistics based on /cpes/ response data
def analyzeBaseStrings(rawDataSet, json_response: Dict[str, Any]) -> Dict[str, Any]:

    # Initialize some data collection variables
    base_strings = defaultdict(lambda: {"depTrueCount": 0, "depFalseCount": 0, "versionsFound": {}})
    total_deprecated = 0
    total_active = 0
    
    for product in json_response["products"]:
        
        cpe_name = product["cpe"]["cpeName"]
        cpe_components = breakoutCPEComponents(cpe_name) 
        cpe_version_value = cpe_components['version']
        base_cpe_name = constructSearchString(cpe_components, "base")

        # Populate version_found based on comparisons to query results
        for check in rawDataSet.get('cpeVersionChecks', []):
            versions_found = []
            # Ensure check is a dictionary and has a 'version' key
            if isinstance(check, dict) and 'version' in check:
                # Compare the version value with cpe_version_value
                if 'version' in check and check['version'] == cpe_version_value:
                    versions_found.append({'version': check['version']})
                if 'lessThan' in check and check['lessThan'] == cpe_version_value:
                    versions_found.append({'lessThan': check['version']})
                if 'lessThanOrEqual' in check and check['lessThanOrEqual'] == cpe_version_value:
                    versions_found.append({'lessThanOrEqual': check['version']})
            
                base_strings[base_cpe_name]['versionsFound'] = versions_found
        
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
#
# Processes the mapping of /cpes/ API results with the baseStrings derived from external data
def replaceCPEStringsWithMappings(primaryDataframe: pd.DataFrame, final_sorted_result: List[Dict[str, Any]],):
    # Create a copy of the dataframe to avoid modifying the original
    updated_df = primaryDataframe.copy()
    
    # Iterate through each row in the DataFrame
    for index, row in updated_df.iterrows():
        # Initialize a dictionary to store the matched values
        matched_values = {}
        
        # Get the cpeBaseStrings for the current row
        cpe_base_strings = row['cpeBaseStrings']
        
        # Compare each cpeBaseString with the keys in final_sorted_result
        for cpe_string in cpe_base_strings:
            for entry in final_sorted_result:
                for key, value in entry.items():
                    if cpe_string == key:
                        matched_values[key] = value
        
        # Replace the content of the cpeBaseStrings field with the dictionary of matched values
        updated_df.at[index, 'cpesQueryData'] = matched_values
    
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
def suggestCPEData(apiKey, rawDataSet, case):
    match case:
        # Case 1 covers the original CVE List implementation
        case 1:

            # Iterate through each row in the DataFrame
            for index, row in rawDataSet.iterrows():
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

                    if 'platformFormatType' in row and row['platformFormatType'] in ['cpeApplicability']:
                        print ("[WARN]  cpeApplicability data identified! This is not currently supported! This means that any data related to cpeApplicability will not be processed or included in the results.")

                # Add the cpeBaseStrings list to the cpeBaseStrings column of primaryDataframe
                rawDataSet.at[index, 'cpeBaseStrings'] = cpeBaseStrings
                uniqueStringList = deriveCPEMatchStringList(rawDataSet)
            
            cpeQueryData = bulkQueryandProcessNVDCPEs(apiKey, rawDataSet, uniqueStringList)

            # Sort the query data results so that the most relevant cpeBaseStrings are listed first.
            sortedCPEQueryData = sort_broad_entries(cpeQueryData)
            final_sorted_result = sort_base_strings(sortedCPEQueryData)

            rawDataSet = replaceCPEStringsWithMappings(rawDataSet, cpeQueryData)

            return rawDataSet
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
                base_string_stats = analyzeBaseStrings(rawDataSet, json_response)
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
# Determines affected section sub-type, populates dataSource, sourceID, sourceRole, and rawPlatformData
def processCVEAffectedEntry(entry, source_id, source_role):
    rows = []
    # Case 1: version and status exist
    if 'versions' in entry:
        for version in entry['versions']:
            if 'version' in version and 'status' in version and 'versionType' not in version:
                singleVersionEntry = entry
                singleVersionEntry['versions'] = version
                rows.append({
                    'dataSource': 'CVEAPI',
                    'sourceID': source_id,
                    'sourceRole': source_role,
                    'platformFormatType': 'cveAffectsVersionSingle',
                    'hasCPEArray': 'cpes' in entry,  # This will be True if entry contains cpes array, False otherwise
                    'rawPlatformData': singleVersionEntry,
                    'cpeBaseStrings': '',
                    'cpeVersionChecks': {'version': version['version']},
                    'cpesQueryData' : ''
                })
    
    # Case 2: version and versionType exist
    if 'versions' in entry:
        for version in entry['versions']:
            if 'version' in version and 'versionType' in version:
                

                if 'lessThan' in version:
                    rows.append({
                        'dataSource': 'CVEAPI',
                        'sourceID': source_id,
                        'sourceRole': source_role,
                        'platformFormatType': 'cveAffectsVersionRange',
                        'hasCPEArray': 'cpes' in entry,  # This will be True if entry contains cpes array, False otherwise
                        'rawPlatformData': entry,                    
                        'cpeBaseStrings': '',
                        'cpeVersionChecks': {'version': version['version'], 'lessThan': version['lessThan']},
                        'cpesQueryData' : ''
                    })
                elif 'lessThanOrEqual' in version:
                    rows.append({
                        'dataSource': 'CVEAPI',
                        'sourceID': source_id,
                        'sourceRole': source_role,
                        'platformFormatType': 'cveAffectsVersionRange',
                        'hasCPEArray': 'cpes' in entry,
                        'rawPlatformData': entry,                    
                        'cpeBaseStrings': '',
                        'cpeVersionChecks': {'version': version['version'], 'lessThanOrEqual': version['lessThanOrEqual']},
                        'cpesQueryData' : ''
                    })
                else: #'version' lone wolf:
                    rows.append({
                        'dataSource': 'CVEAPI',
                        'sourceID': source_id,
                        'sourceRole': source_role,
                        'platformFormatType': 'cveAffectsVersionSingle',
                        'hasCPEArray': 'cpes' in entry,
                        'rawPlatformData': singleVersionEntry,
                        'cpeBaseStrings': '',
                        'cpeVersionChecks': {'version': version['version']},
                        'cpesQueryData' : ''
                })
    
    return rows
#
# Determines platformFormatType for data, populates dataSource, sourceID, sourceRole, and rawPlatformData
def processCVERecordData(df, cve_data):
    if 'containers' in cve_data:
        rows = []
        for container in cve_data['containers'].get('cna', []):
            source_id = cve_data['containers'].get('cna', {}).get('providerMetadata', {}).get('orgId')
            
            # Process affected section
            if 'affected' in container:
                print('CVE List CNA Affected Section Found...')
                affected_entries = cve_data['containers'].get('cna', {}).get('affected')
                for entry in affected_entries:
                    rows.extend(processCVEAffectedEntry(entry, source_id, 'CNA'))
            
            # Process cpeApplicability section
            if 'cpeApplicability' in container:
                print('CVE List CNA CPE Applicability Section Found...')
                rows.append({
                    'dataSource': 'CVEAPI',
                    'sourceID': source_id,
                    'sourceRole': 'CNA',
                    'platformFormatType': 'cpeApplicability',
                    'rawPlatformData': cve_data['containers'].get('cna', {}).get('cpeApplicability'),
                    'cpeBaseStrings': '',
                    'cpeVersionChecks': '',
                    'cpesQueryData' : ''
                })

        # Process ADP entries
        for container in cve_data['containers'].get('adp', []):
            source_id = container.get('providerMetadata', {}).get('orgId')
            
            # Process affected section
            if 'affected' in container:
                print('CVE List ADP Affected Section Found...')
                affected_entries = container.get('affected', [])
                for entry in affected_entries:
                    rows.extend(processCVEAffectedEntry(entry, source_id, 'ADP'))
            
            # Process cpeApplicability section
            if 'cpeApplicability' in container:
                print('CVE List ADP CPE Applicability Section Found...')
                rows.append({
                    'dataSource': 'CVEAPI',
                    'sourceID': source_id,
                    'sourceRole': 'ADP',
                    'platformFormatType': 'cpeApplicability',
                    'rawPlatformData': container.get('cpeApplicability'),
                    'cpeBaseStrings': '',
                    'cpeVersionChecks': '',
                    'cpesQueryData' : ''
                })
        if rows:
            df = pd.concat([df, pd.DataFrame(rows)], ignore_index=True)
    
    return df
#
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
                    'cpesQueryData' : ''
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
            productVCullValue = (formatFor23CPE(attributeString1 + "_"))
            if (productVCullValue) in attributeString2:
                attributeString2 = attributeString2.replace((productVCullValue), "")

            return (attributeString2)
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
