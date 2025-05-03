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
    # Enhanced sorting logic with more granular priority handling
    def sort_key(item):
        base_key, attributes = item
        # Check for the presence of specific tags
        has_affected_cpes_array = any(key.startswith('searchSourcecveAffectedCPEsArray') for key in attributes.keys())
        has_vendor_product = any(key.startswith('searchSourcevendorproduct') for key in attributes.keys())
        has_product = any(key.startswith('searchSourceproduct') and not key.startswith('searchSourcevendorproduct') for key in attributes.keys())
        has_vendor = any(key.startswith('searchSourcevendor') and not key.startswith('searchSourcevendorproduct') for key in attributes.keys())

        # Multi-level priority system - create a composite priority value
        # Primary level: cpes array (yes/no) - 0 or 10
        # Secondary level: source type priority (0-4)
        
        primary_priority = 0 if has_affected_cpes_array else 10
        
        if has_vendor_product:
            secondary_priority = 0   # vendor+product (highest secondary)
        elif has_product:
            secondary_priority = 1   # product only
        elif has_vendor:
            secondary_priority = 2   # vendor only
        else:
            secondary_priority = 3   # other sources (lowest)

        # Combine to get a composite priority score where CPE array entries are always higher
        # regardless of secondary priority, but among CPE array entries, vendor+product > product > vendor
        composite_priority = primary_priority + secondary_priority

        # Apply additional sorting criteria after the composite priority
        return (
            composite_priority,                      # Primary: composite source priority
            attributes.get('depFalseCount', 0) == 0, # Secondary: depFalseCount
            -attributes.get('searchCount', 0),       # Tertiary: searchCount
            -attributes.get('versionsFound', 0),     # Quaternary: versionsFound
            -(attributes.get('depFalseCount', 0) + attributes.get('depTrueCount', 0)), # Quinary: total count
            -attributes.get('depFalseCount', 0)      # Senary: depFalseCount
        )

    # Sort the dictionary and return as a new dictionary
    sorted_base_strings = dict(sorted(unique_base_strings.items(), key=sort_key))
    return sorted_base_strings
#
def reduceToTop10(workingDataset: pd.DataFrame) -> pd.DataFrame:
    
    trimmedDataset = workingDataset.copy()
    top_10_base_strings_dict = {}

    # Create a mapping of CPE strings that came from cveAffectedCPEsArray
    cpes_array_sources = {}
    for index, row in workingDataset.iterrows():
        if 'platformEntryMetadata' in row:
            metadata = row['platformEntryMetadata']
            if 'cpeBaseStrings' in metadata and 'cpeSourceTypes' in metadata and 'cveAffectedCPEsArray' in metadata.get('cpeSourceTypes', []):
                for cpe_string in metadata['cpeBaseStrings']:
                    cpes_array_sources[cpe_string] = True

    def consolidateBaseStrings(data, unique_base_strings, duplicate_keys):
        for key, value in data.items():
            if isinstance(value, dict):
                cpe_breakout = breakoutCPEAttributes(key)  # Updated function name
                recorded_keys = {k: v for k, v in cpe_breakout.items() if v != '*' and k not in ['cpePrefix', 'cpeVersion']}
                recorded_keys_str = "".join(recorded_keys.keys())
                
                # Check if this key is from the cveAffectedCPEsArray using our mapping
                is_from_cpes_array = key in cpes_array_sources
                
                if 'base_strings' in value:
                    base_strings = value['base_strings']
                    for base_key, base_value in base_strings.items():
                        if base_key in unique_base_strings:
                            duplicate_keys[base_key] = duplicate_keys.get(base_key, 1) + 1
                            unique_base_strings[base_key]['searchCount'] += 1
                            unique_base_strings[base_key]['searchSource' + recorded_keys_str] = key
                            # Mark if this is from CPEs array
                            if is_from_cpes_array:
                                unique_base_strings[base_key]['searchSourcecveAffectedCPEsArray'] = key
                        else:
                            unique_base_strings[base_key] = base_value
                            unique_base_strings[base_key]['searchCount'] = 1
                            unique_base_strings[base_key]['searchSource' + recorded_keys_str] = key
                            # Mark if this is from CPEs array
                            if is_from_cpes_array:
                                unique_base_strings[base_key]['searchSourcecveAffectedCPEsArray'] = key
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
                            cpe_breakout = breakoutCPEAttributes(cpe_value)
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
        
        # Access cpeVersionChecks from platformEntryMetadata dictionary
        platform_metadata = row.get('platformEntryMetadata', {})
        cpe_version_checks = platform_metadata.get('cpeVersionChecks', [])
        
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
    updated_df = rawDataSet.copy()
    
    for index, row in updated_df.iterrows():
        matchedValues = {}
        
        # Get cpeBaseStrings from platformEntryMetadata
        platform_metadata = row.get('platformEntryMetadata', {})
        cpeBaseStringsList = platform_metadata.get('cpeBaseStrings', [])
        
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
                        # Create a copy of the results to modify
                        result_copy = value.copy()
                        
                        # If there are row-specific results, use only this row's data
                        if "row_specific_results" in result_copy and index in result_copy["row_specific_results"]:
                            # Get this row's specific results
                            row_result = result_copy["row_specific_results"][index]
                            
                            # Replace general results with row-specific ones
                            if "base_strings" in row_result:
                                result_copy["base_strings"] = row_result["base_strings"]
                            if "unique_base_count" in row_result:
                                result_copy["unique_base_count"] = row_result["unique_base_count"]
                            if "total_deprecated" in row_result:
                                result_copy["total_deprecated"] = row_result["total_deprecated"]
                            if "total_active" in row_result:
                                result_copy["total_active"] = row_result["total_active"]
                            
                            # Remove the row_specific_results to avoid redundancy
                            del result_copy["row_specific_results"]
                        
                        matchedValues[key] = result_copy
        
        # Update the content of the 'rawCPEsQueryData' field with the dictionary of matched values
        updated_df.at[index, 'rawCPEsQueryData'] = matchedValues
    
    return updated_df
#
# Generates a list of unique cpeMatchStrings based on the contents of cpeBaseStrings
def deriveCPEMatchStringList(rawDataSet):
    """
    Extract unique CPE base strings from all rows in the dataset.
    Logs warnings if unexpected data formats are encountered.
    """
    distinct_values = set()

    # Iterate through each row in the DataFrame
    for index, row in rawDataSet.iterrows():
        if 'platformEntryMetadata' not in row:
            print(f"[WARNING] Row {index} missing platformEntryMetadata")
            continue
            
        platform_metadata = row['platformEntryMetadata']
        if 'cpeBaseStrings' not in platform_metadata:
            print(f"[WARNING] Row {index} missing cpeBaseStrings in platformEntryMetadata")
            continue
        
        cpe_base_strings = platform_metadata['cpeBaseStrings']
        
        # Check if cpeBaseStrings is the expected list type
        if not isinstance(cpe_base_strings, list):
            print(f"[WARNING] Row {index} has cpeBaseStrings that is not a list (type: {type(cpe_base_strings)})")
            # Try to convert to list if possible
            if isinstance(cpe_base_strings, (tuple, set)):
                cpe_base_strings = list(cpe_base_strings)
            elif cpe_base_strings and not pd.isna(cpe_base_strings):
                cpe_base_strings = [str(cpe_base_strings)]
            else:
                cpe_base_strings = []
        
        # Process the strings (now guaranteed to be a list)
        for cpe_string in cpe_base_strings:
            if not cpe_string:  # Skip empty strings but log them
                print(f"[WARNING] Empty CPE string found in row {index}")
                continue
                
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

                # Initialize curation tracking
                curation_tracking = {
                    "vendor": [],
                    "product": [],
                    "vendorProduct": []
                }

                # Get platformFormatType from platformEntryMetadata
                platform_metadata = row.get('platformEntryMetadata', {})
                platform_format_type = platform_metadata.get('platformFormatType', '')

                # Check if platformFormatType is cveAffectsVersionSingle or cveAffectsVersionRange
                if platform_format_type in ['cveAffectsVersionSingle', 'cveAffectsVersionRange', 'cveAffectsVersionMix']:
                    
                    if 'rawPlatformData' in row:
                        platform_data = row['rawPlatformData']
                        
                    # Generate CPE Match Strings based on available content
                    if 'vendor' in platform_data:
                        # Improved check for n/a values - convert to lowercase and check multiple formats
                        vendor_value = platform_data['vendor']
                        if isinstance(vendor_value, str) and vendor_value.lower() in ["n/a", "n\\/a", "n/a"]:
                            print("[INFO] Skipping vendor search string generation - 'n/a' placeholder detected")
                            # Set a flag in metadata
                            if 'vendorNAConcern' not in rawDataset.at[index, 'platformEntryMetadata']:
                                rawDataset.at[index, 'platformEntryMetadata']['vendorNAConcern'] = True
                        else:
                            # Only proceed with normal CPE string generation if not n/a
                            cpeValidstring = formatFor23CPE(platform_data['vendor'])
                            original_vendor = cpeValidstring
                            culledString = curateCPEAttributes('vendor', cpeValidstring, True)

                            # Track curation
                            if culledString != original_vendor:
                                curation_tracking["vendor"].append({
                                    "original": original_vendor,
                                    "curated": culledString
                                })
                            
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
                            rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update  + ":" + edition  + ":" + lang  + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                            scratchSearchStringBreakout = breakoutCPEAttributes(rawMatchString)
                            scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                            cpeBaseStrings.append(scratchMatchString)

                    # Generate CPE Match Strings based on available content for 'product'
                    if 'product' in platform_data:
                        # Improved check for n/a values - convert to lowercase and check multiple formats
                        product_value = platform_data['product']
                        if isinstance(product_value, str) and product_value.lower() in ["n/a", "n\\/a", "n/a"]:
                            print("[INFO] Skipping product search string generation - 'n/a' placeholder detected")
                            # Set a flag in metadata
                            if 'productNAConcern' not in rawDataset.at[index, 'platformEntryMetadata']:
                                rawDataset.at[index, 'platformEntryMetadata']['productNAConcern'] = True
                        else:
                            # Only proceed with normal CPE string generation if not n/a
                            cpeValidstring = formatFor23CPE(platform_data['product'])
                            original_product = cpeValidstring
                            culledString = curateCPEAttributes('product', cpeValidstring, True)

                            # Track curation
                            if culledString != original_product:
                                curation_tracking["product"].append({
                                    "original": original_product,
                                    "curated": culledString
                                })
                            
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
                            rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update  + ":" + edition  + ":" + lang  + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                            scratchSearchStringBreakout = breakoutCPEAttributes(rawMatchString)
                            scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                            cpeBaseStrings.append(scratchMatchString)

                    # Initialize platform_values_searched at the beginning of the platform entry processing
                    platform_values_searched = False

                    # Generate CPE Match Strings based on available content for 'platform'

                    if 'platforms' in platform_data and isinstance(platform_data['platforms'], list):
                        platforms = platform_data['platforms']
                        platform_found_but_not_recognized = False
                        
                        # Iterate through each platform in the array
                        for platform_item in platforms:
                            platform_string = platform_item.lower() if isinstance(platform_item, str) else ""
                            
                            if not platform_string:
                                continue
                                
                            # Mark that we found platform data (even if it's "unknown")
                            platform_found_but_not_recognized = True
                                
                            # Handle common architecture terms in platform strings
                            if "32-bit" in platform_string or "x32" in platform_string or "x86" in platform_string:
                                platform_values_searched = True
                                targetHW = "x86"
                                rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + edition + ":" + lang + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                                scratchSearchStringBreakout = breakoutCPEAttributes(rawMatchString)
                                scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                                cpeBaseStrings.append(scratchMatchString)
                                
                            if "64-bit" in platform_string or "x64" in platform_string or "x86_64" in platform_string:
                                platform_values_searched = True
                                targetHW = "x64"
                                rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + edition + ":" + lang + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                                scratchSearchStringBreakout = breakoutCPEAttributes(rawMatchString)
                                scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                                cpeBaseStrings.append(scratchMatchString)
                                
                            if "arm" in platform_string and "arm64" not in platform_string:
                                platform_values_searched = True
                                targetHW = "arm"
                                rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + edition + ":" + lang + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                                scratchSearchStringBreakout = breakoutCPEAttributes(rawMatchString)
                                scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                                cpeBaseStrings.append(scratchMatchString)
                                
                            if "arm64" in platform_string:
                                platform_values_searched = True
                                targetHW = "arm64"
                                rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + edition + ":" + lang + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                                scratchSearchStringBreakout = breakoutCPEAttributes(rawMatchString)
                                scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                                cpeBaseStrings.append(scratchMatchString)
                                
                        # At the end of processing platforms, check if we had platforms but couldn't recognize any
                        # This will catch cases like "Unknown" platforms
                        if platform_found_but_not_recognized and not platform_values_searched:
                            if 'platformDataConcern' not in rawDataset.at[index, 'platformEntryMetadata']:
                                rawDataset.at[index, 'platformEntryMetadata']['platformDataConcern'] = True

                    # When processing platform data
                    if 'platforms' in platform_data and isinstance(platform_data['platforms'], list):
                        all_platforms_mapped = True  # Start with assumption that all platforms can be mapped
                        
                        for platform_item in platform_data['platforms']:
                            if platform_item and isinstance(platform_item, str):
                                original_platform = platform_item
                                
                                # Try to map the platform using the curateCPEAttributes function
                                curated_platform, was_mapped = curateCPEAttributes('platform', platform_item, None)
                                
                                if was_mapped:
                                    platform_values_searched = True
                                    targetHW = curated_platform
                                    rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + edition + ":" + lang + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                                    scratchSearchStringBreakout = breakoutCPEAttributes(rawMatchString)
                                    scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                                    cpeBaseStrings.append(scratchMatchString)
                                    
                                    # Track the mapping in the curation tracking
                                    if 'platform' not in curation_tracking:
                                        curation_tracking["platform"] = []
                                        
                                    curation_tracking["platform"].append({
                                        "original": original_platform,
                                        "curated": curated_platform
                                    })
                                else:
                                    all_platforms_mapped = False
                        
                        # Set the platformDataConcern flag if any platform couldn't be mapped
                        if platform_data['platforms'] and not all_platforms_mapped:
                            rawDataset.at[index, 'platformEntryMetadata']['platformDataConcern'] = True

                    # Generate CPE Match Strings based on available content for 'packageName'
                    if 'packageName' in platform_data and isinstance(platform_data['packageName'], str):
                        package_name = platform_data['packageName']
                        
                        # Check if this is a Maven package (based on collection URL or package format)
                        is_maven_package = False
                        if 'collectionURL' in platform_data and 'repo.maven.apache.org' in platform_data['collectionURL']:
                            is_maven_package = True
                        elif ':' in package_name and ('.' in package_name.split(':')[0]):
                            # Heuristic: if there's a colon and dots in the first part, it's likely Maven format
                            is_maven_package = True
                        
                        if is_maven_package and ':' in package_name:
                            print(f"[INFO] Processing Maven package: {package_name}")
                            
                            # Split Maven package name into groupId and artifactId
                            group_id, artifact_id = package_name.split(':', 1)
                            
                            # Format properly for CPE string
                            cpe_group_id = formatFor23CPE(group_id)
                            cpe_artifact_id = formatFor23CPE(artifact_id)
                            
                            # 1. Create a CPE string with just the groupId as the vendor
                            part = "*"
                            vendor = cpe_group_id
                            product = "*"
                            version = "*"
                            update = "*"
                            edition = "*"
                            lang = "*"
                            swEdition = "*"
                            targetSW = "*"
                            targetHW = "*"
                            other = "*"
                            
                            group_id_match_string = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + edition + ":" + lang + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                            if group_id_match_string not in cpeBaseStrings:
                                cpeBaseStrings.append(group_id_match_string)
                            
                            # 2. Create a CPE string with the artifactId as the product
                            part = "*"
                            vendor = "*"
                            product = "*" + cpe_artifact_id + "*"
                            version = "*"
                            update = "*"
                            edition = "*"
                            lang = "*"
                            swEdition = "*"
                            targetSW = "*"
                            targetHW = "*"
                            other = "*"
                            
                            artifact_id_match_string = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + edition + ":" + lang + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                            if artifact_id_match_string not in cpeBaseStrings:
                                cpeBaseStrings.append(artifact_id_match_string)
                            
                            # 3. Create a CPE string with groupId as vendor and artifactId as product
                            part = "*"
                            vendor = cpe_group_id
                            product = "*" + cpe_artifact_id + "*"
                            version = "*"
                            update = "*"
                            edition = "*"
                            lang = "*"
                            swEdition = "*"
                            targetSW = "*"
                            targetHW = "*"
                            other = "*"
                            
                            combined_match_string = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + edition + ":" + lang + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                            if combined_match_string not in cpeBaseStrings:
                                cpeBaseStrings.append(combined_match_string)
                                
                            # Add metadata to track Maven package processing
                            if 'packageSourceTypes' not in rawDataset.at[index, 'platformEntryMetadata']:
                                rawDataset.at[index, 'platformEntryMetadata']['packageSourceTypes'] = []
                            if 'maven' not in rawDataset.at[index, 'platformEntryMetadata']['packageSourceTypes']:
                                rawDataset.at[index, 'platformEntryMetadata']['packageSourceTypes'].append('maven')
                        
                        else:
                            # Process non-Maven packages with the existing code
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
                            rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + edition + ":" + lang + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                            scratchSearchStringBreakout = breakoutCPEAttributes(rawMatchString)
                            scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                            cpeBaseStrings.append(scratchMatchString)

                    # Generate CPE Match Strings based on available content for 'vendor' and 'product'
                    if 'vendor' in platform_data and 'product' in platform_data:
                        vendor_value = platform_data['vendor']
                        product_value = platform_data['product']
                        
                        # Skip vendor+product CPE generation if either contains n/a
                        if (isinstance(vendor_value, str) and vendor_value.lower() in ["n/a", "n\\/a", "n/a"]) or \
                           (isinstance(product_value, str) and product_value.lower() in ["n/a", "n\\/a", "n/a"]):
                            print("[INFO] Skipping vendor+product search string generation - 'n/a' placeholder detected")
                        else:
                            # Only proceed with normal CPE string generation if neither is n/a
                            # 1. Create base string with uncurated values first
                            cpeValidstringVendor = formatFor23CPE(platform_data['vendor'])
                            cpeValidstringProduct = formatFor23CPE(platform_data['product'])
                            original_vendor_product = {
                                "vendor": cpeValidstringVendor,
                                "product": cpeValidstringProduct
                            }
                            
                            part = "*"
                            vendor = cpeValidstringVendor
                            product = cpeValidstringProduct
                            version = "*"
                            update = "*"
                            edition = "*"
                            lang = "*"
                            swEdition = "*"
                            targetSW = "*"
                            targetHW = "*"
                            other = "*"

                            # Build a CPE Search String with raw values
                            rawMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + edition + ":" + lang + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                            scratchSearchStringBreakout = breakoutCPEAttributes(rawMatchString)
                            rawSearchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                            if rawSearchString not in cpeBaseStrings:
                                cpeBaseStrings.append(rawSearchString)
                            
                            # 2. Now create base string with curated values
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

                            # Build a CPE Search String from curated elements
                            curatedMatchString = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + edition + ":" + lang + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                            scratchSearchStringBreakout = breakoutCPEAttributes(curatedMatchString)
                            # Use the standard baseQuery type for the partvendorproduct search - this will add wildcards to the product field
                            curatedSearchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                            if curatedSearchString not in cpeBaseStrings:
                                cpeBaseStrings.append(curatedSearchString)

                            vendor_original = platform_data['vendor']
                            product_original = platform_data['product']
                            
                            # Track vendor+product curation if either value was modified
                            if vendor != vendor_original or product != product_original:
                                # Add combined vendor+product curation tracking
                                if 'vendor_product' not in curation_tracking:
                                    curation_tracking['vendor_product'] = []
                                
                                curation_tracking['vendor_product'].append({
                                    "original": f"{vendor_original}:{product_original}",
                                    "curated": f"{vendor}:{product}"
                                })

                    # Generate CPE Match Strings based on available content for 'vendor' and 'packageName'
                    if 'vendor' in platform_data and 'packageName' in platform_data:
                        cpeValidstringVendor = formatFor23CPE(platform_data['vendor'])
                        cpeValidstringPackageName = formatFor23CPE(platform_data['packageName'])
                        culledStringVendor = curateCPEAttributes('vendor', cpeValidstringVendor, True)
                        culledStringProduct = curateCPEAttributes('vendorProduct', culledStringVendor, cpeValidstringPackageName)
                        
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
                        scratchSearchStringBreakout = breakoutCPEAttributes(rawMatchString)
                        scratchMatchString = constructSearchString(scratchSearchStringBreakout, "baseQuery")
                        cpeBaseStrings.append(scratchMatchString)           

                        vendor_original = platform_data['vendor']
                        packageName_original = platform_data['packageName']
                        
                        # Track vendor+packageName curation if values were modified
                        if vendor != vendor_original or product != packageName_original:
                            # Add combined vendor+packageName curation tracking
                            if 'vendor_package' not in curation_tracking:
                                curation_tracking['vendor_package'] = []
                            
                            curation_tracking['vendor_package'].append({
                                "original": f"{vendor_original}:{packageName_original}",
                                "curated": f"{vendor}:{product}"
                            })

                    # Extract and use CPEs from the CVE affected entry's 'cpes' array
                    if 'cpes' in platform_data and isinstance(platform_data['cpes'], list):
                        for cpe in platform_data['cpes']:
                            # Only add valid CPE strings
                            if cpe and isinstance(cpe, str) and cpe.startswith('cpe:'):
                                # Parse CPE to make sure it's properly formatted
                                cpe_attributes = breakoutCPEAttributes(cpe)
                                
                                # For CPEs from the array, create two different versions
                                # 1. The exact CPE with wildcarded version/update for direct search
                                exact_cpe_attributes = dict(cpe_attributes)
                                exact_cpe_attributes['version'] = '*'  # Always set version to wildcard
                                exact_cpe_attributes['update'] = '*'   # Always set update to wildcard
                                
                                # Build the exact CPE string (no added wildcards to product)
                                exact_cpe_string = ""
                                for item in exact_cpe_attributes:
                                    exact_cpe_string += str(exact_cpe_attributes[item]) + ":"
                                
                                # Remove the trailing colon
                                exact_cpe_string = exact_cpe_string.rstrip(":")
                                
                                # Add to cpeBaseStrings if not already there
                                if exact_cpe_string not in cpeBaseStrings:
                                    cpeBaseStrings.append(exact_cpe_string)
                                    
                                    # Track the source of this CPE base string
                                    if 'cpeSourceTypes' not in rawDataset.at[index, 'platformEntryMetadata']:
                                        rawDataset.at[index, 'platformEntryMetadata']['cpeSourceTypes'] = []
                                    if 'cveAffectedCPEsArray' not in rawDataset.at[index, 'platformEntryMetadata']['cpeSourceTypes']:
                                        rawDataset.at[index, 'platformEntryMetadata']['cpeSourceTypes'].append('cveAffectedCPEsArray')
                                
                                # 2. Add a searchSourcepartvendorproduct version that follows the same pattern as other searches
                                # Only if there is a valid product in the CPE
                                if cpe_attributes['product'] != '*':
                                    part = cpe_attributes['part']  # Preserve the part from the CPE
                                    vendor = cpe_attributes['vendor']  # Preserve the vendor from the CPE
                                    product = "*" + cpe_attributes['product'] + "*"  # Add wildcards like other searches
                                    version = "*"
                                    update = "*"
                                    edition = "*"
                                    lang = "*"
                                    swEdition = "*"
                                    targetSW = "*"
                                    targetHW = "*"
                                    other = "*"

                                    # Build a CPE Search String with wildcarded product
                                    wildcarded_match_string = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":" + update + ":" + edition + ":" + lang + ":" + swEdition + ":" + targetSW + ":" + targetHW + ":" + other
                                    
                                    # Add this search string if it's not already in the list
                                    if wildcarded_match_string not in cpeBaseStrings:
                                        cpeBaseStrings.append(wildcarded_match_string)

                # Update the cpeBaseStrings in platformEntryMetadata instead of as a separate column
                rawDataset.at[index, 'platformEntryMetadata']['cpeBaseStrings'] = cpeBaseStrings

                # Store curation tracking in metadata if any changes were found
                has_curations = any(curation_tracking.values())
                if has_curations:
                    rawDataset.at[index, 'platformEntryMetadata']['cpeCurationTracking'] = curation_tracking
            
            # Generate unique string list for API queries using the updated deriveCPEMatchStringList
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
    
    # Track which version checks belong to which row
    row_version_checks = {}
    for index, row in rawDataSet.iterrows():
        if 'platformEntryMetadata' in row and 'cpeVersionChecks' in row['platformEntryMetadata']:
            checks = row['platformEntryMetadata']['cpeVersionChecks']
            if checks:  # Only add non-empty lists
                row_version_checks[index] = checks
    
    # Track which rows are interested in which query strings
    row_query_mapping = {}
    for index, row in rawDataSet.iterrows():
        if 'platformEntryMetadata' in row and 'cpeBaseStrings' in row['platformEntryMetadata']:
            cpe_strings = row['platformEntryMetadata']['cpeBaseStrings']
            if isinstance(cpe_strings, list):
                for cpe_string in cpe_strings:
                    if cpe_string not in row_query_mapping:
                        row_query_mapping[cpe_string] = []
                    row_query_mapping[cpe_string].append(index)
    
    for query_string in tqdm(query_list):
        # Skip empty queries
        if not query_string:
            continue
        
        try:
            json_response = gatherData.gatherNVDCPEData(apiKey, "cpeMatchString", query_string)
            
            # Check for invalid_cpe status from our updated gatherNVDCPEData function
            if json_response and json_response.get("status") == "invalid_cpe":
                print(f"[WARNING] Skipping invalid CPE match string: {query_string}")
                stats = {
                    "matches_found": 0,
                    "status": "invalid_cpe",
                    "error_message": json_response.get("error", "Invalid cpeMatchstring parameter")
                }
                bulk_results.append({query_string: stats})
                continue
                
            if 'totalResults' in json_response:
                # General statistics common to all rows
                base_stats = {
                    "matches_found": json_response['totalResults'],
                    "is_truncated": json_response["resultsPerPage"] < json_response["totalResults"],
                }
                
                if "products" in json_response:
                    # Find which rows care about this query string
                    relevant_row_indices = row_query_mapping.get(query_string, [])
                    row_specific_results = {}
                    
                    # For each relevant row, perform row-specific version matching
                    for row_index in relevant_row_indices:
                        # Get this row's version checks
                        row_checks = row_version_checks.get(row_index, [])
                        
                        # Process with just this row's checks
                        row_stats = analyzeBaseStrings(row_checks, json_response)
                        row_specific_results[row_index] = row_stats
                    
                    # Store both common stats and row-specific results
                    stats = {
                        **base_stats,
                        "row_specific_results": row_specific_results
                    }
                else:
                    stats = base_stats
            else:
                stats = {
                    "matches_found": 0,
                    "status": "error",
                    "error_message": str(json_response)
                }
        except Exception as e:
            error_message = str(e)
            print(f"[WARNING] Error querying NVD API for '{query_string}': {error_message}")
            
            # Don't retry for invalid cpeMatchstring errors
            if "Invalid cpeMatchstring parameter" in error_message:
                print(f"[WARNING] Invalid CPE match string detected, skipping: {query_string}")
                stats = {
                    "matches_found": 0,
                    "status": "invalid_cpe",
                    "error_message": error_message
                }
            else:
                # For other errors, report but continue
                stats = {
                    "matches_found": 0,
                    "status": "error",
                    "error_message": error_message
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
        cpe_attributes = breakoutCPEAttributes(cpe_name)  # Updated function name
        cpe_version_value = cpe_attributes['version']
        base_cpe_name = constructSearchString(cpe_attributes, "base")

        # Populate versions_found based on comparisons to query results
        versions_found = base_strings[base_cpe_name]['versionsFoundContent']
        unique_versions = set()
        
        for check in cpeVersionChecks:
            # Each check is already a dictionary, no need for inner loop
            if 'version' in check and check['version'] == cpe_version_value:
                version_pair = ('version', check['version'])
                if version_pair not in unique_versions:
                    versions_found.append({'version': cpe_name})
                    unique_versions.add(version_pair)
            if 'lessThan' in check and check['lessThan'] == cpe_version_value:
                less_than_pair = ('lessThan', check['lessThan'])
                if less_than_pair not in unique_versions:
                    versions_found.append({'lessThan': cpe_name})
                    unique_versions.add(less_than_pair)
            if 'lessThanOrEqual' in check and check['lessThanOrEqual'] == cpe_version_value:
                less_than_or_equal_pair = ('lessThanOrEqual', check['lessThanOrEqual'])
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


def processCVEData(dataframe, cveRecordData, nvdSourceData=None):
    # Initialize source tracking
    used_source_ids = set()
    added_sources = set()
    # Track whether we've added NIST already
    nist_added = False
    
    # Still add nvd@nist.gov to used_source_ids for matching
    used_source_ids.add('nvd@nist.gov')
    
    # Initialize global CVE metadata
    global_cve_metadata = {
        'cveId': cveRecordData.get('cveMetadata', {}).get('cveId', ''),
        'descriptionData': [],
        'referencesData': [], 
        'sourceData': []
    }
    
    # Extract source IDs from containers as usual...
    
    # Now process the NVD source data with complete used_source_ids
    if nvdSourceData is not None:
        # Track which sources we've already added to avoid duplicates
        added_sources = set()
        
        for _, source_row in nvdSourceData.iterrows():
            source_id = source_row.get('orgId', '')
            
            # Skip if we've already added this source
            if source_id in added_sources:
                continue
                
            # Special handling for NIST/NVD sources
            if (source_id == '' or source_id == 'nvd@nist.gov' or 
                ('sourceIdentifiers' in source_row and 
                 isinstance(source_row['sourceIdentifiers'], list) and 
                 'nvd@nist.gov' in source_row['sourceIdentifiers'])):
                
                if nist_added:
                    # Skip duplicate NIST entries
                    continue
                    
                # Add standardized NIST entry
                source_info = {
                    "sourceId": "nvd@nist.gov",
                    "name": "NIST",
                    "contactEmail": "nvd@nist.gov",
                    "sourceIdentifiers": ["nvd@nist.gov"]
                }
                global_cve_metadata['sourceData'].append(source_info)
                
                # Mark as added to prevent duplicates
                added_sources.add('')
                added_sources.add('nvd@nist.gov')
                nist_added = True
                continue
            
            # Regular source matching logic for non-NIST sources...
            # Check if this source ID is in our used sources (direct match by orgId)
            source_matched = False
            if source_id in used_source_ids:
                source_matched = True
            
            # Or check if any of our used IDs are in this source's identifiers
            elif 'sourceIdentifiers' in source_row and isinstance(source_row['sourceIdentifiers'], list):
                for used_id in used_source_ids:
                    if used_id in source_row['sourceIdentifiers']:
                        source_matched = True
                        break
            
            # If we matched this source, add it and mark as added
            if source_matched:
                # Create source info object
                source_info = {
                    "sourceId": source_id,
                    "name": source_row.get('name', 'Unknown'),
                    "contactEmail": source_row.get('contactEmail', ''),
                    "sourceIdentifiers": source_row.get('sourceIdentifiers', [])
                }
                
                # Add to the array
                global_cve_metadata['sourceData'].append(source_info)
                # Mark both the source ID and all its identifiers as added
                added_sources.add(source_id)
                for uuid in source_row.get('sourceIdentifiers', []):
                    added_sources.add(uuid)
    
    result_df = dataframe.copy()
    
    # Track products for duplicate identification
    product_key_to_row_indices = {}
    
    row_index = len(result_df)
    
    # Create global CVE metadata to store information that applies to the entire CVE
    global_cve_metadata = {
        'cveId': cveRecordData.get('cveMetadata', {}).get('cveId', ''),
        'descriptionData': [],
        'referencesData': [], 
        'sourceData': []
    }
    
    # Set to track all source IDs used in this CVE
    used_source_ids = set()
    
    if 'containers' in cveRecordData:
        # First, collect all descriptions and references from both CNA and ADP
        for container_type in ['cna', 'adp']:
            if container_type == 'cna' and 'cna' in cveRecordData['containers']:
                containers = [cveRecordData['containers']['cna']]
            elif container_type == 'adp' and 'adp' in cveRecordData.get('containers', {}):
                containers = cveRecordData['containers']['adp']
            else:
                continue
                
            for container in containers:
                source_id = container.get('providerMetadata', {}).get('orgId', 'Unknown')
                source_role = container_type.upper()
                
                # Add this source ID to our set of used sources
                used_source_ids.add(source_id)
                
                # Extract descriptions for Provenance Assistance
                if 'descriptions' in container:
                    description_data = {
                        'sourceId': source_id,
                        'sourceRole': source_role,
                        'descriptions': [
                            {'lang': desc.get('lang', ''), 'value': desc.get('value', '')}
                            for desc in container['descriptions']
                            if 'lang' in desc and 'value' in desc
                        ]
                    }
                    
                    # Add to global CVE metadata
                    global_cve_metadata['descriptionData'].append(description_data)
                
                # Extract references data
                if 'references' in container:
                    references_data = {
                        'sourceId': source_id,
                        'sourceRole': source_role,
                        'references': [
                            {
                                'url': ref.get('url', ''),
                                'name': ref.get('name', ''),
                                'tags': ref.get('tags', [])
                            }
                            for ref in container.get('references', [])
                        ]
                    }
                    
                    # Add to global CVE metadata
                    global_cve_metadata['referencesData'].append(references_data)

        # Add NVD as a used source if we're processing NVD data
        used_source_ids.add('nvd@nist.gov')
                
        # Add relevant source information from nvdSourceData to global metadata
        if nvdSourceData is not None:
            # Track which sources we've already added to avoid duplicates
            added_sources = set()
            
            for _, source_row in nvdSourceData.iterrows():
                source_id = source_row.get('orgId', '')
                
                # Skip if we've already added this source
                if source_id in added_sources:
                    continue
                    
                # Check if this source ID is in our used sources (direct match by orgId)
                source_matched = False
                if source_id in used_source_ids:
                    source_matched = True
                
                # Or check if any of our used IDs are in this source's identifiers
                elif 'sourceIdentifiers' in source_row and isinstance(source_row['sourceIdentifiers'], list):
                    for used_id in used_source_ids:
                        if used_id in source_row['sourceIdentifiers']:
                            source_matched = True
                            break
                
                # If we matched this source, add it and mark as added
                if source_matched:
                    # Create source info object
                    source_info = {
                        "sourceId": source_id,
                        "name": source_row.get('name', 'Unknown'),
                        "contactEmail": source_row.get('contactEmail', ''),
                        "sourceIdentifiers": source_row.get('sourceIdentifiers', [])
                    }
                    
                    # Add to the array
                    global_cve_metadata['sourceData'].append(source_info)
                    added_sources.add(source_id)
                    
                    # Also add entries with explicit UUIDs that the frontend might check for
                    for uuid in source_row.get('sourceIdentifiers', []):
                        uuid_source_info = source_info.copy()
                        uuid_source_info["sourceId"] = uuid
                        global_cve_metadata['sourceData'].append(uuid_source_info)
        
        # Now process affected entries and add rows to dataframe
        for container_type in ['cna', 'adp']:
            if container_type == 'cna' and 'cna' in cveRecordData['containers']:
                containers = [cveRecordData['containers']['cna']]
            elif container_type == 'adp' and 'adp' in cveRecordData.get('containers', {}):
                containers = cveRecordData['containers']['adp']
            else:
                continue
                
            for container in containers:
                source_id = container.get('providerMetadata', {}).get('orgId', 'Unknown')
                source_role = container_type.upper()
                
                # Handle affected entries
                if 'affected' in container:
                    for affected in container['affected']:
                        # Create a unique key for duplicate detection
                        product_key = create_product_key(affected, source_id)
                        
                        # Get versions - this is where we need to ensure proper structure
                        versions_checks = []
                        if affected.get('versions') and isinstance(affected.get('versions'), list):
                            # Direct assignment - each version check is already a dictionary
                            versions_checks = affected.get('versions', [])
                        
                        # Check if CPE array exists
                        has_cpe_array = 'cpes' in affected
                        
                        # Create the platformEntryMetadata dictionary with all consolidated fields
                        platform_entry_metadata = {
                            'dataSource': 'CVEAPI',
                            'platformFormatType': determine_platform_format_type(affected),
                            'hasCPEArray': has_cpe_array,
                            'cpeBaseStrings': [],
                            'cpeVersionChecks': versions_checks,
                            'duplicateRowIndices': []
                        }
                        
                        # Create a new row in the dataframe
                        new_row = {
                            'sourceID': source_id,
                            'sourceRole': source_role,
                            'rawPlatformData': affected,
                            'platformEntryMetadata': platform_entry_metadata,
                            'rawCPEsQueryData': [],
                            'sortedCPEsQueryData': [],
                            'trimmedCPEsQueryData': []
                        }
                        
                        # Track duplicate relationships
                        if product_key in product_key_to_row_indices:
                            # Get existing row indices with this key
                            duplicate_indices = product_key_to_row_indices[product_key]
                            
                            # Add reference to existing duplicates
                            new_row['platformEntryMetadata']['duplicateRowIndices'] = duplicate_indices.copy()
                            
                            # Update existing rows to point to this new row
                            for idx in duplicate_indices:
                                result_df.at[idx, 'platformEntryMetadata']['duplicateRowIndices'].append(row_index)
                            
                            # Add this row to the tracking
                            product_key_to_row_indices[product_key].append(row_index)
                        else:
                            # First occurrence of this product key
                            product_key_to_row_indices[product_key] = [row_index]
                        
                        # Append to dataframe
                        result_df = pd.concat([result_df, pd.DataFrame([new_row])], ignore_index=True)
                        row_index += 1

    # After processing nvdSourceData, add any missing sources from used_source_ids
    for source_id in used_source_ids:
        if source_id not in added_sources:
            # Skip NIST fallbacks if we already added NIST
            if (source_id == '' or source_id == 'nvd@nist.gov') and nist_added:
                continue
                
            # Special case for NVD/NIST that wasn't found in source data
            if source_id == '' or source_id == 'nvd@nist.gov':
                if not nist_added:
                    source_info = {
                        "sourceId": "nvd@nist.gov",
                        "name": "NIST",
                        "contactEmail": "nvd@nist.gov", 
                        "sourceIdentifiers": ["nvd@nist.gov"]
                    }
                    global_cve_metadata['sourceData'].append(source_info)
                    added_sources.add('')
                    added_sources.add('nvd@nist.gov')
                    nist_added = True
                continue
            
            # Regular fallback processing for other sources...
            # First, check if we can find this source in nvdSourceData
            # This ensures we don't create duplicates with different info
            source_name = None
            source_email = None
            
            # Special case for NVD/NIST
            if source_id == 'nvd@nist.gov':
                source_name = "NIST"
                source_email = "nvd@nist.gov"
            else:
                # Check in NVD source data first if available
                if nvdSourceData is not None:
                    for _, source_row in nvdSourceData.iterrows():
                        # Check if this source matches by ID or identifiers
                        if source_row.get('orgId') == source_id or (
                            'sourceIdentifiers' in source_row and
                            isinstance(source_row['sourceIdentifiers'], list) and
                            source_id in source_row['sourceIdentifiers']
                        ):
                            source_name = source_row.get('name')
                            source_email = source_row.get('contactEmail')
                            break
                
            
            # If we still don't have a name, use the ID as fallback
            if not source_name:
                source_name = source_id
            
            # Create source info object
            source_info = {
                "sourceId": source_id,
                "name": source_name,
                "contactEmail": source_email or "",
                "sourceIdentifiers": [source_id]
            }
            
            # Add to the array
            global_cve_metadata['sourceData'].append(source_info)
            added_sources.add(source_id)

    return result_df, global_cve_metadata

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
                        
                        # Create platformEntryMetadata
                        platform_entry_metadata = {
                            'dataSource': 'NVDAPI',
                            'platformFormatType': 'nvdConfiguration',
                            'hasCPEArray': False,
                            'cpeBaseStrings': [],
                            'cpeVersionChecks': [],
                            'duplicateRowIndices': []
                        }
                        
                        # Create a new row with the complete configuration
                        new_row = {
                            'sourceID': source_id,
                            'sourceRole': source_role,
                            'rawPlatformData': config,
                            'platformEntryMetadata': platform_entry_metadata,
                            'rawCPEsQueryData': [],
                            'sortedCPEsQueryData': [],
                            'trimmedCPEsQueryData': []
                        }
                        
                        # Append to dataframe
                        result_df = pd.concat([result_df, pd.DataFrame([new_row])], ignore_index=True)
    except Exception as e:
        print(f"[ERROR] Error processing NVD record data: {e}")
    
    return result_df

def determine_platform_format_type(affected):
    """Determine if versions are single values, ranges, a mixture of both, or not provided"""
    versions = affected.get('versions', [])
    
    # Check if versions array is empty or not provided
    if not versions:
        return 'cveAffectsNoVersions'
    
    # Check for range indicators and exact versions
    has_range = False
    has_exact = False
    
    for version in versions:
        # Check for range indicators
        if any(key in version for key in ['lessThan', 'lessThanOrEqual', 'versionStartIncluding', 'versionEndIncluding']):
            has_range = True
        # Check for exact version
        elif 'version' in version:
            has_exact = True
        
        # If we've found both types, we can return early
        if has_range and has_exact:
            return 'cveAffectsVersionMix'
    
    # Determine the type based on what we found
    if has_range:
        return 'cveAffectsVersionRange'
    elif has_exact:
        return 'cveAffectsVersionSingle'
    else:
        return 'cveAffectsNoVersions'  # Fallback for unexpected version format

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
# Enhanced version of curateCPEAttributes to remove version information from product attributes

def curateCPEAttributes(case, attributeString1, attributeString2):
    match case:
        case 'vendor':
            # Store original value before curation
            originalAttribute = attributeString1
            
            # Vendor Aliases
            if ("apache_software_foundation") in attributeString1:
                attributeString1 = attributeString1.replace("apache_software_foundation", "apache")
                
            # Remove "inc" and preceding spaces from the end of vendor names
            attributeString1 = re.sub(r'[\s_]+inc$', '', attributeString1)
            
            # Also handle variations like "inc." with a period
            attributeString1 = re.sub(r'[\s_]+inc\.$', '', attributeString1)
            attributeString1 = re.sub(r'[\s_]+inc\\\.$', '', attributeString1)  # Handle escaped period
            
            # Clean up trailing underscores that might be left
            attributeString1 = attributeString1.rstrip('_')

            return (attributeString1)

        case 'product':
            # Store original value before curation
            originalAttribute = attributeString1
            
            # General Trimming
            if ("apache_") in attributeString1:
                attributeString1 = attributeString1.replace("apache_", "")

            if ("_software") in attributeString1:
                attributeString1 = attributeString1.replace("_software", "")

            if ("_version") in attributeString1:
                attributeString1 = attributeString1.replace("_version", "")

            if ("_plugin") in attributeString1:
                attributeString1 = attributeString1.replace("_plugin", "")
                
            # Remove version numbers
            # Pattern: product 1.2.3 or product 1.2 or product 1
            attributeString1 = re.sub(r'[\s_][\d]+\.[\d]+\.[\d]+$', '', attributeString1)
            attributeString1 = re.sub(r'[\s_][\d]+\.[\d]+$', '', attributeString1)
            attributeString1 = re.sub(r'[\s_][\d]+$', '', attributeString1)
            
            # Remove "version X.Y" patterns
            attributeString1 = re.sub(r'[\s_]version[\s_][\d]+\.[\d]+(?:\s\(.+\))?', '', attributeString1)
            attributeString1 = re.sub(r'[\s_]version[\s_][\d]+(?:\s\(.+\))?', '', attributeString1)
            
            # Remove "vX.Y" patterns
            attributeString1 = re.sub(r'[\s_]v[\d]+\.[\d]+(?:\s\(.+\))?', '', attributeString1)
            attributeString1 = re.sub(r'[\s_]v[\d]+(?:\s\(.+\))?', '', attributeString1)
            
            # Special case for AND/OR in version strings
            attributeString1 = re.sub(r'[\s_][\d]+\.[\d]+[\s_](?:AND|OR)[\s_][\d]+\.[\d]+', '', attributeString1)
            
            # Clean up trailing whitespace converted to underscores
            attributeString1 = attributeString1.rstrip('_')
            
            return (attributeString1)
        
        case 'vendorProduct':
            # Store original value before curation
            originalProduct = attributeString2
            
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
                
            # Remove version numbers
            # Pattern: product 1.2.3 or product 1.2 or product 1
            attributeString2 = re.sub(r'[\s_][\d]+\.[\d]+\.[\d]+$', '', attributeString2)
            attributeString2 = re.sub(r'[\s_][\d]+\.[\d]+$', '', attributeString2)
            attributeString2 = re.sub(r'[\s_][\d]+$', '', attributeString2)
            
            # Remove "version X.Y" patterns
            attributeString2 = re.sub(r'[\s_]version[\s_][\d]+\.[\d]+(?:\s\(.+\))?', '', attributeString2)
            attributeString2 = re.sub(r'[\s_]version[\s_][\d]+(?:\s\(.+\))?', '', attributeString2)
            
            # Remove "vX.Y" patterns
            attributeString2 = re.sub(r'[\s_]v[\d]+\.[\d]+(?:\s\(.+\))?', '', attributeString2)
            attributeString2 = re.sub(r'[\s_]v[\d]+(?:\s\(.+\))?', '', attributeString2)
            
            # Special case for AND/OR in version strings
            attributeString2 = re.sub(r'[\s_][\d]+\.[\d]+[\s_](?:AND|OR)[\s_][\d]+\.[\d]+', '', attributeString2)
            
            # Clean up trailing whitespace converted to underscores
            attributeString2 = attributeString2.rstrip('_')
            
            return attributeString2

        case 'platform':
            # New case to handle platform data curation
            originalPlatform = attributeString1
            
            # Map common platform designations to CPE targetHW values
            platform_mappings = {
                'x86': 'x86',
                'x86_64': 'x64',
                'x64': 'x64',
                'arm': 'arm',
                'arm64': 'arm64',
                '32-bit': 'x86',
                '64-bit': 'x64',
            }
            
            # Try to match the platform to known values (case-insensitive)
            platform_lower = attributeString1.lower() if isinstance(attributeString1, str) else ""
            for key, value in platform_mappings.items():
                if key in platform_lower:
                    # Return the mapped value and True to indicate successful mapping
                    return (value, True)
                    
            # If no match is found, return original and False flag
            return (originalPlatform, False)
            
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
# Identify if CPE 2.3/2.2 provided and breakout into attribute based dictionary
def breakoutCPEAttributes(cpeMatchString):
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
                print("[FAULT]  CVE Services CVE ID check failed! CVE-ID from Services returned as ", checkDataSet["cveMetadata"]["cveId"])
                raise ValueError(f"CVE ID mismatch: expected {checkValue}, got {checkDataSet['cveMetadata']['cveId']}")
        
        case "cveStatusCheck":
            # Confirm the CVE ID is not REJECTED
            if checkDataSet["cveMetadata"]["state"] == checkValue:
                print("[FAULT]  CVE record is in the " + checkDataSet["cveMetadata"]["state"] + " state!")
                raise ValueError(f"CVE {checkDataSet['cveMetadata']['cveId']} is in {checkDataSet['cveMetadata']['state']} state")
            else:
                checkValue == True
                
        case "cveIdFormat":
            # Confirm that the CVE ID entered is a valid CVE ID
            pattern = re.compile("^CVE-[0-9]{4}-[0-9]{4,19}$")
            if re.fullmatch(pattern, checkValue):
                checkValue == True
            else:
                print("[FAULT]  CVE ID Format check failed! \"", checkValue, "\"")
                raise ValueError(f"Invalid CVE ID format: {checkValue}")
        case _:
            print("[FAULT]  Unexpected Case for Integrity Check!")
            raise ValueError(f"Unknown integrity check type: {checkType}")

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