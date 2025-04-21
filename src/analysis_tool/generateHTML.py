# Import Python dependencies
import pandas as pd
import json
import html
from build_info import VERSION, TOOLNAME
import os
import datetime

# Import Analysis Tool 
import processData

# Add this class definition near the top of the file, after the imports
class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles sets and other non-standard JSON types"""
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        if pd.isna(obj):
            return None
        try:
            return json.JSONEncoder.default(self, obj)
        except TypeError:
            # If we can't encode it normally, convert to string
            return str(obj)

def convertRowDataToHTML(row, nvdSourceData: pd.DataFrame, tableIndex=0) -> str:
    # Access platformEntryMetadata for consolidated fields
    platform_metadata = row.get('platformEntryMetadata', {})
    platform_format_type = platform_metadata.get('platformFormatType', '')
    raw_platform_data = row.get('rawPlatformData', {})
    
    # Convert platform format type to human-readable format
    readable_format_type = platform_format_type
    if platform_format_type == 'cveAffectsVersionRange':
        readable_format_type = "CVE Affects Version Range(s)"
    elif platform_format_type == 'cveAffectsVersionSingle':
        readable_format_type = "CVE Affects Version(s) Exact" 
    elif platform_format_type == 'cveAffectsVersionMix':
        readable_format_type = "CVE Affects Version(s) Exact and Range(s)"
    elif platform_format_type == 'cveAffectsNoVersions':
        readable_format_type = "CVE Affects Product (No Versions)"
    elif platform_format_type == 'nvdConfiguration':
        readable_format_type = "NVD Configuration"

    # Add ID to the table based on the index
    html = f"<table id=\"rowDataTable_{tableIndex}\" class=\"table table-hover\">"
    
    # Define the keys and their labels, ensuring rawPlatformData is last
    keys_and_labels = [
        ('platformEntryMetadata.dataSource', 'Data Source'),
        ('sourceID', 'Source ID'),
        ('sourceRole', 'Source Role')
        # rawPlatformData is handled separately below
    ]
    
    # Process the standard metadata keys first
    for key, label in keys_and_labels:
        if '.' in key:  # Handle nested properties
            parent, child = key.split('.')
            if parent in row and child in row[parent]:
                value = row[parent][child]
                html += f"""
                <tr>
                    <td>{label}</td>
                    <td>{value}</td>
                </tr>
                """
        elif key in row:  # Handle direct properties
            value = row[key]
            if key == 'sourceID':
                source_info = processData.getNVDSourceDataByUUID(value, nvdSourceData)
                if source_info:
                    name = source_info.get('name', 'N/A')
                    contact_email = source_info.get('contactEmail', 'N/A')
                    source_identifiers = source_info.get('sourceIdentifiers', [])
                    tooltip_content = f"Contact Email: {contact_email} &#013;Source Identifiers: {', '.join(source_identifiers)}"
                    value = f"<span title=\"{tooltip_content}\">{name}</span>"
                html += f"""
                <tr>
                    <td>{label}</td>
                    <td>{value}</td>
                </tr>
                """
            else:
                html += f"""
                <tr>
                    <td>{label}</td>
                    <td>{value}</td>
                </tr>
                """

    # Add Platform Entry Notifications with badges immediately after sourceRole
    html += "<tr><td>Platform Entry Notifications</td><td>"

    # Group badges by priority level
    danger_badges = []
    warning_badges = []
    sourceDataConcern_badges = []
    info_badges = []
    standard_badges = []

    # 1. Platform Format Type badge with version checks tooltip
    version_checks = platform_metadata.get('cpeVersionChecks', [])
    version_tooltip = "No versions detected!"
    if version_checks:
        # Format each version check on a new line for better readability
        version_lines = []
        for check in version_checks:
            check_str = ", ".join([f"{k}: {v}" for k, v in check.items()])
            version_lines.append(check_str)
        
        version_tooltip = "&#013;".join(version_lines)

    # Select badge color and priority based on platform format type
    if platform_format_type == 'cveAffectsNoVersions':
        danger_badges.append(f'<span class="badge bg-danger" title="{version_tooltip}">{readable_format_type}</span> ')
    else:
        info_badges.append(f'<span class="badge bg-info" title="{version_tooltip}">{readable_format_type}</span> ')

    # 2. Duplicate Entries badge (warning) if duplicateRowIndices exist
    duplicate_indices = platform_metadata.get('duplicateRowIndices', [])
    if duplicate_indices:
        duplicate_tooltip = f"This entry has duplicate data at row(s): {', '.join(map(str, duplicate_indices))}"
        warning_badges.append(f'<span class="badge bg-warning" title="{duplicate_tooltip}">Duplicate Entries Detected</span> ')

    # 3. Git version type badge - checking version type
    if 'versions' in raw_platform_data and isinstance(raw_platform_data['versions'], list):
        has_git_version = any(
            v and isinstance(v, dict) and v.get('versionType') == "git" 
            for v in raw_platform_data.get('versions', [])
        )
        if has_git_version:
            git_tooltip = "git versionType not advised for CPE Ranges"
            
            # Determine badge color based on platform format type
            git_badge_color = "bg-warning"  # Default: warning level
            
            # Elevate to danger level when used with version ranges
            if platform_format_type in ['cveAffectsVersionRange', 'cveAffectsVersionMix']:
                git_badge_color = "bg-danger"  # Danger level for ranges
                git_tooltip = "CRITICAL: CPE Range Matching Logic does not currently support git versionTypes"
                
            warning_badges.append(f'<span class="badge {git_badge_color}" title="{git_tooltip}">git versionType</span> ')

    # 4. Special Version Structure badges - more detailed detection of special cases
    if 'versions' in raw_platform_data and isinstance(raw_platform_data['versions'], list):
        versions = raw_platform_data['versions']
        
        # 4.1 Check for wildcard patterns in version ranges
        has_wildcards = False
        for v in versions:
            if isinstance(v, dict) and ('lessThanOrEqual' in v or 'lessThan' in v):
                constraint_value = v.get('lessThanOrEqual', '') or v.get('lessThan', '')
                if '*' in str(constraint_value):
                    has_wildcards = True
                    version_tooltip = 'Versions array contains wildcard patterns requiring special handling'
                    warning_badges.append(f'<span class="badge bg-warning" title="{version_tooltip}">Wildcard Patterns</span> ')
                    break
        
        # 4.2 Check for version with changes
        has_changes = False
        for v in versions:
            if v and 'changes' in v and v['changes']:
                has_changes = True
                changes_tooltip = 'Versions array contains change history information requiring special handling'
                warning_badges.append(f'<span class="badge bg-warning" title="{changes_tooltip}">Has Version Changes</span> ')
                break

    # 5. CPE Array badge - only show count in tooltip if there are actual CPEs
    cpes_array = []
    has_cpe_array = platform_metadata.get('hasCPEArray', False)
    if has_cpe_array and 'cpes' in raw_platform_data and isinstance(raw_platform_data['cpes'], list):
        cpes_array = [cpe for cpe in raw_platform_data['cpes'] if cpe and isinstance(cpe, str) and cpe.startswith('cpe:')]
        if cpes_array:  # Only show badge if there are actual CPEs
            cpe_count = len(cpes_array)
            cpe_tooltip = f"Versions array contains {cpe_count} CPEs from affected entry: " + ", ".join(cpes_array)
            info_badges.append(f'<span class="badge bg-info" title="{cpe_tooltip}">CVE Affected CPES Data: {cpe_count}</span> ') # We have no way of knowing if this is supposed to be Match Criteria or CPE Names, safer to treat as Match Strings.

    # 6. CPE Base Strings badge - only show if strings were generated
    cpe_base_strings = platform_metadata.get('cpeBaseStrings', [])
    if cpe_base_strings:
        # Sort the strings for the tooltip
        sorted_cpe_base_strings = sort_cpe_strings_for_tooltip(cpe_base_strings)
        base_strings_tooltip = "&#013;".join(sorted_cpe_base_strings)
        standard_badges.append(f'<span class="badge bg-secondary" title="{base_strings_tooltip}">CPE Base String Searches</span> ')

    # 7. Add Platform Data Concern badge if needed - UPDATED TO USE CUSTOM STYLE
    if platform_metadata.get('platformDataConcern', False):
        platform_tooltip = 'Platforms array data was not able to be mapped to any known target hardware values'
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{platform_tooltip}">Platforms Data Concern</span> ')

    # 8. Add Versions Data Concern badge for improper version formatting
    if 'versions' in raw_platform_data and isinstance(raw_platform_data['versions'], list):
        versions = raw_platform_data['versions']
        version_concerns = []
        
        # Extended list of comparators to check for
        comparators = ['<', '>', '=', '<=', '=<', '=>', '>=', '!=']
        
        # Add text-based version comparators
        text_comparators = [
            # Range indicators
            'through', 'thru', 'to', 'between', 'and',
            
            # Upper bound indicators
            'before', 'prior to', 'earlier than', 'up to', 'until', 
            'not after', 'older than', 'below',
            
            # Lower bound indicators
            'after', 'since', 'later than', 'newer than', 
            'starting with', 'from', 'above',
            
            # Approximation indicators
            'about', 'approximately', 'circa', 'around', 'roughly',
            
            # Inclusive/exclusive indicators
            'inclusive', 'exclusive', 'including', 'excluding',
            
            # Non-specific versions
            'all versions', 'any version', 'multiple versions',
            
            # Reference directives
            'see references', 'see advisory', 'refer to', 'check', 'as noted',
            
            # Missing/Unknown values
            'unspecified', 'unknown', 'none', 'undefined', 'various',
            
            # Descriptive statements
            'supported', 'unstable', 'development', 'beta', 'release candidate', 'nightly',
            
            # Date-based indicators that aren't version numbers
            'builds', 'release', 'pre-', 'post-',
            
            # Unclear bounds
            'earliest', 'recent', 'legacy', 'past', 'future', 'latest',
            
            # Commitish references
            'commit', 'git hash', 'branch'
        ]
        
        # Check for improper comparators in version fields
        for v in versions:
            if not isinstance(v, dict):
                continue
            
            # Check 'version' field
            if 'version' in v and isinstance(v['version'], str):
                version_value = v['version'].lower()  # Convert to lowercase for case-insensitive matching
                
                # Check for symbolic comparators
                if any(comp in version_value for comp in comparators):
                    version_concerns.append(f"Version field may contain comparator: {v['version']}")
                
                # Check for text comparators
                elif any(text_comp in version_value for text_comp in text_comparators):
                    version_concerns.append(f"Version field may contain inappropriate text: {v['version']}")
            
            # Check 'lessThan' field
            if 'lessThan' in v and isinstance(v['lessThan'], str):
                less_than_value = v['lessThan'].lower()  # Add toLowerCase for consistency
                if any(comp in less_than_value for comp in comparators):
                    version_concerns.append(f"LessThan field contains comparator: {v['lessThan']}")
                elif any(text_comp in less_than_value for text_comp in text_comparators):
                    version_concerns.append(f"LessThan field contains text comparator: {v['lessThan']}")
            
            # Check 'lessThanOrEqual' field
            if 'lessThanOrEqual' in v and isinstance(v['lessThanOrEqual'], str):
                less_than_or_equal_value = v['lessThanOrEqual'].lower()  # Add toLowerCase for consistency
                if any(comp in less_than_or_equal_value for comp in comparators):
                    version_concerns.append(f"LessThanOrEqual field contains comparator: {v['lessThanOrEqual']}")
                elif any(text_comp in less_than_or_equal_value for text_comp in text_comparators):
                    version_concerns.append(f"LessThanOrEqual field contains text comparator: {v['lessThanOrEqual']}")
        
        # If we found any version concerns, add the badge
        if version_concerns:
            versions_tooltip = 'Versions array contains formatting issues:&#013;' + '&#013;'.join(version_concerns)
            sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{versions_tooltip}">Versions Data Concern</span> ')

    # 9. Add N/A Data Concern badges for problematic vendor/product values
    if 'vendor' in raw_platform_data and isinstance(raw_platform_data['vendor'], str) and raw_platform_data['vendor'].lower() == 'n/a':
        vendor_na_tooltip = 'Vendor field contains "n/a" which prevents proper CPE matching'
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{vendor_na_tooltip}">Vendor: N/A</span> ')

    if 'product' in raw_platform_data and isinstance(raw_platform_data['product'], str) and raw_platform_data['product'].lower() == 'n/a':
        product_na_tooltip = 'Product field contains "n/a" which prevents proper CPE matching'
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{product_na_tooltip}">Product: N/A</span> ')

    # 10. Add CPE Curation Badge for tracking when CPE strings were modified
    curation_tracking = platform_metadata.get('cpeCurationTracking', {})
    if curation_tracking:
        # Check if any curation happened in any fields
        has_vendor_curation = curation_tracking.get('vendor', [])
        has_product_curation = curation_tracking.get('product', [])
        has_platform_curation = curation_tracking.get('platform', [])  # New: check for platform curation
        
        if has_vendor_curation or has_product_curation or has_platform_curation:  # Include platform curation
            # Build a simple tooltip listing all value changes
            curation_tooltip = 'Modified values:&#013;'
            
            # List vendor modifications
            for mod in has_vendor_curation:
                curation_tooltip += f"Vendor: {mod['original']} → {mod['curated']}&#013;"
            
            # List product modifications
            for mod in has_product_curation:
                curation_tooltip += f"Product: {mod['original']} → {mod['curated']}&#013;"
                
            # List platform modifications that were successfully mapped
            for mod in has_platform_curation:
                curation_tooltip += f"Platform: {mod['original']} → {mod['curated']}&#013;"
            
            # Create a badge with the new name - no count included
            sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{curation_tooltip}">Source to CPE Attribute Curation</span> ')

    # Add badges in priority order: Danger -> Warning -> Info -> Standard
    html += ''.join(danger_badges)
    html += ''.join(warning_badges)
    html += ''.join(sourceDataConcern_badges)
    html += ''.join(info_badges)
    html += ''.join(standard_badges)

    html += "</td></tr>"

    # Now handle rawPlatformData after the notifications section
    if 'rawPlatformData' in row:
        value = row['rawPlatformData']
        if 'vendor' in value:
            html += f"""
            <tr>
                <td>Vendor Value</td>
                <td>{value['vendor']}</td>
            </tr>
            """
        if 'product' in value:
            html += f"""
            <tr>
                <td>Product Value</td>
                <td>{value['product']}</td>
            </tr>
            """
        if 'repo' in value:
            html += f"""
            <tr>
                <td>Repo</td>
                <td>{value['repo']}</td>
            </tr>
            """
        if 'collectionUrl' in value:
            html += f"""
            <tr>
                <td>Collection URL</td>
                <td>{value['collectionUrl']}</td>
            </tr>
            """
        if 'packageName' in value:
            html += f"""
            <tr>
                <td>Package Name</td>
                <td>{value['packageName']}</td>
            </tr>
            """
        if 'platforms' in value:
            html += f"""
            <tr>
                <td>Platforms</td>
                <td>{value['platforms']}</td>
            </tr>
            """
        if 'modules' in value:
            html += f"""
            <tr>
                <td>Modules</td>
                <td>{value['modules']}</td>
            </tr>
            """
        if 'programFiles' in value:
            html += f"""
            <tr>
                <td>Program Files</td>
                <td>{value['programFiles']}</td>
            </tr>
            """
        if 'programRoutines' in value:
            html += f"""
            <tr>
                <td>Program Routines</td>
                <td>{value['programRoutines']}</td>
            </tr>
            """
        import json
        json_value = json.dumps(value, cls=CustomJSONEncoder)
        
        html += f"""
        <tr>
            <td>Raw Platform Data</td>
            <td><details><summary>Review rawPlatformData</summary>
            <code id="rawPlatformData_{tableIndex}" class="rawPlatformData">{json_value}</code></details></td>
        </tr>
        """
    
    html += "</table>"
        
    return html.replace('\n', '')

def convertCPEsQueryDataToHTML(sortedCPEsQueryData: dict, tableIndex=0) -> str:
    
    # Remove JSON column from table
    html = f"""
    <table id="matchesTable_{tableIndex}" class="table table-hover matchesTable">
    <thead>
      <tr>
        <th style="width: 50%">CPE Base String</th>
        <th style="width: 50%">Match Details</th>
      </tr>
    </thead>
    <tbody>
    """
    
    for base_key, base_value in sortedCPEsQueryData.items():
        total_match_count = (base_value.get('depFalseCount', 0) + base_value.get('depTrueCount', 0))
        dep_true_count = base_value.get('depTrueCount', 0)
        dep_false_count = base_value.get('depFalseCount', 0)
        versions_found = base_value.get('versionsFound', 0)
        
        # Calculate search_count correctly by checking for cveAffectedCPEsArray
        search_count = base_value.get('searchCount', 0)
        has_cpes_array_source = 'searchSourcecveAffectedCPEsArray' in base_value
        
        # If the CPEs array source isn't already counted in searchCount, add it
        if has_cpes_array_source and not any(k.startswith('searchSource') and 'cveAffectedCPEsArray' in k for k in base_value.keys() if k != 'searchSourcecveAffectedCPEsArray'):
            search_count += 1
            
        versions_found_content = base_value.get('versionsFoundContent', [])
        
        # Create Version Matches Identified tooltip content from versionsFoundContent
        versions_found_tooltip_content = "&#10;".join(
            "&#10;".join(f"{k}: {v}" for k, v in version.items())
            for version in versions_found_content
        )
        
        # Create Relevant Match String Searches tooltip content
        search_keys = []
        for key in base_value.keys():
            if key.startswith('searchSource'):
                search_keys.append((key, base_value[key]))

        # Sort the search keys based on a priority order
        def sort_search_keys(item):
            key, _ = item
            if 'cveAffectedCPEsArray' in key:
                return 0  # Highest priority
            elif 'partvendorproduct' in key:
                return 1
            elif 'vendorproduct' in key:
                return 2
            elif 'product' in key:
                return 3
            elif 'vendor' in key:
                return 4
            else:
                return 5

        # Sort the keys
        sorted_search_keys = sorted(search_keys, key=sort_search_keys)

        # Create the tooltip content
        search_keys_tooltip_content = ""
        for key, value in sorted_search_keys:
            search_keys_tooltip_content += f"{key}:  {value}&#10;"
        
        # Sanitize base_key for use as ID
        base_key_id = base_key.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_")
        
        html += f"""
        <tr id="row_{base_key_id}" class="cpe-row" data-cpe-base="{base_key}">
            <td class="text-break">{base_key}</td>
            <td>
                <div class="d-flex flex-wrap gap-1 align-items-center">
                    <span class="badge rounded-pill bg-secondary" title="{search_keys_tooltip_content}">Relevant Match String Searches: {search_count}</span>
                    <span class="badge rounded-pill bg-success" title="{versions_found_tooltip_content}">Version Matches Identified: {versions_found}</span>
                    <div class="badge bg-primary d-inline-flex align-items-center">
                        Total CPE Names: {total_match_count}
                        <span class="badge bg-info ms-1">Final: {dep_false_count}</span>
                        <span class="badge bg-warning ms-1">Deprecated: {dep_true_count}</span>
                    </div>
                </div>
            </td>
        </tr>
        """

    html += """
    </tbody>
    </table>
    """

    return html.replace('\n', '')

# Add the new file to the list of JS files to include
def getCPEJsonScript() -> str:
    
    # Get the current script's directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define the files with paths relative to the current script
    js_files = [
        os.path.join(current_dir, "static", "js", "utils.js"),
        os.path.join(current_dir, "static", "js", "cpe_json_handler.js"),
        os.path.join(current_dir, "static", "js", "ui_controller.js"),
        os.path.join(current_dir, "static", "js", "selection_manager.js"),
        os.path.join(current_dir, "static", "js", "timestamp_handler.js"),
        os.path.join(current_dir, "static", "js", "provenance_assistance.js")
    ]
    
    # Read JavaScript files
    js_content = ""
    
    # Read each file and add its content to the script tag
    for js_file in js_files:
        try:
            with open(js_file, 'r') as f:
                js_content += f.read() + "\n\n"
        except Exception as e:
            print(f"Error reading JavaScript file {js_file}: {e}")
            # Add placeholder comment if file can't be read
            js_content += f"// Error loading {js_file}\n\n"
    
    # Return the JavaScript wrapped in a script tag
    return f"<script>\n{js_content}\n</script>"

def update_cpeQueryHTML_column(dataframe, nvdSourceData):
    """Updates the dataframe to include a column with HTML for CPE query results"""
    
    # Make a copy to avoid modifying the original
    result_df = dataframe.copy()
    
    for index, row in result_df.iterrows():
        # Existing attribute code
        data_attrs = []
        
        # Add data attributes with platform info, etc.
        if ('platformData' in row):
            platform_data = row['platformData']
            try:
                # Add data ID for better reference
                data_attrs.append(f'id="platform-data-container-{index}"')
                
                # Keep existing data attributes
                platform_data_json = json.dumps(platform_data, cls=CustomJSONEncoder)
                data_attrs.append(f'data-platform-data="{html.escape(platform_data_json)}"')
                
                # Add a unique ID for the raw platform data for easier access
                data_attrs.append(f'data-raw-platform-id="raw-platform-{index}"')
            except Exception as e:
                print(f"Error serializing platform data: {e}")
        
        # Create the collapse button with a proper container ID (no changes needed here)
        collapse_button_html = f'<div class="mb-3 d-flex gap-2" id="buttonContainer_{index}"><button id="collapseRowButton_{index}" class="btn btn-secondary" onclick="toggleRowCollapse({index})">Collapse Row (Mark Complete)</button></div>'
        
        # Populate the rowDataHTML column with the HTML content
        row_html_content = convertRowDataToHTML(row, nvdSourceData, index)
        result_df.at[index, 'rowDataHTML'] = collapse_button_html + row_html_content
        
        # Create the main HTML div with all data attributes and a unique ID
        if ('trimmedCPEsQueryData' in row):
            sortedCPEsQueryData = row['trimmedCPEsQueryData'] 
            
            # Determine if matches table is empty to decide if provenance div should be expanded
            has_matches = bool(sortedCPEsQueryData)
            
            attr_string = " ".join(data_attrs)
            html_content = f"""<div id="cpe-query-container-{index}" class="cpe-query-container" {attr_string}>"""
            
            # Add provenance assistance div ABOVE the matches table and ONLY for non-NVD rows
            if 'sourceRole' in row and row['sourceRole'] != 'NVD':
                provenance_div = create_provenance_assistance_div(index, collapsed=has_matches)
                html_content += provenance_div
            
            # Add the matches table after the provenance div
            html_content += convertCPEsQueryDataToHTML(sortedCPEsQueryData, index)
            html_content += "</div>"  # Close the container div
            result_df.at[index, 'cpeQueryHTML'] = html_content
    
    return result_df

# Modify the buildHTMLPage function to accept and include globalCVEMetadata

def buildHTMLPage(affectedHtml, targetCve, globalCVEMetadata=None, vdbIntelHtml=None,):
    
    # Generate UTC timestamp for the page creation
    utc_timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    
    # Get the current script's directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # CSS file path relative to the current script
    css_file = os.path.join(current_dir, "static", "css", "styles.css")
    
    # Read CSS file
    css_content = ""
    try:
        with open(css_file, 'r') as f:
            css_content = f.read()
    except Exception as e:
        print(f"Error reading CSS file {css_file}: {e}")
        css_content = "/* Error loading CSS file */"

    pageStartHTML = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.3.0/font/bootstrap-icons.css">
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous"></script>
        <style>
        {css_content}
        </style>
    </head>
    <body>
    """
    
    # Add the hidden div for globalCVEMetadata if provided
    globalCVEMetadataHTML = ""
    if globalCVEMetadata is not None:
        # Encode the JSON data and escape any HTML special characters
        global_metadata_json = json.dumps(globalCVEMetadata, cls=CustomJSONEncoder)
        escaped_metadata = html.escape(global_metadata_json)
        
        # Create hidden div with the data attribute
        globalCVEMetadataHTML = f"""
        <!-- Hidden div containing global CVE metadata for Provenance Assistance -->
        <div id="global-cve-metadata" style="display:none;" data-cve-metadata='{escaped_metadata}'></div>
        """
    
    pageBodyHeaderHTML = f"""
    <!-- Tool Info Header -->
    <div class="header" style="margin-left: 10px;">
        <h1>NVD Analysis Intelligence Tool <small>{TOOLNAME} version: {VERSION}</small></h1>
    </div>
    {globalCVEMetadataHTML}
    """
    
    # Rest of the function remains unchanged
    pageBodyTabsHTML = """
    <!-- Tab links -->
    <div class="tab">
        <button class="tablinks" onclick="openCity(event, 'cveListCPESuggester')">CVE List CPE Suggester</button>
        <button class="tablinks" onclick="openCity(event, 'vdbIntelDashboard')">VDB Intel Dashboard</button>
    </div>
    """
    
    # Updated cveIdIndicatorHTML without the inline JavaScript
    cveIdIndicatorHTML = f"""
    <div class="d-flex align-items-center justify-content-between" style="margin-left: 10px; margin-right: 10px;">
        <h3 style="margin-bottom: 0px;"><b>{targetCve}</b></h3>
        <span id="generationTimestamp" class="text-muted">Generated: <time datetime="{utc_timestamp}"></time></span>
    </div>
    <hr style="margin: 10px; border: 1px solid;">
    """
    
    # Updated pageBodyCPESuggesterHTML without the inline JavaScript
    pageBodyCPESuggesterHTML = f"""
    <!-- CVE List CPE Suggester -->
    <div id="cveListCPESuggester" class="tabcontent" style="display: block; border-left: 0px;">
        <h3>CVE List CPE Suggester</h3>
        {affectedHtml}
        <script>
            // Initialize the timestamp handler with the generated timestamp
            window.timestampHandler.init("{utc_timestamp}");
        </script>
    </div>
    """
    
    if (vdbIntelHtml is None):
        pageBodyVDBIntelHTML = """
        <!-- VDB Intel Dashboard -->
        <div id="vdbIntelDashboard" class="tabcontent" style="border-left: 0px;">
            <h3>VDB Intel Dashboard</h3>
            <p>Basic User Mode does not support VDB Intel Check!</p>
        </div>
        """
    else:
        pageBodyVDBIntelHTML = f"""
        <!-- VDB Intel Dashboard -->
        <div id="vdbIntelDashboard" class="tabcontent" style="border-left: 0px;">
            <h3>VDB Intel Dashboard</h3>
            {vdbIntelHtml}
        </div>
        """
        
    pageEndHTML = """
    <script>
    function openCity(evt, cityName) {
        var i, tabcontent, tablinks;
        tabcontent = document.getElementsByClassName("tabcontent");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
        }
        tablinks = document.getElementsByClassName("tablinks");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].className = tablinks[i].className.replace(" active", "");
        }
        document.getElementById(cityName).style.display = "block";
        evt.currentTarget.className += " active";
    }
    </script>
    </body>
    </html>
    """
    
    fullHtml = (pageStartHTML + getCPEJsonScript() + pageBodyHeaderHTML + pageBodyTabsHTML + cveIdIndicatorHTML + 
                pageBodyCPESuggesterHTML + pageBodyVDBIntelHTML + pageEndHTML)
    
    return fullHtml

def sort_cpe_strings_for_tooltip(base_strings):
    """Sort CPE base strings for tooltip display in a logical order."""
    def get_sort_key(cpe_string):
        # Extract parts to use for sorting
        parts = cpe_string.split(':')
        if len(parts) < 12:
            # Not a valid CPE - sort to bottom
            return (9, cpe_string)
            
        # Get the key parts
        part_type = parts[2]  # 'a', 'o', 'h' or '*'
        vendor = parts[3]
        product = parts[4]
        has_specific_vendor = vendor != '*'
        has_specific_product = product != '*' and not product.startswith('*') and not product.endswith('*')
        has_wildcard_product = product != '*' and (product.startswith('*') or product.endswith('*')) 
        has_hardware_info = parts[11] != '*'  # targetHW field
        
        # Prioritize strings
        if "cpe:2.3:a:" in cpe_string and has_specific_vendor and has_specific_product:
            # Exact application CPE priority
            priority = 0
        elif part_type != '*' and has_specific_vendor and has_specific_product:
            # Other exact part type with specific vendor and product
            priority = 1
        elif has_hardware_info:
            # Hardware-specific CPE strings
            priority = 2
        elif has_specific_vendor and has_wildcard_product:
            # Vendor + wildcarded product
            priority = 3
        elif has_specific_vendor:
            # Vendor only
            priority = 4
        elif has_specific_product or has_wildcard_product:
            # Product only
            priority = 5
        else:
            # Generic patterns
            priority = 6
            
        return (priority, vendor, product, cpe_string)
    
    # Sort the strings using the custom sort key
    return sorted(base_strings, key=get_sort_key)

def strings_were_curated(original, curated):
    """Compare original string with curated string, ignoring insignificant differences"""
    # Remove trailing underscores that might be added/removed during formatting
    original = original.rstrip('_')
    curated = curated.rstrip('_')
    return original != curated

def create_provenance_assistance_div(index, collapsed=True):
    """Creates a collapsible div for Provenance Assistance
    
    Args:
        index: The row index for unique IDs
        collapsed: Whether the div should be collapsed by default
    """
    collapse_class = "collapse" if collapsed else "collapse show"
    
    # Use simple HTML arrows instead of Bootstrap icons
    arrow_icon = "▼" if collapsed else "▲"
    
    html = f"""
    <div class="card mb-3">
        <div class="card-header d-flex justify-content-between align-items-center" 
             id="provenanceHeader_{index}" 
             data-bs-toggle="collapse" 
             data-bs-target="#provenanceCollapse_{index}" 
             style="cursor: pointer;">
            <h5 class="mb-0">
                Provenance Assistance
            </h5>
            <span class="arrow-icon">{arrow_icon}</span>
        </div>
        <div id="provenanceCollapse_{index}" class="{collapse_class}" aria-labelledby="provenanceHeader_{index}">
            <div class="card-body">
                <!-- Description buttons will be horizontally aligned -->
                <div id="descriptionButtons_{index}" class="description-buttons mb-3 d-flex flex-wrap gap-2">
                    <!-- Buttons will be populated via JavaScript -->
                </div>
                
                <!-- Dedicated area for displaying description content -->
                <div id="descriptionContent_{index}" class="description-content mt-3 border-top pt-3" style="display: none;">
                    <!-- Description content will be populated here when a button is clicked -->
                </div>
            </div>
        </div>
    </div>
    """
    
    return html.replace('\n', '')