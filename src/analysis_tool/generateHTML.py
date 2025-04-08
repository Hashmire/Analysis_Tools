# Import Python dependencies
import pandas as pd
import json
import html
from sys import exit
from build_info import VERSION, TOOLNAME
import os

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
        ('sourceRole', 'Source Role'),
        ('rawPlatformData', 'Raw Platform Data')
    ]
    
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
            if key == 'rawPlatformData':
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
                    <td>{label}</td>
                    <td><details><summary>Review rawPlatformData</summary>
                    <code id="rawPlatformData_{tableIndex}" class="rawPlatformData">{json_value}</code></details></td>
                </tr>
                """
            elif key == 'sourceID':
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
    
    # Add Platform Entry Notifications with badges
    html += "<tr><td>Platform Entry Notifications</td><td>"
    
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

    # Select badge color based on platform format type
    badge_color = "bg-info"  # Default color for most cases
    if platform_format_type == 'cveAffectsNoVersions':
        badge_color = "bg-danger"  # Red badge for no versions case

    # Use readable_format_type and appropriate badge color
    html += f'<span class="badge {badge_color}" title="{version_tooltip}">{readable_format_type}</span> '

    # 2. Duplicate Entries badge (warning) if duplicateRowIndices exist
    duplicate_indices = platform_metadata.get('duplicateRowIndices', [])
    if duplicate_indices:
        duplicate_tooltip = f"This data appears to be a duplicate of row: {', '.join(map(str, duplicate_indices))}"
        html += f'<span class="badge bg-warning" title="{duplicate_tooltip}">Duplicate Entries Detected</span> '

    # 3. CPE Array badge if hasCPEArray is True (not based on cpeBaseStrings)
    if platform_metadata.get('hasCPEArray', False):
        # Get the actual CPEs from rawPlatformData
        cpes_array = []
        if 'rawPlatformData' in row and 'cpes' in row['rawPlatformData']:
            cpes_array = row['rawPlatformData']['cpes']
        
        cpe_tooltip = "CPE Array included in original data"
        if cpes_array:
            cpe_tooltip = f"{', '.join(cpes_array)}"
        
        html += f'<span class="badge bg-info" title="{cpe_tooltip}">CPEs Array Included</span> '

    # 4. CPE Base Strings badge for API search strings
    cpe_base_strings = platform_metadata.get('cpeBaseStrings', [])
    if cpe_base_strings:
        base_strings_tooltip = "&#013;".join(cpe_base_strings)
        html += f'<span class="badge bg-secondary" title="{base_strings_tooltip}">CPE Base String Searches</span> '

    html += "</td></tr>"
    
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
        search_count = base_value.get('searchCount', 0)
        versions_found_content = base_value.get('versionsFoundContent', [])
        
        # Create Version Matches Identified tooltip content from versionsFoundContent
        versions_found_tooltip_content = "&#10;".join(
            "&#10;".join(f"{k}: {v}" for k, v in version.items())
            for version in versions_found_content
        )
        
        # Create Relevant Match String Searches tooltip content from ('search' + recorded_keys_str) keys 
        search_keys_tooltip_content = ""
        for key in base_value.keys():
            if key.startswith('searchSource'):
                search_keys_tooltip_content += f"{key}:  {base_value[key]}&#10;"
        
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

# New function to get the CPE JSON generation JavaScript
def getCPEJsonScript() -> str:
    
    # Get the current script's directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define the files with paths relative to the current script
    js_files = [
        os.path.join(current_dir, "static", "js", "utils.js"),
        os.path.join(current_dir, "static", "js", "cpe_json_handler.js"),
        os.path.join(current_dir, "static", "js", "ui_controller.js"),
        os.path.join(current_dir, "static", "js", "selection_manager.js")
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
            attr_string = " ".join(data_attrs)
            html_content = f"""<div id="cpe-query-container-{index}" class="cpe-query-container" {attr_string}>"""
            html_content += convertCPEsQueryDataToHTML(sortedCPEsQueryData, index)
            html_content += "</div>"  # Close the container div
            result_df.at[index, 'cpeQueryHTML'] = html_content
    
    return result_df

# Builds a simple html page with Bootstrap styling
def buildHTMLPage(affectedHtml, targetCve, vdbIntelHtml=None):
    
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
        <style>
        {css_content}
        </style>
    </head>
    <body>
    """
    pageBodyHeaderHTML = f"""
    <!-- Tool Info Header -->
    <div class="header" style="margin-left: 10px;">
        <h1>NVD Analysis Intelligence Tool <small>{TOOLNAME} version: {VERSION}</small></h1>
    </div>
    """
    pageBodyTabsHTML = """
    <!-- Tab links -->
    <div class="tab">
        <button class="tablinks" onclick="openCity(event, 'cveListCPESuggester')">CVE List CPE Suggester</button>
        <button class="tablinks" onclick="openCity(event, 'vdbIntelDashboard')">VDB Intel Dashboard</button>
    </div>
    """
    cveIdIndicatorHTML = f"""
    <h3 style="margin-bottom: 0px; margin-left: 10px;"><b>{targetCve} results</b></h3>
    <hr style="margin: 10px; border: 1px solid;">
    """
    pageBodyCPESuggesterHTML = f"""
    <!-- CVE List CPE Suggester -->
    <div id="cveListCPESuggester" class="tabcontent" style="display: block; border-left: 0px;">
        <h3>CVE List CPE Suggester</h3>
        {affectedHtml}
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
    pageEndHTML = "</body></html>"
    fullHtml = (pageStartHTML + getCPEJsonScript() + pageBodyHeaderHTML + pageBodyTabsHTML + cveIdIndicatorHTML + 
                pageBodyCPESuggesterHTML + pageBodyVDBIntelHTML + pageEndHTML)
    
    return fullHtml