# Import Python dependencies
import pandas as pd
import json
import html
import os
import datetime
import re 

# Import the new logging system
from .workflow_logger import get_logger, LogGroup

# Get logger instance
logger = get_logger()

# Import the new badge and modal system
from .badge_modal_system import *

# Load configuration
def load_config():
    """Load configuration from config.json"""
    try:
        config_path = os.path.join(os.path.dirname(__file__), 'config.json')
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        # Return a default config to prevent crashes
        return {
            'application': {
                'toolname': 'Hashmire/Analysis_Tools',
                'version': '0.1.0'
            }
        }

config = load_config()
VERSION = config['application']['version']
TOOLNAME = config['application']['toolname']

# Import Analysis Tool
from . import processData

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
    html = f"""<div id="rowDataTable_{tableIndex}_container" class="table-container">
    <table id="rowDataTable_{tableIndex}" class="table table-hover">"""
    
    # Define the keys and their labels, ensuring rawPlatformData is last
    keys_and_labels = [
        ('platformEntryMetadata.dataResource', 'Data Resource'),
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

    # Get characteristics once using consolidated function
    raw_platform_data = row.get('rawPlatformData', {})
    characteristics = analyze_version_characteristics(raw_platform_data)

    # Extract vendor and product for use throughout the function
    vendor = raw_platform_data.get('vendor', 'unknown')
    product = raw_platform_data.get('product', 'unknown')

    # Group badges by priority level
    danger_badges = []
    warning_badges = []
    sourceDataConcern_badges = []
    info_badges = []
    standard_badges = []

    # ===== 🟢 SUCCESS BADGES (Green) =====
    
    # 1. Confirmed Mappings badge (consolidates confirmed and culled mappings)
    confirmed_mappings = platform_metadata.get('confirmedMappings', [])
    culled_mappings = platform_metadata.get('culledConfirmedMappings', [])
    
    if confirmed_mappings:
        # Build tooltip with confirmed mappings and any culled mappings
        confirmed_tooltip = f"Confirmed CPE mappings available ({len(confirmed_mappings)}):&#013;" + "&#013;".join(confirmed_mappings)
        
        # Add culled mappings info if any exist
        if culled_mappings:
            confirmed_tooltip += "&#013;&#013;Less specific mappings filtered out:&#013;" + "&#013;".join(culled_mappings)
        
        standard_badges.append(f'<span class="badge bg-success" title="{confirmed_tooltip}">Confirmed Mappings: {len(confirmed_mappings)}</span> ')

    # ===== 🔴 DANGER BADGES (Red) =====
    
    # 2. git versionType badge (with version ranges) - CRITICAL
    if characteristics['has_git_version_type']:
        git_tooltip = "Versioning based on the git versionType is not advised for CPE Names, consider non-git versioning."
        git_badge_color = "bg-warning"
        
        # Elevate to danger level when used with version ranges
        if platform_format_type in ['cveAffectsVersionRange', 'cveAffectsVersionMix']:
            git_badge_color = "bg-danger"
            git_tooltip = "CRITICAL: CPE Range Matching Logic does not currently support git versionTypes&#013;Detected in version range context"
            
        if git_badge_color == "bg-danger":
            danger_badges.append(f'<span class="badge {git_badge_color}" title="{git_tooltip}">git versionType</span> ')
        else:
            warning_badges.append(f'<span class="badge {git_badge_color}" title="{git_tooltip}">git versionType</span> ')

    # 3. Platform Format Type badge - CVE Affects Product (No Versions) 
    version_checks = platform_metadata.get('cpeVersionChecks', [])
    version_tooltip = "No versions detected!"
    if version_checks:
        version_lines = []
        for check in version_checks:
            check_str = ", ".join([f"{k}: {v}" for k, v in check.items()])
            version_lines.append(check_str)
        version_tooltip = "&#013;".join(version_lines)

    if platform_format_type == 'cveAffectsNoVersions':
        danger_badges.append(f'<span class="badge bg-danger" title="{version_tooltip}">{readable_format_type}</span> ')
    # Note: Platform Format Type for other cases is now handled in Supporting Information modal

    # ===== 🔵 INFO BADGES (Blue) =====
    
    # Note: CVE Affected CPES Data is now handled in Supporting Information modal

    # ===== 🟡 WARNING BADGES (Yellow) =====
    
    # 6. git versionType badge (without version ranges) - Already handled above in badge #2
    
    # 7. Has Version Changes badge
    if characteristics['has_version_changes']:
        changes_tooltip = 'Versions array contains change history information requiring special handling'
        warning_badges.append(f'<span class="badge bg-warning" title="{changes_tooltip}">Has Version Changes</span> ')

    # 8. JSON Generation Rules badge (unified wildcards + update patterns)
    has_wildcards = characteristics['has_wildcards']
    has_update_patterns = characteristics['has_update_patterns'] and characteristics['update_patterns']
    
    if has_wildcards or has_update_patterns:
        # Use the unified JSON Generation Rules badge system that handles both wildcards and update patterns
        json_rules_badge = create_json_generation_rules_badge(tableIndex, raw_platform_data, vendor, product, row)
        if json_rules_badge:
            warning_badges.append(json_rules_badge)

    # ===== ⚫ STANDARD BADGES (Gray) =====
    
    # Note: The following badges are now consolidated into the Supporting Information modal:
    # - CPE API Error Detection Badge
    # - CPE Base String Searches badge
    # - Source to CPE Transformations Applied badge

    # ===== 🟪 SOURCE DATA CONCERN BADGES (Purple) =====
    
    # 13. Vendor: N/A badge
    if 'vendor' in raw_platform_data and isinstance(raw_platform_data['vendor'], str) and raw_platform_data['vendor'].lower() == 'n/a':
        vendor_na_tooltip = 'Vendor field contains \'n/a\' which prevents proper CPE matching&#013;Original value: \'n/a\''
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{vendor_na_tooltip}">Vendor: N/A</span> ')

    # 14. Product: N/A badge
    if 'product' in raw_platform_data and isinstance(raw_platform_data['product'], str) and raw_platform_data['product'].lower() == 'n/a':
        product_na_tooltip = 'Product field contains \'n/a\' which prevents proper CPE matching&#013;Original value: \'n/a\''
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{product_na_tooltip}">Product: N/A</span> ')

    # 15. Versions Data Concern badge
    if characteristics['version_concerns']:
        versions_tooltip = 'Versions array contains formatting issues:&#013;' + '&#013;'.join(characteristics['version_concerns'])
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{versions_tooltip}">Versions Data Concern</span> ')
    
    # 16. CPEs Array Data Concern badge
    # TODO: Enhance this badge with full CPE 2.3 LINT validation checks including:
    #       - Attribute format validation (alphanumeric, underscore, hyphen only)
    #       - Proper escaping of special characters
    #       - Valid enumeration values for part, update, edition, language fields
    #       - Complete structural validation beyond just version text patterns
    if 'cpes' in raw_platform_data and isinstance(raw_platform_data['cpes'], list):
        cpe_concerns = []
        for cpe in raw_platform_data['cpes']:
            if isinstance(cpe, str) and cpe.startswith('cpe:'):
                parts = cpe.split(':')
                if len(parts) >= 6 and parts[0] == 'cpe' and parts[1] == '2.3':
                    version = parts[5]
                    if any(text_comp in version.lower() for text_comp in VERSION_TEXT_PATTERNS):
                        cpe_concerns.append(f"CPE contains improper version text: {cpe}")
                        break
        
        if cpe_concerns:
            cpe_tooltip = 'CPEs array contains formatting issues:&#013;' + '&#013;'.join(cpe_concerns)
            sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{cpe_tooltip}">CPEs Array Data Concern</span> ')

    # 17. Duplicate Entries Detected badge
    duplicate_indices = platform_metadata.get('duplicateRowIndices', [])
    if duplicate_indices:
        duplicate_tooltip = f"This entry has duplicate data at row(s): {', '.join(map(str, duplicate_indices))}&#013;Multiple identical platform configurations found"
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{duplicate_tooltip}">Duplicate Entries Detected</span> ')

    # 18. Platforms Data Concern badge
    if platform_metadata.get('platformDataConcern', False):
        platform_tooltip = 'Unexpected Platforms data detected in affected entry'
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{platform_tooltip}">Platforms Data Concern</span> ')

    # ===== 🔍 SUPPORTING INFORMATION MODAL =====
    
    # Create the unified Supporting Information badge to replace Standard and Info badges
    supporting_info_badge = create_supporting_information_badge(
        table_index=tableIndex,
        row=row,
        platform_metadata=platform_metadata,
        raw_platform_data=raw_platform_data,
        characteristics=characteristics,
        platform_format_type=platform_format_type,
        readable_format_type=readable_format_type,
        vendor=vendor,
        product=product,
        nvd_source_data=nvdSourceData
    )
    
    # If we have supporting information, add it to the standard badges category
    if supporting_info_badge:
        standard_badges.append(supporting_info_badge)

    # Add badges in priority order: Danger -> Warning -> Data Concern -> Info -> Standard
    html += ''.join(danger_badges)
    html += ''.join(warning_badges)
    html += ''.join(sourceDataConcern_badges)
    html += ''.join(info_badges)
    html += ''.join(standard_badges)    # Log badge summary for this row
    badge_details = {}
    
    # Extract badge names from each category
    if danger_badges:
        badge_names = []
        for badge_html in danger_badges:
            # Extract text between > and < 
            import re
            match = re.search(r'>([^<]+)</span>', badge_html)
            if match:
                badge_names.append(match.group(1))
        badge_details["Danger"] = badge_names
    
    if warning_badges:
        badge_names = []
        for badge_html in warning_badges:
            import re
            match = re.search(r'>([^<]+)</span>', badge_html)
            if match:
                badge_names.append(match.group(1))
        badge_details["Warning"] = badge_names
    
    if sourceDataConcern_badges:
        badge_names = []
        for badge_html in sourceDataConcern_badges:
            import re
            match = re.search(r'>([^<]+)</span>', badge_html)
            if match:
                badge_names.append(match.group(1))
        badge_details["Data Concern"] = badge_names
    
    if info_badges:
        badge_names = []
        for badge_html in info_badges:
            import re
            match = re.search(r'>([^<]+)</span>', badge_html)
            if match:
                badge_names.append(match.group(1))
        badge_details["Info"] = badge_names
    
    if standard_badges:
        badge_names = []
        for badge_html in standard_badges:
            import re
            match = re.search(r'>([^<]+)</span>', badge_html)
            if match:
                badge_names.append(match.group(1))
        badge_details["Standard"] = badge_names
    
    if badge_details:
        vendor = row.get('rawPlatformData', {}).get('vendor', 'Unknown')
        product = row.get('rawPlatformData', {}).get('product', 'Unknown')
        source_role = row.get('sourceRole', 'Unknown')
        
        # Format badge details for logging
        badge_summary = []
        for badge_type, badge_names in badge_details.items():
            if len(badge_names) == 1:
                badge_summary.append(f"{badge_type}: {badge_names[0]}")
            else:
                badge_summary.append(f"{badge_type}: [{', '.join(badge_names)}]")
        
        logger.info(f"Badges added for row {tableIndex} ({source_role}): {vendor}/{product} ({' | '.join(badge_summary)})", group="badge_gen")
    else:
        vendor = row.get('rawPlatformData', {}).get('vendor', 'Unknown')
        product = row.get('rawPlatformData', {}).get('product', 'Unknown')
        source_role = row.get('sourceRole', 'Unknown')
        logger.debug(f"No badges added for row {tableIndex} ({source_role}): {vendor}/{product}", group="badge_gen")

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
                <td>Repository</td>
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
    
    html += "</table></div>"
        
    return html.replace('\n', '')

def create_empty_matches_table(tableIndex=0) -> str:
    """
    Create an empty matches table structure for when there are no CPE suggestions
    but the Custom CPE Builder still needs a table to add rows to.
    """
    return f"""
    <div class="card mb-3">
        <div class="card-header d-flex justify-content-between align-items-center collapsed" 
             id="cpeHeader_{tableIndex}" 
             data-bs-toggle="collapse" 
             data-bs-target="#cpeCollapse_{tableIndex}" 
             style="cursor: pointer;">
            <h5 class="mb-0">
                CPE Suggestions
            </h5>
            <span class="arrow-icon">&uarr;</span>
        </div>
        <div id="cpeCollapse_{tableIndex}" class="collapse" aria-labelledby="cpeHeader_{tableIndex}">
            <div class="card-body">
                <p class="text-muted mb-3">No CPE suggestions available. Use the Custom CPE Builder above to create entries.</p>
                <div id="matchesTable_{tableIndex}_container" class="table-container">
                    <table id="matchesTable_{tableIndex}" class="table table-hover matchesTable">
                        <thead>
                            <tr>
                                <th style="width: 65%">CPE Base String</th>
                                <th style="width: 35%">Information</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Custom CPE rows will be added here -->
                        </tbody>
                    </table>
                </div>
                
                <!-- JSON Generation Settings Container -->
                <div id="jsonSettings_matchesTable_{tableIndex}" class="json-settings-container mb-3" style="display: none;">
                    <!-- Settings content will be populated by initializeJsonSettings() -->
                </div>
                
            </div>
        </div>
    </div>
    """.replace('\n', '')

def convertCPEsQueryDataToHTML(sortedCPEsQueryData: dict, tableIndex=0, row_data=None) -> str:
    try:
        # Early exit if there's no data to process
        if not sortedCPEsQueryData or len(sortedCPEsQueryData) == 0:
            logger.debug(f"No CPE query data to process for table {tableIndex}", group="PAGE_GEN")
            return f"""
            <div class="card mb-3">
                <div class="card-header">
                    <h5 class="mb-0">CPE Suggestions</h5>
                </div>
                <div class="card-body">
                    <p class="text-muted">No CPE suggestions available for this entry.</p>
                </div>
            </div>
            """.replace('\n', '')
        
        logger.debug(f"Processing {len(sortedCPEsQueryData)} CPE query results for table {tableIndex}", group="PAGE_GEN")
        
        # Create a collapsible card similar to Provenance Assistance
        html_content = f"""
        <div class="card mb-3">
            <div class="card-header d-flex justify-content-between align-items-center" 
                 id="cpeHeader_{tableIndex}" 
                 data-bs-toggle="collapse" 
                 data-bs-target="#cpeCollapse_{tableIndex}" 
                 style="cursor: pointer;">
                <h5 class="mb-0">
                    CPE Suggestions
                </h5>
                <span class="arrow-icon">&uarr;</span>
            </div>
            <div id="cpeCollapse_{tableIndex}" class="collapse show" aria-labelledby="cpeHeader_{tableIndex}">
                <div class="card-body">
                    <div id="matchesTable_{tableIndex}_container" class="table-container">
                    <table id="matchesTable_{tableIndex}" class="table table-hover matchesTable">
                    <thead>
                      <tr>
                        <th style="width: 65%">CPE Base String</th>
                        <th style="width: 35%">Information</th>
                      </tr>
                    </thead>
                    <tbody>
                    """
        # Get confirmed mappings from row data if available
        confirmed_mappings = []
        if row_data is not None and hasattr(row_data, 'get') and 'platformEntryMetadata' in row_data:
            platform_metadata = row_data['platformEntryMetadata']
            confirmed_mappings = platform_metadata.get('confirmedMappings', [])
        
        if confirmed_mappings:
            logger.debug(f"Processing {len(confirmed_mappings)} confirmed mappings", group="PAGE_GEN")
        
        # First, process confirmed mappings and check for duplicates in API results
        confirmed_mappings_processed = set()
        for cpe_base in confirmed_mappings:
            # Check if this confirmed mapping also exists in the API results
            if cpe_base in sortedCPEsQueryData:
                # This is a duplicate - merge the information
                base_value = sortedCPEsQueryData[cpe_base]
                
                total_match_count = (base_value.get('depFalseCount', 0) + base_value.get('depTrueCount', 0))
                dep_true_count = base_value.get('depTrueCount', 0)
                dep_false_count = base_value.get('depFalseCount', 0)
                
                # Skip confirmed mappings where all API results are deprecated (no viable CPE names)
                if total_match_count > 0 and dep_true_count == total_match_count:
                    logger.debug(f"Skipping confirmed mapping {cpe_base} - all {total_match_count} results deprecated", group="PAGE_GEN")
                    confirmed_mappings_processed.add(cpe_base)
                    continue
                
                versions_found = base_value.get('versionsFound', 0)
                
                # Calculate search_count correctly by checking for cveAffectedCPEsArray
                search_count = base_value.get('searchCount', 0)
                has_cpes_array_source = 'searchSourcecveAffectedCPEsArray' in base_value
                
                # If the CPEs array source isn't already counted in searchCount, add it
                base_value_keys = list(base_value.keys()) if hasattr(base_value, 'keys') else []
                cpe_array_already_counted = any(
                    k.startswith('searchSource') and 'cveAffectedCPEsArray' in k 
                    for k in base_value_keys 
                    if k != 'searchSourcecveAffectedCPEsArray'
                )
                
                if has_cpes_array_source and not cpe_array_already_counted:
                    search_count += 1
                    
                versions_found_content = base_value.get('versionsFoundContent', [])
                
                # Create Version Matches Identified tooltip content from versionsFoundContent
                versions_found_tooltip_content = "Versions Matches Identified:  &#10;".join(
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
                search_keys_tooltip_content = "Relevant Match String Searches:&#10;"
                for key, value in sorted_search_keys:
                    search_keys_tooltip_content += f"{key}:  {value}&#10;"
                
                # Sanitize base_key for use as ID
                base_key_id = cpe_base.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_")
                
                # Create enhanced reference/provenance content
                references = base_value.get('references', [])
                references_html = ""
                
                if references:
                    # Group references by type for better organization
                    ref_types = {}
                    for ref in references:
                        ref_type = ref.get('type', 'Unknown')
                        if ref_type not in ref_types:
                            ref_types[ref_type] = []
                        ref_types[ref_type].append(ref)
                    
                    # Create a more detailed tooltip with organized sections
                    references_tooltip_content = "CPE Provenance & References:&#10;&#10;"
                    
                    # Show top reference types with counts
                    type_summary = []
                    for ref_type, type_refs in ref_types.items():
                        total_freq = sum(r.get('frequency', 1) for r in type_refs)
                        type_summary.append((ref_type, len(type_refs), total_freq))
                    
                    # Sort by total frequency for most relevant types first
                    type_summary.sort(key=lambda x: x[2], reverse=True)
                    
                    # Add type summary
                    for ref_type, count, total_freq in type_summary[:4]:  # Show top 4 types
                        references_tooltip_content += f"• {ref_type}: {count} refs ({total_freq} occurrences)&#10;"
                    
                    if len(type_summary) > 4:
                        remaining_types = len(type_summary) - 4
                        references_tooltip_content += f"• ...and {remaining_types} more type(s)&#10;"
                    
                    references_tooltip_content += "&#10;Top References:&#10;"
                    
                    # Show top 5 individual references
                    for ref in references[:5]:
                        ref_type = ref.get('type', 'Unknown')
                        ref_url = ref.get('url', 'No URL')
                        ref_count = ref.get('frequency', 1)
                        # Truncate long URLs for readability
                        display_url = ref_url if len(ref_url) <= 60 else ref_url[:57] + "..."
                        references_tooltip_content += f"[{ref_type}] {display_url} ({ref_count}x)&#10;"
                    
                    if len(references) > 5:
                        references_tooltip_content += f"...and {len(references) - 5} more references"
                          # Create expandable reference section HTML
                base_key_safe = cpe_base.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_").replace("*", "star")
                
                references_html = f'''
                <div class="reference-section">
                    <span class="badge modal-badge bg-info" 
                          onclick="BadgeModalManager.openReferencesModal('{base_key_safe}', '{cpe_base.replace("'", "\\'")}', {len(references)})" id="refBadge_{base_key_safe}">
                        📋 Provenance ({len(references)})
                    </span>
                </div>'''
                
                # Store reference data in a global JavaScript object for the modal
                ref_data_js = "{"
                for ref_type, type_refs in sorted(ref_types.items(), key=lambda x: sum(r.get('frequency', 1) for r in x[1]), reverse=True):
                    total_freq = sum(r.get('frequency', 1) for r in type_refs)
                    ref_data_js += f'''
                        "{ref_type}": {{
                            "total_freq": {total_freq},
                            "refs": ['''
                    
                    for ref in type_refs:
                        ref_url = ref.get('url', 'No URL').replace('"', '\\"').replace("'", "\\'")
                        ref_count = ref.get('frequency', 1)
                        ref_data_js += f'''
                                {{"url": "{ref_url}", "count": {ref_count}}},'''
                    
                    ref_data_js = ref_data_js.rstrip(',') + "]}, "
                
                ref_data_js = ref_data_js.rstrip(', ') + "}"
                
                # Parse the JSON for storage in global registry
                ref_data_dict = json.loads(ref_data_js)
                
                # Register reference data with the global CPE registry (deduplicated)
                register_cpe_data(cpe_base, 'references', ref_data_dict)
                
                # Create reference HTML without inline script
                references_html = f'''
                <div class="reference-section">
                    <span class="badge modal-badge bg-info" 
                          onclick="BadgeModalManager.openReferencesModal('{base_key_safe}', '{cpe_base.replace("'", "\\'")}', {len(references)})" id="refBadge_{base_key_safe}">
                        📋 Provenance ({len(references)})
                    </span>
                </div>'''
                
                # Create sorting priority data structure
                sorting_data = {
                    "searches": {},
                    "versions": versions_found_content,
                    "statistics": {
                        "total_cpe_names": total_match_count,
                        "final_count": dep_false_count,
                        "deprecated_count": dep_true_count
                    },
                    "confirmedMapping": {
                        "confidence": "High",
                        "source": "Manual Verification",
                        "verified_date": "Platform Entry"
                    }
                }
                
                # Add search source data
                for key, value in sorted_search_keys:
                    sorting_data["searches"][key] = value
                
                # Register sorting priority data with the global CPE registry (deduplicated)
                register_cpe_data(cpe_base, 'sortingPriority', sorting_data)
                
                # Let frontend JavaScript calculate tab count dynamically from actual data
                context_count = ""  # Remove hardcoded count, let JS calculate
                
                # Create merged row with both confirmed mapping badge and API data
                html_content += f"""
                <tr id="row_{base_key_id}" class="cpe-row confirmed-mapping-row" data-cpe-base="{cpe_base}">
                    <td class="text-break">{cpe_base}</td>
                    <td>
                        <div class="d-flex flex-wrap gap-1 align-items-center">
                            <span class="badge modal-badge bg-success"
                                  onclick="BadgeModalManager.openConfirmedMappingModal('{base_key_safe}', '{cpe_base.replace("'", "\\'")}')">
                                ✅ Confirmed Mapping
                            </span>
                            <span class="badge modal-badge bg-secondary" 
                                  onclick="BadgeModalManager.openSortingPriorityModal('{base_key_safe}', '{cpe_base.replace("'", "\\'")}', 'statistics')">
                                📈 Sorting Priority Context
                            </span>"""
                
                # Add enhanced references section if available
                if references:
                    html_content += references_html
                
                html_content += f"""
                        </div>
                    </td>
                </tr>
                """
                
                # Mark this confirmed mapping as processed and track for removal from API results
                confirmed_mappings_processed.add(cpe_base)
            else:
                # This confirmed mapping is not in API results - show as confirmed mapping only
                base_key_id = cpe_base.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_")
                base_key_safe = cpe_base.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_").replace("*", "star")
                
                # Create minimal sorting priority data for confirmed mapping only
                sorting_data = {
                    "confirmedMapping": {
                        "confidence": "High",
                        "source": "Manual Verification",
                        "verified_date": "Platform Entry"
                    }
                }
                
                # Convert sorting data to JavaScript format
                sorting_data_js = json.dumps(sorting_data, cls=CustomJSONEncoder)
                
                # Register sorting priority data
                sorting_priority_html = f'''
                <script>
                    BadgeModal.registerData('sortingPriority', '{base_key_safe}', {sorting_data_js});
                </script>'''
                
                html_content += f"""
                <tr id="row_{base_key_id}" class="cpe-row confirmed-mapping-row" data-cpe-base="{cpe_base}">
                    <td class="text-break">{cpe_base}</td>
                    <td>
                        <div class="d-flex flex-wrap gap-1 align-items-center">
                            <span class="badge modal-badge bg-success"
                                  onclick="BadgeModalManager.openConfirmedMappingModal('{base_key_safe}', '{cpe_base.replace("'", "\\'")}')">
                                ✅ Confirmed Mapping
                            </span>
                        </div>
                    </td>
                </tr>
                {sorting_priority_html}
                """
                confirmed_mappings_processed.add(cpe_base)
        
        # Process all API query results, excluding those already processed as confirmed mappings
        for base_key, base_value in sortedCPEsQueryData.items():
            # Skip this API result if it was already processed as a confirmed mapping
            if base_key in confirmed_mappings_processed:
                continue
                
            total_match_count = (base_value.get('depFalseCount', 0) + base_value.get('depTrueCount', 0))
            dep_true_count = base_value.get('depTrueCount', 0)
            dep_false_count = base_value.get('depFalseCount', 0)
            versions_found = base_value.get('versionsFound', 0)
            
            # Skip CPE base strings where all results are deprecated (no viable CPE names)
            if total_match_count > 0 and dep_true_count == total_match_count:
                logger.debug(f"Skipping {base_key} - all {total_match_count} results deprecated", group="PAGE_GEN")
                continue
            
            # Calculate search_count correctly by checking for cveAffectedCPEsArray
            search_count = base_value.get('searchCount', 0)
            has_cpes_array_source = 'searchSourcecveAffectedCPEsArray' in base_value
            
            # If the CPEs array source isn't already counted in searchCount, add it
            base_value_keys = list(base_value.keys()) if hasattr(base_value, 'keys') else []
            cpe_array_already_counted = any(
                k.startswith('searchSource') and 'cveAffectedCPEsArray' in k 
                for k in base_value_keys 
                if k != 'searchSourcecveAffectedCPEsArray'
            )
            if has_cpes_array_source and not cpe_array_already_counted:
                search_count += 1
                
            versions_found_content = base_value.get('versionsFoundContent', [])
            
            # Create Version Matches Identified tooltip content from versionsFoundContent
            versions_found_tooltip_content = "Versions Matches Identified:  &#10;".join(
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
            search_keys_tooltip_content = "Relevant Match String Searches:&#10;"
            for key, value in sorted_search_keys:
                search_keys_tooltip_content += f"{key}:  {value}&#10;"
            
            # Create enhanced reference/provenance content
            references = base_value.get('references', [])
            references_html = ""
            
            # Define base_key_safe for use in modal system (needed for both references and sorting priority)
            base_key_safe = base_key.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_").replace("*", "star")
            
            if references:
                # Group references by type for better organization
                ref_types = {}
                for ref in references:
                    ref_type = ref.get('type', 'Unknown')
                    if ref_type not in ref_types:
                        ref_types[ref_type] = []
                    ref_types[ref_type].append(ref)
                
                # Create a more detailed tooltip with organized sections
                references_tooltip_content = "CPE Provenance & References:&#10;&#10;"
                
                # Show top reference types with counts
                type_summary = []
                for ref_type, type_refs in ref_types.items():
                    total_freq = sum(r.get('frequency', 1) for r in type_refs)
                    type_summary.append((ref_type, len(type_refs), total_freq))
                
                # Sort by total frequency for most relevant types first
                type_summary.sort(key=lambda x: x[2], reverse=True)
                
                # Add type summary
                for ref_type, count, total_freq in type_summary[:4]:  # Show top 4 types
                    references_tooltip_content += f"• {ref_type}: {count} refs ({total_freq} occurrences)&#10;"
                
                if len(type_summary) > 4:
                    remaining_types = len(type_summary) - 4
                    references_tooltip_content += f"• ...and {remaining_types} more type(s)&#10;"
                
                references_tooltip_content += "&#10;Top References:&#10;"
                
                # Show top 5 individual references
                for ref in references[:5]:
                    ref_type = ref.get('type', 'Unknown')
                    ref_url = ref.get('url', 'No URL')
                    ref_count = ref.get('frequency', 1)
                    # Truncate long URLs for readability
                    display_url = ref_url if len(ref_url) <= 60 else ref_url[:57] + "..."
                    references_tooltip_content += f"[{ref_type}] {display_url} ({ref_count}x)&#10;"
                
                if len(references) > 5:
                    references_tooltip_content += f"...and {len(references) - 5} more references"
                
                # Create expandable reference section HTML
                references_html = f'''
                <div class="reference-section">
                    <span class="badge modal-badge bg-info" 
                          onclick="BadgeModalManager.openReferencesModal('{base_key_safe}', '{base_key.replace("'", "\\'")}', {len(references)})" id="refBadge_{base_key_safe}">
                        📋 Provenance ({len(references)})
                    </span>
                </div>'''
                
                # Store reference data in a global JavaScript object for the modal
                ref_data_js = "{"
                for ref_type, type_refs in sorted(ref_types.items(), key=lambda x: sum(r.get('frequency', 1) for r in x[1]), reverse=True):
                    total_freq = sum(r.get('frequency', 1) for r in type_refs)
                    ref_data_js += f'''
                        "{ref_type}": {{
                            "total_freq": {total_freq},
                            "refs": ['''
                    
                    for ref in type_refs:
                        ref_url = ref.get('url', 'No URL').replace('"', '\\"').replace("'", "\\'")
                        ref_count = ref.get('frequency', 1)
                        ref_data_js += f'''
                                {{"url": "{ref_url}", "count": {ref_count}}},'''
                    
                    ref_data_js = ref_data_js.rstrip(',') + "]}, "
                
                ref_data_js = ref_data_js.rstrip(', ') + "}"
                
                # Parse the JSON for storage in global registry
                ref_data_dict = json.loads(ref_data_js)
                
                # Register reference data with the global CPE registry (deduplicated)
                register_cpe_data(base_key, 'references', ref_data_dict)
                
                # Create reference HTML without inline script
                references_html = f'''
                <div class="reference-section">
                    <span class="badge modal-badge bg-info" 
                          onclick="BadgeModalManager.openReferencesModal('{base_key_safe}', '{base_key.replace("'", "\\'")}', {len(references)})" id="refBadge_{base_key_safe}">
                        📋 Provenance ({len(references)})
                    </span>
                </div>'''
            
            # Create sorting priority data structure for this base_key
            sorting_data = {
                "searches": {},
                "versions": versions_found_content,
                "statistics": {
                    "total_cpe_names": total_match_count,
                    "final_count": dep_false_count,
                    "deprecated_count": dep_true_count
                }
            }
            
            # Add search source data
            for key, value in sorted_search_keys:
                sorting_data["searches"][key] = value
            
            # Register sorting priority data with the global CPE registry (deduplicated)
            register_cpe_data(base_key, 'sortingPriority', sorting_data)
            
            # Sanitize base_key for use as ID
            base_key_id = base_key.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_")
            
            # Let frontend JavaScript calculate tab count dynamically from actual data
            context_count = ""  # Remove hardcoded count, let JS calculate
            
            html_content += f"""
            <tr id="row_{base_key_id}" class="cpe-row" data-cpe-base="{base_key}">
                <td class="text-break">{base_key}</td>
                <td>
                <div class="d-flex flex-wrap gap-1 align-items-center">
                    <span class="badge modal-badge bg-secondary" 
                          onclick="BadgeModalManager.openSortingPriorityModal('{base_key_safe}', '{base_key.replace("'", "\\'")}', 'statistics')">
                        📈 Sorting Priority Context
                    </span>"""
            
            # Add enhanced references section if available
            if references:
                html_content += references_html
            
            html_content += f"""
                    </div>
                </td>
            </tr>
            """

        # Close the table and container divs
        html_content += """
        </tbody>
        </table>
        </div>
                
                <!-- JSON Generation Settings Container -->
                <div id="jsonSettings_""" + f"matchesTable_{tableIndex}" + """" class="json-settings-container mb-3" style="display: none;">
                    <!-- Settings content will be populated by initializeJsonSettings() -->
                </div>
                
            </div>
        </div>
    </div>
    """
        return html_content.replace('\n', '')
    except Exception as e:
        logger.error(f"HTML conversion failed: Unable to convert CPE query data to HTML at table index {tableIndex} - {e}", group="page_generation")
        logger.error(f"sortedCPEsQueryData type: {type(sortedCPEsQueryData)}", group="page_generation")
        if hasattr(sortedCPEsQueryData, 'keys'):
            logger.error(f"sortedCPEsQueryData keys: {list(sortedCPEsQueryData.keys())}", group="page_generation")
        raise e

# Add the new file to the list of JS files to include
def getCPEJsonScript() -> str:
    # Get the current script's directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Define the files with paths relative to the current script
    js_files = [
        os.path.join(current_dir, "static", "js", "badge_modal_system.js"),  # Add modular system first
        os.path.join(current_dir, "static", "js", "modular_rules.js"),
        os.path.join(current_dir, "static", "js", "cpe_json_handler.js"),
        os.path.join(current_dir, "static", "js", "ui_controller.js"),
        os.path.join(current_dir, "static", "js", "selection_manager.js"),
        os.path.join(current_dir, "static", "js", "timestamp_handler.js"),
        os.path.join(current_dir, "static", "js", "provenance_assistance.js"),
        os.path.join(current_dir, "static", "js", "completion_tracker.js"),
        os.path.join(current_dir, "static", "js", "custom_cpe_builder.js")
    ]
    
    # Read JavaScript files
    js_content = ""
    
    # Read each file and add its content to the script tag
    for js_file in js_files:
        try:
            with open(js_file, 'r', encoding='utf-8') as f:
                js_content += f.read() + "\n\n"

        except Exception as e:
            logger.error(f"JavaScript file loading failed: Unable to read JS file '{js_file}' - {e}", group="page_generation")
            # Add placeholder comment if file can't be read
            js_content += f"// Error loading {js_file}\n\n"
    # Add JSON settings HTML injection with defensive checking
    safe_json_settings = JSON_SETTINGS_HTML if 'JSON_SETTINGS_HTML' in globals() and JSON_SETTINGS_HTML else {}
    
    # Implement deduplication for JSON_SETTINGS_HTML to prevent bloat
    # Check if all settings are identical and use a template approach
    if safe_json_settings:
        # Get a sample key to check if all settings are identical
        sample_key = next(iter(safe_json_settings.keys()))
        sample_content = safe_json_settings[sample_key]
        
        # Check if all settings are identical (common case)
        all_identical = all(content == sample_content for content in safe_json_settings.values())
        
        if all_identical and len(safe_json_settings) > 1:
            # Use a template approach to reduce size
            logger.debug(f"Deduplicating JSON_SETTINGS_HTML - found {len(safe_json_settings)} identical entries", group="page_generation")
            json_settings_injection = f"""
    // JSON Settings HTML template (deduplicated for efficiency)
    window.JSON_SETTINGS_TEMPLATE = {json.dumps(sample_content, cls=CustomJSONEncoder)};
    window.JSON_SETTINGS_KEYS = {json.dumps(list(safe_json_settings.keys()), cls=CustomJSONEncoder)};
    // Create JSON_SETTINGS_HTML from template
    window.JSON_SETTINGS_HTML = {{}};
    window.JSON_SETTINGS_KEYS.forEach(key => {{
        window.JSON_SETTINGS_HTML[key] = window.JSON_SETTINGS_TEMPLATE.replace(/matchesTable_0/g, key);
    }});
    """
        else:
            json_settings_injection = f"""
    // JSON Settings HTML generated by Python and injected on page load
    window.JSON_SETTINGS_HTML = {json.dumps(safe_json_settings, cls=CustomJSONEncoder)};
    """
    else:
        json_settings_injection = """
    // No JSON Settings HTML data
    window.JSON_SETTINGS_HTML = {};
    """
    
    # Add intelligent settings injection with defensive checking
    safe_intelligent_settings = INTELLIGENT_SETTINGS if 'INTELLIGENT_SETTINGS' in globals() and INTELLIGENT_SETTINGS else {}
    intelligent_settings_js = ""
    if safe_intelligent_settings:
        # Check if all intelligent settings are identical
        if len(safe_intelligent_settings) > 1:
            sample_key = next(iter(safe_intelligent_settings.keys()))
            sample_settings = safe_intelligent_settings[sample_key]
            
            all_identical = all(settings == sample_settings for settings in safe_intelligent_settings.values())
            
            if all_identical:
                # Use template approach for identical settings
                logger.debug(f"Deduplicating INTELLIGENT_SETTINGS - found {len(safe_intelligent_settings)} identical entries", group="page_generation")
                intelligent_settings_js = f"""
        // Intelligent settings template (deduplicated for efficiency)
        window.INTELLIGENT_SETTINGS_TEMPLATE = {json.dumps(sample_settings, cls=CustomJSONEncoder)};
        window.INTELLIGENT_SETTINGS_KEYS = {json.dumps(list(safe_intelligent_settings.keys()), cls=CustomJSONEncoder)};
        // Create INTELLIGENT_SETTINGS from template
        window.INTELLIGENT_SETTINGS = {{}};
        window.INTELLIGENT_SETTINGS_KEYS.forEach(key => {{
            window.INTELLIGENT_SETTINGS[key] = window.INTELLIGENT_SETTINGS_TEMPLATE;
        }});
        """
            else:
                intelligent_settings_js = f"""
        // Intelligent settings computed by Python
        window.INTELLIGENT_SETTINGS = {json.dumps(safe_intelligent_settings, cls=CustomJSONEncoder)};
        """
        else:
            intelligent_settings_js = f"""
        // Intelligent settings computed by Python
        window.INTELLIGENT_SETTINGS = {json.dumps(safe_intelligent_settings, cls=CustomJSONEncoder)};
        """
    
    # Inject NON_SPECIFIC_VERSION_VALUES as a global JavaScript variable
    # This ensures the JavaScript uses the same list as Python (single source of truth)
    non_specific_versions_js = f"""
    // Non-specific version values injected from Python (single source of truth)
    window.NON_SPECIFIC_VERSION_VALUES = {json.dumps(NON_SPECIFIC_VERSION_VALUES)};
    """
    
    # Get consolidated registrations from badge_modal_system
    consolidated_cpe_registrations = get_consolidated_cpe_registration_script()
    consolidated_platform_registrations = get_consolidated_platform_notification_script()
    
    # Log summary statistics for debugging bloat issues
    total_settings_keys = len(safe_json_settings)
    total_intelligent_keys = len(safe_intelligent_settings)
    
    if total_settings_keys > 10 or total_intelligent_keys > 10:
        logger.info(f"Large dataset detected - {total_settings_keys} JSON settings entries, {total_intelligent_keys} intelligent settings entries", group="page_generation")

    js_content += (json_settings_injection + intelligent_settings_js + 
                  non_specific_versions_js + consolidated_cpe_registrations + 
                  consolidated_platform_registrations)
    
    return f"<script>\n{js_content}\n</script>"

def update_cpeQueryHTML_column(dataframe, nvdSourceData):
    """Updates the dataframe to include a column with HTML for CPE query results"""
    
    # Make a copy to avoid modifying the original
    result_df = dataframe.copy()
    
    for index, row in result_df.iterrows():
        # Existing attribute code
        data_attrs = []
        
        # Add data attributes with platform info, etc.
        if 'platformData' in row.index and not pd.isna(row['platformData']):
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
                logger.error(f"Platform data serialization failed: Unable to convert platform data to JSON - {e}", group="page_generation")
        
        # Check if this row has update-related content
        raw_platform_data = row.get('rawPlatformData', {})
        has_update_content = has_update_related_content(raw_platform_data)
        
        # Create the collapse button and update toggle button
        buttons_html = f'<button id="collapseRowButton_{index}" class="btn btn-secondary" onclick="toggleRowCollapse({index})">Collapse Row (Mark Complete)</button>'
        
        collapse_button_html = f'<div class="mb-3 d-flex gap-2" id="buttonContainer_{index}">{buttons_html}</div>'
          # Populate the rowDataHTML column with the HTML content
        row_html_content = convertRowDataToHTML(row, nvdSourceData, index)
        result_df.at[index, 'rowDataHTML'] = collapse_button_html + row_html_content
        
        # Create the main HTML div with all data attributes and a unique ID
        if 'trimmedCPEsQueryData' in row.index and pd.notna(row['trimmedCPEsQueryData']):
            sortedCPEsQueryData = row['trimmedCPEsQueryData'] 
            
            # Determine if matches table is empty to decide if provenance div should be expanded
            # trimmedCPEsQueryData should be a dictionary, check if it has entries
            if isinstance(sortedCPEsQueryData, dict):
                has_matches = len(sortedCPEsQueryData) > 0
            elif hasattr(sortedCPEsQueryData, '__len__'):
                has_matches = len(sortedCPEsQueryData) > 0
            else:
                has_matches = False
            
            attr_string = " ".join(data_attrs)
            html_content = f"""<div id="cpe-query-container-{index}" class="cpe-query-container" {attr_string}>"""
            
            # Add provenance assistance div ABOVE the matches table and ONLY for non-NVD rows
            if 'sourceRole' in row.index and not pd.isna(row['sourceRole']) and str(row['sourceRole']) != 'NVD':
                provenance_div = create_provenance_assistance_div(index, collapsed=has_matches)
                html_content += provenance_div
            # Add custom CPE Builder section between provenance assistance and CPE suggestions
            customCPEBuilderHTML = create_custom_cpe_builder_div(index, collapsed=has_matches)
            html_content += customCPEBuilderHTML
            
            # Add the matches table after the custom CPE Builder div
            # Always create the table structure, even if empty, so Custom CPE Builder can add rows
            if has_matches:
                html_content += convertCPEsQueryDataToHTML(sortedCPEsQueryData, index, row)
            else:
                # No CPE query results - create empty table structure for Custom CPE Builder
                html_content += create_empty_matches_table(index)
            
            html_content += "</div>"  # Close the container div
            result_df.at[index, 'cpeQueryHTML'] = html_content
        
        # Store settings HTML for this table
        table_id = f"matchesTable_{index}"
        raw_platform_data = row.get('rawPlatformData', {})
        store_json_settings_html(table_id, raw_platform_data)
    
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
        logger.error(f"CSS file loading failed: Unable to read CSS file '{css_file}' - {e}", group="page_generation")
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
        <h1>{TOOLNAME}<small> - version: {VERSION}</small></h1>
    </div>
    {globalCVEMetadataHTML}
    """
    
    # Rest of the function remains unchanged
    # <button class="tablinks" onclick="openCity(event, 'vdbIntelDashboard')">VDB Intel Dashboard</button>
    pageBodyTabsHTML = """
    <!-- Tab links -->
    <div class="tab">
        <button class="tablinks" onclick="openCity(event, 'cveListCPESuggester')">CVE List CPE Suggester</button>
    </div>
    """
    
    # Updated cveIdIndicatorHTML without the inline JavaScript
    cveIdIndicatorHTML = f"""
    <div class="d-flex align-items-center justify-content-between" style="margin-left: 10px; margin-right: 10px;">
        <h3 id="cve-id" style="margin-bottom: 0px;"><b>{targetCve}</b></h3>
        <span id="generationTimestamp" class="text-muted">Generated: <time datetime="{utc_timestamp}"></time></span>
    </div>
    <hr style="margin: 10px; border: 1px solid;">
    """
    
    # Updated pageBodyCPESuggesterHTML without the inline JavaScript
    pageBodyCPESuggesterHTML = f"""
    <!-- CPE Applicability Generator -->
    <div id="cveListCPESuggester" class="tabcontent" style="display: block; border-left: 0px;">
        <div id="cpeSuggesterHeader" class="header">
            <h3>CPE Applicability Generator</h3>
        </div>
        {affectedHtml}
        <script>
            // Initialize the timestamp handler with the generated timestamp
            window.timestampHandler.init("{utc_timestamp}");
        </script>
    </div>
    """
    
    #if (vdbIntelHtml is None):
    #    pageBodyVDBIntelHTML = """
    #    <!-- VDB Intel Dashboard -->
    #    <div id="vdbIntelDashboard" class="tabcontent" style="border-left: 0px;">
    #        <h3>VDB Intel Dashboard</h3>
    #        <p>Basic User Mode does not support VDB Intel Check!</p>
    #    </div>
    #    """
    #else:
    #    pageBodyVDBIntelHTML = f"""
    #    <!-- VDB Intel Dashboard -->
    #    <div id="vdbIntelDashboard" class="tabcontent" style="border-left: 0px;">
    #        <h3>VDB Intel Dashboard</h3>
    #        {vdbIntelHtml}
    #    </div>
    #    """
        
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
                pageBodyCPESuggesterHTML + pageEndHTML)
    
    # Log file size information to help detect bloat
    html_size = len(fullHtml)
    if html_size > 1000000:  # 1MB threshold
        logger.warning(f"Large HTML file generated for {targetCve}: {html_size:,} bytes ({html_size/1024/1024:.1f}MB)", group="page_generation")
    elif html_size > 500000:  # 500KB threshold
        logger.info(f"Medium HTML file generated for {targetCve}: {html_size:,} bytes ({html_size/1024:.1f}KB)", group="page_generation")
    
    return fullHtml

def create_provenance_assistance_div(index, collapsed=True):
    """Creates a collapsible div for Provenance Assistance
    
    Args:
        index: The row index for unique IDs
        collapsed: Whether the div should be collapsed by default
    """
    collapse_class = "collapse" if collapsed else "collapse show"
    
    # Use simple HTML arrows
    arrow_icon = "&darr;" if collapsed else "&uarr;"
    
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
                <!-- Main container for all provenance elements -->
                <div class="d-flex flex-row flex-wrap gap-3">
                    <!-- Provenance links -->
                    <div id="provenanceLinks_{index}" class="provenance-links">
                        <!-- Link cards will be populated via JavaScript -->
                    </div>
                    
                    <!-- Description buttons -->
                    <div id="descriptionButtons_{index}" class="description-buttons">
                        <!-- Buttons will be populated via JavaScript -->
                    </div>
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


def create_custom_cpe_builder_div(index, collapsed=True):
    """Creates a collapsible div for Custom CPE Builder
    
    Args:
        index: The row index for unique IDs
        collapsed: Whether the div should be collapsed by default
    """
    collapse_class = "collapse" if collapsed else "collapse show"
    
    # Use simple HTML arrows
    arrow_icon = "&darr;" if collapsed else "&uarr;"
    
    html = f"""
    <div class="card mb-3">
        <div class="card-header d-flex justify-content-between align-items-center" 
             id="customCPEBuilderHeader_{index}" 
             data-bs-toggle="collapse" 
             data-bs-target="#customCPEBuilderCollapse_{index}" 
             style="cursor: pointer;">
            <h5 class="mb-0">
                Custom CPE Builder
            </h5>
            <span class="arrow-icon">{arrow_icon}</span>
        </div>
        <div id="customCPEBuilderCollapse_{index}" class="{collapse_class}" aria-labelledby="customCPEBuilderHeader_{index}">
            <div class="card-body">
                <div id="customCPEBuilder-content-{index}" class="customCPEBuilder">
                    <!-- Content will be populated by custom_cpe_builder.js -->
                </div>
            </div>
        </div>
    </div>
    """
    
    return html.replace('\n', '')

def create_json_generation_settings_html(table_id, settings=None):
    """Creates settings HTML with intelligent defaults and detailed tooltips"""
    
    # Helper function to determine if checkbox should be checked
    def checked(setting_name):
        if settings and setting_name in settings:
            return 'checked' if settings[setting_name] else ''
        return 'checked'  # Default to checked if no specific setting
    
    html = f"""
    <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center" 
             style="cursor: pointer;"
             data-bs-toggle="collapse" 
             data-bs-target="#settingsCollapse_{table_id}">
            <h6 class="mb-0">
                <i class="fas fa-cog"></i> JSON Generation Settings
            </h6>
            <span class="arrow-icon">&uarr;</span>
        </div>
        <div id="settingsCollapse_{table_id}" class="collapse">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6 class="text-muted mb-2">Processing Features</h6>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableWildcards_{table_id}" 
                                   data-setting="enableWildcardExpansion"
                                   data-table-id="{table_id}" 
                                   {checked('enableWildcardExpansion')}>
                            <label class="form-check-label" for="enableWildcards_{table_id}" 
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Converts wildcard patterns into version ranges. For example, '5.4.*' becomes a range from '5.4.0' to '5.5.0' (exclusive). Useful when version data contains wildcard patterns that need to be expanded into precise ranges for matching.">
                                <small>Expand Wildcards 
                                    <span class="text-muted">(5.4.* → ranges)</span>
                                    <span class="feature-indicator" data-feature="hasWildcards"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableGaps_{table_id}" 
                                   data-setting="enableGapProcessing"
                                   data-table-id="{table_id}" 
                                   {checked('enableGapProcessing')}>
                            <label class="form-check-label" for="enableGaps_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Fills gaps between unaffected version ranges by inferring affected versions. For example, if 1.0-2.0 and 4.0-5.0 are unaffected, it infers that 2.1-3.9 is affected. Particularly useful when vulnerability data specifies what's NOT affected rather than what IS affected.">
                                <small>Fill Gaps 
                                    <span class="text-muted">(infer affected ranges)</span>
                                    <span class="feature-indicator" data-feature="hasGapProcessing"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enablePatches_{table_id}" 
                                   data-setting="enableVersionChanges"
                                   data-table-id="{table_id}" 
                                   {checked('enableVersionChanges')}>
                            <label class="form-check-label" for="enablePatches_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Processes version.changes arrays to extract patch and fix information. For example, if a version has changes: [status: 'fixed', at: '1.2.3'], it creates a vulnerable range from the base version up to (but not including) the fix version. Essential for handling detailed patching timelines.">
                                <small>Process Patches 
                                    <span class="text-muted">(version.changes)</span>
                                    <span class="feature-indicator" data-feature="hasVersionChanges"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableSpecialTypes_{table_id}" 
                                   data-setting="enableSpecialVersionTypes"
                                   data-table-id="{table_id}" 
                                   {checked('enableSpecialVersionTypes')}>
                            <label class="form-check-label" for="enableSpecialTypes_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Handles non-standard version types beyond semantic versioning. Examples include date-based versions (20231201), commit hashes (abc123def), custom version schemes, or version types marked with special versionType fields. Required when dealing with diverse software versioning schemes.">
                                <small>Special Version Types 
                                    <span class="text-muted">(dates, commits)</span>
                                    <span class="feature-indicator" data-feature="hasSpecialVersionTypes"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableMultipleBranches_{table_id}" 
                                   data-setting="enableMultipleBranches"
                                   data-table-id="{table_id}" 
                                   {checked('enableMultipleBranches')}>
                            <label class="form-check-label" for="enableMultipleBranches_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Handles products with multiple version families or branches (≥3 major.minor combinations). For example, a product with versions 1.0.x, 2.1.x, 3.0.x, and 4.2.x has multiple branches. Groups and processes each branch separately to handle complex version trees with parallel development streams.">
                                <small>Multiple Branches 
                                    <span class="text-muted">(≥3 version families)</span>
                                    <span class="feature-indicator" data-feature="hasMultipleBranches"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableUpdatePatterns_{table_id}" 
                                   data-setting="enableUpdatePatterns"
                                   data-table-id="{table_id}" 
                                   {checked('enableUpdatePatterns')}>
                            <label class="form-check-label" for="enableUpdatePatterns_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Recognizes and processes update patterns in version strings. Handles formats like '3.1.0 p7' (patch 7), '2.0.0 sp1' (service pack 1), '1.0.0-hotfix.2', or '4.0 update 3'. Transforms these into proper CPE format with update components for accurate vulnerability matching.">
                                <small>Update Pattern Processing 
                                    <span class="text-muted">(patch, service pack, hotfix)</span>
                                    <span class="feature-indicator" data-feature="hasUpdatePatterns"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <h6 class="text-muted mb-2">Status Processing</h6>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableInverseStatus_{table_id}" 
                                   data-setting="enableInverseStatus"
                                   data-table-id="{table_id}" 
                                   {checked('enableInverseStatus')}>
                            <label class="form-check-label" for="enableInverseStatus_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Handles cases where defaultStatus='unaffected' with explicit affected entries. Instead of assuming all versions are vulnerable, it processes only the specifically marked affected versions while treating everything else as unaffected. Common in advisories that list specific vulnerable versions.">
                                <small>Inverse Status 
                                    <span class="text-muted">(default unaffected)</span>
                                    <span class="feature-indicator" data-feature="hasInverseStatus"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableMixedStatus_{table_id}" 
                                   data-setting="enableMixedStatus"
                                   data-table-id="{table_id}" 
                                   {checked('enableMixedStatus')}>
                            <label class="form-check-label" for="enableMixedStatus_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Handles complex scenarios with both affected and multiple unaffected versions in the same dataset. Processes mixed status combinations where some versions are explicitly marked as affected while others are marked as unaffected. Useful for complex vulnerability patterns with scattered affected versions.">
                                <small>Mixed Status 
                                    <span class="text-muted">(multiple unaffected)</span>
                                    <span class="feature-indicator" data-feature="hasMixedStatus"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """
    
    return html.replace('\n', '')

# Store generated settings HTML for JavaScript access
JSON_SETTINGS_HTML = {}
INTELLIGENT_SETTINGS = {}

# Ensure clean state on module import
def _initialize_clean_state():
    """Initialize clean global state when module is imported"""
    global JSON_SETTINGS_HTML, INTELLIGENT_SETTINGS, GLOBAL_CPE_DATA_REGISTRY
    JSON_SETTINGS_HTML = {}
    INTELLIGENT_SETTINGS = {}
    GLOBAL_CPE_DATA_REGISTRY = {
        'references': {},
        'sortingPriority': {},
        'registered_cpes': set()
    }

# Call initialization immediately
_initialize_clean_state()

def is_cpe_data_registered(cpe_base_string, data_type):
    """
    Check if CPE data is already registered.
    
    Args:
        cpe_base_string: The CPE base string
        data_type: The type of data ('references' or 'sortingPriority')
    
    Returns:
        bool: True if already registered
    """
    global GLOBAL_CPE_DATA_REGISTRY
    
    base_key_safe = cpe_base_string.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_").replace("*", "star")
    return base_key_safe in GLOBAL_CPE_DATA_REGISTRY[data_type]

def clear_global_html_state():
    """Clear global HTML generation state to prevent accumulation between CVE processing runs"""
    global JSON_SETTINGS_HTML, INTELLIGENT_SETTINGS
    
    # Log statistics before clearing (for debugging bloat issues)
    if JSON_SETTINGS_HTML:
        logger.debug(f"Clearing HTML state: {len(JSON_SETTINGS_HTML)} JSON settings entries", group="page_generation")
    
    # Clear badge and modal registries (now handled by external module)
    clear_all_registries()
    
    # Reinitialize local HTML state
    JSON_SETTINGS_HTML = {}
    INTELLIGENT_SETTINGS = {}
    
    logger.debug("Cleared global HTML state and badge/modal registries", group="page_generation")

def analyze_data_for_smart_defaults(raw_platform_data):
    """Analyze platform data to determine intelligent defaults for JSON generation settings"""
    # Default settings - start with most common configuration
    settings = {
        'enableWildcardExpansion': True,
        'enableVersionChanges': False,
        'enableSpecialVersionTypes': True,
        'enableInverseStatus': False,
        'enableMultipleBranches': False,
        'enableMixedStatus': False,
        'enableGapProcessing': True,
        'enableUpdatePatterns': False
    }
    
    # For now, return consistent settings for all tables to enable template deduplication
    # TODO: Add intelligent analysis based on raw_platform_data content
    return settings

def store_json_settings_html(table_id, raw_platform_data=None):
    """Store the JSON settings HTML for a table with intelligent defaults"""
    global JSON_SETTINGS_HTML, INTELLIGENT_SETTINGS
    
    # Ensure global dictionaries exist and are initialized
    if 'JSON_SETTINGS_HTML' not in globals() or JSON_SETTINGS_HTML is None:
        JSON_SETTINGS_HTML = {}
    if 'INTELLIGENT_SETTINGS' not in globals() or INTELLIGENT_SETTINGS is None:
        INTELLIGENT_SETTINGS = {}
    
    # Analyze data to determine which checkboxes should be checked
    settings = analyze_data_for_smart_defaults(raw_platform_data) if raw_platform_data else {
        'enableWildcardExpansion': True,
        'enableVersionChanges': False,
        'enableSpecialVersionTypes': True,
        'enableInverseStatus': False,
        'enableMultipleBranches': False,
        'enableMixedStatus': False,
        'enableGapProcessing': True,
        'enableUpdatePatterns': False
    }
    
    # Check if we already have identical settings registered to prevent bloat
    settings_json = json.dumps(settings, sort_keys=True)
    for existing_table_id, existing_settings in INTELLIGENT_SETTINGS.items():
        if json.dumps(existing_settings, sort_keys=True) == settings_json:
            # Settings are identical, skip HTML generation to reduce bloat
            logger.debug(f"Skipping identical settings HTML for {table_id} (matches {existing_table_id})", group="page_generation")
            return
    
    # Store the HTML
    JSON_SETTINGS_HTML[table_id] = create_json_generation_settings_html(table_id, settings)
    
    # Store intelligent settings for JavaScript
    INTELLIGENT_SETTINGS[table_id] = settings


