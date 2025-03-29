# Import Python dependencies
import pandas as pd
from sys import exit
from build_info import VERSION, TOOLNAME

# Import Analysis Tool 
import processData


def convertRowDataToHTML(row, nvdSourceData: pd.DataFrame, tableIndex=0) -> str:
    has_cpe_array_content = bool(row.get('hasCPEArray', False))

    # Add ID to the table based on the index
    html = f"<table id=\"rowDataTable_{tableIndex}\" class=\"table table-hover\">"
    
    # Define the keys and their labels, ensuring rawPlatformData is last
    keys_and_labels = [
        ('dataSource', 'Data Source'),
        ('sourceID', 'Source ID'),
        ('sourceRole', 'Source Role'),
        ('platformFormatType', 'Platform Format Type'),
        ('rawPlatformData', 'Raw Platform Data')
    ]
    
    for key, label in keys_and_labels:
        if key in row:
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
                html += f"""
                <tr>
                    <td>{label}</td>
                    <td><details><summary>Review rawPlatformData</summary><code>{value}</code></details></td>
                </tr>
                """
            elif key == 'platformFormatType':
                if has_cpe_array_content:
                    tooltip_content = "CPE Array Included"
                    value += f" <span title=\"{tooltip_content}\">  &#10003;</span>"
                html += f"""
                <tr>
                    <td>{label}</td>
                    <td>{value}</td>
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
    return """
    <script>
    // Track selected rows per table
    const tableSelections = new Map(); // Map<tableId, Set<cpeBase>>
    const consolidatedJsons = new Map(); // Map<tableId, json>
    
    // Function to toggle row collapse state
    function toggleRowCollapse(tableIndex) {
        const rowDataTable = document.getElementById(`rowDataTable_${tableIndex}`);
        const matchesTable = document.getElementById(`matchesTable_${tableIndex}`);
        const jsonContainer = document.querySelector(`.consolidated-json-container[data-index="${tableIndex}"]`);
        const collapseButton = document.getElementById(`collapseRowButton_${tableIndex}`);
        
        if (rowDataTable && matchesTable) {
            // Toggle visibility
            const isCollapsed = rowDataTable.classList.toggle('d-none');
            matchesTable.classList.toggle('d-none');
            if (jsonContainer) jsonContainer.classList.toggle('d-none');
            
            // Update button text
            if (collapseButton) {
                collapseButton.textContent = isCollapsed ? 'Expand Row (Completed)' : 'Collapse Row (Mark Complete)';
                collapseButton.classList.toggle('btn-success', isCollapsed);
                collapseButton.classList.toggle('btn-secondary', !isCollapsed);
            }
        }
    }
    
    // Add event listeners when the DOM is fully loaded
    document.addEventListener('DOMContentLoaded', function() {
        // Add a master "Export All Configurations" button at the top of cveListCPESuggester
        const cveListCPESuggester = document.getElementById('cveListCPESuggester');
        if (cveListCPESuggester) {
            // Create the Export All container at the beginning
            const allContainer = document.createElement('div');
            allContainer.classList.add('all-configurations-container', 'mt-3', 'mb-5');
            allContainer.id = 'allConfigurationsContainer';
            allContainer.innerHTML = `
                <div class="d-grid gap-2 col-12 mx-auto">
                    <button id="exportAllConfigurations" class="btn btn-danger">Export All Configurations</button>
                </div>
                <div id="allConfigurationsDisplay" class="mt-3" style="display: none;">
                    <h4>Complete Configuration JSON</h4>
                    <p class="text-muted">This combines all selected CPEs from all tables, with each table creating its own configuration node.</p>
                    <pre id="allConfigurationsContent" style="max-height: 600px; overflow-y: auto; background: #f8f9fa; padding: 15px; border-radius: 5px;"></pre>
                </div>
            `;
            
            // Insert at the beginning of cveListCPESuggester
            if (cveListCPESuggester.firstChild) {
                cveListCPESuggester.insertBefore(allContainer, cveListCPESuggester.firstChild.nextSibling);
            } else {
                cveListCPESuggester.appendChild(allContainer);
            }
            
            // Add click handler to the Export All button
            document.getElementById('exportAllConfigurations').addEventListener('click', function() {
                const display = document.getElementById('allConfigurationsDisplay');
                const content = document.getElementById('allConfigurationsContent');
                
                if (display && content) {
                    // Create master JSON with configurations from all tables
                    const masterJson = generateAllConfigurationsJson();
                    
                    if (!masterJson || !masterJson.configurations || masterJson.configurations.length === 0) {
                        content.textContent = 'No CPEs selected in any table. Please select at least one CPE row.';
                    } else {
                        content.textContent = JSON.stringify(masterJson, null, 2);
                    }
                    
                    // Toggle display
                    display.style.display = display.style.display === 'none' ? 'block' : 'none';
                    this.textContent = display.style.display === 'none' ? 'Export All Configurations' : 'Hide All Configurations';
                }
            });
        }

        // Find all matchesTables (there may be multiple)
        const tables = document.querySelectorAll('table[id^="matchesTable"]');
        
        tables.forEach((table, tableIndex) => {
            const tableId = table.id;
            
            // Initialize selections for this table
            tableSelections.set(tableId, new Set());
            
            // Add click handlers to all CPE rows in this table
            const rows = table.querySelectorAll('.cpe-row');
            rows.forEach(function(row) {
                row.addEventListener('click', function(event) {
                    // Get data attributes
                    const cpeBase = this.getAttribute('data-cpe-base');
                    
                    // Get selections for this table
                    const selectedRows = tableSelections.get(tableId);
                    
                    // Check if this row is already active (selected)
                    const isAlreadyActive = this.classList.contains('table-active');
                    
                    // Handle row selection based on whether Ctrl/Cmd key is pressed
                    if (event.ctrlKey || event.metaKey) {
                        // Toggle this row only, without affecting other selections
                        if (isAlreadyActive) {
                            this.classList.remove('table-active');
                            selectedRows.delete(cpeBase);
                        } else {
                            this.classList.add('table-active');
                            selectedRows.add(cpeBase);
                        }
                    } else {
                        // No modifier key: toggle this row only if it's the only one selected
                        if (isAlreadyActive && selectedRows.size === 1 && selectedRows.has(cpeBase)) {
                            // If only this row is selected, toggle it off
                            this.classList.remove('table-active');
                            selectedRows.delete(cpeBase);
                        } else {
                            // If clicking a new row or multiple rows are selected, just select this one
                            if (!isAlreadyActive) {
                                // Clear other selections only if not using modifier key
                                rows.forEach(r => {
                                    if (r !== this && r.classList.contains('table-active')) {
                                        r.classList.remove('table-active');
                                    }
                                });
                                
                                // Select this row
                                this.classList.add('table-active');
                                selectedRows.clear();
                                selectedRows.add(cpeBase);
                            }
                        }
                    }
                    
                    // Update consolidated JSON display for this table
                    updateConsolidatedJson(tableId);
                    
                    // Ensure the master export button is properly displayed
                    updateExportAllButton();
                });
            });
            
            // Add a container for consolidated JSON right after this table
            const container = document.createElement('div');
            container.classList.add('consolidated-json-container', 'mt-3', 'mb-4');
            container.setAttribute('data-index', tableIndex); // Add this line
            container.innerHTML = `
                <button id="showConsolidatedJson_${tableId}" class="btn btn-primary">Show Consolidated JSON</button>
                <div id="consolidatedJsonDisplay_${tableId}" class="mt-3" style="display: none;">
                    <h4>Consolidated Configuration JSON</h4>
                    <pre id="consolidatedJsonContent_${tableId}" style="max-height: 400px; overflow-y: auto; background: #f8f9fa; padding: 15px; border-radius: 5px;"></pre>
                </div>
            `;
            
            // Place the container directly after the table
            table.parentNode.insertBefore(container, table.nextSibling);
            
            // Add click handler to the button
            document.getElementById(`showConsolidatedJson_${tableId}`).addEventListener('click', function() {
                const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
                const content = document.getElementById(`consolidatedJsonContent_${tableId}`);
                
                if (display && content) {
                    const selectedRows = tableSelections.get(tableId);
                    
                    if (!selectedRows || selectedRows.size === 0) {
                        content.textContent = 'No rows selected. Please select at least one row.';
                    } else {
                        // Get the consolidated JSON for this table
                        const json = consolidatedJsons.get(tableId);
                        content.textContent = JSON.stringify(json, null, 2);
                    }
                    
                    // Toggle display
                    display.style.display = display.style.display === 'none' ? 'block' : 'none';
                    this.textContent = display.style.display === 'none' ? 'Show Consolidated JSON' : 'Hide Consolidated JSON';
                }
            });
        });
        
        // Initial update of Export All button visibility
        updateExportAllButton();
    });
    
    // Modify the updateConsolidatedJson function to also update button text:
    function updateConsolidatedJson(tableId) {
        const selectedRows = tableSelections.get(tableId);
        
        if (!selectedRows || selectedRows.size === 0) {
            consolidatedJsons.set(tableId, null);
            
            // Update the button text to show "Show Consolidated JSON" when no rows are selected
            const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
            if (showButton) {
                showButton.textContent = "Show Consolidated JSON";
            }
            
            // Hide the display if it's currently visible
            const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
            if (display && display.style.display !== 'none') {
                display.style.display = 'none';
            }
            
            return;
        }
        
        // Extract the table index from tableId (e.g. "matchesTable_0" -> "0")
        const tableIndex = tableId.split('_')[1];
        
        // Look specifically for the corresponding rowDataTable with the same index
        const rowDataTableId = `rowDataTable_${tableIndex}`;
        const rowDataTable = document.getElementById(rowDataTableId);
        
        let dataSource = "Unknown";
        let sourceId = "Unknown";
        let sourceRole = "Unknown";
        
        if (rowDataTable) {
            const rows = rowDataTable.getElementsByTagName('tr');
            
            // Scan through all rows in this specific table
            for (let i = 0; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                if (cells.length >= 2) {
                    const labelCell = cells[0];
                    const valueCell = cells[1];
                    
                    if (labelCell.textContent.includes("Data Source")) {
                        dataSource = valueCell.textContent.trim();
                    }
                    else if (labelCell.textContent.includes("Source ID")) {
                        // Extract just the UUID part if there's more text
                        const sourceIdText = valueCell.textContent.trim();
                        const uuidMatch = sourceIdText.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
                        if (uuidMatch) {
                            sourceId = uuidMatch[0];
                        } else {
                            sourceId = sourceIdText;
                        }
                    }
                    else if (labelCell.textContent.includes("Source Role")) {
                        sourceRole = valueCell.textContent.trim();
                    }
                }
            }
        }
        
        // Create configurations structure with proper array format
        const json = {
            "configurations": [
                {
                    "operator": "OR",
                    "negate": false,
                    "cpeMatch": [],
                    // Add generatedFromSource at the configuration level
                    "generatedFromSource": {
                        "dataSource": dataSource,
                        "sourceId": sourceId,
                        "sourceRole": sourceRole
                    }
                }
            ]
        };
        
        // Add each selected CPE to the cpeMatch array
        selectedRows.forEach(cpeBase => {
            const cpeMatch = createCpeMatchObject(cpeBase);
            json.configurations[0].cpeMatch.push(cpeMatch);
        });
        
        // Store the consolidated JSON for this table
        consolidatedJsons.set(tableId, json);
        
        // Update button text if the display is visible
        const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
        const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
        
        if (display && showButton && display.style.display !== 'none') {
            showButton.textContent = "Hide Consolidated JSON";
        }
    }
    
    function updateExportAllButton() {
        // Check if any tables have selected rows
        let hasSelections = false;
        tableSelections.forEach((selections) => {
            if (selections.size > 0) {
                hasSelections = true;
            }
        });
        
        // Show/hide the Export All button container based on whether there are selections
        const container = document.getElementById('allConfigurationsContainer');
        if (container) {
            container.style.display = hasSelections ? 'block' : 'none';
        }
    }
    
    function generateAllConfigurationsJson() {
        // Create master JSON with all configurations
        const masterJson = {
            "configurations": []
        };
        
        // Add each table's configuration as a separate node in the configurations array
        consolidatedJsons.forEach((json, tableId) => {
            if (json && json.configurations && json.configurations.length > 0) {
                // Each configuration from a table should retain its generatedFromSource
                json.configurations.forEach(config => {
                    // Make sure we're including the generatedFromSource in each configuration
                    if (config.generatedFromSource) {
                        // It's already at the right level
                        masterJson.configurations.push(config);
                    } else {
                        // If it's missing (shouldn't happen with our code), add empty placeholder
                        config.generatedFromSource = {
                            "dataSource": "Unknown",
                            "sourceId": "Unknown",
                            "sourceRole": "Unknown"
                        };
                        masterJson.configurations.push(config);
                    }
                });
            }
        });
        
        return masterJson;
    }
    
    function createCpeMatchObject(cpeBase) {
        // Create a cpeMatch object for the given CPE base string
        const cpeMatch = {
            "criteria": cpeBase,
            "matchCriteriaId": "generated_" + Math.random().toString(36).substr(2, 9),
            "vulnerable": true
        };
        
        return cpeMatch;
    }
    </script>
    """

# Fix the collapse button in update_cpeQueryHTML_column - remove newlines
def update_cpeQueryHTML_column(primaryDataframe, nvdSourceData) -> pd.DataFrame:
    for index, row in primaryDataframe.iterrows():
        
        # Create a collapse button for this row - as a single line to avoid extra whitespace
        collapse_button_html = f'<div class="mb-3"><button id="collapseRowButton_{index}" class="btn btn-secondary" onclick="toggleRowCollapse({index})">Collapse Row (Mark Complete)</button></div>'
        
        # Populate the rowDataHTML column with the HTML content
        row_html_content = convertRowDataToHTML(row, nvdSourceData, index)
        primaryDataframe.at[index, 'rowDataHTML'] = collapse_button_html + row_html_content
        
        # Populate the cpeQueryHTML column with HTML content
        sortedCPEsQueryData = row['trimmedCPEsQueryData'] 
        html_content = convertCPEsQueryDataToHTML(sortedCPEsQueryData, index)
        primaryDataframe.at[index, 'cpeQueryHTML'] = html_content

    return primaryDataframe

# Builds a simple html page with Bootstrap styling
def buildHTMLPage(affectedHtml, targetCve, vdbIntelHtml=None):
    pageStartHTML = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">
        <style>
            .bg-pivot {
                --bs-bg-opacity: 1;
                background-color: rgb(181, 90, 232) !important;
            }
            .tab {
                overflow: hidden;
                border: 1px solid #ccc;
                background-color: #f1f1f1;
            }
            .tab button {
                background-color: inherit;
                float: left;
                border: none;
                outline: none;
                cursor: pointer;
                padding: 14px 16px;
                transition: 0.3s;
            }
            .tab button:hover {
                background-color: #ddd;
            }
            .tab button.active {
                background-color: #ccc;
            }
            .tabcontent {
                display: none;
                margin-left: 10px;
                border: 1px solid #ccc;
                border-top: none;
            }
            table.dataframe {
                table-layout: fixed;
                width: 100%;
            }
            table.dataframe td:first-child {
                width: 20%;
            }
            table.dataframe td:last-child {
                width: 80%;
            }
            /* Fix for the table row selection styling */
            .table-active,
            .table-active > td,
            .table-active > th {
                background-color: rgba(0, 123, 255, 0.35) !important;  /* Clearly visible blue */
            }
            .table-hover tbody tr:hover:not(.table-active) {
                background-color: rgba(0, 0, 0, 0.075) !important;  /* Light gray for hover */
            }
            /* Ensure selected trumps hover */
            .table-hover tbody tr.table-active:hover {
                background-color: rgba(0, 123, 255, 0.45) !important;  /* Slightly darker blue when hovering selected row */
            }
            /* Add pointer cursor to rows that can be selected */
            .cpe-row {
                cursor: pointer;
            }
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
    pageBodyJavaScript = """
    <script>
        function openCity(evt, cityName) {
            // Declare all variables
            var i, tabcontent, tablinks;

            // Get all elements with class="tabcontent" and hide them
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }

            // Get all elements with class="tablinks" and remove the class "active"
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }

            // Show the current tab, and add an "active" class to the button that opened the tab
            document.getElementById(cityName).style.display = "block";
            evt.currentTarget.className += " active";
        }
    </script>
    """
    pageEndHTML = "</body></html>"
    fullHtml = (pageStartHTML + pageBodyHeaderHTML + pageBodyTabsHTML + cveIdIndicatorHTML + pageBodyCPESuggesterHTML + pageBodyVDBIntelHTML + pageBodyJavaScript + getCPEJsonScript() + pageEndHTML)
    
    return fullHtml