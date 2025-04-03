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
    
    // Add CSS for better row selection visibility
    const style = document.createElement('style');
    style.textContent = `
        .table-active {
            background-color: rgba(0, 123, 255, 0.35) !important;
            font-weight: bold;
            border-left: 3px solid #007bff;
        }
        .json-container {
            transition: all 0.3s ease-in-out;
        }
        .btn-success {
            transition: background-color 0.3s ease;
        }
    `;
    document.head.appendChild(style);
    
    // Function to toggle row collapse state
    function toggleRowCollapse(tableIndex) {
        try {
            const rowDataTable = document.getElementById(`rowDataTable_${tableIndex}`);
            const matchesTable = document.getElementById(`matchesTable_${tableIndex}`);
            const jsonContainer = document.querySelector(`.consolidated-json-container[data-index="${tableIndex}"]`);
            const collapseButton = document.getElementById(`collapseRowButton_${tableIndex}`);
            const tableId = `matchesTable_${tableIndex}`; 
            
            // Define isCollapsed variable outside the if block
            let isCollapsed = false;
            
            if (rowDataTable && matchesTable) {
                // Toggle visibility for tables
                isCollapsed = rowDataTable.classList.toggle('d-none');
                matchesTable.classList.toggle('d-none');
                
                // Always ensure the JSON container is in the right place
                // regardless of collapsed state
                if (jsonContainer && collapseButton) {
                    // Get the parent of the collapse button
                    const buttonParent = collapseButton.parentNode;
                    
                    // Always move the JSON container to be adjacent to the button
                    buttonParent.parentNode.insertBefore(jsonContainer, buttonParent.nextSibling);
                    
                    // Add some spacing for better visual separation
                    jsonContainer.classList.add('mt-2');
                    
                    // IMPORTANT: Update the consolidated JSON button to maintain selection count
                    const selectedRows = tableSelections.get(tableId);
                    const selectionCount = selectedRows ? selectedRows.size : 0;
                    
                    // Find the consolidated JSON button
                    const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
                    const altShowButton = document.getElementById(`showConsolidatedJson_matchesTable_${tableIndex}`);
                    const buttonToUpdate = showButton || altShowButton;
                    
                    // Update the button text to maintain selection count
                    if (buttonToUpdate) {
                        // Check if display is visible
                        const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
                        const isVisible = display && display.style.display !== 'none';
                        
                        // ADDED: Make sure we're seeing consistent behavior between the display and button
                        if (isVisible && display.style.display !== 'block') {
                            display.style.display = 'block';
                        }
                        
                        if (selectionCount > 0) {
                            buttonToUpdate.textContent = isVisible 
                                ? `Hide Consolidated JSON (${selectionCount} selected)` 
                                : `Show Consolidated JSON (${selectionCount} selected)`;
                        } else {
                            buttonToUpdate.textContent = isVisible 
                                ? `Hide Consolidated JSON` 
                                : `Show Consolidated JSON`;
                        }
                        
                        // ADDED: Ensure button styling matches display state
                        if (isVisible) {
                            buttonToUpdate.classList.remove('btn-primary');
                            buttonToUpdate.classList.add('btn-success');
                        } else {
                            buttonToUpdate.classList.remove('btn-success');
                            buttonToUpdate.classList.add('btn-primary');
                        }
                    }
                    
                    // Also update the display content if it's visible
                    updateJsonDisplayIfVisible(tableId);
                }
                
                // Update button text
                if (collapseButton) {
                    collapseButton.textContent = isCollapsed ? 'Expand Row (Completed)' : 'Collapse Row (Mark Complete)';
                    collapseButton.classList.toggle('btn-success', isCollapsed);
                    collapseButton.classList.toggle('btn-secondary', !isCollapsed);
                }
            }
            // Define variables before using them in console.debug
            const selectedRows = tableSelections.get(tableId) || new Set();
            const selectionCount = selectedRows.size;
            
            // Get display visibility state
            const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
            const isVisible = display && display.style.display !== 'none';
            
            console.debug(`Table ${tableId} collapsed: ${isCollapsed}, Selection count: ${selectionCount}, JSON visible: ${isVisible}`);
            // Update the completion tracker
            updateCompletionTracker();
            // Update the export all configurations button text
            updateExportAllButton();
            
            // NEW LINE: Preserve JSON display state
            preserveJsonDisplayState(tableIndex);
        } catch(e) {
            console.error(`Error in toggleRowCollapse for tableIndex ${tableIndex}:`, e);
        }
    }
    
    // Add event listeners when the DOM is fully loaded
    document.addEventListener('DOMContentLoaded', function() {
        try {
            // Find all matchesTables (there may be multiple) - MOVED UP FROM BELOW
            const tables = document.querySelectorAll('table[id^="matchesTable"]');
            
            // Add a master "Export All Configurations" button at the top of cveListCPESuggester
            const cveListCPESuggester = document.getElementById('cveListCPESuggester');
            if (cveListCPESuggester) {
                // Create the Export All container at the beginning
                const allContainer = document.createElement('div');
                allContainer.classList.add('all-configurations-container', 'mt-3', 'mb-5');
                allContainer.id = 'allConfigurationsContainer';
                allContainer.innerHTML = `
                    <!-- NEW: Add configuration summary above the button -->
                    <div id="configurationSummary" class="text-center mb-2" style="font-weight: 500;"></div>
                    <div class="d-grid gap-2 col-12 mx-auto">
                        <button id="exportAllConfigurations" class="btn btn-danger">Show All Configurations</button>
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
                        
                        // Update the button text to reflect current state (without configuration details)
                        this.textContent = display.style.display === 'none' ? 'Show All Configurations' : 'Hide All Configurations';
                    }
                });
                
                // Add this to the DOMContentLoaded event handler after creating the export all container
                // Create a completion tracker container only if allContainer exists
                const completionTrackerContainer = document.createElement('div');
                completionTrackerContainer.classList.add('completion-tracker-container', 'mt-3', 'mb-3', 'p-3', 'border', 'rounded');
                completionTrackerContainer.id = 'completionTrackerContainer';
                completionTrackerContainer.innerHTML = `
                    <h4>Completion Progress</h4>
                    <div class="progress mb-2">
                        <div id="completionProgressBar" class="progress-bar bg-success" role="progressbar" style="width: 0%" 
                             aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</</div>
                    </div>
                    <div class="d-flex justify-content-between">
                        <span id="completedRowsCount">0 rows completed</span>
                        <span id="totalRowsCount">${tables.length} total rows</span>
                    </div>
                `;

                // Insert right after the export all container, using the allContainer we just created
                allContainer.parentNode.insertBefore(completionTrackerContainer, allContainer.nextSibling);

                // Initialize the completion tracker
                updateCompletionTracker();
            }

            // Rest of your code remains the same...
            tables.forEach((table, tableIndex) => {
                const tableId = table.id;
                
                // Initialize selections for this table
                tableSelections.set(tableId, new Set());
                
                // Add click handlers to all CPE rows in this table
                const rows = table.querySelectorAll('.cpe-row');
                rows.forEach(function(row) {
                    row.addEventListener('click', function(event) {
                        try {
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
                        } catch(e) {
                            console.error(`Error handling row click in table ${tableId}:`, e);
                            
                            // NEW: Update UI to show error and return to previous state
                            // This ensures the UI isn't left in an inconsistent state
                            alert(`Error processing selection. The UI has been restored to its previous state.`);
                            
                            // Force refresh selections from the current DOM state
                            const currentSelections = new Set();
                            rows.forEach(r => {
                                if (r.classList.contains('table-active')) {
                                    const cpeBase = r.getAttribute('data-cpe-base');
                                    if (cpeBase) {
                                        currentSelections.add(cpeBase);
                                    }
                                }
                            });
                            
                            // Reset the selections to match the DOM
                            tableSelections.set(tableId, currentSelections);
                            
                            // Update the button states to match the current DOM
                            updateConsolidatedJson(tableId);
                            updateExportAllButton();
                        }
                    });
                });
                
                // Add a container for consolidated JSON right after this table
                const container = document.createElement('div');
                container.classList.add('consolidated-json-container', 'mt-3', 'mb-4', 'json-container');
                container.setAttribute('data-index', tableIndex);
                container.innerHTML = `
                    <div id="consolidatedJsonDisplay_${tableId}" class="mt-3" style="display: none;">
                        <h4>Consolidated Configuration JSON</h4>
                        <pre id="consolidatedJsonContent_${tableId}" style="max-height: 400px; overflow-y: auto; background: #f8f9fa; padding: 15px; border-radius: 5px;"></pre>
                    </div>
                `;
                
                // Place the container directly after the table
                table.parentNode.insertBefore(container, table.nextSibling);
                
                // Create the consolidated JSON button and place it next to the collapse button
                const jsonButton = document.createElement('button');
                jsonButton.id = `showConsolidatedJson_${tableId}`;
                jsonButton.className = 'btn btn-primary';
                jsonButton.textContent = 'Show Consolidated JSON';

                // Find the button container and add the JSON button
                const collapseButtonContainer = document.getElementById(`buttonContainer_${tableIndex}`);
                if (collapseButtonContainer) {
                    collapseButtonContainer.appendChild(jsonButton);
                }

                // Add click handler to the button - find it first since it's already in the DOM
                const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
                if (showButton) {
                    showButton.addEventListener('click', function() {
                        try {
                            const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
                            
                            if (display) {
                                // Check if the corresponding table is collapsed
                                const matchesTable = document.getElementById(tableId);
                                const tableIndex = tableId.split('_')[1];
                                const rowDataTable = document.getElementById(`rowDataTable_${tableIndex}`);
                                const isTableCollapsed = matchesTable.classList.contains('d-none');
                                const jsonContainer = document.querySelector(`.consolidated-json-container[data-index="${tableIndex}"]`);
                                const collapseButton = document.getElementById(`collapseRowButton_${tableIndex}`);
                                
                                // Toggle display
                                const isVisible = display.style.display === 'none' ? false : true;
                                display.style.display = isVisible ? 'none' : 'block';
                                
                                // ADDED: Always ensure the JSON container is in the right place when showing
                                if (!isVisible && jsonContainer && collapseButton) {
                                    // Get the parent of the collapse button
                                    const buttonParent = collapseButton.parentNode;
                                    
                                    // Always move the JSON container to be adjacent to the button
                                    buttonParent.parentNode.insertBefore(jsonContainer, buttonParent.nextSibling);
                                    
                                    // Add some spacing for better visual separation
                                    jsonContainer.classList.add('mt-2');
                                }
                                
                                // Get selection count for button text
                                const selectedRows = tableSelections.get(tableId);
                                const selectionCount = selectedRows ? selectedRows.size : 0;
                                
                                // Update button text with count and state
                                if (selectionCount > 0) {
                                    this.textContent = isVisible ? 
                                        `Show Consolidated JSON (${selectionCount} selected)` : 
                                        `Hide Consolidated JSON (${selectionCount} selected)`;
                                } else {
                                    this.textContent = isVisible ? 'Show Consolidated JSON' : 'Hide Consolidated JSON';
                                }
                                
                                // Update content when showing
                                if (!isVisible) {
                                    updateJsonDisplayIfVisible(tableId);
                                }
                                
                                // Update button styling
                                if (!isVisible) {
                                    this.classList.remove('btn-primary');
                                    this.classList.add('btn-success');
                                } else {
                                    this.classList.remove('btn-success');
                                    this.classList.add('btn-primary');
                                }
                            }
                        } catch(e) {
                            console.error(`Error toggling JSON display for table ${tableId}:`, e);
                        }
                    });
                }
            });
            
            // Initial update of Export All button visibility
            updateExportAllButton();
            
        } catch(e) {
            console.error("Error in DOMContentLoaded event handler:", e);
        }
    });
    
    // Update JSON display if it's currently visible
    function updateJsonDisplayIfVisible(tableId) {
        try {
            const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
            const content = document.getElementById(`consolidatedJsonContent_${tableId}`);
            
            // Only update if the display is visible
            if (display && content && display.style.display !== 'none') {
                const selectedRows = tableSelections.get(tableId);
                
                if (!selectedRows || selectedRows.size === 0) {
                    content.textContent = 'No rows selected. Please select at least one row.';
                } else {
                    // Get the consolidated JSON for this table
                    const json = consolidatedJsons.get(tableId);
                    content.textContent = JSON.stringify(json, null, 2);
                }
            }
        } catch(e) {
            console.error(`Error updating JSON display for table ${tableId}:`, e);
        }
    }
    
    // Parse a CPE string to extract vendor and product information
    function parseCpeString(cpeString) {
        try {
            // For CPE 2.3 formatted strings (cpe:2.3:part:vendor:product:version:...)
            const parts = cpeString.split(':');
            if (parts.length >= 5) {
                return {
                    vendor: parts[3].toLowerCase(),
                    product: parts[4].toLowerCase()
                };
            }
            return { vendor: null, product: null };
        } catch (e) {
            console.warn("Error parsing CPE string:", e);
            return { vendor: null, product: null };
        }
    }
    
    // Create a more efficient approach to statistics generation
    function updateConsolidatedJson(tableId) {
        try {
            const selectedRows = tableSelections.get(tableId);
            
            // Early return for no selections - improves efficiency
            if (!selectedRows || selectedRows.size === 0) {
                consolidatedJsons.set(tableId, null);
                updateButton(tableId, false);
                updateJsonDisplayIfVisible(tableId);
                return;
            } else {
                updateButton(tableId, true);
            }
            
            // Gather required data only once
            const tableIndex = tableId.split('_')[1];
            const metadata = gatherTableMetadata(tableIndex);
            const selectionCount = selectedRows.size;
            
            // Create just the basic structure with generatorData shell
            let json = {
                "configurations": [
                    {
                        "operator": "OR",
                        "negate": false,
                        "cpeMatch": [],
                        "generatorData": {
                            "generatedFromSource": {
                                "dataSource": metadata.dataSource,
                                "sourceId": metadata.sourceId,
                                "sourceRole": metadata.sourceRole
                            }
                            // We'll add statistics only after we have the complete structure
                        }
                    }
                ]
            };
            
            // Process different data sources and build the JSON structure
            if (processJsonBasedOnSource(json, selectedRows, metadata)) {
                // Now that we have the complete structure, calculate statistics once
                calculateAndAddStatistics(json, selectedRows, metadata.rawPlatformData, metadata);
                
                // Store the consolidated JSON for this table
                consolidatedJsons.set(tableId, json);
                
                // Update display and button
                updateJsonDisplay(tableId, json, selectionCount);
            } else {
                consolidatedJsons.set(tableId, null);
            }
            
            updateAllConfigurationsDisplay();
        } catch(e) {
            console.error(`Error updating consolidated JSON for table ${tableId}:`, e);
        }
    }

    // Calculate statistics only once after we have the full structure
    function calculateAndAddStatistics(json, selectedRows, rawPlatformData, metadata) {
        const selectionCount = selectedRows.size;
        let totalMatches = 0;
        let rangeMatches = 0;
        let exactMatches = 0;
        
        // Use precomputed totalVersions from metadata if available, otherwise calculate
        let totalVersions = metadata && metadata.totalVersions ? 
            metadata.totalVersions : 
            calculateTotalVersions(selectedRows, rawPlatformData);
        
        // Process statistics based on final JSON structure
        if (json.configurations[0].cpeMatch && json.configurations[0].cpeMatch.length > 0) {
            totalMatches = json.configurations[0].cpeMatch.length;
            
            // Count range vs exact matches
            json.configurations[0].cpeMatch.forEach(match => {
                if (isRangeMatch(match)) {
                    rangeMatches++;
                } else {
                    exactMatches++;
                }
            });
        } else if (json.configurations[0].nodes) {
            json.configurations[0].nodes.forEach(node => {
                if (node.cpeMatch) {
                    totalMatches += node.cpeMatch.length;
                    
                    // Count range vs exact matches in this node
                    node.cpeMatch.forEach(match => {
                        if (isRangeMatch(match)) {
                            rangeMatches++;
                        } else {
                            exactMatches++;
                        }
                    });
                }
            });
        }
        
        // Store statistics directly in generatorData - no redundant storage
        if (json.configurations[0].generatorData) {
            json.configurations[0].generatorData.matchStats = {
                totalMatches: totalMatches,
                rangeMatches: rangeMatches,
                exactMatches: exactMatches,
                selectedCriteria: selectionCount
            };
            
            json.configurations[0].generatorData.versionStats = {
                totalVersions: totalVersions,
                selectedCriteria: selectionCount
            };
        }
        
        // Also remove any accidentally created stats objects that are outside generatorData
        // BUT NOW with warnings so we can track when this is happening
        if (json.configurations[0].matchStats) {
            console.warn('WARNING: Found matchStats outside of generatorData - deleting to avoid duplication');
            delete json.configurations[0].matchStats;
        }
        if (json.configurations[0].versionStats) {
            console.warn('WARNING: Found versionStats outside of generatorData - deleting to avoid duplication');
            delete json.configurations[0].versionStats;
        }
    }
    
    function updateExportAllButton() {
        try {
            // Check if any tables have selected rows
            let hasSelections = false;
            let totalSelections = 0;
            let configCount = 0;
            let configDetails = [];
            let totalVersions = 0;
            
            tableSelections.forEach((selections, tableId) => {
                if (selections.size > 0) {
                    hasSelections = true;
                    totalSelections += selections.size;
                    configCount++;
                    
                    // Get version count from this table's JSON if available
                    const json = consolidatedJsons.get(tableId);
                    if (json && json.configurations && json.configurations.length > 0) {
                        const versionCount = json.configurations[0].cpeMatch.length;
                        configDetails.push(`${selections.size} Criteria, ${versionCount} versions`);
                        totalVersions += versionCount;
                    } else {
                        configDetails.push(`${selections.size} criteria`);
                        totalVersions += selections.size; // Assume 1 version per Criteria if no detailed data
                    }
                }
            });
            
            // Show/hide the Export All button container based on whether there are selections
            const container = document.getElementById('allConfigurationsContainer');
            const exportButton = document.getElementById('exportAllConfigurations');
            const configSummary = document.getElementById('configurationSummary');
            
            if (container && exportButton) {
                container.style.display = hasSelections ? 'block' : 'none';
                
                // Update the summary text with selection count and version information
                if (hasSelections && configSummary) {
                    const display = document.getElementById('allConfigurationsDisplay');
                    
                    // Format the config summary
                    const summaryText = `${configCount} config${configCount !== 1 ? 's' : ''} (${configDetails.join(', ')})`;
                    
                    // Update the summary text instead of changing the button text
                    configSummary.textContent = summaryText;
                    
                    // Keep button text simple - just show/hide state
                    exportButton.textContent = display && display.style.display !== 'none' ? 
                        'Hide All Configurations' : 'Show All Configurations';
                } else if (configSummary) {
                    configSummary.textContent = '';
                }
            }
        } catch(e) {
            console.error("Error updating export all button:", e);
        }
    }
    
    // Update the all configurations display
    function updateAllConfigurationsDisplay() {
        try {
            const display = document.getElementById('allConfigurationsDisplay');
            const content = document.getElementById('allConfigurationsContent');
            
            if (display && content && display.style.display !== 'none') {
                // Create master JSON with configurations from all tables
                const masterJson = generateAllConfigurationsJson();
                
                if (!masterJson || !masterJson.configurations || masterJson.configurations.length === 0) {
                    content.textContent = 'No CPEs selected in any table. Please select at least one CPE row.';
                } else {
                    content.textContent = JSON.stringify(masterJson, null, 2);
                }
            }
        } catch(e) {
            console.error("Error updating all configurations display:", e);
        }
    }
    
    function generateAllConfigurationsJson() {
        try {
            // Create master JSON with all configurations
            const masterJson = {
                "configurations": []
            };
            
            // Add each table's configuration as a separate node in the configurations array
            consolidatedJsons.forEach((json, tableId) => {
                if (json && json.configurations && json.configurations.length > 0) {
                    // Each configuration from a table should retain its generatorData
                    json.configurations.forEach(config => {
                        // Ensure the generatorData structure is preserved
                        if (config.generatorData) {
                            masterJson.configurations.push(config);
                        } else {
                            // If generatorData is missing, add a placeholder
                            config.generatorData = {
                                "generatedFromSource": {
                                    "dataSource": "Unknown",
                                    "sourceId": "Unknown",
                                    "sourceRole": "Unknown"
                                },
                                "versionStats": {
                                    "totalVersions": 0,
                                    "selectedCriteria": 0
                                },
                                "matchStats": {
                                    "totalMatches": 0,
                                    "rangeMatches": 0,
                                    "exactMatches": 0,
                                    "selectedCriteria": 0
                                }
                            };
                            masterJson.configurations.push(config);
                        }
                    });
                }
            });
            
            return masterJson;
        } catch(e) {
            console.error("Error generating all configurations JSON:", e);
            return { "configurations": [] };
        }
    }
    
    function createCpeMatchObject(cpeBase) {
        try {
            // Create a cpeMatch object for the given CPE base string
            const cpeMatch = {
                "criteria": cpeBase,
                "matchCriteriaId": "generated_" + Math.random().toString(36).substr(2, 9),
                "vulnerable": true
            };
            
            return cpeMatch;
        } catch(e) {
            console.error("Error creating CPE match object:", e);
            return {
                "criteria": "error_creating_cpe_match",
                "matchCriteriaId": "error_" + Date.now(),
                "vulnerable": true
            };
        }
    }

    // Process raw platform data to generate cpeMatch objects with version information
    function processVersionDataToCpeMatches(cpeBase, rawVersionData) {
        try {
            // Array to hold all generated cpeMatch objects
            const cpeMatches = [];
            
            // If no version data provided or no versions array, return a basic cpeMatch object
            if (!rawVersionData || !Array.isArray(rawVersionData.versions) || rawVersionData.versions.length === 0) {
                const basicMatch = createCpeMatchObject(cpeBase);
                return [basicMatch];
            }
            
            // Process each version entry in the versions array
            for (const versionInfo of rawVersionData.versions) {
                // Skip if there's no version information at all
                if (!versionInfo) continue;
                
                // Create a new cpeMatch object for this version
                const cpeMatch = {
                    "criteria": cpeBase,
                    "matchCriteriaId": "generated_" + Math.random().toString(36).substr(2, 9),
                    "vulnerable": versionInfo.status !== 'unaffected' // Set vulnerable based on status
                };
                
                // Handle different version patterns
                if (versionInfo.hasOwnProperty('lessThan')) {
                    // Version range with start (inclusive) and end (exclusive)
                    if (versionInfo.version) {
                        // Remove the "version 0" special handling - all versions should be treated the same
                        cpeMatch.versionStartIncluding = versionInfo.version;
                    }
                    if (versionInfo.lessThan) {
                        cpeMatch.versionEndExcluding = versionInfo.lessThan;
                    }
                    cpeMatches.push(cpeMatch);
                } 
                else if (versionInfo.hasOwnProperty('lessThanOrEqual')) {
                    // Version range with start (inclusive) and end (inclusive)
                    if (versionInfo.version) {
                        // Remove the "version 0" special handling - all versions should be treated the same
                        cpeMatch.versionStartIncluding = versionInfo.version;
                    }
                    if (versionInfo.lessThanOrEqual) {
                        cpeMatch.versionEndIncluding = versionInfo.lessThanOrEqual;
                    }
                    cpeMatches.push(cpeMatch);
                }
                // Handle greater than ranges (if present)
                else if (versionInfo.hasOwnProperty('greaterThan')) {
                    if (versionInfo.greaterThan) {
                        cpeMatch.versionStartExcluding = versionInfo.greaterThan;
                    }
                    if (versionInfo.version && versionInfo.version !== '*') {
                        cpeMatch.versionEndIncluding = versionInfo.version;
                    }
                    cpeMatches.push(cpeMatch);
                }
                // Handle greater than or equal ranges (if present)
                else if (versionInfo.hasOwnProperty('greaterThanOrEqual')) {
                    if (versionInfo.greaterThanOrEqual) {
                        cpeMatch.versionStartIncluding = versionInfo.greaterThanOrEqual;
                    }
                    if (versionInfo.version && versionInfo.version !== '*') {
                        cpeMatch.versionEndIncluding = versionInfo.version;
                    }
                    cpeMatches.push(cpeMatch);
                }
                // Handle single version - the most common case
                else if (versionInfo.hasOwnProperty('version')) {
                    // Split the CPE to update the version component (the 6th component, index 5)
                    const cpeParts = cpeBase.split(':');
                    if (cpeParts.length >= 6) {
                        // Replace the version part (at index 5)
                        cpeParts[5] = versionInfo.version;
                        // Rebuild the CPE string with updated version
                        cpeMatch.criteria = cpeParts.join(':');
                    }
                    cpeMatches.push(cpeMatch);
                }
            }
            
            // If no valid cpeMatch objects were created, return a basic one
            if (cpeMatches.length === 0) {
                const basicMatch = createCpeMatchObject(cpeBase);
                return [basicMatch];
            }
            
            return cpeMatches;
        } catch (e) {
            console.error("Error processing version data:", e);
            // Return a basic cpeMatch object in case of error
            const errorMatch = createCpeMatchObject(cpeBase);
            return [errorMatch];
        }
    }

    // Add this function to track completion status
    function updateCompletionTracker() {
        try {
            const tables = document.querySelectorAll('table[id^="rowDataTable_"]');
            let completedCount = 0;
            const totalCount = tables.length;
            
            // Count how many tables are collapsed (completed)
            tables.forEach(table => {
                if (table.classList.contains('d-none')) {
                    completedCount++;
                }
            });
            
            // Calculate percentage
            const percentage = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;
            
            // Update the progress bar
            const progressBar = document.getElementById('completionProgressBar');
            const completedRowsCount = document.getElementById('completedRowsCount');
            const totalRowsCount = document.getElementById('totalRowsCount');
            
            if (progressBar && completedRowsCount && totalRowsCount) {
                progressBar.style.width = `${percentage}%`;
                progressBar.textContent = `${percentage}%`;
                progressBar.setAttribute('aria-valuenow', percentage);
                
                // Change format to succinct fraction followed by "rows"
                completedRowsCount.textContent = `${completedCount}/${totalCount} rows`;
                // Remove the separate total count display since it's now in the fraction
                totalRowsCount.textContent = ''; // or just hide this element with display:none
            }
        } catch(e) {
            console.error('Error updating completion tracker:', e);
        }
    }
    
    // Maintain JSON display state across row toggle operations
    function preserveJsonDisplayState(tableIndex) {
        const tableId = `matchesTable_${tableIndex}`;
        const jsonContainer = document.querySelector(`.consolidated-json-container[data-index="${tableIndex}"]`);
        const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
        const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
        
        if (!jsonContainer || !display || !showButton) return;
        
        // Store current state
        const isDisplayVisible = display.style.display !== 'none';
        const selectedRows = tableSelections.get(tableId);
        const selectionCount = selectedRows ? selectedRows.size : 0;
        
        // Get json and detailed statistics
        const json = consolidatedJsons.get(tableId);
        let statsStr = `${selectionCount} selected`;
        
        // Extract detailed statistics if available
        if (json && json.configurations && json.configurations.length > 0) {
            if (json.configurations[0].matchStats) {
                const stats = json.configurations[0].matchStats;
                statsStr = `${stats.selectedCriteria || stats.selectedCPEs} Criteria, ${stats.totalMatches} versions (${stats.exactMatches} exact, ${stats.rangeMatches} ranges)`;
            } else {
                // Fall back to basic statistics if detailed stats aren't available
                let versionCount = selectionCount;
                if (json.configurations[0].versionStats) {
                    versionCount = json.configurations[0].versionStats.totalVersions;
                } else if (json.configurations[0].cpeMatch) {
                    versionCount = json.configurations[0].cpeMatch.length;
                } else if (json.configurations[0].nodes) {
                    versionCount = getTotalCPEMatches(json.configurations[0]);
                }
                statsStr = `${selectionCount} Criteria, ${versionCount} versions`;
            }
        }
        
        // Ensure the button text and state matches the display visibility
        if (isDisplayVisible) {
            showButton.textContent = `Hide Consolidated JSON (${statsStr})`;
            showButton.classList.remove('btn-primary');
            showButton.classList.add('btn-success');
            
            // Also ensure the JSON content is updated
            updateJsonDisplayIfVisible(tableId);
        } else {
            showButton.textContent = `Show Consolidated JSON (${statsStr})`;
            showButton.classList.remove('btn-success');
            showButton.classList.add('btn-primary');
        }
        
        // Ensure proper container positioning
        const collapseButton = document.getElementById(`collapseRowButton_${tableIndex}`);
        if (collapseButton) {
            const buttonParent = collapseButton.parentNode;
            buttonParent.parentNode.insertBefore(jsonContainer, buttonParent.nextSibling);
        }
    }

    function getTotalCPEMatches(config) {
        let count = 0;
        if (config.nodes) {
            for (const node of config.nodes) {
                if (node.cpeMatch) {
                    count += node.cpeMatch.length;
                }
            }
        } else if (config.cpeMatch) {
            count = config.cpeMatch.length;
        }
        return count;
    }

    function processBasicVersionData(selectedRows, rawPlatformData, json) {
        let totalVersions = 0;
        
        // Add cpeMatch objects for each selected CPE, processing version information
        selectedRows.forEach(cpeBase => {
            // If we have raw platform data, process each version into cpeMatch objects
            if (rawPlatformData) {
                const cpeMatches = processVersionDataToCpeMatches(cpeBase, rawPlatformData);
                
                // Track version statistics
                cpeMatches.forEach(match => {
                    json.configurations[0].cpeMatch.push(match);
                    totalVersions++;
                });
            } else {
                // No version data, just use the basic CPE
                const basicMatch = createCpeMatchObject(cpeBase);
                json.configurations[0].cpeMatch.push(basicMatch);
                totalVersions++;
            }
        });
        
        // IMPORTANT: Return the totalVersions to be used by calculateAndAddStatistics
        return totalVersions;
    }

    // Add this function before updateConsolidatedJson
    function updateButton(tableId, hasSelections) {
        try {
            // Find the consolidated JSON button
            const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
            if (!showButton) return;
            
            // Update button state based on whether there are selections
            if (hasSelections) {
                showButton.disabled = false;
                const selectedRows = tableSelections.get(tableId);
                const selectionCount = selectedRows ? selectedRows.size : 0;
                
                // Check if the display is visible
                const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
                const isVisible = display && display.style.display !== 'none';
                
                // Update button text with selection count
                showButton.textContent = isVisible 
                    ? `Hide Consolidated JSON (${selectionCount} selected)` 
                    : `Show Consolidated JSON (${selectionCount} selected)`;
            } else {
                // Reset button text when no selections
                showButton.textContent = 'Show Consolidated JSON';
                showButton.disabled = false; // Keep enabled to allow showing "no selections" message
            }
        } catch(e) {
            console.error(`Error updating button for table ${tableId}:`, e);
        }
    }

    // Also need to add the updateJsonDisplay function that's referenced but missing
    function updateJsonDisplay(tableId, json, selectionCount) {
        try {
            const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
            const content = document.getElementById(`consolidatedJsonContent_${tableId}`);
            const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
            
            if (display && content) {
                // Check if the display is already visible
                const isVisible = display.style.display !== 'none';
                
                // Update the content
                if (json) {
                    content.textContent = JSON.stringify(json, null, 2);
                } else {
                    content.textContent = 'No selections or error generating JSON.';
                }
                
                // Update button text if it's found
                if (showButton) {
                    // Get detailed stats for the button text if available
                    let statsStr = `${selectionCount} selected`;
                    
                    if (json && json.configurations && json.configurations.length > 0 && 
                        json.configurations[0].generatorData && json.configurations[0].generatorData.matchStats) {
                        const stats = json.configurations[0].generatorData.matchStats;
                        statsStr = `${stats.selectedCriteria} Criteria, ${stats.totalMatches} versions` +
                                   ` (${stats.exactMatches} exact, ${stats.rangeMatches} ranges)`;
                    }
                    
                    showButton.textContent = isVisible 
                        ? `Hide Consolidated JSON (${statsStr})` 
                        : `Show Consolidated JSON (${statsStr})`;
                    
                    // Update button styling
                    if (isVisible) {
                        showButton.classList.remove('btn-primary');
                        showButton.classList.add('btn-success');
                    } else {
                        showButton.classList.remove('btn-success');
                        showButton.classList.add('btn-primary');
                    }
                }
            }
        } catch(e) {
            console.error(`Error updating JSON display for table ${tableId}:`, e);
        }
    }

    // Also need to add the function to determine if a match is a range match
    function isRangeMatch(match) {
        return match.hasOwnProperty('versionStartIncluding') || 
               match.hasOwnProperty('versionStartExcluding') || 
               match.hasOwnProperty('versionEndIncluding') || 
               match.hasOwnProperty('versionEndExcluding');
    }

    // Also need to add the function to calculate total versions
    function calculateTotalVersions(selectedRows, rawPlatformData) {
        try {
            if (rawPlatformData && rawPlatformData.versions && Array.isArray(rawPlatformData.versions)) {
                return rawPlatformData.versions.length;
            }
            return selectedRows.size; // Fallback to number of selected rows
        } catch(e) {
            console.error("Error calculating total versions:", e);
            return selectedRows.size;
        }
    }

    // And finally, need to add a placeholder for the function that processes JSON based on source
    function processJsonBasedOnSource(json, selectedRows, metadata) {
        try {
            // Process the JSON structure based on the data source
            const dataSource = metadata.dataSource;
            let totalVersions = 0;
            
            if (dataSource === 'NVDAPI') {
                // Special handling for NVD API data
                totalVersions = processBasicVersionData(selectedRows, metadata.rawPlatformData, json);
            } else {
                // Default handling for other data sources
                totalVersions = processBasicVersionData(selectedRows, metadata.rawPlatformData, json);
            }
            
            // Store totalVersions in the metadata for use in calculateAndAddStatistics
            metadata.totalVersions = totalVersions;
            
            return true;
        } catch(e) {
            console.error("Error processing JSON based on source:", e);
            return false;
        }
    }

    // Add function to gather table metadata
    function gatherTableMetadata(tableIndex) {
        try {
            // Get the corresponding metadata from data attributes
            const container = document.querySelector(`.cpe-query-container[data-table-index="${tableIndex}"]`);
            
            if (!container) {
                return {
                    dataSource: "Unknown",
                    sourceId: "Unknown",
                    sourceRole: "Unknown",
                    rawPlatformData: null
                };
            }
            
            // Extract metadata from data attributes
            const dataSource = container.getAttribute('data-source') || "Unknown";
            const sourceId = container.getAttribute('data-source-id') || "Unknown";
            const sourceRole = container.getAttribute('data-source-role') || "Unknown";
            
            // Get raw platform data if available
            let rawPlatformData = null;
            const platformDataAttr = container.getAttribute('data-platform-data');
            if (platformDataAttr) {
                try {
                    rawPlatformData = JSON.parse(platformDataAttr);
                } catch (e) {
                    console.warn(`Could not parse platform data for table ${tableIndex}:`, e);
                }
            }
            
            return {
                dataSource,
                sourceId,
                sourceRole,
                rawPlatformData
            };
        } catch(e) {
            console.error(`Error gathering metadata for table ${tableIndex}:`, e);
            return {
                dataSource: "Error",
                sourceId: "Error",
                sourceRole: "Error",
                rawPlatformData: null
            };
        }
    }
    </script>
    """

def update_cpeQueryHTML_column(dataframe, nvdSourceData):
    """Updates the dataframe to include a column with HTML for CPE query results"""
    import json
    import html
    import pandas as pd
    
    # Make a copy to avoid modifying the original
    result_df = dataframe.copy()
    
    # Process each row to create the cpeQueryHTML content
    for index, row in result_df.iterrows():
        # Initialize data attributes for the container
        data_attrs = []
        
        # Add platform data attribute (including raw config data if applicable)
        platform_data = None
        
        # First check if we have rawPlatformData
        if ('rawPlatformData' in row and row['rawPlatformData'] is not None):
            platform_data = row['rawPlatformData']
            
            # If this is NVD data and we have rawConfigData, include it in platform data
            if (row.get('dataSource') == 'NVDAPI' and 'rawConfigData' in row and row['rawConfigData'] is not None):
                # Instead of embedding the entire configuration, create a reference
                if (isinstance(platform_data, dict)):
                    # Just add a reference indicator and version stats
                    platform_data['hasEmbeddedConfig'] = True
                    
                    # Extract version statistics from config if possible
                    if (isinstance(row['rawConfigData'], dict) and 'nodes' in row['rawConfigData']):
                        total_cpes = 0
                        for node in row['rawConfigData'].get('nodes', []):
                            if ('cpeMatch' in node):
                                total_cpes += len(node['cpeMatch']);
                        platform_data['configStats'] = {'totalCPEs': total_cpes}
                
                # Add the raw config data as a separate attribute
                try:
                    config_json = json.dumps(row['rawConfigData'])
                    escaped_config_json = html.escape(config_json)
                    data_attrs.append(f'data-raw-config="{escaped_config_json}"')
                except Exception as e:
                    print(f"Error serializing config data: {e}")
        
        # Serialize and escape the platform data
        if (platform_data):
            try:
                platform_json = json.dumps(platform_data)
                escaped_json = html.escape(platform_json)
                data_attrs.append(f'data-raw-platform="{escaped_json}"')
            except Exception as e:
                print(f"Error serializing platform data: {e}")
        
        # Create the collapse button with a proper container ID
        collapse_button_html = f'<div class="mb-3 d-flex gap-2" id="buttonContainer_{index}"><button id="collapseRowButton_{index}" class="btn btn-secondary" onclick="toggleRowCollapse({index})">Collapse Row (Mark Complete)</button></div>'
        
        # Populate the rowDataHTML column with the HTML content
        row_html_content = convertRowDataToHTML(row, nvdSourceData, index)
        result_df.at[index, 'rowDataHTML'] = collapse_button_html + row_html_content
        
        # Create the main HTML div with all data attributes
        if ('trimmedCPEsQueryData' in row):
            sortedCPEsQueryData = row['trimmedCPEsQueryData'] 
            attr_string = " ".join(data_attrs)
            html_content = f"""<div class="cpe-query-container" {attr_string}>"""
            html_content += convertCPEsQueryDataToHTML(sortedCPEsQueryData, index)
            html_content += "</div>"  # Close the container div
            result_df.at[index, 'cpeQueryHTML'] = html_content
    
    return result_df

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
    fullHtml = (pageStartHTML + getCPEJsonScript() + pageBodyHeaderHTML + pageBodyTabsHTML + cveIdIndicatorHTML + 
                pageBodyCPESuggesterHTML + pageBodyVDBIntelHTML + pageBodyJavaScript + pageEndHTML)
    
    return fullHtml