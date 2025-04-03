/**
 * Function to handle tab navigation
 * @param {Event} evt - The click event
 * @param {string} tabName - The ID of the tab to open
 */
function openCity(evt, cityName) {
    // Declare all variables
    let i, tabcontent, tablinks;

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

// Make the function available globally
window.openCity = openCity;

/**
 * Function to toggle row collapse state
 * @param {number} tableIndex - Index of the table
 */
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
        
        // Preserve JSON display state
        preserveJsonDisplayState(tableIndex);
    } catch(e) {
        console.error(`Error in toggleRowCollapse for tableIndex ${tableIndex}:`, e);
    }
}

/**
 * Initialize the event listeners for tables and buttons
 */
function initializeEventListeners() {
    try {
        // Find all matchesTables (there may be multiple)
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

            // Insert right after the export all container
            allContainer.parentNode.insertBefore(completionTrackerContainer, allContainer.nextSibling);

            // Initialize the completion tracker
            updateCompletionTracker();
        }

        // Initialize each table
        tables.forEach((table, tableIndex) => {
            const tableId = table.id;
            
            // Initialize selections for this table
            tableSelections.set(tableId, new Set());
            
            // Add click handlers to all CPE rows in this table
            const rows = table.querySelectorAll('.cpe-row');
            rows.forEach(function(row) {
                row.addEventListener('click', function(event) {
                    // Don't handle clicks on elements with their own handlers
                    if (event.target.tagName === 'BUTTON' || 
                        event.target.tagName === 'A' ||
                        event.target.closest('button') ||
                        event.target.closest('a')) {
                        return;
                    }
                    
                    // Toggle row selection
                    let cpeBase = row.getAttribute('data-cpe-base');
                    
                    // Normalize CPE base string when getting it from the row
                    cpeBase = normalizeCpeString(cpeBase);
                    
                    const selections = tableSelections.get(tableId);
                    
                    if (selections.has(cpeBase)) {
                        selections.delete(cpeBase);
                        row.classList.remove('table-active');
                    } else {
                        selections.add(cpeBase);
                        row.classList.add('table-active');
                    }
                    
                    // Update the JSON
                    updateConsolidatedJson(tableId);
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
                            
                            // Always ensure the JSON container is in the right place when showing
                            if (!isVisible && jsonContainer && collapseButton) {
                                // Get the parent of the collapse button
                                const buttonParent = collapseButton.parentNode;
                                
                                // Always move the JSON container to be adjacent to the button
                                buttonParent.parentNode.insertBefore(jsonContainer, buttonParent.nextSibling);
                                
                                // Add some spacing for better visual separation
                                jsonContainer.classList.add('mt-2');
                            }
                            
                            // Get the json and statistics - ENSURE THIS CODE IS INCLUDED
                            const json = consolidatedJsons.get(tableId);
                            const selectedRows = tableSelections.get(tableId);
                            const selectionCount = selectedRows ? selectedRows.size : 0;
                            const statsStr = getStatisticsString(json, selectionCount);
                            
                            // Update button text with count and state
                            this.textContent = isVisible ? 
                                `Show Consolidated JSON (${statsStr})` : 
                                `Hide Consolidated JSON (${statsStr})`;
                            
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
        console.error("Error initializing event listeners:", e);
    }
}

// Make toggleRowCollapse available globally for HTML button onclick handlers
window.toggleRowCollapse = toggleRowCollapse;

// Initialize everything when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', initializeEventListeners);

/**
 * Maintain JSON display state across row toggle operations
 * @param {number} tableIndex - Index of the table
 */
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
    
    // Get json and statistics
    const json = consolidatedJsons.get(tableId);
    const statsStr = getStatisticsString(json, selectionCount);
    
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