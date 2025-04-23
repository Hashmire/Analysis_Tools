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
        
        if (rowDataTable && matchesTable && collapseButton) {
            // Check if the row is currently collapsed
            const isCollapsed = rowDataTable.classList.contains('collapsed');
            
            if (isCollapsed) {
                // Expand row
                rowDataTable.classList.remove('collapsed');
                // Explicitly set display and max-height to ensure visibility
                rowDataTable.style.display = 'table';
                rowDataTable.style.maxHeight = '5000px';
                
                matchesTable.classList.remove('collapsed');
                matchesTable.style.display = 'table';
                matchesTable.style.maxHeight = '5000px';
                
                // Also make sure parent elements are visible
                if (rowDataTable.parentElement && rowDataTable.parentElement.tagName === 'TD') {
                    rowDataTable.parentElement.style.display = '';
                }
                if (matchesTable.parentElement && matchesTable.parentElement.tagName === 'TD') {
                    matchesTable.parentElement.style.display = '';
                }
                
                // Ensure JSON container is visible if it's after the rowDataTable
                if (jsonContainer) {
                    jsonContainer.style.display = '';
                }
            } else {
                // Collapse row
                rowDataTable.classList.add('collapsed');
                // Use display:none in addition to max-height to ensure it's hidden
                rowDataTable.style.display = 'none';
                rowDataTable.style.maxHeight = '0';
                
                matchesTable.classList.add('collapsed');
                matchesTable.style.display = 'none';
                matchesTable.style.maxHeight = '0';
                
                // Also hide the JSON container if it's expanded
                if (jsonContainer) {
                    const jsonDisplay = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
                    if (jsonDisplay && !jsonDisplay.classList.contains('collapsed')) {
                        if (typeof toggleConsolidatedJson === 'function') {
                            toggleConsolidatedJson(tableId);
                        }
                    }
                }
            }
            
            // Update button styling
            collapseButton.textContent = !isCollapsed ? 'Expand Row (Completed)' : 'Collapse Row (Mark Complete)';
            
            if (!isCollapsed) {
                collapseButton.classList.remove('btn-secondary');
                collapseButton.classList.add('btn-success');
            } else {
                collapseButton.classList.remove('btn-success');
                collapseButton.classList.add('btn-secondary');
            }
            
            // Update any elements that need to track collapse state
            if (typeof updateCompletionTracker === 'function') {
                updateCompletionTracker();
            }

            // Handle the essential functionality directly:
            const selectedRows = window.tableSelections ? window.tableSelections.get(tableId) : null;
            const selectionCount = selectedRows ? selectedRows.size : 0;
            
            // Update JSON button state if needed
            const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
            if (showButton) {
                showButton.disabled = selectionCount === 0;
                
                // Ensure consistent button text
                const isJsonDisplayVisible = document.getElementById(`consolidatedJsonDisplay_${tableId}`) && 
                                           !document.getElementById(`consolidatedJsonDisplay_${tableId}`).classList.contains('collapsed');
                
                const json = consolidatedJsons.get(tableId);
                const statsStr = getStatisticsString(json, selectionCount);
                
                showButton.textContent = isJsonDisplayVisible ? 
                    `Hide Consolidated JSON (${statsStr})` : 
                    `Show Consolidated JSON (${statsStr})`;
                
                // Update button styling
                if (isJsonDisplayVisible) {
                    showButton.classList.remove('btn-primary');
                    showButton.classList.add('btn-success');
                } else {
                    showButton.classList.remove('btn-success');
                    showButton.classList.add('btn-primary');
                }
            }
            
            // Show or hide the JSON container based on table state
            if (jsonContainer) {
                if (!isCollapsed) { // If we're collapsing the table, potentially hide the JSON
                    const jsonDisplay = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
                    if (jsonDisplay && !jsonDisplay.classList.contains('collapsed')) {
                        // Only hide if it's defined in the global scope
                        if (typeof toggleConsolidatedJson === 'function') {
                            toggleConsolidatedJson(tableId);
                        } else if (window.toggleConsolidatedJson) {
                            window.toggleConsolidatedJson(tableId);
                        }
                    }
                }
            }
            
            // If these functions are defined, call them
            if (typeof preserveJsonDisplayState === 'function') {
                preserveJsonDisplayState(tableIndex);
            }
        }
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
        
        // Add transition class to all tables
        tables.forEach((table, tableIndex) => {
            // Add transition class to the matches table
            if (!table.classList.contains('row-transition')) {
                table.classList.add('row-transition');
            }
            
            // Add transition class to the corresponding row data table
            const rowDataTable = document.getElementById(`rowDataTable_${tableIndex}`);
            if (rowDataTable && !rowDataTable.classList.contains('row-transition')) {
                rowDataTable.classList.add('row-transition');
            }
        });
        
        // Handling of the JSON display toggle - Fix for 'display is not defined' error
        document.querySelectorAll('[id^="showConsolidatedJson_"]').forEach(button => {
            if (button) {
                button.addEventListener('click', function() {
                    try {
                        const tableId = this.id.replace('showConsolidatedJson_', '');
                        const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
                        
                        if (display) {

                            const isVisible = display.style.display !== 'none';
                        }
                    } catch(e) {
                        console.error(`Error handling button click:`, e);
                    }
                });
            }
        });
        
        // Add a master "Export All Configurations" button at the top of cveListCPESuggester
        const cveListCPESuggester = document.getElementById('cveListCPESuggester');
        
        // Scan for git versionTypes and add warnings (add this near the beginning)
        if (typeof scanForGitVersionTypes === 'function') {
            scanForGitVersionTypes();
        }
        
        if (cveListCPESuggester) {
            // Create the Export All container at the beginning
            const allContainer = document.createElement('div');
            allContainer.classList.add('all-configurations-container', 'mt-3', 'mb-5');
            allContainer.id = 'allConfigurationsContainer';
            allContainer.innerHTML = `
                <!-- NEW: Add configuration summary above the button -->
                <div id="configurationSummary" class="text-center mb-2"></div>
                <div class="d-grid gap-2 col-12 mx-auto">
                    <button id="exportAllConfigurations" class="btn btn-danger">Show All Configurations</button>
                </div>
                <div id="allConfigurationsDisplay" class="mt-3 consolidated-json-container" style="display: none;">
                    <h4>Complete Configuration JSON</h4>
                    <p class="text-muted">This combines all selected CPEs from all tables, with each table creating its own configuration node.</p>
                    <pre id="allConfigurationsContent"></pre>
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
                    const isVisible = display.style.display !== 'none';
                    if (isVisible) {
                        // Prepare to hide
                        display.style.opacity = '0';
                        display.style.maxHeight = '0';
                        
                        setTimeout(() => {
                            display.style.display = 'none';
                        }, 300);
                    } else {
                        // Prepare to show
                        display.style.display = 'block';
                        display.style.opacity = '0';
                        display.style.maxHeight = '0';
                        
                        setTimeout(() => {
                            display.style.opacity = '1';
                            display.style.maxHeight = display.scrollHeight + 'px';
                        }, 10);
                    }
                    
                    // Update the button text to reflect current state (without configuration details)
                    this.textContent = isVisible ? 'Show All Configurations' : 'Hide All Configurations';
                    
                    // Toggle button styling with transition
                    if (isVisible) {
                        this.classList.remove('btn-success');
                        this.classList.add('btn-danger');
                    } else {
                        this.classList.remove('btn-danger');
                        this.classList.add('btn-success');
                    }
                }
            });
            
            // Add transition class to Export All button
            const exportButton = document.getElementById('exportAllConfigurations');
            if (exportButton) {
                if (!exportButton.classList.contains('btn-transition')) {
                    exportButton.classList.add('btn-transition');
                }
            }
            
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
        // After creating allContainer
        const allConfigurationsDisplay = document.getElementById('allConfigurationsDisplay');
        if (allConfigurationsDisplay && !allConfigurationsDisplay.classList.contains('consolidated-json-container')) {
            allConfigurationsDisplay.classList.add('consolidated-json-container');
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
            
            // Find the row data table's container - it's in the first cell of the row
            const rowDataTable = document.getElementById(`rowDataTable_${tableIndex}`);
            let containerTarget = null;
            
            if (rowDataTable) {
                // Get the parent TD element where the rowDataTable is located
                const parentCell = rowDataTable.closest('td');
                if (parentCell) {
                    containerTarget = parentCell;
                } else {
                    containerTarget = rowDataTable.parentNode; // Fallback
                }
                
                rowDataTable.classList.add('collapsible-content');
                rowDataTable.style.maxHeight = rowDataTable.scrollHeight + 'px';
            }
            
            // Convert the matchesTable to use the new collapsible structure
            table.classList.add('collapsible-content');
            table.style.maxHeight = table.scrollHeight + 'px';
            
            // Create a container for consolidated JSON right after the row data table
            const container = document.createElement('div');
            container.classList.add('consolidated-json-container', 'mt-3', 'mb-4', 'json-container');
            // Give an ID to the container for easier reference
            container.id = `jsonContainer_${tableId}`;
            // Add the transition class
            container.classList.add('row-transition');
            container.setAttribute('data-index', tableIndex);
            container.innerHTML = `
                <div id="consolidatedJsonDisplay_${tableId}" class="collapsible-content collapsed">
                    <h4>Consolidated Configuration JSON</h4>
                    <pre id="consolidatedJsonContent_${tableId}"></pre>
                </div>
            `;
            
            // Place the container before the rowDataTable in the first cell
            if (containerTarget && rowDataTable) {
                // Insert before the rowDataTable instead of after
                rowDataTable.insertAdjacentElement('beforebegin', container);
            } else {
                // Fallback to original placement after the table
                table.parentNode.insertBefore(container, table.nextSibling);
            }
            
            // Create the consolidated JSON button and place it next to the collapse button
            const jsonButton = document.createElement('button');
            jsonButton.id = `showConsolidatedJson_${tableId}`;
            jsonButton.className = 'btn btn-primary';
            // Disable by default since there are no selections initially
            jsonButton.disabled = true;
            // Add the btn-transition class
            jsonButton.classList.add('btn-transition');
            jsonButton.textContent = 'Show Consolidated JSON (0 selected)';

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
                            // Use the toggleConsolidatedJson function if available
                            if (typeof toggleConsolidatedJson === 'function') {
                                toggleConsolidatedJson(tableId);
                            } else {
                                // Fallback toggle logic if the function isn't available
                                const isCollapsed = display.classList.contains('collapsed');
                                
                                if (isCollapsed) {
                                    // Show content
                                    display.classList.remove('collapsed');
                                    display.style.maxHeight = display.scrollHeight + 'px';
                                } else {
                                    // Hide content
                                    display.classList.add('collapsed');
                                    display.style.maxHeight = '0';
                                }
                                
                                // Update button text with count and state
                                const selectedRows = tableSelections.get(tableId);
                                const selectionCount = selectedRows ? selectedRows.size : 0;
                                const json = consolidatedJsons.get(tableId);
                                const statsStr = getStatisticsString(json, selectionCount);
                                
                                this.textContent = isCollapsed ? 
                                    `Hide Consolidated JSON (${statsStr})` : 
                                    `Show Consolidated JSON (${statsStr})`;
                                
                                // Update content when showing
                                if (isCollapsed && typeof updateJsonDisplayIfVisible === 'function') {
                                    updateJsonDisplayIfVisible(tableId);
                                }
                                
                                // Update button styling
                                if (isCollapsed) {
                                    this.classList.remove('btn-primary');
                                    this.classList.add('btn-success');
                                } else {
                                    this.classList.remove('btn-success');
                                    this.classList.add('btn-primary');
                                }
                            }
                        }
                    } catch(e) {
                        console.error(`Error toggling JSON display for table ${tableId}:`, e);
                    }
                });
            }

            // Also for any existing buttons that we find later:
            if (showButton && !showButton.classList.contains('btn-transition')) {
                showButton.classList.add('btn-transition');
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
    const isDisplayVisible = !display.classList.contains('collapsed');
    const selectedRows = tableSelections.get(tableId);
    const selectionCount = selectedRows ? selectedRows.size : 0;
    
    // Get json and statistics
    const json = consolidatedJsons.get(tableId);
    const statsStr = getStatisticsString(json, selectionCount);
    
    // Ensure the button is disabled if there are no selections
    showButton.disabled = selectionCount === 0;
    
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
}

/**
 * Toggle consolidated JSON display with improved state handling
 * @param {string} tableId - ID of the table
 */
function toggleConsolidatedJson(tableId) {
    try {
        const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
        const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
        
        if (!display || !showButton) return;
        
        const selectedRows = tableSelections.get(tableId);
        const selectionCount = selectedRows ? selectedRows.size : 0;
        
        // Disable button if there are no selections
        showButton.disabled = selectionCount === 0;
        
        if (selectionCount > 0) {
            // Using classList.toggle to add/remove the collapsed class
            const wasCollapsed = display.classList.contains('collapsed');
            
            if (wasCollapsed) {
                // SHOW the content
                display.classList.remove('collapsed');
                display.style.maxHeight = display.scrollHeight + 'px';
                
                // Update button
                const statsStr = getStatisticsString(consolidatedJsons.get(tableId), selectionCount);
                showButton.textContent = `Hide Consolidated JSON (${statsStr})`;
                showButton.classList.remove('btn-primary');
                showButton.classList.add('btn-success');
            } else {
                // HIDE the content
                display.classList.add('collapsed');
                display.style.maxHeight = '0';
                
                // Update button
                const statsStr = getStatisticsString(consolidatedJsons.get(tableId), selectionCount);
                showButton.textContent = `Show Consolidated JSON (${statsStr})`;
                showButton.classList.remove('btn-success');
                showButton.classList.add('btn-primary');
            }
            
            // Update content when showing
            if (wasCollapsed) {
                updateJsonDisplayIfVisible(tableId);
            }
        } else {
            // Ensure display is collapsed with no selections
            display.classList.add('collapsed');
            display.style.maxHeight = '0';
            
            // Update button for no selections state
            showButton.textContent = `Show Consolidated JSON (0 selected)`;
            showButton.classList.remove('btn-success');
            showButton.classList.add('btn-primary');
        }
    } catch(e) {
        console.error(`Error in toggleConsolidatedJson for tableId ${tableId}:`, e);
    }
}

// Add transition classes to elements when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Add transition classes to all tables
    document.querySelectorAll('table[id^="rowDataTable_"], table[id^="matchesTable_"]').forEach(table => {
        table.classList.add('row-transition');
    });
    
    // Add transition class to buttons
    document.querySelectorAll('[id^="collapseRowButton_"], [id^="showConsolidatedJson_"]').forEach(button => {
        button.classList.add('btn-transition');
    });
    
    // Add transition class to JSON containers
    document.querySelectorAll('.consolidated-json-container, [id^="consolidatedJsonDisplay_"]').forEach(container => {
        container.classList.add('consolidated-json-container');
    });
});

// Add CSS for the collapsible content
document.addEventListener('DOMContentLoaded', function() {
    // Create a style element
    const style = document.createElement('style');
    style.textContent = `
        .collapsible-content {
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }
        .collapsible-content.collapsed {
            max-height: 0 !important;
            overflow: hidden;
        }
        .btn-transition {
            transition: background-color 0.3s, color 0.3s, border-color 0.3s;
        }
    `;
    document.head.appendChild(style);
    
    // Update existing elements
    document.querySelectorAll('table[id^="rowDataTable_"], table[id^="matchesTable_"]').forEach(table => {
        table.classList.add('collapsible-content');
        table.style.maxHeight = table.scrollHeight + 'px';
    });
    
    document.querySelectorAll('[id^="consolidatedJsonDisplay_"]').forEach(container => {
        container.classList.add('collapsible-content');
        container.classList.add('collapsed');
        container.style.maxHeight = '0';
    });
    
    // Add transition class to buttons
    document.querySelectorAll('[id^="collapseRowButton_"], [id^="showConsolidatedJson_"]').forEach(button => {
        button.classList.add('btn-transition');
    });
});

/**
 * Update the completion tracker
 */
function updateCompletionTracker() {
    try {
        const tables = document.querySelectorAll('table[id^="rowDataTable_"]');
        let completedCount = 0;
        const totalCount = tables.length;
        
        // Count how many tables are collapsed (completed)
        tables.forEach(table => {
            // Check both class and display style to determine if collapsed
            if (table.classList.contains('collapsed') || table.style.display === 'none') {
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

// Add specific initialization to ensure proper display of tables
document.addEventListener('DOMContentLoaded', function() {
    // Check for any tables that need to start collapsed
    const tableButtons = document.querySelectorAll('[id^="collapseRowButton_"]');
    tableButtons.forEach(button => {
        if (button.textContent.includes('Expand Row')) {
            // Extract index from button ID
            const index = button.id.replace('collapseRowButton_', '');
            const rowDataTable = document.getElementById(`rowDataTable_${index}`);
            const matchesTable = document.getElementById(`matchesTable_${index}`);
            
            // Apply collapsed state explicitly
            if (rowDataTable) {
                rowDataTable.classList.add('collapsed');
                rowDataTable.style.display = 'none';
                rowDataTable.style.maxHeight = '0';
            }
            
            if (matchesTable) {
                matchesTable.classList.add('collapsed');
                matchesTable.style.display = 'none';
                matchesTable.style.maxHeight = '0';
            }
        }
    });
    
    // Initialize the completion tracker
    if (typeof updateCompletionTracker === 'function') {
        updateCompletionTracker();
    }
});

/**
 * Add specific initialization to ensure proper position of JSON containers
 */
document.addEventListener('DOMContentLoaded', function() {
    // After everything is loaded, ensure buttons are properly disabled
    document.querySelectorAll('[id^="showConsolidatedJson_"]').forEach(button => {
        const tableId = button.id.replace('showConsolidatedJson_', '');
        const selectedRows = tableSelections.get(tableId);
        
        // Disable button if there are no selections or the table hasn't been initialized yet
        if (!selectedRows || selectedRows.size === 0) {
            button.disabled = true;
            button.textContent = `Show Consolidated JSON (0 selected)`;
        }
    });
    
    // After everything is loaded, make one more pass to ensure JSON containers are positioned correctly
    setTimeout(() => {
        document.querySelectorAll('table[id^="rowDataTable_"]').forEach(table => {
            const tableIndex = table.id.replace('rowDataTable_', '');
            const tableId = `matchesTable_${tableIndex}`;
            const jsonContainer = document.getElementById(`jsonContainer_${tableId}`);
            
            if (jsonContainer && table) {
                // Re-insert the JSON container before the rowDataTable
                table.insertAdjacentElement('beforebegin', jsonContainer);
            }
        });
    }, 100);
});

/**
 * Update the consolidated JSON for a table
 * @param {string} tableId - ID of the table
 */
function updateConsolidatedJson(tableId) {
    try {
        // Get the selected rows for this table
        const selectedRows = tableSelections.get(tableId);
        
        if (!selectedRows || selectedRows.size === 0) {
            console.debug(`No rows selected for table ${tableId}`);
            consolidatedJsons.set(tableId, null);
            
            // Always update button state when there are no selections
            updateButton(tableId, false);
            
            // Update JSON display if it's visible
            updateJsonDisplayIfVisible(tableId);
            
            return;
        }
        
        // Extract the table index from the table ID
        const tableIndex = tableId.split('_')[1];
        
        // Extract metadata and raw platform data from the row data table
        const extractedData = extractDataFromTable(tableIndex);
        
        // Process the JSON based on the source
        const json = processJsonBasedOnSource(
            selectedRows, 
            extractedData.rawPlatformData, 
            extractedData.metadata
        );
        
        // Store the consolidated JSON for this table
        consolidatedJsons.set(tableId, json);
        
        console.debug(`Updated consolidated JSON for table ${tableId}`);
        
        // Find the consolidated JSON button
        const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
        
        // Update button with selection information
        if (showButton) {
            const statsStr = getStatisticsString(json, selectedRows.size);
            
            // Check if the display is currently visible
            const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
            const isVisible = display && !display.classList.contains('collapsed');
            
            // Update button text
            showButton.textContent = isVisible ? 
                `Hide Consolidated JSON (${statsStr})` : 
                `Show Consolidated JSON (${statsStr})`;
            
            // Update button state
            showButton.disabled = selectedRows.size === 0;
            
            // Update button styling based on display visibility
            if (isVisible) {
                showButton.classList.remove('btn-primary');
                showButton.classList.add('btn-success');
            } else {
                showButton.classList.remove('btn-success');
                showButton.classList.add('btn-primary');
            }
        }
        
        // Always update the JSON display if it's visible
        updateJsonDisplayIfVisible(tableId);
        
        // Also update the "Export All" button and configurations display
        updateExportAllButton();
        updateAllConfigurationsDisplay();
        
    } catch(e) {
        console.error(`Error updating consolidated JSON for table ${tableId}:`, e);
        consolidatedJsons.set(tableId, null);
    }
}

/**
 * Update the button state and text
 * @param {string} tableId - ID of the table
 * @param {boolean} hasSelections - Whether there are selections
 */
function updateButton(tableId, hasSelections) {
    try {
        const button = document.getElementById(`showConsolidatedJson_${tableId}`);
        
        if (button) {
            // Disable if there are no selections
            button.disabled = !hasSelections;
            
            // Update button text with selection count
            const statsStr = hasSelections ? 
                getStatisticsString(consolidatedJsons.get(tableId), tableSelections.get(tableId).size) : 
                "0 selected";
                
            // Check if the display is visible
            const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
            const isVisible = display && !display.classList.contains('collapsed');
            
            button.textContent = isVisible ? 
                `Hide Consolidated JSON (${statsStr})` : 
                `Show Consolidated JSON (${statsStr})`;
                
            // Update button tooltip
            button.title = hasSelections ? 
                'Show/hide the consolidated JSON' : 
                'Select rows to generate JSON';
        }
    } catch(e) {
        console.error(`Error updating button for table ${tableId}:`, e);
    }
}

// Add classes to elements when page loads (no CSS injection)
document.addEventListener('DOMContentLoaded', function() {
    // Add classes to tables
    document.querySelectorAll('table[id^="rowDataTable_"], table[id^="matchesTable_"]').forEach(table => {
        table.classList.add('collapsible-content');
        // Only set maxHeight if the table is visible
        if (!table.classList.contains('collapsed')) {
            table.style.maxHeight = Math.max(table.scrollHeight, 5000) + 'px';
        }
    });
    
    // Set up JSON display containers
    document.querySelectorAll('[id^="consolidatedJsonDisplay_"]').forEach(container => {
        container.classList.add('collapsible-content');
        container.classList.add('collapsed');
        container.style.maxHeight = '0';
    });
    
    // Add transition class to buttons
    document.querySelectorAll('[id^="collapseRowButton_"], [id^="showConsolidatedJson_"]').forEach(button => {
        button.classList.add('btn-transition');
    });
});