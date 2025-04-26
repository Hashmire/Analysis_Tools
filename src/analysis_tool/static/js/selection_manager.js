/**
 * Function to handle tab navigation
 * @param {Event} evt - The click event
 * @param {string} tabName - The ID of the tab to open
 */
function openCity(evt, cityName) {
    let tabcontent = document.getElementsByClassName("tabcontent");
    for (let i = 0; i < tabcontent.length; i++) {
        tabcontent[i].classList.add('d-none');
    }
    
    let tablinks = document.getElementsByClassName("tablinks");
    for (let i = 0; i < tablinks.length; i++) {
        tablinks[i].classList.remove("active");
    }
    
    document.getElementById(cityName).classList.remove('d-none');
    evt.currentTarget.classList.add("active");
}

// Make the function available globally
window.openCity = openCity;

/**
 * Function to toggle row collapse state
 * @param {number} tableIndex - Index of the table
 */
function toggleRowCollapse(tableIndex) {
    try {
        const rowDataTableContainer = document.getElementById(`rowDataTable_${tableIndex}_container`);
        const matchesTableContainer = document.getElementById(`matchesTable_${tableIndex}_container`);
        const collapseButton = document.getElementById(`collapseRowButton_${tableIndex}`);
        
        if (rowDataTableContainer && matchesTableContainer && collapseButton) {
            // Check if currently collapsed
            const isCollapsed = rowDataTableContainer.classList.contains('collapsed');
            
            if (isCollapsed) {
                // Expand tables
                rowDataTableContainer.classList.remove('collapsed');
                matchesTableContainer.classList.remove('collapsed');
            } else {
                // Collapse tables
                rowDataTableContainer.classList.add('collapsed');
                matchesTableContainer.classList.add('collapsed');
                
                // Also collapse JSON if it's visible
                const jsonDisplay = document.getElementById(`consolidatedJsonDisplay_matchesTable_${tableIndex}`);
                if (jsonDisplay && !jsonDisplay.classList.contains('collapsed')) {
                    toggleConsolidatedJson(`matchesTable_${tableIndex}`);
                }
            }
            
            // Update button
            collapseButton.textContent = isCollapsed ? 'Collapse Row (Mark Complete)' : 'Expand Row (Completed)';
            if (isCollapsed) {
                collapseButton.classList.remove('btn-success');
                collapseButton.classList.add('btn-secondary');
            } else {
                collapseButton.classList.remove('btn-secondary');
                collapseButton.classList.add('btn-success');
            }
            
            // Update completion tracker
            if (typeof updateCompletionTracker === 'function') {
                updateCompletionTracker();
            }
        }
    } catch(e) {
        console.error(`Error in toggleRowCollapse for tableIndex ${tableIndex}:`, e);
    }
}

// Make toggleRowCollapse available globally for HTML button onclick handlers
window.toggleRowCollapse = toggleRowCollapse;

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
        
        showButton.disabled = selectionCount === 0;
        
        if (selectionCount > 0) {
            // Toggle collapsed class only - no style manipulation
            display.classList.toggle('collapsed');
            const isCollapsed = display.classList.contains('collapsed');
            
            // Update button with stats and style
            const statsStr = getStatisticsString(consolidatedJsons.get(tableId), selectionCount);
            showButton.textContent = isCollapsed ? 
                `Show Consolidated JSON (${statsStr})` : 
                `Hide Consolidated JSON (${statsStr})`;
            
            // Toggle button classes
            if (isCollapsed) {
                showButton.classList.remove('btn-success');
                showButton.classList.add('btn-primary');
            } else {
                showButton.classList.remove('btn-primary');
                showButton.classList.add('btn-success');
                updateJsonDisplayIfVisible(tableId);
            }
        } else {
            // No selections case
            display.classList.add('collapsed');
            showButton.textContent = `Show Consolidated JSON (0 selected)`;
            showButton.classList.remove('btn-success');
            showButton.classList.add('btn-primary');
        }
    } catch(e) {
        console.error(`Error in toggleConsolidatedJson for tableId ${tableId}:`, e);
    }
}

/**
 * Update the completion tracker with source-specific information
 */
function updateCompletionTracker() {
    try {
        const tableContainers = document.querySelectorAll('div[id^="rowDataTable_"][id$="_container"]');
        let completedCount = 0;
        const totalCount = tableContainers.length;
        
        // Track completion by source
        const sourceStats = {};
        const sourceNames = {};
        
        // Get source data from global metadata
        const sourceData = getSourceData();
        
        // First pass: examine all tables to find source identifiers
        tableContainers.forEach(container => {
            const isCompleted = container.classList.contains('collapsed');
            const tableIndex = container.id.replace('rowDataTable_', '').replace('_container', '');
            
            // Get the actual table
            const rowDataTable = document.getElementById(`rowDataTable_${tableIndex}`);
            if (!rowDataTable) return;
            
            // Find source information - specifically look for Source ID row
            const sourceRows = rowDataTable.querySelectorAll('tr');
            let sourceId = null;
            
            // First try to find Source ID row with UUID
            for (const row of sourceRows) {
                const firstCell = row.querySelector('td:first-child');
                if (!firstCell || firstCell.textContent.trim() !== 'Source ID') continue;
                
                const sourceCell = row.querySelector('td:nth-child(2) span[title]');
                if (!sourceCell || !sourceCell.title) continue;
                
                const titleText = sourceCell.title;
                
                // Check if this is the NIST source (special case)
                if (titleText.includes('Contact Email: nvd@nist.gov')) {
                    sourceId = 'nvd@nist.gov';
                    break;
                }
                
                // Extract all UUIDs from Source Identifiers section
                const identifiersSection = titleText.match(/Source Identifiers:\s*([^]*?)(?=\n|$)/);
                if (identifiersSection && identifiersSection[1]) {
                    // Split by comma and trim whitespace
                    const identifiers = identifiersSection[1].split(',').map(id => id.trim());
                    
                    // Find a valid UUID format in the identifiers
                    for (const id of identifiers) {
                        if (id.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
                            sourceId = id;
                            break;
                        }
                    }
                    
                    // If we found a UUID, break out of the row loop
                    if (sourceId) break;
                }
            }
            
            // Skip if no source ID found
            if (!sourceId) {
                console.debug(`No source ID found for table ${tableIndex}`);
                return;
            }
            
            // Initialize source stats if not already tracked
            if (!sourceStats[sourceId]) {
                sourceStats[sourceId] = { total: 0, completed: 0 };
                
                // Get source name from global metadata
                if (sourceData && sourceData[sourceId]) {
                    sourceNames[sourceId] = sourceData[sourceId].name || sourceId;
                } else {
                    // Basic fallback for display - just use the first 8 chars for UUID
                    sourceNames[sourceId] = sourceId;
                }
            }
            
            // Update source stats
            sourceStats[sourceId].total++;
            if (isCompleted) {
                sourceStats[sourceId].completed++;
                completedCount++;
            }
        });
        
        // Calculate percentage
        const percentage = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;
        
        // Update UI
        const progressBar = document.getElementById('completionProgressBar');
        const completedRowsCount = document.getElementById('completedRowsCount');
        const totalRowsCount = document.getElementById('totalRowsCount');
        
        if (progressBar && completedRowsCount && totalRowsCount) {
            progressBar.style.width = `${percentage}%`;
            progressBar.textContent = `${percentage}%`;
            progressBar.setAttribute('aria-valuenow', percentage);
            
            const displayElements = [];
            
            // Add the overall completion count
            displayElements.push(`${completedCount}/${totalCount} rows`);
            
            // Sort sources by name for consistent display
            const sortedSourceIds = Object.keys(sourceStats).sort((a, b) => 
                sourceNames[a].localeCompare(sourceNames[b])
            );
            
            // Add each source with its completion status
            if (sortedSourceIds.length > 0) {
                const sourceElements = [];
                
                sortedSourceIds.forEach(sourceId => {
                    const stats = sourceStats[sourceId];
                    const sourceName = sourceNames[sourceId];
                    
                    // Use a checkmark for fully completed sources, otherwise show fraction
                    const indicator = stats.completed === stats.total ? 
                        '\u2713' : // Unicode checkmark character
                        `${stats.completed}/${stats.total}`;
                    
                    sourceElements.push(`${sourceName}: ${indicator}`);
                });
                
                // Join the source elements with commas
                if (sourceElements.length > 0) {
                    displayElements.push(`Sources: ${sourceElements.join(', ')}`);
                }
            }
            
            // Update the text content with all elements
            completedRowsCount.textContent = displayElements.join(' | ');
            
            // Hide the separate total count as it's now incorporated
            totalRowsCount.textContent = '';
        }
    } catch(e) {
        console.error('Error updating completion tracker:', e);
    }
}

/**
 * Get the source data from the global metadata
 * @returns {Object|null} The source data object or null if not found
 */
function getSourceData() {
    try {
        const metadataDiv = document.getElementById('global-cve-metadata');
        if (!metadataDiv || !metadataDiv.hasAttribute('data-cve-metadata')) {
            return null;
        }
        
        const metadata = JSON.parse(metadataDiv.getAttribute('data-cve-metadata'));
        return metadata.sourceData || {};
    } catch (e) {
        console.error('Error retrieving source data:', e);
        return {};
    }
}

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
            const isVisible = !display.classList.contains('collapsed');
            
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
            const isVisible = !display.classList.contains('collapsed');
            
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

/**
 * Toggle provenance description visibility with smooth animation
 * @param {string} buttonId - ID of the toggle button
 */
function toggleProvenanceDescription(buttonId) {
    try {
        const descriptionId = buttonId.replace('toggle_', 'description_');
        const descriptionElement = document.getElementById(descriptionId);
        const button = document.getElementById(buttonId);
        
        if (!descriptionElement || !button) return;
        
        // Toggle the collapsed class for animation
        descriptionElement.classList.toggle('collapsed');
        const isCollapsed = descriptionElement.classList.contains('collapsed');
        
        // Update the button text and styling
        button.textContent = isCollapsed ? 'Show Description' : 'Hide Description';
        if (isCollapsed) {
            button.classList.remove('btn-success');
            button.classList.add('btn-info');
        } else {
            button.classList.remove('btn-info');
            button.classList.add('btn-success');
        }
    } catch(e) {
        console.error(`Error toggling provenance description for ${buttonId}:`, e);
    }
}

// Make the function available globally
window.toggleProvenanceDescription = toggleProvenanceDescription;

// Add a helper function to get source information by UUID

/**
 * Get source information from global metadata by UUID
 * @param {string} uuid - The source UUID to look up
 * @returns {Object|null} - The source info object or null if not found
 */
function getSourceInfoByUuid(uuid) {
    const metadataDiv = document.getElementById('global-cve-metadata');
    if (!metadataDiv || !metadataDiv.hasAttribute('data-cve-metadata')) {
        return null;
    }
    
    try {
        const metadata = JSON.parse(metadataDiv.getAttribute('data-cve-metadata'));
        if (!metadata || !metadata.sourceData) {
            return null;
        }
        
        return metadata.sourceData[uuid] || null;
    } catch (e) {
        console.error('Error parsing source metadata:', e);
        return null;
    }
}

// Single consolidated initialization for all DOM elements
document.addEventListener('DOMContentLoaded', function() {
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
    
    // Add a master "Export All Configurations" button at the top of cveListCPESuggester
    const cveListCPESuggester = document.getElementById('cveListCPESuggester');
    const cpeSuggesterHeader = document.getElementById('cpeSuggesterHeader');
    
    if (cveListCPESuggester && cpeSuggesterHeader) {
        // Create the Export All container
        const allContainer = document.createElement('div');
        allContainer.classList.add('all-configurations-container', 'mt-1', 'mb-1');
        allContainer.id = 'allConfigurationsContainer';
        allContainer.innerHTML = `
            <!-- Configuration summary above the button -->
            <div id="configurationSummary" class="text-center mb-2"></div>
            <div class="d-grid gap-2 col-12 mx-auto">
                <button id="exportAllConfigurations" class="btn btn-primary btn-transition">Show All Configurations</button>
            </div>
            <div id="allConfigurationsDisplay" class="mt-2 consolidated-json-container collapsed">
                <h4>Complete Configuration JSON</h4>
                <p class="text-muted">This combines all selected CPEs from all tables, with each table creating its own configuration node.</p>
                <pre id="allConfigurationsContent"></pre>
            </div>
        `;
        
        // Create a completion tracker container
        const completionTrackerContainer = document.createElement('div');
        completionTrackerContainer.classList.add('completion-tracker-container', 'mt-1', 'mb-1', 'p-3', 'border', 'rounded');
        completionTrackerContainer.id = 'completionTrackerContainer';
        completionTrackerContainer.innerHTML = `
            <h4>Completion Progress</h4>
            <div class="progress mb-2">
                <div id="completionProgressBar" class="progress-bar bg-success" role="progressbar" style="width: 0%" 
                     aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
            </div>
            <div class="d-flex justify-content-between">
                <span id="completedRowsCount">0 rows completed</span>
                <span id="totalRowsCount">${tables.length} total rows</span>
            </div>
        `;
        
        // Insert containers after the header in the correct order
        cpeSuggesterHeader.parentNode.insertBefore(completionTrackerContainer, cpeSuggesterHeader.nextSibling);
        completionTrackerContainer.parentNode.insertBefore(allContainer, completionTrackerContainer.nextSibling);
        
        // Add click handler to the Export All button
        document.getElementById('exportAllConfigurations').addEventListener('click', function() {
            const display = document.getElementById('allConfigurationsDisplay');
            const content = document.getElementById('allConfigurationsContent');
            
            if (display && content) {
                // Create master JSON
                const masterJson = generateAllConfigurationsJson();
                
                // Update content
                if (!masterJson || !masterJson.configurations || masterJson.configurations.length === 0) {
                    content.textContent = 'No CPEs selected in any table. Please select at least one CPE row.';
                } else {
                    content.textContent = JSON.stringify(masterJson, null, 2);
                }
                
                // Toggle visibility class
                display.classList.toggle('collapsed');
                
                // Update button text based on collapsed state
                const isCollapsed = display.classList.contains('collapsed');
                this.textContent = isCollapsed ? 'Show All Configurations' : 'Hide All Configurations';
                
                // Toggle button styling with classes
                if (isCollapsed) {
                    this.classList.remove('btn-success');
                    this.classList.add('btn-primary');
                } else {
                    this.classList.remove('btn-primary');
                    this.classList.add('btn-success');
                }
            }
        });
    } else {
        console.error('Error: Could not find required elements for container positioning', {
            cveListCPESuggester: !!cveListCPESuggester,
            cpeSuggesterHeader: !!cpeSuggesterHeader
        });
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
                
                // Update the consolidated JSON for this table
                updateConsolidatedJson(tableId);
                
                // Update the Export All button (this will also update configSummary)
                updateExportAllButton();
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
        }
        
        // Convert the matchesTable to use the new collapsible structure
        table.classList.add('collapsible-content');
        
        // Create a container for consolidated JSON right after the row data table
        const container = document.createElement('div');
        container.classList.add('json-container', 'mt-3', 'mb-4');
        container.id = `jsonContainer_${tableId}`;
        container.setAttribute('data-index', tableIndex);
        container.innerHTML = `
            <div id="consolidatedJsonDisplay_${tableId}" class="json-display-container collapsed">
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
                    toggleConsolidatedJson(tableId);
                } catch(e) {
                    console.error(`Error toggling JSON display for table ${tableId}:`, e);
                }
            });
        }
    });
    
    // Initial update of Export All button visibility
    updateExportAllButton();
    
    // Initialize button transitions
    document.querySelectorAll('[id^="collapseRowButton_"], [id^="showConsolidatedJson_"], #exportAllConfigurations').forEach(button => {
        button.classList.add('btn-transition');
    });
    
    // Initialize JSON display containers
    document.querySelectorAll('[id^="consolidatedJsonDisplay_"]').forEach(container => {
        container.classList.add('json-display-container');
    });
    
    // Check for any tables that need to start collapsed
    const tableButtons = document.querySelectorAll('[id^="collapseRowButton_"]');
    tableButtons.forEach(button => {
        if (button.textContent.includes('Expand Row')) {
            // Extract index from button ID
            const index = button.id.replace('collapseRowButton_', '');
            const rowDataTableContainer = document.getElementById(`rowDataTable_${index}_container`);
            const matchesTableContainer = document.getElementById(`matchesTable_${index}_container`);
            
            // Apply collapsed state to containers
            if (rowDataTableContainer) rowDataTableContainer.classList.add('collapsed');
            if (matchesTableContainer) matchesTableContainer.classList.add('collapsed');
        }
    });
    
    // Initialize the completion tracker
    if (typeof updateCompletionTracker === 'function') {
        updateCompletionTracker();
    }
    
    // Scan for git versionTypes if available
    if (typeof scanForGitVersionTypes === 'function') {
        scanForGitVersionTypes();
    }
    
    // Initialize provenance description containers
    document.querySelectorAll('[id^="description_"]').forEach(container => {
        container.classList.add('description-container', 'collapsed');
        
        // Find associated button and update its text/style
        const buttonId = container.id.replace('description_', 'toggle_');
        const button = document.getElementById(buttonId);
        if (button) {
            button.textContent = 'Show Description';
            button.classList.add('btn-transition', 'btn-info');
        }
    });
    
    // Initialize provenance description containers
    document.querySelectorAll('[id^="description_"]').forEach(container => {
        container.classList.add('description-container');
        
        // If not already collapsed, add collapsed class
        if (!container.classList.contains('collapsed')) {
            container.classList.add('collapsed');
        }
        
        // Find associated button and update its text/style
        const buttonId = container.id.replace('description_', 'toggle_');
        const button = document.getElementById(buttonId);
        if (button) {
            button.textContent = 'Show Description';
            button.classList.add('btn-transition', 'btn-info');
        }
    });
    
    // Also check for description content areas from the provenance assistance module
    document.querySelectorAll('.description-content').forEach(content => {
        // Make sure they have the proper transition classes
        if (!content.classList.contains('collapsed')) {
            content.classList.add('collapsed');
        }
    });
    
    // Initialize provenance description containers
    document.querySelectorAll('[id^="description_"]').forEach(container => {
        container.classList.add('description-container', 'collapsed');
        
        // Find associated button and update its text/style
        const buttonId = container.id.replace('description_', 'toggle_');
        const button = document.getElementById(buttonId);
        if (button) {
            button.textContent = 'Show Description';
            button.classList.add('btn-transition', 'btn-info');
        }
    });
});