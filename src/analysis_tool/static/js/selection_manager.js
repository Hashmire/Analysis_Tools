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
 * @param {string} action - Optional action: 'complete' or 'skip' 
 */
function toggleRowCollapse(tableIndex, action) {
    try {
        const rowDataTableContainer = document.getElementById(`rowDataTable_${tableIndex}_container`);
        const matchesTableContainer = document.getElementById(`matchesTable_${tableIndex}_container`);
        const collapseButton = document.getElementById(`collapseRowButton_${tableIndex}`);
        
        // Add arrow icon toggle for CPE Suggestions card
        const cpeHeaderArrow = document.querySelector(`#cpeHeader_${tableIndex} .arrow-icon`);
        const provenanceHeaderArrow = document.querySelector(`#provenanceHeader_${tableIndex} .arrow-icon`);
        
        if (rowDataTableContainer && matchesTableContainer && collapseButton) {
            // Check if currently collapsed
            const isCollapsed = rowDataTableContainer.classList.contains('collapsed');
            
            if (isCollapsed) {
                // Expand tables
                rowDataTableContainer.classList.remove('collapsed');
                matchesTableContainer.classList.remove('collapsed');
                
                // Also remove status classes when expanding
                rowDataTableContainer.classList.remove('completed-row');
                rowDataTableContainer.classList.remove('skipped-row');
                
                // Ensure collapse sections are also shown
                const cpeCollapse = document.getElementById(`cpeCollapse_${tableIndex}`);
                const provenanceCollapse = document.getElementById(`provenanceCollapse_${tableIndex}`);
                
                if (cpeCollapse) {
                    cpeCollapse.classList.add('show');
                    if (cpeHeaderArrow) cpeHeaderArrow.innerHTML = "&darr;"; // Use innerHTML with HTML entity
                }
                
                if (provenanceCollapse) {
                    provenanceCollapse.classList.add('show');
                    if (provenanceHeaderArrow) provenanceHeaderArrow.innerHTML = "&darr;"; // Use innerHTML with HTML entity
                }
                
                // Check if we're using the dropdown approach by looking for parent .btn-group
                const btnGroup = collapseButton.closest('.btn-group');
                
                if (btnGroup) {
                    // We're using the dropdown approach
                    collapseButton.innerHTML = 'Collapse Row <span class="caret"></span>';
                    collapseButton.classList.remove('btn-success', 'btn-warning');
                    collapseButton.classList.add('btn-secondary', 'dropdown-toggle');
                    collapseButton.setAttribute('data-bs-toggle', 'dropdown');
                    collapseButton.setAttribute('aria-haspopup', 'true');
                    collapseButton.setAttribute('aria-expanded', 'false');
                    
                    // Make sure the dropdown menu is visible again
                    const dropdownMenu = btnGroup.querySelector('.dropdown-menu');
                    if (dropdownMenu) {
                        dropdownMenu.style.display = '';
                    }
                    
                    // Remove any directly attached click event
                    collapseButton.onclick = null;
                } else {
                    // We're using the direct button approach (from HTML)
                    collapseButton.textContent = 'Collapse Row (Complete)';
                    collapseButton.classList.remove('btn-success', 'btn-warning');
                    collapseButton.classList.add('btn-secondary');
                    
                    // Restore the original onclick handler
                    collapseButton.onclick = function() {
                        toggleRowCollapse(tableIndex);
                    };
                }
                
                // Make sure CPE Suggestions div is visible when expanding
                const cpeQueryContainer = document.getElementById(`cpe-query-container-${tableIndex}`);
                if (cpeQueryContainer) {
                    cpeQueryContainer.style.display = '';
                }
            } else {
                // If no action was provided but we're using the original onclick handler,
                // default to 'complete' to maintain backward compatibility
                if (!action) {
                    action = 'complete';
                }
                
                // Collapse tables with specified action
                rowDataTableContainer.classList.add('collapsed');
                matchesTableContainer.classList.add('collapsed');
                
                // Mark the row with the appropriate status class
                if (action === 'skip') {
                    rowDataTableContainer.classList.add('skipped-row');
                    rowDataTableContainer.classList.remove('completed-row');
                    collapseButton.textContent = 'Expand Row (Skipped)';
                    collapseButton.classList.remove('btn-secondary', 'dropdown-toggle');
                    collapseButton.classList.add('btn-warning');
                } else {
                    rowDataTableContainer.classList.add('completed-row');
                    rowDataTableContainer.classList.remove('skipped-row');
                    collapseButton.textContent = 'Expand Row (Completed)';
                    collapseButton.classList.remove('btn-secondary', 'dropdown-toggle');
                    collapseButton.classList.add('btn-success');
                }
                
                // Remove dropdown attributes if they exist
                collapseButton.removeAttribute('data-bs-toggle');
                collapseButton.removeAttribute('aria-haspopup');
                collapseButton.removeAttribute('aria-expanded');
                
                // Also collapse the Bootstrap collapse sections
                const cpeCollapse = document.getElementById(`cpeCollapse_${tableIndex}`);
                const provenanceCollapse = document.getElementById(`provenanceCollapse_${tableIndex}`);
                
                if (cpeCollapse) {
                    cpeCollapse.classList.remove('show');
                    if (cpeHeaderArrow) cpeHeaderArrow.innerHTML = "&uarr;"; // Use innerHTML with HTML entity
                }
                
                if (provenanceCollapse) {
                    provenanceCollapse.classList.remove('show'); 
                    if (provenanceHeaderArrow) provenanceHeaderArrow.innerHTML = "&uarr;"; // Use innerHTML with HTML entity
                }
                
                // Also collapse JSON if it's visible
                const jsonDisplay = document.getElementById(`consolidatedJsonDisplay_matchesTable_${tableIndex}`);
                if (jsonDisplay && !jsonDisplay.classList.contains('collapsed')) {
                    toggleConsolidatedJson(`matchesTable_${tableIndex}`);
                }
                
                // Also hide CPE Suggestions div when row collapses
                const cpeQueryContainer = document.getElementById(`cpe-query-container-${tableIndex}`);
                if (cpeQueryContainer) {
                    cpeQueryContainer.style.display = 'none';
                }
                
                // Hide the dropdown menu when an option is selected (if using dropdown)
                const btnGroup = collapseButton.closest('.btn-group');
                if (btnGroup) {
                    const dropdownMenu = btnGroup.querySelector('.dropdown-menu');
                    if (dropdownMenu) {
                        // Hide the dropdown menu
                        dropdownMenu.style.display = 'none';
                    }
                }
                
                // Set the click handler for the expand button
                collapseButton.onclick = function() {
                    toggleRowCollapse(tableIndex);
                };
            }
            
            // Update completion tracker
            if (typeof window.updateCompletionTracker === 'function') {
                window.updateCompletionTracker();
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
        
        cpeSuggesterHeader.parentNode.insertBefore(allContainer, cpeSuggesterHeader.nextSibling);
        
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
        
        // Find the existing button container
        const buttonContainer = document.getElementById(`buttonContainer_${tableIndex}`);
        if (buttonContainer) {
            // Clear any existing collapse button
            const existingButton = document.getElementById(`collapseRowButton_${tableIndex}`);
            if (existingButton) {
                buttonContainer.removeChild(existingButton);
            }
            
            // Create dropdown group
            const dropdownGroup = document.createElement('div');
            dropdownGroup.className = 'btn-group';
            
            // Create main button
            const mainButton = document.createElement('button');
            mainButton.id = `collapseRowButton_${tableIndex}`;
            mainButton.className = 'btn btn-secondary dropdown-toggle btn-transition';
            mainButton.innerHTML = 'Collapse Row <span class="caret"></span>';
            mainButton.setAttribute('data-bs-toggle', 'dropdown');
            mainButton.setAttribute('aria-haspopup', 'true');
            mainButton.setAttribute('aria-expanded', 'false');
            dropdownGroup.appendChild(mainButton);
            
            // Create dropdown menu
            const dropdownMenu = document.createElement('ul');
            dropdownMenu.className = 'dropdown-menu';
            
            // Create menu items
            const completeItem = document.createElement('li');
            const completeLink = document.createElement('a');
            completeLink.className = 'dropdown-item';
            completeLink.href = '#';
            completeLink.textContent = 'Mark as Complete';
            completeLink.onclick = function(e) {
                e.preventDefault();
                toggleRowCollapse(tableIndex, 'complete');
            };
            completeItem.appendChild(completeLink);
            
            const skipItem = document.createElement('li');
            const skipLink = document.createElement('a');
            skipLink.className = 'dropdown-item';
            skipLink.href = '#';
            skipLink.textContent = 'Mark as Skip';
            skipLink.onclick = function(e) {
                e.preventDefault();
                toggleRowCollapse(tableIndex, 'skip');
            };
            skipItem.appendChild(skipLink);
            
            // Add items to menu
            dropdownMenu.appendChild(completeItem);
            dropdownMenu.appendChild(skipItem);
            
            // Add menu to group
            dropdownGroup.appendChild(dropdownMenu);
            
            // Add the group to the container
            buttonContainer.appendChild(dropdownGroup);
        }
        
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
    
    // Add a single mutation observer for all collapse sections
    const observer = new MutationObserver((mutations) => {
        mutations.forEach(mutation => {
            if (mutation.attributeName === 'class') {
                const target = mutation.target;
                if (target.id && (target.id.startsWith('cpeCollapse_') || target.id.startsWith('provenanceCollapse_'))) {
                    const index = target.id.split('_')[1];
                    const type = target.id.startsWith('cpe') ? 'cpe' : 'provenance';
                    const arrowElement = document.querySelector(`#${type}Header_${index} .arrow-icon`);
                    
                    if (arrowElement) {
                        // Use HTML entities and innerHTML instead of Unicode and textContent
                        const isShown = target.classList.contains('show');
                        arrowElement.innerHTML = isShown ? "&darr;" : "&uarr;";
                    }
                }
            }
        });
    });
    
    // Apply the observer to all collapse sections
    const collapseSections = document.querySelectorAll('[id^="cpeCollapse_"],[id^="provenanceCollapse_"]');
    collapseSections.forEach(section => {
        observer.observe(section, { attributes: true });
    });
    
    // Initialize all arrow icons with HTML entities
    document.querySelectorAll('.arrow-icon').forEach(arrow => {
        const parentHeader = arrow.closest('.card-header');
        if (!parentHeader) return;
        
        const targetId = parentHeader.getAttribute('data-bs-target');
        if (!targetId) return;
        
        const target = document.querySelector(targetId);
        if (!target) return;
        
        // Set initial state using HTML entities
        const isShown = target.classList.contains('show');
        arrow.innerHTML = isShown ? "&darr;" : "&uarr;";
    });
});

// Export helpers needed by completion_tracker.js
window.getSourceData = getSourceData;
window.getSourceById = getSourceById;