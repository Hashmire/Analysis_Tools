/**
 * Update JSON display if it's currently visible
 * @param {string} tableId - ID of the table
 */
function updateJsonDisplayIfVisible(tableId) {
    try {
        const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
        const content = document.getElementById(`consolidatedJsonContent_${tableId}`);
        
        // Use class check instead of style.display
        if (display && content && !display.classList.contains('collapsed')) {
            const selectedRows = tableSelections.get(tableId);
            const selectionCount = selectedRows ? selectedRows.size : 0;
            
            if (!selectedRows || selectedRows.size === 0) {
                content.textContent = 'No rows selected. Please select at least one row.';
                return;
            }
            
            // Get the consolidated JSON for this table
            const json = consolidatedJsons.get(tableId);
            
            if (json) {
                // json is now already an array, so just stringify it
                content.textContent = JSON.stringify(json, null, 2);
            } else {
                content.textContent = 'No selections or error generating JSON.';
            }
            
            // Also update the button text
            updateJsonDisplay(tableId, json, selectionCount);
        }
    } catch(e) {
        console.error(`Error updating JSON display for table ${tableId}:`, e);
    }
}

/**
 * Update the JSON display and button based on the content
 * @param {string} tableId - ID of the table
 * @param {Object} json - The JSON to display
 * @param {number} selectionCount - Number of selected items
 */
function updateJsonDisplay(tableId, json, selectionCount) {
    try {
        const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
        const content = document.getElementById(`consolidatedJsonContent_${tableId}`);
        const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
        
        if (display && content) {
            // Check if the display is already visible
            const isVisible = !display.classList.contains('collapsed');
            
            // Update the content
            if (json) {
                content.textContent = JSON.stringify(json, null, 2);
            } else {
                content.textContent = 'No selections or error generating JSON.';
            }
            
            // Update button text if it's found
            if (showButton) {
                // Get statistics string
                const statsStr = getStatisticsString(json, selectionCount);
                
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

/**
 * Update the Export All Configurations button
 */
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
        
        const container = document.getElementById('allConfigurationsContainer');
        const exportButton = document.getElementById('exportAllConfigurations');
        const configSummary = document.getElementById('configurationSummary');
        
        if (container && exportButton && configSummary) {
            // Always enable/disable the button based on selections
            exportButton.disabled = !hasSelections;
            
            if (hasSelections) {
                const display = document.getElementById('allConfigurationsDisplay');
                
                // Format the config summary
                const summaryText = `${configCount} config${configCount !== 1 ? 's' : ''} (${configDetails.join(', ')})`;
                
                // Update the summary text
                configSummary.textContent = summaryText;
                
                // Keep button text simple - just show/hide state
                exportButton.textContent = display && !display.classList.contains('collapsed') ? 
                    'Hide All Configurations' : 'Show All Configurations';
            } else {
                // No selections in any table
                configSummary.textContent = 'No CPEs selected yet';
                exportButton.textContent = 'Show All Configurations';
            }
            
            // Ensure the display is updated if it's open
            updateAllConfigurationsDisplay();
        }
    } catch(e) {
        console.error("Error updating export all button:", e);
    }
}

/**
 * Update the all configurations display
 */
function updateAllConfigurationsDisplay() {
    try {
        const display = document.getElementById('allConfigurationsDisplay');
        const content = document.getElementById('allConfigurationsContent');
        
        // Always update regardless of visibility - this ensures content is ready when display is shown
        if (display && content) {
            const allConfigs = generateAllConfigurationsJson();
            console.debug("updateAllConfigurationsDisplay - allConfigs:", allConfigs, "length:", allConfigs.length);
            
            // More detailed debugging
            console.debug("allConfigs type:", typeof allConfigs);
            console.debug("allConfigs isArray:", Array.isArray(allConfigs));
            console.debug("allConfigs content:", JSON.stringify(allConfigs).substring(0, 100) + "...");
            
            // Simplify the condition - just check if array has items
            if (Array.isArray(allConfigs) && allConfigs.length > 0) {
                content.textContent = JSON.stringify(allConfigs, null, 2);
            } else {
                content.textContent = 'No CPEs selected in any table. Please select at least one CPE row.';
            }
        }
    } catch(e) {
        console.error("Error updating all configurations display:", e);
    }
}

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
    
    // Store current state using class check
    const isDisplayVisible = !display.classList.contains('collapsed');
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