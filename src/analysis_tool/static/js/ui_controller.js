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
                
                // Add copy button if it doesn't exist
                if (!document.getElementById(`copyButton_${tableId}`)) {
                    const copyButton = document.createElement('button');
                    copyButton.id = `copyButton_${tableId}`;
                    copyButton.className = 'btn btn-sm btn-outline-secondary copy-button';
                    copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy to Clipboard';
                    copyButton.onclick = function() { 
                        copyToClipboard(content.textContent, `copyButton_${tableId}`);
                    };
                    // Insert before the pre element
                    display.insertBefore(copyButton, content);
                }
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
        
        if (!display || !content) {
            console.warn('Could not find allConfigurations display elements');
            return;
        }
        
        // Check if display is currently visible
        const isDisplayVisible = !display.classList.contains('collapsed');
        if (!isDisplayVisible) return;
        
        // Generate all configurations JSON
        const allConfigs = generateAllConfigurationsJson();
        
        // Make sure we have configurations to display
        if (allConfigs && allConfigs.length > 0) {
            content.textContent = JSON.stringify(allConfigs, null, 2);
            
            // Add buttons container if it doesn't exist
            let buttonsContainer = document.getElementById('allConfigButtonsContainer');
            if (!buttonsContainer) {
                buttonsContainer = document.createElement('div');
                buttonsContainer.id = 'allConfigButtonsContainer';
                buttonsContainer.className = 'mb-2';
                // Insert before the pre element
                display.insertBefore(buttonsContainer, content);
                
                // Add copy button
                const copyButton = document.createElement('button');
                copyButton.id = 'copyAllConfigsButton';
                copyButton.className = 'btn btn-sm btn-outline-secondary me-2';
                copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy to Clipboard';
                copyButton.onclick = function() { 
                    copyToClipboard(content.textContent, 'copyAllConfigsButton');
                };
                buttonsContainer.appendChild(copyButton);
                
                // Add export button
                const exportButton = document.createElement('button');
                exportButton.id = 'exportAllConfigsButton';
                exportButton.className = 'btn btn-sm btn-outline-primary';
                exportButton.innerHTML = '<i class="fas fa-download"></i> Export to File';
                exportButton.onclick = function() { 
                    exportToFile(content.textContent);
                };
                buttonsContainer.appendChild(exportButton);
            }
            
            // Update configuration summary with count of configurations
            const summary = document.getElementById('configurationSummary');
            if (summary) {
                let totalCPEMatches = 0;
                allConfigs.forEach(config => {
                    totalCPEMatches += getTotalCPEMatches(config);
                });
                
                summary.textContent = `${allConfigs.length} configurations with ${totalCPEMatches} total matches`;
            }
        } else {
            content.textContent = 'No configurations available. Please select rows from tables.';
        }
    } catch(e) {
        console.error('Error updating all configurations display:', e);
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

/**
 * Copy content to clipboard and show feedback
 * @param {string} text - Text to copy
 * @param {string} buttonId - ID of button that was clicked
 */
function copyToClipboard(text, buttonId) {
    try {
        navigator.clipboard.writeText(text).then(() => {
            // Show success feedback on button
            const button = document.getElementById(buttonId);
            const originalText = button.innerHTML;
            button.innerHTML = '<i class="fas fa-check"></i> Copied!';
            button.classList.add('btn-success');
            button.classList.remove('btn-outline-secondary');
            
            // Reset button after delay
            setTimeout(() => {
                button.innerHTML = originalText;
                button.classList.remove('btn-success');
                button.classList.add('btn-outline-secondary');
            }, 2000);
        }).catch(err => {
            console.error('Could not copy text: ', err);
        });
    } catch(e) {
        console.error('Error copying to clipboard:', e);
    }
}

/**
 * Export JSON content to file
 * @param {string} content - Content to export
 */
function exportToFile(content) {
    try {
        // Get CVE ID directly from the element with id "cve-id"
        let cveId = "config";
        const cveElement = document.getElementById("cve-id");
        
        if (cveElement && cveElement.textContent) {
            cveId = cveElement.textContent.trim();
        }
        
        // Create blob and download link
        const blob = new Blob([content], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `${cveId}-configurations.json`;
        document.body.appendChild(link);
        link.click();
        
        // Clean up
        setTimeout(() => {
            URL.revokeObjectURL(url);
            document.body.removeChild(link);
        }, 100);
    } catch(e) {
        console.error('Error exporting to file:', e);
    }
}