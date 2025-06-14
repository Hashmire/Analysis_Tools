/**
 * Completion tracker module for CVE analysis tool
 * 
 * This module provides source data management functions and completion tracking.
 */

/**
 * Update the completion tracker with source-specific information
 */
function updateCompletionTracker() {
    try {
        const tableContainers = document.querySelectorAll('div[id^="rowDataTable_"][id$="_container"]');
        let completedCount = 0;
        let skippedCount = 0;
        const totalCount = tableContainers.length;
        
        // Track completion by source
        const sourceStats = {};
        const sourceNames = {};
        
        // Get source data from global metadata
        const sourceData = getSourceData();
        
        // First pass: examine all tables to find source identifiers
        tableContainers.forEach(container => {
            const isCompleted = container.classList.contains('collapsed') && container.classList.contains('completed-row');
            const isSkipped = container.classList.contains('collapsed') && container.classList.contains('skipped-row');
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
                sourceStats[sourceId] = { total: 0, completed: 0, skipped: 0 };
                
                // Get source name from global metadata
                const sourceInfo = getSourceById(sourceId);
                sourceNames[sourceId] = sourceInfo ? sourceInfo.name : sourceId;
            }
            
            // Update source stats
            sourceStats[sourceId].total++;
            
            if (isCompleted) {
                sourceStats[sourceId].completed++;
                completedCount++;
            } else if (isSkipped) {
                sourceStats[sourceId].skipped++;
                skippedCount++;
            }
        });
        
        // Calculate percentage - include both completed and skipped in progress
        const processedCount = completedCount + skippedCount;
        const percentage = totalCount > 0 ? Math.round((processedCount / totalCount) * 100) : 0;
        
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
            displayElements.push(`${processedCount}/${totalCount} rows`);
            
            // Add completed/skipped breakdown if there are any skipped rows
            if (skippedCount > 0) {
                displayElements.push(`${skippedCount} skipped`);
            }
            
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
                    
                    // Count both completed and skipped for the source's progress
                    const processedForSource = stats.completed + stats.skipped;
                    
                    // Use plain text for status indicators to avoid encoding issues
                    let indicator;
                    if (processedForSource === stats.total) {
                        indicator = 'Done';
                    } else {
                        indicator = `${processedForSource}/${stats.total}`;
                    }
                    
                    // If there are skipped items, add details in parentheses using ASCII
                    if (stats.skipped > 0) {
                        indicator += ` (${stats.skipped} skipped)`;
                    }
                    
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
 * @returns {Array|null} The source data array or null if not found
 */
function getSourceData() {
    try {
        const metadataDiv = document.getElementById('global-cve-metadata');
        if (!metadataDiv || !metadataDiv.hasAttribute('data-cve-metadata')) {
            return null;
        }
        
        const metadata = JSON.parse(metadataDiv.getAttribute('data-cve-metadata'));
        return metadata.sourceData || [];  // Return as array instead of object
    } catch (e) {
        console.error('Error retrieving source data:', e);
        return [];  // Return empty array instead of empty object
    }
}

/**
 * Get source information by ID from the global metadata
 * @param {string} sourceId - The source ID to look for
 * @returns {Object|null} Source information or null if not found
 */
function getSourceById(sourceId) {
    try {
        const sourceData = getSourceData();
        if (!sourceData || !Array.isArray(sourceData)) {
            console.warn(`No source data available when looking up sourceId: ${sourceId}`);
            return null;
        }
        
        // First try exact match on sourceId
        let source = sourceData.find(source => source.sourceId === sourceId);
        
        // If not found, try checking sourceIdentifiers
        if (!source) {
            source = sourceData.find(source => 
                source.sourceIdentifiers && 
                Array.isArray(source.sourceIdentifiers) && 
                source.sourceIdentifiers.includes(sourceId)
            );
        }
        
        // Log when source is not found
        if (!source) {
            console.warn(`Source not found for ID: ${sourceId}`);
            // Debug: dump all available source IDs to help troubleshooting
            console.debug('Available source IDs:', 
                sourceData.map(s => ({id: s.sourceId, name: s.name, identifiers: s.sourceIdentifiers}))
            );
        }
        
        return source;
    } catch (e) {
        console.error(`Error retrieving source data for ID ${sourceId}:`, e);
        return null;
    }
}

/**
 * Create the completion tracker UI elements
 * @param {number} totalTables - Total number of tables to track
 */
function initializeCompletionTracker(totalTables) {
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
            <span id="totalRowsCount">${totalTables} total rows</span>
        </div>
    `;

    return completionTrackerContainer;
}

// Initialize completion tracker on document load
document.addEventListener('DOMContentLoaded', function() {
    try {
        // Find all matchesTables (there may be multiple)
        const tables = document.querySelectorAll('table[id^="matchesTable"]');
        
        // Check if the completion tracker container already exists
        if (!document.getElementById('completionTrackerContainer')) {
            // Find where to insert the tracker
            const cpeSuggesterHeader = document.getElementById('cpeSuggesterHeader');
            const allContainer = document.getElementById('allConfigurationsContainer');
            
            if (cpeSuggesterHeader) {
                // Create tracker container
                const completionTrackerContainer = initializeCompletionTracker(tables.length);
                
                // Insert the completion tracker in the DOM
                if (allContainer) {
                    cpeSuggesterHeader.parentNode.insertBefore(completionTrackerContainer, allContainer);
                } else {
                    cpeSuggesterHeader.parentNode.insertBefore(
                        completionTrackerContainer, 
                        cpeSuggesterHeader.nextSibling
                    );
                }
                
                // Initial tracker update
                updateCompletionTracker();
            }        }
    } catch(e) {
        console.error('Error initializing completion tracker:', e);
    }
});

// =============================================================================
// Global Exports - All window assignments consolidated here
// =============================================================================
window.getSourceData = getSourceData;
window.getSourceById = getSourceById;
window.updateCompletionTracker = updateCompletionTracker;
window.initializeCompletionTracker = initializeCompletionTracker;