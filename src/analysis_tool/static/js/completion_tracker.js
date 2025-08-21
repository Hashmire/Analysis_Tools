/**
 * Completion tracker module for Hashmire/Analysis_Tools
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
            
            // Use the unified data extraction system for source resolution
            let sourceId = null;
            
            try {
                // Use unified data extraction
                if (typeof window.unifiedExtractDataFromTable !== 'function') {
                    console.error(`Unified data extraction not available for table ${tableIndex}. Check that unified_data_extraction.js is loaded.`);
                    return;
                }
                
                const extractedData = window.unifiedExtractDataFromTable(tableIndex);
                sourceId = extractedData.metadata.sourceId;
                console.debug(`Table ${tableIndex}: extracted sourceId via unified approach: ${sourceId}`);
            } catch (error) {
                console.error(`Error extracting source data for table ${tableIndex}:`, error);
                return;
            }
            
            // Skip if no source ID found
            if (!sourceId || sourceId === 'Unknown') {
                console.debug(`No valid source ID found for table ${tableIndex}`);
                return;
            }
            
            // Initialize source stats if not already tracked
            if (!sourceStats[sourceId]) {
                sourceStats[sourceId] = { total: 0, completed: 0, skipped: 0 };
                
                // Use unified source system for consistent data access
                const sourceInfo = window.UnifiedSourceManager ? 
                    window.UnifiedSourceManager.getSourceById(sourceId) : null;
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
 * Get all source data using the unified source system
 * @returns {Object} The source registry object
 */
function getSourceData() {
    if (!window.UnifiedSourceManager) {
        console.error('Unified source manager not available for source data');
        return {};
    }
    
    return window.UnifiedSourceManager.getAllSources();
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
window.updateCompletionTracker = updateCompletionTracker;
window.initializeCompletionTracker = initializeCompletionTracker;