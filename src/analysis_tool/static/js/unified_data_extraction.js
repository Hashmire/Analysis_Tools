/**
 * Unified Data Extraction
 * 
 * Provides unified data extraction functions that work with the centralized 
 * source management system. Replaces extractDataFromTable and other legacy functions.
 */

/**
 * Extract metadata and rawPlatformData using the unified source system
 * @param {string|number} tableIndex - Index of the table
 * @returns {Object} Extracted data including metadata and rawPlatformData
 */
function unifiedExtractDataFromTable(tableIndex) {
    // Ensure unified source manager is available
    if (!window.UnifiedSourceManager) {
        throw new Error("Unified source manager not available. Check that unified source data is loaded first.");
    }
    
    // Default metadata
    const result = {
        metadata: {
            dataResource: "Unknown",
            sourceId: "Unknown", 
            sourceName: "Unknown",
            sourceRole: "Unknown"
        },
        rawPlatformData: null
    };
    
    // Get the row data table
    const rowDataTable = document.getElementById(`rowDataTable_${tableIndex}`);
    
    if (rowDataTable) {
        // Get all rows in the table
        const rows = rowDataTable.querySelectorAll('tr');
        
        // Process the first three rows to extract metadata
        for (let i = 0; i < rows.length && i < 3; i++) {
            const cells = rows[i].querySelectorAll('td');
            if (cells.length >= 2) {
                const labelCell = cells[0];
                const valueCell = cells[1];
                
                // Extract data source from first row
                if (i === 0 && labelCell.textContent.trim() === "Data Resource") {
                    result.metadata.dataResource = valueCell.textContent.trim();
                    console.debug(`Found dataResource: ${result.metadata.dataResource}`);
                }
                
                // Extract source ID from second row
                else if (i === 1 && labelCell.textContent.trim() === "Source ID") {
                    const spanWithTitle = valueCell.querySelector('span[title]');
                    if (spanWithTitle) {
                        const titleText = spanWithTitle.getAttribute('title');
                        console.debug(`Source ID title text: "${titleText}"`);
                        
                        // Match pattern: "Source Identifiers: something, UUID"
                        const uuidPattern = /Source Identifiers:.*?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;
                        const match = titleText.match(uuidPattern);
                        
                        if (match && match[1]) {
                            const extractedUuid = match[1];
                            
                            // Use unified source system - NO FALLBACKS
                            const sourceInfo = window.UnifiedSourceManager.getSourceById(extractedUuid);
                            if (sourceInfo) {
                                result.metadata.sourceId = extractedUuid;
                                result.metadata.sourceName = sourceInfo.name;
                                console.debug(`Found sourceId UUID: ${result.metadata.sourceId}, resolved to: ${result.metadata.sourceName}`);
                            } else {
                                // Fail fast if source not found in unified system
                                throw new Error(`Source ${extractedUuid} not found in unified source registry. Check source data initialization.`);
                            }
                        } else {
                            // STRICT UUID REQUIREMENT - No fallbacks
                            throw new Error(`No UUID found in source identifier title: "${titleText}". All sources must have valid UUIDs.`);
                        }
                    } else {
                        // STRICT REQUIREMENT - No span with title means invalid data structure
                        throw new Error(`Source ID cell must contain span with title attribute containing UUID. Found: "${valueCell.textContent.trim()}"`);
                    }
                }
                
                // Extract source role from third row
                else if (i === 2 && labelCell.textContent.trim() === "Source Role") {
                    result.metadata.sourceRole = valueCell.textContent.trim();
                    console.debug(`Found sourceRole: ${result.metadata.sourceRole}`);
                }
            }
        }
        
        // Extract rawPlatformData
        const rawDataElement = document.getElementById(`rawPlatformData_${tableIndex}`);
        if (rawDataElement && rawDataElement.textContent) {
            try {
                result.rawPlatformData = JSON.parse(rawDataElement.textContent);
                console.debug(`Raw platform data found for table ${tableIndex}`);
            } catch (parseError) {
                console.error(`Error parsing raw platform data for table ${tableIndex}:`, parseError);
                throw parseError; // Fail fast
            }
        } else {
            console.debug(`No raw platform data element found with ID rawPlatformData_${tableIndex}`);
        }
    } else {
        console.debug(`Row data table not found for index ${tableIndex}`);
    }
    
    return result;
}

/**
 * Resolve source display information using unified source system
 * @param {string} sourceId - The source identifier (UUID)
 * @returns {string} Human-readable source display name
 */
function unifiedResolveSourceDisplay(sourceId) {
    if (!window.UnifiedSourceManager) {
        throw new Error("Unified source manager not available");
    }
    
    const sourceInfo = window.UnifiedSourceManager.getSourceById(sourceId);
    if (sourceInfo) {
        return sourceInfo.name;
    }
    
    // STRICT UUID REQUIREMENT - No graceful fallbacks
    throw new Error(`Source ${sourceId} not found in unified registry. All sources must be registered.`);
}

/**
 * Check if a source exists in the unified registry
 * @param {string} sourceId - The source identifier to check
 * @returns {boolean} True if source exists, false otherwise
 */
function unifiedHasSource(sourceId) {
    if (!window.UnifiedSourceManager) {
        return false;
    }
    
    return window.UnifiedSourceManager.hasSource(sourceId);
}

// =============================================================================
// Global Exports
// =============================================================================
window.unifiedExtractDataFromTable = unifiedExtractDataFromTable;
window.unifiedResolveSourceDisplay = unifiedResolveSourceDisplay;
window.unifiedHasSource = unifiedHasSource;

console.debug("Unified data extraction functions loaded - STRICT UUID-only mode");
