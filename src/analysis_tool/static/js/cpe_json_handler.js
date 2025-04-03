// Global maps to store selections and generated JSONs
const tableSelections = new Map(); // Map<tableId, Set<cpeBase>>
const consolidatedJsons = new Map(); // Map<tableId, JSON>

/**
 * Creates a CPE match object for a given CPE base string
 * @param {string} cpeBase - The base CPE string
 * @returns {Object} A CPE match object
 */

/**
 * Process version data into cpeMatch objects
 * @param {string} cpeBase - The base CPE string
 * @param {Object} rawPlatformData - Raw platform data
 * @returns {Array} Array of cpeMatch objects
 */
function processVersionDataToCpeMatches(cpeBase, rawPlatformData) {
    try {
        // Normalize the base CPE string first to ensure it has enough components
        cpeBase = normalizeCpeString(cpeBase);
        
        const cpeMatches = [];
        
        // Check if we have valid version data
        if (!rawPlatformData || !rawPlatformData.versions || !Array.isArray(rawPlatformData.versions) || rawPlatformData.versions.length === 0) {
            console.debug("No version data available, using basic CPE match");
            const basicMatch = createCpeMatchObject(cpeBase);
            return [basicMatch];
        }
        
        console.debug(`Processing ${rawPlatformData.versions.length} versions for ${cpeBase}`);
        
        for (const versionInfo of rawPlatformData.versions) {
            if (!versionInfo) continue;
            
            const cpeMatch = {
                "criteria": cpeBase,
                "matchCriteriaId": "generated_" + Math.random().toString(36).substr(2, 9),
                "vulnerable": versionInfo.status !== 'unaffected'
            };
            
            const hasRangeSpec = versionInfo.hasOwnProperty('lessThan') || 
                              versionInfo.hasOwnProperty('lessThanOrEqual') ||
                              versionInfo.hasOwnProperty('greaterThan') ||
                              versionInfo.hasOwnProperty('greaterThanOrEqual');
            
            if (hasRangeSpec) {
                // For range specifications
                if (versionInfo.hasOwnProperty('greaterThan')) {
                    cpeMatch.versionStartExcluding = versionInfo.greaterThan;
                }
                else if (versionInfo.hasOwnProperty('greaterThanOrEqual')) {
                    cpeMatch.versionStartIncluding = versionInfo.greaterThanOrEqual;
                }
                else if (versionInfo.hasOwnProperty('version') && 
                        (versionInfo.hasOwnProperty('lessThan') || versionInfo.hasOwnProperty('lessThanOrEqual'))) {
                    cpeMatch.versionStartIncluding = versionInfo.version;
                }
                
                if (versionInfo.hasOwnProperty('lessThan')) {
                    cpeMatch.versionEndExcluding = versionInfo.lessThan;
                }
                else if (versionInfo.hasOwnProperty('lessThanOrEqual')) {
                    cpeMatch.versionEndIncluding = versionInfo.lessThanOrEqual;
                }
                
                cpeMatches.push(cpeMatch);
            } 
            else if (versionInfo.hasOwnProperty('version')) {
                // For explicit versions, we update the CPE string directly
                const cpeParts = cpeBase.split(':');
                
                // Replace the version component at index 5
                cpeParts[5] = versionInfo.version;
                cpeMatch.criteria = cpeParts.join(':');
                
                cpeMatches.push(cpeMatch);
            }
            else {
                // If we can't determine the version structure, use the base CPE
                cpeMatches.push(cpeMatch);
            }
        }
        
        if (cpeMatches.length === 0) {
            console.debug("No matches created, using basic CPE match");
            const basicMatch = createCpeMatchObject(cpeBase);
            return [basicMatch];
        }
        
        return cpeMatches;
    } catch (e) {
        console.error("Error processing version data:", e);
        const basicMatch = createCpeMatchObject(cpeBase);
        return [basicMatch];
    }
}

/**
 * Process basic version data into a configuration object
 * @param {Set} selectedCPEs - Set of selected CPE base strings
 * @param {Object} rawPlatformData - Raw platform data
 * @returns {Object} Configuration object
 */
function processBasicVersionData(selectedCPEs, rawPlatformData) {
    try {
        console.debug("Processing basic version data for", selectedCPEs.size, "CPEs");
        
        // Create a base configuration
        const baseConfig = {
            "operator": "OR",
            "cpeMatch": []
        };
        
        // Track version stats
        let totalVersions = 0;
        
        // Process each selected CPE
        selectedCPEs.forEach(cpeBase => {
            // Process version data into cpeMatch objects
            const cpeMatches = processVersionDataToCpeMatches(cpeBase, rawPlatformData);
            
            console.debug(`Generated ${cpeMatches.length} CPE matches for ${cpeBase}`);
            
            // Add all cpeMatches to the configuration
            baseConfig.cpeMatch.push(...cpeMatches);
            
            // Update version count
            totalVersions += cpeMatches.length;
        });
        
        // Store version stats in the configuration
        baseConfig.versionStats = {
            totalVersions: totalVersions,
            selectedCriteria: selectedCPEs.size
        };
        
        return baseConfig;
    } catch(e) {
        console.error("Error processing basic version data:", e);
        return {
            "operator": "OR",
            "cpeMatch": []
        };
    }
}

/**
 * Processes the basic version data for selected CPEs
 * @param {Set} selectedRows - Set of selected CPE rows
 * @param {Object} rawPlatformData - Raw platform data
 * @param {Object} json - The JSON object to update
 * @returns {number} Total versions processed
 */
function processBasicVersionDataOld(selectedRows, rawPlatformData, json) {
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

/**
 * Process JSON based on the data source
 * @param {Object} json - The JSON object to update
 * @param {Set} selectedRows - Set of selected CPE rows
 * @param {Object} metadata - Table metadata
 * @returns {boolean} True if processing was successful
 */
function processJsonBasedOnSourceOld(json, selectedRows, metadata) {
    try {
        // Process the JSON structure based on the data source
        const dataSource = metadata.dataSource;
        let totalVersions = 0;
        
        if (dataSource === 'NVDAPI') {
            // Special handling for NVD API data
            totalVersions = processBasicVersionDataOld(selectedRows, metadata.rawPlatformData, json);
        } else {
            // Default handling for other data sources
            totalVersions = processBasicVersionDataOld(selectedRows, metadata.rawPlatformData, json);
        }
        
        // Store totalVersions in the metadata for use in calculateAndAddStatistics
        metadata.totalVersions = totalVersions;
        
        return true;
    } catch(e) {
        console.error("Error processing JSON based on source:", e);
        return false;
    }
}

/**
 * Process JSON based on source type
 * @param {Set} selectedCPEs - Set of selected CPE base strings
 * @param {Object} rawPlatformData - Raw platform data
 * @param {Object} metadata - Table metadata
 * @returns {Object} Generated JSON
 */
function processJsonBasedOnSource(selectedCPEs, rawPlatformData, metadata) {
    // Create a base JSON structure
    const json = {
        "configurations": []
    };
    
    try {
        console.debug(`Processing JSON based on ${metadata.dataSource} source with ${selectedCPEs.size} selected CPEs`);
        
        // Check if we have embedded configuration (for NVD data)
        if (metadata.dataSource === 'NVDAPI' && rawPlatformData && rawPlatformData.rawConfigData) {
            // For NVD API data, we have the complete configuration
            console.debug("Using embedded NVD configuration");
            json.configurations.push(rawPlatformData.rawConfigData);
        } 
        // Regular version data processing
        else {
            console.debug("Processing version data for CPEs");
            // Process the basic version data
            const config = processBasicVersionData(selectedCPEs, rawPlatformData);
            
            // Add metadata
            config.generatorData = {
                "generatedFromSource": {
                    "dataSource": metadata.dataSource || "Unknown",
                    "sourceId": metadata.sourceId || "Unknown",
                    "sourceRole": metadata.sourceRole || "Unknown"
                }
            };
            
            json.configurations.push(config);
        }
        
        // Calculate and add statistics
        calculateAndAddStatistics(json, selectedCPEs, rawPlatformData, metadata);
        
        return json;
    } catch (e) {
        console.error("Error processing JSON:", e);
        
        // Create a fallback configuration
        json.configurations.push({
            "operator": "OR",
            "cpeMatch": [],
            "generatorData": {
                "generatedFromSource": {
                    "dataSource": metadata.dataSource || "Unknown",
                    "sourceId": metadata.sourceId || "Unknown",
                    "sourceRole": metadata.sourceRole || "Unknown",
                    "error": e.message
                }
            }
        });
        
        return json;
    }
}

/**
 * Calculate and add statistics to the JSON
 * @param {Object} json - The JSON to update
 * @param {Set} selectedRows - Selected rows
 * @param {Object} rawPlatformData - Raw platform data
 * @param {Object} metadata - Table metadata
 */
function calculateAndAddStatistics(json, selectedRows, rawPlatformData, metadata) {
    const selectionCount = selectedRows.size;
    let totalMatches = 0;
    let rangeMatches = 0;
    let exactMatches = 0;
    
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
    
    // Always create generatorData if it doesn't exist
    if (!json.configurations[0].generatorData) {
        json.configurations[0].generatorData = {
            "generatedFromSource": {
                "dataSource": metadata.dataSource || "Unknown",
                "sourceId": metadata.sourceId || "Unknown",
                "sourceRole": metadata.sourceRole || "Unknown"
            }
        };
    }
    
    // Store statistics in generatorData.matchStats only
    json.configurations[0].generatorData.matchStats = {
        totalMatches: totalMatches,
        rangeMatches: rangeMatches,
        exactMatches: exactMatches,
        selectedCriteria: selectionCount
    };
    
    // Remove any old-style statistics to avoid confusion
    if (json.configurations[0].matchStats) {
        delete json.configurations[0].matchStats;
    }
    if (json.configurations[0].versionStats) {
        delete json.configurations[0].versionStats;
    }
}

/**
 * Generate JSON with all configurations from all tables
 * @returns {Object} Master JSON with all configurations
 */
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
            
            // Always update button state even if no rows are selected
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
            const isVisible = display && display.style.display !== 'none';
            
            // Update button text
            showButton.textContent = isVisible ? 
                `Hide Consolidated JSON (${statsStr})` : 
                `Show Consolidated JSON (${statsStr})`;
            
            // Update button state
            showButton.disabled = false;
            
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
 * Extract metadata and rawPlatformData from the row data table
 * @param {string|number} tableIndex - Index of the table
 * @returns {Object} Extracted data including metadata and rawPlatformData
 */
function extractDataFromTable(tableIndex) {
    // Default metadata
    const result = {
        metadata: {
            dataSource: "Unknown",
            sourceId: "Unknown", 
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
                if (i === 0 && labelCell.textContent.trim() === "Data Source") {
                    result.metadata.dataSource = valueCell.textContent.trim();
                    console.debug(`Found dataSource: ${result.metadata.dataSource}`);
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
                            result.metadata.sourceId = match[1];
                            console.debug(`Found sourceId UUID: ${result.metadata.sourceId}`);
                        } else {
                            // If no UUID found, use the text content as fallback
                            result.metadata.sourceId = valueCell.textContent.trim();
                            console.debug(`UUID not found in title, using text as sourceId: ${result.metadata.sourceId}`);
                        }
                    } else {
                        // No span with title, just use the text content
                        result.metadata.sourceId = valueCell.textContent.trim();
                        console.debug(`No title attribute found, using text as sourceId: ${result.metadata.sourceId}`);
                    }
                }
                
                // Extract source role from third row
                else if (i === 2 && labelCell.textContent.trim() === "Source Role") {
                    result.metadata.sourceRole = valueCell.textContent.trim();
                    console.debug(`Found sourceRole: ${result.metadata.sourceRole}`);
                }
            }
        }
        
        // Direct access by ID for rawPlatformData - simple and reliable
        const rawDataElement = document.getElementById(`rawPlatformData_${tableIndex}`);
        if (rawDataElement && rawDataElement.textContent) {
            try {
                result.rawPlatformData = JSON.parse(rawDataElement.textContent);
                console.debug(`Raw platform data found for table ${tableIndex}`);
            } catch (parseError) {
                console.error(`Error parsing raw platform data for table ${tableIndex}:`, parseError);
            }
        } else {
            console.debug(`No raw platform data element found with ID rawPlatformData_${tableIndex}`);
        }
    } else {
        console.debug(`Row data table not found for index ${tableIndex}`);
    }
    
    return result;
}