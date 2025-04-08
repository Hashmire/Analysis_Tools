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
        
        // Check if there are git versionTypes and add warning indicator if found
        const hasGitVersionType = rawPlatformData.versions.some(versionInfo => 
            versionInfo && versionInfo.versionType === "git");
        
        if (hasGitVersionType) {
            // Add warning indicator to the UI
            addGitVersionTypeWarning(rawPlatformData.tableIndex);
        }
        
        console.debug(`Processing ${rawPlatformData.versions.length} versions for ${cpeBase}`);
        
        // Special case for Linux kernel using enhanced detection
        if (isLinuxKernelPlatformData(rawPlatformData, cpeBase)) {
            console.debug("Special case: Processing Linux kernel version data");
            
            // Add visual indicator for Linux Kernel special handling
            addLinuxKernelSpecialCaseBadge();
            
            return processLinuxKernelVersions(cpeBase, rawPlatformData);
        }
        
        // Standard processing for other products
        console.debug(`Processing ${rawPlatformData.versions.length} versions for ${cpeBase}`);
        
        // Determine default vulnerability status
        const defaultIsAffected = rawPlatformData.defaultStatus === "affected";
        
        for (const versionInfo of rawPlatformData.versions) {
            if (!versionInfo) continue;
            
            // Determine if this version is vulnerable based on status
            const isVulnerable = versionInfo.status === "affected";
            
            // Create cpeMatch using the consolidated function
            const cpeMatch = createCpeMatchFromVersionInfo(cpeBase, versionInfo, isVulnerable);
            cpeMatches.push(cpeMatch);
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
 * Special handler for Linux kernel version data
 * @param {string} cpeBase - Base CPE string for Linux kernel
 * @param {Object} rawPlatformData - Raw platform data
 * @returns {Array} Array of cpeMatch objects
 */
function processLinuxKernelVersions(cpeBase, rawPlatformData) {
    console.debug("Processing Linux kernel version ranges");
    const cpeMatches = [];
    const defaultIsAffected = rawPlatformData.defaultStatus === "affected";
    
    try {
        // Group versions by status (affected vs unaffected)
        const affectedVersions = [];
        const unaffectedVersions = [];
        
        rawPlatformData.versions.forEach(versionInfo => {
            if (versionInfo.status === "affected") {
                affectedVersions.push(versionInfo);
            } else if (versionInfo.status === "unaffected") {
                unaffectedVersions.push(versionInfo);
            }
        });
        
        console.debug(`Found ${affectedVersions.length} affected and ${unaffectedVersions.length} unaffected version entries`);
        
        // For defaultStatus=affected, handle unaffected ranges and gaps
        if (defaultIsAffected) {
            // First pass: process unaffected ranges and generate the affected ranges
            if (unaffectedVersions.length > 0) {
                processGapsBetweenUnaffectedRanges(cpeBase, unaffectedVersions, affectedVersions, cpeMatches);
            }
            
            // Second pass: add any explicit affected version not covered by the above
            for (const affectedInfo of affectedVersions) {
                // Check if this explicit affected entry is already covered by our generated ranges
                let isCovered = false;
                
                // Simple case: it's a single version with no range qualifiers
                if (affectedInfo.version && !affectedInfo.lessThan && !affectedInfo.lessThanOrEqual &&
                    !affectedInfo.greaterThan && !affectedInfo.greaterThanOrEqual) {
                    
                    // Check if this version is covered by any of our generated ranges
                    for (const cpeMatch of cpeMatches) {
                        if (isVersionCoveredByRange(affectedInfo.version, cpeMatch)) {
                            isCovered = true;
                            break;
                        }
                    }
                    
                    // If not covered, add it
                    if (!isCovered) {
                        const cpeMatch = createCpeMatchFromVersionInfo(cpeBase, affectedInfo, true);
                        cpeMatches.push(cpeMatch);
                    }
                }
                // For complex ranges, always add them explicitly
                else {
                    const cpeMatch = createCpeMatchFromVersionInfo(cpeBase, affectedInfo, true);
                    cpeMatches.push(cpeMatch);
                }
            }
        }
        // For defaultStatus=unaffected, just add the explicit affected entries
        else {
            for (const affectedInfo of affectedVersions) {
                const cpeMatch = createCpeMatchFromVersionInfo(cpeBase, affectedInfo, true);
                cpeMatches.push(cpeMatch);
            }
        }
        
        console.debug(`Generated ${cpeMatches.length} CPE matches for Linux kernel`);
        
        if (cpeMatches.length === 0) {
            console.debug("No Linux kernel matches created, using basic CPE match");
            const basicMatch = createCpeMatchObject(cpeBase);
            return [basicMatch];
        }
        
        return cpeMatches;
    } catch (e) {
        console.error("Error in Linux kernel version processing:", e);
        console.error(e.stack);
        const basicMatch = createCpeMatchObject(cpeBase);
        return [basicMatch];
    }
}

/**
 * Add a visual badge indicating Linux kernel special case processing
 */
function addLinuxKernelSpecialCaseBadge() {
    try {
        // Find all rowDataTable elements
        const rowDataTables = document.querySelectorAll('table[id^="rowDataTable_"]');
        
        for (const table of rowDataTables) {
            // Find the Raw Platform Data row
            const rows = table.querySelectorAll('tr');
            for (const row of rows) {
                const cells = row.querySelectorAll('td');
                if (cells.length >= 2 && cells[0].textContent.trim() === "Raw Platform Data") {
                    // Check if badge already exists
                    if (cells[1].querySelector('.linux-kernel-badge')) {
                        continue;
                    }
                    
                    // Find the details element
                    const detailsElement = cells[1].querySelector('details');
                    if (detailsElement) {
                        // Create the badge - now uses CSS from styles.css
                        const badge = document.createElement('span');
                        badge.className = 'linux-kernel-badge';
                        badge.title = 'Linux kernel version data is being processed with special case handling. Please review the generated configurations carefully.';
                        badge.textContent = 'Linux Kernel Special Handling';
                        
                        // Insert the badge before the details element
                        detailsElement.parentNode.insertBefore(badge, detailsElement);
                        
                        // Add info icon
                        const infoIcon = document.createElement('i');
                        infoIcon.className = 'fas fa-info-circle ml-1';
                        infoIcon.style.fontSize = '0.9em';
                        badge.appendChild(document.createTextNode(' '));
                        badge.appendChild(infoIcon);
                        
                        console.debug("Added Linux Kernel special case badge");
                    }
                }
            }
        }
    } catch (e) {
        console.error("Error adding Linux Kernel special case badge:", e);
    }
}

/**
 * Check if a version range is already covered by explicit affected entries
 * @param {string} startVersion - Start version of range
 * @param {string|null} endVersion - End version of range (null for unlimited)
 * @param {Array} affectedVersions - Array of explicitly affected version info
 * @returns {boolean} True if the range is already covered
 */
function isRangeCoveredByExplicitEntries(startVersion, endVersion, affectedVersions) {
    for (const affectedInfo of affectedVersions) {
        // Determine the bounds of this affected entry
        let affectedStart = null;
        let affectedEnd = null;
        
        // Get start bound
        if (affectedInfo.greaterThanOrEqual) {
            affectedStart = affectedInfo.greaterThanOrEqual;
        } else if (affectedInfo.greaterThan) {
            affectedStart = incrementVersion(affectedInfo.greaterThan);
        } else if (affectedInfo.version) {
            affectedStart = affectedInfo.version;
        }
        
        // Get end bound
        if (affectedInfo.lessThan) {
            affectedEnd = affectedInfo.lessThan;
        } else if (affectedInfo.lessThanOrEqual) {
            affectedEnd = incrementVersion(affectedInfo.lessThanOrEqual);
        }
        
        // Check if this affected entry covers the entire range we're looking at
        if (affectedStart && compareVersions(affectedStart, startVersion) <= 0) {
            // The affected start is earlier than or equal to our start
            if (!affectedEnd || !endVersion || compareVersions(affectedEnd, endVersion) >= 0) {
                // The affected end is later than or equal to our end (or unlimited)
                return true;
            }
        }
    }
    
    return false;
}

/**
 * Update the previous upper bound based on unaffected range info
 * @param {Object} unaffectedInfo - Unaffected version info object
 * @returns {string|null} The new upper bound for the next affected range
 */
function calculateNextUpperBound(unaffectedInfo) {
    if (unaffectedInfo.lessThanOrEqual === "*") {
        // This covers everything above the version
        return null; // No more ranges above this
    } else if (unaffectedInfo.lessThanOrEqual && unaffectedInfo.lessThanOrEqual.includes("*")) {
        // Handle version wildcards like "5.4.*"
        return getNextVersionAfterWildcard(unaffectedInfo.lessThanOrEqual);
    } else if (unaffectedInfo.lessThan) {
        return unaffectedInfo.lessThan;
    } else if (unaffectedInfo.lessThanOrEqual) {
        // Add a tiny increment to make it exclusive
        return incrementVersion(unaffectedInfo.lessThanOrEqual);
    } else {
        // Single version - the upper bound is the next version
        return incrementVersion(unaffectedInfo.version);
    }
}

/**
 * Get the next version after a wildcard pattern
 * @param {string} versionPattern - Version pattern like "5.4.*"
 * @returns {string} Next version
 */
function getNextVersionAfterWildcard(versionPattern) {
    // Handle wildcard patterns like "5.4.*"
    if (versionPattern.includes('*')) {
        // Extract the prefix before the wildcard
        const prefix = versionPattern.split('*')[0].replace(/\.$/, '');
        
        // Split into parts
        const parts = prefix.split('.');
        
        // For patterns like "5.4.*", we want to get "5.5"
        // For patterns like "5.4.2.*", we want to get "5.4.3"
        if (parts.length >= 2) {
            // Increment the last component before the wildcard
            const lastPart = parseInt(parts[parts.length - 1], 10);
            if (!isNaN(lastPart)) {
                parts[parts.length - 1] = (lastPart + 1).toString();
                
                // Log patch-level wildcards for tracking
                if (parts.length > 2) {
                    console.warn(`Handling patch-level wildcard: ${versionPattern} -> ${parts.join('.')}`);
                }
                
                return parts.join('.');
            }
        }
        return prefix; // Fallback: Return the prefix unchanged
    }
    
    // For non-wildcard patterns, defer to incrementVersion
    return incrementVersion(versionPattern);
}

/**
 * Helper function to sort version info objects
 * @param {Array} versionInfoArray - Array of version info objects
 * @returns {Array} Sorted array
 */
function sortVersionInfo(versionInfoArray) {
    return [...versionInfoArray].sort((a, b) => {
        // First compare by version
        const verA = a.version || "0";
        const verB = b.version || "0";
        
        // If versionType is semver, use semver-style comparison
        if ((a.versionType === "semver" || b.versionType === "semver")) {
            return compareVersions(verA, verB);
        } else {
            // Simple string comparison for non-semver
            return verA.localeCompare(verB);
        }
    });
}

/**
 * Compare two version strings
 * @param {string} versionA - First version
 * @param {string} versionB - Second version
 * @returns {number} Comparison result (-1, 0, 1)
 */
function compareVersions(versionA, versionB) {
    const aParts = versionA.split('.').map(part => parseInt(part, 10) || 0);
    const bParts = versionB.split('.').map(part => parseInt(part, 10) || 0);
    
    // Compare version components
    for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
        const aVal = i < aParts.length ? aParts[i] : 0;
        const bVal = i < bParts.length ? bParts[i] : 0;
        
        if (aVal !== bVal) {
            return aVal - bVal;
        }
    }
    
    return 0;
}

/**
 * Increment a version string slightly
 * @param {string} version - Version string
 * @returns {string} Incremented version
 */
function incrementVersion(version) {
    if (!version) return version;
    
    // For semantic versions
    if (version.includes('.')) {
        const parts = version.split('.');
        const lastPart = parseInt(parts[parts.length - 1], 10);
        
        if (!isNaN(lastPart)) {
            parts[parts.length - 1] = (lastPart + 1).toString();
            return parts.join('.');
        }
    }
    
    // For simple integer versions
    const numVersion = parseInt(version, 10);
    if (!isNaN(numVersion)) {
        return (numVersion + 1).toString();
    }
    
    return version;
}

/**
 * Generate a unique match criteria ID
 * @returns {string} A unique match criteria ID
 */
function generateMatchCriteriaId() {
    return 'generated_' + Math.random().toString(36).substr(2, 9).toUpperCase();
}

/**
 * Process basic version data into a configuration object
 * @param {Set} selectedCPEs - Set of selected CPE base strings or DOM elements
 * @param {Object} rawPlatformData - Raw platform data
 * @returns {Object} Configuration object
 */
function processBasicVersionData(selectedCPEs, rawPlatformData) {
    const config = {
        "operator": "OR",
        "negate": false,
        "cpeMatch": []
    };
    
    // Store the tableIndex in rawPlatformData for reference
    if (rawPlatformData && !rawPlatformData.tableIndex && rawPlatformData.elementId) {
        // Extract table index from element ID if present
        const match = rawPlatformData.elementId.match(/rawPlatformData_(\d+)/);
        if (match && match[1]) {
            rawPlatformData.tableIndex = match[1];
        }
    }
    
    // Process each selected CPE
    selectedCPEs.forEach(cpeRow => {
        let cpeBase;
        
        // Check if cpeRow is a DOM element or a string
        if (typeof cpeRow === 'string') {
            cpeBase = cpeRow;
        } else if (cpeRow && typeof cpeRow.getAttribute === 'function') {
            cpeBase = cpeRow.getAttribute('data-cpe-base');
        } else {
            console.warn("Invalid CPE row type:", typeof cpeRow);
            return;
        }
        
        if (!cpeBase) {
            console.warn("No CPE base found for row:", cpeRow);
            return;
        }
        
        // Process version data into cpeMatch objects
        const cpeMatches = processVersionDataToCpeMatches(cpeBase, rawPlatformData);
        
        console.debug(`Generated ${cpeMatches.length} CPE matches for ${cpeBase}`);
        
        // Add all cpeMatches to the configuration
        config.cpeMatch.push(...cpeMatches);
    });
    
    return config;
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

/**
 * Get the next version after a wildcard pattern
 * @param {string} versionPattern - Version pattern like "5.4.*"
 * @returns {string} Next version like "5.5"
 */
function getNextVersionAfterWildcard(versionPattern) {
    // Handle wildcard patterns like "5.4.*"
    if (versionPattern.includes('*')) {
        // Extract the prefix before the wildcard
        const prefix = versionPattern.split('*')[0].replace(/\.$/, '');
        
        // Split into parts
        const parts = prefix.split('.');
        
        // For patterns like "5.4.*", we want to get "5.5"
        if (parts.length >= 2) {
            // Increment the last component before the wildcard
            const lastPart = parseInt(parts[parts.length - 1], 10);
            if (!isNaN(lastPart)) {
                parts[parts.length - 1] = (lastPart + 1).toString();
                return parts.join('.');
            }
        }
        return prefix; // Fallback: Return the prefix unchanged
    }
    
    // For non-wildcard patterns, defer to incrementVersion
    return incrementVersion(versionPattern);
}

/**
 * Update the previous upper bound based on unaffected range info
 * @param {Object} unaffectedInfo - Unaffected version info object
 * @returns {string|null} The new upper bound for the next affected range
 */
function calculateNextUpperBound(unaffectedInfo) {
    if (unaffectedInfo.lessThanOrEqual === "*") {
        // This covers everything above the version
        return null; // No more ranges above this
    } else if (unaffectedInfo.lessThanOrEqual && unaffectedInfo.lessThanOrEqual.includes("*")) {
        // Handle version wildcards like "5.4.*"
        return getNextVersionAfterWildcard(unaffectedInfo.lessThanOrEqual);
    } else if (unaffectedInfo.lessThan) {
        return unaffectedInfo.lessThan;
    } else if (unaffectedInfo.lessThanOrEqual) {
        // Add a tiny increment to make it exclusive
        return incrementVersion(unaffectedInfo.lessThanOrEqual);
    } else {
        // Single version - the upper bound is the next version
        return incrementVersion(unaffectedInfo.version);
    }
}

/**
 * Enhanced Linux Kernel Detection
 * @param {Object} rawPlatformData - Raw platform data
 * @param {string} cpeBase - Base CPE string
 * @returns {boolean} True if the platform data is for Linux kernel
 */
function isLinuxKernelPlatformData(rawPlatformData, cpeBase) {
    if (!rawPlatformData || !cpeBase) {
        return false;
    }
    
    // Primary detection: Check product and vendor in platform data
    const isLinuxProduct = 
        rawPlatformData.product === "Linux" || 
        rawPlatformData.product === "Linux Kernel" ||
        (typeof rawPlatformData.product === "string" && 
         rawPlatformData.product.toLowerCase().includes("linux kernel"));
    
    const isLinuxVendor = 
        rawPlatformData.vendor === "Linux" || 
        rawPlatformData.vendor === "Linux Foundation" ||
        (typeof rawPlatformData.vendor === "string" && 
         rawPlatformData.vendor.toLowerCase().includes("linux"));
    
    const hasCpeMatch = cpeBase.includes(":linux:linux_kernel:") || 
                        cpeBase.includes(":linux:");
    
    // Check for Linux kernel in CPE
    if (isLinuxProduct && isLinuxVendor && hasCpeMatch) {
        return true;
    }
    
    // Secondary detection: Check for complex version structure specific to Linux kernel
    if (rawPlatformData.versions && rawPlatformData.versions.length > 0 && hasCpeMatch) {
        // Count number of versions with wildcard formats like "5.4.*"
        const wildcardVersions = rawPlatformData.versions.filter(v => 
            v && v.lessThanOrEqual && typeof v.lessThanOrEqual === "string" && 
            v.lessThanOrEqual.includes("*")
        );
        
        // If we have multiple wildcarded versions and a Linux-like CPE, it's likely Linux kernel
        if (wildcardVersions.length >= 2 && hasCpeMatch) {
            console.debug("Detected Linux kernel based on version pattern analysis");
            return true;
        }
    }
    
    return false;
}

/**
 * Create a CPE match object from version info
 * @param {string} cpeBase - Base CPE string
 * @param {Object} versionInfo - Version info object
 * @param {boolean} isVulnerable - Vulnerability status
 * @returns {Object} CPE match object
 */
function createCpeMatchFromVersionInfo(cpeBase, versionInfo, isVulnerable) {
    // Handle single version with no range indicators
    if (versionInfo.version && !versionInfo.lessThan && !versionInfo.lessThanOrEqual && 
        !versionInfo.greaterThan && !versionInfo.greaterThanOrEqual) {
        
        // Create a CPE match with explicit version embedded in the criteria
        const cpeParts = cpeBase.split(':');
        cpeParts[5] = versionInfo.version; // Replace wildcard with explicit version
        
        return {
            "criteria": cpeParts.join(':'),
            "matchCriteriaId": generateMatchCriteriaId(),
            "vulnerable": isVulnerable
        };
    } else {
        // Range specification (existing code for handling ranges)
        const cpeMatch = {
            "criteria": cpeBase,
            "matchCriteriaId": generateMatchCriteriaId(),
            "vulnerable": isVulnerable
        };
        
        // Add version range attributes
        if (versionInfo.version) {
            cpeMatch.versionStartIncluding = versionInfo.version;
        }
        if (versionInfo.greaterThan) {
            cpeMatch.versionStartExcluding = versionInfo.greaterThan;
        }
        else if (versionInfo.greaterThanOrEqual) {
            cpeMatch.versionStartIncluding = versionInfo.greaterThanOrEqual;
        }
        
        if (versionInfo.lessThan) {
            cpeMatch.versionEndExcluding = versionInfo.lessThan;
        }
        else if (versionInfo.lessThanOrEqual) {
            cpeMatch.versionEndIncluding = versionInfo.lessThanOrEqual;
        }
        
        return cpeMatch;
    }
}

/**
 * Process gaps between unaffected ranges to create affected ranges
 * @param {string} cpeBase - Base CPE string
 * @param {Array} unaffectedVersions - Array of unaffected version info objects
 * @param {Array} affectedVersions - Array of explicitly affected version info objects
 * @param {Array} cpeMatches - Array to add new cpeMatch objects to
 */
function processGapsBetweenUnaffectedRanges(cpeBase, unaffectedVersions, affectedVersions, cpeMatches) {
    console.debug("Processing gaps between unaffected ranges");
    
    // First, organize the unaffected versions by their starting version and ending version
    const unaffectedRanges = [];
    
    for (const info of unaffectedVersions) {
        let startVer, endVer;
        
        // Determine start version
        if (info.version) {
            startVer = info.version;
        } else if (info.greaterThanOrEqual) {
            startVer = info.greaterThanOrEqual;
        } else if (info.greaterThan) {
            startVer = incrementVersion(info.greaterThan);
        } else {
            startVer = "0"; // Default to beginning
        }
        
        // Determine end version - this is the end of the unaffected range
        if (info.lessThan) {
            endVer = info.lessThan;
        } else if (info.lessThanOrEqual && info.lessThanOrEqual === "*") {
            endVer = null; // Unlimited
        } else if (info.lessThanOrEqual && info.lessThanOrEqual.includes("*")) {
            // Handle wildcards like 5.4.*
            const wildcard = info.lessThanOrEqual;
            
            // Extract the numeric part (like "5.4" from "5.4.*")
            const versionBase = wildcard.split("*")[0].replace(/\.$/, '');
            const parts = versionBase.split(".");
            
            if (parts.length >= 2) {
                // For 5.4.*, the end of the unaffected range is 5.5
                const majorVersion = parseInt(parts[0], 10);
                const minorVersion = parseInt(parts[1], 10);
                
                if (!isNaN(majorVersion) && !isNaN(minorVersion)) {
                    endVer = `${majorVersion}.${minorVersion + 1}`;
                    console.debug(`Processed wildcard ${wildcard} to next version ${endVer}`);
                } else {
                    endVer = incrementVersion(versionBase);
                }
            } else {
                endVer = incrementVersion(versionBase);
            }
        } else if (info.lessThanOrEqual) {
            endVer = incrementVersion(info.lessThanOrEqual);
        } else {
            // Single version, so end is next version
            endVer = incrementVersion(startVer);
        }
        
        unaffectedRanges.push({ start: startVer, end: endVer });
    }
    
    // Sort the ranges by start version
    unaffectedRanges.sort((a, b) => compareVersions(a.start, b.start));
    
    console.debug("Sorted unaffected ranges:");
    unaffectedRanges.forEach((range, i) => {
        console.debug(`Range ${i}: ${range.start} to ${range.end || "unlimited"}`);
    });
    
    // Now find the gaps between unaffected ranges
    // First, set up the initial lower bound
    let previousRange = null;
    
    // Handle the special case for patched versions first - before the main loop
    // This ensures we correctly handle cases where version 5.4 is marked affected but 5.4.277 is unaffected
    const patchVersionCandidates = unaffectedRanges.filter(range => 
        range.start.includes(".") && range.start.split(".").length > 2
    );
    
    for (const patchRange of patchVersionCandidates) {
        // Get the base version from the patched version (5.4 from 5.4.277)
        const startParts = patchRange.start.split('.');
        const baseVersion = (startParts.length >= 2) ? `${startParts[0]}.${startParts[1]}` : startParts[0];
        
        // Check if this base version matches an affected version
        const matchingAffected = affectedVersions.find(av => 
            av.version && (av.version === baseVersion || av.version.startsWith(baseVersion + "."))
        );
        
        if (matchingAffected) {
            console.debug(`Found patched version ${patchRange.start} for base affected version ${baseVersion}`);
            
            // Create a non-vulnerable range from base to patched version (inclusive)
            cpeMatches.push({
                criteria: cpeBase,
                matchCriteriaId: generateMatchCriteriaId(),
                vulnerable: false,
                versionStartIncluding: baseVersion,
                versionEndIncluding: patchRange.start
            });
            
            console.debug(`Created unaffected range from ${baseVersion} to ${patchRange.start} (inclusive)`);
            
            // Create a vulnerable range from patched version (exclusive) to the next minor
            if (patchRange.end) {
                cpeMatches.push({
                    criteria: cpeBase,
                    matchCriteriaId: generateMatchCriteriaId(),
                    vulnerable: true,
                    versionStartExcluding: patchRange.start,
                    versionEndExcluding: patchRange.end
                });
                
                console.debug(`Created affected range from ${patchRange.start} (exclusive) to ${patchRange.end}`);
            }
        }
    }
    
    // Main loop for processing gaps between unaffected ranges
    for (let i = 0; i < unaffectedRanges.length; i++) {
        const currentRange = unaffectedRanges[i];
        
        // If we have a previous range and there's a gap between
        if (previousRange && previousRange.end && compareVersions(previousRange.end, currentRange.start) < 0) {
            console.debug(`Found gap between ${previousRange.end} and ${currentRange.start}`);
            
            // Skip creating affected ranges for gaps that overlap with our patch handling above
            let shouldCreateGapRange = true;
            
            // Check if this gap starts with a base version (like 5.4) that has special patched handling
            for (const patchRange of patchVersionCandidates) {
                const startParts = patchRange.start.split('.');
                const baseVersion = (startParts.length >= 2) ? `${startParts[0]}.${startParts[1]}` : startParts[0];
                
                // If the start of this gap matches a base version we've already handled
                if (previousRange.end === baseVersion) {
                    console.debug(`Skipping gap starting at ${baseVersion} as it's handled by patch special case`);
                    shouldCreateGapRange = false;
                    break;
                }
            }
            
            // Only create the gap range if we didn't handle it as a patch case
            if (shouldCreateGapRange) {
                cpeMatches.push({
                    criteria: cpeBase,
                    matchCriteriaId: generateMatchCriteriaId(),
                    vulnerable: true,
                    versionStartIncluding: previousRange.end,
                    versionEndExcluding: currentRange.start
                });
            }
        }
        
        previousRange = currentRange;
    }
    
    // If the last range doesn't extend to infinity, add a final affected range
    if (previousRange && previousRange.end) {
        console.debug(`Adding final range from ${previousRange.end} to infinity`);
        
        cpeMatches.push({
            criteria: cpeBase,
            matchCriteriaId: generateMatchCriteriaId(),
            vulnerable: true,
            versionStartIncluding: previousRange.end
        });
    }
}

/**
 * Check if a version is covered by a cpeMatch range
 * @param {string} version - Version to check
 * @param {Object} cpeMatch - cpeMatch object with range data
 * @returns {boolean} True if the version is covered
 */
function isVersionCoveredByRange(version, cpeMatch) {
    // If this is an exact match (not a range)
    if (cpeMatch.criteria.includes(`:${version}:`)) {
        return true;
    }
    
    let isGreaterThanLower = true;
    let isLessThanUpper = true;
    
    // Check lower bound
    if (cpeMatch.versionStartIncluding && compareVersions(version, cpeMatch.versionStartIncluding) < 0) {
        isGreaterThanLower = false;
    }
    if (cpeMatch.versionStartExcluding && compareVersions(version, cpeMatch.versionStartExcluding) <= 0) {
        isGreaterThanLower = false;
    }
    
    // Check upper bound
    if (cpeMatch.versionEndIncluding && compareVersions(version, cpeMatch.versionEndIncluding) > 0) {
        isLessThanUpper = false;
    }
    if (cpeMatch.versionEndExcluding && compareVersions(version, cpeMatch.versionEndExcluding) >= 0) {
        isLessThanUpper = false;
    }
    
    return isGreaterThanLower && isLessThanUpper;
}

/**
 * Add a warning indicator for git versionType
 * @param {string|number} tableIndex - The table index
 */
function addGitVersionTypeWarning(tableIndex) {
    try {
        // Find all rowDataTable elements
        const rowDataTable = document.getElementById(`rowDataTable_${tableIndex}`);
        if (!rowDataTable) return;
        
        // Find the Raw Platform Data row
        const rows = rowDataTable.querySelectorAll('tr');
        for (const row of rows) {
            const cells = row.querySelectorAll('td');
            if (cells.length >= 2 && cells[0].textContent.trim() === "Raw Platform Data") {
                // Check if badge already exists
                if (cells[1].querySelector('.git-versiontype-badge')) {
                    continue;
                }
                
                // Find the details element
                const detailsElement = cells[1].querySelector('details');
                if (detailsElement) {
                    // Create the badge - uses CSS from styles.css like Linux kernel badge
                    const badge = document.createElement('span');
                    badge.className = 'git-versiontype-badge';
                    badge.title = 'git versionType not advised for CPE Ranges';
                    badge.textContent = 'git versionType';
                    
                    // Insert the badge before the details element
                    detailsElement.parentNode.insertBefore(badge, detailsElement);
                    
                    // Add info icon
                    const infoIcon = document.createElement('i');
                    infoIcon.className = 'fas fa-info-circle ml-1';
                    infoIcon.style.fontSize = '0.9em';
                    badge.appendChild(document.createTextNode(' '));
                    badge.appendChild(infoIcon);
                    
                    console.debug("Added git versionType warning badge");
                }
            }
        }
    } catch (e) {
        console.error("Error adding git versionType warning badge:", e);
    }
}

// Add this function to scan for git versionTypes on page load
function scanForGitVersionTypes() {
    // Look for all rawPlatformData elements
    const rawPlatformDataElements = document.querySelectorAll('[id^="rawPlatformData_"]');
    
    rawPlatformDataElements.forEach(element => {
        try {
            // Extract the table index from the ID
            const tableIndex = element.id.replace('rawPlatformData_', '');
            
            // Parse the JSON content
            const rawPlatformData = JSON.parse(element.textContent);
            
            // Check if any versions have git versionType
            if (rawPlatformData && 
                rawPlatformData.versions && 
                Array.isArray(rawPlatformData.versions) &&
                rawPlatformData.versions.some(versionInfo => 
                    versionInfo && versionInfo.versionType === "git")) {
                
                // Add the warning badge
                addGitVersionTypeWarning(tableIndex);
            }
        } catch (e) {
            console.warn("Error checking for git versionType:", e);
        }
    });
}

// Instead, export the function so it can be called from the existing initialization
window.scanForGitVersionTypes = scanForGitVersionTypes;
