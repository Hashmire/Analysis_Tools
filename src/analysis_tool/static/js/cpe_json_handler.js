// Global maps to store selections and generated JSONs
window.tableSelections = window.tableSelections || new Map();
window.consolidatedJsons = window.consolidatedJsons || new Map();
window.rowSettings = window.rowSettings || new Map();

/**
 * Creates a CPE match object for a given CPE base string
 * @param {string} cpeBase - The base CPE string
 * @returns {Object} A CPE match object
 */
function createCpeMatchObject(cpeBase) {
    // Normalize the base CPE string if needed
    cpeBase = normalizeCpeString(cpeBase);
    
    return {
        "criteria": cpeBase,
        "matchCriteriaId": generateMatchCriteriaId(),
        "vulnerable": true
    };
}

/**
 * Process version data into cpeMatch objects
 * @param {string} cpeBase - The base CPE string
 * @param {Object} rawPlatformData - Raw platform data
 * @param {string} tableId - Table identifier for settings
 * @returns {Array} Array of cpeMatch objects
 */
function processVersionDataToCpeMatches(cpeBase, rawPlatformData, tableId) {
    // Get table-specific settings instead of global
    const tableSettings = window.rowSettings.get(tableId) || {};
    
    // Use table settings with conservative defaults
    const settings = {
        enableWildcardExpansion: tableSettings.enableWildcardExpansion || false,
        enableVersionChanges: tableSettings.enableVersionChanges || false,
        enableSpecialVersionTypes: tableSettings.enableSpecialVersionTypes || false,
        enableInverseStatus: tableSettings.enableInverseStatus || false,
        enableMultipleBranches: tableSettings.enableMultipleBranches || false,
        enableMixedStatus: tableSettings.enableMixedStatus || false,
        enableGapProcessing: tableSettings.enableGapProcessing || false,
        enableUpdatePatterns: tableSettings.enableUpdatePatterns || false,  
        // Core features remain enabled
        enableStatusProcessing: true,
        enableRangeHandling: true
    };
    
    console.debug(`Processing ${tableId} with settings:`, settings);
    
    // Normalize the base CPE string if needed
    cpeBase = normalizeCpeString(cpeBase);
    
    // Check if we have valid version data
    if (!rawPlatformData || !rawPlatformData.versions || !Array.isArray(rawPlatformData.versions) || rawPlatformData.versions.length === 0) {
        console.debug("No version data available, using basic CPE match");
        const basicMatch = createCpeMatchObject(cpeBase);
        return [basicMatch];
    }
    
    console.debug(`Processing ${rawPlatformData.versions.length} versions for ${cpeBase}`);
      // **MODULAR RULES ENGINE** - Primary approach for JSON generation
    if (window.ModularRuleEngine) {
        console.debug("Using modular rules engine for JSON generation");
        const ruleEngine = new window.ModularRuleEngine(settings, rawPlatformData);
        const matches = ruleEngine.generateMatches(cpeBase);
        
        if (matches.length > 0) {
            console.debug(`Modular rules engine generated ${matches.length} matches for ${cpeBase}`);
            return matches;
        } else {
            console.warn(`Modular rules engine returned no matches for ${cpeBase}. This may indicate:
                - No applicable rules for the version data structure
                - All rules were disabled in settings
                - Version data may be malformed or empty`);
            console.debug("Raw platform data:", JSON.stringify(rawPlatformData, null, 2));
            console.debug("Settings:", JSON.stringify(settings, null, 2));
            
            // Return basic match as last resort
            const basicMatch = createCpeMatchObject(cpeBase);
            console.debug("Returning basic CPE match as fallback");
            return [basicMatch];
        }
    } else {
        console.error("Modular rules engine (ModularRuleEngine) is not loaded. This is a critical dependency.");
        console.error("Please ensure modular_rules.js is properly loaded before cpe_json_handler.js");
        
        // Return basic match to prevent complete failure
        const basicMatch = createCpeMatchObject(cpeBase);
        console.debug("Returning basic CPE match due to missing modular rules engine");
        return [basicMatch];    }
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
 * Process JSON based on source type
 * @param {Set} selectedCPEs - Set of selected CPE base strings
 * @param {Object} rawPlatformData - Raw platform data
 * @param {Object} metadata - Table metadata
 * @returns {Object} Generated JSON
 */
function processJsonBasedOnSource(selectedCPEs, rawPlatformData, metadata) {
    // Create a base structure WITHOUT the outer wrapper
    let configs = [];
    
    try {
        console.debug(`Processing JSON based on ${metadata.dataResource} source with ${selectedCPEs.size} selected CPEs`);
        
        // Check if we have embedded configuration (for NVD data)
        if (metadata.dataResource === 'NVDAPI' && rawPlatformData && rawPlatformData.rawConfigData) {
            // For NVD API data, we have the complete configuration
            console.debug("Using embedded NVD configuration");
            // Wrap in nodes array to match allConfigurations format
            configs.push({
                nodes: [rawPlatformData.rawConfigData]
            });
        } 
        // Regular version data processing
        else {
            console.debug("Processing version data for CPEs");
            // Process the basic version data
            const config = processBasicVersionData(selectedCPEs, rawPlatformData);
            
            // Comment out generatorData creation
            /* 
            // Add metadata
            config.generatorData = {
                "generatedFromSource": {
                    "dataResource": metadata.dataResource || "Unknown",
                    "sourceId": metadata.sourceId || "Unknown",
                    "sourceRole": metadata.sourceRole || "Unknown"
                }
            };
            */

            // MODIFIED: Wrap config in nodes array
            configs.push({
                nodes: [config]
            });
        }
        
        return configs;
    } catch (e) {
        console.error("Error processing JSON:", e);
        
        // Return an empty array as fallback
        return [];
    }
}



/**
 * Generate JSON with all configurations from all tables
 * @returns {Array} Array of configurations
 */
function generateAllConfigurationsJson() {
    try {
        const allConfigs = [];
        
        // Add debugging to inspect the consolidatedJsons content
        console.debug("generateAllConfigurationsJson - entries in consolidatedJsons:", consolidatedJsons.size);
        
        // Add each table's configuration directly to the allConfigs array
        consolidatedJsons.forEach((json, tableId) => {
            console.debug(`Checking table ${tableId}, json type: ${typeof json}, is array: ${Array.isArray(json)}, length: ${json ? (Array.isArray(json) ? json.length : 'not array') : 'null'}`);
            
            // If json is not what we expect, log for debugging
            if (json && !Array.isArray(json)) {
                console.debug("Unexpected json structure:", JSON.stringify(json).substring(0, 200) + "...");
            }
            
            // If table has valid JSON, add all configs from this table
            if (json && Array.isArray(json) && json.length > 0) {
                // Each configuration is already properly structured with a nodes array,
                // so we can add them directly to allConfigs without additional wrapping
                json.forEach(config => {
                    allConfigs.push(config);
                });
                console.debug(`Added ${json.length} configs to allConfigs from table ${tableId}`);
            }
        });
        
        console.debug(`Total configurations in allConfigs: ${allConfigs.length}`);
        return allConfigs;
    } catch(e) {
        console.error("Error generating all configurations JSON:", e);
        return [];  // Return empty array as fallback
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
            dataResource: "Unknown",
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
 * Create a CPE match object from version info
 * @param {string} cpeBase - Base CPE string
 * @param {Object} versionInfo - Version info object
 * @param {boolean} isVulnerable - Vulnerability status
 * @returns {Object} CPE match object
 */
function createCpeMatchFromVersionInfo(cpeBase, versionInfo, isVulnerable) {
    // Check for "n/a" and similar values that should be treated like wildcards
    const nonSpecificVersions = ["n/a", "not available", "not applicable", "unavailable", "na", "nil", "none", "*"];
    
    // Handle single version with no range indicators
    if (versionInfo.version && !versionInfo.lessThan && !versionInfo.lessThanOrEqual && 
        !versionInfo.greaterThan && !versionInfo.greaterThanOrEqual) {
        
        // Special case: If version is a wildcard or n/a value, keep the wildcard in the criteria
        if (nonSpecificVersions.includes(versionInfo.version.toLowerCase())) {
            return {
                "criteria": cpeBase, // Keep base CPE with wildcard intact
                "matchCriteriaId": generateMatchCriteriaId(),
                "vulnerable": isVulnerable
            };
        }
        
        // Create a CPE match with explicit version embedded in the criteria
        const cpeParts = cpeBase.split(':');
        // Apply formatCPEComponent to properly encode the version
        cpeParts[5] = window.formatCPEComponent ? 
            window.formatCPEComponent(versionInfo.version) : 
            versionInfo.version; // Replace wildcard with encoded version
        
        return {
            "criteria": cpeParts.join(':'),
            "matchCriteriaId": generateMatchCriteriaId(),
            "vulnerable": isVulnerable
        };
    } else {
        // Range specification with potential wildcards
        const cpeMatch = {
            "criteria": cpeBase,
            "matchCriteriaId": generateMatchCriteriaId(),
            "vulnerable": isVulnerable
        };
        
        // Handle start version (lower bound)
        // If version is a wildcard or n/a value, don't include any start version constraint
        const hasNonSpecificStartVersion = versionInfo.version && nonSpecificVersions.includes(versionInfo.version.toLowerCase());
        if (versionInfo.version && !hasNonSpecificStartVersion) {
            cpeMatch.versionStartIncluding = window.formatCPEComponent ? 
                window.formatCPEComponent(versionInfo.version) : 
                versionInfo.version;
        } else if (versionInfo.greaterThan) {
            cpeMatch.versionStartExcluding = window.formatCPEComponent ? 
                window.formatCPEComponent(versionInfo.greaterThan) : 
                versionInfo.greaterThan;
        } else if (versionInfo.greaterThanOrEqual) {
            cpeMatch.versionStartIncluding = window.formatCPEComponent ? 
                window.formatCPEComponent(versionInfo.greaterThanOrEqual) : 
                versionInfo.greaterThanOrEqual;
        }
        
        // Handle end version (upper bound)
        // If lessThan/lessThanOrEqual is a wildcard or n/a value, don't include any end version constraint
        const hasNonSpecificLessThan = versionInfo.lessThan && nonSpecificVersions.includes(versionInfo.lessThan.toLowerCase());
        const hasNonSpecificLessThanOrEqual = versionInfo.lessThanOrEqual && nonSpecificVersions.includes(versionInfo.lessThanOrEqual.toLowerCase());
        
        if (versionInfo.lessThan && !hasNonSpecificLessThan) {
            cpeMatch.versionEndExcluding = window.formatCPEComponent ? 
                window.formatCPEComponent(versionInfo.lessThan) : 
                versionInfo.lessThan;
        } else if (versionInfo.lessThanOrEqual && !hasNonSpecificLessThanOrEqual) {
            cpeMatch.versionEndIncluding = window.formatCPEComponent ? 
                window.formatCPEComponent(versionInfo.lessThanOrEqual) : 
                versionInfo.lessThanOrEqual;
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
 * Check for special version structure patterns
 * @param {Object} rawPlatformData - Raw platform data
 * @returns {boolean} True if special case handling is needed
 */
function hasSpecialVersionStructure(rawPlatformData) {
    if (!rawPlatformData) {
        return false;
    }
    
    // Check for unaffected default status with explicit affected entries
    const hasUnaffectedDefault = rawPlatformData.defaultStatus === 'unaffected';
    
    // Count affected and unaffected entries
    let affectedEntries = 0;
    let unaffectedEntries = 0;
    
    if (rawPlatformData.versions && Array.isArray(rawPlatformData.versions)) {
        rawPlatformData.versions.forEach(v => {
            if (v && v.status === 'affected') affectedEntries++;
            if (v && v.status === 'unaffected') unaffectedEntries++;
        });
    }
    
    // Special case if default is unaffected but there are affected entries
    // Or if there are multiple unaffected entries
    return (hasUnaffectedDefault && affectedEntries > 0) || unaffectedEntries > 1;
}

/**
 * Generate JSON output with timestamp
 * @returns {Object} JSON object with timestamp
 */
function generateJsonOutput() {
    // Existing JSON generation code
    const json = {
        // ... existing properties
    };
    
    // Comment out timestamp addition
    /*
    // Add timestamp if available through the timestamp handler
    if (window.timestampHandler && typeof window.timestampHandler.getTimestamp === 'function') {
        json.generatorTimestamp = window.timestampHandler.getTimestamp();
    }
    */
    
    return json;
}

/**
 * Handle settings changes for a specific row (matchesTable)
 * @param {string} tableId - Table identifier (e.g., "matchesTable_0")
 */
function onRowSettingsChange(tableId) {
    const settingsKey = tableId;
    const rowSettings = window.rowSettings.get(settingsKey);
    console.debug(`Row settings changed for ${settingsKey}:`, rowSettings);
    
    // Regenerate JSON for this specific table if it has selections
    const selectedRows = window.tableSelections.get(tableId);
    if (selectedRows && selectedRows.size > 0) {
        updateConsolidatedJson(tableId);
    }
}

// Export functions and maps to global scope for integrations with other modules
window.tableSelections = tableSelections;
window.consolidatedJsons = consolidatedJsons;
window.createCpeMatchObject = createCpeMatchObject;
window.processJsonBasedOnSource = processJsonBasedOnSource;

