/**
 * CPE JSON Handler
 * 
 * Handles generation of CPE match objects and JSON configurations.
 * Uses shared utility functions from modular_rules.js for version comparison and ID generation.
 */

/**
 * Ensure CPE string has standard format with enough components
 * @param {string} cpeBase - The CPE string to normalize
 * @returns {string} Normalized CPE string
 */
function normalizeCpeString(cpeBase) {
    if (!cpeBase) return "cpe:2.3:a:*:*:*:*:*:*:*:*:*";
    
    // Split the CPE into its components
    const parts = cpeBase.split(':');
    
    // Check if we have the basic structure (cpe:2.3:part)
    if (parts.length < 3) {
        console.error("Invalid CPE string format:", cpeBase);
        return "cpe:2.3:a:*:*:*:*:*:*:*:*:*";
    }
    
    // Ensure it has part:vendor:product components
    while (parts.length < 5) {
        parts.push('*');
    }
    
    // Ensure it has version component so we can replace it later
    if (parts.length < 6) {
        parts.push('*');
    }
    
    // For complete format, ensure it has all 13 parts
    while (parts.length < 13) {
        parts.push('*');
    }
    
    return parts.join(':');
}

/**
 * Determine vulnerability based on status (mirrors Python logic)
 * @param {string} status - The status value ('affected', 'unaffected', 'unknown')
 * @returns {boolean} True if vulnerable (affected), false otherwise
 */
function determineVulnerability(status) {
    // Only 'affected' status means vulnerable
    // 'unaffected' and 'unknown' both mean not vulnerable
    return status === 'affected';
}

/**
 * Creates a CPE match object for a given CPE base string
 * @param {string} cpeBase - The base CPE string
 * @param {boolean} isVulnerable - Whether this is vulnerable
 * @returns {Object} A CPE match object
 */
function createCpeMatchObject(cpeBase, isVulnerable = true) {
    // Normalize the base CPE string if needed
    cpeBase = normalizeCpeString(cpeBase);
    
    return {
        "criteria": cpeBase,
        "matchCriteriaId": generateMatchCriteriaId(),
        "vulnerable": isVulnerable
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
        enableWildcardExpansion: tableSettings.enableWildcardExpansion !== undefined ? tableSettings.enableWildcardExpansion : false,
        enableVersionChanges: tableSettings.enableVersionChanges !== undefined ? tableSettings.enableVersionChanges : false,
        enableSpecialVersionTypes: tableSettings.enableSpecialVersionTypes !== undefined ? tableSettings.enableSpecialVersionTypes : false,
        enableInverseStatus: tableSettings.enableInverseStatus !== undefined ? tableSettings.enableInverseStatus : false,
        enableMultipleBranches: tableSettings.enableMultipleBranches !== undefined ? tableSettings.enableMultipleBranches : false,
        enableMixedStatus: tableSettings.enableMixedStatus !== undefined ? tableSettings.enableMixedStatus : false,
        enableGapProcessing: tableSettings.enableGapProcessing !== undefined ? tableSettings.enableGapProcessing : false,
        enableUpdatePatterns: tableSettings.enableUpdatePatterns !== undefined ? tableSettings.enableUpdatePatterns : false,  
        // Core features remain enabled
        enableStatusProcessing: true,
        enableRangeHandling: true
    };
    
    console.debug(`Processing ${tableId} with settings:`, settings);
    
    // Normalize the base CPE string if needed
    cpeBase = normalizeCpeString(cpeBase);
    
    // **CUSTOM CPE HANDLING** - Check if this is a custom CPE first
    if (window.customCPEHandlers && window.customCPEHandlers.has(cpeBase)) {
        console.debug(`Processing custom CPE: ${cpeBase}`);
        
        // Check for missing rawPlatformData
        if (!rawPlatformData) {
            console.error(`CRITICAL: No rawPlatformData available for custom CPE ${cpeBase}. This may cause issues in JSON generation.`);
            // For custom CPEs without platform data, return the basic custom match
            const handler = window.customCPEHandlers.get(cpeBase);
            return [handler.createMatch()];
        }
        
        // Custom CPEs use the same modular rules engine with the same settings
        console.debug(`Applying modular rules to custom CPE: ${cpeBase}`);
    }
    
    // Check if we have valid version data (for both custom and standard CPEs)
    if (!rawPlatformData || !rawPlatformData.versions || !Array.isArray(rawPlatformData.versions) || rawPlatformData.versions.length === 0) {
        console.debug("No version data available, using basic CPE match with defaultStatus");
        
        // Determine vulnerability from defaultStatus when no version data exists
        const defaultStatus = rawPlatformData ? rawPlatformData.defaultStatus || 'unknown' : 'unknown';
        const isVulnerable = determineVulnerability(defaultStatus);
        console.debug(`Using defaultStatus '${defaultStatus}' → vulnerable: ${isVulnerable}`);
        
        // For custom CPEs, use their handler to create the basic match
        if (window.customCPEHandlers && window.customCPEHandlers.has(cpeBase)) {
            const handler = window.customCPEHandlers.get(cpeBase);
            // Note: Custom CPE handlers may have their own vulnerability logic
            return [handler.createMatch()];
        }
        
        // For standard CPEs, use the standard basic match with proper vulnerability
        const basicMatch = createCpeMatchObject(cpeBase, isVulnerable);
        return [basicMatch];
    }
    
    console.debug(`Processing ${rawPlatformData.versions.length} versions for ${cpeBase}`);
      // **MODULAR RULES ENGINE** - Primary approach for JSON generation (works for both custom and standard CPEs)
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
            
            // Critical error - modular rules engine should always produce results
            throw new Error(`No matches generated for ${cpeBase} - check version data structure and settings`);
        }
    } else {
        const errorMsg = "Modular rules engine (ModularRuleEngine) is not loaded. This is a critical dependency.";
        console.error(errorMsg);
        console.error("Please ensure modular_rules.js is properly loaded before cpe_json_handler.js");
        
        throw new Error(errorMsg);
    }
}


/**
 * Process basic version data into a configuration object
 * @param {Set} selectedCPEs - Set of selected CPE base strings or DOM elements
 * @param {Object} rawPlatformData - Raw platform data
 * @param {string} tableId - Table identifier for settings
 * @returns {Object} Configuration object
 */
function processBasicVersionData(selectedCPEs, rawPlatformData, tableId) {
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
        const cpeMatches = processVersionDataToCpeMatches(cpeBase, rawPlatformData, tableId);
        
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
 * @param {string} tableId - Table identifier for settings
 * @returns {Object} Generated JSON
 */
function processJsonBasedOnSource(selectedCPEs, rawPlatformData, metadata, tableId) {
    // Create a base structure WITHOUT the outer wrapper
    let configs = [];
    
    try {
        const sourceInfo = metadata.sourceName && metadata.sourceName !== "Unknown" ? 
            `${metadata.sourceName} (${metadata.sourceId})` : 
            metadata.sourceId;
        console.debug(`Processing JSON based on ${metadata.dataResource} source [${sourceInfo}] with ${selectedCPEs.size} selected CPEs`);
        
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
        else {            console.debug("Processing version data for CPEs");            // Process the basic version data
            const config = processBasicVersionData(selectedCPEs, rawPlatformData, tableId);

            // Wrap config in nodes array
            configs.push({
                nodes: [config]
            });
        }
        
        return configs;
    } catch (e) {
        console.error("Error processing JSON:", e);
        throw e; // Fail fast - do not mask errors with fallbacks
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
        throw e; // Fail fast - do not mask errors with fallbacks
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
    // Get non-specific version values from the injected Python list (single source of truth)
    // Fall back to hardcoded list if injection failed
    const nonSpecificVersions = (window.NON_SPECIFIC_VERSION_VALUES || [
        "unspecified", "unknown", "none", "undefined", "various",
        "n/a", "not available", "not applicable", "unavailable",
        "na", "nil", "tbd", "to be determined", "pending",
        "not specified", "not determined", "not known", "not listed",
        "not provided", "missing", "empty", "null"
    ]).concat(["*"]); // Always include "*" as a wildcard
    
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
            cpeMatch.versionEndExcluding = window.formatCPEComponent ?                window.formatCPEComponent(versionInfo.lessThan) : 
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

// =============================================================================
// Global Exports - All window assignments consolidated here
// =============================================================================
// Global maps to store selections and generated JSONs
window.tableSelections = window.tableSelections || new Map();
window.consolidatedJsons = window.consolidatedJsons || new Map();
window.rowSettings = window.rowSettings || new Map();

// Export functions for integration with other modules
window.determineVulnerability = determineVulnerability;
window.normalizeCpeString = normalizeCpeString;
window.createCpeMatchObject = createCpeMatchObject;
window.processJsonBasedOnSource = processJsonBasedOnSource;

