/**
 * Parse a CPE string to extract vendor and product information
 * @param {string} cpeString - The CPE string to parse
 * @returns {Object} Object with vendor and product properties
 */
function parseCpeString(cpeString) {
    try {
        // For CPE 2.3 formatted strings (cpe:2.3:part:vendor:product:version:...)
        const parts = cpeString.split(':');
        if (parts.length >= 5) {
            return {
                vendor: parts[3].toLowerCase(),
                product: parts[4].toLowerCase()
            };
        }
        return { vendor: null, product: null };
    } catch (e) {
        console.warn("Error parsing CPE string:", e);
        return { vendor: null, product: null };
    }
}

/**
 * Check if a cpeMatch object represents a version range
 * @param {Object} match - The cpeMatch object to check
 * @returns {boolean} True if it's a range match
 */
function isRangeMatch(match) {
    return match.hasOwnProperty('versionStartIncluding') || 
           match.hasOwnProperty('versionStartExcluding') ||
           match.hasOwnProperty('versionEndIncluding') ||
           match.hasOwnProperty('versionEndExcluding');
}

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
 * Calculate total versions from raw platform data
 * @param {Set} selectedRows - Set of selected CPE rows
 * @param {Object} rawPlatformData - Raw platform version data
 * @returns {number} Total number of versions
 */
function calculateTotalVersions(selectedRows, rawPlatformData) {
    try {
        if (rawPlatformData && rawPlatformData.versions && Array.isArray(rawPlatformData.versions)) {
            return rawPlatformData.versions.length;
        }
        return selectedRows.size; // Fallback to number of selected rows
    } catch(e) {
        console.error("Error calculating total versions:", e);
        return selectedRows.size;
    }
}

/**
 * Count total CPE matches in a configuration
 * @param {Object} config - Configuration object
 * @returns {number} Count of CPE matches
 */
function getTotalCPEMatches(config) {
    let count = 0;
    if (config.nodes) {
        for (const node of config.nodes) {
            if (node.cpeMatch) {
                count += node.cpeMatch.length;
            }
        }
    } else if (config.cpeMatch) {
        count = config.cpeMatch.length;
    }
    return count;
}

/**
 * Gather metadata from a table
 * @param {number} tableIndex - Index of the table
 * @returns {Object} Table metadata 
 */
function gatherTableMetadata(tableIndex) {
    try {
        // Get the corresponding metadata from data attributes
        const container = document.querySelector(`.cpe-query-container[data-table-index="${tableIndex}"]`);
        
        if (!container) {
            return {
                dataResource: "Unknown",
                sourceId: "Unknown",
                sourceRole: "Unknown",
                rawPlatformData: null
            };
        }
        
        // Extract metadata from data attributes
        const dataResource = container.getAttribute('data-source') || "Unknown";
        const sourceId = container.getAttribute('data-source-id') || "Unknown";
        const sourceRole = container.getAttribute('data-source-role') || "Unknown";
        
        // Get raw platform data if available
        let rawPlatformData = null;
        const platformDataAttr = container.getAttribute('data-platform-data');
        if (platformDataAttr) {
            try {
                rawPlatformData = JSON.parse(platformDataAttr);
                // Add table index and element ID for reference
                rawPlatformData.tableIndex = tableIndex;
                rawPlatformData.elementId = `rawPlatformData_${tableIndex}`;
            } catch (e) {
                console.warn(`Could not parse platform data for table ${tableIndex}:`, e);
            }
        }
        
        return {
            dataResource,
            sourceId,
            sourceRole,
            rawPlatformData
        };
    } catch(e) {
        console.error(`Error gathering metadata for table ${tableIndex}:`, e);
        return {
            dataResource: "Error",
            sourceId: "Error",
            sourceRole: "Error",
            rawPlatformData: null
        };
    }
}

/**
 * Get statistics string from JSON
 * @param {Object} json - The JSON to extract statistics from
 * @param {number} selectionCount - Number of selected items as fallback
 * @returns {string} Formatted statistics string
 */
function getStatisticsString(json, selectionCount) {
    if (!json || !json.configurations || !json.configurations.length || !json.configurations[0]) {
        return `${selectionCount} selected`;
    }
    
    // Get statistics from generatorData.matchStats
    if (json.configurations[0].generatorData && json.configurations[0].generatorData.matchStats) {
        const stats = json.configurations[0].generatorData.matchStats;
        return `${stats.selectedCriteria} Criteria, ${stats.totalMatches} versions` +
               ` (${stats.exactMatches} exact, ${stats.rangeMatches} ranges)`;
    }
    
    // Fallback to simple count
    return `${selectionCount} selected`;
}

/**
 * Create a basic cpeMatch object
 * @param {string} cpeBase - Base CPE string
 * @returns {Object} Basic cpeMatch object
 */
function createCpeMatchObject(cpeBase) {
    // Normalize the CPE string
    const normalizedCpe = normalizeCpeString(cpeBase);
    
    return {
        "criteria": normalizedCpe,
        "matchCriteriaId": "generated_" + Math.random().toString(36).substr(2, 9),
        "vulnerable": true
    };
}