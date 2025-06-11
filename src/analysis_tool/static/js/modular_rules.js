/**
 * Modular JSON Generation Rules System
 * 
 * This module implements a truly modular rule system where each processing rule
 * can be independently enabled/disabled and applied in a composable manner.
 */

/**
 * Rule Registry - Each rule is a self-contained module
 */
const JSON_GENERATION_RULES = {
    
    /**
     * Wildcard Expansion Rule
     * Converts patterns like "5.4.*" into version ranges
     */
    wildcardExpansion: {
        name: 'Wildcard Expansion',
        description: 'Converts wildcard patterns (5.4.*) to version ranges',
        
        // Check if this rule should be applied
        shouldApply: (versionData, settings) => {
            return settings.enableWildcardExpansion && 
                   versionData.versions.some(v => 
                       v && (v.lessThanOrEqual && String(v.lessThanOrEqual).includes('*') || 
                            v.lessThan && String(v.lessThan).includes('*'))
                   );
        },
        
        // Apply the rule to version data
        process: (cpeBase, versionInfo, isVulnerable, context) => {
            const matches = [];
            
            // Handle wildcards in lessThanOrEqual
            if (versionInfo.lessThanOrEqual && String(versionInfo.lessThanOrEqual).includes('*')) {
                const wildcard = versionInfo.lessThanOrEqual;
                const prefix = wildcard.split('*')[0].replace(/\.$/, '');
                const parts = prefix.split('.');
                
                if (parts.length >= 2) {
                    const majorVersion = parseInt(parts[0], 10);
                    const minorVersion = parseInt(parts[1], 10);
                    
                    if (!isNaN(majorVersion) && !isNaN(minorVersion)) {
                        const startVersion = versionInfo.version || `${majorVersion}.${minorVersion}`;
                        const endVersion = `${majorVersion}.${minorVersion + 1}`;                        matches.push({
                            criteria: cpeBase,
                            matchCriteriaId: generateMatchCriteriaId(),
                            vulnerable: isVulnerable,
                            versionStartIncluding: startVersion,
                            versionEndExcluding: endVersion
                        });
                        
                        console.debug(`[Wildcard Rule] Created range for ${wildcard}: ${startVersion} to ${endVersion}`);
                        return { processed: true, matches };
                    }
                }
            }
            
            // Similar logic for lessThan wildcards
            if (versionInfo.lessThan && String(versionInfo.lessThan).includes('*')) {
                // Handle lessThan wildcard logic here
                console.debug(`[Wildcard Rule] Processing lessThan wildcard: ${versionInfo.lessThan}`);
            }
            
            return { processed: false, matches: [] };
        }
    },

    /**
     * Version Changes Rule
     * Processes version.changes arrays for fix information
     */
    versionChanges: {
        name: 'Version Changes',
        description: 'Processes version.changes arrays for patches and fixes',
        
        shouldApply: (versionData, settings) => {
            return settings.enableVersionChanges && 
                   versionData.versions.some(v => 
                       v && v.changes && Array.isArray(v.changes) && v.changes.length > 0
                   );
        },
        
        process: (cpeBase, versionInfo, isVulnerable, context) => {
            const matches = [];
            
            if (versionInfo.changes && Array.isArray(versionInfo.changes)) {
                for (const change of versionInfo.changes) {
                    if (change.status === "fixed" && change.at) {                        matches.push({
                            criteria: cpeBase,
                            matchCriteriaId: generateMatchCriteriaId(),
                            vulnerable: true,
                            versionStartIncluding: versionInfo.version,
                            versionEndExcluding: change.at
                        });
                        
                        console.debug(`[Version Changes Rule] Added range for fix: ${versionInfo.version} to ${change.at}`);
                    }
                }
                
                if (matches.length > 0) {
                    return { processed: true, matches };
                }
            }
            
            return { processed: false, matches: [] };
        }
    },

    /**
     * Inverse Status Rule
     * Handles defaultStatus=unaffected with explicit affected entries
     */
    inverseStatus: {
        name: 'Inverse Status Processing',
        description: 'Handles default unaffected status with specific affected versions',
        
        shouldApply: (versionData, settings) => {
            if (!settings.enableInverseStatus) return false;
            
            const hasDefaultUnaffected = versionData.defaultStatus === 'unaffected';
            const affectedVersions = versionData.versions.filter(v => v && v.status === 'affected');
            return hasDefaultUnaffected && affectedVersions.length > 0;
        },
        
        // This rule processes the entire version dataset, not individual versions
        processDataset: (cpeBase, versionData, settings, context) => {
            const matches = [];
            const affectedVersions = versionData.versions.filter(v => v && v.status === 'affected');
            
            console.debug(`[Inverse Status Rule] Processing ${affectedVersions.length} affected versions with default unaffected`);
            
            for (const affectedInfo of affectedVersions) {
                // Check if other rules should process this version first
                const otherRulesResult = context.applyOtherRules(cpeBase, affectedInfo, true, ['inverseStatus']);
                
                if (otherRulesResult.processed) {
                    matches.push(...otherRulesResult.matches);                } else {
                    // Standard processing for this affected version
                    const cpeMatch = createCpeMatchFromVersionInfo(cpeBase, affectedInfo, true);
                    matches.push(cpeMatch);
                }
            }
            
            return { processed: true, matches };
        }
    },

    /**
     * Mixed Status Rule
     * Handles complex combinations of affected and multiple unaffected versions
     */
    mixedStatus: {
        name: 'Mixed Status Processing',
        description: 'Handles complex affected/unaffected status combinations',
        
        shouldApply: (versionData, settings) => {
            if (!settings.enableMixedStatus) return false;
            
            const affectedVersions = versionData.versions.filter(v => v && v.status === 'affected');
            const unaffectedVersions = versionData.versions.filter(v => v && v.status === 'unaffected');
            return affectedVersions.length > 0 && unaffectedVersions.length > 1;
        },
        
        processDataset: (cpeBase, versionData, settings, context) => {
            const matches = [];
            const affectedVersions = versionData.versions.filter(v => v && v.status === 'affected');
            const unaffectedVersions = versionData.versions.filter(v => v && v.status === 'unaffected');
            
            console.debug(`[Mixed Status Rule] Processing ${affectedVersions.length} affected, ${unaffectedVersions.length} unaffected`);
            
            // Process affected versions normally
            for (const affectedInfo of affectedVersions) {
                const otherRulesResult = context.applyOtherRules(cpeBase, affectedInfo, true, ['mixedStatus']);
                
                if (otherRulesResult.processed) {
                    matches.push(...otherRulesResult.matches);                } else {
                    const cpeMatch = createCpeMatchFromVersionInfo(cpeBase, affectedInfo, true);
                    matches.push(cpeMatch);
                }
            }
            
            // For mixed status, we might need gap processing between unaffected ranges
            if (settings.enableGapProcessing) {
                console.debug(`[Mixed Status Rule] Delegating gap processing between unaffected ranges`);
                // This would integrate with the gap processing rule
            }
            
            return { processed: true, matches };
        }
    },

    /**
     * Gap Processing Rule
     * Fills gaps between unaffected version ranges
     */
    gapProcessing: {
        name: 'Gap Processing',
        description: 'Fills gaps between unaffected version ranges',
        
        shouldApply: (versionData, settings) => {
            if (!settings.enableGapProcessing) return false;
            
            const hasRanges = versionData.versions.some(v => 
                v && (v.lessThan || v.lessThanOrEqual || v.greaterThan || v.greaterThanOrEqual));
            const hasExactVersions = versionData.versions.some(v => 
                v && v.version && v.version !== '*');
            
            return hasRanges && hasExactVersions;
        },
        
        processDataset: (cpeBase, versionData, settings, context) => {
            console.debug(`[Gap Processing Rule] Analyzing version ranges for gaps`);
            
            // This is a complex rule that would analyze unaffected ranges
            // and create affected ranges in the gaps between them
            const matches = [];
            const unaffectedVersions = versionData.versions.filter(v => v && v.status === 'unaffected');
            
            // Sort and analyze unaffected ranges to find gaps
            // Implementation would go here based on the existing processGapsBetweenUnaffectedRanges logic
            
            return { processed: false, matches }; // Placeholder for now
        }
    },

    /**
     * Special Version Types Rule
     * Handles non-standard version types (dates, commits, etc.)
     */
    specialVersionTypes: {
        name: 'Special Version Types',
        description: 'Handles non-standard version types like dates and commits',
        
        shouldApply: (versionData, settings) => {
            if (!settings.enableSpecialVersionTypes) return false;
            
            return versionData.versions.some(v => 
                v && v.versionType && !['semver', 'string'].includes(v.versionType) && v.versionType !== 'git'
            );
        },
        
        process: (cpeBase, versionInfo, isVulnerable, context) => {
            if (versionInfo.versionType && !['semver', 'string'].includes(versionInfo.versionType)) {                console.debug(`[Special Version Types Rule] Processing ${versionInfo.versionType}: ${versionInfo.version}`);
                // Apply special handling based on version type
                const cpeMatch = createCpeMatchFromVersionInfo(cpeBase, versionInfo, isVulnerable);
                
                return { processed: true, matches: [cpeMatch] };
            }
            
            return { processed: false, matches: [] };
        }
    },    /**
     * Update Patterns Rule
     * Recognizes and processes patch/hotfix/service pack patterns
     */
    updatePatterns: {
        name: 'Update Patterns',
        description: 'Recognizes patch, hotfix, and service pack version patterns',
        
        shouldApply: (versionData, settings) => {
            if (!settings.enableUpdatePatterns) return false;
            
            const updatePatterns = [
                /alpha/i, /beta/i, /rc/i, /patch/i, /hotfix/i, /service[\s\-_]+pack/i, 
                /sp\d/i, /\.p\d/i, /\.sp\d/i, /hf\d/i, /update/i, /upd/i
            ];
            
            return versionData.versions.some(v => 
                v && v.version && updatePatterns.some(pattern => pattern.test(v.version))
            );
        },
          process: (cpeBase, versionInfo, isVulnerable, context) => {
            const version = versionInfo.version;
            
            // Enhanced pattern definitions with proper ordering (specific patterns first)
            const updatePatterns = [
                // Specific patterns first to avoid incorrect matches
                
                // Service pack patterns (most specific first)
                { pattern: /^(.+?)\.sp(\d+)$/i, type: 'sp' }, // Handle 3.0.0.sp1
                { pattern: /^(.+?)[\.\-_]*service[\s\-_]+pack[\.\-_]*(\d*)[\.\-_]*$/i, type: 'sp' },
                { pattern: /^(.+?)[\.\-_]*sp[\.\-_]*(\d+)[\.\-_]*$/i, type: 'sp' },
                
                // Patch patterns (handle p-notation specifically)
                { pattern: /^(.+?)\.p(\d+)$/i, type: 'patch' }, // Handle 3.1.0.p7
                { pattern: /^(.+?)[\.\-_]*patch[\.\-_]*(\d*)[\.\-_]*$/i, type: 'patch' },
                
                // Beta patterns (handle .1 notation specifically)
                { pattern: /^(.+?)-beta\.(\d+)$/i, type: 'beta' }, // Handle 1.0.0-beta.1
                { pattern: /^(.+?)[\.\-_]*beta[\.\-_]*(\d*)[\.\-_]*$/i, type: 'beta' },
                { pattern: /^(.+?)[\.\-_]*b[\.\-_]*(\d+)[\.\-_]*$/i, type: 'beta' },
                
                // Alpha patterns
                { pattern: /^(.+?)-alpha\.(\d+)$/i, type: 'alpha' }, // Handle 1.0.0-alpha.1
                { pattern: /^(.+?)[\.\-_]*alpha[\.\-_]*(\d*)[\.\-_]*$/i, type: 'alpha' },
                { pattern: /^(.+?)[\.\-_]*a[\.\-_]*(\d+)[\.\-_]*$/i, type: 'alpha' },
                
                // Release candidate patterns
                { pattern: /^(.+?)-rc\.(\d+)$/i, type: 'rc' }, // Handle 1.0.0-rc.1
                { pattern: /^(.+?)[\.\-_]*rc[\.\-_]*(\d*)[\.\-_]*$/i, type: 'rc' },
                { pattern: /^(.+?)[\.\-_]*release[\s\-_]+candidate[\.\-_]*(\d*)[\.\-_]*$/i, type: 'rc' },
                
                // Hotfix patterns (handle .2 notation specifically)
                { pattern: /^(.+?)-hotfix\.(\d+)$/i, type: 'hotfix' }, // Handle 2.1.0-hotfix.2
                { pattern: /^(.+?)[\.\-_]*hotfix[\.\-_]*(\d*)[\.\-_]*$/i, type: 'hotfix' },
                { pattern: /^(.+?)[\.\-_]*hf[\.\-_]*(\d+)[\.\-_]*$/i, type: 'hotfix' },
                
                // Patch patterns with specific numbering (handle .5 notation)
                { pattern: /^(.+?)-patch\.(\d+)$/i, type: 'patch' }, // Handle 2.0.0-patch.5
                
                // Update patterns
                { pattern: /^(.+?)[\.\-_]*update[\.\-_]*(\d*)[\.\-_]*$/i, type: 'update' },
                { pattern: /^(.+?)[\.\-_]*upd[\.\-_]*(\d+)[\.\-_]*$/i, type: 'update' },
                
                // Fix patterns
                { pattern: /^(.+?)[\.\-_]*fix[\.\-_]*(\d+)[\.\-_]*$/i, type: 'fix' },
                
                // Revision patterns
                { pattern: /^(.+?)[\.\-_]*revision[\.\-_]*(\d+)[\.\-_]*$/i, type: 'revision' },
                { pattern: /^(.+?)[\.\-_]*rev[\.\-_]*(\d+)[\.\-_]*$/i, type: 'revision' }
            ];
            
            for (const { pattern, type } of updatePatterns) {
                const match = version.match(pattern);
                if (match) {
                    console.debug(`[Update Patterns Rule] Detected ${type} pattern: ${version}`);
                    
                    // Extract base version and update component
                    const baseVersion = match[1];
                    let updateNumber = match[2] || '';
                    
                    // Handle p-notation expansion (p7 → patch7)
                    let finalType = type;
                    if (pattern.source.includes('\\.p(') && type === 'patch') {
                        // This is the p-notation pattern, already correct type
                        finalType = 'patch';
                    }
                    
                    // Clean and format the update component
                    let updateComponent;
                    if (updateNumber) {
                        // Remove any punctuation from the number and combine with type
                        const cleanNumber = updateNumber.replace(/[\.\-_,]/g, '');
                        updateComponent = `${finalType}${cleanNumber}`;
                    } else {
                        // Just use the type name if no number
                        updateComponent = finalType;
                    }
                    
                    console.debug(`[Update Patterns Rule] Transforming ${version} → base: ${baseVersion}, update: ${updateComponent}`);
                    
                    // Create modified CPE with update component
                    const cpeMatch = createCpeMatchWithUpdate(cpeBase, baseVersion, updateComponent, isVulnerable);
                    
                    return { processed: true, matches: [cpeMatch] };
                }
            }
            
            return { processed: false, matches: [] };
        }
    },

    /**
     * Multiple Branches Rule
     * Handles products with multiple version families (≥3 major.minor branches)
     */
    multipleBranches: {
        name: 'Multiple Branches',
        description: 'Handles products with multiple version families',
        
        shouldApply: (versionData, settings) => {
            if (!settings.enableMultipleBranches) return false;
            
            const versionBranches = new Set();
            versionData.versions.forEach(v => {
                if (v && v.version && typeof v.version === 'string') {
                    const parts = v.version.split('.');
                    if (parts.length >= 2) {
                        versionBranches.add(`${parts[0]}.${parts[1]}`);
                    }
                }
            });
            
            return versionBranches.size >= 3;
        },
        
        processDataset: (cpeBase, versionData, settings, context) => {
            const matches = [];
            const branchMap = new Map();
            
            // Group versions by branch
            versionData.versions.forEach(v => {
                if (v && v.version && typeof v.version === 'string') {
                    const parts = v.version.split('.');
                    if (parts.length >= 2) {
                        const branch = `${parts[0]}.${parts[1]}`;
                        if (!branchMap.has(branch)) {
                            branchMap.set(branch, []);
                        }
                        branchMap.get(branch).push(v);
                    }
                }
            });
            
            console.debug(`[Multiple Branches Rule] Processing ${branchMap.size} version branches`);
            
            // Process each branch separately
            for (const [branch, versions] of branchMap) {
                console.debug(`[Multiple Branches Rule] Processing branch ${branch} with ${versions.length} versions`);
                
                for (const versionInfo of versions) {
                    const isVulnerable = versionInfo.status === "affected";
                    const otherRulesResult = context.applyOtherRules(cpeBase, versionInfo, isVulnerable, ['multipleBranches']);
                      if (otherRulesResult.processed) {
                        matches.push(...otherRulesResult.matches);
                    } else {
                        const cpeMatch = createCpeMatchFromVersionInfo(cpeBase, versionInfo, isVulnerable);
                        matches.push(cpeMatch);
                    }
                }
            }
            
            return { processed: true, matches };
        }
    }
};

/**
 * Modular Rule Engine
 * Applies enabled rules in the correct order and handles rule interactions
 */
class ModularRuleEngine {
    constructor(settings, versionData) {
        this.settings = settings;
        this.versionData = versionData;
        this.appliedRules = new Set();
    }

    /**
     * Get all rules that should be applied based on settings and data
     */
    getApplicableRules() {
        const applicable = [];
        
        for (const [ruleId, rule] of Object.entries(JSON_GENERATION_RULES)) {
            if (rule.shouldApply(this.versionData, this.settings)) {
                applicable.push({ id: ruleId, rule });
                console.debug(`[Rule Engine] Rule '${rule.name}' is applicable`);
            }
        }
        
        return applicable;
    }

    /**
     * Apply other rules to a version (used by rules that need to delegate)
     */
    applyOtherRules(cpeBase, versionInfo, isVulnerable, excludeRules = []) {
        const availableRules = this.getApplicableRules().filter(({id}) => !excludeRules.includes(id));
        
        for (const {id, rule} of availableRules) {
            if (rule.process) {
                const result = rule.process(cpeBase, versionInfo, isVulnerable, this);
                if (result.processed) {
                    this.appliedRules.add(id);
                    return result;
                }
            }
        }
        
        return { processed: false, matches: [] };
    }

    /**
     * Process a single version through applicable rules
     */
    processVersion(cpeBase, versionInfo, isVulnerable) {
        const result = this.applyOtherRules(cpeBase, versionInfo, isVulnerable);
          if (!result.processed) {
            // No rules applied, use standard processing
            const cpeMatch = createCpeMatchFromVersionInfo(cpeBase, versionInfo, isVulnerable);
            return [cpeMatch];
        }
        
        return result.matches;
    }

    /**
     * Process the entire dataset through dataset-level rules
     */
    processDataset(cpeBase) {
        const datasetRules = this.getApplicableRules().filter(({rule}) => rule.processDataset);
        
        for (const {id, rule} of datasetRules) {
            console.debug(`[Rule Engine] Applying dataset rule: ${rule.name}`);
            const result = rule.processDataset(cpeBase, this.versionData, this.settings, this);
            
            if (result.processed) {
                this.appliedRules.add(id);
                return result.matches;
            }
        }
        
        return null; // No dataset rules applied
    }    /**
     * Main processing entry point
     */
    generateMatches(cpeBase) {
        const matches = [];
        
        // First, try dataset-level rules
        const datasetMatches = this.processDataset(cpeBase);
        if (datasetMatches) {
            matches.push(...datasetMatches);
            console.debug(`[Rule Engine] Dataset processing completed with ${datasetMatches.length} matches`);
            
            // apply per-version rules that might modify the results
            console.debug(`[Rule Engine] Checking for additional per-version rules`);
            const additionalMatches = this.processAdditionalVersionRules(cpeBase, datasetMatches);
            if (additionalMatches.length > 0) {
                console.debug(`[Rule Engine] Applied additional per-version rules, adding ${additionalMatches.length} more matches`);
                matches.push(...additionalMatches);
            }
            
            return matches;
        }
        
        // Fall back to per-version processing
        console.debug(`[Rule Engine] Falling back to per-version processing`);
        for (const versionInfo of this.versionData.versions) {
            if (!versionInfo) continue;
            
            const isVulnerable = versionInfo.status === "affected";
            const versionMatches = this.processVersion(cpeBase, versionInfo, isVulnerable);
            matches.push(...versionMatches);
        }
        
        console.debug(`[Rule Engine] Generated ${matches.length} total matches using rules: ${Array.from(this.appliedRules).join(', ')}`);
        return matches;
    }

    /**
     * Process additional per-version rules that should apply even when dataset rules are used
     */
    processAdditionalVersionRules(cpeBase, existingMatches) {
        const additionalMatches = [];
        // Get applicable per-version rules that should still be applied
        // Note: updatePatterns is already processed during dataset processing via other rules
        const perVersionRules = this.getApplicableRules().filter(({ rule }) => 
            !rule.processDataset && rule.process && 
            false // Temporarily disable additional per-version processing to avoid duplicates
        );
        
        if (perVersionRules.length === 0) {
            return additionalMatches;
        }
        
        console.debug(`[Rule Engine] Found ${perVersionRules.length} additional per-version rules to apply`);
        
        // Apply per-version rules to versions that match their patterns
        for (const versionInfo of this.versionData.versions) {
            if (!versionInfo) continue;
            
            const isVulnerable = versionInfo.status === "affected";
            
            for (const { id, rule } of perVersionRules) {
                const result = rule.process(cpeBase, versionInfo, isVulnerable, this);
                if (result.processed && result.matches.length > 0) {
                    console.debug(`[Rule Engine] Applied additional rule '${rule.name}' to version ${versionInfo.version}`);
                    additionalMatches.push(...result.matches);
                    this.appliedRules.add(id);
                }
            }
        }
        
        return additionalMatches;
    }
}

/**
 * Create a CPE match object with update component
 * @param {string} cpeBase - Base CPE string (e.g., "cpe:2.3:a:*:*:*:*:*:*:*:*:*")
 * @param {string} version - Base version (e.g., "2.0.0")
 * @param {string} update - Update component (e.g., "patch.5")
 * @param {boolean} isVulnerable - Whether this version is vulnerable
 * @returns {Object} CPE match object with proper update component
 */
function createCpeMatchWithUpdate(cpeBase, version, update, isVulnerable) {
    // Parse the base CPE to extract components
    const cpeComponents = cpeBase.split(':');
    
    // Ensure we have all 12 components for CPE 2.3 format
    // cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    while (cpeComponents.length < 12) {
        cpeComponents.push('*');
    }
    
    // Set the version (position 5) and update (position 6) fields
    cpeComponents[5] = version || '*';     // version (base version without update)
    cpeComponents[6] = update || '*';      // update (patch/hotfix/sp component)
    
    const cpeString = cpeComponents.join(':');
    
    console.debug(`[Update Patterns Rule] Created CPE with update field: ${cpeString}`);
    
    return {
        criteria: cpeString,
        matchCriteriaId: generateMatchCriteriaId(),
        vulnerable: isVulnerable
    };
}

window.ModularRuleEngine = ModularRuleEngine;
window.JSON_GENERATION_RULES = JSON_GENERATION_RULES;

console.debug("Modular Rules System loaded");
