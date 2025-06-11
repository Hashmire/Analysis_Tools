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
                // Traditional patterns
                /alpha/i, /beta/i, /rc/i, /patch/i, /hotfix/i, /service[\s\-_]+pack/i, 
                /sp\d/i, /\.p\d/i, /\.sp\d/i, /hf\d/i, /update/i, /upd/i,
                
                // Space-separated patterns (common in CVE data)
                /\s+p\d+$/i, /\s+patch\s*\d+/i, /\s+sp\d+$/i, /\s+hotfix\s*\d+/i,
                /\s+update\s*\d+/i, /\s+beta\s*\d*/i, /\s+alpha\s*\d*/i, 
                /\s+rc\s*\d*/i, /\s+fix\s*\d+/i, /\s+revision\s*\d+/i, /\s+rev\s*\d+/i
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
                
                // SPACE-SEPARATED PATTERNS (for real-world CVE data formats)
                // These must come first as they're more specific than the general patterns below
                
                // Space-separated patch patterns (most common in CVE data)
                { pattern: /^(.+?)\s+p(\d+)$/i, type: 'patch' }, // Handle "3.0.0 p1", "3.1.0 p2"
                { pattern: /^(.+?)\s+patch\s*(\d+)$/i, type: 'patch' }, // Handle "3.3 Patch 1", "3.3 Patch 2"
                { pattern: /^(.+?)\s+Patch\s*(\d+)$/i, type: 'patch' }, // Handle "3.3 Patch 1" (capitalized)
                
                // Space-separated service pack patterns
                { pattern: /^(.+?)\s+sp(\d+)$/i, type: 'sp' }, // Handle "2.0.0 sp1"
                { pattern: /^(.+?)\s+service\s+pack\s*(\d+)$/i, type: 'sp' }, // Handle "2.0.0 service pack 1"
                { pattern: /^(.+?)\s+Service\s+Pack\s*(\d+)$/i, type: 'sp' }, // Handle "2.0.0 Service Pack 1"
                
                // Space-separated hotfix patterns
                { pattern: /^(.+?)\s+hotfix\s*(\d+)$/i, type: 'hotfix' }, // Handle "3.0.0 hotfix 1"
                { pattern: /^(.+?)\s+Hotfix\s*(\d+)$/i, type: 'hotfix' }, // Handle "3.0.0 Hotfix 1"
                { pattern: /^(.+?)\s+hf(\d+)$/i, type: 'hotfix' }, // Handle "3.0.0 hf1"
                
                // Space-separated update patterns
                { pattern: /^(.+?)\s+update\s*(\d+)$/i, type: 'update' }, // Handle "3.0.0 update 1"
                { pattern: /^(.+?)\s+Update\s*(\d+)$/i, type: 'update' }, // Handle "3.0.0 Update 1"
                { pattern: /^(.+?)\s+upd(\d+)$/i, type: 'update' }, // Handle "3.0.0 upd1"
                
                // Space-separated beta patterns
                { pattern: /^(.+?)\s+beta\s*(\d*)$/i, type: 'beta' }, // Handle "1.0.0 beta", "1.0.0 beta 1"
                { pattern: /^(.+?)\s+Beta\s*(\d*)$/i, type: 'beta' }, // Handle "1.0.0 Beta 1"
                { pattern: /^(.+?)\s+b(\d+)$/i, type: 'beta' }, // Handle "1.0.0 b1"
                
                // Space-separated alpha patterns
                { pattern: /^(.+?)\s+alpha\s*(\d*)$/i, type: 'alpha' }, // Handle "1.0.0 alpha", "1.0.0 alpha 1"
                { pattern: /^(.+?)\s+Alpha\s*(\d*)$/i, type: 'alpha' }, // Handle "1.0.0 Alpha 1"
                { pattern: /^(.+?)\s+a(\d+)$/i, type: 'alpha' }, // Handle "1.0.0 a1"
                
                // Space-separated release candidate patterns
                { pattern: /^(.+?)\s+rc\s*(\d*)$/i, type: 'rc' }, // Handle "1.0.0 rc", "1.0.0 rc 1"
                { pattern: /^(.+?)\s+RC\s*(\d*)$/i, type: 'rc' }, // Handle "1.0.0 RC 1"
                { pattern: /^(.+?)\s+release\s+candidate\s*(\d*)$/i, type: 'rc' }, // Handle "1.0.0 release candidate 1"
                { pattern: /^(.+?)\s+Release\s+Candidate\s*(\d*)$/i, type: 'rc' }, // Handle "1.0.0 Release Candidate 1"
                
                // Space-separated fix patterns
                { pattern: /^(.+?)\s+fix\s*(\d+)$/i, type: 'fix' }, // Handle "3.0.0 fix 1"
                { pattern: /^(.+?)\s+Fix\s*(\d+)$/i, type: 'fix' }, // Handle "3.0.0 Fix 1"
                
                // Space-separated revision patterns
                { pattern: /^(.+?)\s+revision\s*(\d+)$/i, type: 'revision' }, // Handle "3.0.0 revision 1"
                { pattern: /^(.+?)\s+Revision\s*(\d+)$/i, type: 'revision' }, // Handle "3.0.0 Revision 1"
                { pattern: /^(.+?)\s+rev\s*(\d+)$/i, type: 'revision' }, // Handle "3.0.0 rev 1"
                { pattern: /^(.+?)\s+Rev\s*(\d+)$/i, type: 'revision' }, // Handle "3.0.0 Rev 1"
                
                // TRADITIONAL DOT/DASH/UNDERSCORE PATTERNS (existing patterns)
                
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
                    const baseVersion = match[1].trim(); // Trim any trailing spaces
                    let updateNumber = match[2] || '';
                    
                    // Handle p-notation expansion (p7 -> patch7)
                    let finalType = type;
                    if (pattern.source.includes('\\.p(') && type === 'patch') {
                        // This is the p-notation pattern, already correct type
                        finalType = 'patch';
                    }
                    
                    // Clean and format the update component
                    let updateComponent;
                    if (updateNumber) {
                        // Remove any punctuation and spaces from the number and combine with type
                        const cleanNumber = updateNumber.replace(/[\.\-_,\s]/g, '');
                        updateComponent = `${finalType}${cleanNumber}`;
                    } else {
                        // Just use the type name if no number
                        updateComponent = finalType;
                    }
                    
                    console.debug(`[Update Patterns Rule] Transforming ${version} -> base: ${baseVersion}, update: ${updateComponent}`);
                    
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
     * Handles products with multiple version families (>=3 major.minor branches)
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
    }    /**
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
        
        // Detect potential rule conflicts
        this.detectRuleConflicts(applicable);
        
        return applicable;
    }    /**
     * Detect and warn about potential rule conflicts with enhanced analysis
     */
    detectRuleConflicts(applicableRules) {
        const ruleNames = applicableRules.map(r => r.id);
        const conflicts = [];
        
        // Enhanced conflict patterns with detailed analysis
        const conflictPatterns = [
            {
                rules: ['mixedStatus', 'inverseStatus'],
                severity: 'HIGH',
                warning: 'Mixed Status and Inverse Status rules may overlap in processing affected versions',
                resolution: 'Will use priority order or cooperative processing if compatible'
            },
            {
                rules: ['updatePatterns', 'wildcardExpansion'],
                severity: 'MEDIUM',
                warning: 'Update Patterns and Wildcard Expansion may both process versioned patterns',
                resolution: 'Will apply per-version rules after dataset rules to avoid conflicts'
            },
            {
                rules: ['multipleBranches', 'mixedStatus'],
                severity: 'LOW',
                warning: 'Multiple Branches and Mixed Status may both process complex version datasets',
                resolution: 'Will use Branch-Aware Mixed Status cooperative processing'
            },
            {
                rules: ['gapProcessing', 'mixedStatus'],
                severity: 'LOW',
                warning: 'Gap Processing and Mixed Status may create overlapping version ranges',
                resolution: 'Will use Mixed Status with Gap Processing cooperative processing'
            },
            {
                rules: ['multipleBranches', 'gapProcessing'],
                severity: 'MEDIUM',
                warning: 'Multiple Branches and Gap Processing may create complex rule interactions',
                resolution: 'Will use priority order processing'
            },
            {
                rules: ['inverseStatus', 'gapProcessing'],
                severity: 'LOW',
                warning: 'Inverse Status and Gap Processing can work together effectively',
                resolution: 'Will use Inverse Status with Gap Processing cooperative processing'
            }
        ];
        
        console.group(`[Rule Engine] Conflict Analysis for ${applicableRules.length} applicable rules`);
        
        for (const pattern of conflictPatterns) {
            const hasAllRules = pattern.rules.every(rule => ruleNames.includes(rule));
            if (hasAllRules) {
                conflicts.push(pattern);
                
                const severityStyle = pattern.severity === 'HIGH' ? 'error' : 
                                    pattern.severity === 'MEDIUM' ? 'warn' : 'info';
                
                console[severityStyle](`[${pattern.severity}] ${pattern.warning}`);
                console.info(`  Conflicting rules: ${pattern.rules.join(', ')}`);
                console.info(`  Resolution strategy: ${pattern.resolution}`);
            }
        }
          if (conflicts.length === 0) {
            console.info('[OK] No rule conflicts detected - all rules can work independently');
        } else {
            console.warn(`[WARNING] ${conflicts.length} potential rule conflicts detected`);
            console.info('Rule coordination system will handle conflicts using cooperative processing or priority order');
        }
        
        console.groupEnd();
        
        // Log rule application summary
        this.logRuleApplicationSummary(applicableRules, conflicts);
    }

    /**
     * Log a summary of how rules will be applied
     */
    logRuleApplicationSummary(applicableRules, conflicts) {
        console.group('[Rule Engine] Rule Application Summary');
        
        const datasetRules = applicableRules.filter(r => r.rule.processDataset);
        const perVersionRules = applicableRules.filter(r => r.rule.process && !r.rule.processDataset);
          console.info(`[Dataset] Rules (${datasetRules.length}): ${datasetRules.map(r => r.rule.name).join(', ')}`);
        console.info(`[Per-Version] Rules (${perVersionRules.length}): ${perVersionRules.map(r => r.rule.name).join(', ')}`);
        
        if (conflicts.length > 0) {
            const cooperativeConflicts = conflicts.filter(c => c.resolution.includes('cooperative'));
            const priorityConflicts = conflicts.filter(c => c.resolution.includes('priority'));
            
            if (cooperativeConflicts.length > 0) {
                console.info(`[Cooperative] Processing: ${cooperativeConflicts.length} rule combinations`);
            }
            if (priorityConflicts.length > 0) {
                console.info(`[Priority] Order Processing: ${priorityConflicts.length} rule combinations`);
            }
        }
        
        console.groupEnd();
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
    }    /**
     * Process the entire dataset through dataset-level rules with cooperative processing
     */
    processDataset(cpeBase) {
        const datasetRules = this.getApplicableRules().filter(({rule}) => rule.processDataset);
        
        if (datasetRules.length === 0) {
            return null;
        }
        
        // Detect if we have multiple applicable dataset rules
        const ruleNames = datasetRules.map(r => r.rule.name);
        console.debug(`[Rule Engine] Found ${datasetRules.length} applicable dataset rules: ${ruleNames.join(', ')}`);
        
        // Define rule coordination strategies
        const cooperativeRules = this.getCooperativeRuleGroups(datasetRules);
        
        if (cooperativeRules.length > 0) {
            // Use cooperative processing for compatible rule combinations
            console.debug(`[Rule Engine] Using cooperative processing for rule groups`);
            return this.processCooperativeRules(cpeBase, cooperativeRules);
        } else {
            // Use single rule processing with enhanced priority
            console.debug(`[Rule Engine] Using single rule processing with priority order`);
            return this.processSingleDatasetRule(cpeBase, datasetRules);
        }
    }

    /**
     * Identify groups of rules that can work together cooperatively
     */
    getCooperativeRuleGroups(datasetRules) {
        const ruleIds = datasetRules.map(r => r.id);
        const cooperativeGroups = [];
        
        // Define compatible rule combinations that can work together
        const compatibleCombinations = [
            {
                name: 'Branch-Aware Mixed Status',
                rules: ['multipleBranches', 'mixedStatus'],
                strategy: 'branch_then_status',
                description: 'Process by branches first, then apply mixed status logic within each branch'
            },
            {
                name: 'Mixed Status with Gap Processing',
                rules: ['mixedStatus', 'gapProcessing'],
                strategy: 'status_then_gaps',
                description: 'Process mixed status first, then fill gaps between unaffected ranges'
            },
            {
                name: 'Inverse Status with Gap Processing',
                rules: ['inverseStatus', 'gapProcessing'],
                strategy: 'inverse_then_gaps',
                description: 'Process inverse status first, then fill gaps'
            }
        ];
        
        for (const combination of compatibleCombinations) {
            const hasAllRules = combination.rules.every(rule => ruleIds.includes(rule));
            if (hasAllRules) {
                const applicableRules = datasetRules.filter(r => combination.rules.includes(r.id));
                cooperativeGroups.push({
                    ...combination,
                    applicableRules
                });
                console.debug(`[Rule Engine] Found cooperative group: ${combination.name}`);
            }
        }
        
        return cooperativeGroups;
    }

    /**
     * Process multiple rules cooperatively using defined strategies
     */
    processCooperativeRules(cpeBase, cooperativeGroups) {
        // Use the first cooperative group found (could be enhanced to choose best match)
        const group = cooperativeGroups[0];
        console.debug(`[Rule Engine] Applying cooperative strategy: ${group.name} - ${group.description}`);
        
        switch (group.strategy) {
            case 'branch_then_status':
                return this.processBranchThenStatus(cpeBase, group.applicableRules);
            
            case 'status_then_gaps':
                return this.processStatusThenGaps(cpeBase, group.applicableRules);
            
            case 'inverse_then_gaps':
                return this.processInverseThenGaps(cpeBase, group.applicableRules);
            
            default:
                console.warn(`[Rule Engine] Unknown cooperative strategy: ${group.strategy}`);
                return this.processSingleDatasetRule(cpeBase, group.applicableRules);
        }
    }

    /**
     * Strategy: Process by branches first, then apply mixed status within each branch
     */
    processBranchThenStatus(cpeBase, rules) {
        const branchRule = rules.find(r => r.id === 'multipleBranches');
        const statusRule = rules.find(r => r.id === 'mixedStatus');
        
        if (!branchRule || !statusRule) {
            return this.processSingleDatasetRule(cpeBase, rules);
        }
        
        const matches = [];
        const branchMap = new Map();
        
        // Group versions by branch (from multipleBranches logic)
        this.versionData.versions.forEach(v => {
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
        
        console.debug(`[Rule Engine] Processing ${branchMap.size} branches with mixed status logic`);
        
        // Apply mixed status processing within each branch
        for (const [branch, versions] of branchMap) {
            const branchAffected = versions.filter(v => v.status === 'affected');
            const branchUnaffected = versions.filter(v => v.status === 'unaffected');
            
            console.debug(`[Rule Engine] Branch ${branch}: ${branchAffected.length} affected, ${branchUnaffected.length} unaffected`);
            
            // Process each version in this branch
            for (const versionInfo of versions) {
                const isVulnerable = versionInfo.status === "affected";
                const otherRulesResult = this.applyOtherRules(cpeBase, versionInfo, isVulnerable, ['multipleBranches', 'mixedStatus']);
                
                if (otherRulesResult.processed) {
                    matches.push(...otherRulesResult.matches);
                } else {
                    const cpeMatch = createCpeMatchFromVersionInfo(cpeBase, versionInfo, isVulnerable);
                    matches.push(cpeMatch);
                }
            }
        }
        
        this.appliedRules.add('multipleBranches');
        this.appliedRules.add('mixedStatus');
        return matches;
    }

    /**
     * Strategy: Process mixed status first, then apply gap processing
     */
    processStatusThenGaps(cpeBase, rules) {
        const statusRule = rules.find(r => r.id === 'mixedStatus');
        const gapRule = rules.find(r => r.id === 'gapProcessing');
        
        if (!statusRule || !gapRule) {
            return this.processSingleDatasetRule(cpeBase, rules);
        }
        
        // First apply mixed status processing
        const statusResult = statusRule.rule.processDataset(cpeBase, this.versionData, this.settings, this);
        const matches = statusResult.processed ? [...statusResult.matches] : [];
        
        if (statusResult.processed) {
            this.appliedRules.add('mixedStatus');
            console.debug(`[Rule Engine] Mixed status processing generated ${matches.length} matches`);
            
            // Then apply gap processing to fill any gaps
            const gapResult = gapRule.rule.processDataset(cpeBase, this.versionData, this.settings, this);
            if (gapResult.processed && gapResult.matches.length > 0) {
                matches.push(...gapResult.matches);
                this.appliedRules.add('gapProcessing');
                console.debug(`[Rule Engine] Gap processing added ${gapResult.matches.length} additional matches`);
            }
        }
        
        return matches.length > 0 ? matches : null;
    }

    /**
     * Strategy: Process inverse status first, then apply gap processing
     */
    processInverseThenGaps(cpeBase, rules) {
        const inverseRule = rules.find(r => r.id === 'inverseStatus');
        const gapRule = rules.find(r => r.id === 'gapProcessing');
        
        if (!inverseRule || !gapRule) {
            return this.processSingleDatasetRule(cpeBase, rules);
        }
        
        // First apply inverse status processing
        const inverseResult = inverseRule.rule.processDataset(cpeBase, this.versionData, this.settings, this);
        const matches = inverseResult.processed ? [...inverseResult.matches] : [];
        
        if (inverseResult.processed) {
            this.appliedRules.add('inverseStatus');
            console.debug(`[Rule Engine] Inverse status processing generated ${matches.length} matches`);
            
            // Then apply gap processing
            const gapResult = gapRule.rule.processDataset(cpeBase, this.versionData, this.settings, this);
            if (gapResult.processed && gapResult.matches.length > 0) {
                matches.push(...gapResult.matches);
                this.appliedRules.add('gapProcessing');
                console.debug(`[Rule Engine] Gap processing added ${gapResult.matches.length} additional matches`);
            }
        }
        
        return matches.length > 0 ? matches : null;
    }

    /**
     * Fallback: Process single dataset rule with priority order
     */
    processSingleDatasetRule(cpeBase, datasetRules) {
        const priorityOrder = ['multipleBranches', 'mixedStatus', 'inverseStatus', 'gapProcessing'];
        const orderedRules = [];
        
        // Add rules in priority order first
        for (const priorityRule of priorityOrder) {
            const found = datasetRules.find(({id}) => id === priorityRule);
            if (found) {
                orderedRules.push(found);
            }
        }
        
        // Add any remaining rules
        for (const rule of datasetRules) {
            if (!orderedRules.find(({id}) => id === rule.id)) {
                orderedRules.push(rule);
            }
        }
        
        console.debug(`[Rule Engine] Applying single dataset rule in priority order: ${orderedRules.map(r => r.rule.name).join(', ')}`);
        
        for (const {id, rule} of orderedRules) {
            console.debug(`[Rule Engine] Trying dataset rule: ${rule.name}`);
            const result = rule.processDataset(cpeBase, this.versionData, this.settings, this);
            
            if (result.processed) {
                this.appliedRules.add(id);
                console.debug(`[Rule Engine] Dataset rule '${rule.name}' successfully processed the dataset`);
                return result.matches;
            }
        }
        
        return null; // No dataset rules applied
    }/**
     * Main processing entry point
     */
    generateMatches(cpeBase) {
        const matches = [];
        
        // First, try dataset-level rules
        const datasetMatches = this.processDataset(cpeBase);
        if (datasetMatches) {
            matches.push(...datasetMatches);
            console.debug(`[Rule Engine] Dataset processing completed with ${datasetMatches.length} matches`);
            
            // Apply additional per-version rules that might modify the results
            console.debug(`[Rule Engine] Checking for additional per-version rules`);
            const additionalMatches = this.processAdditionalVersionRules(cpeBase, datasetMatches);
            if (additionalMatches.length > 0) {
                console.debug(`[Rule Engine] Applied additional per-version rules, adding ${additionalMatches.length} more matches`);
                matches.push(...additionalMatches);
            }
            
            // Deduplicate matches to prevent conflicts
            const deduplicatedMatches = this.deduplicateMatches(matches);
            if (deduplicatedMatches.length !== matches.length) {
                console.warn(`[Rule Engine] Removed ${matches.length - deduplicatedMatches.length} duplicate matches`);
            }
            
            return deduplicatedMatches;
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
        return this.deduplicateMatches(matches);
    }

    /**
     * Remove duplicate matches that could be caused by rule conflicts
     */
    deduplicateMatches(matches) {
        const seen = new Set();
        const deduplicated = [];
        
        for (const match of matches) {
            // Create a unique key for this match based on critical properties
            const key = JSON.stringify({
                criteria: match.criteria,
                vulnerable: match.vulnerable,
                versionStartIncluding: match.versionStartIncluding,
                versionStartExcluding: match.versionStartExcluding,
                versionEndIncluding: match.versionEndIncluding,
                versionEndExcluding: match.versionEndExcluding
            });
            
            if (!seen.has(key)) {
                seen.add(key);
                deduplicated.push(match);
            } else {
                console.debug(`[Rule Engine] Filtered duplicate match: ${key}`);
            }
        }
        
        return deduplicated;
    }    /**
     * Process additional per-version rules with enhanced coordination
     */
    processAdditionalVersionRules(cpeBase, existingMatches) {
        const additionalMatches = [];
        
        // Get per-version rules that should still be applied after dataset processing
        const perVersionRules = this.getApplicableRules().filter(({ id, rule }) => 
            !rule.processDataset && 
            rule.process && 
            !this.appliedRules.has(id)
        );
        
        if (perVersionRules.length === 0) {
            console.debug(`[Rule Engine] No additional per-version rules to apply`);
            return additionalMatches;
        }
        
        console.debug(`[Rule Engine] Found ${perVersionRules.length} additional per-version rules: ${perVersionRules.map(r => r.rule.name).join(', ')}`);
        
        // Enhanced version tracking with more detailed analysis
        const processedVersions = this.analyzeProcessedVersions(existingMatches);
        const versionCoverage = this.calculateVersionCoverage(existingMatches);
        
        console.debug(`[Rule Engine] Version coverage analysis: ${JSON.stringify(versionCoverage, null, 2)}`);
        
        // Apply per-version rules with intelligent filtering
        for (const versionInfo of this.versionData.versions) {
            if (!versionInfo || !versionInfo.version) continue;
            
            const versionKey = this.createVersionKey(versionInfo);
            const shouldProcessVersion = this.shouldProcessAdditionalVersion(versionInfo, processedVersions, versionCoverage);
            
            if (!shouldProcessVersion) {
                console.debug(`[Rule Engine] Skipping version ${versionInfo.version} - adequate coverage exists`);
                continue;
            }
            
            const isVulnerable = versionInfo.status === "affected";
            
            for (const { id, rule } of perVersionRules) {
                // Check if this rule is appropriate for this version
                if (!this.isRuleApplicableToVersion(rule, versionInfo)) {
                    continue;
                }
                
                const result = rule.process(cpeBase, versionInfo, isVulnerable, this);
                if (result.processed && result.matches.length > 0) {
                    console.debug(`[Rule Engine] Applied additional rule '${rule.name}' to version ${versionInfo.version}`);
                    
                    // Filter out matches that would duplicate existing coverage
                    const uniqueMatches = this.filterDuplicateMatches(result.matches, existingMatches, additionalMatches);
                    additionalMatches.push(...uniqueMatches);
                    
                    this.appliedRules.add(id);
                    processedVersions.add(versionKey);
                    break; // Only apply first matching rule per version to avoid conflicts
                }
            }
        }
        
        return additionalMatches;
    }

    /**
     * Analyze which versions have been processed by dataset rules
     */
    analyzeProcessedVersions(existingMatches) {
        const processedVersions = new Set();
        
        for (const match of existingMatches) {
            // Extract all version identifiers from the match
            if (match.versionStartIncluding) {
                processedVersions.add(this.normalizeVersion(match.versionStartIncluding));
            }
            if (match.versionEndIncluding) {
                processedVersions.add(this.normalizeVersion(match.versionEndIncluding));
            }
            if (match.versionStartExcluding) {
                processedVersions.add(this.normalizeVersion(match.versionStartExcluding));
            }
            if (match.versionEndExcluding) {
                processedVersions.add(this.normalizeVersion(match.versionEndExcluding));
            }
            
            // Extract version from CPE criteria if present
            if (match.criteria) {
                const cpeVersion = match.criteria.split(':')[5];
                if (cpeVersion && cpeVersion !== '*') {
                    processedVersions.add(this.normalizeVersion(cpeVersion));
                }
            }
        }
        
        return processedVersions;
    }

    /**
     * Calculate what percentage of versions are covered by existing matches
     */
    calculateVersionCoverage(existingMatches) {
        const totalVersions = this.versionData.versions.length;
        const coveredVersions = new Set();
        const rangeMatches = [];
        const exactMatches = [];
        
        for (const match of existingMatches) {
            if (match.versionStartIncluding || match.versionStartExcluding || 
                match.versionEndIncluding || match.versionEndExcluding) {
                rangeMatches.push(match);
            } else {
                // Exact version match
                const cpeVersion = match.criteria?.split(':')[5];
                if (cpeVersion && cpeVersion !== '*') {
                    exactMatches.push(cpeVersion);
                    coveredVersions.add(this.normalizeVersion(cpeVersion));
                }
            }
        }
        
        // For range matches, estimate coverage by checking if versions fall within ranges
        for (const version of this.versionData.versions) {
            if (version && version.version) {
                const normalizedVersion = this.normalizeVersion(version.version);
                
                for (const rangeMatch of rangeMatches) {
                    if (this.isVersionInRange(normalizedVersion, rangeMatch)) {
                        coveredVersions.add(normalizedVersion);
                        break;
                    }
                }
            }
        }
        
        return {
            totalVersions,
            coveredVersions: coveredVersions.size,
            coveragePercentage: (coveredVersions.size / totalVersions) * 100,
            rangeMatches: rangeMatches.length,
            exactMatches: exactMatches.length,
            uncoveredVersions: totalVersions - coveredVersions.size
        };
    }

    /**
     * Determine if a version should be processed by additional rules
     */
    shouldProcessAdditionalVersion(versionInfo, processedVersions, versionCoverage) {
        const versionKey = this.createVersionKey(versionInfo);
        
        // Always skip if this exact version was already processed
        if (processedVersions.has(this.normalizeVersion(versionInfo.version))) {
            return false;
        }
        
        // Apply additional rules if coverage is low (less than 80%)
        if (versionCoverage.coveragePercentage < 80) {
            return true;
        }
        
        // Apply additional rules for special version types that might need specific handling
        if (versionInfo.versionType && !['semver', 'string'].includes(versionInfo.versionType)) {
            return true;
        }
        
        // Apply additional rules for versions with complex patterns
        if (this.hasComplexVersionPattern(versionInfo.version)) {
            return true;
        }
        
        return false;
    }

    /**
     * Check if a per-version rule is applicable to a specific version
     */
    isRuleApplicableToVersion(rule, versionInfo) {
        // Create a minimal version data context for the shouldApply check
        const versionContext = {
            versions: [versionInfo]
        };
        
        try {
            return rule.shouldApply(versionContext, this.settings);
        } catch (error) {
            console.warn(`[Rule Engine] Error checking rule applicability for ${rule.name}: ${error.message}`);
            return false;
        }
    }

    /**
     * Filter out matches that would duplicate existing coverage
     */
    filterDuplicateMatches(newMatches, existingMatches, additionalMatches) {
        const allMatches = [...existingMatches, ...additionalMatches];
        const uniqueMatches = [];
        
        for (const newMatch of newMatches) {
            let isDuplicate = false;
            
            for (const existingMatch of allMatches) {
                if (this.areMatchesEquivalent(newMatch, existingMatch)) {
                    isDuplicate = true;
                    break;
                }
            }
            
            if (!isDuplicate) {
                uniqueMatches.push(newMatch);
            } else {
                console.debug(`[Rule Engine] Filtered duplicate match for ${newMatch.criteria}`);
            }
        }
        
        return uniqueMatches;
    }

    /**
     * Helper methods for version analysis
     */
    createVersionKey(versionInfo) {
        return `${versionInfo.version || 'unknown'}_${versionInfo.status || 'unknown'}_${versionInfo.versionType || 'default'}`;
    }

    normalizeVersion(version) {
        return String(version).toLowerCase().trim();
    }

    hasComplexVersionPattern(version) {
        if (!version) return false;
        
        const complexPatterns = [
            /\*/,                    // Wildcards
            /[a-zA-Z]/,             // Contains letters (alpha, beta, etc.)
            /\s+/,                  // Contains spaces
            /-[a-zA-Z]/,            // Dash followed by letters
            /\+/                    // Plus signs
        ];
        
        return complexPatterns.some(pattern => pattern.test(version));
    }

    isVersionInRange(version, rangeMatch) {
        // Simplified range checking - would need more sophisticated version comparison in practice
        try {
            if (rangeMatch.versionStartIncluding && version < rangeMatch.versionStartIncluding) {
                return false;
            }
            if (rangeMatch.versionStartExcluding && version <= rangeMatch.versionStartExcluding) {
                return false;
            }
            if (rangeMatch.versionEndIncluding && version > rangeMatch.versionEndIncluding) {
                return false;
            }
            if (rangeMatch.versionEndExcluding && version >= rangeMatch.versionEndExcluding) {
                return false;
            }
            return true;
        } catch (error) {
            return false;
        }
    }

    areMatchesEquivalent(match1, match2) {
        return JSON.stringify(this.normalizeMatchForComparison(match1)) === 
               JSON.stringify(this.normalizeMatchForComparison(match2));
    }

    normalizeMatchForComparison(match) {
        return {
            criteria: match.criteria,
            vulnerable: match.vulnerable,
            versionStartIncluding: match.versionStartIncluding,
            versionStartExcluding: match.versionStartExcluding,
            versionEndIncluding: match.versionEndIncluding,
            versionEndExcluding: match.versionEndExcluding
        };
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
