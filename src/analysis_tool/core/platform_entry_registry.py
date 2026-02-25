#!/usr/bin/env python3
"""
Registry and Data Collection System for NVD-ish Pipeline
=========================================================

This module provides registry-based data collection for the Analysis Tools NVD-ish pipeline.
It handles:

1. Platform entry notification registry (PENR) for data transfer between processing stages
2. Placeholder value detection and constants
3. Source data concern (SDC) detection and analysis
4. Alias extraction for curator functionality
5. Update pattern detection and transformation
6. CPE-AS generation support functions

The registry pattern enables data collection during CVE processing that is later consumed
by nvd_ish_collector for integration into enhanced NVD-ish JSON records.

HTML generation code removed in v0.1.1 - this module now focuses solely on data collection.
"""
from typing import Dict, List, Tuple, Optional, Any
import html  # For html.escape() in analyze_version_characteristics
import json
import re
from ..logging.workflow_logger import get_logger

# Get logger instance
logger = get_logger()

# ===== GLOBAL REGISTRIES =====

# Platform Entry Notification registry (keyed by table index/row)
# Core data bridge between processing stages and nvd-ish collector
PLATFORM_ENTRY_NOTIFICATION_REGISTRY = {
    'wildcardGeneration': {},  # table_index -> wildcard transformation data
    'updatePatterns': {},      # table_index -> update pattern data
    'sourceDataConcerns': {},   # table_index -> source data quality concerns
    'aliasExtraction': {},     # table_index -> alias extraction data for curator functionality
    'confirmedMappings': {},   # table_index -> confirmed mapping data for nvd-ish integration
    'cpeBaseStringSearches': {}, # table_index -> CPE match strings searched data for nvd-ish collector
    'cpeMatchStringsCulled': {}, # table_index -> CPE match strings culled data for nvd-ish collector
    'top10CPESuggestions': {}  # table_index -> top 10 CPE suggestions data for nvd-ish collector
}

# ===== CONSTANTS AND PATTERNS =====
# Define placeholder values for non-version fields (vendor, product, platforms, packageName)
GENERAL_PLACEHOLDER_VALUES = [
    'unspecified', 'unknown', 'none', 'undefined', 'various',
    'n/a', 'not available', 'not applicable', 'unavailable',
    'na', 'nil', 'tbd', 'to be determined', 'pending',
    'not specified', 'not determined', 'not known', 'not listed',
    'not provided', 'missing', 'empty', 'null', '-',
    'see references', 'see advisory', 'check', 'noted', 'all',
    'all platforms', 'contact vendor', 'check with vendor'
]

# Define placeholder values specific to version fields (version, lessThan, changes.at)
VERSION_PLACEHOLDER_VALUES = [
    'unspecified', 'unknown', 'none', 'undefined', 'various',
    'n/a', 'not available', 'not applicable', 'unavailable',
    'na', 'nil', 'tbd', 'to be determined', 'pending',
    'not specified', 'not determined', 'not known', 'not listed',
    'not provided', 'missing', 'empty', 'null', '-', 'multiple versions',
    'see references', 'see advisory', 'check', 'noted', 'all'
    # Note: 'all' included per requirements - observed in real CVE data as wildcard indicator
    # Note: "0" is NOT a placeholder - treated as literal version value
]

# Define comparator patterns used for detecting comparison operators in data fields
COMPARATOR_PATTERNS = ['<', '>', '=', '<=', '=<', '=>', '>=', '!=']

# Define text based range patterns for version field(s) 
# Text comparator patterns organized by type for backend categorization
TEXT_COMPARATOR_PATTERNS = {
    'Upper Bound Comparators': ['prior to', 'earlier than', 'before', 'until', 'below', 'up to'],
    'Lower Bound Comparators': ['later than', 'newer than', 'after', 'since', 'from', 'above'],
    'Range Separators': ['through', 'thru', 'between', 'and', 'to'],
    'Approximation Patterns': ['about', 'approximately', 'circa', 'around', 'roughly'],
    'Inclusive/Exclusive Indicators': ['inclusive', 'exclusive', 'including', 'excluding'],
    'Temporal/Status Indicators': ['earliest', 'recent', 'legacy', 'past', 'future', 'latest', 'current']
}

# Flattened list for backward compatibility with existing detection logic
ALL_TEXT_COMPARATOR_PATTERNS = []
for pattern_type, patterns in TEXT_COMPARATOR_PATTERNS.items():
    ALL_TEXT_COMPARATOR_PATTERNS.extend(patterns)

# Regex patterns for detecting version range formats
TEXT_COMPARATOR_REGEX_PATTERNS = [
    {
        'pattern': re.compile(r'\d+(?:\.\d+)*\s+-\s+\d+(?:\.\d+)*', re.IGNORECASE),
        'patternType': 'Hyphenated Version Range'
    }
]

# All versions terms that should be represented as "*"
ALL_VERSION_VALUES = [
    'all versions', 'all', 'all version', 'any version', 'any versions', 'any'
]

# Bloat terms that should be removed from version fields
BLOAT_TEXT_VALUES = [
    'version', 'versions', 'ver'
]

# ===== UTILITY FUNCTIONS FOR CPE-AS GENERATION =====

def determine_vulnerability_from_status(status: str) -> bool:
    """
    Centralized vulnerability determination logic for CPE Applicability Statements.
    
    Args:
        status: Status value from CVE 5.0 data ('affected', 'unaffected', 'unknown')
    
    Returns:
        Boolean indicating vulnerability status (True if affected, False otherwise)
    
    Examples:
        >>> determine_vulnerability_from_status('affected')
        True
        >>> determine_vulnerability_from_status('unaffected')
        False
        >>> determine_vulnerability_from_status('unknown')
        False
    """
    return status == 'affected'

# ===== REGISTRY MANAGEMENT FUNCTIONS =====

def clear_all_registries():
    """Clear all data registries for new processing run"""
    global PLATFORM_ENTRY_NOTIFICATION_REGISTRY
    
    PLATFORM_ENTRY_NOTIFICATION_REGISTRY = {
        'wildcardGeneration': {},
        'updatePatterns': {},
        'sourceDataConcerns': {},
        'aliasExtraction': {},
        'confirmedMappings': {},
        'cpeBaseStringSearches': {},
        'cpeMatchStringsCulled': {},
        'top10CPESuggestions': {}
    }

def register_platform_notification_data(table_index: int, data_type: str, data: Dict) -> bool:
    """
    Register platform entry notification data for a specific table row.
    
    Args:
        table_index: The table/row index
        data_type: The type of data ('wildcardGeneration', 'updatePatterns', 'jsonGenerationRules', 'supportingInformation')
        data: The data to store
    
    Returns:
        bool: True if data was newly registered, False if already existed
    """
    global PLATFORM_ENTRY_NOTIFICATION_REGISTRY
    
    # Ensure the data_type key exists
    if data_type not in PLATFORM_ENTRY_NOTIFICATION_REGISTRY:
        PLATFORM_ENTRY_NOTIFICATION_REGISTRY[data_type] = {}
    
    # Check if this table data is already registered
    if table_index in PLATFORM_ENTRY_NOTIFICATION_REGISTRY[data_type]:
        return False  # Already registered
    
    # CRITICAL: Do NOT skip registration for identical data with different table indices
    PLATFORM_ENTRY_NOTIFICATION_REGISTRY[data_type][table_index] = data
    
    return True  # Newly registered

# ===== TEMPLATE DEDUPLICATION SYSTEM =====

def analyze_wildcard_generation(raw_platform_data: Dict) -> Dict:
    """
    Analyze wildcard generation patterns to mirror JavaScript wildcardExpansion rule logic.
    Returns information about wildcard transformations and version ranges.
    """
    wildcard_info = {
        'has_wildcards': False,
        'wildcard_transformations': []
    }
    
    if not raw_platform_data or 'versions' not in raw_platform_data:
        return wildcard_info
    
    versions = raw_platform_data.get('versions', [])
    if not isinstance(versions, list):
        return wildcard_info
    
    # Process each version to detect wildcard patterns
    for version in versions:
        if not isinstance(version, dict):
            continue
        
        # Check version field for wildcards
        if 'version' in version and isinstance(version['version'], str) and '*' in version['version']:
            wildcard_info['has_wildcards'] = True
            transformation = analyze_wildcard_transformation(version['version'], 'version')
            if transformation:
                wildcard_info['wildcard_transformations'].append(transformation)
        
        # Check lessThanOrEqual field for wildcards
        if 'lessThanOrEqual' in version and isinstance(version['lessThanOrEqual'], str) and '*' in version['lessThanOrEqual']:
            wildcard_info['has_wildcards'] = True
            transformation = analyze_wildcard_transformation(version['lessThanOrEqual'], 'lessThanOrEqual')
            if transformation:
                wildcard_info['wildcard_transformations'].append(transformation)
        
        # Check lessThan field for wildcards
        if 'lessThan' in version and isinstance(version['lessThan'], str) and '*' in version['lessThan']:
            wildcard_info['has_wildcards'] = True
            transformation = analyze_wildcard_transformation(version['lessThan'], 'lessThan')
            if transformation:
                wildcard_info['wildcard_transformations'].append(transformation)
    
    return wildcard_info

def analyze_wildcard_transformation(version_str: str, field: str) -> Optional[Dict]:
    """
    Analyze a single wildcard pattern and return transformation information.
    
    Args:
        version_str: The version string containing wildcards
        field: The field name ('version', 'lessThan', 'lessThanOrEqual')
    
    Returns:
        Dict with transformation details or None if no valid transformation
    """
    if not version_str or '*' not in version_str:
        return None
    
    if version_str == "*":
        # Global wildcard transformation
        return {
            'field': field,
            'original': version_str,
            'start_version': '0',
            'end_version': '∞',
            'type': 'global_wildcard'
        }
    
    # Specific wildcard pattern (e.g., "5.4.*", "2.1.0.*")
    if version_str.endswith('*'):
        base_pattern = version_str.rstrip('*').rstrip('.')
        
        # Parse the base version to determine range
        if '.' in base_pattern:
            parts = base_pattern.split('.')
            
            # Handle different wildcard levels
            if len(parts) == 2:  # e.g., "5.4.*"
                major, minor = parts
                start_version = f"{major}.{minor}.0"
                try:
                    next_minor = str(int(minor) + 1)
                    end_version = f"{major}.{next_minor}.0"
                except ValueError:
                    # Handle non-numeric version components like "0-beta"
                    end_version = f"{major}.{minor}.∞"
            elif len(parts) == 3:  # e.g., "5.4.3.*"
                major, minor, patch = parts
                start_version = f"{major}.{minor}.{patch}.0"
                try:
                    next_patch = str(int(patch) + 1)
                    end_version = f"{major}.{minor}.{next_patch}.0"
                except ValueError:
                    # Handle non-numeric version components like "0-beta"
                    end_version = f"{major}.{minor}.{patch}.∞"
            else:
                # Complex patterns - fail with clear error rather than guessing
                raise ValueError(f"Unsupported complex wildcard pattern: {base_pattern}")
        else:
            # Single component wildcard (e.g., "5.*")
            start_version = base_pattern + ".0.0"
            try:
                next_major = str(int(base_pattern) + 1)
                end_version = f"{next_major}.0.0"
            except ValueError:
                # Handle non-numeric version components
                end_version = f"{base_pattern}.∞"
        
        return {
            'field': field,
            'original': version_str,
            'start_version': start_version,
            'end_version': end_version,
            'type': 'specific_wildcard'
        }
    
    return None

# ===== VERSION ANALYSIS FUNCTIONS =====

def analyze_version_characteristics(raw_platform_data):
    """Centralized analysis of version data characteristics - SINGLE SOURCE OF TRUTH"""
    if not raw_platform_data or not isinstance(raw_platform_data, dict):
        return {
            'has_wildcards': False,
            'has_version_changes': False,
            'has_special_version_types': False,
            'has_git_version_type': False,
            'has_inverse_status': False,
            'has_multiple_branches': False,
            'has_mixed_status': False,
            'needs_infer_affected_ranges': False,
            'has_update_patterns': False,  
            'wildcard_patterns': [],
            'special_version_types': [],
            'version_families': set(),
            'status_types': set()
        }
    
    versions = raw_platform_data.get('versions', [])
    if not isinstance(versions, list):
        return {}
    
    characteristics = {
        'has_wildcards': False,
        'has_version_changes': False,
        'has_special_version_types': False,
        'has_git_version_type': False,
        'has_inverse_status': False,
        'has_multiple_branches': False,
        'has_mixed_status': False,
        'needs_infer_affected_ranges': False,
        'has_update_patterns': False, 
        'wildcard_patterns': [],
        'special_version_types': [],
        'version_families': set(),
        'status_types': set(),
        'update_patterns': []
    }
    
    # Track patterns for settings analysis only
    processed_update_patterns = set()  # Track update patterns for settings
    
    for version in versions:
        if not isinstance(version, dict):
            continue
        
        # === WILDCARD DETECTION ===
        for field in ['version', 'lessThan', 'lessThanOrEqual']:
            if field in version and isinstance(version[field], str) and '*' in version[field]:
                characteristics['has_wildcards'] = True
                characteristics['wildcard_patterns'].append(f"{field}: {version[field]}")
        
        # === VERSION CHANGES DETECTION ===
        if version.get('changes'):
            characteristics['has_version_changes'] = True
        
        # === VERSION TYPE DETECTION ===
        version_type = version.get('versionType')
        if version_type and version_type not in ['semver', 'string', None]:
            characteristics['has_special_version_types'] = True
            characteristics['special_version_types'].append(version_type)
            if version_type == 'git':
                characteristics['has_git_version_type'] = True
        
        # === STATUS COLLECTION ===
        if 'status' in version and version['status']:
            characteristics['status_types'].add(version['status'])
        
        # === VERSION FAMILY EXTRACTION ===
        for field in ['version', 'lessThan', 'lessThanOrEqual']:
            if field in version and isinstance(version[field], str):
                version_str = version[field]
                if version_str and version_str != '*':
                    match = re.match(r'^(\d+)', version_str)
                    if match:
                        characteristics['version_families'].add(match.group(1))
                        break
        
        # Update pattern detection for settings analysis (using proper pattern matching)
        for field in ['version', 'lessThan', 'lessThanOrEqual']:
            if field not in version:
                continue
                
            field_value = version[field]
            
            # Skip None, empty, or non-processable values
            if field_value is None:
                continue
            
            # Handle string values for update pattern detection
            if isinstance(field_value, str):
                # Skip empty strings
                if not field_value.strip():
                    continue
                
                # Extract all transformation patterns from the update_patterns list using the helper function
                # This ensures we use the same comprehensive patterns for detection as for transformation
                update_patterns, kb_exclusion_patterns = get_update_patterns()
                update_pattern_regexes = []
                for pattern_dict in update_patterns:
                    if 'pattern' in pattern_dict:
                        try:
                            compiled_pattern = re.compile(pattern_dict['pattern'], re.IGNORECASE)
                            update_pattern_regexes.append(compiled_pattern)
                        except re.error:
                            # Skip invalid regex patterns
                            continue
                
                has_update_pattern = any(pattern.match(field_value) for pattern in update_pattern_regexes)
                
                # Set flag for settings analysis
                if has_update_pattern:
                    characteristics['has_update_patterns'] = True
                    
                    # Use the transformation function to get the actual transformation for settings tracking
                    base_version, update_component, transformed_version = transform_version_with_update_pattern(field_value)
                    
                    if base_version and update_component and transformed_version:
                        # Show the actual transformation (before → after) for settings tracking
                        update_info = f"Update pattern for {field}: {field_value} → {transformed_version}"
                        processed_update_patterns.add(html.escape(update_info))
                    else:
                        # Soft failure: Log warning and skip this transformation
                        # This happens when regex patterns incorrectly match firmware identifiers, etc.
                        logger.warning(f"Update pattern matched but transformation failed for {field}={field_value}. Skipping transformation for this field.", group="DATA_PROC")
                        
                        # Add a descriptive info for settings tracking
                        update_info = f"Unprocessable update pattern in {field}: {field_value} (transformation skipped)"
                        processed_update_patterns.add(html.escape(update_info))
    
    
    # === ASSIGN COLLECTED DATA TO CHARACTERISTICS ===
    # Update patterns tracking for settings analysis
    characteristics['update_patterns'] = list(processed_update_patterns)
    
    # === DERIVED CHARACTERISTICS ===
    characteristics['has_inverse_status'] = raw_platform_data.get('defaultStatus') == 'unaffected'
    characteristics['has_multiple_branches'] = len(characteristics['version_families']) >= 3
    characteristics['has_mixed_status'] = (
        len(characteristics['status_types']) > 1 and 
        'affected' in characteristics['status_types'] and 
        'unaffected' in characteristics['status_types']
    )
    
    # Gap processing logic
    has_ranges = any(v and isinstance(v, dict) and ('lessThan' in v or 'lessThanOrEqual' in v) for v in versions)
    has_exact_versions = any(v and isinstance(v, dict) and 'version' in v and v['version'] and v['version'] != '*' for v in versions)
    characteristics['needs_gap_processing'] = (has_ranges and has_exact_versions) or characteristics['has_wildcards']
    
    return characteristics

def has_update_related_content(raw_platform_data):
    """Check if rawPlatformData contains update-related content that can be extracted by JavaScript"""
    if not raw_platform_data or 'versions' not in raw_platform_data:
        return False
    
    versions = raw_platform_data.get('versions', [])
    if not isinstance(versions, list):
        return False
    
    # Check for update patterns using the existing transform function
    for version in versions:
        if not isinstance(version, dict):
            continue
            
        fields_to_check = [
            version.get('version', ''),
            version.get('lessThan', ''),
            version.get('lessThanOrEqual', '')
        ]
        
        for field_value in fields_to_check:
            if field_value and isinstance(field_value, str):
                base_version, update_component, _ = transform_version_with_update_pattern(field_value)
                if base_version and update_component:
                    return True
    
    return False

# ===== UPDATE PATTERN ANALYSIS FUNCTIONS =====

def get_update_patterns():
    """
    Get the comprehensive list of update transformation patterns.
    
    Returns a tuple of (update_patterns, kb_exclusion_patterns) where update_patterns is a list
    of pattern dictionaries used for version string transformation.
    
    CRITICAL PATTERN ORDERING REQUIREMENTS:
    ========================================
    Pattern matching uses FIRST-MATCH semantics - the function returns as soon as a pattern matches.
    
    1. NUMBERED PATTERNS MUST COME BEFORE NUMBERLESS PATTERNS
       - Numbered: '^(.+?)\\s+beta\\s*(\\d+)$' matches "2.0.0 beta 1" → base="2.0.0", update="beta1"
       - Numberless: '^(.+?)\\s+beta$' matches "2.0.0 beta" → base="2.0.0", update="beta"
       - If numberless comes first, it will incorrectly match "2.0.0 beta 1" as base="2.0.0 beta", update=""
    
    2. SPECIFIC PATTERNS BEFORE GENERAL PATTERNS
       - More specific patterns (e.g., "cumulative update") must precede general patterns (e.g., "update")
       - This prevents "14.0.0 cu 5" from matching as "update" instead of "cu"
    
    3. PRERELEASE PATTERN GROUPS (beta, alpha, rc) HAVE BOTH NUMBERED AND NUMBERLESS VARIANTS
       - Numbered patterns handle: "2.0.0-beta.1", "2.0.0 beta 1", "2.0.0_beta_1"
       - Numberless patterns handle: "2.0.0-beta", "2.0.0 beta", "2.0.0_beta"
       - All separator types supported: dash (-), dot (.), underscore (_), space ( )
       - Numberless patterns are common in package managers (npm, cargo, PyPI, etc.)
    
    4. OTHER PATTERN GROUPS TYPICALLY ONLY HAVE NUMBERED VARIANTS
       - Patch, hotfix, update, etc. are rarely used without numeric components
       - Having different pattern counts per group is intentional and reflects real-world usage
    
    This function ensures consistency between detection (transform_version_with_update_pattern)
    and transformation logic across Python and JavaScript implementations.
    """
    # KB EXCLUSION PATTERNS - These patterns detect KB references and exclude them
    # KB patterns are documentation references, not version patterns
    kb_exclusion_patterns = [
        r'(?i)^.*?kb\d+.*?$',                    # Basic KB pattern (case insensitive)
        r'(?i)^.*?KB\d+.*?$',                    # Uppercase KB pattern  
        r'(?i)^.*?[\.\-_]kb[\.\-_]?\d+.*?$',     # KB with separators
        r'(?i)^.*?\s+kb\s*\d+.*?$',              # KB with spaces
        r'(?i)^.*?\s+KB\s*\d+.*?$',              # Uppercase KB with spaces
        r'(?i)^.*?[\.\-_]+kb\d+.*?$',            # KB with prefix separators
        r'(?i)^.*?kb[\.\-_]+\d+.*?$',            # KB with suffix separators
        r'(?i)^.*?[\.\-_]kb[\.\-_]\d+.*?$'       # KB with surrounding separators
    ]
    
    # Check for KB exclusion patterns first
    for kb_pattern in kb_exclusion_patterns:
        if re.match(kb_pattern, str(''), re.IGNORECASE):  # This will be checked per string later
            pass  # This is just for pattern definition
    
    update_patterns = [
        
        # ===== PATCH TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+p\s*(\d+)$', 'type': 'patch'},  # Handle "3.0.0 p1"
        {'pattern': r'^(.+?)\s+patch\s*(\d+)$', 'type': 'patch'},  # Handle "3.3 patch 1"
        {'pattern': r'^(.+?)\s+Patch\s*(\d+)$', 'type': 'patch'},  # Handle "3.3 Patch 1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])p(\d+)$', 'type': 'patch'},  # Handle "2.3.0p12"
        
        # 3. Specific notation patterns
        {'pattern': r'^(.+?)\.p(\d+)$', 'type': 'patch'},  # Handle "3.1.0.p7"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_patch_(\d+)$', 'type': 'patch'},  # Handle "2.0.0_patch_5"
        {'pattern': r'^(.+?)-patch-(\d+)$', 'type': 'patch'},  # Handle "2.0.0-patch-5"
        {'pattern': r'^(.+?)\.patch\.(\d+)$', 'type': 'patch'},  # Handle "2.0.0.patch.5"
        {'pattern': r'^(.+?)_p_(\d+)$', 'type': 'patch'},  # Handle "2.0.0_p_5"
        
        
        # ===== SERVICE_PACK TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+sp\s*(\d+)$', 'type': 'sp'},  # Handle "2.0.0 sp1"
        {'pattern': r'^(.+?)\s+service\s+pack\s*(\d+)$', 'type': 'sp'},  # Handle "2.0.0 service pack 1"
        {'pattern': r'^(.+?)\s+Service\s+Pack\s*(\d+)$', 'type': 'sp'},  # Handle "2.0.0 Service Pack 1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])sp(\d+)$', 'type': 'sp'},  # Handle "1sp1"
        
        # 3. Specific notation patterns
        {'pattern': r'^(.+?)\.sp(\d+)$', 'type': 'sp'},  # Handle "3.0.0.sp1"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_sp_(\d+)$', 'type': 'sp'},  # Handle "13.0.0_sp_4"
        {'pattern': r'^(.+?)-sp-(\d+)$', 'type': 'sp'},  # Handle "13.0.0-sp-4"
        {'pattern': r'^(.+?)\.sp\.(\d+)$', 'type': 'sp'},  # Handle "13.0.0.sp.4"
        {'pattern': r'^(.+?)_service_pack_(\d+)$', 'type': 'sp'},  # Handle "4.0.0_service_pack_3"
        
        
        # ===== APPLICATION_PACK TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+ap\s*(\d+)$', 'type': 'ap'},  # Handle "24.0 ap375672"
        {'pattern': r'^(.+?)\s+application\s+pack\s*(\d+)$', 'type': 'ap'},  # Handle "24.0 application pack 375672"
        {'pattern': r'^(.+?)\s+Application\s+Pack\s*(\d+)$', 'type': 'ap'},  # Handle "24.0 Application Pack 375672"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])ap(\d+)$', 'type': 'ap'},  # Handle "1ap3"
        
        # 3. Specific notation patterns
        {'pattern': r'^(.+?)\.ap(\d+)$', 'type': 'ap'},  # Handle "24.0.ap375672"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_ap_(\d+)$', 'type': 'ap'},  # Handle "15.0.0_ap_6"
        {'pattern': r'^(.+?)-ap-(\d+)$', 'type': 'ap'},  # Handle "15.0.0-ap-6"
        {'pattern': r'^(.+?)\.ap\.(\d+)$', 'type': 'ap'},  # Handle "15.0.0.ap.6"
        {'pattern': r'^(.+?)_application_pack_(\d+)$', 'type': 'ap'},  # Handle "4.0.0_application_pack_3"
        
        
        # ===== HOTFIX TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+hotfix\s*(\d+)$', 'type': 'hotfix'},  # Handle "3.0.0 hotfix 1"
        {'pattern': r'^(.+?)\s+Hotfix\s*(\d+)$', 'type': 'hotfix'},  # Handle "3.0.0 Hotfix 1"
        {'pattern': r'^(.+?)\s+hf\s*(\d+)$', 'type': 'hotfix'},  # Handle "3.0.0 hf1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])hotfix(\d+)$', 'type': 'hotfix'},  # Handle "1.0.0hotfix1"
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])hf(\d+)$', 'type': 'hotfix'},  # Handle "1.0.0hf1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-hotfix\.(\d+)$', 'type': 'hotfix'},  # Handle "2.1.0-hotfix.2"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_hotfix_(\d+)$', 'type': 'hotfix'},  # Handle "4.0.0_hotfix_3"
        {'pattern': r'^(.+?)-hotfix-(\d+)$', 'type': 'hotfix'},  # Handle "4.0.0-hotfix-3"
        {'pattern': r'^(.+?)_hf_(\d+)$', 'type': 'hotfix'},  # Handle "5.0.0_hf_2"
        
        
        # ===== CUMULATIVE UPDATE TERM GROUP =====
        # 1. Space-separated patterns (MUST come before general update patterns)
        {'pattern': r'^(.+?)\s+cu\s*(\d+)$', 'type': 'cu'},  # Handle "14.0.0 cu 5"
        {'pattern': r'^(.+?)\s+cumulative\s+update\s*(\d+)$', 'type': 'cu'},  # Handle "8.0.0 cumulative update 1" → standardized to cu
        {'pattern': r'^(.+?)\s+Cumulative\s+Update\s*(\d+)$', 'type': 'cu'},  # Handle "8.0.0 Cumulative Update 1" → standardized to cu
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])cu(\d+)$', 'type': 'cu'},  # Handle "1.0.0cu1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-cu\.(\d+)$', 'type': 'cu'},  # Handle "2.1.0-cu.2"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)[\.\-_]*cu[\.\-_]*(\d+)[\.\-_]*$', 'type': 'cu'},  # Handle "14.0.0-cu-5"
        {'pattern': r'^(.+?)[\.\-_]*cumulative[\s\-_]+update[\.\-_]*(\d+)[\.\-_]*$', 'type': 'cu'},  # Handle flexible → standardized to cu
        {'pattern': r'^(.+?)-cumulative-update-(\d+)$', 'type': 'cu'},  # Handle "4.0.0-cumulative-update-3" → standardized to cu
        {'pattern': r'^(.+?)_cumulative_update_(\d+)$', 'type': 'cu'},  # Handle "4.0.0_cumulative_update_3" → standardized to cu
        
        
        # ===== UPDATE TERM GROUP (general - must come after specific patterns) =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+update\s*(\d+)$', 'type': 'update'},  # Handle "3.0.0 update 1"
        {'pattern': r'^(.+?)\s+Update\s*(\d+)$', 'type': 'update'},  # Handle "3.0.0 Update 1"
        {'pattern': r'^(.+?)\s+upd\s*(\d+)$', 'type': 'update'},  # Handle "3.0.0 upd1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])update(\d+)$', 'type': 'update'},  # Handle "4.0.0update1"
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])upd(\d+)$', 'type': 'update'},  # Handle "4.0.0upd1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-upd\.(\d+)$', 'type': 'update'},  # Handle "7.0.0-upd.4"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_update_(\d+)$', 'type': 'update'},  # Handle "5.0.0_update_2"
        {'pattern': r'^(.+?)-update-(\d+)$', 'type': 'update'},  # Handle "5.0.0-update-2"
        {'pattern': r'^(.+?)_upd_(\d+)$', 'type': 'update'},  # Handle "6.0.0_upd_3"
        
        
        # ===== BETA TERM GROUP =====
        # 1. Space-separated patterns (numbered - must come before numberless)
        {'pattern': r'^(.+?)\s+beta\s*(\d+)$', 'type': 'beta'},  # Handle "1.0.0 beta 1"
        {'pattern': r'^(.+?)\s+Beta\s*(\d+)$', 'type': 'beta'},  # Handle "1.0.0 Beta 1"
        {'pattern': r'^(.+?)\s+b\s*(\d+)$', 'type': 'beta'},  # Handle "1.0.0 b1"
        
        # 2. Direct concatenation patterns (numbered)
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])beta(\d+)$', 'type': 'beta'},  # Handle "4.0.0beta1"
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])b(\d+)$', 'type': 'beta'},  # Handle "4.0.0b1"
        
        # 3. Dash-dot notation patterns (numbered)
        {'pattern': r'^(.+?)-beta\.(\d+)$', 'type': 'beta'},  # Handle "1.0.0-beta.1"
        
        # 4. Flexible separator patterns (numbered)
        {'pattern': r'^(.+?)_beta_(\d+)$', 'type': 'beta'},  # Handle "1.0.0_beta_1"
        {'pattern': r'^(.+?)-beta-(\d+)$', 'type': 'beta'},  # Handle "1.0.0-beta-1"
        {'pattern': r'^(.+?)\.beta\.(\d+)$', 'type': 'beta'},  # Handle "1.0.0.beta.1"
        
        # 0. Numberless patterns (prerelease identifiers without numeric component)
        # MUST come after all numbered patterns to avoid false matches
        {'pattern': r'^(.+?)-beta$', 'type': 'beta'},  # Handle "2.0.0-beta"
        {'pattern': r'^(.+?)\.beta$', 'type': 'beta'},  # Handle "2.0.0.beta"
        {'pattern': r'^(.+?)_beta$', 'type': 'beta'},  # Handle "2.0.0_beta"
        {'pattern': r'^(.+?)\s+beta$', 'type': 'beta'},  # Handle "2.0.0 beta"
        
        
        # ===== ALPHA TERM GROUP =====
        # 1. Space-separated patterns (numbered - must come before numberless)
        {'pattern': r'^(.+?)\s+alpha\s*(\d+)$', 'type': 'alpha'},  # Handle "1.0.0 alpha 1"
        {'pattern': r'^(.+?)\s+Alpha\s*(\d+)$', 'type': 'alpha'},  # Handle "1.0.0 Alpha 1"
        {'pattern': r'^(.+?)\s+a\s*(\d+)$', 'type': 'alpha'},  # Handle "1.0.0 a1"
        
        # 2. Direct concatenation patterns (numbered)
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])alpha(\d+)$', 'type': 'alpha'},  # Handle "2.0.0alpha1"
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])a(\d+)$', 'type': 'alpha'},  # Handle "2.0.0a1"
        
        # 3. Dash-dot notation patterns (numbered)
        {'pattern': r'^(.+?)-alpha\.(\d+)$', 'type': 'alpha'},  # Handle "1.0.0-alpha.1"
        
        # 4. Flexible separator patterns (numbered)
        {'pattern': r'^(.+?)_alpha_(\d+)$', 'type': 'alpha'},  # Handle "3.0.0_alpha_2"
        {'pattern': r'^(.+?)-alpha-(\d+)$', 'type': 'alpha'},  # Handle "3.0.0-alpha-2"
        {'pattern': r'^(.+?)_a_(\d+)$', 'type': 'alpha'},  # Handle "4.0.0_a_3"
        
        # 0. Numberless patterns (prerelease identifiers without numeric component)
        # MUST come after all numbered patterns to avoid false matches
        {'pattern': r'^(.+?)-alpha$', 'type': 'alpha'},  # Handle "1.0.0-alpha"
        {'pattern': r'^(.+?)\.alpha$', 'type': 'alpha'},  # Handle "1.0.0.alpha"
        {'pattern': r'^(.+?)_alpha$', 'type': 'alpha'},  # Handle "1.0.0_alpha"
        {'pattern': r'^(.+?)\s+alpha$', 'type': 'alpha'},  # Handle "1.0.0 alpha"
        
        
        # ===== RELEASE_CANDIDATE TERM GROUP =====
        # 1. Space-separated patterns (numbered - must come before numberless)
        {'pattern': r'^(.+?)\s+rc\s*(\d+)$', 'type': 'rc'},  # Handle "1.0.0 rc 1"
        {'pattern': r'^(.+?)\s+RC\s*(\d+)$', 'type': 'rc'},  # Handle "1.0.0 RC 1"
        {'pattern': r'^(.+?)\s+release\s+candidate\s*(\d+)$', 'type': 'rc'},  # Handle "1.0.0 release candidate 1"
        {'pattern': r'^(.+?)\s+Release\s+Candidate\s*(\d+)$', 'type': 'rc'},  # Handle "1.0.0 Release Candidate 1"
        
        # 2. Direct concatenation patterns (numbered)
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])rc(\d+)$', 'type': 'rc'},  # Handle "3.0.0rc1"
        
        # 3. Dash-dot notation patterns (numbered)
        {'pattern': r'^(.+?)-rc\.(\d+)$', 'type': 'rc'},  # Handle "1.0.0-rc.1"
        
        # 4. Flexible separator patterns (numbered)
        {'pattern': r'^(.+?)_rc_(\d+)$', 'type': 'rc'},  # Handle "2.0.0_rc_2"
        {'pattern': r'^(.+?)-rc-(\d+)$', 'type': 'rc'},  # Handle "2.0.0-rc-2"
        {'pattern': r'^(.+?)_release_candidate_(\d+)$', 'type': 'rc'},  # Handle "4.0.0_release_candidate_3"
        
        # 0. Numberless patterns (prerelease identifiers without numeric component)
        # MUST come after all numbered patterns to avoid false matches
        {'pattern': r'^(.+?)-rc$', 'type': 'rc'},  # Handle "3.0.0-rc"
        {'pattern': r'^(.+?)\.rc$', 'type': 'rc'},  # Handle "3.0.0.rc"
        {'pattern': r'^(.+?)_rc$', 'type': 'rc'},  # Handle "3.0.0_rc"
        {'pattern': r'^(.+?)\s+rc$', 'type': 'rc'},  # Handle "3.0.0 rc"
        
        
        # ===== FIX TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+fix\s*(\d+)$', 'type': 'fix'},  # Handle "3.0.0 fix 1"
        {'pattern': r'^(.+?)\s+Fix\s*(\d+)$', 'type': 'fix'},  # Handle "3.0.0 Fix 1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])fix(\d+)$', 'type': 'fix'},  # Handle "5.0.0fix1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-fix\.(\d+)$', 'type': 'fix'},  # Handle "2.1.0-fix.2"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_fix_(\d+)$', 'type': 'fix'},  # Handle "4.0.0_fix_2"
        {'pattern': r'^(.+?)-fix-(\d+)$', 'type': 'fix'},  # Handle "4.0.0-fix-2"
        {'pattern': r'^(.+?)\.fix\.(\d+)$', 'type': 'fix'},  # Handle "6.0.0.fix.3"
        {'pattern': r'^(.+?)[\.\-_]*fix[\.\-_]*(\d+)[\.\-_]*$', 'type': 'fix'},  # Handle flexible patterns
        {'pattern': r'^(.+?)_fix(\d+)$', 'type': 'fix'},  # Handle "8.0.0_fix4" (no separator around number)
        
        
        # ===== REVISION TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+revision\s*(\d+)$', 'type': 'revision'},  # Handle "3.0.0 revision 1"
        {'pattern': r'^(.+?)\s+Revision\s*(\d+)$', 'type': 'revision'},  # Handle "3.0.0 Revision 1"
        {'pattern': r'^(.+?)\s+rev\s*(\d+)$', 'type': 'revision'},  # Handle "3.0.0 rev 1"
        {'pattern': r'^(.+?)\s+Rev\s*(\d+)$', 'type': 'revision'},  # Handle "3.0.0 Rev 1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])revision(\d+)$', 'type': 'revision'},  # Handle "6.0.0revision1"
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])rev(\d+)$', 'type': 'revision'},  # Handle "6.0.0rev1"
        
        # 3. Dash-dot notation patterns (none specific for revision)
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_revision_(\d+)$', 'type': 'revision'},  # Handle "7.0.0_revision_2"
        {'pattern': r'^(.+?)-revision-(\d+)$', 'type': 'revision'},  # Handle "7.0.0-revision-2"
        {'pattern': r'^(.+?)_rev_(\d+)$', 'type': 'revision'},  # Handle "8.0.0_rev_3"
        
        
        # ===== MAINTENANCE_RELEASE TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+mr\s*(\d+)$', 'type': 'mr'},  # Handle "16.0.0 mr 7"
        {'pattern': r'^(.+?)\s+maintenance\s+release\s*(\d+)$', 'type': 'mr'},  # Handle "2.5.0 maintenance release 1" → standardized to mr
        {'pattern': r'^(.+?)\s+Maintenance\s+Release\s*(\d+)$', 'type': 'mr'},  # Handle "2.5.0 Maintenance Release 1" → standardized to mr
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])mr(\d+)$', 'type': 'mr'},  # Handle "1.0.0mr1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-mr\.(\d+)$', 'type': 'mr'},  # Handle "3.1.0-mr.2"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)[\.\-_]*mr[\.\-_]*(\d+)[\.\-_]*$', 'type': 'mr'},  # Handle "16.0.0_mr_7"
        {'pattern': r'^(.+?)[\.\-_]*maintenance[\s\-_]+release[\.\-_]*(\d+)[\.\-_]*$', 'type': 'mr'},  # Handle flexible → standardized to mr
        {'pattern': r'^(.+?)-maintenance-release-(\d+)$', 'type': 'mr'},  # Handle "4.0.0-maintenance-release-3" → standardized to mr
        {'pattern': r'^(.+?)_maintenance_release_(\d+)$', 'type': 'mr'},  # Handle "4.0.0_maintenance_release_3" → standardized to mr
        
        
        # ===== BUILD TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+build\s*(\d+)$', 'type': 'build'},  # Handle "1.0.0 build 1"
        {'pattern': r'^(.+?)\s+Build\s*(\d+)$', 'type': 'build'},  # Handle "1.0.0 Build 1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])build(\d+)$', 'type': 'build'},  # Handle "7.0.0build1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-build\.(\d+)$', 'type': 'build'},  # Handle "2.1.0-build.2"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_build_(\d+)$', 'type': 'build'},  # Handle "1.0.0_build_1"
        {'pattern': r'^(.+?)-build-(\d+)$', 'type': 'build'},  # Handle "2.0.0-build-2"
        {'pattern': r'^(.+?)\.build\.(\d+)$', 'type': 'build'},  # Handle "3.0.0.build.3"
        {'pattern': r'^(.+?)_build_(\d+)$', 'type': 'build'},  # Handle "4.0.0_build_4"
        {'pattern': r'^(.+?)-build-(\d+)$', 'type': 'build'},  # Handle "5.0.0-build-5"
        
        
        # ===== RELEASE TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+release\s*(\d+)$', 'type': 'release'},  # Handle "2.0.0 release 1"
        {'pattern': r'^(.+?)\s+Release\s*(\d+)$', 'type': 'release'},  # Handle "2.0.0 Release 1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])release(\d+)$', 'type': 'release'},  # Handle "8.0.0release1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-release\.(\d+)$', 'type': 'release'},  # Handle "3.1.0-release.2"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_release_(\d+)$', 'type': 'release'},  # Handle "2.0.0_release_1"
        {'pattern': r'^(.+?)-release-(\d+)$', 'type': 'release'},  # Handle "3.0.0-release-2"
        {'pattern': r'^(.+?)\.release\.(\d+)$', 'type': 'release'},  # Handle "4.0.0.release.3"
        {'pattern': r'^(.+?)_release_(\d+)$', 'type': 'release'},  # Handle "5.0.0_release_4"
        {'pattern': r'^(.+?)-release-(\d+)$', 'type': 'release'},  # Handle "6.0.0-release-5"
        
        
        # ===== MILESTONE TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+milestone\s*(\d+)$', 'type': 'milestone'},  # Handle "4.0.0 milestone 1"
        {'pattern': r'^(.+?)\s+Milestone\s*(\d+)$', 'type': 'milestone'},  # Handle "4.0.0 Milestone 1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])milestone(\d+)$', 'type': 'milestone'},  # Handle "9.0.0milestone1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-milestone\.(\d+)$', 'type': 'milestone'},  # Handle "4.1.0-milestone.2"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_milestone_(\d+)$', 'type': 'milestone'},  # Handle "3.0.0_milestone_1"
        {'pattern': r'^(.+?)-milestone-(\d+)$', 'type': 'milestone'},  # Handle "5.0.0-milestone-2"
        {'pattern': r'^(.+?)\.milestone\.(\d+)$', 'type': 'milestone'},  # Handle "6.0.0.milestone.3"
        {'pattern': r'^(.+?)_milestone_(\d+)$', 'type': 'milestone'},  # Handle "7.0.0_milestone_4"
        {'pattern': r'^(.+?)-milestone-(\d+)$', 'type': 'milestone'},  # Handle "8.0.0-milestone-5"
        
        
        # ===== SNAPSHOT TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+snapshot\s*(\d+)$', 'type': 'snapshot'},  # Handle "5.0.0 snapshot 1"
        {'pattern': r'^(.+?)\s+Snapshot\s*(\d+)$', 'type': 'snapshot'},  # Handle "5.0.0 Snapshot 1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])snapshot(\d+)$', 'type': 'snapshot'},  # Handle "10.0.0snapshot1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-snapshot\.(\d+)$', 'type': 'snapshot'},  # Handle "5.1.0-snapshot.2"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_snapshot_(\d+)$', 'type': 'snapshot'},  # Handle "4.0.0_snapshot_1"
        {'pattern': r'^(.+?)-snapshot-(\d+)$', 'type': 'snapshot'},  # Handle "6.0.0-snapshot-2"
        {'pattern': r'^(.+?)\.snapshot\.(\d+)$', 'type': 'snapshot'},  # Handle "7.0.0.snapshot.3"
        {'pattern': r'^(.+?)_snapshot_(\d+)$', 'type': 'snapshot'},  # Handle "8.0.0_snapshot_4"
        {'pattern': r'^(.+?)-snapshot-(\d+)$', 'type': 'snapshot'},  # Handle "9.0.0-snapshot-5"
        
        
        # ===== PREVIEW TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+preview\s*(\d+)$', 'type': 'preview'},  # Handle "6.0.0 preview 1"
        {'pattern': r'^(.+?)\s+Preview\s*(\d+)$', 'type': 'preview'},  # Handle "6.0.0 Preview 1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])preview(\d+)$', 'type': 'preview'},  # Handle "11.0.0preview1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-preview\.(\d+)$', 'type': 'preview'},  # Handle "6.1.0-preview.2"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_preview_(\d+)$', 'type': 'preview'},  # Handle "5.0.0_preview_1"
        {'pattern': r'^(.+?)-preview-(\d+)$', 'type': 'preview'},  # Handle "7.0.0-preview-2"
        {'pattern': r'^(.+?)\.preview\.(\d+)$', 'type': 'preview'},  # Handle "8.0.0.preview.3"
        {'pattern': r'^(.+?)_preview_(\d+)$', 'type': 'preview'},  # Handle "9.0.0_preview_4"
        {'pattern': r'^(.+?)-preview-(\d+)$', 'type': 'preview'},  # Handle "10.0.0-preview-5"
        
        
        # ===== CANDIDATE TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+candidate\s*(\d+)$', 'type': 'candidate'},  # Handle "7.0.0 candidate 1"
        {'pattern': r'^(.+?)\s+Candidate\s*(\d+)$', 'type': 'candidate'},  # Handle "7.0.0 Candidate 1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])candidate(\d+)$', 'type': 'candidate'},  # Handle "12.0.0candidate1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-candidate\.(\d+)$', 'type': 'candidate'},  # Handle "7.1.0-candidate.2"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_candidate_(\d+)$', 'type': 'candidate'},  # Handle "6.0.0_candidate_1"
        {'pattern': r'^(.+?)-candidate-(\d+)$', 'type': 'candidate'},  # Handle "8.0.0-candidate-2"
        {'pattern': r'^(.+?)\.candidate\.(\d+)$', 'type': 'candidate'},  # Handle "9.0.0.candidate.3"
        {'pattern': r'^(.+?)_candidate_(\d+)$', 'type': 'candidate'},  # Handle "10.0.0_candidate_4"
        {'pattern': r'^(.+?)-candidate-(\d+)$', 'type': 'candidate'},  # Handle "11.0.0-candidate-5"
        
        
        # ===== DEVELOPMENT TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+development\s*(\d+)$', 'type': 'development'},  # Handle "8.0.0 development 1"
        {'pattern': r'^(.+?)\s+Development\s*(\d+)$', 'type': 'development'},  # Handle "8.0.0 Development 1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])development(\d+)$', 'type': 'development'},  # Handle "13.0.0development1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-development\.(\d+)$', 'type': 'development'},  # Handle "8.1.0-development.2"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_development_(\d+)$', 'type': 'development'},  # Handle "7.0.0_development_1"
        {'pattern': r'^(.+?)-development-(\d+)$', 'type': 'development'},  # Handle "9.0.0-development-2"
        {'pattern': r'^(.+?)\.development\.(\d+)$', 'type': 'development'},  # Handle "10.0.0.development.3"
        {'pattern': r'^(.+?)_development_(\d+)$', 'type': 'development'},  # Handle "11.0.0_development_4"
        {'pattern': r'^(.+?)-development-(\d+)$', 'type': 'development'},  # Handle "12.0.0-development-5"
        
        
        # ===== DEVICE_PACK TERM GROUP =====
        
        # 1. Specific notation patterns (most specific first - must come before general patterns)
        {'pattern': r'^([^_]+)_DP(\d+)$', 'type': 'dp'},  # Handle "3.4_DP1" (original case) - exclude underscore from base
        
        # 2. Space-separated patterns
        {'pattern': r'^(.+?)\s+dp\s*(\d+)$', 'type': 'dp'},  # Handle "3.4 dp 1"
        {'pattern': r'^(.+?)\s+DP\s*(\d+)$', 'type': 'dp'},  # Handle "3.4 DP 1"
        {'pattern': r'^(.+?)\s+device\s+pack\s*(\d+)$', 'type': 'dp'},  # Handle "3.4 device pack 1" → standardized to dp
        
        # 3. Direct concatenation patterns (general patterns come after specific ones)
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])dp(\d+)$', 'type': 'dp'},  # Handle "3.4dp1"
        
        # 4. Flexible separator patterns  
        {'pattern': r'^(.+?)_dp_(\d+)$', 'type': 'dp'},  # Handle "2.0.0_dp_3"
        {'pattern': r'^(.+?)-dp-(\d+)$', 'type': 'dp'},  # Handle "4.0.0-dp-4"
        {'pattern': r'^(.+?)\.dp\.(\d+)$', 'type': 'dp'},  # Handle "6.0.0.dp.5"
        {'pattern': r'^(.+?)_device_pack_(\d+)$', 'type': 'dp'},  # Handle "7.0.0_device_pack_6" → standardized to dp
        
    ]
    
    return update_patterns, kb_exclusion_patterns

def transform_version_with_update_pattern(version_str: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Transform a version string with update patterns to match JavaScript modular_rules.js logic.
    Returns a tuple: (base_version, update_component, transformed_version) or (None, None, None) if no match.
    
    This function mirrors the JavaScript updatePatterns logic exactly.
    """
    if not version_str:
        return None, None, None
    
    # Get the comprehensive patterns from the helper function
    update_patterns, kb_exclusion_patterns = get_update_patterns()
   
    for pattern_info in update_patterns:
        pattern = re.compile(pattern_info['pattern'], re.IGNORECASE)
        match = pattern.match(version_str)
        if match:
            # Extract base version and update component
            base_version = match.group(1).strip()  # Trim any trailing spaces
            update_number = match.group(2) if len(match.groups()) > 1 else ''
            pattern_type = pattern_info['type']
            
            # Handle p-notation expansion (p7 -> patch7)
            final_type = pattern_type
            if '.p(' in pattern_info['pattern'] and pattern_type == 'patch':
                final_type = 'patch'
            
            # Clean and format the update component
            if update_number:
                update_component = f"{final_type}{update_number}"
            else:
                update_component = final_type
            
            # Create the transformed version string (base:update format like CPE)
            transformed_version = f"{base_version}:{update_component}"
            
            return base_version, update_component, transformed_version
    
    return None, None, None

def analyze_update_patterns(raw_platform_data: Dict) -> Dict:
    """
    Analyze update patterns in version data.
    Returns information about detected update patterns and transformations.
    """
    update_info = {
        'has_update_patterns': False,
        'update_transformations': [],
        'pattern_types': set()
    }
    
    if not raw_platform_data or 'versions' not in raw_platform_data:
        return update_info
    
    versions = raw_platform_data.get('versions', [])
    if not isinstance(versions, list):
        return update_info
    
    # Check for version ranges first
    has_ranges = any(v and isinstance(v, dict) and ('lessThan' in v or 'lessThanOrEqual' in v) for v in versions)
    
    for version in versions:
        if not isinstance(version, dict):
            continue
            
        fields_to_check = [
            ('version', version.get('version', '')),
            ('lessThan', version.get('lessThan', '')),
            ('lessThanOrEqual', version.get('lessThanOrEqual', ''))
        ]
        
        for field_name, field_value in fields_to_check:
            if field_value and isinstance(field_value, str):
                base_version, update_component, transformed_version = transform_version_with_update_pattern(field_value)
                
                if base_version and update_component:
                    update_info['has_update_patterns'] = True
                    
                    # Extract pattern type
                    pattern_type = update_component.rstrip('0123456789')
                    update_info['pattern_types'].add(pattern_type)
                    
                    transformation = {
                        'field': field_name,
                        'original': field_value,
                        'base_version': base_version,
                        'update_component': update_component,
                        'transformed_version': transformed_version,
                        'pattern_type': pattern_type,
                        'blocked_by_ranges': has_ranges
                    }
                    
                    update_info['update_transformations'].append(transformation)
    
    return update_info

def create_cpe_processing_registry_entry(table_index: int, cpe_base_strings: list, culled_cpe_strings: list) -> None:
    """
    Create and register separate CPE match strings searched and culled data for nvd-ish collector.
    
    This function properly isolates searched CPE strings from culled CPE strings by
    placing them in separate registries for better data organization and processing.
    
    Args:
        table_index: The table index for this entry
        cpe_base_strings: List of valid CPE match strings that were searched
        culled_cpe_strings: List of CPE match strings that were culled with reasons
    """
    try:
        # Create separate data structures for searched vs culled CPE strings
        cpe_searched_data = {
            'used_strings': cpe_base_strings,
            'used_count': len(cpe_base_strings)
        }
        
        cpe_culled_data = {
            'culled_strings': culled_cpe_strings,
            'culled_count': len(culled_cpe_strings)
        }
        
        # Register at top level in separate registries for proper isolation
        register_platform_notification_data(table_index, 'cpeBaseStringSearches', cpe_searched_data)
        register_platform_notification_data(table_index, 'cpeMatchStringsCulled', cpe_culled_data)
            
    except Exception as e:
        logger.warning(f"Failed to create CPE base string searches registry entry for table {table_index}: {e}", group="badge_modal")

def create_confirmed_mappings_registry_entry(table_index: int, confirmed_mappings: list, affected_entry: dict) -> None:
    """
    Create and register confirmed mappings data for nvd-ish collector integration.
    
    Args:
        table_index: The table index for this entry  
        confirmed_mappings: List of confirmed CPE base strings
        affected_entry: The affected entry this relates to
    """
    try:
        if not confirmed_mappings:
            # No confirmed mappings found - still register empty entry for consistency
            register_platform_notification_data(table_index, 'confirmedMappings', {
                'sourceId': 'Hashmire/Analysis_Tools v0.2.0',
                'cvelistv5AffectedEntryIndex': affected_entry.get('cvelistv5AffectedEntryIndex', 'unknown'),
                'confirmedMappings': []
            })
            return
        
        # Create confirmed mappings structure for NVD-ish format
        confirmed_mappings_data = {
            'sourceId': 'Hashmire/Analysis_Tools v0.2.0',
            'cvelistv5AffectedEntryIndex': affected_entry.get('cvelistv5AffectedEntryIndex', 'unknown'),
            'confirmedMappings': confirmed_mappings  # Just the CPE base string list
        }
        
        # Register confirmed mappings data for this table index
        register_platform_notification_data(table_index, 'confirmedMappings', confirmed_mappings_data)
        
        if logger:
            logger.debug(f"Registered {len(confirmed_mappings)} confirmed mappings for table {table_index}", group="badge_modal")
            
    except Exception as e:
        logger.warning(f"Failed to create confirmed mappings registry entry for table {table_index}: {e}", group="badge_modal")

def create_top10_cpe_suggestions_registry_entry(table_index: int, top10_data: dict) -> None:
    """
    Create and register top 10 CPE base string suggestions for nvd-ish collector integration.
    
    This stores the ranked CPE base string suggestions derived from NVD /cpes/ API analysis,
    following the same pattern as other PENR registrations for proper data isolation.
    
    Args:
        table_index: The table index for this entry
        top10_data: Dictionary of top 10 CPE base strings with their metadata from reduceToTop10()
    """
    try:
        # Transform the top10_data into the documented format with ranking
        top10_suggestions = []
        
        for rank, (cpe_base_string, metadata) in enumerate(top10_data.items(), 1):
            suggestion_entry = {
                'cpeBaseString': cpe_base_string,
                'rank': str(rank)
            }
            top10_suggestions.append(suggestion_entry)
        
        # Register the top 10 suggestions data in PENR
        top10_registry_data = {
            'top10SuggestedCPEBaseStrings': top10_suggestions,
            'suggestion_count': len(top10_suggestions)
        }
        
        register_platform_notification_data(table_index, 'top10CPESuggestions', top10_registry_data)
        
    except Exception as e:
        logger.warning(f"Failed to create top 10 CPE suggestions registry entry for table {table_index}: {e}", group="badge_modal")

def detect_cross_affected_entry_overlaps(affected_entries: List[Dict]) -> List[Dict]:
    """
    Detect overlapping ranges across different affected entries with identical alias properties.
    
    Compares all affected array entries to find those with identical alias data:
    - vendor (case-insensitive)
    - product (case-insensitive) 
    - platforms[*] (set equality, any order)
    - repo
    - packageName
    - collectionURL
    
    For entries with identical alias properties, checks their versions for overlapping ranges.
    
    Returns list of overlap concerns with identical alias data included for debugging.
    """
    from packaging import version
    
    overlaps = []
    
    # Helper function to create identity key from all provided alias properties
    def get_alias_key(entry):
        """
        Create identity key from all provided alias properties.
        
        Two entries are considered identical if ALL their alias properties match exactly.
        This is a conservative approach that only flags entries as duplicates when they
        are demonstrably identical based on the data actually provided.
        
        Alias properties: vendor, product, platforms, repo, packageName, collectionURL
        """
        if not isinstance(entry, dict):
            return None
            
        # Extract all potential alias properties, normalizing for consistent comparison
        vendor = entry.get('vendor', '').lower().strip() if entry.get('vendor') else None
        product = entry.get('product', '').lower().strip() if entry.get('product') else None
        repo = entry.get('repo', '').strip() if entry.get('repo') else None
        package_name = entry.get('packageName', '').strip() if entry.get('packageName') else None
        collection_url = entry.get('collectionURL', '').strip() if entry.get('collectionURL') else None
        
        # Normalize platforms array (set equality, order-independent)
        platforms = entry.get('platforms', [])
        if isinstance(platforms, list):
            platforms_normalized = tuple(sorted([p.strip() for p in platforms if isinstance(p, str)]))
        else:
            platforms_normalized = tuple()
        
        # Create identity tuple from all alias properties
        # None values are preserved to distinguish between missing vs empty values
        return (vendor, product, platforms_normalized, repo, package_name, collection_url)
    
    def get_alias_object(entry):
        """Extract alias properties as object for debugging output"""
        alias_obj = {}
        if entry.get('vendor'):
            alias_obj['vendor'] = entry['vendor']
        if entry.get('product'):
            alias_obj['product'] = entry['product']
        if entry.get('platforms'):
            alias_obj['platforms'] = entry['platforms']
        if entry.get('repo'):
            alias_obj['repo'] = entry['repo']
        if entry.get('packageName'):
            alias_obj['packageName'] = entry['packageName']
        if entry.get('collectionURL'):
            alias_obj['collectionURL'] = entry['collectionURL']
        return alias_obj
    
    # Group affected entries by identical alias properties
    alias_groups = {}
    for entry_idx, entry in enumerate(affected_entries):
        if not isinstance(entry, dict):
            continue
            
        alias_key = get_alias_key(entry)
        if alias_key is None:
            continue
            
        if alias_key not in alias_groups:
            alias_groups[alias_key] = []
        
        alias_groups[alias_key].append({
            'index': entry_idx,
            'entry': entry,
            'alias_object': get_alias_object(entry)
        })
    
    # For each group with multiple entries, check for version overlaps
    for alias_key, group_entries in alias_groups.items():
        if len(group_entries) < 2:
            continue  # No overlaps possible with single entry
        
        # Compare versions between all pairs in this alias group
        for i in range(len(group_entries)):
            for j in range(i + 1, len(group_entries)):
                entry1 = group_entries[i]
                entry2 = group_entries[j]
                
                versions1 = entry1['entry'].get('versions', [])
                versions2 = entry2['entry'].get('versions', [])
                
                if not isinstance(versions1, list) or not isinstance(versions2, list):
                    continue
                
                # Collect all ranges from both entries (including changes arrays)
                ranges1 = []
                ranges2 = []
                
                # Extract ranges from entry1
                for v1_idx, version1 in enumerate(versions1):
                    if not isinstance(version1, dict):
                        continue
                    
                    # Main version range (only if it has boundaries)
                    if any(field in version1 for field in ['lessThan', 'lessThanOrEqual']):
                        ranges1.append({**version1, 'source': f"affected[{entry1['index']}].versions[{v1_idx}]"})
                    
                    # Changes array ranges
                    if 'changes' in version1 and isinstance(version1['changes'], list):
                        for c_idx, change in enumerate(version1['changes']):
                            if isinstance(change, dict) and 'at' in change:
                                ranges1.append({
                                    'version': change['at'],
                                    'status': change.get('status', 'unknown'),
                                    'source': f"affected[{entry1['index']}].versions[{v1_idx}].changes[{c_idx}]"
                                })
                
                # Extract ranges from entry2
                for v2_idx, version2 in enumerate(versions2):
                    if not isinstance(version2, dict):
                        continue
                    
                    # Main version range (only if it has boundaries)
                    if any(field in version2 for field in ['lessThan', 'lessThanOrEqual']):
                        ranges2.append({**version2, 'source': f"affected[{entry2['index']}].versions[{v2_idx}]"})
                    
                    # Changes array ranges
                    if 'changes' in version2 and isinstance(version2['changes'], list):
                        for c_idx, change in enumerate(version2['changes']):
                            if isinstance(change, dict) and 'at' in change:
                                ranges2.append({
                                    'version': change['at'],
                                    'status': change.get('status', 'unknown'),
                                    'source': f"affected[{entry2['index']}].versions[{v2_idx}].changes[{c_idx}]"
                                })
                
                # Compare all ranges between the two entries
                for range1 in ranges1:
                    for range2 in ranges2:
                        overlap_result = check_range_overlap_semantic(range1, range2)
                        
                        if overlap_result:
                            # Add identical alias data to the detected pattern
                            overlap_result['detectedPattern']['identicalAlias'] = entry1['alias_object']
                            
                            # Update field reference to show cross-entry nature
                            overlap_result['field'] = f"affected[{entry1['index']}].versions[*]"
                            
                            overlaps.append(overlap_result)
    
    return overlaps


def detect_comprehensive_range_overlaps(versions: List[Dict]) -> List[Dict]:
    """
    Comprehensive range overlap detection including wildcard patterns and numeric ranges.
    Returns unified list of overlap concerns for overlappingRanges.
    
    CRITICAL: Applies update pattern transformations BEFORE overlap detection to avoid
    false positives where legitimate update patterns create apparent overlaps.
    """
    from packaging import version
    
    overlaps = []
    
    # 1. APPLY UPDATE PATTERN TRANSFORMATIONS FIRST
    # Transform all version strings using update patterns before checking overlaps
    transformed_versions = []
    for v_idx, v in enumerate(versions):
        if not isinstance(v, dict):
            transformed_versions.append(v)
            continue
            
        # Create a transformed copy of the version entry
        transformed_v = v.copy()
        
        # Transform version fields that might contain update patterns
        for field in ['version', 'lessThan', 'lessThanOrEqual']:
            if field in v and isinstance(v[field], str) and v[field]:
                base_version, update_component, transformed_version = transform_version_with_update_pattern(v[field])
                if base_version and transformed_version:
                    # Use the base version for overlap detection (strip update patterns)
                    transformed_v[field] = base_version
        
        # Also transform changes array 'at' fields
        if 'changes' in v and isinstance(v['changes'], list):
            transformed_changes = []
            for change in v['changes']:
                if isinstance(change, dict) and 'at' in change and isinstance(change['at'], str):
                    base_version, update_component, transformed_version = transform_version_with_update_pattern(change['at'])
                    transformed_change = change.copy()
                    if base_version:
                        # Use the base version for overlap detection
                        transformed_change['at'] = base_version
                    transformed_changes.append(transformed_change)
                else:
                    transformed_changes.append(change)
            transformed_v['changes'] = transformed_changes
        
        transformed_versions.append(transformed_v)
    
    # 2. WILDCARD OVERLAP DETECTION (on transformed versions)
    wildcard_ranges = []
    for v_idx, v in enumerate(transformed_versions):
        if isinstance(v, dict) and v.get('version') == '*' and ('lessThan' in v or 'lessThanOrEqual' in v):
            branch_end = v.get('lessThan') or v.get('lessThanOrEqual')
            if branch_end:
                wildcard_ranges.append({
                    'source': f'versions[{v_idx}]',
                    'version': '*',
                    'lessThan': v.get('lessThan'),
                    'lessThanOrEqual': v.get('lessThanOrEqual'),
                    'status': v.get('status', 'unknown'),
                    'version_idx': v_idx,
                    'branch_end': branch_end
                })
    
    # Check for wildcard overlaps (multiple * with different bounds)
    if len(wildcard_ranges) > 1:
        unique_branches = list(set([r['branch_end'] for r in wildcard_ranges]))
        if len(unique_branches) > 1:
            overlaps.append({
                "field": "versions", 
                "sourceValue": wildcard_ranges,
                "detectedPattern": {
                    "overlapType": "wildcard_multiple_bounds",
                    "branches": sorted(unique_branches)
                },
                "overlap_type": "wildcard_multiple_bounds",
                "affected_ranges": wildcard_ranges,
                "range_description": f"Multiple wildcard patterns with different upper bounds: {', '.join(sorted(unique_branches))}",
                "related_table_indices": [r['version_idx'] for r in wildcard_ranges]
            })
    
    # 3. NUMERIC RANGE OVERLAP DETECTION (on transformed versions)
    numeric_ranges = []
    
    # Extract numeric ranges from transformed versions and changes arrays
    for v_idx, v in enumerate(transformed_versions):
        if not isinstance(v, dict):
            continue
            
        # Main version range (only process actual ranges, not explicit single versions)
        version_str = v.get('version', '0')
        if version_str != '*' and version_str not in VERSION_PLACEHOLDER_VALUES:
            # Only consider this a range if it has range boundaries (lessThan/lessThanOrEqual)
            # Explicit single versions without boundaries are not ranges
            has_range_boundaries = any(field in v for field in ['lessThan', 'lessThanOrEqual'])
            if has_range_boundaries:
                try:
                    range_data = {
                        'source': f'versions[{v_idx}]',
                        'version': version_str,
                        'lessThan': v.get('lessThan'),
                        'lessThanOrEqual': v.get('lessThanOrEqual'),
                        'status': v.get('status', 'unknown'),
                        'version_idx': v_idx
                    }
                    numeric_ranges.append(range_data)
                except:
                    pass
        
        # Changes array ranges (using transformed data)
        if 'changes' in v and isinstance(v['changes'], list):
            for c_idx, change in enumerate(v['changes']):
                if isinstance(change, dict) and 'at' in change:
                    at_value = change['at']
                    if at_value and at_value != '*' and at_value not in VERSION_PLACEHOLDER_VALUES:
                        try:
                            change_range = {
                                'source': f'versions[{v_idx}].changes[{c_idx}]',
                                'version': at_value,
                                'status': change.get('status', 'unknown'),
                                'version_idx': v_idx,
                                'change_idx': c_idx
                            }
                            numeric_ranges.append(change_range)
                        except:
                            pass
    
    # Compare numeric ranges for overlaps
    for i, range1 in enumerate(numeric_ranges):
        for j, range2 in enumerate(numeric_ranges[i + 1:], i + 1):
            overlap = check_range_overlap_semantic(range1, range2)
            if overlap:
                overlaps.append(overlap)
    
    return overlaps

def check_range_overlap_semantic(range1: Dict, range2: Dict) -> Optional[Dict]:
    """
    Check if two version ranges overlap using semantic version comparison.
    Returns overlap details if found, None otherwise.
    """
    from packaging import version
    
    # Skip overlap detection for git version types (commit hashes don't follow semver)
    range1_version_type = range1.get('versionType', '')
    range2_version_type = range2.get('versionType', '')
    if range1_version_type == 'git' or range2_version_type == 'git':
        return None
    
    try:
        # Parse versions
        v1_start = version.parse(str(range1['version']))
        v2_start = version.parse(str(range2['version']))
        
        # Get end bounds
        v1_end = None
        v1_end_inclusive = False
        if range1.get('lessThan'):
            v1_end = version.parse(str(range1['lessThan']))
            v1_end_inclusive = False
        elif range1.get('lessThanOrEqual'):
            v1_end = version.parse(str(range1['lessThanOrEqual']))
            v1_end_inclusive = True
        
        v2_end = None
        v2_end_inclusive = False
        if range2.get('lessThan'):
            v2_end = version.parse(str(range2['lessThan']))
            v2_end_inclusive = False
        elif range2.get('lessThanOrEqual'):
            v2_end = version.parse(str(range2['lessThanOrEqual']))
            v2_end_inclusive = True
        
        # Check for overlaps - only process actual ranges with boundaries
        overlap_type = None
        
        # Both must be ranges (have end bounds) to be considered for overlap
        if v1_end is None or v2_end is None:
            # Skip: at least one is an explicit single version without boundaries
            return None
        
        # Range vs Range overlaps (both have boundaries)
        if v1_end is not None and v2_end is not None:
            # Check if ranges overlap
            if (v1_start < v2_end or (v2_end_inclusive and v1_start == v2_end)) and \
               (v2_start < v1_end or (v1_end_inclusive and v2_start == v1_end)):
                if v1_start == v2_start and v1_end == v2_end and v1_end_inclusive == v2_end_inclusive:
                    overlap_type = "identical_ranges"
                elif v1_start <= v2_start and v1_end >= v2_end:
                    overlap_type = "range1_contains_range2"
                elif v2_start <= v1_start and v2_end >= v1_end:
                    overlap_type = "range2_contains_range1"
                else:
                    overlap_type = "partial_overlap"
        
        if overlap_type:
            return {
                "field": "versions",
                "sourceValue": f"{range1['source']} & {range2['source']}",
                "detectedPattern": {
                    "overlapType": overlap_type,
                    "range1Source": range1['source'],
                    "range2Source": range2['source'],
                    "range1": f"{range1['version']} to {range1.get('lessThan') or range1.get('lessThanOrEqual')}",
                    "range2": f"{range2['version']} to {range2.get('lessThan') or range2.get('lessThanOrEqual')}"
                }
            }
    
    except Exception:
        # If version parsing fails, skip this comparison
        pass
    
    return None

# ===== SOURCE DATA CONCERNS FUNCTIONS =====

def preprocess_platform_data_for_analysis(raw_platform_data: Dict) -> Dict:
    """
    Preprocess platform data by applying update pattern transformations before source data concern analysis.
    
    This ensures all source data concern checks work with normalized versions rather than raw update patterns,
    preventing false positives where legitimate update patterns appear as overlaps or other issues.
    
    Only processes version-related fields - vendor/product/platforms fields are preserved as-is.
    
    Args:
        raw_platform_data: The raw platform data dictionary
        
    Returns:
        Deep copy of platform data with update patterns normalized in version fields only
    """
    import copy
    
    # Create a deep copy to avoid modifying the original data
    curated_data = copy.deepcopy(raw_platform_data)
    
    # Process version fields if they exist (only versions and changes arrays need curation)
    if 'versions' in curated_data and isinstance(curated_data['versions'], list):
        for version_entry in curated_data['versions']:
            if not isinstance(version_entry, dict):
                continue
                
            # Transform version fields that might contain update patterns
            for field in ['version', 'lessThan', 'lessThanOrEqual']:
                if field in version_entry and isinstance(version_entry[field], str) and version_entry[field]:
                    original_version = version_entry[field]
                    base_version, update_component, transformed_version = transform_version_with_update_pattern(original_version)
                    if base_version and base_version != original_version:
                        # Use the base version for analysis (strip update patterns)
                        version_entry[field] = base_version
            
            # Also transform changes array 'at' fields
            if 'changes' in version_entry and isinstance(version_entry['changes'], list):
                for change in version_entry['changes']:
                    if isinstance(change, dict) and 'at' in change and isinstance(change['at'], str):
                        original_at = change['at']
                        base_version, update_component, transformed_version = transform_version_with_update_pattern(original_at)
                        if base_version and base_version != original_at:
                            # Use the base version for analysis
                            change['at'] = base_version
    
    return curated_data


def create_source_data_concerns_badge(table_index: int, raw_platform_data: Dict, characteristics: Dict, 
                                       platform_metadata: Dict, row: Dict) -> None:
    """
    Create a unified Source Data Concerns badge for platform entries.
    
    Analyzes platform data for quality issues and populates PLATFORM_ENTRY_NOTIFICATION_REGISTRY
    with detected concerns for downstream reporting.
    
    Args:
        table_index: The table index for unique identification
        raw_platform_data: The raw platform data to analyze
        characteristics: Version characteristics analysis
        platform_metadata: Platform metadata from the row
        row: The complete row data for header information
    """
    import re  # Local import to ensure availability in this function scope
    
    # CRITICAL: Preprocess platform data to apply update pattern transformations
    # This prevents false positives where legitimate update patterns appear as overlaps or data concerns
    curated_platform_data = preprocess_platform_data_for_analysis(raw_platform_data)
    
    # Collect all source data concerns
    concerns_data = {
        "placeholderData": [],
        "textComparators": [],
        "mathematicalComparators": [],
        "versionGranularity": [],
        "whitespaceIssues": [],
        "invalidCharacters": [],
        "overlappingRanges": [],
        "allVersionsPatterns": [],
        "bloatTextDetection": []
    }
    
    concerns_count = 0
    concern_types = []
    
    # === SKIP LOGIC INFRASTRUCTURE ===
    # Track skip conditions per field to eliminate improper multi-count findings
    field_skip_registry = {}  # field_name -> {"placeholder": bool, "math_comparators": set(), "text_regex": bool, "whitespace": bool}
    
    def normalize_field_name(field, version_idx=None, change_idx=None):
        """Standardize field names across all detection groups"""
        if version_idx is not None:
            if change_idx is not None:
                return f"versions[{version_idx}].changes[{change_idx}].{field}"
            else:
                return f"versions[{version_idx}].{field}"
        elif field.startswith('platforms['):
            return field  # Already normalized
        else:
            return field  # vendor, product, packageName
    
    def register_field_skip(field_name, skip_type, skip_data=None):
        """Register a skip condition for a specific field"""
        if field_name not in field_skip_registry:
            field_skip_registry[field_name] = {
                "placeholder": False, 
                "math_comparators": set(), 
                "text_regex": False, 
                "whitespace": False
            }
        
        if skip_type == "placeholder":
            field_skip_registry[field_name]["placeholder"] = True
        elif skip_type == "math_comparators":
            field_skip_registry[field_name]["math_comparators"].update(skip_data)
        elif skip_type == "text_regex":
            field_skip_registry[field_name]["text_regex"] = True
        elif skip_type == "whitespace":
            field_skip_registry[field_name]["whitespace"] = True
    
    def should_skip_field(field_name, detection_type):
        """Check if a field should be skipped for a specific detection type"""
        if field_name not in field_skip_registry:
            return False
        
        registry = field_skip_registry[field_name]
        
        # Priority 1: Placeholder skips ALL other detections
        if registry["placeholder"]:
            return True
        
        # Handle specific detection type exclusions
        if detection_type == "mathematical_comparators":
            return bool(registry["math_comparators"])
        elif detection_type == "text_regex":
            return registry["text_regex"]
        elif detection_type == "whitespace":
            return registry["whitespace"]
        
        return False
    
    # Vendor Placeholder Data Detection
    if 'vendor' in raw_platform_data and isinstance(raw_platform_data['vendor'], str):
        vendor_value = raw_platform_data['vendor'].strip()
        vendor_lower = vendor_value.lower()
        # Use exact matching for placeholder detection - these are specific bad data entry practices
        is_placeholder = vendor_lower in [v.lower() for v in GENERAL_PLACEHOLDER_VALUES]
        
        if is_placeholder:
            # Register skip condition for this field
            register_field_skip("vendor", "placeholder")
            
            detected_pattern = next(v for v in GENERAL_PLACEHOLDER_VALUES if v.lower() == vendor_lower)
            concerns_data["placeholderData"].append({
                "field": "vendor",
                "sourceValue": vendor_value,
                "detectedPattern": {"detectedValue": detected_pattern}
            })
            concerns_count += 1
    # Product Placeholder Data Detection    
    if 'product' in raw_platform_data and isinstance(raw_platform_data['product'], str):
        product_value = raw_platform_data['product'].strip()
        product_lower = product_value.lower()
        # Use exact matching for placeholder detection - these are specific bad data entry practices
        is_placeholder = product_lower in [v.lower() for v in GENERAL_PLACEHOLDER_VALUES]
        
        if is_placeholder:
            # Register skip condition for this field
            register_field_skip("product", "placeholder")
            
            detected_pattern = next(v for v in GENERAL_PLACEHOLDER_VALUES if v.lower() == product_lower)
            concerns_data["placeholderData"].append({
                "field": "product", 
                "sourceValue": product_value,
                "detectedPattern": {"detectedValue": detected_pattern}
            })
            concerns_count += 1
    
    if concerns_data["placeholderData"]:
        concern_types.append("Placeholder Detection")
    
    # Version Placeholder Data Detection 
    if 'versions' in curated_platform_data and isinstance(curated_platform_data['versions'], list):
        version_fields = ['version', 'lessThan', 'lessThanOrEqual']
        
        for version_idx, version_entry in enumerate(curated_platform_data['versions']):
            if isinstance(version_entry, dict):
                # Check standard version fields
                for field in version_fields:
                    field_value = version_entry.get(field)
                    if isinstance(field_value, str) and field_value.strip():
                        field_value_lower = field_value.strip().lower()
                        # Use exact matching for placeholder detection - these are specific bad data entry practices
                        is_placeholder = field_value_lower in [v.lower() for v in VERSION_PLACEHOLDER_VALUES]
                        
                        if is_placeholder:
                            # Register skip condition for this specific version field
                            normalized_field = normalize_field_name(field, version_idx)
                            register_field_skip(normalized_field, "placeholder")
                            
                            detected_pattern = next(v for v in VERSION_PLACEHOLDER_VALUES if v.lower() == field_value_lower)
                            concerns_data["placeholderData"].append({
                                "field": field,
                                "sourceValue": field_value,
                                "detectedPattern": {"detectedValue": detected_pattern}
                            })
                            concerns_count += 1
                
                # Check changes array for version status changes
                if 'changes' in version_entry and isinstance(version_entry['changes'], list):
                    for idx, change in enumerate(version_entry['changes']):
                        if isinstance(change, dict):
                            change_at_value = change.get('at')
                            if isinstance(change_at_value, str) and change_at_value.strip():
                                field_value_lower = change_at_value.strip().lower()
                                # Use exact matching for placeholder detection
                                is_placeholder = field_value_lower in [v.lower() for v in VERSION_PLACEHOLDER_VALUES]
                                
                                if is_placeholder:
                                    # Register skip condition for this specific change field
                                    normalized_field = normalize_field_name("at", version_idx, idx)
                                    register_field_skip(normalized_field, "placeholder")
                                    
                                    detected_pattern = next(v for v in VERSION_PLACEHOLDER_VALUES if v.lower() == field_value_lower)
                                    concerns_data["placeholderData"].append({
                                        "field": f"changes[{idx}].at",
                                        "sourceValue": change_at_value,
                                        "detectedPattern": {"detectedValue": detected_pattern}
                                    })
                                    concerns_count += 1
        
        # Update concern types if version field placeholder patterns were found
        if concerns_data["placeholderData"] and "Placeholder Detection" not in concern_types:
            concern_types.append("Placeholder Detection")
    
    # Platform Placeholder Data Detection
    if 'platforms' in raw_platform_data and isinstance(raw_platform_data['platforms'], list):
        for idx, platform_item in enumerate(raw_platform_data['platforms']):
            if isinstance(platform_item, str):
                platform_lower = platform_item.lower().strip()
                # Use exact matching for placeholder detection - these are specific bad data entry practices
                is_placeholder = platform_lower in [v.lower() for v in GENERAL_PLACEHOLDER_VALUES]
                
                if is_placeholder:
                    # Register skip condition for this platform field
                    register_field_skip(f"platforms[{idx}]", "placeholder")
                    
                    detected_pattern = next(v for v in GENERAL_PLACEHOLDER_VALUES if v.lower() == platform_lower)
                    concerns_data["placeholderData"].append({
                        "field": f"platforms[{idx}]",
                        "sourceValue": platform_item,
                        "detectedPattern": {"detectedValue": detected_pattern}
                    })
                    concerns_count += 1
                    
                    # Update concern types if not already added
                    if "Placeholder Detection" not in concern_types:
                        concern_types.append("Placeholder Detection")
    
    # Package Name Placeholder Data Detection
    if 'packageName' in raw_platform_data and isinstance(raw_platform_data['packageName'], str):
        package_value = raw_platform_data['packageName'].strip()
        package_lower = package_value.lower()
        # Use exact matching for placeholder detection - these are specific bad data entry practices
        is_placeholder = package_lower in [v.lower() for v in GENERAL_PLACEHOLDER_VALUES]
        
        if is_placeholder:
            # Register skip condition for this field
            register_field_skip("packageName", "placeholder")
            
            detected_pattern = next(v for v in GENERAL_PLACEHOLDER_VALUES if v.lower() == package_lower)
            concerns_data["placeholderData"].append({
                "field": "packageName", 
                "sourceValue": package_value,
                "detectedPattern": {"detectedValue": detected_pattern}
            })
            concerns_count += 1
            
            # Update concern types if not already added
            if "Placeholder Detection" not in concern_types:
                concern_types.append("Placeholder Detection")
    
    # === Version Granularity Detection ===
    if 'versions' in curated_platform_data and isinstance(curated_platform_data['versions'], list):
        import re  # Local import to avoid scoping issues
        version_granularities = {}  # base_version -> {granularity: [ {field: value}, ... ]}
        version_fields = ['version', 'lessThan', 'lessThanOrEqual']
        
        for version_entry in curated_platform_data['versions']:
            if isinstance(version_entry, dict):
                # Check standard version fields
                for field in version_fields:
                    if field in version_entry and isinstance(version_entry[field], str):
                        version_str = version_entry[field].strip()
                        if not version_str or version_str == '*':
                            continue
                        # Extract base version number (major version only)
                        # Handle both single-part (e.g., "2") and multi-part (e.g., "1.0.1.0.5.6.7.8.9.10.11.12.13") versions
                        base_match = re.match(r'^(\d+)', version_str)
                        if base_match:
                            major_version = base_match.group(1)  # e.g., "1", "2", "3"
                            # Count the number of parts by splitting on dots
                            parts = version_str.split('.')
                            granularity_count = len(parts)
                            granularity = f"{granularity_count}-part"
                            if major_version not in version_granularities:
                                version_granularities[major_version] = {}
                            if granularity not in version_granularities[major_version]:
                                version_granularities[major_version][granularity] = []
                            version_granularities[major_version][granularity].append({
                                "field": field,
                                "sourceValue": version_str
                            })
                
                # Check changes array for version status changes
                if 'changes' in version_entry and isinstance(version_entry['changes'], list):
                    for idx, change in enumerate(version_entry['changes']):
                        if isinstance(change, dict) and 'at' in change:
                            at_value = change['at']
                            if isinstance(at_value, str) and at_value.strip():
                                version_str = at_value.strip()
                                if version_str and version_str != '*':
                                    # Extract base version number (major version only) 
                                    # Handle both single-part (e.g., "2") and multi-part (e.g., "1.0.1.0.5.6.7.8.9.10.11.12.13") versions
                                    base_match = re.match(r'^(\d+)', version_str)
                                    if base_match:
                                        major_version = base_match.group(1)  # e.g., "1", "2", "3"
                                        # Count the number of parts by splitting on dots
                                        parts = version_str.split('.')
                                        granularity_count = len(parts)
                                        granularity = f"{granularity_count}-part"
                                        if major_version not in version_granularities:
                                            version_granularities[major_version] = {}
                                        if granularity not in version_granularities[major_version]:
                                            version_granularities[major_version][granularity] = []
                                        version_granularities[major_version][granularity].append({
                                            "field": f"changes[{idx}].at",
                                            "sourceValue": version_str
                                        })
        
        # Only flag bases with >1 granularity (inconsistent granularity)
        for base, granularities in version_granularities.items():
            if len(granularities) > 1:
                # Group all unique versions by granularity for visual alignment
                granularity_groups = {}
                for granularity_type, field_list in granularities.items():
                    granularity_count = granularity_type.split('-')[0]
                    if granularity_count not in granularity_groups:
                        granularity_groups[granularity_count] = {}
                    
                    for field_info in field_list:
                        version = field_info['sourceValue']
                        if version not in granularity_groups[granularity_count]:
                            granularity_groups[granularity_count][version] = field_info['field']
                
                # Add entries grouped by granularity for visual alignment
                for granularity_count in sorted(granularity_groups.keys()):
                    unique_versions = granularity_groups[granularity_count]
                    for version in sorted(unique_versions.keys()):
                        field = unique_versions[version]
                        concerns_data["versionGranularity"].append({
                            "field": field,
                            "sourceValue": version,
                            "detectedPattern": {
                                "base": base,
                                "granularity": granularity_count
                            }
                        })
                
                # Count unique granularities per base group (not individual version entries)
                concerns_count += len(granularities)
        
        # Update concern types if version granularity patterns were found
        if concerns_data["versionGranularity"]:
            concern_types.append("Version Granularity Detection")

    # === Comparator Pattern Detection ===
    # Check vendor for comparator patterns
    if 'vendor' in raw_platform_data and isinstance(raw_platform_data['vendor'], str):
        vendor_value = raw_platform_data['vendor'].strip()
        if vendor_value:
            vendor_lower = vendor_value.lower()
            matching_comparators = [comp for comp in COMPARATOR_PATTERNS if comp in vendor_lower]
            if matching_comparators:
                # Register skip condition for invalid characters - exclude math operators
                register_field_skip("vendor", "math_comparators", set(['<', '>', '=', '!']))
                
                concerns_data["mathematicalComparators"].append({
                    "field": "vendor",
                    "sourceValue": vendor_value,
                    "detectedPattern": {"detectedValue": ', '.join(matching_comparators)}
                })
                concerns_count += 1
    
    # Check product for comparator patterns
    if 'product' in raw_platform_data and isinstance(raw_platform_data['product'], str):
        product_value = raw_platform_data['product'].strip()
        if product_value:
            product_lower = product_value.lower()
            matching_comparators = [comp for comp in COMPARATOR_PATTERNS if comp in product_lower]
            if matching_comparators:
                # Register skip condition for invalid characters - exclude math operators
                register_field_skip("product", "math_comparators", set(['<', '>', '=', '!']))
                
                concerns_data["mathematicalComparators"].append({
                    "field": "product",
                    "sourceValue": product_value,
                    "detectedPattern": {"detectedValue": ', '.join(matching_comparators)}
                })
                concerns_count += 1
    
    # Check platforms array for comparator patterns
    if 'platforms' in raw_platform_data and isinstance(raw_platform_data['platforms'], list):
        for idx, platform_item in enumerate(raw_platform_data['platforms']):
            if isinstance(platform_item, str):
                platform_value = platform_item.strip()
                if platform_value:
                    platform_lower = platform_value.lower()
                    matching_comparators = [comp for comp in COMPARATOR_PATTERNS if comp in platform_lower]
                    if matching_comparators:
                        # Register skip condition for invalid characters - exclude math operators
                        register_field_skip(f"platforms[{idx}]", "math_comparators", set(['<', '>', '=', '!']))
                        
                        concerns_data["mathematicalComparators"].append({
                            "field": f"platforms[{idx}]",
                            "sourceValue": platform_value,
                            "detectedPattern": {"detectedValue": ', '.join(matching_comparators)}
                        })
                        concerns_count += 1
    
    # Check packageName for comparator patterns
    if 'packageName' in raw_platform_data and isinstance(raw_platform_data['packageName'], str):
        package_value = raw_platform_data['packageName'].strip()
        if package_value:
            package_lower = package_value.lower()
            matching_comparators = [comp for comp in COMPARATOR_PATTERNS if comp in package_lower]
            if matching_comparators:
                # Register skip condition for invalid characters - exclude math operators
                register_field_skip("packageName", "math_comparators", set(['<', '>', '=', '!']))
                
                concerns_data["mathematicalComparators"].append({
                    "field": "packageName",
                    "sourceValue": package_value,
                    "detectedPattern": {"detectedValue": ', '.join(matching_comparators)}
                })
                concerns_count += 1
    
    # Update concern types if any comparator patterns were found
    if concerns_data["mathematicalComparators"]:
        concern_types.append("Mathematical Comparator Detection")

    # Check version fields for comparator patterns  
    if 'versions' in curated_platform_data and isinstance(curated_platform_data['versions'], list):
        version_fields = ['version', 'lessThan', 'lessThanOrEqual']
        
        for version_idx, version_entry in enumerate(curated_platform_data['versions']):
            if isinstance(version_entry, dict):
                # Check standard version fields
                for field in version_fields:
                    field_value = version_entry.get(field)
                    if isinstance(field_value, str) and field_value.strip():
                        field_lower = field_value.lower()
                        matching_comparators = [comp for comp in COMPARATOR_PATTERNS if comp in field_lower]
                        if matching_comparators:
                            # Register skip condition for invalid characters - exclude math operators
                            normalized_field = normalize_field_name(field, version_idx)
                            register_field_skip(normalized_field, "math_comparators", set(['<', '>', '=', '!']))
                            
                            concerns_data["mathematicalComparators"].append({
                                "field": field,
                                "sourceValue": field_value,
                                "detectedPattern": {"detectedValue": ', '.join(matching_comparators)}
                            })
                            concerns_count += 1
                
                # Check changes array for version status changes
                if 'changes' in version_entry and isinstance(version_entry['changes'], list):
                    for idx, change in enumerate(version_entry['changes']):
                        if isinstance(change, dict):
                            change_at_value = change.get('at')
                            if isinstance(change_at_value, str) and change_at_value.strip():
                                field_lower = change_at_value.lower()
                                matching_comparators = [comp for comp in COMPARATOR_PATTERNS if comp in field_lower]
                                if matching_comparators:
                                    # Register skip condition for invalid characters - exclude math operators
                                    normalized_field = normalize_field_name("at", version_idx, idx)
                                    register_field_skip(normalized_field, "math_comparators", set(['<', '>', '=', '!']))
                                    
                                    concerns_data["mathematicalComparators"].append({
                                        "field": f"changes[{idx}].at",
                                        "sourceValue": change_at_value,
                                        "detectedPattern": {"detectedValue": ', '.join(matching_comparators)}
                                    })
                                    concerns_count += 1
        
        # Update concern types if version field comparator patterns were found
        if concerns_data["mathematicalComparators"] and "Mathematical Comparator Detection" not in concern_types:
            concern_types.append("Mathematical Comparator Detection")

    # === Text Comparator Detection ===
    # Check version fields for text-based comparison patterns
    if 'versions' in curated_platform_data and isinstance(curated_platform_data['versions'], list):
        version_fields = ['version', 'lessThan', 'lessThanOrEqual']
        
        for version_idx, version_entry in enumerate(curated_platform_data['versions']):
            if isinstance(version_entry, dict):
                # Check standard version fields
                for field in version_fields:
                    field_value = version_entry.get(field)
                    if isinstance(field_value, str) and field_value.strip():
                        field_lower = field_value.lower()
                        # Check each string pattern and report individually with pattern type
                        for pattern_type, patterns in TEXT_COMPARATOR_PATTERNS.items():
                            for pattern in patterns:
                                # Use word boundary detection to prevent false positives like "Connector" triggering "to"
                                import re
                                pattern_regex = r'\b' + re.escape(pattern) + r'\b'
                                if re.search(pattern_regex, field_lower):
                                    # Register skip condition for invalid characters - exclude space for Range Separators only
                                    if pattern_type == "Range Separators":
                                        normalized_field = normalize_field_name(field, version_idx)
                                        register_field_skip(normalized_field, "text_regex", True)
                                    
                                    concerns_data["textComparators"].append({
                                        "field": field,
                                        "sourceValue": field_value,
                                        "detectedPattern": {
                                            "detectedValue": pattern,
                                            "patternType": pattern_type
                                        }
                                    })
                                    concerns_count += 1
                        
                        # Check regex patterns for version ranges
                        for regex_pattern in TEXT_COMPARATOR_REGEX_PATTERNS:
                            match = regex_pattern['pattern'].search(field_value)
                            if match:
                                # Register skip condition for invalid characters - exclude space for regex patterns only
                                normalized_field = normalize_field_name(field, version_idx)
                                register_field_skip(normalized_field, "text_regex", True)
                                
                                concerns_data["textComparators"].append({
                                    "field": field,
                                    "sourceValue": field_value,
                                    "detectedPattern": {
                                        "detectedValue": match.group(0),
                                        "patternType": regex_pattern['patternType']
                                    }
                                })
                                concerns_count += 1
                
                # Check changes array for version status changes
                if 'changes' in version_entry and isinstance(version_entry['changes'], list):
                    for idx, change in enumerate(version_entry['changes']):
                        if isinstance(change, dict):
                            # Check changes[].at field
                            change_at_value = change.get('at')
                            if isinstance(change_at_value, str) and change_at_value.strip():
                                field_lower = change_at_value.lower()
                                # Check each string pattern and report individually with pattern type
                                for pattern_type, patterns in TEXT_COMPARATOR_PATTERNS.items():
                                    for pattern in patterns:
                                        # Use word boundary detection to prevent false positives
                                        pattern_regex = r'\b' + re.escape(pattern) + r'\b'
                                        if re.search(pattern_regex, field_lower):
                                            # Register skip condition for invalid characters - exclude space for text comparators in changes arrays
                                            normalized_field = normalize_field_name("at", version_idx, idx)
                                            register_field_skip(normalized_field, "text_regex", True)
                                            
                                            concerns_data["textComparators"].append({
                                                "field": f"changes[{idx}].at",
                                                "sourceValue": change_at_value,
                                                "detectedPattern": {
                                                    "detectedValue": pattern,
                                                    "patternType": pattern_type
                                                }
                                            })
                                            concerns_count += 1
                                
                                # Check regex patterns for version ranges
                                for regex_pattern in TEXT_COMPARATOR_REGEX_PATTERNS:
                                    match = regex_pattern['pattern'].search(change_at_value)
                                    if match:
                                        # Register skip condition for invalid characters - exclude space for regex patterns only
                                        normalized_field = normalize_field_name("at", version_idx, idx)
                                        register_field_skip(normalized_field, "text_regex", True)
                                        
                                        concerns_data["textComparators"].append({
                                            "field": f"changes[{idx}].at",
                                            "sourceValue": change_at_value,
                                            "detectedPattern": {
                                                "detectedValue": match.group(0),
                                                "patternType": regex_pattern['patternType']
                                            }
                                        })
                                        concerns_count += 1
                            
                            # Check changes[].status field
                            change_status_value = change.get('status')
                            if isinstance(change_status_value, str) and change_status_value.strip():
                                field_lower = change_status_value.lower()
                                # Check each string pattern and report individually with pattern type
                                for pattern_type, patterns in TEXT_COMPARATOR_PATTERNS.items():
                                    for pattern in patterns:
                                        # Use word boundary detection to prevent false positives
                                        pattern_regex = r'\b' + re.escape(pattern) + r'\b'
                                        if re.search(pattern_regex, field_lower):
                                            # Register skip condition for invalid characters - exclude space for Range Separators only
                                            if pattern_type == "Range Separators":
                                                normalized_field = normalize_field_name("status", version_idx, idx)
                                                register_field_skip(normalized_field, "text_regex", True)
                                            
                                            concerns_data["textComparators"].append({
                                                "field": f"changes[{idx}].status",
                                                "sourceValue": change_status_value,
                                                "detectedPattern": {
                                                    "detectedValue": pattern,
                                                    "patternType": pattern_type
                                                }
                                            })
                                            concerns_count += 1
                                
                                # Check regex patterns for version ranges
                                for regex_pattern in TEXT_COMPARATOR_REGEX_PATTERNS:
                                    match = regex_pattern['pattern'].search(change_status_value)
                                    if match:
                                        # Register skip condition for invalid characters - exclude space for regex patterns only
                                        normalized_field = normalize_field_name("status", version_idx, idx)
                                        register_field_skip(normalized_field, "text_regex", True)
                                        
                                        concerns_data["textComparators"].append({
                                            "field": f"changes[{idx}].status",
                                            "sourceValue": change_status_value,
                                            "detectedPattern": {
                                                "detectedValue": match.group(0),
                                                "patternType": regex_pattern['patternType']
                                            }
                                        })
                                        concerns_count += 1
        
        # Update concern types if text comparator patterns were found
        if concerns_data["textComparators"]:
            concern_types.append("Text Comparator Detection")
    
    # All Versions Pattern Detection
    if 'versions' in curated_platform_data and isinstance(curated_platform_data['versions'], list):
        version_fields = ['version', 'lessThan', 'lessThanOrEqual']
        
        for version_entry in curated_platform_data['versions']:
            if isinstance(version_entry, dict):
                # Check standard version fields
                for field in version_fields:
                    field_value = version_entry.get(field)
                    if isinstance(field_value, str) and field_value.strip():
                        field_lower = field_value.strip().lower()
                        # Check for exact match with ALL_VERSION_VALUES
                        for pattern in ALL_VERSION_VALUES:
                            if field_lower == pattern.lower():
                                concerns_data["allVersionsPatterns"].append({
                                    "field": field,
                                    "sourceValue": field_value,
                                    "detectedPattern": {"detectedValue": pattern}
                                })
                                concerns_count += 1
                
                # Check changes array for version status changes
                if 'changes' in version_entry and isinstance(version_entry['changes'], list):
                    for idx, change in enumerate(version_entry['changes']):
                        if isinstance(change, dict):
                            # Check changes[].at field
                            change_at_value = change.get('at')
                            if isinstance(change_at_value, str) and change_at_value.strip():
                                field_lower = change_at_value.strip().lower()
                                # Check for exact match with ALL_VERSION_VALUES
                                for pattern in ALL_VERSION_VALUES:
                                    if field_lower == pattern.lower():
                                        concerns_data["allVersionsPatterns"].append({
                                            "field": f"changes[{idx}].at",
                                            "sourceValue": change_at_value,
                                            "detectedPattern": {"detectedValue": pattern}
                                        })
                                        concerns_count += 1
        
        # Update concern types if all versions patterns were found
        if concerns_data["allVersionsPatterns"]:
            concern_types.append("All Versions Pattern Detection")
    
    # Check for bloat text patterns in version fields
    if curated_platform_data.get('versions'):
        for version_entry in curated_platform_data['versions']:
            if isinstance(version_entry, dict):
                # Check standard version fields
                for field in version_fields:
                    field_value = version_entry.get(field)
                    if isinstance(field_value, str) and field_value.strip():
                        field_lower = field_value.strip().lower()
                        # Check for bloat text patterns using word boundaries
                        for bloat_text in BLOAT_TEXT_VALUES:
                            # Use regex to match whole words (case-insensitive)
                            import re
                            pattern = r'\b' + re.escape(bloat_text.lower()) + r'\b'
                            if re.search(pattern, field_lower):
                                concerns_data["bloatTextDetection"].append({
                                    "field": field,
                                    "sourceValue": field_value,
                                    "detectedPattern": {"detectedValue": bloat_text}
                                })
                                concerns_count += 1
                                break  # Only record first match per field
                
                # Check changes array for version status changes
                if 'changes' in version_entry and isinstance(version_entry['changes'], list):
                    for idx, change in enumerate(version_entry['changes']):
                        if isinstance(change, dict):
                            # Check changes[].at field
                            change_at_value = change.get('at')
                            if isinstance(change_at_value, str) and change_at_value.strip():
                                field_lower = change_at_value.strip().lower()
                                # Check for bloat text patterns using word boundaries
                                for bloat_text in BLOAT_TEXT_VALUES:
                                    # Use regex to match whole words (case-insensitive)
                                    import re
                                    pattern = r'\b' + re.escape(bloat_text.lower()) + r'\b'
                                    if re.search(pattern, field_lower):
                                        concerns_data["bloatTextDetection"].append({
                                            "field": f"changes[{idx}].at",
                                            "sourceValue": change_at_value,
                                            "detectedPattern": {"detectedValue": bloat_text}
                                        })
                                        concerns_count += 1
                                        break  # Only record first match per field
        
        # Update concern types if bloat text detection found issues
        if concerns_data["bloatTextDetection"]:
            concern_types.append("Bloat Text Detection")
    
    # Check for bloat text patterns in version fields
    if curated_platform_data.get('versions'):
        for version_entry in curated_platform_data['versions']:
            if isinstance(version_entry, dict):
                # Check standard version fields
                for field in version_fields:
                    field_value = version_entry.get(field)
                    if isinstance(field_value, str) and field_value.strip():
                        field_lower = field_value.strip().lower()
                        # Check for bloat text patterns using word boundaries
                        for bloat_text in BLOAT_TEXT_VALUES:
                            # Use regex to match whole words (case-insensitive)
                            import re
                            pattern = r'\b' + re.escape(bloat_text.lower()) + r'\b'
                            if re.search(pattern, field_lower):
                                concerns_data["bloatTextDetection"].append({
                                    "field": field,
                                    "sourceValue": field_value,
                                    "detectedPattern": {"detectedValue": bloat_text}
                                })
                                concerns_count += 1
                                break  # Only record first match per field
                
                # Check changes array for version status changes
                if 'changes' in version_entry and isinstance(version_entry['changes'], list):
                    for idx, change in enumerate(version_entry['changes']):
                        if isinstance(change, dict):
                            # Check changes[].at field
                            change_at_value = change.get('at')
                            if isinstance(change_at_value, str) and change_at_value.strip():
                                field_lower = change_at_value.strip().lower()
                                # Check for bloat text patterns using word boundaries
                                for bloat_text in BLOAT_TEXT_VALUES:
                                    # Use regex to match whole words (case-insensitive)
                                    import re
                                    pattern = r'\b' + re.escape(bloat_text.lower()) + r'\b'
                                    if re.search(pattern, field_lower):
                                        concerns_data["bloatTextDetection"].append({
                                            "field": f"changes[{idx}].at",
                                            "sourceValue": change_at_value,
                                            "detectedPattern": {"detectedValue": bloat_text}
                                        })
                                        concerns_count += 1
                                        break  # Only record first match per field
        
    # Vendor Bloat Text Detection - detect vendor text redundantly included in product/packageName fields
    if 'vendor' in raw_platform_data and isinstance(raw_platform_data['vendor'], str):
        vendor_value = raw_platform_data['vendor'].strip()
        if vendor_value and not _is_placeholder_value(vendor_value):
            vendor_lower = vendor_value.lower()
            
            # Check for vendor text in product field (full word match only)
            if 'product' in raw_platform_data and isinstance(raw_platform_data['product'], str):
                product_value = raw_platform_data['product'].strip()
                if product_value:
                    product_lower = product_value.lower()
                    # Use pattern that matches vendor as separate word (surrounded by whitespace or string boundaries)
                    # This prevents matching in hyphenated compounds like "nodejs-fun-product"
                    vendor_pattern = r'(?:^|\s)' + re.escape(vendor_lower) + r'(?:\s|$)'
                    if re.search(vendor_pattern, product_lower) and product_lower != vendor_lower:
                        concerns_data["bloatTextDetection"].append({
                            "field": "product",
                            "sourceValue": product_value,
                            "detectedPattern": {"detectedValue": vendor_value, "patternType": "vendor_redundancy"}
                        })
                        concerns_count += 1
            
            # Check for vendor text in packageName field (full word match only)
            if 'packageName' in raw_platform_data and isinstance(raw_platform_data['packageName'], str):
                package_name_value = raw_platform_data['packageName'].strip()
                if package_name_value:
                    package_name_lower = package_name_value.lower()
                    # Use pattern that matches vendor as separate word (surrounded by whitespace or string boundaries)
                    # This prevents matching in hyphenated compounds like "nodejs-fun-product"
                    vendor_pattern = r'(?:^|\s)' + re.escape(vendor_lower) + r'(?:\s|$)'
                    if re.search(vendor_pattern, package_name_lower) and package_name_lower != vendor_lower:
                        concerns_data["bloatTextDetection"].append({
                            "field": "packageName",
                            "sourceValue": package_name_value,
                            "detectedPattern": {"detectedValue": vendor_value, "patternType": "vendor_redundancy"}
                        })
                        concerns_count += 1
        
        # Update concern types if bloat text detection found issues
        if concerns_data["bloatTextDetection"]:
            concern_types.append("Bloat Text Detection")
    
    # Helper function to detect whitespace issues
    def detect_whitespace_issues(field_value):
        """Detect and classify whitespace issues in a field value"""
        if not isinstance(field_value, str) or not field_value:
            return None
            
        issues = []
        if field_value.startswith(' '):
            issues.append("leading")
        if field_value.endswith(' '):
            issues.append("trailing")
        if '  ' in field_value:  # Multiple consecutive spaces
            issues.append("excessive")
            
        if issues:
            # Generate replaced text with visible whitespace markers
            replaced_text = field_value
            replaced_text = replaced_text.replace(' ', '!')  # Replace spaces with !
            replaced_text = replaced_text.replace('\t', '►')  # Replace tabs with ►
            replaced_text = replaced_text.replace('\n', '↵')  # Replace newlines with ↵
            replaced_text = replaced_text.replace('\r', '◄')  # Replace carriage returns with ◄
            
            return {
                "whitespaceTypes": issues,
                "replacedText": replaced_text
            }
        return None
    
    # Check vendor field
    if 'vendor' in raw_platform_data and isinstance(raw_platform_data['vendor'], str):
        vendor_value = raw_platform_data['vendor']
        whitespace_data = detect_whitespace_issues(vendor_value)
        if whitespace_data:
            # Register skip condition for invalid characters - exclude space
            register_field_skip("vendor", "whitespace", True)
            
            concerns_data["whitespaceIssues"].append({
                "field": "vendor",
                "sourceValue": vendor_value,
                "detectedPattern": whitespace_data
            })
            concerns_count += 1
    
    # Check product field  
    if 'product' in raw_platform_data and isinstance(raw_platform_data['product'], str):
        product_value = raw_platform_data['product']
        whitespace_data = detect_whitespace_issues(product_value)
        if whitespace_data:
            # Register skip condition for invalid characters - exclude space
            register_field_skip("product", "whitespace", True)
            
            concerns_data["whitespaceIssues"].append({
                "field": "product",
                "sourceValue": product_value,
                "detectedPattern": whitespace_data
            })
            concerns_count += 1
    
    # Check packageName field
    if 'packageName' in raw_platform_data and isinstance(raw_platform_data['packageName'], str):
        package_value = raw_platform_data['packageName']
        whitespace_data = detect_whitespace_issues(package_value)
        if whitespace_data:
            # Register skip condition for invalid characters - exclude space
            register_field_skip("packageName", "whitespace", True)
            
            concerns_data["whitespaceIssues"].append({
                "field": "packageName",
                "sourceValue": package_value,
                "detectedPattern": whitespace_data
            })
            concerns_count += 1
    
    # Check platforms array
    if 'platforms' in raw_platform_data and isinstance(raw_platform_data['platforms'], list):
        for idx, platform_item in enumerate(raw_platform_data['platforms']):
            if isinstance(platform_item, str):
                whitespace_data = detect_whitespace_issues(platform_item)
                if whitespace_data:
                    # Register skip condition for invalid characters - exclude space
                    register_field_skip(f"platforms[{idx}]", "whitespace", True)
                    
                    concerns_data["whitespaceIssues"].append({
                        "field": f"platforms[{idx}]",
                        "sourceValue": platform_item,
                        "detectedPattern": whitespace_data
                    })
                    concerns_count += 1
    
    # Check version-related fields
    if 'versions' in raw_platform_data and isinstance(raw_platform_data['versions'], list):
        for version_idx, version_entry in enumerate(raw_platform_data['versions']):
            if isinstance(version_entry, dict):
                # Check standard version fields
                version_fields = ['version', 'lessThan', 'lessThanOrEqual']
                for field in version_fields:
                    field_value = version_entry.get(field)
                    if isinstance(field_value, str):
                        whitespace_data = detect_whitespace_issues(field_value)
                        if whitespace_data:
                            # Register skip condition for invalid characters - exclude space
                            normalized_field = normalize_field_name(field, version_idx)
                            register_field_skip(normalized_field, "whitespace", True)
                            
                            concerns_data["whitespaceIssues"].append({
                                "field": f"versions[{version_idx}].{field}",
                                "sourceValue": field_value,
                                "detectedPattern": whitespace_data
                            })
                            concerns_count += 1
                
                # Check changes array
                if 'changes' in version_entry and isinstance(version_entry['changes'], list):
                    for change_idx, change in enumerate(version_entry['changes']):
                        if isinstance(change, dict):
                            at_value = change.get('at')
                            if isinstance(at_value, str):
                                whitespace_data = detect_whitespace_issues(at_value)
                                if whitespace_data:
                                    # Register skip condition for invalid characters - exclude space
                                    normalized_field = normalize_field_name("at", version_idx, change_idx)
                                    register_field_skip(normalized_field, "whitespace", True)
                                    
                                    concerns_data["whitespaceIssues"].append({
                                        "field": f"versions[{version_idx}].changes[{change_idx}].at",
                                        "sourceValue": at_value,
                                        "detectedPattern": whitespace_data
                                    })
                                    concerns_count += 1
                            
                            # Check status fields
                            status_value = change.get('status')
                            if isinstance(status_value, str):
                                whitespace_data = detect_whitespace_issues(status_value)
                                if whitespace_data:
                                    # Register skip condition for invalid characters - exclude space
                                    normalized_field = normalize_field_name("status", version_idx, change_idx)
                                    register_field_skip(normalized_field, "whitespace", True)
                                    
                                    concerns_data["whitespaceIssues"].append({
                                        "field": f"versions[{version_idx}].changes[{change_idx}].status",
                                        "sourceValue": status_value,
                                        "detectedPattern": whitespace_data
                                    })
                                    concerns_count += 1
    
    # Update concern types if whitespace issues were found
    if concerns_data["whitespaceIssues"]:
        concern_types.append("Whitespace Detection")

    # === RANGE OVERLAP DETECTION ===
    if 'versions' in curated_platform_data and isinstance(curated_platform_data['versions'], list):
        versions = curated_platform_data.get('versions', [])
        
        # Comprehensive range overlap detection (includes wildcards and numeric ranges)
        range_overlaps = detect_comprehensive_range_overlaps(versions)
        if range_overlaps:
            concerns_data["overlappingRanges"].extend(range_overlaps)
            concerns_count += len(range_overlaps)
    
    # === CROSS-AFFECTED-ENTRY OVERLAP DETECTION ===
    # Check for overlapping ranges across different affected entries with identical alias properties
    if 'affected' in raw_platform_data and isinstance(raw_platform_data['affected'], list):
        # Preprocess each affected entry to normalize update patterns before cross-entry analysis
        curated_affected_entries = []
        for entry in raw_platform_data['affected']:
            if isinstance(entry, dict):
                curated_entry = preprocess_platform_data_for_analysis(entry)
                curated_affected_entries.append(curated_entry)
        
        cross_entry_overlaps = detect_cross_affected_entry_overlaps(curated_affected_entries)
        if cross_entry_overlaps:
            concerns_data["overlappingRanges"].extend(cross_entry_overlaps)
            concerns_count += len(cross_entry_overlaps)
    
    # Update concern types for range overlaps
    if concerns_data["overlappingRanges"]:
        concern_types.append("Overlapping Ranges")

    # === INVALID CHARACTER DETECTION ===
    if 'versions' in curated_platform_data and isinstance(curated_platform_data['versions'], list):
        import re
        # Allow-list pattern for valid version characters
        # Allows: alphanumeric, hyphens, asterisks, underscores, colons, dots, plus, parentheses, tildes
        valid_version_pattern = r'^(\*|[a-zA-Z0-9]+[-*_:.+()~a-zA-Z0-9]*)$'
        
        for version_idx, version_entry in enumerate(curated_platform_data['versions']):
            if isinstance(version_entry, dict):
                version_fields = ['version', 'lessThan', 'lessThanOrEqual']
                for field in version_fields:
                    field_value = version_entry.get(field)
                    if isinstance(field_value, str) and field_value.strip():
                        # Check if version matches valid pattern
                        if not re.match(valid_version_pattern, field_value):
                            # Find specific invalid characters by excluding valid ones
                            invalid_chars = list(set(re.findall(r'[^a-zA-Z0-9\-*_:.+()~]', field_value)))
                            if invalid_chars:  # Only add if we actually found invalid characters
                                # Check if this field should be skipped for invalid character detection
                                normalized_field = normalize_field_name(field, version_idx)
                                
                                if should_skip_field(normalized_field, "invalid_characters"):
                                    continue  # Skip invalid character detection for this field entirely
                                
                                # Get exclusion sets from field registry for non-skipped fields
                                if normalized_field in field_skip_registry:
                                    registry = field_skip_registry[normalized_field]
                                    excluded_chars = set()
                                    excluded_chars.update(registry["math_comparators"])  # Math operators
                                    if registry["text_regex"]:
                                        excluded_chars.add(' ')  # Space from hyphenated ranges
                                    if registry["whitespace"]:
                                        excluded_chars.add(' ')  # Space from whitespace issues
                                else:
                                    excluded_chars = set()
                                
                                filtered_chars = []
                                for invalid_char in invalid_chars:
                                    if invalid_char not in excluded_chars:
                                        filtered_chars.append(invalid_char)
                                
                                # Use proper format for individual invalid characters
                                for invalid_char in filtered_chars:
                                    concerns_data["invalidCharacters"].append({
                                        "field": field,
                                        "sourceValue": field_value,
                                        "detectedPattern": {"detectedValue": invalid_char}
                                    })
                                    concerns_count += 1
                
                # Check changes array for invalid characters
                if 'changes' in version_entry and isinstance(version_entry['changes'], list):
                    for change_idx, change in enumerate(version_entry['changes']):
                        if isinstance(change, dict):
                            change_at_value = change.get('at')
                            if isinstance(change_at_value, str) and change_at_value.strip():
                                # Check if version matches valid pattern
                                if not re.match(valid_version_pattern, change_at_value):
                                    # Find specific invalid characters by excluding valid ones
                                    invalid_chars = list(set(re.findall(r'[^a-zA-Z0-9\-*_:.+()~]', change_at_value)))
                                    if invalid_chars:  # Only add if we actually found invalid characters
                                        # Check if this field should be skipped for invalid character detection
                                        normalized_field = normalize_field_name("at", version_idx, change_idx)
                                        
                                        if should_skip_field(normalized_field, "invalid_characters"):
                                            continue  # Skip invalid character detection for this field entirely
                                        
                                        # Get exclusion sets from field registry for non-skipped fields
                                        if normalized_field in field_skip_registry:
                                            registry = field_skip_registry[normalized_field]
                                            excluded_chars = set()
                                            excluded_chars.update(registry["math_comparators"])  # Math operators
                                            if registry["text_regex"]:
                                                excluded_chars.add(' ')  # Space from hyphenated ranges
                                            if registry["whitespace"]:
                                                excluded_chars.add(' ')  # Space from whitespace issues
                                        else:
                                            excluded_chars = set()
                                        
                                        filtered_chars = []
                                        for invalid_char in invalid_chars:
                                            if invalid_char not in excluded_chars:
                                                filtered_chars.append(invalid_char)
                                        
                                        # Use proper format for individual invalid characters
                                        for invalid_char in filtered_chars:
                                            concerns_data["invalidCharacters"].append({
                                                "field": f"changes[{change_idx}].at",
                                                "sourceValue": change_at_value,
                                                "detectedPattern": {"detectedValue": invalid_char}
                                            })
                                            concerns_count += 1    # Update concern types for invalid character detection
    if concerns_data["invalidCharacters"]:
        concern_types.append("Invalid Character Detection")
    
    # If no concerns detected, return None
    if concerns_count == 0:
        return None
    
    # Extract source role information from row data
    # Handle pandas Series safely by checking for empty/non-empty state
    try:
        if row is not None and hasattr(row, 'get'):
            source_role = row.get('sourceRole', 'Unknown Source')
        else:
            source_role = 'Unknown Source'
    except (ValueError, TypeError):
        # GRACEFUL DEGRADATION: Handle pandas Series boolean ambiguity for display layer
        source_role = 'Unknown Source'
    
    # Register the concerns data for the modal
    PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns'] = PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('sourceDataConcerns', {})
    
    # Preserve existing registry data (like overlappingRanges) if it exists
    if table_index in PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns']:
        existing_entry = PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns'][table_index]
        existing_concerns = existing_entry.get('concerns', {})
        existing_summary = existing_entry.get('summary', {})
        
        # Merge new concerns_data with existing concerns, preserving existing keys
        merged_concerns = existing_concerns.copy()
        merged_concerns.update(concerns_data)  # This will overwrite existing keys with new data from analysis
        
        # Calculate total concerns including existing data (like overlappingRanges)
        total_existing_concerns = 0
        existing_concern_types = existing_summary.get('concern_types', [])
        for concern_type, concern_list in existing_concerns.items():
            if isinstance(concern_list, list) and concern_list and concern_type not in concerns_data:
                total_existing_concerns += len(concern_list)
        
        # Update the entry while preserving existing data
        PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns'][table_index] = {
            "concerns": merged_concerns,
            "sourceRole": source_role,  # Add source role to the registered data
            "summary": {
                "total_concerns": concerns_count + total_existing_concerns,
                "concern_types": list(set(concern_types + existing_concern_types))  # Merge and deduplicate
            }
        }
    else:
        # Create new entry if none exists
        PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns'][table_index] = {
            "concerns": concerns_data,
            "sourceRole": source_role,  # Add source role to the registered data
            "summary": {
                "total_concerns": concerns_count,
                "concern_types": concern_types
            }
        }
    


def create_alias_extraction_badge(table_index: int, raw_platform_data: Dict, row: Dict) -> None:
    """
    Create an Alias Extraction badge for curator functionality integration.
    
    Extracts alias data from CVE platform entries by expanding platforms array into 
    separate alias entries. Each alias entry contains flat key-value pairs with no arrays.
    Populates PLATFORM_ENTRY_NOTIFICATION_REGISTRY for downstream reporting.
    
    Args:
        table_index: The table index for unique identification
        raw_platform_data: The raw platform data to extract aliases from
        row: The complete row data for header information
    """
    from ..logging.workflow_logger import get_logger
    logger = get_logger()
    
    # Initialize the alias extraction registry
    PLATFORM_ENTRY_NOTIFICATION_REGISTRY['aliasExtraction'] = PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('aliasExtraction', {})
    
    # Check for meaningful properties
    meaningful_properties = []
    for prop in ['vendor', 'product', 'platforms', 'modules', 'packageName', 'repo', 'programRoutines', 'programFiles', 'collectionURL']:
        if prop in raw_platform_data and not _is_placeholder_value(raw_platform_data[prop]):
            meaningful_properties.append(prop)
    
    # Check for unsupported array fields and log warnings
    unsupported_arrays = ['modules', 'programFiles', 'programRoutines']
    for field in unsupported_arrays:
        if field in raw_platform_data and isinstance(raw_platform_data[field], list) and raw_platform_data[field]:
            logger.warning(f"Found unsupported array field '{field}' with {len(raw_platform_data[field])} values in alias extraction - this will be supported in future versions")
    
    # Silently skip if no meaningful properties
    if not meaningful_properties:
        return None
    
    # Extract CVE ID for source tracking
    cve_id = None
    if hasattr(row, 'get'):
        cve_id = row.get('cve_id') or row.get('CVE_ID') or row.get('cveId')
    elif isinstance(row, dict):
        cve_id = row.get('cve_id') or row.get('CVE_ID') or row.get('cveId')
    
    # Extract base properties
    vendor = raw_platform_data.get('vendor')
    product = raw_platform_data.get('product')
    platforms = raw_platform_data.get('platforms', [])
    
    # Platform expansion logic following curator pattern exactly
    entry_count = 0
    
    if not platforms:
        # Create single entry without platform data
        alias_data = _create_alias_data(raw_platform_data, vendor, product, None, cve_id)
        if alias_data:  # Only store if meaningful data exists
            PLATFORM_ENTRY_NOTIFICATION_REGISTRY['aliasExtraction'][str(table_index)] = alias_data
            entry_count += 1
    else:
        # Create separate entries for each platform (curator pattern)
        for i, platform in enumerate(platforms):
            # Always create alias entry - let _create_alias_data handle platform filtering
            alias_data = _create_alias_data(raw_platform_data, vendor, product, platform, cve_id)
            if alias_data:  # Only store if meaningful data exists
                # Use unique table index for each platform entry (collector compatibility)
                platform_index = f"{table_index}_platform_{i}"
                PLATFORM_ENTRY_NOTIFICATION_REGISTRY['aliasExtraction'][platform_index] = alias_data
                entry_count += 1
    
    # Return None if no valid entries created (curator pattern)
    if entry_count == 0:
        return None
    


def _create_alias_data(affected_item: Dict, vendor: str = None, product: str = None, platform: str = None, cve_id: str = None) -> Dict:
    """
    Create a single alias entry with supported fields only.
    
    Args:
        affected_item: The affected item data
        vendor: Vendor name (may be None)
        product: Product name (may be None)  
        platform: Platform name (may be None)
        collectionURL: Collection URL (may be None)
        packageName: Package name (may be None)
        repo: Repository name (may be None)
        cve_id: CVE ID for source tracking
        
    Returns:
        Dictionary containing alias data, or empty dict if no meaningful data
    """
    # Initialize with source_cve tracking (curator pattern)
    alias_data = {'source_cve': []}
    if cve_id:
        alias_data['source_cve'] = [cve_id]
    
    # Core identification fields - only include if meaningful and not None
    if vendor is not None and not _is_placeholder_value(vendor):
        alias_data['vendor'] = vendor
        
    if product is not None and not _is_placeholder_value(product):
        alias_data['product'] = product
        
    if platform is not None and not _is_placeholder_value(platform):
        alias_data['platform'] = platform
    
    # Additional CVE 5.X fields - only include if they exist and are meaningful  
    # Note: defaultStatus is excluded as it doesn't represent alias data (curator pattern)
    additional_fields = ['collectionURL', 'packageName', 'repo']
    
    for field_name in additional_fields:
        if field_name in affected_item:
            field_value = affected_item[field_name]
            if not _is_placeholder_value(field_value):
                alias_data[field_name] = field_value
    
    # Handle complex fields (arrays) if they exist and have meaningful content
    for complex_field in ['programRoutines', 'programFiles', 'modules']:
        if complex_field in affected_item:
            field_value = affected_item[complex_field]
            if isinstance(field_value, list):
                # Filter placeholder values from arrays
                meaningful_values = [v for v in field_value if not _is_placeholder_value(v)]
                if meaningful_values:
                    alias_data[complex_field] = meaningful_values
            elif not _is_placeholder_value(field_value):
                alias_data[complex_field] = field_value
    
    # Only return alias if it has meaningful data beyond just source_cve (curator pattern)
    if len(alias_data) > 1:  # More than just 'source_cve'
        # Generate unique alias key based on ALL meaningful properties (curator pattern)
        key_parts = []
        for key_field in sorted(alias_data.keys()):
            if key_field != 'source_cve':  # Exclude source_cve from grouping key
                key_parts.append(f"{key_field}:{str(alias_data[key_field]).lower()}")
        alias_data['_alias_key'] = '||'.join(key_parts)  # Store for collector use
        return alias_data
    
    return {}


def _is_placeholder_value(value) -> bool:
    """
    Check if a value is considered a placeholder.
    
    Args:
        value: The value to check
        
    Returns:
        True if the value is a placeholder, False otherwise
    """
    if not value or value in [None, "", 0]:
        return True
        
    # Convert to string and normalize for checking
    str_value = str(value).lower().strip()
    
    # Use the existing centralized placeholder patterns from this module
    return str_value in [pattern.lower() for pattern in GENERAL_PLACEHOLDER_VALUES]
