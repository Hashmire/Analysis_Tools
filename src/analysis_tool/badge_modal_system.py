#!/usr/bin/env python3
"""
Badge and Modal System for Platform Entry Notifications
========================================================

This module handles the creation and management of interactive badges and modal content
for the Analysis Tools HTML generation system. It provides:

1. Badge creation with various priority levels (danger, warning, info, etc.)
2. Modal data registration and management
3. Wildcard generation analysis and transformation
4. Update pattern detection and processing
5. Data registry management for deduplication

The system supports both CPE-scoped data (for references/sorting priority)
and row-scoped data (for platform entry notifications like wildcard generation).
"""

import json
import re
import html
from typing import Dict, List, Tuple, Optional, Any, Set
import re
import json
import html
from .workflow_logger import get_logger

# Get logger instance
logger = get_logger()

# ===== GLOBAL REGISTRIES =====

# CPE-scoped data registry (keyed by CPE base strings)
GLOBAL_CPE_DATA_REGISTRY = {
    'references': {},       # CPE base string -> reference data
    'sortingPriority': {},  # CPE base string -> sorting data
    'registered_cpes': set() # Track which CPEs have been processed
}

# Platform Entry Notification registry (keyed by table index/row)
PLATFORM_ENTRY_NOTIFICATION_REGISTRY = {
    'wildcardGeneration': {},  # table_index -> wildcard transformation data
    'updatePatterns': {},      # table_index -> update pattern data
    'jsonGenerationRules': {}, # table_index -> combined JSON generation rules data
    'supportingInformation': {} # table_index -> supporting information data
}

# ===== CONSTANTS AND PATTERNS =====
# Define non-specific version values that should be treated as placeholders
# This list is used for both version data concern checks and JavaScript JSON generation
NON_SPECIFIC_VERSION_VALUES = [
    'unspecified', 'unknown', 'none', 'undefined', 'various',
    'n/a', 'not available', 'not applicable', 'unavailable',
    'na', 'nil', 'tbd', 'to be determined', 'pending',
    'not specified', 'not determined', 'not known', 'not listed',
    'not provided', 'missing', 'empty', 'null'
]

# Define version text patterns at module level for reuse
VERSION_TEXT_PATTERNS = [
    # Range indicators
    'through', 'thru', 'to', 'between', 'and',
    
    # Upper bound indicators
    'before', 'prior to', 'earlier than', 'up to', 'until', 
    'not after', 'older than', 'below',
    
    # Lower bound indicators
    'after', 'since', 'later than', 'newer than', 
    'starting with', 'from', 'above',
    
    # Approximation indicators
    'about', 'approximately', 'circa', 'around', 'roughly',
    
    # Inclusive/exclusive indicators
    'inclusive', 'exclusive', 'including', 'excluding',
    
    # Non-specific versions
    'all versions', 'any version', 'multiple versions',
    
    # Reference directives
    'see references', 'see advisory', 'refer to', 'check', 'as noted',
    
    # Missing/Unknown values (use the shared constant)
    *NON_SPECIFIC_VERSION_VALUES,
    
    # Descriptive statements
    'supported', 'unstable', 'development', 'beta', 'release candidate', 'nightly',
    
    # Date-based indicators that aren't version numbers
    'builds', 'release', 'pre-', 'post-',
    
    # Unclear bounds
    'earliest', 'recent', 'legacy', 'past', 'future', 'latest',
    
    # Commitish references
    'commit', 'git hash', 'branch',
    
    # Version range text indicators
    '_and_prior', '_and_later', '_and_earlier', '_and_newer',
    'and_prior', 'and_later', 'and_earlier', 'and_newer'
]


# ===== REGISTRY MANAGEMENT FUNCTIONS =====

def clear_all_registries():
    """Clear all badge and modal data registries"""
    global GLOBAL_CPE_DATA_REGISTRY, PLATFORM_ENTRY_NOTIFICATION_REGISTRY
    
    GLOBAL_CPE_DATA_REGISTRY = {
        'references': {},
        'sortingPriority': {},
        'registered_cpes': set()
    }
    
    PLATFORM_ENTRY_NOTIFICATION_REGISTRY = {
        'wildcardGeneration': {},
        'updatePatterns': {},
        'jsonGenerationRules': {},
        'supportingInformation': {}
    }
    
    logger.debug("Cleared all badge and modal registries", group="badge_modal")

def register_cpe_data(cpe_base_string: str, data_type: str, data: Dict) -> bool:
    """
    Register CPE-scoped data in the global registry to prevent duplication.
    
    Args:
        cpe_base_string: The CPE base string (e.g., "cpe:2.3:a:vendor:product:*")
        data_type: The type of data ('references' or 'sortingPriority')
        data: The data to store
    
    Returns:
        bool: True if data was newly registered, False if already existed
    """
    global GLOBAL_CPE_DATA_REGISTRY
    
    # Ensure the data_type key exists
    if data_type not in GLOBAL_CPE_DATA_REGISTRY:
        GLOBAL_CPE_DATA_REGISTRY[data_type] = {}
    
    # Create safe key for JavaScript
    base_key_safe = cpe_base_string.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_").replace("*", "star")
    
    # Check if this CPE data is already registered
    if base_key_safe in GLOBAL_CPE_DATA_REGISTRY[data_type]:
        return False  # Already registered
    
    # Register the data
    GLOBAL_CPE_DATA_REGISTRY[data_type][base_key_safe] = data
    GLOBAL_CPE_DATA_REGISTRY['registered_cpes'].add(cpe_base_string)
    
    return True  # Newly registered

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
    
    # Check for identical data already registered with different table indices
    # This helps prevent bloat from duplicate content
    data_json = json.dumps(data, sort_keys=True)
    for existing_index, existing_data in PLATFORM_ENTRY_NOTIFICATION_REGISTRY[data_type].items():
        if json.dumps(existing_data, sort_keys=True) == data_json:
            logger.debug(f"Skipping duplicate {data_type} data for table {table_index} (identical to table {existing_index})", group="badge_modal")
            return False  # Duplicate content
    
    # Register the data
    PLATFORM_ENTRY_NOTIFICATION_REGISTRY[data_type][table_index] = data
    
    return True  # Newly registered

def get_consolidated_cpe_registration_script() -> str:
    """
    Generate a single consolidated script block with all CPE data registrations.
    
    Returns:
        str: JavaScript code block with all BadgeModal.registerData calls
    """
    global GLOBAL_CPE_DATA_REGISTRY
    
    script_content = ""
    
    # Register all references data
    references_count = len(GLOBAL_CPE_DATA_REGISTRY['references'])
    for base_key_safe, ref_data in GLOBAL_CPE_DATA_REGISTRY['references'].items():
        ref_data_js = json.dumps(ref_data)
        script_content += f"    BadgeModal.registerData('references', '{base_key_safe}', {ref_data_js});\n"
    
    # Register all sorting priority data
    sorting_count = len(GLOBAL_CPE_DATA_REGISTRY['sortingPriority'])
    for base_key_safe, sorting_data in GLOBAL_CPE_DATA_REGISTRY['sortingPriority'].items():
        sorting_data_js = json.dumps(sorting_data)
        script_content += f"    BadgeModal.registerData('sortingPriority', '{base_key_safe}', {sorting_data_js});\n"
    
    if script_content:
        logger.debug(f"Generated CPE registrations - {references_count} references, {sorting_count} sorting priority entries", group="badge_modal")
        return f"""
// Consolidated CPE data registrations (deduplicated)
{script_content}"""
    else:
        return ""

def get_consolidated_platform_notification_script() -> str:
    """
    Generate a single consolidated script block with all platform notification data registrations.
    
    Returns:
        str: JavaScript code block with all platform notification data registrations
    """
    global PLATFORM_ENTRY_NOTIFICATION_REGISTRY
    
    script_content = ""
    
    # Register all wildcard generation data
    wildcard_count = len(PLATFORM_ENTRY_NOTIFICATION_REGISTRY['wildcardGeneration'])
    for table_index, wildcard_data in PLATFORM_ENTRY_NOTIFICATION_REGISTRY['wildcardGeneration'].items():
        wildcard_data_js = json.dumps(wildcard_data)
        script_content += f"    BadgeModal.registerData('wildcardGeneration', '{table_index}', {wildcard_data_js});\n"
    
    # Register all update pattern data
    update_count = len(PLATFORM_ENTRY_NOTIFICATION_REGISTRY['updatePatterns'])
    for table_index, update_data in PLATFORM_ENTRY_NOTIFICATION_REGISTRY['updatePatterns'].items():
        update_data_js = json.dumps(update_data)
        script_content += f"    BadgeModal.registerData('updatePatterns', '{table_index}', {update_data_js});\n"
    
    # Register all JSON generation rules data
    rules_count = len(PLATFORM_ENTRY_NOTIFICATION_REGISTRY['jsonGenerationRules'])
    for table_index, rules_data in PLATFORM_ENTRY_NOTIFICATION_REGISTRY['jsonGenerationRules'].items():
        rules_data_js = json.dumps(rules_data)
        script_content += f"    BadgeModal.registerData('jsonGenerationRules', '{table_index}', {rules_data_js});\n"
    
    # Register all supporting information data
    supporting_count = len(PLATFORM_ENTRY_NOTIFICATION_REGISTRY['supportingInformation'])
    for table_index, supporting_data in PLATFORM_ENTRY_NOTIFICATION_REGISTRY['supportingInformation'].items():
        supporting_data_js = json.dumps(supporting_data)
        script_content += f"    BadgeModal.registerData('supportingInformation', '{table_index}', {supporting_data_js});\n"
    
    if script_content:
        logger.debug(f"Generated platform registrations - {wildcard_count} wildcard, {update_count} update patterns, {rules_count} rules, {supporting_count} supporting info", group="badge_modal")
        return f"""
// Consolidated platform notification data registrations
{script_content}"""
    else:
        return ""
    
    if script_content:
        return f"""
// Consolidated Platform Entry Notification data registrations
{script_content}"""
    else:
        return ""

# ===== WILDCARD ANALYSIS FUNCTIONS =====

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
                    # Handle non-numeric version components
                    end_version = f"{major}.{minor}.{patch}.∞"
            else:
                # Fallback for complex patterns
                start_version = base_pattern + ".0"
                end_version = "unknown"
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
            'needs_gap_processing': False,
            'has_update_patterns': False,  
            'wildcard_patterns': [],
            'special_version_types': [],
            'version_families': set(),
            'status_types': set(),
            'version_concerns': []
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
        'needs_gap_processing': False,
        'has_update_patterns': False, 
        'wildcard_patterns': [],
        'special_version_types': [],
        'version_families': set(),
        'status_types': set(),
        'version_concerns': [],
        'update_patterns': []
    }
    
    # Extended list of comparators to check for
    comparators = ['<', '>', '=', '<=', '=<', '=>', '>=', '!=']
    
    processed_concerns = set()  
    processed_update_patterns = set()  # Track update patterns separately
    
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
        
        # === DETAILED VERSION CONCERNS DETECTION (PER VERSION) ===
        for field in ['version', 'lessThan', 'lessThanOrEqual']:
            if field not in version:
                continue
                
            field_value = version[field]
            
            # Skip None, empty, or non-processable values
            if field_value is None:
                continue
            
            # Handle string values
            if isinstance(field_value, str):
                # Skip empty strings
                if not field_value.strip():
                    continue
                    
                field_value_lower = field_value.lower()
                # Check ALL pattern types
                has_comparator = any(comp in field_value_lower for comp in comparators)
                has_text_pattern = any(text_comp in field_value_lower for text_comp in VERSION_TEXT_PATTERNS)
                
                update_patterns = [
                    # Alpha patterns
                    r'^(.+?)[\.\-_\s]*alpha[\.\-_\s]*(\d*)[\.\-_\s]*$',
                    r'^(.+?)[\.\-_\s]*a[\.\-_\s]*(\d+)[\.\-_\s]*$',
                    
                    # Beta patterns
                    r'^(.+?)[\.\-_\s]*beta[\.\-_\s]*(\d*)[\.\-_\s]*$',
                    r'^(.+?)[\.\-_\s]*b[\.\-_\s]*(\d+)[\.\-_\s]*$',
                    
                    # Release candidate patterns
                    r'^(.+?)[\.\-_\s]*rc[\.\-_\s]*(\d*)[\.\-_\s]*$',
                    r'^(.+?)[\.\-_\s]*release[\s\-_]+candidate[\.\-_\s]*(\d*)[\.\-_\s]*$',
                    
                    # Patch patterns
                    r'^(.+?)[\.\-_\s]*patch[\.\-_\s]*(\d*)[\.\-_\s]*$',
                    r'^(.+?)[\.\-_\s]*p[\.\-_\s]*(\d+)[\.\-_\s]*$',
                    r'^(.+?)\.p(\d+)$', # Handle 3.1.0.p7
                    
                    # Hotfix patterns
                    r'^(.+?)[\.\-_\s]*hotfix[\.\-_\s]*(\d*)[\.\-_\s]*$',
                    r'^(.+?)[\.\-_\s]*hf[\.\-_\s]*(\d+)[\.\-_\s]*$',
                    
                    # Service pack patterns
                    r'^(.+?)[\.\-_\s]*service[\s\-_]+pack[\.\-_\s]*(\d*)[\.\-_]*$',
                    r'^(.+?)[\.\-_\s]*sp[\.\-_]*(\d+)[\.\-_]*$',
                    r'^(.+?)\.sp(\d+)$', # Handle 3.0.0.sp1
                    
                    # Update patterns
                    r'^(.+?)[\.\-_\s]*update[\.\-_\s]*(\d*)[\.\-_\s]*$',
                    r'^(.+?)[\.\-_\s]*upd[\.\-_\s]*(\d+)[\.\-_\s]*$',
                    
                    # Fix patterns
                    r'^(.+?)[\.\-_\s]*fix[\.\-_\s]*(\d+)[\.\-_\s]*$',
                    
                    # Revision patterns
                    r'^(.+?)[\.\-_\s]*revision[\.\-_\s]*(\d+)[\.\-_\s]*$',
                    r'^(.+?)[\.\-_\s]*rev[\.\-_\s]*(\d+)[\.\-_\s]*$'
                ]
                compiled_update_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in update_patterns]
                has_update_pattern = any(pattern.match(field_value) for pattern in compiled_update_patterns)
                
                # Collect all applicable concerns
                if has_comparator:
                    matching_comps = [comp for comp in comparators if comp in field_value_lower]
                    concern = f"Comparator in {field}: {field_value} (found: {', '.join(matching_comps)})"
                    processed_concerns.add(html.escape(concern))
                
                if has_text_pattern:
                    matching_patterns = [text_comp for text_comp in VERSION_TEXT_PATTERNS if text_comp in field_value_lower]
                    limited_patterns = matching_patterns[:3]
                    pattern_text = ', '.join(limited_patterns)
                    if len(matching_patterns) > 3:
                        pattern_text += f" (+{len(matching_patterns) - 3} more)"
                    concern = f"Text in {field}: {field_value} (patterns: {pattern_text})"
                    processed_concerns.add(html.escape(concern))
                
                # Add update pattern concerns
                if has_update_pattern:
                    characteristics['has_update_patterns'] = True  # Set the flag!
                    
                    # Use the transformation function to get the actual transformation
                    base_version, update_component, transformed_version = transform_version_with_update_pattern(field_value)
                    
                    if base_version and update_component and transformed_version:
                        # Show the actual transformation (before → after)
                        concern = f"Update pattern for {field}: {field_value} → {transformed_version}"
                        processed_update_patterns.add(html.escape(concern))
                    else:
                        # Fallback for patterns that match but don't transform (shouldn't happen)
                        matching_update_patterns = [pattern.pattern for pattern in compiled_update_patterns if pattern.match(field_value)]
                        pattern_names = []
                        for pattern in matching_update_patterns[:3]:  # Limit to 3
                            if 'patch' in pattern:
                                pattern_names.append('patch')
                            elif 'sp|service' in pattern:
                                pattern_names.append('service pack')
                            elif 'alpha' in pattern:
                                pattern_names.append('alpha')
                            elif 'beta' in pattern:
                                pattern_names.append('beta')
                            elif 'rc|release' in pattern:
                                pattern_names.append('release candidate')
                            elif 'hotfix|hf' in pattern:
                                pattern_names.append('hotfix')
                            elif 'update|upd' in pattern:
                                pattern_names.append('update')
                            elif 'fix' in pattern:
                                pattern_names.append('fix')
                            elif 'revision|rev' in pattern:
                                pattern_names.append('revision')
                        
                        if pattern_names:
                            concern = f"Update attribute content in {field}: {field_value} ({', '.join(set(pattern_names))})"
                            processed_update_patterns.add(html.escape(concern))
            
            # Handle dictionary values (nested version objects)
            elif isinstance(field_value, dict):
                # Recursively check nested string values
                for nested_key, nested_value in field_value.items():
                    if isinstance(nested_value, str) and nested_value.strip():
                        nested_value_lower = nested_value.lower()
                        
                        # Check nested values for concerns
                        if any(comp in nested_value_lower for comp in comparators):
                            concern = f"Comparator in {field}.{nested_key}: {nested_value}"
                            processed_concerns.add(html.escape(concern))
                        
                        if any(text_comp in nested_value_lower for text_comp in VERSION_TEXT_PATTERNS):
                            concern = f"Text in {field}.{nested_key}: {nested_value}"
                            processed_concerns.add(html.escape(concern))
                    
                    # Handle deeply nested structures
                    elif isinstance(nested_value, dict):
                        for deep_key, deep_value in nested_value.items():
                            if isinstance(deep_value, str) and deep_value.strip():
                                deep_value_lower = deep_value.lower()
                                if any(text_comp in deep_value_lower for text_comp in VERSION_TEXT_PATTERNS):
                                    concern = f"Text in {field}.{nested_key}.{deep_key}: {deep_value}"
                                    processed_concerns.add(html.escape(concern))
            
            # Handle list values (arrays of version objects)
            elif isinstance(field_value, list):
                for i, list_item in enumerate(field_value):
                    if isinstance(list_item, str) and list_item.strip():
                        list_item_lower = list_item.lower()
                        if any(text_comp in list_item_lower for text_comp in VERSION_TEXT_PATTERNS):
                            concern = f"Text in {field}[{i}]: {list_item}"
                            processed_concerns.add(html.escape(concern))
                    elif isinstance(list_item, dict):
                        for list_key, list_value in list_item.items():
                            if isinstance(list_value, str) and list_value.strip():
                                list_value_lower = list_value.lower()
                                if any(text_comp in list_value_lower for text_comp in VERSION_TEXT_PATTERNS):
                                    concern = f"Text in {field}[{i}].{list_key}: {list_value}"
                                    processed_concerns.add(html.escape(concern))
            
            # Log unexpected types
            elif field_value is not None:  
                logger.error(f"DataFrame type coercion detected in version field '{field}': expected string, got {type(field_value).__name__}. This indicates pandas DataFrame processing issue.", group="data_processing")
    
    # === MULTIPLE WILDCARD BRANCHES CHECK ===
    wildcard_branches = []
    for v in versions:
        if isinstance(v, dict) and v.get('version') == '*' and ('lessThan' in v or 'lessThanOrEqual' in v):
            branch_end = v.get('lessThan') or v.get('lessThanOrEqual')
            wildcard_branches.append(branch_end)
    
    if len(wildcard_branches) > 1:
        branch_ranges = ", ".join(wildcard_branches)
        processed_concerns.add(f"Multiple overlapping branch ranges with wildcard starts: {branch_ranges}")
    
    # === INCONSISTENT VERSION GRANULARITY CHECK ===
    version_granularities = {}  # Track different version granularity patterns
    base_versions = set()  # Track base versions (e.g., "3.3" from "3.3.0" or "3.3 Patch 1")
    version_examples = {}  # Track examples for each base version and granularity
    
    for v in versions:
        if isinstance(v, dict) and 'version' in v and isinstance(v['version'], str):
            version_str = v['version'].strip()
            if not version_str or version_str == '*':
                continue
                
            # Extract base version number (before any patches/updates)
            # Handle cases like "3.0.0 p1", "3.3 Patch 1", "3.1.0", etc.
            base_match = re.match(r'^(\d+\.\d+)(?:\.(\d+))?', version_str)
            if base_match:
                major_minor = base_match.group(1)  # e.g., "3.0", "3.3"
                patch_part = base_match.group(2)   # e.g., "0" from "3.0.0", None from "3.3"
                
                # Determine granularity: 2-part (3.3) vs 3-part (3.3.0)
                if patch_part is not None:
                    granularity = "3-part"
                else:
                    granularity = "2-part"
                
                # Track this base version and its granularity
                base_versions.add(major_minor)
                if major_minor not in version_granularities:
                    version_granularities[major_minor] = set()
                    version_examples[major_minor] = {}
                version_granularities[major_minor].add(granularity)
                
                # Store examples for this granularity
                if granularity not in version_examples[major_minor]:
                    version_examples[major_minor][granularity] = []
                if len(version_examples[major_minor][granularity]) < 2:  # Limit to 2 examples
                    version_examples[major_minor][granularity].append(version_str)
    
    # Check for inconsistent granularity within the same base version
    inconsistent_bases = []
    for base_version, granularities in version_granularities.items():
        if len(granularities) > 1:
            granularity_descriptions = []
            for granularity in sorted(list(granularities)):
                examples = version_examples[base_version][granularity]
                examples_str = ", ".join(examples)
                granularity_descriptions.append(f"{granularity} ({examples_str})")
            
            inconsistent_bases.append(f"{base_version}: {', '.join(granularity_descriptions)}")
    
    if inconsistent_bases:
        concern = f"Inconsistent version granularity: {', '.join(inconsistent_bases)}"
        processed_concerns.add(concern)
    
    # === ASSIGN COLLECTED DATA TO CHARACTERISTICS ===
    # Assign version concerns to characteristics
    characteristics['version_concerns'] = list(processed_concerns)
    # Assign update patterns to characteristics
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

def analyze_data_for_smart_defaults(raw_platform_data):
    """Generate intelligent settings using centralized analysis"""
    characteristics = analyze_version_characteristics(raw_platform_data)
    
    # Special case: If update patterns exist but version ranges are detected,
    # do not enable update patterns by default
    enable_update_patterns = characteristics['has_update_patterns']
    if enable_update_patterns and raw_platform_data:
        versions = raw_platform_data.get('versions', [])
        has_ranges = any(v and isinstance(v, dict) and ('lessThan' in v or 'lessThanOrEqual' in v) for v in versions)
        if has_ranges:
            enable_update_patterns = False
    
    # When wildcards are present, disable multiple branches processing
    # to prevent rule conflicts.
    enable_multiple_branches = characteristics['has_multiple_branches']
    if characteristics['has_wildcards'] and enable_multiple_branches:
        enable_multiple_branches = False
    
    return {
        'enableWildcardExpansion': characteristics['has_wildcards'],
        'enableVersionChanges': characteristics['has_version_changes'],
        'enableSpecialVersionTypes': characteristics['has_special_version_types'],
        'enableInverseStatus': characteristics['has_inverse_status'],
        'enableMultipleBranches': enable_multiple_branches,
        'enableMixedStatus': characteristics['has_mixed_status'],
        'enableGapProcessing': characteristics['needs_gap_processing'],
        'enableUpdatePatterns': enable_update_patterns
    }

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

def transform_version_with_update_pattern(version_str: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Transform a version string with update patterns to match JavaScript modular_rules.js logic.
    Returns a tuple: (base_version, update_component, transformed_version) or (None, None, None) if no match.
    
    This function mirrors the JavaScript updatePatterns logic exactly.
    """
    if not version_str:
        return None, None, None
    
    # Enhanced pattern definitions with proper ordering (specific patterns first)
    # Matches the JavaScript updatePatterns exactly
    update_patterns = [
        # SPACE-SEPARATED PATTERNS (for real-world CVE data formats)
        # These must come first as they're more specific than the general patterns below
        
        # Space-separated patch patterns (most common in CVE data)
        {'pattern': r'^(.+?)\s+p(\d+)$', 'type': 'patch'},  # Handle "3.0.0 p1", "3.1.0 p2"
        {'pattern': r'^(.+?)\s+patch\s*(\d+)$', 'type': 'patch'},  # Handle "3.3 Patch 1", "3.3 Patch 2"
        {'pattern': r'^(.+?)\s+Patch\s*(\d+)$', 'type': 'patch'},  # Handle "3.3 Patch 1" (capitalized)
        
        # Space-separated service pack patterns
        {'pattern': r'^(.+?)\s+sp(\d+)$', 'type': 'sp'},  # Handle "2.0.0 sp1"
        {'pattern': r'^(.+?)\s+service\s+pack\s*(\d+)$', 'type': 'sp'},  # Handle "2.0.0 service pack 1"
        {'pattern': r'^(.+?)\s+Service\s+Pack\s*(\d+)$', 'type': 'sp'},  # Handle "2.0.0 Service Pack 1"
        
        # Space-separated hotfix patterns
        {'pattern': r'^(.+?)\s+hotfix\s*(\d+)$', 'type': 'hotfix'},  # Handle "3.0.0 hotfix 1"
        {'pattern': r'^(.+?)\s+Hotfix\s*(\d+)$', 'type': 'hotfix'},  # Handle "3.0.0 Hotfix 1"
        {'pattern': r'^(.+?)\s+hf(\d+)$', 'type': 'hotfix'},  # Handle "3.0.0 hf1"
        
        # Space-separated update patterns
        {'pattern': r'^(.+?)\s+update\s*(\d+)$', 'type': 'update'},  # Handle "3.0.0 update 1"
        {'pattern': r'^(.+?)\s+Update\s*(\d+)$', 'type': 'update'},  # Handle "3.0.0 Update 1"
        {'pattern': r'^(.+?)\s+upd(\d+)$', 'type': 'update'},  # Handle "3.0.0 upd1"
        
        # Space-separated beta patterns
        {'pattern': r'^(.+?)\s+beta\s*(\d*)$', 'type': 'beta'},  # Handle "1.0.0 beta", "1.0.0 beta 1"
        {'pattern': r'^(.+?)\s+Beta\s*(\d*)$', 'type': 'beta'},  # Handle "1.0.0 Beta 1"
        {'pattern': r'^(.+?)\s+b(\d+)$', 'type': 'beta'},  # Handle "1.0.0 b1"
        
        # Space-separated alpha patterns
        {'pattern': r'^(.+?)\s+alpha\s*(\d*)$', 'type': 'alpha'},  # Handle "1.0.0 alpha", "1.0.0 alpha 1"
        {'pattern': r'^(.+?)\s+Alpha\s*(\d*)$', 'type': 'alpha'},  # Handle "1.0.0 Alpha 1"
        {'pattern': r'^(.+?)\s+a(\d+)$', 'type': 'alpha'},  # Handle "1.0.0 a1"
        
        # Release candidate patterns
        {'pattern': r'^(.+?)\s+rc\s*(\d*)$', 'type': 'rc'},  # Handle "1.0.0 rc", "1.0.0 rc 1"
        {'pattern': r'^(.+?)\s+RC\s*(\d*)$', 'type': 'rc'},  # Handle "1.0.0 RC 1"
        {'pattern': r'^(.+?)\s+release\s+candidate\s*(\d*)$', 'type': 'rc'},  # Handle "1.0.0 release candidate 1"
        {'pattern': r'^(.+?)\s+Release\s+Candidate\s*(\d*)$', 'type': 'rc'},  # Handle "1.0.0 Release Candidate 1"
        
        # Space-separated fix patterns
        {'pattern': r'^(.+?)\s+fix\s*(\d+)$', 'type': 'fix'},  # Handle "3.0.0 fix 1"
        {'pattern': r'^(.+?)\s+Fix\s*(\d+)$', 'type': 'fix'},  # Handle "3.0.0 Fix 1"
        
        # Space-separated revision patterns
        {'pattern': r'^(.+?)\s+revision\s*(\d+)$', 'type': 'revision'},  # Handle "3.0.0 revision 1"
        {'pattern': r'^(.+?)\s+Revision\s*(\d+)$', 'type': 'revision'},  # Handle "3.0.0 Revision 1"
        {'pattern': r'^(.+?)\s+rev\s*(\d+)$', 'type': 'revision'},  # Handle "3.0.0 rev 1"
        {'pattern': r'^(.+?)\s+Rev\s*(\d+)$', 'type': 'revision'},  # Handle "3.0.0 Rev 1"
        
        # TRADITIONAL DOT/DASH/UNDERSCORE PATTERNS (existing patterns)
        
        # Service pack patterns (most specific first)
        {'pattern': r'^(.+?)\.sp(\d+)$', 'type': 'sp'},  # Handle 3.0.0.sp1
        {'pattern': r'^(.+?)[\.\-_]*service[\s\-_]+pack[\.\-_]*(\d*)[\.\-_]*$', 'type': 'sp'},
        {'pattern': r'^(.+?)[\.\-_]*sp[\.\-_]*(\d+)[\.\-_]*$', 'type': 'sp'},
        
        # Patch patterns (handle p-notation specifically)
        {'pattern': r'^(.+?)\.p(\d+)$', 'type': 'patch'},  # Handle 3.1.0.p7
        {'pattern': r'^(.+?)[\.\-_]*patch[\.\-_]*(\d*)[\.\-_]*$', 'type': 'patch'},
        
        # Beta patterns (handle .1 notation specifically)
        {'pattern': r'^(.+?)-beta\.(\d+)$', 'type': 'beta'},  # Handle 1.0.0-beta.1
        {'pattern': r'^(.+?)[\.\-_]*beta[\.\-_]*(\d*)[\.\-_]*$', 'type': 'beta'},
        {'pattern': r'^(.+?)[\.\-_]*b[\.\-_]*(\d+)[\.\-_]*$', 'type': 'beta'},
        
        # Alpha patterns
        {'pattern': r'^(.+?)-alpha\.(\d+)$', 'type': 'alpha'},  # Handle 1.0.0-alpha.1
        {'pattern': r'^(.+?)[\.\-_]*alpha[\.\-_]*(\d*)[\.\-_]*$', 'type': 'alpha'},
        {'pattern': r'^(.+?)[\.\-_]*a[\.\-_]*(\d+)[\.\-_]*$', 'type': 'alpha'},
        
        # Release candidate patterns
        {'pattern': r'^(.+?)-rc\.(\d+)$', 'type': 'rc'},  # Handle 1.0.0-rc.1
        {'pattern': r'^(.+?)[\.\-_]*rc[\.\-_]*(\d*)[\.\-_]*$', 'type': 'rc'},
        {'pattern': r'^(.+?)[\.\-_]*release[\s\-_]+candidate[\.\-_]*(\d*)[\.\-_]*$', 'type': 'rc'},
        
        # Hotfix patterns (handle .2 notation specifically)
        {'pattern': r'^(.+?)-hotfix\.(\d+)$', 'type': 'hotfix'},  # Handle 2.1.0-hotfix.2
        {'pattern': r'^(.+?)[\.\-_]*hotfix[\.\-_]*(\d*)[\.\-_]*$', 'type': 'hotfix'},
        {'pattern': r'^(.+?)[\.\-_]*hf[\.\-_]*(\d+)[\.\-_]*$', 'type': 'hotfix'},
        
        # Patch patterns with specific numbering (handle .5 notation)
        {'pattern': r'^(.+?)-patch\.(\d+)$', 'type': 'patch'},  # Handle 2.0.0-patch.5
        
        # Update patterns
        {'pattern': r'^(.+?)[\.\-_]*update[\.\-_]*(\d*)[\.\-_]*$', 'type': 'update'},
        {'pattern': r'^(.+?)[\.\-_]*upd[\.\-_]*(\d+)[\.\-_]*$', 'type': 'update'},
        
        # Fix patterns
        {'pattern': r'^(.+?)[\.\-_]*fix[\.\-_]*(\d+)[\.\-_]*$', 'type': 'fix'},
        
        # Revision patterns
        {'pattern': r'^(.+?)[\.\-_]*revision[\.\-_]*(\d+)[\.\-_]*$', 'type': 'revision'},
        {'pattern': r'^(.+?)[\.\-_]*rev[\.\-_]*(\d+)[\.\-_]*$', 'type': 'revision'}
    ]
    
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

# ===== BADGE CREATION FUNCTIONS =====

def create_json_generation_rules_badge(table_index: int, raw_platform_data: Dict, vendor: str, product: str, row: Dict) -> Optional[str]:
    """
    Create a unified JSON Generation Rules badge that combines wildcard generation and update patterns.
    
    Args:
        table_index: The table index for unique identification
        raw_platform_data: The raw platform data to analyze
        vendor: The vendor name
        product: The product name
        row: The complete row data for header information
    
    Returns:
        HTML string for the badge, or None if no applicable rules detected
    """
    # Analyze both wildcard generation and update patterns
    wildcard_info = analyze_wildcard_generation(raw_platform_data)
    update_info = analyze_update_patterns(raw_platform_data)
    
    # Check if any rules apply
    has_wildcards = wildcard_info['has_wildcards']
    has_update_patterns = update_info['has_update_patterns']
    
    if not has_wildcards and not has_update_patterns:
        return None
    
    # Build modal content with tabs for each rule type
    modal_content = {
        "rules": [],
        "summary": {
            "total_rules": 0,
            "rule_types": []
        }
    }
    
    # Add wildcard generation tab if applicable
    if has_wildcards and wildcard_info['wildcard_transformations']:
        wildcard_count = len(wildcard_info['wildcard_transformations'])
        modal_content["rules"].append({
            "type": "wildcardGeneration",
            "title": "Wildcard Generation",
            "count": wildcard_count,
            "transformations": []
        })
        
        # Collect all version entries for context matching (legacy logic)
        versions = raw_platform_data.get('versions', [])
        
        # Group transformations by field for better organization (legacy logic)
        field_groups = {}
        for transformation in wildcard_info['wildcard_transformations']:
            field = transformation['field']
            if field not in field_groups:
                field_groups[field] = []
            field_groups[field].append(transformation)
        
        # Process each field group for the modal (legacy logic)
        for field in sorted(field_groups.keys()):
            transformations = field_groups[field]
            
            field_name = field.replace('lessThanOrEqual', 'Upper Bound (≤)').replace('lessThan', 'Upper Bound (<)').replace('version', 'Version')
            
            for transformation in transformations:
                original = transformation['original']
                start_version = transformation['start_version']
                end_version = transformation['end_version']
                field_key = transformation['field']
                
                # Find the complete version entry that contains this wildcard pattern (legacy logic)
                complete_entry = None
                for version in versions:
                    if not version or not isinstance(version, dict):
                        continue
                    if field_key in version and version[field_key] == original:
                        complete_entry = version
                        break
                
                # Determine the derivation description based on field type (legacy logic)
                if field_key == 'lessThanOrEqual':
                    derivation_desc = "Derive Upper Bound (excluding)"
                elif field_key == 'lessThan':
                    derivation_desc = "Derive Upper Bound (excluding)"
                elif field_key == 'version':
                    derivation_desc = "Derive Version Range"
                else:
                    derivation_desc = "Derive Range"
                
                # Create realistic CPE match object transformations (enhanced legacy logic)
                if original == "*":
                    # Global wildcard transformation
                    input_json = complete_entry if complete_entry else {field_key: original}
                    if end_version == '∞':
                        output_json = {"versionStartIncluding": complete_entry.get('version', '0') if complete_entry else '0'}
                    else:
                        output_json = {
                            "versionStartIncluding": complete_entry.get('version', '0') if complete_entry else '0',
                            "versionEndExcluding": end_version
                        }
                    explanation = f"Global wildcard '*' uses version '{complete_entry.get('version', '0') if complete_entry else '0'}' as start, expands to unbounded or bounded range"
                else:
                    # Specific wildcard pattern transformation
                    input_json = complete_entry if complete_entry else {field_key: original}
                    version_value = complete_entry.get('version') if complete_entry else 'unknown'
                    
                    # For lessThan/lessThanOrEqual fields, the actual transformation uses the version field as the start (legacy logic)
                    if field_key in ['lessThanOrEqual', 'lessThan']:
                        output_json = {
                            "versionStartIncluding": version_value,
                            "versionEndExcluding": end_version
                        }
                        explanation = f"Uses version '{version_value}' as range start, wildcard pattern '{original}' expands upper bound to '{end_version}'"
                    else:  # version field with wildcard
                        # For version field wildcards, use the calculated range
                        output_json = {"versionStartIncluding": start_version, "versionEndExcluding": end_version}
                        explanation = f"Version wildcard pattern '{original}' expands to range [{start_version}, {end_version})"
                
                modal_content["rules"][0]["transformations"].append({
                    "field": field_key,
                    "field_display": field_name,
                    "derivation_desc": derivation_desc,
                    "input": input_json,
                    "output": output_json,
                    "explanation": explanation
                })
        
        modal_content["summary"]["rule_types"].append("Wildcard Generation")
        modal_content["summary"]["total_rules"] += 1
    
    # Add update patterns tab if applicable
    if has_update_patterns and update_info['update_transformations']:
        update_count = len(update_info['update_transformations'])
        update_patterns_rule = {
            "type": "updatePatterns",
            "title": "Update Pattern Detection",
            "count": update_count,
            "transformations": []
        }
        modal_content["rules"].append(update_patterns_rule)
        
        # Get the index of the update patterns rule we just added
        update_patterns_index = len(modal_content["rules"]) - 1
        
        # Process update pattern transformations
        for transformation in update_info['update_transformations']:
            field_display = transformation['field'].replace('version', 'Version').replace('lessThanOrEqual', 'Less Than Or Equal').replace('lessThan', 'Less Than')
            
            input_json = {transformation['field']: transformation['original']}
            output_json = {
                "version": transformation['base_version'],
                "update": transformation['update_component']
            }
            
            explanation = f"Update pattern '{transformation['original']}' splits into base version and update component"
            if transformation.get('blocked_by_ranges'):
                explanation += " (Note: Blocked by version ranges in data)"
            
            modal_content["rules"][update_patterns_index]["transformations"].append({
                "field": transformation['field'],
                "field_display": field_display,
                "input": input_json,
                "output": output_json,
                "explanation": explanation,
                "pattern_type": transformation['pattern_type']
            })
        
        modal_content["summary"]["rule_types"].append("Update Pattern Detection")
        modal_content["summary"]["total_rules"] += 1
    
    # Register the modal content
    register_platform_notification_data(table_index, 'jsonGenerationRules', modal_content)
    
    # Create tooltip
    rule_types = " + ".join(modal_content["summary"]["rule_types"])
    total_transformations = sum(rule.get("count", 0) for rule in modal_content["rules"])
    tooltip = f'JSON Generation Rules detected - {rule_types} ({total_transformations} transformation(s)). Click for detailed examples.'
    
    # Create the badge HTML with proper header format
    source_role = row.get('sourceRole', 'Unknown')
    
    # Build header components
    header_parts = []
    header_parts.append(source_role)
    
    # Add vendor/product
    if vendor and vendor != 'unknown':
        header_parts.append(vendor)
    if product and product != 'unknown':
        header_parts.append(product)
    
    # Add other relevant identifiers
    if 'packageName' in raw_platform_data and raw_platform_data['packageName']:
        header_parts.append(raw_platform_data['packageName'])
    elif 'repo' in raw_platform_data and raw_platform_data['repo']:
        header_parts.append(raw_platform_data['repo'])
    
    # Format as: Platform Entry X (CNA, SourceID, Vendor/Product/PackageName/etc.)
    header_identifier = f"Platform Entry {table_index} ({', '.join(header_parts)})"
    
    badge_html = f'<span class="badge modal-badge bg-warning" onclick="BadgeModalManager.openJsonGenerationRulesModal(\'{table_index}\', \'{header_identifier}\')" title="{tooltip}">⚙️ JSON Generation Rules</span> '
    
    return badge_html

# ===== SUPPORTING INFORMATION MODAL SYSTEM =====

def create_supporting_information_badge(table_index: int, row: Dict, platform_metadata: Dict, 
                                       raw_platform_data: Dict, characteristics: Dict,
                                       platform_format_type: str, readable_format_type: str,
                                       vendor: str, product: str, nvd_source_data: Dict) -> Optional[str]:
    """
    Create a unified Supporting Information badge that consolidates Standard and Info badges.
    
    Args:
        table_index: The table index for unique identification
        row: The complete row data
        platform_metadata: Platform metadata from the row
        raw_platform_data: The raw platform data
        characteristics: Version characteristics analysis
        platform_format_type: The platform format type
        readable_format_type: Human-readable format type
        vendor: The vendor name
        product: The product name
        nvd_source_data: NVD source data for lookups
    
    Returns:
        HTML string for the badge, or None if no supporting information detected
    """
    # Collect all supporting information
    supporting_info = {
        "tabs": [],
        "summary": {
            "total_items": 0,
            "categories": []
        }
    }
    
    # === VERSIONS ARRAY DETAILS TAB ===
    versions_details = []
    
    # 1. CVE Affected CPES Data
    cpes_array = []
    has_cpe_array = platform_metadata.get('hasCPEArray', False)
    if has_cpe_array and 'cpes' in raw_platform_data and isinstance(raw_platform_data['cpes'], list):
        cpes_array = [cpe for cpe in raw_platform_data['cpes'] if cpe and isinstance(cpe, str) and cpe.startswith('cpe:')]
        if cpes_array:
            cpe_count = len(cpes_array)
            versions_details.append({
                "title": "CVE Affected CPES Data",
                "content": f"{cpe_count} CPEs detected",
                "details": f"Versions array contains {cpe_count} CPEs from affected entry",
                "cpes": cpes_array,
                "type": "cpe_data"
            })
    
    # 2. Versions Array Structure
    if 'versions' in raw_platform_data and isinstance(raw_platform_data['versions'], list):
        versions_array = raw_platform_data['versions']
        if versions_array:
            versions_details.append({
                "title": "Versions Array Structure",
                "content": f"{len(versions_array)} version entries",
                "details": "Complete structure of the versions array from platform data",
                "versions_array": versions_array,
                "type": "versions_structure"
            })
    
    # Add versions tab (first priority)
    if versions_details:
        supporting_info["tabs"].append({
            "id": "versions",
            "title": "Versions Array Details",
            "icon": "fas fa-code-branch",
            "items": versions_details
        })
        supporting_info["summary"]["categories"].append("Versions Array Details")
    
    # === SEARCH OPERATIONS TAB ===
    search_operations = []
    
    # 1. CPE Base String Searches
    cpe_base_strings = platform_metadata.get('cpeBaseStrings', [])
    culled_cpe_strings = platform_metadata.get('culledCpeBaseStrings', [])
    
    if cpe_base_strings or culled_cpe_strings:
        used_count = len(cpe_base_strings)
        culled_count = len(culled_cpe_strings)
        
        search_operations.append({
            "title": "CPE Base String Processing",
            "content": f"{used_count} used, {culled_count} culled",
            "details": "CPE base strings generated and searched for platform matching",
            "used_strings": sort_cpe_strings_for_tooltip(cpe_base_strings),
            "culled_strings": culled_cpe_strings,
            "used_count": used_count,
            "culled_count": culled_count,
            "type": "cpe_searches"
        })
    
    # Add search tab (second priority)
    if search_operations:
        supporting_info["tabs"].append({
            "id": "search",
            "title": "CPE Base Strings Searched",
            "icon": "fas fa-search",
            "items": search_operations
        })
        supporting_info["summary"]["categories"].append("CPE Base Strings Searched")
    
    # === DATA TRANSFORMATIONS TAB ===
    transformations = []
    
    # 1. Source to CPE Transformations Applied
    try:
        from . import processData  # Import here to avoid circular import
    except ImportError:
        logger.warning("Could not import processData module", group="badge_modal")
    
    curation_tracking = platform_metadata.get('cpeCurationTracking', {})
    unicode_normalization_details = platform_metadata.get('unicodeNormalizationDetails', {})
    unicode_normalization_used = platform_metadata.get('unicodeNormalizationApplied', False)
    
    has_curation = bool(curation_tracking)
    has_unicode_details = bool(unicode_normalization_details.get('transformations') or unicode_normalization_details.get('skipped_fields'))
    has_legacy_unicode = unicode_normalization_used and not has_unicode_details
    
    if has_curation or has_unicode_details or has_legacy_unicode:
        transformation_details = {
            "title": "Source to CPE Transformations",
            "content": "Applied to normalize source data",
            "details": "Transformations applied to convert source vulnerability data to CPE format",
            "type": "source_transformations"
        }
        
        # Collect transformation details
        all_transformations = []
        
        # Unicode normalization details
        if has_unicode_details:
            unicode_transforms = unicode_normalization_details.get('transformations', [])
            unicode_skipped = unicode_normalization_details.get('skipped_fields', [])
            
            for transform in unicode_transforms:
                all_transformations.append({
                    "category": "Unicode Normalization",
                    "field": transform['field'].replace('_', ' ').title(),
                    "original": transform['original'],
                    "transformed": transform['normalized'],
                    "type": "unicode"
                })
            
            for skipped in unicode_skipped:
                all_transformations.append({
                    "category": "Unicode Normalization",
                    "field": skipped['field'].replace('_', ' ').title(),
                    "original": skipped['original'],
                    "transformed": "[SKIPPED]",
                    "reason": skipped['reason'],
                    "type": "unicode_skipped"
                })
        
        # Legacy unicode normalization
        elif has_legacy_unicode:
            all_transformations.append({
                "category": "Unicode Normalization",
                "field": "General",
                "original": "Various Unicode characters",
                "transformed": "ASCII equivalents",
                "type": "unicode_legacy"
            })
        
        # Curation tracking details
        if has_curation:
            for field_name, modifications in curation_tracking.items():
                display_name = field_name.replace('_', ' ').title()
                for mod in modifications:
                    all_transformations.append({
                        "category": "Field Curation",
                        "field": display_name,
                        "original": mod['original'],
                        "transformed": mod['curated'],
                        "type": "curation"
                    })
        
        transformation_details["transformations"] = all_transformations
        transformations.append(transformation_details)
    
    # Add transformations tab (third priority)
    if transformations:
        supporting_info["tabs"].append({
            "id": "transformations",
            "title": "Data Transformations",
            "icon": "fas fa-exchange-alt",
            "items": transformations
        })
        supporting_info["summary"]["categories"].append("Data Transformations")
    
    # === API RESULTS TAB ===
    api_results = []
    
    # 1. CPE API Error Detection
    sorted_cpe_query_data = row.get('sortedCPEsQueryData', {})
    if sorted_cpe_query_data:
        cpe_error_messages = []
        invalid_cpe_count = 0
        successful_queries = 0
        
        for cpe_string, query_data in sorted_cpe_query_data.items():
            if isinstance(query_data, dict):
                if query_data.get('status') == 'invalid_cpe' or query_data.get('status') == 'error':
                    invalid_cpe_count += 1
                    error_msg = query_data.get('error_message', 'Unknown CPE API error')
                    cpe_error_messages.append({
                        "cpe": cpe_string,
                        "error": error_msg,
                        "status": query_data.get('status', 'unknown')
                    })
                else:
                    successful_queries += 1
        
        if invalid_cpe_count > 0 or successful_queries > 0:
            api_results.append({
                "title": "CPE API Query Results",
                "content": f"{successful_queries} successful, {invalid_cpe_count} errors",
                "details": f"NVD CPE API query results for {len(sorted_cpe_query_data)} CPE strings",
                "errors": cpe_error_messages,
                "successful_count": successful_queries,
                "type": "cpe_api_results"
            })
    
    # Add API results tab (fourth priority)
    if api_results:
        supporting_info["tabs"].append({
            "id": "api",
            "title": "API Results",
            "icon": "fas fa-server",
            "items": api_results
        })
        supporting_info["summary"]["categories"].append("API Results")
    
    # Check if we have any supporting information to display
    if not supporting_info["tabs"]:
        return None
    
    # Calculate total items across all tabs
    total_items = sum(len(tab["items"]) for tab in supporting_info["tabs"])
    supporting_info["summary"]["total_items"] = total_items
    
    # Register the modal content
    register_platform_notification_data(table_index, 'supportingInformation', supporting_info)
    
    # Create tooltip
    categories = " + ".join(supporting_info["summary"]["categories"])
    tooltip = f'Supporting Information available - {categories} ({total_items} item(s)). Click for detailed technical insights and debugging information.'
    
    # Create the badge HTML with proper header format
    source_role = row.get('sourceRole', 'Unknown')
    
    # Build header components
    header_parts = []
    header_parts.append(source_role)
    
    # Add vendor/product
    if vendor and vendor != 'unknown':
        header_parts.append(vendor)
    if product and product != 'unknown':
        header_parts.append(product)
    
    # Add other relevant identifiers
    if 'packageName' in raw_platform_data and raw_platform_data['packageName']:
        header_parts.append(raw_platform_data['packageName'])
    elif 'repo' in raw_platform_data and raw_platform_data['repo']:
        header_parts.append(raw_platform_data['repo'])
    
    # Format as: Platform Entry X (CNA, SourceID, Vendor/Product/PackageName/etc.)
    display_value = f"Platform Entry {table_index} ({', '.join(header_parts)})"
    
    badge_html = f'<span class="badge modal-badge bg-secondary" onclick="BadgeModalManager.openSupportingInformationModal(\'{table_index}\', \'{display_value}\')" title="{tooltip}">🔍 Supporting Information</span> '
    
    return badge_html

# ===== UTILITY FUNCTIONS =====

def sort_cpe_strings_for_tooltip(base_strings):
    """Sort CPE base strings for tooltip display in a logical order."""
    def get_sort_key(cpe_string):
        # Extract parts to use for sorting
        parts = cpe_string.split(':')
        if len(parts) < 12:
            # Not a valid CPE - sort to bottom
            return (9, cpe_string)
            
        # Get the key parts
        part_type = parts[2]  # 'a', 'o', 'h' or '*'
        vendor = parts[3]
        product = parts[4]
        has_specific_vendor = vendor != '*'
        has_specific_product = product != '*' and not product.startswith('*') and not product.endswith('*')
        has_wildcard_product = product != '*' and (product.startswith('*') or product.endswith('*')) 
        has_hardware_info = parts[11] != '*'  # targetHW field
        
        # Prioritize strings
        if "cpe:2.3:a:" in cpe_string and has_specific_vendor and has_specific_product:
            # Exact application CPE priority
            priority = 0
        elif part_type != '*' and has_specific_vendor and has_specific_product:
            # Other exact part type with specific vendor and product
            priority = 1
        elif has_hardware_info:
            # Hardware-specific CPE strings
            priority = 2
        elif has_specific_vendor and has_wildcard_product:
            # Vendor + wildcarded product
            priority = 3
        elif has_specific_vendor:
            # Vendor only
            priority = 4
        elif has_specific_product or has_wildcard_product:
            # Product only
            priority = 5
        else:
            # Generic patterns
            priority = 6
            
        return (priority, vendor, product, cpe_string)
    
    # Sort the strings using the custom sort key
    return sorted(base_strings, key=get_sort_key)

def strings_were_curated(original, curated):
    """Compare original string with curated string, ignoring insignificant differences"""
    # Remove trailing underscores that might be added/removed during formatting
    original = original.rstrip('_')
    curated = curated.rstrip('_')
    return original != curated

# ===== HTML GENERATION FUNCTIONS =====

def create_json_generation_settings_html(table_id, settings=None):
    """Creates settings HTML with intelligent defaults and detailed tooltips"""
    
    # Helper function to determine if checkbox should be checked
    def checked(setting_name):
        if settings and setting_name in settings:
            return 'checked' if settings[setting_name] else ''
        return 'checked'  # Default to checked if no specific setting
    
    html = f"""
    <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center" 
             style="cursor: pointer;"
             data-bs-toggle="collapse" 
             data-bs-target="#settingsCollapse_{table_id}">
            <h6 class="mb-0">
                <i class="fas fa-cog"></i> JSON Generation Settings
            </h6>
            <span class="arrow-icon">&uarr;</span>
        </div>
        <div id="settingsCollapse_{table_id}" class="collapse">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6 class="text-muted mb-2">Processing Features</h6>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableWildcards_{table_id}" 
                                   data-setting="enableWildcardExpansion"
                                   data-table-id="{table_id}" 
                                   {checked('enableWildcardExpansion')}>
                            <label class="form-check-label" for="enableWildcards_{table_id}" 
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Converts wildcard patterns into version ranges. For example, '5.4.*' becomes a range from '5.4.0' to '5.5.0' (exclusive). Useful when version data contains wildcard patterns that need to be expanded into precise ranges for matching.">
                                <small>Expand Wildcards 
                                    <span class="text-muted">(5.4.* → ranges)</span>
                                    <span class="feature-indicator" data-feature="hasWildcards"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableGaps_{table_id}" 
                                   data-setting="enableGapProcessing"
                                   data-table-id="{table_id}" 
                                   {checked('enableGapProcessing')}>
                            <label class="form-check-label" for="enableGaps_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Fills gaps between unaffected version ranges by inferring affected versions. For example, if 1.0-2.0 and 4.0-5.0 are unaffected, it infers that 2.1-3.9 is affected. Particularly useful when vulnerability data specifies what's NOT affected rather than what IS affected.">
                                <small>Fill Gaps 
                                    <span class="text-muted">(infer affected ranges)</span>
                                    <span class="feature-indicator" data-feature="hasGapProcessing"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enablePatches_{table_id}" 
                                   data-setting="enableVersionChanges"
                                   data-table-id="{table_id}" 
                                   {checked('enableVersionChanges')}>
                            <label class="form-check-label" for="enablePatches_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Processes version.changes arrays to extract patch and fix information. For example, if a version has changes: [status: 'fixed', at: '1.2.3'], it creates a vulnerable range from the base version up to (but not including) the fix version. Essential for handling detailed patching timelines.">
                                <small>Process Patches 
                                    <span class="text-muted">(version.changes)</span>
                                    <span class="feature-indicator" data-feature="hasVersionChanges"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableSpecialTypes_{table_id}" 
                                   data-setting="enableSpecialVersionTypes"
                                   data-table-id="{table_id}" 
                                   {checked('enableSpecialVersionTypes')}>
                            <label class="form-check-label" for="enableSpecialTypes_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Handles non-standard version types beyond semantic versioning. Examples include date-based versions (20231201), commit hashes (abc123def), custom version schemes, or version types marked with special versionType fields. Required when dealing with diverse software versioning schemes.">
                                <small>Special Version Types 
                                    <span class="text-muted">(dates, commits)</span>
                                    <span class="feature-indicator" data-feature="hasSpecialVersionTypes"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableMultipleBranches_{table_id}" 
                                   data-setting="enableMultipleBranches"
                                   data-table-id="{table_id}" 
                                   {checked('enableMultipleBranches')}>
                            <label class="form-check-label" for="enableMultipleBranches_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Handles products with multiple version families or branches (≥3 major.minor combinations). For example, a product with versions 1.0.x, 2.1.x, 3.0.x, and 4.2.x has multiple branches. Groups and processes each branch separately to handle complex version trees with parallel development streams.">
                                <small>Multiple Branches 
                                    <span class="text-muted">(≥3 version families)</span>
                                    <span class="feature-indicator" data-feature="hasMultipleBranches"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableUpdatePatterns_{table_id}" 
                                   data-setting="enableUpdatePatterns"
                                   data-table-id="{table_id}" 
                                   {checked('enableUpdatePatterns')}>
                            <label class="form-check-label" for="enableUpdatePatterns_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Recognizes and processes update patterns in version strings. Handles formats like '3.1.0 p7' (patch 7), '2.0.0 sp1' (service pack 1), '1.0.0-hotfix.2', or '4.0 update 3'. Transforms these into proper CPE format with update components for accurate vulnerability matching.">
                                <small>Update Pattern Processing 
                                    <span class="text-muted">(patch, service pack, hotfix)</span>
                                    <span class="feature-indicator" data-feature="hasUpdatePatterns"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <h6 class="text-muted mb-2">Status Processing</h6>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableInverseStatus_{table_id}" 
                                   data-setting="enableInverseStatus"
                                   data-table-id="{table_id}" 
                                   {checked('enableInverseStatus')}>
                            <label class="form-check-label" for="enableInverseStatus_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Handles cases where defaultStatus='unaffected' with explicit affected entries. Instead of assuming all versions are vulnerable, it processes only the specifically marked affected versions while treating everything else as unaffected. Common in advisories that list specific vulnerable versions.">
                                <small>Inverse Status 
                                    <span class="text-muted">(default unaffected)</span>
                                    <span class="feature-indicator" data-feature="hasInverseStatus"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableMixedStatus_{table_id}" 
                                   data-setting="enableMixedStatus"
                                   data-table-id="{table_id}" 
                                   {checked('enableMixedStatus')}>
                            <label class="form-check-label" for="enableMixedStatus_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Handles complex scenarios with both affected and multiple unaffected versions in the same dataset. Processes mixed status combinations where some versions are explicitly marked as affected while others are marked as unaffected. Useful for complex vulnerability patterns with scattered affected versions.">
                                <small>Mixed Status 
                                    <span class="text-muted">(multiple unaffected)</span>
                                    <span class="feature-indicator" data-feature="hasMixedStatus"></span>
                                    <i class="fas fa-info-circle text-muted ms-1"></i>
                                </small>
                            </label>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """
    
    return html.replace('\n', '')

def create_provenance_assistance_div(index, collapsed=True):
    """Creates a collapsible div for Provenance Assistance
    
    Args:
        index: The row index for unique IDs
        collapsed: Whether the div should be collapsed by default
    """
    collapse_class = "collapse" if collapsed else "collapse show"
    
    # Use simple HTML arrows
    arrow_icon = "&darr;" if collapsed else "&uarr;"
    
    html = f"""
    <div class="card mb-3">
        <div class="card-header d-flex justify-content-between align-items-center" 
             id="provenanceHeader_{index}" 
             data-bs-toggle="collapse" 
             data-bs-target="#provenanceCollapse_{index}" 
             style="cursor: pointer;">
            <h5 class="mb-0">
                Provenance Assistance
            </h5>
            <span class="arrow-icon">{arrow_icon}</span>
        </div>
        <div id="provenanceCollapse_{index}" class="{collapse_class}" aria-labelledby="provenanceHeader_{index}">
            <div class="card-body">
                <!-- Main container for all provenance elements -->
                <div class="d-flex flex-row flex-wrap gap-3">
                    <!-- Provenance links -->
                    <div id="provenanceLinks_{index}" class="provenance-links">
                        <!-- Link cards will be populated via JavaScript -->
                    </div>
                    
                    <!-- Description buttons -->
                    <div id="descriptionButtons_{index}" class="description-buttons">
                        <!-- Buttons will be populated via JavaScript -->
                    </div>
                </div>
                
                <!-- Dedicated area for displaying description content -->
                <div id="descriptionContent_{index}" class="description-content mt-3 border-top pt-3" style="display: none;">
                    <!-- Description content will be populated here when a button is clicked -->
                </div>
            </div>
        </div>
    </div>
    """
    
    return html.replace('\n', '')

def create_custom_cpe_builder_div(index, collapsed=True):
    """Creates a collapsible div for Custom CPE Builder
    
    Args:
        index: The row index for unique IDs
        collapsed: Whether the div should be collapsed by default
    """
    collapse_class = "collapse" if collapsed else "collapse show"
    
    # Use simple HTML arrows
    arrow_icon = "&darr;" if collapsed else "&uarr;"
    
    html = f"""
    <div class="card mb-3">
        <div class="card-header d-flex justify-content-between align-items-center" 
             id="customCPEBuilderHeader_{index}" 
             data-bs-toggle="collapse" 
             data-bs-target="#customCPEBuilderCollapse_{index}" 
             style="cursor: pointer;">
            <h5 class="mb-0">
                Custom CPE Builder
            </h5>
            <span class="arrow-icon">{arrow_icon}</span>
        </div>
        <div id="customCPEBuilderCollapse_{index}" class="{collapse_class}" aria-labelledby="customCPEBuilderHeader_{index}">
            <div class="card-body">
                <div id="customCPEBuilder-content-{index}" class="customCPEBuilder">
                    <!-- Content will be populated by custom_cpe_builder.js -->
                </div>
            </div>
        </div>
    </div>
    """
    
    return html.replace('\n', '')

# ===== GLOBAL STATE MANAGEMENT =====

# Store generated settings HTML for JavaScript access
JSON_SETTINGS_HTML = {}
INTELLIGENT_SETTINGS = {}

def _initialize_clean_state():
    """Initialize clean global state when module is imported"""
    global JSON_SETTINGS_HTML, INTELLIGENT_SETTINGS, GLOBAL_CPE_DATA_REGISTRY, PLATFORM_ENTRY_NOTIFICATION_REGISTRY
    JSON_SETTINGS_HTML = {}
    INTELLIGENT_SETTINGS = {}
    GLOBAL_CPE_DATA_REGISTRY = {
        'references': {},
        'sortingPriority': {},
        'registered_cpes': set()
    }
    PLATFORM_ENTRY_NOTIFICATION_REGISTRY = {
        'wildcardGeneration': {},
        'updatePatterns': {},
        'jsonGenerationRules': {},
        'supportingInformation': {}
    }

# Call initialization immediately
_initialize_clean_state()

def is_cpe_data_registered(cpe_base_string, data_type):
    """
    Check if CPE data is already registered.
    
    Args:
        cpe_base_string: The CPE base string
        data_type: The type of data ('references' or 'sortingPriority')
    
    Returns:
        bool: True if already registered
    """
    global GLOBAL_CPE_DATA_REGISTRY
    
    base_key_safe = cpe_base_string.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_").replace("*", "star")
    return base_key_safe in GLOBAL_CPE_DATA_REGISTRY[data_type]

def clear_global_html_state():
    """Clear global HTML generation state to prevent accumulation between CVE processing runs"""
    global JSON_SETTINGS_HTML, INTELLIGENT_SETTINGS
    
    # Clear badge and modal registries (now handled by external module)
    clear_all_registries()
    
    # Reinitialize local HTML state
    JSON_SETTINGS_HTML = {}
    INTELLIGENT_SETTINGS = {}
    
    logger.debug("Cleared global HTML state and badge/modal registries", group="page_generation")

def store_json_settings_html(table_id, raw_platform_data=None):
    """Store the JSON settings HTML for a table with intelligent defaults"""
    global JSON_SETTINGS_HTML, INTELLIGENT_SETTINGS
    
    # Ensure global dictionaries exist and are initialized
    if 'JSON_SETTINGS_HTML' not in globals() or JSON_SETTINGS_HTML is None:
        JSON_SETTINGS_HTML = {}
    if 'INTELLIGENT_SETTINGS' not in globals() or INTELLIGENT_SETTINGS is None:
        INTELLIGENT_SETTINGS = {}
    
    # Analyze data to determine which checkboxes should be checked
    settings = analyze_data_for_smart_defaults(raw_platform_data) if raw_platform_data else {}
    
    # Store the HTML
    JSON_SETTINGS_HTML[table_id] = create_json_generation_settings_html(table_id, settings)
    
    # Store intelligent settings for JavaScript
    INTELLIGENT_SETTINGS[table_id] = settings

