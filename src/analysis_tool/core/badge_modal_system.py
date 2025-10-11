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
from typing import Dict, List, Tuple, Optional, Any, Set
import json
import re
import html
from ..logging.workflow_logger import get_logger
from ..logging.workflow_logger import get_logger

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
    'supportingInformation': {}, # table_index -> supporting information data
    'sourceDataConcerns': {},   # table_index -> source data quality concerns
    'aliasExtraction': {}      # table_index -> alias extraction data for curator functionality
}
# Global KB exclusions tracking
global_kb_exclusions = []

# ===== CONSTANTS AND PATTERNS =====
# Define placeholder values for non-version fields (vendor, product, platforms, packageName)
GENERAL_PLACEHOLDER_VALUES = [
    'unspecified', 'unknown', 'none', 'undefined', 'various',
    'n/a', 'not available', 'not applicable', 'unavailable',
    'na', 'nil', 'tbd', 'to be determined', 'pending',
    'not specified', 'not determined', 'not known', 'not listed',
    'not provided', 'missing', 'empty', 'null', '-',
    'see references', 'see advisory', 'check', 'noted', 'all'
]

# Define placeholder values specific to version fields (version, lessThan, changes.at)
VERSION_PLACEHOLDER_VALUES = [
    'unspecified', 'unknown', 'none', 'undefined', 'various',
    'n/a', 'not available', 'not applicable', 'unavailable',
    'na', 'nil', 'tbd', 'to be determined', 'pending',
    'not specified', 'not determined', 'not known', 'not listed',
    'not provided', 'missing', 'empty', 'null', '-', 'multiple versions',
    'see references', 'see advisory', 'check', 'noted'
    # Note: 'all' is NOT included here as it may be legitimate in version contexts
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
        'supportingInformation': {},
        'sourceDataConcerns': {},
        'aliasExtraction': {}
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

# ===== TEMPLATE DEDUPLICATION SYSTEM =====

def classify_count(count: int) -> str:
    """Classify counts into standard size categories for pattern recognition."""
    if count == 1:
        return "single"
    elif 2 <= count <= 5:
        return "small"
    elif 6 <= count <= 15:
        return "medium"
    else:  # 16+
        return "large"

def analyze_reference_patterns(ref_data: Dict) -> str:
    """
    Analyze reference data to generate a deterministic pattern key.
    
    Args:
        ref_data: Dictionary containing reference type data (advisor, vendor, patch, etc.)
        
    Returns:
        Pattern key string like "advisor:small|vendor:medium|patch:single|total:medium"
    """
    if not ref_data:
        return "empty"
    
    # Count references by type
    type_counts = {}
    total_refs = 0
    
    for ref_type, refs in ref_data.items():
        if isinstance(refs, list):
            count = len(refs)
            type_counts[ref_type] = count
            total_refs += count
        elif isinstance(refs, dict):
            # Handle nested reference structures
            count = len(refs)
            type_counts[ref_type] = count
            total_refs += count
    
    # Generate pattern components
    pattern_parts = []
    
    # Sort by type name for consistency
    for ref_type in sorted(type_counts.keys()):
        count = type_counts[ref_type]
        classification = classify_count(count)
        pattern_parts.append(f"{ref_type}:{classification}")
    
    # Add total count classification
    total_classification = classify_count(total_refs)
    pattern_parts.append(f"total:{total_classification}")
    
    return "|".join(pattern_parts)

def analyze_sorting_priority_patterns(sorting_data: Dict) -> str:
    """
    Analyze sorting priority data to generate a deterministic pattern key.
    
    Args:
        sorting_data: Dictionary containing searches, versions, statistics, confirmedMapping
        
    Returns:
        Pattern key like "searches:snapdragon,generic_wildcard|versions:5|stats:medium|confirmed:true"
    """
    if not sorting_data:
        return "empty"
    
    pattern_parts = []
    
    # Analyze search patterns
    if 'searches' in sorting_data and sorting_data['searches']:
        search_types = []
        searches = sorting_data['searches']
        
        # Detect search pattern types
        for search_key in searches.keys():
            if 'snapdragon' in search_key.lower():
                search_types.append('snapdragon')
            elif 'wildcard' in search_key.lower() or '*' in str(searches[search_key]):
                search_types.append('wildcard')
            elif 'exact' in search_key.lower():
                search_types.append('exact')
            else:
                search_types.append('generic')
        
        # Remove duplicates and sort for consistency
        unique_types = sorted(set(search_types))
        pattern_parts.append(f"searches:{','.join(unique_types)}")
    
    # Analyze version count
    if 'versions' in sorting_data and sorting_data['versions']:
        version_count = len(sorting_data['versions'])
        version_classification = classify_count(version_count)
        pattern_parts.append(f"versions:{version_classification}")
    
    # Analyze statistics
    if 'statistics' in sorting_data and sorting_data['statistics']:
        stats = sorting_data['statistics']
        if 'total_cpe_names' in stats:
            total_cpe_names = stats['total_cpe_names']
            stats_classification = classify_count(total_cpe_names)
            pattern_parts.append(f"stats:{stats_classification}")
    
    # Include confirmed mapping boolean
    has_confirmed = 'confirmedMapping' in sorting_data and sorting_data['confirmedMapping']
    pattern_parts.append(f"confirmed:{str(has_confirmed).lower()}")
    
    return "|".join(pattern_parts)

def analyze_wildcard_generation_patterns(wildcard_data: Dict) -> str:
    """
    Analyze wildcard generation data patterns for templating.
    
    Args:
        wildcard_data: Dictionary containing wildcard generation data
        
    Returns:
        Pattern key like "transformations:small|fields:medium|total_patterns:5"
    """
    if not wildcard_data:
        return "empty"
    
    pattern_parts = []
    
    # Analyze transformations count
    if 'wildcardGeneration' in wildcard_data and 'transformations' in wildcard_data['wildcardGeneration']:
        transformation_count = len(wildcard_data['wildcardGeneration']['transformations'])
        transformation_classification = classify_count(transformation_count)
        pattern_parts.append(f"transformations:{transformation_classification}")
    
    # Analyze summary data if available
    if 'wildcardGeneration' in wildcard_data and 'summary' in wildcard_data['wildcardGeneration']:
        summary = wildcard_data['wildcardGeneration']['summary']
        if 'fields_affected' in summary:
            fields_count = len(summary['fields_affected'])
            fields_classification = classify_count(fields_count)
            pattern_parts.append(f"fields:{fields_classification}")
        
        if 'total_patterns' in summary:
            total_patterns = summary['total_patterns']
            pattern_parts.append(f"total_patterns:{total_patterns}")
    
    # Check for other rule types
    rule_types = []
    if 'updatePatterns' in wildcard_data:
        rule_types.append('update')
    if 'versionRanges' in wildcard_data:
        rule_types.append('ranges')
    
    if rule_types:
        pattern_parts.append(f"rule_types:{','.join(sorted(rule_types))}")
    
    return "|".join(pattern_parts) if pattern_parts else "basic_wildcard"

def analyze_update_patterns_data_patterns(update_data: Dict) -> str:
    """
    Analyze update pattern data patterns for templating.
    
    Args:
        update_data: Dictionary containing update pattern data
        
    Returns:
        Pattern key like "transformations:medium|pattern_types:3|blocked:true"
    """
    if not update_data:
        return "empty"
    
    pattern_parts = []
    
    # Analyze transformations count
    if 'transformations' in update_data:
        transformation_count = len(update_data['transformations'])
        transformation_classification = classify_count(transformation_count)
        pattern_parts.append(f"transformations:{transformation_classification}")
        
        # Analyze pattern types diversity
        pattern_types = set()
        blocked_count = 0
        for transformation in update_data['transformations']:
            if 'pattern_type' in transformation:
                pattern_types.add(transformation['pattern_type'])
            if transformation.get('blocked_by_ranges', False):
                blocked_count += 1
        
        if pattern_types:
            pattern_types_count = len(pattern_types)
            pattern_parts.append(f"pattern_types:{pattern_types_count}")
        
        if blocked_count > 0:
            pattern_parts.append(f"blocked:{blocked_count}")
    
    return "|".join(pattern_parts) if pattern_parts else "basic_update"

def analyze_json_rules_patterns(rules_data: Dict) -> str:
    """
    Analyze JSON generation rules patterns for templating.
    
    Args:
        rules_data: Dictionary containing JSON generation rules data
        
    Returns:
        Pattern key like "rules:small|types:medium|total_transformations:15"
    """
    if not rules_data:
        return "empty"
    
    pattern_parts = []
    
    # Analyze rules count and types
    if 'rules' in rules_data:
        rules_count = len(rules_data['rules'])
        rules_classification = classify_count(rules_count)
        pattern_parts.append(f"rules:{rules_classification}")
        
        # Count different rule types
        rule_types = set()
        total_transformations = 0
        for rule in rules_data['rules']:
            if 'type' in rule:
                rule_types.add(rule['type'])
            if 'transformations' in rule:
                total_transformations += len(rule['transformations'])
        
        if rule_types:
            rule_types_count = len(rule_types)
            rule_types_classification = classify_count(rule_types_count)
            pattern_parts.append(f"types:{rule_types_classification}")
        
        if total_transformations > 0:
            pattern_parts.append(f"total_transformations:{total_transformations}")
    
    # Analyze summary data if available
    if 'summary' in rules_data:
        summary = rules_data['summary']
        if 'total_rules' in summary:
            total_rules = summary['total_rules']
            pattern_parts.append(f"summary_rules:{total_rules}")
    
    return "|".join(pattern_parts) if pattern_parts else "basic_rules"

def analyze_supporting_info_patterns(supporting_data: Dict) -> str:
    """
    Analyze supporting information patterns for templating.
    
    Args:
        supporting_data: Dictionary containing supporting information data
        
    Returns:
        Pattern key like "categories:small|total_items:medium|tab_count:3"
    """
    if not supporting_data:
        return "empty"

    pattern_parts = []
    
    # Check if this data contains version-specific content that should not be templated
    has_version_data = False
    if 'tabs' in supporting_data:
        for tab in supporting_data['tabs']:
            if 'items' in tab:
                for item in tab['items']:
                    # Check if this item contains version array data
                    if (item.get('type') == 'versions_structure' and 
                        'versions_array' in item and 
                        item['versions_array']):
                        has_version_data = True
                        break
            if has_version_data:
                break
    
    # If this supporting information contains version data, make it unique to prevent templating
    if has_version_data:
        # Generate a unique pattern that includes the actual version data hash
        import hashlib
        import json
        data_hash = hashlib.md5(json.dumps(supporting_data, sort_keys=True).encode()).hexdigest()[:8]
        return f"version_specific:{data_hash}"
    
    # For non-version data, use the original pattern analysis
    # Analyze summary data
    if 'summary' in supporting_data:
        summary = supporting_data['summary']
        
        if 'categories' in summary:
            categories_count = len(summary['categories'])
            categories_classification = classify_count(categories_count)
            pattern_parts.append(f"categories:{categories_classification}")
        
        if 'total_items' in summary:
            total_items = summary['total_items']
            items_classification = classify_count(total_items)
            pattern_parts.append(f"total_items:{items_classification}")
    
    # Analyze tab structure
    if 'tabs' in supporting_data:
        tab_count = len(supporting_data['tabs'])
        pattern_parts.append(f"tab_count:{tab_count}")
        
        # Analyze content types in tabs (excluding version-specific types)
        content_types = set()
        for tab in supporting_data['tabs']:
            if 'items' in tab:
                for item in tab['items']:
                    item_type = item.get('type', 'unknown')
                    # Skip version-specific types from pattern analysis
                    if item_type not in ['versions_structure']:
                        content_types.add(item_type)
        
        if content_types:
            content_types_count = len(content_types)
            pattern_parts.append(f"content_types:{content_types_count}")
    
    return "|".join(pattern_parts) if pattern_parts else "basic_supporting"

def analyze_json_settings_html_patterns(html_content: str) -> str:
    """
    Analyze JSON Generation Settings HTML patterns for templating.
    
    Args:
        html_content: The HTML string content for JSON generation settings
        
    Returns:
        Pattern key like "checkboxes:9|tooltips:9|sections:2|collapse:true"
    """
    if not html_content:
        return "empty"
    
    pattern_parts = []
    
    # Count checkboxes (form-check-input elements)
    checkbox_count = html_content.count('class="form-check-input row-setting"')
    checkbox_classification = classify_count(checkbox_count)
    pattern_parts.append(f"checkboxes:{checkbox_classification}")
    
    # Count tooltips (data-bs-toggle="tooltip" elements)
    tooltip_count = html_content.count('data-bs-toggle="tooltip"')
    tooltip_classification = classify_count(tooltip_count)
    pattern_parts.append(f"tooltips:{tooltip_classification}")
    
    # Count sections (col-md-6 divisions)
    section_count = html_content.count('class="col-md-6"')
    pattern_parts.append(f"sections:{section_count}")
    
    # Check for collapse functionality
    has_collapse = 'data-bs-toggle="collapse"' in html_content
    pattern_parts.append(f"collapse:{str(has_collapse).lower()}")
    
    # Count different feature types by analyzing checkbox IDs
    feature_types = set()
    if 'enableWildcards_' in html_content:
        feature_types.add('wildcards')
    if 'enablePatches_' in html_content:
        feature_types.add('patches')
    if 'enableSpecialTypes_' in html_content:
        feature_types.add('special_types')
    if 'enableMultipleBranches_' in html_content:
        feature_types.add('branches')
    if 'enableUpdatePatterns_' in html_content:
        feature_types.add('updates')
    if 'enableGaps_' in html_content:
        feature_types.add('gaps')
    if 'enableInverseStatus_' in html_content:
        feature_types.add('inverse')
    if 'enableMixedStatus_' in html_content:
        feature_types.add('mixed')
    if 'enableCpeBaseGeneration_' in html_content:
        feature_types.add('cpe_base')
    
    if feature_types:
        feature_count = len(feature_types)
        feature_classification = classify_count(feature_count)
        pattern_parts.append(f"features:{feature_classification}")
    
    return "|".join(pattern_parts) if pattern_parts else "basic_html"

def analyze_intelligent_settings_patterns(settings_data: Dict) -> str:
    """
    Analyze intelligent settings configuration patterns for templating.
    
    Args:
        settings_data: Dictionary containing intelligent settings configuration
        
    Returns:
        Pattern key like "enabled:small|disabled:medium|total:9"
    """
    if not settings_data:
        return "empty"
    
    pattern_parts = []
    
    # Count enabled vs disabled settings
    enabled_count = sum(1 for value in settings_data.values() if value is True)
    disabled_count = sum(1 for value in settings_data.values() if value is False)
    total_count = len(settings_data)
    
    if enabled_count > 0:
        enabled_classification = classify_count(enabled_count)
        pattern_parts.append(f"enabled:{enabled_classification}")
    
    if disabled_count > 0:
        disabled_classification = classify_count(disabled_count)
        pattern_parts.append(f"disabled:{disabled_classification}")
    
    total_classification = classify_count(total_count)
    pattern_parts.append(f"total:{total_classification}")
    
    # Analyze specific feature combinations for common patterns
    if settings_data.get('enableWildcardExpansion') and settings_data.get('enableGapProcessing'):
        pattern_parts.append("combo:wildcard_gap")
    
    if settings_data.get('enableMultipleBranches') and settings_data.get('enableSpecialVersionTypes'):
        pattern_parts.append("combo:branches_special")
    
    if settings_data.get('enableInverseStatus') and settings_data.get('enableMixedStatus'):
        pattern_parts.append("combo:status_complex")
    
    return "|".join(pattern_parts) if pattern_parts else "basic_settings"

def generate_template_structures(data_registry: Dict, data_type: str) -> Tuple[Dict, Dict]:
    """
    Analyze data registry and generate template structures for deduplication.
    
    Args:
        data_registry: Dictionary of key -> data mappings
        data_type: Type of data ('references', 'sortingPriority', 'wildcardGeneration', 'updatePatterns', 'jsonGenerationRules', 'supportingInformation', 'jsonSettingsHTML', 'intelligentSettings')
        
    Returns:
        Tuple of (templates, mappings) dictionaries
    """
    if not data_registry:
        return {}, {}
    
    # Group data by patterns
    patterns_to_keys = {}
    patterns_to_data = {}
    
    for key, data in data_registry.items():
        if data_type == 'references':
            pattern = analyze_reference_patterns(data)
        elif data_type == 'sortingPriority':
            pattern = analyze_sorting_priority_patterns(data)
        elif data_type == 'wildcardGeneration':
            pattern = analyze_wildcard_generation_patterns(data)
        elif data_type == 'updatePatterns':
            pattern = analyze_update_patterns_data_patterns(data)
        elif data_type == 'jsonGenerationRules':
            pattern = analyze_json_rules_patterns(data)
        elif data_type == 'supportingInformation':
            pattern = analyze_supporting_info_patterns(data)
        elif data_type == 'jsonSettingsHTML':
            pattern = analyze_json_settings_html_patterns(data)
        elif data_type == 'intelligentSettings':
            pattern = analyze_intelligent_settings_patterns(data)
        else:
            # PATTERN GENERATION: Create unique pattern for unrecognized data types
            pattern = f"unknown_{len(str(data))}"
        
        if pattern not in patterns_to_keys:
            patterns_to_keys[pattern] = []
            patterns_to_data[pattern] = data  # Use first occurrence as template
        
        patterns_to_keys[pattern].append(key)
    
    # Generate templates for patterns with 2+ instances
    templates = {}
    mappings = {}
    template_counter = 0
    
    total_entries = len(data_registry)
    template_entries = 0
    
    for pattern, keys in patterns_to_keys.items():
        pattern_count = len(keys)
        
        # Template any pattern with 2+ instances
        if pattern_count >= 2:
            template_id = f"{data_type}_template_{template_counter}"
            templates[template_id] = patterns_to_data[pattern]
            mappings[template_id] = keys
            template_entries += pattern_count
            template_counter += 1
    
    # Log deduplication analysis
    direct_entries = total_entries - template_entries
    space_savings = (template_entries / total_entries * 100) if total_entries > 0 else 0
    
    logger.debug(f"Template analysis for {data_type}: {total_entries} total, {template_entries} templated, {direct_entries} direct, {space_savings:.1f}% space savings", group="badge_modal")
    
    return templates, mappings

def get_consolidated_cpe_registration_script() -> str:
    """
    Generate a single consolidated script block with all CPE data registrations.
    Uses template deduplication when beneficial for space savings.
    
    Returns:
        str: JavaScript code block with BadgeModal.registerData calls or template structures
    """
    global GLOBAL_CPE_DATA_REGISTRY
    
    if not GLOBAL_CPE_DATA_REGISTRY['references'] and not GLOBAL_CPE_DATA_REGISTRY['sortingPriority']:
        return ""
    
    script_content = ""
    
    # Process references data
    if GLOBAL_CPE_DATA_REGISTRY['references']:
        ref_templates, ref_mappings = generate_template_structures(
            GLOBAL_CPE_DATA_REGISTRY['references'], 'references')
        
        if ref_templates:
            # Generate template-based registration
            script_content += "// References templates\n"
            script_content += f"window.REFERENCES_TEMPLATES = {json.dumps(ref_templates, separators=(',', ':'))};\n"
            script_content += f"window.REFERENCES_MAPPINGS = {json.dumps(ref_mappings, separators=(',', ':'))};\n"
            
            # Generate template expansion code
            script_content += """
// Expand references templates
Object.keys(window.REFERENCES_TEMPLATES).forEach(templateId => {
    const template = window.REFERENCES_TEMPLATES[templateId];
    const keys = window.REFERENCES_MAPPINGS[templateId];
    
    keys.forEach(baseKeySafe => {
        const dataForKey = JSON.parse(JSON.stringify(template));
        BadgeModal.registerData('references', baseKeySafe, dataForKey);
    });
});
"""
            
            # Get templated keys for direct registration exclusion
            templated_keys = set()
            for keys in ref_mappings.values():
                templated_keys.update(keys)
        else:
            templated_keys = set()
        
        # Handle direct registration for non-templated references
        direct_ref_count = 0
        for key, data in GLOBAL_CPE_DATA_REGISTRY['references'].items():
            if key not in templated_keys:
                ref_data_js = json.dumps(data, separators=(',', ':'))
                script_content += f"    BadgeModal.registerData('references', '{key}', {ref_data_js});\n"
                direct_ref_count += 1
        
        if direct_ref_count > 0:
            logger.debug(f"References: {direct_ref_count} direct registrations (patterns not beneficial for templating)", group="badge_modal")
    
    # Process sorting priority data
    if GLOBAL_CPE_DATA_REGISTRY['sortingPriority']:
        sort_templates, sort_mappings = generate_template_structures(
            GLOBAL_CPE_DATA_REGISTRY['sortingPriority'], 'sortingPriority')
        
        if sort_templates:
            # Generate template-based registration
            script_content += "// Sorting priority templates\n"
            script_content += f"window.SORTING_TEMPLATES = {json.dumps(sort_templates, separators=(',', ':'))};\n"
            script_content += f"window.SORTING_MAPPINGS = {json.dumps(sort_mappings, separators=(',', ':'))};\n"
            
            # Generate template expansion code
            script_content += """
// Expand sorting priority templates
Object.keys(window.SORTING_TEMPLATES).forEach(templateId => {
    const template = window.SORTING_TEMPLATES[templateId];
    const keys = window.SORTING_MAPPINGS[templateId];
    
    keys.forEach(baseKeySafe => {
        const dataForKey = JSON.parse(JSON.stringify(template));
        BadgeModal.registerData('sortingPriority', baseKeySafe, dataForKey);
    });
});
"""
            
            # Get templated keys for direct registration exclusion
            templated_keys = set()
            for keys in sort_mappings.values():
                templated_keys.update(keys)
        else:
            templated_keys = set()
        
        # Handle direct registration for non-templated sorting priority data
        direct_sort_count = 0
        for key, data in GLOBAL_CPE_DATA_REGISTRY['sortingPriority'].items():
            if key not in templated_keys:
                sort_data_js = json.dumps(data, separators=(',', ':'))
                script_content += f"    BadgeModal.registerData('sortingPriority', '{key}', {sort_data_js});\n"
                direct_sort_count += 1
        
        if direct_sort_count > 0:
            logger.debug(f"SortingPriority: {direct_sort_count} direct registrations (patterns not beneficial for templating)", group="badge_modal")
    
    if script_content:
        return f"""
// Consolidated CPE data registrations with template deduplication
{script_content}"""
    else:
        return ""

def get_consolidated_platform_notification_script() -> str:
    """
    Generate a single consolidated script block with all platform notification data registrations.
    Uses template deduplication when beneficial for space savings.
    
    Returns:
        str: JavaScript code block with BadgeModal.registerData calls or template structures
    """
    global PLATFORM_ENTRY_NOTIFICATION_REGISTRY
    
    # Check if we have any platform data to process
    total_data_count = sum(len(registry) for registry in PLATFORM_ENTRY_NOTIFICATION_REGISTRY.values())
    if total_data_count == 0:
        return ""
    
    script_content = ""
    all_data_types = ['wildcardGeneration', 'updatePatterns', 'jsonGenerationRules', 'supportingInformation', 'sourceDataConcerns', 'aliasExtraction']
    
    # Process each platform data type
    for data_type in all_data_types:
        data_registry = PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get(data_type, {})
        if not data_registry:
            continue
        
        # Generate template structures for this data type
        templates, mappings = generate_template_structures(data_registry, data_type)
        
        if templates:
            # Generate template-based registration
            template_var_name = f"{data_type.upper()}_TEMPLATES"
            mapping_var_name = f"{data_type.upper()}_MAPPINGS"
            
            script_content += f"// {data_type} templates\n"
            script_content += f"window.{template_var_name} = {json.dumps(templates, separators=(',', ':'))};\n"
            script_content += f"window.{mapping_var_name} = {json.dumps(mappings, separators=(',', ':'))};\n"
            
            # Generate template expansion code
            script_content += f"""
// Expand {data_type} templates
Object.keys(window.{template_var_name}).forEach(templateId => {{
    const template = window.{template_var_name}[templateId];
    const keys = window.{mapping_var_name}[templateId];
    
    keys.forEach(tableIndex => {{
        const dataForKey = JSON.parse(JSON.stringify(template));
        BadgeModal.registerData('{data_type}', tableIndex, dataForKey);
    }});
}});
"""
            
            # Get templated keys for direct registration exclusion
            templated_keys = set()
            for keys in mappings.values():
                templated_keys.update(keys)
        else:
            templated_keys = set()
        
        # Handle direct registration for non-templated data
        direct_count = 0
        for table_index, data in data_registry.items():
            if table_index not in templated_keys:
                data_js = json.dumps(data, separators=(',', ':'))
                script_content += f"    BadgeModal.registerData('{data_type}', '{table_index}', {data_js});\n"
                direct_count += 1
        
        if direct_count > 0:
            logger.debug(f"{data_type}: {direct_count} direct registrations (patterns not beneficial for templating)", group="badge_modal")
    
    if script_content:
        # Ensure all required keys exist in the registry
        PLATFORM_ENTRY_NOTIFICATION_REGISTRY.setdefault('wildcardGeneration', {})
        PLATFORM_ENTRY_NOTIFICATION_REGISTRY.setdefault('updatePatterns', {})
        PLATFORM_ENTRY_NOTIFICATION_REGISTRY.setdefault('jsonGenerationRules', {})
        PLATFORM_ENTRY_NOTIFICATION_REGISTRY.setdefault('supportingInformation', {})
        PLATFORM_ENTRY_NOTIFICATION_REGISTRY.setdefault('sourceDataConcerns', {})
        
        # Log individual counts for debugging
        wildcard_count = len(PLATFORM_ENTRY_NOTIFICATION_REGISTRY['wildcardGeneration'])
        update_count = len(PLATFORM_ENTRY_NOTIFICATION_REGISTRY['updatePatterns'])
        rules_count = len(PLATFORM_ENTRY_NOTIFICATION_REGISTRY['jsonGenerationRules'])
        supporting_count = len(PLATFORM_ENTRY_NOTIFICATION_REGISTRY['supportingInformation'])
        concerns_count = len(PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns'])
        logger.debug(f"Platform registrations - {wildcard_count} wildcard, {update_count} update patterns, {rules_count} rules, {supporting_count} supporting info, {concerns_count} data concerns", group="badge_modal")
        
        return f"""
// Consolidated platform notification data registrations with template deduplication
{script_content}"""
    else:
        return ""

def get_consolidated_json_settings_script() -> str:
    """
    Generate a consolidated script block for JSON Generation Settings with template deduplication.
    Uses pattern analysis to group similar HTML content and settings configurations.
    
    Returns:
        str: JavaScript code block with JSON_SETTINGS_HTML and INTELLIGENT_SETTINGS assignments
    """
    # Import the global dictionaries from generateHTML module
    from . import generateHTML
    
    json_settings_html = getattr(generateHTML, 'JSON_SETTINGS_HTML', {})
    intelligent_settings = getattr(generateHTML, 'INTELLIGENT_SETTINGS', {})
    
    if not json_settings_html and not intelligent_settings:
        return ""
    
    script_content = ""
    
    # Process JSON Settings HTML
    if json_settings_html:
        html_templates, html_mappings = generate_template_structures(
            json_settings_html, 'jsonSettingsHTML')
        
        if html_templates:
            # Generate template-based registration for HTML
            script_content += "// JSON Settings HTML templates\n"
            script_content += f"window.JSON_SETTINGS_HTML_TEMPLATES = {json.dumps(html_templates, separators=(',', ':'))};\n"
            script_content += f"window.JSON_SETTINGS_HTML_MAPPINGS = {json.dumps(html_mappings, separators=(',', ':'))};\n"
            
            # Generate template expansion code for HTML
            script_content += """
// Expand JSON Settings HTML templates
Object.keys(window.JSON_SETTINGS_HTML_TEMPLATES).forEach(templateId => {
    const template = window.JSON_SETTINGS_HTML_TEMPLATES[templateId];
    const keys = window.JSON_SETTINGS_HTML_MAPPINGS[templateId];
    
    keys.forEach(tableId => {
        // Replace table ID references in template to match target table
        const htmlContent = template.replace(/matchesTable_0/g, tableId)
                                   .replace(/enableWildcards_matchesTable_0/g, `enableWildcards_${tableId}`)
                                   .replace(/enablePatches_matchesTable_0/g, `enablePatches_${tableId}`)
                                   .replace(/enableSpecialTypes_matchesTable_0/g, `enableSpecialTypes_${tableId}`)
                                   .replace(/enableMultipleBranches_matchesTable_0/g, `enableMultipleBranches_${tableId}`)
                                   .replace(/enableUpdatePatterns_matchesTable_0/g, `enableUpdatePatterns_${tableId}`)
                                   .replace(/enableGaps_matchesTable_0/g, `enableGaps_${tableId}`)
                                   .replace(/enableInverseStatus_matchesTable_0/g, `enableInverseStatus_${tableId}`)
                                   .replace(/enableMixedStatus_matchesTable_0/g, `enableMixedStatus_${tableId}`)
                                   .replace(/enableCpeBaseGeneration_matchesTable_0/g, `enableCpeBaseGeneration_${tableId}`)
                                   .replace(/settingsCollapse_matchesTable_0/g, `settingsCollapse_${tableId}`);
        
        window.JSON_SETTINGS_HTML = window.JSON_SETTINGS_HTML || {};
        window.JSON_SETTINGS_HTML[tableId] = htmlContent;
    });
});
"""
            
            # Get templated keys for direct registration exclusion
            templated_keys = set()
            for keys in html_mappings.values():
                templated_keys.update(keys)
        else:
            templated_keys = set()
        
        # Handle direct registration for non-templated HTML
        direct_html_count = 0
        for table_id, html_content in json_settings_html.items():
            if table_id not in templated_keys:
                # Ensure the global object exists
                script_content += "window.JSON_SETTINGS_HTML = window.JSON_SETTINGS_HTML || {};\n"
                script_content += f"window.JSON_SETTINGS_HTML['{table_id}'] = {json.dumps(html_content, separators=(',', ':'))};\n"
                direct_html_count += 1
        
        if direct_html_count > 0:
            logger.debug(f"JSON Settings HTML: {direct_html_count} direct registrations (patterns not beneficial for templating)", group="badge_modal")
    
    # Process Intelligent Settings
    if intelligent_settings:
        settings_templates, settings_mappings = generate_template_structures(
            intelligent_settings, 'intelligentSettings')
        
        if settings_templates:
            # Generate template-based registration for settings
            script_content += "// Intelligent Settings templates\n"
            script_content += f"window.INTELLIGENT_SETTINGS_TEMPLATES = {json.dumps(settings_templates, separators=(',', ':'))};\n"
            script_content += f"window.INTELLIGENT_SETTINGS_MAPPINGS = {json.dumps(settings_mappings, separators=(',', ':'))};\n"
            
            # Generate template expansion code for settings
            script_content += """
// Expand Intelligent Settings templates
Object.keys(window.INTELLIGENT_SETTINGS_TEMPLATES).forEach(templateId => {
    const template = window.INTELLIGENT_SETTINGS_TEMPLATES[templateId];
    const keys = window.INTELLIGENT_SETTINGS_MAPPINGS[templateId];
    
    keys.forEach(tableId => {
        // Settings data can be used directly (no table ID substitution needed)
        window.INTELLIGENT_SETTINGS = window.INTELLIGENT_SETTINGS || {};
        window.INTELLIGENT_SETTINGS[tableId] = JSON.parse(JSON.stringify(template));
    });
});
"""
            
            # Get templated keys for direct registration exclusion
            templated_keys = set()
            for keys in settings_mappings.values():
                templated_keys.update(keys)
        else:
            templated_keys = set()
        
        # Handle direct registration for non-templated settings
        direct_settings_count = 0
        for table_id, settings_data in intelligent_settings.items():
            if table_id not in templated_keys:
                # Ensure the global object exists
                script_content += "window.INTELLIGENT_SETTINGS = window.INTELLIGENT_SETTINGS || {};\n"
                script_content += f"window.INTELLIGENT_SETTINGS['{table_id}'] = {json.dumps(settings_data, separators=(',', ':'))};\n"
                direct_settings_count += 1
        
        if direct_settings_count > 0:
            logger.debug(f"Intelligent Settings: {direct_settings_count} direct registrations (patterns not beneficial for templating)", group="badge_modal")
    
    if script_content:
        # Log individual counts for debugging
        html_count = len(json_settings_html) if json_settings_html else 0
        settings_count = len(intelligent_settings) if intelligent_settings else 0
        logger.debug(f"JSON Settings registrations - {html_count} HTML entries, {settings_count} intelligent settings", group="badge_modal")
        
        return f"""
// Consolidated JSON Generation Settings registrations with template deduplication
{script_content}"""
    else:
        return ""

# ===== SIMPLE CASE DETECTION =====

def is_modal_only_case(raw_platform_data: Dict) -> bool:
    """
    Detect cases that should get modal content only (no JSON Generation Settings).
    
    This unified function combines what were previously "simple" and "all versions" cases
    since they both have the same behavior: modal content only, no interactive settings.
    
    Args:
        raw_platform_data: The raw platform data from CVE/NVD APIs
        
    Returns:
        bool: True if this case should get modal only (no JSON settings)
    """
    if not raw_platform_data or not isinstance(raw_platform_data, dict):
        return True  # No data = modal only
    
    versions = raw_platform_data.get('versions', [])
    default_status = raw_platform_data.get('defaultStatus', 'unknown')
    
    # CASE 1: Simple cases - defaultStatus with no version constraints
    # (implies all versions have that status)
    if not versions and default_status in ['affected', 'unaffected', 'unknown']:
        logger.debug(f"Modal-only case detected: Simple defaultStatus '{default_status}' with no versions", group="DATA_PROC")
        return True
    
    # CASE 2: Basic version patterns with no constraints
    if len(versions) <= 2:
        all_versions_patterns = 0
        for version in versions:
            if not isinstance(version, dict):
                continue
                
            if (version.get('status') in ['affected', 'unaffected', 'unknown'] and 
                version.get('version') in ['*', '0'] and
                not version.get('changes') and  # No complex version.changes
                not version.get('lessThanOrEqual') and  # No range constraints
                not version.get('lessThan') and  # No range constraints
                version.get('versionType', 'semver') in ['custom', 'semver']):
                all_versions_patterns += 1
        
        # If all versions are basic patterns, this is modal-only
        if all_versions_patterns == len(versions) and all_versions_patterns > 0:
            logger.debug(f"Modal-only case detected: {all_versions_patterns} basic all-versions patterns", group="DATA_PROC")
            return True
    
    # CASE 3: Complex "All Versions" patterns that still only need modal content
    for version in versions:
        if not isinstance(version, dict):
            continue
            
        status = version.get('status', 'unknown')
        # Process ALL statuses (affected, unaffected, unknown)
        if status not in ['affected', 'unaffected', 'unknown']:
            continue
            
        # lessThanOrEqual: "*" alone (all versions up to infinity) - without specific start version
        if version.get('lessThanOrEqual') == '*' and not version.get('version'):
            logger.debug("Modal-only case detected: lessThanOrEqual '*' pattern with no start version", group="DATA_PROC")
            return True
        
        # version: "*" with additional constraints (needs wildcard processing but still modal-only)
        if (version.get('version') == '*' and 
            (version.get('lessThanOrEqual') or version.get('lessThan'))):
            logger.debug("Modal-only case detected: version '*' with additional constraints", group="DATA_PROC")
            return True
    
    return False

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
            'needs_gap_processing': False,
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
        'needs_gap_processing': False,
        'has_update_patterns': False, 
        'wildcard_patterns': [],
        'special_version_types': [],
        'version_families': set(),
        'status_types': set(),
        'update_patterns': []
    }
    
    # Extended list of comparators to check for - using production constant
    
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

def analyze_data_for_smart_defaults(raw_platform_data):
    """
    Analyze platform data to determine intelligent defaults for JSON generation settings.
    Returns None for simple cases to skip JSON generation entirely.
    """
    # NEW: Check for simple cases first
    if not raw_platform_data:
        return None  # No data = no JSON generation needed
    
    if is_modal_only_case(raw_platform_data):
        logger.debug("Skipping settings analysis for modal-only case", group="BADGE_GEN")
        return None  # Modal-only case = no JSON generation needed
    
    # EXISTING: Continue with existing settings analysis for complex cases
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

    # Analyze CPE base generation needs
    cpe_base_info = analyze_cpe_base_string_generation(raw_platform_data)
    enable_cpe_base_generation = cpe_base_info['has_cpe_base_generation']
    
    return {
        'enableWildcardExpansion': characteristics['has_wildcards'],
        'enableVersionChanges': characteristics['has_version_changes'],
        'enableSpecialVersionTypes': characteristics['has_special_version_types'],
        'enableInverseStatus': characteristics['has_inverse_status'],
        'enableMultipleBranches': enable_multiple_branches,
        'enableMixedStatus': characteristics['has_mixed_status'],
        'enableGapProcessing': characteristics['needs_gap_processing'],
        'enableUpdatePatterns': enable_update_patterns,
        'enableCpeBaseGeneration': enable_cpe_base_generation
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

def get_update_patterns():
    """
    Get the comprehensive list of update transformation patterns.
    This ensures consistency between detection and transformation functions.
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
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+beta\s*(\d+)$', 'type': 'beta'},  # Handle "1.0.0 beta 1"
        {'pattern': r'^(.+?)\s+Beta\s*(\d+)$', 'type': 'beta'},  # Handle "1.0.0 Beta 1"
        {'pattern': r'^(.+?)\s+b\s*(\d+)$', 'type': 'beta'},  # Handle "1.0.0 b1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])beta(\d+)$', 'type': 'beta'},  # Handle "4.0.0beta1"
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])b(\d+)$', 'type': 'beta'},  # Handle "4.0.0b1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-beta\.(\d+)$', 'type': 'beta'},  # Handle "1.0.0-beta.1"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_beta_(\d+)$', 'type': 'beta'},  # Handle "1.0.0_beta_1"
        {'pattern': r'^(.+?)-beta-(\d+)$', 'type': 'beta'},  # Handle "1.0.0-beta-1"
        {'pattern': r'^(.+?)\.beta\.(\d+)$', 'type': 'beta'},  # Handle "1.0.0.beta.1"
        
        
        # ===== ALPHA TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+alpha\s*(\d+)$', 'type': 'alpha'},  # Handle "1.0.0 alpha 1"
        {'pattern': r'^(.+?)\s+Alpha\s*(\d+)$', 'type': 'alpha'},  # Handle "1.0.0 Alpha 1"
        {'pattern': r'^(.+?)\s+a\s*(\d+)$', 'type': 'alpha'},  # Handle "1.0.0 a1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])alpha(\d+)$', 'type': 'alpha'},  # Handle "2.0.0alpha1"
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])a(\d+)$', 'type': 'alpha'},  # Handle "2.0.0a1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-alpha\.(\d+)$', 'type': 'alpha'},  # Handle "1.0.0-alpha.1"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_alpha_(\d+)$', 'type': 'alpha'},  # Handle "3.0.0_alpha_2"
        {'pattern': r'^(.+?)-alpha-(\d+)$', 'type': 'alpha'},  # Handle "3.0.0-alpha-2"
        {'pattern': r'^(.+?)_a_(\d+)$', 'type': 'alpha'},  # Handle "4.0.0_a_3"
        
        
        # ===== RELEASE_CANDIDATE TERM GROUP =====
        # 1. Space-separated patterns
        {'pattern': r'^(.+?)\s+rc\s*(\d+)$', 'type': 'rc'},  # Handle "1.0.0 rc 1"
        {'pattern': r'^(.+?)\s+RC\s*(\d+)$', 'type': 'rc'},  # Handle "1.0.0 RC 1"
        {'pattern': r'^(.+?)\s+release\s+candidate\s*(\d+)$', 'type': 'rc'},  # Handle "1.0.0 release candidate 1"
        {'pattern': r'^(.+?)\s+Release\s+Candidate\s*(\d+)$', 'type': 'rc'},  # Handle "1.0.0 Release Candidate 1"
        
        # 2. Direct concatenation patterns
        {'pattern': r'^(.+?)(?<![a-zA-Z\.])rc(\d+)$', 'type': 'rc'},  # Handle "3.0.0rc1"
        
        # 3. Dash-dot notation patterns
        {'pattern': r'^(.+?)-rc\.(\d+)$', 'type': 'rc'},  # Handle "1.0.0-rc.1"
        
        # 4. Flexible separator patterns
        {'pattern': r'^(.+?)_rc_(\d+)$', 'type': 'rc'},  # Handle "2.0.0_rc_2"
        {'pattern': r'^(.+?)-rc-(\d+)$', 'type': 'rc'},  # Handle "2.0.0-rc-2"
        {'pattern': r'^(.+?)_release_candidate_(\d+)$', 'type': 'rc'},  # Handle "4.0.0_release_candidate_3"
        
        
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
        # NOTE: Order matters! Specific patterns must come before general patterns
        
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

def analyze_cpe_base_string_generation(raw_platform_data: Dict) -> Dict:
    """
    Analyze if this platform entry represents "all versions" cases that need special JSON generation.
    
    This handles cases where version constraints represent "all versions" scenarios:
    - defaultStatus: "affected" with no version constraints (implies all versions)
    - version: "*" (explicitly all versions)  
    - lessThanOrEqual: "*" (all versions up to infinity)
    - version: "0" with lessThanOrEqual: "*" (range covering all versions)
    
    Args:
        raw_platform_data: The raw platform data from CVE/NVD APIs
        
    Returns:
        Dict with information about CPE base string generation needs
    """
    cpe_base_info = {
        'has_cpe_base_generation': False,
        'transformations': []
    }
    
    if not raw_platform_data or not isinstance(raw_platform_data, dict):
        return cpe_base_info
    
    versions = raw_platform_data.get('versions', [])
    default_status = raw_platform_data.get('defaultStatus', 'unknown')
    
    # Case 1: defaultStatus with no version constraints (implies all versions)
    if not versions:  # No versions array means defaultStatus applies to all versions
        cpe_base_info['has_cpe_base_generation'] = True
        cpe_base_info['transformations'].append({
            'type': 'defaultStatusAllVersions',
            'description': f'defaultStatus: "{default_status}" with no version constraints implies all versions are {default_status}',
            'pattern': f'defaultStatus: {default_status}',
            'status': default_status,  # Pass the status for vulnerability determination
            'cpe_generation_need': f'Generate CPE base string with wildcard version (*) to represent all versions as {default_status}'
        })
    
    # Case 2-4: Explicit "all versions" patterns in version constraints
    for version in versions:
        if not isinstance(version, dict):
            continue
            
        status = version.get('status', 'unknown')
        # Process ALL statuses (affected, unaffected, unknown) for CPE generation
        
        # Case 2: version: "*" (explicitly all versions)
        if version.get('version') == '*':
            cpe_base_info['has_cpe_base_generation'] = True
            cpe_base_info['transformations'].append({
                'type': 'explicitWildcard',
                'description': f'version: "*" explicitly represents all versions with status "{status}"',
                'pattern': 'version: "*"',
                'status': status,  # Pass the status for vulnerability determination
                'cpe_generation_need': f'Generate CPE base string with wildcard version (*) to match all versions as {status}'
            })
        
        # Case 3: lessThanOrEqual: "*" alone (all versions up to infinity) - but only without a specific start version
        if version.get('lessThanOrEqual') == '*' and not version.get('version'):
            cpe_base_info['has_cpe_base_generation'] = True
            cpe_base_info['transformations'].append({
                'type': 'lessThanOrEqualWildcard',
                'description': f'lessThanOrEqual: "*" with no start version represents all versions up to infinity with status "{status}"',
                'pattern': 'lessThanOrEqual: "*" (no start version)',
                'status': status,  # Pass the status for vulnerability determination
                'cpe_generation_need': f'Generate CPE base string with wildcard version (*) to cover infinite version range as {status}'
            })
    
    return cpe_base_info

# ===== BADGE CREATION FUNCTIONS =====

def create_json_generation_rules_badge(table_index: int, raw_platform_data: Dict, vendor: str, product: str, row: Dict) -> Optional[str]:
    """
    Create a unified JSON Generation Rules badge with optimized detection logic.
    
    Detection hierarchy:
    1. Simple cases: Skip all processing (no badge)
    2. All Versions cases: Badge with modal but no JSON settings HTML
    3. Complex cases: Badge with modal and full JSON settings HTML
    
    Args:
        table_index: The table index for unique identification
        raw_platform_data: The raw platform data to analyze
        vendor: The vendor name
        product: The product name
        row: The complete row data for header information
    
    Returns:
        HTML string for the badge, or None if no applicable rules detected
    """
    # STEP 1: Check for modal-only cases - include them in All Versions modal
    if is_modal_only_case(raw_platform_data):
        logger.debug(f"Modal-only case detected for table {table_index} - creating All Versions badge with modal content only", group="BADGE_GEN")
        
        # Create modal content for simple case
        modal_content = {
            "rules": [],
            "summary": {
                "total_rules": 1,
                "rule_types": ["All Versions Pattern"]
            }
        }
        
        # Determine vulnerability based on defaultStatus
        default_status = raw_platform_data.get('defaultStatus', 'unknown')
        is_vulnerable = default_status == 'affected'
        
        # Add simple case tab content
        simple_case_rule = {
            "type": "allVersionsPattern",
            "title": "All Versions",
            "count": 1,
            "setting_key": "enableCpeBaseGeneration",
            "table_id": f"matchesTable_{table_index}",
            "description": f"Simple 'CVE Affects Product (No Versions)' case - defaultStatus '{default_status}' with no version constraints implies all versions are {default_status}.",
            "transformations": [
                {
                    "type": "defaultStatusAllVersions",
                    "description": f"defaultStatus: '{default_status}' with no version constraints implies all versions are {default_status}",
                    "input": {
                        "defaultStatus": default_status
                        # No versions array present
                    },
                    "output": {
                        "cpeMatch": [
                            [
                                {
                                    "criteria": "cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "generated_RVFOW3S3G",
                                    "vulnerable": is_vulnerable
                                }
                            ]
                        ]
                    },
                    "explanation": f"Simple case where no version constraints means all versions are {default_status} - creates basic CPE base string match with vulnerable={is_vulnerable}",
                    "pattern": f"defaultStatus: '{default_status}', no versions array"
                }
            ]
        }
        modal_content["rules"].append(simple_case_rule)
        
        # Register the modal content
        register_platform_notification_data(table_index, 'jsonGenerationRules', modal_content)
        
        # Create badge with simple case tooltip
        tooltip = f"Simple case: CVE Affects Product (No Versions) - defaultStatus '{default_status}' with no versions implies all versions are {default_status}."
        
        # Create the badge HTML
        source_role = row.get('sourceRole', 'Unknown')
        header_parts = [source_role]
        if vendor and vendor != 'unknown':
            header_parts.append(vendor)
        if product and product != 'unknown':
            header_parts.append(product)
        
        header_identifier = f"Platform Entry {table_index} ({', '.join(header_parts)})"
        badge_html = f'<span class="badge modal-badge bg-warning" onclick="BadgeModalManager.openJsonGenerationRulesModal(\'{table_index}\', \'{header_identifier}\')" title="{tooltip}">⚙️ JSON Generation Rules</span> '
        
        return badge_html
    
    # STEP 2: Complex cases need full analysis with wildcard generation, update patterns, and CPE base generation
    logger.debug(f"Complex case detected for table {table_index} - full JSON generation processing", group="BADGE_GEN")
    
    # EXISTING: Continue with existing badge creation logic for complex cases
    # Analyze wildcard generation, update patterns, and CPE base generation
    wildcard_info = analyze_wildcard_generation(raw_platform_data)
    update_info = analyze_update_patterns(raw_platform_data)
    cpe_base_info = analyze_cpe_base_string_generation(raw_platform_data)
    
    # Check if any rules apply
    has_wildcards = wildcard_info['has_wildcards']
    has_update_patterns = update_info['has_update_patterns']
    has_cpe_base_generation = cpe_base_info['has_cpe_base_generation']
    
    if not has_wildcards and not has_update_patterns and not has_cpe_base_generation:
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
    
    # Add CPE base generation tab if applicable
    if has_cpe_base_generation and cpe_base_info['transformations']:
        cpe_count = len(cpe_base_info['transformations'])
        cpe_base_rule = {
            "type": "allVersionsPattern",
            "title": "All Versions Pattern",
            "count": cpe_count,
            "setting_key": "enableCpeBaseGeneration",
            "table_id": f"matchesTable_{table_index}",
            "description": "Handles 'all versions' cases with appropriate JSON generation. Processes scenarios like defaultStatus: 'affected' or version: '*' that represent broad version coverage.",
            "transformations": []
        }
        modal_content["rules"].append(cpe_base_rule)
        
        # Get the index of the CPE base rule we just added
        cpe_base_index = len(modal_content["rules"]) - 1
        
        # Process CPE base generation transformations
        for transformation in cpe_base_info['transformations']:
            modal_content["rules"][cpe_base_index]["transformations"].append({
                "type": transformation['type'],
                "description": transformation['description'],
                "pattern": transformation['pattern'],
                "cpe_generation_need": transformation['cpe_generation_need'],
                "json_implication": "Requires generating CPE base string with wildcard version for comprehensive coverage"
            })
        
        modal_content["summary"]["rule_types"].append("All Versions Pattern")
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
                                       vendor: str, product: str) -> Optional[str]:
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
                        <div class="form-check mb-1">
                            <input class="form-check-input row-setting" type="checkbox" 
                                   id="enableCpeBaseGeneration_{table_id}" 
                                   data-setting="enableCpeBaseGeneration"
                                   data-table-id="{table_id}" 
                                   {checked('enableCpeBaseGeneration')}>
                            <label class="form-check-label" for="enableCpeBaseGeneration_{table_id}"
                                   data-bs-toggle="tooltip" data-bs-placement="top" 
                                   title="Handles 'all versions' cases that need CPE base string generation. Processes scenarios like defaultStatus: 'affected' with no versions, or explicit wildcard patterns (version: '*', lessThanOrEqual: '*') that represent broad version coverage requiring wildcard CPE generation.">
                                <small>All Versions Pattern Processing 
                                    <span class="text-muted">(CPE base string generation)</span>
                                    <span class="feature-indicator" data-feature="hasCpeBaseGeneration"></span>
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
        'supportingInformation': {},
        'sourceDataConcerns': {},
        'aliasExtraction': {}
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
    """
    Store JSON settings HTML for complex cases only.
    Simple cases and All Versions cases skip storage entirely to save file space.
    """
    global JSON_SETTINGS_HTML, INTELLIGENT_SETTINGS
    
    # Ensure global dictionaries exist and are initialized
    if 'JSON_SETTINGS_HTML' not in globals() or JSON_SETTINGS_HTML is None:
        JSON_SETTINGS_HTML = {}
    if 'INTELLIGENT_SETTINGS' not in globals() or INTELLIGENT_SETTINGS is None:
        INTELLIGENT_SETTINGS = {}
    
    # STEP 1: Check for modal-only cases - these don't need JSON generation settings
    if not raw_platform_data or is_modal_only_case(raw_platform_data):
        logger.debug(f"Skipping JSON generation for {table_id} - modal-only case detected", group="BADGE_GEN")
        return  # Don't store anything, no JSON generation needed
    
    # STEP 2: Complex cases - generate full settings analysis and HTML
    settings = analyze_data_for_smart_defaults(raw_platform_data)
    
    # If settings is None (shouldn't happen for complex cases, but safety check)
    if settings is None:
        logger.debug(f"Unexpected: Complex case returned None settings for {table_id}", group="BADGE_GEN")
        return
    
    # Store the HTML and settings for complex cases
    JSON_SETTINGS_HTML[table_id] = create_json_generation_settings_html(table_id, settings)
    INTELLIGENT_SETTINGS[table_id] = settings
    
    logger.debug(f"Generated JSON settings HTML for complex case {table_id}", group="BADGE_GEN")

# ===== SOURCE DATA CONCERNS MODAL SYSTEM =====

# ===== RANGE OVERLAP DETECTION FUNCTIONS =====

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
                                     platform_metadata: Dict, row: Dict) -> Optional[str]:
    """
    Create a unified Source Data Concerns badge that consolidates all source data quality issues.
    
    Args:
        table_index: The table index for unique identification
        raw_platform_data: The raw platform data to analyze
        characteristics: Version characteristics analysis
        platform_metadata: Platform metadata from the row
        row: The complete row data for header information
        
    Returns:
        HTML string for the badge, or None if no source data concerns detected
    """
    
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
    
    # Vendor Placeholder Data Detection
    if 'vendor' in raw_platform_data and isinstance(raw_platform_data['vendor'], str):
        vendor_value = raw_platform_data['vendor'].strip()
        vendor_lower = vendor_value.lower()
        # Use exact matching for placeholder detection - these are specific bad data entry practices
        is_placeholder = vendor_lower in [v.lower() for v in GENERAL_PLACEHOLDER_VALUES]
        
        if is_placeholder:
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
        
        for version_entry in curated_platform_data['versions']:
            if isinstance(version_entry, dict):
                # Check standard version fields
                for field in version_fields:
                    field_value = version_entry.get(field)
                    if isinstance(field_value, str) and field_value.strip():
                        field_value_lower = field_value.strip().lower()
                        # Use exact matching for placeholder detection - these are specific bad data entry practices
                        is_placeholder = field_value_lower in [v.lower() for v in VERSION_PLACEHOLDER_VALUES]
                        
                        if is_placeholder:
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
        
        for version_entry in curated_platform_data['versions']:
            if isinstance(version_entry, dict):
                # Check standard version fields
                for field in version_fields:
                    field_value = version_entry.get(field)
                    if isinstance(field_value, str) and field_value.strip():
                        field_lower = field_value.lower()
                        matching_comparators = [comp for comp in COMPARATOR_PATTERNS if comp in field_lower]
                        if matching_comparators:
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
        
        for version_entry in curated_platform_data['versions']:
            if isinstance(version_entry, dict):
                # Check standard version fields
                for field in version_fields:
                    field_value = version_entry.get(field)
                    if isinstance(field_value, str) and field_value.strip():
                        field_lower = field_value.lower()
                        # Check each string pattern and report individually with pattern type
                        for pattern_type, patterns in TEXT_COMPARATOR_PATTERNS.items():
                            for pattern in patterns:
                                if pattern in field_lower:
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
                                        if pattern in field_lower:
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
                                        if pattern in field_lower:
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
        
        for version_entry in curated_platform_data['versions']:
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
                                # Use proper format for individual invalid characters
                                for invalid_char in invalid_chars:
                                    concerns_data["invalidCharacters"].append({
                                        "field": field,
                                        "sourceValue": field_value,
                                        "detectedPattern": {"detectedValue": invalid_char}
                                    })
                                    concerns_count += 1
                
                # Check changes array for invalid characters
                if 'changes' in version_entry and isinstance(version_entry['changes'], list):
                    for idx, change in enumerate(version_entry['changes']):
                        if isinstance(change, dict):
                            change_at_value = change.get('at')
                            if isinstance(change_at_value, str) and change_at_value.strip():
                                # Check if version matches valid pattern
                                if not re.match(valid_version_pattern, change_at_value):
                                    # Find specific invalid characters by excluding valid ones
                                    invalid_chars = list(set(re.findall(r'[^a-zA-Z0-9\-*_:.+()~]', change_at_value)))
                                    if invalid_chars:  # Only add if we actually found invalid characters
                                        # Use proper format for individual invalid characters
                                        for invalid_char in invalid_chars:
                                            concerns_data["invalidCharacters"].append({
                                                "field": f"changes[{idx}].at",
                                                "sourceValue": change_at_value,
                                                "detectedPattern": {"detectedValue": invalid_char}
                                            })
                                            concerns_count += 1
    
    # Update concern types for invalid character detection
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
    
    # Build header identifier for the modal
    header_parts = []
    if 'cna' in raw_platform_data:
        header_parts.append(raw_platform_data['cna'])
    if 'source_id' in raw_platform_data:
        header_parts.append(raw_platform_data['source_id'])
    if 'vendor' in raw_platform_data:
        header_parts.append(raw_platform_data['vendor'])
    if 'product' in raw_platform_data:
        header_parts.append(raw_platform_data['product'])
    
    header_identifier = f"Platform Entry {table_index} ({', '.join(header_parts)})"
    
    # Get the final total count and concern types from the registry (includes overlapping ranges)
    final_entry = PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns'][table_index]
    final_count = final_entry['summary']['total_concerns']
    final_concern_types = final_entry['summary']['concern_types']
    
    # Create tooltip showing concern summary
    concern_summary = f"{final_count} issues: {', '.join(final_concern_types)}"
    tooltip = f"Source data quality issues detected&#013;{concern_summary}&#013;Click to view detailed LINT analysis"
    
    # Create the badge HTML with purple theme
    badge_html = f'<span class="badge modal-badge bg-sourceDataConcern" onclick="BadgeModalManager.openSourceDataConcernsModal(\'{table_index}\', \'{header_identifier}\')" title="{tooltip}">🔍 Source Data Concerns ({final_count})</span> '
    
    return badge_html


def create_alias_extraction_badge(table_index: int, raw_platform_data: Dict, row: Dict) -> Optional[str]:
    """
    Create an Alias Extraction badge for curator functionality integration.
    
    Extracts alias data from CVE platform entries for curator-style source mapping analysis.
    This function follows the curator's platform expansion logic where platforms arrays
    are broken out into separate alias entries for collector compatibility.
    
    Args:
        table_index: The table index for unique identification
        raw_platform_data: The raw platform data to extract aliases from
        row: The complete row data for header information
        
    Returns:
        HTML string for the badge, or None if no alias data can be extracted
    """
    
    # Initialize the alias extraction registry
    PLATFORM_ENTRY_NOTIFICATION_REGISTRY['aliasExtraction'] = PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('aliasExtraction', {})
    
    # CRITICAL: Check for meaningful properties following curator logic exactly
    meaningful_properties = []
    for prop in ['vendor', 'product', 'platforms', 'modules', 'packageName', 'repo', 'programRoutines', 'programFiles', 'collectionURL']:
        if prop in raw_platform_data and not _is_placeholder_value(raw_platform_data[prop]):
            meaningful_properties.append(prop)
    
    # Silently skip if no meaningful properties (expected for many CVEs, following curator pattern)
    if not meaningful_properties:
        return None
    
    # Extract CVE ID for source tracking (curator requirement)
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
            # Skip placeholder platforms (curator filtering)
            if not _is_placeholder_value(platform):
                alias_data = _create_alias_data(raw_platform_data, vendor, product, platform, cve_id)
                if alias_data:  # Only store if meaningful data exists
                    # Use unique table index for each platform entry (collector compatibility)
                    platform_index = f"{table_index}_platform_{i}"
                    PLATFORM_ENTRY_NOTIFICATION_REGISTRY['aliasExtraction'][platform_index] = alias_data
                    entry_count += 1
    
    # Return None if no valid entries created (curator pattern)
    if entry_count == 0:
        return None
    
    # Build header identifier for the modal
    header_parts = []
    if 'cna' in raw_platform_data:
        header_parts.append(raw_platform_data['cna'])
    if 'source_id' in raw_platform_data:
        header_parts.append(raw_platform_data['source_id'])
    if vendor and not _is_placeholder_value(vendor):
        header_parts.append(vendor)
    if product and not _is_placeholder_value(product):
        header_parts.append(product)
    
    header_identifier = f"Platform Entry {table_index} ({', '.join(header_parts)})"
    
    # Create tooltip with curator-style information
    tooltip = f"Source mapping extraction data&#013;{entry_count} alias entries with meaningful properties&#013;Click to view detailed alias information"
    
    # Create the badge HTML with curator theme (blue for extraction)
    badge_html = f'<span class="badge modal-badge bg-info" onclick="BadgeModalManager.openAliasExtractionModal(\'{table_index}\', \'{header_identifier}\')" title="{tooltip}">📋 Aliases ({entry_count})</span> '
    
    return badge_html


def _create_alias_data(affected_item: Dict, vendor: str = None, product: str = None, platform: str = None, cve_id: str = None) -> Dict:
    """
    Create alias data entry following curator logic exactly.
    
    Args:
        affected_item: The affected item data
        vendor: Vendor name (may be None)
        product: Product name (may be None)  
        platform: Platform name (may be None)
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
    Check if a value is considered a placeholder following curator logic exactly.
    
    Args:
        value: The value to check
        
    Returns:
        True if the value is a placeholder, False otherwise
    """
    if not value or value in [None, "", 0]:
        return True
        
    # Convert to string and normalize for checking (matching curator exactly)
    str_value = str(value).lower().strip()
    
    # Comprehensive placeholder patterns (based on curator sourceDataConcern analysis)
    placeholder_patterns = [
        'n/a', 'n\\/a', 'n\\a', 'na', 'unknown', 'unspecified', 'not specified',
        'not applicable', 'none', 'null', 'undefined', '-', '--', '---',
        'tbd', 'to be determined', 'pending', 'missing', 'empty', 'blank',
        'default', 'generic', 'various', 'multiple', 'mixed', 'other',
        'all', 'any', '*', 'no information', 'no data', 'not available',
        'not disclosed', 'confidential', 'redacted', 'vendor', 'product',
        # Platform-specific placeholders
        'all platforms', 'multiple platforms', 'various platforms', 'unspecified platform',
        'all versions', 'multiple versions', 'various versions', 'all systems'
    ]
    
    return str_value in placeholder_patterns

