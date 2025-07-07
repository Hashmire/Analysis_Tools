# Import Python dependencies
import pandas as pd
import json
import html
import os
import datetime
import re 

# Import the new logging system
from .workflow_logger import get_logger, LogGroup

# Get logger instance
logger = get_logger()

# NOTE: Debug logging is disabled by default in config.json (level: "INFO", debug group: enabled: false)
# To enable debug logging temporarily for troubleshooting:
# 1. Change "level": "DEBUG" in config.json, OR
# 2. Change "DEBUG": {"enabled": true} in config.json logging groups
# Debug messages help with troubleshooting pandas Series issues and HTML generation

def extract_badge_names(badge_html_list):
    """Extract badge names from HTML badge list"""
    badge_names = []
    for badge_html in badge_html_list:
        # Extract text between > and </span>
        match = re.search(r'>([^<]+)</span>', badge_html)
        if match:
            badge_names.append(match.group(1))
    return badge_names

# Load configuration
def load_config():
    """Load configuration from config.json"""
    try:
        config_path = os.path.join(os.path.dirname(__file__), 'config.json')
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        # Return a default config to prevent crashes
        return {
            'application': {
                'toolname': 'Hashmire/Analysis_Tools',
                'version': '0.1.0'
            }
        }

config = load_config()
VERSION = config['application']['version']
TOOLNAME = config['application']['toolname']

# Import Analysis Tool
from . import processData

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

class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles sets and other non-standard JSON types"""
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        if pd.isna(obj):
            return None
        try:
            return json.JSONEncoder.default(self, obj)
        except TypeError:
            # If we can't encode it normally, convert to string
            return str(obj)

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
        'version_concerns': []
    }
    
    # Extended list of comparators to check for
    comparators = ['<', '>', '=', '<=', '=<', '=>', '>=', '!=']
    
    
    processed_concerns = set()  
    
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
                    r'^(.+?)[\.\-_]*alpha[\.\-_]*(\d*)[\.\-_]*$',
                    r'^(.+?)[\.\-_]*a[\.\-_]*(\d+)[\.\-_]*$',
                    
                    # Beta patterns
                    r'^(.+?)[\.\-_]*beta[\.\-_]*(\d*)[\.\-_]*$',
                    r'^(.+?)[\.\-_]*b[\.\-_]*(\d+)[\.\-_]*$',
                    
                    # Release candidate patterns
                    r'^(.+?)[\.\-_]*rc[\.\-_]*(\d*)[\.\-_]*$',
                    r'^(.+?)[\.\-_]*release[\s\-_]+candidate[\.\-_]*(\d*)[\.\-_]*$',
                    
                    # Patch patterns
                    r'^(.+?)[\.\-_]*patch[\.\-_]*(\d*)[\.\-_]*$',
                    r'^(.+?)[\.\-_]*p[\.\-_]*(\d+)[\.\-_]*$',
                    r'^(.+?)\.p(\d+)$', # Handle 3.1.0.p7
                    
                    # Hotfix patterns
                    r'^(.+?)[\.\-_]*hotfix[\.\-_]*(\d*)[\.\-_]*$',
                    r'^(.+?)[\.\-_]*hf[\.\-_]*(\d+)[\.\-_]*$',
                    
                    # Service pack patterns
                    r'^(.+?)[\.\-_]*service[\s\-_]+pack[\.\-_]*(\d*)[\.\-_]*$',
                    r'^(.+?)[\.\-_]*sp[\.\-_]*(\d+)[\.\-_]*$',
                    r'^(.+?)\.sp(\d+)$', # Handle 3.0.0.sp1
                    
                    # Update patterns
                    r'^(.+?)[\.\-_]*update[\.\-_]*(\d*)[\.\-_]*$',
                    r'^(.+?)[\.\-_]*upd[\.\-_]*(\d+)[\.\-_]*$',
                    
                    # Fix patterns
                    r'^(.+?)[\.\-_]*fix[\.\-_]*(\d+)[\.\-_]*$',
                    
                    # Revision patterns
                    r'^(.+?)[\.\-_]*revision[\.\-_]*(\d+)[\.\-_]*$',
                    r'^(.+?)[\.\-_]*rev[\.\-_]*(\d+)[\.\-_]*$'
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
                        processed_concerns.add(html.escape(concern))
            
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
            
            # Handle unexpected types
            elif field_value is not None:  
                concern = f"Unexpected data type in {field}: {type(field_value).__name__}"
                processed_concerns.add(html.escape(concern))
    
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
    
    # FINALIZE VERSION CONCERNS (AFTER ALL VERSIONS PROCESSED)
    characteristics['version_concerns'] = list(processed_concerns)[:20]  # Limit to 20 concerns max
    if len(processed_concerns) > 20:
        characteristics['version_concerns'].append(f"... and {len(processed_concerns) - 20} more concerns")
    
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

def convertRowDataToHTML(row, nvdSourceData: pd.DataFrame, tableIndex=0) -> str:
    # Access platformEntryMetadata for consolidated fields
    platform_metadata = row.get('platformEntryMetadata', {})
    platform_format_type = platform_metadata.get('platformFormatType', '')
    raw_platform_data = row.get('rawPlatformData', {})
    
    # Convert platform format type to human-readable format
    readable_format_type = platform_format_type
    if platform_format_type == 'cveAffectsVersionRange':
        readable_format_type = "CVE Affects Version Range(s)"
    elif platform_format_type == 'cveAffectsVersionSingle':
        readable_format_type = "CVE Affects Version(s) Exact" 
    elif platform_format_type == 'cveAffectsVersionMix':
        readable_format_type = "CVE Affects Version(s) Exact and Range(s)"
    elif platform_format_type == 'cveAffectsNoVersions':
        readable_format_type = "CVE Affects Product (No Versions)"
    elif platform_format_type == 'nvdConfiguration':
        readable_format_type = "NVD Configuration"

    # Add ID to the table based on the index
    html = f"""<div id="rowDataTable_{tableIndex}_container" class="table-container">
    <table id="rowDataTable_{tableIndex}" class="table table-hover">"""
    
    # Define the keys and their labels, ensuring rawPlatformData is last
    keys_and_labels = [
        ('platformEntryMetadata.dataResource', 'Data Resource'),
        ('sourceID', 'Source ID'),
        ('sourceRole', 'Source Role')
        # rawPlatformData is handled separately below
    ]
    
    # Process the standard metadata keys first
    for key, label in keys_and_labels:
        if '.' in key:  # Handle nested properties
            parent, child = key.split('.')
            if parent in row and child in row[parent]:
                value = row[parent][child]
                html += f"""
                <tr>
                    <td>{label}</td>
                    <td>{value}</td>
                </tr>
                """
        elif key in row:  # Handle direct properties
            value = row[key]
            if key == 'sourceID':
                source_info = processData.getNVDSourceDataByUUID(value, nvdSourceData)
                if source_info:
                    name = source_info.get('name', 'N/A')
                    contact_email = source_info.get('contactEmail', 'N/A')
                    source_identifiers = source_info.get('sourceIdentifiers', [])
                    tooltip_content = f"Contact Email: {contact_email} &#013;Source Identifiers: {', '.join(source_identifiers)}"
                    value = f"<span title=\"{tooltip_content}\">{name}</span>"
                html += f"""
                <tr>
                    <td>{label}</td>
                    <td>{value}</td>
                </tr>
                """
            else:
                html += f"""
                <tr>
                    <td>{label}</td>
                    <td>{value}</td>
                </tr>
                """

    # Add Platform Entry Notifications with badges immediately after sourceRole
    html += "<tr><td>Platform Entry Notifications</td><td>"

    # Get characteristics once using consolidated function
    raw_platform_data = row.get('rawPlatformData', {})
    characteristics = analyze_version_characteristics(raw_platform_data)

    # Group badges by priority level
    danger_badges = []
    warning_badges = []
    sourceDataConcern_badges = []
    info_badges = []
    standard_badges = []

    # 1. Platform Format Type badge
    version_checks = platform_metadata.get('cpeVersionChecks', [])
    version_tooltip = "No versions detected!"
    if version_checks:
        version_lines = []
        for check in version_checks:
            check_str = ", ".join([f"{k}: {v}" for k, v in check.items()])
            version_lines.append(check_str)
        version_tooltip = "&#013;".join(version_lines)

    if platform_format_type == 'cveAffectsNoVersions':
        danger_badges.append(f'<span class="badge bg-danger" title="{version_tooltip}">{readable_format_type}</span> ')
    else:
        info_badges.append(f'<span class="badge bg-info" title="{version_tooltip}">{readable_format_type}</span> ')

    # 2. Duplicate Entries badge
    duplicate_indices = platform_metadata.get('duplicateRowIndices', [])
    if duplicate_indices:
        duplicate_tooltip = f"This entry has duplicate data at row(s): {', '.join(map(str, duplicate_indices))}"
        warning_badges.append(f'<span class="badge bg-warning" title="{duplicate_tooltip}">Duplicate Entries Detected</span> ')

    # 3. Git version type badge using consolidated analysis
    if characteristics['has_git_version_type']:
        git_tooltip = "git versionType not advised for CPE Ranges"
        git_badge_color = "bg-warning"
        
        # Elevate to danger level when used with version ranges
        if platform_format_type in ['cveAffectsVersionRange', 'cveAffectsVersionMix']:
            git_badge_color = "bg-danger"
            git_tooltip = "CRITICAL: CPE Range Matching Logic does not currently support git versionTypes"
            
        warning_badges.append(f'<span class="badge {git_badge_color}" title="{git_tooltip}">git versionType</span> ')

    # 4. Wildcard patterns badge using consolidated analysis
    if characteristics['has_wildcards']:
        wildcard_tooltip = 'Versions array contains wildcard patterns requiring special handling'
        warning_badges.append(f'<span class="badge bg-warning" title="{wildcard_tooltip}">Wildcard Patterns</span> ')
        
    # 5. Version changes badge using consolidated analysis
    if characteristics['has_version_changes']:
        changes_tooltip = 'Versions array contains change history information requiring special handling'
        warning_badges.append(f'<span class="badge bg-warning" title="{changes_tooltip}">Has Version Changes</span> ')

    # 6. CPE Array badge
    cpes_array = []
    has_cpe_array = platform_metadata.get('hasCPEArray', False)
    if has_cpe_array and 'cpes' in raw_platform_data and isinstance(raw_platform_data['cpes'], list):
        cpes_array = [cpe for cpe in raw_platform_data['cpes'] if cpe and isinstance(cpe, str) and cpe.startswith('cpe:')]
        if cpes_array:
            cpe_count = len(cpes_array)
            cpe_tooltip = f"Versions array contains {cpe_count} CPEs from affected entry: " + ", ".join(cpes_array)
            info_badges.append(f'<span class="badge bg-info" title="{cpe_tooltip}">CVE Affected CPES Data: {cpe_count}</span> ')    # 7. CPE Base Strings badge
    cpe_base_strings = platform_metadata.get('cpeBaseStrings', [])
    if cpe_base_strings:
        sorted_cpe_base_strings = sort_cpe_strings_for_tooltip(cpe_base_strings)
        base_strings_tooltip = "&#013;".join(sorted_cpe_base_strings)
        standard_badges.append(f'<span class="badge bg-secondary" title="{base_strings_tooltip}">CPE Base String Searches</span> ')

    # 8. Culled Confirmed Mappings badge
    culled_mappings = platform_metadata.get('culledConfirmedMappings', [])
    if culled_mappings:
        culled_tooltip = "Confirmed mappings filtered out due to lower specificity:&#013;" + "&#013;".join(culled_mappings)
        standard_badges.append(f'<span class="badge bg-secondary" title="{culled_tooltip}">Culled Confirmed Mappings: {len(culled_mappings)}</span> ')    # 9. Platform Data Concern badge
    if platform_metadata.get('platformDataConcern', False):
        platform_tooltip = 'Unexpected Platforms data detected in affected entry'
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{platform_tooltip}">Platforms Data Concern</span> ')

    # 10. Version concerns badge using consolidated analysis
    if characteristics['version_concerns']:
        versions_tooltip = 'Versions array contains formatting issues:&#013;' + '&#013;'.join(characteristics['version_concerns'])
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{versions_tooltip}">Versions Data Concern</span> ')
    
    # 9b. CPEs Array Data Concern
    if 'cpes' in raw_platform_data and isinstance(raw_platform_data['cpes'], list):
        cpe_concerns = []
        for cpe in raw_platform_data['cpes']:
            if isinstance(cpe, str) and cpe.startswith('cpe:'):
                parts = cpe.split(':')
                if len(parts) >= 6 and parts[0] == 'cpe' and parts[1] == '2.3':
                    version = parts[5]
                    if any(text_comp in version.lower() for text_comp in VERSION_TEXT_PATTERNS):
                        cpe_concerns.append(f"CPE contains improper version text: {cpe}")
                        break
        
        if cpe_concerns:
            cpe_tooltip = 'CPEs array contains formatting issues:&#013;' + '&#013;'.join(cpe_concerns)
            sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{cpe_tooltip}">CPEs Array Data Concern</span> ')

    # 11. Add N/A Data Concern badges for problematic vendor/product values
    if 'vendor' in raw_platform_data and isinstance(raw_platform_data['vendor'], str) and raw_platform_data['vendor'].lower() == 'n/a':
        vendor_na_tooltip = 'Vendor field contains "n/a" which prevents proper CPE matching'
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{vendor_na_tooltip}">Vendor: N/A</span> ')

    if 'product' in raw_platform_data and isinstance(raw_platform_data['product'], str) and raw_platform_data['product'].lower() == 'n/a':
        product_na_tooltip = 'Product field contains "n/a" which prevents proper CPE matching'
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{product_na_tooltip}">Product: N/A</span> ')    # 11. Enhanced CPE Curation Badge - includes detailed Unicode normalization info
    curation_tracking = platform_metadata.get('cpeCurationTracking', {})
    unicode_normalization_details = platform_metadata.get('unicodeNormalizationDetails', {})
    # Keep legacy flag check for backward compatibility
    unicode_normalization_used = platform_metadata.get('unicodeNormalizationApplied', False)

    # Determine if we have any transformations or normalization to report
    has_curation = bool(curation_tracking)
    has_unicode_details = bool(unicode_normalization_details.get('transformations') or unicode_normalization_details.get('skipped_fields'))
    has_legacy_unicode = unicode_normalization_used and not has_unicode_details

    if has_curation or has_unicode_details or has_legacy_unicode:
        # Build enhanced tooltip with both curation and normalization info
        curation_tooltip = 'Source to CPE transformations applied:&#013;'
        
        # Add detailed Unicode normalization info if present
        if has_unicode_details:
            transformations = unicode_normalization_details.get('transformations', [])
            skipped_fields = unicode_normalization_details.get('skipped_fields', [])
            
            for transform in transformations:
                field = transform['field'].replace('_', ' ').title()
                curation_tooltip += f"{field}: '{transform['original']}' → '{transform['normalized']}'&#013;"
            
            for skipped in skipped_fields:
                field = skipped['field'].replace('_', ' ').title()
                curation_tooltip += f"{field}: '{skipped['original']}' → [SKIPPED - {skipped['reason']}]&#013;"
        
        # Add legacy Unicode normalization info if present
        elif has_legacy_unicode:
            curation_tooltip += 'Unicode characters normalized to ASCII&#013;'
        
        # Add existing curation info
        if has_curation:
            # List vendor modifications
            for mod in curation_tracking.get('vendor', []):
                curation_tooltip += f"Vendor: {mod['original']} → {mod['curated']}&#013;"
            
            # List product modifications  
            for mod in curation_tracking.get('product', []):
                curation_tooltip += f"Product: {mod['original']} → {mod['curated']}&#013;"
                
            # List platform modifications
            for mod in curation_tracking.get('platform', []):
                curation_tooltip += f"Platform: {mod['original']} → {mod['curated']}&#013;"
            
            # List vendor+product combinations
            for mod in curation_tracking.get('vendor_product', []):
                curation_tooltip += f"Vendor+Product: {mod['original']} → {mod['curated']}&#013;"
            
            # List vendor+packageName combinations
            for mod in curation_tracking.get('vendor_package', []):
                curation_tooltip += f"Vendor+Package: {mod['original']} → {mod['curated']}&#013;"
        
        # Enhanced badge name to reflect broader scope
        sourceDataConcern_badges.append(f'<span class="badge bg-sourceDataConcern" title="{curation_tooltip}">Source to CPE Transformations Applied</span> ')

    # 12. CPE API Error Detection Badge
    sorted_cpe_query_data = row.get('sortedCPEsQueryData', {})
    if sorted_cpe_query_data:
        cpe_error_messages = []
        invalid_cpe_count = 0
        
        for cpe_string, query_data in sorted_cpe_query_data.items():
            if isinstance(query_data, dict):
                # Check for error status
                if query_data.get('status') == 'invalid_cpe' or query_data.get('status') == 'error':
                    invalid_cpe_count += 1
                    error_msg = query_data.get('error_message', 'Unknown CPE API error')
                    cpe_error_messages.append(f"CPE: {cpe_string}&#013;Error: {error_msg}")
        
        if invalid_cpe_count > 0:
            error_tooltip = f"NVD CPE API returned errors for {invalid_cpe_count} CPE strings:&#013;" + "&#013;&#013;".join(cpe_error_messages)
            warning_badges.append(f'<span class="badge bg-danger" title="{error_tooltip}">CPE API Errors ({invalid_cpe_count})</span> ')

    # Add badges in priority order: Danger -> Warning -> Info -> Standard
    html += ''.join(danger_badges)
    html += ''.join(warning_badges)
    html += ''.join(sourceDataConcern_badges)
    html += ''.join(info_badges)
    html += ''.join(standard_badges)    # Log badge summary for this row
    badge_details = {}
    
    # Extract badge names from each category
    if danger_badges:
        badge_names = []
        for badge_html in danger_badges:
            # Extract text between > and < 
            import re
            match = re.search(r'>([^<]+)</span>', badge_html)
            if match:
                badge_names.append(match.group(1))
        badge_details["Danger"] = badge_names
    
    if warning_badges:
        badge_names = []
        for badge_html in warning_badges:
            import re
            match = re.search(r'>([^<]+)</span>', badge_html)
            if match:
                badge_names.append(match.group(1))
        badge_details["Warning"] = badge_names
    
    if sourceDataConcern_badges:
        badge_names = []
        for badge_html in sourceDataConcern_badges:
            import re
            match = re.search(r'>([^<]+)</span>', badge_html)
            if match:
                badge_names.append(match.group(1))
        badge_details["Data Concern"] = badge_names
    
    if info_badges:
        badge_names = []
        for badge_html in info_badges:
            import re
            match = re.search(r'>([^<]+)</span>', badge_html)
            if match:
                badge_names.append(match.group(1))
        badge_details["Info"] = badge_names
    
    if standard_badges:
        badge_names = []
        for badge_html in standard_badges:
            import re
            match = re.search(r'>([^<]+)</span>', badge_html)
            if match:
                badge_names.append(match.group(1))
        badge_details["Standard"] = badge_names
    
    if badge_details:
        vendor = row.get('rawPlatformData', {}).get('vendor', 'Unknown')
        product = row.get('rawPlatformData', {}).get('product', 'Unknown')
        source_role = row.get('sourceRole', 'Unknown')
        
        # Format badge details for logging
        badge_summary = []
        for badge_type, badge_names in badge_details.items():
            if len(badge_names) == 1:
                badge_summary.append(f"{badge_type}: {badge_names[0]}")
            else:
                badge_summary.append(f"{badge_type}: [{', '.join(badge_names)}]")
        
        logger.info(f"Badges added for row {tableIndex} ({source_role}): {vendor}/{product} ({' | '.join(badge_summary)})", group="badge_gen")
    else:
        vendor = row.get('rawPlatformData', {}).get('vendor', 'Unknown')
        product = row.get('rawPlatformData', {}).get('product', 'Unknown')
        source_role = row.get('sourceRole', 'Unknown')
        logger.debug(f"No badges added for row {tableIndex} ({source_role}): {vendor}/{product}", group="badge_gen")

    html += "</td></tr>"

    # Now handle rawPlatformData after the notifications section
    if 'rawPlatformData' in row:
        value = row['rawPlatformData']
        if 'vendor' in value:
            html += f"""
            <tr>
                <td>Vendor Value</td>
                <td>{value['vendor']}</td>
            </tr>
            """
        if 'product' in value:
            html += f"""
            <tr>
                <td>Product Value</td>
                <td>{value['product']}</td>
            </tr>
            """
        if 'repo' in value:
            html += f"""
            <tr>
                <td>Repository</td>
                <td>{value['repo']}</td>
            </tr>
            """
        if 'collectionUrl' in value:
            html += f"""
            <tr>
                <td>Collection URL</td>
                <td>{value['collectionUrl']}</td>
            </tr>
            """
        if 'packageName' in value:
            html += f"""
            <tr>
                <td>Package Name</td>
                <td>{value['packageName']}</td>
            </tr>
            """
        if 'platforms' in value:
            html += f"""
            <tr>
                <td>Platforms</td>
                <td>{value['platforms']}</td>
            </tr>
            """
        if 'modules' in value:
            html += f"""
            <tr>
                <td>Modules</td>
                <td>{value['modules']}</td>
            </tr>
            """
        if 'programFiles' in value:
            html += f"""
            <tr>
                <td>Program Files</td>
                <td>{value['programFiles']}</td>
            </tr>
            """
        if 'programRoutines' in value:
            html += f"""
            <tr>
                <td>Program Routines</td>
                <td>{value['programRoutines']}</td>
            </tr>
            """
        import json
        json_value = json.dumps(value, cls=CustomJSONEncoder)
        
        html += f"""
        <tr>
            <td>Raw Platform Data</td>
            <td><details><summary>Review rawPlatformData</summary>
            <code id="rawPlatformData_{tableIndex}" class="rawPlatformData">{json_value}</code></details></td>
        </tr>
        """
    
    html += "</table></div>"
        
    return html.replace('\n', '')

def convertCPEsQueryDataToHTML(sortedCPEsQueryData: dict, tableIndex=0, row_data=None) -> str:
    try:
        # Early exit if there's no data to process
        if not sortedCPEsQueryData or len(sortedCPEsQueryData) == 0:
            logger.debug(f"No CPE query data to process for table {tableIndex}", group="PAGE_GEN")
            return f"""
            <div class="card mb-3">
                <div class="card-header">
                    <h5 class="mb-0">CPE Suggestions</h5>
                </div>
                <div class="card-body">
                    <p class="text-muted">No CPE suggestions available for this entry.</p>
                </div>
            </div>
            """.replace('\n', '')
        
        logger.debug(f"Processing {len(sortedCPEsQueryData)} CPE query results for table {tableIndex}", group="PAGE_GEN")
        
        # Create a collapsible card similar to Provenance Assistance
        html_content = f"""
        <div class="card mb-3">
            <div class="card-header d-flex justify-content-between align-items-center" 
                 id="cpeHeader_{tableIndex}" 
                 data-bs-toggle="collapse" 
                 data-bs-target="#cpeCollapse_{tableIndex}" 
                 style="cursor: pointer;">
                <h5 class="mb-0">
                    CPE Suggestions
                </h5>
                <span class="arrow-icon">&uarr;</span>
            </div>
            <div id="cpeCollapse_{tableIndex}" class="collapse show" aria-labelledby="cpeHeader_{tableIndex}">
                <div class="card-body">
                    <div id="matchesTable_{tableIndex}_container" class="table-container">
                    <table id="matchesTable_{tableIndex}" class="table table-hover matchesTable">
                    <thead>
                      <tr>
                        <th style="width: 65%">CPE Base String</th>
                        <th style="width: 35%">Information</th>
                      </tr>
                    </thead>
                    <tbody>
                    """
        # Get confirmed mappings from row data if available
        confirmed_mappings = []
        if row_data is not None and hasattr(row_data, 'get') and 'platformEntryMetadata' in row_data:
            platform_metadata = row_data['platformEntryMetadata']
            confirmed_mappings = platform_metadata.get('confirmedMappings', [])
        
        if confirmed_mappings:
            logger.debug(f"Processing {len(confirmed_mappings)} confirmed mappings", group="PAGE_GEN")
        
        # First, process confirmed mappings and check for duplicates in API results
        confirmed_mappings_processed = set()
        for cpe_base in confirmed_mappings:
            # Check if this confirmed mapping also exists in the API results
            if cpe_base in sortedCPEsQueryData:
                # This is a duplicate - merge the information
                base_value = sortedCPEsQueryData[cpe_base]
                
                total_match_count = (base_value.get('depFalseCount', 0) + base_value.get('depTrueCount', 0))
                dep_true_count = base_value.get('depTrueCount', 0)
                dep_false_count = base_value.get('depFalseCount', 0)
                
                # Skip confirmed mappings where all API results are deprecated (no viable CPE names)
                if total_match_count > 0 and dep_true_count == total_match_count:
                    logger.debug(f"Skipping confirmed mapping {cpe_base} - all {total_match_count} results deprecated", group="PAGE_GEN")
                    confirmed_mappings_processed.add(cpe_base)
                    continue
                
                versions_found = base_value.get('versionsFound', 0)
                
                # Calculate search_count correctly by checking for cveAffectedCPEsArray
                search_count = base_value.get('searchCount', 0)
                has_cpes_array_source = 'searchSourcecveAffectedCPEsArray' in base_value
                
                # If the CPEs array source isn't already counted in searchCount, add it
                base_value_keys = list(base_value.keys()) if hasattr(base_value, 'keys') else []
                cpe_array_already_counted = any(
                    k.startswith('searchSource') and 'cveAffectedCPEsArray' in k 
                    for k in base_value_keys 
                    if k != 'searchSourcecveAffectedCPEsArray'
                )
                
                if has_cpes_array_source and not cpe_array_already_counted:
                    search_count += 1
                    
                versions_found_content = base_value.get('versionsFoundContent', [])
                
                # Create Version Matches Identified tooltip content from versionsFoundContent
                versions_found_tooltip_content = "Versions Matches Identified:  &#10;".join(
                    "&#10;".join(f"{k}: {v}" for k, v in version.items())
                    for version in versions_found_content
                )
                
                # Create Relevant Match String Searches tooltip content
                search_keys = []
                for key in base_value.keys():
                    if key.startswith('searchSource'):
                        search_keys.append((key, base_value[key]))

                # Sort the search keys based on a priority order
                def sort_search_keys(item):
                    key, _ = item
                    if 'cveAffectedCPEsArray' in key:
                        return 0  # Highest priority
                    elif 'partvendorproduct' in key:
                        return 1
                    elif 'vendorproduct' in key:
                        return 2
                    elif 'product' in key:
                        return 3
                    elif 'vendor' in key:
                        return 4
                    else:
                        return 5

                # Sort the keys
                sorted_search_keys = sorted(search_keys, key=sort_search_keys)

                # Create the tooltip content
                search_keys_tooltip_content = "Relevant Match String Searches:&#10;"
                for key, value in sorted_search_keys:
                    search_keys_tooltip_content += f"{key}:  {value}&#10;"
                
                # Sanitize base_key for use as ID
                base_key_id = cpe_base.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_")
                
                # Create enhanced reference/provenance content
                references = base_value.get('references', [])
                references_html = ""
                
                if references:
                    # Group references by type for better organization
                    ref_types = {}
                    for ref in references:
                        ref_type = ref.get('type', 'Unknown')
                        if ref_type not in ref_types:
                            ref_types[ref_type] = []
                        ref_types[ref_type].append(ref)
                    
                    # Create a more detailed tooltip with organized sections
                    references_tooltip_content = "CPE Provenance & References:&#10;&#10;"
                    
                    # Show top reference types with counts
                    type_summary = []
                    for ref_type, type_refs in ref_types.items():
                        total_freq = sum(r.get('frequency', 1) for r in type_refs)
                        type_summary.append((ref_type, len(type_refs), total_freq))
                    
                    # Sort by total frequency for most relevant types first
                    type_summary.sort(key=lambda x: x[2], reverse=True)
                    
                    # Add type summary
                    for ref_type, count, total_freq in type_summary[:4]:  # Show top 4 types
                        references_tooltip_content += f"• {ref_type}: {count} refs ({total_freq} occurrences)&#10;"
                    
                    if len(type_summary) > 4:
                        remaining_types = len(type_summary) - 4
                        references_tooltip_content += f"• ...and {remaining_types} more type(s)&#10;"
                    
                    references_tooltip_content += "&#10;Top References:&#10;"
                    
                    # Show top 5 individual references
                    for ref in references[:5]:
                        ref_type = ref.get('type', 'Unknown')
                        ref_url = ref.get('url', 'No URL')
                        ref_count = ref.get('frequency', 1)
                        # Truncate long URLs for readability
                        display_url = ref_url if len(ref_url) <= 60 else ref_url[:57] + "..."
                        references_tooltip_content += f"[{ref_type}] {display_url} ({ref_count}x)&#10;"
                    
                    if len(references) > 5:
                        references_tooltip_content += f"...and {len(references) - 5} more references"
                          # Create expandable reference section HTML
                base_key_safe = cpe_base.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_").replace("*", "star")
                
                references_html = f'''
                <div class="reference-section">
                    <span class="badge modal-badge bg-info" 
                          onclick="BadgeModalManager.openReferencesModal('{base_key_safe}', '{cpe_base.replace("'", "\\'")}', {len(references)})" id="refBadge_{base_key_safe}">
                        📋 Provenance ({len(references)})
                    </span>
                </div>'''
                
                # Store reference data in a global JavaScript object for the modal
                ref_data_js = "{"
                for ref_type, type_refs in sorted(ref_types.items(), key=lambda x: sum(r.get('frequency', 1) for r in x[1]), reverse=True):
                    total_freq = sum(r.get('frequency', 1) for r in type_refs)
                    ref_data_js += f'''
                        "{ref_type}": {{
                            "total_freq": {total_freq},
                            "refs": ['''
                    
                    for ref in type_refs:
                        ref_url = ref.get('url', 'No URL').replace('"', '\\"').replace("'", "\\'")
                        ref_count = ref.get('frequency', 1)
                        ref_data_js += f'''
                                {{"url": "{ref_url}", "count": {ref_count}}},'''
                    
                    ref_data_js = ref_data_js.rstrip(',') + "]}, "
                
                ref_data_js = ref_data_js.rstrip(', ') + "}"
                
                # Register reference data with the modular badge modal system
                references_html += f'''
                <script>
                    BadgeModal.registerData('references', '{base_key_safe}', {ref_data_js});
                </script>'''
                
                # Create sorting priority data structure
                sorting_data = {
                    "searches": {},
                    "versions": versions_found_content,
                    "statistics": {
                        "total_cpe_names": total_match_count,
                        "final_count": dep_false_count,
                        "deprecated_count": dep_true_count
                    },
                    "confirmedMapping": {
                        "confidence": "High",
                        "source": "Manual Verification",
                        "verified_date": "Platform Entry"
                    }
                }
                
                # Add search source data
                for key, value in sorted_search_keys:
                    sorting_data["searches"][key] = value
                
                # Convert sorting data to JavaScript format
                sorting_data_js = json.dumps(sorting_data, cls=CustomJSONEncoder)
                
                # Register sorting priority data with the modular badge modal system
                sorting_priority_html = f'''
                <script>
                    BadgeModal.registerData('sortingPriority', '{base_key_safe}', {sorting_data_js});
                </script>'''
                
                # Let frontend JavaScript calculate tab count dynamically from actual data
                context_count = ""  # Remove hardcoded count, let JS calculate
                
                # Create merged row with both confirmed mapping badge and API data
                html_content += f"""
                <tr id="row_{base_key_id}" class="cpe-row confirmed-mapping-row" data-cpe-base="{cpe_base}">
                    <td class="text-break">{cpe_base}</td>
                    <td>
                        <div class="d-flex flex-wrap gap-1 align-items-center">
                            <span class="badge modal-badge bg-success"
                                  onclick="BadgeModalManager.openConfirmedMappingModal('{base_key_safe}', '{cpe_base.replace("'", "\\'")}')">
                                ✅ Confirmed Mapping
                            </span>
                            <span class="badge modal-badge bg-secondary" 
                                  onclick="BadgeModalManager.openSortingPriorityModal('{base_key_safe}', '{cpe_base.replace("'", "\\'")}', 'statistics')">
                                📈 Sorting Priority Context
                            </span>"""
                
                # Add enhanced references section if available
                if references:
                    html_content += references_html
                
                # Add sorting priority registration
                html_content += sorting_priority_html
                
                html_content += f"""
                        </div>
                    </td>
                </tr>
                """
                
                # Mark this confirmed mapping as processed and track for removal from API results
                confirmed_mappings_processed.add(cpe_base)
            else:
                # This confirmed mapping is not in API results - show as confirmed mapping only
                base_key_id = cpe_base.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_")
                base_key_safe = cpe_base.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_").replace("*", "star")
                
                # Create minimal sorting priority data for confirmed mapping only
                sorting_data = {
                    "confirmedMapping": {
                        "confidence": "High",
                        "source": "Manual Verification",
                        "verified_date": "Platform Entry"
                    }
                }
                
                # Convert sorting data to JavaScript format
                sorting_data_js = json.dumps(sorting_data, cls=CustomJSONEncoder)
                
                # Register sorting priority data
                sorting_priority_html = f'''
                <script>
                    BadgeModal.registerData('sortingPriority', '{base_key_safe}', {sorting_data_js});
                </script>'''
                
                html_content += f"""
                <tr id="row_{base_key_id}" class="cpe-row confirmed-mapping-row" data-cpe-base="{cpe_base}">
                    <td class="text-break">{cpe_base}</td>
                    <td>
                        <div class="d-flex flex-wrap gap-1 align-items-center">
                            <span class="badge modal-badge bg-success"
                                  onclick="BadgeModalManager.openConfirmedMappingModal('{base_key_safe}', '{cpe_base.replace("'", "\\'")}')">
                                ✅ Confirmed Mapping
                            </span>
                        </div>
                    </td>
                </tr>
                {sorting_priority_html}
                """
                confirmed_mappings_processed.add(cpe_base)
        
        # Process all API query results, excluding those already processed as confirmed mappings
        for base_key, base_value in sortedCPEsQueryData.items():
            # Skip this API result if it was already processed as a confirmed mapping
            if base_key in confirmed_mappings_processed:
                continue
                
            total_match_count = (base_value.get('depFalseCount', 0) + base_value.get('depTrueCount', 0))
            dep_true_count = base_value.get('depTrueCount', 0)
            dep_false_count = base_value.get('depFalseCount', 0)
            versions_found = base_value.get('versionsFound', 0)
            
            # Skip CPE base strings where all results are deprecated (no viable CPE names)
            if total_match_count > 0 and dep_true_count == total_match_count:
                logger.debug(f"Skipping {base_key} - all {total_match_count} results deprecated", group="PAGE_GEN")
                continue
            
            # Calculate search_count correctly by checking for cveAffectedCPEsArray
            search_count = base_value.get('searchCount', 0)
            has_cpes_array_source = 'searchSourcecveAffectedCPEsArray' in base_value
            
            # If the CPEs array source isn't already counted in searchCount, add it
            base_value_keys = list(base_value.keys()) if hasattr(base_value, 'keys') else []
            cpe_array_already_counted = any(
                k.startswith('searchSource') and 'cveAffectedCPEsArray' in k 
                for k in base_value_keys 
                if k != 'searchSourcecveAffectedCPEsArray'
            )
            if has_cpes_array_source and not cpe_array_already_counted:
                search_count += 1
                
            versions_found_content = base_value.get('versionsFoundContent', [])
            
            # Create Version Matches Identified tooltip content from versionsFoundContent
            versions_found_tooltip_content = "Versions Matches Identified:  &#10;".join(
                "&#10;".join(f"{k}: {v}" for k, v in version.items())
                for version in versions_found_content
            )
            
            # Create Relevant Match String Searches tooltip content
            search_keys = []
            for key in base_value.keys():
                if key.startswith('searchSource'):
                    search_keys.append((key, base_value[key]))

            # Sort the search keys based on a priority order
            def sort_search_keys(item):
                key, _ = item
                if 'cveAffectedCPEsArray' in key:
                    return 0  # Highest priority
                elif 'partvendorproduct' in key:
                    return 1
                elif 'vendorproduct' in key:
                    return 2
                elif 'product' in key:
                    return 3
                elif 'vendor' in key:
                    return 4
                else:
                    return 5

            # Sort the keys
            sorted_search_keys = sorted(search_keys, key=sort_search_keys)

            # Create the tooltip content
            search_keys_tooltip_content = "Relevant Match String Searches:&#10;"
            for key, value in sorted_search_keys:
                search_keys_tooltip_content += f"{key}:  {value}&#10;"
            
            # Create enhanced reference/provenance content
            references = base_value.get('references', [])
            references_html = ""
            
            # Define base_key_safe for use in modal system (needed for both references and sorting priority)
            base_key_safe = base_key.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_").replace("*", "star")
            
            if references:
                # Group references by type for better organization
                ref_types = {}
                for ref in references:
                    ref_type = ref.get('type', 'Unknown')
                    if ref_type not in ref_types:
                        ref_types[ref_type] = []
                    ref_types[ref_type].append(ref)
                
                # Create a more detailed tooltip with organized sections
                references_tooltip_content = "CPE Provenance & References:&#10;&#10;"
                
                # Show top reference types with counts
                type_summary = []
                for ref_type, type_refs in ref_types.items():
                    total_freq = sum(r.get('frequency', 1) for r in type_refs)
                    type_summary.append((ref_type, len(type_refs), total_freq))
                
                # Sort by total frequency for most relevant types first
                type_summary.sort(key=lambda x: x[2], reverse=True)
                
                # Add type summary
                for ref_type, count, total_freq in type_summary[:4]:  # Show top 4 types
                    references_tooltip_content += f"• {ref_type}: {count} refs ({total_freq} occurrences)&#10;"
                
                if len(type_summary) > 4:
                    remaining_types = len(type_summary) - 4
                    references_tooltip_content += f"• ...and {remaining_types} more type(s)&#10;"
                
                references_tooltip_content += "&#10;Top References:&#10;"
                
                # Show top 5 individual references
                for ref in references[:5]:
                    ref_type = ref.get('type', 'Unknown')
                    ref_url = ref.get('url', 'No URL')
                    ref_count = ref.get('frequency', 1)
                    # Truncate long URLs for readability
                    display_url = ref_url if len(ref_url) <= 60 else ref_url[:57] + "..."
                    references_tooltip_content += f"[{ref_type}] {display_url} ({ref_count}x)&#10;"
                
                if len(references) > 5:
                    references_tooltip_content += f"...and {len(references) - 5} more references"
                
                # Create expandable reference section HTML
                references_html = f'''
                <div class="reference-section">
                    <span class="badge modal-badge bg-info" 
                          onclick="BadgeModalManager.openReferencesModal('{base_key_safe}', '{base_key.replace("'", "\\'")}', {len(references)})" id="refBadge_{base_key_safe}">
                        📋 Provenance ({len(references)})
                    </span>
                </div>'''
                
                # Store reference data in a global JavaScript object for the modal
                ref_data_js = "{"
                for ref_type, type_refs in sorted(ref_types.items(), key=lambda x: sum(r.get('frequency', 1) for r in x[1]), reverse=True):
                    total_freq = sum(r.get('frequency', 1) for r in type_refs)
                    ref_data_js += f'''
                        "{ref_type}": {{
                            "total_freq": {total_freq},
                            "refs": ['''
                    
                    for ref in type_refs:
                        ref_url = ref.get('url', 'No URL').replace('"', '\\"').replace("'", "\\'")
                        ref_count = ref.get('frequency', 1)
                        ref_data_js += f'''
                                {{"url": "{ref_url}", "count": {ref_count}}},'''
                    
                    ref_data_js = ref_data_js.rstrip(',') + "]}, "
                
                ref_data_js = ref_data_js.rstrip(', ') + "}"
                
                # Register reference data with the modular badge modal system
                references_html += f'''
                <script>
                    BadgeModal.registerData('references', '{base_key_safe}', {ref_data_js});
                </script>'''
            
            # Create sorting priority data structure for this base_key
            sorting_data = {
                "searches": {},
                "versions": versions_found_content,
                "statistics": {
                    "total_cpe_names": total_match_count,
                    "final_count": dep_false_count,
                    "deprecated_count": dep_true_count
                }
            }
            
            # Add search source data
            for key, value in sorted_search_keys:
                sorting_data["searches"][key] = value
            
            # Convert sorting data to JavaScript format
            sorting_data_js = json.dumps(sorting_data, cls=CustomJSONEncoder)
            
            # Register sorting priority data with the modular badge modal system
            sorting_priority_html = f'''
            <script>
                BadgeModal.registerData('sortingPriority', '{base_key_safe}', {sorting_data_js});
            </script>'''
            
            # Sanitize base_key for use as ID
            base_key_id = base_key.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_")
            
            # Let frontend JavaScript calculate tab count dynamically from actual data
            context_count = ""  # Remove hardcoded count, let JS calculate
            
            html_content += f"""
            <tr id="row_{base_key_id}" class="cpe-row" data-cpe-base="{base_key}">
                <td class="text-break">{base_key}</td>
                <td>
                <div class="d-flex flex-wrap gap-1 align-items-center">
                    <span class="badge modal-badge bg-secondary" 
                          onclick="BadgeModalManager.openSortingPriorityModal('{base_key_safe}', '{base_key.replace("'", "\\'")}', 'statistics')">
                        📈 Sorting Priority Context
                    </span>"""
            
            # Add enhanced references section if available
            if references:
                html_content += references_html
            
            # Add sorting priority registration
            html_content += sorting_priority_html
            
            html_content += f"""
                    </div>
                </td>
            </tr>
            """

        # Close the table and container divs
        html_content += """
        </tbody>
        </table>
        </div>
                </div>
            </div>
        </div>
        """
        return html_content.replace('\n', '')
    except Exception as e:
        logger.error(f"HTML conversion failed: Unable to convert CPE query data to HTML at table index {tableIndex} - {e}", group="page_generation")
        logger.error(f"sortedCPEsQueryData type: {type(sortedCPEsQueryData)}", group="page_generation")
        if hasattr(sortedCPEsQueryData, 'keys'):
            logger.error(f"sortedCPEsQueryData keys: {list(sortedCPEsQueryData.keys())}", group="page_generation")
        raise e

# Add the new file to the list of JS files to include
def getCPEJsonScript() -> str:
    # Get the current script's directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Define the files with paths relative to the current script
    js_files = [
        os.path.join(current_dir, "static", "js", "badge_modal_system.js"),  # Add modular system first
        os.path.join(current_dir, "static", "js", "modular_rules.js"),
        os.path.join(current_dir, "static", "js", "cpe_json_handler.js"),
        os.path.join(current_dir, "static", "js", "ui_controller.js"),
        os.path.join(current_dir, "static", "js", "selection_manager.js"),
        os.path.join(current_dir, "static", "js", "timestamp_handler.js"),
        os.path.join(current_dir, "static", "js", "provenance_assistance.js"),
        os.path.join(current_dir, "static", "js", "completion_tracker.js"),
        os.path.join(current_dir, "static", "js", "custom_cpe_builder.js")
    ]
    
    # Read JavaScript files
    js_content = ""
    
    # Read each file and add its content to the script tag
    for js_file in js_files:
        try:
            with open(js_file, 'r', encoding='utf-8') as f:
                js_content += f.read() + "\n\n"
        except Exception as e:
            logger.error(f"JavaScript file loading failed: Unable to read JS file '{js_file}' - {e}", group="page_generation")
            # Add placeholder comment if file can't be read
            js_content += f"// Error loading {js_file}\n\n"
    # Add JSON settings HTML injection with defensive checking
    safe_json_settings = JSON_SETTINGS_HTML if 'JSON_SETTINGS_HTML' in globals() and JSON_SETTINGS_HTML else {}
    json_settings_injection = f"""
    // JSON Settings HTML generated by Python and injected on page load
    window.JSON_SETTINGS_HTML = {json.dumps(safe_json_settings, cls=CustomJSONEncoder)};
    """
    
    # Add intelligent settings injection with defensive checking
    safe_intelligent_settings = INTELLIGENT_SETTINGS if 'INTELLIGENT_SETTINGS' in globals() and INTELLIGENT_SETTINGS else {}
    intelligent_settings_js = ""
    if safe_intelligent_settings:
        intelligent_settings_js = f"""
        // Intelligent settings computed by Python
        window.INTELLIGENT_SETTINGS = {json.dumps(safe_intelligent_settings, cls=CustomJSONEncoder)};
        """
    
    # Inject NON_SPECIFIC_VERSION_VALUES as a global JavaScript variable
    # This ensures the JavaScript uses the same list as Python (single source of truth)
    non_specific_versions_js = f"""
    // Non-specific version values injected from Python (single source of truth)
    window.NON_SPECIFIC_VERSION_VALUES = {json.dumps(NON_SPECIFIC_VERSION_VALUES)};
    """
    

    js_content += json_settings_injection + intelligent_settings_js + non_specific_versions_js
    
    # Return the JavaScript wrapped in a script tag
    return f"<script>\n{js_content}\n</script>"

def has_update_related_content(raw_platform_data):
    """Check if rawPlatformData contains update-related content that can be extracted by JavaScript"""
    if not raw_platform_data or 'versions' not in raw_platform_data:
        return False
    
    versions = raw_platform_data.get('versions', [])
    if not isinstance(versions, list):
        return False
    
    # Synchronized patterns with JavaScript Update Patterns rule
    # These must match exactly to ensure button only shows when extraction will work
    update_patterns = [
        # Alpha patterns
        r'^(.+?)[\.\-_]*alpha[\.\-_]*(\d*)[\.\-_]*$',
        r'^(.+?)[\.\-_]*a[\.\-_]*(\d+)[\.\-_]*$',
        
        # Beta patterns
        r'^(.+?)[\.\-_]*beta[\.\-_]*(\d*)[\.\-_]*$',
        r'^(.+?)[\.\-_]*b[\.\-_]*(\d+)[\.\-_]*$',
        
        # Release candidate patterns
        r'^(.+?)[\.\-_]*rc[\.\-_]*(\d*)[\.\-_]*$',
        r'^(.+?)[\.\-_]*release[\s\-_]+candidate[\.\-_]*(\d*)[\.\-_]*$',
        
        # Patch patterns
        r'^(.+?)[\.\-_]*patch[\.\-_]*(\d*)[\.\-_]*$',
        r'^(.+?)[\.\-_]*p[\.\-_]*(\d+)[\.\-_]*$',
        r'^(.+?)\.p(\d+)$', # Handle 3.1.0.p7
        
        # Hotfix patterns
        r'^(.+?)[\.\-_]*hotfix[\.\-_]*(\d*)[\.\-_]*$',
        r'^(.+?)[\.\-_]*hf[\.\-_]*(\d+)[\.\-_]*$',
        
        # Service pack patterns
        r'^(.+?)[\.\-_]*service[\s\-_]+pack[\.\-_]*(\d*)[\.\-_]*$',
        r'^(.+?)[\.\-_]*sp[\.\-_]*(\d+)[\.\-_]*$',
        r'^(.+?)\.sp(\d+)$', # Handle 3.0.0.sp1
        
        # Update patterns
        r'^(.+?)[\.\-_]*update[\.\-_]*(\d*)[\.\-_]*$',
        r'^(.+?)[\.\-_]*upd[\.\-_]*(\d+)[\.\-_]*$',
        
        # Fix patterns
        r'^(.+?)[\.\-_]*fix[\.\-_]*(\d+)[\.\-_]*$',
        
        # Revision patterns
        r'^(.+?)[\.\-_]*revision[\.\-_]*(\d+)[\.\-_]*$',
        r'^(.+?)[\.\-_]*rev[\.\-_]*(\d+)[\.\-_]*$'
    ]
    
    # Compile patterns for efficiency (case-insensitive to match JavaScript /i flag)
    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in update_patterns]
    
    # Check version, lessThan, and lessThanOrEqual fields
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
                for pattern in compiled_patterns:
                    if pattern.match(field_value):  # Use match() for anchored patterns
                        return True
    
    return False

def update_cpeQueryHTML_column(dataframe, nvdSourceData):
    """Updates the dataframe to include a column with HTML for CPE query results"""
    
    # Make a copy to avoid modifying the original
    result_df = dataframe.copy()
    
    for index, row in result_df.iterrows():
        # Existing attribute code
        data_attrs = []
        
        # Add data attributes with platform info, etc.
        if 'platformData' in row.index and not pd.isna(row['platformData']):
            platform_data = row['platformData']
            try:
                # Add data ID for better reference
                data_attrs.append(f'id="platform-data-container-{index}"')
                
                # Keep existing data attributes
                platform_data_json = json.dumps(platform_data, cls=CustomJSONEncoder)
                data_attrs.append(f'data-platform-data="{html.escape(platform_data_json)}"')
                
                # Add a unique ID for the raw platform data for easier access
                data_attrs.append(f'data-raw-platform-id="raw-platform-{index}"')
            except Exception as e:
                logger.error(f"Platform data serialization failed: Unable to convert platform data to JSON - {e}", group="page_generation")
        
        # Check if this row has update-related content
        raw_platform_data = row.get('rawPlatformData', {})
        has_update_content = has_update_related_content(raw_platform_data)
        
        # Create the collapse button and update toggle button
        buttons_html = f'<button id="collapseRowButton_{index}" class="btn btn-secondary" onclick="toggleRowCollapse({index})">Collapse Row (Mark Complete)</button>'
        
        collapse_button_html = f'<div class="mb-3 d-flex gap-2" id="buttonContainer_{index}">{buttons_html}</div>'
          # Populate the rowDataHTML column with the HTML content
        row_html_content = convertRowDataToHTML(row, nvdSourceData, index)
        result_df.at[index, 'rowDataHTML'] = collapse_button_html + row_html_content
        
        # Create the main HTML div with all data attributes and a unique ID
        if 'trimmedCPEsQueryData' in row.index and pd.notna(row['trimmedCPEsQueryData']):
            sortedCPEsQueryData = row['trimmedCPEsQueryData'] 
            
            # Determine if matches table is empty to decide if provenance div should be expanded
            # trimmedCPEsQueryData should be a dictionary, check if it has entries
            if isinstance(sortedCPEsQueryData, dict):
                has_matches = len(sortedCPEsQueryData) > 0
            elif hasattr(sortedCPEsQueryData, '__len__'):
                has_matches = len(sortedCPEsQueryData) > 0
            else:
                has_matches = False
            
            attr_string = " ".join(data_attrs)
            html_content = f"""<div id="cpe-query-container-{index}" class="cpe-query-container" {attr_string}>"""
            
            # Add provenance assistance div ABOVE the matches table and ONLY for non-NVD rows
            if 'sourceRole' in row.index and not pd.isna(row['sourceRole']) and str(row['sourceRole']) != 'NVD':
                provenance_div = create_provenance_assistance_div(index, collapsed=has_matches)
                html_content += provenance_div
            # Add custom CPE Builder section between provenance assistance and CPE suggestions
            customCPEBuilderHTML = create_custom_cpe_builder_div(index, collapsed=has_matches)
            html_content += customCPEBuilderHTML
            
            # Add the matches table after the custom CPE Builder div, but only if there's data to process
            if has_matches:
                html_content += convertCPEsQueryDataToHTML(sortedCPEsQueryData, index, row)
            else:
                # No CPE query results to process - add a simple message or skip entirely
                html_content += f"""
                <div class="card mb-3">
                    <div class="card-header">
                        <h5 class="mb-0">CPE Suggestions</h5>
                    </div>
                    <div class="card-body">
                        <p class="text-muted">No CPE suggestions available for this entry.</p>
                    </div>
                </div>
                """.replace('\n', '')
            
            html_content += "</div>"  # Close the container div
            result_df.at[index, 'cpeQueryHTML'] = html_content
        
        # Store settings HTML for this table
        table_id = f"matchesTable_{index}"
        raw_platform_data = row.get('rawPlatformData', {})
        store_json_settings_html(table_id, raw_platform_data)
    
    return result_df

# Modify the buildHTMLPage function to accept and include globalCVEMetadata

def buildHTMLPage(affectedHtml, targetCve, globalCVEMetadata=None, vdbIntelHtml=None,):
    
    # Generate UTC timestamp for the page creation
    utc_timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    
    # Get the current script's directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # CSS file path relative to the current script
    css_file = os.path.join(current_dir, "static", "css", "styles.css")
    
    # Read CSS file
    css_content = ""
    try:
        with open(css_file, 'r') as f:
            css_content = f.read()
    except Exception as e:
        logger.error(f"CSS file loading failed: Unable to read CSS file '{css_file}' - {e}", group="page_generation")
        css_content = "/* Error loading CSS file */"

    pageStartHTML = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.3.0/font/bootstrap-icons.css">
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous"></script>
        <style>
        {css_content}
        </style>
    </head>
    <body>
    """
    
    # Add the hidden div for globalCVEMetadata if provided
    globalCVEMetadataHTML = ""
    if globalCVEMetadata is not None:
        # Encode the JSON data and escape any HTML special characters
        global_metadata_json = json.dumps(globalCVEMetadata, cls=CustomJSONEncoder)
        escaped_metadata = html.escape(global_metadata_json)
        
        # Create hidden div with the data attribute
        globalCVEMetadataHTML = f"""
        <!-- Hidden div containing global CVE metadata for Provenance Assistance -->
        <div id="global-cve-metadata" style="display:none;" data-cve-metadata='{escaped_metadata}'></div>
        """
    
    pageBodyHeaderHTML = f"""
    <!-- Tool Info Header -->
    <div class="header" style="margin-left: 10px;">
        <h1>{TOOLNAME}<small> - version: {VERSION}</small></h1>
    </div>
    {globalCVEMetadataHTML}
    """
    
    # Rest of the function remains unchanged
    # <button class="tablinks" onclick="openCity(event, 'vdbIntelDashboard')">VDB Intel Dashboard</button>
    pageBodyTabsHTML = """
    <!-- Tab links -->
    <div class="tab">
        <button class="tablinks" onclick="openCity(event, 'cveListCPESuggester')">CVE List CPE Suggester</button>
    </div>
    """
    
    # Updated cveIdIndicatorHTML without the inline JavaScript
    cveIdIndicatorHTML = f"""
    <div class="d-flex align-items-center justify-content-between" style="margin-left: 10px; margin-right: 10px;">
        <h3 id="cve-id" style="margin-bottom: 0px;"><b>{targetCve}</b></h3>
        <span id="generationTimestamp" class="text-muted">Generated: <time datetime="{utc_timestamp}"></time></span>
    </div>
    <hr style="margin: 10px; border: 1px solid;">
    """
    
    # Updated pageBodyCPESuggesterHTML without the inline JavaScript
    pageBodyCPESuggesterHTML = f"""
    <!-- CPE Applicability Generator -->
    <div id="cveListCPESuggester" class="tabcontent" style="display: block; border-left: 0px;">
        <div id="cpeSuggesterHeader" class="header">
            <h3>CPE Applicability Generator</h3>
        </div>
        {affectedHtml}
        <script>
            // Initialize the timestamp handler with the generated timestamp
            window.timestampHandler.init("{utc_timestamp}");
        </script>
    </div>
    """
    
    #if (vdbIntelHtml is None):
    #    pageBodyVDBIntelHTML = """
    #    <!-- VDB Intel Dashboard -->
    #    <div id="vdbIntelDashboard" class="tabcontent" style="border-left: 0px;">
    #        <h3>VDB Intel Dashboard</h3>
    #        <p>Basic User Mode does not support VDB Intel Check!</p>
    #    </div>
    #    """
    #else:
    #    pageBodyVDBIntelHTML = f"""
    #    <!-- VDB Intel Dashboard -->
    #    <div id="vdbIntelDashboard" class="tabcontent" style="border-left: 0px;">
    #        <h3>VDB Intel Dashboard</h3>
    #        {vdbIntelHtml}
    #    </div>
    #    """
        
    pageEndHTML = """
    <script>
    function openCity(evt, cityName) {
        var i, tabcontent, tablinks;
        tabcontent = document.getElementsByClassName("tabcontent");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
        }
        tablinks = document.getElementsByClassName("tablinks");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].className = tablinks[i].className.replace(" active", "");
        }
        document.getElementById(cityName).style.display = "block";
        evt.currentTarget.className += " active";
    }
    </script>
    </body>
    </html>
    """
    
    fullHtml = (pageStartHTML + getCPEJsonScript() + pageBodyHeaderHTML + pageBodyTabsHTML + cveIdIndicatorHTML + 
                pageBodyCPESuggesterHTML + pageEndHTML)
    
    return fullHtml

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

# Add this new function along with the other div creation functions

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

# Store generated settings HTML for JavaScript access
JSON_SETTINGS_HTML = {}
INTELLIGENT_SETTINGS = {}

# Ensure clean state on module import
def _initialize_clean_state():
    """Initialize clean global state when module is imported"""
    global JSON_SETTINGS_HTML, INTELLIGENT_SETTINGS
    JSON_SETTINGS_HTML = {}
    INTELLIGENT_SETTINGS = {}

# Call initialization immediately
_initialize_clean_state()

# Update the HTML generation for provenance descriptions:
def generateProvenanceDetailsHTML(provenance_data, provenance_id):
    html = f"""
    <div class="description-container-wrapper">
        <button id="toggle_{provenance_id}" class="btn btn-info btn-sm btn-transition mb-2"
                onclick="toggleProvenanceDescription('toggle_{provenance_id}')">Show Description</button>
        <div id="description_{provenance_id}" class="description-container collapsed">
            <div class="card">
                <div class="card-body">
                    {provenance_data['description']}
                </div>
            </div>
        </div>
    </div>
    """
    return html

def analyze_data_for_smart_defaults(raw_platform_data):
    """Generate intelligent settings using centralized analysis"""
    characteristics = analyze_version_characteristics(raw_platform_data)
    
    return {
        'enableWildcardExpansion': characteristics['has_wildcards'],
        'enableVersionChanges': characteristics['has_version_changes'],
        'enableSpecialVersionTypes': characteristics['has_special_version_types'],
        'enableInverseStatus': characteristics['has_inverse_status'],
        'enableMultipleBranches': characteristics['has_multiple_branches'],
        'enableMixedStatus': characteristics['has_mixed_status'],
        'enableGapProcessing': characteristics['needs_gap_processing'],
        'enableUpdatePatterns': characteristics['has_update_patterns']
    }

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

def clear_global_html_state():
    """Clear global HTML generation state to prevent accumulation between CVE processing runs"""
    global JSON_SETTINGS_HTML, INTELLIGENT_SETTINGS
    
    # Reinitialize to ensure completely fresh state
    JSON_SETTINGS_HTML = {}
    INTELLIGENT_SETTINGS = {}
    
    logger.debug("Cleared global HTML state - reinitialized fresh dictionaries", group="page_generation")

