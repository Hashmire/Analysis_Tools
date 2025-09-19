# Import Python dependencies
import pandas as pd
import json
import html
import os
import datetime
import re 

# Import the new logging system
from ..logging.workflow_logger import get_logger, LogGroup

# Import global source manager functions
from ..storage.nvd_source_manager import get_source_info, get_source_name

# Import unified source manager
from .unified_source_manager import get_unified_source_manager

# Get logger instance
logger = get_logger()

# Import the new badge and modal system
from .badge_modal_system import *

def detect_overlapping_ranges(dataframe: pd.DataFrame) -> Dict[int, List[Dict]]:
    """
    Detect overlapping version ranges across all platform entries with semantic version comparison.
    
    Analyzes all rows in the dataframe to identify cases where multiple platform entries
    have version ranges that overlap or could be consolidated into a single range.
    Uses semantic version comparison for accurate overlap detection.
    
    Args:
        dataframe: The complete dataframe with all platform entries
        
    Returns:
        Dictionary mapping table indices to lists of overlapping range findings
    """
    import re
    from packaging import version
    
    logger.debug(f"detect_overlapping_ranges called with {len(dataframe)} entries", group="PAGE_GEN")
    
    findings = {}  # table_index -> list of findings
    
    # Group platform entries by all CPE base string properties that create unique platform identities
    cpe_groups = {}
    
    for index, row in dataframe.iterrows():
        raw_platform_data = row.get('rawPlatformData', {})
        
        # Extract all fields used in Unique CPE Base String generation
        vendor = raw_platform_data.get('vendor', '').strip().lower()
        product = raw_platform_data.get('product', '').strip().lower()
        platforms = raw_platform_data.get('platforms', [])
        package_name = raw_platform_data.get('packageName', '').strip()
        collection_url = raw_platform_data.get('collectionURL', '').strip()
        
        # Skip entries without proper vendor/product (core requirements)
        if not vendor or not product or vendor in ['unknown', 'n/a', '-'] or product in ['unknown', 'n/a', '-']:
            continue
        
        # Create comprehensive CPE base string identifier including all distinguishing fields
        cpe_base_parts = [vendor, product]
        
        # Add platforms if present (affects targetHW in CPE generation)
        if platforms and isinstance(platforms, list):
            platforms_str = '|'.join(sorted([str(p).lower().strip() for p in platforms if p]))
            if platforms_str:
                cpe_base_parts.append(f"platforms:{platforms_str}")
        
        # Add packageName if present (creates separate vendor/product combinations for Maven)
        if package_name:
            cpe_base_parts.append(f"package:{package_name.lower()}")
            
        # Add collectionURL if present (distinguishes package sources)
        if collection_url:
            cpe_base_parts.append(f"collection:{collection_url.lower()}")
        
        # Create CPE base string identifier
        cpe_base = '|'.join(cpe_base_parts)
        
        if cpe_base not in cpe_groups:
            cpe_groups[cpe_base] = []
        
        cpe_groups[cpe_base].append({
            'table_index': index,
            'raw_platform_data': raw_platform_data,
            'row': row
        })
    
    logger.debug(f"Grouped platform entries: {len(cpe_groups)} CPE groups found", group="PAGE_GEN")
    for cpe_base, entries in cpe_groups.items():
        logger.debug(f"CPE group '{cpe_base}': {len(entries)} entries", group="PAGE_GEN")
    
    # Analyze each CPE group for overlapping ranges
    for cpe_base, entries in cpe_groups.items():
        if len(entries) < 2:
            logger.debug(f"Skipping CPE group '{cpe_base}': only {len(entries)} entry", group="PAGE_GEN")
            continue  # Need at least 2 entries to have overlaps
        
        logger.debug(f"Analyzing CPE group '{cpe_base}' with {len(entries)} entries for overlaps", group="PAGE_GEN")
        
        # Extract version ranges from each entry
        version_ranges = []
        for entry in entries:
            ranges = extract_version_ranges(entry['raw_platform_data'])
            logger.debug(f"Table {entry['table_index']}: extracted {len(ranges)} version ranges", group="PAGE_GEN")
            for version_range in ranges:
                version_ranges.append({
                    'table_index': entry['table_index'],
                    'range': version_range,
                    'vendor': entry['raw_platform_data'].get('vendor', ''),
                    'product': entry['raw_platform_data'].get('product', ''),
                    'entry': entry
                })
                logger.debug(f"Table {entry['table_index']}: range {version_range}", group="PAGE_GEN")
        
        # Check for overlaps between version ranges
        overlaps = find_range_overlaps(version_ranges)
        
        logger.debug(f"CPE group '{cpe_base}': found {len(overlaps)} overlaps from {len(version_ranges)} version ranges", group="PAGE_GEN")
        
        # Process overlaps and create findings for affected table indices
        for overlap in overlaps:
            logger.debug(f"Processing overlap: {overlap['overlap_type']} affecting tables {overlap['affected_table_indices']}", group="PAGE_GEN")
            # Create findings for all affected table indices with perspective-based descriptions
            for table_index in overlap['affected_table_indices']:
                if table_index not in findings:
                    findings[table_index] = []
                
                # Get cross-references (other table indices involved)
                cross_refs = [idx for idx in overlap['affected_table_indices'] if idx != table_index]
                
                # Create perspective-based description for this table
                perspective_description = create_perspective_description(
                    table_index, cross_refs, overlap, version_ranges
                )
                
                finding = {
                    'overlap_type': overlap['overlap_type'],
                    'range_description': perspective_description['description'],
                    'related_table_indices': cross_refs,
                    'suggestion': perspective_description['suggestion'],
                    'affected_ranges': overlap['ranges_involved'],
                    'cpe_base': cpe_base
                }
                
                findings[table_index].append(finding)
                logger.debug(f"Added finding to table {table_index}: {overlap['overlap_type']} overlap", group="PAGE_GEN")
    
    return findings

def create_perspective_description(current_table_index: int, related_table_indices: List[int], 
                                  overlap_info: Dict, all_version_ranges: List[Dict]) -> Dict:
    """
    Create perspective-based description of overlaps from the current table's viewpoint.
    
    Args:
        current_table_index: The table index being described
        related_table_indices: Other table indices involved in overlaps
        overlap_info: The overlap information
        all_version_ranges: All version ranges to look up details
        
    Returns:
        Dictionary with description and suggestion from current table's perspective
    """
    # Find the current table's range
    current_range = None
    related_ranges = []
    
    for version_range in all_version_ranges:
        if version_range['table_index'] == current_table_index:
            current_range = version_range['range']
        elif version_range['table_index'] in related_table_indices:
            related_ranges.append({
                'table_index': version_range['table_index'],
                'range': version_range['range']
            })
    
    if not current_range or not related_ranges:
        return {
            'description': "Has overlapping ranges with other platform entries",
            'suggestion': "Review ranges for potential consolidation or proper bounds definition"
        }
    
    # Format current range
    current_range_desc = format_range(current_range)
    
    # Analyze relationships from current table's perspective
    complete_overlaps = []
    partial_overlaps = []
    
    for related in related_ranges:
        relationship = analyze_range_relationship(current_range, related['range'])
        if relationship['type'] in ['contains', 'contained']:
            complete_overlaps.append({
                'table': related['table_index'],
                'range': format_range(related['range']),
                'relationship': relationship
            })
        else:
            partial_overlaps.append({
                'table': related['table_index'], 
                'range': format_range(related['range']),
                'relationship': relationship
            })
    
    # Build perspective-based description with elegant language
    if complete_overlaps:
        complete_desc = []
        for overlap in complete_overlaps:
            if overlap['relationship']['type'] == 'contains':
                complete_desc.append(f"encompasses the more restrictive range {overlap['range']} from table {overlap['table']}")
            else:  # contained
                complete_desc.append(f"falls entirely within the broader range {overlap['range']} from table {overlap['table']}")
        
        if len(complete_desc) == 1:
            description = f"This version range ({current_range_desc}) {complete_desc[0]}."
        else:
            description = f"This version range ({current_range_desc}) {' and '.join(complete_desc)}."
    elif partial_overlaps:
        partial_desc = []
        for overlap in partial_overlaps:
            partial_desc.append(f"overlaps with range {overlap['range']} from table {overlap['table']}")
        
        if len(partial_desc) == 1:
            description = f"This version range ({current_range_desc}) {partial_desc[0]}."
        else:
            description = f"This version range ({current_range_desc}) {' and '.join(partial_desc)}."
    else:
        description = f"This version range ({current_range_desc}) has overlapping relationships with other platform entries."
    
    # Create dual advisement (consolidation AND proper bounds)
    suggestion_parts = []
    
    # Consolidation advisement
    if complete_overlaps and any(o['relationship']['type'] == 'contains' for o in complete_overlaps):
        suggestion_parts.append("CONSOLIDATION: Consider using this broader range and removing the narrower overlapping ranges")
    elif complete_overlaps and any(o['relationship']['type'] == 'contained' for o in complete_overlaps):
        broader_tables = [str(o['table']) for o in complete_overlaps if o['relationship']['type'] == 'contained']
        suggestion_parts.append(f"CONSOLIDATION: Consider removing this range in favor of the broader range(s) in table(s) {', '.join(broader_tables)}")
    elif partial_overlaps:
        suggestion_parts.append("CONSOLIDATION: Consider consolidating overlapping ranges into a single unified range")
    
    # Proper bounds advisement
    if is_unbounded_range(current_range):
        suggestion_parts.append("PROPER BOUNDS: Consider adding explicit lower bounds to this range to eliminate ambiguity")
    else:
        suggestion_parts.append("PROPER BOUNDS: Consider reviewing and clarifying the exact bounds for this range")
    
    suggestion = "<br>".join(suggestion_parts)
    
    return {
        'description': description,
        'suggestion': suggestion
    }

def analyze_range_relationship(range1: Dict, range2: Dict) -> Dict:
    """Analyze the relationship between two ranges."""
    bounds1 = get_range_bounds(range1)
    bounds2 = get_range_bounds(range2)
    
    if not bounds1 or not bounds2:
        return {'type': 'partial', 'details': 'Unable to determine precise relationship'}
    
    overlap_type = determine_overlap_type(bounds1, bounds2)
    return {'type': overlap_type or 'partial', 'bounds1': bounds1, 'bounds2': bounds2}

def is_unbounded_range(version_range: Dict) -> bool:
    """Check if a range is unbounded (has no explicit lower bound)."""
    from .badge_modal_system import NON_SPECIFIC_VERSION_VALUES
    
    # Check if version is a placeholder/unspecified
    if version_range.get('version'):
        version_str = str(version_range['version']).lower().strip()
        if version_str in [val.lower() for val in NON_SPECIFIC_VERSION_VALUES]:
            # This is a placeholder, only upper bounds are supported in CVE 5.X
            return True  # Placeholder versions are effectively unbounded below
    
    # In CVE 5.X, ranges are defined by version (starting point) + lessThan/lessThanOrEqual
    # A range is unbounded if version is * or a placeholder
    version_str = str(version_range.get('version', '')).lower().strip()
    return version_str == '*' or version_str in [val.lower() for val in NON_SPECIFIC_VERSION_VALUES]

def extract_version_ranges(raw_platform_data: Dict) -> List[Dict]:
    """
    Extract version ranges from platform data for overlap analysis.
    
    Args:
        raw_platform_data: Raw platform data containing version information
        
    Returns:
        List of version range dictionaries with start/end bounds
    """
    ranges = []
    versions = raw_platform_data.get('versions', [])
    
    if not isinstance(versions, list):
        return ranges
    
    for version_entry in versions:
        if not isinstance(version_entry, dict):
            continue
        
        # Extract range boundaries (CVE 5.X only supports version + lessThan/lessThanOrEqual)
        version_range = {
            'version': version_entry.get('version'),
            'lessThan': version_entry.get('lessThan'),
            'lessThanOrEqual': version_entry.get('lessThanOrEqual'),
            'versionType': version_entry.get('versionType'),
            'status': version_entry.get('status', 'unknown'),
            'raw_entry': version_entry
        }
        
        # Skip empty ranges
        range_fields = [version_range['version'], version_range['lessThan'], 
                       version_range['lessThanOrEqual']]
        if not any(field for field in range_fields if field):
            continue
        
        ranges.append(version_range)
    
    return ranges

def find_range_overlaps(version_ranges: List[Dict]) -> List[Dict]:
    """
    Find overlapping version ranges using semantic version comparison.
    
    Args:
        version_ranges: List of version range entries with table indices
        
    Returns:
        List of overlap findings with suggestions for consolidation
    """
    from packaging import version
    
    overlaps = []
    processed_pairs = set()
    
    for i, range1 in enumerate(version_ranges):
        for j, range2 in enumerate(version_ranges[i + 1:], i + 1):
            # Skip if same table index (internal ranges are handled separately)
            if range1['table_index'] == range2['table_index']:
                continue
            
            # Create unique pair identifier
            pair_key = tuple(sorted([range1['table_index'], range2['table_index']]))
            if pair_key in processed_pairs:
                continue
            processed_pairs.add(pair_key)
            
            # Check for overlap
            overlap_result = check_range_overlap(range1['range'], range2['range'])
            if overlap_result:
                overlap_info = {
                    'overlap_type': overlap_result['type'],
                    'description': f"Ranges {format_range(range1['range'])} and {format_range(range2['range'])} {overlap_result['description']}",
                    'affected_table_indices': [range1['table_index'], range2['table_index']],
                    'ranges_involved': [range1['range'], range2['range']],
                    'suggestion': generate_consolidation_suggestion(range1['range'], range2['range'], overlap_result)
                }
                overlaps.append(overlap_info)
    
    return overlaps

def check_range_overlap(range1: Dict, range2: Dict) -> Optional[Dict]:
    """
    Check if two version ranges overlap using semantic version comparison.
    
    Args:
        range1: First version range
        range2: Second version range
        
    Returns:
        Dict with overlap information if overlap exists, None otherwise
    """
    from packaging import version
    
    try:
        # Extract and normalize version bounds
        r1_bounds = get_range_bounds(range1)
        r2_bounds = get_range_bounds(range2)
        
        # Both bounds should exist (even if empty for unbounded ranges)
        if r1_bounds is None or r2_bounds is None:
            return None
        
        # Check for overlap
        overlap_type = determine_overlap_type(r1_bounds, r2_bounds)
        if overlap_type:
            return {
                'type': overlap_type,
                'description': get_overlap_description(overlap_type),
                'bounds1': r1_bounds,
                'bounds2': r2_bounds
            }
    
    except Exception as e:
        # Skip ranges with invalid version formats
        logger.debug(f"Version comparison failed: {e}", group="PAGE_GEN")
        return None
    
    return None

def get_range_bounds(version_range: Dict) -> Optional[Dict]:
    """
    Convert version range to normalized bounds.
    
    Args:
        version_range: Version range dictionary
        
    Returns:
        Dictionary with min/max bounds or None if invalid
    """
    from packaging import version
    
    bounds = {}
    
    # Handle single version
    if version_range.get('version'):
        version_str = str(version_range['version']).lower().strip()
        
        # Import the NON_SPECIFIC_VERSION_VALUES from badge_modal_system
        from .badge_modal_system import NON_SPECIFIC_VERSION_VALUES
        
        # Special handling for * as completely unbounded range
        if version_str == '*':
            # * represents a completely unbounded range (all versions)
            # Don't set any bounds - this will be handled as unbounded
            pass
        # Special handling for placeholder values - these should be omitted from range calculation
        elif version_str in [val.lower() for val in NON_SPECIFIC_VERSION_VALUES]:
            # These are placeholder values that represent missing/undefined data
            # Don't set bounds here - let the range bounds logic handle lessThan/greaterThan only
            pass
        else:
            try:
                v = version.parse(version_str)
                bounds['min'] = v
                bounds['max'] = v
                bounds['min_inclusive'] = True
                bounds['max_inclusive'] = True
            except:
                # If not a valid version and not a placeholder, check if we have range bounds
                if not (version_range.get('lessThan') or version_range.get('lessThanOrEqual')):
                    return None
    
    # Handle range bounds (CVE 5.X only supports lessThan/lessThanOrEqual for upper bounds)
    # Lower bounds are established by the 'version' field as the starting point
    try:
        if version_range.get('lessThan'):
            bounds['max'] = version.parse(str(version_range['lessThan']))
            bounds['max_inclusive'] = False
        elif version_range.get('lessThanOrEqual'):
            bounds['max'] = version.parse(str(version_range['lessThanOrEqual']))
            bounds['max_inclusive'] = True
            
        # If we have a version field and it's not a placeholder, set it as lower bound
        if version_range.get('version'):
            version_str = str(version_range['version']).lower().strip()
            # Import the NON_SPECIFIC_VERSION_VALUES from badge_modal_system
            from .badge_modal_system import NON_SPECIFIC_VERSION_VALUES
            
            if version_str != '*' and version_str not in [val.lower() for val in NON_SPECIFIC_VERSION_VALUES]:
                try:
                    bounds['min'] = version.parse(version_str)
                    bounds['min_inclusive'] = True
                except:
                    pass  # If version parsing fails, treat as unbounded below
            
    except:
        return None
    
    # Ensure we have valid bounds
    if 'min' not in bounds and 'max' not in bounds:
        # Check if this is a completely unbounded range (* with no other bounds)
        if version_range.get('version') == '*' and not any([
            version_range.get('lessThan'),
            version_range.get('lessThanOrEqual')
        ]):
            # This is a completely unbounded range - return empty bounds to indicate this
            return {}
        else:
            return None
    
    # For ranges with only upper bound or only lower bound, this is valid
    # (represents unbounded ranges where placeholder data was omitted)
    
    return bounds

def determine_overlap_type(bounds1: Dict, bounds2: Dict) -> Optional[str]:
    """
    Determine the type of overlap between two version ranges.
    
    Args:
        bounds1: First range bounds
        bounds2: Second range bounds
        
    Returns:
        String describing overlap type or None if no overlap
    """
    # Handle completely unbounded ranges (empty bounds or no min/max)
    bounds1_unbounded = (bounds1 is None or 
                        len(bounds1) == 0 or 
                        (not bounds1.get('min') and not bounds1.get('max')))
    bounds2_unbounded = (bounds2 is None or 
                        len(bounds2) == 0 or 
                        (not bounds2.get('min') and not bounds2.get('max')))
    
    if bounds1_unbounded and bounds2_unbounded:
        return "identical"  # Both completely unbounded
    
    if bounds1_unbounded:
        return "contains"  # bounds1 (unbounded) contains bounds2
    
    if bounds2_unbounded:
        return "contained"  # bounds1 is contained in bounds2 (unbounded)
    
    # Handle unbounded ranges
    r1_min = bounds1.get('min')
    r1_max = bounds1.get('max')
    r2_min = bounds2.get('min')
    r2_max = bounds2.get('max')
    
    # Check if ranges actually overlap
    if r1_max and r2_min:
        if r1_max < r2_min or (r1_max == r2_min and not (bounds1.get('max_inclusive') and bounds2.get('min_inclusive'))):
            return None
    
    if r2_max and r1_min:
        if r2_max < r1_min or (r2_max == r1_min and not (bounds2.get('max_inclusive') and bounds1.get('min_inclusive'))):
            return None
    
    # Determine overlap type with better logic for unbounded ranges
    
    # Case 1: Identical ranges
    if (r1_min == r2_min and r1_max == r2_max and 
        bounds1.get('min_inclusive') == bounds2.get('min_inclusive') and
        bounds1.get('max_inclusive') == bounds2.get('max_inclusive')):
        return "identical"
    
    # Case 2: One range completely contains the other
    # Range 1 contains Range 2
    r1_contains_r2 = True
    if r2_min is not None:
        if r1_min is None:  # r1 is unbounded below, so it contains r2's lower bound
            pass
        elif r1_min > r2_min:  # r1's lower bound is higher than r2's
            r1_contains_r2 = False
        elif r1_min == r2_min and not bounds1.get('min_inclusive') and bounds2.get('min_inclusive'):
            r1_contains_r2 = False
    
    if r2_max is not None:
        if r1_max is None:  # r1 is unbounded above, so it contains r2's upper bound
            pass
        elif r1_max < r2_max:  # r1's upper bound is lower than r2's
            r1_contains_r2 = False
        elif r1_max == r2_max and not bounds1.get('max_inclusive') and bounds2.get('max_inclusive'):
            r1_contains_r2 = False
    
    # Range 2 contains Range 1
    r2_contains_r1 = True
    if r1_min is not None:
        if r2_min is None:  # r2 is unbounded below, so it contains r1's lower bound
            pass
        elif r2_min > r1_min:  # r2's lower bound is higher than r1's
            r2_contains_r1 = False
        elif r2_min == r1_min and not bounds2.get('min_inclusive') and bounds1.get('min_inclusive'):
            r2_contains_r1 = False
    
    if r1_max is not None:
        if r2_max is None:  # r2 is unbounded above, so it contains r1's upper bound
            pass
        elif r2_max < r1_max:  # r2's upper bound is lower than r1's
            r2_contains_r1 = False
        elif r2_max == r1_max and not bounds2.get('max_inclusive') and bounds1.get('max_inclusive'):
            r2_contains_r1 = False
    
    if r1_contains_r2 and not r2_contains_r1:
        return "contains"
    elif r2_contains_r1 and not r1_contains_r2:
        return "contained"
    elif r1_contains_r2 and r2_contains_r1:
        return "identical"  # They contain each other, so they're effectively identical
    else:
        return "partial"

def get_overlap_description(overlap_type: str) -> str:
    """Get human-readable description of overlap type."""
    descriptions = {
        "identical": "are identical and should be consolidated",
        "contains": "has complete overlap - one range contains the other",
        "contained": "has complete overlap - one range is contained within the other", 
        "partial": "have partial overlap and could potentially be consolidated"
    }
    return descriptions.get(overlap_type, "overlap")

def format_range(version_range: Dict) -> str:
    """Format version range for display."""
    # Import the NON_SPECIFIC_VERSION_VALUES from badge_modal_system
    from .badge_modal_system import NON_SPECIFIC_VERSION_VALUES
    
    # Check if we have a version field that's not a placeholder
    if version_range.get('version'):
        version_str = str(version_range['version']).lower().strip()
        
        # Special handling for * as completely unbounded
        if version_str == '*':
            # Check if we have any bounds - if not, it's completely unbounded
            has_bounds = any([
                version_range.get('lessThan'),
                version_range.get('lessThanOrEqual')
            ])
            if not has_bounds:
                return "all versions"
        elif version_str not in [val.lower() for val in NON_SPECIFIC_VERSION_VALUES]:
            # Show the version as starting point for CVE 5.X ranges
            version_part = f"v{version_range['version']}"
    
    # Build range description from bounds (CVE 5.X format)
    parts = []
    
    # Add version as starting point if it's not a placeholder
    if version_range.get('version'):
        version_str = str(version_range['version']).lower().strip()
        if version_str != '*' and version_str not in [val.lower() for val in NON_SPECIFIC_VERSION_VALUES]:
            parts.append(f"v{version_range['version']}")
    
    # Add upper bounds
    if version_range.get('lessThan'):
        parts.append(f"<{version_range['lessThan']}")
    elif version_range.get('lessThanOrEqual'):
        parts.append(f"<={version_range['lessThanOrEqual']}")
    
    if parts:
        return " AND ".join(parts)
    else:
        # This is an unbounded range (no specific bounds)
        return "unbounded"

def generate_consolidation_suggestion(range1: Dict, range2: Dict, overlap_result: Dict) -> str:
    """Generate consolidation suggestion based on overlap analysis."""
    overlap_type = overlap_result['type']
    bounds1 = overlap_result['bounds1']
    bounds2 = overlap_result['bounds2']
    
    if overlap_type == "identical":
        return "Consider consolidating identical ranges into a single platform entry"
    elif overlap_type == "contains":
        # Determine which range is broader
        range1_broader = is_range_broader(bounds1, bounds2)
        if range1_broader:
            broader_range_desc = format_bounds_description(bounds1)
            return f"Consider using the broader range ({broader_range_desc}) and removing the narrower range"
        else:
            broader_range_desc = format_bounds_description(bounds2)
            return f"Consider using the broader range ({broader_range_desc}) and removing the narrower range"
    elif overlap_type == "contained":
        # Same as contains, but phrased differently
        range1_broader = is_range_broader(bounds1, bounds2)
        if range1_broader:
            broader_range_desc = format_bounds_description(bounds1)
            return f"Consider using the broader range ({broader_range_desc}) and removing the narrower range"
        else:
            broader_range_desc = format_bounds_description(bounds2)
            return f"Consider using the broader range ({broader_range_desc}) and removing the narrower range"
    elif overlap_type == "partial":
        # Try to suggest a consolidated range that encompasses both
        consolidated_bounds = get_consolidated_bounds(bounds1, bounds2)
        consolidated_desc = format_bounds_description(consolidated_bounds)
        return f"Consider consolidating to range {consolidated_desc}"
    
    return "Review for potential consolidation"

def is_range_broader(bounds1: Dict, bounds2: Dict) -> bool:
    """Determine if bounds1 is broader than bounds2."""
    # A range is broader if it has a lower minimum or higher maximum (or is unbounded)
    
    # Check lower bound
    lower_broader = False
    if bounds1.get('min') is None and bounds2.get('min') is not None:
        lower_broader = True  # bounds1 is unbounded below
    elif bounds2.get('min') is None and bounds1.get('min') is not None:
        lower_broader = False  # bounds2 is unbounded below
    elif bounds1.get('min') is not None and bounds2.get('min') is not None:
        lower_broader = bounds1['min'] < bounds2['min']
    else:
        lower_broader = False  # Both unbounded or neither has min
    
    # Check upper bound
    upper_broader = False
    if bounds1.get('max') is None and bounds2.get('max') is not None:
        upper_broader = True  # bounds1 is unbounded above
    elif bounds2.get('max') is None and bounds1.get('max') is not None:
        upper_broader = False  # bounds2 is unbounded above
    elif bounds1.get('max') is not None and bounds2.get('max') is not None:
        upper_broader = bounds1['max'] > bounds2['max']
    else:
        upper_broader = False  # Both unbounded or neither has max
    
    return lower_broader or upper_broader

def get_consolidated_bounds(bounds1: Dict, bounds2: Dict) -> Dict:
    """Get consolidated bounds that encompass both ranges."""
    consolidated = {}
    
    # Take the lower minimum (or unbounded if either is unbounded)
    if bounds1.get('min') is None or bounds2.get('min') is None:
        # One is unbounded below, so consolidated range is unbounded below
        pass
    else:
        consolidated['min'] = min(bounds1['min'], bounds2['min'])
        consolidated['min_inclusive'] = True  # Use inclusive for simplicity
    
    # Take the higher maximum (or unbounded if either is unbounded)
    if bounds1.get('max') is None or bounds2.get('max') is None:
        # One is unbounded above, so consolidated range is unbounded above
        pass
    else:
        consolidated['max'] = max(bounds1['max'], bounds2['max'])
        consolidated['max_inclusive'] = True  # Use inclusive for simplicity
    
    return consolidated

def format_bounds_description(bounds: Dict) -> str:
    """Format bounds for human-readable description."""
    parts = []
    
    if bounds.get('min') is not None:
        op = ">=" if bounds.get('min_inclusive') else ">"
        parts.append(f"{op}{bounds['min']}")
    else:
        parts.append("unbounded below")
    
    if bounds.get('max') is not None:
        op = "<=" if bounds.get('max_inclusive') else "<"
        parts.append(f"{op}{bounds['max']}")
    else:
        parts.append("unbounded above")
    
    if len(parts) == 2 and "unbounded" not in " ".join(parts):
        return " AND ".join(parts)
    elif len(parts) == 1:
        return parts[0]
    else:
        return " AND ".join(parts)

# Load configuration
def load_config():
    """Load configuration from config.json"""
    try:
        # Config file is in the parent directory (src/analysis_tool/config.json)
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        # GRACEFUL DEGRADATION: Presentation layer defaults for HTML generation
        # Provides safe display values when config.json is unavailable (non-critical functionality)
        if logger:
            logger.warning(f"Could not load config for HTML generation: {e}", group="initialization")
        return {
            'application': {
                'toolname': 'Hashmire/Analysis_Tools',
                'version': 'UNKOWN'
            }
        }

config = load_config()
VERSION = config['application']['version']
TOOLNAME = config['application']['toolname']

def get_css_content(external_assets_config=None):
    """Get CSS content - either as external reference or inline content"""
    if external_assets_config and external_assets_config.get('enabled', False):
        # Return external CSS reference
        base_url = external_assets_config.get('base_url', '')
        css_path = external_assets_config.get('css', {}).get('styles', 'css/styles.css')
        css_url = base_url + css_path
        return f'<link rel="stylesheet" href="{css_url}">'
    else:
        # Return inline CSS
        current_dir = os.path.dirname(os.path.abspath(__file__))
        css_file = os.path.join(current_dir, "..", "static", "css", "styles.css")
        
        try:
            with open(css_file, 'r') as f:
                css_content = f.read()
        except Exception as e:
            logger.error(f"CSS file loading failed: Unable to read CSS file '{css_file}' - {e}", group="page_generation")
            css_content = "/* Error loading CSS file */"
            
        return f'<style>\n{css_content}\n</style>'

def get_javascript_references():
    """Get JavaScript content - either as external references or inline scripts"""
    external_assets = config.get('external_assets', {})
    
    if external_assets.get('enabled', False):
        # Return external JavaScript references
        base_url = external_assets.get('base_url', '')
        js_files = external_assets.get('js', {})
        
        references = []
        # Maintain the same order as inline version
        js_order = [
            'badge_modal_system',
            'modular_rules', 
            'cpe_json_handler',
            'ui_controller',
            'selection_manager',
            'timestamp_handler',
            'provenance_assistance',
            'completion_tracker',
            'custom_cpe_builder'
        ]
        
        for js_key in js_order:
            if js_key in js_files:
                js_url = base_url + js_files[js_key]
                references.append(f'<script src="{js_url}"></script>')
        
        return '\n'.join(references)
    else:
        # Return empty string - inline version handled separately
        return ""

def get_dynamic_data_injection():
    """Get the dynamic JavaScript data that needs to be injected regardless of external assets"""
    # Import badge modal system functions
    from .badge_modal_system import get_consolidated_cpe_registration_script, get_consolidated_platform_notification_script
    
    # Add JSON settings HTML injection
    from .badge_modal_system import get_consolidated_json_settings_script
    consolidated_json_settings_registrations = get_consolidated_json_settings_script()
    
    # If we don't have consolidated registrations, fall back to the basic logic
    if not consolidated_json_settings_registrations:
        safe_json_settings = JSON_SETTINGS_HTML if 'JSON_SETTINGS_HTML' in globals() and JSON_SETTINGS_HTML else {}
        
        # Implement basic JSON settings handling to prevent bloat
        # Check if all settings are identical and use a template approach
        if safe_json_settings:
            # Get a sample key to check if all settings are identical
            sample_key = next(iter(safe_json_settings.keys()))
            sample_content = safe_json_settings[sample_key]
            
            # Check if all settings are identical (common case)
            all_identical = all(content == sample_content for content in safe_json_settings.values())
            
            if all_identical and len(safe_json_settings) > 1:
                # Use a template approach to reduce size
                logger.debug(f"Using template for JSON_SETTINGS_HTML - found {len(safe_json_settings)} identical entries", group="page_generation")
                json_settings_injection = f"""
    // JSON Settings HTML template (for efficiency)
    window.JSON_SETTINGS_TEMPLATE = {json.dumps(sample_content, cls=CustomJSONEncoder)};
    window.JSON_SETTINGS_KEYS = {json.dumps(list(safe_json_settings.keys()), cls=CustomJSONEncoder)};
    // Create JSON_SETTINGS_HTML from template
    window.JSON_SETTINGS_HTML = {{}};
    window.JSON_SETTINGS_KEYS.forEach(key => {{
        window.JSON_SETTINGS_HTML[key] = window.JSON_SETTINGS_TEMPLATE.replace(/matchesTable_0/g, key);
    }});
    """
            else:
                json_settings_injection = f"""
    // JSON Settings HTML generated by Python and injected on page load
    window.JSON_SETTINGS_HTML = {json.dumps(safe_json_settings, cls=CustomJSONEncoder)};
    """
        else:
            json_settings_injection = """
    // No JSON Settings HTML data
    window.JSON_SETTINGS_HTML = {};
    """
        
        # Add intelligent settings injection with defensive checking
        safe_intelligent_settings = INTELLIGENT_SETTINGS if 'INTELLIGENT_SETTINGS' in globals() and INTELLIGENT_SETTINGS else {}
        intelligent_settings_js = ""
        if safe_intelligent_settings:
            # Check if all intelligent settings are identical
            if len(safe_intelligent_settings) > 1:
                sample_key = next(iter(safe_intelligent_settings.keys()))
                sample_settings = safe_intelligent_settings[sample_key]
                
                all_identical = all(settings == sample_settings for settings in safe_intelligent_settings.values())
                
                if all_identical:
                    # Use template approach for identical settings
                    logger.debug(f"Using template for INTELLIGENT_SETTINGS - found {len(safe_intelligent_settings)} identical entries", group="page_generation")
                    intelligent_settings_js = f"""
        // Intelligent settings template (for efficiency)
        window.INTELLIGENT_SETTINGS_TEMPLATE = {json.dumps(sample_settings, cls=CustomJSONEncoder)};
        window.INTELLIGENT_SETTINGS_KEYS = {json.dumps(list(safe_intelligent_settings.keys()), cls=CustomJSONEncoder)};
        // Create INTELLIGENT_SETTINGS from template
        window.INTELLIGENT_SETTINGS = {{}};
        window.INTELLIGENT_SETTINGS_KEYS.forEach(key => {{
            window.INTELLIGENT_SETTINGS[key] = window.INTELLIGENT_SETTINGS_TEMPLATE;
        }});
        """
                else:
                    intelligent_settings_js = f"""
        // Intelligent settings computed by Python
        window.INTELLIGENT_SETTINGS = {json.dumps(safe_intelligent_settings, cls=CustomJSONEncoder)};
        """
            else:
                intelligent_settings_js = f"""
        // Intelligent settings computed by Python
        window.INTELLIGENT_SETTINGS = {json.dumps(safe_intelligent_settings, cls=CustomJSONEncoder)};
        """
        
        # Combine consolidated injections
        consolidated_json_settings_registrations = json_settings_injection + intelligent_settings_js
    
    # Inject NON_SPECIFIC_VERSION_VALUES as a global JavaScript variable
    # This ensures the JavaScript uses the same list as Python (single source of truth)
    non_specific_versions_js = f"""
    // Non-specific version values injected from Python (single source of truth)
    window.NON_SPECIFIC_VERSION_VALUES = {json.dumps(NON_SPECIFIC_VERSION_VALUES)};
    """
    
    # Get consolidated registrations from badge_modal_system
    consolidated_cpe_registrations = get_consolidated_cpe_registration_script()
    consolidated_platform_registrations = get_consolidated_platform_notification_script()
    
    # Log summary statistics for debugging bloat issues
    total_settings_keys = len(JSON_SETTINGS_HTML) if 'JSON_SETTINGS_HTML' in globals() and JSON_SETTINGS_HTML else 0
    total_intelligent_keys = len(INTELLIGENT_SETTINGS) if 'INTELLIGENT_SETTINGS' in globals() and INTELLIGENT_SETTINGS else 0
    
    if total_settings_keys > 10 or total_intelligent_keys > 10:
        logger.info(f"Large dataset detected - {total_settings_keys} JSON settings entries, {total_intelligent_keys} intelligent settings entries", group="page_generation")

    dynamic_data = (consolidated_json_settings_registrations + 
                   non_specific_versions_js + consolidated_cpe_registrations + 
                   consolidated_platform_registrations)
    
    return f"<script>\n{dynamic_data}\n</script>"

# Import Analysis Tool
from . import processData

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

def safe_js_string(value):
    """
    Safely encode a string for use in JavaScript contexts.
    This prevents issues with escape sequences and special characters.
    """
    # Use JSON encoding to handle all escape sequences properly
    # Then remove the outer quotes since we'll add them back in the template
    return json.dumps(str(value))[1:-1]

def convertRowDataToHTML(row, tableIndex=0) -> str:
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
                source_info = get_source_info(value)
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

    # Extract vendor and product for use throughout the function
    vendor = raw_platform_data.get('vendor', 'unknown')
    product = raw_platform_data.get('product', 'unknown')

    # Group badges by priority level
    danger_badges = []
    warning_badges = []
    sourceDataConcern_badges = []
    info_badges = []
    standard_badges = []

    # ===== 🟢 SUCCESS BADGES (Green) =====
    
    # 1. Confirmed Mappings badge (consolidates confirmed and culled mappings)
    confirmed_mappings = platform_metadata.get('confirmedMappings', [])
    culled_mappings = platform_metadata.get('culledConfirmedMappings', [])
    
    if confirmed_mappings:
        # Build tooltip with confirmed mappings and any culled mappings
        confirmed_tooltip = f"Confirmed CPE mappings available ({len(confirmed_mappings)}):&#013;" + "&#013;".join(confirmed_mappings)
        
        # Add culled mappings info if any exist
        if culled_mappings:
            confirmed_tooltip += "&#013;&#013;Less specific mappings filtered out:&#013;" + "&#013;".join(culled_mappings)
        
        standard_badges.append(f'<span class="badge bg-success" title="{confirmed_tooltip}">Confirmed Mappings: {len(confirmed_mappings)}</span> ')

    # ===== 🔴 DANGER BADGES (Red) =====
    
    # 2. git versionType badge (with version ranges) - CRITICAL
    if characteristics['has_git_version_type']:
        git_tooltip = "Versioning based on the git versionType is not advised for CPE Names, consider non-git versioning."
        git_badge_color = "bg-warning"
        
        # Elevate to danger level when used with version ranges
        if platform_format_type in ['cveAffectsVersionRange', 'cveAffectsVersionMix']:
            git_badge_color = "bg-danger"
            git_tooltip = "CRITICAL: CPE Range Matching Logic does not currently support git versionTypes&#013;Detected in version range context"
            
        if git_badge_color == "bg-danger":
            danger_badges.append(f'<span class="badge {git_badge_color}" title="{git_tooltip}">git versionType</span> ')
        else:
            warning_badges.append(f'<span class="badge {git_badge_color}" title="{git_tooltip}">git versionType</span> ')

    # 3. Platform Format Type badge - CVE Affects Product (No Versions) 
    version_checks = platform_metadata.get('cpeVersionChecks', [])
    version_tooltip = "No versions detected!"
    if version_checks:
        version_lines = []
        for check in version_checks:
            check_str = ", ".join([f"{k}: {v}" for k, v in check.items()])
            version_lines.append(check_str)
        version_tooltip = "&#013;".join(version_lines)

    # Check if this will be handled by modal-only cases in JSON Generation Rules
    from .badge_modal_system import is_modal_only_case
    
    if platform_format_type == 'cveAffectsNoVersions' and not is_modal_only_case(raw_platform_data):
        danger_badges.append(f'<span class="badge bg-danger" title="{version_tooltip}">{readable_format_type}</span> ')
    # Note: Platform Format Type for other cases is now handled in Supporting Information modal
    # Note: Simple cases (defaultStatus 'affected' + no versions) are now handled in JSON Generation Rules All Versions modal

    # ===== 🔵 INFO BADGES (Blue) =====
    
    # Note: CVE Affected CPES Data is now handled in Supporting Information modal

    # ===== 🟡 WARNING BADGES (Yellow) =====
    
    # 6. git versionType badge (without version ranges) - Already handled above in badge #2
    
    # 7. Has Version Changes badge
    if characteristics['has_version_changes']:
        changes_tooltip = 'Versions array contains change history information requiring special handling'
        warning_badges.append(f'<span class="badge bg-warning" title="{changes_tooltip}">Has Version Changes</span> ')

    # 8. JSON Generation Rules badge (unified wildcards + update patterns + all versions)
    has_wildcards = characteristics['has_wildcards']
    has_update_patterns = characteristics['has_update_patterns'] and characteristics['update_patterns']
    
    # Always call the unified JSON Generation Rules badge system - it handles simple cases, all versions, and complex cases
    json_rules_badge = create_json_generation_rules_badge(tableIndex, raw_platform_data, vendor, product, row)
    if json_rules_badge:
        warning_badges.append(json_rules_badge)

    # ===== ⚫ STANDARD BADGES (Gray) =====
    
    # Note: The following badges are now consolidated into the Supporting Information modal:
    # - CPE API Error Detection Badge
    # - CPE Base String Searches badge
    # - Source to CPE Transformations Applied badge

    # ===== 🟪 SOURCE DATA CONCERN BADGE (Purple) =====
    
    # Create the unified Source Data Concerns badge to replace individual purple badges
    from .badge_modal_system import create_source_data_concerns_badge, PLATFORM_ENTRY_NOTIFICATION_REGISTRY
    from ..logging.badge_contents_collector import get_badge_contents_collector, collect_clean_platform_entry
    
    source_data_concerns_badge = create_source_data_concerns_badge(
        table_index=tableIndex,
        raw_platform_data=raw_platform_data,
        characteristics=characteristics,
        platform_metadata=platform_metadata,
        row=row
    )
    
    # Debug: Check what overlapping ranges data exists for this table index
    from .badge_modal_system import PLATFORM_ENTRY_NOTIFICATION_REGISTRY
    if tableIndex in [2, 4, 5]:  # macOS entries
        registry_data = PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('sourceDataConcerns', {}).get(tableIndex, {})
        if registry_data:
            overlapping_data = registry_data.get('concerns', {}).get('overlappingRanges', [])
            logger.debug(f"Table {tableIndex} overlapping ranges: {len(overlapping_data)} findings", group="PAGE_GEN")
            if overlapping_data:
                logger.debug(f"Table {tableIndex} overlapping ranges data: {overlapping_data[:1]}", group="PAGE_GEN")  # Show first finding
        else:
            logger.debug(f"Table {tableIndex} has no registry data", group="PAGE_GEN")
    
    # If we have source data concerns, add it to the sourceDataConcern_badges category and collect the data
    if source_data_concerns_badge:
        sourceDataConcern_badges.append(source_data_concerns_badge)
        
        # Collect badge contents for report generation
        registry_data = PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('sourceDataConcerns', {}).get(tableIndex, {})
        if registry_data:
            source_id = row.get('sourceID', 'Unknown')
            concerns_data = registry_data.get('concerns', {})
            concerns_summary = registry_data.get('summary', {})
            concerns_count = concerns_summary.get('total_concerns', 0)
            concern_types = concerns_summary.get('concern_types', [])
            
            collector = get_badge_contents_collector()
            collector.collect_source_data_concern(
                table_index=tableIndex,
                source_id=source_id,
                vendor=vendor,
                product=product,
                concerns_data=concerns_data,
                concerns_count=concerns_count,
                concern_types=concern_types
            )
    else:
        # No source data concerns found - collect this as a clean platform entry
        source_id = row.get('sourceID', 'Unknown')
        if source_id and source_id != 'Unknown':
            collect_clean_platform_entry(source_id)

    # ===== 🔍 SUPPORTING INFORMATION MODAL =====
    
    # Create the unified Supporting Information badge to replace Standard and Info badges
    supporting_info_badge = create_supporting_information_badge(
        table_index=tableIndex,
        row=row,
        platform_metadata=platform_metadata,
        raw_platform_data=raw_platform_data,
        characteristics=characteristics,
        platform_format_type=platform_format_type,
        readable_format_type=readable_format_type,
        vendor=vendor,
        product=product
    )
    
    # If we have supporting information, add it to the standard badges category
    if supporting_info_badge:
        standard_badges.append(supporting_info_badge)

    # Add badges in priority order: Danger -> Warning -> Data Concern -> Info -> Standard
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
        source_id = row.get('sourceID', 'Unknown')
        source_role = row.get('sourceRole', 'Unknown')
        
        # Format badge details for logging
        badge_summary = []
        for badge_type, badge_names in badge_details.items():
            if len(badge_names) == 1:
                badge_summary.append(f"{badge_type}: {badge_names[0]}")
            else:
                badge_summary.append(f"{badge_type}: [{', '.join(badge_names)}]")
        
        logger.info(f"Badges added for row {tableIndex} ({source_id}): {vendor}/{product} ({' | '.join(badge_summary)})", group="badge_gen")
    else:
        vendor = row.get('rawPlatformData', {}).get('vendor', 'Unknown')
        product = row.get('rawPlatformData', {}).get('product', 'Unknown')
        source_id = row.get('sourceID', 'Unknown')
        source_role = row.get('sourceRole', 'Unknown')
        logger.debug(f"No badges added for row {tableIndex} ({source_id}): {vendor}/{product}", group="badge_gen")

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

def create_empty_matches_table(tableIndex=0) -> str:
    """
    Create an empty matches table structure for when there are no CPE suggestions
    but the Custom CPE Builder still needs a table to add rows to.
    """
    return f"""
    <div class="card mb-3">
        <div class="card-header d-flex justify-content-between align-items-center collapsed" 
             id="cpeHeader_{tableIndex}" 
             data-bs-toggle="collapse" 
             data-bs-target="#cpeCollapse_{tableIndex}" 
             style="cursor: pointer;">
            <h5 class="mb-0">
                CPE Suggestions
            </h5>
            <span class="arrow-icon">&uarr;</span>
        </div>
        <div id="cpeCollapse_{tableIndex}" class="collapse" aria-labelledby="cpeHeader_{tableIndex}">
            <div class="card-body">
                <p class="text-muted mb-3">No CPE suggestions available. Use the Custom CPE Builder above to create entries.</p>
                <div id="matchesTable_{tableIndex}_container" class="table-container">
                    <table id="matchesTable_{tableIndex}" class="table table-hover matchesTable">
                        <thead>
                            <tr>
                                <th style="width: 65%">CPE Base String</th>
                                <th style="width: 35%">Information</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Custom CPE rows will be added here -->
                        </tbody>
                    </table>
                </div>
                
                <!-- JSON Generation Settings Container -->
                <div id="jsonSettings_matchesTable_{tableIndex}" class="json-settings-container mb-3" style="display: none;">
                    <!-- Settings content will be populated by initializeJsonSettings() -->
                </div>
                
            </div>
        </div>
    </div>
    """.replace('\n', '')

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
                          onclick="BadgeModalManager.openReferencesModal('{base_key_safe}', '{safe_js_string(cpe_base)}', {len(references)})" id="refBadge_{base_key_safe}">
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
                        ref_url = safe_js_string(ref.get('url', 'No URL'))
                        ref_count = ref.get('frequency', 1)
                        ref_data_js += f'''
                                {{"url": "{ref_url}", "count": {ref_count}}},'''
                    
                    ref_data_js = ref_data_js.rstrip(',') + "]}, "
                
                ref_data_js = ref_data_js.rstrip(', ') + "}"
                
                # Parse the JSON for storage in global registry
                ref_data_dict = json.loads(ref_data_js)
                
                # Register reference data with the global CPE registry
                register_cpe_data(cpe_base, 'references', ref_data_dict)
                
                # Create reference HTML without inline script
                references_html = f'''
                <div class="reference-section">
                    <span class="badge modal-badge bg-info" 
                          onclick="BadgeModalManager.openReferencesModal('{base_key_safe}', '{safe_js_string(cpe_base)}', {len(references)})" id="refBadge_{base_key_safe}">
                        📋 Provenance ({len(references)})
                    </span>
                </div>'''
                
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
                
                # Register sorting priority data with the global CPE registry (deduplicated)
                register_cpe_data(cpe_base, 'sortingPriority', sorting_data)
                
                # Let frontend JavaScript calculate tab count dynamically from actual data
                context_count = ""  # Remove hardcoded count, let JS calculate
                
                # Create merged row with both confirmed mapping badge and API data
                html_content += f"""
                <tr id="row_{base_key_id}" class="cpe-row confirmed-mapping-row" data-cpe-base="{cpe_base}">
                    <td class="text-break">{cpe_base}</td>
                    <td>
                        <div class="d-flex flex-wrap gap-1 align-items-center">
                            <span class="badge modal-badge bg-success"
                                  onclick="BadgeModalManager.openConfirmedMappingModal('{base_key_safe}', '{safe_js_string(cpe_base)}')">
                                ✅ Confirmed Mapping
                            </span>
                            <span class="badge modal-badge bg-secondary" 
                                  onclick="BadgeModalManager.openSortingPriorityModal('{base_key_safe}', '{safe_js_string(cpe_base)}', 'statistics')">
                                📈 Sorting Priority Context
                            </span>"""
                
                # Add enhanced references section if available
                if references:
                    html_content += references_html
                
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
                                  onclick="BadgeModalManager.openConfirmedMappingModal('{base_key_safe}', '{safe_js_string(cpe_base)}')">
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
                          onclick="BadgeModalManager.openReferencesModal('{base_key_safe}', '{safe_js_string(base_key)}', {len(references)})" id="refBadge_{base_key_safe}">
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
                        ref_url = safe_js_string(ref.get('url', 'No URL'))
                        ref_count = ref.get('frequency', 1)
                        ref_data_js += f'''
                                {{"url": "{ref_url}", "count": {ref_count}}},'''
                    
                    ref_data_js = ref_data_js.rstrip(',') + "]}, "
                
                ref_data_js = ref_data_js.rstrip(', ') + "}"
                
                # Parse the JSON for storage in global registry
                ref_data_dict = json.loads(ref_data_js)
                
                # Register reference data with the global CPE registry
                register_cpe_data(base_key, 'references', ref_data_dict)
                
                # Create reference HTML without inline script
                references_html = f'''
                <div class="reference-section">
                    <span class="badge modal-badge bg-info" 
                          onclick="BadgeModalManager.openReferencesModal('{base_key_safe}', '{safe_js_string(base_key)}', {len(references)})" id="refBadge_{base_key_safe}">
                        📋 Provenance ({len(references)})
                    </span>
                </div>'''
            
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
            
                # Register sorting priority data with the global CPE registry
                register_cpe_data(base_key, 'sortingPriority', sorting_data)            # Sanitize base_key for use as ID
            base_key_id = base_key.replace(":", "_").replace(".", "_").replace(" ", "_").replace("/", "_")
            
            # Let frontend JavaScript calculate tab count dynamically from actual data
            context_count = ""  # Remove hardcoded count, let JS calculate
            
            html_content += f"""
            <tr id="row_{base_key_id}" class="cpe-row" data-cpe-base="{base_key}">
                <td class="text-break">{base_key}</td>
                <td>
                <div class="d-flex flex-wrap gap-1 align-items-center">
                    <span class="badge modal-badge bg-secondary" 
                          onclick="BadgeModalManager.openSortingPriorityModal('{base_key_safe}', '{safe_js_string(base_key)}', 'statistics')">
                        📈 Sorting Priority Context
                    </span>"""
            
            # Add enhanced references section if available
            if references:
                html_content += references_html
            
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
                
                <!-- JSON Generation Settings Container -->
                <div id="jsonSettings_""" + f"matchesTable_{tableIndex}" + """" class="json-settings-container mb-3" style="display: none;">
                    <!-- Settings content will be populated by initializeJsonSettings() -->
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
    # UNIFIED ARCHITECTURE: Load order is critical for dependency resolution
    js_files = [
        # 1. Unified data extraction (after unified source data injection)
        os.path.join(current_dir, "..", "static", "js", "unified_data_extraction.js"),
        # 2. Core systems
        os.path.join(current_dir, "..", "static", "js", "badge_modal_system.js"),
        os.path.join(current_dir, "..", "static", "js", "modular_rules.js"),
        # 3. Data handlers (now depend on unified extraction)
        os.path.join(current_dir, "..", "static", "js", "cpe_json_handler.js"),
        # 4. UI and interaction systems
        os.path.join(current_dir, "..", "static", "js", "ui_controller.js"),
        os.path.join(current_dir, "..", "static", "js", "selection_manager.js"),
        os.path.join(current_dir, "..", "static", "js", "timestamp_handler.js"),
        os.path.join(current_dir, "..", "static", "js", "provenance_assistance.js"),
        # 5. Completion tracking (depends on unified data extraction)
        os.path.join(current_dir, "..", "static", "js", "completion_tracker.js"),
        # 6. Application-specific modules (depend on everything above)
        os.path.join(current_dir, "..", "static", "js", "custom_cpe_builder.js")
    ]
    
    # Read JavaScript files
    js_content = ""
    
    # FIRST: Inject unified source data before any other JavaScript
    unified_manager = get_unified_source_manager()
    unified_manager.initialize()
    unified_source_js = unified_manager.generate_javascript_data()
    js_content += unified_source_js + "\n\n"
    
    # THEN: Read each static JavaScript file and add its content
    for js_file in js_files:
        try:
            with open(js_file, 'r', encoding='utf-8') as f:
                js_content += f.read() + "\n\n"

        except Exception as e:
            logger.error(f"JavaScript file loading failed: Unable to read JS file '{js_file}' - {e}", group="page_generation")
            # Add placeholder comment if file can't be read
            js_content += f"// Error loading {js_file}\n\n"
    
    # Get dynamic data injection content
    dynamic_data = get_dynamic_data_injection()
    
    # Return combined inline script with both static JS and dynamic data
    return f"<script>\n{js_content}\n</script>{dynamic_data}"

def update_cpeQueryHTML_column(dataframe):
    """Updates the dataframe to include a column with HTML for CPE query results"""
    
    # Make a copy to avoid modifying the original
    result_df = dataframe.copy()
    
    # ===== CONSOLIDATED ANALYSIS: OVERLAPPING RANGES DETECTION =====
    # Run consolidated analysis before individual row processing to detect overlapping ranges
    logger.debug(f"Starting overlapping ranges detection for {len(result_df)} platform entries", group="PAGE_GEN")
    overlapping_ranges_findings = detect_overlapping_ranges(result_df)
    logger.debug(f"Overlapping ranges detection complete: {len(overlapping_ranges_findings)} entries with findings", group="PAGE_GEN")
    
    # Distribute overlapping ranges findings to relevant table indices for badge display
    for table_index, findings in overlapping_ranges_findings.items():
        logger.debug(f"Registering {len(findings)} overlapping ranges findings for table {table_index}", group="PAGE_GEN")
        
        # Register the findings in the Source Data Concerns registry
        from .badge_modal_system import PLATFORM_ENTRY_NOTIFICATION_REGISTRY
        
        # Ensure sourceDataConcerns registry exists
        if 'sourceDataConcerns' not in PLATFORM_ENTRY_NOTIFICATION_REGISTRY:
            PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns'] = {}
        
        # Add overlapping ranges to existing concerns or create new entry
        if table_index not in PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns']:
            logger.debug(f"Creating new registry entry for table {table_index}", group="PAGE_GEN")
            PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns'][table_index] = {
                "concerns": {
                    "placeholderData": [],
                    "versionTextPatterns": [],
                    "versionComparators": [],
                    "versionGranularity": [],
                    "wildcardBranches": [],
                    "cpeArrayConcerns": [],
                    "duplicateEntries": [],
                    "missingAffectedProducts": [],
                    "overlappingRanges": []
                },
                "sourceRole": "Unknown Source",
                "summary": {
                    "total_concerns": 0,
                    "concern_types": []
                }
            }
        
        # Ensure overlappingRanges exists in concerns
        concerns = PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns'][table_index]["concerns"]
        if "overlappingRanges" not in concerns:
            concerns["overlappingRanges"] = []
        
        # Add the findings
        concerns["overlappingRanges"].extend(findings)
        logger.debug(f"Added {len(findings)} findings to table {table_index}, total overlapping ranges: {len(concerns['overlappingRanges'])}", group="PAGE_GEN")
        
        # Update summary
        summary = PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns'][table_index]["summary"]
        summary["total_concerns"] += len(findings)
        if findings and "Overlapping Ranges" not in summary["concern_types"]:
            summary["concern_types"].append("Overlapping Ranges")
            
        logger.debug(f"Table {table_index} summary updated: {summary['total_concerns']} total concerns, types: {summary['concern_types']}", group="PAGE_GEN")
    
    # ===== INDIVIDUAL ROW PROCESSING =====
    # Now process individual rows - badges will include overlapping ranges data registered above
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
        row_html_content = convertRowDataToHTML(row, index)
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
            
            # Add the matches table after the custom CPE Builder div
            # Always create the table structure, even if empty, so Custom CPE Builder can add rows
            if has_matches:
                html_content += convertCPEsQueryDataToHTML(sortedCPEsQueryData, index, row)
            else:
                # No CPE query results - create empty table structure for Custom CPE Builder
                html_content += create_empty_matches_table(index)
            
            html_content += "</div>"  # Close the container div
            result_df.at[index, 'cpeQueryHTML'] = html_content
        
        # Store settings HTML for this table - ONLY if it needs JSON generation settings
        table_id = f"matchesTable_{index}"
        raw_platform_data = row.get('rawPlatformData', {})
        
        # Import the modal-only case detection function
        from .badge_modal_system import is_modal_only_case
        
        # Only create JSON settings HTML for complex cases that need interactive settings
        # Skip modal-only cases - they only need modal content, no settings
        if not is_modal_only_case(raw_platform_data):
            store_json_settings_html(table_id, raw_platform_data)
    
    return result_df

# Modify the buildHTMLPage function to accept and include globalCVEMetadata
def buildHTMLPage(affectedHtml, targetCve, globalCVEMetadata=None, external_assets_config=None):
    
    # Generate UTC timestamp for the page creation
    utc_timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    
    # Get CSS content (external reference or inline content based on config)
    css_content = get_css_content(external_assets_config)
    
    # Get JavaScript references if external assets are enabled
    if external_assets_config and external_assets_config.get('enabled', False):
        # Use the passed external assets configuration
        base_url = external_assets_config.get('base_url', '')
        js_files = external_assets_config.get('js', {})
        
        logger.debug(f"Generating external JS references: base_url={base_url}, js_files_count={len(js_files)}", group="page_generation")
        
        references = []
        # Maintain the same order as inline version
        js_order = [
            'badge_modal_system',
            'modular_rules', 
            'cpe_json_handler',
            'ui_controller',
            'selection_manager',
            'timestamp_handler',
            'provenance_assistance',
            'completion_tracker',
            'custom_cpe_builder'
        ]
        
        for js_key in js_order:
            if js_key in js_files:
                js_url = base_url + js_files[js_key]
                references.append(f'<script src="{js_url}"></script>')
        
        js_references = '\n'.join(references)
        logger.debug(f"Generated {len(references)} external JS script tags", group="page_generation")
    else:
        logger.debug(f"External assets disabled. Config enabled: {external_assets_config.get('enabled') if external_assets_config else 'N/A'}", group="page_generation")
        js_references = ""

    pageStartHTML = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.3.0/font/bootstrap-icons.css">
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous"></script>
        {css_content}
        {js_references}
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
    
    # Get JavaScript content based on external assets configuration
    if external_assets_config and external_assets_config.get('enabled', False):
        # Use external JavaScript references (included in pageStartHTML) + dynamic data injection
        dynamic_data_script = get_dynamic_data_injection()
        fullHtml = (pageStartHTML + pageBodyHeaderHTML + pageBodyTabsHTML + cveIdIndicatorHTML + 
                    pageBodyCPESuggesterHTML + pageEndHTML + dynamic_data_script)
    else:
        # Use inline JavaScript (existing behavior)
        fullHtml = (pageStartHTML + getCPEJsonScript() + pageBodyHeaderHTML + pageBodyTabsHTML + cveIdIndicatorHTML + 
                    pageBodyCPESuggesterHTML + pageEndHTML)
    
    # Log file size information to help detect bloat
    html_size = len(fullHtml)
    if html_size > 1000000:  # 1MB threshold
        logger.warning(f"Large HTML file generated for {targetCve}: {html_size:,} bytes ({html_size/1024/1024:.1f}MB)", group="page_generation")
    elif html_size > 500000:  # 500KB threshold
        logger.info(f"Medium HTML file generated for {targetCve}: {html_size:,} bytes ({html_size/1024:.1f}KB)", group="page_generation")
    
    return fullHtml

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
    global JSON_SETTINGS_HTML, INTELLIGENT_SETTINGS, GLOBAL_CPE_DATA_REGISTRY
    JSON_SETTINGS_HTML = {}
    INTELLIGENT_SETTINGS = {}
    GLOBAL_CPE_DATA_REGISTRY = {
        'references': {},
        'sortingPriority': {},
        'registered_cpes': set()
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
    
    # Log statistics before clearing (for debugging bloat issues)
    if JSON_SETTINGS_HTML:
        logger.debug(f"Clearing HTML state: {len(JSON_SETTINGS_HTML)} JSON settings entries", group="page_generation")
    
    # Clear badge and modal registries (now handled by external module)
    clear_all_registries()
    
    # Reinitialize local HTML state
    JSON_SETTINGS_HTML = {}
    INTELLIGENT_SETTINGS = {}
    
    logger.debug("Cleared global HTML state and badge/modal registries", group="page_generation")

def analyze_data_for_smart_defaults(raw_platform_data):
    """Analyze platform data to determine intelligent defaults for JSON generation settings"""
    # Import here to avoid circular imports
    from .badge_modal_system import analyze_version_characteristics
    
    # Default settings - start with most common configuration
    settings = {
        'enableWildcardExpansion': True,
        'enableVersionChanges': False,
        'enableSpecialVersionTypes': True,
        'enableInverseStatus': False,
        'enableMultipleBranches': False,
        'enableMixedStatus': False,
        'enableGapProcessing': True,
        'enableUpdatePatterns': False
    }
    
    # Use the unified analysis function to set intelligent defaults
    if raw_platform_data:
        characteristics = analyze_version_characteristics(raw_platform_data)
        
        # Update settings based on actual data characteristics
        if characteristics.get('has_wildcards'):
            settings['enableWildcardExpansion'] = True
            
        if characteristics.get('has_version_changes'):
            settings['enableVersionChanges'] = True
            
        if characteristics.get('has_special_version_types'):
            settings['enableSpecialVersionTypes'] = True
            
        if characteristics.get('has_multiple_branches'):
            settings['enableMultipleBranches'] = True
            
        if characteristics.get('has_mixed_statuses'):
            settings['enableMixedStatus'] = True
            
        if characteristics.get('has_gaps_for_processing'):
            settings['enableGapProcessing'] = True
            
        # This is the key fix - use actual update patterns detection!
        if characteristics.get('has_update_patterns') and characteristics.get('update_patterns'):
            settings['enableUpdatePatterns'] = True
    
    return settings

def store_json_settings_html(table_id, raw_platform_data=None):
    """Store the JSON settings HTML for a table with intelligent defaults"""
    global JSON_SETTINGS_HTML, INTELLIGENT_SETTINGS
    
    # Ensure global dictionaries exist and are initialized
    if 'JSON_SETTINGS_HTML' not in globals() or JSON_SETTINGS_HTML is None:
        JSON_SETTINGS_HTML = {}
    if 'INTELLIGENT_SETTINGS' not in globals() or INTELLIGENT_SETTINGS is None:
        INTELLIGENT_SETTINGS = {}
    
    # Analyze data to determine which checkboxes should be checked
    settings = analyze_data_for_smart_defaults(raw_platform_data) if raw_platform_data else {
        'enableWildcardExpansion': True,
        'enableVersionChanges': False,
        'enableSpecialVersionTypes': True,
        'enableInverseStatus': False,
        'enableMultipleBranches': False,
        'enableMixedStatus': False,
        'enableGapProcessing': True,
        'enableUpdatePatterns': False
    }
    
    # Store the HTML for later use
    JSON_SETTINGS_HTML[table_id] = create_json_generation_settings_html(table_id, settings)
    
    # Store intelligent settings for JavaScript (even if identical - template system handles this)
    INTELLIGENT_SETTINGS[table_id] = settings
    
    # Log the registration for debugging
    logger.debug(f"Registered JSON settings for {table_id}", group="page_generation")


