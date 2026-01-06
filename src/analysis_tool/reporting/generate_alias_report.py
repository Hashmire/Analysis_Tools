#!/usr/bin/env python3
"""
Alias Extraction Report Generator from NVD-ish Cache

Scans enriched NVD-ish records and generates per-source alias extraction reports
independent of live CVE processing. Splits data by source to handle large datasets
that would otherwise fail to parse in the dashboard.

This script REPLACES the legacy --alias-report functionality in generate_dataset.py.
The new approach generates reports from the NVD-ish cache asynchronously, avoiding
memory issues and allowing parallel execution with dataset generation.

Entry Points:
    - Standalone (Primary): python -m src.analysis_tool.reporting.generate_alias_report [options]
    - Legacy (Deprecated): python generate_dataset.py --alias-report [options]
    
    Use standalone mode for better performance and reliability.

Architecture:
    - Reads from: cache/nvd-ish_2.0_cves/
    - Extracts: enrichedCVEv5Affected.cveListV5AffectedEntries[*].aliasExtraction
    - Generates: 
        * aliasExtractionReport_index.json (source listing and global metadata)
        * aliasExtractionReport_[sourcename]_[id].json (per-source data)

Output Structure:
    runs/[run_id]/logs/
        ├── aliasExtractionReport_index.json
        ├── aliasExtractionReport_Fortinet_6abe59d8.json
        ├── aliasExtractionReport_Microsoft_abcd1234.json
        └── ... (one file per source)

Usage:
    # Standalone - creates new run directory
    python -m src.analysis_tool.reporting.generate_alias_report

    # Use existing run directory (e.g., from generate_dataset)
    python -m src.analysis_tool.reporting.generate_alias_report \
        --run-id 2025-12-01_10-30-00_dataset_last_7_days_nvd-ish

    # Filter by source UUID
    python -m src.analysis_tool.reporting.generate_alias_report \
        --source-uuid 6abe59d8-c742-4dff-8ce8-9b0ca1073da8

    # Programmatic
    from src.analysis_tool.reporting.generate_alias_report import generate_report
    generate_report(cache_name="nvd-ish_2.0_cves", source_uuid=None, run_directory=None)
"""

import json
import sys
import traceback
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# CRITICAL IMPORTS - must succeed or script fails
from ..logging.workflow_logger import get_logger
from ..storage.run_organization import get_analysis_tools_root
from ..core.badge_modal_system import (
    GENERAL_PLACEHOLDER_VALUES,
    ALL_TEXT_COMPARATOR_PATTERNS,
    TEXT_COMPARATOR_REGEX_PATTERNS
)

logger = get_logger()

# Presentation-layer imports with graceful degradation
try:
    from .. import __version__
except ImportError:
    __version__ = "unknown"


def load_config() -> Dict:
    """
    Load configuration from config.json with fallback to defaults.
    
    Returns:
        Configuration dictionary
    """
    try:
        project_root = get_analysis_tools_root()
        config_path = project_root / "src" / "analysis_tool" / "config.json"
        
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            if logger:
                logger.warning(f"Config file not found at {config_path}, using defaults", group="ALIAS_REPORT")
            return {}
    except Exception as e:
        if logger:
            logger.warning(f"Failed to load config: {e}, using defaults", group="ALIAS_REPORT")
        return {}


def generate_alias_html_report(report_data: Dict, output_path: Path, report_template_path: Path, tool_version: str = "unknown") -> None:
    """
    Generate HTML report for individual alias extraction source.
    
    Args:
        report_data: JSON report data to inject
        output_path: Path where HTML file should be written
        report_template_path: Path to Alias_Mapping_Report_Template.html template
        tool_version: Tool version string to display in header
    """
    # Read the report template
    with open(report_template_path, 'r', encoding='utf-8') as f:
        template_html = f.read()
    
    # Escape and prepare the JSON data for injection
    json_data = json.dumps(report_data, ensure_ascii=False)
    
    # Replace the null declaration with actual data
    # The template has: let currentData = null;
    # We replace it with: let currentData = {actual_data};
    
    null_declaration = "let currentData = null;"
    
    if null_declaration in template_html:
        # Replace the null initialization with actual data
        data_declaration = f"let currentData = {json_data};"
        html_output = template_html.replace(null_declaration, data_declaration, 1)
    else:
        # Fallback: Look for <script> tag and inject after it
        script_pos = template_html.find('<script>')
        if script_pos != -1:
            # Find end of opening script tag
            script_end = template_html.find('>', script_pos)
            if script_end != -1:
                data_script = f"\n        // Injected data from Alias Extraction report\n        let currentData = {json_data};\n"
                html_output = template_html[:script_end + 1] + data_script + template_html[script_end + 1:]
            else:
                raise RuntimeError("Could not find injection point in report template")
        else:
            raise RuntimeError("Could not find injection point in report template")
    
    # Fix CSS path to be relative to reports directory
    html_output = html_output.replace('href="../css/alias_mapping_dashboard.css"', 'href="css/alias_mapping_dashboard.css"')
    html_output = html_output.replace("href='../css/alias_mapping_dashboard.css'", "href='css/alias_mapping_dashboard.css'")
    
    # Replace version placeholder with actual version
    html_output = html_output.replace('{{TOOL_VERSION}}', tool_version)
    
    # Write the generated HTML
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_output)


def generate_alias_index_html(index_data: Dict, output_path: Path, index_template_path: Path, tool_version: str = "unknown") -> None:
    """
    Generate HTML index page for alias extraction reports.
    
    Args:
        index_data: Index JSON data
        output_path: Path where index HTML should be written
        index_template_path: Path to Alias_Mapping_Index_Template.html template
        tool_version: Tool version string to display in header
    """
    # Read the index template
    with open(index_template_path, 'r', encoding='utf-8') as f:
        template_html = f.read()
    
    # Modify index data to include HTML report links instead of JSON file references
    modified_index = index_data.copy()
    modified_index['sources'] = []
    
    for source in index_data['sources']:
        source_copy = source.copy()
        # Replace JSON filename with HTML filename
        json_filename = source['report_file']
        html_filename = json_filename.replace('.json', '.html')
        source_copy['report_file'] = html_filename
        modified_index['sources'].append(source_copy)
    
    # Escape and prepare the JSON data for injection
    json_data = json.dumps(modified_index, ensure_ascii=False)
    
    # Replace the null declaration with actual data
    # The template has: let dashboardData = null;
    # We replace it with: let dashboardData = {actual_data};
    
    null_declaration = "let dashboardData = null;"
    
    if null_declaration in template_html:
        # Replace the null initialization with actual data
        data_declaration = f"let dashboardData = {json_data};"
        html_output = template_html.replace(null_declaration, data_declaration, 1)
    else:
        # Fallback: Look for document.addEventListener and inject before it
        dom_ready_marker = "document.addEventListener('DOMContentLoaded', function()"
        
        if dom_ready_marker in template_html:
            insertion_point = template_html.find(dom_ready_marker)
            data_script = f"\n        // Injected data from Alias Extraction report\n        let dashboardData = {json_data};\n\n        "
            html_output = template_html[:insertion_point] + data_script + template_html[insertion_point:]
        else:
            raise RuntimeError("Could not find injection point in index template")
    
    # Replace version placeholder with actual version
    html_output = html_output.replace('{{TOOL_VERSION}}', tool_version)
    
    # Write the generated HTML
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_output)


class AliasReportBuilder:
    """
    Builds per-source aliasExtractionReport files from NVD-ish cache records.
    
    Generates separate report files for each source to handle large datasets.
    Applies curator-compatible deduplication and grouping logic within each source.
    """
    
    def __init__(self, source_manager=None, mapping_manager=None):
        """
        Initialize the report builder.
        
        Args:
            source_manager: Optional NVD source manager for UUID resolution
            mapping_manager: Optional confirmed mapping manager for fast lookup
        """
        self.source_manager = source_manager
        self.mapping_manager = mapping_manager
        self.global_metadata = {
            'run_started_at': datetime.now(timezone.utc).isoformat(),
            'total_cves_processed': 0,
            'total_sources': 0,
            'extraction_source': 'Analysis_Tools_NVDish_Cache_Scanner',
            'tool_version': __version__,
            'report_scope': 'Alias Extraction - Per-Source Reports',
            'status': 'in_progress'
        }
        
        self.sources = defaultdict(lambda: {
            'metadata': {
                'total_cves_processed': 0,
                'unique_aliases_extracted': 0,
                'product_groups_created': 0
            },
            'all_alias_data': {},
            'cve_ids': set(),
            'source_ids': set()
        })
    
    def add_cve_aliases(self, cve_id: str, entries: List[Dict]) -> None:
        """
        Process alias extraction data from one CVE's affected entries.
        Groups aliases by organization name (consolidated across all source identifiers).
        Preserves sourceDataConcerns for each alias.
        
        Args:
            cve_id: CVE identifier
            entries: List of cveListV5AffectedEntries from NVD-ish record
        """
        entries_by_org = defaultdict(list)
        org_source_ids = {}
        
        for entry in entries:
            origin = entry.get('originAffectedEntry', {})
            source_id = origin.get('sourceId', 'unknown_source')
            org_name = self._resolve_source_name(source_id)
            
            alias_extraction = entry.get('aliasExtraction', {})
            aliases = alias_extraction.get('aliases', [])
            sdc_data = entry.get('sourceDataConcerns', {})
            
            if aliases:
                entries_by_org[org_name].append({
                    'aliases': aliases,
                    'entry': entry,
                    'source_id': source_id,
                    'sdc_concerns': sdc_data.get('concerns', {})
                })
                
                if org_name not in org_source_ids:
                    org_source_ids[org_name] = set()
                org_source_ids[org_name].add(source_id)
        
        for org_name, source_entries in entries_by_org.items():
            source_data = self.sources[org_name]
            
            for entry_data in source_entries:
                sdc_concerns = entry_data['sdc_concerns']
                
                for alias in entry_data['aliases']:
                    alias_key = self._generate_alias_key(alias)
                    
                    if alias_key not in source_data['all_alias_data']:
                        alias_with_tracking = dict(alias)
                        alias_with_tracking['source_cve'] = [cve_id]
                        alias_with_tracking['_sdc_concerns'] = self._extract_alias_concerns(alias, sdc_concerns)
                        source_data['all_alias_data'][alias_key] = alias_with_tracking
                    else:
                        existing_cves = source_data['all_alias_data'][alias_key].get('source_cve', [])
                        if cve_id not in existing_cves:
                            source_data['all_alias_data'][alias_key]['source_cve'].append(cve_id)
            
            if cve_id not in source_data['cve_ids']:
                source_data['cve_ids'].add(cve_id)
                source_data['metadata']['total_cves_processed'] += 1
            
            for entry_data in source_entries:
                source_data['source_ids'].add(entry_data['source_id'])
        
        if entries_by_org:
            self.global_metadata['total_cves_processed'] += 1
    
    def _resolve_source_name(self, source_id: str) -> str:
        """
        Resolve source identifier (UUID or email) to human-readable organization name.
        
        Args:
            source_id: Source UUID or email identifier
            
        Returns:
            Human-readable organization name or the identifier itself if not found
        """
        if self.source_manager and self.source_manager.is_initialized():
            info = self.source_manager.get_source_info(source_id)
            if info:
                return info.get('name', source_id)
        
        return source_id
    
    def _generate_alias_key(self, alias: Dict) -> str:
        """
        Generate deduplication key from alias properties.
        
        Must match badge_modal_system._create_alias_data() logic:
        - Sort keys alphabetically
        - Exclude 'source_cve' from key
        - Lowercase all values
        - Format: 'field1:value1||field2:value2||...'
        
        Args:
            alias: Alias dictionary from NVD-ish record
            
        Returns:
            Deduplication key string
        """
        key_parts = []
        for field in sorted(alias.keys()):
            if field != 'source_cve':
                value = str(alias[field]).lower()
                key_parts.append(f"{field}:{value}")
        
        return '||'.join(key_parts)
    
    def _extract_alias_concerns(self, alias: Dict, sdc_concerns: Dict) -> Dict:
        """
        Extract relevant SDC concerns for alias fields (vendor, product, platform, packageName, collectionURL, repo).
        
        Includes ALL concern categories that apply to the alias fields, matching JavaScript detection.
        
        Args:
            alias: Alias dictionary with field values
            sdc_concerns: Source data concerns from NVD-ish record (entry-level concerns)
            
        Returns:
            Dictionary of concerns relevant to this alias's fields
        """
        relevant_concerns = {}
        
        for category, category_concerns in sdc_concerns.items():
            if not category_concerns:
                continue
            
            alias_relevant = []
            for concern in category_concerns:
                concern_field = concern.get('field', '')
                source_value = concern.get('sourceValue', '')
                
                if concern_field == 'vendor' and alias.get('vendor') == source_value:
                    alias_relevant.append(concern)
                elif concern_field == 'product' and alias.get('product') == source_value:
                    alias_relevant.append(concern)
                elif concern_field == 'packageName' and alias.get('packageName') == source_value:
                    alias_relevant.append(concern)
                elif concern_field.startswith('platforms[') or concern_field == 'platform':
                    alias_platform = alias.get('platform') or alias.get('platforms', '')
                    if alias_platform == source_value:
                        alias_relevant.append(concern)
            
            if alias_relevant:
                relevant_concerns[category] = alias_relevant
        
        return relevant_concerns
    
    def finalize(self) -> Dict[str, Dict]:
        """
        Build final per-source report structures.
        
        Returns:
            Dictionary mapping source_id to report data: {source_id: {metadata: {}, aliasGroups: [], confirmedMappings: []}}
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        per_source_reports = {}
        
        for org_name, source_info in self.sources.items():
            # Group aliases by property pattern for this organization
            consolidated_groups = {}
            
            for alias_data in source_info['all_alias_data'].values():
                # Create grouping key based on property TYPES (not values)
                property_types = []
                for key_field in sorted(alias_data.keys()):
                    if key_field != 'source_cve':
                        if isinstance(alias_data[key_field], list):
                            property_types.append(f"{key_field}({len(alias_data[key_field])})")
                        else:
                            property_types.append(key_field)
                
                group_key = "_".join(property_types) if property_types else "unknown_properties"
                
                if group_key not in consolidated_groups:
                    consolidated_groups[group_key] = []
                
                consolidated_groups[group_key].append(alias_data)
            
            # Create alias groups
            alias_groups = []
            for group_key, aliases in consolidated_groups.items():
                # Sort aliases by CVE count (most referenced first)
                aliases.sort(key=lambda x: len(x.get('source_cve', [])), reverse=True)
                
                alias_groups.append({
                    'alias_group': group_key,
                    'aliases': aliases
                })
            
            # Sort alias groups by total alias count (largest first)
            alias_groups.sort(key=lambda group: -len(group['aliases']))
            
            # Load confirmed mappings for all source identifiers of this organization
            confirmed_mappings = []
            
            # Fail-fast: Manager must be initialized if we reach this point
            if not self.mapping_manager or not self.mapping_manager.is_initialized():
                raise RuntimeError(
                    f"Confirmed mapping manager not initialized during report generation for {org_name}. "
                    "Manager should have been initialized at entry point."
                )
            
            # Use pre-loaded mapping manager (O(1) lookup)
            for src_id in source_info['source_ids']:
                mappings = self.mapping_manager.get_mappings_for_source(src_id)
                if mappings:
                    confirmed_mappings.extend(mappings)
                    break  # Use first found
            
            # Build organization metadata
            metadata = {
                'source_id': list(source_info['source_ids'])[0] if source_info['source_ids'] else org_name,  # Primary identifier
                'source_name': org_name,
                'all_source_identifiers': sorted(list(source_info['source_ids'])),  # All identifiers for transparency
                'extraction_timestamp': timestamp,
                'run_started_at': self.global_metadata['run_started_at'],
                'total_cves_processed': source_info['metadata']['total_cves_processed'],
                'unique_aliases_extracted': len(source_info['all_alias_data']),
                'product_groups_created': len(alias_groups),
                'extraction_source': 'Analysis_Tools_NVDish_Cache_Scanner',
                'tool_version': __version__,
                'curator_compatibility': True,
                'status': 'completed'
            }
            
            per_source_reports[org_name] = {
                'metadata': metadata,
                'aliasGroups': alias_groups,
                'confirmedMappings': confirmed_mappings
            }
        
        # Update global metadata
        self.global_metadata['total_sources'] = len(per_source_reports)
        self.global_metadata['last_updated'] = timestamp
        self.global_metadata['status'] = 'completed'
        
        return per_source_reports


def scan_nvd_ish_cache(cache_dir: Path) -> List[Path]:
    """
    Scan NVD-ish cache directory for CVE JSON files.
    
    Args:
        cache_dir: Path to NVD-ish cache (e.g., cache/nvd-ish_2.0_cves)
        
    Returns:
        Sorted list of Path objects for JSON files
        
    Note:
        Unlike SDC report, we can't pre-filter by source at file level
        because aliases can come from any source. Must scan all files and
        filter during extraction.
    """
    json_files = []
    
    for json_file in cache_dir.rglob("CVE-*.json"):
        json_files.append(json_file)
    
    return sorted(json_files)


def extract_aliases_from_record(
    json_file: Path,
    source_uuid_filter: Optional[str] = None
) -> Tuple[Optional[str], List[Dict]]:
    """
    Load NVD-ish record and extract alias extraction data.
    
    Args:
        json_file: Path to NVD-ish JSON file
        source_uuid_filter: Optional source UUID to filter entries
        
    Returns:
        Tuple of (cve_id, affected_entries_with_aliases) or (None, []) on error
    """
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            record = json.load(f)
        
        cve_id = record.get('id')
        if not cve_id:
            if logger:
                logger.warning(f"No CVE ID found in {json_file.name}", group="ALIAS_REPORT")
            return None, []
        
        enriched = record.get('enrichedCVEv5Affected', {})
        if not enriched:
            if logger:
                logger.debug(f"No enrichedCVEv5Affected in {cve_id}", group="ALIAS_REPORT")
            return cve_id, []
        
        entries = enriched.get('cveListV5AffectedEntries', [])
        
        # Filter entries by source UUID if specified
        if source_uuid_filter:
            filtered_entries = []
            for entry in entries:
                origin = entry.get('originAffectedEntry', {})
                source_id = origin.get('sourceId', '')
                
                if source_id == source_uuid_filter:
                    filtered_entries.append(entry)
            
            return cve_id, filtered_entries
        
        return cve_id, entries
        
    except json.JSONDecodeError as e:
        if logger:
            logger.warning(f"Invalid JSON in {json_file.name}: {e}", group="ALIAS_REPORT")
        return None, []
    except Exception as e:
        if logger:
            logger.warning(f"Failed to process {json_file.name}: {e}", group="ALIAS_REPORT")
        return None, []


def _has_alias_concerns(alias: dict) -> bool:
    """
    Check if an alias has data quality concerns.
    
    Optimized for boolean detection - returns immediately upon finding first concern.
    Uses imported constants from badge_modal_system.py (single source of truth).
    Matches JavaScript detectSourceDataConcerns and Python SDC detection.
    
    Args:
        alias: Alias dictionary with field values
        
    Returns:
        True if alias has any data quality concerns, False otherwise
    """
    import re
    
    # === REGEX PATTERNS (inline for compatibility with imported text patterns) ===
    VALID_VERSION_PATTERN = re.compile(r'^(\*|[a-zA-Z0-9]+[-*_:.+()~a-zA-Z0-9]*)$')
    INVALID_CHARS_FINDER = re.compile(r'[^a-zA-Z0-9\-*_:.+()~]')
    
    # === FIELD LIST (matching JavaScript aliasFields) ===
    fields_to_check = ['vendor', 'product', 'platform', 'packageName', 'collectionURL', 'repo']
    
    for field_name in fields_to_check:
        field_value = alias.get(field_name, '')
        if not field_value or not isinstance(field_value, str):
            continue
        
        field_lower = field_value.lower().strip()
        
        # === 1. PLACEHOLDER DETECTION (using imported GENERAL_PLACEHOLDER_VALUES) ===
        if field_lower in [p.lower() for p in GENERAL_PLACEHOLDER_VALUES]:
            return True
        
        # === 2. WHITESPACE ISSUES ===
        if field_value != field_value.lstrip():
            return True
        if field_value != field_value.rstrip():
            return True
        if '  ' in field_value:
            return True
        
        # === 3. TEXT COMPARATOR DETECTION (using imported ALL_TEXT_COMPARATOR_PATTERNS) ===
        for comparator in ALL_TEXT_COMPARATOR_PATTERNS:
            if comparator.lower() in field_lower:
                return True
        
        # Hyphenated version range detection (using imported TEXT_COMPARATOR_REGEX_PATTERNS)
        for regex_pattern in TEXT_COMPARATOR_REGEX_PATTERNS:
            if regex_pattern['pattern'].search(field_value):
                return True
        
        # === 4. INVALID CHARACTER DETECTION ===
        if not VALID_VERSION_PATTERN.match(field_value) and field_value != '*':
            invalid_chars = INVALID_CHARS_FINDER.findall(field_value)
            if invalid_chars:
                return True
    
    # === 5. BLOAT TEXT DETECTION (vendor redundancy) ===
    vendor = alias.get('vendor', '')
    if vendor and isinstance(vendor, str) and vendor.strip():
        vendor_lower = vendor.lower().strip()
        
        # Skip if vendor is a placeholder (using imported GENERAL_PLACEHOLDER_VALUES)
        if vendor_lower not in [p.lower() for p in GENERAL_PLACEHOLDER_VALUES]:
            product = alias.get('product', '')
            if product and isinstance(product, str):
                product_lower = product.lower().strip()
                if vendor_lower in product_lower and product_lower != vendor_lower:
                    return True
            
            package_name = alias.get('packageName', '')
            if package_name and isinstance(package_name, str):
                package_lower = package_name.lower().strip()
                if vendor_lower in package_lower and package_lower != vendor_lower:
                    return True
    
    return False


def calculate_alias_statistics(report_data: dict) -> dict:
    """
    Calculate statistics from alias report data for index display.
    Uses centralized detection logic with constants from badge_modal_system.py.
    
    Analyzes aliasGroups and confirmedMappings to determine:
    - Total unique aliases
    - Confirmed mapping coverage percentage
    - Count and percentage of confirmed aliases with data concerns
    - Count and percentage of unconfirmed aliases with data concerns
    
    Args:
        report_data: Dict containing 'aliasGroups' and 'confirmedMappings'
        
    Returns:
        Dict with statistics
    """
    
    alias_groups = report_data.get('aliasGroups', [])
    confirmed_mappings = report_data.get('confirmedMappings', [])
    
    unconfirmed_aliases = []
    unconfirmed_keys = set()
    
    for group in alias_groups:
        for alias in group.get('aliases', []):
            vendor = alias.get('vendor', '').strip()
            product = alias.get('product', '').strip()
            platform = alias.get('platform', alias.get('platforms', '')).strip()
            key = f"{vendor.lower()}:{product.lower()}:{platform.lower()}"
            
            unconfirmed_aliases.append(alias)
            unconfirmed_keys.add(key)
    
    confirmed_aliases = []
    confirmed_keys = set()
    
    for mapping in confirmed_mappings:
        for alias in mapping.get('aliases', []):
            vendor = alias.get('vendor', '').strip()
            product = alias.get('product', '').strip()
            platform = alias.get('platform', alias.get('platforms', '')).strip()
            key = f"{vendor.lower()}:{product.lower()}:{platform.lower()}"
            
            confirmed_aliases.append(alias)
            confirmed_keys.add(key)
    
    actual_unconfirmed_keys = unconfirmed_keys - confirmed_keys
    total_unique = len(confirmed_keys) + len(actual_unconfirmed_keys)
    confirmed_count = len(confirmed_aliases)
    
    confirmed_with_concerns = 0
    for alias in confirmed_aliases:
        if _has_alias_concerns(alias):
            confirmed_with_concerns += 1
    
    unconfirmed_with_concerns = 0
    unconfirmed_count = 0
    for alias in unconfirmed_aliases:
        vendor = alias.get('vendor', '').strip()
        product = alias.get('product', '').strip()
        platform = alias.get('platform', alias.get('platforms', '')).strip()
        key = f"{vendor.lower()}:{product.lower()}:{platform.lower()}"
        
        if key in actual_unconfirmed_keys:
            unconfirmed_count += 1
            if _has_alias_concerns(alias):
                unconfirmed_with_concerns += 1
    
    total_aliases = confirmed_count + unconfirmed_count
    confirmed_coverage_pct = (confirmed_count / total_aliases * 100) if total_aliases > 0 else 0
    confirmed_with_concerns_pct = (confirmed_with_concerns / confirmed_count * 100) if confirmed_count > 0 else 0
    unconfirmed_with_concerns_pct = (unconfirmed_with_concerns / unconfirmed_count * 100) if unconfirmed_count > 0 else 0
    
    return {
        'total_unique_aliases': total_aliases,
        'confirmed_count': confirmed_count,
        'confirmed_coverage_pct': round(confirmed_coverage_pct, 1),
        'confirmed_with_concerns_count': confirmed_with_concerns,
        'confirmed_with_concerns_pct': round(confirmed_with_concerns_pct, 1),
        'unconfirmed_count': unconfirmed_count,
        'unconfirmed_with_concerns_count': unconfirmed_with_concerns,
        'unconfirmed_with_concerns_pct': round(unconfirmed_with_concerns_pct, 1)
    }


def generate_report(
    cache_name: str = "nvd-ish_2.0_cves",
    source_uuid: Optional[str] = None,
    run_directory: Optional[Path] = None
) -> str:
    """
    Generate per-source aliasExtractionReport files from NVD-ish cache records.
    
    Args:
        cache_name: Name of cache directory within project cache/ folder
        source_uuid: Optional source UUID to filter to single source
        run_directory: Optional run directory path. If None, creates new run directory.
        
    Returns:
        Path to generated index file
        
    Raises:
        FileNotFoundError: If cache directory doesn't exist
        ValueError: If cache_name contains path traversal characters
    """
    # Security: Prevent path traversal
    if '..' in cache_name or '/' in cache_name or '\\' in cache_name:
        raise ValueError(f"Invalid cache_name: {cache_name}")
    
    project_root = get_analysis_tools_root()
    cache_path = project_root / "cache" / cache_name
    
    if not cache_path.exists():
        raise FileNotFoundError(f"Cache directory not found: {cache_path}")
    
    config = load_config()
    progress_interval = config.get('alias_report', {}).get('progress_interval', 2000)
    
    try:
        from ..reporting.dataset_contents_collector import get_dataset_contents_collector
        get_dataset_contents_collector(config_dict=config)
    except ImportError:
        if logger:
            logger.debug("Dataset contents collector not available - skipping initialization", group="ALIAS_REPORT")
    except Exception as e:
        if logger:
            logger.warning(f"Dataset contents collector initialization failed: {e}", group="ALIAS_REPORT")
    
    if logger:
        logger.info(f"Starting Alias Extraction report generation from NVD-ish cache", group="ALIAS_REPORT")
        logger.info(f"  Configuration loaded: {config.get('application', {}).get('toolname', 'Analysis_Tools')} v{config.get('application', {}).get('version', 'unknown')}", group="ALIAS_REPORT")
        logger.info(f"  Cache name: {cache_name}", group="ALIAS_REPORT")
        logger.info(f"  Cache path: {cache_path}", group="ALIAS_REPORT")
        if source_uuid:
            logger.info(f"  Source UUID filter: {source_uuid}", group="ALIAS_REPORT")
        logger.info(f"  Progress interval: {progress_interval}", group="ALIAS_REPORT")
    
    source_manager = None
    try:
        from ..storage.nvd_source_manager import get_or_refresh_source_manager
        
        # Get API key from config for potential cache refresh
        api_key = config.get('defaults', {}).get('default_api_key', '')
        
        # Get source manager using intelligent cache management
        source_manager = get_or_refresh_source_manager(api_key, log_group="ALIAS_REPORT")
    except ImportError:
        if logger:
            logger.warning("Source manager module not available - organization UUIDs will be displayed as-is", group="ALIAS_REPORT")
        source_manager = None
    except Exception as e:
        if logger:
            logger.warning(f"Source manager initialization failed: {e}", group="ALIAS_REPORT")
            logger.debug(f"Source manager error details: {e.__class__.__name__}", group="ALIAS_REPORT")
        source_manager = None
    
    # Initialize confirmed mapping manager (REQUIRED for alias reports)
    mapping_manager = None
    try:
        from ..storage.confirmed_mapping_manager import get_global_mapping_manager
        
        mapping_manager = get_global_mapping_manager()
        
        if not mapping_manager.is_initialized():
            if not source_manager or not source_manager.is_initialized():
                if logger:
                    logger.error("Cannot initialize confirmed mapping manager - source manager not available", group="ALIAS_REPORT")
                raise RuntimeError(
                    "Source manager must be initialized before confirmed mapping manager. "
                    "Unable to generate alias report without mapping manager."
                )
            
            mapping_manager.initialize(source_manager=source_manager)
            if not mapping_manager.is_initialized():
                if logger:
                    logger.error("Failed to initialize confirmed mapping manager", group="ALIAS_REPORT")
                raise RuntimeError("Failed to initialize confirmed mapping manager - cannot generate alias report")
            
            if logger:
                logger.info(f"Confirmed mapping manager initialized: {mapping_manager.get_stats()['files_loaded']} files", group="ALIAS_REPORT")
    except ImportError:
        if logger:
            logger.error("Mapping manager module not available - cannot generate alias report", group="ALIAS_REPORT")
        raise RuntimeError("Confirmed mapping manager module not available - alias reports require mapping manager")
    except RuntimeError:
        raise  # Re-raise RuntimeError from above
    except Exception as e:
        if logger:
            logger.error(f"Mapping manager initialization failed: {e}", group="ALIAS_REPORT")
        raise RuntimeError(f"Failed to initialize confirmed mapping manager: {e}")
    
    builder = AliasReportBuilder(source_manager=source_manager, mapping_manager=mapping_manager)
    json_files = scan_nvd_ish_cache(cache_path)
    
    if logger:
        logger.info(f"Found {len(json_files)} NVD-ish records to process", group="ALIAS_REPORT")
    
    processed_count = 0
    skipped_count = 0
    aliases_found_count = 0
    
    for idx, json_file in enumerate(json_files, 1):
        cve_id, entries = extract_aliases_from_record(json_file, source_uuid_filter=source_uuid)
        
        if cve_id is None:
            skipped_count += 1
            continue
        
        has_aliases = any(
            entry.get('aliasExtraction', {}).get('aliases', [])
            for entry in entries
        )
        
        if has_aliases:
            builder.add_cve_aliases(cve_id, entries)
            aliases_found_count += 1
        
        processed_count += 1
        
        if idx % progress_interval == 0 and logger:
            logger.info(f"Processed {idx}/{len(json_files)} records...", group="ALIAS_REPORT")
    
    if logger:
        logger.debug(
            f"Processing complete: {processed_count} CVEs, "
            f"{aliases_found_count} with aliases, {skipped_count} skipped",
            group="ALIAS_REPORT"
        )
    
    per_source_reports = builder.finalize()
    
    if run_directory is None:
        from ..storage.run_organization import create_run_directory
        
        descriptor = "alias_report"
        if source_uuid and per_source_reports:
            for org_name, report in per_source_reports.items():
                if source_uuid in report['metadata'].get('all_source_identifiers', []):
                    descriptor += f"_{org_name[:20].replace(' ', '_')}"
                    break
            else:
                descriptor += f"_{source_uuid[:8]}"
        else:
            descriptor += "_all_sources"
        
        run_directory, _ = create_run_directory(
            execution_type="alias_report",
            subdirs=["logs", "reports"]
        )
    
    if logger and hasattr(logger, 'set_run_logs_directory'):
        logger.set_run_logs_directory(run_directory / "logs")
    
    output_dir = run_directory / "logs"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    reports_dir = run_directory / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    css_dir = reports_dir / "css"
    css_dir.mkdir(parents=True, exist_ok=True)
    
    # Locate index template and CSS
    project_root = get_analysis_tools_root()
    index_template = project_root / "src" / "analysis_tool" / "static" / "templates" / "Alias_Mapping_Index_Template.html"
    report_template = project_root / "src" / "analysis_tool" / "static" / "templates" / "Alias_Mapping_Report_Template.html"
    css_source = project_root / "src" / "analysis_tool" / "static" / "css" / "alias_mapping_dashboard.css"
    
    html_generation_enabled = index_template.exists() and report_template.exists()
    
    # Copy CSS file to reports directory if it exists
    if css_source.exists() and html_generation_enabled:
        import shutil
        css_dest = css_dir / "alias_mapping_dashboard.css"
        try:
            shutil.copy2(css_source, css_dest)
            if logger:
                logger.debug(f"Copied CSS file to {css_dest}", group="ALIAS_REPORT")
        except Exception as e:
            if logger:
                logger.warning(f"Failed to copy CSS file: {e}", group="ALIAS_REPORT")
    
    if not html_generation_enabled and logger:
        logger.warning(f"Templates not found - HTML generation disabled", group="ALIAS_REPORT")
        logger.warning(f"  Index: {index_template}", group="ALIAS_REPORT")
        logger.warning(f"  Report: {report_template}", group="ALIAS_REPORT")
    
    if logger:
        logger.info(f"Writing {len(per_source_reports)} source-specific reports...", group="ALIAS_REPORT")
    
    written_files = []
    written_orgs = []
    skipped_orgs = []
    html_files = []
    
    for org_name, report_data in per_source_reports.items():
        # Skip organizations with no aliases
        if report_data['metadata']['unique_aliases_extracted'] == 0:
            skipped_orgs.append(org_name)
            continue
        
        safe_name = ''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in org_name)
        
        all_ids = report_data['metadata'].get('all_source_identifiers', [])
        suffix = all_ids[0][:8] if all_ids and len(all_ids[0]) >= 8 else (all_ids[0] if all_ids else 'unknown')
        suffix = ''.join(c if c.isalnum() else '_' for c in suffix)
        
        base_filename = f"aliasExtractionReport_{safe_name}_{suffix}"
        
        json_file = output_dir / f"{base_filename}.json"
        temp_file = json_file.with_suffix('.tmp')
        
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            temp_file.replace(json_file)
            written_files.append(json_file.name)
            written_orgs.append(org_name)
            
            if logger:
                logger.info(
                    f"  {json_file.name}: {report_data['metadata']['unique_aliases_extracted']} aliases, "
                    f"{report_data['metadata']['product_groups_created']} groups",
                    group="ALIAS_REPORT"
                )
            
        except Exception as e:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except:
                    pass
            raise RuntimeError(f"Failed to write JSON report for {org_name}: {e}")
        
        if html_generation_enabled:
            try:
                html_file = reports_dir / f"{base_filename}.html"
                generate_alias_html_report(report_data, html_file, report_template, __version__)
                html_files.append(html_file)
            except Exception as e:
                if logger:
                    logger.warning(f"Failed to generate HTML for {org_name}: {e}", group="ALIAS_REPORT")
    
    if logger and skipped_orgs:
        logger.debug(f"Skipped {len(skipped_orgs)} organizations with no aliases", group="ALIAS_REPORT")
    
    # Write index file listing all organizations with calculated statistics
    index_sources = []
    for org_name in written_orgs:
        stats = calculate_alias_statistics(per_source_reports[org_name])
        
        index_sources.append({
            'source_id': per_source_reports[org_name]['metadata']['source_id'],
            'source_name': org_name,
            'all_source_identifiers': per_source_reports[org_name]['metadata'].get('all_source_identifiers', []),
            'report_file': f"aliasExtractionReport_{''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in org_name)}_{''.join(c if c.isalnum() else '_' for c in (per_source_reports[org_name]['metadata'].get('all_source_identifiers', ['unknown'])[0][:8] if per_source_reports[org_name]['metadata'].get('all_source_identifiers') else 'unknown'))}.json",
            'total_cves_processed': per_source_reports[org_name]['metadata']['total_cves_processed'],
            'unique_aliases_extracted': per_source_reports[org_name]['metadata']['unique_aliases_extracted'],
            'product_groups_created': per_source_reports[org_name]['metadata']['product_groups_created'],
            'total_unique_aliases': stats['total_unique_aliases'],
            'confirmed_count': stats['confirmed_count'],
            'confirmed_coverage_pct': stats['confirmed_coverage_pct'],
            'confirmed_with_concerns_count': stats['confirmed_with_concerns_count'],
            'confirmed_with_concerns_pct': stats['confirmed_with_concerns_pct'],
            'unconfirmed_with_concerns_count': stats['unconfirmed_with_concerns_count'],
            'unconfirmed_with_concerns_pct': stats['unconfirmed_with_concerns_pct']
        })
    
    index_data = {
        'metadata': builder.global_metadata,
        'sources': index_sources
    }
    
    # Write JSON index file
    index_file = output_dir / "aliasExtractionReport_index.json"
    temp_file = index_file.with_suffix('.tmp')
    
    try:
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(index_data, f, indent=2, ensure_ascii=False)
        
        temp_file.replace(index_file)
        
        if logger:
            logger.debug(f"Index file written: {index_file}", group="ALIAS_REPORT")
        
    except Exception as e:
        if logger:
            logger.error(f"Failed to write index file: {e}", group="ALIAS_REPORT")
        if temp_file.exists():
            try:
                temp_file.unlink()
            except:
                pass
        raise
    
    if html_generation_enabled:
        try:
            index_html = reports_dir / "Alias_Extraction_Report_Index.html"
            generate_alias_index_html(index_data, index_html, index_template, __version__)
            html_files.append(index_html)
            if logger:
                logger.info(f"Generated HTML index page: {index_html.name}", group="ALIAS_REPORT")
        except Exception as e:
            if logger:
                logger.warning(f"Failed to generate HTML index: {e}", group="ALIAS_REPORT")
                import traceback
                logger.debug(f"Index generation error details: {traceback.format_exc()}", group="ALIAS_REPORT")
    
    if logger:
        total_aliases_across_sources = sum(s['unique_aliases_extracted'] for s in index_data['sources'])
        total_cves_across_sources = sum(s['total_cves_processed'] for s in index_data['sources'])
        
        logger.info(f"", group="ALIAS_REPORT")
        logger.info(f"=" * 70, group="ALIAS_REPORT")
        logger.info(f"ALIAS EXTRACTION REPORT GENERATION COMPLETE", group="ALIAS_REPORT")
        logger.info(f"=" * 70, group="ALIAS_REPORT")
        logger.info(f"", group="ALIAS_REPORT")
        
        # File Processing
        logger.info(f"FILE PROCESSING:", group="ALIAS_REPORT")
        logger.info(f"  NVD-ish JSON files found: {len(json_files)}", group="ALIAS_REPORT")
        logger.info(f"  NVD-ish files processed: {processed_count}", group="ALIAS_REPORT")
        logger.info(f"  NVD-ish files skipped: {skipped_count}", group="ALIAS_REPORT")
        logger.info(f"  JSON report files written: {len(written_orgs)} source + 1 index", group="ALIAS_REPORT")
        if html_files:
            logger.info(f"  HTML report files written: {len(html_files) - 1} source + 1 index", group="ALIAS_REPORT")
        logger.info(f"", group="ALIAS_REPORT")
        
        # CVE Counts
        logger.info(f"CVE STATISTICS:", group="ALIAS_REPORT")
        logger.info(f"  Global unique CVEs: {builder.global_metadata['total_cves_processed']}", group="ALIAS_REPORT")
        logger.info(f"  CVEs across sources: {total_cves_across_sources}", group="ALIAS_REPORT")
        logger.info(f"  Multi-source overlap: {total_cves_across_sources - builder.global_metadata['total_cves_processed']}", group="ALIAS_REPORT")
        logger.info(f"", group="ALIAS_REPORT")
        
        # Alias Statistics
        logger.info(f"ALIAS EXTRACTION STATISTICS:", group="ALIAS_REPORT")
        logger.info(f"  Total unique aliases extracted: {total_aliases_across_sources}", group="ALIAS_REPORT")
        logger.info(f"  CVEs with aliases: {aliases_found_count}", group="ALIAS_REPORT")
        logger.info(f"  Organizations with aliases: {len(written_orgs)}", group="ALIAS_REPORT")
        if skipped_orgs:
            logger.info(f"  Organizations with no aliases (skipped): {len(skipped_orgs)}", group="ALIAS_REPORT")
        logger.info(f"", group="ALIAS_REPORT")
        
        # Confirmed Mapping Statistics
        if builder.mapping_manager and builder.mapping_manager.is_initialized():
            mapping_stats = builder.mapping_manager.get_stats()
            logger.info(f"CONFIRMED MAPPING FILES:", group="ALIAS_REPORT")
            logger.info(f"  Files loaded at startup: {mapping_stats['files_loaded']}", group="ALIAS_REPORT")
            logger.info(f"  Files used in this run: {mapping_stats['files_used']}", group="ALIAS_REPORT")
            logger.info(f"  Files available but unused: {mapping_stats['files_loaded'] - mapping_stats['files_used']}", group="ALIAS_REPORT")
            if mapping_stats['used_files']:
                logger.info(f"  Used files: {', '.join(mapping_stats['used_files'])}", group="ALIAS_REPORT")
            logger.info(f"", group="ALIAS_REPORT")
            logger.info(f"  Organizations with no aliases (skipped): {len(skipped_orgs)}", group="ALIAS_REPORT")
        logger.info(f"", group="ALIAS_REPORT")
        
        # Top Organizations by Alias Count
        logger.info(f"TOP ORGANIZATIONS BY ALIAS COUNT:", group="ALIAS_REPORT")
        top_orgs = sorted(index_data['sources'], key=lambda x: x['unique_aliases_extracted'], reverse=True)[:10]
        for idx, org in enumerate(top_orgs, 1):
            logger.info(f"  {idx}. {org['source_name']}: {org['unique_aliases_extracted']} aliases ({org['total_cves_processed']} CVEs)", group="ALIAS_REPORT")
        logger.info(f"", group="ALIAS_REPORT")
        
        # Output Paths
        logger.info(f"OUTPUT LOCATIONS:", group="ALIAS_REPORT")
        logger.info(f"  JSON Index: {index_file}", group="ALIAS_REPORT")
        logger.info(f"  JSON Reports: {output_dir}", group="ALIAS_REPORT")
        if html_files:
            logger.info(f"  HTML Index: {html_files[0]}", group="ALIAS_REPORT")
            logger.info(f"  HTML Reports: {reports_dir}", group="ALIAS_REPORT")
        logger.info(f"  Run directory: {run_directory}", group="ALIAS_REPORT")
        logger.info(f"", group="ALIAS_REPORT")
        logger.info(f"=" * 70, group="ALIAS_REPORT")
        logger.info(f"", group="ALIAS_REPORT")
    
    # Validate report statistics
    if logger:
        logger.info(f"Running statistics validation...", group="ALIAS_REPORT")
        validation_results = validate_report_statistics(index_file, output_dir)
        
        if validation_results['mismatched_sources'] == 0:
            logger.info(f"✓ VALIDATION PASSED: All {validation_results['total_sources']} sources aligned", group="ALIAS_REPORT")
        else:
            logger.warning(f"✗ VALIDATION FAILED: {validation_results['mismatched_sources']} of {validation_results['total_sources']} sources mismatched", group="ALIAS_REPORT")
            for mismatch in validation_results['mismatches']:
                if 'error' in mismatch:
                    logger.error(f"  Validation error: {mismatch['error']}", group="ALIAS_REPORT")
                else:
                    logger.warning(f"  {mismatch['source_name']}: {mismatch['field']} mismatch (index={mismatch['index_value']}, calculated={mismatch['calculated_value']})", group="ALIAS_REPORT")
        logger.info(f"", group="ALIAS_REPORT")
    
    return str(index_file)


def validate_report_statistics(index_file: Path, reports_dir: Path) -> dict:
    """
    Validate that index statistics match individual report calculations.
    
    Loads the index and each source report, recalculates statistics from the
    report data, and compares against the index values. This ensures the
    index page displays accurate data that matches the detailed reports.
    
    Args:
        index_file: Path to aliasExtractionReport_index.json
        reports_dir: Directory containing individual report JSON files
        
    Returns:
        dict with validation results:
            {
                'total_sources': int,
                'aligned_sources': int,
                'mismatched_sources': int,
                'mismatches': [{'source_name': str, 'field': str, 'index_value': val, 'calculated_value': val}]
            }
    """
    logger = get_logger()
    
    try:
        # Load index
        with open(index_file, 'r', encoding='utf-8') as f:
            index = json.load(f)
        
        results = {
            'total_sources': len(index['sources']),
            'aligned_sources': 0,
            'mismatched_sources': 0,
            'mismatches': []
        }
        
        for source in index['sources']:
            source_name = source['source_name']
            report_file = reports_dir / source['report_file']
            
            if not report_file.exists():
                results['mismatches'].append({
                    'source_name': source_name,
                    'field': 'file_missing',
                    'index_value': source['report_file'],
                    'calculated_value': 'FILE NOT FOUND'
                })
                results['mismatched_sources'] += 1
                continue
            
            # Load report
            with open(report_file, 'r', encoding='utf-8') as f:
                report = json.load(f)
            
            unconfirmed_aliases = []
            unconfirmed_keys = set()
            for group in report.get('aliasGroups', []):
                for alias in group.get('aliases', []):
                    vendor = alias.get('vendor', '').strip().lower()
                    product = alias.get('product', '').strip().lower()
                    platform = alias.get('platform', alias.get('platforms', '')).strip().lower()
                    key = f'{vendor}:{product}:{platform}'
                    unconfirmed_aliases.append(alias)
                    unconfirmed_keys.add(key)
            
            confirmed_aliases = []
            confirmed_keys = set()
            for mapping in report.get('confirmedMappings', []):
                for alias in mapping.get('aliases', []):
                    vendor = alias.get('vendor', '').strip().lower()
                    product = alias.get('product', '').strip().lower()
                    platform = alias.get('platform', alias.get('platforms', '')).strip().lower()
                    key = f'{vendor}:{product}:{platform}'
                    confirmed_aliases.append(alias)
                    confirmed_keys.add(key)
            
            actual_unconfirmed_keys = unconfirmed_keys - confirmed_keys
            
            # Count unconfirmed that are ACTUALLY unconfirmed
            unconfirmed_count = 0
            for alias in unconfirmed_aliases:
                vendor = alias.get('vendor', '').strip().lower()
                product = alias.get('product', '').strip().lower()
                platform = alias.get('platform', alias.get('platforms', '')).strip().lower()
                key = f'{vendor}:{product}:{platform}'
                if key in actual_unconfirmed_keys:
                    unconfirmed_count += 1
            
            # Calculate totals and coverage
            confirmed_count = len(confirmed_aliases)
            total_aliases = confirmed_count + unconfirmed_count
            coverage_pct = round((confirmed_count / total_aliases * 100), 1) if total_aliases > 0 else 0
            
            # Count concerns using centralized detection logic from module-level helper
            confirmed_with_concerns = 0
            for mapping in report.get('confirmedMappings', []):
                for alias in mapping.get('aliases', []):
                    if _has_alias_concerns(alias):
                        confirmed_with_concerns += 1
            
            unconfirmed_with_concerns = 0
            for group in report.get('aliasGroups', []):
                for alias in group.get('aliases', []):
                    vendor = alias.get('vendor', '').strip().lower()
                    product = alias.get('product', '').strip().lower()
                    platform = alias.get('platform', alias.get('platforms', '')).strip().lower()
                    key = f'{vendor}:{product}:{platform}'
                    
                    if key in actual_unconfirmed_keys:
                        if _has_alias_concerns(alias):
                            unconfirmed_with_concerns += 1
            
            # Compare with index values
            source_matched = True
            
            if source['total_unique_aliases'] != total_aliases:
                results['mismatches'].append({
                    'source_name': source_name,
                    'field': 'total_unique_aliases',
                    'index_value': source['total_unique_aliases'],
                    'calculated_value': total_aliases
                })
                source_matched = False
            
            if source['confirmed_coverage_pct'] != coverage_pct:
                results['mismatches'].append({
                    'source_name': source_name,
                    'field': 'confirmed_coverage_pct',
                    'index_value': source['confirmed_coverage_pct'],
                    'calculated_value': coverage_pct
                })
                source_matched = False
            
            if source['confirmed_with_concerns_count'] != confirmed_with_concerns:
                results['mismatches'].append({
                    'source_name': source_name,
                    'field': 'confirmed_with_concerns_count',
                    'index_value': source['confirmed_with_concerns_count'],
                    'calculated_value': confirmed_with_concerns
                })
                source_matched = False
            
            if source['unconfirmed_with_concerns_count'] != unconfirmed_with_concerns:
                results['mismatches'].append({
                    'source_name': source_name,
                    'field': 'unconfirmed_with_concerns_count',
                    'index_value': source['unconfirmed_with_concerns_count'],
                    'calculated_value': unconfirmed_with_concerns
                })
                source_matched = False
            
            if source_matched:
                results['aligned_sources'] += 1
            else:
                results['mismatched_sources'] += 1
        
        return results
        
    except Exception as e:
        if logger:
            logger.error(f"Validation failed: {e}", group="ALIAS_REPORT")
        return {
            'total_sources': 0,
            'aligned_sources': 0,
            'mismatched_sources': 0,
            'mismatches': [{'error': str(e)}]
        }


def main():
    """Command-line interface for standalone execution."""
    import argparse
    
    # Load config for defaults
    config = load_config()
    default_cache_name = config.get('nvd_ish_output', {}).get('cache_name', 'nvd-ish_2.0_cves')
    
    parser = argparse.ArgumentParser(
        description="Generate Alias Extraction report from NVD-ish cache",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate report in a new run directory
  python -m src.analysis_tool.reporting.generate_alias_report

  # Use existing run directory (e.g., from generate_dataset)
  python -m src.analysis_tool.reporting.generate_alias_report \
      --run-id 2025-12-01_10-30-00_dataset_last_7_days_nvd-ish

  # Filter by source UUID
  python -m src.analysis_tool.reporting.generate_alias_report \
      --source-uuid 6abe59d8-c742-4dff-8ce8-9b0ca1073da8

  # Use custom cache directory
  python -m src.analysis_tool.reporting.generate_alias_report \
      --custom-cache nvd-ish_test_data
        """
    )
    
    parser.add_argument(
        '--run-id',
        help='Existing run ID to use (creates new run if not specified)'
    )
    
    parser.add_argument(
        '--source-uuid',
        help='Filter aliases by source UUID (affects confirmedMappings lookup)'
    )
    
    parser.add_argument(
        '--custom-cache',
        default=default_cache_name,
        help=f'Cache directory name within cache/ folder (default: {default_cache_name})'
    )
    
    args = parser.parse_args()
    
    try:
        # Determine run directory
        run_directory = None
        if args.run_id:
            # Find and use existing run directory
            project_root = get_analysis_tools_root()
            run_directory = project_root / "runs" / args.run_id
            
            if not run_directory.exists():
                raise ValueError(f"Run directory does not exist: {run_directory}")
            
            if logger:
                logger.info(f"Using existing run directory: {args.run_id}", group="ALIAS_REPORT")
        
        # Generate report
        index_path = generate_report(
            cache_name=args.custom_cache,
            source_uuid=args.source_uuid,
            run_directory=run_directory
        )
        
        # Extract run directory from index path
        index_file_path = Path(index_path)
        actual_run_dir = index_file_path.parent.parent
        run_id = actual_run_dir.name
        
        print(f"\nPer-source alias reports generated successfully")
        print(f"JSON Index: {index_path}")
        print(f"JSON Reports: {index_file_path.parent}")
        print(f"\nRun ID: {run_id}")
        
        return 0
        
    except Exception as e:
        if logger:
            logger.error(f"Report generation failed: {e}", group="ALIAS_REPORT")
        print(f"\nError: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
