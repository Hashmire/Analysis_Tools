#!/usr/bin/env python3
"""
CPE-AS Automation Report Generator from NVD-ish Cache

Scans enriched NVD-ish records and generates per-source CPE-AS automation success
reports independent of live CVE processing. Splits data by source to handle 
large datasets.

Architecture:
    - Reads from: cache/nvd-ish_2.0_cves/
    - Extracts: Automation-relevant metrics from NVD-ish records
    - Generates: 
        * cpeAsAutomationReport_index.json (source listing and global metadata)
        * cpeAsAutomationReport_[sourcename]_[id].json (per-source data)

Output Structure:
    runs/[run_id]/logs/
        ├── cpeAsAutomationReport_index.json
        ├── cpeAsAutomationReport_Adobe_12345678.json
        ├── cpeAsAutomationReport_Microsoft_abcd1234.json
        └── ... (one file per source)

Usage:
    # Standalone - creates new run directory
    python -m src.analysis_tool.reporting.generate_cpeas_automation_report

    # Use existing run directory (e.g., from generate_dataset)
    python -m src.analysis_tool.reporting.generate_cpeas_automation_report \\
        --run-id 2026-01-25_10-30-00_dataset_last_7_days_nvd-ish

    # Programmatic
    from src.analysis_tool.reporting.generate_cpeas_automation_report import generate_report
    generate_report(cache_name="nvd-ish_2.0_cves", run_directory=None)
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from collections import defaultdict

# CRITICAL IMPORTS - must succeed or script fails
from ..logging.workflow_logger import get_logger
from ..storage.run_organization import get_analysis_tools_root
logger = get_logger()

# Presentation-layer imports with graceful degradation
try:
    from .. import __version__
except ImportError:
    __version__ = "unknown"


def load_config() -> Dict:
    """Load configuration file with defaults."""
    try:
        project_root = get_analysis_tools_root()
        config_path = project_root / "src" / "analysis_tool" / "config.json"
        
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            logger.warning(f"Config file not found at {config_path}, using hardcoded defaults", group="DATA_PROC")
            return {}
    except Exception as e:
        logger.warning(f"Failed to load config: {e}, using hardcoded defaults", group="DATA_PROC")
        return {}


class CPEASAutomationReportBuilder:
    """
    Builds per-source CPE-AS automation reports from NVD-ish cache records.
    
    Generates separate report files for each source to handle large datasets.
    """
    
    def __init__(self, source_manager=None):
        """
        Initialize the report builder.
        
        Args:
            source_manager: Optional NVD source manager for UUID resolution
        """
        self.source_manager = source_manager
        self.global_metadata = {
            'run_started_at': datetime.now(timezone.utc).isoformat(),
            'total_cves_processed': 0,
            'total_sources': 0,
            'report_scope': 'CPE Automation Success - Per-Source Reports',
            'status': 'in_progress'
        }
        
        # Group data by source_id
        self.sources = defaultdict(lambda: {
            'metadata': {
                'total_cves_processed': 0,
            },
            'summary': {},
            'cve_data': [],
            'cve_lookup': {},  # Map CVE ID to CVE data entry for multi-entry support
            'cve_ids': set()  # Track unique CVEs per source
        })
    
    def add_cve(self, cve_id: str, nvd_ish_record: Dict) -> None:
        """
        Process one CVE's NVD-ish record and extract metrics by source.
        
        Groups all affected entries under single CVE with:
        - Per-entry CPE determination confidence
        - Per-entry CPE-AS generation breakdown
        - Per-version granular data (pattern, concerns, status)
        - CVE-level rollup metadata
        
        Args:
            cve_id: CVE identifier
            nvd_ish_record: Full NVD-ish enhanced record
        """
        # Extract source information from enriched data
        enriched_data = nvd_ish_record.get('enrichedCVEv5Affected', {})
        affected_entries = enriched_data.get('cveListV5AffectedEntries', [])
        
        if not affected_entries:
            return
        
        # Group entries by source
        entries_by_source = defaultdict(list)
        
        for entry_idx, entry in enumerate(affected_entries):
            origin = entry.get('originAffectedEntry', {})
            source_id = origin.get('sourceId', 'Unknown')
            entries_by_source[source_id].append((entry_idx, entry))
        
        # Process each source's entries for this CVE
        for source_id, source_entries in entries_by_source.items():
            source_info = self.sources[source_id]
            
            # Find or create CVE entry for this source
            if cve_id in source_info['cve_lookup']:
                cve_entry = source_info['cve_lookup'][cve_id]
            else:
                # Create new CVE entry
                cve_entry = {
                    'cve_id': cve_id,
                    'source_identifier': nvd_ish_record.get('sourceIdentifier', 'unknown'),
                    'published': nvd_ish_record.get('published', ''),
                    'cve_metadata': {},
                    'affected_entries': []
                }
                source_info['cve_lookup'][cve_id] = cve_entry
                source_info['cve_data'].append(cve_entry)
                source_info['cve_ids'].add(cve_id)
                source_info['metadata']['total_cves_processed'] += 1
            
            # Process each affected entry for this CVE
            for entry_idx, entry in source_entries:
                entry_data = self._extract_entry_metrics(entry, entry_idx)
                cve_entry['affected_entries'].append(entry_data)
            
            # Calculate CVE-level metadata after all entries added
            cve_entry['cve_metadata'] = self._calculate_cve_metadata(cve_entry['affected_entries'])
    
    def _extract_entry_metrics(self, entry: Dict, entry_idx: int) -> Dict:
        """
        Extract automation metrics from a single affected entry with version-level granularity.
        
        Args:
            entry: Single affected entry from cveListV5AffectedEntries
            entry_idx: Index of this entry in the affected array
            
        Returns:
            Dictionary with entry_index, cpe_determination_confidence, cpe_as_breakdown,
            pattern_usage (frequency dict), concerns_summary, and versions array
        """
        metrics = {
            'entry_index': entry_idx
        }
        
        # CPE Determination confidence analysis
        cpe_det = entry.get('cpeDetermination', {})
        confirmed_mappings = cpe_det.get('confirmedMappings', [])
        top10_suggestions = cpe_det.get('top10SuggestedCPEBaseStrings', [])
        
        if confirmed_mappings:
            metrics['cpe_determination_confidence'] = 'confirmedMapping'
        elif top10_suggestions:
            metrics['cpe_determination_confidence'] = 'top10Suggestion'
        else:
            metrics['cpe_determination_confidence'] = 'nothing'
        
        # CPE-AS Pattern Detection analysis with version-level granularity
        cpe_as_gen = entry.get('cpeAsGeneration', {})
        cpe_match_objects = cpe_as_gen.get('cpeMatchObjects', [])
        
        # Extract per-version data and build frequency distributions
        versions = []
        pattern_usage = {}
        concerns_summary_set = set()
        cpe_as_breakdown = {'complete': 0, 'partial': 0, 'none': 0}
        
        for match_obj in cpe_match_objects:
            # Extract version string from match object
            version_str = self._extract_version_string(match_obj)
            pattern = match_obj.get('appliedPattern', '')
            concerns = match_obj.get('concerns', [])
            
            # Determine CPE-AS status for this version
            if concerns:
                cpe_as_status = 'partial'
                cpe_as_breakdown['partial'] += 1
            else:
                cpe_as_status = 'complete'
                cpe_as_breakdown['complete'] += 1
            
            # Build version entry
            versions.append({
                'version': version_str,
                'cpe_as_status': cpe_as_status,
                'pattern': pattern,
                'concerns': concerns
            })
            
            # Count pattern frequency
            if pattern:
                pattern_usage[pattern] = pattern_usage.get(pattern, 0) + 1
            
            # Aggregate concerns
            concerns_summary_set.update(concerns)
        
        # Handle entries with no CPE-AS generation
        origin = entry.get('originAffectedEntry', {})
        origin_versions = origin.get('versions', [])
        if not cpe_match_objects and origin_versions:
            # No automation for these versions
            for ver_obj in origin_versions:
                version_str = ver_obj.get('version', 'unknown')
                versions.append({
                    'version': version_str,
                    'cpe_as_status': 'none',
                    'pattern': None,
                    'concerns': []
                })
                cpe_as_breakdown['none'] += 1
        
        metrics['cpe_as_breakdown'] = cpe_as_breakdown
        metrics['pattern_usage'] = pattern_usage
        metrics['concerns_summary'] = sorted(list(concerns_summary_set))
        metrics['versions'] = versions
        
        return metrics
    
    def _extract_version_string(self, match_obj: Dict) -> str:
        """
        Extract human-readable version string from CPE match object.
        
        Args:
            match_obj: CPE match object from cpeAsGeneration
            
        Returns:
            Version string for display (e.g., "1.0.0", "< 2.0.0", ">= 1.5.0, < 2.0.0")
        """
        # Check for exact version
        if match_obj.get('versionEndExcluding'):
            return f"< {match_obj['versionEndExcluding']}"
        elif match_obj.get('versionEndIncluding'):
            return f"<= {match_obj['versionEndIncluding']}"
        elif match_obj.get('versionStartIncluding') and match_obj.get('versionEndExcluding'):
            return f">= {match_obj['versionStartIncluding']}, < {match_obj['versionEndExcluding']}"
        elif match_obj.get('versionStartExcluding') and match_obj.get('versionEndExcluding'):
            return f"> {match_obj['versionStartExcluding']}, < {match_obj['versionEndExcluding']}"
        elif match_obj.get('versionStartIncluding'):
            return f">= {match_obj['versionStartIncluding']}"
        elif match_obj.get('versionStartExcluding'):
            return f"> {match_obj['versionStartExcluding']}"
        
        # Fallback to criteria if no version bounds
        criteria = match_obj.get('criteria', '')
        if criteria:
            # Extract version from CPE string if present
            parts = criteria.split(':')
            if len(parts) > 4:
                return parts[4] if parts[4] != '*' else 'all versions'
        
        return 'unknown'
    
    def _calculate_cve_metadata(self, affected_entries: List[Dict]) -> Dict:
        """
        Calculate CVE-level metadata from affected entries.
        
        Args:
            affected_entries: List of affected entry data dicts
            
        Returns:
            CVE metadata with rollups and overall status
        """
        total_entries = len(affected_entries)
        entries_full = 0
        entries_partial = 0
        entries_none = 0
        
        total_versions = 0
        total_cpe_matches = 0
        cpe_as_rollup = {'complete': 0, 'partial': 0, 'none': 0}
        
        for entry in affected_entries:
            # Count entry automation level based on CPE DETERMINATION confidence only
            # This determines the CVE-level "CPE Determination" badge counts
            cpe_det_conf = entry.get('cpe_determination_confidence', 'nothing')
            cpe_as_breakdown = entry.get('cpe_as_breakdown', {})
            
            # Entry CPE Determination classification:
            # - Full: confirmedMapping + all versions have complete CPE-AS
            # - Partial: confirmedMapping (but not all complete) OR top10Suggestion
            # - None: nothing (no confirmed mapping, no suggestions)
            
            if cpe_det_conf == 'confirmedMapping':
                # Has confirmed mapping - check if all versions are complete
                all_complete = (cpe_as_breakdown.get('complete', 0) > 0 and 
                              cpe_as_breakdown.get('partial', 0) == 0 and 
                              cpe_as_breakdown.get('none', 0) == 0)
                if all_complete:
                    entries_full += 1
                else:
                    entries_partial += 1
            elif cpe_det_conf == 'top10Suggestion':
                # Has suggestions but no confirmed mapping
                entries_partial += 1
            else:
                # No confirmed mapping, no suggestions (cpe_det_conf == 'nothing')
                entries_none += 1
            
            # Aggregate version counts
            versions = entry.get('versions', [])
            total_versions += len(versions)
            total_cpe_matches += cpe_as_breakdown.get('complete', 0) + cpe_as_breakdown.get('partial', 0)
            
            # Rollup CPE-AS status
            cpe_as_rollup['complete'] += cpe_as_breakdown.get('complete', 0)
            cpe_as_rollup['partial'] += cpe_as_breakdown.get('partial', 0)
            cpe_as_rollup['none'] += cpe_as_breakdown.get('none', 0)
        
        # Determine overall status
        if entries_full == total_entries:
            overall_status = 'full'
        elif entries_none == total_entries:
            overall_status = 'none'
        else:
            overall_status = 'partial'
        
        return {
            'total_affected_entries': total_entries,
            'entries_full_automation': entries_full,
            'entries_partial_automation': entries_partial,
            'entries_no_automation': entries_none,
            'total_versions': total_versions,
            'total_cpe_matches': total_cpe_matches,
            'cpe_as_rollup': cpe_as_rollup,
            'overall_status': overall_status
        }
    
    def _resolve_source_name(self, source_id: str) -> str:
        """Resolve source UUID to human-readable name."""
        if self.source_manager:
            return self.source_manager.get_source_name(source_id)
        return source_id
    
    def finalize(self) -> Dict:
        """
        Finalize per-source reports and generate summaries.
        
        Calculates aggregated metrics for each source:
        - Total CVEs processed
        - Automation success rates (full, partial, none)
        - CPE determination confidence distribution
        - CPE-AS generation success distribution
        - Common concerns and patterns
        
        Returns:
            Dictionary mapping source_id to report data with summary statistics
        """
        self.global_metadata['status'] = 'completed'
        self.global_metadata['run_completed_at'] = datetime.now(timezone.utc).isoformat()
        self.global_metadata['total_sources'] = len(self.sources)
        
        # Build per-source reports with summary statistics
        per_source_reports = {}
        
        for source_id, source_info in self.sources.items():
            # Remove non-serializable data structures
            source_info.pop('cve_ids', None)
            source_info.pop('cve_lookup', None)
            
            # Add source name to metadata
            source_info['metadata']['source_id'] = source_id
            source_info['metadata']['source_name'] = self._resolve_source_name(source_id)
            source_info['metadata']['run_started_at'] = self.global_metadata['run_started_at']
            
            # Calculate summary statistics
            source_info['summary'] = self._calculate_source_summary(source_info['cve_data'])
            
            per_source_reports[source_id] = source_info
        
        return per_source_reports
    
    def _calculate_source_summary(self, cve_data: List[Dict]) -> Dict:
        """
        Calculate summary statistics for a source's CVE data.
        
        Args:
            cve_data: List of CVE data entries (with new affected_entries structure)
            
        Returns:
            Dictionary of summary statistics matching template expectations
        """
        total_cves = len(cve_data)
        
        if total_cves == 0:
            return {
                'total_cves': 0,
                'automation_level_stats': {},
                'cpe_determination_stats': {},
                'cpe_as_stats': {},
                'version_stats': {},
                'top_concerns': [],
                'top_patterns': []
            }
        
        # CVE-level automation distribution (from cve_metadata.overall_status)
        automation_level_counts = {'full': 0, 'partial': 0, 'none': 0}
        
        # Entry-level aggregations
        entry_cpe_det_counts = {'confirmedMapping': 0, 'top10Suggestion': 0, 'nothing': 0}
        
        # Version-level aggregations
        version_cpe_as_counts = {'complete': 0, 'partial': 0, 'none': 0}
        
        # Concern and pattern aggregation
        all_concerns = []
        pattern_counts = {}
        
        for cve in cve_data:
            # CVE-level status
            cve_metadata = cve.get('cve_metadata', {})
            overall_status = cve_metadata.get('overall_status', 'none')
            automation_level_counts[overall_status] = automation_level_counts.get(overall_status, 0) + 1
            
            # Process each affected entry
            for entry in cve.get('affected_entries', []):
                # Entry-level CPE determination
                cpe_det_conf = entry.get('cpe_determination_confidence', 'nothing')
                entry_cpe_det_counts[cpe_det_conf] += 1
                
                # Aggregate concerns from entry
                all_concerns.extend(entry.get('concerns_summary', []))
                
                # Aggregate patterns and count frequency
                pattern_usage = entry.get('pattern_usage', {})
                for pattern, count in pattern_usage.items():
                    pattern_counts[pattern] = pattern_counts.get(pattern, 0) + count
                
                # Aggregate version-level CPE-AS status
                cpe_as_breakdown = entry.get('cpe_as_breakdown', {})
                version_cpe_as_counts['complete'] += cpe_as_breakdown.get('complete', 0)
                version_cpe_as_counts['partial'] += cpe_as_breakdown.get('partial', 0)
                version_cpe_as_counts['none'] += cpe_as_breakdown.get('none', 0)
        
        # Calculate total entries and versions
        total_entries = sum(entry_cpe_det_counts.values())
        total_versions = sum(version_cpe_as_counts.values())
        
        # Count unique concerns
        concern_counts = {}
        for concern in all_concerns:
            concern_counts[concern] = concern_counts.get(concern, 0) + 1
        
        # Sort by frequency
        top_concerns = sorted(concern_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_patterns = sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Build summary matching template format
        return {
            'total_cves': total_cves,
            'automation_level_stats': {
                'full_count': automation_level_counts['full'],
                'partial_count': automation_level_counts['partial'],
                'none_count': automation_level_counts['none'],
                'full_rate': round(automation_level_counts['full'] / total_cves * 100, 1) if total_cves > 0 else 0,
                'partial_rate': round(automation_level_counts['partial'] / total_cves * 100, 1) if total_cves > 0 else 0,
                'none_rate': round(automation_level_counts['none'] / total_cves * 100, 1) if total_cves > 0 else 0
            },
            'cpe_determination_stats': {
                'confirmed_mapping_count': entry_cpe_det_counts['confirmedMapping'],
                'top10_suggestion_count': entry_cpe_det_counts['top10Suggestion'],
                'nothing_count': entry_cpe_det_counts['nothing'],
                'confirmed_mapping_rate': round(entry_cpe_det_counts['confirmedMapping'] / total_entries * 100, 1) if total_entries > 0 else 0,
                'top10_suggestion_rate': round(entry_cpe_det_counts['top10Suggestion'] / total_entries * 100, 1) if total_entries > 0 else 0,
                'nothing_rate': round(entry_cpe_det_counts['nothing'] / total_entries * 100, 1) if total_entries > 0 else 0
            },
            'cpe_as_stats': {
                'complete_count': version_cpe_as_counts['complete'],
                'partial_count': version_cpe_as_counts['partial'],
                'none_count': version_cpe_as_counts['none'],
                'complete_rate': round(version_cpe_as_counts['complete'] / total_versions * 100, 1) if total_versions > 0 else 0,
                'partial_rate': round(version_cpe_as_counts['partial'] / total_versions * 100, 1) if total_versions > 0 else 0,
                'none_rate': round(version_cpe_as_counts['none'] / total_versions * 100, 1) if total_versions > 0 else 0
            },
            'version_stats': {
                'complete_count': version_cpe_as_counts['complete'],
                'partial_count': version_cpe_as_counts['partial'],
                'none_count': version_cpe_as_counts['none'],
                'complete_rate': round(version_cpe_as_counts['complete'] / total_versions * 100, 1) if total_versions > 0 else 0,
                'partial_rate': round(version_cpe_as_counts['partial'] / total_versions * 100, 1) if total_versions > 0 else 0,
                'none_rate': round(version_cpe_as_counts['none'] / total_versions * 100, 1) if total_versions > 0 else 0
            },
            'top_concerns': [{'concern': c, 'count': cnt} for c, cnt in top_concerns],
            'top_patterns': [{'pattern': p, 'count': cnt} for p, cnt in top_patterns]
        }


def scan_nvd_ish_cache(cache_path: Path, cve_filter: Optional[Set[str]] = None) -> List[Path]:
    """
    Scan NVD-ish cache directory for JSON files (searches recursively).
    
    Args:
        cache_path: Path to cache directory
        cve_filter: Optional set of CVE IDs to filter for
        
    Returns:
        List of JSON file paths
    """
    json_files = []
    
    # Search recursively for CVE JSON files
    for json_file in cache_path.rglob("CVE-*.json"):
        if cve_filter:
            cve_id = json_file.stem
            if cve_id not in cve_filter:
                continue
        
        json_files.append(json_file)
    
    return sorted(json_files)


def extract_metrics_from_record(json_file: Path) -> tuple[str, Dict]:
    """
    Extract automation metrics from NVD-ish record.
    
    Args:
        json_file: Path to NVD-ish JSON file
        
    Returns:
        Tuple of (cve_id, nvd_ish_record) or (None, None) if invalid
    """
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            nvd_ish_record = json.load(f)
        
        # Extract CVE ID
        cve_id = json_file.stem
        
        return cve_id, nvd_ish_record
        
    except Exception as e:
        if logger:
            logger.warning(f"Failed to process {json_file.name}: {e}", group="DATA_PROC")
        return None, None


def generate_html_report(report_data: Dict, output_path: Path, dashboard_template_path: Path, tool_version: str = "unknown") -> None:
    """
    Generate HTML dashboard report with injected data.
    
    Args:
        report_data: JSON report data to inject (source summary + cve_data)
        output_path: Path where HTML file should be written
        dashboard_template_path: Path to CPE-AS_Automation_Source_Report_Example.html template
        tool_version: Tool version string to display in header
    """
    # Read the dashboard template
    with open(dashboard_template_path, 'r', encoding='utf-8') as f:
        template_html = f.read()
    
    # Escape and prepare the JSON data for injection
    json_data = json.dumps(report_data, ensure_ascii=False)
    
    # Replace the hardcoded example data with actual data
    # The template has: let dashboardData = {...};
    # We need to find the start and end of this declaration
    
    start_marker = "let dashboardData = {"
    
    if start_marker in template_html:
        # Find the start of the data declaration
        start_pos = template_html.find(start_marker)
        
        # Find the end - look for the closing }; that ends the object
        # Start searching after the opening brace
        search_start = start_pos + len(start_marker)
        brace_count = 1  # We've already seen the opening brace
        end_pos = search_start
        
        while brace_count > 0 and end_pos < len(template_html):
            if template_html[end_pos] == '{':
                brace_count += 1
            elif template_html[end_pos] == '}':
                brace_count -= 1
            end_pos += 1
        
        # Now find the semicolon after the closing brace
        while end_pos < len(template_html) and template_html[end_pos] != ';':
            end_pos += 1
        end_pos += 1  # Include the semicolon
        
        # Replace the entire declaration
        data_declaration = f"let dashboardData = {json_data};"
        html_output = template_html[:start_pos] + data_declaration + template_html[end_pos:]
    else:
        raise RuntimeError("Could not find 'let dashboardData' in source report template")
    
    # Fix CSS path to use local css/ directory (CSS file is copied to reports/css/)
    html_output = html_output.replace(
        'href="../src/analysis_tool/static/css/cpeas_automation_dashboard.css"',
        'href="css/cpeas_automation_dashboard.css"'
    )
    html_output = html_output.replace(
        "href='../src/analysis_tool/static/css/cpeas_automation_dashboard.css'",
        "href='css/cpeas_automation_dashboard.css'"
    )
    
    # Replace version placeholder with actual version
    html_output = html_output.replace('{{TOOL_VERSION}}', tool_version)
    
    # Write the generated HTML
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_output)


def generate_index_html(index_data: Dict, output_path: Path, index_template_path: Path, reports_dir: Path, tool_version: str = "unknown") -> None:
    """
    Generate HTML index page with links to source reports.
    
    Args:
        index_data: Index JSON data
        output_path: Path where index HTML should be written
        index_template_path: Path to CPE-AS_Automation_Index_Example.html template
        reports_dir: Path to reports directory for calculating relative links
        tool_version: Tool version string to display in header
    """
    # Read the index template
    with open(index_template_path, 'r', encoding='utf-8') as f:
        template_html = f.read()
    
    # Modify index data to include HTML report links instead of JSON file references
    modified_index = index_data.copy()
    modified_index['sources'] = []
    
    for source in index_data.get('sources', []):
        source_copy = source.copy()
        # Replace JSON filename with HTML filename
        json_filename = source.get('report_file', '')
        if json_filename:
            html_filename = json_filename.replace('.json', '.html')
            source_copy['report_file'] = html_filename
        modified_index['sources'].append(source_copy)
    
    # Escape and prepare the JSON data for injection
    json_data = json.dumps(modified_index, ensure_ascii=False)
    
    # Replace the hardcoded example data with actual data
    # The template has: let dashboardData = {...};
    # We need to find the start and end of this declaration
    
    start_marker = "let dashboardData = {"
    
    if start_marker in template_html:
        # Find the start of the data declaration
        start_pos = template_html.find(start_marker)
        
        # Find the end - look for the closing }; that ends the object
        # Start searching after the opening brace
        search_start = start_pos + len(start_marker)
        brace_count = 1  # We've already seen the opening brace
        end_pos = search_start
        
        while brace_count > 0 and end_pos < len(template_html):
            if template_html[end_pos] == '{':
                brace_count += 1
            elif template_html[end_pos] == '}':
                brace_count -= 1
            end_pos += 1
        
        # Now find the semicolon after the closing brace
        while end_pos < len(template_html) and template_html[end_pos] != ';':
            end_pos += 1
        end_pos += 1  # Include the semicolon
        
        # Replace the entire declaration
        data_declaration = f"let dashboardData = {json_data};"
        html_output = template_html[:start_pos] + data_declaration + template_html[end_pos:]
    else:
        raise RuntimeError("Could not find 'let dashboardData' in index template")
    
    # Fix CSS path to use local css/ directory (CSS file is copied to reports/css/)
    html_output = html_output.replace(
        'href="../src/analysis_tool/static/css/cpeas_automation_dashboard.css"',
        'href="css/cpeas_automation_dashboard.css"'
    )
    html_output = html_output.replace(
        "href='../src/analysis_tool/static/css/cpeas_automation_dashboard.css'",
        "href='css/cpeas_automation_dashboard.css'"
    )
    
    # Replace version placeholder with actual version
    html_output = html_output.replace('{{TOOL_VERSION}}', tool_version)
    
    # Write the generated HTML
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_output)


def generate_report(
    cache_name: str = "nvd-ish_2.0_cves",
    run_directory: Optional[Path] = None
) -> str:
    """
    Generate CPE automation report from NVD-ish cache records.
    
    Args:
        cache_name: Name of cache directory within project cache/ folder
        run_directory: Optional run directory path. If None, creates new run directory.
        
    Returns:
        Path to generated index file
        
    Raises:
        FileNotFoundError: If cache directory doesn't exist
        ValueError: If cache_name contains path traversal characters
    """
    # Security: Prevent path traversal attacks
    if '..' in cache_name or '/' in cache_name or '\\' in cache_name:
        raise ValueError(f"Invalid cache name: {cache_name}")
    
    # Construct cache path
    project_root = get_analysis_tools_root()
    cache_path = project_root / "cache" / cache_name
    
    if not cache_path.exists():
        raise FileNotFoundError(f"Cache directory not found: {cache_path}")
    
    # Get progress interval from config
    config = load_config()
    progress_interval = config.get('cpeas_automation_report', {}).get('progress_interval', 2000)
    
    if logger:
        logger.info(f"Starting CPE automation report generation", group="DATA_PROC")
        logger.info(f"  Cache: {cache_path}", group="DATA_PROC")
    
    # Get source manager for UUID resolution
    source_manager = None
    try:
        from ..storage.nvd_source_manager import get_or_refresh_source_manager
        api_key = config.get('defaults', {}).get('default_api_key', '')
        source_manager = get_or_refresh_source_manager(api_key, log_group="DATA_PROC")
    except Exception as e:
        if logger:
            logger.warning(f"Source manager unavailable: {e}", group="DATA_PROC")
    
    # Scan cache
    builder = CPEASAutomationReportBuilder(source_manager=source_manager)
    json_files = scan_nvd_ish_cache(cache_path, cve_filter=None)
    
    if logger:
        logger.info(f"Found {len(json_files)} NVD-ish records to process", group="DATA_PROC")
    
    # Process each CVE
    processed_count = 0
    
    for idx, json_file in enumerate(json_files, 1):
        cve_id, nvd_ish_record = extract_metrics_from_record(json_file)
        
        if cve_id and nvd_ish_record:
            builder.add_cve(cve_id, nvd_ish_record)
            processed_count += 1
        
        if idx % progress_interval == 0 and logger:
            logger.info(f"Processed {idx}/{len(json_files)} records...", group="DATA_PROC")
    
    # Generate per-source reports
    per_source_reports = builder.finalize()
    
    # Determine output directory
    if run_directory is None:
        from ..storage.run_organization import create_run_directory
        run_directory, run_id = create_run_directory(
            execution_type="cpeas_automation_report",
            subdirs=["logs", "reports"]
        )
        logger.info(f"Created run directory: {run_id}", group="DATA_PROC")
    
    # Output directories
    output_dir = run_directory / "logs"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    reports_dir = run_directory / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    css_dir = reports_dir / "css"
    css_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy CSS file
    css_source = project_root / "src" / "analysis_tool" / "static" / "css" / "cpeas_automation_dashboard.css"
    if css_source.exists():
        import shutil
        css_dest = css_dir / "cpeas_automation_dashboard.css"
        shutil.copy2(css_source, css_dest)
    
    # Locate dashboard templates
    dashboard_dir = project_root / "dashboards"
    source_template_path = dashboard_dir / "CPE-AS_Automation_Source_Report_Example.html"
    index_template_path = dashboard_dir / "CPE-AS_Automation_Index_Example.html"
    
    if not source_template_path.exists():
        logger.warning(f"Source report template not found: {source_template_path}", group="DATA_PROC")
        logger.warning("HTML generation will be skipped", group="DATA_PROC")
        source_template_path = None
    
    if not index_template_path.exists():
        logger.warning(f"Index template not found: {index_template_path}", group="DATA_PROC")
        logger.warning("Index HTML generation will be skipped", group="DATA_PROC")
        index_template_path = None
    
    # Write per-source reports (JSON + HTML)
    written_files = []
    source_list_for_index = []
    
    for source_id, report_data in per_source_reports.items():
        source_name = report_data['metadata']['source_name']
        safe_source_name = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in source_name)
        
        # Generate filenames
        json_filename = f"cpeAsAutomationReport_{safe_source_name}_{source_id[:8]}.json"
        html_filename = f"cpeAsAutomationReport_{safe_source_name}_{source_id[:8]}.html"
        
        # Write JSON to logs directory
        json_path = output_dir / json_filename
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        # Generate HTML report if template available
        if source_template_path:
            html_path = reports_dir / html_filename
            try:
                # Build report data structure for template (must match template's expected structure)
                template_data = {
                    'metadata': report_data['metadata'],
                    'summary': report_data['summary'],
                    'cve_data': report_data['cve_data']
                }
                generate_html_report(template_data, html_path, source_template_path, __version__)
                written_files.append(html_filename)
            except Exception as e:
                logger.error(f"Failed to generate HTML for {source_name}: {e}", group="DATA_PROC")
                written_files.append(json_filename)
        else:
            written_files.append(json_filename)
        
        # Build source entry for index with stats from summary
        summary = report_data['summary']
        automation_stats = summary.get('automation_level_stats', {})
        cpe_det_stats = summary.get('cpe_determination_stats', {})
        version_stats = summary.get('version_stats', {})
        
        source_list_for_index.append({
            'source_id': source_id,
            'source_name': source_name,
            'total_cves': summary.get('total_cves', 0),
            'automation_level_stats': {
                'full_count': automation_stats.get('full_count', 0),
                'partial_count': automation_stats.get('partial_count', 0),
                'none_count': automation_stats.get('none_count', 0)
            },
            'cpe_determination_stats': {
                'confirmed_mapping_count': cpe_det_stats.get('confirmed_mapping_count', 0),
                'top10_suggestion_count': cpe_det_stats.get('top10_suggestion_count', 0),
                'nothing_count': cpe_det_stats.get('nothing_count', 0)
            },
            'version_stats': {
                'complete_count': version_stats.get('complete_count', 0),
                'partial_count': version_stats.get('partial_count', 0),
                'none_count': version_stats.get('none_count', 0)
            },
            'report_file': html_filename if source_template_path else json_filename
        })
    
    # Generate index JSON
    index_data = {
        'metadata': {
            **builder.global_metadata,
            'tool_version': __version__,
            'cache_source': cache_name,
            'total_sources': len(per_source_reports),
            'total_cves_processed': sum(s.get('total_cves', 0) for s in source_list_for_index)
        },
        'sources': source_list_for_index
    }
    
    index_json_path = output_dir / "cpeAsAutomationReport_index.json"
    with open(index_json_path, 'w', encoding='utf-8') as f:
        json.dump(index_data, f, indent=2, ensure_ascii=False)
    
    # Generate index HTML if template available
    if index_template_path:
        index_html_path = reports_dir / "CPE-AS_Automation_Index.html"
        try:
            generate_index_html(index_data, index_html_path, index_template_path, reports_dir, __version__)
            if logger:
                logger.info(f"Generated index HTML: {index_html_path}", group="DATA_PROC")
        except Exception as e:
            logger.error(f"Failed to generate index HTML: {e}", group="DATA_PROC")
    
    if logger:
        logger.info(f"Generated {len(written_files)} source reports", group="DATA_PROC")
        logger.info(f"Index JSON: {index_json_path}", group="DATA_PROC")
    
    return str(index_json_path)


def main():
    """Command-line entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate CPE Automation Success reports from NVD-ish cache"
    )
    parser.add_argument(
        '--cache-name',
        default='nvd-ish_2.0_cves',
        help='Cache directory name (default: nvd-ish_2.0_cves)'
    )
    parser.add_argument(
        '--run-id',
        help='Existing run ID to use (format: YYYY-MM-DD_HH-MM-SS_description)'
    )
    
    args = parser.parse_args()
    
    # Resolve run directory if provided
    run_directory = None
    if args.run_id:
        project_root = get_analysis_tools_root()
        run_directory = project_root / "runs" / args.run_id
        if not run_directory.exists():
            print(f"Error: Run directory not found: {run_directory}", file=sys.stderr)
            sys.exit(1)
    
    try:
        index_path = generate_report(
            cache_name=args.cache_name,
            run_directory=run_directory
        )
        print(f"Report generated successfully: {index_path}")
        return 0
    except Exception as e:
        print(f"Error generating report: {e}", file=sys.stderr)
        if logger:
            logger.error(f"Report generation failed: {e}", group="DATA_PROC")
        return 1


if __name__ == '__main__':
    sys.exit(main())

