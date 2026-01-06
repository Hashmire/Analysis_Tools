#!/usr/bin/env python3
"""
Source Data Concern Report Generator from NVD-ish Cache

Scans enriched NVD-ish records and generates per-source SDC report files
independent of live CVE processing. Splits data by source to handle large datasets
that would otherwise fail to parse in the dashboard.

Architecture:
    - Reads from: cache/nvd-ish_2.0_cves/
    - Extracts: enrichedCVEv5Affected.cveListV5AffectedEntries[*].sourceDataConcerns
    - Generates: 
        * sourceDataConcernReport_index.json (source listing and global metadata)
        * sourceDataConcernReport_[sourcename]_[id].json (per-source data)

Output Structure:
    runs/[run_id]/logs/
        ├── sourceDataConcernReport_index.json
        ├── sourceDataConcernReport_Adobe_12345678.json
        ├── sourceDataConcernReport_Microsoft_abcd1234.json
        └── ... (one file per source)

Usage:
    # Standalone - creates new run directory
    python -m src.analysis_tool.reporting.generate_sdc_report

    # Use existing run directory (e.g., from generate_dataset)
    python -m src.analysis_tool.reporting.generate_sdc_report \\
        --run-id 2025-12-01_10-30-00_dataset_last_7_days_nvd-ish

    # Programmatic
    from src.analysis_tool.reporting.generate_sdc_report import generate_report
    generate_report(cache_name="nvd-ish_2.0_cves", run_directory=None)
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
import html

# Minimal imports - only what's needed for cache scanning and source resolution
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
            logger.warning(f"Config file not found at {config_path}, using hardcoded defaults", group="SDC_REPORT")
            return {}
    except Exception as e:
        logger.warning(f"Failed to load config: {e}, using hardcoded defaults", group="SDC_REPORT")
        return {}


class SDCReportBuilder:
    """
    Builds per-source sourceDataConcernReport files from NVD-ish cache records.
    
    Generates separate report files for each source to handle large datasets.
    
    Schema for each source report matches SDC_Source_Report_Template.html format:
    {
      "metadata": {
        "source_id": "UUID",
        "source_name": "Human readable name",
        "run_started_at": "ISO timestamp",
        "total_cves_processed": int,
        "total_platform_entries": int,
        "entries_with_concerns": int,
        "concern_type_counts": [{"concern_type": "key", "count": int}]
      },
      "cve_data": [...]
    }
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
            'report_scope': 'Platform Entry Notifications - Source Data Concerns (Per-Source Reports)',
            'status': 'in_progress'
        }
        # Group data by source_id: {source_id: {'metadata': {...}, 'cve_data': [...], 'concern_counter': {...}}}
        self.sources = defaultdict(lambda: {
            'metadata': {
                'total_cves_processed': 0,
                'total_platform_entries': 0,
                'entries_with_concerns': 0,
            },
            'cve_data': [],
            'concern_counter': defaultdict(int),
            'cve_ids': set()  # Track unique CVEs per source
        })
    
    def add_cve(self, cve_id: str, entries: List[Dict]) -> None:
        """
        Process one CVE's affected entries and group by source.
        
        Args:
            cve_id: CVE identifier
            entries: List of cveListV5AffectedEntries from NVD-ish record
        """
        # Group entries by source_id for this CVE
        entries_by_source = defaultdict(lambda: {'entries': [], 'clean_count': 0})
        
        for idx, entry in enumerate(entries):
            origin = entry.get('originAffectedEntry', {})
            sdc = entry.get('sourceDataConcerns', {})
            concerns = sdc.get('concerns', {})
            
            source_id = origin.get('sourceId', 'Unknown')
            
            if concerns:  # Entry has concerns
                entries_by_source[source_id]['entries'].append((idx, entry, concerns))
            else:  # Clean entry
                entries_by_source[source_id]['clean_count'] += 1
        
        # Process each source's entries for this CVE
        for source_id, source_data in entries_by_source.items():
            source_info = self.sources[source_id]
            
            # Track this CVE for this source (all CVEs with any entries)
            if cve_id not in source_info['cve_ids']:
                source_info['cve_ids'].add(cve_id)
                source_info['metadata']['total_cves_processed'] += 1
            
            platform_entries = []
            cve_concern_counter = defaultdict(int)
            
            # Process entries with concerns
            for idx, entry, concerns in source_data['entries']:
                origin = entry.get('originAffectedEntry', {})
                vendor = origin.get('vendor', 'Unknown')
                product = origin.get('product', 'Unknown')
                
                concern_types = list(concerns.keys())
                total_concerns = sum(len(v) for v in concerns.values() if isinstance(v, list))
                
                # Resolve source name
                source_name = self._resolve_source_name(source_id)
                
                # Build concern breakdown
                concern_breakdown = {
                    ct: len(concerns[ct]) 
                    for ct in concern_types 
                    if isinstance(concerns[ct], list)
                }
                
                # Build concerns detail
                concerns_detail = [
                    {
                        'concern_type': ct,
                        'concerns': concerns[ct]
                    }
                    for ct in concern_types
                    if isinstance(concerns[ct], list) and concerns[ct]
                ]
                
                platform_entry = {
                    'platform_entry_id': f"{cve_id}_entry_{idx}",
                    'table_index': idx,
                    'source_id': source_id,
                    'source_name': source_name,
                    'vendor': vendor,
                    'product': product,
                    'total_concerns': total_concerns,
                    'concern_types': concern_types,
                    'concern_breakdown': concern_breakdown,
                    'concerns_detail': concerns_detail
                }
                platform_entries.append(platform_entry)
                
                # Update source-level counters
                source_info['metadata']['total_platform_entries'] += 1
                source_info['metadata']['entries_with_concerns'] += 1
                
                # Count individual concerns by type (not just entries with concerns)
                for ct in concern_types:
                    if isinstance(concerns[ct], list):
                        concern_count = len(concerns[ct])
                        source_info['concern_counter'][ct] += concern_count
                        cve_concern_counter[ct] += concern_count
            
            # Add clean entries count
            clean_count = source_data['clean_count']
            source_info['metadata']['total_platform_entries'] += clean_count
            
            # Build CVE entry for this source (include all CVEs - dashboard needs them for counting)
            if platform_entries or clean_count > 0:
                cve_metadata = {
                    'total_platform_entries': len(platform_entries) + clean_count,
                    'entries_with_concerns': len(platform_entries),
                    'concern_type_counts': [
                        {'concern_type': ct, 'count': count}
                        for ct, count in sorted(cve_concern_counter.items())
                        if count > 0  # Only include concern types with actual occurrences
                    ],
                    'processing_timestamp': datetime.now(timezone.utc).isoformat()
                }
                
                clean_platform_entries = [{
                    'sourceID': source_id,
                    'source_name': self._resolve_source_name(source_id),
                    'cleanPlatformCount': clean_count
                }] if clean_count > 0 else []
                
                source_info['cve_data'].append({
                    'cve_id': cve_id,
                    'platform_entries': platform_entries,
                    'clean_platform_entries': clean_platform_entries,
                    'cve_metadata': cve_metadata
                })
        
        # Update global CVE counter
        self.global_metadata['total_cves_processed'] += 1
    
    def _resolve_source_name(self, source_id: str) -> str:
        """
        Resolve source UUID to human-readable name.
        
        Args:
            source_id: Source UUID or identifier
            
        Returns:
            Human-readable source name or the UUID itself if not in source cache
            
        Note:
            Only falls back to UUID when source manager is unavailable.
            If source manager is initialized but can't resolve the UUID,
            returns the UUID (which will be caught by validation checks later).
        """
        if self.source_manager and self.source_manager.is_initialized():
            # Source manager available - use it (may return UUID if not found)
            name = self.source_manager.get_source_name(source_id)
            return name if name else source_id
        
        # Source manager not available - return UUID as-is
        # This will be detected by validation checks in the statistics section
        return source_id
    
    def finalize(self) -> Dict[str, Dict]:
        """
        Build final per-source report structures.
        
        Returns:
            Dictionary mapping source_id to report data: {source_id: {metadata: {}, cve_data: []}}
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        per_source_reports = {}
        
        for source_id, source_info in self.sources.items():
            # Finalize source-level concern counts
            concern_type_counts = [
                {'concern_type': ct, 'count': count}
                for ct, count in sorted(source_info['concern_counter'].items())
                if count > 0  # Only include concern types with actual occurrences
            ]
            
            # Build source metadata
            metadata = {
                'source_id': source_id,
                'source_name': self._resolve_source_name(source_id),
                'run_started_at': self.global_metadata['run_started_at'],
                'last_updated': timestamp,
                'total_cves_processed': source_info['metadata']['total_cves_processed'],
                'total_platform_entries': source_info['metadata']['total_platform_entries'],
                'entries_with_concerns': source_info['metadata']['entries_with_concerns'],
                'concern_type_counts': concern_type_counts,
                'report_scope': 'Platform Entry Notifications - Source Data Concerns Only',
                'status': 'completed'
            }
            
            per_source_reports[source_id] = {
                'metadata': metadata,
                'cve_data': source_info['cve_data']
            }
        
        # Update global metadata
        self.global_metadata['total_sources'] = len(per_source_reports)
        self.global_metadata['last_updated'] = timestamp
        self.global_metadata['status'] = 'completed'
        
        return per_source_reports


def scan_nvd_ish_cache(cache_dir: Path, cve_filter: Optional[Set[str]] = None) -> List[Path]:
    """
    Scan NVD-ish cache directory for CVE JSON files.
    
    Args:
        cache_dir: Path to NVD-ish cache (e.g., cache/nvd-ish_2.0_cves)
        cve_filter: Optional set of CVE IDs to include (for selective processing)
        
    Returns:
        Sorted list of Path objects for JSON files
    """
    json_files = []
    
    for json_file in cache_dir.rglob("CVE-*.json"):
        if cve_filter:
            # Extract CVE ID from filename
            cve_id = json_file.stem  # CVE-YYYY-NNNNN
            if cve_id not in cve_filter:
                continue
        
        json_files.append(json_file)
    
    return sorted(json_files)


def extract_sdc_from_record(json_file: Path) -> Tuple[Optional[str], List[Dict]]:
    """
    Load NVD-ish record and extract source data concerns.
    
    Args:
        json_file: Path to NVD-ish JSON file
        
    Returns:
        Tuple of (cve_id, affected_entries) or (None, []) on error
    """
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            record = json.load(f)
        
        cve_id = record.get('id')
        if not cve_id:
            if logger:
                logger.warning(f"No CVE ID found in {json_file.name}", group="SDC_REPORT")
            return None, []
        
        enriched = record.get('enrichedCVEv5Affected', {})
        if not enriched:
            if logger:
                logger.debug(f"No enrichedCVEv5Affected in {cve_id}", group="SDC_REPORT")
            return cve_id, []
        
        entries = enriched.get('cveListV5AffectedEntries', [])
        
        return cve_id, entries
        
    except json.JSONDecodeError as e:
        if logger:
            logger.warning(f"Invalid JSON in {json_file.name}: {e}", group="SDC_REPORT")
        return None, []
    except Exception as e:
        if logger:
            logger.warning(f"Failed to process {json_file.name}: {e}", group="SDC_REPORT")
        return None, []


def generate_html_report(report_data: Dict, output_path: Path, dashboard_template_path: Path, tool_version: str = "unknown") -> None:
    """
    Generate HTML dashboard report with injected data.
    
    Args:
        report_data: JSON report data to inject
        output_path: Path where HTML file should be written
        dashboard_template_path: Path to SDC_Source_Report_Template.html template
        tool_version: Tool version string to display in header
    """
    # Read the dashboard template
    with open(dashboard_template_path, 'r', encoding='utf-8') as f:
        template_html = f.read()
    
    # Escape and prepare the JSON data for injection
    json_data = json.dumps(report_data, ensure_ascii=False)
    
    # Create the injection script
    injection_script = f"""<script>
const injectedDashboardData = {json_data};
</script>"""
    
    # Insert the injection script before the main script section
    # Look for the data injection point comment
    injection_marker = '<!-- Data Injection Point -->'
    
    if injection_marker in template_html:
        html_output = template_html.replace(injection_marker, injection_script)
    else:
        # Fallback: insert before first <script> tag
        script_pos = template_html.find('<script>')
        if script_pos != -1:
            html_output = template_html[:script_pos] + injection_script + '\n    ' + template_html[script_pos:]
        else:
            raise RuntimeError("Could not find injection point in dashboard template")
    
    # Fix CSS path to be relative to reports directory (not parent directory)
    # The dashboard template uses various CSS paths, normalize them all
    html_output = html_output.replace('href="../css/sdc_dashboard.css"', 'href="css/sdc_dashboard.css"')
    html_output = html_output.replace("href='../css/sdc_dashboard.css'", "href='css/sdc_dashboard.css'")
    
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
        index_template_path: Path to SDC_Source_Index_Template.html template
        reports_dir: Path to reports directory for calculating relative links
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
            data_script = f"\n        // Injected data from SDC report\n        let dashboardData = {json_data};\n\n        "
            html_output = template_html[:insertion_point] + data_script + template_html[insertion_point:]
        else:
            raise RuntimeError("Could not find injection point in index template")
    
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
    Generate sourceDataConcernReport.json from NVD-ish cache records.
    
    Args:
        cache_name: Name of cache directory within project cache/ folder (e.g., 'nvd-ish_2.0_cves')
        run_directory: Optional run directory path. If None, creates new run directory.
        
    Returns:
        Path to generated index file
        
    Raises:
        FileNotFoundError: If cache directory doesn't exist
        ValueError: If cache_name contains path traversal characters
    """
    # Security: Prevent path traversal attacks
    if '..' in cache_name or '/' in cache_name or '\\' in cache_name:
        raise ValueError(f"Invalid cache name: {cache_name}. Must be a directory name only, no path separators.")
    
    # Construct cache path within project cache directory
    project_root = get_analysis_tools_root()
    cache_path = project_root / "cache" / cache_name
    
    # Validate cache directory exists
    if not cache_path.exists():
        raise FileNotFoundError(f"Cache directory not found: {cache_path}")
    
    # Get progress interval from config
    config = load_config()
    progress_interval = config.get('sdc_report', {}).get('progress_interval', 2000)
    
    if logger:
        logger.info(f"Starting SDC report generation from NVD-ish cache", group="SDC_REPORT")
        logger.info(f"  Cache name: {cache_name}", group="SDC_REPORT")
        logger.info(f"  Cache path: {cache_path}", group="SDC_REPORT")
        logger.info(f"  Progress interval: {progress_interval}", group="SDC_REPORT")
    
    # Get source manager for UUID resolution (uses cache or refreshes as needed)
    source_manager = None
    try:
        from ..storage.nvd_source_manager import get_or_refresh_source_manager
        
        # Get API key from config for potential cache refresh
        api_key = config.get('defaults', {}).get('default_api_key', '')
        
        # Get source manager using intelligent cache management
        source_manager = get_or_refresh_source_manager(api_key, log_group="SDC_REPORT")
                
    except ImportError as e:
        # Missing dependencies - this is expected in minimal environments
        if logger:
            logger.error(f"Source manager dependencies not available: {e}", group="SDC_REPORT")
        raise ImportError(
            f"Required dependencies for source manager not available: {e}. "
        )
    except Exception as e:
        # Unexpected error - log with full context for debugging
        if logger:
            logger.error(f"Source manager initialization failed: {e}", group="SDC_REPORT")
            logger.debug(f"Traceback: {__import__('traceback').format_exc()}", group="SDC_REPORT")
        raise RuntimeError(
            f"Failed to initialize source manager: {e}. "
        )
    
    # Scan cache
    builder = SDCReportBuilder(source_manager=source_manager)
    json_files = scan_nvd_ish_cache(cache_path, cve_filter=None)
    
    if logger:
        logger.info(f"Found {len(json_files)} NVD-ish records to process", group="SDC_REPORT")
    
    # Process each CVE
    processed_count = 0
    skipped_count = 0
    
    for idx, json_file in enumerate(json_files, 1):
        cve_id, entries = extract_sdc_from_record(json_file)
        
        if cve_id and entries:
            builder.add_cve(cve_id, entries)
            processed_count += 1
        else:
            skipped_count += 1
        
        # Progress logging
        if idx % progress_interval == 0 and logger:
            logger.info(f"Processed {idx}/{len(json_files)} records...", group="SDC_REPORT")
    
    # Generate per-source reports
    per_source_reports = builder.finalize()
    
    # Determine output directory
    if run_directory is None:
        # Create new run directory if not provided
        from ..storage.run_organization import create_run_directory
        run_directory, run_id = create_run_directory(
            execution_type="sdc_report",
            subdirs=["logs", "reports"]
        )
        logger.info(f"Created run directory: {run_id}", group="SDC_REPORT")
    
    # Output goes to logs subdirectory (JSON files)
    output_dir = run_directory / "logs"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Reports go to reports subdirectory (HTML files)
    reports_dir = run_directory / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Create CSS directory and copy CSS file for HTML reports
    css_dir = reports_dir / "css"
    css_dir.mkdir(parents=True, exist_ok=True)
    
    # Locate dashboard template and CSS
    project_root = get_analysis_tools_root()
    dashboard_template = project_root / "src" / "analysis_tool" / "static" / "templates" / "SDC_Source_Report_Template.html"
    index_template = project_root / "src" / "analysis_tool" / "static" / "templates" / "SDC_Source_Index_Template.html"
    css_source = project_root / "src" / "analysis_tool" / "static" / "css" / "sdc_dashboard.css"
    
    html_generation_enabled = dashboard_template.exists() and index_template.exists()
    
    # Copy CSS file to reports directory if it exists
    if css_source.exists() and html_generation_enabled:
        import shutil
        css_dest = css_dir / "sdc_dashboard.css"
        try:
            shutil.copy2(css_source, css_dest)
            if logger:
                logger.debug(f"Copied CSS file to {css_dest}", group="SDC_REPORT")
        except Exception as e:
            if logger:
                logger.warning(f"Failed to copy CSS file: {e}", group="SDC_REPORT")
    
    if not html_generation_enabled and logger:
        logger.warning(f"Dashboard templates not found - HTML generation disabled", group="SDC_REPORT")
        logger.warning(f"  Dashboard: {dashboard_template}", group="SDC_REPORT")
        logger.warning(f"  Index: {index_template}", group="SDC_REPORT")
    
    if logger:
        logger.info(f"Writing {len(per_source_reports)} source-specific reports...", group="SDC_REPORT")
    
    # Write per-source report files (JSON and HTML)
    written_files = []
    written_source_ids = []  # Track source_ids that actually got files written
    skipped_sources = []
    html_files = []
    
    for source_id, report_data in per_source_reports.items():
        source_name = report_data['metadata']['source_name']
        total_cves = report_data['metadata']['total_cves_processed']
        
        # Skip sources with no CVEs (nothing to report)
        if total_cves == 0:
            skipped_sources.append((source_name, source_id))
            if logger:
                logger.debug(f"Skipping report for {source_name} (no CVEs processed)", group="SDC_REPORT")
            continue
        
        # Generate report for sources with CVEs (even if all clean)
        safe_source_name = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in source_name)
        
        # Generate filename: sourceDataConcernReport_[sourcename]_[first8chars].json
        source_id_short = source_id[:8] if len(source_id) >= 8 else source_id
        base_filename = f"sourceDataConcernReport_{safe_source_name}_{source_id_short}"
        
        # Write JSON file
        source_file = output_dir / f"{base_filename}.json"
        temp_file = source_file.with_suffix('.tmp')
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            temp_file.replace(source_file)
            written_files.append(source_file)
            written_source_ids.append(source_id)  # Track this source_id as written
            
        except Exception as e:
            if temp_file.exists():
                temp_file.unlink()
            raise RuntimeError(f"Failed to write JSON report for {source_name}: {e}")
        
        # Generate HTML dashboard if templates available
        if html_generation_enabled:
            try:
                html_file = reports_dir / f"{base_filename}.html"
                generate_html_report(report_data, html_file, dashboard_template, __version__)
                html_files.append(html_file)
            except Exception as e:
                if logger:
                    logger.warning(f"Failed to generate HTML for {source_name}: {e}", group="SDC_REPORT")
    
    if logger and skipped_sources:
        logger.info(f"Skipped {len(skipped_sources)} sources with no CVEs", group="SDC_REPORT")
    
    # Write index file listing all sources with comprehensive statistics
    # Only include sources that actually had files written (tracked in written_source_ids)
    index_data = {
        'metadata': builder.global_metadata,
        'sources': [
            {
                'source_id': source_id,
                'source_name': per_source_reports[source_id]['metadata']['source_name'],
                'report_file': f"sourceDataConcernReport_{''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in per_source_reports[source_id]['metadata']['source_name'])}_{source_id[:8] if len(source_id) >= 8 else source_id}.json",
                'total_cves_processed': per_source_reports[source_id]['metadata']['total_cves_processed'],
                'total_platform_entries': per_source_reports[source_id]['metadata']['total_platform_entries'],
                'entries_with_concerns': per_source_reports[source_id]['metadata']['entries_with_concerns'],
                'entries_without_concerns': per_source_reports[source_id]['metadata']['total_platform_entries'] - per_source_reports[source_id]['metadata']['entries_with_concerns'],
                'concern_type_counts': per_source_reports[source_id]['metadata']['concern_type_counts'],
                'last_updated': per_source_reports[source_id]['metadata']['last_updated'],
                'status': per_source_reports[source_id]['metadata']['status'],
                'source_identifiers': source_manager.get_source_info(source_id).get('sourceIdentifiers', []) if source_manager.get_source_info(source_id) else []
            }
            for source_id in written_source_ids  # Use the actual written source_ids
        ]
    }
    
    # Write JSON index file
    index_file = output_dir / "sourceDataConcernReport_index.json"
    temp_file = index_file.with_suffix('.tmp')
    try:
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(index_data, f, indent=2, ensure_ascii=False)
        
        temp_file.replace(index_file)
        written_files.insert(0, index_file)
        
    except Exception as e:
        if temp_file.exists():
            temp_file.unlink()
        raise RuntimeError(f"Failed to write index file: {e}")
    
    # Generate HTML index page if templates available
    if html_generation_enabled:
        try:
            index_html = reports_dir / "SDC_Report_Index.html"
            generate_index_html(index_data, index_html, index_template, reports_dir, __version__)
            html_files.insert(0, index_html)
            if logger:
                logger.info(f"Generated HTML index page: {index_html.name}", group="SDC_REPORT")
        except Exception as e:
            if logger:
                logger.warning(f"Failed to generate HTML index: {e}", group="SDC_REPORT")
                import traceback
                logger.debug(f"Index generation error details: {traceback.format_exc()}", group="SDC_REPORT")
    
    # Calculate essential statistics
    run_end = datetime.now(timezone.utc)
    run_start = datetime.fromisoformat(builder.global_metadata['run_started_at'])
    duration = (run_end - run_start).total_seconds()
    
    total_cves_across_sources = sum(s['total_cves_processed'] for s in index_data['sources'])
    total_entries_across_sources = sum(s['total_platform_entries'] for s in index_data['sources'])
    total_entries_with_concerns = sum(s['entries_with_concerns'] for s in index_data['sources'])
    total_entries_without_concerns = sum(s['entries_without_concerns'] for s in index_data['sources'])
    
    # Aggregate all concern types
    global_concern_counts = defaultdict(int)
    for source in index_data['sources']:
        for concern in source['concern_type_counts']:
            global_concern_counts[concern['concern_type']] += concern['count']
    
    # Source coverage analysis - split between encountered and reported
    sources_encountered_in_records = set(per_source_reports.keys())  # All sources from builder (including 0-CVE sources)
    sources_with_reports = set(written_source_ids)  # Only sources that actually had files written (CVEs > 0)
    unique_orgs_in_cache = {}  # canonical_id -> org_name mapping
    sources_with_resolved_names = set()
    sources_with_unresolved_names = set()
    
    if source_manager and source_manager.is_initialized():
        # Get unique organizations from source manager (not all identifiers)
        try:
            if hasattr(source_manager, 'get_unique_organizations'):
                unique_orgs_in_cache = source_manager.get_unique_organizations()
            
            # Track name resolution for sources with reports
            for source_id in sources_with_reports:
                name = source_manager.get_source_name(source_id)
                # Consider a source unresolved if:
                # 1. Name is None/empty
                # 2. Name starts with "Unknown Source"
                # 3. Name equals the source_id (source manager returned UUID because it couldn't resolve)
                if name and not name.startswith("Unknown Source") and name != source_id:
                    sources_with_resolved_names.add(source_id)
                else:
                    sources_with_unresolved_names.add(source_id)
        except Exception as e:
            if logger:
                logger.debug(f"Could not retrieve source manager data: {e}", group="SDC_REPORT")
    
    # Compare organizations (not identifiers)
    # Map encountered sources to their canonical org IDs for fair comparison
    canonical_orgs_encountered = set()
    unmapped_source_ids = set()  # Track source_ids that couldn't be mapped to known orgs
    
    for source_id in sources_encountered_in_records:
        # If this source_id is a canonical org ID in cache, use it
        if source_id in unique_orgs_in_cache:
            canonical_orgs_encountered.add(source_id)
        else:
            # Otherwise, try to find which org this identifier belongs to
            found_mapping = False
            for canonical_id, org_name in unique_orgs_in_cache.items():
                if source_manager:
                    encountered_name = source_manager.get_source_name(source_id)
                    if encountered_name == org_name:
                        canonical_orgs_encountered.add(canonical_id)
                        found_mapping = True
                        break
            
            # If we couldn't map it, count it as an unknown/orphaned organization
            if not found_mapping:
                unmapped_source_ids.add(source_id)
                # Count unmapped source_ids as unique organizations (they represent real entities in the data)
                canonical_orgs_encountered.add(source_id)
    
    orgs_in_cache_not_encountered = set(unique_orgs_in_cache.keys()) - canonical_orgs_encountered
    sources_skipped_no_cves = sources_encountered_in_records - sources_with_reports
    
    # Data consistency checks
    entry_math_valid = (total_entries_with_concerns + total_entries_without_concerns) == total_entries_across_sources
    all_report_files_exist = all((output_dir / s['report_file']).exists() for s in index_data['sources'])
    
    # Log comprehensive summary
    if logger:
        logger.info(f"", group="SDC_REPORT")
        logger.info(f"=" * 70, group="SDC_REPORT")
        logger.info(f"SDC REPORT GENERATION COMPLETE", group="SDC_REPORT")
        logger.info(f"=" * 70, group="SDC_REPORT")
        logger.info(f"", group="SDC_REPORT")
        
        # File Processing
        logger.info(f"FILE PROCESSING:", group="SDC_REPORT")
        logger.info(f"  NVD-ish JSON files found: {len(json_files)}", group="SDC_REPORT")
        logger.info(f"  NVD-ish files processed: {processed_count}", group="SDC_REPORT")
        logger.info(f"  NVD-ish files skipped: {skipped_count}", group="SDC_REPORT")
        logger.info(f"  JSON report files written: {len(written_files) - 1} source + 1 index", group="SDC_REPORT")
        if html_generation_enabled:
            logger.info(f"  HTML report files written: {len(html_files) - 1} source + 1 index", group="SDC_REPORT")
        else:
            logger.info(f"  HTML generation: Disabled (templates not found)", group="SDC_REPORT")
        logger.info(f"", group="SDC_REPORT")
        
        # CVE Counts
        logger.info(f"CVE STATISTICS:", group="SDC_REPORT")
        logger.info(f"  Global unique CVEs: {builder.global_metadata['total_cves_processed']}", group="SDC_REPORT")
        logger.info(f"  CVEs across sources: {total_cves_across_sources}", group="SDC_REPORT")
        logger.info(f"  Multi-source overlap: {total_cves_across_sources - builder.global_metadata['total_cves_processed']}", group="SDC_REPORT")
        logger.info(f"", group="SDC_REPORT")
        
        # Entry Totals
        logger.info(f"PLATFORM ENTRY STATISTICS:", group="SDC_REPORT")
        logger.info(f"  Total entries: {total_entries_across_sources}", group="SDC_REPORT")
        logger.info(f"  Entries with concerns: {total_entries_with_concerns}", group="SDC_REPORT")
        logger.info(f"  Entries without concerns: {total_entries_without_concerns}", group="SDC_REPORT")
        if total_entries_across_sources > 0:
            concern_rate = (total_entries_with_concerns / total_entries_across_sources) * 100
            logger.info(f"  Concern rate: {concern_rate:.1f}%", group="SDC_REPORT")
        logger.info(f"", group="SDC_REPORT")
        
        # All Concern Types (sorted by prevalence)
        logger.info(f"CONCERN TYPE BREAKDOWN (by prevalence):", group="SDC_REPORT")
        if global_concern_counts:
            for concern_type, count in sorted(global_concern_counts.items(), key=lambda x: x[1], reverse=True):
                logger.info(f"  {concern_type}: {count}", group="SDC_REPORT")
        else:
            logger.info(f"  (No concerns detected)", group="SDC_REPORT")
        logger.info(f"", group="SDC_REPORT")
        
        # Source Coverage Analysis
        logger.info(f"SOURCE COVERAGE ANALYSIS:", group="SDC_REPORT")
        logger.info(f"  Unique organizations in NVD source cache: {len(unique_orgs_in_cache)}", group="SDC_REPORT")
        logger.info(f"  Organizations encountered in NVD-ish records: {len(canonical_orgs_encountered)}", group="SDC_REPORT")
        logger.info(f"  Organizations with report files generated: {len(sources_with_reports)}", group="SDC_REPORT")
        logger.info(f"  Sources skipped (0 CVEs): {len(sources_skipped_no_cves)}", group="SDC_REPORT")
        logger.info(f"", group="SDC_REPORT")
        
        # Check: Organizations in cache but not encountered in any records
        if orgs_in_cache_not_encountered:
            logger.warning(f"  [WARNING] {len(orgs_in_cache_not_encountered)} organizations have no CVE records in this cache:", group="SDC_REPORT")
            for canonical_id in sorted(orgs_in_cache_not_encountered):
                org_name = unique_orgs_in_cache.get(canonical_id, canonical_id)
                logger.warning(f"            - {org_name} ({canonical_id[:8]}...)", group="SDC_REPORT")
        else:
            logger.info(f"  [PASS] All cached organizations were encountered in processed records", group="SDC_REPORT")
        
        # Check: Sources with unresolved names (UUIDs not in source cache)
        if sources_with_unresolved_names:
            logger.warning(f"  [WARNING] {len(sources_with_unresolved_names)} unmapped source UUID(s) not in NVD source cache:", group="SDC_REPORT")
            for source_id in sorted(sources_with_unresolved_names):
                # Get CVE IDs for this source (up to 3)
                if source_id in per_source_reports:
                    cve_ids = [cve['cve_id'] for cve in per_source_reports[source_id]['cve_data']]
                    cve_count = len(cve_ids)
                    cve_sample = cve_ids[:3]
                    cve_display = ', '.join(cve_sample)
                    if cve_count > 3:
                        cve_display += f" and {cve_count - 3} more"
                    logger.warning(f"            - {source_id} ({cve_count} CVE(s): {cve_display})", group="SDC_REPORT")
                else:
                    logger.warning(f"            - {source_id}", group="SDC_REPORT")
        else:
            logger.info(f"  [PASS] All sources with reports have resolved names", group="SDC_REPORT")
        logger.info(f"", group="SDC_REPORT")
        
        # Data Consistency Checks
        logger.info(f"DATA CONSISTENCY CHECKS:", group="SDC_REPORT")
        
        # Check: Platform entry arithmetic
        if entry_math_valid:
            logger.info(f"  [PASS] Platform entry arithmetic is valid", group="SDC_REPORT")
            logger.info(f"         Entries with concerns ({total_entries_with_concerns}) + without concerns ({total_entries_without_concerns}) = total ({total_entries_across_sources})", group="SDC_REPORT")
        else:
            logger.error(f"  [FAIL] Platform entry arithmetic INVALID", group="SDC_REPORT")
            logger.error(f"         Entries with concerns ({total_entries_with_concerns}) + without concerns ({total_entries_without_concerns}) != total ({total_entries_across_sources})", group="SDC_REPORT")
        
        # Check: All referenced report files exist on disk
        if all_report_files_exist:
            logger.info(f"  [PASS] All {len(index_data['sources'])} source report files exist on disk", group="SDC_REPORT")
            logger.info(f"         Every source listed in index file has a corresponding JSON report file", group="SDC_REPORT")
        else:
            logger.error(f"  [FAIL] Some source report files are MISSING from disk", group="SDC_REPORT")
            logger.error(f"         Index file references files that were not successfully written", group="SDC_REPORT")
        
        # Check: Report count matches expected
        expected_files = len(sources_with_reports) + 1  # Source files + index
        actual_files = len(written_files)
        if expected_files == actual_files:
            logger.info(f"  [PASS] Report file count matches expected", group="SDC_REPORT")
            logger.info(f"         Expected {expected_files} files (index + {len(sources_with_reports)} sources), wrote {actual_files}", group="SDC_REPORT")
        else:
            logger.error(f"  [FAIL] Report file count MISMATCH", group="SDC_REPORT")
            logger.error(f"         Expected {expected_files} files, actually wrote {actual_files}", group="SDC_REPORT")
        logger.info(f"", group="SDC_REPORT")
        
        # Run Context
        logger.info(f"RUN CONTEXT:", group="SDC_REPORT")
        logger.info(f"  Duration: {duration:.1f}s", group="SDC_REPORT")
        logger.info(f"  JSON index file: {index_file}", group="SDC_REPORT")
        if html_generation_enabled:
            logger.info(f"  HTML index file: {reports_dir / 'SDC_Report_Index.html'}", group="SDC_REPORT")
            logger.info(f"  HTML reports directory: {reports_dir}", group="SDC_REPORT")
        logger.info(f"=" * 70, group="SDC_REPORT")
        logger.info(f"", group="SDC_REPORT")
    
    return str(index_file)


def main():
    """Command-line interface for standalone execution."""
    import argparse
    try:
        from ..storage.run_organization import create_run_directory, ensure_run_directory
    except ImportError:
        # Standalone execution - need to implement minimal stubs
        def create_run_directory(**kwargs):
            """Minimal stub for standalone execution."""
            run_dir = get_analysis_tools_root() / "runs" / f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_sdc_report"
            run_dir.mkdir(parents=True, exist_ok=True)
            return run_dir, run_dir.name
        
        def ensure_run_directory(run_id):
            """Minimal stub for standalone execution."""
            run_dir = get_analysis_tools_root() / "runs" / run_id
            if not run_dir.exists():
                raise ValueError(f"Run directory does not exist: {run_dir}")
            return run_dir
    
    # Load config for defaults
    config = load_config()
    default_cache_name = config.get('nvd_ish_output', {}).get('cache_name', 'nvd-ish_2.0_cves')
    
    parser = argparse.ArgumentParser(
        description="Generate Source Data Concern report from NVD-ish cache",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate report in a new run directory (uses default cache)
  python -m src.analysis_tool.reporting.generate_sdc_report

  # Use existing run directory (e.g., from generate_dataset)
  python -m src.analysis_tool.reporting.generate_sdc_report \\
      --run-id 2025-12-01_10-30-00_dataset_last_7_days_nvd-ish

  # Use custom cache directory (name only, must exist in cache/ folder)
  python -m src.analysis_tool.reporting.generate_sdc_report \\
      --custom-cache nvd-ish_test_data
        """
    )
    
    parser.add_argument(
        '--run-id',
        help='Existing run ID to use (creates new run if not specified)'
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
            from ..storage.run_organization import get_analysis_tools_root
            project_root = get_analysis_tools_root()
            run_directory = project_root / "runs" / args.run_id
            
            if not run_directory.exists():
                raise ValueError(f"Run directory does not exist: {run_directory}")
            
            logger.info(f"Using existing run directory: {args.run_id}", group="SDC_REPORT")
        
        # Generate report (will create run directory if needed)
        index_path = generate_report(
            cache_name=args.custom_cache,
            run_directory=run_directory
        )
        # Extract run directory from index path
        index_file_path = Path(index_path)
        actual_run_dir = index_file_path.parent.parent
        run_id = actual_run_dir.name
        reports_dir = actual_run_dir / "reports"
        
        print(f"\nPer-source reports generated successfully")
        print(f"JSON Index: {index_path}")
        print(f"JSON Reports: {index_file_path.parent}")
        
        if reports_dir.exists() and (reports_dir / "SDC_Report_Index.html").exists():
            print(f"\nHTML Index: {reports_dir / 'SDC_Report_Index.html'}")
            print(f"HTML Reports: {reports_dir}")
            print(f"\nOpen the HTML index in your browser to view interactive reports")
        
        print(f"\nRun ID: {run_id}")
        return 0
    except Exception as e:
        import traceback
        logger.error(f"Report generation failed: {e}", group="SDC_REPORT")
        print(f"\nError: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
