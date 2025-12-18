#!/usr/bin/env python3
"""
Source Data Concern Report Generator from NVD-ish Cache

Scans enriched NVD-ish records and generates sourceDataConcernReport.json
independent of live CVE processing. This is a cache-to-report transformation
utility that treats NVD-ish records as the source of truth.

Architecture:
    - Reads from: cache/nvd-ish_2.0_cves/
    - Extracts: enrichedCVEv5Affected.cveListV5AffectedEntries[*].sourceDataConcerns
    - Generates: sourceDataConcernReport.json (matching dashboard schema)

Usage:
    # Standalone
    python -m src.analysis_tool.reporting.generate_sdc_report \
        --cache-dir cache/nvd-ish_2.0_cves \
        --output-file runs/[run_id]/logs/sourceDataConcernReport.json

    # Programmatic
    from src.analysis_tool.reporting import generate_sdc_report
    generate_sdc_report(cache_dir="cache/nvd-ish_2.0_cves", output_file="output.json")
"""

import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

# Minimal imports - only what's needed for cache scanning and source resolution
try:
    from ..logging.workflow_logger import get_logger
    from ..storage.run_organization import get_analysis_tools_root
    logger = get_logger()
except ImportError:
    # Fallback for standalone execution
    import logging
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)
    
    def get_analysis_tools_root():
        """Fallback for standalone execution."""
        return Path(__file__).resolve().parent.parent.parent.parent


def load_config() -> Dict:
    """Load configuration file with defaults."""
    try:
        project_root = get_analysis_tools_root()
        config_path = project_root / "src" / "analysis_tool" / "config.json"
        
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            logger.warning(f"Config file not found at {config_path}, using hardcoded defaults")
            return {}
    except Exception as e:
        logger.warning(f"Failed to load config: {e}, using hardcoded defaults")
        return {}


class SDCReportBuilder:
    """
    Builds sourceDataConcernReport.json from NVD-ish cache records.
    
    Schema matches the format expected by sourceDataConcernDashboard.html:
    {
      "metadata": {
        "run_started_at": "ISO timestamp",
        "total_cves_processed": int,
        "total_platform_entries": int,
        "entries_with_concerns": int,
        "concern_type_counts": [{"concern_type": "key", "count": int}]
      },
      "cve_data": [
        {
          "cve_id": "CVE-YYYY-XXXXX",
          "platform_entries": [...],
          "clean_platform_entries": [...],
          "cve_metadata": {...}
        }
      ]
    }
    """
    
    def __init__(self, source_manager=None):
        """
        Initialize the report builder.
        
        Args:
            source_manager: Optional NVD source manager for UUID resolution
        """
        self.source_manager = source_manager
        self.metadata = {
            'run_started_at': datetime.now(timezone.utc).isoformat(),
            'total_cves_processed': 0,
            'total_platform_entries': 0,
            'entries_with_concerns': 0,
            'concern_type_counts': [],
            'report_scope': 'Platform Entry Notifications - Source Data Concerns Only',
            'status': 'in_progress'
        }
        self.cve_data = []
        self.concern_type_counter = defaultdict(int)
    
    def add_cve(self, cve_id: str, entries: List[Dict]) -> None:
        """
        Process one CVE's affected entries and add to report.
        
        Args:
            cve_id: CVE identifier
            entries: List of cveListV5AffectedEntries from NVD-ish record
        """
        platform_entries = []
        clean_entries_by_source = defaultdict(int)
        cve_concern_type_counter = defaultdict(int)
        
        cve_metadata = {
            'total_platform_entries': 0,
            'entries_with_concerns': 0,
            'concern_type_counts': [],
            'processing_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        for idx, entry in enumerate(entries):
            origin = entry.get('originAffectedEntry', {})
            sdc = entry.get('sourceDataConcerns', {})
            concerns = sdc.get('concerns', {})
            
            source_id = origin.get('sourceId', 'Unknown')
            vendor = origin.get('vendor', 'Unknown')
            product = origin.get('product', 'Unknown')
            
            cve_metadata['total_platform_entries'] += 1
            self.metadata['total_platform_entries'] += 1
            
            if concerns:  # Entry has source data concerns
                concern_types = list(concerns.keys())
                total_concerns = sum(len(v) for v in concerns.values() if isinstance(v, list))
                
                # Resolve source name
                source_name = self._resolve_source_name(source_id)
                
                # Build concern breakdown (concern type -> count)
                concern_breakdown = {
                    ct: len(concerns[ct]) 
                    for ct in concern_types 
                    if isinstance(concerns[ct], list)
                }
                
                # Build concerns detail array (grouped by concern type)
                concerns_detail = [
                    {
                        'concern_type': ct,
                        'concerns': concerns[ct]
                    }
                    for ct in concern_types
                    if isinstance(concerns[ct], list) and concerns[ct]
                ]
                
                # Create platform entry object
                platform_entry = {
                    'platform_entry_id': f"entry_{idx}",
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
                
                # Update counts
                cve_metadata['entries_with_concerns'] += 1
                self.metadata['entries_with_concerns'] += 1
                
                for ct in concern_types:
                    self.concern_type_counter[ct] += 1
                    cve_concern_type_counter[ct] += 1
            
            else:  # Clean entry (no concerns)
                clean_entries_by_source[source_id] += 1
        
        # Build CVE-level concern type counts
        cve_metadata['concern_type_counts'] = [
            {'concern_type': ct, 'count': count}
            for ct, count in sorted(cve_concern_type_counter.items())
        ]
        
        # Build clean platform entries (grouped by source)
        clean_platform_entries = [
            {
                'sourceID': source_id,
                'source_name': self._resolve_source_name(source_id),
                'cleanPlatformCount': count
            }
            for source_id, count in clean_entries_by_source.items()
        ]
        
        # Add CVE to report data
        self.cve_data.append({
            'cve_id': cve_id,
            'platform_entries': platform_entries,
            'clean_platform_entries': clean_platform_entries,
            'cve_metadata': cve_metadata
        })
        
        self.metadata['total_cves_processed'] += 1
    
    def _resolve_source_name(self, source_id: str) -> str:
        """
        Resolve source UUID to human-readable name.
        
        Args:
            source_id: Source UUID or identifier
            
        Returns:
            Human-readable source name or fallback
        """
        if self.source_manager and self.source_manager.is_initialized():
            try:
                name = self.source_manager.get_source_name(source_id)
                if name:
                    return name
            except Exception as e:
                if logger:
                    logger.debug(f"Source name resolution failed for {source_id}: {e}", group="SDC_REPORT")
        
        # Fallback to abbreviated source ID
        if source_id and len(source_id) > 8:
            return f"Unknown Source ({source_id[:8]}...)"
        return f"Unknown Source ({source_id})"
    
    def finalize(self) -> Dict:
        """
        Build final report structure with completed metadata.
        
        Returns:
            Complete report dictionary ready for JSON serialization
        """
        # Convert concern type counter to sorted array
        self.metadata['concern_type_counts'] = [
            {'concern_type': ct, 'count': count}
            for ct, count in sorted(self.concern_type_counter.items())
        ]
        
        self.metadata['last_updated'] = datetime.now(timezone.utc).isoformat()
        self.metadata['status'] = 'completed'
        
        return {
            'metadata': self.metadata,
            'cve_data': self.cve_data
        }


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


def generate_report(
    cache_dir: str = "cache/nvd-ish_2.0_cves",
    output_file: str = None,
    cve_list: Optional[List[str]] = None,
    source_uuid: Optional[str] = None,
    progress_interval: int = 50
) -> str:
    """
    Generate sourceDataConcernReport.json from NVD-ish cache records.
    
    Args:
        cache_dir: Path to NVD-ish cache directory
        output_file: Path to output JSON file
        cve_list: Optional list of CVE IDs to process (None = all)
        source_uuid: Optional source UUID filter (not yet implemented)
        progress_interval: Log progress every N files
        
    Returns:
        Path to generated report file
        
    Raises:
        FileNotFoundError: If cache directory doesn't exist
        RuntimeError: If output file path is invalid
    """
    cache_path = Path(cache_dir)
    
    # Validate cache directory
    if not cache_path.exists():
        raise FileNotFoundError(f"Cache directory not found: {cache_dir}")
    
    # Validate output file
    if not output_file:
        raise RuntimeError("Output file path is required")
    
    if logger:
        logger.info(f"Starting SDC report generation from NVD-ish cache", group="SDC_REPORT")
        logger.info(f"  Cache directory: {cache_dir}", group="SDC_REPORT")
        logger.info(f"  Output file: {output_file}", group="SDC_REPORT")
    
    # Initialize source manager for UUID resolution
    source_manager = None
    try:
        import pandas as pd
        from ..storage.nvd_source_manager import get_global_source_manager
        from ..storage.run_organization import get_analysis_tools_root
        
        source_manager = get_global_source_manager()
        
        # Only initialize if not already initialized
        if not source_manager.is_initialized():
            # Try to load from cache
            cache_file = get_analysis_tools_root() / "cache" / "nvd_source_data.json"
            
            if cache_file.exists():
                if logger:
                    logger.info(f"Loading NVD source data from cache: {cache_file}", group="SDC_REPORT")
                
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                
                # Extract source_data list and convert to DataFrame
                source_list = cache_data.get('source_data', [])
                if not source_list:
                    raise ValueError("Cache file exists but contains no source_data")
                
                sources_df = pd.DataFrame(source_list)
                source_manager.initialize(sources_df)
                
                if logger:
                    logger.info(f"Source manager initialized with {source_manager.get_source_count()} sources from cache", group="SDC_REPORT")
            else:
                if logger:
                    logger.warning(f"NVD source cache not found at {cache_file} - UUIDs will not be resolved", group="SDC_REPORT")
                source_manager = None
        else:
            if logger:
                logger.info(f"Source manager already initialized with {source_manager.get_source_count()} sources", group="SDC_REPORT")
                
    except ImportError as e:
        if logger:
            logger.error(f"Failed to import required dependencies: {e}", group="SDC_REPORT")
        source_manager = None
    except Exception as e:
        if logger:
            logger.error(f"Source manager initialization failed - UUIDs will not be resolved: {e}", group="SDC_REPORT")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}", group="SDC_REPORT")
        source_manager = None
    
    # Build CVE filter set if provided
    cve_filter = set(cve_list) if cve_list else None
    
    # Scan cache
    builder = SDCReportBuilder(source_manager=source_manager)
    json_files = scan_nvd_ish_cache(cache_path, cve_filter)
    
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
    
    # Generate final report
    report_data = builder.finalize()
    
    # Write with atomic pattern (temp file + rename)
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    temp_file = output_path.with_suffix('.tmp')
    try:
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        # Atomic rename
        temp_file.replace(output_path)
        
    except Exception as e:
        # Clean up temp file on error
        if temp_file.exists():
            temp_file.unlink()
        raise RuntimeError(f"Failed to write report file: {e}")
    
    # Log summary
    if logger:
        logger.info(f"SDC report generation completed", group="SDC_REPORT")
        logger.info(f"  Report file: {output_file}", group="SDC_REPORT")
        logger.info(f"  Total CVEs: {report_data['metadata']['total_cves_processed']}", group="SDC_REPORT")
        logger.info(f"  Total platform entries: {report_data['metadata']['total_platform_entries']}", group="SDC_REPORT")
        logger.info(f"  Entries with concerns: {report_data['metadata']['entries_with_concerns']}", group="SDC_REPORT")
        logger.info(f"  Clean platform entries: {report_data['metadata']['total_platform_entries'] - report_data['metadata']['entries_with_concerns']}", group="SDC_REPORT")
        logger.info(f"  Processed: {processed_count}, Skipped: {skipped_count}", group="SDC_REPORT")
    
    return str(output_path)


def main():
    """Command-line interface for standalone execution."""
    import argparse
    from ..storage.run_organization import create_run_directory, ensure_run_directory
    
    # Load config for defaults
    config = load_config()
    default_cache_dir = config.get('nvd_ish_output', {}).get('path', 'cache/nvd-ish_2.0_cves')
    
    parser = argparse.ArgumentParser(
        description="Generate Source Data Concern report from NVD-ish cache",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate report in a new run directory
  python -m src.analysis_tool.reporting.generate_sdc_report

  # Use existing run directory (e.g., from generate_dataset)
  python -m src.analysis_tool.reporting.generate_sdc_report \\
      --run-id 2025-12-01_10-30-00_dataset_last_7_days_nvd-ish

  # Process specific CVE list
  python -m src.analysis_tool.reporting.generate_sdc_report \\
      --cve-list CVE-2024-12345 CVE-2024-12346

  # Custom cache directory
  python -m src.analysis_tool.reporting.generate_sdc_report \\
      --cache-dir custom_cache/nvd-ish_2.0_cves
        """
    )
    
    parser.add_argument(
        '--run-id',
        help='Existing run ID to use (creates new run if not specified)'
    )
    
    parser.add_argument(
        '--cache-dir',
        default=default_cache_dir,
        help=f'NVD-ish cache directory (default: {default_cache_dir})'
    )
    
    parser.add_argument(
        '--cve-list',
        nargs='+',
        help='Optional list of CVE IDs to process (space-separated)'
    )
    
    parser.add_argument(
        '--progress',
        type=int,
        default=50,
        help='Log progress every N records (default: 50)'
    )
    
    args = parser.parse_args()
    
    try:
        # Determine run directory
        if args.run_id:
            # Use existing run directory
            run_directory = ensure_run_directory(args.run_id)
            run_id = args.run_id
            logger.info(f"Using existing run directory: {run_id}")
        else:
            # Create new run directory for standalone report generation
            run_directory, run_id = create_run_directory(
                execution_type="sdc_report",
                subdirs=["logs"]
            )
            logger.info(f"Created new run directory: {run_id}")
        
        # Set output path in run's logs directory
        output_file = run_directory / "logs" / "sourceDataConcernReport.json"
        
        logger.info(f"Run directory: {run_directory}")
        logger.info(f"Output file: {output_file}")
        
        report_path = generate_report(
            cache_dir=args.cache_dir,
            output_file=str(output_file),
            cve_list=args.cve_list,
            progress_interval=args.progress
        )
        print(f"\nReport generated successfully: {report_path}")
        print(f"Run ID: {run_id}")
        return 0
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        print(f"\nError: {e}")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
