#!/usr/bin/env python3
"""
Generate Dataset Report - Automated Report Generation

Generates HTML reports for dataset generation runs during automated processing.

Individual dataset reports are auto-generated during dataset processing via
dataset_contents_collector.finalize_report().

Harvest index reports are auto-generated during harvest processing via
update_harvest_index_incremental().
"""

import json
import sys
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional

from ..logging.workflow_logger import get_logger
from ..storage.run_organization import get_analysis_tools_root

logger = get_logger()

try:
    from .. import __version__
except ImportError:
    __version__ = "unknown"


# ============================================================================
# Dataset Report Functions (Individual Reports)
# ============================================================================

def generate_dataset_report(dataset_run_dir: Path) -> bool:
    """
    Generate HTML dataset report from generateDatasetReport.json.
    
    Args:
        dataset_run_dir: Path to the dataset run directory containing logs/generateDatasetReport.json
        
    Returns:
        True if report generated successfully, False otherwise
    """
    try:
        dataset_run_dir = Path(dataset_run_dir)
        
        # Locate the JSON report file
        json_report_path = dataset_run_dir / "logs" / "generateDatasetReport.json"
        if not json_report_path.exists():
            return False
        
        # Load JSON data
        
        with open(json_report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        # Prepare output paths - place in parent harvest run's reports directory
        # Check if this dataset is part of a harvest run (parent directory contains other datasets)
        parent_dir = dataset_run_dir.parent
        if parent_dir.name.startswith('20') and '_harvest_' in parent_dir.name:
            # This is a dataset within a harvest run - use parent's reports directory
            reports_dir = parent_dir / "reports"
        else:
            # Standalone dataset run - use its own reports directory
            reports_dir = dataset_run_dir / "reports"
        
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        css_dir = reports_dir / "css"
        css_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate unique report name based on directory name
        report_filename = f"{dataset_run_dir.name}_report.html"
        output_html_path = reports_dir / report_filename
        
        # Locate template and CSS files
        project_root = get_analysis_tools_root()
        template_path = project_root / "src" / "analysis_tool" / "static" / "templates" / "Generate_Dataset_Report_Template.html"
        css_source_path = project_root / "src" / "analysis_tool" / "static" / "css" / "generate_dataset_dashboard.css"
        
        if not template_path.exists():
            logger.error(f"Template not found: {template_path}")
            return False
        
        if not css_source_path.exists():
            logger.error(f"CSS file not found: {css_source_path}")
            return False
        
        # Load template
        with open(template_path, 'r', encoding='utf-8') as f:
            template_html = f.read()
        
        # Convert report data to JSON string for injection
        report_json = json.dumps(report_data, indent=2)
        
        # Inject data by replacing the null declaration
        injection_pattern = 'let dashboardData = null;'
        if injection_pattern not in template_html:
            logger.error("Template injection point not found: 'let dashboardData = null;'")
            return False
        
        injected_html = template_html.replace(
            injection_pattern,
            f'let dashboardData = {report_json};'
        )
        
        # Copy CSS file to reports/css/
        css_dest_path = css_dir / "generate_dataset_dashboard.css"
        shutil.copy2(css_source_path, css_dest_path)
        
        # Write generated HTML
        with open(output_html_path, 'w', encoding='utf-8') as f:
            f.write(injected_html)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate dataset report: {e}")
        return False


# ============================================================================
# Dataset Index Functions (Session-Level Index)
# ============================================================================

def parse_dataset_report_stats(dataset_dir: Path) -> Optional[Dict]:
    """
    Parse generateDatasetReport.json from a dataset run directory.
    
    Args:
        dataset_dir: Path to dataset run directory
        
    Returns:
        Dictionary containing dataset statistics, or None if not found
    """
    report_file = dataset_dir / "logs" / "generateDatasetReport.json"
    if not report_file.exists():
        return None
    
    try:
        with open(report_file, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        # Extract key statistics
        processing = report_data.get('processing', {})
        log_stats = report_data.get('log_stats', {})
        metadata = report_data.get('metadata', {})
        
        return {
            'source': metadata.get('source_name', ''),
            'uuid': metadata.get('source_uuid', ''),
            'total_cves': processing.get('total_cves', 0),
            'processed_cves': processing.get('processed_cves', 0),
            'warnings': log_stats.get('warning_count', 0),
            'errors': log_stats.get('error_count', 0),
            'status': metadata.get('status', 'unknown'),
            'runtime': report_data.get('performance', {}).get('total_runtime', 0)
        }
    except Exception:
        return None


def load_harvest_index_json(run_directory: Path) -> Optional[Dict]:
    """
    Load generate_dataset_index.json from run directory.
    
    Args:
        run_directory: Path to harvest run directory
        
    Returns:
        Dictionary containing harvest data from JSON, or None if not found
    """
    json_file = run_directory / "logs" / "generate_dataset_index.json"
    
    if not json_file.exists():
        logger.error(
            f"generate_dataset_index.json not found at {json_file}. "
            "This file should be created during harvest processing.",
            group="DATASET_INDEX"
        )
        return None
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        
        return json_data
        
    except Exception as e:
        logger.error(f"Failed to load generate_dataset_index.json: {e}", group="DATASET_INDEX")
        return None


def generate_dataset_index(run_directory: Path) -> Optional[Path]:
    """
    Generate HTML index page from harvest session log.
    
    Args:
        run_directory: Path to run directory.
        
    Returns:
        Path to generated HTML file, or None if generation failed
    """
    project_root = get_analysis_tools_root()
    
    harvest_data = load_harvest_index_json(run_directory)
    if not harvest_data:
        logger.error(
            "Failed to load generate_dataset_index.json. "
            "This file should be created during harvest processing.",
            group="DATASET_INDEX"
        )
        return None
    
    # Load template
    template_path = project_root / "src" / "analysis_tool" / "static" / "templates" / "Generate_Dataset_Index_Template.html"
    if not template_path.exists():
        logger.error(f"Template not found: {template_path}", group="DATASET_INDEX")
        return None
    
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    
    # Serialize structured JSON for template injection
    json_data = json.dumps(harvest_data, ensure_ascii=False)
    
    # Replace null declaration with actual data (following SDC pattern)
    null_declaration = "let datasetData = null;"
    
    if null_declaration in template_content:
        # Replace the null initialization with actual data
        data_declaration = f"let datasetData = {json_data};"
        html_content = template_content.replace(null_declaration, data_declaration, 1)
    else:
        # Fallback: insert before document.addEventListener
        dom_ready_marker = "document.addEventListener('DOMContentLoaded', function()"
        if dom_ready_marker in template_content:
            insertion_point = template_content.find(dom_ready_marker)
            data_script = f"\n        // Injected data from generate dataset session\n        let datasetData = {json_data};\n\n        "
            html_content = template_content[:insertion_point] + data_script + template_content[insertion_point:]
        else:
            logger.error("Could not find data injection point in template", group="DATASET_INDEX")
            return None
    
    # Replace version and generation time placeholders
    html_content = html_content.replace('{{TOOL_VERSION}}', __version__)
    html_content = html_content.replace('{{GENERATION_TIME}}', datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))
    
    # Write output file to reports directory
    reports_dir = run_directory / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy CSS file to reports/css/ directory
    css_source = project_root / "src" / "analysis_tool" / "static" / "css" / "generate_dataset_dashboard.css"
    css_dest_dir = reports_dir / "css"
    css_dest_dir.mkdir(parents=True, exist_ok=True)
    css_dest = css_dest_dir / "generate_dataset_dashboard.css"
    
    try:
        shutil.copy2(css_source, css_dest)
    except Exception as e:
        logger.warning(f"Failed to copy CSS file: {e}", group="DATASET_INDEX")
    
    output_file = reports_dir / "generate_dataset_index.html"
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file
        
    except Exception as e:
        logger.error(f"Failed to write HTML file: {e}", group="DATASET_INDEX")
        return None


def update_harvest_index_incremental(run_directory: Path, harvest_stats: Dict, current_source_info: Optional[tuple] = None) -> bool:
    """
    Update generate_dataset_index.json and regenerate HTML index during harvest processing.
    
    Updates are additive - any combination of updates can happen in a single call:
    - current_source_info provided: Mark that source as 'in_progress'
    - harvest_stats['sources']: Add or update those source entries
    - harvest_stats['session_end']: Finalize session metadata (duration, status)
    
    Args:
        run_directory: Path to harvest run directory
        harvest_stats: Dict with any of: 'sources', 'session_start', 'session_end', 'duration', 'status', 'total_sources'
        current_source_info: Optional tuple of (source_name, source_uuid) to mark as in-progress
        
    Returns:
        True if update successful, False otherwise
    """
    try:
        json_path = run_directory / "logs" / "generate_dataset_index.json"
        
        # Load existing data or create new structure
        if json_path.exists():
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            # Initialize new structure
            # Calculate initial duration if session_start is available
            session_start = harvest_stats.get('session_start')
            if session_start:
                try:
                    start_dt = datetime.fromisoformat(session_start.replace('Z', '+00:00'))
                    elapsed = datetime.now(timezone.utc) - start_dt
                    duration = f"{int(elapsed.total_seconds())}s"
                except Exception as e:
                    logger.warning(f"Failed to parse session_start timestamp '{session_start}': {e}", group="DATASET_INDEX")
                    duration = 'ERROR: Invalid Timestamp'
            else:
                duration = 'In Progress'
            
            data = {
                'metadata': {
                    'run_id': run_directory.name,
                    'tool_version': __version__,
                    'generated_at': datetime.now(timezone.utc).isoformat(),
                    'session_start': session_start,
                    'session_end': None,
                    'duration': duration,
                    'status': 'In Progress'
                },
                'summary': {
                    'total_sources': harvest_stats.get('total_sources', 0),
                    'successful': 0,
                    'failed': 0,
                    'skipped': 0,
                    'interrupted': 0,
                    'not_processed': harvest_stats.get('total_sources', 0),
                    'total_cves_processed': 0,
                    'total_warnings': 0,
                    'total_errors': 0
                },
                'datasets': []
            }
        
        # Mark source as in-progress if requested
        if current_source_info:
            source_name, source_uuid = current_source_info
            datasets = data.get('datasets', [])
            found = False
            for dataset in datasets:
                if dataset.get('uuid') == source_uuid:
                    dataset['status'] = 'in_progress'
                    dataset['details'] = 'Currently processing'
                    found = True
                    break
            
            if not found:
                datasets.append({
                    'source': source_name,
                    'uuid': source_uuid,
                    'status': 'in_progress',
                    'details': 'Currently processing'
                })
            
            data['datasets'] = datasets
        
        # Add or update source entries if provided
        if harvest_stats and 'sources' in harvest_stats:
            datasets = data.get('datasets', [])
            
            for source in harvest_stats['sources']:
                source_uuid = source.get('uuid')
                
                # Find existing entry or create new
                existing = None
                for dataset in datasets:
                    if dataset.get('uuid') == source_uuid:
                        existing = dataset
                        break
                
                if existing:
                    # Update existing entry
                    existing.update({
                        'status': source.get('status'),
                        'details': source.get('details', '')
                    })
                else:
                    # Create new entry
                    existing = {
                        'source': source.get('name'),
                        'uuid': source_uuid,
                        'status': source.get('status'),
                        'details': source.get('details', '')
                    }
                    datasets.append(existing)
                
                # Add dataset directory information for completed sources
                if source.get('status') == 'completed':
                    dataset_dir_name = Path(source['dataset_run_dir']).name
                    existing['directory'] = dataset_dir_name
                    existing['report_filename'] = f"{dataset_dir_name}_report.html"
                
                # Add CVE information
                if 'cve_info' in source:
                    cve_info = source['cve_info']
                    if isinstance(cve_info, (list, tuple)) and len(cve_info) == 2:
                        existing['processed_cves'] = cve_info[0]
                        existing['total_cves'] = cve_info[1]
                    elif isinstance(cve_info, int):
                        existing['total_cves'] = cve_info
                
                # Add detailed metrics
                for field in ['warnings', 'errors', 'runtime']:
                    if field in source:
                        existing[field] = source[field]
            
            data['datasets'] = datasets
            
            # Recalculate summary statistics
            summary = data['summary']
            summary['successful'] = sum(1 for d in datasets if d.get('status') == 'completed')
            summary['failed'] = sum(1 for d in datasets if d.get('status') == 'failed')
            summary['skipped'] = sum(1 for d in datasets if d.get('status') == 'skipped')
            summary['interrupted'] = sum(1 for d in datasets if d.get('status') == 'interrupted')
            summary['not_processed'] = sum(1 for d in datasets if d.get('status') == 'not_processed')
            summary['total_cves_processed'] = sum(d.get('processed_cves', 0) for d in datasets if d.get('status') == 'completed')
            summary['total_warnings'] = sum(d.get('warnings', 0) for d in datasets if d.get('status') == 'completed')
            summary['total_errors'] = sum(d.get('errors', 0) for d in datasets if d.get('status') == 'completed')
        
        # Finalize session metadata if provided
        if harvest_stats and 'session_end' in harvest_stats:
            data['metadata']['session_end'] = harvest_stats.get('session_end')
            data['metadata']['duration'] = harvest_stats.get('duration', 'Unknown')
            data['metadata']['status'] = harvest_stats.get('status', 'Completed')
        
        # Write updated data
        temp_file = json_path.with_suffix('.tmp')
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        temp_file.replace(json_path)
        
        # Always regenerate HTML after JSON update (silent for live updates)
        html_result = generate_dataset_index(run_directory)
        return html_result is not None
        
    except Exception as e:
        logger.warning(f"Failed to update harvest index: {e}", group="DATASET_INDEX")
        return False
