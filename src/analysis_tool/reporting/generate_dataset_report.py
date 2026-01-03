#!/usr/bin/env python3
"""
Generate Dataset Report - Unified CLI for Dataset Dashboard Generation

Generates HTML reports for dataset generation runs, including both
session-level index pages and individual dataset reports.

NOTE: Individual dataset reports are auto-generated during dataset processing
via dataset_contents_collector.finalize_report(). This script provides manual
generation capabilities for re-generating reports or creating session indexes.

Usage:
    # Generate session index (lists all datasets in a harvest run)
    python -m src.analysis_tool.reporting.generate_dataset_report index [--run-id <id>]
    
    # Generate individual dataset report (usually auto-generated)
    python -m src.analysis_tool.reporting.generate_dataset_report report <dataset-dir>
    
    # Generate everything (index + all dataset reports)
    python -m src.analysis_tool.reporting.generate_dataset_report all [--run-id <id>]
"""

import json
import re
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

def generate_dataset_report(dataset_run_dir: Path, verbose: bool = True) -> bool:
    """
    Generate HTML dataset report from generateDatasetReport.json.
    
    Args:
        dataset_run_dir: Path to the dataset run directory containing logs/generateDatasetReport.json
        verbose: If True, log generation progress. If False, generate silently.
        
    Returns:
        True if report generated successfully, False otherwise
    """
    try:
        dataset_run_dir = Path(dataset_run_dir)
        
        # Locate the JSON report file
        json_report_path = dataset_run_dir / "logs" / "generateDatasetReport.json"
        if not json_report_path.exists():
            if verbose:
                logger.warning(f"Dataset report JSON not found: {json_report_path}")
            return False
        
        # Load JSON data
        if verbose:
            logger.info(f"Loading dataset report data from {json_report_path.name}")
        
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
        if verbose:
            logger.info("Loading Generate_Dataset_Report_Template.html")
        
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
        if verbose:
            try:
                rel_path = css_dest_path.relative_to(dataset_run_dir)
                logger.info(f"Copying CSS to {rel_path}")
            except ValueError:
                # CSS is in parent directory, just show the filename
                logger.info(f"Copying CSS to {css_dest_path.name}")
        
        shutil.copy2(css_source_path, css_dest_path)
        
        # Write generated HTML
        if verbose:
            try:
                rel_path = output_html_path.relative_to(dataset_run_dir)
                logger.info(f"Writing dataset report to {rel_path}")
            except ValueError:
                # Report is in parent directory, just show the filename
                logger.info(f"Writing dataset report to {output_html_path.name}")
        
        with open(output_html_path, 'w', encoding='utf-8') as f:
            f.write(injected_html)
        
        if verbose:
            try:
                rel_path = output_html_path.relative_to(dataset_run_dir)
                logger.info(f"✓ Dataset report generated successfully: {rel_path}")
            except ValueError:
                # Report is in parent directory, use absolute path
                logger.info(f"✓ Dataset report generated successfully: {output_html_path}")
        
        return True
        
    except Exception as e:
        if verbose:
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
            'total_cves': processing.get('total_cves', 0),
            'processed_cves': processing.get('processed_cves', 0),
            'warnings': log_stats.get('warning_count', 0),
            'errors': log_stats.get('error_count', 0),
            'status': metadata.get('status', 'unknown'),
            'runtime': report_data.get('performance', {}).get('total_runtime', 0)
        }
    except Exception:
        return None


def parse_harvest_log(log_file_path: Path) -> Dict:
    """
    Parse harvest session log file and extract processing statistics.
    
    Args:
        log_file_path: Path to harvest session log file
        
    Returns:
        Dictionary containing harvest session data
    """
    data = {
        'run_id': '',
        'session_start': None,
        'session_end': None,
        'duration': 'Unknown',
        'status': 'Unknown',
        'total_sources': 0,
        'successful': 0,
        'failed': 0,
        'skipped': 0,
        'interrupted': 0,
        'not_processed': 0,
        'sources': [],
        'total_cves_processed': 0,
        'total_warnings': 0,
        'total_errors': 0
    }
    
    # Extract run_id from parent directory name
    data['run_id'] = log_file_path.parent.parent.name
    
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            log_content = f.read()
    except Exception as e:
        logger.warning(f"Failed to read log file: {e}")
        return data
    
    # Extract session start time
    start_match = re.search(r'Harvest session started at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', log_content)
    if start_match:
        data['session_start'] = start_match.group(1).replace(' ', 'T')
    
    # Extract status summary counts
    status_match = re.search(
        r'STATUS: Completed (\d+)/(\d+) sources \((\d+) successful, (\d+) skipped, (\d+) failed(?:, (\d+) interrupted)?(?:, (\d+) not processed)?\)',
        log_content
    )
    if status_match:
        data['total_sources'] = int(status_match.group(2))
        data['successful'] = int(status_match.group(3))
        data['skipped'] = int(status_match.group(4))
        data['failed'] = int(status_match.group(5))
        if status_match.group(6):
            data['interrupted'] = int(status_match.group(6))
        if status_match.group(7):
            data['not_processed'] = int(status_match.group(7))
    
    # Determine overall status
    if data['successful'] > 0 and data['failed'] == 0:
        data['status'] = 'Completed Successfully'
    elif data['failed'] > 0:
        data['status'] = f"Completed with {data['failed']} Failures"
    else:
        data['status'] = 'In Progress'
    
    # Parse problem sources (skipped, failed, interrupted, not processed)
    # Look for SKIPPED SOURCES REPORT
    skipped_section = re.search(
        r'SKIPPED SOURCES REPORT:(.+?)(?=(?:FAILED SOURCES REPORT:|INTERRUPTED SOURCE REPORT:|NOT PROCESSED SOURCES REPORT:|STATUS:|Harvest session ended:|All processable sources|$))',
        log_content,
        re.DOTALL
    )
    if skipped_section:
        skipped_text = skipped_section.group(1)
        for source_match in re.finditer(r'\[WARNING\].*?\] ([^\n]+)\n.*?UUID: ([a-f0-9-]+)\n.*?CVE Count: ([\d,]+)', skipped_text, re.DOTALL):
            data['sources'].append({
                'name': source_match.group(1).strip(),
                'uuid': source_match.group(2),
                'cve_info': source_match.group(3),
                'status': 'skipped',
                'details': 'Exceeded CVE threshold'
            })
    
    # Look for FAILED SOURCES REPORT
    failed_section = re.search(
        r'FAILED SOURCES REPORT:(.+?)(?=(?:INTERRUPTED SOURCE REPORT:|NOT PROCESSED SOURCES REPORT:|STATUS:|Harvest session ended:|All processable sources|$))',
        log_content,
        re.DOTALL
    )
    if failed_section:
        failed_text = failed_section.group(1)
        for source_match in re.finditer(
            r'\[ERROR\].*?\] ([^\n]+)\n.*?UUID: ([a-f0-9-]+)\n.*?CVE Count: ([^\n]+)\n.*?Error Type: ([^\n]+)',
            failed_text,
            re.DOTALL
        ):
            data['sources'].append({
                'name': source_match.group(1).strip(),
                'uuid': source_match.group(2),
                'cve_info': source_match.group(3).strip(),
                'status': 'failed',
                'details': source_match.group(4).strip()
            })
    
    # Look for INTERRUPTED SOURCE REPORT
    interrupted_section = re.search(
        r'INTERRUPTED SOURCE REPORT:(.+?)(?=(?:NOT PROCESSED SOURCES REPORT:|STATUS:|Harvest session ended:|All processable sources|$))',
        log_content,
        re.DOTALL
    )
    if interrupted_section:
        interrupted_text = interrupted_section.group(1)
        for source_match in re.finditer(r'\[WARNING\].*?\] ([^\n]+)\n.*?UUID: ([a-f0-9-]+)', interrupted_text, re.DOTALL):
            data['sources'].append({
                'name': source_match.group(1).strip(),
                'uuid': source_match.group(2),
                'cve_info': 'Interrupted',
                'status': 'interrupted',
                'details': 'Processing interrupted'
            })
    
    # Look for NOT PROCESSED SOURCES REPORT
    not_processed_section = re.search(
        r'NOT PROCESSED SOURCES REPORT:(.+?)(?=(?:STATUS:|Harvest session ended:|All processable sources|$))',
        log_content,
        re.DOTALL
    )
    if not_processed_section:
        not_processed_text = not_processed_section.group(1)
        for source_match in re.finditer(r'\[WARNING\].*?\] ([^\n]+)\n.*?UUID: ([a-f0-9-]+)', not_processed_text, re.DOTALL):
            data['sources'].append({
                'name': source_match.group(1).strip(),
                'uuid': source_match.group(2),
                'cve_info': 'Not attempted',
                'status': 'not_processed',
                'details': 'Early termination'
            })
    
    # Calculate session end time from log file modification time
    try:
        mtime = log_file_path.stat().st_mtime
        data['session_end'] = datetime.fromtimestamp(mtime).isoformat()
        
        # Calculate duration if we have both start and end
        if data['session_start']:
            start_dt = datetime.fromisoformat(data['session_start'])
            end_dt = datetime.fromtimestamp(mtime)
            duration_sec = (end_dt - start_dt).total_seconds()
            hours = int(duration_sec // 3600)
            minutes = int((duration_sec % 3600) // 60)
            seconds = int(duration_sec % 60)
            data['duration'] = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    except:
        pass
    
    return data


def generate_dataset_index(run_directory: Optional[Path] = None, verbose: bool = True) -> Optional[Path]:
    """
    Generate HTML index page from harvest session log.
    
    Args:
        run_directory: Path to run directory. If None, finds most recent harvest run.
        verbose: If True, log info messages. Set False for iterative updates.
        
    Returns:
        Path to generated HTML file, or None if generation failed
    """
    project_root = get_analysis_tools_root()
    
    # Find run directory if not provided
    if run_directory is None:
        runs_dir = project_root / "runs"
        harvest_runs = sorted([
            d for d in runs_dir.iterdir() 
            if d.is_dir() and '_harvest_' in d.name
        ], reverse=True)
        
        if not harvest_runs:
            if verbose:
                logger.error("No harvest run directories found", group="DATASET_INDEX")
            return None
        
        run_directory = harvest_runs[0]
        if verbose:
            logger.info(f"Using most recent harvest run: {run_directory.name}", group="DATASET_INDEX")
    
    # Find log file
    log_dir = run_directory / "logs"
    if not log_dir.exists():
        if verbose:
            logger.error(f"Log directory not found: {log_dir}", group="DATASET_INDEX")
        return None
    
    # Find the harvest session log (supports both naming patterns)
    log_files = list(log_dir.glob("*harvest_session*.log"))
    if not log_files:
        if verbose:
            logger.error(f"No harvest session log found in {log_dir}", group="DATASET_INDEX")
        return None
    
    # Use the most recent log file if multiple exist
    log_file = sorted(log_files, key=lambda f: f.stat().st_mtime, reverse=True)[0]
    if verbose:
        logger.info(f"Parsing log file: {log_file.name}", group="DATASET_INDEX")
    
    # Parse log file
    harvest_data = parse_harvest_log(log_file)
    
    # Scan for nested dataset runs and extract their statistics
    dataset_runs = []
    total_cves = 0
    total_warnings = 0
    total_errors = 0
    
    for item in run_directory.iterdir():
        if item.is_dir() and '_dataset_' in item.name:
            report_stats = parse_dataset_report_stats(item)
            if report_stats:
                # Extract source info from directory name pattern
                dir_name = item.name
                parts = dir_name.split('_dataset_')
                if len(parts) == 2:
                    source_identifier = parts[1].replace('_nvd-ish', '').replace('_', ' ')
                else:
                    source_identifier = dir_name
                
                # Generate report filename using dataset directory name
                report_filename = f"{item.name}_report.html"
                
                dataset_runs.append({
                    'directory': item.name,
                    'dataset_dir': item.name,
                    'report_filename': report_filename,
                    'source': source_identifier,
                    'total_cves': report_stats['total_cves'],
                    'processed_cves': report_stats['processed_cves'],
                    'warnings': report_stats['warnings'],
                    'errors': report_stats['errors'],
                    'status': report_stats['status'],
                    'runtime': f"{report_stats['runtime']:.1f}s"
                })
                
                total_cves += report_stats['processed_cves']
                total_warnings += report_stats['warnings']
                total_errors += report_stats['errors']
    
    # Add dataset run information to harvest data
    harvest_data['dataset_runs'] = sorted(dataset_runs, key=lambda x: x['directory'])
    harvest_data['total_cves_processed'] = total_cves
    harvest_data['total_warnings'] = total_warnings
    harvest_data['total_errors'] = total_errors
    
    # Load template
    template_path = project_root / "src" / "analysis_tool" / "static" / "templates" / "Generate_Dataset_Index_Template.html"
    if not template_path.exists():
        if verbose:
            logger.error(f"Template not found: {template_path}", group="DATASET_INDEX")
        return None
    
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    
    # Prepare JSON data for injection
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
            if verbose:
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
        if verbose:
            logger.warning(f"Failed to copy CSS file: {e}", group="DATASET_INDEX")
    
    output_file = reports_dir / "dataset_index.html"
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        if verbose:
            logger.debug(f"Generated dataset index: {output_file}", group="DATASET_INDEX")
        return output_file
        
    except Exception as e:
        if verbose:
            logger.error(f"Failed to write HTML file: {e}", group="DATASET_INDEX")
        return None


def generate_all(run_directory: Optional[Path] = None, verbose: bool = True) -> bool:
    """
    Generate both index and all dataset reports for a harvest run.
    
    Args:
        run_directory: Path to run directory. If None, finds most recent harvest run.
        verbose: If True, log info messages.
        
    Returns:
        True if all generation succeeded, False otherwise
    """
    project_root = get_analysis_tools_root()
    
    # Find run directory if not provided
    if run_directory is None:
        runs_dir = project_root / "runs"
        harvest_runs = sorted([
            d for d in runs_dir.iterdir() 
            if d.is_dir() and '_harvest_' in d.name
        ], reverse=True)
        
        if not harvest_runs:
            if verbose:
                logger.error("No harvest run directories found")
            return False
        
        run_directory = harvest_runs[0]
        if verbose:
            logger.info(f"Using most recent harvest run: {run_directory.name}")
    
    run_directory = Path(run_directory)
    
    # Generate all dataset reports
    if verbose:
        logger.info("Generating dataset reports...")
    
    dataset_dirs = [d for d in run_directory.iterdir() if d.is_dir() and '_dataset_' in d.name]
    report_count = 0
    
    for dataset_dir in dataset_dirs:
        if generate_dataset_report(dataset_dir, verbose=False):
            report_count += 1
    
    if verbose:
        logger.info(f"Generated {report_count}/{len(dataset_dirs)} dataset reports")
    
    # Generate index
    if verbose:
        logger.info("Generating dataset index...")
    
    index_file = generate_dataset_index(run_directory, verbose=verbose)
    
    if index_file:
        if verbose:
            logger.info(f"✓ All reports generated successfully")
        return True
    else:
        return False


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """CLI entry point with subcommands"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate Dataset Reports - Unified CLI for dataset generation reporting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Subcommands:
  index     Generate session index (lists all datasets in a harvest run)
  report    Generate individual dataset report
  all       Generate everything (index + all dataset reports)

Examples:
  # Generate index for most recent harvest run
  python -m src.analysis_tool.reporting.generate_dataset_report index
  
  # Generate index for specific run
  python -m src.analysis_tool.reporting.generate_dataset_report index --run-id 2026-01-03_14-29-00_harvest_general_nvd_ish_only
  
  # Generate individual dataset report
  python -m src.analysis_tool.reporting.generate_dataset_report report runs/2026-01-03_14-29-00_harvest_general_nvd_ish_only/2026-01-03_14-29-03_dataset_Foxit_nvd-ish
  
  # Generate all reports for a harvest run
  python -m src.analysis_tool.reporting.generate_dataset_report all --run-id 2026-01-03_14-29-00_harvest_general_nvd_ish_only
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Subcommand to execute')
    
    # Index subcommand
    index_parser = subparsers.add_parser('index', help='Generate session index page')
    index_parser.add_argument('--run-id', help='Run directory name (e.g., 2026-01-03_14-29-00_harvest_general_nvd_ish_only)')
    
    # Report subcommand
    report_parser = subparsers.add_parser('report', help='Generate individual dataset report')
    report_parser.add_argument('dataset_dir', type=Path, help='Path to dataset run directory')
    report_parser.add_argument('--quiet', action='store_true', help='Suppress output messages')
    
    # All subcommand
    all_parser = subparsers.add_parser('all', help='Generate index and all dataset reports')
    all_parser.add_argument('--run-id', help='Run directory name (e.g., 2026-01-03_14-29-00_harvest_general_nvd_ish_only)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Handle index subcommand
    if args.command == 'index':
        run_directory = None
        if args.run_id:
            project_root = get_analysis_tools_root()
            run_directory = project_root / "runs" / args.run_id
            if not run_directory.exists():
                logger.error(f"Run directory not found: {run_directory}", group="DATASET_INDEX")
                sys.exit(1)
        
        output_file = generate_dataset_index(run_directory, verbose=True)
        
        if output_file:
            print(f"✓ Dataset index generated: {output_file}")
            sys.exit(0)
        else:
            print("✗ Failed to generate dataset index")
            sys.exit(1)
    
    # Handle report subcommand
    elif args.command == 'report':
        success = generate_dataset_report(args.dataset_dir, verbose=not args.quiet)
        sys.exit(0 if success else 1)
    
    # Handle all subcommand
    elif args.command == 'all':
        run_directory = None
        if args.run_id:
            project_root = get_analysis_tools_root()
            run_directory = project_root / "runs" / args.run_id
            if not run_directory.exists():
                logger.error(f"Run directory not found: {run_directory}")
                sys.exit(1)
        
        success = generate_all(run_directory, verbose=True)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
