#!/usr/bin/env python3
"""
NVD Source UUID Harvester and Dataset Processor
This script fetches all source UUIDs from the NVD sources API and processes them
through generate_dataset.py with the specified parameters.
"""

import requests
import json
import subprocess
import sys
import argparse
import time
import os
from pathlib import Path
from datetime import datetime, timezone

# Initialize WorkflowLogger and run organization
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from analysis_tool.logging.workflow_logger import get_logger
from analysis_tool.storage.run_organization import create_run_directory, get_current_run_paths
from analysis_tool.core.gatherData import checkSourceCVECount, harvestSourceUUIDs

logger = get_logger()

# Global reference to active subprocess for interrupt handling
_active_subprocess = None


def get_analysis_tools_root():
    """Get the absolute path to the Analysis_Tools project root"""
    current_file = Path(__file__).resolve()
    return current_file.parent


def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'src', 'analysis_tool', 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)


def initialize_source_manager_for_harvest(api_key):
    """
    Initialize NVD source manager for harvest session.
    This ensures source data is loaded once and cached for all subprocess calls.
    Uses get_or_refresh_source_manager() for consistent cache management.
    
    Raises:
        ValueError: If API key is invalid or source data cannot be fetched
        RuntimeError: If initialization fails for any other reason
    """
    logger.info("Initializing NVD source manager for harvest session...", group="CACHE_MANAGEMENT")
    
    sys.path.insert(0, str(get_analysis_tools_root() / "src"))
    from analysis_tool.storage.nvd_source_manager import get_or_refresh_source_manager
    
    # Initialize source manager - fails fast if unable to initialize
    source_manager = get_or_refresh_source_manager(api_key, log_group="CACHE_MANAGEMENT")
    
    logger.info(f"Source manager initialized with {source_manager.get_source_count()} sources", 
               group="CACHE_MANAGEMENT")


def run_generate_dataset(source_name, source_uuid, allow_logging=True, 
                         parent_run_dir=None, **kwargs):
    """
    Run generate_dataset.py for a specific source UUID
    
    Args:
        source_name (str): Human-readable source name for logging
        source_uuid (str): UUID of the source to process
        allow_logging (bool): Whether to allow console logging to pass through
        parent_run_dir (Path): Parent run directory for hierarchical organization (harvest run directory)
        **kwargs: All processed parameters to pass to generate_dataset.py
        
    Returns:
        Tuple of (success: bool, run_dir: str or None, error_type: str or None, statistics: dict or None) - 
        success status, dataset run directory path, error type if failed, and statistics dict from subprocess
    """
    project_root = get_analysis_tools_root()
    generate_script = project_root / "generate_dataset.py"
    
    # Build command
    cmd = [
        sys.executable, # Unbuffered output (interpreter flag)
        "-u",           # -u is mandatory Python interpreter flag (not a script parameter) for unbuffered stdout/stderr
                        # Required for real-time log streaming through subprocess.PIPE
        str(generate_script),
        "--api-key", kwargs['api_key'],
        "--source-uuid", source_uuid
    ]
    
    # Add parent run directory for hierarchical organization
    if parent_run_dir:
        cmd.extend(["--parent-run-dir", str(parent_run_dir)])
    
    # Add feature flags (only add flags that are true)
    if kwargs['sdc_report']:
        cmd.extend(["--sdc-report"])
    if kwargs['cpe_determination']:
        cmd.extend(["--cpe-determination"])
    if kwargs['alias_report']:
        cmd.extend(["--alias-report"])
    if kwargs['cpe_as_generator']:
        cmd.extend(["--cpe-as-generator"])
    if kwargs['nvd_ish_only']:
        cmd.extend(["--nvd-ish-only"])
    
    # Add optional parameters only if they exist
    if kwargs.get('external_assets'):
        cmd.extend(["--external-assets"])
    
    if 'statuses' in kwargs:
        cmd.extend(["--statuses"] + kwargs['statuses'])
    
    if 'last_days' in kwargs:
        cmd.extend(["--last-days", str(kwargs['last_days'])])
    
    if 'start_date' in kwargs:
        cmd.extend(["--start-date", kwargs['start_date']])
    
    if 'end_date' in kwargs:
        cmd.extend(["--end-date", kwargs['end_date']])
    
    logger.info(f"{'='*60}", group="HARVEST")
    logger.info(f"Processing source: {source_name}", group="HARVEST")
    logger.info(f"UUID: {source_uuid}", group="HARVEST")
    logger.debug(f"Command: {' '.join(cmd)}", group="HARVEST")
    logger.info(f"{'='*60}", group="HARVEST")
    
    try:
        # Stream output in real-time while capturing needed information
        dataset_run_dir = None
        statistics = None
        process = subprocess.Popen(cmd, cwd=project_root,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, bufsize=1)
        
        # Store global reference for interrupt handling
        global _active_subprocess
        _active_subprocess = process
        
        # Process stdout line by line in real-time
        for line in process.stdout:
            # Extract run directory if present
            if 'Run directory:' in line:
                dataset_run_dir = line.split('Run directory:', 1)[1].strip()
            
            # Extract statistics output from subprocess
            if line.startswith('DATASET_STATS:'):
                try:
                    stats_json = line.split('DATASET_STATS:', 1)[1].strip()
                    statistics = json.loads(stats_json)
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse dataset statistics: {e}", group="HARVEST")
            
            # Display output in real-time if logging enabled
            if allow_logging:
                print(line, end='')
        
        # Wait for process to complete
        return_code = process.wait()
        
        # Handle any stderr output
        stderr_output = process.stderr.read()
        if allow_logging and stderr_output:
            print(stderr_output, end='', file=sys.stderr)
        
        # Clear global subprocess reference
        _active_subprocess = None
        
        if return_code != 0:
            raise subprocess.CalledProcessError(return_code, cmd, '', stderr_output)
        
        logger.info(f"[SUCCESS] Successfully processed {source_name}", group="HARVEST")
        
        # Update harvest index after successful processing
        if parent_run_dir:
            try:
                from analysis_tool.reporting.generate_dataset_report import update_harvest_index_incremental
                update_harvest_index_incremental(parent_run_dir, {}, current_source_info=None)
            except Exception as e:
                logger.warning(f"Failed to update harvest index after successful processing (non-critical): {e}", group="HARVEST")
        
        return True, dataset_run_dir, None, statistics
        
    except subprocess.CalledProcessError as e:
        # Clear global subprocess reference on error
        _active_subprocess = None
        logger.error(f"Error processing {source_name}: {e}", group="HARVEST")
        error_type = f"Exit code {e.returncode}"
        return False, dataset_run_dir, error_type, None
    except Exception as e:
        # Clear global subprocess reference on error
        _active_subprocess = None
        logger.error(f"Unexpected error processing {source_name}: {e}", group="HARVEST")
        error_type = f"Unexpected: {type(e).__name__}"
        
        # Update harvest index after error
        if parent_run_dir:
            try:
                from analysis_tool.reporting.generate_dataset_report import update_harvest_index_incremental
                update_harvest_index_incremental(parent_run_dir, {}, current_source_info=None)
            except Exception as e:
                logger.warning(f"Failed to update harvest index after error (non-critical): {e}", group="HARVEST")
        
        return False, None, error_type, None


def main():
    parser = argparse.ArgumentParser(
        description='Harvest NVD source UUIDs and process them through generate_dataset.py'
    )
    
    # Load configuration first to get defaults
    try:
        config = load_config()
        harvest_config = config.get('harvest_and_process_sources', {})
        defaults_config = config.get('defaults', {})
        local_cve_config = config.get('cache_settings', {}).get('cve_list_v5', {})
    except Exception as e:
        logger.warning(f"Could not load config file: {e}", group="INIT")
        harvest_config = {}
        defaults_config = {}
        local_cve_config = {}
    
    # Tool Output - Feature flags
    output_group = parser.add_argument_group('Tool Output', 'Select which analysis outputs to generate')
    output_group.add_argument(
        "--sdc-report",
        nargs='?',
        const='true',
        choices=['true', 'false'],
        help="Generate Source Data Concerns report (default: false, true if flag provided without value)"
    )
    output_group.add_argument(
        "--cpe-determination",
        nargs='?',
        const='true', 
        choices=['true', 'false'],
        help="Generate CPE suggestions via NVD CPE API calls (default: false, true if flag provided without value)"
    )
    output_group.add_argument(
        "--alias-report",
        nargs='?',
        const='true',
        choices=['true', 'false'],
        help="Enable alias report generation for curator functionality (default: false, true if flag provided without value)"
    )
    output_group.add_argument(
        "--cpe-as-generator",
        nargs='?',
        const='true',
        choices=['true', 'false'],
        help="Generate CPE Applicability Statements as interactive HTML pages (default: false, true if flag provided without value)"
    )
    output_group.add_argument(
        "--nvd-ish-only",
        nargs='?',
        const='true',
        choices=['true', 'false'],
        help="Generate complete NVD-ish enriched records without report files or HTML (ignores other output flags)"
    )
    
    # Dataset Generation - Parameters passed to generate_dataset.py
    dataset_group = parser.add_argument_group('Dataset Generation', 'Control CVE data selection and dataset creation')
    dataset_group.add_argument(
        "--api-key",
        nargs='?',
        const='CONFIG_DEFAULT',
        help="NVD API key. Use without value to use config default, or provide explicit key"
    )
    dataset_group.add_argument(
        "--external-assets",
        action="store_true",
        help="Enable external assets in analysis"
    )
    dataset_group.add_argument(
        "--statuses",
        nargs='*',
        help="Vulnerability statuses to include"
    )
    dataset_group.add_argument(
        "--last-days",
        type=int,
        help="Generate dataset for CVEs modified in the last N days"
    )
    dataset_group.add_argument(
        "--start-date",
        type=str,
        help="Start date for lastModified filter (YYYY-MM-DD or ISO format)"
    )
    dataset_group.add_argument(
        "--end-date",
        type=str,
        help="End date for lastModified filter (YYYY-MM-DD or ISO format)"
    )
    
    # Harvest Control - Parameters only relevant to this script
    harvest_group = parser.add_argument_group('Harvest Control', 'Control source harvesting behavior')
    harvest_group.add_argument(
        "--quiet-individual",
        action="store_true",
        default=harvest_config.get('quiet_individual', False),
        help=f"Don't show individual generate_dataset.py output (default: {harvest_config.get('quiet_individual', False)})"
    )
    harvest_group.add_argument(
        "--max-cves",
        type=int,
        default=harvest_config.get('max_cves_per_source', 5000),
        help=f"Maximum number of CVEs a source can have before being skipped (default: {harvest_config.get('max_cves_per_source', 5000)})"
    )
    
    args = parser.parse_args()
    
    # === FEATURE FLAG VALIDATION ===
    # Ensure at least one tool output feature is enabled (or nvd-ish-only mode)
    feature_flags = ['sdc_report', 'cpe_determination', 'alias_report', 'cpe_as_generator', 'nvd_ish_only']
    enabled_features = []
    
    for flag in feature_flags:
        flag_value = getattr(args, flag, None)
        if flag_value is not None and flag_value.lower() == 'true':
            enabled_features.append(flag.replace('_', '-'))
    
    if not enabled_features:
        logger.error("At least one feature must be enabled for harvest processing!", group="HARVEST")
        logger.info("Available features:", group="HARVEST")
        logger.info("  --sdc-report               : Generate Source Data Concerns report", group="HARVEST")
        logger.info("  --cpe-determination          : Generate CPE suggestions via NVD CPE API calls", group="HARVEST")
        logger.info("  --alias-report             : Generate alias report via curator features", group="HARVEST")
        logger.info("  --cpe-as-generator         : Generate CPE Applicability Statements as interactive HTML pages", group="HARVEST")
        logger.info("  --nvd-ish-only             : Generate complete NVD-ish enriched records without report files or HTML", group="HARVEST")
        logger.info("", group="HARVEST")
        logger.info("Example usage:", group="HARVEST")
        logger.info("  python harvest_and_process_sources.py --sdc-report", group="HARVEST")
        logger.info("  python harvest_and_process_sources.py --cpe-determination --cpe-as-generator", group="HARVEST")
        logger.info("  python harvest_and_process_sources.py --nvd-ish-only", group="HARVEST")
        logger.stop_file_logging()
        sys.exit(1)
    
    # === INTELLIGENT PARAMETER HANDLING ===
    
    # Process Tool Output parameters (always pass explicit boolean values)
    processed_params = {}
    
    # Handle boolean flags - convert to explicit true/false
    for flag in ['sdc_report', 'cpe_determination', 'alias_report', 'cpe_as_generator', 'nvd_ish_only']:
        flag_value = getattr(args, flag, None)
        if flag_value is not None:
            # Parameter provided - convert to boolean and pass with explicit value
            processed_params[flag] = flag_value.lower() == 'true' if isinstance(flag_value, str) else flag_value
        else:
            # No parameter provided - pass as false
            processed_params[flag] = False
    
    # Validate that at least one feature is enabled (including nvd-ish-only)
    feature_enabled = any(processed_params[flag] for flag in ['sdc_report', 'cpe_determination', 'alias_report', 'cpe_as_generator', 'nvd_ish_only'])
    if not feature_enabled:
        logger.error("At least one feature must be enabled for harvest processing!", group="HARVEST")
        logger.info("Available features:", group="HARVEST")
        logger.info("  --sdc-report               : Generate Source Data Concerns report", group="HARVEST")
        logger.info("  --cpe-determination          : Generate CPE suggestions via NVD CPE API calls", group="HARVEST")
        logger.info("  --alias-report             : Generate alias report via curator features", group="HARVEST")
        logger.info("  --cpe-as-generator         : Generate CPE Applicability Statements as interactive HTML pages", group="HARVEST")
        logger.info("  --nvd-ish-only             : Generate complete NVD-ish enriched records without report files or HTML", group="HARVEST")
        logger.info("", group="HARVEST")
        logger.info("Example usage:", group="HARVEST")
        logger.info("  python harvest_and_process_sources.py --sdc-report", group="HARVEST")
        logger.info("  python harvest_and_process_sources.py --cpe-determination --cpe-as-generator", group="HARVEST")
        logger.info("  python harvest_and_process_sources.py --nvd-ish-only", group="HARVEST")
        logger.stop_file_logging()
        sys.exit(1)
    
    # Handle API key with intelligent config resolution
    api_key = None
    if args.api_key == 'CONFIG_DEFAULT':
        # Parameter provided without value - check config
        config_key = defaults_config.get('default_api_key')
        if config_key:
            api_key = config_key
        else:
            logger.error("API key is required for source harvesting and processing", group="HARVEST")
            logger.info("No API key found in config.json default_api_key setting", group="HARVEST")
            logger.info("Either provide --api-key <key> or set default_api_key in config.json", group="HARVEST")
            logger.stop_file_logging()
            sys.exit(1)
    elif args.api_key:
        # Parameter provided with value - validate and use
        api_key = args.api_key
    else:
        # No parameter provided - check config
        config_key = defaults_config.get('default_api_key')
        if config_key:
            api_key = config_key
        else:
            logger.error("API key is required for source harvesting and processing", group="HARVEST")
            logger.info("Either use --api-key parameter or set default_api_key in config.json", group="HARVEST")
            logger.info("NVD API without a key has severe rate limits that make processing impractical", group="HARVEST")
            logger.stop_file_logging()
            sys.exit(1)
    
    processed_params['api_key'] = api_key
    
    # Handle local CVE repo with intelligent config resolution
    # Handle external assets
    if args.external_assets:
        processed_params['external_assets'] = True
    
    # Handle statuses with validation
    if hasattr(args, 'statuses') and args.statuses is not None:
        if len(args.statuses) == 0:
            # Parameter provided but no values - warn and don't pass
            logger.warning("--statuses parameter provided without values, ignoring. Will default to 'all statuses'", group="HARVEST")
        else:
            # Validate status values
            valid_statuses = ['Received', 'Awaiting Analysis', 'Undergoing Analysis', 'Modified', 'Published', 'Rejected']
            invalid_statuses = [s for s in args.statuses if s not in valid_statuses]
            if invalid_statuses:
                logger.error(f"Invalid status values: {invalid_statuses}", group="HARVEST")
                logger.info(f"Valid statuses are: {valid_statuses}", group="HARVEST")
                logger.stop_file_logging()
                sys.exit(1)
            processed_params['statuses'] = args.statuses
    
    # Handle date parameters with validation
    for date_param in ['last_days', 'start_date', 'end_date']:
        value = getattr(args, date_param, None)
        if value is not None:
            if date_param == 'last_days':
                if value <= 0:
                    logger.error(f"--last-days must be a positive integer, got: {value}", group="HARVEST")
                    logger.stop_file_logging()
                    sys.exit(1)
                processed_params[date_param] = value
            elif date_param in ['start_date', 'end_date']:
                # Basic date format validation
                try:
                    from datetime import datetime as dt_parser
                    # Try parsing as YYYY-MM-DD first, then ISO format
                    if len(value) == 10 and value.count('-') == 2:
                        dt_parser.strptime(value, '%Y-%m-%d')
                    else:
                        dt_parser.fromisoformat(value.replace('Z', '+00:00'))
                    processed_params[date_param] = value
                except ValueError:
                    logger.error(f"Invalid date format for --{date_param.replace('_', '-')}: {value}", group="HARVEST")
                    logger.info("Use YYYY-MM-DD or ISO format (e.g., 2024-01-01 or 2024-01-01T00:00:00Z)", group="HARVEST")
                    logger.stop_file_logging()
                    sys.exit(1)
        # If parameter provided without value, warn and don't pass
        elif hasattr(args, date_param) and getattr(args, date_param) == '':
            logger.warning(f"--{date_param.replace('_', '-')} parameter provided without value, ignoring", group="HARVEST")
    
    # Create harvest run directory
    enabled_features_str = "_".join(enabled_features)
    harvest_context = f"harvest_{enabled_features_str}"
    run_directory, run_id = create_run_directory(
        run_context=harvest_context,
        execution_type="harvest",
        tool_flags={feat.replace('-', '_'): True for feat in enabled_features},
        subdirs=["logs"]  # Harvest runs only need logs, no generated_pages
    )
    run_paths = get_current_run_paths(run_id)
    
    # Start file logging to run's logs directory
    logger.set_run_logs_directory(str(run_paths['logs']))
    logger.start_file_logging("generate_dataset")
    
    # Track session start time for duration calculation
    session_start_time = datetime.now(timezone.utc)
    
    logger.stage_start("NVD Source Harvester & Dataset Processor", "Initializing multi-source processing", group="HARVEST")
    logger.info("="*60, group="HARVEST")
    logger.info(f"Run directory: {run_directory}", group="HARVEST")
    logger.info(f"Run ID: {run_id}", group="HARVEST")
    logger.info(f"Using API key for enhanced rate limits", group="HARVEST")
    
    # Harvest source UUIDs
    source_info, api_totals = harvestSourceUUIDs()
    
    if not source_info:
        logger.warning("No source UUIDs found to process", group="HARVEST")
        logger.stop_file_logging()
        sys.exit(1)
    
    # Initialize source manager for harvest session and subprocesses
    initialize_source_manager_for_harvest(processed_params['api_key'])
    
    # Create initial harvest index with metadata before processing starts
    logger.info("Initializing harvest index...", group="HARVEST")
    try:
        from analysis_tool.reporting.generate_dataset_report import update_harvest_index_incremental
        # Create initial index with all sources marked as not_processed
        initial_sources = []
        for source_name, source_uuid, last_modified in source_info:
            initial_sources.append({
                'name': source_name,
                'uuid': source_uuid,
                'status': 'not_processed',
                'details': 'Source was in queue but never processed'
            })
        
        initial_stats = {
            'session_start': session_start_time.isoformat(),
            'session_end': None,
            'duration': 'In Progress',
            'status': 'In Progress',
            'total_sources': len(source_info),
            'successful': 0,
            'failed': 0,
            'skipped': 0,
            'interrupted': 0,
            'not_processed': len(source_info),  # All sources start as not_processed
            'sources': initial_sources
        }
        update_harvest_index_incremental(run_directory, initial_stats)
        logger.info("Harvest index initialized with all sources", group="HARVEST")
    except Exception as e:
        logger.warning(f"Could not initialize harvest index: {e}", group="HARVEST")
    
    # Process each source
    logger.stage_start("Multi-Source Processing", f"Processing {len(source_info)} sources", group="HARVEST")
    logger.info(f"{'='*60}", group="HARVEST")
    
    skipped_sources = []
    failed_sources = []
    successful_sources = []
    not_processed_sources = []
    last_processed_index = -1
    termination_reason = None
    current_source_info = None
    
    try:
        for i, (source_name, source_uuid, last_modified) in enumerate(source_info, 1):
            last_processed_index = i - 1  # Update to current index (0-based)
            logger.stage_progress(current=i, total=len(source_info), item=f"{source_name} (modified: {last_modified})", group="HARVEST")
            
            # Check CVE count first
            cve_count, should_skip = checkSourceCVECount(source_uuid, processed_params['api_key'], args.max_cves)
            
            # Track current source being processed
            current_source_info = (source_name, source_uuid)
            
            # Update harvest index to show this source as in progress
            try:
                from analysis_tool.reporting.generate_dataset_report import update_harvest_index_incremental
                update_harvest_index_incremental(run_directory, {}, current_source_info=current_source_info)
            except Exception as e:
                logger.warning(f"Failed to mark source as in-progress in harvest index (non-critical): {e}", group="HARVEST")
            
            if should_skip:
                logger.info(f"Skipped {source_name} (too many CVEs: {cve_count:,})", group="HARVEST")
                skipped_sources.append((source_name, source_uuid, cve_count))
            else:
                success, dataset_run_dir, error_type, statistics = run_generate_dataset(
                    source_name=source_name,
                    source_uuid=source_uuid,
                    allow_logging=not args.quiet_individual,
                    parent_run_dir=run_directory,
                    **processed_params
                )
                
                if success:
                    # Use statistics returned from subprocess (in-memory data, no file parsing needed)
                    if statistics:
                        cve_info = (statistics['processed_cves'], statistics['total_cves'])
                        warnings_count = statistics['warnings']
                        errors_count = statistics['errors']
                        runtime = statistics['runtime']
                    else:
                        # No statistics available - shouldn't happen for successful runs but handle gracefully
                        logger.warning(f"No statistics returned for successful source {source_name}", group="HARVEST")
                        cve_info = (cve_count, cve_count) if cve_count is not None else None
                        warnings_count = 0
                        errors_count = 0
                        runtime = 0
                    
                    successful_sources.append((source_name, source_uuid, cve_info, dataset_run_dir, warnings_count, errors_count, runtime))
                    # Provide audit trail to detailed dataset logs
                    if dataset_run_dir:
                        logger.info(f"Dataset logs available at: {dataset_run_dir}", group="HARVEST")
                    
                    # Update harvest index with completed source data
                    try:
                        from analysis_tool.reporting.generate_dataset_report import update_harvest_index_incremental
                        # Build incremental harvest_statistics with completed sources so far
                        current_time = datetime.now(timezone.utc)
                        elapsed = current_time - session_start_time
                        hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
                        minutes, seconds = divmod(remainder, 60)
                        duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                        incremental_stats = {
                            'sources': [],
                            'total_sources': len(source_info),
                            'successful': len(successful_sources),
                            'failed': len(failed_sources),
                            'skipped': len(skipped_sources),
                            'interrupted': 0,
                            'not_processed': len(source_info) - (len(successful_sources) + len(failed_sources) + len(skipped_sources)),
                            'session_start': session_start_time.isoformat(),
                            'session_end': current_time.isoformat(),
                            'duration': duration_str,
                            'status': 'In Progress'
                        }
                        # Add all successful sources processed so far
                        for src_name, src_uuid, src_cve_info, src_dir, src_warnings, src_errors, src_runtime in successful_sources:
                            incremental_stats['sources'].append({
                                'name': src_name,
                                'uuid': src_uuid,
                                'status': 'completed',
                                'details': 'Successfully processed',
                                'cve_info': src_cve_info,
                                'dataset_run_dir': src_dir,
                                'warnings': src_warnings,
                                'errors': src_errors,
                                'runtime': src_runtime
                            })
                        # Add all failed sources so far - use whatever statistics were captured before failure
                        for src_name, src_uuid, src_cve_info, src_error, src_dir, src_warnings, src_errors, src_runtime in failed_sources:
                            details = f"Failed: {src_error}" if src_error else "Failed"
                            incremental_stats['sources'].append({
                                'name': src_name,
                                'uuid': src_uuid,
                                'status': 'failed',
                                'details': details,
                                'cve_info': src_cve_info,
                                'dataset_run_dir': src_dir,
                                'warnings': src_warnings,
                                'errors': src_errors,
                                'runtime': src_runtime
                            })
                        # Add all skipped sources so far
                        for src_name, src_uuid, src_cve_count in skipped_sources:
                            incremental_stats['sources'].append({
                                'name': src_name,
                                'uuid': src_uuid,
                                'status': 'skipped',
                                'details': f"Exceeded --max-cves {args.max_cves} threshold",
                                'cve_info': src_cve_count
                            })
                        update_harvest_index_incremental(run_directory, incremental_stats)
                    except Exception as e:
                        logger.warning(f"Failed to update harvest index with completed source data (non-critical): {e}", group="HARVEST")
                else:
                    # Track failed source with statistics if available from subprocess
                    if statistics:
                        cve_info = (statistics['processed_cves'], statistics['total_cves'])
                        warnings_count = statistics['warnings']
                        errors_count = statistics['errors']
                        runtime = statistics['runtime']
                    else:
                        # No statistics available - failure occurred before stats could be generated
                        cve_info = (0, cve_count) if cve_count is not None else None
                        warnings_count = 0
                        errors_count = 0
                        runtime = 0
                    
                    failed_sources.append((source_name, source_uuid, cve_info, error_type, dataset_run_dir, warnings_count, errors_count, runtime))
                    
                    # Update harvest index with failed source data
                    try:
                        from analysis_tool.reporting.generate_dataset_report import update_harvest_index_incremental
                        # Build incremental harvest_statistics with all sources so far
                        current_time = datetime.now(timezone.utc)
                        elapsed = current_time - session_start_time
                        hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
                        minutes, seconds = divmod(remainder, 60)
                        duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                        incremental_stats = {
                            'sources': [],
                            'total_sources': len(source_info),
                            'successful': len(successful_sources),
                            'failed': len(failed_sources),
                            'skipped': len(skipped_sources),
                            'interrupted': 0,
                            'not_processed': len(source_info) - (len(successful_sources) + len(failed_sources) + len(skipped_sources)),
                            'session_start': session_start_time.isoformat(),
                            'session_end': current_time.isoformat(),
                            'duration': duration_str,
                            'status': 'In Progress'
                        }
                        # Add all successful sources processed so far
                        for src_name, src_uuid, src_cve_info, src_dir, src_warnings, src_errors, src_runtime in successful_sources:
                            incremental_stats['sources'].append({
                                'name': src_name,
                                'uuid': src_uuid,
                                'status': 'completed',
                                'details': "Successfully processed",
                                'cve_info': src_cve_info,
                                'dataset_run_dir': src_dir,
                                'warnings': src_warnings,
                                'errors': src_errors,
                                'runtime': src_runtime
                            })
                        # Add all failed sources so far - use whatever statistics were captured before failure
                        for src_name, src_uuid, src_cve_info, src_error, src_dir, src_warnings, src_errors, src_runtime in failed_sources:
                            details = f"Failed: {src_error}" if src_error else "Failed"
                            incremental_stats['sources'].append({
                                'name': src_name,
                                'uuid': src_uuid,
                                'status': 'failed',
                                'details': details,
                                'cve_info': src_cve_info,
                                'dataset_run_dir': src_dir,
                                'warnings': src_warnings,
                                'errors': src_errors,
                                'runtime': src_runtime
                            })
                        # Add all skipped sources so far
                        for src_name, src_uuid, src_cve_count in skipped_sources:
                            incremental_stats['sources'].append({
                                'name': src_name,
                                'uuid': src_uuid,
                                'status': 'skipped',
                                'details': f"Exceeded --max-cves {args.max_cves} threshold",
                                'cve_info': src_cve_count
                            })
                        update_harvest_index_incremental(run_directory, incremental_stats)
                    except Exception as e:
                        logger.warning(f"Failed to update harvest index with failed source data (non-critical): {e}", group="HARVEST")
            
            # Small delay between requests to be respectful to the API
            if i < len(source_info):  # Don't delay after the last one
                time.sleep(1)
                
    except KeyboardInterrupt:
        termination_reason = "Script interrupted"
        logger.warning("\nProcessing interrupted - terminating active subprocess...", group="HARVEST")
        
        # Terminate any active subprocess
        global _active_subprocess
        if _active_subprocess and _active_subprocess.poll() is None:
            _active_subprocess.terminate()
            try:
                _active_subprocess.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _active_subprocess.kill()
                _active_subprocess.wait()
        
    except SystemExit as e:
        termination_reason = "Script terminated"
        logger.error("", group="HARVEST")
        logger.error("="*60, group="HARVEST")
        logger.error("PROCESSING TERMINATED", group="HARVEST")
        logger.error("="*60, group="HARVEST")
        logger.error(f"Script terminated with exit code: {e.code}", group="HARVEST")
        
    except Exception as e:
        termination_reason = "Script crashed"
        logger.error("", group="HARVEST")
        logger.error("="*60, group="HARVEST")
        logger.error("PROCESSING CRASHED", group="HARVEST")
        logger.error("="*60, group="HARVEST")
        logger.error(f"Unexpected error: {e}", group="HARVEST")
        import traceback
        logger.error(f"Traceback:\n{traceback.format_exc()}", group="HARVEST")
    
    finally:
        # Handle source that was being processed when interrupted
        interrupted_source_info = None
        if termination_reason and current_source_info:
            # The current source was interrupted mid-processing
            interrupted_source_info = current_source_info  # (name, uuid)
        
        # Calculate not-processed sources (those that were never attempted)
        # last_processed_index is 0-based, so sources from index last_processed_index+1 onward were not attempted
        if last_processed_index < len(source_info) - 1:
            for j in range(last_processed_index + 1, len(source_info)):
                source_name, source_uuid, last_modified = source_info[j]
                not_processed_sources.append((source_name, source_uuid))
    
    # Summary
    logger.stage_end("Multi-Source Processing", f"{len(successful_sources)}/{len(source_info)} sources processed successfully", group="HARVEST")
    
    # If terminated early, show clear status
    if termination_reason:
        logger.warning(f"STATUS: {termination_reason.upper()}", group="HARVEST")
    else:
        logger.info(f"STATUS: PROCESSING COMPLETE", group="HARVEST")
    
    logger.info(f"Total sources from NVD API: {api_totals['total_from_api']}", group="HARVEST")
    logger.info(f"Sources filtered out (no UUID): {api_totals['sources_without_uuid']}", group="HARVEST")
    if api_totals['duplicates_found'] > 0:
        logger.info(f"Sources filtered out (duplicates): {api_totals['duplicates_found']}", group="HARVEST")
    logger.info(f"Sources available for processing: {api_totals['unique_sources_available']}", group="HARVEST")
    logger.info(f"Sources attempted: {len(successful_sources) + len(failed_sources) + len(skipped_sources)}", group="HARVEST")
    
    # Show not-processed and interrupted counts if any
    not_processed_count = len(not_processed_sources)
    interrupted_count = 1 if interrupted_source_info else 0
    if not_processed_count > 0:
        logger.warning(f"Sources not attempted (early termination): {not_processed_count}", group="HARVEST")
    if interrupted_count > 0:
        logger.warning(f"Sources interrupted mid-processing: {interrupted_count}", group="HARVEST")
    
    logger.data_summary("Processing Results", group="HARVEST",
        successful=len(successful_sources),
        failed=len(failed_sources),
        skipped_too_many_cves=len(skipped_sources),
        interrupted=interrupted_count,
        not_processed=not_processed_count,
        total_sources=len(source_info))
    
    # Report skipped sources details
    if skipped_sources:
        logger.info(f"SKIPPED SOURCES REPORT:", group="HARVEST")
        logger.info(f"The following {len(skipped_sources)} sources were skipped due to exceeding the CVE threshold of {args.max_cves:,}:", group="HARVEST")
        for source_name, source_uuid, cve_count in skipped_sources:
            logger.warning(f"{source_name}", group="HARVEST")
            logger.info(f"  UUID: {source_uuid}", group="HARVEST")
            logger.info(f"  CVE Count: {cve_count:,}", group="HARVEST")
    
    # Report failed sources details
    if failed_sources:
        logger.error(f"FAILED SOURCES REPORT:", group="HARVEST")
        logger.info(f"The following {len(failed_sources)} sources failed to process:", group="HARVEST")
        for source_name, source_uuid, cve_info, error_type, dataset_run_dir, warnings_count, errors_count, runtime in failed_sources:
            logger.error(f"{source_name}", group="HARVEST")
            logger.info(f"  UUID: {source_uuid}", group="HARVEST")
            if cve_info is not None:
                # cve_info is always (processed, total) tuple format
                processed, total = cve_info
                if processed == 0:
                    logger.info(f"  CVE Count: 0 of {total:,} (failed before processing started)", group="HARVEST")
                else:
                    logger.info(f"  CVE Count: {processed:,} of {total:,} (failed during processing)", group="HARVEST")
            else:
                logger.info(f"  CVE Count: Count not available (very early failure)", group="HARVEST")
            logger.info(f"  Error Type: {error_type}", group="HARVEST")
            if dataset_run_dir:
                logger.info(f"  Run Location: {dataset_run_dir}", group="HARVEST")
            else:
                logger.info(f"  Run Location: Not created (early failure)", group="HARVEST")
    
    # Report interrupted source (was being processed when script was interrupted)
    if interrupted_source_info:
        logger.warning(f"INTERRUPTED SOURCE REPORT:", group="HARVEST")
        logger.info(f"The following source was interrupted mid-processing:", group="HARVEST")
        source_name, source_uuid = interrupted_source_info
        logger.warning(f"{source_name}", group="HARVEST")
        logger.info(f"  UUID: {source_uuid}", group="HARVEST")
    
    # Report not-processed sources (never attempted due to early termination)
    if not_processed_sources:
        logger.warning(f"NOT PROCESSED SOURCES REPORT:", group="HARVEST")
        logger.info(f"The following {len(not_processed_sources)} sources were NEVER ATTEMPTED due to early termination:", group="HARVEST")
        for source_name, source_uuid in not_processed_sources:
            logger.warning(f"{source_name}", group="HARVEST")
            logger.info(f"  UUID: {source_uuid}", group="HARVEST")
    
    # Calculate session duration
    session_end_time = datetime.now(timezone.utc)
    duration_str = 'Unknown'
    if session_start_time:
        duration_sec = (session_end_time - session_start_time).total_seconds()
        hours = int(duration_sec // 3600)
        minutes = int((duration_sec % 3600) // 60)
        seconds = int(duration_sec % 60)
        duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    # Determine final session status
    if termination_reason:
        session_status = 'Interrupted - Early Termination'
    elif len(failed_sources) == 0 and len(successful_sources) > 0:
        session_status = 'Completed Successfully'
    elif len(failed_sources) > 0:
        session_status = f"Completed with {len(failed_sources)} Failures"
    else:
        session_status = 'Unknown'
    
    # Final harvest index and report generation
    logger.info("Finalizing harvest session reports...", group="HARVEST")
    try:
        # Import update function to finalize session metadata
        from analysis_tool.reporting.generate_dataset_report import update_harvest_index_incremental
        
        # Build final harvest statistics including interrupted and not_processed sources
        final_stats = {
            'sources': [],
            'session_end': session_end_time.isoformat(),
            'duration': duration_str,
            'status': session_status
        }
        
        # Mark interrupted source if early termination occurred during processing
        if interrupted_source_info:
            source_name, source_uuid = interrupted_source_info
            final_stats['sources'].append({
                'name': source_name,
                'uuid': source_uuid,
                'status': 'interrupted',
                'details': 'Early Termination',
                'cve_info': None
            })
        
        # Add not_processed sources as skipped with early termination reason
        for source_name, source_uuid in not_processed_sources:
            final_stats['sources'].append({
                'name': source_name,
                'uuid': source_uuid,
                'status': 'skipped',
                'details': 'Early Termination',
                'cve_info': None
            })
        
        update_harvest_index_incremental(run_directory, final_stats)
        logger.info("Harvest session data finalized", group="HARVEST")
    except Exception as e:
        logger.warning(f"Error finalizing harvest session data: {e}", group="HARVEST")
    
    # Determine exit status based on what happened
    if termination_reason:
        # Early termination - always exit with error
        logger.error(f"Harvest session ended: {termination_reason}", group="HARVEST")
        logger.warning(f"Summary: {len(successful_sources)} successful, {len(failed_sources)} failed, {len(skipped_sources)} skipped, {interrupted_count} interrupted, {not_processed_count} not processed", group="HARVEST")
        logger.stop_file_logging()
        sys.exit(1)
    elif len(failed_sources) > 0:
        # Completed but with failures
        logger.warning(f"{len(failed_sources)} sources failed to process. See FAILED SOURCES REPORT above for details.", group="HARVEST")
        logger.stop_file_logging()
        sys.exit(1)
    else:
        # Fully successful completion
        logger.info(f"All processable sources completed successfully! ({len(skipped_sources)} sources skipped due to size)", group="HARVEST")
        logger.stop_file_logging()
        sys.exit(0)

if __name__ == "__main__":
    main()