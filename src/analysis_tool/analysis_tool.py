#!/usr/bin/env python3
"""
CVE Processor Script

This script runs analysis_tool.py for a list of CVEs or processes all CVE records.
"""

import os
import sys
import argparse
from pathlib import Path
import re
import json
import time
from datetime import datetime, timedelta

import gatherData
import processData
import generateHTML

# Import the new logging system
from workflow_logger import (
    get_logger, LogGroup, LogLevel,
    start_initialization, end_initialization,
    start_cve_queries, end_cve_queries,
    start_unique_cpe_generation, end_unique_cpe_generation,
    start_cpe_queries, end_cpe_queries,
    start_confirmed_mappings, end_confirmed_mappings,
    start_page_generation, end_page_generation,
    start_audit, end_audit,
    log_init, log_cve_query, log_data_proc, log_page_gen
)

# Get logger instance
logger = get_logger()

# Load configuration
def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)

config = load_config()

def process_test_file(test_file_path, nvd_source_data):
    """Process a test file containing CVE data for testing modular rules."""
    log_init(f"Processing test file: {test_file_path}")
    
    # Clear global HTML state to prevent accumulation from previous processing
    generateHTML.clear_global_html_state()
    
    try:
        start_initialization("Test file processing")
        
        # Load test data from JSON file
        with open(test_file_path, 'r', encoding='utf-8') as f:
            test_data = json.load(f)
        
        # Extract CVE ID from test data
        cve_id = test_data.get('cveMetadata', {}).get('cveId', 'TEST-CVE-0000-0000')
        log_init(f"Test CVE ID: {cve_id}")
        
        # Make sure the string is formatted well
        cve_id = cve_id.strip().upper()
        processData.integrityCheckCVE("cveIdFormat", cve_id)
        
        # Create Primary Datasets from external sources
        primaryDataframe = gatherData.gatherPrimaryDataframe()        # Use test data as CVE record data (instead of API call)
        cveRecordData = test_data
        
        # Create minimal mock NVD record data for test files
        nvdRecordData = {
            "vulnerabilities": [{
                "cve": {
                    "id": cve_id,
                    "descriptions": [],
                    "references": [],
                    "configurations": []
                }
            }]
        }        
        
        end_initialization("Test file loaded")
        
        start_cve_queries("Processing test CVE data")
          # Process the vulnerability record data
        primaryDataframe, globalCVEMetadata = processData.processCVEData(primaryDataframe, cveRecordData, nvd_source_data)             
        primaryDataframe = processData.processNVDRecordData(primaryDataframe, nvdRecordData)
        
        end_cve_queries("Test CVE data processed")
        
        start_confirmed_mappings("Processing confirmed mappings")
        
        # Process confirmed mappings
        primaryDataframe = processData.process_confirmed_mappings(primaryDataframe)
        
        # Skip CPE suggestions for test files to avoid API calls
        # primaryDataframe = processData.suggestCPEData(nvd_api_key, primaryDataframe, 1)
        
        # For test files, ensure CPE data fields are proper dictionaries instead of empty lists
        for index, row in primaryDataframe.iterrows():
            if isinstance(primaryDataframe.at[index, 'sortedCPEsQueryData'], list):
                primaryDataframe.at[index, 'sortedCPEsQueryData'] = {}
            if isinstance(primaryDataframe.at[index, 'trimmedCPEsQueryData'], list):
                primaryDataframe.at[index, 'trimmedCPEsQueryData'] = {}
        
        end_confirmed_mappings("Confirmed mappings processed")
        
        start_page_generation("Generating HTML output")
        
        # Generate HTML
        primaryDataframe = generateHTML.update_cpeQueryHTML_column(primaryDataframe, nvd_source_data)
        
        # Clean up dataframe
        columns_to_drop = ['sourceID', 'sourceRole', 'rawPlatformData', 'rawCPEsQueryData', 
                          'sortedCPEsQueryData', 'trimmedCPEsQueryData', 'platformEntryMetadata']
        for col in columns_to_drop:
            primaryDataframe = primaryDataframe.drop(col, axis=1, errors='ignore')

        # Set column widths
        num_cols = len(primaryDataframe.columns)
        col_widths = ['20%', '80%'] if num_cols == 2 else [f"{100/num_cols}%"] * num_cols

        # Convert to HTML
        affectedHtml2 = primaryDataframe.to_html(
            classes='table table-stripped',
            col_space=col_widths,
            escape=False,
            index=False
        )

        # Format HTML headers
        if 'rowDataHTML' in primaryDataframe.columns:
            affectedHtml2 = re.sub(r'<th[^>]*>rowDataHTML</th>', 
                                  r'<th class="hidden-header" style="min-width: 20%;">rowDataHTML</th>', 
                                  affectedHtml2)

        if 'cpeQueryHTML' in primaryDataframe.columns:
            affectedHtml2 = re.sub(r'<th[^>]*>cpeQueryHTML</th>',                                  r'<th class="hidden-header" style="min-width: 80%;">cpeQueryHTML</th>', 
                                  affectedHtml2)
        
        # Generate page and save HTML
        allConsoleHTML = generateHTML.buildHTMLPage(affectedHtml2, cve_id, globalCVEMetadata)

        # Save output
        sub_directory = Path(f"{os.getcwd()}{os.sep}generated_pages")
        sub_directory.mkdir(parents=True, exist_ok=True)
        filename = f"{cve_id}.html"
        filepath = sub_directory / filename
        
        with filepath.open("w", encoding="utf-8") as fd:
            fd.write(allConsoleHTML)
        
        logger.file_operation("Generated", str(filepath), "test file", group="PAGE_GEN")
        end_page_generation("HTML file created")
        return filepath
        
    except Exception as e:
        logger.error(f"Test file processing failed: Unable to process test file '{test_file_path}' - {str(e)}", group="initialization")
        logger.debug(f"Error type: {type(e).__name__}", group="initialization")
        import traceback
        traceback.print_exc()
        return None

def process_cve(cve_id, nvd_api_key, nvd_source_data):
    """Process a single CVE using the analysis tool functionality."""
    
    # Clear global HTML state to prevent accumulation from previous CVEs
    generateHTML.clear_global_html_state()
    
    # Audit: Verify global state is properly cleared before processing
    audit_global_state_cleared()
    
    try:
        # Make sure the string is formatted well
        cve_id = cve_id.strip().upper()
        processData.integrityCheckCVE("cveIdFormat", cve_id)
        
        # Create Primary Datasets from external sources
        primaryDataframe = gatherData.gatherPrimaryDataframe()
        
        start_cve_queries(f"Gathering data for {cve_id}")
        
        log_init(f"Processing {cve_id}")

        # Gather CVE List Record and NVD Dataset Records for the target CVE
        cveRecordData = gatherData.gatherCVEListRecord(cve_id)
        
        # Check if CVE is in REJECTED state
        if cveRecordData and 'cveMetadata' in cveRecordData:
            state = cveRecordData.get('cveMetadata', {}).get('state')
            if state == 'REJECTED':
                logger.warning(f"{cve_id} is in REJECTED state - skipping processing", group="cve_queries")
                return None
        
        try:
            nvdRecordData = gatherData.gatherNVDCVERecord(nvd_api_key, cve_id)
        except Exception as api_error:
            # Handle specific NVD API errors
            error_str = str(api_error)
            if "Invalid cpeMatchstring parameter" in error_str:
                logger.warning(f"{cve_id} has invalid CPE match string - skipping processing", group="data_processing")
                logger.debug(f"Error: {error_str}", group="data_processing")
                return None
            else:
                # Re-raise other exceptions
                raise
        
        end_cve_queries("CVE data retrieved")
        
        start_unique_cpe_generation("Processing CVE and NVD data")
        
        # Process the vulnerability record data
        primaryDataframe, globalCVEMetadata = processData.processCVEData(primaryDataframe, cveRecordData, nvd_source_data)
        primaryDataframe = processData.processNVDRecordData(primaryDataframe, nvdRecordData)

        # Suggest CPE data based on collected information (includes internal CPE generation and query stages)
        try:
            primaryDataframe = processData.suggestCPEData(nvd_api_key, primaryDataframe, 1)
        except Exception as cpe_error:
            # Handle CPE suggestion errors
            logger.warning(f"CPE suggestion failed for {cve_id}: Unable to complete CPE data suggestion - {str(cpe_error)}", group="data_processing")
            logger.info("Continuing with available data...", group="data_processing")
        
        # Note: CPE generation and query stages are now handled internally by suggestCPEData
        
        start_confirmed_mappings("Processing confirmed mappings")

        # Process confirmed mappings
        try:
            primaryDataframe = processData.process_confirmed_mappings(primaryDataframe)
        except Exception as mapping_error:
            logger.warning(f"Confirmed mappings failed for {cve_id}: Unable to process confirmed mappings - {str(mapping_error)}", group="data_processing")
            logger.info("Continuing with available data...", group="data_processing")
            import traceback
            traceback.print_exc()

        end_confirmed_mappings("Confirmed mappings processed")
        
        start_page_generation("Generating HTML output")
        
        # Generate HTML
        primaryDataframe = generateHTML.update_cpeQueryHTML_column(primaryDataframe, nvd_source_data)
        
        # Clean up dataframe
        columns_to_drop = ['sourceID', 'sourceRole', 'rawPlatformData', 'rawCPEsQueryData', 
                          'sortedCPEsQueryData', 'trimmedCPEsQueryData', 'platformEntryMetadata']
        for col in columns_to_drop:
            primaryDataframe = primaryDataframe.drop(col, axis=1, errors='ignore')

        # Set column widths
        num_cols = len(primaryDataframe.columns)
        col_widths = ['20%', '80%'] if num_cols == 2 else [f"{100/num_cols}%"] * num_cols

        # Convert to HTML
        affectedHtml2 = primaryDataframe.to_html(
            classes='table table-stripped',
            col_space=col_widths,
            escape=False,
            index=False
        )

        # Format HTML headers
        if 'rowDataHTML' in primaryDataframe.columns:
            affectedHtml2 = re.sub(r'<th[^>]*>rowDataHTML</th>', 
                                  r'<th class="hidden-header" style="min-width: 20%;">rowDataHTML</th>', 
                                  affectedHtml2)

        if 'cpeQueryHTML' in primaryDataframe.columns:
            affectedHtml2 = re.sub(r'<th[^>]*>cpeQueryHTML</th>', 
                                  r'<th class="hidden-header" style="min-width: 80%;">cpeQueryHTML</th>', 
                                  affectedHtml2)

        # Generate page and save HTML
        allConsoleHTML = generateHTML.buildHTMLPage(affectedHtml2, cve_id, globalCVEMetadata)

        # Save output
        sub_directory = Path(f"{os.getcwd()}{os.sep}generated_pages")
        sub_directory.mkdir(parents=True, exist_ok=True)
        filename = f"{cve_id}.html"
        filepath = sub_directory / filename
        
        with filepath.open("w", encoding="utf-8") as fd:
            fd.write(allConsoleHTML)
        
        logger.file_operation("Generated", str(filepath), group="page_generation")
        end_page_generation("HTML file created")
        return {
            'success': True,
            'filepath': str(filepath)
        }
        
    except Exception as e:
        logger.error(f"CVE processing failed for {cve_id}: Unable to complete analysis workflow - {str(e)}", group="data_processing")
        return {
            'success': False,
            'error': str(e)
        }

def get_all_cves(nvd_api_key):
    """Get all CVEs from NVD API."""
    return gatherData.gatherAllCVEIDs(nvd_api_key)

def audit_global_state():
    """Audit global state for potential bloat accumulation"""
    try:
        from cpe_cache import get_global_cache_manager
        import generateHTML
        
        issues = []
          # Check CPE cache size
        cache_manager = get_global_cache_manager()
        if cache_manager.is_initialized():
            cache = cache_manager.get_cache()            
            cache_size = len(cache.cache_data) if hasattr(cache, 'cache_data') else 0
            if cache_size > 50000:  # Threshold for large cache - increased from 10000 to 50000
                issues.append(f"Large CPE cache: {cache_size} entries")
            else:
                logger.debug(f"CPE cache size: {cache_size} entries", group="CPE_QUERY")
        
        # Check HTML settings growth during processing (warn if excessive accumulation)
        html_settings_size = len(generateHTML.JSON_SETTINGS_HTML) if hasattr(generateHTML, 'JSON_SETTINGS_HTML') else 0
        intelligent_settings_size = len(generateHTML.INTELLIGENT_SETTINGS) if hasattr(generateHTML, 'INTELLIGENT_SETTINGS') else 0
        
        # These grow during processing, so only warn if extremely large (suggests memory leak)
        if html_settings_size > 1000:  # Very high threshold - indicates potential memory leak
            issues.append(f"Excessive HTML settings accumulation: {html_settings_size} entries")
        if intelligent_settings_size > 1000:  # Very high threshold - indicates potential memory leak
            issues.append(f"Excessive intelligent settings accumulation: {intelligent_settings_size} entries")
              # Report issues or all-clear
        if issues:            
            logger.warning(f"Global state bloat detected: {', '.join(issues)}", group="data_processing")
        else:
            logger.debug("Global state clean", group="data_processing")
            
        return len(issues) == 0
    except Exception as e:
        logger.debug(f"Global state audit failed: {e}", group="data_processing")
        return False

def audit_file_size(filepath, expected_max_kb=1000):
    """Audit generated file size for bloat detection"""
    try:
        if os.path.exists(filepath):
            file_size_kb = os.path.getsize(filepath) / 1024
            
            if file_size_kb > expected_max_kb:
                logger.warning(f"Large output file detected: {os.path.basename(filepath)} ({file_size_kb:.1f}KB > {expected_max_kb}KB)", group="page_generation")
                
                # If extremely large, provide more details
                if file_size_kb > expected_max_kb * 5:
                    logger.error(f"Extremely large file: {os.path.basename(filepath)} ({file_size_kb:.1f}KB) - investigate for bloat", group="page_generation")
                    
                return False
            else:
                logger.debug(f"File size normal: {os.path.basename(filepath)} ({file_size_kb:.1f}KB)", group="page_generation")
                return True
    except Exception as e:
        logger.debug(f"File size audit failed for {filepath}: {e}", group="data_processing")
        
    return True

def audit_cache_and_mappings_stats():
    """Audit cache hit rates and confirmed mappings statistics"""
    try:
        from cpe_cache import get_global_cache_manager
        import processData
        
        stats_info = []
        
        # Get CPE cache statistics
        cache_manager = get_global_cache_manager()
        if cache_manager.is_initialized():
            cache = cache_manager.get_cache()
            cache_stats = cache.get_stats()
            session_total = cache_stats['session_hits'] + cache_stats['session_misses']
            session_hit_rate = (cache_stats['session_hits'] / session_total * 100) if session_total > 0 else 0
            
            stats_info.append(f"CPE cache: {cache_stats['session_hits']}/{session_total} session hits ({session_hit_rate:.1f}%)")
            stats_info.append(f"CPE cache lifetime: {cache_stats['lifetime_hit_rate']}% hit rate, {cache_stats['lifetime_api_calls_saved']} API calls saved")
        else:
            stats_info.append("CPE cache: Not initialized")
          # Get confirmed mappings statistics
        try:
            mappings_stats = processData.get_confirmed_mappings_stats()
            if mappings_stats['total_processed'] > 0:
                stats_info.append(f"Confirmed mappings: {mappings_stats['successful_mappings']}/{mappings_stats['total_processed']} entries had mappings ({mappings_stats['hit_rate']}%)")
                stats_info.append(f"Total confirmed mappings found: {mappings_stats['total_mappings_found']}")
            else:
                stats_info.append("Confirmed mappings: No CVEs processed yet")
        except Exception as e:
            stats_info.append(f"Confirmed mappings: Stats unavailable ({e})")
          # Log the comprehensive statistics
        logger.debug("=== Cache & Mappings Statistics ===", group="DATA_PROC")
        for info in stats_info:
            logger.debug(info, group="DATA_PROC")
        logger.debug("==================================", group="DATA_PROC")
        
        return True
    except Exception as e:
        logger.debug(f"Cache and mappings stats audit failed: {e}", group="initialization")
        return False

def audit_global_state_cleared():
    """Audit function to verify global state is properly cleared before CVE processing"""
    issues = []
    
    # Check HTML settings state - should be empty at start of CVE processing
    html_settings_size = len(generateHTML.JSON_SETTINGS_HTML) if hasattr(generateHTML, 'JSON_SETTINGS_HTML') else 0
    intelligent_settings_size = len(generateHTML.INTELLIGENT_SETTINGS) if hasattr(generateHTML, 'INTELLIGENT_SETTINGS') else 0
    
    if html_settings_size > 0:
        issues.append(f"HTML settings not cleared: {html_settings_size} entries remain")
    if intelligent_settings_size > 0:
        issues.append(f"Intelligent settings not cleared: {intelligent_settings_size} entries remain")    # Report issues or confirm clean state
    if issues:            
        logger.warning(f"Global state not properly cleared: {', '.join(issues)}", group="data_processing")
    else:
        logger.debug("Global state properly cleared before CVE processing", group="data_processing")

def main():
    """Main function to process CVEs based on command line arguments."""
    parser = argparse.ArgumentParser(description="Process CVE records with analysis_tool.py")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--cve", nargs="+", help="One or more CVE IDs to process")
    group.add_argument("--file", help="Text file with CVE IDs (one per line)")
    group.add_argument("--test-file", help="JSON file with test CVE data for modular rules testing")
    group.add_argument("--all", action="store_true", help="Process all CVE records")
    parser.add_argument("--api-key", help="NVD API Key (optional but recommended)")
    parser.add_argument("--no-browser", action="store_true", help="Don't open results in browser")
    parser.add_argument("--debug", action="store_true", help="Debug mode - uses DEFAULT_CVE_MODE setting")
    parser.add_argument("--save-skipped", help="Save list of skipped CVEs to specified file")
    
    # Set to "single" for a single CVE or "all" for all CVEs
    DEFAULT_CVE_MODE = "single"  # Change this to "all" when needed    DEFAULT_CVE_ID = "CVE-2024-20515"  # Default CVE to process in single mode
    
    args = parser.parse_args()
    
    # Generate parameter string for log filename
    if args.cve:
        if len(args.cve) == 1:
            params = args.cve[0]
        else:
            params = f"CVE_batch_{len(args.cve)}_items"
    elif args.file:
        filename = os.path.basename(args.file).replace('.txt', '').replace('.', '_')
        params = filename
    elif args.test_file:
        filename = os.path.basename(args.test_file).replace('.json', '').replace('.', '_')
        params = filename
    elif args.all:
        params = "all_CVEs"
    else:
        # Debug mode with default
        params = "debug_mode"
    
    # Start file logging with generated parameters
    logger.start_file_logging(params)
    
    # Load configuration
    config = processData.load_config()
    
    # Get API key (shared by both test file and CVE processing)
    nvd_api_key = ""
    if not args.test_file:  # Only prompt for API key if not processing test files
        nvd_api_key = args.api_key or config['debug']['default_api_key'] or input("Enter NVD API Key (optional, but processing will be slower without it): ").strip()
    else:
        nvd_api_key = args.api_key or ""  # API key is optional for test files
    
    # Gather NVD Source Data (done once, shared by both paths)
    logger.info("Gathering NVD source entries...", group="initialization")
    nvd_source_data = gatherData.gatherNVDSourceData(nvd_api_key)    # Initialize global CPE cache (done once per session, shared by both paths)
    from cpe_cache import get_global_cache_manager
    cache_manager = get_global_cache_manager()
    cache_manager.initialize(config.get('cache', {}))

    # Handle test file processing
    if args.test_file:
        logger.info("Test file mode: Processing local test file instead of querying APIs", group="initialization")
          # Check if test file exists
        if not os.path.exists(args.test_file):
            logger.error(f"Test file '{args.test_file}' not found", group="data_processing")
            sys.exit(1)
        
        # Process the test file (using shared nvd_source_data and cache_manager)
        filepath = process_test_file(args.test_file, nvd_source_data)
          # Cleanup cache after test file processing
        cache_manager.save_and_cleanup()
        
        if filepath:
            logger.info(f"Test file processed successfully: {filepath}", group="page_generation")
            # Open in browser if requested
            if not args.no_browser:
                import webbrowser
                webbrowser.open_new_tab(f"file:///{filepath}")
        else:
            logger.error("Test file processing failed: Unable to generate HTML output from test data", group="data_processing")
            logger.stop_file_logging()
            sys.exit(1)
        
        # Save and cleanup global CPE cache
        cache_manager.save_and_cleanup()
        
        # Stop file logging before returning
        logger.stop_file_logging()
        
        return
      # Debug mode - set default options based on config
    if args.debug or not (args.cve or args.file or args.all):
        if config['debug']['default_cve_mode'].lower() == "all":
            logger.info("Debug mode: Processing all CVEs by default", group="initialization")
            args.all = True
        else:
            logger.info(f"Debug mode: Processing single CVE {config['debug']['default_cve_id']}", group="initialization")
            args.cve = [config['debug']['default_cve_id']]    
    
    # Start main initialization stage
    start_initialization("Setting up analysis environment")
      # Initial memory and state audit
    audit_global_state()
    audit_cache_and_mappings_stats()
    
    # Initial system audit
    start_audit("Baseline system state verification")
    audit_global_state()
    audit_cache_and_mappings_stats()
    end_audit("System state verified - ready for CVE processing")

    
    cves_to_process = []
    
    if args.cve:
        cves_to_process = args.cve
    elif args.file:
        try:
            with open(args.file, 'r') as file:
                cves_to_process = [line.strip() for line in file if line.strip()]
        except Exception as e:
            logger.error(f"CVE list file reading failed: Unable to read file '{args.file}' - {e}", group="data_processing")
            sys.exit(1)
    elif args.all:
        cves_to_process = get_all_cves(nvd_api_key)
      # Reverse the order of CVEs to process newer ones first (typically higher CVE numbers)
    cves_to_process.sort(reverse=True)
    
    logger.info(f"Processing {len(cves_to_process)} CVE records (newest first)...", group="initialization")
    
    # Generate initial dashboard for real-time monitoring
    try:
        import subprocess
        from pathlib import Path
        
        project_root = Path(__file__).parent.parent.parent
        log_analyzer_path = project_root / "scripts" / "log_analyzer.py"
        dashboard_output = project_root / "reports" / "dashboard_data.json"
        
        if log_analyzer_path.exists():
            logger.info("Generating initial dashboard for real-time monitoring...", group="initialization")
            
            # Run log analyzer to create initial dashboard
            result = subprocess.run([
                sys.executable, str(log_analyzer_path),
                "--output", str(dashboard_output),
                "--summary"  # Generate both JSON and local HTML dashboard
            ], capture_output=True, text=True, cwd=str(project_root))
            
            if result.returncode == 0:
                logger.info("Dashboard ready: Open reports/local_dashboard.html to monitor progress", group="initialization")
            else:
                logger.debug(f"Dashboard initialization warning: {result.stderr.strip()}", group="initialization")
    
    except Exception as e:
        logger.debug(f"Dashboard initialization error: {e}", group="initialization")
    
    end_initialization("Analysis environment ready, CVE list prepared")
    
    # Process all CVEs with progress tracking
    generated_files = []
    skipped_cves = []
    skipped_reasons = {}
    total_cves = len(cves_to_process)
    start_time = time.time()
    progress_config = config.get('progress', {})
    show_progress = progress_config.get('enabled', True)
    show_eta = progress_config.get('show_eta', True)
    show_timing = progress_config.get('show_individual_timing', True)
    
    if show_progress:
        logger.info(f"Starting processing of {total_cves} CVE records", group="initialization")
    
    for index, cve in enumerate(cves_to_process):
        cve_start_time = time.time()
        current_cve_num = index + 1
        
        # Calculate progress and time estimates
        if show_progress:
            elapsed_time = time.time() - start_time
            if index > 0 and show_eta:  # Avoid division by zero
                avg_time_per_cve = elapsed_time / index
                remaining_cves = total_cves - index
                estimated_remaining_time = avg_time_per_cve * remaining_cves
                eta = datetime.now() + timedelta(seconds=estimated_remaining_time)
                
                # Format time estimates
                elapsed_str = str(timedelta(seconds=int(elapsed_time)))
                remaining_str = str(timedelta(seconds=int(estimated_remaining_time)))
                eta_str = eta.strftime("%H:%M:%S")
                progress_msg = (f"Processing CVE {current_cve_num}/{total_cves} ({cve}) | "
                              f"Progress: {(current_cve_num-1)/total_cves*100:.1f}% | "
                              f"Elapsed: {elapsed_str} | ETA: {eta_str} | Remaining: {remaining_str}")
            else:
                progress_msg = f"Processing CVE {current_cve_num}/{total_cves} ({cve}) | Progress: {(current_cve_num-1)/total_cves*100:.1f}%"            
            logger.info(progress_msg, group="cve_queries")
        
        try:
            logger.info(f"Processing {cve}...", group="processing")
              # Audit global state periodically
            if index > 0 and index % 10 == 0:  # Every 10 CVEs
                start_audit(f"Mid-processing audit checkpoint (CVE {current_cve_num}/{total_cves})")
                
                # Show processing statistics
                elapsed_time = time.time() - start_time  
                if current_cve_num > 1:
                    avg_time_per_cve = elapsed_time / (current_cve_num - 1)
                    estimated_remaining_time = avg_time_per_cve * (total_cves - current_cve_num + 1)
                    elapsed_str = str(timedelta(seconds=int(elapsed_time)))
                    remaining_str = str(timedelta(seconds=int(estimated_remaining_time)))
                    eta = datetime.now() + timedelta(seconds=estimated_remaining_time)
                    eta_str = eta.strftime("%H:%M:%S")
                    
                    logger.debug(f"Processing statistics: {(current_cve_num-1)/total_cves*100:.1f}% complete", group="INIT")
                    logger.debug(f"Timing: Elapsed: {elapsed_str} | ETA: {eta_str} | Remaining: {remaining_str}", group="INIT")
                    logger.debug(f"Performance: Average {avg_time_per_cve:.2f}s per CVE", group="INIT")
                
                audit_global_state()
                audit_cache_and_mappings_stats()
                
                # Generate dashboard update every 10 CVEs
                try:
                    import subprocess
                    from pathlib import Path
                    
                    # Get the project root directory (Analysis_Tools)
                    project_root = Path(__file__).parent.parent.parent
                    log_analyzer_path = project_root / "scripts" / "log_analyzer.py"
                    dashboard_output = project_root / "reports" / "dashboard_data.json"
                    
                    if log_analyzer_path.exists():
                        logger.debug(f"Updating dashboard data at checkpoint {current_cve_num}/{total_cves}", group="INIT")
                        
                        # Run log analyzer to update dashboard (suppress output to avoid log pollution)
                        result = subprocess.run([
                            sys.executable, str(log_analyzer_path),
                            "--output", str(dashboard_output),
                            "--no-local-dashboard"  # Skip local dashboard during processing for performance
                        ], capture_output=True, text=True, cwd=str(project_root))
                        
                        if result.returncode == 0:
                            logger.debug("Dashboard data updated successfully", group="INIT")
                        else:
                            logger.debug(f"Dashboard update warning: {result.stderr.strip()}", group="INIT")
                    
                except Exception as e:
                    logger.debug(f"Dashboard update error: {e}", group="INIT")
                
                end_audit("Checkpoint audit complete")
            
            # Process the CVE
            result = process_cve(cve, nvd_api_key, nvd_source_data)
            
            if result and result['success']:
                generated_files.append(result['filepath'])
                
                # Audit file size for bloat detection
                audit_file_size(result['filepath'])
                
                if show_timing:
                    cve_elapsed = time.time() - cve_start_time
                    logger.info(f"Successfully processed {cve} in {cve_elapsed:.2f}s", group="processing")
                else:
                    logger.info(f"Successfully processed {cve}", group="processing")
                
                # Open in browser if single CVE
                if len(cves_to_process) == 1 and not args.no_browser:
                    import webbrowser
                    webbrowser.open_new_tab(f"file:///{result['filepath']}")
            else:
                error_msg = result['error'] if result else "Unknown error"
                logger.error(f"Failed to process {cve}: {error_msg}", group="data_processing")
                skipped_cves.append(cve)
                skipped_reasons[cve] = error_msg
                
        except Exception as e:
            logger.error(f"Unexpected error processing {cve}: {e}", group="data_processing")
            skipped_cves.append(cve)
            skipped_reasons[cve] = f"Unexpected error: {e}"
    
    # Final audit after all processing
    start_audit("Final system state audit")
    audit_global_state()
    audit_cache_and_mappings_stats()
    end_audit("Processing complete - final audit finished")
    
    # Save and cleanup global CPE cache
    cache_manager.save_and_cleanup()
    
    # Final summary
    total_time = time.time() - start_time
    success_count = len(generated_files)
    
    logger.info(f"Processing complete!", group="completion")
    logger.info(f"Total CVEs processed: {total_cves}", group="completion")
    logger.info(f"Successfully generated: {success_count}", group="completion")
    logger.info(f"Skipped: {len(skipped_cves)}", group="completion")
    logger.info(f"Total time: {str(timedelta(seconds=int(total_time)))}", group="completion")
    
    # Final dashboard update
    try:
        import subprocess
        from pathlib import Path
        
        project_root = Path(__file__).parent.parent.parent
        log_analyzer_path = project_root / "scripts" / "log_analyzer.py"
        dashboard_output = project_root / "reports" / "dashboard_data.json"
        
        if log_analyzer_path.exists():
            logger.info("Updating final dashboard...", group="completion")
            
            # Run log analyzer for final update
            result = subprocess.run([
                sys.executable, str(log_analyzer_path),
                "--output", str(dashboard_output)
            ], capture_output=True, text=True, cwd=str(project_root))
            
            if result.returncode == 0:
                logger.info("Dashboard updated with final results: reports/local_dashboard.html", group="completion")
            else:
                logger.debug(f"Final dashboard update warning: {result.stderr.strip()}", group="completion")
    
    except Exception as e:
        logger.debug(f"Final dashboard update error: {e}", group="completion")
    
    if success_count > 0:
        avg_time = total_time / success_count
        logger.info(f"Average time per CVE: {avg_time:.2f}s", group="completion")
    
    # Save skipped CVEs if requested
    if args.save_skipped and skipped_cves:
        try:
            with open(args.save_skipped, 'w') as f:
                for cve in skipped_cves:
                    reason = skipped_reasons.get(cve, "Unknown reason")
                    f.write(f"{cve}\t{reason}\n")
            logger.info(f"Skipped CVEs saved to {args.save_skipped}", group="completion")
        except Exception as e:
            logger.error(f"Failed to save skipped CVEs: {e}", group="data_processing")
    
    # Display generated files
    if generated_files:
        logger.info("Generated files:", group="completion")
        for filepath in generated_files[-10:]:  # Show last 10 files
            logger.info(f"  {filepath}", group="completion")
        if len(generated_files) > 10:
            logger.info(f"  ... and {len(generated_files) - 10} more files", group="completion")
    
    # Stop file logging
    logger.stop_file_logging()


if __name__ == "__main__":
    main()
