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
import subprocess
import threading
from datetime import datetime, timedelta

from . import gatherData
from . import processData
from . import generateHTML

# Import the new logging system
from ..logging.workflow_logger import (
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

# Import run organization utilities
from ..storage.run_organization import create_run_directory, get_current_run_paths

# Get logger instance
logger = get_logger()

# Global run paths for current analysis session
current_run_paths = None

# Global variable to track dashboard update threads
_dashboard_update_threads = []

# Centralized path resolution functions
def get_analysis_tools_root():
    """Get the absolute path to the Analysis_Tools project root"""
    current_file = Path(__file__).resolve()
    
    # Navigate up from src/analysis_tool/analysis_tool.py to Analysis_Tools/
    # analysis_tool.py -> analysis_tool/ -> src/ -> Analysis_Tools/
    return current_file.parent.parent.parent

def get_project_path(relative_path=""):
    """Get absolute path within Analysis_Tools directory"""
    return get_analysis_tools_root() / relative_path

def ensure_project_directory(relative_path):
    """Ensure a directory exists within the Analysis_Tools project and return its path"""
    dir_path = get_project_path(relative_path)
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path

# Load configuration
def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)

config = load_config()

def process_test_file(test_file_path):
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
        
        # Initialize badge contents collection for this test CVE
        from ..logging.badge_contents_collector import start_cve_collection, complete_cve_collection
        start_cve_collection(cve_id)
        
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
        
        # Record stage in real-time collector
        try:
            from ..logging.dataset_contents_collector import record_stage_start, record_stage_end
            record_stage_start("cve_queries")
        except Exception as e:
            logger.debug(f"Real-time collector unavailable for stage tracking: {e}", group="data_processing")
        
        start_cve_queries("Processing test CVE data")
          # Process the vulnerability record data
        primaryDataframe, globalCVEMetadata = processData.processCVEData(primaryDataframe, cveRecordData)             
        primaryDataframe = processData.processNVDRecordData(primaryDataframe, nvdRecordData)
        
        end_cve_queries("Test CVE data processed")
        
        # Record stage completion in real-time collector
        try:
            from ..logging.dataset_contents_collector import record_stage_end
            record_stage_end("cve_queries")
            record_stage_start("confirmed_mappings")
        except Exception as e:
            logger.debug(f"Real-time collector unavailable for stage tracking: {e}", group="data_processing")
        
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
        primaryDataframe = generateHTML.update_cpeQueryHTML_column(primaryDataframe)
        
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
        external_assets_for_html = config.get('external_assets', {})
        allConsoleHTML = generateHTML.buildHTMLPage(affectedHtml2, cve_id, globalCVEMetadata, external_assets_config=external_assets_for_html)

        # For test files, use run-specific directory
        if not ('current_run_paths' in globals() and current_run_paths):
            raise RuntimeError("Run paths not initialized - test runs require run directory system")
            
        # Use existing run paths
        filepath = current_run_paths["generated_pages"] / f"{cve_id}.html"
        
        with filepath.open("w", encoding="utf-8") as fd:
            fd.write(allConsoleHTML)
        
        logger.file_operation("Generated", str(filepath), "test file", group="PAGE_GEN")
        end_page_generation("HTML file created")
        
        # Complete badge contents collection for this test CVE
        complete_cve_collection()
        
        return filepath
        
    except Exception as e:
        logger.error(f"Test file processing failed: Unable to process test file '{test_file_path}' - {str(e)}", group="initialization")
        logger.debug(f"Error type: {type(e).__name__}", group="initialization")
        
        # Still complete badge contents collection even if processing failed
        complete_cve_collection()
        
        import traceback
        traceback.print_exc()
        return None

def process_cve(cve_id, nvd_api_key):
    """Process a single CVE using the analysis tool functionality."""
    global config
    
    # Clear global HTML state to prevent accumulation from previous CVEs
    generateHTML.clear_global_html_state()
    
    # Audit: Verify global state is properly cleared before processing
    audit_global_state_cleared()
    
    # Initialize badge contents collection for this CVE
    from ..logging.badge_contents_collector import start_cve_collection, complete_cve_collection
    start_cve_collection(cve_id)
    
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
                
                # Complete badge contents collection for this record
                complete_cve_collection()
                
                # Ensure progress tracking is properly updated for skipped CVEs
                from ..logging.dataset_contents_collector import finish_cve_processing
                finish_cve_processing(cve_id)
                
                # Return a result indicating the CVE was skipped due to REJECTED status
                return {
                    'success': False,
                    'skipped': True,
                    'reason': 'REJECTED',
                    'cve_id': cve_id,
                    'filepath': None
                }
        
        # TEMPORARILY DISABLED: NVD /cves/ API calls and processing
        # TODO: Re-enable when NVD configuration data utilization is implemented
        # This code is preserved for future enhancement when we add functionality to:
        # 1. Process NVD configurations for cross-validation with CVE List data
        # 2. Enable user selection and export of NVD-provided CPE configurations
        # 3. Implement comparison/conflict resolution between CNA and NVD data
        #
        # try:
        #     nvdRecordData = gatherData.gatherNVDCVERecord(nvd_api_key, cve_id)
        # except Exception as api_error:
        #     # Handle specific NVD API errors
        #     error_str = str(api_error)
        #     if "Invalid cpeMatchstring parameter" in error_str:
        #         logger.warning(f"{cve_id} has invalid CPE match string - skipping processing", group="data_processing")
        #         logger.debug(f"Error: {error_str}", group="data_processing")
        #         return None
        #     else:
        #         # Re-raise other exceptions
        #         raise
        
        # Create minimal mock NVD record data (no configurations) to maintain workflow compatibility
        nvdRecordData = {
            "vulnerabilities": [{
                "cve": {
                    "id": cve_id,
                    "descriptions": [],
                    "references": [],
                    "configurations": []  # Empty configurations array - no NVD data processed
                }
            }]
        }
        
        end_cve_queries("CVE data retrieved")
        
        start_unique_cpe_generation("Processing CVE and NVD data")
        
        # Process the vulnerability record data
        primaryDataframe, globalCVEMetadata = processData.processCVEData(primaryDataframe, cveRecordData)
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
        primaryDataframe = generateHTML.update_cpeQueryHTML_column(primaryDataframe)
        
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
        external_assets_for_html = config.get('external_assets', {})
        allConsoleHTML = generateHTML.buildHTMLPage(affectedHtml2, cve_id, globalCVEMetadata, external_assets_config=external_assets_for_html)

        # Save output to run-specific generated_pages directory
        if not current_run_paths:
            raise RuntimeError("Run paths not initialized - run directory system required")
        
        sub_directory = current_run_paths["generated_pages"]
        
        filename = f"{cve_id}.html"
        filepath = sub_directory / filename
        
        with filepath.open("w", encoding="utf-8") as fd:
            fd.write(allConsoleHTML)
        
        logger.file_operation("Generated", str(filepath), group="page_generation")
        
        # Record file generation in dashboard collector
        try:
            from ..logging.dataset_contents_collector import record_output_file, get_current_cve_processing_time, update_cve_affected_entries_count
            
            # Get processing time for this CVE
            processing_time = get_current_cve_processing_time()
            
            # Count platform entries (dataframe rows)
            dataframe_rows = len(primaryDataframe) if 'primaryDataframe' in locals() else None
            
            # Update the final affected entries count for accurate dashboard reporting
            if dataframe_rows is not None:
                update_cve_affected_entries_count(cve_id, dataframe_rows)
            
            # Record the generated file with enhanced metadata
            record_output_file(
                filename=filename,
                file_path=str(filepath),
                cve_count=1,  # Individual CVE files always have 1 CVE
                cve_id=cve_id,
                dataframe_rows=dataframe_rows,
                processing_time=processing_time,
                bloat_analysis=None  # Bloat analysis could be added later if needed
            )
            
        except Exception as e:
            # Don't fail file generation if dashboard recording fails
            if logger:
                logger.warning(f"Failed to record file generation in dashboard: {e}", group="page_generation")
        
        end_page_generation("HTML file created")
        
        # Complete badge contents collection for this CVE
        complete_cve_collection()
        
        return {
            'success': True,
            'filepath': str(filepath)
        }
        
    except Exception as e:
        logger.error(f"CVE processing failed for {cve_id}: Unable to complete analysis workflow - {str(e)}", group="data_processing")
        
        # Still complete badge contents collection even if processing failed
        complete_cve_collection()
        
        return {
            'success': False,
            'error': str(e)
        }

def audit_global_state(warn_on_bloat=True):
    """Audit global state for potential bloat accumulation
    
    Args:
        warn_on_bloat (bool): Whether to emit warnings for detected bloat. 
                             Set to False for interim audits, True for final audits.
    """
    try:
        from ..storage.cpe_cache import get_global_cache_manager
        from . import generateHTML
        
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
            if warn_on_bloat:
                logger.warning(f"Global state bloat detected: {', '.join(issues)}", group="data_processing")
            else:
                logger.debug(f"Global state monitoring: {', '.join(issues)}", group="data_processing")
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
        from ..storage.cpe_cache import get_global_cache_manager
        from . import processData
        
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

def update_dashboard_async(current_cve_num, total_cves):
    """Update dashboard in parallel without blocking main CVE processing"""
    def _update_dashboard():
        # Use the dataset contents collector for real-time updates
        try:
            from ..logging.dataset_contents_collector import get_dataset_contents_collector
            collector = get_dataset_contents_collector()
            if collector.output_file_path:
                collector.save_to_file(collector.output_file_path)
                logger.debug(f"Dashboard checkpoint update at {current_cve_num}/{total_cves} (background)", group="data_processing")
        except Exception as e:
            logger.debug(f"Dashboard checkpoint update error: {e}", group="data_processing")
    
    # Start background thread
    thread = threading.Thread(target=_update_dashboard, daemon=True)
    thread.start()
    
    # Clean up completed threads
    global _dashboard_update_threads
    _dashboard_update_threads = [t for t in _dashboard_update_threads if t.is_alive()]
    _dashboard_update_threads.append(thread)

def wait_for_dashboard_updates():
    """Wait for all background dashboard updates to complete"""
    global _dashboard_update_threads
    for thread in _dashboard_update_threads:
        if thread.is_alive():
            logger.debug("Waiting for background dashboard update to complete...", group="completion")
            thread.join(timeout=30)  # Wait up to 30 seconds
    _dashboard_update_threads.clear()

def finalize_dashboard_data():
    """Finalize dashboard data using the dataset contents collector"""
    try:
        from ..logging.dataset_contents_collector import get_dataset_contents_collector, update_cache_statistics
        
        # Update cache statistics with actual data from CPE cache
        update_cache_statistics()
        
        collector = get_dataset_contents_collector()
        if collector.output_file_path:
            # Perform final save with enhanced log analysis
            result = collector.save_to_file(collector.output_file_path)
            if result:
                logger.debug("Final dashboard data generated with enhanced log analysis", group="completion")
                return True
            else:
                logger.debug("Final dashboard generation completed with warnings", group="completion")
                return False
        else:
            logger.debug("No dashboard output path configured", group="completion")
            return False
    except Exception as e:
        logger.debug(f"Final dashboard generation error: {e}", group="completion")
        return False

def main():
    """Main function to process CVEs based on command line arguments."""
    global current_run_paths
    
    parser = argparse.ArgumentParser(description="Process CVE records with analysis_tool.py")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--cve", nargs="+", help="One or more CVE IDs to process")
    group.add_argument("--file", help="Text file with CVE IDs (one per line)")
    group.add_argument("--test-file", help="JSON file with test CVE data for modular rules testing")
    parser.add_argument("--api-key", help="NVD API Key (optional but recommended)")
    parser.add_argument("--no-browser", action="store_true", help="Don't open results in browser")
    parser.add_argument("--no-cache", action="store_true", help="Disable CPE cache for faster testing")
    parser.add_argument("--external-assets", action="store_true", help="Use external asset references instead of inline CSS/JS (reduces file size)")
    parser.add_argument("--run-id", help="Continue within existing run directory (used by generate_dataset.py integration)")
    
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
    else:
        # No arguments provided - use config debug defaults
        params = "config_defaults"
    
    # Load configuration (logging will be started after run directory is created)
    config = processData.load_config()
    
    # Override external assets setting if CLI argument is provided
    if args.external_assets:
        logger.info("External assets enabled via CLI argument - overriding config setting", group="initialization")
        # Copy the external_assets configuration from api.external_assets and enable it
        if 'api' in config and 'external_assets' in config['api']:
            config['external_assets'] = config['api']['external_assets'].copy()
            config['external_assets']['enabled'] = True
        else:
            # Fail fast if required config structure is missing
            logger.error(
                f"External assets requested via --external-assets but config structure is missing. "
                f"Expected config['api']['external_assets'] section in config.json. "
                f"Please verify your configuration file contains the required external_assets section."
            )
        
        # Update the global config as well so process_cve function can access it
        import sys
        current_module = sys.modules[__name__]
        current_module.config = config
        
        # Update the generateHTML module's config
        from . import generateHTML
        generateHTML.config = config
    
    # Get API key (shared by both test file and CVE processing)
    nvd_api_key = ""
    if not args.test_file:  # Only check for API key if not processing test files
        nvd_api_key = args.api_key or config['defaults']['default_api_key'] or ""
        
        if nvd_api_key:
            logger.info(f"Using NVD API key for faster processing", group="initialization")
        else:
            logger.warning("No NVD API key provided - processing will be MUCH slower due to rate limiting", group="initialization")
            logger.info("Consider using --api-key parameter or setting default_api_key in config.json for better performance", group="initialization")
    else:
        nvd_api_key = args.api_key or ""  # API key is optional for test files
    
    # Gather NVD Source Data (done once, shared by both paths)
    logger.info("Gathering NVD source entries...", group="initialization")
    nvd_source_data = gatherData.gatherNVDSourceData(nvd_api_key)
    
    # Initialize global NVD source manager (done once per session, shared by both paths)
    from ..storage.nvd_source_manager import get_global_source_manager
    source_manager = get_global_source_manager()
    source_manager.initialize(nvd_source_data)
    
    # Initialize global CPE cache (done once per session, shared by both paths)
    from ..storage.cpe_cache import get_global_cache_manager
    cache_manager = get_global_cache_manager()
    
    if args.no_cache:
        logger.info("Cache disabled for testing mode", group="initialization")
        # Initialize with disabled cache configuration
        cache_config = config.get('cache', {}).copy()
        cache_config['enabled'] = False
        cache_manager.initialize(cache_config)
    else:
        cache_manager.initialize(config.get('cache', {}))
    
    # Handle test file processing
    if args.test_file:
        logger.info("Test file mode: Processing local test file instead of querying APIs", group="initialization")
        
        # Check if test file exists
        if not os.path.exists(args.test_file):
            logger.error(f"Test file '{args.test_file}' not found", group="data_processing")
            sys.exit(1)
        
        # Create test run directory
        from ..storage.run_organization import create_run_directory, get_current_run_paths
        test_context = os.path.basename(args.test_file).replace('.json', '').replace('.', '_')
        run_path, run_id = create_run_directory(test_context, is_test=True)
        logger.info(f"Created test run directory: {run_id}", group="initialization")
        
        # Set global run paths for test processing
        current_run_paths = get_current_run_paths(run_id)
        
        # Initialize badge contents collector with test run paths
        from ..logging.badge_contents_collector import initialize_badge_contents_report
        initialize_badge_contents_report(current_run_paths["logs"])
        
        # Process the test file (using global source manager)
        filepath = process_test_file(args.test_file)
        
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
        
        # Finalize badge contents report for test file processing
        from ..logging.badge_contents_collector import finalize_badge_contents_report
        badge_report_path = finalize_badge_contents_report()
        if badge_report_path:
            logger.info(f"Badge contents report finalized: {badge_report_path}", group="completion")
        
        # Stop file logging before returning
        logger.stop_file_logging()
        
        return
    # No arguments provided - use config debug defaults
    if not (args.cve or args.file or args.test_file):
        logger.info(f"No arguments provided: Processing single CVE {config['defaults']['default_cve_id']} per config defaults", group="initialization")
        args.cve = [config['defaults']['default_cve_id']]    
    
    # Create or use existing run directory for this analysis session
    from ..storage.run_organization import create_run_directory, get_current_run_paths
    
    if args.run_id:
        # Use existing run directory (called from generate_dataset.py)
        logger.info(f"Continuing analysis within existing run: {args.run_id}", group="initialization")
        run_id = args.run_id
        run_paths = get_current_run_paths(run_id)
        run_path = run_paths["run_root"]
        
        # Verify run directory exists
        if not run_path.exists():
            logger.error(f"Specified run directory does not exist: {run_path}", group="initialization")
            return 1
            
        logger.info(f"Using existing run directory: {run_path}", group="initialization")
    else:
        # Create new run directory
        run_context = None
        if args.cve and len(args.cve) == 1:
            run_context = args.cve[0]
        elif args.cve:
            run_context = f"batch_{len(args.cve)}_CVEs"
        elif args.file:
            run_context = os.path.basename(args.file).replace('.txt', '').replace('.', '_')
        
        run_path, run_id = create_run_directory(run_context)
        logger.info(f"Created analysis run directory: {run_id}", group="initialization")
        
        # Get paths for this run
        run_paths = get_current_run_paths(run_id)
    
    # Store run info globally for other modules to access
    current_run_paths = run_paths
    
    # Update logger to use run-specific logs directory
    logger.set_run_logs_directory(str(run_paths["logs"]))
    
    # Now start file logging with the correct run-specific directory
    logger.start_file_logging(params)
    
    # Initialize badge contents collector with run-specific logs directory
    from ..logging.badge_contents_collector import clear_badge_contents_collector, initialize_badge_contents_report
    from ..logging.dataset_contents_collector import (
        clear_dataset_contents_collector, 
        save_dashboard_data,
        start_processing_run,
        initialize_dashboard_collector
    )
    
    # Clear any existing state
    clear_badge_contents_collector()
    clear_dataset_contents_collector()
    
    # Initialize badge contents collector
    if initialize_badge_contents_report(str(run_paths["logs"])):
        logger.info("Badge contents collector initialized for source data concerns reporting", group="initialization")
    else:
        logger.warning("Failed to initialize badge contents collector", group="initialization")
    
    # Initialize real-time dashboard collector
    if initialize_dashboard_collector(str(run_paths["logs"])):
        logger.info("Real-time dashboard collector initialized for live progress tracking", group="initialization")
    else:
        logger.warning("Failed to initialize real-time dashboard collector", group="initialization")
    
    # Start main initialization stage
    start_initialization("Setting up analysis environment")
      # Initial memory and state audit
    audit_global_state(warn_on_bloat=False)
    audit_cache_and_mappings_stats()
    
    # Initial system audit
    start_audit("Baseline system state verification")
    audit_global_state(warn_on_bloat=False)
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
      # Reverse the order of CVEs to process newer ones first (typically higher CVE numbers)
    cves_to_process.sort(reverse=True)
    
    logger.info(f"Processing {len(cves_to_process)} CVE records (newest first)...", group="initialization")
    
    # Start real-time dashboard processing run
    try:
        from ..logging.dataset_contents_collector import start_processing_run
        start_processing_run(len(cves_to_process))
        logger.info("Real-time dashboard collector configured for processing run", group="initialization")
    except Exception as e:
        logger.warning(f"Failed to start real-time dashboard processing run: {e}", group="initialization")
    
    # Generate initial dashboard for real-time monitoring
    logger.info("Generating initial dashboard for real-time monitoring...", group="initialization")
    # The dataset contents collector automatically handles initial dashboard setup
    # No legacy log_analyzer.py needed - all data flows through the collector
    if current_run_paths:
        logger.info(f"Dashboard ready: Monitor progress at runs/{run_id}/logs/generateDatasetReport.json", group="initialization")
    else:
        logger.info("Dashboard ready: Monitor progress in logs/generateDatasetReport.json", group="initialization")
    
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
            
            # Start CVE processing in real-time collector
            try:
                from ..logging.dataset_contents_collector import start_cve_processing
                start_cve_processing(cve)
            except Exception as e:
                logger.debug(f"Real-time collector unavailable for CVE tracking: {e}", group="data_processing")
            
              # Audit global state periodically
            if index > 0 and index % 100 == 0:  # Every 100 CVEs
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
                
                audit_global_state(warn_on_bloat=False)
                audit_cache_and_mappings_stats()
                
                # Start dashboard update in parallel (non-blocking)
                update_dashboard_async(current_cve_num, total_cves)
                logger.debug("Background dashboard update started", group="INIT")
                
                end_audit("Checkpoint audit complete")
            
            # Process the CVE
            result = process_cve(cve, nvd_api_key)
            
            # Handle results: successful processing, skipped CVEs, or failures
            if result:
                if result['success']:
                    generated_files.append(result['filepath'])
                    
                    if show_timing:
                        cve_elapsed = time.time() - cve_start_time
                        logger.info(f"Successfully processed {cve} in {cve_elapsed:.2f}s", group="processing")
                    else:
                        logger.info(f"Successfully processed {cve}", group="processing")
                    
                    # Open in browser if single CVE
                    if len(cves_to_process) == 1 and not args.no_browser:
                        import webbrowser
                        webbrowser.open_new_tab(f"file:///{result['filepath']}")
                        
                elif result.get('skipped'):
                    # CVE was skipped (e.g., REJECTED status)
                    if show_timing:
                        cve_elapsed = time.time() - cve_start_time
                        logger.info(f"Skipped {cve} ({result.get('reason', 'unknown reason')}) in {cve_elapsed:.2f}s", group="processing")
                    else:
                        logger.info(f"Skipped {cve} ({result.get('reason', 'unknown reason')})", group="processing")
                else:
                    # CVE processing failed with error
                    error_msg = result.get('error', 'Unknown error')
                    logger.error(f"Failed to process {cve}: {error_msg}", group="data_processing")
                    skipped_cves.append(cve)
                    skipped_reasons[cve] = error_msg
                
                # Complete CVE processing in real-time collector for all result types
                try:
                    from ..logging.dataset_contents_collector import finish_cve_processing
                    finish_cve_processing(cve)
                except Exception as e:
                    logger.debug(f"Real-time collector unavailable for CVE completion tracking: {e}", group="data_processing")
            else:
                # CVE processing failed entirely - no result returned
                logger.error(f"Failed to process {cve}: No result returned", group="data_processing")
                skipped_cves.append(cve)
                skipped_reasons[cve] = "No result returned"
                
                # Still complete CVE processing in real-time collector to maintain accurate counts
                try:
                    from ..logging.dataset_contents_collector import finish_cve_processing
                    finish_cve_processing(cve)
                except Exception as e:
                    logger.debug(f"Real-time collector unavailable for CVE completion tracking: {e}", group="data_processing")
                
        except Exception as e:
            logger.error(f"Unexpected error processing {cve}: {e}", group="data_processing")
            skipped_cves.append(cve)
            skipped_reasons[cve] = f"Unexpected error: {e}"
    
    # Final audit after all processing
    start_audit("Final system state audit")
    audit_global_state(warn_on_bloat=True)
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
    
    # Wait for any pending background dashboard updates and perform final update
    wait_for_dashboard_updates()
    
    logger.info("Updating final dashboard...", group="completion")
    if finalize_dashboard_data():
        if current_run_paths:
            logger.info(f"Dashboard updated with final results: runs/{run_id}/logs/generateDatasetReport.json", group="completion")
        else:
            logger.info("Dashboard updated with final results: logs/generateDatasetReport.json", group="completion")
    else:
        logger.debug("Final dashboard update completed with warnings", group="completion")
    
    if success_count > 0:
        avg_time = total_time / success_count
        logger.info(f"Average time per CVE: {avg_time:.2f}s", group="completion")
    
    # Log skipped CVEs details for debugging
    if skipped_cves:
        logger.warning(f"Processing completed with {len(skipped_cves)} skipped CVEs", group="completion")
        logger.info("Skipped CVE details:", group="completion")
        for cve in skipped_cves:
            reason = skipped_reasons.get(cve, "Unknown reason")
            logger.error(f"SKIPPED: {cve} - {reason}", group="data_processing")
    
    # Display generated files
    if generated_files:
        logger.info("Generated files:", group="completion")
        for filepath in generated_files[-10:]:  # Show last 10 files
            logger.info(f"  {filepath}", group="completion")
        if len(generated_files) > 10:
            logger.info(f"  ... and {len(generated_files) - 10} more files", group="completion")
    
    # Finalize badge contents report
    from ..logging.badge_contents_collector import finalize_badge_contents_report
    badge_report_path = finalize_badge_contents_report()
    if badge_report_path:
        logger.info(f"Badge contents report finalized: {badge_report_path}", group="completion")
    
    # Finalize real-time dashboard collector
    try:
        from ..logging.dataset_contents_collector import save_dashboard_data
        dashboard_file_path = str(run_paths["logs"] / "generateDatasetReport.json")
        dashboard_report_path = save_dashboard_data(dashboard_file_path)
        if dashboard_report_path:
            logger.info(f"Real-time dashboard report finalized: {dashboard_report_path}", group="completion")
    except Exception as e:
        logger.warning(f"Failed to finalize real-time dashboard collector: {e}", group="completion")
    
    # Stop file logging
    logger.stop_file_logging()


if __name__ == "__main__":
    main()
