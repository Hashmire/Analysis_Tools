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
from datetime import datetime, timedelta, timezone

# Import for potential scoping issues 
import datetime as dt

def _ensure_src_path():
    """Ensure src directory is in Python path"""
    if not hasattr(_ensure_src_path, '_initialized'):
        project_root = Path(__file__).parent.parent.parent.parent  # Go up to Analysis_Tools/
        src_path = project_root / "src"
        if str(src_path) not in sys.path:
            sys.path.insert(0, str(src_path))
        _ensure_src_path._initialized = True

# Initialize path setup
_ensure_src_path()

from . import gatherData
from . import processData

# Import the new logging system
from ..logging.workflow_logger import (
    get_logger, LogGroup, LogLevel,
    start_cve_queries, end_cve_queries,
    start_unique_cpe_generation, end_unique_cpe_generation,
    start_cpe_queries, end_cpe_queries,
    start_audit, end_audit,
    log_cve_query, log_data_proc
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
    logger.info(f"Processing test file: {test_file_path}", group="DATA_PROC")
    
    
    try:
        # Load test data from JSON file
        with open(test_file_path, 'r', encoding='utf-8') as f:
            test_data = json.load(f)
        
        # Extract CVE ID from test data
        cve_id = test_data.get('cveMetadata', {}).get('cveId', 'TEST-CVE-0000-0000')
        logger.info(f"Test CVE ID: {cve_id}", group="DATA_PROC")
        
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
        
        # Record stage in real-time collector
        try:
            from ..reporting.dataset_contents_collector import record_stage_start, record_stage_end
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
            from ..reporting.dataset_contents_collector import record_stage_end
            record_stage_end("cve_queries")
        except Exception as e:
            logger.debug(f"Real-time collector unavailable for stage tracking: {e}", group="data_processing")
        
        
        # For test files, ensure CPE data fields are proper dictionaries instead of empty lists
        for index, row in primaryDataframe.iterrows():
            if isinstance(primaryDataframe.at[index, 'sortedCPEsQueryData'], list):
                primaryDataframe.at[index, 'sortedCPEsQueryData'] = {}
            if isinstance(primaryDataframe.at[index, 'trimmedCPEsQueryData'], list):
                primaryDataframe.at[index, 'trimmedCPEsQueryData'] = {}
        
        end_cve_queries("Test CVE data processed")
        
        # Source Data Concerns Processing for test files
        logger.info("Generating Source Data Concerns report", group="data_processing")
        from .platform_entry_registry import create_source_data_concerns_badge, PLATFORM_ENTRY_NOTIFICATION_REGISTRY
        from ..logging.badge_contents_collector import get_badge_contents_collector, collect_clean_platform_entry
        
        collector = get_badge_contents_collector()
        for index, row in primaryDataframe.iterrows():
            # Extract basic row data
            source_id = row.get('sourceID', 'Unknown')
            raw_platform_data = row.get('rawPlatformData', {})
            platform_metadata = row.get('platformEntryMetadata', {})
            
            vendor = raw_platform_data.get('vendor', 'Unknown')
            product = raw_platform_data.get('product', 'Unknown')
            
            # Collect source data concerns and populate the registry
            create_source_data_concerns_badge(
                table_index=index,
                raw_platform_data=raw_platform_data,
                characteristics={},  # Empty for SDC report only
                platform_metadata=platform_metadata,
                row=row
            )
            
            # Check if source data concerns were found and collect them
            registry_data = PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('sourceDataConcerns', {}).get(index, {})
            if registry_data:
                concerns_data = registry_data.get('concerns', {})
                concerns_summary = registry_data.get('summary', {})
                concerns_count = concerns_summary.get('total_concerns', 0)
                concern_types = concerns_summary.get('concern_types', [])
                
                collector.collect_source_data_concern(
                    table_index=index,
                    source_id=source_id,
                    vendor=vendor,
                    product=product,
                    concerns_data=concerns_data,
                    concerns_count=concerns_count,
                    concern_types=concern_types
                )
            else:
                # No source data concerns found - collect this as a clean platform entry
                if source_id and source_id != 'Unknown':
                    collect_clean_platform_entry(source_id)
        
        logger.info("SDC report processing completed", group="data_processing")
        
        logger.debug("Test file processing complete", group="report_gen")
        
        # Complete badge contents collection for this test CVE
        complete_cve_collection()
        
        return True
        
    except Exception as e:
        logger.error(f"Test file processing failed: Unable to process test file '{test_file_path}' - {str(e)}", group="initialization")
        logger.debug(f"Error type: {type(e).__name__}", group="initialization")
        
        # Still complete badge contents collection even if processing failed
        complete_cve_collection()
        
        import traceback
        traceback.print_exc()
        return None

def set_global_source_uuid(source_uuid):
    """Set the global source UUID for filtering throughout the processing pipeline."""
    from .unified_source_manager import get_unified_source_manager
    
    manager = get_unified_source_manager()
    manager.set_source_uuid_filter(source_uuid)
    
    if source_uuid:
        logger.info(f"Global source UUID set for filtering: {source_uuid}", group="initialization")

def process_cve(cve_id, nvd_api_key, sdc_report=False, cpe_determination=False, alias_report=False, cpe_as_generator=False, nvd_ish_only=False):
    """Process a single CVE using the analysis tool functionality.
    
    Args:
        cve_id: The CVE ID to process
        nvd_api_key: NVD API key for CPE queries (ignored if cpe_determination=False)
        sdc_report: If True, generate Source Data Concerns report
        cpe_determination: If True, perform NVD CPE API calls and generate CPE determination
        alias_report: If True, generate alias report via curator features
        cpe_as_generator: If True, generate CPE Applicability Statements as interactive HTML pages
        nvd_ish_only: If True, generate only NVD-ish enriched records without report files or HTML
    
    Note:
        Source UUID filtering is controlled by the global _global_source_uuid variable
        set via set_global_source_uuid() function.
    """
    global config
    
    
    # Clear global registry state before processing new CVE
    from .platform_entry_registry import clear_all_registries
    clear_all_registries()
    logger.debug("Environment prepared - registries cleared", group="data_processing")
    
    # Initialize badge contents collection for this CVE
    from ..logging.badge_contents_collector import start_cve_collection, complete_cve_collection
    from ..storage.nvd_ish_collector import get_nvd_ish_collector
    start_cve_collection(cve_id)
    
    # Get NVD-ish collector for this processing session
    nvd_ish_collector = get_nvd_ish_collector()
    
    try:
        # Make sure the string is formatted well
        cve_id = cve_id.strip().upper()
        processData.integrityCheckCVE("cveIdFormat", cve_id)
        
        # Create Primary Datasets from external sources
        primaryDataframe = gatherData.gatherPrimaryDataframe()
        
        start_cve_queries()
        
        # Initialize tool execution metadata collection
        tool_execution_timestamps = {}

        # Gather CVE List Record and NVD Dataset Records for the target CVE
        cveRecordData = gatherData.gatherCVEListRecordLocal(cve_id)
        
        # Check if CVE is in REJECTED state
        if cveRecordData and 'cveMetadata' in cveRecordData:
            state = cveRecordData.get('cveMetadata', {}).get('state')
            if state == 'REJECTED':
                logger.info(f"{cve_id} is in REJECTED state - skipping processing", group="cve_queries")
                
                # Complete badge contents collection for this record
                complete_cve_collection()
                
                
                # Return a result indicating the CVE was skipped due to REJECTED status
                return {
                    'success': False,
                    'skipped': True,
                    'reason': 'REJECTED',
                    'cve_id': cve_id,
                    'filepath': None
                }
        
        
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
        
        end_cve_queries()
        
        start_unique_cpe_generation()
        
        # Process the vulnerability record data
        primaryDataframe, globalCVEMetadata = processData.processCVEData(primaryDataframe, cveRecordData)
        primaryDataframe = processData.processNVDRecordData(primaryDataframe, nvdRecordData)

        # Platform Data Processing and CPE Generation
        if cpe_determination:
            # Full CPE processing: platform data + CPE generation + API calls
            # Use same timestamp for both cpeDetermination and cpeDeterminationMetadata (set at same execution point)
            cpe_timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            tool_execution_timestamps['cpeDetermination'] = cpe_timestamp
            tool_execution_timestamps['cpeDeterminationMetadata'] = cpe_timestamp
            try:
                primaryDataframe = processData.suggestCPEData(nvd_api_key, primaryDataframe, 1, 
                                                            alias_report=alias_report, cpe_as_generator=cpe_as_generator)
            except Exception as cpe_error:
                logger.warning(f"CPE suggestion failed for {cve_id}: Unable to complete CPE data suggestion - {str(cpe_error)}", group="data_processing")
                logger.info("Continuing with available data...", group="data_processing")
        elif sdc_report or alias_report or cpe_as_generator:
            # Platform data processing only (no CPE generation or API calls)
            if cpe_as_generator:
                tool_execution_timestamps['cpeAsGeneration'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            try:
                primaryDataframe = processData.processPlatformDataOnly(primaryDataframe, 
                                                                     alias_report=alias_report, cpe_as_generator=cpe_as_generator)
            except Exception as platform_error:
                logger.warning(f"Platform processing failed for {cve_id}: Unable to complete platform analysis - {str(platform_error)}", group="data_processing")
                logger.info("Continuing with available data...", group="data_processing")
        else:
            logger.info(f"Platform processing skipped - no features requiring platform data are enabled", group="data_processing")
        
        # Source Data Concerns Processing
        if sdc_report:
            logger.info("Generating Source Data Concerns report", group="data_processing")
            tool_execution_timestamps['sourceDataConcerns'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            
            # Process each row in the dataframe to collect source data concerns
            from .platform_entry_registry import create_source_data_concerns_badge, PLATFORM_ENTRY_NOTIFICATION_REGISTRY
            from ..logging.badge_contents_collector import get_badge_contents_collector, collect_clean_platform_entry
            
            collector = get_badge_contents_collector()
            for index, row in primaryDataframe.iterrows():
                # Extract basic row data
                source_id = row.get('sourceID', 'Unknown')
                raw_platform_data = row.get('rawPlatformData', {})
                platform_metadata = row.get('platformEntryMetadata', {})
                
                vendor = raw_platform_data.get('vendor', 'Unknown')
                product = raw_platform_data.get('product', 'Unknown')
                
                # Collect source data concerns and populate the registry
                create_source_data_concerns_badge(
                    table_index=index,
                    raw_platform_data=raw_platform_data,
                    characteristics={},  # Empty for SDC report only
                    platform_metadata=platform_metadata,
                    row=row
                )
                
                # Check if source data concerns were found and collect them
                registry_data = PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('sourceDataConcerns', {}).get(index, {})
                if registry_data:
                    concerns_data = registry_data.get('concerns', {})
                    concerns_summary = registry_data.get('summary', {})
                    concerns_count = concerns_summary.get('total_concerns', 0)
                    concern_types = concerns_summary.get('concern_types', [])
                    
                    collector.collect_source_data_concern(
                        table_index=index,
                        source_id=source_id,
                        vendor=vendor,
                        product=product,
                        concerns_data=concerns_data,
                        concerns_count=concerns_count,
                        concern_types=concern_types
                    )
                else:
                    # No source data concerns found - collect this as a clean platform entry
                    if source_id and source_id != 'Unknown':
                        collect_clean_platform_entry(source_id)
            
            logger.info("SDC report processing completed", group="data_processing")
        
        # Alias Extraction Processing (ignores source UUID filtering) - Runs independently of SDC
        if alias_report:
            try:
                logger.info("Starting alias extraction processing (all sources)", group="data_processing")
                tool_execution_timestamps['aliasExtraction'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                
                # Import alias extraction functions
                from .platform_entry_registry import create_alias_extraction_badge, PLATFORM_ENTRY_NOTIFICATION_REGISTRY
                from ..logging.badge_contents_collector import collect_alias_extraction_data, get_badge_contents_collector
                
                collector = get_badge_contents_collector()
                # Initialize CVE processing session for alias extraction
                collector.start_cve_processing(cve_id)
                logger.debug(f"Badge contents collector initialized for alias extraction - CVE {cve_id}", group="data_processing")
                
                # Process CVE data to get all entries (no filtering in processCVEData)
                alias_dataframe = gatherData.gatherPrimaryDataframe()
                alias_dataframe, _ = processData.processCVEData(alias_dataframe, cveRecordData)
                
                # Process each row in the dataframe to collect alias extraction data
                for index, row in alias_dataframe.iterrows():
                    logger.debug(f"Processing alias extraction for row {index} (all sources)", group="data_processing")
                    
                    # Extract basic row data
                    source_id = row.get('sourceID', 'Unknown')
                    raw_platform_data = row.get('rawPlatformData', {})
                    cve_id_for_alias = row.get('cve_id', cve_id)  # Use row-specific CVE ID if available
                    
                    # Ensure the row has the CVE ID in the expected format for alias extraction
                    row_with_cve = dict(row)
                    row_with_cve['cve_id'] = cve_id_for_alias
                    
                    # Collect alias extraction data and populate the registry
                    create_alias_extraction_badge(
                        table_index=index,
                        raw_platform_data=raw_platform_data,
                        row=row_with_cve
                    )
                    
                    # Check if alias extraction data was generated and collect it
                    alias_registry_data = PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('aliasExtraction', {})
                    
                    # Count entries for this table index (including platform expansion)
                    matching_entries = {}
                    entry_count = 0
                    
                    for reg_key, reg_data in alias_registry_data.items():
                        # Check for direct match or platform expansion match
                        if reg_key == str(index) or reg_key.startswith(f"{index}_platform_"):
                            matching_entries[reg_key] = reg_data
                            entry_count += 1
                    
                    if matching_entries:
                        # Collect the alias extraction data for this platform entry
                        collect_alias_extraction_data(
                            table_index=index,
                            source_id=source_id,
                            alias_data=matching_entries,
                            entry_count=entry_count,
                            cve_id=cve_id_for_alias
                        )
                
                logger.info("Alias extraction processing completed (all sources)", group="data_processing")
                
                # Complete badge contents collection for this CVE
                complete_cve_collection()
                
            except Exception as alias_error:
                logger.error(f"Alias extraction failed for {cve_id}: {str(alias_error)}", group="data_processing")
                logger.info("Continuing without alias extraction...", group="data_processing")
        
        
        # Confirmed Mappings Processing
        if cpe_determination or alias_report or cpe_as_generator:
            try:
                # Import confirmed mapping functions
                from .processData import extract_confirmed_mappings_for_affected_entry
                from .platform_entry_registry import create_confirmed_mappings_registry_entry
                
                # Extract affected entries from CVE List V5 data for confirmed mapping processing
                if cveRecordData and 'containers' in cveRecordData:
                    affected_entries = []
                    
                    # Extract affected entries from all containers (CNA + ADP)
                    for container_key, container_data in cveRecordData['containers'].items():
                        if container_key == 'adp' and isinstance(container_data, list):
                            # ADP is an array of containers
                            for adp_index, adp_container in enumerate(container_data):
                                if isinstance(adp_container, dict) and 'affected' in adp_container:
                                    source_org_id = adp_container.get('providerMetadata', {}).get('orgId', 'unknown_source')
                                    
                                    for entry_index, affected_entry in enumerate(adp_container['affected']):
                                        affected_with_source = affected_entry.copy()
                                        affected_with_source['source'] = source_org_id
                                        affected_with_source['cvelistv5AffectedEntryIndex'] = f'cve.containers.adp[{adp_index}].affected.[{entry_index}]'
                                        affected_entries.append(affected_with_source)
                        elif isinstance(container_data, dict) and 'affected' in container_data:
                            # Regular container (like CNA)
                            source_org_id = container_data.get('providerMetadata', {}).get('orgId', 'unknown_source')
                            
                            for entry_index, affected_entry in enumerate(container_data['affected']):
                                affected_with_source = affected_entry.copy()
                                affected_with_source['source'] = source_org_id
                                affected_with_source['cvelistv5AffectedEntryIndex'] = f'cve.containers.{container_key}.affected.[{entry_index}]'
                                affected_entries.append(affected_with_source)
                    
                    # Process each affected entry for confirmed mappings
                    for table_index, affected_entry in enumerate(affected_entries):
                        logger.debug(f"Processing confirmed mappings for affected entry {table_index}", group="data_processing")
                        
                        # Extract confirmed mappings for this affected entry
                        confirmed_mappings = extract_confirmed_mappings_for_affected_entry(affected_entry)
                        
                        # Register confirmed mappings data for nvd-ish integration
                        create_confirmed_mappings_registry_entry(table_index, confirmed_mappings, affected_entry)
                        
                        if confirmed_mappings:
                            logger.debug(f"Found {len(confirmed_mappings)} confirmed mappings for affected entry {table_index}", group="data_processing")
                
            except Exception as confirmed_error:
                logger.error(f"Confirmed mappings processing failed for {cve_id}: {str(confirmed_error)}", group="data_processing")
                logger.info("Continuing without confirmed mappings...", group="data_processing")
        
        # Complete NVD-ish enhanced record collection for this CVE
        logger.info(f"Starting NVD-ish enhanced record collection for {cve_id}", group="data_processing")
        try:
            # Import Platform Entry Notification Registry for nvd-ish integration
            from .platform_entry_registry import PLATFORM_ENTRY_NOTIFICATION_REGISTRY
            
            nvd_ish_collector.start_cve_processing(cve_id)
            
            # Always collect NVD base record and CVE List V5 data
            nvd_ish_collector.collect_nvd_base_record()  # Auto-loads from NVD 2.0 cache
            nvd_ish_collector.collect_cve_list_v5_data(cveRecordData)  # Pass CVE List V5 data from API/cache
            
            if alias_report:
                from ..logging.badge_contents_collector import get_badge_contents_collector
                badge_collector = get_badge_contents_collector()
                badge_collector.complete_cve_processing()
                logger.debug(f"Badge contents collector completed for CVE {cve_id}", group="data_processing")
            
            # Integrate source data concerns from Platform Entry Notification Registry
            nvd_ish_collector.collect_source_data_concerns_from_registry(PLATFORM_ENTRY_NOTIFICATION_REGISTRY)
            
            # Integrate alias extraction data from Platform Entry Notification Registry
            if alias_report:
                nvd_ish_collector.collect_alias_extraction_from_registry(PLATFORM_ENTRY_NOTIFICATION_REGISTRY)
            
            # Integrate CPE suggestions data from Platform Entry Notification Registry 
            if cpe_determination or nvd_ish_only:
                nvd_ish_collector.collect_cpe_determination_from_registry(PLATFORM_ENTRY_NOTIFICATION_REGISTRY)
            
            # Integrate confirmed mappings data from Platform Entry Notification Registry
            if cpe_determination or alias_report or cpe_as_generator or nvd_ish_only:
                nvd_ish_collector.collect_confirmed_mappings_from_registry(PLATFORM_ENTRY_NOTIFICATION_REGISTRY)
            
            # Generate CPE-AS data AFTER cpeDetermination and confirmed mappings are populated
            # This follows documented order: originAffectedEntry → sourceDataConcerns → aliasExtraction → cpeDetermination → cpeAsGeneration
            if cpe_as_generator or nvd_ish_only:
                nvd_ish_collector._generate_all_cpe_as()
            
            # Integrate CPE-AS generation data from Platform Entry Notification Registry (badge system path)
            # Note: In nvd-ish-only mode, CPE-AS is generated directly above, not from registry
            if cpe_as_generator and not nvd_ish_only:
                nvd_ish_collector.collect_cpe_as_generation_from_registry(PLATFORM_ENTRY_NOTIFICATION_REGISTRY)
            
            # Collect tool execution metadata with timestamps
            if tool_execution_timestamps:
                nvd_ish_collector.collect_tool_execution_metadata(tool_execution_timestamps)
       
            nvd_ish_collector.complete_cve_processing()
            
            logger.info(f"NVD-ish enhanced record collection completed for {cve_id}", group="data_processing")
        except RuntimeError as runtime_error:
            # Catch dual-source validation failures specifically
            logger.error(f"NVD-ish record generation failed for {cve_id} - {runtime_error}", group="data_processing")
            import traceback
            logger.debug(f"RuntimeError traceback:\n{traceback.format_exc()}", group="data_processing")
        except Exception as collection_error:
            import traceback
            logger.error(f"Failed to complete NVD-ish collection for {cve_id}: {collection_error}", group="data_processing")
            logger.error(f"Full traceback:\n{traceback.format_exc()}", group="data_processing")

        # Complete badge contents collection and return success
        complete_cve_collection()
        
        return {
            'success': True,
            'sdc_report': sdc_report,
            'cpe_suggestions': cpe_determination,
            'alias_report': alias_report,
            'cve_as_generator': cpe_as_generator,
            'cve_id': cve_id,
            'filepath': None
        }
        
    except Exception as e:
        logger.error(f"CVE processing failed for {cve_id}: Unable to complete analysis workflow - {str(e)}", group="data_processing")
        
        # Still complete badge contents collection even if processing failed
        complete_cve_collection()
        
        return {
            'success': False,
            'error': str(e),
            'cve_id': cve_id
        }

def audit_global_state(warn_on_bloat=True):
    """Audit global state for potential bloat accumulation
    
    Args:
        warn_on_bloat (bool): Whether to emit warnings for detected bloat. 
                             Set to False for interim audits, True for final audits.
    """
    try:
        from ..storage.cpe_cache import get_global_cache_manager
        
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
    logger.debug("Environment prepared for new CVE processing", group="data_processing")

def update_dashboard_async(current_cve_num, total_cves):
    """Update dashboard in parallel without blocking main CVE processing"""
    def _update_dashboard():
        # Use the dataset contents collector for real-time updates
        try:
            from ..reporting.dataset_contents_collector import get_dataset_contents_collector
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
        from ..reporting.dataset_contents_collector import get_dataset_contents_collector, update_cache_statistics
        
        # Update cache statistics with actual data from CPE cache
        # Don't save here - generate_dataset.py will call finalize_dataset_contents_report() which saves
        update_cache_statistics()
        return True
    except Exception as e:
        logger.debug(f"Failed to update cache statistics: {e}", group="completion")
        return False

def main():
    """Main function to process CVEs based on command line arguments."""
    global current_run_paths
    
    parser = argparse.ArgumentParser(description="Process CVE records with analysis_tool.py")
    
    # Group 1: Tool Output - What analysis outputs to generate
    output_group = parser.add_argument_group('Tool Output', 'Select which analysis outputs to generate')
    output_group.add_argument("--nvd-ish-only", nargs='?', const='true', choices=['true', 'false'], default='false',
                             help="Generate complete NVD-ish enriched records without report files or HTML (ignores other output flags)")
    output_group.add_argument("--sdc-report", nargs='?', const='true', choices=['true', 'false'], default='false',
                             help="Generate Source Data Concerns report (default: false, true if flag provided without value)")
    output_group.add_argument("--cpe-determination", nargs='?', const='true', choices=['true', 'false'], default='false', 
                             help="Generate CPE determination via NVD CPE API calls (default: false, true if flag provided without value)")
    output_group.add_argument("--alias-report", nargs='?', const='true', choices=['true', 'false'], default='false',
                             help="Generate alias report via curator features (default: false, true if flag provided without value)")
    output_group.add_argument("--cpe-as-generator", nargs='?', const='true', choices=['true', 'false'], default='false',
                             help="Generate CPE Applicability Statements as interactive HTML pages (default: false, true if flag provided without value)")
    
    # Group 2: Data Input/Sources - Specify what data to process and where to get it
    input_group = parser.add_argument_group('Data Input/Sources', 'Specify input data and data sources')
    input_sources = input_group.add_mutually_exclusive_group()
    input_sources.add_argument("--cve", nargs="+", help="One or more CVE IDs to process")
    input_sources.add_argument("--file", help="Text file with CVE IDs (one per line)")
    input_sources.add_argument("--test-file", help="JSON file with test CVE data for modular rules testing")
    input_group.add_argument("--api-key", type=str, nargs='?', const='CONFIG_DEFAULT', help="NVD API Key. Use without value to use config default, or provide explicit key")
    input_group.add_argument("--source-uuid", help="Filter platform entries by source UUID")
    
    # Group 3: Processing Control - Control how processing is performed and output is presented
    control_group = parser.add_argument_group('Processing Control', 'Control processing behavior and output presentation')
    control_group.add_argument("--no-cache", action="store_true", help="Disable CPE cache for faster testing")
    control_group.add_argument("--run-id", help="Continue within existing run directory (used by generate_dataset.py integration)")
    
    args = parser.parse_args()
    
    # Convert string boolean arguments to actual booleans
    sdc_report = args.sdc_report.lower() == 'true'
    cpe_determination = args.cpe_determination.lower() == 'true'
    alias_report = args.alias_report.lower() == 'true'
    cpe_as_generator = args.cpe_as_generator.lower() == 'true'
    nvd_ish_only = args.nvd_ish_only.lower() == 'true'
    
    logger.info("=== Analysis Tool Initialization Phase ===", group="INIT")
    
    # Handle --nvd-ish-only flag processing (enable analysis, disable output)
    if nvd_ish_only:
        # Enable ALL analysis processes for complete enrichment
        sdc_report = True
        cpe_determination = True
        alias_report = True  # Always enable for nvd-ish records (uses default curator mappings if no source_uuid)
        cpe_as_generator = True
    
    # Validate feature combinations
    # Note: nvd-ish-only mode doesn't require source-uuid because it extracts all aliases without filtering
    if alias_report and not args.source_uuid and not nvd_ish_only:
        print("ERROR: --alias-report requires --source-uuid to determine the appropriate confirmed mappings file")
        print("Example usage:")
        print("  python -m src.analysis_tool.core.analysis_tool --cve CVE-2024-XXXX --alias-report --source-uuid your-uuid-here")
        return
    
    # Validate that at least one feature is enabled (or nvd-ish-only mode)
    if not any([sdc_report, cpe_determination, alias_report, cpe_as_generator, nvd_ish_only]):
        print("ERROR: At least one feature must be enabled!")
        print("Available features:")
        print("  --sdc-report               : Generate Source Data Concerns report")
        print("  --cpe-determination        : Generate CPE determination via NVD CPE API calls")
        print("  --alias-report             : Generate alias report via curator features (COMING SOON)")
        print("  --cpe-as-generator         : Generate CPE Applicability Statements as interactive HTML pages")
        print("  --nvd-ish-only             : Generate complete NVD-ish enriched records without report files or HTML")
        print("")
        print("Example usage:")
        print("  python -m src.analysis_tool.core.analysis_tool --cve CVE-2024-20515 --sdc-report")
        print("  python -m src.analysis_tool.core.analysis_tool --cve CVE-2024-20515 --cpe-determination --cpe-as-generator")
        print("  python -m src.analysis_tool.core.analysis_tool --cve CVE-2024-20515 --nvd-ish-only --source-uuid your-uuid")
        return 1
    
    # Set global source UUID for filtering throughout the pipeline
    set_global_source_uuid(args.source_uuid)
    
    # Report enabled features
    enabled_features = []
    if nvd_ish_only:
        enabled_features.append("NVD-ish Enriched Records")
    if sdc_report:
        enabled_features.append("Source Data Concerns")
    if cpe_determination:
        enabled_features.append("CPE Determination")
    if alias_report:
        enabled_features.append("Alias Report")
    if cpe_as_generator:
        enabled_features.append("CPE-AS Generator")
    
    if enabled_features:
        logger.info(f"Enabled features: {', '.join(enabled_features)}", group="initialization")
    else:
        logger.info("No optional features enabled", group="initialization")
    
    # Automatically enable appropriate flags when CPE features are disabled
    if not cpe_determination and not cpe_as_generator:
        args.no_cache = True
        logger.info("CPE features disabled - enabling optimizations (--no-cache)", group="initialization")
    
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
    
    # Get API key (shared by both test file and CVE processing)
    nvd_api_key = ""
    
    # Handle API key resolution with config fallback
    if args.api_key == 'CONFIG_DEFAULT' or args.api_key is None:
        # Use config default when --api-key is used without value or not provided
        nvd_api_key = config['defaults']['default_api_key'] or ""
        if nvd_api_key and args.api_key == 'CONFIG_DEFAULT':
            logger.info(f"NVD API key detected | Source: Configuration", group="initialization")
        elif not nvd_api_key and args.api_key == 'CONFIG_DEFAULT':
            logger.warning("--api-key used without value but no default_api_key set in config.json", group="initialization")
            logger.info("Set default_api_key in config.json or provide key directly with --api-key YOUR_KEY", group="initialization")
    else:
        # Use explicitly provided API key
        nvd_api_key = args.api_key
        logger.info(f"NVD API key detected | Source: Direct Input", group="initialization")
    
    # Warn if no API key is available (for non-test files)
    if not nvd_api_key and not args.test_file:
        logger.warning("No NVD API key available - processing will be MUCH slower due to rate limiting", group="initialization")
        logger.info("Use --api-key YOUR_KEY or --api-key (for config default) or set default_api_key in config.json", group="initialization")
    
    # Get global NVD source manager (uses cache or refreshes as needed)
    from ..storage.nvd_source_manager import get_or_refresh_source_manager
    source_manager = get_or_refresh_source_manager(nvd_api_key, log_group="initialization")
    
    # Resolve organization name now that source manager is initialized
    from ..reporting.dataset_contents_collector import resolve_organization_name_if_needed
    resolve_organization_name_if_needed()
    
    # Initialize unified source manager
    from .unified_source_manager import get_unified_source_manager
    unified_manager = get_unified_source_manager()
    unified_manager.initialize()
    
    # Initialize global CPE cache (done once per session, shared by both paths)
    from ..storage.cpe_cache import get_global_cache_manager
    cache_manager = get_global_cache_manager()
    
    if args.no_cache:
        logger.info("Cache disabled for testing mode", group="initialization")
        # Initialize with disabled cache configuration
        cache_config = config.get('cache_settings', {}).get('cpe_cache', {}).copy()
        cache_config['enabled'] = False
        cache_manager.initialize(cache_config)
    else:
        cache_manager.initialize(config.get('cache_settings', {}).get('cpe_cache', {}))
    
    # Initialize confirmed mapping manager (requires NVD source manager)
    from ..storage.confirmed_mapping_manager import get_global_mapping_manager
    from ..storage.nvd_source_manager import get_global_source_manager
    
    mapping_manager = get_global_mapping_manager()
    if not mapping_manager.is_initialized():
        source_manager = get_global_source_manager()
        if not source_manager.is_initialized():
            raise RuntimeError(
                "NVD source manager must be initialized before confirmed mapping manager. "
                "Ensure harvest_and_process_sources.py or generate_dataset.py ran first to create source cache."
            )
        
        mapping_manager.initialize(source_manager=source_manager)
        logger.info(
            f"Confirmed mapping manager initialized: {mapping_manager.get_stats()['files_loaded']} files loaded",
            group="initialization"
        )
    else:
        logger.info("Confirmed mapping manager already initialized", group="initialization")
    
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
        
        # Configure alias reporting for incremental saves if enabled in test mode
        if alias_report and args.source_uuid:
            from ..logging.badge_contents_collector import configure_alias_reporting
            configure_alias_reporting(current_run_paths["logs"], args.source_uuid)
            logger.info("Alias reporting configured for incremental saves during test file processing", group="initialization")
        
        # Initialize dashboard collector for test file mode
        from ..reporting.dataset_contents_collector import initialize_dashboard_collector
        processing_mode = "test"
        cache_disabled = True  # Cache is always disabled for test files
        cache_disable_reason = "test-file"
        if initialize_dashboard_collector(str(current_run_paths["logs"]), processing_mode, cache_disabled, cache_disable_reason):
            logger.info("Dashboard collector initialized for test file mode", group="initialization")            
        
        # Process the test file (using global source manager)
        filepath = process_test_file(args.test_file)
        
        # Cleanup cache after test file processing
        cache_manager.save_and_cleanup()
        
        if filepath:
            logger.info("Test file processed successfully", group="data_processing")
        else:
            logger.error("Test file processing failed", group="data_processing")
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
        logger.info(f"Continuing use of existing run directory: {args.run_id}", group="initialization")
        
        # Check if run_id is a full path or just an ID
        from pathlib import Path
        run_id_path = Path(args.run_id)
        if run_id_path.is_absolute() and run_id_path.exists():
            # Full path provided - use it directly
            run_path = run_id_path
            run_id = run_path.name
            # Build run_paths dictionary manually for full path case
            run_paths = {
                "run_root": run_path,
                "logs": run_path / "logs"
            }
        else:
            # Just an ID provided - resolve it
            run_id = args.run_id
            run_paths = get_current_run_paths(run_id)
            run_path = run_paths["run_root"]
        
        # Verify run directory exists
        if not run_path.exists():
            logger.error(f"Specified run directory does not exist: {run_path}", group="initialization")
            return 1
    else:
        # Create new run directory using enhanced naming
        execution_type = "analysis"
        
        # Determine range/context specification
        range_spec = None
        if args.cve and len(args.cve) == 1:
            range_spec = args.cve[0]
        elif args.cve:
            range_spec = f"batch_{len(args.cve)}_CVEs"
        elif args.file:
            range_spec = os.path.basename(args.file).replace('.txt', '').replace('.', '_')
        
        # Prepare tool flags (only include those that are true)
        tool_flags = {}
        if sdc_report:
            tool_flags['sdc'] = True
        if cpe_determination:
            tool_flags['cpe-sug'] = True
        if alias_report:
            tool_flags['alias'] = True
        if cpe_as_generator:
            tool_flags['cpe-as-gen'] = True
        
        # Get source shortname if available
        source_shortname = None
        if args.source_uuid:
            # Try to resolve source UUID to shortname
            try:
                # Add src to path if not already there
                from pathlib import Path
                project_root = Path(__file__).parent.parent.parent.parent
                src_path = project_root / "src"
                if str(src_path) not in sys.path:
                    sys.path.insert(0, str(src_path))
                
                from ..storage.nvd_source_manager import get_or_refresh_source_manager
                
                # Get source manager for shortname resolution
                source_manager = get_or_refresh_source_manager(nvd_api_key, log_group="initialization")
                
                # Get human-readable shortname (capped to 7-8 characters)
                full_shortname = source_manager.get_source_shortname(args.source_uuid)
                source_shortname = full_shortname[:8] if len(full_shortname) > 8 else full_shortname
                
                logger.info(f"Resolved source UUID {args.source_uuid[:8]}... to shortname: '{source_shortname}'", group="initialization")
            except Exception as e:
                logger.warning(f"Could not resolve source UUID to shortname: {e}", group="initialization")
                source_shortname = None
        
        # Create run directory using enhanced naming
        # Check if we're in a test environment to enable consolidated test run handling
        is_test = os.environ.get('CONSOLIDATED_TEST_RUN') == '1'
        
        run_path, run_id = create_run_directory(
            execution_type=execution_type,
            source_shortname=source_shortname,
            range_spec=range_spec,
            tool_flags=tool_flags if tool_flags else None,
            is_test=is_test
        )
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
    from ..reporting.dataset_contents_collector import (
        clear_dataset_contents_collector, 
        save_dashboard_data,
        start_processing_run,
        initialize_dashboard_collector
    )
    from ..storage.nvd_ish_collector import get_nvd_ish_collector
    
    # Clear any existing state - but preserve dashboard data if continuing from generate_dataset
    clear_badge_contents_collector()
    if not args.run_id:
        # Only clear dashboard collector for new runs, not when continuing from generate_dataset
        clear_dataset_contents_collector()
    
    # Clear global registry state at run start to prevent cross-run contamination
    from .platform_entry_registry import clear_all_registries
    clear_all_registries()
    logger.debug("Global registries cleared at run initialization", group="initialization")
    
    # Initialize NVD-ish collector for enhanced record generation
    nvd_ish_collector = get_nvd_ish_collector()
    
    # Initialize badge contents collector - only create SDC report file if SDC reporting is enabled AND not in nvd-ish-only mode
    if sdc_report and not nvd_ish_only:
        initialize_badge_contents_report(str(run_paths["logs"]))
    else:
        # For alias extraction or nvd-ish-only mode, we still need the collector instance but don't create SDC report file
        from ..logging.badge_contents_collector import get_badge_contents_collector
        get_badge_contents_collector()  # This just creates the instance
    
    # Configure alias reporting for incremental saves if enabled (and not in nvd-ish-only mode)
    if alias_report and args.source_uuid and not nvd_ish_only:
        from ..logging.badge_contents_collector import configure_alias_reporting
        configure_alias_reporting(str(run_paths["logs"]), args.source_uuid)
        logger.info("Alias reporting configured for incremental saves during CVE processing", group="initialization")
    
    # Configure NVD-ish only mode for memory optimization if enabled
    if nvd_ish_only:
        from ..logging.badge_contents_collector import configure_nvd_ish_only_mode
        configure_nvd_ish_only_mode(True)  # Logs at DEBUG level internally
    
    # Initialize real-time dashboard collector
    from ..reporting.dataset_contents_collector import get_dataset_contents_collector
    get_dataset_contents_collector(config_dict=config)
    
    # Determine processing mode for dashboard tracking
    processing_mode = "sdc-only" if (sdc_report and not cpe_determination and not alias_report and not cpe_as_generator) else ("test" if args.test_file else "full")
    
    # Determine cache disable reason
    cache_disabled = args.no_cache
    cache_disable_reason = None
    if cache_disabled:
        if sdc_report and not cpe_determination and not alias_report and not cpe_as_generator:
            cache_disable_reason = "sdc-only"
        elif args.test_file:
            cache_disable_reason = "test-file"
        else:
            cache_disable_reason = "manual"
    
    if not initialize_dashboard_collector(str(run_paths["logs"]), processing_mode, cache_disabled, cache_disable_reason):
        logger.warning("Failed to initialize real-time dashboard collector", group="DATA_PROC")
    
    logger.info("=== END Analysis Tool Initialization Phase ===", group="INIT")

    
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
    
    total_cves = len(cves_to_process)
    
    # Start real-time dashboard processing run
    try:
        from ..reporting.dataset_contents_collector import start_processing_run, update_total_cves
        start_processing_run(total_cves)
        # Synchronize collector's total with the actual CVE count after loading
        update_total_cves(total_cves)
    except Exception as e:
        logger.warning(f"Failed to start real-time dashboard processing run: {e}", group="initialization")
    
    # Process all CVEs with progress tracking
    skipped_cves = []
    skipped_reasons = {}
    success_count = 0
    start_time = time.time()
    progress_config = config.get('progress', {})
    show_progress = progress_config.get('enabled', True)
    show_eta = progress_config.get('show_eta', True)
    show_timing = progress_config.get('show_individual_timing', True)
    
    if show_progress:
        logger.info("=== Starting CVE Record Processing Loop ===", group="INIT")
    
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
                eta = datetime.now(timezone.utc) + dt.timedelta(seconds=estimated_remaining_time)

                # Format time estimates
                elapsed_str = str(dt.timedelta(seconds=int(elapsed_time)))
                remaining_str = str(dt.timedelta(seconds=int(estimated_remaining_time)))
                eta_str = eta.strftime("%H:%M:%S")
                progress_msg = (f"Processing CVE {current_cve_num}/{total_cves} ({cve}) | "
                              f"Progress: {(current_cve_num-1)/total_cves*100:.1f}% | "
                              f"Elapsed: {elapsed_str} | ETA: {eta_str} | Remaining: {remaining_str}")
            else:
                progress_msg = f"Processing CVE {current_cve_num}/{total_cves} ({cve}) | Progress: {(current_cve_num-1)/total_cves*100:.1f}%"            
            logger.info(progress_msg, group="cve_queries")
        
        try:
            logger.info(f"Processing {cve}...", group="processing")
            
            # Memory optimization: clear cross-CVE alias tracking in nvd-ish-only mode
            if nvd_ish_only and index > 0:
                # Clear only the cross-CVE data accumulation used for alias reports
                # since we don't generate alias reports in nvd-ish-only mode
                from ..logging.badge_contents_collector import get_badge_contents_collector
                collector = get_badge_contents_collector()
                if hasattr(collector, 'cve_data'):
                    collector.cve_data.clear()  # Clear accumulated CVE data to prevent memory bloat
            
            # Start CVE processing in real-time collector
            try:
                from ..reporting.dataset_contents_collector import start_cve_processing
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
                    elapsed_str = str(dt.timedelta(seconds=int(elapsed_time)))
                    remaining_str = str(dt.timedelta(seconds=int(estimated_remaining_time)))
                    eta = datetime.now(timezone.utc) + dt.timedelta(seconds=estimated_remaining_time)
                    eta_str = eta.strftime("%H:%M:%S")
                    
                    logger.debug(f"Processing statistics: {(current_cve_num-1)/total_cves*100:.1f}% complete", group="INIT")
                    logger.debug(f"Timing: Elapsed: {elapsed_str} | ETA: {eta_str} | Remaining: {remaining_str}", group="INIT")
                    logger.debug(f"Performance: Average {avg_time_per_cve:.2f}s per CVE", group="INIT")
                    
                    # Memory optimization: additional cleanup in nvd-ish-only mode
                    if nvd_ish_only:
                        logger.debug(f"Memory usage at checkpoint - applying aggressive cleanup (nvd-ish-only mode)", group="INIT")
                
                audit_global_state(warn_on_bloat=False)
                audit_cache_and_mappings_stats()
                
                # Start dashboard update in parallel (non-blocking)
                update_dashboard_async(current_cve_num, total_cves)
                logger.debug("Background dashboard update started", group="INIT")
                
                end_audit("Checkpoint audit complete")
            
            # Process the CVE
            result = process_cve(cve, nvd_api_key, sdc_report, cpe_determination, alias_report, cpe_as_generator, nvd_ish_only)
            
            # Handle results: successful processing, skipped CVEs, or failures
            if result:
                if result['success']:
                    # Log successful processing
                    feature_names = []
                    if result.get('sdc_report'): feature_names.append("SDC")
                    if result.get('cpe_suggestions'): feature_names.append("CPE-determination")
                    if result.get('alias_report'): feature_names.append("alias")
                    if result.get('cve_as_generator'): feature_names.append("CPE-AS")
                    feature_suffix = f" ({', '.join(feature_names)})" if feature_names else ""
                    
                    if show_timing:
                        cve_elapsed = time.time() - cve_start_time
                        logger.info(f"Successfully processed {cve}{feature_suffix} in {cve_elapsed:.2f}s", group="processing")
                    else:
                        logger.info(f"Successfully processed {cve}{feature_suffix}", group="processing")
                    
                    success_count += 1
                    
                    # Mark as successfully completed in progress tracker
                    try:
                        from ..reporting.dataset_contents_collector import finish_cve_processing
                        finish_cve_processing(cve, skipped=False)
                    except Exception as e:
                        logger.debug(f"Real-time collector unavailable for CVE completion tracking: {e}", group="data_processing")
                        
                elif result.get('skipped'):
                    # CVE was skipped (e.g., REJECTED status)
                    if show_timing:
                        cve_elapsed = time.time() - cve_start_time
                        logger.info(f"Skipped {cve} ({result.get('reason', 'unknown reason')}) in {cve_elapsed:.2f}s", group="processing")
                    else:
                        logger.info(f"Skipped {cve} ({result.get('reason', 'unknown reason')})", group="processing")
                    
                    # Mark as skipped in progress tracker
                    try:
                        from ..reporting.dataset_contents_collector import finish_cve_processing
                        finish_cve_processing(cve, skipped=True)
                    except Exception as e:
                        logger.debug(f"Real-time collector unavailable for CVE completion tracking: {e}", group="data_processing")
                else:
                    # CVE processing failed with error
                    error_msg = result.get('error', 'Unknown error')
                    logger.error(f"Failed to process {cve}: {error_msg}", group="data_processing")
                    skipped_cves.append(cve)
                    skipped_reasons[cve] = error_msg
                
                    # Mark as completed (failed) in progress tracker
                    try:
                        from ..reporting.dataset_contents_collector import finish_cve_processing
                        finish_cve_processing(cve, skipped=False)
                    except Exception as e:
                        logger.debug(f"Real-time collector unavailable for CVE completion tracking: {e}", group="data_processing")
            else:
                # CVE processing failed entirely - no result returned
                logger.error(f"Failed to process {cve}: No result returned", group="data_processing")
                skipped_cves.append(cve)
                skipped_reasons[cve] = "No result returned"
                
                # Still complete CVE processing in real-time collector to maintain accurate counts
                try:
                    from ..reporting.dataset_contents_collector import finish_cve_processing
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
    
    logger.info(f"Processing complete!", group="completion")
    logger.info(f"Total CVEs processed: {total_cves}", group="completion")
    logger.info(f"Successfully generated: {success_count}", group="completion")
    logger.info(f"Skipped: {len(skipped_cves)}", group="completion")
    logger.info(f"Total time: {str(dt.timedelta(seconds=int(total_time)))}", group="completion")
    
    # Wait for any pending background dashboard updates and perform final update
    wait_for_dashboard_updates()
    finalize_dashboard_data()
    
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
    
    # Finalize badge contents report (skip in NVD-ish only mode)
    from ..logging.badge_contents_collector import finalize_badge_contents_report, generate_alias_extraction_report
    if not nvd_ish_only:
        badge_report_path = finalize_badge_contents_report()
        if badge_report_path:
            logger.info(f"Badge contents report finalized: {badge_report_path}", group="completion")
    
    # Generate alias extraction report if enabled (skip in NVD-ish only mode)
    if args.alias_report and not nvd_ish_only:
        source_uuid = getattr(args, 'source_uuid', None) or 'unknown_source'
        alias_report_path = generate_alias_extraction_report(str(run_paths["logs"]), source_uuid)
        if alias_report_path:
            logger.info(f"Alias extraction report generated: {alias_report_path}", group="completion")
        else:
            logger.info("No alias extraction data found - alias report not generated", group="completion")
    
    # Stop file logging
    logger.stop_file_logging()
    
    # Return success exit code
    return 0


if __name__ == "__main__":
    sys.exit(main())
