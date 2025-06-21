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
    log_init, log_cve_query, log_data_proc, log_error_handle, log_page_gen
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
            affectedHtml2 = re.sub(r'<th[^>]*>cpeQueryHTML</th>', 
                                  r'<th class="hidden-header" style="min-width: 80%;">cpeQueryHTML</th>', 
                                  affectedHtml2)        # Generate page and save HTML
        allConsoleHTML = generateHTML.buildHTMLPage(affectedHtml2, cve_id, globalCVEMetadata)

        # Save output
        sub_directory = Path(f"{os.getcwd()}{os.sep}generated_pages")
        sub_directory.mkdir(parents=True, exist_ok=True)
        filename = f"{cve_id}.html"
        filepath = sub_directory / filename
        
        with filepath.open("w", encoding="utf-8") as fd:
            fd.write(allConsoleHTML)        
        logger.file_operation("Generated", str(filepath), "test file", group="page_generation")
        end_page_generation("HTML file created")
        return filepath
        
    except Exception as e:
        logger.error(f"Failed to process test file {test_file_path}: {str(e)}", group="error_handling")
        logger.debug(f"Error type: {type(e).__name__}", group="error_handling")
        import traceback
        traceback.print_exc()
        return None

def process_cve(cve_id, nvd_api_key, nvd_source_data):
    """Process a single CVE using the analysis tool functionality."""
    
    # Clear global HTML state to prevent accumulation from previous CVEs    generateHTML.clear_global_html_state()    
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
                logger.warning(f"{cve_id} has invalid CPE match string - skipping processing", group="error_handling")
                logger.debug(f"Error: {error_str}", group="error_handling")
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
            logger.warning(f"{cve_id} encountered an error during CPE suggestion: {str(cpe_error)}", group="error_handling")
            logger.info("Continuing with available data...", group="error_handling")
        
        # Note: CPE generation and query stages are now handled internally by suggestCPEData
        
        start_confirmed_mappings("Processing confirmed mappings")

        # Process confirmed mappings
        try:
            primaryDataframe = processData.process_confirmed_mappings(primaryDataframe)
        except Exception as mapping_error:
            logger.warning(f"{cve_id} encountered an error during confirmed mappings: {str(mapping_error)}", group="error_handling")
            logger.info("Continuing with available data...", group="error_handling")
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
        return filepath
        
    except Exception as e:
        logger.error(f"Failed to process {cve_id}: {str(e)}", group="error_handling")
        return None

def get_all_cves(nvd_api_key):
    """Get all CVEs from NVD API."""
    return gatherData.gatherAllCVEIDs(nvd_api_key)

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
    DEFAULT_CVE_MODE = "single"  # Change this to "all" when needed
    DEFAULT_CVE_ID = "CVE-2024-20515"  # Default CVE to process in single mode
    
    args = parser.parse_args()
    
    # Handle test file processing
    if args.test_file:
        logger.info("Test file mode: Processing local test file instead of querying APIs", group="initialization")
        
        # Check if test file exists
        if not os.path.exists(args.test_file):
            logger.error(f"Test file '{args.test_file}' not found", group="error_handling")
            sys.exit(1)
        
        # For test files, we still need NVD source data for product mapping
        nvd_api_key = args.api_key or ""  # API key is optional for test files
        logger.info("Gathering NVD source data...", group="initialization")
        nvd_source_data = gatherData.gatherNVDSourceData(nvd_api_key)
        
        # Process the test file
        filepath = process_test_file(args.test_file, nvd_source_data)
        
        if filepath:
            logger.info(f"Test file processed successfully: {filepath}", group="page_generation")
            
            # Open in browser if requested
            if not args.no_browser:
                import webbrowser
                webbrowser.open_new_tab(f"file:///{filepath}")
        else:
            logger.error("Test file processing failed", group="error_handling")
            sys.exit(1)
        
        return
    
    # Debug mode - set default options based on config
    if args.debug or not (args.cve or args.file or args.all):
        if config['debug']['default_cve_mode'].lower() == "all":
            logger.info("Debug mode: Processing all CVEs by default", group="initialization")
            args.all = True
        else:
            logger.info(f"Debug mode: Processing single CVE {config['debug']['default_cve_id']}", group="initialization")
            args.cve = [config['debug']['default_cve_id']]    
    # Get API key
    nvd_api_key = args.api_key or config['debug']['default_api_key'] or input("Enter NVD API Key (optional, but processing will be slower without it): ").strip()
    
    # Start main initialization stage
    start_initialization("Setting up analysis environment")
    
    # Gather NVD Source Data (done once)
    logger.info("Gathering NVD source data...", group="initialization")
    nvd_source_data = gatherData.gatherNVDSourceData(nvd_api_key)
    
    cves_to_process = []
    
    if args.cve:
        cves_to_process = args.cve
    elif args.file:
        try:
            with open(args.file, 'r') as file:
                cves_to_process = [line.strip() for line in file if line.strip()]
        except Exception as e:
            logger.error(f"Error reading file {args.file}: {e}", group="error_handling")
            sys.exit(1)
    elif args.all:
        cves_to_process = get_all_cves(nvd_api_key)
      # Reverse the order of CVEs to process newer ones first (typically higher CVE numbers)
    cves_to_process.sort(reverse=True)
    
    logger.info(f"Processing {len(cves_to_process)} CVE records (newest first)...", group="initialization")
    
    end_initialization("Analysis environment ready, CVE list prepared")
    
    # Process all CVEs
    generated_files = []
    skipped_cves = []
    skipped_reasons = {}  
    total_cves = len(cves_to_process)
    for index, cve in enumerate(cves_to_process):
        try:
            filepath = process_cve(cve, nvd_api_key, nvd_source_data)
            if filepath:
                generated_files.append(filepath)
            else:
                skipped_cves.append(cve)
                skipped_reasons[cve] = "CVE processing returned None (possibly REJECTED state)"
                logger.info(f"Skipped {cve} - continuing with next CVE", group="initialization")
        except Exception as e:
            logger.error(f"Failed to process {cve}: {e}", group="error_handling")
            logger.info("Continuing with next CVE...", group="initialization")
            skipped_cves.append(cve)
            skipped_reasons[cve] = str(e)
            # Continue with the next CVE regardless of any errors
            continue
    
    logger.info(f"Processed {len(generated_files)} CVE records successfully.", group="initialization")
    
    # Report skipped CVEs
    if skipped_cves:
        logger.info(f"Skipped {len(skipped_cves)} CVE records:", group="initialization")
        
        # Show a sample of skipped CVEs if there are many
        display_limit = 20
        if len(skipped_cves) <= display_limit:
            for cve in skipped_cves:
                reason = skipped_reasons.get(cve, "Unknown reason")
                logger.info(f"  - {cve}: {reason}", group="initialization")
        else:
            for cve in skipped_cves[:display_limit]:
                reason = skipped_reasons.get(cve, "Unknown reason")
                logger.info(f"  - {cve}: {reason}", group="initialization")
            logger.info(f"  ...and {len(skipped_cves) - display_limit} more (see skipped CVEs file for complete list)", group="initialization")
        
        # Save skipped CVEs to file if requested
        if args.save_skipped or len(skipped_cves) > display_limit:
            skipped_file = args.save_skipped or "skipped_cves.txt"
            try:
                with open(skipped_file, 'w') as f:
                    f.write("# Skipped CVEs and reasons\n")
                    f.write("# Format: CVE_ID,Reason\n")
                    for cve in skipped_cves:
                        reason = skipped_reasons.get(cve, "Unknown reason")
                        # Escape commas in reason to maintain CSV format
                        reason_escaped = reason.replace(',', '\\,')
                        f.write(f"{cve},{reason_escaped}\n")
                logger.info(f"Saved list of skipped CVEs to {skipped_file}", group="initialization")
            except Exception as e:
                logger.error(f"Error saving skipped CVEs list: {e}", group="error_handling")
    
    logger.info(f"Output files saved in {Path(f'{os.getcwd()}{os.sep}generated_pages')}", group="initialization")
    
    # Open results in browser if requested
    if not args.no_browser and generated_files:
        import webbrowser
        for filepath in generated_files[:5]:  # Open only first 5 files to avoid browser overload
            webbrowser.open_new_tab(f"file:///{filepath}")
        if len(generated_files) > 5:
            logger.info(f"Note: Opened only the first 5 of {len(generated_files)} generated files in browser", group="initialization")

if __name__ == "__main__":
    main()