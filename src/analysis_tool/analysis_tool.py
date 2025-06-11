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

def process_test_file(test_file_path, nvd_source_data):
    """Process a test file containing CVE data for testing modular rules."""
    print(f"Processing test file: {test_file_path}...")
    
    try:
        # Load test data from JSON file
        with open(test_file_path, 'r', encoding='utf-8') as f:
            test_data = json.load(f)
        
        # Extract CVE ID from test data
        cve_id = test_data.get('cveMetadata', {}).get('cveId', 'TEST-CVE-0000-0000')
        print(f"Test CVE ID: {cve_id}")
        
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
        
        # Process the vulnerability record data
        primaryDataframe, globalCVEMetadata = processData.processCVEData(primaryDataframe, cveRecordData, nvd_source_data)             
        primaryDataframe = processData.processNVDRecordData(primaryDataframe, nvdRecordData)      
        
        # Skip CPE suggestions for test files to avoid API calls
        # primaryDataframe = processData.suggestCPEData(nvd_api_key, primaryDataframe, 1)
        
        # For test files, ensure CPE data fields are proper dictionaries instead of empty lists
        for index, row in primaryDataframe.iterrows():
            if isinstance(primaryDataframe.at[index, 'sortedCPEsQueryData'], list):
                primaryDataframe.at[index, 'sortedCPEsQueryData'] = {}
            if isinstance(primaryDataframe.at[index, 'trimmedCPEsQueryData'], list):
                primaryDataframe.at[index, 'trimmedCPEsQueryData'] = {}
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
        
        print(f"Generated test file: {filepath}")
        return filepath
        
    except Exception as e:
        print(f"[ERROR] Failed to process test file {test_file_path}: {str(e)}")
        return None

def process_cve(cve_id, nvd_api_key, nvd_source_data):
    """Process a single CVE using the analysis tool functionality."""
    print(f"Processing {cve_id}...")
    
    # Make sure the string is formatted well
    cve_id = cve_id.strip().upper()
    processData.integrityCheckCVE("cveIdFormat", cve_id)
    
    # Create Primary Datasets from external sources
    primaryDataframe = gatherData.gatherPrimaryDataframe()

    try:
        # Gather CVE List Record and NVD Dataset Records for the target CVE
        cveRecordData = gatherData.gatherCVEListRecord(cve_id)
        
        # Check if CVE is in REJECTED state
        if cveRecordData and 'cveMetadata' in cveRecordData:
            state = cveRecordData.get('cveMetadata', {}).get('state')
            if state == 'REJECTED':
                print(f"[WARNING] {cve_id} is in REJECTED state - skipping processing")
                return None
        
        try:
            nvdRecordData = gatherData.gatherNVDCVERecord(nvd_api_key, cve_id)
        except Exception as api_error:
            # Handle specific NVD API errors
            error_str = str(api_error)
            if "Invalid cpeMatchstring parameter" in error_str:
                print(f"[WARNING] {cve_id} has invalid CPE match string - skipping processing")
                print(f"          Error: {error_str}")
                return None
            else:
                # Re-raise other exceptions
                raise
        
        # Process the vulnerability record data
        primaryDataframe, globalCVEMetadata = processData.processCVEData(primaryDataframe, cveRecordData, nvd_source_data)             
        primaryDataframe = processData.processNVDRecordData(primaryDataframe, nvdRecordData)

        # Suggest CPE data based on collected information
        try:
            primaryDataframe = processData.suggestCPEData(nvd_api_key, primaryDataframe, 1)
        except Exception as cpe_error:
            # Handle CPE suggestion errors
            print(f"[WARNING] {cve_id} encountered an error during CPE suggestion: {str(cpe_error)}")
            print("          Continuing with available data...")
            
        
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
        
        print(f"Generated {filepath}")
        return filepath
    except Exception as e:
        print(f"[ERROR] Failed to process {cve_id}: {str(e)}")
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
        print("Test file mode: Processing local test file instead of querying APIs")
        
        # Check if test file exists
        if not os.path.exists(args.test_file):
            print(f"Error: Test file '{args.test_file}' not found")
            sys.exit(1)
        
        # For test files, we still need NVD source data for product mapping
        nvd_api_key = args.api_key or ""  # API key is optional for test files
        print("Gathering NVD source data...")
        nvd_source_data = gatherData.gatherNVDSourceData(nvd_api_key)
        
        # Process the test file
        filepath = process_test_file(args.test_file, nvd_source_data)
        
        if filepath:
            print(f"Test file processed successfully: {filepath}")
            
            # Open in browser if requested
            if not args.no_browser:
                import webbrowser
                webbrowser.open_new_tab(f"file:///{filepath}")
        else:
            print("Test file processing failed")
            sys.exit(1)
        
        return
    
    # Debug mode - set default options based on DEFAULT_CVE_MODE
    if args.debug or not (args.cve or args.file or args.all):
        if DEFAULT_CVE_MODE.lower() == "all":
            print("Debug mode: Processing all CVEs by default")
            args.all = True
        else:
            print(f"Debug mode: Processing single CVE {DEFAULT_CVE_ID}")
            args.cve = [DEFAULT_CVE_ID]
    
    # Get API key
    nvd_api_key = args.api_key or input("Enter NVD API Key (optional, but processing will be slower without it): ").strip()
    
    # Gather NVD Source Data (done once)
    print("Gathering NVD source data...")
    nvd_source_data = gatherData.gatherNVDSourceData(nvd_api_key)
    
    cves_to_process = []
    
    if args.cve:
        cves_to_process = args.cve
    elif args.file:
        try:
            with open(args.file, 'r') as file:
                cves_to_process = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(f"Error reading file {args.file}: {e}")
            sys.exit(1)
    elif args.all:
        cves_to_process = get_all_cves(nvd_api_key)
    
    # Reverse the order of CVEs to process newer ones first (typically higher CVE numbers)
    cves_to_process.sort(reverse=True)
    
    print(f"Processing {len(cves_to_process)} CVE records (newest first)...")
    
    # Process all CVEs
    generated_files = []
    skipped_cves = []
    skipped_reasons = {}  
    
    total_cves = len(cves_to_process)
    for index, cve in enumerate(cves_to_process):
        try:
            print(f"[{index+1}/{total_cves}] Processing {cve}...")
            filepath = process_cve(cve, nvd_api_key, nvd_source_data)
            if filepath:
                generated_files.append(filepath)
            else:
                skipped_cves.append(cve)
                skipped_reasons[cve] = "CVE processing returned None (possibly REJECTED state)"
                print(f"[INFO] Skipped {cve} - continuing with next CVE")
        except Exception as e:
            print(f"[ERROR] Failed to process {cve}: {e}")
            print("[INFO] Continuing with next CVE...")
            skipped_cves.append(cve)
            skipped_reasons[cve] = str(e)
            # Continue with the next CVE regardless of any errors
            continue
    
    print(f"\nProcessed {len(generated_files)} CVE records successfully.")
    
    # Report skipped CVEs
    if skipped_cves:
        print(f"Skipped {len(skipped_cves)} CVE records:")
        
        # Show a sample of skipped CVEs if there are many
        display_limit = 20
        if len(skipped_cves) <= display_limit:
            for cve in skipped_cves:
                reason = skipped_reasons.get(cve, "Unknown reason")
                print(f"  - {cve}: {reason}")
        else:
            for cve in skipped_cves[:display_limit]:
                reason = skipped_reasons.get(cve, "Unknown reason")
                print(f"  - {cve}: {reason}")
            print(f"  ...and {len(skipped_cves) - display_limit} more (see skipped CVEs file for complete list)")
        
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
                print(f"Saved list of skipped CVEs to {skipped_file}")
            except Exception as e:
                print(f"Error saving skipped CVEs list: {e}")
    
    print(f"Output files saved in {Path(f'{os.getcwd()}{os.sep}generated_pages')}")
    
    # Open results in browser if requested
    if not args.no_browser and generated_files:
        import webbrowser
        for filepath in generated_files[:5]:  # Open only first 5 files to avoid browser overload
            webbrowser.open_new_tab(f"file:///{filepath}")
        if len(generated_files) > 5:
            print(f"Note: Opened only the first 5 of {len(generated_files)} generated files in browser")

if __name__ == "__main__":
    main()