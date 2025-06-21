#!/usr/bin/env python3
"""
Test script to demonstrate the new logging system with all implemented groups
"""

import sys
import os

# Add the src/analysis_tool directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src', 'analysis_tool'))

from workflow_logger import WorkflowLogger

def demo_logging_system():
    """Demonstrate the new logging system with all implemented groups and features"""
    logger = WorkflowLogger()
    
    print("=" * 60)
    print("ANALYSIS TOOL - NEW LOGGING SYSTEM DEMONSTRATION")
    print("=" * 60)
    print()
    
    # Simulate a complete CVE processing workflow using all implemented groups
    cve_id = "CVE-2024-20515"
    
    # Stage 1: Initialization
    logger.stage_start("Initialization", f"CVE {cve_id}")
    logger.info("Loading configuration files", group="initialization")
    logger.info("Setting up primary dataframe", group="initialization")
    logger.info("Validating CVE ID format", group="initialization")
    logger.debug("Debug mode enabled in configuration", group="initialization")
    logger.warning("Using default API configuration (no key provided)", group="initialization")
    logger.stage_end("Initialization", "Primary dataframe created")
    print()
    
    # Stage 2: CVE Queries
    logger.stage_start("CVE Queries", f"Gathering data for {cve_id}")
    logger.api_call("MITRE CVE API", {"cve_id": cve_id}, group="cve_queries")
    logger.info("CVE state validation passed", group="cve_queries")
    logger.api_response("MITRE CVE API", "Success", group="cve_queries")
    logger.api_call("NVD CVE API", {"cve_id": cve_id, "api_key": "provided"}, group="cve_queries")
    logger.info("Processing NVD CVE record data", group="cve_queries")
    logger.api_response("NVD CVE API", "Success", group="cve_queries")
    logger.api_call("NVD Source API", {}, group="cve_queries")
    logger.info("Gathering NVD source mappings", group="cve_queries")
    logger.api_response("NVD Source API", "Success", group="cve_queries")
    logger.debug("CVE metadata extraction completed", group="cve_queries")
    logger.stage_end("CVE Queries", "CVE data retrieved")
    print()
    
    # Stage 3: Unique CPE Generation
    logger.stage_start("Unique CPE Generation", "Processing CVE and NVD data")
    logger.info("Extracting CPE base strings from CVE platforms", group="cpe_generation")
    logger.data_summary("CVE Data Processing", platforms_found=12, cpe_strings_extracted=45, group="cpe_generation")
    logger.info("Processing NVD configuration data", group="cpe_generation")
    logger.data_summary("NVD Data Processing", configurations_found=3, cpe_matches_extracted=18, group="cpe_generation")
    logger.info("Deduplicating CPE base strings", group="cpe_generation")
    logger.debug("Applying CPE normalization rules", group="cpe_generation")
    logger.warning("Found 3 CPE strings with placeholder data", group="cpe_generation")
    logger.data_summary("Deduplication Results", total_cpe_strings=63, unique_cpe_strings=28, group="cpe_generation")
    logger.stage_end("Unique CPE Generation", "CPE base strings extracted")
    print()
    
    # Stage 4: Badge Generation
    logger.stage_start("Badge Generation", "Processing confirmed mappings")
    logger.info("Loading confirmed mappings from local files", group="badge_generation")
    logger.debug("Processing microsoft.json mapping file", group="badge_generation")
    logger.debug("Processing linux_kernel.json mapping file", group="badge_generation")
    logger.data_summary("Confirmed Mappings", mapping_files_loaded=2, total_mappings=156, applied_mappings=12, group="badge_generation")
    logger.info("Generating status badges for products", group="badge_generation")
    logger.info("Applying confirmed mapping badges", group="badge_generation")
    logger.info("Applying suggested product badges", group="badge_generation")
    logger.warning("3 products have no matching CPE entries", group="badge_generation")
    logger.data_summary("Badge Results", confirmed_products=12, suggested_products=134, no_match_products=3, group="badge_generation")
    logger.stage_end("Badge Generation", "Confirmed mappings processed")
    print()
    
    # Stage 5: CPE Queries
    logger.stage_start("CPE Queries", "Querying NVD CPE API")
    logger.info("Generating Unique CPE Match Strings...", group="cpe_queries")
    logger.data_summary("CPE Summary", total_processed=1, queries_generated=4, group="cpe_queries")
    logger.info("Querying NVD /cpes/ API to get CPE Dictionary information...", group="cpe_queries")
    logger.debug("Processing paginated API responses", group="cpe_queries")
    logger.warning("Rate limiting detected, applying delay", group="cpe_queries")
    logger.info("Collected 20000 of 35180 results...", group="cpe_queries")
    logger.info("Collected 35180 of 35180 results...", group="cpe_queries")
    logger.warning("2 queries failed due to invalid CPE format", group="cpe_queries")
    logger.stage_end("CPE Queries", "CPE queries completed")
    print()
    
    # Stage 6: Page Generation
    logger.stage_start("Page Generation", "Generating HTML output")
    logger.info("Converting dataframe to HTML", group="page_generation")
    logger.info("Applying CSS styling and JavaScript", group="page_generation")
    logger.info("Embedding interactive components", group="page_generation")
    logger.debug("Adding modular rules JavaScript modules", group="page_generation")
    logger.debug("Adding provenance assistance features", group="page_generation")
    logger.info("Generating JSON configuration widgets", group="page_generation")
    logger.file_operation("Generated", f"E:\\Git\\Analysis_Tools\\generated_pages\\{cve_id}.html", group="page_generation")
    logger.stage_end("Page Generation", "HTML file created")
    print()
    
    # Stage 7: Data Processing Examples
    logger.info("Cleaning dataframe columns", group="data_processing")
    logger.debug("Dropping temporary processing columns", group="data_processing")
    logger.info("Applying column width configurations", group="data_processing")
    logger.warning("Some rows missing platform metadata", group="data_processing")
    logger.info("Found 156 confirmed mapping(s) for row 1", group="data_processing")
    logger.info("Culled 12 less specific confirmed mapping(s) for row 1", group="data_processing")
    logger.warning("Row 5 missing platformEntryMetadata", group="data_processing")
    logger.warning("Empty CPE string found in row 7", group="data_processing")
    logger.info("Processing Maven package: org.apache.httpd", group="data_processing")
    logger.info("ISSUES FOUND (3 total):", group="data_processing")
    logger.info("  Placeholder Data (2 entries):", group="data_processing")
    logger.info("  Row 1 (CVE): vendor='n/a', product='n/a'", group="data_processing")
    logger.info("No issues detected - all data processed successfully", group="data_processing")
    print()
    
    # Stage 8: Error Handling Examples
    logger.warning("Simulated API rate limit warning", group="error_handling")
    logger.error("Error processing NVD record data: Connection timeout", group="error_handling")
    logger.error("Failed to process CVE-2024-99999: Invalid state", group="error_handling")
    logger.warning("Error processing confirmed mappings for row 15: Missing field", group="error_handling")
    logger.warning("Error querying NVD API for 'invalid_cpe': Malformed request", group="error_handling")
    logger.error("CVE Services CVE ID check failed! CVE-ID mismatch", group="error_handling")
    logger.error("CVE record is in the REJECTED state!", group="error_handling")
    logger.warning("Malformed CPE string: cpe:2.3:invalid", group="error_handling")
    logger.info("Applying retry logic for failed requests", group="error_handling")
    logger.debug("Error recovery mechanisms activated", group="error_handling")
    logger.warning("Continuing with available data after partial failure", group="error_handling")
    print()

    print("=" * 60)
    print("LOGGING DEMONSTRATION COMPLETE")
    print("=" * 60)
    print()
    print("The new logging system provides:")
    print("• Organized groups for different workflow stages")
    print("• Clean messages without redundant group prefixes")
    print("• Stage banners for clear workflow organization")
    print("• Consistent formatting and timestamps")
    print("• Color-coded output (when supported)")
    print("• Structured data summaries")
    print("• API call tracking")
    print("• File operation logging")
    print("• Progress tracking within stages")
    print("• Configurable log levels and group enabling/disabling")
    print("• Debug, Info, Warning, and Error level examples for each group")
    print()
    print("All implemented logging groups demonstrated:")
    print("• initialization - System startup and CVE processing setup")
    print("• cve_queries - CVE data retrieval from MITRE and NVD APIs")
    print("• cpe_generation - CPE string extraction and deduplication")
    print("• badge_generation - Status badges and confirmed mappings")
    print("• cpe_queries - NVD CPE API queries and product matching")
    print("• page_generation - HTML generation and file output")
    print("• data_processing - Data validation and processing operations")
    print("• error_handling - Exception handling and error recovery")

if __name__ == "__main__":
    demo_logging_system()
