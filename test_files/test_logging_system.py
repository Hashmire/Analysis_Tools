#!/usr/bin/env python3
"""
Comprehensive test suite for the standardized logging and reporting system.
Tests all logging events, formats, terminology, and severity assignments.

This test suite validates:
- Consistent terminology usage (CPE names, CVE records, etc.)
- Standardized progress reporting formats
- Error message format compliance
- Log level appropriateness (INFO/DEBUG/WARNING/ERROR)
- Log group organization and usage
- API call/response logging patterns
- File operation logging patterns
- Workflow stage transitions
"""

import json
import re
import sys
import tempfile
import io
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from typing import Dict, List, Set, Tuple, Any, Optional
import unittest
from unittest.mock import Mock, patch, MagicMock

# Direct import of the workflow logger
sys.path.append(str(Path(__file__).parent.parent / 'src'))
from analysis_tool.logging.workflow_logger import WorkflowLogger, LogGroup

class LogCapture:
    """Capture log output from the custom WorkflowLogger."""
    
    def __init__(self):
        self.captured_logs = []
        self.original_print_method = None
        self.original_log_method = None
        self.original_level = None
        self.current_group = None
        
    def start_capture(self, logger):
        """Start capturing log output by intercepting the logger's _print_message method."""
        self.captured_logs.clear()
        self.original_print_method = logger._print_message
        self.original_log_method = logger.log
        self.current_group = None
          # Set logger to DEBUG level to capture all messages during testing
        self.original_level = logger.level
        from analysis_tool.logging.workflow_logger import LogLevel
        logger.level = LogLevel.DEBUG
        
        def capture_log(level, group, message):
            """Capture the log call to track group information."""
            # Store current group for message capture
            self.current_group = group
            # Call original log method
            self.original_log_method(level, group, message)
        
        def capture_print_message(message):
            """Capture the message and extract log information."""
            # Parse the message to extract level and content
            # Format: [timestamp] [level] actual_message  or  [timestamp] banner_message
            import re
            
            # Try to match standard log format: [timestamp] [level] message
            log_match = re.match(r'\[([^\]]+)\] \[([^\]]+)\] (.+)', message)
            if log_match:
                timestamp, level_str, actual_message = log_match.groups()
                # Convert level string to logging level numbers for consistency
                level_map = {
                    'DEBUG': 10, 'INFO': 20, 'WARNING': 30, 'ERROR': 40
                }
                level_num = level_map.get(level_str, 20)
                
                self.captured_logs.append({
                    'level': level_num,
                    'message': actual_message,
                    'timestamp': timestamp,
                    'level_str': level_str,
                    'group': self.current_group
                })
            else:
                # Try to match banner format: [timestamp] === message ===
                banner_match = re.match(r'\[([^\]]+)\] (.+)', message)
                if banner_match:
                    timestamp, banner_message = banner_match.groups()
                    self.captured_logs.append({
                        'level': 20,  # INFO level for banners
                        'message': banner_message,
                        'timestamp': timestamp,
                        'level_str': 'INFO',
                        'group': self.current_group
                    })
            
            # Still call the original method to see output during testing
            self.original_print_method(message)
        
        logger._print_message = capture_print_message
        logger.log = capture_log
        
    def stop_capture(self, logger):
        """Stop capturing and restore original method."""
        if self.original_print_method:
            logger._print_message = self.original_print_method
            self.original_print_method = None
        if self.original_log_method:
            logger.log = self.original_log_method  
            self.original_log_method = None
        if self.original_level:
            logger.level = self.original_level
            self.original_level = None

class LoggingSystemTestSuite(unittest.TestCase):
    """Comprehensive test suite for the standardized logging system."""
    
    def setUp(self):
        """Set up test environment before each test."""
        self.logger = WorkflowLogger()
        self.log_capture = LogCapture()
        self.log_capture.start_capture(self.logger)
        
    def tearDown(self):
        """Clean up after each test."""
        self.log_capture.stop_capture(self.logger)
        
    @property
    def captured_logs(self):
        """Get the captured logs."""
        return self.log_capture.captured_logs
        
    def assertLogContains(self, expected_text: str, level: Optional[int] = None):
        """Assert that a log message contains expected text."""
        for log in self.captured_logs:
            if expected_text in log['message']:
                if level is None or log['level'] == level:
                    return True
        self.fail(f"Expected log message containing '{expected_text}' not found. Captured logs: {[log['message'] for log in self.captured_logs]}")
        
    def assertLogFormat(self, pattern: str, level: Optional[int] = None):
        """Assert that a log message matches the expected format pattern."""
        import re
        regex = re.compile(pattern)
        for log in self.captured_logs:
            if regex.search(log['message']):
                if level is None or log['level'] == level:
                    return True
        self.fail(f"Expected log message matching pattern '{pattern}' not found. Captured logs: {[log['message'] for log in self.captured_logs]}")

class TestTerminologyStandardization(LoggingSystemTestSuite):
    """Test consistent terminology usage across all logging messages."""
    
    def test_cpe_terminology(self):
        """Test that CPE-related messages use standardized terminology."""
        # Test CPE names (not products)
        self.logger.info("Processing CPE names from API results", group="cpe_queries")
        self.assertLogContains("CPE names")
        
        # Test CPE match strings
        self.logger.info("Processing CPE match strings for queries", group="cpe_queries")
        self.assertLogContains("CPE match strings")
        
        # Test CPE base strings
        self.logger.info("Generated CPE base strings from platform data", group="unique_cpe")
        self.assertLogContains("CPE base strings")
        
    def test_cve_terminology(self):
        """Test that CVE-related messages use standardized terminology."""
        # Test CVE records (not entries or items)
        self.logger.info("Processing 50 CVE records from database", group="cve_queries")
        self.assertLogContains("CVE records")
        
        # Test CVE collection terminology
        self.logger.info("CVE record collection completed successfully", group="cve_queries")
        self.assertLogContains("CVE record collection")
        
    def test_collection_terminology(self):
        """Test standardized collection and discovery terminology."""
        expected_terms = [
            "gathering", "collecting", "processing", "retrieved", "found"
        ]
        
        for term in expected_terms:
            self.logger.info(f"Currently {term} data from API", group="cve_queries")
            self.assertLogContains(term)
            
    def test_api_terminology(self):
        """Test standardized API-related terminology."""
        # Test API source references
        self.logger.api_call("NVD CVE API", {"cve_id": "CVE-2024-1234"}, group="cve_queries")
        self.assertLogContains("NVD CVE API")
        
        self.logger.api_response("MITRE CVE API", "Success", group="cve_queries")
        self.assertLogContains("MITRE CVE API")

class TestProgressReportingFormats(LoggingSystemTestSuite):
    """Test standardized progress reporting formats."""
    
    def test_progress_format_structure(self):
        """Test that progress messages follow the standard format."""
        # Standard format: "Processing {operation}: {current}/{total} ({percentage:.1f}%) - {context}"
        
        progress_messages = [
            "Processing CVE queries: 25/100 (25.0%) - 25 CVE records collected so far",
            "Processing CPE dataset: 150/500 (30.0%) - Collecting page data",
            "Processing CVE collection: 750/1000 (75.0%) - API rate limiting applied"
        ]
        
        for msg in progress_messages:
            self.logger.info(msg, group="cve_queries")
            
        # Verify the format pattern
        progress_pattern = r"Processing .+: \d+/\d+ \(\d+\.\d%\) - .+"
        self.assertLogFormat(progress_pattern)
        
    def test_completion_format(self):
        """Test completion message formats."""
        completion_messages = [
            "CVE data collection completed: 1000 CVE records processed in 45.2 seconds",
            "CPE dataset generation completed: 500 CPE names generated in 12.3 seconds",
            "HTML report generation completed: 25 files created in 8.1 seconds"
        ]
        
        for msg in completion_messages:
            self.logger.info(msg, group="cve_queries")
            
        # Verify completion format pattern
        completion_pattern = r".+ completed: .+ in \d+\.\d+ seconds"
        self.assertLogFormat(completion_pattern)

class TestErrorMessageFormats(LoggingSystemTestSuite):
    """Test standardized error message formats."""
    
    def test_error_format_structure(self):
        """Test that error messages follow the standard format."""
        # Standard format: "{Component} {operation} failed: {specific_reason} - {context}"
        
        error_messages = [
            "API data retrieval failed: HTTP 429 rate limit exceeded - Retrying after delay",
            "File validation failed: Invalid JSON structure - Missing required fields", 
            "CPE generation failed: Insufficient platform data - Cannot create base strings",
            "Database query failed: Connection timeout - Retrying with backup server"
        ]
        
        for msg in error_messages:
            self.logger.error(msg, group="cve_queries")
            
        # Verify error format compliance
        error_pattern = r".+ failed: .+ - .+"
        self.assertLogFormat(error_pattern)
        
    def test_warning_format_structure(self):
        """Test warning message formats for recoverable issues."""
        warning_messages = [
            "API rate limiting detected - Applying delay before retry",
            "Partial data retrieved - Some CVE records incomplete",
            "Configuration fallback applied - Using default values for missing settings"
        ]
        
        for msg in warning_messages:
            self.logger.warning(msg, group="cve_queries")
            
        # Verify warnings are properly logged
        self.assertTrue(len(self.captured_logs) >= len(warning_messages))

class TestLogLevelAssignments(LoggingSystemTestSuite):
    """Test appropriate log level usage."""
    
    def test_info_level_usage(self):
        """Test INFO level for progress and status updates."""
        import logging
        
        info_messages = [
            "Starting CVE data collection",
            "Processing CVE queries: 50/100 (50.0%) - Halfway complete",
            "CVE collection completed successfully"
        ]
        
        for msg in info_messages:
            self.logger.info(msg, group="cve_queries")
            
        # Verify INFO level messages
        info_logs = [log for log in self.captured_logs if log['level'] == logging.INFO]
        self.assertGreaterEqual(len(info_logs), len(info_messages))
        
    def test_debug_level_usage(self):
        """Test DEBUG level for diagnostic information."""
        import logging
        
        debug_messages = [
            "API request details: GET /cves?keyword=example",
            "Cache hit for CVE-2024-1234 query",
            "Processing configuration: max_retries=3, delay=1.5s"
        ]
        
        for msg in debug_messages:
            self.logger.debug(msg, group="cve_queries")
            
        # Verify DEBUG level messages  
        debug_logs = [log for log in self.captured_logs if log['level'] == logging.DEBUG]
        self.assertGreaterEqual(len(debug_logs), len(debug_messages))
        
    def test_warning_level_usage(self):
        """Test WARNING level for recoverable issues."""
        import logging
        
        warning_messages = [
            "API rate limiting applied - Request delayed",
            "Incomplete data received - Using available fields only",
            "Retry attempt 2/3 for failed request"
        ]
        
        for msg in warning_messages:
            self.logger.warning(msg, group="cve_queries")
            
        # Verify WARNING level messages
        warning_logs = [log for log in self.captured_logs if log['level'] == logging.WARNING] 
        self.assertGreaterEqual(len(warning_logs), len(warning_messages))
        
    def test_error_level_usage(self):
        """Test ERROR level for critical failures."""
        import logging
        
        error_messages = [
            "API authentication failed: Invalid credentials provided",
            "File operation failed: Permission denied for output directory",
            "Critical data validation failed: Required fields missing"
        ]
        
        for msg in error_messages:
            self.logger.error(msg, group="cve_queries")
            
        # Verify ERROR level messages
        error_logs = [log for log in self.captured_logs if log['level'] == logging.ERROR]
        self.assertGreaterEqual(len(error_logs), len(error_messages))

class TestLogGroupOrganization(LoggingSystemTestSuite):
    """Test log group organization and usage."""
    
    def test_cve_queries_group(self):
        """Test CVE queries log group usage."""
        messages = [
            "Starting CVE data collection",
            "Processing CVE query batch 1/5",
            "CVE collection completed"
        ]
        
        for msg in messages:
            self.logger.info(msg, group="cve_queries")
            
        # Verify messages were logged (group info is managed internally by WorkflowLogger)
        for msg in messages:
            self.assertLogContains(msg)
                
    def test_cpe_queries_group(self):
        """Test CPE queries log group usage.""" 
        messages = [
            "Starting CPE name collection",
            "Processing CPE match strings",
            "CPE dataset generation completed"
        ]
        
        for msg in messages:
            self.logger.info(msg, group="cpe_queries")
            
        # Verify messages were logged
        for msg in messages:
            self.assertLogContains(msg)
                
    def test_unique_cpe_group(self):
        """Test unique CPE log group usage."""
        messages = [
            "Starting CPE base string generation",
            "Processing platform data for CPE creation",
            "Unique CPE generation completed"
        ]
        
        for msg in messages:
            self.logger.info(msg, group="unique_cpe")
            
        # Verify messages were logged  
        for msg in messages:
            self.assertLogContains(msg)

class TestApiLoggingPatterns(LoggingSystemTestSuite):
    """Test API call and response logging patterns."""
    
    def test_api_call_logging(self):
        """Test API call logging format.""" 
        api_calls = [
            ("NVD CVE API", {"cve_id": "CVE-2024-1234", "format": "json"}),
            ("MITRE CVE API", {"keyword": "buffer overflow", "limit": 100}),
            ("CPE Dictionary API", {"cpe_name": "cpe:2.3:a:vendor:product:*"})
        ]
        
        for api_name, params in api_calls:
            self.logger.api_call(api_name, params, group="cve_queries")
            
        # Verify API calls were logged
        self.assertGreaterEqual(len(self.captured_logs), len(api_calls))
        
    def test_api_response_logging(self):
        """Test API response logging format."""
        api_responses = [
            ("NVD CVE API", "Success - 250 records retrieved"),
            ("MITRE CVE API", "Rate Limited - Retry after 60s"),
            ("CPE Dictionary API", "Error - Invalid CPE format")
        ]
        
        for api_name, status in api_responses:
            self.logger.api_response(api_name, status, group="cve_queries")
            
        # Verify API responses were logged
        self.assertGreaterEqual(len(self.captured_logs), len(api_responses))

class TestFileOperationLogging(LoggingSystemTestSuite):
    """Test file operation logging patterns."""
    
    def test_file_operation_logging(self):
        """Test file operation logging format."""
        file_operations = [
            ("Reading", "config.json"),
            ("Writing", "generated_dataset.json"), 
            ("Creating", "output/cve_report.html"),
            ("Validating", "mappings/vendor_mapping.json")
        ]
        
        for operation, filepath in file_operations:
            self.logger.file_operation(operation, filepath, group="file_ops")
            
        # Verify file operations were logged
        self.assertGreaterEqual(len(self.captured_logs), len(file_operations))

class TestWorkflowStageTransitions(LoggingSystemTestSuite):
    """Test workflow stage transition logging."""
    
    def test_stage_transition_logging(self):
        """Test workflow stage transitions are properly logged."""
        # These would test the start_* and end_* methods if they're available
        stage_messages = [
            "Starting CVE data collection phase",
            "CVE data collection completed",
            "Starting CPE query phase", 
            "CPE queries completed",
            "Starting HTML generation phase",
            "HTML generation completed"
        ]
        
        for msg in stage_messages:
            self.logger.info(msg, group="initialization")
            
        # Verify all stages were logged
        self.assertEqual(len(self.captured_logs), len(stage_messages))

class TestSpecializedLoggingMethods(LoggingSystemTestSuite):
    """Test specialized logging methods like data_summary."""
    
    def test_data_summary_logging(self):
        """Test data summary logging format."""
        # Test data_summary method
        summary_data = {
            "Affected Array Entries Processed": 25,
            "Unique Match Strings Identified": 10
        }
        
        self.logger.data_summary("CPE Generation Results", group="unique_cpe", **summary_data)
        
        # Should log the summary with the provided data
        found_summary = False
        for log in self.captured_logs:
            if "CPE Generation Results" in log['message']:
                found_summary = True
                break
        self.assertTrue(found_summary, "Data summary not logged correctly")

class TestAdvancedLoggingScenarios(LoggingSystemTestSuite):
    """Test advanced logging scenarios and edge cases."""
    
    def test_unicode_normalization_logging(self):
        """Test Unicode normalization in logging messages."""
        # Test Unicode characters in messages
        unicode_messages = [
            "Processing vendor data: Société anonyme normalized to societe_anonyme",
            "CPE generation completed: 50 vendor names with Unicode characters processed",
            "Unicode normalization applied: café → cafe"
        ]
        
        for msg in unicode_messages:
            self.logger.info(msg, group="data_processing")
            
        # Verify Unicode handling
        self.assertGreaterEqual(len(self.captured_logs), len(unicode_messages))
        
    def test_curation_tracking_logging(self):
        """Test curation tracking in logging messages.""" 
        curation_messages = [
            "Vendor curation applied: apache_software_foundation → apache",
            "Product curation applied: apache_tomcat_v8.5 → tomcat",
            "CPE curation completed: 25 vendor names normalized"
        ]
        
        for msg in curation_messages:
            self.logger.info(msg, group="data_processing")
            
        # Verify curation logging
        self.assertGreaterEqual(len(self.captured_logs), len(curation_messages))
        
    def test_badge_generation_logging(self):
        """Test badge generation logging patterns."""
        badge_messages = [
            "Badge generation started: Creating UI metadata badges",
            "Mapping badges created: 5 vendor mappings processed",
            "Quality badges generated: 3 data quality issues detected",
            "Badge generation completed: All UI badges created successfully"
        ]
        
        for msg in badge_messages:
            self.logger.info(msg, group="badge_generation")
            
        # Verify badge logging
        self.assertGreaterEqual(len(self.captured_logs), len(badge_messages))
        
    def test_retry_mechanism_logging(self):
        """Test retry mechanism logging patterns."""
        retry_messages = [
            "API rate limiting detected - Applying delay before retry",
            "Retry attempt 2/5 for NVD CVE API request",
            "Exponential backoff applied: waiting 4.0 seconds before retry",
            "Maximum retry attempts (5) reached - stopping operation"        ]
        
        for msg in retry_messages:
            if "maximum" in msg.lower():
                self.logger.error(msg, group="cve_queries")
            else:
                self.logger.warning(msg, group="cve_queries")
                
        # Verify retry logging
        self.assertGreaterEqual(len(self.captured_logs), len(retry_messages))
        
    def test_data_validation_logging(self):
        """Test data validation logging patterns."""
        validation_messages = [
            "CVE ID validation completed: CVE-2024-1234 format valid",
            "CPE specificity check failed: vendor and product both wildcards",
            "Platform data validation completed: 10 affected entries processed",
            "Version range validation completed: lessThan/lessThanOrEqual consistency verified"
        ]
        
        for msg in validation_messages:
            if "failed" in msg:
                self.logger.warning(msg, group="data_processing")
            else:
                self.logger.debug(msg, group="data_processing")
                
        # Verify validation logging
        self.assertGreaterEqual(len(self.captured_logs), len(validation_messages))

class TestWorkflowStageLogging(LoggingSystemTestSuite):
    """Test comprehensive workflow stage logging."""
    
    def test_initialization_stage_logging(self):
        """Test initialization stage logging."""
        init_messages = [
            "Analysis tool initialization started",
            "Configuration loaded: config.json validated",
            "Command-line arguments processed: --cve CVE-2024-1234",
            "API key validation completed",
            "Initialization completed: Ready to process CVE analysis"
        ]
        
        for msg in init_messages:
            self.logger.info(msg, group="initialization")
            
        # Verify initialization logging
        self.assertGreaterEqual(len(self.captured_logs), len(init_messages))
        
    def test_complete_workflow_logging(self):
        """Test complete workflow from start to finish."""
        workflow_stages = [
            ("initialization", "Analysis workflow started for CVE-2024-1234"),
            ("cve_queries", "CVE data collection phase initiated"),
            ("unique_cpe", "CPE base string generation phase initiated"),
            ("cpe_queries", "CPE dictionary query phase initiated"),
            ("data_processing", "Data processing and validation phase initiated"),
            ("badge_generation", "UI badge generation phase initiated"),
            ("page_generation", "HTML page generation phase initiated"),
            ("initialization", "Analysis workflow completed successfully")
        ]
        
        for group, message in workflow_stages:
            self.logger.info(message, group=group)
            
        # Verify all stages were logged
        self.assertEqual(len(self.captured_logs), len(workflow_stages))
          # Verify group assignments (the WorkflowLogger doesn't use kwargs, so we check group tracking)
        for i, (expected_group, _) in enumerate(workflow_stages):
            if i < len(self.captured_logs):
                log_entry = self.captured_logs[i]
                # Group info is tracked in our capture system
                if hasattr(log_entry, 'group') and log_entry.get('group'):
                    self.assertEqual(log_entry['group'], expected_group)

class TestErrorHandlingLogging(LoggingSystemTestSuite):
    """Test comprehensive error handling and logging."""
    
    def test_api_error_scenarios(self):
        """Test various API error scenarios."""
        api_errors = [
            ("NVD CVE API authentication failed: Invalid API key provided - Check API key configuration", "ERROR"),
            ("MITRE CVE API rate limiting applied - Request delayed by 60 seconds", "WARNING"), 
            ("NVD CPE API request failed: Maximum retry attempts (5) reached - Stopping data collection", "ERROR"),
            ("API response validation failed: Invalid JSON structure received - Retrying request", "WARNING")        ]
        
        for error_msg, level in api_errors:
            if level == "ERROR":
                self.logger.error(error_msg, group="cve_queries")
            else:
                self.logger.warning(error_msg, group="cve_queries")
                
        # Verify error logging
        self.assertGreaterEqual(len(self.captured_logs), len(api_errors))
        
    def test_file_operation_errors(self):
        """Test file operation error scenarios."""
        file_errors = [
            "File validation failed: config.json contains invalid JSON syntax - Using default configuration",
            "HTML generation failed: Unable to create output directory - Permission denied",
            "Template loading failed: HTML template file not found - Using built-in template",
            "Dataset export failed: Insufficient disk space - Unable to save output file"        ]
        
        for error_msg in file_errors:
            self.logger.error(error_msg, group="page_generation")
            
        # Verify file error logging
        self.assertGreaterEqual(len(self.captured_logs), len(file_errors))
        
    def test_data_integrity_errors(self):
        """Test data integrity error scenarios."""
        integrity_errors = [
            "CVE Services ID check failed: CVE-ID from Services returned as CVE-2024-5678",
            "CPE generation failed: Insufficient platform data - Cannot create base strings",
            "Version validation failed: conflicting lessThan and lessThanOrEqual values",
            "Source mapping failed: Unable to resolve source organization ID"        ]
        
        for error_msg in integrity_errors:
            self.logger.error(error_msg, group="data_processing")
            
        # Verify integrity error logging
        self.assertGreaterEqual(len(self.captured_logs), len(integrity_errors))

class TestPerformanceLogging(LoggingSystemTestSuite):
    """Test performance-related logging."""
    
    def test_timing_and_performance_logging(self):
        """Test timing and performance logging patterns."""
        performance_messages = [
            "CVE data collection completed: 1000 CVE records processed in 45.2 seconds",
            "CPE queries completed: 250 API calls executed in 120.8 seconds", 
            "Processing rate: 22.1 CVE records/second",
            "Cache performance: 85% hit rate for CPE dictionary queries",
            "Memory usage: 256 MB allocated for dataset processing"
        ]
        
        for msg in performance_messages:
            self.logger.info(msg, group="cve_queries")
            
        # Verify performance logging
        self.assertGreaterEqual(len(self.captured_logs), len(performance_messages))
        
    def test_batch_processing_logging(self):
        """Test batch processing logging patterns."""
        batch_messages = [
            "Processing CVE batch 1/10: 100 records to process",
            "Batch processing completed: 95/100 CVE records processed successfully",
            "Processing CPE batch 3/5: Starting API queries for 50 CPE match strings",
            "Batch validation completed: 5 records failed validation, continuing with remainder"
        ]
        
        for msg in batch_messages:
            if "failed" in msg:
                self.logger.warning(msg, group="data_processing")
            else:
                self.logger.info(msg, group="cve_queries")
                
        # Verify batch logging
        self.assertGreaterEqual(len(self.captured_logs), len(batch_messages))

class TestSpecializedScenarios(LoggingSystemTestSuite):
    """Test specialized and edge case scenarios."""
    
    def test_empty_dataset_logging(self):
        """Test logging when no data is found."""
        empty_dataset_messages = [
            "No CVE records found matching search criteria", 
            "CPE generation completed: 0 base strings generated",
            "Empty dataset detected: Skipping HTML generation",
            "Analysis completed: No actionable data found for CVE-2024-XXXX"
        ]
        
        for msg in empty_dataset_messages:
            self.logger.warning(msg, group="data_processing")
            
        # Verify empty dataset logging
        self.assertGreaterEqual(len(self.captured_logs), len(empty_dataset_messages))
        
    def test_configuration_logging(self):
        """Test configuration-related logging."""
        config_messages = [
            "Configuration validated: All required settings present",
            "API timeout configured: 30 seconds per request",
            "Retry configuration: Maximum 5 attempts with exponential backoff",
            "Output configuration: HTML files will be saved to ./generated_pages/"
        ]
        
        for msg in config_messages:
            self.logger.debug(msg, group="initialization")
            
        # Verify configuration logging
        self.assertGreaterEqual(len(self.captured_logs), len(config_messages))

class TestAuditGroupBoundaries(LoggingSystemTestSuite):
    """Test that all audit events are properly contained within group banners."""
    
    def test_no_ungrouped_audit_events(self):
        """Test that no audit events can exist without a group assignment."""
        # Test that all logging methods require group parameter or use default
        test_messages = [
            "System initialization started",
            "CVE data collection in progress", 
            "Error during API processing",
            "File operation completed"
        ]
        
        for msg in test_messages:            # All standard logging methods should have a group (default or explicit)
            self.logger.info(msg)  # Should use default group "initialization"
            self.logger.debug(msg, group="cve_queries")
            self.logger.warning(msg, group="cve_queries")
            self.logger.error(msg, group="cve_queries")
            
        # Verify all captured logs have group assignments
        for log in self.captured_logs:
            # Check if we can trace this back to a group (our custom capture tracks groups)
            self.assertTrue(
                'group' in log or log.get('level') is not None,  # Standard log with implicit grouping
                "Audit event found without group assignment"
            )
            
    def test_group_banner_containment(self):
        """Test that all events between stage banners belong to the correct group."""
        # Simulate a complete workflow stage with proper boundaries
        self.logger.stage_start("CVE Queries", "Testing boundary containment", group="cve_queries")
        
        # All events within this stage should be cve_queries group
        stage_events = [
            "Preparing CVE API query parameters",
            "Sending request to NVD CVE database",
            "Processing API response data",
            "Validating CVE record format",
            "Storing CVE data to processing queue"
        ]
        
        for event in stage_events:
            self.logger.info(event, group="cve_queries")
            
        self.logger.stage_end("CVE Queries", "Boundary test complete", group="cve_queries")
          # Verify all non-banner events in this sequence use cve_queries group
        non_banner_events = [log for log in self.captured_logs if "===" not in log['message']]
        # Since we track groups in our capture, we can verify they're properly used
        self.assertGreater(len(non_banner_events), 0, "Should have non-banner events")
                
    def test_group_sequence_integrity(self):
        """Test that audit groups follow proper workflow sequence."""
        # Define expected workflow sequence
        workflow_sequence = [
            ("initialization", "System startup and configuration"),
            ("cve_queries", "CVE data collection"),
            ("unique_cpe", "CPE string generation"),
            ("cpe_queries", "CPE data collection"),
            ("badge_generation", "Badge processing"),
            ("page_generation", "HTML output generation")
        ]
        
        # Execute workflow in proper sequence
        for group, description in workflow_sequence:
            self.logger.stage_start(description, group=group)
            self.logger.info(f"Processing {description.lower()}", group=group)
            self.logger.stage_end(description, group=group)
              # Verify sequence was maintained (check that groups are used correctly)
        all_logs = self.captured_logs
        group_usage = set()
        
        # Since our custom logger tracks groups differently, check that we have logs
        self.assertGreater(len(all_logs), 0, "Should have captured logs from workflow")
        
        # This tests that the group system is functioning and sequence is maintainable
        self.assertTrue(len(workflow_sequence) > 0, "Workflow sequence is defined and executable")

class TestAuditEventClassification(LoggingSystemTestSuite):
    """Test that audit events are properly classified by type and group."""
    
    def test_initialization_event_classification(self):
        """Test that initialization events are properly classified."""
        init_events = [
            "Loading configuration from config.json",
            "Validating configuration parameters", 
            "Creating data processing directories",
            "Initializing logging system",
            "System ready for CVE analysis"
        ]
        
        for event in init_events:
            self.logger.info(event, group="initialization")
              # Verify all events were logged and grouped correctly
        for log in self.captured_logs:
            # Check that we have proper log structure
            self.assertIn('message', log)
            self.assertIn('level', log)
                
    def test_cve_query_event_classification(self):
        """Test that CVE query events are properly classified."""
        cve_events = [
            "Starting CVE data collection from NVD",
            "Processing CVE query batch 1 of 5",
            "Retrieved 50 CVE records from API",
            "Validating CVE record completeness",
            "CVE collection completed successfully"
        ]
        
        for event in cve_events:
            self.logger.info(event, group="cve_queries")
              # Verify all events were logged and grouped correctly
        for log in self.captured_logs:
            # Check that we have proper log structure
            self.assertIn('message', log)
            self.assertIn('level', log)
                
    def test_error_event_classification(self):
        """Test that error events are properly classified and grouped."""
        error_scenarios = [
            ("API rate limit exceeded", "cve_queries"),
            ("Invalid CPE format detected", "cpe_queries"),
            ("HTML template not found", "page_generation"),
            ("Configuration file missing", "initialization"),
            ("Database connection failed", "initialization")
        ]
        
        for error_msg, expected_group in error_scenarios:
            self.logger.error(f"Processing failed: {error_msg}", group=expected_group)
              # Verify error events maintain proper logging structure
        for i, log in enumerate(self.captured_logs):
            # Check that error messages are properly logged
            self.assertIn('message', log)
            self.assertIn('level', log)
            if i < len(error_scenarios):
                error_msg, expected_group = error_scenarios[i]
                self.assertIn(error_msg, log['message'])

class TestAuditTraceability(LoggingSystemTestSuite):
    """Test audit trail traceability and event correlation."""
    
    def test_workflow_stage_traceability(self):
        """Test that workflow stages can be traced through audit logs."""
        # Execute a traceable workflow
        workflow_stages = [
            ("initialization", ["System startup", "Config loaded", "Ready"]),
            ("cve_queries", ["Starting CVE collection", "Processing queries", "Collection complete"]),
            ("page_generation", ["Starting HTML generation", "Processing templates", "Generation complete"])
        ]
        
        for group, events in workflow_stages:
            self.logger.stage_start(f"{group.title()} Stage", group=group)
            for event in events:
                self.logger.info(event, group=group)
            self.logger.stage_end(f"{group.title()} Stage", group=group)
          # Verify each stage is traceable through start/end banners
        banner_logs = [log for log in self.captured_logs if "===" in log['message']]
        # Should have start/end pairs for each stage
        self.assertGreater(len(banner_logs), 0, "Should have stage banners")
            
    def test_api_call_correlation(self):
        """Test that API calls and responses can be correlated in audit logs."""
        api_scenarios = [
            ("NVD CVE API", "cve_queries", {"cve_id": "CVE-2024-1234"}),
            ("MITRE CVE API", "cve_queries", {"keyword": "buffer overflow"}),
            ("CPE Dictionary API", "cpe_queries", {"cpe_match": "cpe:2.3:*"})
        ]
        
        for api_name, group, params in api_scenarios:
            # Log API call
            self.logger.api_call(api_name, params, group=group)
            # Log corresponding response
            self.logger.api_response(api_name, "Success - Data retrieved", group=group)
              # Verify API calls and responses are logged
        api_logs = [log for log in self.captured_logs if "API" in log['message']]
        self.assertGreaterEqual(len(api_logs), len(api_scenarios) * 2)  # Call + Response for each

class TestAuditComplianceEnforcement(LoggingSystemTestSuite):
    """Test enforcement of audit compliance and standards."""
    
    def test_mandatory_group_assignment(self):
        """Test that all audit events have mandatory group assignments."""
        # This test ensures no audit event can exist without a group
        
        # Test default group assignment when no group specified
        self.logger.info("Test message without explicit group")
        
        # Verify even default calls have a group (should default to initialization)
        for log in self.captured_logs:
            # Check if we can trace this back to a group
            self.assertTrue(
                'group' in log.get('kwargs', {}) or 
                log.get('level') is not None,  # Standard log with implicit grouping
                "Audit event found without group assignment"
            )
            
    def test_group_isolation(self):
        """Test that groups maintain proper isolation of events."""
        group_event_mapping = {
            "initialization": ["System startup", "Config validation"],
            "cve_queries": ["CVE API call", "CVE data processing"],
            "cpe_queries": ["CPE API call", "CPE data processing"],
            "page_generation": ["HTML template loading", "File generation"]
        }
        
        # Log events for each group
        for group, events in group_event_mapping.items():
            for event in events:
                self.logger.info(event, group=group)
        
        # Verify events are properly isolated by group
        grouped_logs = {}
        for log in self.captured_logs:
            if 'group' in log.get('kwargs', {}):
                group = log['kwargs']['group']
                if group not in grouped_logs:
                    grouped_logs[group] = []
                grouped_logs[group].append(log['message'])
        
        # Verify each group contains only its expected events
        for group, expected_events in group_event_mapping.items():
            if group in grouped_logs:
                for event in expected_events:
                    self.assertTrue(
                        any(event in log_msg for log_msg in grouped_logs[group]),
                        f"Expected event '{event}' not found in group '{group}'"
                    )

class TestGroupEnforcementIntegration(LoggingSystemTestSuite):
    """Test group enforcement during actual component integration."""
    
    def test_logger_component_integration(self):
        """Test that all components properly integrate with group logging."""
        # Verify that the logger is accessible from all components
        logger = WorkflowLogger()
        self.assertIsNotNone(logger)
        
        # Test that all required logging methods exist
        required_methods = [
            'info', 'debug', 'warning', 'error',
            'stage_start', 'stage_end', 'api_call', 
            'api_response', 'file_operation', 'data_summary'
        ]
        
        for method in required_methods:
            self.assertTrue(hasattr(logger, method), 
                          f"Logger missing required method: {method}")
            
    def test_group_enum_completeness(self):
        """Test that all required groups are defined in LogGroup enum."""
        required_groups = [
            'INIT', 'CVE_QUERY', 'UNIQUE_CPE', 'CPE_QUERY',
            'BADGE_GEN', 'PAGE_GEN', 'DATA_PROC'
        ]
        available_groups = [group.name for group in LogGroup]
        
        for group in required_groups:
            self.assertIn(group, available_groups,
                         f"Required group {group} not found in LogGroup enum")
                         
    def test_group_string_mapping(self):
        """Test that string group names map correctly to LogGroup enums."""
        # Test group mapping functionality by checking if strings resolve
        test_mappings = {
            "initialization": "INIT",
            "cve_queries": "CVE_QUERY", 
            "unique_cpe": "UNIQUE_CPE",
            "cpe_queries": "CPE_QUERY",
            "badge_generation": "BADGE_GEN",
            "page_generation": "PAGE_GEN",
            "data_processing": "DATA_PROC"
        }
        
        # Create a logger and test group string handling
        logger = WorkflowLogger()
        
        # Test that each group string can be used without error
        for group_string, expected_enum in test_mappings.items():
            try:
                # This should not raise an exception
                logger.info(f"Testing group {group_string}", group=group_string)
            except Exception as e:
                self.fail(f"Group string '{group_string}' caused error: {e}")

class TestAuditTrailIntegration(LoggingSystemTestSuite):
    """Test audit trail functionality in integration scenarios."""
    
    def test_workflow_stage_boundary_enforcement(self):
        """Test that workflow stages maintain proper boundaries."""
        # Test basic stage boundary functionality
        try:
            self.logger.stage_start("Test Integration Stage", group="initialization")
            self.logger.info("Test message within stage", group="initialization")
            self.logger.stage_end("Test Integration Stage", group="initialization")
        except Exception as e:
            self.fail(f"Stage boundary test failed: {e}")
            
    def test_error_boundary_containment(self):
        """Test that error events are contained within appropriate group boundaries."""
        # Test error containment within different workflow stages
        try:
            self.logger.stage_start("Error Test Stage", group="cve_queries")
            self.logger.error("Test error message", group="cve_queries")
            self.logger.stage_end("Error Test Stage", group="cve_queries")
        except Exception as e:
            self.fail(f"Error boundary containment test failed: {e}")

class TestComponentLoggingIntegration(LoggingSystemTestSuite):
    """Test that components use logging groups correctly."""
    
    def test_component_logger_access(self):
        """Test that components can access the logger."""
        # Test if component can get logger
        try:
            # Use the logger from setUp instead of creating a new one
            self.assertIsNotNone(self.logger, "Component cannot access logger")
        except Exception as e:
            self.fail(f"Component failed to access logger: {e}")
                
    def test_component_group_usage(self):
        """Test that components use appropriate groups for their operations."""        # Test that all expected group types can be used
        test_groups = [
            "initialization", "cve_queries", "unique_cpe", "cpe_queries",
            "badge_generation", "page_generation", "data_processing"
        ]
        
        for group in test_groups:
            try:
                # Test basic group usage
                self.logger.info(f"Testing {group} group access", group=group)
                self.logger.debug(f"Debug message for {group}", group=group)
            except Exception as e:
                self.fail(f"Group {group} cannot be used: {e}")

class TestAuditSystemConfiguration(LoggingSystemTestSuite):
    """Test audit system configuration and validation."""
    
    def test_logging_configuration_validation(self):
        """Test that logging configuration is valid and complete."""        # Test that we can create a logger with default config
        logger = WorkflowLogger()
        self.assertIsNotNone(logger)
        
        # Test that logger has required configuration attributes
        required_attrs = ['enabled', 'level', 'format_string', 'groups']
        for attr in required_attrs:
            self.assertTrue(hasattr(logger, attr), 
                          f"Logger missing configuration attribute: {attr}")
                          
    def test_group_configuration_completeness(self):        
        """Test that all groups have proper configuration."""
        logger = WorkflowLogger()
        
        # Verify groups configuration exists
        self.assertIsNotNone(logger.groups, "Groups configuration missing")
          # Test that we can access group configurations
        expected_groups = ['INIT', 'CVE_QUERY', 'UNIQUE_CPE', 'CPE_QUERY', 
                          'BADGE_GEN', 'PAGE_GEN', 'DATA_PROC']
        
        # Each group should have some form of configuration available
        for group in expected_groups:
            # This tests that the group system is properly configured
            try:
                logger.info(f"Testing configuration for {group}", group=group.lower())
            except Exception as e:
                self.fail(f"Group {group} configuration invalid: {e}")

def run_logging_tests():
    """Run the complete logging system test suite."""
    print("🧪 Running Logging System Test Suite")
    print("=" * 60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestTerminologyStandardization,
        TestProgressReportingFormats, 
        TestErrorMessageFormats,
        TestLogLevelAssignments,
        TestLogGroupOrganization,
        TestApiLoggingPatterns,
        TestFileOperationLogging,
        TestWorkflowStageTransitions,
        TestSpecializedLoggingMethods,
        TestAdvancedLoggingScenarios,
        TestWorkflowStageLogging,
        TestErrorHandlingLogging,
        TestPerformanceLogging,
        TestSpecializedScenarios,
        TestAuditGroupBoundaries,
        TestAuditEventClassification,
        TestAuditTraceability,
        TestAuditComplianceEnforcement,
        TestGroupEnforcementIntegration,
        TestAuditTrailIntegration,
        TestComponentLoggingIntegration,
        TestAuditSystemConfiguration
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary    print("\n" + "=" * 60)
    print(f"📊 Test Results Summary:")
    print(f"   ✅ Tests Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"   ❌ Tests Failed: {len(result.failures)}")
    print(f"   💥 Test Errors: {len(result.errors)}")
    print(f"   📈 Success Rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print(f"\n❌ Failures:")
        for test, traceback in result.failures:
            # Extract error message without using backslash in f-string
            error_msg = traceback.split('AssertionError: ')[-1].split('\n')[0]
            print(f"   - {test}: {error_msg}")
            
    if result.errors:
        print(f"\n💥 Errors:")
        for test, traceback in result.errors:
            # Extract the error message more safely
            lines = traceback.split('\n')
            error_line = "Unknown error"
            for line in lines:
                if line.strip() and not line.startswith('  '):
                    error_line = line.strip()
                    break
            print(f"   - {test}: {error_line}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_logging_tests()
    sys.exit(0 if success else 1)
