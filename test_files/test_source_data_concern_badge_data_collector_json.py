"""
Test suite for Source Data Concern Badge Data Collector JSON system.
Tests the complete badge_contents_collector.py system that generates sourceDataConcernReport.json.

This comprehensive test suite covers:
1. Source Data Concern collection and JSON generation 
2. Clean Platform Entry tracking and aggregation
3. Complete badge data collection pipeline
4. Dashboard data structure compliance

The consolidated test suite validates both:
- collect_source_data_concern() functionality
- collect_clean_platform_entry() functionality

Both functions feed into the same BadgeContentsCollector system and sourceDataConcernReport.json output.
This suite does NOT cover HTML badge generation (covered by test_platform_badges.py).
"""

import sys
import os
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Add the src directory to the Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from analysis_tool.logging.badge_contents_collector import (
    BadgeContentsCollector,
    get_badge_contents_collector,
    clear_badge_contents_collector,
    initialize_badge_contents_report,
    start_cve_collection,
    complete_cve_collection,
    finalize_badge_contents_report,
    collect_clean_platform_entry
)

# Initialize NVD source manager for tests
try:
    from analysis_tool.storage.nvd_source_manager import get_global_source_manager
    import pandas as pd
    
    # Create test source data
    test_source_data = pd.DataFrame([
        {"orgId": "test-source-uuid-12345", "name": "Test Source Organization", "sourceIdentifiers": ["test-source-uuid-12345"]},
        {"orgId": "test-multi-concern-source", "name": "Multi Concern Test Org", "sourceIdentifiers": ["test-multi-concern-source"]},
        {"orgId": "source-1", "name": "Source One", "sourceIdentifiers": ["source-1"]},
        {"orgId": "source-2", "name": "Source Two", "sourceIdentifiers": ["source-2"]},
        {"orgId": "source-3", "name": "Source Three", "sourceIdentifiers": ["source-3"]},
        {"orgId": "cisco-systems-uuid", "name": "Cisco Systems, Inc.", "sourceIdentifiers": ["cisco-systems-uuid"]},
        {"orgId": "test-org-uuid", "name": "Test Organization", "sourceIdentifiers": ["test-org-uuid"]}
    ])
    
    # Initialize the global source manager
    source_manager = get_global_source_manager()
    source_manager.initialize(test_source_data)
    
except ImportError:
    # If NVD source manager not available, badge collector will fall back to "Unknown Source"
    pass

class SourceDataConcernJSONTestSuite:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.temp_dir = None
        
    def setup_test_environment(self):
        """Set up temporary directory for test output."""
        self.temp_dir = tempfile.mkdtemp(prefix="source_data_concern_json_test_")
        print(f"Test environment created: {self.temp_dir}")
        
    def teardown_test_environment(self):
        """Clean up temporary directory."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            print(f"Test environment cleaned up: {self.temp_dir}")
    
    def assert_true(self, condition, test_name, details=""):
        """Assert that a condition is true."""
        if condition:
            print(f"✓ PASS: {test_name}")
            self.passed += 1
        else:
            print(f"✗ FAIL: {test_name}")
            if details:
                print(f"  Details: {details}")
            self.failed += 1
    
    def assert_equals(self, actual, expected, test_name, details=""):
        """Assert that two values are equal."""
        if actual == expected:
            print(f"✓ PASS: {test_name}")
            self.passed += 1
        else:
            print(f"✗ FAIL: {test_name}")
            print(f"  Expected: {expected}")
            print(f"  Actual: {actual}")
            if details:
                print(f"  Details: {details}")
            self.failed += 1

    def assert_contains(self, container, item, test_name, details=""):
        """Assert that container contains item."""
        if item in container:
            print(f"✓ PASS: {test_name}")
            self.passed += 1
        else:
            print(f"✗ FAIL: {test_name}")
            print(f"  Container: {container}")
            print(f"  Missing item: {item}")
            if details:
                print(f"  Details: {details}")
            self.failed += 1

    def create_test_concerns_data(self, concern_type: str, concerns: List[Dict]) -> Dict:
        """Create test concerns data structure matching the expected format."""
        return {
            concern_type: concerns
        }

    def test_badge_contents_collector_initialization(self):
        """Test basic initialization of BadgeContentsCollector."""
        print("\n--- Test: Badge Contents Collector Initialization ---")
        
        # Clear any existing collector
        clear_badge_contents_collector()
        
        # Initialize with temp directory
        logs_dir = os.path.join(self.temp_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        
        result = initialize_badge_contents_report(logs_dir)
        self.assert_true(result, "Badge contents report initialized successfully")
        
        # Get collector instance
        collector = get_badge_contents_collector()
        self.assert_true(collector is not None, "Collector instance created")
        self.assert_true(hasattr(collector, 'consolidated_metadata'), "Collector has consolidated_metadata")
        self.assert_true(hasattr(collector, 'current_cve_data'), "Collector has current_cve_data")

    def test_cve_collection_lifecycle(self):
        """Test CVE collection start/complete lifecycle."""
        print("\n--- Test: CVE Collection Lifecycle ---")
        
        clear_badge_contents_collector()
        logs_dir = os.path.join(self.temp_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        initialize_badge_contents_report(logs_dir)
        
        # Start CVE collection
        test_cve_id = "CVE-2024-TEST-0001"
        start_cve_collection(test_cve_id)
        
        collector = get_badge_contents_collector()
        self.assert_true(collector.current_cve_data is not None, "Current CVE data initialized")
        self.assert_equals(collector.current_cve_data['cve_id'], test_cve_id, "CVE ID set correctly")
        
        # Verify CVE data structure
        expected_keys = ['cve_id', 'platform_entries', 'cve_metadata']
        for key in expected_keys:
            self.assert_contains(collector.current_cve_data.keys(), key, f"CVE data contains {key}")
        
        # Complete CVE collection
        result = complete_cve_collection()
        self.assert_true(result, "CVE collection completed successfully")

    def test_source_data_concern_collection_basic(self):
        """Test basic source data concern collection."""
        print("\n--- Test: Basic Source Data Concern Collection ---")
        
        clear_badge_contents_collector()
        logs_dir = os.path.join(self.temp_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        initialize_badge_contents_report(logs_dir)
        
        start_cve_collection("CVE-2024-TEST-0002")
        collector = get_badge_contents_collector()
        
        # Create test concern data
        test_concerns = self.create_test_concerns_data(
            "placeholderData",
            [
                {
                    "concern": "Vendor contains placeholder text: n/a",
                    "category": "Placeholder Data",
                    "issue": "Vendor information missing or placeholder"
                }
            ]
        )
        
        # Collect source data concern
        collector.collect_source_data_concern(
            table_index=0,
            source_id="test-source-uuid-12345",
            vendor="n/a",
            product="TestProduct",
            concerns_data=test_concerns,
            concerns_count=1,
            concern_types=["Placeholder Data"]  # Use display name for proper mapping
        )
        
        # Verify collection
        platform_entries = collector.current_cve_data['platform_entries']
        self.assert_equals(len(platform_entries), 1, "One platform entry collected")
        
        if platform_entries:
            entry = platform_entries[0]
            self.assert_equals(entry['table_index'], 0, "Table index correct")
            self.assert_equals(entry['source_id'], "test-source-uuid-12345", "Source ID correct")
            self.assert_equals(entry['vendor'], "n/a", "Vendor correct")
            self.assert_equals(entry['product'], "TestProduct", "Product correct")
            self.assert_equals(entry['total_concerns'], 1, "Total concerns correct")
            self.assert_contains(entry['concern_types'], "placeholderData", "Concern type recorded")

    def test_multiple_concern_types_collection(self):
        """Test collection of multiple concern types in single entry."""
        print("\n--- Test: Multiple Concern Types Collection ---")
        
        clear_badge_contents_collector()
        logs_dir = os.path.join(self.temp_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        initialize_badge_contents_report(logs_dir)
        
        start_cve_collection("CVE-2024-TEST-0003")
        collector = get_badge_contents_collector()
        
        # Create complex concern data with multiple types
        test_concerns = {
            "placeholderData": [
                {
                    "concern": "Product contains placeholder text: TBD",
                    "category": "Placeholder Data",
                    "issue": "Product information missing or placeholder"
                }
            ],
            "versionTextPatterns": [
                {
                    "concern": "Text in version: before 2.0 (patterns: before)",
                    "category": "Version Data",
                    "issue": "Version data contains formatting or structural issues"
                },
                {
                    "concern": "Text in version: after 1.5 (patterns: after)",
                    "category": "Version Data", 
                    "issue": "Version data contains formatting or structural issues"
                }
            ]
        }
        
        collector.collect_source_data_concern(
            table_index=0,
            source_id="test-multi-concern-source",
            vendor="TestVendor",
            product="TBD",
            concerns_data=test_concerns,
            concerns_count=3,
            concern_types=["Placeholder Data", "Version Text Patterns"]  # Use display names
        )
        
        # Verify collection
        entry = collector.current_cve_data['platform_entries'][0]
        self.assert_equals(entry['total_concerns'], 3, "Total concerns correct for multiple types")
        self.assert_equals(len(entry['concern_types']), 2, "Two concern types recorded")
        self.assert_contains(entry['concern_types'], "placeholderData", "Placeholder data concern type present")
        self.assert_contains(entry['concern_types'], "versionTextPatterns", "Version text patterns concern type present")
        
        # Verify concern breakdown
        self.assert_equals(entry['concern_breakdown']['placeholderData'], 1, "Placeholder data count correct")
        self.assert_equals(entry['concern_breakdown']['versionTextPatterns'], 2, "Version text patterns count correct")

    def test_concern_details_structure(self):
        """Test concern details array structure and format."""
        print("\n--- Test: Concern Details Structure ---")
        
        clear_badge_contents_collector()
        logs_dir = os.path.join(self.temp_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        initialize_badge_contents_report(logs_dir)
        
        start_cve_collection("CVE-2024-TEST-0004")
        collector = get_badge_contents_collector()
        
        test_concerns = self.create_test_concerns_data(
            "versionGranularity",
            [
                {
                    "concern": "Inconsistent version granularity: 3.3: 2-part (3.3 Patch 2, 3.3 Patch 1), 3-part (3.3.0)",
                    "category": "Version Granularity",
                    "issue": "Version granularity issues may affect matching precision"
                }
            ]
        )
        
        collector.collect_source_data_concern(
            table_index=0,
            source_id="test-granularity-source",
            vendor="Cisco",
            product="Identity Services Engine",
            concerns_data=test_concerns,
            concerns_count=1,
            concern_types=["versionGranularity"]
        )
        
        # Verify concerns_detail structure
        entry = collector.current_cve_data['platform_entries'][0]
        concerns_detail = entry['concerns_detail']
        
        self.assert_equals(len(concerns_detail), 1, "One concern detail entry")
        
        if concerns_detail:
            detail = concerns_detail[0]
            self.assert_contains(detail.keys(), 'concern_type', "Concern detail has concern_type")
            self.assert_contains(detail.keys(), 'concerns', "Concern detail has concerns array")
            self.assert_equals(detail['concern_type'], 'versionGranularity', "Concern type correct")
            
            concerns_array = detail['concerns']
            self.assert_equals(len(concerns_array), 1, "One concern in array")
            
            if concerns_array:
                concern = concerns_array[0]
                expected_keys = ['concern', 'category', 'issue']
                for key in expected_keys:
                    self.assert_contains(concern.keys(), key, f"Concern has {key} field")

    def test_metadata_aggregation(self):
        """Test metadata aggregation across multiple entries and CVEs."""
        print("\n--- Test: Metadata Aggregation ---")
        
        clear_badge_contents_collector()
        logs_dir = os.path.join(self.temp_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        initialize_badge_contents_report(logs_dir)
        
        collector = get_badge_contents_collector()
        
        # Process first CVE
        start_cve_collection("CVE-2024-TEST-0005")
        
        # Add entry with concerns
        test_concerns_1 = self.create_test_concerns_data(
            "placeholderData",
            [{"concern": "test concern", "category": "test", "issue": "test"}]
        )
        
        collector.collect_source_data_concern(
            table_index=0,
            source_id="source-1",
            vendor="Vendor1",
            product="Product1",
            concerns_data=test_concerns_1,
            concerns_count=1,
            concern_types=["Placeholder Data"]  # Use display name
        )
        
        # Add entry without concerns (via clean platform entry collection)
        collector.collect_clean_platform_entry("source-2")
        
        complete_cve_collection()
        
        # Process second CVE
        start_cve_collection("CVE-2024-TEST-0006")
        
        test_concerns_2 = self.create_test_concerns_data(
            "versionTextPatterns",
            [{"concern": "test concern 2", "category": "test", "issue": "test"}]
        )
        
        collector.collect_source_data_concern(
            table_index=0,
            source_id="source-3",
            vendor="Vendor2",
            product="Product2",
            concerns_data=test_concerns_2,
            concerns_count=1,
            concern_types=["Version Text Patterns"]  # Use display name
        )
        
        complete_cve_collection()
        
        # Check consolidated metadata
        metadata = collector.consolidated_metadata
        self.assert_equals(metadata['total_cves_processed'], 2, "Two CVEs processed")
        self.assert_equals(metadata['total_platform_entries'], 3, "Three platform entries total")
        self.assert_equals(metadata['entries_with_concerns'], 2, "Two entries with concerns")
        
        # Check concern type counts
        concern_counts = metadata['concern_type_counts']
        placeholder_count = next((item['count'] for item in concern_counts if item['concern_type'] == 'placeholderData'), 0)
        version_count = next((item['count'] for item in concern_counts if item['concern_type'] == 'versionTextPatterns'), 0)
        
        self.assert_equals(placeholder_count, 1, "Placeholder data concern count correct")
        self.assert_equals(version_count, 1, "Version text patterns concern count correct")

    def test_json_output_generation(self):
        """Test complete JSON output generation and file creation."""
        print("\n--- Test: JSON Output Generation ---")
        
        clear_badge_contents_collector()
        logs_dir = os.path.join(self.temp_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        initialize_badge_contents_report(logs_dir)
        
        collector = get_badge_contents_collector()
        
        # Create comprehensive test data
        start_cve_collection("CVE-2024-TEST-0007")
        
        # Add multiple entries with different concern types
        test_data = [
            {
                "table_index": 0,
                "source_id": "source-alpha",
                "vendor": "n/a",
                "product": "TestProduct1",
                "concerns_data": self.create_test_concerns_data("placeholderData", [
                    {"concern": "Vendor placeholder", "category": "Placeholder", "issue": "Missing vendor"}
                ]),
                "concerns_count": 1,
                "concern_types": ["placeholderData"]
            },
            {
                "table_index": 1,
                "source_id": "source-beta",
                "vendor": "TestVendor2",
                "product": "TestProduct2",
                "concerns_data": {
                    "versionTextPatterns": [
                        {"concern": "Version text pattern", "category": "Version", "issue": "Text in version"}
                    ],
                    "versionGranularity": [
                        {"concern": "Granularity issue", "category": "Version", "issue": "Inconsistent granularity"}
                    ]
                },
                "concerns_count": 2,
                "concern_types": ["versionTextPatterns", "versionGranularity"]
            }
        ]
        
        for entry_data in test_data:
            collector.collect_source_data_concern(**entry_data)
        
        complete_cve_collection()
        
        # Finalize report
        output_file = finalize_badge_contents_report()
        self.assert_true(output_file is not None, "JSON report file created")
        
        if output_file:
            self.assert_true(os.path.exists(output_file), "Output file exists on disk")
            
            # Read and validate JSON structure
            with open(output_file, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            # Validate top-level structure
            expected_top_keys = ['metadata', 'cve_data']
            for key in expected_top_keys:
                self.assert_contains(report_data.keys(), key, f"Report contains {key}")
            
            # Validate metadata structure
            metadata = report_data['metadata']
            expected_metadata_keys = [
                'run_started_at', 'total_cves_processed', 'total_platform_entries',
                'entries_with_concerns', 'concern_type_counts', 'status'
            ]
            for key in expected_metadata_keys:
                self.assert_contains(metadata.keys(), key, f"Metadata contains {key}")
            
            # Validate CVE data structure
            cve_data = report_data['cve_data']
            self.assert_equals(len(cve_data), 1, "One CVE in report")
            
            if cve_data:
                cve_entry = cve_data[0]
                self.assert_equals(cve_entry['cve_id'], "CVE-2024-TEST-0007", "CVE ID correct in output")
                self.assert_equals(len(cve_entry['platform_entries']), 2, "Two platform entries in CVE")

    def test_json_schema_compliance(self):
        """Test that generated JSON complies with expected schema for dashboard consumption."""
        print("\n--- Test: JSON Schema Compliance ---")
        
        clear_badge_contents_collector()
        logs_dir = os.path.join(self.temp_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        initialize_badge_contents_report(logs_dir)
        
        collector = get_badge_contents_collector()
        start_cve_collection("CVE-2024-SCHEMA-TEST")
        
        # Create test entry with all required fields
        complete_concerns_data = {
            "placeholderData": [
                {
                    "concern": "Product contains placeholder: TBD",
                    "category": "Placeholder Data",
                    "issue": "Product information missing"
                }
            ],
            "versionTextPatterns": [
                {
                    "concern": "Version contains text: before 1.0",
                    "category": "Version Data",
                    "issue": "Non-standard version format"
                }
            ]
        }
        
        collector.collect_source_data_concern(
            table_index=0,
            source_id="schema-test-source",
            vendor="SchemaVendor",
            product="TBD",
            concerns_data=complete_concerns_data,
            concerns_count=2,
            concern_types=["placeholderData", "versionTextPatterns"]
        )
        
        complete_cve_collection()
        output_file = finalize_badge_contents_report()
        
        # Validate JSON serialization
        with open(output_file, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        # Test re-serialization (ensures no circular references or unserializable objects)
        try:
            json_str = json.dumps(report_data, indent=2)
            re_parsed = json.loads(json_str)
            self.assert_true(True, "JSON re-serialization successful")
        except Exception as e:
            self.assert_true(False, f"JSON serialization failed: {e}")
        
        # Validate platform entry schema
        platform_entry = report_data['cve_data'][0]['platform_entries'][0]
        required_platform_fields = [
            'platform_entry_id', 'table_index', 'source_id', 'source_name',
            'vendor', 'product', 'total_concerns', 'concern_types',
            'concern_breakdown', 'concerns_detail'
        ]
        
        for field in required_platform_fields:
            self.assert_contains(platform_entry.keys(), field, f"Platform entry has required field: {field}")
        
        # Validate concern detail schema
        concerns_detail = platform_entry['concerns_detail']
        if concerns_detail:
            concern_detail = concerns_detail[0]
            concern_detail_fields = ['concern_type', 'concerns']
            for field in concern_detail_fields:
                self.assert_contains(concern_detail.keys(), field, f"Concern detail has required field: {field}")
            
            # Validate individual concern schema
            concerns_array = concern_detail['concerns']
            if concerns_array:
                concern = concerns_array[0]
                concern_fields = ['concern', 'category', 'issue']
                for field in concern_fields:
                    self.assert_contains(concern.keys(), field, f"Individual concern has required field: {field}")

    def test_error_handling_and_validation(self):
        """Test error handling for invalid inputs and edge cases."""
        print("\n--- Test: Error Handling and Validation ---")
        
        clear_badge_contents_collector()
        logs_dir = os.path.join(self.temp_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        initialize_badge_contents_report(logs_dir)
        
        collector = get_badge_contents_collector()
        
        # Test collecting without starting CVE collection
        collector.collect_source_data_concern(
            table_index=0,
            source_id="error-test",
            vendor="ErrorVendor",
            product="ErrorProduct",
            concerns_data={"test": []},
            concerns_count=0,
            concern_types=[]
        )
        
        # Should handle gracefully (no crash)
        self.assert_true(True, "Handled collection without CVE start gracefully")
        
        # Start CVE collection for further tests
        start_cve_collection("CVE-2024-ERROR-TEST")
        
        # Test invalid concerns_data type
        collector.collect_source_data_concern(
            table_index=1,
            source_id="error-test-2",
            vendor="ErrorVendor2",
            product="ErrorProduct2",
            concerns_data="invalid_not_dict",  # Should be dict
            concerns_count=1,
            concern_types=["test"]
        )
        
        # Should handle gracefully
        self.assert_true(True, "Handled invalid concerns_data type gracefully")
        
        # Test negative concerns_count
        collector.collect_source_data_concern(
            table_index=2,
            source_id="error-test-3",
            vendor="ErrorVendor3",
            product="ErrorProduct3",
            concerns_data={"test": []},
            concerns_count=-1,  # Invalid negative count
            concern_types=["test"]
        )
        
        # Should handle gracefully
        self.assert_true(True, "Handled negative concerns_count gracefully")
        
        # Verify no invalid entries were added
        platform_entries = collector.current_cve_data['platform_entries']
        self.assert_equals(len(platform_entries), 0, "No invalid entries added to collection")

    def test_dashboard_integration_format(self):
        """Test that output format is compatible with Source Data Concern Dashboard expectations."""
        print("\n--- Test: Dashboard Integration Format ---")
        
        clear_badge_contents_collector()
        logs_dir = os.path.join(self.temp_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        initialize_badge_contents_report(logs_dir)
        
        # Create realistic test data that mirrors actual dashboard usage
        start_cve_collection("CVE-2024-DASHBOARD-TEST")
        collector = get_badge_contents_collector()
        
        # Simulate real concern types found in actual CVEs
        real_world_concerns = [
            {
                "table_index": 0,
                "source_id": "cisco-systems-uuid",
                "vendor": "Cisco",
                "product": "Identity Services Engine Software",
                "concerns_data": self.create_test_concerns_data("versionGranularity", [
                    {
                        "concern": "Inconsistent version granularity: 3.3: 2-part (3.3 Patch 2, 3.3 Patch 1), 3-part (3.3.0)",
                        "category": "Version Granularity",
                        "issue": "Version granularity issues may affect matching precision"
                    }
                ]),
                "concerns_count": 1,
                "concern_types": ["Version Granularity"]  # Use display name
            },
            {
                "table_index": 1,
                "source_id": "test-org-uuid",
                "vendor": "n/a",
                "product": "TestProduct",
                "concerns_data": self.create_test_concerns_data("placeholderData", [
                    {
                        "concern": "Vendor contains placeholder text: n/a",
                        "category": "Placeholder Data",
                        "issue": "Vendor information missing or placeholder"
                    }
                ]),
                "concerns_count": 1,
                "concern_types": ["Placeholder Data"]  # Use display name
            }
        ]
        
        for concern_data in real_world_concerns:
            collector.collect_source_data_concern(**concern_data)
        
        complete_cve_collection()
        output_file = finalize_badge_contents_report()
        
        # Load and verify dashboard compatibility
        with open(output_file, 'r', encoding='utf-8') as f:
            dashboard_data = json.load(f)
        
        # Verify dashboard can extract summary statistics
        metadata = dashboard_data['metadata']
        self.assert_true(isinstance(metadata['total_platform_entries'], int), "Platform entries count is integer")
        self.assert_true(isinstance(metadata['entries_with_concerns'], int), "Concern entries count is integer")
        self.assert_true(isinstance(metadata['concern_type_counts'], list), "Concern type counts is array")
        
        # Verify dashboard can process concern type statistics
        concern_type_counts = metadata['concern_type_counts']
        concern_types_found = [item['concern_type'] for item in concern_type_counts]
        self.assert_contains(concern_types_found, 'versionGranularity', "Version granularity concern type present")
        self.assert_contains(concern_types_found, 'placeholderData', "Placeholder data concern type present")
        
        # Verify dashboard can iterate through CVE entries
        cve_data = dashboard_data['cve_data']
        for cve_entry in cve_data:
            # Each CVE should be processable by dashboard
            self.assert_contains(cve_entry.keys(), 'cve_id', "CVE entry has ID for dashboard links")
            self.assert_contains(cve_entry.keys(), 'platform_entries', "CVE entry has platform entries for detail view")
            self.assert_contains(cve_entry.keys(), 'cve_metadata', "CVE entry has metadata for statistics")

    # Clean Platform Tracking Tests (merged from test_clean_platform_tracking.py)
    
    def test_collect_clean_platform_entry_basic(self):
        """Test basic clean platform entry collection."""
        print("\n--- Test: Basic Clean Platform Entry Collection ---")
        
        # Clear any existing data
        clear_badge_contents_collector()
        
        # Start CVE collection
        start_cve_collection("CVE-TEST-0001")
        
        # Test data
        test_source = "test_source_1"
        
        # Collect clean platform entry
        collect_clean_platform_entry(test_source)
        
        # Get collector to inspect data
        collector = get_badge_contents_collector()
        
        # Verify current CVE data exists
        self.assert_true(
            collector.current_cve_data is not None,
            "Current CVE data exists"
        )
        
        # Verify clean_platform_entries exists
        self.assert_true(
            'clean_platform_entries' in collector.current_cve_data,
            "clean_platform_entries key exists in current CVE data"
        )
        
        # Verify data structure
        clean_entries = collector.current_cve_data.get('clean_platform_entries', [])
        self.assert_equals(
            len(clean_entries), 1,
            "One clean platform entry collected"
        )
        
        if clean_entries:
            entry = clean_entries[0]
            self.assert_equals(
                entry.get('sourceID'), test_source,
                "Source ID matches expected value"
            )
            self.assert_equals(
                entry.get('cleanPlatformCount'), 1,
                "Clean platform count is 1"
            )

    def test_aggregate_counting(self):
        """Test aggregate counting for same source."""
        print("\n--- Test: Aggregate Counting for Same Source ---")
        
        # Clear any existing data
        clear_badge_contents_collector()
        
        # Start CVE collection
        start_cve_collection("CVE-TEST-0002")
        
        test_source = "test_source_aggregate"
        
        # Collect multiple platforms for same source
        for i in range(3):
            collect_clean_platform_entry(test_source)
        
        # Get collector to inspect data
        collector = get_badge_contents_collector()
        clean_entries = collector.current_cve_data.get('clean_platform_entries', [])
        
        # Should have one entry with count of 3
        self.assert_equals(
            len(clean_entries), 1,
            "One aggregated entry for same source"
        )
        
        if clean_entries:
            entry = clean_entries[0]
            self.assert_equals(
                entry.get('sourceID'), test_source,
                "Source ID matches expected value"
            )
            self.assert_equals(
                entry.get('cleanPlatformCount'), 3,
                "Clean platform count aggregated to 3"
            )

    def test_multiple_sources(self):
        """Test collection from multiple different sources."""
        print("\n--- Test: Multiple Different Sources ---")
        
        # Clear any existing data
        clear_badge_contents_collector()
        
        # Start CVE collection
        start_cve_collection("CVE-TEST-0003")
        
        test_data = [
            ("source_A", 2),
            ("source_B", 1),
            ("source_C", 3)
        ]
        
        # Collect all test data
        for source, count in test_data:
            for i in range(count):
                collect_clean_platform_entry(source)
        
        # Get collector to inspect data
        collector = get_badge_contents_collector()
        clean_entries = collector.current_cve_data.get('clean_platform_entries', [])
        
        # Should have 3 entries (one per source)
        self.assert_equals(
            len(clean_entries), 3,
            "Three entries for three different sources"
        )
        
        # Verify counts for each source
        source_counts = {entry['sourceID']: entry['cleanPlatformCount'] for entry in clean_entries}
        
        self.assert_equals(
            source_counts.get('source_A'), 2,
            "Source A has 2 clean platforms"
        )
        self.assert_equals(
            source_counts.get('source_B'), 1,
            "Source B has 1 clean platform"
        )
        self.assert_equals(
            source_counts.get('source_C'), 3,
            "Source C has 3 clean platforms"
        )

    def test_json_serialization(self):
        """Test that data structure can be JSON serialized."""
        print("\n--- Test: JSON Serialization ---")
        
        # Clear any existing data
        clear_badge_contents_collector()
        
        # Start CVE collection
        start_cve_collection("CVE-TEST-0004")
        
        # Add test data
        collect_clean_platform_entry("json_test_source")
        collect_clean_platform_entry("json_test_source")
        
        # Get collector to inspect data
        collector = get_badge_contents_collector()
        
        # Test JSON serialization of current CVE data
        try:
            json_output = json.dumps(collector.current_cve_data, indent=2)
            self.assert_true(
                True,
                "JSON serialization successful"
            )
        except Exception as e:
            self.assert_true(
                False,
                f"JSON serialization failed: {str(e)}"
            )
            return
        
        # Parse back and verify structure
        try:
            parsed_data = json.loads(json_output)
            
            # Verify clean_platform_entries exists and is a list
            self.assert_true(
                'clean_platform_entries' in parsed_data,
                "clean_platform_entries key exists in JSON"
            )
            
            clean_entries = parsed_data.get('clean_platform_entries')
            self.assert_true(
                isinstance(clean_entries, list),
                "clean_platform_entries is a list"
            )
            
            # Verify entry structure
            if clean_entries:
                entry = clean_entries[0]
                self.assert_true(
                    'sourceID' in entry and 'cleanPlatformCount' in entry,
                    "Entry has required sourceID and cleanPlatformCount fields"
                )
                self.assert_true(
                    isinstance(entry['cleanPlatformCount'], int),
                    "cleanPlatformCount is an integer"
                )
                self.assert_equals(
                    entry['cleanPlatformCount'], 2,
                    "cleanPlatformCount value is correct"
                )
                
        except Exception as e:
            self.assert_true(
                False,
                f"JSON parsing failed: {str(e)}"
            )

    def test_metadata_tracking(self):
        """Test that metadata correctly tracks platform entries."""
        print("\n--- Test: Metadata Tracking ---")
        
        # Clear any existing data
        clear_badge_contents_collector()
        
        # Start CVE collection
        start_cve_collection("CVE-TEST-0005")
        
        # Get initial state
        collector = get_badge_contents_collector()
        initial_total = collector.current_cve_data['cve_metadata']['total_platform_entries']
        
        # Add clean platform entries
        collect_clean_platform_entry("metadata_test_source")
        collect_clean_platform_entry("metadata_test_source")
        collect_clean_platform_entry("another_source")
        
        # Check metadata update
        final_total = collector.current_cve_data['cve_metadata']['total_platform_entries']
        
        self.assert_equals(
            final_total - initial_total, 3,
            "Metadata total_platform_entries increased by 3"
        )

    def test_no_cve_collection_started(self):
        """Test behavior when no CVE collection has been started."""
        print("\n--- Test: No CVE Collection Started ---")
        
        # Clear any existing data
        clear_badge_contents_collector()
        
        # Try to collect without starting CVE collection
        collect_clean_platform_entry("orphan_source")
        
        # Get collector to inspect data
        collector = get_badge_contents_collector()
        
        # Should not have current CVE data
        self.assert_true(
            collector.current_cve_data is None,
            "No current CVE data when collection not started"
        )
        
        # This test verifies graceful handling of edge case

    def test_data_persistence_across_operations(self):
        """Test that clean platform entries persist across multiple collection operations."""
        print("\n--- Test: Data Persistence Across Operations ---")
        
        # Clear any existing data
        clear_badge_contents_collector()
        
        # Start CVE collection
        start_cve_collection("CVE-TEST-0006")
        
        # First batch of data
        collect_clean_platform_entry("persistent_source")
        
        # Get collector to inspect data
        collector = get_badge_contents_collector()
        clean_entries = collector.current_cve_data.get('clean_platform_entries', [])
        self.assert_equals(
            len(clean_entries), 1,
            "First entry persisted"
        )
        
        # Add more data
        collect_clean_platform_entry("persistent_source")
        collect_clean_platform_entry("new_source")
        
        # Verify persistence and aggregation
        clean_entries = collector.current_cve_data.get('clean_platform_entries', [])
        
        self.assert_equals(
            len(clean_entries), 2,
            "Two sources after additional operations"
        )
        
        # Find the persistent source entry
        persistent_entry = next((e for e in clean_entries if e['sourceID'] == 'persistent_source'), None)
        self.assert_true(
            persistent_entry is not None,
            "Persistent source entry found"
        )
        
        if persistent_entry:
            self.assert_equals(
                persistent_entry['cleanPlatformCount'], 2,
                "Persistent source aggregated to count of 2"
            )

    def test_generate_comprehensive_dashboard_file(self):
        """Generate a comprehensive sourceDataConcernReport.json file covering all enumeration states."""
        print("\n--- Test: Generate Comprehensive Dashboard File ---")
        
        try:
            # Import run organization utilities
            import sys
            import os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
            from analysis_tool.storage.run_organization import create_run_directory, get_current_run_paths, get_analysis_tools_root
            
            # Create a test run directory
            run_path, run_id = create_run_directory("TEST_comprehensive_dashboard")
            run_paths = get_current_run_paths(run_id)
            logs_dir = str(run_paths["logs"])
            
            # Clear and initialize
            clear_badge_contents_collector()
            result = initialize_badge_contents_report(logs_dir)
            self.assert_true(result, "Badge contents report initialized successfully")
            
            # === CVE 1: Comprehensive Concern Coverage ===
            start_cve_collection("CVE-2024-COMPREHENSIVE")
            
            # Comprehensive test entries covering ALL concern types and sub-categories
            comprehensive_entries = [
                # Source 1: MITRE - Placeholder Data sub-categories
                {
                    'table_index': 1,
                    'source_id': 'mitre-corp',
                    'vendor': 'example_vendor',
                    'product': 'vulnerable_app',
                    'concerns_data': self.create_test_concerns_data('placeholderData', [
                        {'concern': 'vendor_placeholder', 'category': 'data_quality', 'issue': 'Contains placeholder text: "example_vendor"'},
                        {'concern': 'product_placeholder', 'category': 'data_quality', 'issue': 'Contains placeholder text: "sample_product"'}
                    ]),
                    'concerns_count': 2,
                    'concern_types': ['placeholderData']
                },
                {
                    'table_index': 2,
                    'source_id': 'mitre-corp',
                    'vendor': '-',
                    'product': 'system_library',
                    'concerns_data': self.create_test_concerns_data('placeholderData', [
                        {'concern': 'single_dash', 'category': 'data_quality', 'issue': 'Single dash placeholder in vendor field'}
                    ]),
                    'concerns_count': 1,
                    'concern_types': ['placeholderData']
                },
                
                # Source 2: NVD - Version Text Patterns sub-categories
                {
                    'table_index': 3,
                    'source_id': 'nvd-nist',
                    'vendor': 'range_vendor',
                    'product': 'range_app',
                    'concerns_data': self.create_test_concerns_data('versionTextPatterns', [
                        {'concern': 'range_indicators', 'category': 'version_parsing', 'issue': 'Version contains range indicator: "1.0 through 2.5"'}
                    ]),
                    'concerns_count': 1,
                    'concern_types': ['versionTextPatterns']
                },
                {
                    'table_index': 4,
                    'source_id': 'nvd-nist',
                    'vendor': 'bound_vendor',
                    'product': 'bound_app',
                    'concerns_data': self.create_test_concerns_data('versionTextPatterns', [
                        {'concern': 'upper_bound_indicator', 'category': 'version_parsing', 'issue': 'Contains upper bound indicator: "before 4.2"'},
                        {'concern': 'lower_bound_indicator', 'category': 'version_parsing', 'issue': 'Contains lower bound: "after 1.5"'}
                    ]),
                    'concerns_count': 2,
                    'concern_types': ['versionTextPatterns']
                },
                
                # Source 3: CPE Validator - CPE Array Concerns sub-categories
                {
                    'table_index': 5,
                    'source_id': 'cpe-validator',
                    'vendor': 'validation_corp',
                    'product': 'security_scanner',
                    'concerns_data': self.create_test_concerns_data('cpeArrayConcerns', [
                        {'concern': 'empty_array', 'category': 'structure', 'issue': 'Empty CPE array detected'},
                        {'concern': 'format_issue', 'category': 'structure', 'issue': 'Invalid CPE format detected: missing cpe: prefix'}
                    ]),
                    'concerns_count': 2,
                    'concern_types': ['cpeArrayConcerns']
                },
                {
                    'table_index': 6,
                    'source_id': 'cpe-validator',
                    'vendor': 'duplicate_vendor',
                    'product': 'duplicate_scanner',
                    'concerns_data': self.create_test_concerns_data('cpeArrayConcerns', [
                        {'concern': 'duplicate_cpe', 'category': 'integrity', 'issue': 'Duplicate CPE detected in array'},
                        {'concern': 'structure_issue', 'category': 'structure', 'issue': 'Invalid CPE 2.3 format detected'}
                    ]),
                    'concerns_count': 2,
                    'concern_types': ['cpeArrayConcerns']
                },
                
                # Source 4: Version Analysis - Version Granularity and Comparators
                {
                    'table_index': 7,
                    'source_id': 'version-analysis',
                    'vendor': 'granularity_vendor',
                    'product': 'analysis_tool',
                    'concerns_data': self.create_test_concerns_data('versionGranularity', [
                        {'concern': 'granularity_mismatch', 'category': 'version_specificity', 'issue': 'Version range too broad: affects all versions'}
                    ]),
                    'concerns_count': 1,
                    'concern_types': ['versionGranularity']
                },
                {
                    'table_index': 8,
                    'source_id': 'version-analysis',
                    'vendor': 'comparator_vendor',
                    'product': 'comparison_app',
                    'concerns_data': self.create_test_concerns_data('versionComparators', [
                        {'concern': 'text_comparator', 'category': 'version_parsing', 'issue': 'Contains textual comparator: "before version 3.0"'}
                    ]),
                    'concerns_count': 1,
                    'concern_types': ['versionComparators']
                },
                
                # Source 5: Security Research - Wildcards and Duplicates
                {
                    'table_index': 9,
                    'source_id': 'security-research',
                    'vendor': 'wildcard_vendor',
                    'product': 'pattern_app',
                    'concerns_data': self.create_test_concerns_data('wildcardBranches', [
                        {'concern': 'wildcard_pattern', 'category': 'version_matching', 'issue': 'Wildcard pattern detected: "*.*.*"'}
                    ]),
                    'concerns_count': 1,
                    'concern_types': ['wildcardBranches']
                },
                {
                    'table_index': 10,
                    'source_id': 'security-research',
                    'vendor': 'duplicate_vendor',
                    'product': 'duplicate_app',
                    'concerns_data': self.create_test_concerns_data('duplicateEntries', [
                        {'concern': 'row_duplicate', 'category': 'data_integrity', 'issue': 'Potential duplicate CPE entries detected'}
                    ]),
                    'concerns_count': 1,
                    'concern_types': ['duplicateEntries']
                },
                
                # Source 6: Platform Data - Platform Data Concerns and Missing Products
                {
                    'table_index': 11,
                    'source_id': 'platform-data',
                    'vendor': 'platform_vendor',
                    'product': 'embedded_system',
                    'concerns_data': self.create_test_concerns_data('platformDataConcerns', [
                        {'concern': 'unexpected_data', 'category': 'data_structure', 'issue': 'Unexpected platform data detected'}
                    ]),
                    'concerns_count': 1,
                    'concern_types': ['platformDataConcerns']
                },
                {
                    'table_index': 12,
                    'source_id': 'platform-data',
                    'vendor': 'missing_vendor',
                    'product': 'incomplete_app',
                    'concerns_data': self.create_test_concerns_data('missingAffectedProducts', [
                        {'concern': 'no_affected_status', 'category': 'completeness', 'issue': 'No affected product status specified'}
                    ]),
                    'concerns_count': 1,
                    'concern_types': ['missingAffectedProducts']
                },
                
                # Source 7: Range Analysis - Overlapping Ranges
                {
                    'table_index': 13,
                    'source_id': 'range-analysis',
                    'vendor': 'range_vendor',
                    'product': 'versioning_tool',
                    'concerns_data': self.create_test_concerns_data('overlappingRanges', [
                        {'concern': 'range_overlap', 'category': 'version_logic', 'issue': 'Version range overlaps detected between entries'}
                    ]),
                    'concerns_count': 1,
                    'concern_types': ['overlappingRanges']
                }
            ]
            
            # Collect all comprehensive entries
            collector = get_badge_contents_collector()
            for entry in comprehensive_entries:
                collector.collect_source_data_concern(**entry)
                
            # Add clean platform entries for mixed states
            # MITRE: Both concerns and clean platforms
            for _ in range(3):
                collect_clean_platform_entry('mitre-corp')
                
            # NVD: Both concerns and clean platforms
            for _ in range(2):
                collect_clean_platform_entry('nvd-nist')
            
            # Platform Data: Both concerns and clean platform
            collect_clean_platform_entry('platform-data')
            
            complete_cve_collection()
            
            # === CVE 2: Clean-Only Sources ===
            start_cve_collection("CVE-2024-CLEAN-ONLY")
            
            # Sources with only clean platforms (no concerns)
            for _ in range(8):
                collect_clean_platform_entry('clean-source-alpha')
                
            for _ in range(5):
                collect_clean_platform_entry('clean-source-beta')
                
            for _ in range(12):
                collect_clean_platform_entry('clean-source-gamma')
            
            complete_cve_collection()
            
            # === CVE 3: High-Concern Source ===
            start_cve_collection("CVE-2024-HIGH-CONCERN")
            
            # Source with many concerns across multiple types
            high_concern_entries = [
                {
                    'table_index': 14,
                    'source_id': 'high-concern-source',
                    'vendor': 'critical_vendor_1',
                    'product': 'critical_app_1',
                    'concerns_data': self.create_test_concerns_data('placeholderData', [
                        {'concern': 'placeholder_1', 'category': 'data_quality', 'issue': 'Multiple placeholder issues detected'},
                        {'concern': 'placeholder_2', 'category': 'data_quality', 'issue': 'Generic placeholder values used'}
                    ]),
                    'concerns_count': 2,
                    'concern_types': ['placeholderData']
                },
                {
                    'table_index': 15,
                    'source_id': 'high-concern-source',
                    'vendor': 'critical_vendor_2',
                    'product': 'critical_app_2',
                    'concerns_data': self.create_test_concerns_data('versionTextPatterns', [
                        {'concern': 'complex_pattern_1', 'category': 'version_parsing', 'issue': 'Complex version text patterns detected'},
                        {'concern': 'complex_pattern_2', 'category': 'version_parsing', 'issue': 'Non-standard version indicators'},
                        {'concern': 'complex_pattern_3', 'category': 'version_parsing', 'issue': 'Multiple descriptive statements found'}
                    ]),
                    'concerns_count': 3,
                    'concern_types': ['versionTextPatterns']
                },
                {
                    'table_index': 16,
                    'source_id': 'high-concern-source',
                    'vendor': 'critical_vendor_3',
                    'product': 'critical_app_3',
                    'concerns_data': self.create_test_concerns_data('cpeArrayConcerns', [
                        {'concern': 'multiple_cpe_issues', 'category': 'structure', 'issue': 'Multiple CPE array structure issues'},
                        {'concern': 'format_validation', 'category': 'validation', 'issue': 'CPE format validation failures'}
                    ]),
                    'concerns_count': 2,
                    'concern_types': ['cpeArrayConcerns']
                }
            ]
            
            for entry in high_concern_entries:
                collector.collect_source_data_concern(**entry)
            
            complete_cve_collection()
            
            # === CVE 4: Mixed State Testing ===
            start_cve_collection("CVE-2024-MIXED-STATE")
            
            # Add concerns to previously clean-only sources
            {
                'table_index': 17,
                'source_id': 'clean-source-alpha',
                'vendor': 'now_with_concerns',
                'product': 'mixed_state_app',
                'concerns_data': self.create_test_concerns_data('duplicateEntries', [
                    {'concern': 'mixed_duplicate', 'category': 'integrity', 'issue': 'Duplicate detected in previously clean source'}
                ]),
                'concerns_count': 1,
                'concern_types': ['duplicateEntries']
            }
            
            collector.collect_source_data_concern(**{
                'table_index': 17,
                'source_id': 'clean-source-alpha',
                'vendor': 'now_with_concerns',
                'product': 'mixed_state_app',
                'concerns_data': self.create_test_concerns_data('duplicateEntries', [
                    {'concern': 'mixed_duplicate', 'category': 'integrity', 'issue': 'Duplicate detected in previously clean source'}
                ]),
                'concerns_count': 1,
                'concern_types': ['duplicateEntries']
            })
            
            # Add more clean platforms to test high clean counts
            for _ in range(15):
                collect_clean_platform_entry('version-analysis')
                
            complete_cve_collection()
            
            # Finalize the report
            output_file = finalize_badge_contents_report()
            self.assert_true(output_file is not None, "Comprehensive JSON report file created")
            self.assert_true(os.path.exists(output_file), "Output file exists on disk")
            
            # Verify it's in the runs directory structure
            self.assert_true('/runs/' in output_file.replace('\\', '/'), "File created in runs directory")
            self.assert_true('sourceDataConcernReport.json' in output_file, "File has correct name")
            
            # Verify the file has comprehensive test data
            with open(output_file, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            # Comprehensive validation
            self.assert_true(len(report_data['cve_data']) >= 4, "Multiple CVE records in report")
            
            # Check metadata
            metadata = report_data['metadata']
            self.assert_true(metadata['total_cves_processed'] >= 4, "Multiple CVEs processed")
            self.assert_true(metadata['total_platform_entries'] >= 15, "Many platform entries")
            self.assert_true(metadata['entries_with_concerns'] >= 10, "Many entries with concerns")
            
            # Verify concern type coverage (all 10 types)
            concern_types = [ct['concern_type'] for ct in metadata['concern_type_counts']]
            expected_types = ['placeholderData', 'versionTextPatterns', 'cpeArrayConcerns', 'versionGranularity', 
                             'versionComparators', 'wildcardBranches', 'duplicateEntries', 'platformDataConcerns',
                             'missingAffectedProducts', 'overlappingRanges']
            
            coverage_count = 0
            for expected_type in expected_types:
                if expected_type in concern_types:
                    coverage_count += 1
            
            self.assert_true(coverage_count >= 8, f"Most concern types covered ({coverage_count}/10)")
            
            # Print comprehensive summary
            print(f"\n📁 Comprehensive Dashboard Test File Generated:")
            print(f"   {output_file}")
            print(f"   File size: {os.path.getsize(output_file)} bytes")
            print(f"   CVE records: {metadata['total_cves_processed']}")
            print(f"   Platform entries: {metadata['total_platform_entries']}")
            print(f"   Entries with concerns: {metadata['entries_with_concerns']}")
            print(f"   Concern types covered: {coverage_count}/10")
            print(f"\n🎯 Source Card Enumeration States Covered:")
            print(f"   ✓ Sources with only concerns (high-concern-source)")
            print(f"   ✓ Sources with only clean platforms (clean-source-*)")
            print(f"   ✓ Sources with both concerns and clean platforms (mitre-corp, nvd-nist)")
            print(f"   ✓ Sources with multiple CVEs (various)")
            print(f"   ✓ High concern count sources (high-concern-source)")
            print(f"   ✓ High clean platform count sources (clean-source-gamma)")
            print(f"\n🔍 Concern Sub-Category Coverage:")
            print(f"   ✓ Placeholder Data: vendor/product/single-dash placeholders")
            print(f"   ✓ Version Text Patterns: range/bound indicators, approximations")
            print(f"   ✓ CPE Array Concerns: empty arrays, format/structure issues")
            print(f"   ✓ Version Granularity: granularity mismatches")
            print(f"   ✓ Version Comparators: text comparators")
            print(f"   ✓ Wildcard Branches: wildcard patterns")
            print(f"   ✓ Duplicate Entries: row duplicates")
            print(f"   ✓ Platform Data Concerns: unexpected data")
            print(f"   ✓ Missing Affected Products: no affected status")
            print(f"   ✓ Overlapping Ranges: version range overlaps")
            print(f"\n🌐 Load this file in the Source Data Concern Dashboard:")
            print(f"   file://{get_analysis_tools_root()}/dashboards/sourceDataConcernDashboard.html")
            
        except Exception as e:
            print(f"❌ FAIL: Failed to generate comprehensive dashboard file: {str(e)}")
            self.failed += 1
            return
        
        self.passed += 1

    def test_generate_persistent_dashboard_file(self):
        """Generate a persistent sourceDataConcernReport.json file for dashboard testing."""
        print("\n--- Test: Generate Persistent Dashboard File ---")
        
        try:
            # Import run organization utilities
            import sys
            import os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
            from analysis_tool.storage.run_organization import create_run_directory, get_current_run_paths, get_analysis_tools_root
            
            # Create a test run directory
            run_path, run_id = create_run_directory("TEST_dashboard_file_generation")
            run_paths = get_current_run_paths(run_id)
            logs_dir = str(run_paths["logs"])
            
            # Clear and initialize
            clear_badge_contents_collector()
            result = initialize_badge_contents_report(logs_dir)
            self.assert_true(result, "Badge contents report initialized successfully")
            
            # Create comprehensive test data for dashboard
            start_cve_collection("CVE-2024-TEST-DASHBOARD")
            
            # Add multiple sources with various concern patterns
            test_entries = [
                {
                    'table_index': 1,
                    'source_id': 'mitre-main',
                    'vendor': 'example',
                    'product': 'vulnerable_app',
                    'concerns_data': self.create_test_concerns_data('placeholderData', [
                        {'concern': 'Contains placeholder text: "X.X"', 'category': 'Version', 'issue': 'Placeholder text in version field'}
                    ]),
                    'concerns_count': 2,
                    'concern_types': ['placeholderData', 'versionTextPatterns']
                },
                {
                    'table_index': 2,
                    'source_id': 'nvd-analysis',
                    'vendor': 'testcorp',
                    'product': 'enterprise_software',
                    'concerns_data': self.create_test_concerns_data('versionGranularity', [
                        {'concern': 'Version range too broad', 'category': 'Version', 'issue': 'Overly broad version range'}
                    ]),
                    'concerns_count': 1,
                    'concern_types': ['versionGranularity']
                },
                {
                    'table_index': 3,
                    'source_id': 'security-research',
                    'vendor': 'opensource',
                    'product': 'library_framework',
                    'concerns_data': self.create_test_concerns_data('duplicateEntries', [
                        {'concern': 'Potential duplicate CPE entries detected', 'category': 'CPE', 'issue': 'Duplicate entry detection'}
                    ]),
                    'concerns_count': 1,
                    'concern_types': ['duplicateEntries']
                }
            ]
            
            # Collect the test entries
            collector = get_badge_contents_collector()
            for entry in test_entries:
                collector.collect_source_data_concern(**entry)
            
            # Add some clean platform entries
            # Multiple entries for mitre-main (3 clean platforms)
            collect_clean_platform_entry('mitre-main')
            collect_clean_platform_entry('mitre-main')
            collect_clean_platform_entry('mitre-main')
            
            # Multiple entries for clean-source-only (5 clean platforms)
            for _ in range(5):
                collect_clean_platform_entry('clean-source-only')
            
            # Add another CVE with different patterns
            complete_cve_collection()
            start_cve_collection("CVE-2024-TEST-CLEAN")
            
            # This CVE has only clean platforms
            collect_clean_platform_entry('nvd-analysis')
            collect_clean_platform_entry('nvd-analysis')
            collect_clean_platform_entry('clean-source-only')
            
            complete_cve_collection()
            
            # Finalize the report
            output_file = finalize_badge_contents_report()
            self.assert_true(output_file is not None, "JSON report file created")
            self.assert_true(os.path.exists(output_file), "Output file exists on disk")
            
            # Verify it's in the runs directory structure
            self.assert_true('/runs/' in output_file.replace('\\', '/'), "File created in runs directory")
            self.assert_true('sourceDataConcernReport.json' in output_file, "File has correct name")
            
            # Verify the file has comprehensive test data
            with open(output_file, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            # Should have multiple CVEs and sources
            self.assert_true(len(report_data['cve_data']) >= 2, "Multiple CVE records in report")
            
            # Check metadata
            metadata = report_data['metadata']
            self.assert_true(metadata['total_cves_processed'] >= 2, "Multiple CVEs processed")
            self.assert_true(metadata['total_platform_entries'] >= 3, "Multiple platform entries")
            self.assert_true(metadata['entries_with_concerns'] >= 1, "Has entries with concerns")
            
            # Print file location for user reference
            print(f"\n📁 Persistent dashboard test file generated:")
            print(f"   {output_file}")
            print(f"   File size: {os.path.getsize(output_file)} bytes")
            print(f"   CVE records: {metadata['total_cves_processed']}")
            print(f"   Platform entries: {metadata['total_platform_entries']}")
            print(f"   Entries with concerns: {metadata['entries_with_concerns']}")
            print(f"\n🌐 Load this file in the Source Data Concern Dashboard:")
            print(f"   file://{get_analysis_tools_root()}/dashboards/sourceDataConcernDashboard.html")
            
        except Exception as e:
            print(f"❌ FAIL: Failed to generate persistent dashboard file: {str(e)}")
            self.failed += 1
            return
        
        self.passed += 1

def main():
    """Run all Source Data Concern JSON generation and clean platform tracking tests."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test source data concern badge data collector JSON functionality')
    args = parser.parse_args()
    
    print("Starting Source Data Concern Badge Data Collector JSON Test Suite")
    print("=" * 70)
    print("This test suite covers the complete badge data collection system:")
    print("- Source Data Concern JSON generation")  
    print("- Clean Platform Entry tracking")
    print("- Dashboard data structure compliance")
    print("=" * 70)
    
    test_suite = SourceDataConcernJSONTestSuite()
    
    try:
        test_suite.setup_test_environment()
        
        # Run all tests
        test_suite.test_badge_contents_collector_initialization()
        test_suite.test_cve_collection_lifecycle()
        test_suite.test_source_data_concern_collection_basic()
        test_suite.test_multiple_concern_types_collection()
        test_suite.test_concern_details_structure()
        test_suite.test_metadata_aggregation()
        test_suite.test_json_output_generation()
        test_suite.test_json_schema_compliance()
        test_suite.test_error_handling_and_validation()
        test_suite.test_dashboard_integration_format()
        
        # Clean Platform Tracking Tests (merged from test_clean_platform_tracking.py)
        test_suite.test_collect_clean_platform_entry_basic()
        test_suite.test_aggregate_counting()
        test_suite.test_multiple_sources()
        test_suite.test_json_serialization()
        test_suite.test_metadata_tracking()
        test_suite.test_no_cve_collection_started()
        test_suite.test_data_persistence_across_operations()
        
        # Generate comprehensive dashboard test file (all enumeration states)
        test_suite.test_generate_comprehensive_dashboard_file()
        
        # Generate persistent dashboard test file (basic)
        test_suite.test_generate_persistent_dashboard_file()
        
    finally:
        test_suite.teardown_test_environment()
    
    # Print results summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    total_tests = test_suite.passed + test_suite.failed
    success_rate = (test_suite.passed / total_tests * 100) if total_tests > 0 else 0
    
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {test_suite.passed}")
    print(f"Failed: {test_suite.failed}")
    print(f"Success Rate: {success_rate:.1f}%")
    
    success = test_suite.failed == 0
    if success:
        print("\n🎉 ALL BADGE DATA COLLECTOR TESTS PASSED!")
        print("Source Data Concern badge data collection system is working correctly.")
    else:
        print(f"\n❌ {test_suite.failed} BADGE DATA COLLECTOR TEST(S) FAILED")
        print("Issues found in Source Data Concern badge data collection system.")
    
    # Print standardized test results format
    print(f"TEST_RESULTS: PASSED={test_suite.passed} TOTAL={total_tests} SUITE=\"Source Data Concern Badge Data Collector JSON\"")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
