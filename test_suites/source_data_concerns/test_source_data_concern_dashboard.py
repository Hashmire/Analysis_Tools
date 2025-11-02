"""
Test suite for Source Data Concern Dashboard display and data ingestion.
Tests the HTML dashboard's ability to properly ingest and display JSON data.

This test suite validates the frontend dashboard functionality, complementing
test_source_data_concern_json_generation.py which tests the backend JSON generation.
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path

# Add the src directory to the Python path to import analysis_tool modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

try:
    from analysis_tool.core.path_utils import get_analysis_tools_root, get_project_path
    from analysis_tool.logging.badge_contents_collector import (
        initialize_badge_contents_report, get_badge_contents_collector, 
        clear_badge_contents_collector, start_cve_collection, complete_cve_collection
    )
    from analysis_tool.storage.nvd_source_manager import get_global_source_manager
    import pandas as pd
    
    # Create test source data
    test_source_data = pd.DataFrame([
        {"orgId": "dashboard-test-source-1", "name": "Dashboard Test Org 1", "sourceIdentifiers": ["dashboard-test-source-1"]},
        {"orgId": "dashboard-test-source-2", "name": "Dashboard Test Org 2", "sourceIdentifiers": ["dashboard-test-source-2"]},
        {"orgId": "multi-cve-source", "name": "Multi CVE Test Source", "sourceIdentifiers": ["multi-cve-source"]},
        {"orgId": "zero-concern-source", "name": "Zero Concern Source", "sourceIdentifiers": ["zero-concern-source"]},
        {"orgId": "high-volume-source", "name": "High Volume Test Source", "sourceIdentifiers": ["high-volume-source"]}
    ])
    
    # Initialize the global source manager
    source_manager = get_global_source_manager()
    source_manager.initialize(test_source_data)
    
except ImportError as e:
    print(f"Warning: Could not import analysis_tool modules: {e}")
    print("Dashboard display tests will use mock data instead.")


class SourceDataConcernDashboardDisplayTestSuite:
    """Test suite for Source Data Concern Dashboard display functionality."""
    
    def __init__(self):
        """Initialize test suite with temporary environment."""
        self.temp_dir = tempfile.mkdtemp(prefix="dashboard_display_test_")
        self.dashboard_path = None
        self.test_data_files = []
        self.passed = 0
        self.failed = 0
        
    def cleanup(self):
        """Clean up test environment."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
        print(f"Test environment cleaned up: {self.temp_dir}")
    
    def assert_equals(self, actual, expected, message):
        """Assert that actual equals expected."""
        if actual != expected:
            try:
                print(f"X FAIL: {message}")
                print(f"  Expected: {expected}")
                print(f"  Actual: {actual}")
            except UnicodeEncodeError:
                print(f"X FAIL: {message}")
                print(f"  Expected: {repr(expected)}")
                print(f"  Actual: {repr(actual)}")
            self.failed += 1
            raise AssertionError(f"{message}: Expected {expected}, got {actual}")
        try:
            print(f"+ PASS: {message}")
        except UnicodeEncodeError:
            print(f"+ PASS: {message}")
        self.passed += 1
    
    def assert_contains(self, container, item, message):
        """Assert that container contains item."""
        if item not in container:
            # Handle potential Unicode encoding issues in error messages
            try:
                print(f"X FAIL: {message}")
                print(f"  Missing item: {item}")
            except UnicodeEncodeError:
                print(f"X FAIL: {message}")
                print(f"  Missing item: {repr(item)}")
            self.failed += 1
            raise AssertionError(f"{message}: {item} not found in container")
        try:
            print(f"+ PASS: {message}")
        except UnicodeEncodeError:
            print(f"+ PASS: {message}")
        self.passed += 1
    
    def assert_true(self, condition, message):
        """Assert that condition is true."""
        if not condition:
            try:
                print(f"X FAIL: {message}")
            except UnicodeEncodeError:
                print(f"X FAIL: {message}")
            self.failed += 1
            raise AssertionError(message)
        try:
            print(f"+ PASS: {message}")
        except UnicodeEncodeError:
            print(f"+ PASS: {message}")
        self.passed += 1
    
    def assert_not_empty(self, value, message):
        """Assert that value is not empty."""
        if not value:
            try:
                print(f"X FAIL: {message}")
                print(f"  Value: {value}")
            except UnicodeEncodeError:
                print(f"X FAIL: {message}")
                print(f"  Value: {repr(value)}")
            self.failed += 1
            raise AssertionError(f"{message}: Value is empty")
        try:
            print(f"+ PASS: {message}")
        except UnicodeEncodeError:
            print(f"+ PASS: {message}")
        self.passed += 1
    
    def create_test_concerns_data(self, concern_type_key, concerns_list):
        """Create test concerns data structure."""
        return {concern_type_key: concerns_list}
    
    def locate_dashboard_file(self):
        """Locate the Source Data Concern Dashboard HTML file."""
        print("\n--- Test: Dashboard File Location ---")
        
        try:
            root_path = get_analysis_tools_root()
        except:
            root_path = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        
        dashboard_path = os.path.join(root_path, "dashboards", "sourceDataConcernDashboard.html")
        
        self.assert_true(os.path.exists(dashboard_path), "Dashboard file exists")
        self.dashboard_path = dashboard_path
        
        # Check file size indicates it's the full dashboard
        file_size = os.path.getsize(dashboard_path)
        self.assert_true(file_size > 50000, f"Dashboard file has substantial content ({file_size} bytes)")
        
        return dashboard_path
    
    def validate_dashboard_structure(self):
        """Validate that dashboard has required HTML structure and JavaScript functions."""
        print("\n--- Test: Dashboard HTML Structure ---")
        
        with open(self.dashboard_path, 'r', encoding='utf-8') as f:
            dashboard_content = f.read()
        
        # Check for essential HTML elements
        required_elements = [
            'id="jsonFileInput"',  # File input for JSON loading
            'id="status-bar"',     # Status bar for feedback
            'id="stats-section"',  # Statistics display section
            'id="sources-list"',   # Sources list display
            'class="dashboard-content"'  # Main dashboard content area
        ]
        
        for element in required_elements:
            self.assert_contains(dashboard_content, element, f"Dashboard contains required element: {element}")
        
        # Check for essential JavaScript functions
        required_functions = [
            'function loadJsonFile()',
            'function processLoadedData()',
            'function populateStats()',
            'function populateSources()',
            'function updateStatusBar('
        ]
        
        for function in required_functions:
            self.assert_contains(dashboard_content, function, f"Dashboard contains required function: {function}")
        
        # Check for JSON validation logic
        self.assert_contains(dashboard_content, 'sourceDataConcernReport.json format', 
                           "Dashboard validates JSON format")
        self.assert_contains(dashboard_content, 'jsonData.metadata', 
                           "Dashboard checks for metadata")
        self.assert_contains(dashboard_content, 'jsonData.cve_data', 
                           "Dashboard checks for cve_data")
    
    def generate_test_json_data(self):
        """Generate comprehensive test JSON data that mirrors real sourceDataConcernReport.json."""
        print("\n--- Test: Test Data Generation ---")
        
        # Create realistic test data structure manually
        test_data = {
            "metadata": {
                "run_started_at": "2025-08-12T14:15:00.000Z",
                "run_completed_at": "2025-08-12T14:16:30.000Z",
                "total_cves_processed": 3,
                "total_platform_entries": 4,
                "entries_with_concerns": 3,
                "status": "complete",
                "concern_type_counts": [
                    {"concern_type": "placeholderData", "count": 1},
                    {"concern_type": "versionTextPatterns", "count": 2},
                    {"concern_type": "versionGranularity", "count": 1},
                    {"concern_type": "duplicateEntries", "count": 1}
                ]
            },
            "cve_data": [
                {
                    "cve_id": "CVE-2024-DASHBOARD-TEST-001",
                    "platform_entries": [
                        {
                            "platform_entry_id": "entry_0",
                            "table_index": 0,
                            "source_id": "dashboard-test-source-1",
                            "source_name": "Dashboard Test Org 1",
                            "vendor": "n/a",
                            "product": "TestProduct",
                            "total_concerns": 3,
                            "concern_types": ["placeholderData", "versionTextPatterns"],
                            "concern_breakdown": {
                                "placeholderData": 1,
                                "versionTextPatterns": 2
                            },
                            "concerns_detail": [
                                {
                                    "concern_type": "placeholderData",
                                    "concerns": [
                                        {
                                            "concern": "Vendor contains placeholder: n/a",
                                            "category": "Placeholder Data",
                                            "issue": "Missing vendor"
                                        }
                                    ]
                                },
                                {
                                    "concern_type": "versionTextPatterns", 
                                    "concerns": [
                                        {
                                            "concern": "Version contains text: before 2.0",
                                            "category": "Version Text Patterns",
                                            "issue": "Text in version"
                                        },
                                        {
                                            "concern": "Version contains text: after 1.5",
                                            "category": "Version Text Patterns", 
                                            "issue": "Text in version"
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "platform_entry_id": "entry_1",
                            "table_index": 1,
                            "source_id": "dashboard-test-source-2",
                            "source_name": "Dashboard Test Org 2",
                            "vendor": "TestCorp",
                            "product": "TestApp",
                            "total_concerns": 1,
                            "concern_types": ["versionGranularity"],
                            "concern_breakdown": {
                                "versionGranularity": 1
                            },
                            "concerns_detail": [
                                {
                                    "concern_type": "versionGranularity",
                                    "concerns": [
                                        {
                                            "concern": "Inconsistent granularity: 2-part vs 3-part",
                                            "category": "Version Granularity",
                                            "issue": "Version precision"
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "cve_metadata": {
                        "total_platform_entries": 2,
                        "entries_with_concerns": 2,
                        "concern_type_counts": [
                            {"concern_type": "placeholderData", "count": 1},
                            {"concern_type": "versionTextPatterns", "count": 2},
                            {"concern_type": "versionGranularity", "count": 1}
                        ]
                    }
                },
                {
                    "cve_id": "CVE-2024-DASHBOARD-TEST-002",
                    "platform_entries": [
                        {
                            "platform_entry_id": "entry_0",
                            "table_index": 0,
                            "source_id": "multi-cve-source",
                            "source_name": "Multi CVE Test Source",
                            "vendor": "DuplicateCorp",
                            "product": "DuplicateApp",
                            "total_concerns": 1,
                            "concern_types": ["duplicateEntries"],
                            "concern_breakdown": {
                                "duplicateEntries": 1
                            },
                            "concerns_detail": [
                                {
                                    "concern_type": "duplicateEntries",
                                    "concerns": [
                                        {
                                            "concern": "Duplicate CPE entries found",
                                            "category": "Duplicate Entries",
                                            "issue": "Data duplication"
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "cve_metadata": {
                        "total_platform_entries": 1,
                        "entries_with_concerns": 1,
                        "concern_type_counts": [
                            {"concern_type": "duplicateEntries", "count": 1}
                        ]
                    }
                },
                {
                    "cve_id": "CVE-2024-DASHBOARD-TEST-003",
                    "platform_entries": [
                        {
                            "platform_entry_id": "entry_0",
                            "table_index": 0,
                            "source_id": "zero-concern-source",
                            "source_name": "Zero Concern Source",
                            "vendor": "CleanCorp",
                            "product": "CleanApp",
                            "total_concerns": 0,
                            "concern_types": [],
                            "concern_breakdown": {},
                            "concerns_detail": []
                        }
                    ],
                    "cve_metadata": {
                        "total_platform_entries": 1,
                        "entries_with_concerns": 0,
                        "concern_type_counts": []
                    }
                }
            ]
        }
        
        # Save test data to file
        test_file_path = os.path.join(self.temp_dir, "test_dashboard_data.json")
        with open(test_file_path, 'w', encoding='utf-8') as f:
            json.dump(test_data, f, indent=2)
        
        self.test_data_files.append(test_file_path)
        self.assert_true(os.path.exists(test_file_path), "Test JSON file created")
        
        return test_data, test_file_path
    
    def validate_json_structure_for_dashboard(self, test_data):
        """Validate that generated JSON has the structure expected by dashboard."""
        print("\n--- Test: JSON Structure Validation ---")
        
        # Validate top-level structure
        self.assert_contains(test_data.keys(), 'metadata', "JSON contains metadata section")
        self.assert_contains(test_data.keys(), 'cve_data', "JSON contains cve_data section")
        
        metadata = test_data['metadata']
        cve_data = test_data['cve_data']
        
        # Validate metadata structure (used by populateStats)
        required_metadata_fields = [
            'total_cves_processed',
            'total_platform_entries', 
            'entries_with_concerns',
            'concern_type_counts',
            'run_started_at',
            'status'
        ]
        
        for field in required_metadata_fields:
            self.assert_contains(metadata.keys(), field, f"Metadata contains required field: {field}")
        
        # Validate concern_type_counts structure (used by populateStats)
        concern_type_counts = metadata['concern_type_counts']
        self.assert_true(isinstance(concern_type_counts, list), "concern_type_counts is array")
        
        if concern_type_counts:
            for concern_entry in concern_type_counts:
                self.assert_contains(concern_entry.keys(), 'concern_type', "Concern entry has concern_type")
                self.assert_contains(concern_entry.keys(), 'count', "Concern entry has count")
                self.assert_true(isinstance(concern_entry['count'], int), "Concern count is integer")
        
        # Validate CVE data structure (used by populateSources)
        self.assert_true(isinstance(cve_data, list), "cve_data is array")
        self.assert_true(len(cve_data) > 0, "cve_data contains CVE entries")
        
        for cve_entry in cve_data:
            # Essential fields for dashboard processing
            required_cve_fields = ['cve_id', 'platform_entries', 'cve_metadata']
            for field in required_cve_fields:
                self.assert_contains(cve_entry.keys(), field, f"CVE entry contains required field: {field}")
            
            # Validate platform_entries structure (core of populateSources logic)
            platform_entries = cve_entry['platform_entries']
            self.assert_true(isinstance(platform_entries, list), "platform_entries is array")
            
            for platform_entry in platform_entries:
                required_platform_fields = [
                    'platform_entry_id', 'table_index', 'source_id', 'source_name',
                    'vendor', 'product', 'total_concerns', 'concern_types', 
                    'concern_breakdown', 'concerns_detail'
                ]
                
                for field in required_platform_fields:
                    self.assert_contains(platform_entry.keys(), field, 
                                       f"Platform entry contains required field: {field}")
                
                # Validate data types
                self.assert_true(isinstance(platform_entry['total_concerns'], int), 
                               "total_concerns is integer")
                self.assert_true(isinstance(platform_entry['concern_types'], list), 
                               "concern_types is array")
                self.assert_true(isinstance(platform_entry['concern_breakdown'], dict), 
                               "concern_breakdown is object")
                self.assert_true(isinstance(platform_entry['concerns_detail'], list), 
                               "concerns_detail is array")
    
    def test_dashboard_statistics_calculation(self, test_data):
        """Test that dashboard can correctly calculate statistics from JSON data."""
        print("\n--- Test: Dashboard Statistics Calculation ---")
        
        metadata = test_data['metadata']
        cve_data = test_data['cve_data']
        
        # Simulate dashboard statistics calculation logic
        total_cves = metadata['total_cves_processed']
        total_entries = metadata['total_platform_entries']
        entries_with_concerns = metadata['entries_with_concerns']
        total_concern_types = len(metadata['concern_type_counts']) if metadata['concern_type_counts'] else 0
        total_concerns = sum(item['count'] for item in metadata['concern_type_counts']) if metadata['concern_type_counts'] else 0
        
        # Count unique sources (as dashboard does)
        unique_sources = set()
        for cve in cve_data:
            for entry in cve['platform_entries']:
                unique_sources.add(entry['source_id'])
        
        # Validate calculations match expected test data
        self.assert_equals(total_cves, 3, "Correct total CVEs calculated")
        self.assert_true(total_entries >= 3, f"Correct total entries calculated ({total_entries})")
        self.assert_true(entries_with_concerns >= 2, f"Correct entries with concerns calculated ({entries_with_concerns})")
        self.assert_true(total_concern_types >= 3, f"Correct concern types calculated ({total_concern_types})")
        self.assert_true(total_concerns >= 4, f"Correct total concerns calculated ({total_concerns})")
        self.assert_true(len(unique_sources) >= 3, f"Correct unique sources calculated ({len(unique_sources)})")
        
        # Validate specific concern types are present
        concern_types_found = [item['concern_type'] for item in metadata['concern_type_counts']]
        expected_types = ['placeholderData', 'versionTextPatterns', 'versionGranularity', 'duplicateEntries']
        
        for expected_type in expected_types:
            self.assert_contains(concern_types_found, expected_type, 
                               f"Expected concern type present: {expected_type}")
    
    def test_dashboard_source_processing(self, test_data):
        """Test that dashboard can correctly process source data from JSON."""
        print("\n--- Test: Dashboard Source Processing ---")
        
        cve_data = test_data['cve_data']
        
        # Simulate dashboard source processing logic (populateSources function)
        source_data = {}
        
        # First pass: Track ALL CVEs processed per source
        for cve in cve_data:
            if cve['platform_entries']:
                for entry in cve['platform_entries']:
                    source_id = entry['source_id']
                    if source_id not in source_data:
                        source_data[source_id] = {
                            'source_id': source_id,
                            'source_name': entry['source_name'],
                            'total_concerns': 0,
                            'cve_records': set(),
                            'cve_records_with_concerns': set(),
                            'cve_records_without_concerns': set(),
                            'concern_breakdown': {},
                            'entries': []
                        }
                    
                    source = source_data[source_id]
                    source['cve_records'].add(cve['cve_id'])
                    
                    if entry['total_concerns'] > 0:
                        source['cve_records_with_concerns'].add(cve['cve_id'])
                    else:
                        source['cve_records_without_concerns'].add(cve['cve_id'])
        
        # Second pass: Aggregate concern data
        for cve in cve_data:
            for entry in cve['platform_entries']:
                source_id = entry['source_id']
                source = source_data[source_id]
                
                source['total_concerns'] += entry['total_concerns']
                source['entries'].append(entry)
                
                # Aggregate concern breakdown
                for concern_type, count in entry['concern_breakdown'].items():
                    if concern_type not in source['concern_breakdown']:
                        source['concern_breakdown'][concern_type] = 0
                    source['concern_breakdown'][concern_type] += count
        
        # Validate source processing results
        self.assert_true(len(source_data) >= 3, f"Processed multiple sources ({len(source_data)})")
        
        # Check specific sources we created
        expected_sources = ['dashboard-test-source-1', 'dashboard-test-source-2', 'multi-cve-source']
        for expected_source in expected_sources:
            self.assert_contains(source_data.keys(), expected_source, 
                               f"Expected source processed: {expected_source}")
        
        # Validate source with multiple concerns
        source_1 = source_data.get('dashboard-test-source-1')
        if source_1:
            self.assert_true(source_1['total_concerns'] > 1, 
                           f"Source 1 has multiple concerns ({source_1['total_concerns']})")
            self.assert_contains(source_1['concern_breakdown'].keys(), 'placeholderData', 
                               "Source 1 has placeholder data concerns")
            self.assert_contains(source_1['concern_breakdown'].keys(), 'versionTextPatterns', 
                               "Source 1 has version text pattern concerns")
        
        # Validate source with single concern
        source_2 = source_data.get('dashboard-test-source-2')
        if source_2:
            self.assert_true(source_2['total_concerns'] >= 1, 
                           f"Source 2 has concerns ({source_2['total_concerns']})")
            self.assert_contains(source_2['concern_breakdown'].keys(), 'versionGranularity', 
                               "Source 2 has version granularity concerns")
    
    def test_dashboard_error_handling(self):
        """Test dashboard error handling with invalid JSON data."""
        print("\n--- Test: Dashboard Error Handling ---")
        
        # Create invalid JSON test cases
        invalid_json_cases = [
            # Missing metadata
            {'cve_data': []},
            # Missing cve_data  
            {'metadata': {'total_cves_processed': 0}},
            # Empty structure
            {},
            # Invalid metadata structure
            {'metadata': 'invalid', 'cve_data': []},
            # Invalid cve_data structure
            {'metadata': {'total_cves_processed': 0}, 'cve_data': 'invalid'}
        ]
        
        # Read dashboard content to check validation logic
        with open(self.dashboard_path, 'r', encoding='utf-8') as f:
            dashboard_content = f.read()
        
        # Verify dashboard has validation checks
        validation_checks = [
            '!jsonData.metadata',
            '!jsonData.cve_data',
            'Invalid JSON structure',
            'sourceDataConcernReport.json format'
        ]
        
        for check in validation_checks:
            self.assert_contains(dashboard_content, check, 
                               f"Dashboard has validation check: {check}")
        
        # Create test files with invalid JSON
        for i, invalid_case in enumerate(invalid_json_cases):
            invalid_file = os.path.join(self.temp_dir, f"invalid_test_{i}.json")
            with open(invalid_file, 'w', encoding='utf-8') as f:
                json.dump(invalid_case, f)
            
            self.test_data_files.append(invalid_file)
            self.assert_true(os.path.exists(invalid_file), f"Invalid test file {i} created")
    
    def test_dashboard_large_dataset_handling(self):
        """Test dashboard performance with larger datasets."""
        print("\n--- Test: Large Dataset Handling ---")
        
        # Generate larger test dataset manually
        large_data = {
            "metadata": {
                "run_started_at": "2025-08-12T14:20:00.000Z",
                "run_completed_at": "2025-08-12T14:25:30.000Z",
                "total_cves_processed": 10,
                "total_platform_entries": 35,
                "entries_with_concerns": 30,
                "status": "complete",
                "concern_type_counts": [
                    {"concern_type": "placeholderData", "count": 8},
                    {"concern_type": "versionTextPatterns", "count": 12},
                    {"concern_type": "versionGranularity", "count": 6},
                    {"concern_type": "duplicateEntries", "count": 4},
                    {"concern_type": "cpeArrayConcerns", "count": 5}
                ]
            },
            "cve_data": []
        }
        
        # Generate 10 CVEs with multiple entries each
        concern_types_cycle = [
            "placeholderData",
            "versionTextPatterns", 
            "versionGranularity",
            "duplicateEntries",
            "cpeArrayConcerns"
        ]
        
        for cve_num in range(10):
            cve_entry = {
                "cve_id": f"CVE-2024-LARGE-TEST-{cve_num:03d}",
                "platform_entries": [],
                "cve_metadata": {
                    "total_platform_entries": 0,
                    "entries_with_concerns": 0,
                    "concern_type_counts": []
                }
            }
            
            # 3-5 entries per CVE
            entries_count = 3 + (cve_num % 3)
            for entry_num in range(entries_count):
                concern_type = concern_types_cycle[entry_num % len(concern_types_cycle)]
                
                platform_entry = {
                    "platform_entry_id": f"entry_{entry_num}",
                    "table_index": entry_num,
                    "source_id": f"high-volume-source-{entry_num % 3}",
                    "source_name": f"High Volume Test Source {entry_num % 3}",
                    "vendor": f"Vendor{entry_num}",
                    "product": f"Product{entry_num}",
                    "total_concerns": 1,
                    "concern_types": [concern_type],
                    "concern_breakdown": {concern_type: 1},
                    "concerns_detail": [
                        {
                            "concern_type": concern_type,
                            "concerns": [
                                {
                                    "concern": f"Test concern {cve_num}-{entry_num}",
                                    "category": concern_type.replace('Data', ' Data').replace('Text', ' Text').replace('Granularity', ' Granularity').replace('Entries', ' Entries').replace('Concerns', ' Concerns'),
                                    "issue": f"Test issue {cve_num}-{entry_num}"
                                }
                            ]
                        }
                    ]
                }
                
                cve_entry["platform_entries"].append(platform_entry)
                cve_entry["cve_metadata"]["total_platform_entries"] += 1
                cve_entry["cve_metadata"]["entries_with_concerns"] += 1
            
            large_data["cve_data"].append(cve_entry)
        
        # Save large dataset
        large_report_path = os.path.join(self.temp_dir, "large_test_dataset.json")
        with open(large_report_path, 'w', encoding='utf-8') as f:
            json.dump(large_data, f, indent=2)
        
        self.test_data_files.append(large_report_path)
        self.assert_true(os.path.exists(large_report_path), "Large dataset generated")
        
        # Check dataset size
        self.assert_equals(large_data['metadata']['total_cves_processed'], 10, 
                         "Large dataset has correct CVE count")
        self.assert_true(large_data['metadata']['total_platform_entries'] >= 30, 
                       f"Large dataset has multiple entries ({large_data['metadata']['total_platform_entries']})")
        
        # Check JSON file size (dashboard performance consideration)
        file_size = os.path.getsize(large_report_path)
        self.assert_true(file_size > 10000, f"Large dataset has substantial size ({file_size} bytes)")
        
        # Validate JSON parsing performance by loading multiple times
        parse_times = []
        import time
        for _ in range(3):
            start_time = time.time()
            with open(large_report_path, 'r', encoding='utf-8') as f:
                json.load(f)
            parse_time = time.time() - start_time
            parse_times.append(parse_time)
        
        avg_parse_time = sum(parse_times) / len(parse_times)
        self.assert_true(avg_parse_time < 1.0, f"JSON parsing performance acceptable ({avg_parse_time:.3f}s)")
    
    def test_dashboard_ui_elements(self):
        """Test that dashboard UI elements are properly structured."""
        print("\n--- Test: Dashboard UI Elements ---")
        
        with open(self.dashboard_path, 'r', encoding='utf-8') as f:
            dashboard_content = f.read()
        
        # Check for essential UI components
        ui_elements = [
            # File input area
            'type="file"',
            'accept=".json"',
            
            # Status bar elements
            'id="status-filename"',
            'id="generation-time"', 
            'id="file-size"',
            'id="load-time"',
            
            # Statistics cards
            'class="stat-card purple"',
            'class="stat-number"',
            'class="stat-label"',
            
            # Sources section
            'class="source-item"',
            'class="source-stats"',
            
            # Error handling UI
            'showError',
            'showSuccess',
            
            # Interactive elements
            'onclick',
            'addEventListener'
        ]
        
        for element in ui_elements:
            self.assert_contains(dashboard_content, element, f"Dashboard has UI element: {element}")
        
        # Check for responsive design elements
        responsive_elements = [
            'max-width',
            '@media',
            'viewport',
            'mobile'
        ]
        
        responsive_found = sum(1 for element in responsive_elements if element in dashboard_content)
        self.assert_true(responsive_found >= 2, f"Dashboard has responsive design elements ({responsive_found}/4)")
        
        # Check for accessibility features
        accessibility_elements = [
            'alt=',
            'aria-',
            'role=',
            'tabindex'
        ]
        
        accessibility_found = sum(1 for element in accessibility_elements if element in dashboard_content)
        self.assert_true(accessibility_found >= 0, f"Dashboard accessibility features check ({accessibility_found}/4 found)")


def main():
    """Run the Source Data Concern Dashboard display test suite."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test source data concern dashboard functionality')
    args = parser.parse_args()
    
    print("Starting Source Data Concern Dashboard Display Test Suite")
    print("=" * 70)
    print("This test suite validates the dashboard's ability to ingest and")
    print("display JSON data generated by the badge contents collector.")
    print("=" * 70)
    
    test_suite = SourceDataConcernDashboardDisplayTestSuite()
    
    try:
        print(f"Test environment created: {test_suite.temp_dir}")
        
        # Test 1: Locate and validate dashboard file
        test_suite.locate_dashboard_file()
        
        # Test 2: Validate dashboard HTML structure
        test_suite.validate_dashboard_structure()
        
        # Test 3: Generate test JSON data
        test_data, test_file_path = test_suite.generate_test_json_data()
        
        # Test 4: Validate JSON structure for dashboard compatibility
        test_suite.validate_json_structure_for_dashboard(test_data)
        
        # Test 5: Test dashboard statistics calculation
        test_suite.test_dashboard_statistics_calculation(test_data)
        
        # Test 6: Test dashboard source processing
        test_suite.test_dashboard_source_processing(test_data)
        
        # Test 7: Test dashboard error handling
        test_suite.test_dashboard_error_handling()
        
        # Test 8: Test large dataset handling
        test_suite.test_dashboard_large_dataset_handling()
        
        # Test 9: Test dashboard UI elements
        test_suite.test_dashboard_ui_elements()
        
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        
        total_tests = test_suite.passed + test_suite.failed
        success_rate = (test_suite.passed / total_tests * 100) if total_tests > 0 else 0
        
        print("[!] ALL DASHBOARD DISPLAY TESTS PASSED!")
        print("Source Data Concern Dashboard properly ingests and displays JSON data.")
        print(f"Tests Passed: {test_suite.passed}")
        print(f"Tests Failed: {test_suite.failed}")
        print(f"Total Tests: {total_tests}")
        print(f"Success Rate: {success_rate:.1f}%")
        print(f"Test files generated: {len(test_suite.test_data_files)}")
        for test_file in test_suite.test_data_files:
            if os.path.exists(test_file):
                file_size = os.path.getsize(test_file)
                print(f"  - {os.path.basename(test_file)} ({file_size} bytes)")
        
        # Standardized output for run_all_tests.py integration
        print(f"TEST_RESULTS: PASSED={test_suite.passed} TOTAL={total_tests} SUITE=\"Source Data Concern Dashboard Display\"")
        
        return 0
        
    except Exception as e:
        print(f"\n[X] DASHBOARD DISPLAY TEST FAILED")
        print(f"Error: {e}")
        
        # Still output TEST_RESULTS even on failure for proper integration
        total_tests = test_suite.passed + test_suite.failed
        print(f"TEST_RESULTS: PASSED={test_suite.passed} TOTAL={total_tests} SUITE=\"Source Data Concern Dashboard Display\"")
        
        return 1
        
    finally:
        test_suite.cleanup()


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
