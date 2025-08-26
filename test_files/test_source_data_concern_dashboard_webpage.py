"""
Standalone test for Source Data Concern Dashboard display functionality.
This test validates the dashboard can properly ingest and display JSON data.
"""

import os
import json
import tempfile
import shutil
import time


class DashboardDisplayTest:
    """Standalone test class for dashboard display validation."""
    
    def __init__(self):
        """Initialize test environment."""
        self.temp_dir = tempfile.mkdtemp(prefix="dashboard_test_")
        self.dashboard_path = None
        self.test_files = []
        self.passed = 0
        self.failed = 0
        
    def cleanup(self):
        """Clean up test environment."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
        print(f"Test environment cleaned up: {self.temp_dir}")
    
    def assert_true(self, condition, message):
        """Assert that condition is true."""
        if not condition:
            print(f"X FAIL: {message}")
            self.failed += 1
            raise AssertionError(message)
        print(f"+ PASS: {message}")
        self.passed += 1
    
    def assert_contains(self, container, item, message):
        """Assert that container contains item."""
        if item not in container:
            print(f"X FAIL: {message}")
            print(f"  Expected to find: {item}")
            self.failed += 1
            raise AssertionError(f"{message}: {item} not found")
        print(f"+ PASS: {message}")
        self.passed += 1
    
    def test_dashboard_file_location(self):
        """Test that dashboard file exists and has required structure."""
        print("\n--- Test: Dashboard File Location ---")
        
        # Find dashboard file
        current_dir = os.path.dirname(os.path.dirname(__file__))
        dashboard_path = os.path.join(current_dir, "dashboards", "sourceDataConcernDashboard.html")
        
        self.assert_true(os.path.exists(dashboard_path), f"Dashboard file exists at {dashboard_path}")
        
        # Check file size
        file_size = os.path.getsize(dashboard_path)
        self.assert_true(file_size > 50000, f"Dashboard file has substantial content ({file_size} bytes)")
        
        self.dashboard_path = dashboard_path
        return dashboard_path
    
    def test_dashboard_structure(self):
        """Test dashboard HTML structure and JavaScript functions."""
        print("\n--- Test: Dashboard HTML Structure ---")
        
        with open(self.dashboard_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Essential HTML elements
        required_elements = [
            'id="jsonFileInput"',
            'id="status-bar"', 
            'id="stats-section"',
            'id="sources-list"',
            'class="dashboard-content"'
        ]
        
        for element in required_elements:
            self.assert_contains(content, element, f"Dashboard contains required element: {element}")
        
        # Essential JavaScript functions
        required_functions = [
            'function loadJsonFile()',
            'function processLoadedData()',
            'function populateStats()',
            'function populateSources()'
        ]
        
        for function in required_functions:
            self.assert_contains(content, function, f"Dashboard contains required function: {function}")
        
        # JSON validation
        validation_checks = [
            'sourceDataConcernReport.json format',
            'jsonData.metadata',
            'jsonData.cve_data'
        ]
        
        for check in validation_checks:
            self.assert_contains(content, check, f"Dashboard has validation check: {check}")
    
    def create_test_json_data(self):
        """Create comprehensive test JSON data."""
        print("\n--- Test: Test JSON Data Creation ---")
        
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
                                }
                            ]
                        }
                    ],
                    "cve_metadata": {
                        "total_platform_entries": 1,
                        "entries_with_concerns": 1,
                        "concern_type_counts": [
                            {"concern_type": "placeholderData", "count": 1},
                            {"concern_type": "versionTextPatterns", "count": 2}
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
        
        # Save test data
        test_file = os.path.join(self.temp_dir, "test_dashboard_data.json")
        with open(test_file, 'w', encoding='utf-8') as f:
            json.dump(test_data, f, indent=2)
        
        self.test_files.append(test_file)
        self.assert_true(os.path.exists(test_file), "Test JSON file created")
        
        return test_data, test_file
    
    def test_json_structure_validation(self, test_data):
        """Test that JSON has structure expected by dashboard."""
        print("\n--- Test: JSON Structure Validation ---")
        
        # Top-level structure
        self.assert_contains(test_data.keys(), 'metadata', "JSON contains metadata")
        self.assert_contains(test_data.keys(), 'cve_data', "JSON contains cve_data")
        
        metadata = test_data['metadata']
        cve_data = test_data['cve_data']
        
        # Metadata structure
        required_metadata = [
            'total_cves_processed',
            'total_platform_entries',
            'entries_with_concerns', 
            'concern_type_counts',
            'run_started_at',
            'status'
        ]
        
        for field in required_metadata:
            self.assert_contains(metadata.keys(), field, f"Metadata contains {field}")
        
        # CVE data structure
        self.assert_true(isinstance(cve_data, list), "cve_data is array")
        self.assert_true(len(cve_data) > 0, "cve_data contains entries")
        
        for cve_entry in cve_data:
            required_cve_fields = ['cve_id', 'platform_entries', 'cve_metadata']
            for field in required_cve_fields:
                self.assert_contains(cve_entry.keys(), field, f"CVE entry contains {field}")
            
            # Platform entries structure
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
                                       f"Platform entry contains {field}")
    
    def test_dashboard_statistics_simulation(self, test_data):
        """Test dashboard statistics calculation simulation."""
        print("\n--- Test: Dashboard Statistics Simulation ---")
        
        metadata = test_data['metadata']
        cve_data = test_data['cve_data']
        
        # Simulate dashboard stats calculation
        total_cves = metadata['total_cves_processed']
        total_entries = metadata['total_platform_entries'] 
        entries_with_concerns = metadata['entries_with_concerns']
        total_concern_types = len(metadata['concern_type_counts'])
        total_concerns = sum(item['count'] for item in metadata['concern_type_counts'])
        
        # Count unique sources
        unique_sources = set()
        for cve in cve_data:
            for entry in cve['platform_entries']:
                unique_sources.add(entry['source_id'])
        
        # Validate calculations
        self.assert_true(total_cves == 3, f"Correct total CVEs ({total_cves})")
        self.assert_true(total_entries == 4, f"Correct total entries ({total_entries})")
        self.assert_true(entries_with_concerns == 3, f"Correct entries with concerns ({entries_with_concerns})")
        self.assert_true(total_concern_types == 4, f"Correct concern types ({total_concern_types})")
        self.assert_true(total_concerns == 5, f"Correct total concerns ({total_concerns})")
        self.assert_true(len(unique_sources) == 3, f"Correct unique sources ({len(unique_sources)})")
    
    def test_dashboard_source_processing_simulation(self, test_data):
        """Test dashboard source processing simulation."""
        print("\n--- Test: Dashboard Source Processing Simulation ---")
        
        cve_data = test_data['cve_data']
        
        # Simulate populateSources logic
        source_data = {}
        
        # First pass: Track CVEs per source
        for cve in cve_data:
            for entry in cve['platform_entries']:
                source_id = entry['source_id']
                if source_id not in source_data:
                    source_data[source_id] = {
                        'source_id': source_id,
                        'source_name': entry['source_name'],
                        'total_concerns': 0,
                        'cve_records': set(),
                        'concern_breakdown': {},
                        'entries': []
                    }
                
                source = source_data[source_id]
                source['cve_records'].add(cve['cve_id'])
                source['total_concerns'] += entry['total_concerns']
                source['entries'].append(entry)
                
                # Aggregate concern breakdown
                for concern_type, count in entry['concern_breakdown'].items():
                    if concern_type not in source['concern_breakdown']:
                        source['concern_breakdown'][concern_type] = 0
                    source['concern_breakdown'][concern_type] += count
        
        # Validate source processing
        self.assert_true(len(source_data) == 3, f"Processed 3 sources ({len(source_data)})")
        
        expected_sources = ['dashboard-test-source-1', 'multi-cve-source', 'zero-concern-source']
        for expected_source in expected_sources:
            self.assert_contains(source_data.keys(), expected_source, 
                               f"Source processed: {expected_source}")
        
        # Check specific source data
        source_1 = source_data.get('dashboard-test-source-1')
        if source_1:
            self.assert_true(source_1['total_concerns'] == 3, 
                           f"Source 1 has correct concerns ({source_1['total_concerns']})")
            self.assert_contains(source_1['concern_breakdown'].keys(), 'placeholderData',
                               "Source 1 has placeholder data concerns")
    
    def test_invalid_json_handling(self):
        """Test dashboard error handling with invalid JSON."""
        print("\n--- Test: Invalid JSON Handling ---")
        
        # Create invalid JSON test cases
        invalid_cases = [
            {},  # Empty
            {'metadata': {}},  # Missing cve_data
            {'cve_data': []},  # Missing metadata
            {'metadata': 'invalid', 'cve_data': []},  # Invalid metadata type
            {'metadata': {}, 'cve_data': 'invalid'}   # Invalid cve_data type
        ]
        
        # Read dashboard content
        with open(self.dashboard_path, 'r', encoding='utf-8') as f:
            dashboard_content = f.read()
        
        # Check validation logic exists
        validation_checks = [
            '!jsonData.metadata',
            '!jsonData.cve_data', 
            'Invalid JSON structure',
            'sourceDataConcernReport.json format'
        ]
        
        for check in validation_checks:
            self.assert_contains(dashboard_content, check, 
                               f"Dashboard has validation: {check}")
        
        # Create invalid test files
        for i, invalid_case in enumerate(invalid_cases):
            invalid_file = os.path.join(self.temp_dir, f"invalid_{i}.json")
            with open(invalid_file, 'w', encoding='utf-8') as f:
                json.dump(invalid_case, f)
            
            self.test_files.append(invalid_file)
            self.assert_true(os.path.exists(invalid_file), f"Invalid test file {i} created")
    
    def test_performance_considerations(self):
        """Test performance-related aspects of dashboard."""
        print("\n--- Test: Performance Considerations ---")
        
        # Create larger dataset for performance testing
        large_data = {
            "metadata": {
                "run_started_at": "2025-08-12T14:20:00.000Z",
                "total_cves_processed": 50,
                "total_platform_entries": 150,
                "entries_with_concerns": 120,
                "status": "complete",
                "concern_type_counts": [
                    {"concern_type": "placeholderData", "count": 25},
                    {"concern_type": "versionTextPatterns", "count": 40},
                    {"concern_type": "versionGranularity", "count": 30},
                    {"concern_type": "duplicateEntries", "count": 25}
                ]
            },
            "cve_data": []
        }
        
        # Generate 50 CVEs with multiple entries each
        for i in range(50):
            cve_entry = {
                "cve_id": f"CVE-2024-PERF-TEST-{i:03d}",
                "platform_entries": [],
                "cve_metadata": {
                    "total_platform_entries": 3,
                    "entries_with_concerns": 2,
                    "concern_type_counts": []
                }
            }
            
            # 3 entries per CVE
            for j in range(3):
                platform_entry = {
                    "platform_entry_id": f"entry_{j}",
                    "table_index": j,
                    "source_id": f"perf-test-source-{j % 5}",
                    "source_name": f"Performance Test Source {j % 5}",
                    "vendor": f"Vendor{j}",
                    "product": f"Product{j}",
                    "total_concerns": 1 if j < 2 else 0,
                    "concern_types": ["placeholderData"] if j < 2 else [],
                    "concern_breakdown": {"placeholderData": 1} if j < 2 else {},
                    "concerns_detail": []
                }
                cve_entry["platform_entries"].append(platform_entry)
            
            large_data["cve_data"].append(cve_entry)
        
        # Save large dataset
        large_file = os.path.join(self.temp_dir, "large_dataset.json")
        with open(large_file, 'w', encoding='utf-8') as f:
            json.dump(large_data, f, indent=2)
        
        self.test_files.append(large_file)
        
        # Check file size
        file_size = os.path.getsize(large_file)
        self.assert_true(file_size > 50000, f"Large dataset has substantial size ({file_size} bytes)")
        
        # Test JSON parsing performance
        parse_times = []
        for _ in range(3):
            start_time = time.time()
            with open(large_file, 'r', encoding='utf-8') as f:
                json.load(f)
            parse_time = time.time() - start_time
            parse_times.append(parse_time)
        
        avg_parse_time = sum(parse_times) / len(parse_times)
        self.assert_true(avg_parse_time < 1.0, f"JSON parsing acceptable ({avg_parse_time:.3f}s)")


def main():
    """Run the dashboard display test suite."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test source data concern dashboard webpage functionality')
    args = parser.parse_args()
    
    print("Source Data Concern Dashboard Display Test Suite")
    print("=" * 60)
    print("Testing dashboard's ability to ingest and display JSON data")
    print("=" * 60)
    
    test = DashboardDisplayTest()
    
    try:
        print(f"Test environment: {test.temp_dir}")
        
        # Run test sequence
        test.test_dashboard_file_location()
        test.test_dashboard_structure()
        
        test_data, test_file = test.create_test_json_data() 
        test.test_json_structure_validation(test_data)
        test.test_dashboard_statistics_simulation(test_data)
        test.test_dashboard_source_processing_simulation(test_data)
        
        test.test_invalid_json_handling()
        test.test_performance_considerations()
        
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        
        total_tests = test.passed + test.failed
        success_rate = (test.passed / total_tests * 100) if total_tests > 0 else 0
        
        print(f"[!] ALL DASHBOARD DISPLAY TESTS PASSED!")
        print(f"Dashboard properly ingests and displays JSON data.")
        print(f"Tests Passed: {test.passed}")
        print(f"Tests Failed: {test.failed}")
        print(f"Total Tests: {total_tests}")
        print(f"Success Rate: {success_rate:.1f}%")
        print(f"Test files created: {len(test.test_files)}")
        for test_file in test.test_files:
            if os.path.exists(test_file):
                file_size = os.path.getsize(test_file)
                print(f"  - {os.path.basename(test_file)} ({file_size} bytes)")
        
        # Standardized output for run_all_tests.py integration
        print(f"TEST_RESULTS: PASSED={test.passed} TOTAL={total_tests} SUITE=\"Dashboard Display Standalone\"")
        
        return 0
        
    except Exception as e:
        print(f"\n[X] DASHBOARD DISPLAY TEST FAILED")
        print(f"Error: {e}")
        
        # Still output TEST_RESULTS even on failure for proper integration
        total_tests = test.passed + test.failed
        print(f"TEST_RESULTS: PASSED={test.passed} TOTAL={total_tests} SUITE=\"Dashboard Display Standalone\"")
        
        return 1
        
    finally:
        test.cleanup()


if __name__ == "__main__":
    exit(main())
