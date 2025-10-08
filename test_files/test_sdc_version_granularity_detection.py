#!/usr/bin/env python3
"""
SDC Version Granularity Detection Test Suite

Tests version granularity detection by running test file and checking sourceDataConcernReport.json
Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Usage:
    python test_files/test_sdc_version_granularity_detection.py
"""

import sys
import os
import json
import subprocess
import glob
from pathlib import Path

# Add src path for analysis_tool imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from analysis_tool.storage.run_organization import find_latest_test_run_report

# Path to the version granularity detection test file
TEST_FILE = os.path.join(os.path.dirname(__file__), "testVersionGranularityDetection.json")

def run_test_and_get_report():
    """Run the test file and extract the sourceDataConcernReport.json"""
    try:
        # Run the tool using the standard command line interface
        cmd = [sys.executable, "run_tools.py", "--test-file", TEST_FILE, "--no-cache", "--sdc-report", "true"]
        
        # Check if running under unified test runner to control browser behavior
        if os.environ.get('UNIFIED_TEST_RUNNER'):
            # Add --no-browser when running under unified test runner
            cmd.append("--no-browser")
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path(__file__).parent.parent)
        
        if result.returncode != 0:
            print(f"❌ Tool execution failed with return code {result.returncode}")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return None
            
        # Use helper function to find report in both standard and consolidated environments
        return find_latest_test_run_report("sourceDataConcernReport.json")
            
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return None

def get_test_cases():
    """Define test cases with expected results based on testVersionGranularityDetection.json"""
    return [
        {
            "description": "Basic Mixed Granularities: 1.0, 1.0.1, 2, 1.0.1.0",
            "table_index": 0,
            "expected_concerns": 3,
            "expected_fields": ["version", "version", "version"],
            "expected_source_values": ["1.0", "1.0.1", "1.0.1.0"],
            "expected_bases": ["1", "1", "1"],
            "expected_granularities": ["2", "3", "4"]
        },
        {
            "description": "All Supported Fields: version, lessThan, lessThanOrEqual, changes[].at",
            "table_index": 1,
            "expected_concerns": 7,
            "expected_fields": ["version", "version", "lessThan", "lessThanOrEqual", "version", "changes[0].at", "changes[1].at"],
            "expected_source_values": ["1.0", "1.0.1", "1.0.1.0", "1.0.1.0.5", "1.1", "1.1.0", "1.1.0.0.1"],
            "expected_bases": ["1", "1", "1", "1", "1", "1", "1"],
            "expected_granularities": ["2", "3", "4", "5", "2", "3", "5"]
        },
        {
            "description": "Edge Cases: Single digits, 15+ granularity levels",
            "table_index": 2,
            "expected_concerns": 6,
            "expected_fields": ["version", "version", "lessThan", "lessThanOrEqual", "version", "changes[0].at"],
            "expected_source_values": ["3", "3.0", "3.0.0.0.0.0.0.0.0.0.0.0.0.0.1", "3.1.2.3.4.5.6.7.8.9.10.11.12.13.14.15", "5", "5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"],
            "expected_bases": ["3", "3", "3", "3", "5", "5"],
            "expected_granularities": ["1", "2", "15", "16", "1", "17"]
        },
        {
            "description": "Multiple Base Versions: 1.x, 2.x, 10.x with different patterns",
            "table_index": 3,
            "expected_concerns": 6,
            "expected_fields": ["version", "version", "version", "version", "version", "lessThan"],
            "expected_source_values": ["1.0", "1.0.1", "2.1", "2.1.0", "10", "10.0.0.0.0"],
            "expected_bases": ["1", "1", "2", "2", "10", "10"],
            "expected_granularities": ["2", "3", "2", "3", "1", "5"]
        },
        {
            "description": "Multi Product A: Mixed granularities",
            "table_index": 4,
            "expected_concerns": 2,
            "expected_fields": ["version", "version"],
            "expected_source_values": ["4.0", "4.0.1.2"],
            "expected_bases": ["4", "4"],
            "expected_granularities": ["2", "4"]
        },
        {
            "description": "Multi Product B: Different granularity patterns",
            "table_index": 5,
            "expected_concerns": 2,
            "expected_fields": ["version", "lessThanOrEqual"],
            "expected_source_values": ["6", "6.1.0"],
            "expected_bases": ["6", "6"],
            "expected_granularities": ["1", "3"]
        },
        {
            "description": "Negative Test: Consistent Granularity (should have no concerns)",
            "table_index": 6,
            "expected_concerns": 0
        },
        {
            "description": "Negative Test: Single Version (should have no concerns)",
            "table_index": 7,
            "expected_concerns": 0
        },
        {
            "description": "Negative Test: Wildcards/Empty (should have no concerns)",
            "table_index": 8,
            "expected_concerns": 0
        },
        {
            "description": "Complex Nested Changes Arrays: Multiple changes per version",
            "table_index": 9,
            "expected_concerns": 7,
            "expected_fields": ["version", "changes[0].at", "changes[1].at", "changes[2].at", "version", "changes[0].at", "changes[1].at"],
            "expected_source_values": ["9.0", "9.0.1", "9.0.1.0", "9.0.1.0.1", "9.1.0.0", "9.1.0.0.0", "9.1.0.0.0.1"],
            "expected_bases": ["9", "9", "9", "9", "9", "9", "9"],
            "expected_granularities": ["2", "3", "4", "5", "4", "5", "6"]
        },
        {
            "description": "Multiple Fields Per Entry: Combined version fields in single entry",
            "table_index": 10,
            "expected_concerns": 4,
            "expected_fields": ["version", "lessThan", "lessThanOrEqual", "version"],
            "expected_source_values": ["11.0", "11.0.1.0", "11.0.1.0.5", "11.1.0.0.0"],
            "expected_bases": ["11", "11", "11", "11"],
            "expected_granularities": ["2", "4", "5", "5"]
        },
        {
            "description": "Complex Base Grouping: 1.x vs 11.x vs 100.x vs 1000.x",
            "table_index": 11,
            "expected_concerns": 4,
            "expected_fields": ["version", "version", "version", "version"],
            "expected_source_values": ["11.0", "11.0.1", "100", "100.0.0"],
            "expected_bases": ["11", "11", "100", "100"],
            "expected_granularities": ["2", "3", "1", "3"]
        }
    ]

def validate_test_case(test_case, report_data):
    """Validate a single test case against the report data"""
    table_index = test_case['table_index']
    
    # Find the platform entry for this table index
    platform_entry = None
    for cve in report_data.get('cve_data', []):
        for entry in cve.get('platform_entries', []):
            if entry.get('table_index') == table_index:
                platform_entry = entry
                break
        if platform_entry:
            break
    
    # If no platform entry is found and no concerns are expected, this is correct
    if not platform_entry:
        count_match = test_case['expected_concerns'] == 0
        structure_match = True
        value_match = True
        concerns = []
    else:
        # Extract version granularity concerns
        concerns = []
        for concern_detail in platform_entry.get('concerns_detail', []):
            if concern_detail.get('concern_type') == 'versionGranularity':
                concerns.extend(concern_detail.get('concerns', []))
        
        # Test count validation
        count_match = len(concerns) == test_case['expected_concerns']
        
        # Structure validation
        if test_case['expected_concerns'] == 0:
            # If we expect 0 concerns, structure passes regardless of what we found
            structure_match = True
        elif len(concerns) == 0:
            # If we expect concerns but found none, structure validation fails
            structure_match = False
        else:
            # We have concerns to validate structure
            structure_match = True
            # Check structure for all concerns
            for concern in concerns:
                if not all(key in concern for key in ['field', 'sourceValue', 'detectedPattern']):
                    structure_match = False
                    break
                pattern = concern['detectedPattern']
                if 'base' not in pattern or 'granularity' not in pattern:
                    structure_match = False
                    break
            
        # Value validation
        if test_case['expected_concerns'] == 0:
            value_match = len(concerns) == 0
        elif structure_match and len(concerns) == test_case['expected_concerns']:
            # Create a mapping of actual concerns for flexible matching
            actual_concerns = {}
            for concern in concerns:
                field = concern['field']
                source_value = concern['sourceValue']
                pattern = concern['detectedPattern']
                
                key = f"{field}:{source_value}"
                actual_concerns[key] = {
                    'base': pattern['base'],
                    'granularity': pattern['granularity']
                }
            
            # Check if all expected concerns are present with correct values
            value_match = True
            for i in range(len(test_case['expected_fields'])):
                expected_key = f"{test_case['expected_fields'][i]}:{test_case['expected_source_values'][i]}"
                
                if expected_key not in actual_concerns:
                    value_match = False
                    break
                
                actual = actual_concerns[expected_key]
                if (actual['base'] != test_case['expected_bases'][i] or
                    actual['granularity'] != test_case['expected_granularities'][i]):
                    value_match = False
                    break
        else:
            value_match = False
    
    # Generate detailed output (similar to whitespace detection)
    status = "✅ PASS" if count_match and structure_match and value_match else "❌ FAIL"
    show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
    
    if show_details:
        print(f"{status} - Test: {test_case['description']}")
        print(f"Checks Performed: {len(concerns)} findings | structure confirmation | value confirmation")
        
        # Create a mock affected entry for display purposes
        test_entry_display = f"Table Index {table_index} entry"
        print(f"CVE Affected Entry: {test_entry_display}")
        
        # Expected data format
        if test_case['expected_concerns'] == 0:
            expected_format = "No version granularity issues should be detected"
        elif test_case['expected_concerns'] == 1:
            expected_format = f"field: '{test_case['expected_fields'][0]}', sourceValue: '{test_case['expected_source_values'][0]}', detectedPattern: {{base: {test_case['expected_bases'][0]}, granularity: {test_case['expected_granularities'][0]}}}"
        else:
            expected_parts = []
            for i in range(len(test_case['expected_fields'])):
                expected_parts.append(f"({test_case['expected_fields'][i]}, {test_case['expected_source_values'][i]}, base: {test_case['expected_bases'][i]}, granularity: {test_case['expected_granularities'][i]})")
            expected_format = f"concerns: {', '.join(expected_parts)}"
        
        print(f"Expected Data: {test_case['expected_concerns']} concerns | {expected_format}")
        
        # Found data format
        if concerns:
            if len(concerns) == 1:
                concern = concerns[0]
                pattern = concern['detectedPattern']
                found_format = f"field: '{concern['field']}', sourceValue: '{concern['sourceValue']}', detectedPattern: {{base: {pattern['base']}, granularity: {pattern['granularity']}}}"
            else:
                found_parts = []
                for concern in concerns:
                    pattern = concern['detectedPattern']
                    found_parts.append(f"({concern['field']}, {concern['sourceValue']}, base: {pattern['base']}, granularity: {pattern['granularity']})")
                found_format = f"concerns: {', '.join(found_parts)}"
            print(f"Found: {len(concerns)} concerns | {found_format}")
        else:
            print(f"Found: {len(concerns)} concerns | No concerns found")
        
        # Detailed validation results
        if count_match:
            print(f"✅ COUNT: {len(concerns)} concerns - (matches expected)")
        else:
            print(f"❌ COUNT: {len(concerns)} concerns - (expected {test_case['expected_concerns']})")
        
        if structure_match:
            print(f"✅ STRUCTURE: field/sourceValue/detectedPattern.base/granularity - (matches expected)")
        else:
            print(f"❌ STRUCTURE: Missing or invalid structure - (expected field/sourceValue/detectedPattern.base/granularity)")
        
        if value_match:
            print(f"✅ VALUES: All values match expected - (matches expected)")
        else:
            print(f"❌ VALUES: Value validation failed - (values do not match expected)")
        
        print()
    
    return count_match and structure_match and value_match

def test_version_granularity_detection():
    """Test version granularity detection functionality"""
    # Only show detailed output if not running under unified test runner
    show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
    
    if show_details:
        print("================================================================================")
        print("VERSION GRANULARITY DETECTION TEST SUITE")
        print("================================================================================")
    
    # Run test and get report
    report_data = run_test_and_get_report()
    if not report_data:
        return False
    
    # Run test cases
    test_cases = get_test_cases()
    passed = 0
    total = len(test_cases)
    
    for test_case in test_cases:
        if validate_test_case(test_case, report_data):
            passed += 1
    
    # Summary matching run_all_tests.py format
    success = passed == total
    
    # Test breakdown (only show if not running under unified test runner)
    if not os.environ.get('UNIFIED_TEST_RUNNER'):
        positive_tests = len([tc for tc in test_cases if tc['expected_concerns'] > 0])
        negative_tests = len([tc for tc in test_cases if tc['expected_concerns'] == 0])
        
        if success:
            print(f"PASS SDC Version Granularity Detection (test duration) ({passed}/{total} tests)")
            print(f"   {passed}/{total} tests passed")
            print(f"   Test breakdown: {positive_tests} positive cases, {negative_tests} negative cases")
        else:
            print(f"FAIL SDC Version Granularity Detection (test duration) ({passed}/{total} tests)")
            print(f"   {passed}/{total} tests passed")
            print(f"   Test breakdown: {positive_tests} positive cases, {negative_tests} negative cases")
        
        print("================================================================================")
    
    # Output standardized test results for run_all_tests.py
    print(f'TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE="SDC Version Granularity Detection"')
    
    return success

if __name__ == "__main__":
    success = test_version_granularity_detection()
    sys.exit(0 if success else 1)
