#!/usr/bin/env python3
"""
SDC Whitespace Detection Test Suite

Tests whitespace data detection by running test file and checking sourceDataConcernReport.json
Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Usage:
    python test_suites/test_sdc_whitespace_detection.py
"""

import sys
import os
import json
import subprocess
from pathlib import Path

# Add src path for analysis_tool imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
from analysis_tool.storage.run_organization import find_latest_test_run_report

# Path to the whitespace detection test file

TEST_FILE = os.path.join(os.path.dirname(__file__), "testWhitespaceDetection.json")

def run_test_and_get_report():
    """Run the test file and extract the sourceDataConcernReport.json"""
    try:
        # Run the tool using the standard command line interface
        cmd = [sys.executable, "-m", "src.analysis_tool.core.analysis_tool", "--test-file", TEST_FILE, "--no-cache", "--sdc-report", "true"]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path(__file__).parent.parent.parent)
        
        if result.returncode != 0:
            print(f"[FAIL] Tool execution failed with return code {result.returncode}")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return None
            
        # Use helper function to find report in both standard and consolidated environments
        return find_latest_test_run_report("sourceDataConcernReport.json")
            
    except Exception as e:
        print(f"[FAIL] Test execution failed: {e}")
        return None

def get_test_cases():
    """Define test cases with expected results based on testWhitespaceDetection.json"""
    return [
        {
            "description": "Leading whitespace: Vendor field with leading space",
            "table_index": 0,
            "expected_concerns": 1,
            "expected_field": "vendor",
            "expected_source_value": " TestVendor",
            "expected_whitespace_types": ["leading"],
            "expected_replaced_text": "!TestVendor"
        },
        {
            "description": "Trailing whitespace: Product field with trailing space",
            "table_index": 1,
            "expected_concerns": 1,
            "expected_field": "product",
            "expected_source_value": "TestProduct ",
            "expected_whitespace_types": ["trailing"],
            "expected_replaced_text": "TestProduct!"
        },
        {
            "description": "Leading/Trailing whitespace: PackageName with both",
            "table_index": 2,
            "expected_concerns": 1,
            "expected_field": "packageName",
            "expected_source_value": " test-package ",
            "expected_whitespace_types": ["leading", "trailing"],
            "expected_replaced_text": "!test-package!"
        },
        {
            "description": "Excessive whitespace: Platforms with multiple spaces",
            "table_index": 3,
            "expected_concerns": 2,
            "expected_fields": ["platforms[0]", "platforms[1]"],
            "expected_source_values": ["  linux  ", "windows  "],
            "expected_whitespace_types": [["leading", "trailing", "excessive"], ["trailing", "excessive"]],
            "expected_replaced_texts": ["!!linux!!", "windows!!"]
        },
        {
            "description": "Leading whitespace: Version field",
            "table_index": 4,
            "expected_concerns": 1,
            "expected_field": "versions[0].version",
            "expected_source_value": " 1.0.0",
            "expected_whitespace_types": ["leading"],
            "expected_replaced_text": "!1.0.0"
        },
        {
            "description": "Trailing whitespace: lessThan field",
            "table_index": 5,
            "expected_concerns": 1,
            "expected_field": "versions[0].lessThan",
            "expected_source_value": "2.0.0 ",
            "expected_whitespace_types": ["trailing"],
            "expected_replaced_text": "2.0.0!"
        },
        {
            "description": "Excessive whitespace: lessThanOrEqual field",
            "table_index": 6,
            "expected_concerns": 1,
            "expected_field": "versions[0].lessThanOrEqual",
            "expected_source_value": "3.0.0  ",
            "expected_whitespace_types": ["trailing", "excessive"],
            "expected_replaced_text": "3.0.0!!"
        },
        {
            "description": "Multiple issues: changes[].at fields",
            "table_index": 7,
            "expected_concerns": 2,
            "expected_fields": ["versions[0].changes[0].at", "versions[0].changes[1].at"],
            "expected_source_values": [" 4.0.0", "5.0.0 "],
            "expected_whitespace_types": [["leading"], ["trailing"]],
            "expected_replaced_texts": ["!4.0.0", "5.0.0!"]
        },
        {
            "description": "Array issues: Multiple platform whitespace issues",
            "table_index": 8,
            "expected_concerns": 3,
            "expected_fields": ["platforms[0]", "platforms[1]", "platforms[2]"],
            "expected_source_values": [" win32", "macos ", "  linux  "],
            "expected_whitespace_types": [["leading"], ["trailing"], ["leading", "trailing", "excessive"]],
            "expected_replaced_texts": ["!win32", "macos!", "!!linux!!"]
        },
        {
            "description": "Control test: No whitespace issues (should have no concerns)",
            "table_index": 9,
            "expected_concerns": 0
        },
        {
            "description": "Multiple version fields: Whitespace across version array",
            "table_index": 10,
            "expected_concerns": 3,
            "expected_fields": ["versions[0].version", "versions[1].version", "versions[2].lessThan"],
            "expected_source_values": [" 1.0.0", "2.0.0 ", "  3.0.0"],
            "expected_whitespace_types": [["leading"], ["trailing"], ["leading", "excessive"]],
            "expected_replaced_texts": ["!1.0.0", "2.0.0!", "!!3.0.0"]
        },
        {
            "description": "Multiple changes array: Whitespace in changes[].at array",
            "table_index": 11,
            "expected_concerns": 3,
            "expected_fields": ["versions[0].changes[0].at", "versions[0].changes[1].at", "versions[0].changes[2].at"],
            "expected_source_values": [" 6.0.0", "7.0.0 ", "  8.0.0  "],
            "expected_whitespace_types": [["leading"], ["trailing"], ["leading", "trailing", "excessive"]],
            "expected_replaced_texts": ["!6.0.0", "7.0.0!", "!!8.0.0!!"]
        },
        {
            "description": "Comprehensive all fields: Whitespace across all supported fields",
            "table_index": 12,
            "expected_concerns": 10,
            "expected_fields": ["vendor", "product", "packageName", "platforms[0]", "platforms[1]", "versions[0].version", "versions[0].lessThan", "versions[0].lessThanOrEqual", "versions[0].changes[0].at", "versions[0].changes[1].at"],
            "expected_source_values": [" TestVendor", "TestProduct ", "  test-pkg  ", " win32", "macos ", " 1.0.0", "2.0.0 ", "  3.0.0  ", " 4.0.0", "5.0.0 "],
            "expected_whitespace_types": [["leading"], ["trailing"], ["leading", "trailing", "excessive"], ["leading"], ["trailing"], ["leading"], ["trailing"], ["leading", "trailing", "excessive"], ["leading"], ["trailing"]],
            "expected_replaced_texts": ["!TestVendor", "TestProduct!", "!!test-pkg!!", "!win32", "macos!", "!1.0.0", "2.0.0!", "!!3.0.0!!", "!4.0.0", "5.0.0!"]
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
        # Extract whitespace concerns
        concerns = []
        for concern_detail in platform_entry.get('concerns_detail', []):
            if concern_detail.get('concern_type') == 'whitespaceIssues':
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
            if test_case['expected_concerns'] == 1:
                # Single concern case
                if len(concerns) == 1:
                    concern = concerns[0]
                    structure_match = all(key in concern for key in ['field', 'sourceValue', 'detectedPattern'])
                    if structure_match:
                        pattern = concern['detectedPattern']
                        structure_match = 'whitespaceTypes' in pattern and 'replacedText' in pattern
                else:
                    structure_match = False
            else:
                # Multiple concerns case - need to match each concern to expected
                if len(concerns) == test_case['expected_concerns']:
                    # Create a mapping of actual concerns for flexible matching
                    actual_concerns = {}
                    for concern in concerns:
                        if not all(key in concern for key in ['field', 'sourceValue', 'detectedPattern']):
                            structure_match = False
                            break
                        pattern = concern['detectedPattern']
                        if 'whitespaceTypes' not in pattern or 'replacedText' not in pattern:
                            structure_match = False
                            break
                        
                        field = concern['field']
                        actual_concerns[field] = {
                            'sourceValue': concern['sourceValue'],
                            'whitespaceTypes': pattern['whitespaceTypes'],
                            'replacedText': pattern['replacedText']
                        }
                    
                else:
                    structure_match = False
        
        # Value validation
        if test_case['expected_concerns'] == 0:
            value_match = len(concerns) == 0
        elif structure_match and len(concerns) == test_case['expected_concerns']:
            if test_case['expected_concerns'] == 1:
                # Single concern case
                concern = concerns[0]
                pattern = concern['detectedPattern']
                value_match = (
                    concern['field'] == test_case['expected_field'] and
                    concern['sourceValue'] == test_case['expected_source_value'] and
                    pattern['whitespaceTypes'] == test_case['expected_whitespace_types'] and
                    pattern['replacedText'] == test_case['expected_replaced_text']
                )
            else:
                # Multiple concerns case - need to match each concern to expected
                actual_concerns = {}
                for concern in concerns:
                    field = concern['field']
                    pattern = concern['detectedPattern']
                    actual_concerns[field] = {
                        'sourceValue': concern['sourceValue'],
                        'whitespaceTypes': pattern['whitespaceTypes'],
                        'replacedText': pattern['replacedText']
                    }
                
                # Check if all expected fields are present with correct values
                value_match = True
                for i, expected_field in enumerate(test_case['expected_fields']):
                    if expected_field not in actual_concerns:
                        value_match = False
                        break
                    
                    actual = actual_concerns[expected_field]
                    if (actual['sourceValue'] != test_case['expected_source_values'][i] or
                        actual['whitespaceTypes'] != test_case['expected_whitespace_types'][i] or
                        actual['replacedText'] != test_case['expected_replaced_texts'][i]):
                        value_match = False
                        break
        else:
            value_match = False
    
    # Generate detailed output (similar to placeholder detection)
    status = "[PASS]" if count_match and structure_match and value_match else "[FAIL]"
    show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
    
    if show_details:
        print(f"{status} - Test: {test_case['description']}")
        print(f"Checks Performed: {len(concerns)} findings | structure confirmation | value confirmation")
        
        # Create a mock affected entry for display purposes (since we don't have direct access to it)
        test_entry_display = f"Table Index {table_index} entry"
        print(f"CVE Affected Entry: {test_entry_display}")
        
        # Expected data format
        if test_case['expected_concerns'] == 0:
            expected_format = "No whitespace issues should be detected"
        elif test_case['expected_concerns'] == 1:
            expected_format = f"field: '{test_case['expected_field']}', sourceValue: '{test_case['expected_source_value']}', detectedPattern: {{whitespaceTypes: {test_case['expected_whitespace_types']}, replacedText: '{test_case['expected_replaced_text']}'}}"
        else:
            expected_parts = []
            for i in range(len(test_case['expected_fields'])):
                expected_parts.append(f"({test_case['expected_fields'][i]}, {test_case['expected_source_values'][i]}, {test_case['expected_whitespace_types'][i]}, {test_case['expected_replaced_texts'][i]})")
            expected_format = f"concerns: {', '.join(expected_parts)}"
        
        print(f"Expected Data: {test_case['expected_concerns']} concerns | {expected_format}")
        
        # Found data format
        if concerns:
            if len(concerns) == 1:
                concern = concerns[0]
                pattern = concern['detectedPattern']
                found_format = f"field: '{concern['field']}', sourceValue: '{concern['sourceValue']}', detectedPattern: {{whitespaceTypes: {pattern['whitespaceTypes']}, replacedText: '{pattern['replacedText']}'}}"
            else:
                found_parts = []
                for concern in concerns:
                    pattern = concern['detectedPattern']
                    found_parts.append(f"({concern['field']}, {concern['sourceValue']}, {pattern['whitespaceTypes']}, {pattern['replacedText']})")
                found_format = f"concerns: {', '.join(found_parts)}"
            print(f"Found: {len(concerns)} concerns | {found_format}")
        else:
            print(f"Found: {len(concerns)} concerns | No concerns found")
        
        # Detailed validation results
        if count_match:
            print(f"[OK] COUNT: {len(concerns)} concerns - (matches expected)")
        else:
            print(f"[FAIL] COUNT: {len(concerns)} concerns - (expected {test_case['expected_concerns']})")
        
        if structure_match:
            print(f"[OK] STRUCTURE: field/sourceValue/detectedPattern.whitespaceTypes/replacedText - (matches expected)")
        else:
            print(f"[FAIL] STRUCTURE: Missing or invalid structure - (expected field/sourceValue/detectedPattern.whitespaceTypes/replacedText)")
        
        if value_match:
            print(f"[OK] VALUES: All values match expected - (matches expected)")
        else:
            print(f"[FAIL] VALUES: Value validation failed - (values do not match expected)")
        
        print()
    
    return count_match and structure_match and value_match

def test_whitespace_detection():
    """Test whitespace detection functionality"""
    # Only show detailed output if not running under unified test runner
    show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
    
    if show_details:
        print("================================================================================")
        print("WHITESPACE DETECTION TEST SUITE")
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
            print(f"PASS SDC Whitespace Detection (test duration) ({passed}/{total} tests)")
            print(f"   {passed}/{total} tests passed")
            print(f"   Test breakdown: {positive_tests} positive cases, {negative_tests} negative cases")
        else:
            print(f"FAIL SDC Whitespace Detection (test duration) ({passed}/{total} tests)")
            print(f"   {passed}/{total} tests passed")
            print(f"   Test breakdown: {positive_tests} positive cases, {negative_tests} negative cases")
        
        print("================================================================================")
    
    # Output standardized test results for run_all_tests.py
    print(f'TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE="SDC Whitespace Detection"')
    
    return success

if __name__ == "__main__":
    success = test_whitespace_detection()
    sys.exit(0 if success else 1)
