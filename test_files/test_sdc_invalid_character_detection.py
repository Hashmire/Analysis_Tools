#!/usr/bin/env python3
"""

Tests invalid character data detection by running test file and checking sourceDataConcernReport.json
Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Usage:
    python test_files/test_sdc_invalid_character_detection.py
"""

import sys
import os
import sys
import os
import json
import subprocess
from pathlib import Path

# Add src path for analysis_tool imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from analysis_tool.storage.run_organization import find_latest_test_run_report

# Path to the invalid character detection test file

TEST_FILE = os.path.join(os.path.dirname(__file__), "testInvalidCharacterDetection.json")

def run_test_and_get_report():
    """Run the test file and extract the sourceDataConcernReport.json"""
    try:
        # Run the tool using the standard command line interface
        cmd = [sys.executable, "-m", "src.analysis_tool.core.analysis_tool", "--test-file", TEST_FILE, "--no-cache", "--sdc-report", "true"]
        
        # Check if running under unified test runner to control browser behavior
        if os.environ.get('UNIFIED_TEST_RUNNER'):
            # Add --no-browser when running under unified test runner
            cmd.append("--no-browser")
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path(__file__).parent.parent)
        
        if result.returncode != 0:
            print(f"[ERROR] Tool execution failed with return code {result.returncode}")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return None
            
        # Find the most recent run directory
        # Use helper function to find report in both standard and consolidated environments
        return find_latest_test_run_report("sourceDataConcernReport.json")
            
    except Exception as e:
        print(f"[ERROR] Test execution failed: {e}")
        return None

def get_test_cases():
    """Define test cases with expected results based on testInvalidCharacterDetection.json"""
    return [
        {
            "description": "No invalid characters detected: Vendor field with null character (not detected by system)",
            "table_index": 0,
            "expected_concerns": 0
        },
        {
            "description": "No invalid characters detected: Product field with SOH character (not detected by system)",
            "table_index": 1,
            "expected_concerns": 0
        },
        {
            "description": "No invalid characters detected: PackageName field with STX character (not detected by system)",
            "table_index": 2,
            "expected_concerns": 0
        },
        {
            "description": "No invalid characters detected: Platform array with ETX and EOT characters (not detected by system)",
            "table_index": 3,
            "expected_concerns": 0
        },
        {
            "description": "Invalid character: Version field with ENQ character (\\u0005)",
            "table_index": 4,
            "expected_concerns": 1,
            "expected_field": "version",
            "expected_source_value": "1.0.0\u0005",
            "expected_detected_value": "\u0005"
        },
        {
            "description": "Invalid character: lessThan field with ACK character (\\u0006)",
            "table_index": 5,
            "expected_concerns": 1,
            "expected_field": "lessThan",
            "expected_source_value": "2.0.0\u0006",
            "expected_detected_value": "\u0006"
        },
        {
            "description": "Invalid character: lessThanOrEqual field with BEL character (\\u0007)",
            "table_index": 6,
            "expected_concerns": 1,
            "expected_field": "lessThanOrEqual",
            "expected_source_value": "3.0.0\u0007",
            "expected_detected_value": "\u0007"
        },
        {
            "description": "Invalid characters: changes[].at fields with BS and HT characters",
            "table_index": 7,
            "expected_concerns": 2,
            "expected_fields": ["changes[0].at", "changes[1].at"],
            "expected_source_values": ["4.0.0\u0008", "5.0.0\u0009"],
            "expected_detected_values": ["\u0008", "\u0009"]
        },
        {
            "description": "No invalid characters detected: Multiple platform array with LF, VT, FF characters (not detected by system)",
            "table_index": 8,
            "expected_concerns": 0
        },
        {
            "description": "Control test: No invalid characters (should have no concerns)",
            "table_index": 9,
            "expected_concerns": 0
        },
        {
            "description": "Invalid characters: Multiple version fields with CR, SO, SI characters",
            "table_index": 10,
            "expected_concerns": 3,
            "expected_fields": ["version", "version", "lessThan"],
            "expected_source_values": ["1.0.0\u000D", "2.0.0\u000E", "3.0.0\u000F"],
            "expected_detected_values": ["\u000D", "\u000E", "\u000F"]
        },
        {
            "description": "Invalid characters: Multiple changes array with DLE, DC1, DC2 characters",
            "table_index": 11,
            "expected_concerns": 3,
            "expected_fields": ["changes[0].at", "changes[1].at", "changes[2].at"],
            "expected_source_values": ["6.0.0\u0010", "7.0.0\u0011", "8.0.0\u0012"],
            "expected_detected_values": ["\u0010", "\u0011", "\u0012"]
        },
        {
            "description": "Comprehensive invalid characters: Only version fields detected (others not detected by system)",
            "table_index": 12,
            "expected_concerns": 5,
            "expected_fields": ["version", "lessThan", "lessThanOrEqual", "changes[0].at", "changes[1].at"],
            "expected_source_values": ["1.0.0\u0018", "2.0.0\u0019", "3.0.0\u001A", "4.0.0\u001B", "5.0.0\u001C"],
            "expected_detected_values": ["\u0018", "\u0019", "\u001A", "\u001B", "\u001C"]
        },
        {
            "description": "Space character in version field (should be flagged by regex)",
            "table_index": 13,
            "expected_concerns": 1,
            "expected_field": "version",
            "expected_source_value": "1.0 beta",
            "expected_detected_value": " "
        },
        {
            "description": "Forward slash in version field (should be flagged by regex)",
            "table_index": 14,
            "expected_concerns": 1,
            "expected_field": "version",
            "expected_source_value": "2.0/final",
            "expected_detected_value": "/"
        },
        {
            "description": "Square brackets in lessThan field (should be flagged by regex)",
            "table_index": 15,
            "expected_concerns": 2,
            "expected_fields": ["lessThan", "lessThan"],
            "expected_source_values": ["3.0[stable]", "3.0[stable]"],
            "expected_detected_values": ["[", "]"]
        },
        {
            "description": "Comma in lessThanOrEqual field (should be flagged by regex)",
            "table_index": 16,
            "expected_concerns": 1,
            "expected_field": "lessThanOrEqual",
            "expected_source_value": "4.0,final",
            "expected_detected_value": ","
        },
        {
            "description": "Multiple invalid characters in changes array (braces, at-sign)",
            "table_index": 17,
            "expected_concerns": 3,
            "expected_fields": ["changes[0].at", "changes[0].at", "changes[1].at"],
            "expected_source_values": ["5.0{patch}", "5.0{patch}", "6.0@release"],
            "expected_detected_values": ["{", "}", "@"]
        },
        {
            "description": "Hash character in version field (should be flagged by regex)",
            "table_index": 18,
            "expected_concerns": 1,
            "expected_field": "version",
            "expected_source_value": "1.0#dev",
            "expected_detected_value": "#"
        },
        {
            "description": "Dollar sign in version field (should be flagged by regex)",
            "table_index": 19,
            "expected_concerns": 1,
            "expected_field": "version",
            "expected_source_value": "2.0$build",
            "expected_detected_value": "$"
        },
        {
            "description": "Percent sign in version field (should be flagged by regex)",
            "table_index": 20,
            "expected_concerns": 1,
            "expected_field": "version",
            "expected_source_value": "3.0%stable",
            "expected_detected_value": "%"
        },
        {
            "description": "Caret character in version field (should be flagged by regex)",
            "table_index": 21,
            "expected_concerns": 1,
            "expected_field": "version",
            "expected_source_value": "4.0^final",
            "expected_detected_value": "^"
        },
        {
            "description": "Ampersand in version field (should be flagged by regex)",
            "table_index": 22,
            "expected_concerns": 1,
            "expected_field": "version",
            "expected_source_value": "5.0&patch",
            "expected_detected_value": "&"
        },
        {
            "description": "Equals sign in version field (detected as mathematical comparator, not invalid character)",
            "table_index": 23,
            "expected_concerns": 0,
            "rationale": "Skip logic prevents '=' from being flagged as invalid character when mathematical comparator detection is active"
        },
        {
            "description": "Valid complex version with all allowed characters (should have no concerns)",
            "table_index": 24,
            "expected_concerns": 0
        }
    ]

def validate_test_case(report_data, test_case):
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
        # Extract invalid character concerns
        concerns = []
        for concern_detail in platform_entry.get('concerns_detail', []):
            if concern_detail.get('concern_type') == 'invalidCharacters':
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
                        structure_match = 'detectedValue' in pattern
                else:
                    structure_match = False
            else:
                # Multiple concerns case - need to match each concern to expected
                if len(concerns) == test_case['expected_concerns']:
                    # Validate structure first
                    for concern in concerns:
                        if not all(key in concern for key in ['field', 'sourceValue', 'detectedPattern']):
                            structure_match = False
                            break
                        pattern = concern['detectedPattern']
                        if 'detectedValue' not in pattern:
                            structure_match = False
                            break
                    
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
                    pattern['detectedValue'] == test_case['expected_detected_value']
                )
            else:
                # Multiple concerns case - need to match each concern to expected
                # Create list of actual values for matching
                actual_values = []
                for concern in concerns:
                    pattern = concern['detectedPattern']
                    actual_values.append({
                        'field': concern['field'],
                        'sourceValue': concern['sourceValue'],
                        'detectedValue': pattern['detectedValue']
                    })
                
                # Try to match each expected value to an actual value
                expected_values = []
                for i in range(len(test_case['expected_fields'])):
                    expected_values.append({
                        'field': test_case['expected_fields'][i],
                        'sourceValue': test_case['expected_source_values'][i],
                        'detectedValue': test_case['expected_detected_values'][i]
                    })
                
                # Check if all expected values can be matched
                value_match = True
                matched_actuals = set()
                for expected in expected_values:
                    found_match = False
                    for j, actual in enumerate(actual_values):
                        if j not in matched_actuals and actual == expected:
                            matched_actuals.add(j)
                            found_match = True
                            break
                    if not found_match:
                        value_match = False
                        break
        else:
            value_match = False
    
    # Generate detailed output (similar to placeholder and whitespace detection)
    status = "✅ PASS" if count_match and structure_match and value_match else "❌ FAIL"
    show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
    
    if show_details:
        print(f"{status} - Test: {test_case['description']}")
        print(f"Checks Performed: {len(concerns)} findings | structure confirmation | value confirmation")
        
        # Create a mock affected entry for display purposes (since we don't have direct access to it)
        test_entry_display = f"Table Index {table_index} entry"
        print(f"CVE Affected Entry: {test_entry_display}")
        
        # Expected data format
        if test_case['expected_concerns'] == 0:
            expected_format = "No invalid characters should be detected"
        elif test_case['expected_concerns'] == 1:
            # Show escaped representation for clarity
            detected_char = repr(test_case['expected_detected_value'])
            expected_format = f"field: '{test_case['expected_field']}', sourceValue: '{test_case['expected_source_value']}', detectedPattern: {{detectedValue: {detected_char}}}"
        else:
            expected_parts = []
            for i in range(len(test_case['expected_fields'])):
                detected_char = repr(test_case['expected_detected_values'][i])
                expected_parts.append(f"({test_case['expected_fields'][i]}, {test_case['expected_source_values'][i]}, {detected_char})")
            expected_format = f"concerns: {', '.join(expected_parts)}"
        
        print(f"Expected Data: {test_case['expected_concerns']} concerns | {expected_format}")
        
        # Found data format
        if concerns:
            if len(concerns) == 1:
                concern = concerns[0]
                pattern = concern['detectedPattern']
                detected_char = repr(pattern['detectedValue'])
                found_format = f"field: '{concern['field']}', sourceValue: '{concern['sourceValue']}', detectedPattern: {{detectedValue: {detected_char}}}"
            else:
                found_parts = []
                for concern in concerns:
                    pattern = concern['detectedPattern']
                    detected_char = repr(pattern['detectedValue'])
                    found_parts.append(f"({concern['field']}, {concern['sourceValue']}, {detected_char})")
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
            print(f"✅ STRUCTURE: field/sourceValue/detectedPattern.detectedValue - (matches expected)")
        else:
            print(f"❌ STRUCTURE: Missing or invalid structure - (expected field/sourceValue/detectedPattern.detectedValue)")
        
        if value_match:
            print(f"✅ VALUES: All values match expected - (matches expected)")
        else:
            print(f"❌ VALUES: Value validation failed - (values do not match expected)")
        
        print()
    
    return count_match and structure_match and value_match

def test_invalid_character_detection():
    """Test invalid character detection functionality"""
    # Only show detailed output if not running under unified test runner
    show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
    
    if show_details:
        print("================================================================================")
        print("INVALID CHARACTER DETECTION TEST SUITE")
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
        if validate_test_case(report_data, test_case):
            passed += 1
        elif show_details:
            print(f"[FAIL] {test_case['description']}")
    
    # Summary matching run_all_tests.py format
    success = passed == total
    
    # Test breakdown (only show if not running under unified test runner)
    if not os.environ.get('UNIFIED_TEST_RUNNER'):
        positive_tests = len([tc for tc in test_cases if tc['expected_concerns'] > 0])
        negative_tests = len([tc for tc in test_cases if tc['expected_concerns'] == 0])
        
        if success:
            print(f"PASS SDC Invalid Character Detection (test duration) ({passed}/{total} tests)")
            print(f"   {passed}/{total} tests passed")
            print(f"   Test breakdown: {positive_tests} positive cases, {negative_tests} negative cases")
        else:
            print(f"FAIL SDC Invalid Character Detection (test duration) ({passed}/{total} tests)")
            print(f"   {passed}/{total} tests passed")
            print(f"   Test breakdown: {positive_tests} positive cases, {negative_tests} negative cases")
        
        print("================================================================================")
    
    # Output standardized test results for run_all_tests.py
    print(f'TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE="SDC Invalid Character Detection"')
    
    return success

if __name__ == "__main__":
    success = test_invalid_character_detection()
    sys.exit(0 if success else 1)