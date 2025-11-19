#!/usr/bin/env python3
"""
SDC Comparator Detection Test Suite

Tests mathematical comparator detection by running test file and checking sourceDataConcernReport.json
Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Usage:
    python test_suites/source_data_concerns/test_sdc_mathematical_comparator_detection.py
"""

import sys
import os
import json
import subprocess
from pathlib import Path

# Add src path for analysis_tool imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
from analysis_tool.storage.run_organization import find_latest_test_run_report

# Path to the mathematical comparator detection test file

TEST_FILE = os.path.join(os.path.dirname(__file__), "testMathematicalComparatorDetection.json")

def run_test_and_get_report():
    """Run the test file and extract the sourceDataConcernReport.json"""
    try:
        # Run the tool using the standard command line interface
        cmd = [sys.executable, "-m", "src.analysis_tool.core.analysis_tool", "--test-file", TEST_FILE, "--no-cache", "--sdc-report", "true"]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path(__file__).parent.parent.parent)
        
        if result.returncode != 0:
            print(f"❌ Tool execution failed with return code {result.returncode}")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return None
            
        # Use helper function to find report in both standard and consolidated environments
        return find_latest_test_run_report("sourceDataConcernReport.json")
        
    except Exception as e:
        print(f"❌ Error running test: {e}")
        return None

def extract_concerns_for_table(report_data, table_index):
    """Extract concerns for a specific table index from the report data"""
    concerns = []
    
    if not report_data or 'cve_data' not in report_data:
        return concerns
        
    # Navigate through the new report structure
    cve_data = report_data['cve_data']
    if not cve_data or len(cve_data) == 0:
        return concerns
        
    # Get first CVE entry (test files typically have one CVE)
    cve_entry = cve_data[0]
    if 'platform_entries' not in cve_entry or table_index >= len(cve_entry['platform_entries']):
        return concerns
        
    platform_entry = cve_entry['platform_entries'][table_index]
    if 'concerns_detail' not in platform_entry:
        return concerns
        
    # Extract mathematical comparator concerns
    for concern_detail in platform_entry['concerns_detail']:
        if concern_detail.get('concern_type') == 'mathematicalComparators':
            if 'concerns' in concern_detail:
                concerns.extend(concern_detail['concerns'])
                
    return concerns

def get_test_cases():
    """Define test cases with expected results based on testComparatorDetection.json"""
    return [
        {
            "description": "Vendor field mathematical comparator detection (foo>=bar)",
            "table_index": 0,
            "affected_entry": {"vendor": "foo>=bar", "product": "Test Product", "versions": [{"version": "1.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "vendor",
            "expected_source_value": "foo>=bar",
            "expected_detected_value": ">, =, >="
        },
        {
            "description": "Product field mathematical comparator detection (baz<=qux)",
            "table_index": 1,
            "affected_entry": {"vendor": "Test Vendor", "product": "baz<=qux", "versions": [{"version": "2.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "product",
            "expected_source_value": "baz<=qux",
            "expected_detected_value": "<, =, <="
        },
        {
            "description": "PackageName field mathematical comparator detection (lib=core)",
            "table_index": 2,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "packageName": "lib=core", "versions": [{"version": "3.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "packageName",
            "expected_source_value": "lib=core",
            "expected_detected_value": "="
        },
        {
            "description": "Platform array mathematical comparator detection (>=linux)",
            "table_index": 3,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "platforms": [">=linux"], "versions": [{"version": "4.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "platforms[0]",
            "expected_source_value": ">=linux",
            "expected_detected_value": ">, =, >="
        },
        {
            "description": "Version field mathematical comparator detection (<1.2.3)",
            "table_index": 4,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "versions": [{"version": "<1.2.3", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "version",
            "expected_source_value": "<1.2.3",
            "expected_detected_value": "<"
        },
        {
            "description": "LessThan field mathematical comparator detection (>=6.0.0)",
            "table_index": 5,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "versions": [{"version": "5.0.0", "lessThan": ">=6.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "lessThan",
            "expected_source_value": ">=6.0.0",
            "expected_detected_value": ">, =, >="
        },
        {
            "description": "LessThanOrEqual field mathematical comparator detection (!=8.0.0)",
            "table_index": 6,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "versions": [{"version": "7.0.0", "lessThanOrEqual": "!=8.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "lessThanOrEqual",
            "expected_source_value": "!=8.0.0",
            "expected_detected_value": "=, !="
        },
        {
            "description": "Changes array mathematical comparator detection (=10.0.0)",
            "table_index": 7,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "versions": [{"version": "9.0.0", "changes": [{"at": "=10.0.0", "status": "unaffected"}]}]},
            "expected_concerns": 1,
            "expected_field": "changes[0].at",
            "expected_source_value": "=10.0.0",
            "expected_detected_value": "="
        },
        {
            "description": "Platform array mathematical comparator detection (<macos)",
            "table_index": 8,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "platforms": ["win32", "<macos"], "versions": [{"version": "11.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "platforms[1]",
            "expected_source_value": "<macos",
            "expected_detected_value": "<"
        },
        {
            "description": "Multiple version array with comparators",
            "table_index": 9,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "versions": [{"version": ">=1.0.0", "status": "affected"}, {"version": "<=2.0.0", "status": "affected"}, {"version": "3.0.0", "lessThan": "!=4.0.0", "status": "affected"}]},
            "expected_concerns": 3,
            "expected_fields": ["version", "version", "lessThan"],
            "expected_source_values": [">=1.0.0", "<=2.0.0", "!=4.0.0"],
            "expected_detected_values": [">, =, >=", "<, =, <=", "=, !="]
        },
        {
            "description": "Multiple changes array with comparators",
            "table_index": 10,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "versions": [{"version": "5.0.0", "changes": [{"at": ">6.0.0", "status": "unaffected"}, {"at": "<=7.0.0", "status": "unaffected"}, {"at": "!=8.0.0", "status": "unaffected"}]}]},
            "expected_concerns": 3,
            "expected_fields": ["changes[0].at", "changes[1].at", "changes[2].at"],
            "expected_source_values": [">6.0.0", "<=7.0.0", "!=8.0.0"],
            "expected_detected_values": [">", "<, =, <=", "=, !="]
        },
        {
            "description": "Comprehensive: multiple comparators in all nested arrays",
            "table_index": 11,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "packageName": "lib=core", "platforms": ["<win32", ">=linux"], "versions": [{"version": "<1.0.0", "lessThan": ">2.0.0", "lessThanOrEqual": "=<3.0.0", "changes": [{"at": "!=4.0.0", "status": "unaffected"}, {"at": "=5.0.0", "status": "unaffected"}]}, {"version": ">=6.0.0", "lessThan": "<=7.0.0", "lessThanOrEqual": "=>8.0.0", "changes": [{"at": "<9.0.0", "status": "unaffected"}, {"at": ">=10.0.0", "status": "unaffected"}]}]},
            "expected_concerns": 13,
            "expected_fields": ["packageName", "platforms[0]", "platforms[1]", "version", "lessThan", "lessThanOrEqual", "changes[0].at", "changes[1].at", "version", "lessThan", "lessThanOrEqual", "changes[0].at", "changes[1].at"],
            "expected_source_values": ["lib=core", "<win32", ">=linux", "<1.0.0", ">2.0.0", "=<3.0.0", "!=4.0.0", "=5.0.0", ">=6.0.0", "<=7.0.0", "=>8.0.0", "<9.0.0", ">=10.0.0"],
            "expected_detected_values": ["=", "<", ">, =, >=", "<", ">", "<, =, =<", "=, !=", "=", ">, =, >=", "<, =, <=", ">, =, =>", "<", ">, =, >="]
        }
    ]

def validate_test_case(test_case, report_data):
    """Validate a single test case against the report data"""
    table_index = test_case['table_index']
    concerns = extract_concerns_for_table(report_data, table_index)
    
    # Debug output (removed for cleaner testing)
    # show_details = True  # Force debug for now 
    # if show_details:
    #     print(f"\n--- Testing table index {table_index}: {test_case['description']} ---")
    #     print(f"Expected concerns: {test_case['expected_concerns']}")
    #     print(f"Actual concerns found: {len(concerns)}")
    #     for i, concern in enumerate(concerns):
    #         print(f"  Concern {i}: {concern}")
    #     if 'expected_detected_values' in test_case:
    #         print(f"Expected detected values: {test_case['expected_detected_values']}")
    
    # Check count
    count_match = len(concerns) == test_case['expected_concerns']
    
    # Check structure for all concerns
    if test_case['expected_concerns'] == 0:
        # If we expect 0 concerns, structure passes regardless of what we found
        structure_match = True
    elif len(concerns) == 0:
        # If we expect concerns but found none, structure validation fails
        structure_match = False
    else:
        # We have concerns to validate structure
        structure_match = True
        for concern in concerns:
            if not (
                'field' in concern and
                'sourceValue' in concern and
                'detectedPattern' in concern and
                isinstance(concern['detectedPattern'], dict) and
                'detectedValue' in concern['detectedPattern']
            ):
                structure_match = False
                break
    
    # Check values
    value_match = False
    if test_case['expected_concerns'] == 0:
        # Negative test case - no concerns should be found
        value_match = len(concerns) == 0
    elif structure_match and concerns:
        if test_case['expected_concerns'] == 1:
            # Single concern validation
            concern = concerns[0]
            value_match = (
                concern['field'] == test_case['expected_field'] and
                concern['sourceValue'] == test_case['expected_source_value'] and
                concern['detectedPattern']['detectedValue'] == test_case['expected_detected_value']
            )
        else:
            # Multiple concern validation - check if all expected concerns are present
            expected_fields = test_case['expected_fields']
            expected_source_values = test_case['expected_source_values']
            expected_detected_values = test_case['expected_detected_values']
            
            # Create sets for comparison (order may vary)
            actual_concerns = set()
            expected_concern_set = set()
            
            for concern in concerns:
                actual_concerns.add((concern['field'], concern['sourceValue'], concern['detectedPattern']['detectedValue']))
            
            for i in range(len(expected_fields)):
                expected_concern_set.add((expected_fields[i], expected_source_values[i], expected_detected_values[i]))
            
            value_match = actual_concerns == expected_concern_set
    
    # Generate output
    status = "✅ PASS" if count_match and structure_match and value_match else "❌ FAIL"
    show_details = os.environ.get('UNIFIED_TEST_RUNNER') != '1'
    
    if show_details:
        print(f"{status} - Test: {test_case['description']}")
        print(f"Checks Performed: {len(concerns)} findings | structure confirmation | value confirmation")
        print(f"CVE Affected Entry: {json.dumps(test_case['affected_entry'], ensure_ascii=False)}")
    
        # Expected data format
        if test_case['expected_concerns'] == 0:
            expected_format = "No comparators should be detected"
        elif test_case['expected_concerns'] == 1:
            expected_format = f"field: '{test_case['expected_field']}', sourceValue: '{test_case['expected_source_value']}', detectedPattern: {{detectedValue: '{test_case['expected_detected_value']}'}}"
        else:
            expected_parts = []
            for i in range(len(test_case['expected_fields'])):
                expected_parts.append(f"({test_case['expected_fields'][i]}, {test_case['expected_source_values'][i]}, {test_case['expected_detected_values'][i]})")
            expected_format = f"concerns: {', '.join(expected_parts)}"
        
        print(f"Expected Data: {test_case['expected_concerns']} concerns | {expected_format}")
        
        # Found data format
        if concerns:
            if len(concerns) == 1:
                concern = concerns[0]
                found_format = f"field: '{concern['field']}', sourceValue: '{concern['sourceValue']}', detectedPattern: {{detectedValue: '{concern['detectedPattern']['detectedValue']}'}}"
            else:
                found_parts = []
                for concern in concerns:
                    found_parts.append(f"({concern['field']}, {concern['sourceValue']}, {concern['detectedPattern']['detectedValue']})")
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



def test_comparator_detection():
    """Test mathematical comparator detection functionality"""
    # Only show detailed output if not running under unified test runner
    show_details = os.environ.get('UNIFIED_TEST_RUNNER') != '1'
    
    if show_details:
        print("================================================================================")
        print("MATHEMATICAL COMPARATOR DETECTION TEST SUITE")
        print("================================================================================")
    
    # Run test and get report
    report_data = run_test_and_get_report()
    if not report_data:
        return False
    
    # Skip debug output for cleaner test results
    # Debug can be enabled if needed for troubleshooting
    
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
    if os.environ.get('UNIFIED_TEST_RUNNER') != '1':
        positive_tests = len([tc for tc in test_cases if tc['expected_concerns'] > 0])
        negative_tests = len([tc for tc in test_cases if tc['expected_concerns'] == 0])
        
        if success:
            print(f"PASS SDC Comparator Detection (test duration) ({passed}/{total} tests)")
            print(f"   {passed}/{total} tests passed")
            print(f"   Test breakdown: {positive_tests} positive cases, {negative_tests} negative cases")
        else:
            print(f"FAIL SDC Comparator Detection (test duration) ({passed}/{total} tests)")
            print(f"   {passed}/{total} tests passed")
            print(f"   Test breakdown: {positive_tests} positive cases, {negative_tests} negative cases")
        
        print("================================================================================")
    
    # Output standardized test results for run_all_tests.py
    print(f'TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE="SDC Comparator Detection"')
    
    return success

def main():
    """Main function to run the test suite"""
    return test_comparator_detection()

if __name__ == "__main__":
    main()
