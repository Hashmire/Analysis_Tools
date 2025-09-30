#!/usr/bin/env python3
"""
SDC Placeholder Detection Test Suite

Tests placeholder data detection by running test file and checking sourceDataConcernReport.json
Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Usage:
    python test_files/test_sdc_placeholder_detection.py
"""

import sys
import os
import json
import subprocess
from pathlib import Path

# Add src path for analysis_tool imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from analysis_tool.storage.run_organization import find_latest_test_run_report

# Path to the placeholder detection test file

TEST_FILE = os.path.join(os.path.dirname(__file__), "testPlaceholderDetection.json")

def run_test_and_get_report():
    """Run the test file and extract the sourceDataConcernReport.json"""
    try:
        # Run the tool using the standard command line interface
        cmd = [sys.executable, "run_tools.py", "--test-file", TEST_FILE, "--no-cache"]
        
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
    """Define test cases with expected results based on testPlaceholderDetection.json"""
    return [
        {
            "description": "Vendor field placeholder detection (n/a)",
            "table_index": 0,
            "affected_entry": {"vendor": "n/a", "product": "Test Product", "versions": [{"version": "1.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "vendor",
            "expected_source_value": "n/a",
            "expected_detected_value": "n/a"
        },
        {
            "description": "Product field placeholder detection (N/A)",
            "table_index": 1,
            "affected_entry": {"vendor": "Test Vendor", "product": "N/A", "versions": [{"version": "2.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "product",
            "expected_source_value": "N/A",
            "expected_detected_value": "n/a"
        },
        {
            "description": "PackageName field placeholder detection (unknown)",
            "table_index": 2,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "packageName": "unknown", "versions": [{"version": "3.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "packageName",
            "expected_source_value": "unknown",
            "expected_detected_value": "unknown"
        },
        {
            "description": "Platform array placeholder detection (unspecified)",
            "table_index": 3,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "platforms": ["unspecified"], "versions": [{"version": "4.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "platforms[0]",
            "expected_source_value": "unspecified",
            "expected_detected_value": "unspecified"
        },
        {
            "description": "Version field placeholder detection (unknown)",
            "table_index": 4,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "versions": [{"version": "unknown", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "version",
            "expected_source_value": "unknown",
            "expected_detected_value": "unknown"
        },
        {
            "description": "Vendor field placeholder detection (N/A uppercase)",
            "table_index": 5,
            "affected_entry": {"vendor": "N/A", "product": "Test Product", "versions": [{"version": "5.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "vendor",
            "expected_source_value": "N/A",
            "expected_detected_value": "n/a"
        },
        {
            "description": "Product field placeholder detection (n/a lowercase)",
            "table_index": 6,
            "affected_entry": {"vendor": "Test Vendor", "product": "n/a", "versions": [{"version": "6.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "product",
            "expected_source_value": "n/a",
            "expected_detected_value": "n/a"
        },
        {
            "description": "PackageName field placeholder detection (N/A uppercase)",
            "table_index": 7,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "packageName": "N/A", "versions": [{"version": "7.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "packageName",
            "expected_source_value": "N/A",
            "expected_detected_value": "n/a"
        },
        {
            "description": "Platform array placeholder detection (N/A)",
            "table_index": 8,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "platforms": ["N/A"], "versions": [{"version": "8.0.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "platforms[0]",
            "expected_source_value": "N/A",
            "expected_detected_value": "n/a"
        },
        {
            "description": "Version field placeholder detection (N/A uppercase)",
            "table_index": 9,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "versions": [{"version": "N/A", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "version",
            "expected_source_value": "N/A",
            "expected_detected_value": "n/a"
        },
        {
            "description": "Platform array placeholder detection (all)",
            "table_index": 10,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "platforms": ["all"], "versions": [{"version": "8.5.0", "status": "affected"}]},
            "expected_concerns": 1,
            "expected_field": "platforms[0]",
            "expected_source_value": "all",
            "expected_detected_value": "all"
        },
        {
            "description": "Multiple field placeholders (vendor: n/a, product: N/A, version: unknown)",
            "table_index": 11,
            "affected_entry": {"vendor": "n/a", "product": "N/A", "versions": [{"version": "unknown", "status": "affected"}]},
            "expected_concerns": 3,
            "expected_fields": ["vendor", "product", "version"],
            "expected_source_values": ["n/a", "N/A", "unknown"],
            "expected_detected_values": ["n/a", "n/a", "unknown"]
        },
        {
            "description": "Multiple platform placeholders (unspecified, various, none)",
            "table_index": 12,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "platforms": ["unspecified", "various", "none"], "versions": [{"version": "9.0.0", "status": "affected"}]},
            "expected_concerns": 3,
            "expected_fields": ["platforms[0]", "platforms[1]", "platforms[2]"],
            "expected_source_values": ["unspecified", "various", "none"],
            "expected_detected_values": ["unspecified", "various", "none"]
        },
        {
            "description": "Multiple version placeholders (none, unknown)",
            "table_index": 13,
            "affected_entry": {"vendor": "n/a", "product": "Test Product", "versions": [{"version": "none", "status": "affected"}, {"version": "unknown", "status": "affected"}]},
            "expected_concerns": 3,
            "expected_fields": ["vendor", "version", "version"],
            "expected_source_values": ["n/a", "none", "unknown"],
            "expected_detected_values": ["n/a", "none", "unknown"]
        },
        {
            "description": "Changes array placeholder detection (at: unspecified, unknown)",
            "table_index": 14,
            "affected_entry": {"vendor": "Test Vendor", "product": "Test Product", "versions": [{"version": "10.0.0", "status": "affected", "changes": [{"at": "unspecified", "status": "unaffected"}, {"at": "unknown", "status": "unaffected"}]}]},
            "expected_concerns": 2,
            "expected_fields": ["changes[0].at", "changes[1].at"],
            "expected_source_values": ["unspecified", "unknown"],
            "expected_detected_values": ["unspecified", "unknown"]
        },
        {
            "description": "Comprehensive placeholders (vendor, product, packageName, platforms, version, lessThan, changes.at)",
            "table_index": 15,
            "affected_entry": {"vendor": "n/a", "product": "not available", "packageName": "unknown", "platforms": ["various", "unspecified", "Windows", "Linux"], "versions": [{"version": "undefined", "lessThan": "pending", "status": "affected", "changes": [{"at": "tbd", "status": "unaffected"}, {"at": "1.2.3", "status": "unaffected"}]}]},
            "expected_concerns": 8,
            "expected_fields": ["vendor", "product", "version", "lessThan", "changes[0].at", "platforms[0]", "platforms[1]", "packageName"],
            "expected_source_values": ["n/a", "not available", "undefined", "pending", "tbd", "various", "unspecified", "unknown"],
            "expected_detected_values": ["n/a", "not available", "undefined", "pending", "tbd", "various", "unspecified", "unknown"]
        },
        {
            "description": "No placeholders detected - valid vendor/product/package/platforms/version",
            "table_index": 16,
            "affected_entry": {"vendor": "Valid-Vendor", "product": "Valid Product Name", "packageName": "valid-package", "platforms": ["Windows", "Linux"], "versions": [{"version": "1.2.3", "lessThan": "1.3.0", "status": "affected"}]},
            "expected_concerns": 0
        },
        {
            "description": "No placeholders detected - hyphenated/multi-word valid values",
            "table_index": 17,
            "affected_entry": {"vendor": "Multi-Word-Vendor", "product": "Test-Product-Name", "packageName": "hyphenated-package-name", "platforms": ["x86_64"], "versions": [{"version": "1.0-beta", "status": "affected"}]},
            "expected_concerns": 0
        }
    ]

def extract_concerns_for_table(report_data, table_index):
    """Extract placeholder concerns for a specific table index"""
    if not report_data or 'cve_data' not in report_data:
        return []
        
    for cve_entry in report_data['cve_data']:
        for platform_entry in cve_entry.get('platform_entries', []):
            if platform_entry.get('table_index') == table_index:
                concerns = []
                for concern_detail in platform_entry.get('concerns_detail', []):
                    if concern_detail.get('concern_type') == 'placeholderData':
                        for concern in concern_detail.get('concerns', []):
                            concerns.append(concern)
                return concerns
    return []

def validate_test_case(test_case, report_data):
    """Validate a single test case against the report data"""
    table_index = test_case['table_index']
    concerns = extract_concerns_for_table(report_data, table_index)
    
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
    show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
    
    if show_details:
        print(f"{status} - Test: {test_case['description']}")
        print(f"Checks Performed: {len(concerns)} findings | structure confirmation | value confirmation")
        print(f"CVE Affected Entry: {json.dumps(test_case['affected_entry'], ensure_ascii=False)}")
    
    # Expected data format
    if test_case['expected_concerns'] == 0:
        expected_format = "No placeholders should be detected"
    elif test_case['expected_concerns'] == 1:
        expected_format = f"field: '{test_case['expected_field']}', sourceValue: '{test_case['expected_source_value']}', detectedPattern: {{detectedValue: '{test_case['expected_detected_value']}'}}"
    else:
        expected_parts = []
        for i in range(len(test_case['expected_fields'])):
            expected_parts.append(f"({test_case['expected_fields'][i]}, {test_case['expected_source_values'][i]}, {test_case['expected_detected_values'][i]})")
        expected_format = f"concerns: {', '.join(expected_parts)}"
    
    if show_details:
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

def test_placeholder_detection():
    """Test placeholder detection functionality"""
    # Only show detailed output if not running under unified test runner
    show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
    
    if show_details:
        print("================================================================================")
        print("PLACEHOLDER DETECTION TEST SUITE")
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
            print(f"PASS SDC Placeholder Detection (test duration) ({passed}/{total} tests)")
            print(f"   {passed}/{total} tests passed")
            print(f"   Test breakdown: {positive_tests} positive cases, {negative_tests} negative cases")
        else:
            print(f"FAIL SDC Placeholder Detection (test duration) ({passed}/{total} tests)")
            print(f"   {passed}/{total} tests passed")
            print(f"   Test breakdown: {positive_tests} positive cases, {negative_tests} negative cases")
        
        print("================================================================================")
    
    # Output standardized test results for run_all_tests.py
    print(f'TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE="SDC Placeholder Detection"')
    
    return success

if __name__ == "__main__":
    success = test_placeholder_detection()
    sys.exit(0 if success else 1)