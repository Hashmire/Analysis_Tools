#!/usr/bin/env python3
"""
Bloat Text Detection Test Suite

This test suite validates the detection of bloat text patterns that should be 
removed from version fields for cleaner parsing. It tests the BLOAT_TEXT_VALUES 
array defined in badge_modal_system.py.

Bloat text patterns detected:
- 'version', 'versions', 'ver'
- Fields tested: version, lessThan, lessThanOrEqual, changes[].at

Detection stores results in bloatTextDetection array with format:
{
    "field": "version",
    "sourceValue": "version 2.011", 
    "detectedPattern": {"detectedValue": "version"}
}
"""

import sys
import os
import json
import subprocess
from pathlib import Path

# Add src path for analysis_tool imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
from analysis_tool.storage.run_organization import find_latest_test_run_report

# Test configuration
TEST_FILE = os.path.join(os.path.dirname(__file__), "testBloatTextDetection.json")

def run_test_and_get_report():
    """Run the test file and extract the sourceDataConcernReport.json"""
    try:
        # Run the tool using the standard command line interface
        cmd = [sys.executable, "-m", "src.analysis_tool.core.analysis_tool", "--test-file", TEST_FILE, "--no-cache", "--sdc-report", "true"]
        
        # Check if running under unified test runner to control browser behavior
        if os.environ.get('UNIFIED_TEST_RUNNER'):
            # Add --no-browser when running under unified test runner
            cmd.append("--no-browser")
        
        # Set environment variable to suppress terminal output during testing
        env = os.environ.copy()
        if os.environ.get('UNIFIED_TEST_RUNNER') != '1':
            env['UNIFIED_TEST_RUNNER'] = '1'
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path(__file__).parent.parent.parent, env=env)
        
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


def extract_bloat_text_patterns(report_data):
    """Extract bloatTextDetection patterns from the source data concern report."""
    patterns = []
    
    try:
        # Navigate through the report structure
        if 'cve_data' not in report_data:
            print("❌ No cve_data found in report")
            return patterns
        
        for cve_entry in report_data['cve_data']:
            if 'platform_entries' not in cve_entry:
                continue
                
            for platform_entry in cve_entry['platform_entries']:
                if 'concerns_detail' not in platform_entry:
                    continue
                    
                # Look for bloatTextDetection concern type
                for concern_detail in platform_entry['concerns_detail']:
                    if concern_detail.get('concern_type') == 'bloatTextDetection':
                        if 'concerns' in concern_detail:
                            for concern in concern_detail['concerns']:
                                # Handle both string and object detectedPattern formats
                                detected_pattern = concern.get('detectedPattern', '')
                                if isinstance(detected_pattern, dict):
                                    pattern_value = detected_pattern.get('detectedValue', '')
                                    pattern_type = detected_pattern.get('patternType', '')
                                else:
                                    pattern_value = detected_pattern
                                    pattern_type = ''
                                
                                # Transform to expected format
                                pattern_info = {
                                    "vendor": platform_entry.get('vendor', ''),
                                    "product": platform_entry.get('product', ''),
                                    "detectedPattern": pattern_value,
                                    "field": concern.get('field', ''),
                                    "sourceValue": concern.get('sourceValue', '')
                                }
                                
                                # Add patternType if present (for vendor_redundancy cases)
                                if pattern_type:
                                    pattern_info["patternType"] = pattern_type
                                    
                                patterns.append(pattern_info)
    
    except Exception as e:
        print(f"❌ Error extracting bloat text patterns: {e}")
    
    return patterns


def get_test_cases():
    """Get expected test results for bloat text detection."""
    return [
        {
            "description": "Version prefix detection",
            "vendor": "Test Vendor",
            "product": "Test Product", 
            "detectedPattern": "version",
            "field": "version",
            "sourceValue": "version 2.011"
        },
        {
            "description": "Versions plural detection in lessThan",
            "vendor": "Test Vendor",
            "product": "Test Product",
            "detectedPattern": "versions", 
            "field": "lessThan",
            "sourceValue": "versions 3.0"
        },
        {
            "description": "Ver abbreviation detection in lessThanOrEqual",
            "vendor": "Test Vendor",
            "product": "Test Product",
            "detectedPattern": "ver",
            "field": "lessThanOrEqual", 
            "sourceValue": "ver 4.5.1"
        },
        {
            "description": "Version detection in changes array",
            "vendor": "Test Vendor",
            "product": "Test Product",
            "detectedPattern": "version",
            "field": "changes[0].at",
            "sourceValue": "version 5.2.3"
        },
        {
            "description": "Ver abbreviation in version field",
            "vendor": "Test Vendor", 
            "product": "Test Product",
            "detectedPattern": "ver",
            "field": "version",
            "sourceValue": "ver 1.8.0_351"
        },
        {
            "description": "Versions plural in version field",
            "vendor": "Test Vendor",
            "product": "Test Product", 
            "detectedPattern": "versions",
            "field": "version", 
            "sourceValue": "versions 3.1"
        },
        {
            "description": "Version detection in lessThan field",
            "vendor": "Test Vendor",
            "product": "Test Product",
            "detectedPattern": "version",
            "field": "lessThan",
            "sourceValue": "version 6.0"
        },
        {
            "description": "Versions detection in lessThanOrEqual field", 
            "vendor": "Test Vendor",
            "product": "Test Product",
            "detectedPattern": "versions",
            "field": "lessThanOrEqual",
            "sourceValue": "versions 7.2"
        },
        {
            "description": "Vendor redundancy - full word match (should detect)",
            "vendor": "NodeJS",
            "product": "NodeJS Product",
            "detectedPattern": "NodeJS",
            "patternType": "vendor_redundancy",
            "field": "product",
            "sourceValue": "NodeJS Product"
        },
        {
            "description": "Vendor redundancy - case insensitive full word match (should detect)",
            "vendor": "NodeJS",
            "product": "Fun nodejs product",
            "detectedPattern": "NodeJS", 
            "patternType": "vendor_redundancy",
            "field": "product",
            "sourceValue": "Fun nodejs product"
        },
        {
            "description": "Vendor redundancy - Apache full word match (should detect)",
            "vendor": "Apache",
            "product": "My Apache Server",
            "detectedPattern": "Apache",
            "patternType": "vendor_redundancy", 
            "field": "product",
            "sourceValue": "My Apache Server"
        }
    ]


def validate_test_case(expected_case, actual_patterns):
    """Validate a specific test case against actual patterns found."""
    # Find matching pattern in actual results
    matching_patterns = [
        p for p in actual_patterns 
        if (p['vendor'] == expected_case['vendor'] and 
            p['product'] == expected_case['product'] and
            p['detectedPattern'].lower() == expected_case['detectedPattern'].lower() and
            p['field'] == expected_case['field'] and
            p['sourceValue'] == expected_case['sourceValue'] and
            # Check patternType if specified in expected case
            (not expected_case.get('patternType') or p.get('patternType') == expected_case.get('patternType')))
    ]
    
    if matching_patterns:
        return True, f"✅ PASS: {expected_case['description']} - Pattern '{expected_case['detectedPattern']}' detected in field '{expected_case['field']}' with value '{expected_case['sourceValue']}'"
    else:
        return False, f"❌ FAIL: {expected_case['description']} - Expected pattern '{expected_case['detectedPattern']}' in field '{expected_case['field']}' with value '{expected_case['sourceValue']}' not found"


def validate_test_case_detailed(expected_case, actual_patterns):
    """Validate a test case with detailed output matching the all versions pattern test format."""
    # Find matching pattern in actual results
    matching_patterns = [
        p for p in actual_patterns 
        if (p['vendor'] == expected_case['vendor'] and 
            p['product'] == expected_case['product'] and
            p['detectedPattern'].lower() == expected_case['detectedPattern'].lower() and
            p['field'] == expected_case['field'] and
            p['sourceValue'] == expected_case['sourceValue'])
    ]
    
    # Build detailed output
    output_lines = []
    
    if matching_patterns:
        output_lines.append(f"✅ PASS - Test: Pattern '{expected_case['detectedPattern']}' in {expected_case['field']} field")
        status_icon = "✅"
    else:
        output_lines.append(f"❌ FAIL - Test: Pattern '{expected_case['detectedPattern']}' in {expected_case['field']} field")
        status_icon = "❌"
    
    output_lines.append("Checks Performed: 1 findings | structure confirmation | value confirmation")
    
    # Show the CVE affected entry context
    output_lines.append(f'CVE Affected Entry: {{"vendor": "{expected_case["vendor"]}","product": "{expected_case["product"]}","versions": [...with {expected_case["field"]} containing "{expected_case["sourceValue"]}"...]}}')
    
    # Show expected vs found data
    output_lines.append(f"Expected Data: 1 concerns | field: '{expected_case['field']}', sourceValue: '{expected_case['sourceValue']}', detectedPattern: '{expected_case['detectedPattern']}'")
    
    if matching_patterns:
        found_pattern = matching_patterns[0]
        output_lines.append(f"Found: 1 concerns | field: '{found_pattern['field']}', sourceValue: '{found_pattern['sourceValue']}', detectedPattern: '{found_pattern['detectedPattern']}'")
        output_lines.append(f"{status_icon} COUNT: 1 concerns - (matches expected)")
        output_lines.append(f"{status_icon} STRUCTURE: field/sourceValue/detectedPattern.detectedValue - (matches expected)")
        output_lines.append(f"{status_icon} VALUES: All values match expected - (matches expected)")
    else:
        output_lines.append("Found: 0 concerns | No matching bloat text patterns found")
        output_lines.append(f"{status_icon} COUNT: 0 concerns - (does not match expected 1)")
        output_lines.append(f"{status_icon} STRUCTURE: field/sourceValue/detectedPattern.detectedValue - (not found)")
        output_lines.append(f"{status_icon} VALUES: Expected values not found - (does not match expected)")
    
    return len(matching_patterns) > 0, "\n".join(output_lines)


def get_false_positive_test_cases():
    """Get test cases that should NOT be detected (avoiding false positives)."""
    return [
        {
            "description": "Vendor redundancy - partial string match (should NOT detect)",
            "vendor": "NodeJS", 
            "product": "nodejs-fun-product",
            "field": "product"
        },
        {
            "description": "Vendor redundancy - partial string match suffix (should NOT detect)",
            "vendor": "NodeJS",
            "product": "fun-nodejs-product", 
            "field": "product"
        },
        {
            "description": "Vendor redundancy - partial string match in compound word (should NOT detect)",
            "vendor": "Apache",
            "product": "apache-server",
            "field": "product"
        }
    ]


def validate_false_positive_case(false_positive_case, actual_patterns):
    """Validate that a pattern should NOT be detected."""
    # Look for patterns that should not exist
    matching_patterns = [
        p for p in actual_patterns
        if (p['vendor'] == false_positive_case['vendor'] and
            p['product'] == false_positive_case['product'] and
            p['field'] == false_positive_case['field'] and
            p.get('patternType') == 'vendor_redundancy')
    ]
    
    if not matching_patterns:
        return True, f"✅ PASS: {false_positive_case['description']} - Correctly NOT detected"
    else:
        return False, f"❌ FAIL: {false_positive_case['description']} - False positive detected: {matching_patterns[0]['detectedPattern']}"


def main():
    """Main test function."""
    print("=" * 84)
    print("BLOAT TEXT DETECTION TEST SUITE")
    print("=" * 84)
    
    # Run the test and get the report
    report_data = run_test_and_get_report()
    if not report_data:
        print("❌ Failed to get test report")
        print("TEST_RESULTS: PASSED=0 TOTAL=8 SUITE=\"SDC Bloat Text Detection\"")
        return 1
    
    # Extract actual patterns found
    actual_patterns = extract_bloat_text_patterns(report_data)
    
    if not actual_patterns:
        print("❌ No bloat text patterns found in report")
        print("TEST_RESULTS: PASSED=0 TOTAL=8 SUITE=\"SDC Bloat Text Detection\"")
        return 1
    
    # Get expected test cases
    expected_cases = get_test_cases()
    false_positive_cases = get_false_positive_test_cases()
    
    # Validate each test case
    passed_tests = 0
    total_tests = len(expected_cases) + len(false_positive_cases)
    
    print("Testing expected detections:")
    print("-" * 50)
    for expected_case in expected_cases:
        is_valid, detailed_output = validate_test_case_detailed(expected_case, actual_patterns)
        if is_valid:
            passed_tests += 1
        print(detailed_output)
        print()  # Add spacing between tests
    
    print("Testing false positive prevention:")
    print("-" * 50)
    for false_positive_case in false_positive_cases:
        is_valid, detailed_output = validate_false_positive_case(false_positive_case, actual_patterns)
        if is_valid:
            passed_tests += 1
        print(detailed_output)
        print()  # Add spacing between tests
    
    # Print summary
    if passed_tests == total_tests:
        print(f"PASS SDC Bloat Text Detection (test duration) ({passed_tests}/{total_tests} tests)")
        print(f"   {passed_tests}/{total_tests} tests passed")
    else:
        failed_tests = total_tests - passed_tests
        print(f"FAIL SDC Bloat Text Detection ({passed_tests}/{total_tests} tests passed, {failed_tests} failed)")
    
    print("=" * 84)
    print(f"TEST_RESULTS: PASSED={passed_tests} TOTAL={total_tests} SUITE=\"SDC Bloat Text Detection\"")
    
    return 0 if passed_tests == total_tests else 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)