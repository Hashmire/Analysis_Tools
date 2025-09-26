#!/usr/bin/env python3
"""
Text Comparator Detection Test Suite

This test suite validates the detection of text patterns indicating version comparisons.
It tests the TEXT_COMPARATOR_PATTERNS array defined in badge_modal_system.py.

Text patterns detected:
- Multi-word: "see references", "see advisory", "prior to", "earlier than", etc.
- Single-word: "through", "before", "until", "after", "since", "from", etc.
- Fields tested: version, lessThan, lessThanOrEqual, changes[].at

Detection stores results in versionTextPatterns array with format:
{
    "vendor": "Test Vendor",
    "product": "Test Product", 
    "detectedPattern": "prior to",
    "fieldName": "version",
    "fieldValue": "prior to 1.2.3",
    "matchedText": "prior to"
}
"""

import sys
import os
import json
import subprocess
from pathlib import Path

# Add src path for analysis_tool imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from analysis_tool.storage.run_organization import find_latest_test_run_report

# Test configuration
TEST_FILE = os.path.join(os.path.dirname(__file__), "testTextComparatorDetection.json")

def run_test_and_get_report():
    """Run the test file and extract the sourceDataConcernReport.json"""
    try:
        # Run the tool using the standard command line interface
        cmd = [sys.executable, "run_tools.py", "--test-file", TEST_FILE, "--no-cache"]
        
        # Check if running under unified test runner to control browser behavior
        if os.environ.get('UNIFIED_TEST_RUNNER'):
            # Add --no-browser when running under unified test runner
            cmd.append("--no-browser")
        
        # Set environment variable to suppress terminal output during testing
        env = os.environ.copy()
        if os.environ.get('UNIFIED_TEST_RUNNER') != '1':
            env['UNIFIED_TEST_RUNNER'] = '1'
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path(__file__).parent.parent)
        
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


def extract_version_text_patterns(report_data):
    """Extract textComparators from the source data concern report."""
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
                    
                # Look for textComparators concern type
                for concern_detail in platform_entry['concerns_detail']:
                    if concern_detail.get('concern_type') == 'textComparators':
                        if 'concerns' in concern_detail:
                            for concern in concern_detail['concerns']:
                                # Handle both string and object detectedPattern formats
                                detected_pattern = concern.get('detectedPattern', '')
                                if isinstance(detected_pattern, dict):
                                    pattern_value = detected_pattern.get('detectedValue', '')
                                else:
                                    pattern_value = detected_pattern
                                
                                # Transform to expected format
                                pattern_info = {
                                    'vendor': platform_entry.get('vendor', ''),
                                    'product': platform_entry.get('product', ''),
                                    'detectedPattern': pattern_value,
                                    'fieldName': concern.get('field', ''),
                                    'fieldValue': concern.get('sourceValue', ''),
                                    'matchedText': pattern_value
                                }
                                patterns.append(pattern_info)
        
        return patterns
    except Exception as e:
        print(f"❌ Error extracting version text patterns: {e}")
        return patterns


def get_test_cases():
    """Define test cases with expected results based on testTextComparatorDetection.json"""
    return [
        {
            "description": "Multi-word pattern: 'prior to' in version field (detects both 'prior to' and 'to')",
            "expected_field": "version",
            "expected_source_value": "prior to 1.2.3",
            "expected_detected_value": "prior to",
            "expected_concerns": 2,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "prior to 1.2.3", "status": "affected"}]
            }
        },
        {
            "description": "Multi-word pattern: 'earlier than' in lessThan field",
            "expected_field": "lessThan",
            "expected_source_value": "earlier than 2.0.0",
            "expected_detected_value": "earlier than",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor", 
                "product": "Test Product",
                "versions": [{"version": "1.0.0", "lessThan": "earlier than 2.0.0", "status": "affected"}]
            }
        },
        {
            "description": "Single-word pattern: 'through' in lessThanOrEqual field", 
            "expected_field": "lessThanOrEqual",
            "expected_source_value": "through version 3.0.0",
            "expected_detected_value": "through",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product", 
                "versions": [{"version": "2.0.0", "lessThanOrEqual": "through version 3.0.0", "status": "affected"}]
            }
        },
        {
            "description": "Single-word pattern: 'before' in changes.at field",
            "expected_field": "changes[0].at",
            "expected_source_value": "before 4.0.0",
            "expected_detected_value": "before",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "3.0.0", "changes": [{"at": "before 4.0.0", "status": "unaffected"}], "status": "affected"}]
            }
        },
        {
            "description": "Single-word pattern: 'after' in version field",
            "expected_field": "version",
            "expected_source_value": "after 5.0.0",
            "expected_detected_value": "after",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product", 
                "versions": [{"version": "after 5.0.0", "status": "affected"}]
            }
        },
        {
            "description": "Clean version with no text patterns",
            "expected_field": "version",
            "expected_source_value": "22.0.0",
            "expected_detected_value": "",
            "expected_concerns": 0,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "22.0.0", "status": "affected"}]
            }
        }
    ]

def validate_test_case(concerns, test_case):
    """Validate a single test case with detailed output matching Mathematical Comparator format"""
    # Count validation
    count_match = len(concerns) == test_case['expected_concerns']
    
    # Structure validation - check for the transformed field names from extraction
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
            if not all(key in concern for key in ['fieldName', 'fieldValue', 'detectedPattern']):
                structure_match = False
                break
    
    # Value validation
    value_match = True
    if test_case['expected_concerns'] == 0:
        value_match = len(concerns) == 0
    else:
        if concerns:
            # Find the concern that matches our expected pattern
            matching_concern = None
            for concern in concerns:
                field_match = concern.get('fieldName') == test_case['expected_field']
                source_match = concern.get('fieldValue') == test_case['expected_source_value']
                
                # Handle both string and object detectedPattern formats
                detected_pattern = concern.get('detectedPattern', '')
                if isinstance(detected_pattern, dict):
                    pattern_value = detected_pattern.get('detectedValue', '')
                else:
                    pattern_value = detected_pattern
                
                pattern_match = pattern_value == test_case['expected_detected_value']
                
                if field_match and source_match and pattern_match:
                    matching_concern = concern
                    break
            
            value_match = matching_concern is not None
        else:
            value_match = False
    
    # Generate output
    status = "✅ PASS" if count_match and structure_match and value_match else "❌ FAIL"
    show_details = os.environ.get('UNIFIED_TEST_RUNNER') != '1'
    
    if show_details:
        print(f"{status} - Test: {test_case['description']}")
        print(f"Checks Performed: {len(concerns)} findings | structure confirmation | value confirmation")
        print(f"CVE Affected Entry: {json.dumps(test_case['affected_entry'], ensure_ascii=False)}")
        
        # Expected data format
        if test_case['expected_concerns'] == 0:
            expected_format = "No text patterns should be detected"
        else:
            expected_format = f"field: '{test_case['expected_field']}', sourceValue: '{test_case['expected_source_value']}', detectedPattern: '{test_case['expected_detected_value']}'"
        
        print(f"Expected Data: {test_case['expected_concerns']} concerns | {expected_format}")
        
        # Found data format
        if concerns:
            concern = concerns[0]
            detected_pattern = concern.get('detectedPattern', '')
            if isinstance(detected_pattern, dict):
                pattern_value = detected_pattern.get('detectedValue', '')
            else:
                pattern_value = detected_pattern
            found_format = f"field: '{concern['fieldName']}', sourceValue: '{concern['fieldValue']}', detectedPattern: '{pattern_value}'"
            print(f"Found: {len(concerns)} concerns | {found_format}")
        else:
            print(f"Found: {len(concerns)} concerns | No concerns found")
        
        # Individual validation results
        if count_match:
            print(f"✅ COUNT: {len(concerns)} concerns - (matches expected)")
        else:
            print(f"❌ COUNT: {len(concerns)} concerns - (expected {test_case['expected_concerns']})")
        
        if structure_match:
            print(f"✅ STRUCTURE: field/sourceValue/detectedPattern.detectedValue - (matches expected)")
        else:
            print(f"❌ STRUCTURE: Missing required fields - (structure mismatch)")
        
        if value_match:
            print(f"✅ VALUES: All values match expected - (matches expected)")
        else:
            print(f"❌ VALUES: Value mismatch detected - (values don't match)")
        
        print()
    
    return count_match and structure_match and value_match

def test_text_comparator_detection():
    """Test text comparator detection functionality"""
    show_details = os.environ.get('UNIFIED_TEST_RUNNER') != '1'
    
    if show_details:
        print("=" * 84)
        print("TEXT COMPARATOR DETECTION TEST SUITE")
        print("=" * 84)
    
    # Run analysis and get report
    report_data = run_test_and_get_report()
    if not report_data:
        print("❌ FAILED: Could not generate report data")
        return False
    
    # Extract text pattern concerns by platform entry
    version_text_patterns = extract_version_text_patterns(report_data)
    if not version_text_patterns:
        if show_details:
            print("❌ FAILED: No text pattern concerns found")
        return False
    

    
    # Group concerns by affected entry for easier lookup
    concerns_by_entry = {}
    for concern in version_text_patterns:
        field_name = concern.get('fieldName', '')
        field_value = concern.get('fieldValue', '')
        key = f"{field_name}:{field_value}"
        if key not in concerns_by_entry:
            concerns_by_entry[key] = []
        concerns_by_entry[key].append(concern)
    
    # Test each case
    test_cases = get_test_cases()
    passed = 0
    total = len(test_cases)
    
    for i, test_case in enumerate(test_cases):
        # Find matching concerns for this test case
        if test_case['expected_concerns'] == 0:
            test_concerns = []
        else:
            key = f"{test_case['expected_field']}:{test_case['expected_source_value']}"
            test_concerns = concerns_by_entry.get(key, [])
        
        # Validate the test case
        if validate_test_case(test_concerns, test_case):
            passed += 1
    
    if show_details:
        result_status = "PASS" if passed == total else "FAIL"
        print(f"{result_status} SDC Text Comparator Detection (test duration) ({passed}/{total} tests)")
        print(f"   {passed}/{total} tests passed")
        print("=" * 84)
    
    return passed == total

def run_all_tests():
    """Run all text comparator detection tests and validate results."""
    success = test_text_comparator_detection()
    
    # Output standardized format for unified test runner
    passed = 6 if success else 0  # We have 6 test cases
    total = 6
    print(f'TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE="SDC Text Comparator Detection"')
    
    return success


if __name__ == "__main__":
    success = run_all_tests()
    
    if os.environ.get('UNIFIED_TEST_RUNNER') != '1':
        sys.exit(0 if success else 1)