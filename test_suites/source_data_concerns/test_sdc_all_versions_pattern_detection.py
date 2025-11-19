#!/usr/bin/env python3
"""
All Versions Pattern Detection Test Suite

This test suite validates the detection of "all versions" patterns that should be 
represented as "*" for consistent parsing. It tests the ALL_VERSION_VALUES array 
defined in badge_modal_system.py.

All versions patterns detected:
- 'all versions', 'all', 'all version', 'any version', 'any versions', 'any'
- Fields tested: version, lessThan, lessThanOrEqual, changes[].at

Detection stores results in allVersionsPatterns array with format:
{
    "field": "version",
    "sourceValue": "all versions", 
    "detectedPattern": {"detectedValue": "all versions"}
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
TEST_FILE = os.path.join(os.path.dirname(__file__), "testAllVersionsPatternDetection.json")

def run_test_and_get_report():
    """Run the test file and extract the sourceDataConcernReport.json"""
    try:
        # Run the tool using the standard command line interface
        cmd = [sys.executable, "-m", "src.analysis_tool.core.analysis_tool", "--test-file", TEST_FILE, "--no-cache", "--sdc-report", "true"]
        
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


def extract_all_versions_patterns(report_data):
    """Extract allVersionsPatterns from the source data concern report."""
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
                    
                # Look for allVersionsPatterns concern type
                for concern_detail in platform_entry['concerns_detail']:
                    if concern_detail.get('concern_type') == 'allVersionsPatterns':
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
                                    "vendor": platform_entry.get('vendor', ''),
                                    "product": platform_entry.get('product', ''),
                                    "detectedPattern": pattern_value,
                                    "fieldName": concern.get('field', ''),
                                    "fieldValue": concern.get('sourceValue', ''),
                                    "matchedText": pattern_value
                                }
                                patterns.append(pattern_info)
    
    except Exception as e:
        print(f"❌ Error extracting patterns: {e}")
    
    return patterns


def get_test_cases():
    """Define test cases with expected results based on testAllVersionsPatternDetection.json"""
    return [
        {
            "description": "Pattern 'all versions' in version field",
            "expected_field": "version",
            "expected_source_value": "all versions",
            "expected_detected_value": "all versions",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "all versions", "status": "affected"}]
            }
        },
        {
            "description": "Pattern 'all' in lessThan field",
            "expected_field": "lessThan",
            "expected_source_value": "all",
            "expected_detected_value": "all",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor", 
                "product": "Test Product",
                "versions": [{"version": "1.0.0", "lessThan": "all", "status": "affected"}]
            }
        },
        {
            "description": "Pattern 'all version' in lessThanOrEqual field", 
            "expected_field": "lessThanOrEqual",
            "expected_source_value": "all version",
            "expected_detected_value": "all version",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product", 
                "versions": [{"version": "2.0.0", "lessThanOrEqual": "all version", "status": "affected"}]
            }
        },
        {
            "description": "Pattern 'any version' in changes.at field",
            "expected_field": "changes[0].at",
            "expected_source_value": "any version",
            "expected_detected_value": "any version",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "3.0.0", "changes": [{"at": "any version", "status": "unaffected"}], "status": "affected"}]
            }
        },
        {
            "description": "Pattern 'any versions' in version field",
            "expected_field": "version",
            "expected_source_value": "any versions",
            "expected_detected_value": "any versions",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product", 
                "versions": [{"version": "any versions", "status": "affected"}]
            }
        },
        {
            "description": "Pattern 'any' in changes.at field",
            "expected_field": "changes[0].at",
            "expected_source_value": "any",
            "expected_detected_value": "any",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "4.0.0", "changes": [{"at": "any", "status": "unaffected"}], "status": "affected"}]
            }
        },
        {
            "description": "Clean version with no all versions patterns",
            "expected_field": "version",
            "expected_source_value": "5.0.0",
            "expected_detected_value": "",
            "expected_concerns": 0,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "5.0.0", "status": "affected"}]
            }
        },
        {
            "description": "Partial match 'all versions before 6.0.0' should NOT be detected (exact match only)",
            "expected_field": "version",
            "expected_source_value": "all versions before 6.0.0",
            "expected_detected_value": "",
            "expected_concerns": 0,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "all versions before 6.0.0", "status": "affected"}]
            }
        }
    ]

def validate_test_case(concerns, test_case):
    """Validate a single test case with detailed output matching other SDC format"""
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
                if (concern.get('fieldName') == test_case['expected_field'] and
                    concern.get('fieldValue') == test_case['expected_source_value'] and
                    concern.get('detectedPattern') == test_case['expected_detected_value']):
                    matching_concern = concern
                    break
            
            value_match = matching_concern is not None
        else:
            value_match = False
    
    return {
        'count_match': count_match,
        'structure_match': structure_match, 
        'value_match': value_match,
        'concerns': concerns
    }

def main():
    """Main test execution function"""
    print("=" * 84)
    print("ALL VERSIONS PATTERN DETECTION TEST SUITE")
    print("=" * 84)
    
    # Run test and get report
    report_data = run_test_and_get_report()
    if not report_data:
        print("❌ FAILED: Could not generate report data")
        print(f"TEST_RESULTS: PASSED=0 TOTAL=8 SUITE=\"SDC All Versions Pattern Detection\"")
        return False
    
    # Extract all versions patterns
    detected_patterns = extract_all_versions_patterns(report_data)
    
    # Get test cases
    test_cases = get_test_cases()
    
    passed = 0
    total = len(test_cases)
    
    for i, test_case in enumerate(test_cases):
        # Filter concerns for this specific test case
        test_concerns = []
        for pattern in detected_patterns:
            if (pattern['fieldName'] == test_case['expected_field'] and 
                pattern['fieldValue'] == test_case['expected_source_value']):
                test_concerns.append(pattern)
        
        # Validate test case
        validation = validate_test_case(test_concerns, test_case)
        
        # Determine pass/fail
        test_passed = validation['count_match'] and validation['structure_match'] and validation['value_match']
        
        if test_passed:
            print(f"✅ PASS - Test: {test_case['description']}")
            passed += 1
        else:
            print(f"❌ FAIL - Test: {test_case['description']}")
        
        # Show detailed check results
        checks_performed = []
        if test_case['expected_concerns'] > 0:
            checks_performed.append(f"{len(test_concerns)} findings")
        else:
            checks_performed.append(f"{len(test_concerns)} findings")
        checks_performed.extend(["structure confirmation", "value confirmation"])
        
        print(f"Checks Performed: {' | '.join(checks_performed)}")
        print(f"CVE Affected Entry: {json.dumps(test_case['affected_entry'], separators=(',', ': '))}")
        
        if test_case['expected_concerns'] == 0:
            print(f"Expected Data: {test_case['expected_concerns']} concerns | No all versions patterns should be detected")
            print(f"Found: {len(test_concerns)} concerns | {'No concerns found' if len(test_concerns) == 0 else 'Unexpected concerns detected'}")
        else:
            print(f"Expected Data: {test_case['expected_concerns']} concerns | field: '{test_case['expected_field']}', sourceValue: '{test_case['expected_source_value']}', detectedPattern: '{test_case['expected_detected_value']}'")
            if test_concerns:
                concern = test_concerns[0]
                print(f"Found: {len(test_concerns)} concerns | field: '{concern['fieldName']}', sourceValue: '{concern['fieldValue']}', detectedPattern: '{concern['detectedPattern']}'")
            else:
                print(f"Found: 0 concerns | No matching concerns found")
        
        # Individual validation results
        count_status = "✅" if validation['count_match'] else "❌"
        structure_status = "✅" if validation['structure_match'] else "❌"  
        value_status = "✅" if validation['value_match'] else "❌"
        
        print(f"{count_status} COUNT: {len(test_concerns)} concerns - ({'matches expected' if validation['count_match'] else 'does not match expected'})")
        print(f"{structure_status} STRUCTURE: field/sourceValue/detectedPattern.detectedValue - ({'matches expected' if validation['structure_match'] else 'does not match expected'})")
        print(f"{value_status} VALUES: All values match expected - ({'matches expected' if validation['value_match'] else 'does not match expected'})")
        print()
    
    # Final summary
    if passed == total:
        print(f"PASS SDC All Versions Pattern Detection (test duration) ({passed}/{total} tests)")
    else:
        print(f"FAIL SDC All Versions Pattern Detection (test duration) ({passed}/{total} tests)")
    
    print(f"   {passed}/{total} tests passed")
    print("=" * 84)
    print(f"TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE=\"SDC All Versions Pattern Detection\"")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)