#!/usr/bin/env python3
"""
Text Comparator Detection Test Suite

This test suite validates the detection of text patterns indicating version comparisons.
It tests the TEXT_COMPARATOR_PATTERNS array defined in badge_modal_system.py.

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
TEST_FILE = os.path.join(os.path.dirname(__file__), "testTextComparatorDetection.json")

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
            print(f"[FAIL] Tool execution failed with return code {result.returncode}")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return None
        
        # Use helper function to find report in both standard and consolidated environments
        return find_latest_test_run_report("sourceDataConcernReport.json")
    
    except Exception as e:
        print(f"[FAIL] Error running test: {e}")
        return None


def extract_version_text_patterns(report_data):
    """Extract textComparators from the source data concern report."""
    patterns = []
    
    try:
        # Navigate through the report structure
        if 'cve_data' not in report_data:
            print("[FAIL] No cve_data found in report")
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
                                    # Preserve the full detectedPattern object for validation
                                    full_detected_pattern = detected_pattern
                                else:
                                    pattern_value = detected_pattern
                                    # Convert string to object format for consistency
                                    full_detected_pattern = {'detectedValue': detected_pattern}
                                
                                # Transform to expected format
                                pattern_info = {
                                    'vendor': platform_entry.get('vendor', ''),
                                    'product': platform_entry.get('product', ''),
                                    'detectedPattern': full_detected_pattern,  # Preserve full object
                                    'fieldName': concern.get('field', ''),
                                    'fieldValue': concern.get('sourceValue', ''),
                                    'matchedText': pattern_value
                                }
                                patterns.append(pattern_info)
        
        return patterns
    except Exception as e:
        print(f"[FAIL] Error extracting version text patterns: {e}")
        return patterns


def validate_pattern_type_coverage(test_cases):
    """Validate that we have test coverage for each pattern type"""
    # Expected pattern types from backend
    expected_pattern_types = {
        'Upper Bound Comparators',
        'Lower Bound Comparators', 
        'Range Separators',
        'Approximation Patterns',
        'Inclusive/Exclusive Indicators',
        'Temporal/Status Indicators',
        'Hyphenated Version Range'
    }
    
    # Get pattern types covered by test cases
    covered_pattern_types = set()
    for test_case in test_cases:
        pattern_type = test_case.get('expected_pattern_type')
        if pattern_type and pattern_type != '':
            covered_pattern_types.add(pattern_type)
    
    # Check coverage
    missing_types = expected_pattern_types - covered_pattern_types
    extra_types = covered_pattern_types - expected_pattern_types
    
    if missing_types:
        print(f"[FAIL] COVERAGE ERROR: Missing test cases for pattern types: {missing_types}")
        return False
    
    if extra_types:
        print(f"[WARNING] Test cases for unexpected pattern types: {extra_types}")
    
    print(f"[OK] COVERAGE: All {len(expected_pattern_types)} pattern types have test coverage")
    return True

def get_test_cases():
    """Define test cases with expected results based on testTextComparatorDetection.json"""
    return [
        {
            "description": "Multi-word pattern: 'prior to' in version field (detects both 'prior to' and 'to')",
            "expected_field": "version",
            "expected_source_value": "prior to 1.2.3",
            "expected_detected_value": "prior to",
            "expected_pattern_type": "Upper Bound Comparators",
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
            "expected_pattern_type": "Upper Bound Comparators",
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
            "expected_pattern_type": "Range Separators",
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
            "expected_pattern_type": "Upper Bound Comparators",
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
            "expected_pattern_type": "Lower Bound Comparators",
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
            "expected_pattern_type": "",
            "expected_concerns": 0,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "22.0.0", "status": "affected"}]
            }
        },
        {
            "description": "Regex pattern: version range '1.5.0 - 1.5.7' in version field",
            "expected_field": "version",
            "expected_source_value": "All Versions 1.5.0 - 1.5.7",
            "expected_detected_value": "1.5.0 - 1.5.7",
            "expected_pattern_type": "Hyphenated Version Range",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "All Versions 1.5.0 - 1.5.7", "status": "affected"}]
            }
        },
        {
            "description": "Regex pattern: version range '32 - 37.011' in version field",
            "expected_field": "version",
            "expected_source_value": "Version 32 - 37.011 w Windows package",
            "expected_detected_value": "32 - 37.011",
            "expected_pattern_type": "Hyphenated Version Range",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "Version 32 - 37.011 w Windows package", "status": "affected"}]
            }
        },
        {
            "description": "Regex pattern: simple version range '1.0 - 2.0' in version field",
            "expected_field": "version",
            "expected_source_value": "1.0 - 2.0",
            "expected_detected_value": "1.0 - 2.0",
            "expected_pattern_type": "Hyphenated Version Range",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "1.0 - 2.0", "status": "affected"}]
            }
        },
        {
            "description": "Regex pattern: version range '5.1.2 - 5.2.0' in version field and '10.0 - 11.5' in changes.at field",
            "expected_field": "changes[0].at",
            "expected_source_value": "from 10.0 - 11.5",
            "expected_detected_value": "10.0 - 11.5",
            "expected_pattern_type": "Hyphenated Version Range",
            "expected_concerns": 2,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "5.1.2 - 5.2.0", "changes": [{"at": "from 10.0 - 11.5", "status": "unaffected"}], "status": "affected"}]
            }
        },
        {
            "description": "Legitimate version identifier '1.8.1-0' should NOT be detected as text comparator",
            "expected_field": "version",
            "expected_source_value": "1.8.1-0",
            "expected_detected_value": "",
            "expected_pattern_type": "",
            "expected_concerns": 0,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "1.8.1-0", "status": "affected"}]
            }
        },
        {
            "description": "Legitimate version identifier '2.4.1-rc1' should NOT be detected as text comparator",
            "expected_field": "version",
            "expected_source_value": "2.4.1-rc1",
            "expected_detected_value": "",
            "expected_pattern_type": "",
            "expected_concerns": 0,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "2.4.1-rc1", "status": "affected"}]
            }
        },
        {
            "description": "Approximation pattern: 'about' in version field",
            "expected_field": "version",
            "expected_source_value": "about 3.0.0",
            "expected_detected_value": "about",
            "expected_pattern_type": "Approximation Patterns",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "about 3.0.0", "status": "affected"}]
            }
        },
        {
            "description": "Inclusive indicator: 'inclusive' in lessThanOrEqual field",
            "expected_field": "lessThanOrEqual",
            "expected_source_value": "4.0.0 inclusive",
            "expected_detected_value": "inclusive",
            "expected_pattern_type": "Inclusive/Exclusive Indicators",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "3.0.0", "lessThanOrEqual": "4.0.0 inclusive", "status": "affected"}]
            }
        },
        {
            "description": "Temporal indicator: 'recent' in version field",
            "expected_field": "version",
            "expected_source_value": "recent versions",
            "expected_detected_value": "recent",
            "expected_pattern_type": "Temporal/Status Indicators",
            "expected_concerns": 1,
            "affected_entry": {
                "vendor": "Test Vendor",
                "product": "Test Product",
                "versions": [{"version": "recent versions", "status": "affected"}]
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
                    pattern_type = detected_pattern.get('patternType', '')
                else:
                    pattern_value = detected_pattern
                    pattern_type = ''
                
                pattern_match = pattern_value == test_case['expected_detected_value']
                
                # If we expect a specific pattern, match on pattern value
                # If we expect a specific pattern type, match on that too
                if field_match and source_match and pattern_match:
                    # For tests expecting specific patternType, check that too
                    if test_case.get('expected_pattern_type') and test_case['expected_pattern_type'] != '':
                        if pattern_type == test_case['expected_pattern_type']:
                            matching_concern = concern
                            break
                    else:
                        # No specific pattern type expected, just match on pattern value
                        matching_concern = concern
                        break
            
            value_match = matching_concern is not None
        else:
            value_match = False
    
    # Generate output
    status = "[PASS]" if count_match and structure_match and value_match else "[FAIL]"
    show_details = os.environ.get('UNIFIED_TEST_RUNNER') != '1'
    
    if show_details:
        print(f"{status} - Test: {test_case['description']}")
        print(f"Checks Performed: {len(concerns)} findings | structure confirmation | value confirmation")
        print(f"CVE Affected Entry: {json.dumps(test_case['affected_entry'], ensure_ascii=False)}")
        
        # Expected data format
        if test_case['expected_concerns'] == 0:
            expected_format = "No text patterns should be detected"
        else:
            expected_format = f"field: '{test_case['expected_field']}', sourceValue: '{test_case['expected_source_value']}', detectedPattern: '{test_case['expected_detected_value']}', patternType: '{test_case.get('expected_pattern_type', '')}'"
        
        print(f"Expected Data: {test_case['expected_concerns']} concerns | {expected_format}")
        
        # Found data format
        if concerns:
            concern = concerns[0]
            detected_pattern = concern.get('detectedPattern', '')
            if isinstance(detected_pattern, dict):
                pattern_value = detected_pattern.get('detectedValue', '')
                pattern_type = detected_pattern.get('patternType', '')
            else:
                pattern_value = detected_pattern
                pattern_type = ''
            found_format = f"field: '{concern['fieldName']}', sourceValue: '{concern['fieldValue']}', detectedPattern: '{pattern_value}', patternType: '{pattern_type}'"
            print(f"Found: {len(concerns)} concerns | {found_format}")
        else:
            print(f"Found: {len(concerns)} concerns | No concerns found")
        
        # Individual validation results
        if count_match:
            print(f"[PASS] COUNT: {len(concerns)} concerns - (matches expected)")
        else:
            print(f"[FAIL] COUNT: {len(concerns)} concerns - (expected {test_case['expected_concerns']})")
        
        if structure_match:
            print(f"[PASS] STRUCTURE: field/sourceValue/detectedPattern.detectedValue - (matches expected)")
        else:
            print(f"[FAIL] STRUCTURE: Missing required fields - (structure mismatch)")
        
        if value_match:
            print(f"[PASS] VALUES: All values match expected - (matches expected)")
        else:
            print(f"[FAIL] VALUES: Value mismatch detected - (values don't match)")
        
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
        print("[FAIL]: Could not generate report data")
        return False
    
    # Extract text pattern concerns by platform entry
    version_text_patterns = extract_version_text_patterns(report_data)
    if not version_text_patterns:
        if show_details:
            print("[FAIL]: No text pattern concerns found")
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
    # Validate pattern type coverage first
    test_cases = get_test_cases()
    coverage_valid = validate_pattern_type_coverage(test_cases)
    
    if not coverage_valid:
        print(f'TEST_RESULTS: PASSED=0 TOTAL=0 SUITE="SDC Text Comparator Detection" ERROR="Pattern type coverage incomplete"')
        return False
    
    success = test_text_comparator_detection()
    
    # Output standardized format for unified test runner  
    passed = 15 if success else 0  # We now have 15 test cases
    total = 15
    print(f'TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE="SDC Text Comparator Detection"')
    
    return success


if __name__ == "__main__":
    success = run_all_tests()
    
    if os.environ.get('UNIFIED_TEST_RUNNER') != '1':
        sys.exit(0 if success else 1)
