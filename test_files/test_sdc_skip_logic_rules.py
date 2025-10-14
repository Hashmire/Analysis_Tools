#!/usr/bin/env python3
"""
SDC Skip Logic Rules Test Suite

Tests skip logic rules that prevent improper multi-count findings by running test file 
and checking sourceDataConcernReport.json. Validates that skip conditions work correctly
to eliminate overlapping concerns between detection groups.

Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Usage:
    python test_files/test_sdc_skip_logic_rules.py
"""

import sys
import os
import json
import subprocess
from pathlib import Path

# Add src path for analysis_tool imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from analysis_tool.storage.run_organization import find_latest_test_run_report

# Path to the skip logic rules test file
TEST_FILE = os.path.join(os.path.dirname(__file__), "testSkipLogicRules.json")

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
            print(f"❌ Tool execution failed with return code {result.returncode}")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return None
            
        # Use helper function to find report in both standard and consolidated environments
        return find_latest_test_run_report("sourceDataConcernReport.json")
            
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return None

def extract_concerns_for_table(report_data, table_index):
    """Extract all concerns for a specific table index from the report data"""
    all_concerns = {}
    
    if not report_data or 'cve_data' not in report_data:
        return all_concerns
        
    # Navigate through the report structure
    cve_data = report_data['cve_data']
    if not cve_data or len(cve_data) == 0:
        return all_concerns
        
    # Get first CVE entry (test files typically have one CVE)
    cve_entry = cve_data[0]
    if 'platform_entries' not in cve_entry or table_index >= len(cve_entry['platform_entries']):
        return all_concerns
        
    platform_entry = cve_entry['platform_entries'][table_index]
    if 'concerns_detail' not in platform_entry:
        return all_concerns
        
    # Extract concerns by type
    for concern_detail in platform_entry['concerns_detail']:
        concern_type = concern_detail.get('concern_type')
        if concern_type and 'concerns' in concern_detail:
            all_concerns[concern_type] = concern_detail['concerns']
                
    return all_concerns

def get_test_cases():
    """Define test cases with expected results based on skip logic rules"""
    return [
        {
            "description": "Priority 1: Placeholder skips all other detections (vendor: n/a with special chars)",
            "table_index": 0,
            "expected_detections": ["placeholderData"],
            "forbidden_detections": ["invalidCharacters", "mathematicalComparators", "textComparators", "whitespaceIssues"],
            "expected_concerns": {"placeholderData": 1},
            "rationale": "Placeholder detection should prevent '/' from being flagged as invalid character"
        },
        {
            "description": "Priority 2: Mathematical comparators skip invalid character detection for math operators",
            "table_index": 1,
            "expected_detections": ["mathematicalComparators"],
            "forbidden_detections": ["invalidCharacters"],
            "forbidden_chars_in_invalid": ["<", ">", "=", "!"],
            "expected_concerns": {"mathematicalComparators": 1},
            "rationale": "Mathematical operators '>=' should not be flagged as invalid characters"
        },
        {
            "description": "Priority 2: Mathematical comparators in version field skip invalid character detection",
            "table_index": 2,
            "expected_detections": ["mathematicalComparators"],
            "forbidden_detections": [],
            "forbidden_chars_in_invalid": ["<", ">", "=", "!"],
            "expected_concerns": {"mathematicalComparators": 1},
            "rationale": "Mathematical operators '<=' in version should not be flagged as invalid"
        },
        {
            "description": "Priority 3: Text comparators skip invalid character detection for space (only for hyphenated ranges)",
            "table_index": 3,
            "expected_detections": ["textComparators"],
            "forbidden_detections": [],
            "forbidden_chars_in_invalid": [" "],
            "expected_concerns": {"textComparators": 1},
            "rationale": "Space in '1.0 to 2.0' should not be flagged as invalid when text comparator detected"
        },
        {
            "description": "Priority 4: Whitespace detection skips invalid character detection for space",
            "table_index": 4,
            "expected_detections": ["whitespaceIssues"],
            "forbidden_detections": [],
            "forbidden_chars_in_invalid": [" "],
            "expected_concerns": {"whitespaceIssues": 1},
            "rationale": "Space in ' TestVendor ' should not be flagged as invalid when whitespace detected"
        },
        {
            "description": "Priority 4: Whitespace detection in version field skips invalid character detection",
            "table_index": 5,
            "expected_detections": ["whitespaceIssues"],
            "forbidden_detections": [],
            "forbidden_chars_in_invalid": [" "],
            "expected_concerns": {"whitespaceIssues": 1},
            "rationale": "Space in ' 5.0.0 ' should not be flagged as invalid when whitespace detected"
        },
        {
            "description": "Text comparator detection without hyphenated range (no space exclusion)",
            "table_index": 6,
            "expected_detections": ["textComparators"],
            "forbidden_detections": [],
            "expected_concerns": {"textComparators": 1},
            "rationale": "'before 6.0.0' should trigger text comparator but space can still be invalid if detected"
        },
        {
            "description": "Priority 3: Text comparator with hyphenated range skips space in invalid detection",
            "table_index": 7,
            "expected_detections": ["textComparators"],
            "forbidden_detections": [],
            "forbidden_chars_in_invalid": [" "],
            "expected_concerns": {"textComparators": 1},
            "rationale": "Space in '1.0 - 2.0' should not be flagged as invalid (hyphenated range pattern)"
        },
        {
            "description": "Invalid character detection only (no skip conditions)",
            "table_index": 8,
            "expected_detections": ["invalidCharacters"],
            "forbidden_detections": [],
            "expected_concerns": {"invalidCharacters": 1},
            "rationale": "'@' in '7.0@build' should be flagged as invalid character"
        },
        {
            "description": "Complex scenario: Multiple detection types on different fields (field-specific behavior)",
            "table_index": 9,
            "expected_detections": ["placeholderData", "mathematicalComparators", "textComparators", "whitespaceIssues"],
            "forbidden_detections": [],
            "expected_concerns": {"placeholderData": 2, "mathematicalComparators": 1, "textComparators": 1, "whitespaceIssues": 1},
            "rationale": "Each field should be detected independently - placeholder in vendor/packageName, math in product, text in version, whitespace in platforms"
        },
        {
            "description": "Mathematical comparators in lessThan field skip invalid character detection",
            "table_index": 10,
            "expected_detections": ["mathematicalComparators"],
            "forbidden_detections": [],
            "forbidden_chars_in_invalid": ["<", ">", "=", "!"],
            "expected_concerns": {"mathematicalComparators": 1},
            "rationale": "Mathematical operators '>=' in lessThan should not be flagged as invalid"
        },
        {
            "description": "Placeholder in changes array skips all other detections for that field",
            "table_index": 11,
            "expected_detections": ["placeholderData"],
            "forbidden_detections": ["invalidCharacters", "mathematicalComparators", "textComparators", "whitespaceIssues"],
            "expected_concerns": {"placeholderData": 1},
            "rationale": "Placeholder 'unknown' in changes[].at should prevent other detections"
        },
        {
            "description": "Mathematical comparators in changes array skip invalid character detection",
            "table_index": 12,
            "expected_detections": ["mathematicalComparators"],
            "forbidden_detections": [],
            "forbidden_chars_in_invalid": ["<", ">", "=", "!"],
            "expected_concerns": {"mathematicalComparators": 1},
            "rationale": "Mathematical operators '<=' in changes[].at should not be flagged as invalid"
        },
        {
            "description": "Text comparators in changes array skip space in invalid character detection",
            "table_index": 13,
            "expected_detections": ["textComparators"],
            "forbidden_detections": [],
            "forbidden_chars_in_invalid": [" "],
            "expected_concerns": {"textComparators": 1},
            "rationale": "Space in 'before 15.0' should not be flagged as invalid when text comparator detected"
        },
        {
            "description": "Whitespace detection in changes array skips invalid character detection for space",
            "table_index": 14,
            "expected_detections": ["whitespaceIssues"],
            "forbidden_detections": [],
            "forbidden_chars_in_invalid": [" "],
            "expected_concerns": {"whitespaceIssues": 1},
            "rationale": "Space in ' 17.0 ' should not be flagged as invalid when whitespace detected"
        },
        {
            "description": "Text comparator with hyphenated range in changes array",
            "table_index": 15,
            "expected_detections": ["textComparators"],
            "forbidden_detections": [],
            "forbidden_chars_in_invalid": [" "],
            "expected_concerns": {"textComparators": 1},
            "rationale": "Space in '1.0 - 2.0' should not be flagged as invalid (hyphenated range pattern)"
        },
        {
            "description": "Invalid character detection in changes array (no skip conditions)",
            "table_index": 16,
            "expected_detections": ["invalidCharacters"],
            "forbidden_detections": [],
            "expected_concerns": {"invalidCharacters": 1},
            "rationale": "'#' in '20.0#build' should be flagged as invalid character"
        },
        {
            "description": "Invalid character detection in version field (no skip conditions)",
            "table_index": 17,
            "expected_detections": ["invalidCharacters"],
            "forbidden_detections": [],
            "expected_concerns": {"invalidCharacters": 1},
            "rationale": "'$' in '21.0$stable' should be flagged as invalid character"
        },
        {
            "description": "Invalid character detection in lessThan field (no skip conditions)",
            "table_index": 18,
            "expected_detections": ["invalidCharacters"],
            "forbidden_detections": [],
            "expected_concerns": {"invalidCharacters": 1},
            "rationale": "'@' in '23.0@patch' should be flagged as invalid character"
        },
        {
            "description": "Multi-platform array with different detection types (field-specific behavior)",
            "table_index": 19,
            "expected_detections": ["placeholderData", "mathematicalComparators", "whitespaceIssues"],
            "forbidden_detections": [],
            "expected_concerns": {"placeholderData": 1, "mathematicalComparators": 1, "whitespaceIssues": 1},
            "rationale": "platforms[0]='n/a' (placeholder), platforms[1]='>=Linux' (math), platforms[2]=' Windows ' (whitespace), platforms[3]='Valid-Platform' (none) - each platform array entry should be detected independently"
        },
        {
            "description": "Multi-version array with different detection types (field-specific behavior)",
            "table_index": 20,
            "expected_detections": ["placeholderData", "mathematicalComparators", "whitespaceIssues", "invalidCharacters"],
            "forbidden_detections": [],
            "expected_concerns": {"placeholderData": 1, "mathematicalComparators": 1, "whitespaceIssues": 1, "invalidCharacters": 1},
            "rationale": "versions[0].version='unknown' (placeholder), versions[1].version='<=2.0.0' (math), versions[2].version=' 3.0.0 ' (whitespace), versions[3].version='4.0@build' (invalid) - each version array entry should be detected independently"
        },
        {
            "description": "Single version with multiple changes array entries (deep nesting field-specific behavior)",
            "table_index": 21,
            "expected_detections": ["placeholderData", "mathematicalComparators", "textComparators", "whitespaceIssues", "invalidCharacters"],
            "forbidden_detections": [],
            "expected_concerns": {"placeholderData": 1, "mathematicalComparators": 1, "textComparators": 1, "whitespaceIssues": 1, "invalidCharacters": 1},
            "rationale": "versions[0].changes[0].at='n/a' (placeholder only - skip logic prevents invalid '/'), changes[1].at='>=6.0' (math), changes[2].at='1.0 - 2.0' (text), changes[3].at=' 7.0 ' (whitespace), changes[4].at='8.0#patch' (invalid '#') - each changes array entry should be detected independently"
        },
        {
            "description": "Multi-version with multi-changes arrays (complex nested field-specific behavior)",
            "table_index": 22,
            "expected_detections": ["placeholderData", "mathematicalComparators", "textComparators", "whitespaceIssues", "invalidCharacters"],
            "forbidden_detections": [],
            "expected_concerns": {"placeholderData": 1, "mathematicalComparators": 1, "textComparators": 1, "whitespaceIssues": 1, "invalidCharacters": 1},
            "rationale": "versions[0].changes[0].at='unknown' (placeholder), versions[0].changes[1].at='<=10.0' (math), versions[1].changes[0].at='before 12.0' (text), versions[1].changes[1].at=' 13.0 ' (whitespace), versions[1].changes[2].at='14.0$beta' (invalid) - each nested field should be detected independently"
        },
        {
            "description": "Complex nested arrays with multiple detection types across all levels",
            "table_index": 23,
            "expected_detections": ["placeholderData", "mathematicalComparators", "textComparators", "whitespaceIssues", "invalidCharacters"],
            "forbidden_detections": [],
            "expected_concerns": {"placeholderData": 2, "mathematicalComparators": 2, "textComparators": 2, "whitespaceIssues": 3, "invalidCharacters": 2},
            "rationale": "Complex scenario with detections across platforms, versions, lessThan, and changes arrays - validates complete field-specific behavior across all nesting levels"
        },
        {
            "description": "Control test: No concerns detected (valid data)",
            "table_index": 24,
            "expected_detections": [],
            "forbidden_detections": ["placeholderData", "mathematicalComparators", "textComparators", "whitespaceIssues", "invalidCharacters"],
            "expected_concerns": {},
            "rationale": "Valid data should not trigger any detection groups"
        }
    ]

def validate_test_case(test_case, all_concerns):
    """Validate a single test case against the extracted concerns"""
    # Check expected detections are present
    expected_present = True
    for detection_type in test_case["expected_detections"]:
        if detection_type not in all_concerns:
            expected_present = False
            break
        expected_count = test_case["expected_concerns"].get(detection_type, 0)
        actual_count = len(all_concerns[detection_type])
        if actual_count != expected_count:
            expected_present = False
            break
    
    # Check forbidden detections are absent
    forbidden_absent = True
    for detection_type in test_case["forbidden_detections"]:
        if detection_type in all_concerns and len(all_concerns[detection_type]) > 0:
            forbidden_absent = False
            break
    
    # Check forbidden characters are not in invalid character detection
    forbidden_chars_absent = True
    if "forbidden_chars_in_invalid" in test_case and "invalidCharacters" in all_concerns:
        for concern in all_concerns["invalidCharacters"]:
            if "detectedPattern" in concern and "detectedValue" in concern["detectedPattern"]:
                detected_char = concern["detectedPattern"]["detectedValue"]
                if detected_char in test_case["forbidden_chars_in_invalid"]:
                    forbidden_chars_absent = False
                    break
    
    # Generate output
    status = "✅ PASS" if expected_present and forbidden_absent and forbidden_chars_absent else "❌ FAIL"
    show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
    
    if show_details:
        print(f"{status} - Test: {test_case['description']}")
        print(f"CVE Affected Entry: Table Index {test_case['table_index']} entry")
        
        # Show expected vs found
        expected_str = ', '.join(test_case["expected_detections"]) if test_case["expected_detections"] else "None"
        forbidden_str = ', '.join(test_case["forbidden_detections"]) if test_case["forbidden_detections"] else "None" 
        print(f"Expected Detections: {expected_str}")
        print(f"Forbidden Detections: {forbidden_str}")
        
        found_detections = [det for det in all_concerns.keys() if len(all_concerns[det]) > 0]
        found_str = ', '.join(found_detections) if found_detections else "None"
        print(f"Found Detections: {found_str}")
        
        # Show forbidden character check results
        if "forbidden_chars_in_invalid" in test_case:
            forbidden_chars_str = ', '.join([f"'{char}'" for char in test_case["forbidden_chars_in_invalid"]])
            print(f"Forbidden Chars in Invalid: {forbidden_chars_str}")
            
            if "invalidCharacters" in all_concerns:
                found_chars = []
                for concern in all_concerns["invalidCharacters"]:
                    if "detectedPattern" in concern and "detectedValue" in concern["detectedPattern"]:
                        found_chars.append(f"'{concern['detectedPattern']['detectedValue']}'")
                found_chars_str = ', '.join(found_chars) if found_chars else "None"
                print(f"Found Invalid Chars: {found_chars_str}")
        
        # Validation results
        if expected_present:
            print(f"✅ EXPECTED: All expected detections present with correct counts")
        else:
            print(f"❌ EXPECTED: Missing expected detections or incorrect counts")
        
        if forbidden_absent:
            print(f"✅ FORBIDDEN: No forbidden detections found")
        else:
            print(f"❌ FORBIDDEN: Found forbidden detections")
        
        if forbidden_chars_absent:
            print(f"✅ SKIP LOGIC: Forbidden characters correctly excluded from invalid detection")
        else:
            print(f"❌ SKIP LOGIC: Forbidden characters incorrectly included in invalid detection")
        
        print(f"Rationale: {test_case['rationale']}")
        print()
    
    return expected_present and forbidden_absent and forbidden_chars_absent

def test_skip_logic_rules():
    """Test skip logic rules functionality"""
    # Only show detailed output if not running under unified test runner
    show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
    
    if show_details:
        print("=" * 71)
        print("=" * 9 + " " * 53 + "=" * 9)
        print("SDC SKIP LOGIC RULES TEST SUITE")
        print("=" * 71)
        print("=" * 9 + " " * 53 + "=" * 9)
    
    # Get report data
    report_data = run_test_and_get_report()
    if not report_data:
        print("❌ Failed to get test report")
        return False
    
    if show_details:
        print(f"✅ Report found: {find_latest_test_run_report('sourceDataConcernReport.json') or 'Unknown path'}")
    
    # Run test cases
    test_cases = get_test_cases()
    passed_tests = 0
    total_tests = len(test_cases)
    
    for test_case in test_cases:
        all_concerns = extract_concerns_for_table(report_data, test_case["table_index"])
        if validate_test_case(test_case, all_concerns):
            passed_tests += 1
        else:
            if show_details:
                print(f"[FAIL] {test_case['description']}")
    
    # Print summary
    if show_details:
        status = "PASS" if passed_tests == total_tests else "FAIL"
        print(f"{status} SDC Skip Logic Rules ({passed_tests}/{total_tests} tests)")
        print(f"   {passed_tests}/{total_tests} tests passed")
        print("=" * 71)
        print("=" * 9 + " " * 53 + "=" * 9)
    
    # Print standardized results
    print(f'TEST_RESULTS: PASSED={passed_tests} TOTAL={total_tests} SUITE="SDC Skip Logic Rules"')
    
    return passed_tests == total_tests

if __name__ == "__main__":
    success = test_skip_logic_rules()
    sys.exit(0 if success else 1)