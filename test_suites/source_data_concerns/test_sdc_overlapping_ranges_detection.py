#!/usr/bin/env python3
"""
SDC Overlapping Ranges Detection Test Suite

Tests overlapping ranges detection by running test file and checking sourceDataConcernReport.json
Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Usage:
    python test_files/test_overlapping_ranges.py
"""

import sys
import os
import json
import subprocess
import glob
from pathlib import Path

# Add src path for analysis_tool imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
from analysis_tool.storage.run_organization import find_latest_test_run_report

# Path to the overlapping ranges detection test file
TEST_FILE = os.path.join(os.path.dirname(__file__), "testOverlappingRanges.json")

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
        print(f"❌ Test execution failed: {e}")
        return None

def get_test_cases():
    """Define test cases with expected results based on testOverlappingRanges.json"""
    return [
        {
            "description": "Wildcard Multiple Bounds: Multiple * patterns with different bounds",
            "table_index": 0,
            "expected_concerns": 1,
            "expected_field": "versions",
            "expected_overlap_type": "wildcard_multiple_bounds",
            "expected_branches": ["1.5.0", "2.0.0", "3.0.0"]
        },
        {
            "description": "Identical Ranges: Exact same version ranges",
            "table_index": 1,
            "expected_concerns": 1,
            "expected_field": "versions",
            "expected_source_value": "versions[0] & versions[1]",
            "expected_overlap_type": "identical_ranges",
            "expected_range1": "1.0.0 to 2.0.0",
            "expected_range2": "1.0.0 to 2.0.0"
        },
        {
            "description": "Partial Overlap: Ranges that partially overlap",
            "table_index": 2,
            "expected_concerns": 1,
            "expected_field": "versions",
            "expected_source_value": "versions[0] & versions[1]",
            "expected_overlap_type": "partial_overlap",
            "expected_range1": "1.0.0 to 3.0.0",
            "expected_range2": "2.0.0 to 4.0.0"
        },
        {
            "description": "Range Containment: One range contains another",
            "table_index": 3,
            "expected_concerns": 1,
            "expected_field": "versions",
            "expected_source_value": "versions[0] & versions[1]",
            "expected_overlap_type": "range1_contains_range2",
            "expected_range1": "1.0.0 to 5.0.0",
            "expected_range2": "2.0.0 to 3.0.0"
        },
        {
            "description": "Update Pattern Overlaps: Update patterns with overlaps",
            "table_index": 4,
            "expected_concerns": 1,
            "expected_field": "versions",
            "expected_source_value": "versions[0] & versions[1]",
            "expected_overlap_type": "identical_ranges",
            "expected_range1": "1.0.0 to 2.0.0",
            "expected_range2": "1.0.0 to 2.0.0"
        },
        {
            "description": "Changes Array: No overlapping ranges expected",
            "table_index": 5,
            "expected_concerns": 0
        },
        {
            "description": "Cross Entry Case 1: No overlapping ranges within entry",
            "table_index": 6,
            "expected_concerns": 0
        },
        {
            "description": "Cross Entry Case 2: No overlapping ranges within entry", 
            "table_index": 7,
            "expected_concerns": 0
        },
        {
            "description": "Repo Package Entry 1: No overlapping ranges within entry",
            "table_index": 8,
            "expected_concerns": 0
        },
        {
            "description": "Repo Package Entry 2: No overlapping ranges within entry",
            "table_index": 9,
            "expected_concerns": 0
        },
        {
            "description": "No Overlap Vendor A: No overlapping ranges expected",
            "table_index": 10,
            "expected_concerns": 0
        },
        {
            "description": "No Overlap Vendor B: No overlapping ranges expected",
            "table_index": 11,
            "expected_concerns": 0
        },
        {
            "description": "Complex Mixed Overlaps: Mixed wildcard and numeric patterns",
            "table_index": 12,
            "expected_concerns": 1,
            "expected_field": "versions",
            "expected_source_value": "versions[1] & versions[2]",
            "expected_overlap_type": "partial_overlap",
            "expected_range1": "1.0.0 to 1.5.0",
            "expected_range2": "1.2.0 to 1.8.0"
        },
        {
            "description": "Version Granularity Overlaps: Fine-grained version overlaps",
            "table_index": 13,
            "expected_concerns": 1,
            "expected_field": "versions",
            "expected_source_value": "versions[0] & versions[1]",
            "expected_overlap_type": "range1_contains_range2",
            "expected_range1": "2.1.0 to 2.2.0",
            "expected_range2": "2.1.5 to 2.1.8"
        },
        {
            "description": "Edge Case Boundary: No overlapping ranges (adjacent)",
            "table_index": 14,
            "expected_concerns": 0
        },
        {
            "description": "Edge Case LessThanOrEqual: Overlapping at boundary",
            "table_index": 15,
            "expected_concerns": 1,
            "expected_field": "versions",
            "expected_source_value": "versions[0] & versions[1]",
            "expected_overlap_type": "partial_overlap",
            "expected_range1": "1.0.0 to 2.0.0",
            "expected_range2": "2.0.0 to 3.0.0"
        },
        {
            "description": "Single Versions: No overlapping ranges expected",
            "table_index": 16,
            "expected_concerns": 0
        },
        {
            "description": "Complex Update Patterns: Update pattern overlaps",
            "table_index": 17,
            "expected_concerns": 1,
            "expected_field": "versions",
            "expected_source_value": "versions[0] & versions[1]",
            "expected_overlap_type": "identical_ranges",
            "expected_range1": "1.0.0 to 1.1.0",
            "expected_range2": "1.0.0 to 1.1.0"
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
        # Extract overlapping ranges concerns
        concerns = []
        for concern_detail in platform_entry.get('concerns_detail', []):
            if concern_detail.get('concern_type') == 'overlappingRanges':
                concerns.extend(concern_detail.get('concerns', []))
        
        # Test count validation
        count_match = len(concerns) == test_case['expected_concerns']
        
        # If no concerns expected, just check count
        if test_case['expected_concerns'] == 0:
            structure_match = True
            value_match = True
        else:
            # Structure and value validation
            structure_match = True
            value_match = True
            
            if test_case['expected_concerns'] == 1:
                # Single concern case
                if len(concerns) == 1:
                    concern = concerns[0]
                    structure_match = all(key in concern for key in ['field', 'detectedPattern'])
                    if structure_match:
                        pattern = concern['detectedPattern']
                        structure_match = 'overlapType' in pattern
                        
                        if structure_match:
                            # Validate based on overlap type
                            overlap_type = pattern['overlapType']
                            field_match = concern['field'] == test_case['expected_field']
                            type_match = overlap_type == test_case['expected_overlap_type']
                            
                            # Type-specific validation
                            if overlap_type == 'wildcard_multiple_bounds':
                                branches_match = set(pattern.get('branches', [])) == set(test_case.get('expected_branches', []))
                                value_match = field_match and type_match and branches_match
                            else:
                                source_value_match = concern.get('sourceValue') == test_case.get('expected_source_value', '')
                                range1_match = pattern.get('range1') == test_case.get('expected_range1', '')
                                range2_match = pattern.get('range2') == test_case.get('expected_range2', '')
                                value_match = field_match and type_match and source_value_match and range1_match and range2_match
                else:
                    structure_match = False
            else:
                # Multiple concerns case - not expected in current test set
                structure_match = False
    
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
            expected_format = "No overlapping ranges should be detected"
        else:
            overlap_type = test_case['expected_overlap_type']
            if overlap_type == 'wildcard_multiple_bounds':
                expected_format = f"field: '{test_case['expected_field']}', detectedPattern: {{overlapType: '{overlap_type}', branches: {test_case.get('expected_branches', [])}}}"
            else:
                expected_format = f"field: '{test_case['expected_field']}', sourceValue: '{test_case.get('expected_source_value', '')}', detectedPattern: {{overlapType: '{overlap_type}', range1: '{test_case.get('expected_range1', '')}', range2: '{test_case.get('expected_range2', '')}'}}"
        
        print(f"Expected Data: {test_case['expected_concerns']} concerns | {expected_format}")
        
        # Found data format
        if concerns:
            concern = concerns[0]
            pattern = concern['detectedPattern']
            overlap_type = pattern['overlapType']
            if overlap_type == 'wildcard_multiple_bounds':
                found_format = f"field: '{concern['field']}', detectedPattern: {{overlapType: '{overlap_type}', branches: {pattern.get('branches', [])}}}"
            else:
                found_format = f"field: '{concern['field']}', sourceValue: '{concern.get('sourceValue', '')}', detectedPattern: {{overlapType: '{overlap_type}', range1: '{pattern.get('range1', '')}', range2: '{pattern.get('range2', '')}'}}"
            print(f"Found: {len(concerns)} concerns | {found_format}")
        else:
            print(f"Found: {len(concerns)} concerns | No concerns found")
        
        # Detailed validation results
        if count_match:
            print(f"✅ COUNT: {len(concerns)} concerns - (matches expected)")
        else:
            print(f"❌ COUNT: {len(concerns)} concerns - (expected {test_case['expected_concerns']})")
        
        if structure_match:
            print(f"✅ STRUCTURE: field/detectedPattern.overlapType - (matches expected)")
        else:
            print(f"❌ STRUCTURE: Missing or invalid structure - (expected field/detectedPattern.overlapType)")
        
        if value_match:
            print(f"✅ VALUES: All values match expected - (matches expected)")
        else:
            print(f"❌ VALUES: Value validation failed - (values do not match expected)")
        
        print()
    
    return count_match and structure_match and value_match

def test_overlapping_ranges_detection():
    """Test overlapping ranges detection functionality"""
    # Only show detailed output if not running under unified test runner
    show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
    
    if show_details:
        print("================================================================================")
        print("OVERLAPPING RANGES DETECTION TEST SUITE")
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
            print(f"PASS SDC Overlapping Ranges Detection (test duration) ({passed}/{total} tests)")
            print(f"   {passed}/{total} tests passed")
            print(f"   Test breakdown: {positive_tests} positive cases, {negative_tests} negative cases")
        else:
            print(f"FAIL SDC Overlapping Ranges Detection (test duration) ({passed}/{total} tests)")
            print(f"   {passed}/{total} tests passed")
            print(f"   Test breakdown: {positive_tests} positive cases, {negative_tests} negative cases")
        
        print("================================================================================")
    
    # Output standardized test results for run_all_tests.py
    print(f'TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE="SDC Overlapping Ranges Detection"')
    
    return success

if __name__ == "__main__":
    success = test_overlapping_ranges_detection()
    sys.exit(0 if success else 1)
