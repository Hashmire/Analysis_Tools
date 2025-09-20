import sys
import os
import json
from pathlib import Path

# Add src to path for absolute imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from analysis_tool.core import badge_modal_system
from analysis_tool.core.analysis_tool import process_test_file
from analysis_tool.storage.nvd_source_manager import get_global_source_manager
from analysis_tool.core import gatherData

# Path to the whitespace detection test file
TEST_FILE = os.path.join(os.path.dirname(__file__), "testWhitespaceDetection.json")

# Ensure NVD Source Manager is initialized for test pipeline
nvd_source_manager = get_global_source_manager()
if not nvd_source_manager.is_initialized():
    nvd_source_data = gatherData.gatherNVDSourceData("")
    nvd_source_manager.initialize(nvd_source_data)

def extract_source_data_concerns():
    # Clear all registries before running
    badge_modal_system.clear_all_registries()
    # Ensure run directory is initialized for test runs
    from analysis_tool.storage.run_organization import create_run_directory, get_current_run_paths
    test_context = "test_whitespace_detection"
    run_path, run_id = create_run_directory(test_context, is_test=True)
    # Run the production pipeline on the test file
    html_path = process_test_file(TEST_FILE)
    # Extract the registry after processing
    registry = badge_modal_system.PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns']
    return registry

def pretty_print_concern_result(table_index, entry, actual, expected, test_name=None):
    test_name = test_name or f"Entry_{table_index}"
    pass_fail = "✅ PASS" if set(actual) == set(expected) else "❌ FAIL"
    print(f"{pass_fail} - Test: {test_name}")
    print(f"  CVE Affected Entry:   {json.dumps(entry, ensure_ascii=False)}")
    print(f"  Expected Data:        {len(expected)} concerns | {expected}")
    print(f"  Found:                {len(actual)} concerns | {actual}")
    checks = []
    match_count = 0
    for exp in expected:
        if exp in actual:
            checks.append(f"    ✅ MATCH FOUND: {exp} - (matches expected)")
            match_count += 1
        else:
            checks.append(f"    ❌ MISSING: {exp} - (expected but not found)")
    
    unexpected_count = 0
    for act in actual:
        if act not in expected:
            checks.append(f"    ⚠️  UNEXPECTED: {act} - (found but not expected)")
            unexpected_count += 1
    
    print(f"  Checks Performed:     {len(expected)} checks | {match_count} concern matches")
    for check in checks:
        print(check)
    
    if unexpected_count > 0:
        print(f"  ⚠️  Note: {unexpected_count} unexpected concerns found")
    print()

def main():
    with open(TEST_FILE, "r", encoding="utf-8") as f:
        test_data = json.load(f)
    affected = test_data["containers"]["cna"]["affected"]
    
    # Hard-coded expected results based on what whitespace detection should find
    # Entry 0: Leading Whitespace Vendor - " TestVendor"
    # Entry 1: Trailing Whitespace Product - "TestProduct "
    # Entry 2: Leading/Trailing Whitespace PackageName - " test-package "
    # Entry 3: Excessive Whitespace Platforms - "  linux  ", "windows  "
    # Entry 4: Leading Whitespace Version - " 1.0.0"
    # Entry 5: Trailing Whitespace lessThan - "2.0.0 "
    # Entry 6: Excessive Whitespace lessThanOrEqual - "3.0.0  "
    # Entry 7: Multiple Whitespace Issues in changes[].at - " 4.0.0", "5.0.0 "
    # Entry 8: Mixed Whitespace Issues Platforms Array - " win32", "macos ", "  linux  "
    # Entry 9: Control Entry - No whitespace issues (should have no concerns)
    # Entry 10: Complex Multiple Version Fields - Multiple whitespace issues
    # Entry 11: Complex Multiple Changes Array - Multiple whitespace issues in changes[].at
    # Entry 12: Comprehensive All Fields - Multiple whitespace issues across all supported fields
    expected_map = {
        0: ["vendor: ' TestVendor' (leading)"],
        1: ["product: 'TestProduct ' (trailing)"],
        2: ["packageName: ' test-package ' (leading/trailing)"],
        3: ["platforms[0]: '  linux  ' (leading/trailing/excessive)", "platforms[1]: 'windows  ' (trailing/excessive)"],
        4: ["versions[0].version: ' 1.0.0' (leading)"],
        5: ["versions[0].lessThan: '2.0.0 ' (trailing)"],
        6: ["versions[0].lessThanOrEqual: '3.0.0  ' (trailing/excessive)"],
        7: ["versions[0].changes[0].at: ' 4.0.0' (leading)", "versions[0].changes[1].at: '5.0.0 ' (trailing)"],
        8: ["platforms[0]: ' win32' (leading)", "platforms[1]: 'macos ' (trailing)", "platforms[2]: '  linux  ' (leading/trailing/excessive)"],
        9: [],  # Control entry - no whitespace issues
        10: [
            "versions[0].version: ' 1.0.0' (leading)",
            "versions[1].version: '2.0.0 ' (trailing)", 
            "versions[2].lessThan: '  3.0.0' (leading/excessive)"
        ],
        11: [
            "versions[0].changes[0].at: ' 6.0.0' (leading)",
            "versions[0].changes[1].at: '7.0.0 ' (trailing)",
            "versions[0].changes[2].at: '  8.0.0  ' (leading/trailing/excessive)"
        ],
        12: [
            "vendor: ' TestVendor' (leading)",
            "product: 'TestProduct ' (trailing)",
            "packageName: '  test-pkg  ' (leading/trailing/excessive)",
            "platforms[0]: ' win32' (leading)",
            "platforms[1]: 'macos ' (trailing)",
            "versions[0].version: ' 1.0.0' (leading)",
            "versions[0].lessThan: '2.0.0 ' (trailing)",
            "versions[0].lessThanOrEqual: '  3.0.0  ' (leading/trailing/excessive)",
            "versions[0].changes[0].at: ' 4.0.0' (leading)",
            "versions[0].changes[1].at: '5.0.0 ' (trailing)"
        ]
    }
    
    # Test descriptions
    test_titles = {
        0: "Leading Whitespace: Vendor with leading space",
        1: "Trailing Whitespace: Product with trailing space",
        2: "Leading/Trailing Whitespace: PackageName with both",
        3: "Excessive Whitespace: Platforms with multiple spaces",
        4: "Leading Whitespace: Version field",
        5: "Trailing Whitespace: lessThan field", 
        6: "Excessive Whitespace: lessThanOrEqual field",
        7: "Multiple Issues: changes[].at fields",
        8: "Array Issues: Multiple platform whitespace issues",
        9: "Control Test: No whitespace issues (should have no concerns)",
        10: "Multiple Version Fields: Whitespace across version array",
        11: "Multiple Changes Array: Whitespace in changes[].at array", 
        12: "Comprehensive All Fields: Whitespace across all supported fields"
    }
    
    registry = extract_source_data_concerns()
    total = len(affected)
    passed = 0
    failed = 0
    
    for idx, entry in enumerate(affected):
        actual = []
        if idx in registry:
            # Check what types of concerns exist
            concerns_data = registry[idx].get('concerns', {})
            
            # Look for whitespace data in the new dedicated whitespaceIssues concern type
            whitespace_data = registry[idx].get('concerns', {}).get('whitespaceIssues', [])
            
            # Process whitespace concerns
            for concern in whitespace_data:
                # Our new whitespace detection stores the data in a structured format
                field = concern.get('field', '')
                source_value = concern.get('sourceValue', '')
                detected_pattern = concern.get('detectedPattern', '')
                
                # For comparison purposes, format as field: detectedPattern
                actual.append(f"{field}: {detected_pattern}")
        
        expected = expected_map.get(idx, [])
        is_pass = set(actual) == set(expected)
        if is_pass:
            passed += 1
        else:
            failed += 1
        
        test_title = test_titles.get(idx, f"Test {idx}")
        pretty_print_concern_result(idx, entry, actual, expected, test_title)
    
    percent = (passed / total) * 100
    print(f"=== Test Summary ===")
    print(f"TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE=\"SDC WHITESPACE DETECTION\"")
    print(f"Failed:  {failed}")
    print(f"Percent: {percent:.1f}%\n")

if __name__ == "__main__":
    main()