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

# Path to the dedicated version granularity detection test file
TEST_FILE = os.path.join(os.path.dirname(__file__), "testVersionGranularityDetection.json")

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
    test_context = "test_version_granularity_detection"
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
            checks.append(f"    ❌ NO MATCH: {exp} not found in actual")
    for act in actual:
        if act not in expected:
            checks.append(f"    ❌ UNEXPECTED: {act} found but not expected")
    print(f"  Checks Performed:     {len(checks)} checks | {match_count} concern matches")
    for c in checks:
        print(c)
    print()

def main():
    with open(TEST_FILE, "r", encoding="utf-8") as f:
        test_data = json.load(f)
    affected = test_data["containers"]["cna"]["affected"]
    
    # Hard-coded expected results based on what version granularity detection should find
    # Entry 0: Basic Mixed Granularity - "1.0" (2-part), "1.0.1" (3-part), "2" (1-part), "1.0.1.0" (4-part)
    # Base "1": "1.0" (2-part), "1.0.1" (3-part), "1.0.1.0" (4-part) - 3 concerns (inconsistent)
    # Base "2": "2" (1-part) - only one granularity, no concerns
    # 
    # Entry 1: All Supported Fields - "1.0" (2-part), "1.0.1" (3-part), "1.0.1.0" (4-part), "1.0.1.0.5" (5-part), "1.1.0" (3-part), "1.1.0.0.1" (5-part)
    # Base "1": all different granularities - 6 concerns
    #
    # Entry 2: Edge Cases - "3" (1-part), "3.0" (2-part), "3.0.0...1" (15-part), "3.1.2...15" (16-part), "5" (1-part), "5.0.0...0" (17-part)
    # Base "3": "3" (1-part), "3.0" (2-part), "3.0.0...1" (15-part), "3.1.2...15" (16-part) - 4 concerns
    # Base "5": "5" (1-part), "5.0.0...0" (17-part) - 2 concerns
    #
    # Entry 3: Multiple Base Versions - "1.0" (2-part), "1.0.1" (3-part), "2.1" (2-part), "2.1.0" (3-part), "10" (1-part), "10.0.0.0.0" (5-part)
    # Base "1": "1.0" (2-part), "1.0.1" (3-part) - 2 concerns
    # Base "2": "2.1" (2-part), "2.1.0" (3-part) - 2 concerns  
    # Base "10": "10" (1-part), "10.0.0.0.0" (5-part) - 2 concerns
    #
    # Entry 4: Multi Product A - "4.0" (2-part), "4.0.1.2" (4-part)
    # Base "4": "4.0" (2-part), "4.0.1.2" (4-part) - 2 concerns
    #
    # Entry 5: Multi Product B - "6" (1-part), "6.1.0" (3-part)
    # Base "6": "6" (1-part), "6.1.0" (3-part) - 2 concerns
    #
    # Entry 6: Negative Case - Consistent Granularity - "7.1.0", "7.2.0", "7.3.0", "7.4.0" (all 3-part)
    # Base "7": all same granularity - NO concerns (this is the negative test)
    #
    # Entry 7: Single Version - "8.0" (only one version)
    # Base "8": only one version - NO concerns (no comparison possible)
    #
    # Entry 8: Wildcards - "*", "" (empty)
    # Base: no numeric versions - NO concerns (wildcards/empty strings ignored)
    #
    # Entry 9: Complex Nested Changes - "9.0" (2-part) with changes "9.0.1" (3-part), "9.0.1.0" (4-part), "9.0.1.0.1" (5-part)
    #                                    "9.1.0.0" (4-part) with changes "9.1.0.0.0" (5-part), "9.1.0.0.0.1" (6-part)
    # Base "9": "9.0" (2-part), "9.0.1" (3-part), "9.0.1.0" (4-part), "9.0.1.0.1" (5-part), "9.1.0.0" (4-part), "9.1.0.0.0" (5-part), "9.1.0.0.0.1" (6-part) - 7 concerns
    #
    # Entry 10: Multiple Fields Per Entry - "11.0" (2-part), "11.0.1.0" (4-part), "11.0.1.0.5" (5-part), "11.1.0.0.0" (5-part)
    # Base "11": "11.0" (2-part), "11.0.1.0" (4-part), "11.0.1.0.5" (5-part), "11.1.0.0.0" (5-part) - 4 concerns
    #
    # Entry 11: Complex Base Grouping - "1.0" (2-part), "11.0" (2-part), "11.0.1" (3-part), "100" (1-part), "100.0.0" (3-part), "1000.1" (2-part)
    # Base "1": "1.0" (2-part) - only one, no concerns
    # Base "11": "11.0" (2-part), "11.0.1" (3-part) - 2 concerns
    # Base "100": "100" (1-part), "100.0.0" (3-part) - 2 concerns
    # Base "1000": "1000.1" (2-part) - only one, no concerns
    expected_map = {
        0: [
            "version: '1.0' (base: 1, granularity: 2)",
            "version: '1.0.1' (base: 1, granularity: 3)", 
            "version: '1.0.1.0' (base: 1, granularity: 4)"
        ],
        1: [
            "version: '1.0' (base: 1, granularity: 2)",
            "version: '1.0.1' (base: 1, granularity: 3)",
            "lessThan: '1.0.1.0' (base: 1, granularity: 4)",
            "lessThanOrEqual: '1.0.1.0.5' (base: 1, granularity: 5)",
            "version: '1.1' (base: 1, granularity: 2)",
            "changes[0].at: '1.1.0' (base: 1, granularity: 3)",
            "changes[1].at: '1.1.0.0.1' (base: 1, granularity: 5)"
        ],
        2: [
            "version: '3' (base: 3, granularity: 1)",
            "version: '3.0' (base: 3, granularity: 2)",
            "lessThan: '3.0.0.0.0.0.0.0.0.0.0.0.0.0.1' (base: 3, granularity: 15)",
            "lessThanOrEqual: '3.1.2.3.4.5.6.7.8.9.10.11.12.13.14.15' (base: 3, granularity: 16)",
            "version: '5' (base: 5, granularity: 1)",
            "changes[0].at: '5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0' (base: 5, granularity: 17)"
        ],
        3: [
            "version: '1.0' (base: 1, granularity: 2)",
            "version: '1.0.1' (base: 1, granularity: 3)",
            "version: '2.1' (base: 2, granularity: 2)",
            "version: '2.1.0' (base: 2, granularity: 3)",
            "version: '10' (base: 10, granularity: 1)",
            "lessThan: '10.0.0.0.0' (base: 10, granularity: 5)"
        ],
        4: [
            "version: '4.0' (base: 4, granularity: 2)",
            "version: '4.0.1.2' (base: 4, granularity: 4)"
        ],
        5: [
            "version: '6' (base: 6, granularity: 1)",
            "lessThanOrEqual: '6.1.0' (base: 6, granularity: 3)"
        ],
        6: [],  # Negative case: consistent granularity - no concerns expected
        7: [],  # Negative case: single version - no concerns expected  
        8: [],  # Negative case: wildcards/empty - no concerns expected
        9: [
            "version: '9.0' (base: 9, granularity: 2)",
            "changes[0].at: '9.0.1' (base: 9, granularity: 3)",
            "changes[1].at: '9.0.1.0' (base: 9, granularity: 4)",
            "changes[2].at: '9.0.1.0.1' (base: 9, granularity: 5)",
            "version: '9.1.0.0' (base: 9, granularity: 4)",
            "changes[0].at: '9.1.0.0.0' (base: 9, granularity: 5)",
            "changes[1].at: '9.1.0.0.0.1' (base: 9, granularity: 6)"
        ],
        10: [
            "version: '11.0' (base: 11, granularity: 2)",
            "lessThan: '11.0.1.0' (base: 11, granularity: 4)",
            "lessThanOrEqual: '11.0.1.0.5' (base: 11, granularity: 5)",
            "version: '11.1.0.0.0' (base: 11, granularity: 5)"
        ],
        11: [
            "version: '11.0' (base: 11, granularity: 2)",
            "version: '11.0.1' (base: 11, granularity: 3)",
            "version: '100' (base: 100, granularity: 1)",
            "version: '100.0.0' (base: 100, granularity: 3)"
        ]
    }
    
    test_titles = {
        0: "Basic Mixed Granularities: 1.0, 1.0.1, 2, 1.0.1.0",
        1: "All Supported Fields: version, lessThan, lessThanOrEqual, changes[].at", 
        2: "Edge Cases: Single digits, 15+ granularity levels",
        3: "Multiple Base Versions: 1.x, 2.x, 10.x with different patterns",
        4: "Multi Product A: Mixed granularities",
        5: "Multi Product B: Different granularity patterns",
        6: "Negative Test: Consistent Granularity (should have no concerns)",
        7: "Negative Test: Single Version (should have no concerns)",
        8: "Negative Test: Wildcards/Empty (should have no concerns)",
        9: "Complex Nested Changes Arrays: Multiple changes per version",
        10: "Multiple Fields Per Entry: Combined version fields in single entry",
        11: "Complex Base Grouping: 1.x vs 11.x vs 100.x vs 1000.x"
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
            
            # Look for version granularity data in the correct location
            vg_data = registry[idx].get('concerns', {}).get('versionGranularity', [])
            
            # Process version granularity concerns using the new detectedPattern structure
            for concern in vg_data:
                field = concern.get('field', 'unknown')
                source_value = concern.get('sourceValue', 'unknown')
                detected_pattern = concern.get('detectedPattern', {})
                base = detected_pattern.get('base', 'unknown')
                granularity = detected_pattern.get('granularity', 'unknown')
                actual.append(f"{field}: '{source_value}' (base: {base}, granularity: {granularity})")
        
        expected = expected_map.get(idx, [])
        is_pass = set(actual) == set(expected)
        if is_pass:
            passed += 1
        else:
            failed += 1
            
        test_title = test_titles.get(idx, f"Entry_{idx}")
        pretty_print_concern_result(idx, entry, actual, expected, test_name=f"Entry_{idx} | {test_title}")
    
    percent = (passed / total) * 100 if total > 0 else 0
    print("\n=== Test Summary ===")
    print(f"TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE=\"SDC VERSION GRANULARITY DETECTION\"")
    print(f"Failed:  {failed}")
    print(f"Percent: {percent:.1f}%\n")

if __name__ == "__main__":
    main()
