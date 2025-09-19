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

# Path to the comparator detection test file
TEST_FILE = os.path.join(os.path.dirname(__file__), "testComparatorDetection.json")

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
    test_context = "test_comparator_detection"
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
    expected_map = {
        0: ["vendor: 'foo>=bar' (>, =, >=)"],
        1: ["product: 'baz<=qux' (<, =, <=)"],
        2: ["packageName: 'lib=core' (=)"],
        3: ["platforms[0]: '>=linux' (>, =, >=)"],
        4: ["versions[0].version: '<1.2.3' (<)"],
        5: ["versions[0].lessThan: '>=6.0.0' (>, =, >=)"],
        6: ["versions[0].lessThanOrEqual: '!=8.0.0' (=, !=)"],
        7: ["versions[0].changes[0].at: '=10.0.0' (=)"],
        8: ["platforms[1]: '<macos' (<)"],
        9: [],
        10: [
            "versions[0].version: '>=1.0.0' (>, =, >=)",
            "versions[1].version: '<=2.0.0' (<, =, <=)",
            "versions[2].lessThan: '!=4.0.0' (=, !=)"
        ],
        11: [
            "versions[0].changes[0].at: '>6.0.0' (>)",
            "versions[0].changes[1].at: '<=7.0.0' (<, =, <=)",
            "versions[0].changes[2].at: '!=8.0.0' (=, !=)"
        ],
        12: [
            "packageName: 'lib=core' (=)",
            "platforms[0]: '<win32' (<)",
            "platforms[1]: '>=linux' (>, =, >=)",
            "versions[0].version: '<1.0.0' (<)",
            "versions[0].lessThan: '>2.0.0' (>)",
            "versions[0].lessThanOrEqual: '=<3.0.0' (<, =, =<)",
            "versions[0].changes[0].at: '!=4.0.0' (=, !=)",
            "versions[0].changes[1].at: '=5.0.0' (=)",
            "versions[1].version: '>=6.0.0' (>, =, >=)",
            "versions[1].lessThan: '<=7.0.0' (<, =, <=)",
            "versions[1].lessThanOrEqual: '=>8.0.0' (>, =, =>)",
            "versions[1].changes[0].at: '<9.0.0' (<)",
            "versions[1].changes[1].at: '>=10.0.0' (>, =, >=)"
        ]
    }
    test_titles = {
        0: "Vendor: foo>=bar",
        1: "Product: baz<=qux",
        2: "PackageName: lib=core",
        3: "Platforms: >=linux",
        4: "Version: <1.2.3",
        5: "lessThan: >=6.0.0",
        6: "lessThanOrEqual: !=8.0.0",
        7: "changes[0].at: =10.0.0",
        8: "Platforms: <macos",
        9: "Control: No comparators (valid data)",
        10: "Multiple versions array with comparators",
        11: "Multiple changes array with comparators",
        12: "Comprehensive: multiple comparators in all nested arrays"
    }
    registry = extract_source_data_concerns()
    total = len(affected)
    passed = 0
    failed = 0
    for idx, entry in enumerate(affected):
        actual = []
        if idx in registry:
            comparator_data = registry[idx].get('concerns', {}).get('versionComparators', [])
            enhanced_actual = []
            versions = entry.get('versions', [])
            platforms = entry.get('platforms', [])
            for c in comparator_data:
                field = c['field']
                value = c['sourceValue']
                detected = c['detectedPattern']
                found = False
                # Handle version fields with index
                if field in ('version', 'lessThan', 'lessThanOrEqual'):
                    for v_idx, v in enumerate(versions):
                        for f in ('version', 'lessThan', 'lessThanOrEqual'):
                            if f == field and v.get(f) == value:
                                enhanced_actual.append(f"versions[{v_idx}].{field}: '{value}' ({detected})")
                                found = True
                                break
                        if found:
                            break
                    if not found:
                        enhanced_actual.append(f"{field}: '{value}' ({detected})")
                elif field.startswith('changes['):
                    # Already has index, but may need to be nested under versions
                    # Try to find which version this change belongs to
                    for v_idx, v in enumerate(versions):
                        changes = v.get('changes', [])
                        for c_idx, change in enumerate(changes):
                            if f"changes[{c_idx}].at" == field and change.get('at') == value:
                                enhanced_actual.append(f"versions[{v_idx}].{field}: '{value}' ({detected})")
                                found = True
                                break
                        if found:
                            break
                    if not found:
                        enhanced_actual.append(f"{field}: '{value}' ({detected})")
                elif field == 'platforms':
                    # Try to find which index in platforms array
                    for p_idx, p in enumerate(platforms):
                        if p == value:
                            enhanced_actual.append(f"platforms[{p_idx}]: '{value}' ({detected})")
                            found = True
                            break
                    if not found:
                        enhanced_actual.append(f"platforms: '{value}' ({detected})")
                else:
                    enhanced_actual.append(f"{field}: '{value}' ({detected})")
            actual = enhanced_actual
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
    print(f"TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE=\"SDC COMPARATOR DETECTION\"")
    print(f"Failed:  {failed}")
    print(f"Percent: {percent:.1f}%\n")

if __name__ == "__main__":
    main()
