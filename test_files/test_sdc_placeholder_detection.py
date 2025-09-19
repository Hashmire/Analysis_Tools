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

# Path to the placeholder detection test file
TEST_FILE = os.path.join(os.path.dirname(__file__), "testPlaceholderDetection.json")

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
    test_context = "test_platform_detection"
    run_path, run_id = create_run_directory(test_context, is_test=True)
    # Set global run paths for test processing (if needed by pipeline)
    # Run the production pipeline on the test file
    html_path = process_test_file(TEST_FILE)
    # Extract the registry after processing
    registry = badge_modal_system.PLATFORM_ENTRY_NOTIFICATION_REGISTRY['sourceDataConcerns']
    return registry

def pretty_print_concern_result(table_index, entry, actual, expected, test_name=None):
    # Compose output for a single affected entry in requested format
    test_name = test_name or f"Entry_{table_index}"
    pass_fail = "✅ PASS" if set(actual) == set(expected) else "❌ FAIL"
    # Output with aligned columns
    print(f"{pass_fail} - Test: {test_name}")
    print(f"  CVE Affected Entry:   {json.dumps(entry, ensure_ascii=False)}")
    print(f"  Expected Data:        {len(expected)} concerns | {expected}")
    print(f"  Found:                {len(actual)} concerns | {actual}")
    checks = []
    match_count = 0
    # Check expected placeholder concerns
    for exp in expected:
        if exp in actual:
            checks.append(f"    ✅ MATCH FOUND: {exp} - (matches expected)")
            match_count += 1
        else:
            checks.append(f"    ❌ NO MATCH: {exp} not found in actual")
    # Check for unexpected concerns
    for act in actual:
        if act not in expected:
            checks.append(f"    ❌ UNEXPECTED: {act} found but not expected")

    # For comprehensive/mixed tests, print explicit NO MATCH for valid values that are not detected
    # Only for the comprehensive test (Entry_14)
    if table_index == 14:
        # List of valid values in the comprehensive entry
        valid_checks = [
            ("platforms: 'Windows'", "platforms", "Windows"),
            ("platforms: 'Linux'", "platforms", "Linux"),
            ("changes[1].at: '1.2.3'", "changes[1].at", "1.2.3"),
            ("version: '1.2.3'", "version", "1.2.3"),
        ]
        for label, field, value in valid_checks:
            # Compose the concern string as it would appear if detected
            concern_str = f"{field}: '{value}'"
            # For changes[1].at, the concern string is changes[1].at: '1.2.3'
            if field.startswith("changes"):
                concern_str = label
            if concern_str not in actual:
                checks.append(f"    ✅ NO MATCH: {label} - (no match expected)")
            else:
                checks.append(f"    ❌ UNEXPECTED: {label} was incorrectly detected as a concern")

    print(f"  Checks Performed:     {len(checks)} checks | {match_count} concern matches")
    for c in checks:
        print(c)
    print()

def main():
    # Load the test file and get affected entries
    with open(TEST_FILE, "r", encoding="utf-8") as f:
        test_data = json.load(f)
    affected = test_data["containers"]["cna"]["affected"]
    # Define expected concerns for each entry (by index)
    expected_map = {
        0: ["vendor: 'n/a'"],
        1: ["product: 'N/A'"],
        2: ["packageName: 'unknown'"],
    3: ["platforms[0]: 'unspecified'"],
        4: ["versions[0].version: 'unknown'"],

        5: ["vendor: 'N/A'"],
        6: ["product: 'n/a'"],
        7: ["packageName: 'N/A'"],
    8: ["platforms[0]: 'N/A'"],
        9: ["versions[0].version: 'N/A'"],

        10: ["vendor: 'n/a'", "product: 'N/A'", "versions[0].version: 'unknown'"],
    11: ["platforms[0]: 'unspecified'", "platforms[1]: 'various'", "platforms[2]: 'none'"],
        12: ["vendor: 'n/a'", "versions[0].version: 'none'", "versions[1].version: 'unknown'"],
    13: ["versions[0].changes[0].at: 'unspecified'", "versions[0].changes[1].at: 'unknown'"],

        14: [
            "vendor: 'n/a'",
            "product: 'not available'",
            "packageName: 'unknown'",
            "platforms[0]: 'various'",
            "platforms[1]: 'unspecified'",
            "versions[0].version: 'undefined'",
            "versions[0].lessThan: 'pending'",
            "versions[0].changes[0].at: 'tbd'"
        ],

        15: [],
        16: [],
    }

    # Titles for each test case
    test_titles = {
        0: "Vendor: n/a",
        1: "Product: N/A",
        2: "PackageName: unknown",
        3: "Platforms: unspecified",
        4: "Version: unknown",

        5: "Vendor: N/A (case variant)",
        6: "Product: n/a (case variant)",
        7: "PackageName: N/A (case variant)",
        8: "Platforms: N/A (case variant)",
        9: "Version: N/A (case variant)",

        10: "Compound: vendor/product/version placeholders",
        11: "Compound: multiple platforms placeholders",
        12: "Compound: multiple version placeholders",
        13: "Compound: multiple changes placeholders",

        14: "Comprehensive: all fields, multi-placeholder",

        15: "Control: No placeholders (valid data)",
        16: "Control: No placeholders (valid data)",
    }
    # Run the pipeline and extract registry
    registry = extract_source_data_concerns()

    # Track pass/fail for summary
    total = len(affected)
    passed = 0
    failed = 0
    for idx, entry in enumerate(affected):
        actual = []
        if idx in registry:
            placeholder_data = registry[idx].get('concerns', {}).get('placeholderData', [])
            # Enhance output: include array indices for versions/changes fields
            enhanced_actual = []
            # If entry has versions, build a mapping from id(placeholder_data item) to (version_idx, change_idx)
            versions = entry.get('versions', [])
            platforms = entry.get('platforms', [])
            for c in placeholder_data:
                field = c['field']
                value = c['sourceValue']
                found = False
                # Version fields with index
                if field in ('version', 'lessThan', 'lessThanOrEqual'):
                    for v_idx, v in enumerate(versions):
                        for f in ('version', 'lessThan', 'lessThanOrEqual'):
                            if f == field and v.get(f) == value:
                                enhanced_actual.append(f"versions[{v_idx}].{field}: '{value}'")
                                found = True
                                break
                        if found:
                            break
                    if not found:
                        enhanced_actual.append(f"{field}: '{value}'")
                # Changes fields with index (nested under versions)
                elif field.startswith('changes['):
                    for v_idx, v in enumerate(versions):
                        changes = v.get('changes', [])
                        for c_idx, change in enumerate(changes):
                            if f"changes[{c_idx}].at" == field and change.get('at') == value:
                                enhanced_actual.append(f"versions[{v_idx}].{field}: '{value}'")
                                found = True
                                break
                        if found:
                            break
                    if not found:
                        enhanced_actual.append(f"{field}: '{value}'")
                # Platforms fields with index
                elif field == 'platforms':
                    for p_idx, p in enumerate(platforms):
                        if p == value:
                            enhanced_actual.append(f"platforms[{p_idx}]: '{value}'")
                            found = True
                            break
                    if not found:
                        enhanced_actual.append(f"platforms: '{value}'")
                else:
                    enhanced_actual.append(f"{field}: '{value}'")
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
    print(f"TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE=\"SDC PLACEHOLDER DETECTION\"")
    print(f"Failed:  {failed}")
    print(f"Percent: {percent:.1f}%\n")

if __name__ == "__main__":
    main()
