#!/usr/bin/env python3
"""
Test: Wildcard Expansion Detection in Unaffected Entries

Validates that wildcard expansion patterns (e.g., "6.12.*") in range fields
are properly detected and added to concerns array even when status='unaffected'.

This test addresses the issue where unaffected entries with wildcards in
lessThan/lessThanOrEqual fields were missing the inferredAffectedFromWildcardExpansion concern.
"""

import json
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root / 'src'))
os.chdir(project_root)  # Change to project root for imports

from analysis_tool.core.cpe_as_generator import handle_pattern_3_4


def test_unaffected_with_wildcard_in_lessThanOrEqual():
    """Test that unaffected entries with wildcards in lessThanOrEqual get the wildcard concern."""
    
    print("\n" + "="*80)
    print("TEST: Unaffected Entry with Wildcard in lessThanOrEqual")
    print("="*80)
    
    # Simulate the Linux kernel affected entry from user's example
    affected_entry = {
        "vendor": "Linux",
        "product": "Linux",
        "defaultStatus": "affected",
    }
    
    cpe_base_string = "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
    
    # Test versions similar to user's data
    versions = [
        {
            "version": "6.12.67",
            "lessThanOrEqual": "6.12.*",
            "status": "unaffected",
            "versionType": "semver"
        },
        {
            "version": "6.18.7",
            "lessThanOrEqual": "6.18.*",
            "status": "unaffected",
            "versionType": "semver"
        }
    ]
    
    # Process with confirmed mapping
    results = handle_pattern_3_4(
        affected_entry=affected_entry,
        cpe_base_string=cpe_base_string,
        versions=versions,
        has_confirmed_mapping=True
    )
    
    print(f"\nGenerated {len(results)} cpeMatch objects")
    
    # Validation
    failures = []
    
    for idx, (result, version_entry) in enumerate(zip(results, versions)):
        version_value = version_entry['version']
        less_than_or_equal = version_entry['lessThanOrEqual']
        
        print(f"\n--- Version Entry {idx} ---")
        print(f"  version: {version_value}")
        print(f"  lessThanOrEqual: {less_than_or_equal}")
        print(f"  status: {version_entry['status']}")
        print(f"  cpeMatch:")
        print(f"    versionsEntryIndex: {result.get('versionsEntryIndex')}")
        print(f"    vulnerable: {result.get('vulnerable')}")
        print(f"    concerns: {result.get('concerns')}")
        
        # Verify concerns array contains both statusUnaffected and inferredAffectedFromWildcardExpansion
        concerns = result.get('concerns', [])
        
        if 'statusUnaffected' not in concerns:
            failures.append(f"Entry {idx}: Missing 'statusUnaffected' in concerns (got: {concerns})")
        else:
            print(f"    ✓ Contains 'statusUnaffected'")
        
        if 'inferredAffectedFromWildcardExpansion' not in concerns:
            failures.append(f"Entry {idx}: Missing 'inferredAffectedFromWildcardExpansion' in concerns (got: {concerns})")
            print(f"    ❌ MISSING 'inferredAffectedFromWildcardExpansion'")
        else:
            print(f"    ✓ Contains 'inferredAffectedFromWildcardExpansion'")
        
        # Verify vulnerable=False for unaffected entries
        if result.get('vulnerable') != False:
            failures.append(f"Entry {idx}: Expected vulnerable=False, got {result.get('vulnerable')}")
        else:
            print(f"    ✓ vulnerable=False")
    
    # Report results
    print("\n" + "="*80)
    if failures:
        print("❌ TEST FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return False
    else:
        print("✅ TEST PASSED: All unaffected entries with wildcards have correct concerns")
        return True


def test_affected_with_wildcard_in_lessThanOrEqual():
    """Test that affected entries with wildcards still work correctly (regression check)."""
    
    print("\n" + "="*80)
    print("TEST: Affected Entry with Wildcard in lessThanOrEqual (Regression Check)")
    print("="*80)
    
    affected_entry = {
        "vendor": "Example",
        "product": "Product",
        "defaultStatus": "affected",
    }
    
    cpe_base_string = "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*"
    
    versions = [
        {
            "version": "1.0",
            "lessThanOrEqual": "1.2.*",
            "status": "affected",
            "versionType": "semver"
        }
    ]
    
    results = handle_pattern_3_4(
        affected_entry=affected_entry,
        cpe_base_string=cpe_base_string,
        versions=versions,
        has_confirmed_mapping=True
    )
    
    print(f"\nGenerated {len(results)} cpeMatch objects")
    
    result = results[0]
    concerns = result.get('concerns', [])
    
    print(f"\nVersion Entry:")
    print(f"  version: 1.0")
    print(f"  lessThanOrEqual: 1.2.*")
    print(f"  status: affected")
    print(f"  cpeMatch:")
    print(f"    versionsEntryIndex: {result.get('versionsEntryIndex')}")
    print(f"    vulnerable: {result.get('vulnerable')}")
    print(f"    appliedPattern: {result.get('appliedPattern')}")
    print(f"    concerns: {concerns}")
    
    failures = []
    
    # Should have wildcard concern
    if 'inferredAffectedFromWildcardExpansion' not in concerns:
        failures.append(f"Missing 'inferredAffectedFromWildcardExpansion' in concerns")
        print(f"  ❌ MISSING wildcard concern")
    else:
        print(f"  ✓ Contains 'inferredAffectedFromWildcardExpansion'")
    
    # Should NOT have statusUnaffected
    if 'statusUnaffected' in concerns:
        failures.append(f"Affected entry should not have 'statusUnaffected' concern")
        print(f"  ❌ Incorrectly has 'statusUnaffected'")
    else:
        print(f"  ✓ Does not contain 'statusUnaffected'")
    
    # Should be vulnerable
    if result.get('vulnerable') != True:
        failures.append(f"Expected vulnerable=True, got {result.get('vulnerable')}")
    else:
        print(f"  ✓ vulnerable=True")
    
    # Should have criteria (full cpeMatch)
    if 'criteria' not in result:
        failures.append(f"Expected 'criteria' field in cpeMatch")
    else:
        print(f"  ✓ Has 'criteria' field")
    
    print("\n" + "="*80)
    if failures:
        print("❌ TEST FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return False
    else:
        print("✅ TEST PASSED: Affected entries with wildcards work correctly")
        return True


def test_unaffected_without_wildcard():
    """Test that unaffected entries without wildcards only have statusUnaffected concern."""
    
    print("\n" + "="*80)
    print("TEST: Unaffected Entry WITHOUT Wildcard (Regression Check)")
    print("="*80)
    
    affected_entry = {
        "vendor": "Example",
        "product": "Product",
        "defaultStatus": "affected",
    }
    
    cpe_base_string = "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*"
    
    versions = [
        {
            "version": "2.0",
            "lessThanOrEqual": "3.0",
            "status": "unaffected",
            "versionType": "semver"
        }
    ]
    
    results = handle_pattern_3_4(
        affected_entry=affected_entry,
        cpe_base_string=cpe_base_string,
        versions=versions,
        has_confirmed_mapping=True
    )
    
    result = results[0]
    concerns = result.get('concerns', [])
    
    print(f"\nVersion Entry:")
    print(f"  version: 2.0")
    print(f"  lessThanOrEqual: 3.0")
    print(f"  status: unaffected")
    print(f"  cpeMatch concerns: {concerns}")
    
    failures = []
    
    # Should only have statusUnaffected
    if concerns != ['statusUnaffected']:
        failures.append(f"Expected concerns=['statusUnaffected'], got {concerns}")
        print(f"  ❌ Unexpected concerns array")
    else:
        print(f"  ✓ Concerns array correct")
    
    print("\n" + "="*80)
    if failures:
        print("❌ TEST FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return False
    else:
        print("✅ TEST PASSED: Unaffected entries without wildcards work correctly")
        return True


def main():
    """Run all test cases."""
    print("\n" + "="*80)
    print("WILDCARD EXPANSION IN UNAFFECTED ENTRIES - TEST SUITE")
    print("="*80)
    
    test_results = []
    
    # Run tests
    test_results.append(("Unaffected with Wildcard", test_unaffected_with_wildcard_in_lessThanOrEqual()))
    test_results.append(("Affected with Wildcard (Regression)", test_affected_with_wildcard_in_lessThanOrEqual()))
    test_results.append(("Unaffected without Wildcard (Regression)", test_unaffected_without_wildcard()))
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    passed = sum(1 for _, result in test_results if result)
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTEST_RESULTS: PASSED={passed} TOTAL={total} SUITE=\"wildcard_expansion_unaffected\"")
    
    if passed == total:
        print("\n✅ ALL TESTS PASSED")
        return 0
    else:
        print(f"\n❌ {total - passed} TEST(S) FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(main())
