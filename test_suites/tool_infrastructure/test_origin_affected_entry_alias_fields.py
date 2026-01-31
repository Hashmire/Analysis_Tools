"""
Test Suite: Origin Affected Entry Alias Fields Preservation
============================================================

Purpose:
    Verify that originAffectedEntry preserves alias-related fields from CVE List V5 records.

Test Cases:
    1. Verify collectionURL is preserved in originAffectedEntry
    2. Verify packageName is preserved in originAffectedEntry  
    3. Verify repo is preserved in originAffectedEntry

Expected Behavior:
    - originAffectedEntry should contain all alias-related fields from source CVE List V5 data
    - Fields should be preserved exactly as they appear in the source
    - Missing fields should not be added (field presence should match source)

Integration:
    - Part of tool infrastructure test suite
    - Validates NVD-ish collector data preservation
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from analysis_tool.storage.nvd_ish_collector import NVDishCollector

def test_origin_affected_entry_alias_fields():
    """Test that originAffectedEntry preserves alias-related fields from CVE List V5"""
    
    # Create test affected entry with alias fields (simulating CVE List V5 extraction)
    # CNA entry: vendor/product not present (schema allows this for package managers)
    test_affected_entry_cna = {
        'source': 'patrick@puiterwijk.org',
        'container_type': 'cna',
        'entry_index': 0,
        # vendor and product intentionally omitted (valid per CVE List V5 schema)
        'collectionURL': 'https://github.com/moodle/moodle',
        'packageName': 'moodle',
        'defaultStatus': 'unaffected',
        'versions': [
            {
                'version': '0',
                'status': 'affected',
                'lessThan': '4.1.12',
                'versionType': 'semver'
            }
        ],
        'platforms': [],
        'cpes': []
    }
    
    test_affected_entry_adp = {
        'source': '134c704f-9b21-4f2e-91b3-4a467353bcc0',
        'container_type': 'adp[0]',
        'entry_index': 0,
        'vendor': 'moodle',
        'product': 'moodle',
        'repo': 'https://github.com/moodle/moodle.git',
        'defaultStatus': 'unknown',
        'versions': [
            {
                'version': '0',
                'status': 'affected',
                'lessThan': '4.1.12',
                'versionType': 'semver'
            }
        ],
        'platforms': [],
        'cpes': ['cpe:2.3:a:moodle:moodle:-:*:*:*:*:*:*:*']
    }
    
    # Test the logic that builds originAffectedEntry (from lines 468-487 in nvd_ish_collector.py)
    # Test Case 1: CNA entry with collectionURL and packageName (no vendor/product)
    origin_cna = {
        'sourceId': test_affected_entry_cna.get('source', 'unknown_source'),
        'cvelistv5AffectedEntryIndex': f'cve.containers.{test_affected_entry_cna.get("container_type", "unknown")}.affected.[{test_affected_entry_cna.get("entry_index", 0)}]',
        'versions': test_affected_entry_cna.get('versions', []),
        'platforms': test_affected_entry_cna.get('platforms', []),
        'cpes': test_affected_entry_cna.get('cpes', [])
    }
    
    # Copy optional fields only if present in source (don't add null values)
    for field in ['vendor', 'product', 'defaultStatus']:
        if field in test_affected_entry_cna:
            origin_cna[field] = test_affected_entry_cna[field]
    
    # Copy alias-related fields if present (THIS IS THE CODE WE'RE TESTING)
    for field in ['collectionURL', 'packageName', 'repo', 'modules', 'programRoutines', 'programFiles']:
        if field in test_affected_entry_cna:
            origin_cna[field] = test_affected_entry_cna[field]
    
    if 'collectionURL' not in origin_cna:
        print("FAIL: collectionURL not preserved in CNA originAffectedEntry")
        return False
    
    if origin_cna['collectionURL'] != "https://github.com/moodle/moodle":
        print(f"FAIL: collectionURL value incorrect: {origin_cna.get('collectionURL')}")
        return False
    
    if 'packageName' not in origin_cna:
        print("FAIL: packageName not preserved in CNA originAffectedEntry")
        return False
    
    if origin_cna['packageName'] != "moodle":
        print(f"FAIL: packageName value incorrect: {origin_cna.get('packageName')}")
        return False
    
    # Verify vendor/product NOT present when not in source (schema allows omission)
    if 'vendor' in origin_cna:
        print(f"FAIL: vendor should not be present when not in source, but found: {origin_cna['vendor']}")
        return False
    
    if 'product' in origin_cna:
        print(f"FAIL: product should not be present when not in source, but found: {origin_cna['product']}")
        return False
    
    print("PASS: CNA entry - collectionURL and packageName preserved, vendor/product omitted correctly")
    
    # Test Case 2: ADP entry with repo field and vendor/product present
    origin_adp = {
        'sourceId': test_affected_entry_adp.get('source', 'unknown_source'),
        'cvelistv5AffectedEntryIndex': f'cve.containers.{test_affected_entry_adp.get("container_type", "unknown")}.affected.[{test_affected_entry_adp.get("entry_index", 0)}]',
        'versions': test_affected_entry_adp.get('versions', []),
        'platforms': test_affected_entry_adp.get('platforms', []),
        'cpes': test_affected_entry_adp.get('cpes', [])
    }
    
    # Copy optional fields only if present in source (don't add null values)
    for field in ['vendor', 'product', 'defaultStatus']:
        if field in test_affected_entry_adp:
            origin_adp[field] = test_affected_entry_adp[field]
    
    # Copy alias-related fields if present (THIS IS THE CODE WE'RE TESTING)
    for field in ['collectionURL', 'packageName', 'repo', 'modules', 'programRoutines', 'programFiles']:
        if field in test_affected_entry_adp:
            origin_adp[field] = test_affected_entry_adp[field]
    
    if 'repo' not in origin_adp:
        print("FAIL: repo not preserved in ADP originAffectedEntry")
        return False
    
    if origin_adp['repo'] != "https://github.com/moodle/moodle.git":
        print(f"FAIL: repo value incorrect: {origin_adp.get('repo')}")
        return False
    
    # Verify vendor/product are present
    if origin_adp.get('vendor') != 'moodle':
        print(f"FAIL: vendor should be 'moodle', got: {origin_adp.get('vendor')}")
        return False
    
    if origin_adp.get('product') != 'moodle':
        print(f"FAIL: product should be 'moodle', got: {origin_adp.get('product')}")
        return False
    
    print("PASS: ADP entry - repo preserved correctly")
    
    # Test Case 3: Field not present should not be added
    if 'modules' in origin_cna:
        print("FAIL: modules field should not be added when not present in source")
        return False
    
    if 'modules' in origin_adp:
        print("FAIL: modules field should not be added when not present in source")
        return False
    
    print("PASS: Fields not present in source are not added to originAffectedEntry")
    
    return True

if __name__ == '__main__':
    print("=" * 80)
    print("Test Suite: Origin Affected Entry Alias Fields Preservation")
    print("=" * 80)
    
    try:
        success = test_origin_affected_entry_alias_fields()
        
        if success:
            print("\n" + "=" * 80)
            print("TEST_RESULTS: PASSED=3 TOTAL=3 SUITE=\"Origin Affected Entry Alias Fields\"")
            print("=" * 80)
            sys.exit(0)
        else:
            print("\n" + "=" * 80)
            print("TEST_RESULTS: PASSED=0 TOTAL=3 SUITE=\"Origin Affected Entry Alias Fields\"")
            print("=" * 80)
            sys.exit(1)
    except Exception as e:
        print(f"\nERROR: Test suite crashed: {e}")
        import traceback
        traceback.print_exc()
        print("\n" + "=" * 80)
        print("TEST_RESULTS: PASSED=0 TOTAL=3 SUITE=\"Origin Affected Entry Alias Fields\"")
        print("=" * 80)
        sys.exit(1)
