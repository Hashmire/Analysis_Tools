#!/usr/bin/env python3
"""
Registry Contamination Reproduction Test

This test demonstrates the PLATFORM_ENTRY_NOTIFICATION_REGISTRY contamination bug
where data from one CVE persists and contaminates subsequent CVE processing.

Expected Behavior:
- Each CVE should have isolated registry data
- CVE-B should NOT contain any data from CVE-A

Actual Behavior (BUG):
- Registry is never cleared between CVEs
- CVE-B's enriched data contains CVE-A's data

Usage:
    python test_registry_contamination.py
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def test_registry_contamination():
    """
    Reproduce the registry contamination bug by processing two CVEs in sequence.
    """
    print("=" * 80)
    print("REGISTRY CONTAMINATION REPRODUCTION TEST")
    print("=" * 80)
    print()
    
    # Import after path setup
    from src.analysis_tool.core.platform_entry_registry import (
        PLATFORM_ENTRY_NOTIFICATION_REGISTRY,
        create_alias_extraction_badge
    )
    
    print("Step 1: Initial Registry State")
    print("-" * 80)
    initial_alias_count = len(PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('aliasExtraction', {}))
    print(f"✓ Registry 'aliasExtraction' entries: {initial_alias_count}")
    print()
    
    # Simulate CVE-A processing (Xiaomi CVE)
    print("Step 2: Simulate CVE-A Processing (Xiaomi/Galaxy FDS SDK)")
    print("-" * 80)
    
    raw_platform_data_a = {
        'vendor': 'Xiaomi Technology Co., Ltd.',
        'product': 'Galaxy FDS Android SDK',
        'packageName': 'galaxy-fds-sdk-android',
        'platforms': ['Android'],
        'repo': 'https://github.com/XiaoMi/galaxy-fds-sdk-android'
    }
    
    row_a = {
        'cve_id': 'CVE-TEST-XIAOMI',
        'sourceID': 'test-source-uuid-xiaomi'
    }
    
    # Process CVE-A entry at table_index 0
    create_alias_extraction_badge(
        table_index=0,
        raw_platform_data=raw_platform_data_a,
        row=row_a
    )
    
    alias_count_after_a = len(PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('aliasExtraction', {}))
    print(f"✓ CVE-A processed at table_index=0")
    print(f"✓ Registry 'aliasExtraction' entries after CVE-A: {alias_count_after_a}")
    
    # Check what was stored
    stored_data_a = PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('aliasExtraction', {})
    if '0' in stored_data_a or '0_platform_0' in stored_data_a:
        print(f"✓ CVE-A data stored in registry at table_index 0")
        for key, value in stored_data_a.items():
            if key.startswith('0'):
                alias_dict = value.get('alias_data', {}) if isinstance(value, dict) else value
                for alias_key, alias_data in (alias_dict.items() if isinstance(alias_dict, dict) else []):
                    vendor = alias_data.get('vendor', 'N/A')
                    product = alias_data.get('product', 'N/A')
                    print(f"  - Entry '{key}': {vendor} / {product}")
    print()
    
    # NOW THE CRITICAL PART: Simulate CVE-B processing WITHOUT clearing registry
    print("Step 3: Simulate CVE-B Processing (Red Hat/BusyBox) - NO REGISTRY CLEAR")
    print("-" * 80)
    print("⚠️  NOTE: audit_global_state_cleared() does NOT clear the registry!")
    print()
    
    raw_platform_data_b = {
        'vendor': 'Red Hat',
        'product': 'Red Hat Enterprise Linux 6',
        'packageName': 'busybox',
        'collectionURL': 'https://access.redhat.com/downloads/content/package-browser/'
    }
    
    row_b = {
        'cve_id': 'CVE-TEST-REDHAT',
        'sourceID': 'test-source-uuid-redhat'
    }
    
    # Process CVE-B entry ALSO at table_index 0
    create_alias_extraction_badge(
        table_index=0,
        raw_platform_data=raw_platform_data_b,
        row=row_b
    )
    
    alias_count_after_b = len(PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('aliasExtraction', {}))
    print(f"✓ CVE-B processed at table_index=0")
    print(f"✓ Registry 'aliasExtraction' entries after CVE-B: {alias_count_after_b}")
    print()
    
    # Check contamination
    print("Step 4: Verify Registry Contamination")
    print("-" * 80)
    
    stored_data_final = PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('aliasExtraction', {})
    
    # Check if we have BOTH CVE-A and CVE-B data at the same table_index
    has_xiaomi = False
    has_redhat = False
    
    print("Registry contents at table_index 0:")
    for key, value in stored_data_final.items():
        if key.startswith('0'):
            alias_dict = value.get('alias_data', {}) if isinstance(value, dict) else value
            for alias_key, alias_data in (alias_dict.items() if isinstance(alias_dict, dict) else []):
                vendor = alias_data.get('vendor', 'N/A')
                product = alias_data.get('product', 'N/A')
                cve_id = alias_data.get('source_cve', 'N/A')
                print(f"  - Entry '{key}': {vendor} / {product} (CVE: {cve_id})")
                
                if 'Xiaomi' in vendor or 'galaxy-fds' in product:
                    has_xiaomi = True
                if 'Red Hat' in vendor or 'busybox' in product:
                    has_redhat = True
    
    print()
    print("=" * 80)
    print("TEST RESULTS")
    print("=" * 80)
    
    if alias_count_after_b > alias_count_after_a:
        print("❌ BUG REPRODUCED: Registry accumulated entries instead of replacing")
        print(f"   - After CVE-A: {alias_count_after_a} entries")
        print(f"   - After CVE-B: {alias_count_after_b} entries")
        print(f"   - Expected: Same count (replacement)")
        print(f"   - Actual: Increased count (accumulation)")
    elif alias_count_after_b == alias_count_after_a:
        print("⚠️  Registry size unchanged, checking for overwrite contamination...")
    
    print()
    
    if has_xiaomi and has_redhat:
        print("❌ CRITICAL BUG: Registry contains data from BOTH CVEs!")
        print("   - Xiaomi data (CVE-A): PRESENT")
        print("   - Red Hat data (CVE-B): PRESENT")
        print()
        print("   This proves that:")
        print("   1. Registry was NOT cleared between CVE-A and CVE-B")
        print("   2. Data from CVE-A persisted into CVE-B processing")
        print("   3. NVD-ish collector would mix both into CVE-B's enriched data")
        return False
    elif has_redhat and not has_xiaomi:
        print("✓ Registry was properly cleared (or overwritten) - CVE-B data only")
        return True
    elif has_xiaomi and not has_redhat:
        print("❌ Registry was NOT updated - Still contains CVE-A data only")
        return False
    else:
        print("⚠️  Unexpected state - no data found")
        return False


def test_nvdish_collector_contamination():
    """
    Demonstrate how contaminated registry data would propagate to NVD-ish records.
    """
    print()
    print("=" * 80)
    print("BADGE COLLECTOR CONTAMINATION TEST")
    print("=" * 80)
    print()
    
    from src.analysis_tool.core.platform_entry_registry import PLATFORM_ENTRY_NOTIFICATION_REGISTRY
    
    # Show current contaminated state
    print("Step 1: Review Contaminated Registry State")
    print("-" * 80)
    
    alias_registry_data = PLATFORM_ENTRY_NOTIFICATION_REGISTRY.get('aliasExtraction', {})
    
    print(f"Registry 'aliasExtraction' contains {len(alias_registry_data)} entries:")
    
    has_xiaomi = False
    has_redhat = False
    
    for key, value in alias_registry_data.items():
        print(f"  Entry '{key}': {type(value).__name__}")
        
        if isinstance(value, dict):
            # Check direct alias_data dict or nested structure
            alias_dict = value.get('alias_data', {})
            if not alias_dict:
                alias_dict = value  # Might be the data itself
            
            # Handle both dict of dicts and simple dict
            if isinstance(alias_dict, dict):
                for alias_key, alias_data in alias_dict.items():
                    if isinstance(alias_data, dict):
                        vendor = alias_data.get('vendor', 'N/A')
                        product = alias_data.get('product', 'N/A')
                        print(f"    Alias '{alias_key}': {vendor} / {product}")
                        
                        if 'Xiaomi' in str(vendor):
                            has_xiaomi = True
                        if 'Red Hat' in str(vendor) or 'busybox' in str(product).lower():
                            has_redhat = True
                    else:
                        print(f"    Alias '{alias_key}': {alias_data}")
    
    print()
    print("Step 2: Simulate NVD-ish Collector Matching Logic")
    print("-" * 80)
    print("When processing CVE-TEST-VICTIM with table_index=0:")
    print()
    
    # Simulate what collect_alias_extraction_from_registry() would do
    matching_entries = {}
    for key, value in alias_registry_data.items():
        if key.startswith('0'):  # Matches table_index 0
            matching_entries[key] = value
            print(f"  ✓ Would match entry '{key}' (starts with '0')")
    
    if len(matching_entries) > 1:
        print()
        print(f"❌ CRITICAL: Found {len(matching_entries)} entries for table_index=0")
        print("   ALL of these would be written to CVE-TEST-VICTIM's aliasExtraction!")
        print()
        
        if has_xiaomi and has_redhat:
            print("❌ CONTAMINATION CONFIRMED:")
            print("   - Xiaomi data (from CVE-A) would contaminate CVE-TEST-VICTIM")  
            print("   - Red Hat data (from CVE-B) would contaminate CVE-TEST-VICTIM")
            print("   - CVE-TEST-VICTIM would have aliases from MULTIPLE different CVEs!")
            return False
    
    return True


def test_registry_with_fix():
    """
    Demonstrates that clear_all_registries() DOES clear the registry properly.
    This should be called between CVE processing to prevent contamination.
    """
    print()
    print("=" * 80)
    print("TEST WITH FIX - VERIFYING clear_all_registries() WORKS")
    print("=" * 80)
    print()
    
    from src.analysis_tool.core.platform_entry_registry import (
        create_alias_extraction_badge,
        clear_all_registries
    )
    import src.analysis_tool.core.platform_entry_registry as per
    
    # Ensure clean start
    clear_all_registries()
    
    print("Step 1: Process CVE-A (Xiaomi)")
    print("-" * 80)
    
    raw_platform_data_a = {
        'vendor': 'Xiaomi Technology Co., Ltd.',
        'product': 'Galaxy FDS Android SDK',
        'packageName': 'galaxy-fds-sdk-android',
        'platforms': ['Android'],
        'repo': 'https://github.com/XiaoMi/galaxy-fds-sdk-android'
    }
    
    row_a = {
        'cve_id': 'CVE-TEST-XIAOMI',
        'sourceID': 'test-source-uuid-xiaomi'
    }
    
    create_alias_extraction_badge(
        table_index=0,
        raw_platform_data=raw_platform_data_a,
        row=row_a
    )
    count_after_a = len(per.PLATFORM_ENTRY_NOTIFICATION_REGISTRY['aliasExtraction'])
    print(f"✓ Registry entries after CVE-A: {count_after_a}")
    print()
    
    print("Step 2: CALL clear_all_registries() (THE FIX)")
    print("-" * 80)
    clear_all_registries()
    count_after_clear = len(per.PLATFORM_ENTRY_NOTIFICATION_REGISTRY['aliasExtraction'])
    print(f"✓ Registry entries after clear: {count_after_clear}")
    print()
    
    print("Step 3: Process CVE-B (Red Hat)")
    print("-" * 80)
    
    raw_platform_data_b = {
        'vendor': 'Red Hat',
        'product': 'Red Hat Enterprise Linux 6',
        'packageName': 'busybox',
        'collectionURL': 'https://access.redhat.com/downloads/content/package-browser/'
    }
    
    row_b = {
        'cve_id': 'CVE-TEST-REDHAT',
        'sourceID': 'test-source-uuid-redhat'
    }
    
    create_alias_extraction_badge(
        table_index=0,
        raw_platform_data=raw_platform_data_b,
        row=row_b
    )
    count_after_b = len(per.PLATFORM_ENTRY_NOTIFICATION_REGISTRY['aliasExtraction'])
    print(f"✓ Registry entries after CVE-B: {count_after_b}")
    print()
    
    print("=" * 80)
    print("RESULTS")
    print("=" * 80)
    
    if count_after_clear == 0 and count_after_b == 1:
        print("✅ FIX VERIFIED: clear_all_registries() properly clears registry")
        print(f"  - After CVE-A: {count_after_a} entry")
        print(f"  - After clear: {count_after_clear} entries (CLEARED)")
        print(f"  - After CVE-B: {count_after_b} entry (FRESH)")
        print()
        print("This fix prevents contamination when called between CVE processing.")
        return True
    else:
        print("❌ UNEXPECTED: clear_all_registries() did not work as expected")
        return False


if __name__ == "__main__":
    print()
    print("Testing registry contamination bug reproduction...")
    print()
    
    # First test: Reproduce the bug
    registry_clean = test_registry_contamination()
    collector_clean = test_nvdish_collector_contamination()
    
    # Second test: Verify the fix works
    fix_works = test_registry_with_fix()
    
    print()
    print("=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    print(f"Bug Reproduction: {'✅ Successfully demonstrated' if not registry_clean else '❌ Failed to reproduce'}")
    print(f"Fix Verification: {'✅ clear_all_registries() works' if fix_works else '❌ Fix failed'}")
    print()
    
    if not registry_clean and fix_works:
        print("CONCLUSION:")
        print("  1. Bug reproduced - registry accumulates without fix")
        print("  2. Fix verified - clear_all_registries() clears properly")
        print("  3. Solution: Replace audit_global_state_cleared() with clear_all_registries()")
        print("     in analysis_tool.py line 252 ✅ (ALREADY APPLIED)")
        sys.exit(0)
    else:
        print("UNEXPECTED TEST RESULTS - review test output above")
        sys.exit(1)
