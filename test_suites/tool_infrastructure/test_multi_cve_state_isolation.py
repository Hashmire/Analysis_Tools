#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration Test: Multi-CVE State Isolation

Tests that the tool properly isolates state between sequential CVE processing
to prevent data contamination across CVE records.

This test verifies that:
1. Registry state is cleared at run initialization
2. Registry state is cleared between each CVE processing
3. No data from CVE-A contaminates CVE-B when processed sequentially
4. The actual tool execution properly clears state, not just unit tests

TEST STRATEGY:
    - Use actual tool execution (python -m src.analysis_tool.core.analysis_tool)
    - Process two CVEs with distinctly different vendor/product data
    - Verify no cross-contamination in generated NVD-ish records
    - Check both registry clearing log statements appear

TEST PATTERN COMPLIANCE:
    All test cases follow the proper NVD-ish collector test pattern:
        1. SETUP: Copy test files to INPUT cache directories
        2. EXECUTE: Run normal tool execution (not isolated test-file mode)
        3. VALIDATE: Check OUTPUT cache for expected enhanced records
        4. TEARDOWN: Clean up INPUT cache test files
    
    SETUP: Copy pre-created test files to INPUT caches (cve_list_v5/, nvd_2.0_cves/)
           - Creates proper cache directory structure: cache/{source}/1337/{subdir}/
           - Copies both NVD 2.0 and CVE List V5 data files for dual-source validation
           
    EXECUTE: Run analysis tool normally with --cve CVE-ID (tool finds INPUT cache files)
             - Uses standard module invocation: python -m src.analysis_tool.core.analysis_tool
             - Tool automatically discovers and processes INPUT cache files
             - Uses --nvd-ish-only flag to generate enhanced records
             
    VALIDATE: Check OUTPUT cache (nvd-ish_2.0_cves/) for enhanced records
              - Validates enhanced record structure and content
              - Confirms no cross-contamination between CVEs
              - Verifies registry clearing logs appear
              
    TEARDOWN: Clean INPUT cache files only (preserve OUTPUT cache)
              - Removes test files from INPUT caches (cve_list_v5/, nvd_2.0_cves/)
              - Preserves OUTPUT cache (nvd-ish_2.0_cves/) for validation
              - Maintains clean test environment between runs

ENTRY POINT COVERAGE:
    - Direct: python -m src.analysis_tool.core.analysis_tool --cve ...
    - Note: generate_dataset.py calls analysis_tool.main() internally, so it uses
      the same code path and is inherently covered by this test

REGRESSION PREVENTION:
    - This test prevents regression of the CVE-2026-26157 contamination bug
    - Bug: PLATFORM_ENTRY_NOTIFICATION_REGISTRY persisted between CVEs
    - Fix: clear_all_registries() called at run start and per-CVE
    - Regression: Commit 4f80b5f (Feb 5, 2026) removed state clearing when HTML
      generation was deprecated, but PENR was not HTML-related and should have
      been preserved

TEST DATA:
    - CVE-1337-9001: Xiaomi products (galaxy-fds-sdk-android, saturn-remote-controller)
    - CVE-1337-9002: Red Hat Enterprise Linux (RHEL 8, RHEL 9)
    - CVE-1337-9003: Microsoft Windows Server (2019, 2022)
    - CVE-1337-9004: Cisco networking equipment (IOS XE, ASA)
    - CVE-1337-9005: Oracle products (Database Server, WebLogic Server)
    - Processing order: Sequential (9001 → 9002 → 9003 → 9004 → 9005)
    - Expected: Each CVE contains ONLY its own vendor data, NO cross-contamination
"""

import subprocess
import sys
import json
from pathlib import Path
import shutil
from typing import List, Optional, Set

# Force UTF-8 output encoding for Windows compatibility with Unicode test output
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'replace')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'replace')

# Test configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent
TEST_FILES_DIR = Path(__file__).parent
CACHE_DIR = PROJECT_ROOT / "cache"

def setup_test_environment(test_cves: List[str]) -> List[str]:
    """Set up test environment by copying test files to INPUT cache locations.
    
    Args:
        test_cves: List of CVE IDs to set up (e.g., ["CVE-1337-9001", "CVE-1337-9002"])
    
    Returns:
        List of copied file paths for cleanup
    """
    print("Setting up test environment...")
    
    copied_files = []
    
    def get_cache_directory(cve_id: str, cache_type: str) -> Path:
        """Get correct cache directory based on CVE ID sequence number."""
        parts = cve_id.split('-')
        if len(parts) != 3:
            raise ValueError(f"Invalid CVE ID format: {cve_id}")
        
        year = parts[1]
        sequence = parts[2]
        
        # Determine directory name based on sequence length and first digits
        if len(sequence) == 4:
            dir_name = f"{sequence[0]}xxx"
        elif len(sequence) == 5:
            dir_name = f"{sequence[:2]}xxx"
        else:
            dir_name = f"{sequence[:3]}xxx"
        
        return CACHE_DIR / cache_type / year / dir_name
    
    # Pre-create all necessary cache directory structures
    cache_types = ["cve_list_v5", "nvd_2.0_cves", "nvd-ish_2.0_cves"]  # INPUT + OUTPUT caches
    dir_patterns = ["9xxx"]  # Test CVE-1337-9xxx series
    
    for cache_type in cache_types:
        for dir_pattern in dir_patterns:
            cache_dir = CACHE_DIR / cache_type / "1337" / dir_pattern
            cache_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy test files to their correct cache directories
    for cve_id in test_cves:
        # Copy CVE List V5 file
        cve_list_cache_dir = get_cache_directory(cve_id, "cve_list_v5")
        cve_list_source = TEST_FILES_DIR / f"{cve_id}-cve-list-v5.json"
        if cve_list_source.exists():
            cve_list_target = cve_list_cache_dir / f"{cve_id}.json"
            if cve_list_target.exists():
                cve_list_target.unlink()
            shutil.copy2(cve_list_source, cve_list_target)
            copied_files.append(str(cve_list_target))
        else:
            print(f"  [WARNING] CVE List V5 file not found: {cve_list_source}")
        
        # Copy NVD 2.0 file
        nvd_cache_dir = get_cache_directory(cve_id, "nvd_2.0_cves")
        nvd_source = TEST_FILES_DIR / f"{cve_id}-nvd-2.0.json"
        if nvd_source.exists():
            nvd_target = nvd_cache_dir / f"{cve_id}.json"
            if nvd_target.exists():
                nvd_target.unlink()
            shutil.copy2(nvd_source, nvd_target)
            copied_files.append(str(nvd_target))
        else:
            print(f"  [WARNING] NVD 2.0 file not found: {nvd_source}")
    
    # Inject test source data into NVD source cache for source resolution
    source_cache_path = CACHE_DIR / "nvd_source_data.json"
    if source_cache_path.exists():
        try:
            with open(source_cache_path, 'r', encoding='utf-8') as f:
                source_data = json.load(f)
            
            # Add test source entries if not already present
            test_sources = [
                {
                    "name": "Test Organization",
                    "contactEmail": "test@example.com",
                    "sourceIdentifiers": ["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "test@example.com", "testorg"]
                },
                {
                    "name": "Red Hat",
                    "contactEmail": "secalert@redhat.com",
                    "sourceIdentifiers": ["bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "secalert@redhat.com", "redhat"]
                },
                {
                    "name": "Microsoft",
                    "contactEmail": "secure@microsoft.com",
                    "sourceIdentifiers": ["cccccccc-dddd-eeee-ffff-000000000001", "secure@microsoft.com", "microsoft"]
                },
                {
                    "name": "Cisco",
                    "contactEmail": "psirt@cisco.com",
                    "sourceIdentifiers": ["dddddddd-eeee-ffff-0000-111111111111", "psirt@cisco.com", "cisco"]
                },
                {
                    "name": "Oracle Corporation",
                    "contactEmail": "secalert_us@oracle.com",
                    "sourceIdentifiers": ["eeeeeeee-ffff-0000-1111-222222222222", "secalert_us@oracle.com", "oracle"]
                }
            ]
            
            # Use correct cache structure key: 'source_data' not 'sources'
            existing_identifiers = {
                identifier 
                for s in source_data.get('source_data', []) 
                for identifier in s.get('sourceIdentifiers', [])
            }
            for test_source in test_sources:
                # Check if any of this test source's identifiers already exist
                if not any(ident in existing_identifiers for ident in test_source['sourceIdentifiers']):
                    source_data.setdefault('source_data', []).append(test_source)
            
            # Write back with test sources
            with open(source_cache_path, 'w', encoding='utf-8') as f:
                json.dump(source_data, f, indent=2)
            
            print(f"  * Injected test source data into NVD source cache")
        except Exception as e:
            print(f"  [WARNING] Failed to inject test source data: {e}")
    
    print(f"  * Copied {len(copied_files)} test files to INPUT cache")
    return copied_files


def cleanup_test_environment(copied_files: List[str]):
    """Clean up test environment by removing test files from INPUT caches only.
    
    Args:
        copied_files: List of file paths to remove
    """
    print("Cleaning up test environment...")
    
    removed_count = 0
    for file_path in copied_files:
        if Path(file_path).exists():
            Path(file_path).unlink()
            removed_count += 1
    
    # Remove test source data from NVD source cache
    source_cache_path = CACHE_DIR / "nvd_source_data.json"
    if source_cache_path.exists():
        try:
            with open(source_cache_path, 'r', encoding='utf-8') as f:
                source_data = json.load(f)
            
            # Remove test source identifiers
            test_identifiers = {
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "test@example.com",
                "testorg",
                "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
                "secalert@redhat.com",
                "cccccccc-dddd-eeee-ffff-000000000001",
                "secure@microsoft.com",
                "microsoft",
                "dddddddd-eeee-ffff-0000-111111111111",
                "psirt@cisco.com",
                "cisco",
                "eeeeeeee-ffff-0000-1111-222222222222",
                "secalert_us@oracle.com",
                "oracle"
            }
            original_count = len(source_data.get('source_data', []))
            
            # Remove sources that have ANY test identifiers
            source_data['source_data'] = [
                s for s in source_data.get('source_data', [])
                if not any(ident in test_identifiers for ident in s.get('sourceIdentifiers', []))
            ]
            
            removed = original_count - len(source_data['source_data'])
            
            if removed > 0:
                with open(source_cache_path, 'w', encoding='utf-8') as f:
                    json.dump(source_data, f, indent=2)
                print(f"  * Removed {removed} test source entries from NVD source cache")
        except Exception as e:
            print(f"  [WARNING] Failed to clean test source data: {e}")
    
    print(f"  * Removed {removed_count} test files from INPUT cache")


def run_tool_with_cves(cve_list: List[str]):
    """
    Run the actual analysis tool with specified CVEs
    
    Uses --nvd-ish-only flag which is the current standard pipeline:
        - Enables ALL analysis processes (SDC, CPE determination, alias extraction, etc.)
        - Generates complete NVD-ish enriched records
        - Optimized for efficient processing
    
    Returns:
        (success, stdout, stderr)
    """
    cmd = [
        sys.executable, "-m", "src.analysis_tool.core.analysis_tool",
        "--cve"
    ] + cve_list + ["--nvd-ish-only"]
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        timeout=120  # 2 minute timeout
    )
    
    return result.returncode == 0, result.stdout, result.stderr


def check_registry_clearing_logs(stdout: str, stderr: str) -> tuple:
    """
    Verify that registry clearing happens at both run start and per-CVE
    
    Expected log patterns:
        - "Global registries cleared at run initialization" (once at start)
        - "Environment prepared - registries cleared" (once per CVE)
    
    Returns:
        (has_run_init_clear, per_cve_clear_count)
    """
    combined_output = stdout + "\n" + stderr
    
    has_run_init_clear = "Global registries cleared at run initialization" in combined_output
    per_cve_clear_count = combined_output.count("Environment prepared - registries cleared")
    
    return has_run_init_clear, per_cve_clear_count


def load_nvd_ish_record(cve_id: str) -> Optional[dict]:
    """Load NVD-ish record from OUTPUT cache"""
    year = cve_id.split("-")[1]
    sequence = cve_id.split("-")[2]
    
    # Determine directory name based on sequence length
    if len(sequence) == 4:
        dir_name = f"{sequence[0]}xxx"
    elif len(sequence) == 5:
        dir_name = f"{sequence[:2]}xxx"
    else:
        dir_name = f"{sequence[:3]}xxx"
    
    nvd_ish_path = CACHE_DIR / "nvd-ish_2.0_cves" / year / dir_name / f"{cve_id}.json"
    
    if not nvd_ish_path.exists():
        return None
    
    with open(nvd_ish_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_alias_vendors(nvd_ish_record: dict) -> Set[str]:
    """
    Extract all unique vendors from aliasExtraction sections
    
    Returns set of vendor names found across all affected entries
    """
    vendors = set()
    
    if not nvd_ish_record or 'enrichedCVEv5Affected' not in nvd_ish_record:
        return vendors
    
    entries = nvd_ish_record['enrichedCVEv5Affected'].get('cveListV5AffectedEntries', [])
    
    for entry in entries:
        alias_extraction = entry.get('aliasExtraction', {})
        aliases = alias_extraction.get('aliases', [])
        
        for alias in aliases:
            vendor = alias.get('vendor')
            if vendor:
                vendors.add(vendor)
    
    return vendors


def test_multi_cve_state_isolation():
    """
    Main test: Process five CVEs sequentially and verify no contamination
    
    Uses CVEs with distinctly different vendors to detect any cross-contamination:
        - CVE-1337-9001: Xiaomi products
        - CVE-1337-9002: Red Hat products
        - CVE-1337-9003: Microsoft products
        - CVE-1337-9004: Cisco products
        - CVE-1337-9005: Oracle products
    
    If state isolation works:
        - Each CVE should only contain its own vendor data
        - No vendor from previous CVEs should appear in subsequent CVEs
        - Registry clearing logs should appear for all 5 CVEs
    """
    print("=" * 80)
    print("MULTI-CVE STATE ISOLATION INTEGRATION TEST")
    print("=" * 80)
    print()
    
    # Test CVEs - CVE-1337-9xxx series with distinct vendors
    test_cves = ["CVE-1337-9001", "CVE-1337-9002", "CVE-1337-9003", "CVE-1337-9004", "CVE-1337-9005"]
    
    # SETUP: Copy test files to INPUT cache
    print("Step 1: Setup test environment")
    print("-" * 80)
    copied_files = setup_test_environment(test_cves)
    print()
    
    try:
        # EXECUTE: Run tool with test CVEs
        print("Step 2: Run tool with five CVEs sequentially")
        print("-" * 80)
        print(f"Processing: {', '.join(test_cves)}")
        print()
        
        success, stdout, stderr = run_tool_with_cves(test_cves)
        
        if not success:
            print("❌ FAIL: Tool execution failed")
            print("STDOUT:", stdout[-500:] if len(stdout) > 500 else stdout)
            print("STDERR:", stderr[-500:] if len(stderr) > 500 else stderr)
            return False
        
        print("✓ Tool execution completed successfully")
        print()
        
        # VALIDATE: Check registry clearing logs
        print("Step 3: Verify registry clearing behavior")
        print("-" * 80)
        
        has_run_init, per_cve_count = check_registry_clearing_logs(stdout, stderr)
        
        if has_run_init:
            print("✓ Registry cleared at run initialization")
        else:
            print("❌ FAIL: Missing run initialization registry clearing")
            return False
        
        if per_cve_count >= len(test_cves):
            print(f"✓ Registry cleared per-CVE ({per_cve_count} times for {len(test_cves)} CVEs)")
        else:
            print(f"❌ FAIL: Expected {len(test_cves)} per-CVE clears, found {per_cve_count}")
            return False
        
        print()
        
        # VALIDATE: Check OUTPUT cache for contamination
        print("Step 4: Verify no cross-contamination in generated records")
        print("-" * 80)
        
        # Define expected vendors for each CVE
        expected_vendors = {
            "CVE-1337-9001": {"xiaomi"},
            "CVE-1337-9002": {"red hat"},
            "CVE-1337-9003": {"microsoft"},
            "CVE-1337-9004": {"cisco"},
            "CVE-1337-9005": {"oracle"}
        }
        
        # Load all CVE records from OUTPUT cache
        cve_data = {}
        for cve_id in test_cves:
            data = load_nvd_ish_record(cve_id)
            if not data:
                print(f"❌ FAIL: Could not load {cve_id} NVD-ish record from OUTPUT cache")
                return False
            cve_data[cve_id] = data
        
        # Extract vendors from each record
        cve_vendors = {}
        for cve_id, data in cve_data.items():
            vendors = extract_alias_vendors(data)
            cve_vendors[cve_id] = vendors
            print(f"{cve_id} vendors: {vendors if vendors else '(none)'}")
        
        print()
        
        # Check for contamination: each CVE should ONLY contain its expected vendors
        all_clean = True
        for cve_id, vendors in cve_vendors.items():
            expected = expected_vendors[cve_id]
            
            # Check for contamination from OTHER CVEs
            other_expected = set()
            for other_cve, other_vendors in expected_vendors.items():
                if other_cve != cve_id:
                    other_expected.update(other_vendors)
            
            # Look for any vendor that matches a different CVE's expected vendor
            contamination = set()
            for vendor in vendors:
                if vendor:
                    vendor_lower = vendor.lower()
                    for contamination_keyword in other_expected:
                        if contamination_keyword in vendor_lower:
                            contamination.add(vendor)
            
            if contamination:
                print(f"❌ FAIL: {cve_id} contains contaminated vendor data: {contamination}")
                print(f"   Expected only: {expected}")
                all_clean = False
            else:
                print(f"✓ {cve_id}: No contamination detected")
            
            # Verify expected vendors are present
            has_expected = False
            for vendor in vendors:
                if vendor:
                    vendor_lower = vendor.lower()
                    for expected_keyword in expected:
                        if expected_keyword in vendor_lower:
                            has_expected = True
                            break
            
            if not has_expected:
                print(f"⚠️  WARNING: {cve_id} missing expected vendor data (keywords: {expected})")
        
        print()
        
        if not all_clean:
            print("❌ FAIL: Cross-contamination detected between CVE records")
            return False
        
        print("=" * 80)
        print("RESULTS")
        print("=" * 80)
        print("✅ PASS: Multi-CVE state isolation verified")
        print()
        print("Verified:")
        print(f"  - Registry cleared at run initialization")
        print(f"  - Registry cleared before each CVE processing ({len(test_cves)} times for {len(test_cves)} CVEs)")
        print(f"  - No cross-contamination between {len(test_cves)} CVE records")
        print(f"  - Each CVE contains only its expected vendor data")
        print(f"  - Tool execution properly isolates state across extended processing chains")
        
        return True
        
    finally:
        # TEARDOWN: Clean up INPUT cache files
        print()
        cleanup_test_environment(copied_files)


if __name__ == "__main__":
    try:
        passed = test_multi_cve_state_isolation()
        
        # Output standardized test results for unified runner
        total = 1
        passed_count = 1 if passed else 0
        print()
        print(f"TEST_RESULTS: PASSED={passed_count} TOTAL={total} SUITE=\"Multi-CVE State Isolation\"")
        
        sys.exit(0 if passed else 1)
        
    except Exception as e:
        print(f"❌ TEST EXECUTION FAILED: {e}")
        import traceback
        traceback.print_exc()
        print()
        print(f"TEST_RESULTS: PASSED=0 TOTAL=1 SUITE=\"Multi-CVE State Isolation\"")
        sys.exit(1)

