#!/usr/bin/env python3
"""
Confirmed Mappings Test Suite (Isolated)

This test suite contains confirmed mapping tests that require isolated execution
due to NVD source manager singleton initialization timing requirements.

Issue: The NVD source manager is a singleton that gets initialized once and reused
across all tool executions. When tests inject test source data into the cache file,
the source manager may have already been initialized with the old cache data,
causing the confirmed mapping manager to reject test mapping files because their
cnaId values aren't found in the source manager's lookup table.

Solution: This isolated suite runs BEFORE any other tests that might initialize
the source manager, ensuring test source data is in place before the singleton
is created.

Test Coverage:
- Test 1: Confirmed Mappings Integration (CVE-1337-2001)
- Test 2: Confirmed Mappings Placeholder Filtering (CVE-1337-3002)

Usage:
    python test_suites/nvd-ish_collector/test_confirmed_mappings.py
"""

import sys
import os
import json
import subprocess
import shutil
from pathlib import Path
from typing import Optional, Dict, Any, List

# Force UTF-8 output encoding for Windows compatibility
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Test configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent
TEST_FILES_DIR = Path(__file__).parent
CACHE_DIR = PROJECT_ROOT / "cache"

class ConfirmedMappingsTestSuite:
    """Isolated test suite for confirmed mapping functionality."""
    
    def __init__(self):
        self.passed = 0
        self.total = 2  # Two confirmed mapping tests
        
    def setup_test_environment(self) -> List[str]:
        """Set up isolated test environment with test source data injected BEFORE any tool execution."""
        print("Setting up isolated confirmed mappings test environment...")
        
        copied_files = []
        
        # Pre-create cache directories
        cache_dirs = [
            CACHE_DIR / "cve_list_v5" / "1337" / "2xxx",
            CACHE_DIR / "cve_list_v5" / "1337" / "3xxx",
            CACHE_DIR / "nvd_2.0_cves" / "1337" / "2xxx",
            CACHE_DIR / "nvd_2.0_cves" / "1337" / "3xxx"
        ]
        
        for cache_dir in cache_dirs:
            cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy test mapping files FIRST (before any tool execution)
        mappings_dir = PROJECT_ROOT / "cache" / "alias_mappings"
        mappings_dir.mkdir(parents=True, exist_ok=True)
        
        # Test 1 mapping file
        test_mapping_source = TEST_FILES_DIR / "test_cve_1337_2001_mappings.json"
        test_mapping_target = mappings_dir / "test_cve_1337_2001_mappings_active.json"
        
        if test_mapping_source.exists():
            if test_mapping_target.exists():
                test_mapping_target.unlink()
            shutil.copy2(test_mapping_source, test_mapping_target)
            copied_files.append(str(test_mapping_target))
            print(f"  * Copied test mapping file for Test 1 (CVE-1337-2001)")
        else:
            print(f"  ⚠️  Test mapping file not found: {test_mapping_source}")
        
        # Test 2 mapping file
        test_mapping_source_3002 = TEST_FILES_DIR / "CVE-1337-3002-confirmed-mappings.json"
        test_mapping_target_3002 = mappings_dir / "testorg.json"
        
        if test_mapping_source_3002.exists():
            if test_mapping_target_3002.exists():
                test_mapping_target_3002.unlink()
            shutil.copy2(test_mapping_source_3002, test_mapping_target_3002)
            copied_files.append(str(test_mapping_target_3002))
            print(f"  * Copied test mapping file for Test 2 (CVE-1337-3002)")
        else:
            print(f"  ⚠️  Test mapping file not found: {test_mapping_source_3002}")
        
        # Inject test source data into NVD source cache BEFORE any tool execution
        source_cache_path = PROJECT_ROOT / "cache" / "nvd_source_data.json"
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
                        "name": "TestOrg",
                        "contactEmail": "testorg@example.com",
                        "sourceIdentifiers": ["bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "testorg@example.com", "testorg"]
                    }
                ]
                
                existing_identifiers = {
                    identifier 
                    for s in source_data.get('source_data', []) 
                    for identifier in s.get('sourceIdentifiers', [])
                }
                
                for test_source in test_sources:
                    if not any(ident in existing_identifiers for ident in test_source['sourceIdentifiers']):
                        source_data.setdefault('source_data', []).append(test_source)
                
                # Write back with test sources
                with open(source_cache_path, 'w', encoding='utf-8') as f:
                    json.dump(source_data, f, indent=2)
                
                print(f"  * Injected test source data into NVD source cache")
            except Exception as e:
                print(f"  ⚠️  Failed to inject test source data: {e}")
        
        print(f"Setup complete. Environment ready for isolated confirmed mapping tests.")
        return copied_files
    
    def cleanup_test_environment(self, copied_files: List[str]):
        """Clean up isolated test environment."""
        print("Cleaning up isolated confirmed mappings test environment...")
        
        removed_count = 0
        
        # Clean up test mapping files
        mappings_dir = PROJECT_ROOT / "cache" / "alias_mappings"
        test_mapping_active = mappings_dir / "test_cve_1337_2001_mappings_active.json"
        test_mapping_3002 = mappings_dir / "testorg.json"
        
        if test_mapping_active.exists():
            test_mapping_active.unlink()
            removed_count += 1
            print(f"  ✓ Removed test mapping file: test_cve_1337_2001_mappings_active.json")
        
        if test_mapping_3002.exists():
            test_mapping_3002.unlink()
            removed_count += 1
            print(f"  ✓ Removed test mapping file: testorg.json")
        
        # Remove test source data from NVD source cache
        source_cache_path = PROJECT_ROOT / "cache" / "nvd_source_data.json"
        if source_cache_path.exists():
            try:
                with open(source_cache_path, 'r', encoding='utf-8') as f:
                    source_data = json.load(f)
                
                # Remove test source entries
                test_identifiers = {
                    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    "test@example.com",
                    "testorg",
                    "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
                    "testorg@example.com"
                }
                
                original_count = len(source_data.get('source_data', []))
                source_data['source_data'] = [
                    s for s in source_data.get('source_data', [])
                    if not any(ident in test_identifiers for ident in s.get('sourceIdentifiers', []))
                ]
                removed = original_count - len(source_data['source_data'])
                
                if removed > 0:
                    with open(source_cache_path, 'w', encoding='utf-8') as f:
                        json.dump(source_data, f, indent=2)
                    removed_count += removed
                    print(f"  ✓ Removed {removed} test source entries from NVD source cache")
            except Exception as e:
                print(f"  ⚠️  Failed to remove test source data: {e}")
        
        # Clean up test CVE files from caches
        cache_dirs = [
            CACHE_DIR / "cve_list_v5" / "1337" / "2xxx",
            CACHE_DIR / "cve_list_v5" / "1337" / "3xxx",
            CACHE_DIR / "nvd_2.0_cves" / "1337" / "2xxx",
            CACHE_DIR / "nvd_2.0_cves" / "1337" / "3xxx"
        ]
        
        for cache_dir in cache_dirs:
            if cache_dir.exists():
                for file in cache_dir.glob("CVE-1337-*.json"):
                    file.unlink()
                    removed_count += 1
        
        print(f"Cleanup complete. Removed {removed_count} test files and entries.")
    
    def run_analysis_tool(self, cve_id: str, additional_args: List[str] = None) -> tuple:
        """Run the analysis tool for a specific CVE and return success status and output path."""
        try:
            cmd = [
                sys.executable,
                "-u",
                "-m", "src.analysis_tool.core.analysis_tool",
                "--cve", cve_id
            ]
            
            if additional_args:
                cmd.extend(additional_args)
            
            process = subprocess.Popen(
                cmd,
                cwd=PROJECT_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            
            stdout, stderr = process.communicate(timeout=300)
            success = process.returncode == 0
            
            # Extract output path from stdout
            output_path = None
            for line in stdout.split('\n'):
                # Look for NVD-ish record cache message (nvd-ish only mode)
                if 'Enhanced record cached:' in line or 'NVD-ish record cached:' in line:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        path_str = parts[1].strip()
                        output_path = Path(path_str)
                        break
                # Also look for HTML file generation message (full mode)
                elif 'File Generated:' in line:
                    parts = line.split(':', 2)  # Split on first 2 colons to skip timestamp
                    if len(parts) > 2:
                        path_str = parts[2].strip()
                        # For HTML files, we need the corresponding NVD-ish JSON
                        html_path = Path(path_str)
                        # Convert HTML path to nvd-ish JSON path
                        # HTML: runs/.../generated_pages/CVE-XXXX-YYYY.html
                        # JSON: cache/nvd-ish_2.0_cves/XXXX/YYYY/CVE-XXXX-YYYY.json
                        cve_id = html_path.stem  # CVE-XXXX-YYYY
                        year = cve_id.split('-')[1]
                        thousands = cve_id.split('-')[2][0] + 'xxx'
                        output_path = CACHE_DIR / "nvd-ish_2.0_cves" / year / thousands / f"{cve_id}.json"
                        break
            
            return success, output_path, stdout, stderr
            
        except Exception as e:
            return False, None, "", str(e)
    
    def test_confirmed_mappings_integration(self) -> bool:
        """Test confirmed mappings integration using CVE-1337-2001 with exact testorg.json matches."""
        print(f"\n=== Test 1: Confirmed Mappings Integration ===")
        
        print(f"  ✓ Using CVE-1337-2001 with test_cve_1337_2001_mappings_active.json for definitive validation")
        
        # SETUP: Copy test files to INPUT cache
        test_files = []
        try:
            cve_list_cache_dir = CACHE_DIR / "cve_list_v5" / "1337" / "2xxx"
            nvd_cache_dir = CACHE_DIR / "nvd_2.0_cves" / "1337" / "2xxx"
            
            cve_list_source = TEST_FILES_DIR / "CVE-1337-2001-cve-list-v5.json"
            cve_list_target = cve_list_cache_dir / "CVE-1337-2001.json"
            if cve_list_target.exists():
                cve_list_target.unlink()
            shutil.copy2(cve_list_source, cve_list_target)
            test_files.append(str(cve_list_target))
            
            nvd_source = TEST_FILES_DIR / "CVE-1337-2001-nvd-2.0.json"
            nvd_target = nvd_cache_dir / "CVE-1337-2001.json"
            if nvd_target.exists():
                nvd_target.unlink()
            shutil.copy2(nvd_source, nvd_target)
            test_files.append(str(nvd_target))
            
            print(f"  ✓ Setup complete: Copied test files to INPUT cache")
            
        except Exception as e:
            print(f"❌ FAIL: Setup failed: {e}")
            return False
        
        # EXECUTE
        success, output_path, stdout, stderr = self.run_analysis_tool(
            "CVE-1337-2001",
            additional_args=["--sdc-report", "--cpe-suggestions", "--alias-report", "--cpe-as-generator", "--source-uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]
        )
        
        # TEARDOWN
        try:
            for test_file in test_files:
                if os.path.exists(test_file):
                    os.unlink(test_file)
            print(f"  ✓ Cleanup complete: Removed {len(test_files)} INPUT cache files")
        except Exception as e:
            print(f"⚠️  WARNING: Cleanup failed: {e}")
        
        if not success:
            print(f"❌ FAIL: Analysis tool failed")
            print(f"STDERR: {stderr}")
            return False
        
        if output_path is None:
            print(f"❌ FAIL: Could not extract output path from analysis tool output")
            print(f"STDOUT:\n{stdout}")
            print(f"STDERR:\n{stderr}")
            return False
        
        # VALIDATE
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            if "enrichedCVEv5Affected" not in data:
                print(f"❌ FAIL: Missing enrichedCVEv5Affected in enhanced record")
                return False
            
            cve_list_entries = data.get("enrichedCVEv5Affected", {}).get("cveListV5AffectedEntries", [])
            if not cve_list_entries:
                print(f"❌ FAIL: No CVE List V5 entries in enhanced record")
                return False
            
            expected_confirmed_mappings = {
                4: ["cpe:2.3:a:testvendor:testproduct:*:*:*:*:*:*:*:*"]
            }
            
            validated_entries = 0
            
            for entry_index, expected_mappings in expected_confirmed_mappings.items():
                if len(cve_list_entries) <= entry_index:
                    print(f"❌ FAIL: Expected at least {entry_index + 1} CVE entries, found {len(cve_list_entries)}")
                    return False
                    
                target_entry = cve_list_entries[entry_index]
                cpe_suggestions = target_entry.get("cpeSuggestions", {})
                confirmed_mappings = cpe_suggestions.get('confirmedMappings', [])
                
                if len(confirmed_mappings) != len(expected_mappings):
                    print(f"❌ FAIL: Entry {entry_index} expected {len(expected_mappings)} confirmed mappings, got {len(confirmed_mappings)}")
                    print(f"  Expected: {expected_mappings}")
                    print(f"  Actual: {confirmed_mappings}")
                    return False
                
                for expected_mapping in expected_mappings:
                    if expected_mapping not in confirmed_mappings:
                        print(f"❌ FAIL: Entry {entry_index} missing expected mapping: {expected_mapping}")
                        return False
                
                validated_entries += 1
                print(f"  ✓ Entry {entry_index}: Validated {len(confirmed_mappings)} confirmed mappings")
            
            print(f"✅ PASS: Confirmed mappings integration validated successfully")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating confirmed mappings: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_confirmed_mappings_placeholder_filtering(self) -> bool:
        """Test confirmed mappings placeholder filtering integration."""
        print(f"\n=== Test 2: Confirmed Mappings Placeholder Filtering Integration ===")
        
        # SETUP
        test_files = []
        try:
            cve_list_cache_dir = CACHE_DIR / "cve_list_v5" / "1337" / "3xxx"
            nvd_cache_dir = CACHE_DIR / "nvd_2.0_cves" / "1337" / "3xxx"
            
            cve_list_source = TEST_FILES_DIR / "CVE-1337-3002-cve-list-v5.json"
            cve_list_target = cve_list_cache_dir / "CVE-1337-3002.json"
            if cve_list_target.exists():
                cve_list_target.unlink()
            shutil.copy2(cve_list_source, cve_list_target)
            test_files.append(str(cve_list_target))
            
            nvd_data = {
                "resultsPerPage": 1,
                "startIndex": 0,
                "totalResults": 1,
                "format": "NVD_CVE",
                "version": "2.0",
                "timestamp": "2025-11-14T00:00:00.000Z",
                "vulnerabilities": [{
                    "cve": {
                        "id": "CVE-1337-3002",
                        "sourceIdentifier": "testorg@example.com",
                        "published": "2001-01-01T00:00:00.000",
                        "lastModified": "2001-01-01T00:00:00.000",
                        "vulnStatus": "Analyzed",
                        "descriptions": [{
                            "lang": "en",
                            "value": "Test CVE for confirmed mappings placeholder filtering validation."
                        }],
                        "configurations": []
                    }
                }]
            }
            
            nvd_target = nvd_cache_dir / "CVE-1337-3002.json"
            if nvd_target.exists():
                nvd_target.unlink()
            with open(nvd_target, 'w', encoding='utf-8') as f:
                json.dump(nvd_data, f, indent=2)
            test_files.append(str(nvd_target))
            
            print(f"  * Setup complete: Copied test files with placeholder data to INPUT cache")
            
        except Exception as e:
            print(f"FAIL: Setup failed: {e}")
            return False
        
        # EXECUTE
        success, output_path, stdout, stderr = self.run_analysis_tool(
            "CVE-1337-3002",
            additional_args=["--sdc-report", "--cpe-suggestions", "--alias-report", "--cpe-as-generator", "--source-uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]
        )
        
        # TEARDOWN
        try:
            for test_file in test_files:
                if os.path.exists(test_file):
                    os.unlink(test_file)
            print(f"  * Cleanup complete: Removed {len(test_files)} INPUT cache files")
        except Exception as e:
            print(f"  WARNING: Cleanup failed: {e}")
        
        if not success:
            print(f"FAIL: Tool execution failed")
            print(f"STDERR: {stderr}")
            return False
        
        if output_path is None:
            print(f"FAIL: Could not extract output path from analysis tool output")
            print(f"STDOUT:\n{stdout}")
            print(f"STDERR:\n{stderr}")
            return False
        
        # VALIDATE
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                nvd_ish_data = json.load(f)
            
            cve_list_entries = nvd_ish_data["enrichedCVEv5Affected"].get("cveListV5AffectedEntries", [])
            if len(cve_list_entries) != 4:
                print(f"FAIL: Expected 4 affected entries, found {len(cve_list_entries)}")
                return False
            
            # Entry 2: validvendor/validproduct - should have confirmed mapping
            entry_2 = cve_list_entries[2]
            confirmed_mappings = entry_2.get("cpeSuggestions", {}).get("confirmedMappings", [])
            
            if len(confirmed_mappings) == 1:
                expected_mapping = "cpe:2.3:a:validvendor:validproduct:*:*:*:*:*:*:*:*"
                if confirmed_mappings[0] == expected_mapping:
                    print(f"  * Entry 2 correctly has confirmed mapping: {confirmed_mappings[0]}")
                else:
                    print(f"FAIL: Entry 2 mapping mismatch. Expected: {expected_mapping}, Found: {confirmed_mappings[0]}")
                    return False
            else:
                print(f"FAIL: Entry 2 (validvendor/validproduct) expected 1 confirmed mapping, found {len(confirmed_mappings)}")
                return False
            
            # Entries 0, 1, 3 should NOT have confirmed mappings (placeholder filtering)
            for i in [0, 1, 3]:
                entry = cve_list_entries[i]
                mappings = entry.get("cpeSuggestions", {}).get("confirmedMappings", [])
                if len(mappings) > 0:
                    print(f"FAIL: Entry {i} should have no mappings due to placeholder filtering, found {len(mappings)}")
                    return False
            
            print(f"PASS: Confirmed mappings placeholder filtering integration test passed")
            print(f"  * Placeholder filtering working: valid entries got mappings, placeholder entries filtered out")
            return True
                
        except Exception as e:
            print(f"FAIL: NVD-ish output validation failed: {e}")
            return False
    
    def run_all_tests(self) -> bool:
        """Run all confirmed mapping tests in isolated environment."""
        
        show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
        
        if show_details:
            print("Confirmed Mappings Test Suite (Isolated)")
            print("=" * 60)
        else:
            print("Confirmed Mappings Test Suite (Isolated)")
        
        # Setup isolated environment
        copied_files = self.setup_test_environment()
        
        try:
            tests = [
                ("Confirmed Mappings Integration", self.test_confirmed_mappings_integration),
                ("Confirmed Mappings Placeholder Filtering Integration", self.test_confirmed_mappings_placeholder_filtering),
            ]
            
            for test_name, test_func in tests:
                try:
                    if test_func():
                        self.passed += 1
                    print(f"Progress: {self.passed}/{self.total} tests passed")
                except Exception as e:
                    print(f"❌ FAIL: {test_name} - Exception: {e}")
            
            print("\n" + "=" * 60)
            print(f"Tests passed: {self.passed}/{self.total}")
            
            success = self.passed == self.total
            if success:
                print("SUCCESS: All confirmed mapping tests passed!")
            else:
                print("FAIL: Some confirmed mapping tests failed")
            
            print(f'TEST_RESULTS: PASSED={self.passed} TOTAL={self.total} SUITE="Confirmed Mappings (Isolated)"')
            
            return success
            
        finally:
            self.cleanup_test_environment(copied_files)


def main():
    """Main entry point for isolated confirmed mappings test suite."""
    test_suite = ConfirmedMappingsTestSuite()
    success = test_suite.run_all_tests()
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
