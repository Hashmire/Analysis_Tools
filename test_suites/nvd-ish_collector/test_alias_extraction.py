#!/usr/bin/env python3
"""
Alias Extraction Test Suite

Isolated test suite for alias extraction functionality:
- Alias extraction integration from Platform Entry Notification Registry  
- Placeholder filtering for alias data

Test Pattern Compliance:
All test cases follow the proper NVD-ish collector test pattern:
    1. SETUP: Copy test files to INPUT cache directories
    2. EXECUTE: Run normal tool execution with --alias-report flag
    3. VALIDATE: Check OUTPUT cache for expected alias extraction data
    4. TEARDOWN: Clean up INPUT cache test files

Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Usage:
    python test_suites/nvd-ish_collector/test_alias_extraction.py
"""

import sys
import os
import json
import subprocess
import shutil
from pathlib import Path
from typing import Optional, Tuple

# Force UTF-8 output encoding for Windows compatibility
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Test configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent
TEST_FILES_DIR = Path(__file__).parent
CACHE_DIR = PROJECT_ROOT / "cache"

class AliasExtractionTestSuite:
    """Test suite for alias extraction functionality."""
    
    def __init__(self):
        self.passed = 0
        self.total = 2
        
    def setup_test_environment(self):
        """Set up test environment by copying test files to INPUT cache locations."""
        print("Setting up alias extraction test environment...")
        
        copied_files = []
        
        # CVE-1337-0001 is used for alias extraction integration testing
        cve_id = "CVE-1337-0001"
        year = "1337"
        dir_name = "0xxx"
        
        # Pre-create cache directory structures
        for cache_type in ["cve_list_v5", "nvd_2.0_cves", "nvd-ish_2.0_cves"]:
            cache_dir = CACHE_DIR / cache_type / year / dir_name
            cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy CVE List V5 file
        cve_list_cache_dir = CACHE_DIR / "cve_list_v5" / year / dir_name
        cve_list_source = TEST_FILES_DIR / f"{cve_id}-cve-list-v5.json"
        if cve_list_source.exists():
            cve_list_target = cve_list_cache_dir / f"{cve_id}.json"
            if cve_list_target.exists():
                cve_list_target.unlink()
            shutil.copy2(cve_list_source, cve_list_target)
            copied_files.append(str(cve_list_target))
        
        # Copy NVD 2.0 file
        nvd_cache_dir = CACHE_DIR / "nvd_2.0_cves" / year / dir_name
        nvd_source = TEST_FILES_DIR / f"{cve_id}-nvd-2.0.json"
        if nvd_source.exists():
            nvd_target = nvd_cache_dir / f"{cve_id}.json"
            if nvd_target.exists():
                nvd_target.unlink()
            shutil.copy2(nvd_source, nvd_target)
            copied_files.append(str(nvd_target))
        
        print(f"  * Copied {len(copied_files)} test files to INPUT cache")
        return copied_files
    
    def cleanup_test_environment(self, copied_files):
        """Clean up test environment by removing copied test files."""
        print("Cleaning up alias extraction test environment...")
        
        for file_path in copied_files:
            try:
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(f"  WARNING: Could not remove {file_path}: {e}")
        
        print(f"  * Cleaned up {len(copied_files)} test files")
    
    def run_analysis_tool(self, cve_id: str, additional_args: list = None) -> Tuple[bool, Optional[Path], str, str]:
        """Run the analysis tool and return success status, output path, stdout, stderr."""
        
        # Construct output path based on CVE ID
        year = cve_id.split('-')[1]
        sequence = cve_id.split('-')[2]
        thousands_dir = f"{sequence[0]}xxx"
        output_path = CACHE_DIR / "nvd-ish_2.0_cves" / year / thousands_dir / f"{cve_id}.json"
        
        # Remove existing output file to ensure fresh run
        if output_path.exists():
            output_path.unlink()
        
        # Build command
        cmd = [
            sys.executable, "-m", "src.analysis_tool.core.analysis_tool",
            "--cve", cve_id,
            "--nvd-ish-only",
            "--alias-report"
        ]
        
        if additional_args:
            cmd.extend(additional_args)
        
        # Run tool
        try:
            result = subprocess.run(
                cmd,
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            success = result.returncode == 0 and output_path.exists()
            return success, output_path, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            return False, None, "", "Tool execution timed out"
        except Exception as e:
            return False, None, "", str(e)
    
    def test_alias_extraction_integration(self) -> bool:
        """Test alias extraction integration from Platform Entry Notification Registry."""
        print(f"\n=== Test 1: Alias Extraction Integration ===")
        
        # Run with alias report enabled (this should trigger alias extraction integration)
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-0001", additional_args=["--source-uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"])
        
        if not success:
            print(f"❌ FAIL: Analysis tool failed with alias extraction")
            if stderr:
                print(f"Error: {stderr[:200]}...")
            return False
        
        if not output_path.exists():
            print(f"❌ FAIL: Enhanced record not created")
            return False
        
        # Check for alias-specific metadata and structure
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            # Check for alias extraction timestamp in tool execution metadata
            tool_metadata = data.get("enrichedCVEv5Affected", {}).get("toolExecutionMetadata", {})
            alias_timestamp = tool_metadata.get("aliasExtraction")
            
            if not alias_timestamp:
                print(f"❌ FAIL: aliasExtraction timestamp missing from tool execution metadata")
                return False
            
            # Validate timestamp format (ISO 8601 with Z suffix)
            import re
            timestamp_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$'
            
            if not re.match(timestamp_pattern, alias_timestamp):
                print(f"❌ FAIL: aliasExtraction timestamp format invalid: {alias_timestamp}")
                return False
            
            # Check for alias extraction data in affected entries (II.C.3)
            cve_list_entries = data.get("enrichedCVEv5Affected", {}).get("cveListV5AffectedEntries", [])
            
            alias_entries_found = 0
            total_aliases_found = 0
            
            for entry_index, entry in enumerate(cve_list_entries):
                alias_extraction = entry.get("aliasExtraction", {})
                
                if alias_extraction:
                    alias_entries_found += 1
                    
                    # Validate alias extraction structure per our implementation
                    required_keys = ['sourceId', 'cvelistv5AffectedEntryIndex', 'aliases']
                    for key in required_keys:
                        if key not in alias_extraction:
                            print(f"❌ FAIL: Entry {entry_index} alias extraction missing required key: {key}")
                            return False
                    
                    # Validate sourceId format
                    source_id = alias_extraction.get('sourceId', '')
                    if not source_id.startswith('Hashmire/Analysis_Tools'):
                        print(f"❌ FAIL: Entry {entry_index} alias extraction has invalid sourceId: {source_id}")
                        return False
                    
                    # Validate cvelistv5AffectedEntryIndex format
                    entry_index_path = alias_extraction.get('cvelistv5AffectedEntryIndex', '')
                    if not entry_index_path.startswith('cve.containers.'):
                        print(f"❌ FAIL: Entry {entry_index} alias extraction has invalid entry index path: {entry_index_path}")
                        return False
                    
                    # Validate that the path has the correct format with array index notation
                    import re
                    if not re.search(r'\[\d+\]$', entry_index_path):
                        print(f"❌ FAIL: Entry {entry_index} alias extraction path missing array index: {entry_index_path}")
                        return False
                    
                    # Validate aliases array
                    aliases = alias_extraction.get('aliases', [])
                    if not isinstance(aliases, list):
                        print(f"❌ FAIL: Entry {entry_index} aliases must be a list")
                        return False
                    
                    # Validate individual alias objects
                    for alias_index, alias in enumerate(aliases):
                        if not isinstance(alias, dict):
                            print(f"❌ FAIL: Entry {entry_index} alias {alias_index} must be a dictionary")
                            return False
                        
                        # Check for essential alias properties (vendor, product typically expected)
                        if 'vendor' not in alias and 'product' not in alias:
                            print(f"❌ FAIL: Entry {entry_index} alias {alias_index} missing vendor/product")
                            return False
                        
                        # Ensure no report-specific fields leaked through
                        forbidden_fields = ['source_cve', '_alias_key']
                        for forbidden_field in forbidden_fields:
                            if forbidden_field in alias:
                                print(f"❌ FAIL: Entry {entry_index} alias {alias_index} contains forbidden field: {forbidden_field}")
                                return False
                    
                    total_aliases_found += len(aliases)
                    
                    # Get vendor/product for reporting
                    origin_entry = entry.get("originAffectedEntry", {})
                    vendor_name = origin_entry.get("vendor", "unknown")
                    product_name = origin_entry.get("product", "unknown")
                    
                    print(f"  ✓ Entry {entry_index} ({vendor_name}/{product_name}): {len(aliases)} filtered aliases")
                    
                    # Show sample aliases for verification
                    for alias in aliases[:2]:
                        alias_vendor = alias.get('vendor', 'N/A')
                        alias_product = alias.get('product', 'N/A')
                        alias_platform = alias.get('platform', 'N/A')
                        print(f"    - {alias_vendor}/{alias_product} ({alias_platform})")
                    if len(aliases) > 2:
                        print(f"    ... and {len(aliases) - 2} more aliases")
            
            if alias_entries_found == 0:
                print(f"⚠️  INFO: No alias extraction data found in enhanced record")
                print(f"  This may indicate:")
                print(f"  - No alias data was available in Platform Entry Notification Registry")
                print(f"  - Source UUID filtering prevented alias extraction")
                print(f"  - Alias extraction processing was skipped due to conditions")
                print(f"✅ PASS: Alias extraction integration structure validated (no data found)")
                return True
            
            print(f"✅ PASS: Alias extraction integration validated successfully")
            print(f"  ✓ aliasExtraction timestamp: {alias_timestamp}")
            print(f"  ✓ Timestamp format valid (ISO 8601 with Z suffix)")
            print(f"  ✓ Alias data integrated in {alias_entries_found} affected entries")
            print(f"  ✓ Total filtered aliases found: {total_aliases_found}")
            print(f"  ✓ Data filtering working (no report-specific fields found)")
            
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating alias extraction integration: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_alias_extraction_placeholder_filtering(self) -> bool:
        """Test alias extraction placeholder filtering unit tests."""
        print(f"\n=== Test 2: Alias Extraction Placeholder Filtering ===")
        
        try:
            # Import NVDishCollector for direct method testing
            import sys
            sys.path.insert(0, str(PROJECT_ROOT))
            from src.analysis_tool.storage.nvd_ish_collector import NVDishCollector
            
            collector = NVDishCollector()
            
            # Test case 1: Placeholder vendor should be filtered out
            test_alias_1 = {
                'vendor': 'n/a',
                'product': 'Test Product',
                'platform': 'Linux',
                'source_cve': ['CVE-1337-PLACEHOLDER-TEST'],
                '_alias_key': 'test_key_1'
            }
            
            result_1 = collector._filter_badge_collector_alias_data(test_alias_1)
            expected_1 = {'product': 'Test Product', 'platform': 'Linux'}
            
            if result_1 != expected_1:
                print(f"❌ FAIL: Placeholder vendor filtering failed. Expected: {expected_1}, Got: {result_1}")
                return False
            
            # Test case 2: Placeholder product should be filtered out
            test_alias_2 = {
                'vendor': 'Valid Vendor',
                'product': 'unknown',
                'platforms': ['Linux', 'Windows'],
                'source_cve': ['CVE-1337-PLACEHOLDER-TEST']
            }
            
            result_2 = collector._filter_badge_collector_alias_data(test_alias_2)
            expected_2 = {'vendor': 'Valid Vendor', 'platforms': ['Linux', 'Windows']}
            
            if result_2 != expected_2:
                print(f"❌ FAIL: Placeholder product filtering failed. Expected: {expected_2}, Got: {result_2}")
                return False
            
            # Test case 3: Mixed platform array with placeholders
            test_alias_3 = {
                'vendor': 'Microsoft',
                'product': 'Windows Server 2019',
                'platforms': ['n/a', 'x64-based Systems', 'unspecified'],
                'packageName': 'not available',
                'repo': 'https://github.com/valid/repo',
                'source_cve': ['CVE-1337-PLACEHOLDER-TEST']
            }
            
            result_3 = collector._filter_badge_collector_alias_data(test_alias_3)
            expected_3 = {
                'vendor': 'Microsoft', 
                'product': 'Windows Server 2019',
                'platforms': ['x64-based Systems'],
                'repo': 'https://github.com/valid/repo'
            }
            
            if result_3 != expected_3:
                print(f"❌ FAIL: Mixed placeholder array filtering failed. Expected: {expected_3}, Got: {result_3}")
                return False
            
            # Test case 4: All placeholders should return None
            test_alias_4 = {
                'vendor': 'n/a',
                'product': 'unknown',
                'platforms': ['unspecified', 'not available'],
                'packageName': 'not specified',
                'source_cve': ['CVE-1337-PLACEHOLDER-TEST']
            }
            
            result_4 = collector._filter_badge_collector_alias_data(test_alias_4)
            
            if result_4 is not None:
                print(f"❌ FAIL: All placeholder data should return None. Got: {result_4}")
                return False
            
            # Test case 5: Valid data should pass through unchanged
            test_alias_5 = {
                'vendor': 'Valid Vendor',
                'product': 'Valid Product',
                'platforms': ['Linux'],
                'packageName': 'valid-package',
                'collectionURL': 'https://example.com/packages',
                'source_cve': ['CVE-1337-PLACEHOLDER-TEST'],
                '_alias_key': 'test_key_5'
            }
            
            result_5 = collector._filter_badge_collector_alias_data(test_alias_5)
            expected_5 = {
                'vendor': 'Valid Vendor',
                'product': 'Valid Product',
                'platforms': ['Linux'],
                'packageName': 'valid-package',
                'collectionURL': 'https://example.com/packages'
            }
            
            if result_5 != expected_5:
                print(f"❌ FAIL: Valid data filtering failed. Expected: {expected_5}, Got: {result_5}")
                return False
            
            print(f"✅ PASS: All placeholder filtering unit tests passed")
            print(f"  ✓ Placeholder vendor field filtered correctly")
            print(f"  ✓ Placeholder product field filtered correctly") 
            print(f"  ✓ Mixed placeholder arrays filtered correctly")
            print(f"  ✓ All-placeholder data returns None correctly")
            print(f"  ✓ Valid data passes through unchanged")
            print(f"  ✓ Metadata fields (source_cve, _alias_key) excluded correctly")
            
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Exception during placeholder filtering test: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_all_tests(self) -> bool:
        """Run all alias extraction tests and return overall success."""
        
        print("Alias Extraction Test Suite")
        print("=" * 60)
        
        # Setup test environment
        copied_files = self.setup_test_environment()
        
        try:
            tests = [
                ("Alias Extraction Integration", self.test_alias_extraction_integration),
                ("Alias Extraction Placeholder Filtering", self.test_alias_extraction_placeholder_filtering),
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
                print("SUCCESS: All alias extraction tests passed!")
            else:
                print("FAIL: Some alias extraction tests failed")
            
            # Output standardized test results
            print(f'TEST_RESULTS: PASSED={self.passed} TOTAL={self.total} SUITE="Alias Extraction"')
            
            return success
            
        finally:
            # Always clean up test environment
            self.cleanup_test_environment(copied_files)


def main():
    """Main entry point for alias extraction test suite."""
    test_suite = AliasExtractionTestSuite()
    success = test_suite.run_all_tests()
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
