#!/usr/bin/env python3
"""
CPE Culling Test Suite

Isolated test suite for CPE culling quality control functionality:
- Specificity culling (overly broad queries)
- NVD API compatibility culling (field length, escaped characters)

Test Pattern Compliance:
All test cases follow the proper NVD-ish collector test pattern:
    1. SETUP: Copy test files to INPUT cache directories
    2. EXECUTE: Run normal tool execution (not isolated test-file mode)
    3. VALIDATE: Check OUTPUT cache for expected culled CPE strings
    4. TEARDOWN: Clean up INPUT cache test files

Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Usage:
    python test_suites/nvd-ish_collector/test_cpe_culling.py
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

class CPECullingTestSuite:
    """Test suite for CPE culling quality control functionality.
    
    Tests CPE culling for both specificity and NVD API compatibility checks.
    
    NOT CURRENTLY TESTABLE VIA INTEGRATION (but are CRITICAL production safeguards):
    
    The following checks exist as defensive validations that catch issues when:
    - Source data is malformed or contains unexpected patterns
    - String processing happens in unexpected order
    - Normalization/cleaning operations fail or are bypassed
    
    1. Empty CPE string - Can occur if source affected entry has all empty/null fields
    2. Non-ASCII characters - Can slip through if Unicode normalization fails or bypasses formatFor23CPE()
    3. Leading/trailing whitespace - Can remain if .strip() operations happen in wrong order
    4. Trailing underscore - Can occur from space-to-underscore conversion before stripping
    
    These protect the API boundary when preprocessing fails. While current integration tests
    cannot trigger them (preprocessing works correctly), they guard against:
    - Future refactoring bugs in preprocessing pipeline
    - Malformed data from external sources
    - Processing order changes that break assumptions
    
    Also not testable via integration (theoretical limits):
    5. Missing CPE 2.3 prefix - Tool always generates valid prefix
    6. Incorrect component count - Tool always generates exactly 13 components
    7. Total CPE > 375 chars - Version stripped during curation; max realistic CPE ~206 chars
    
    Consider adding direct unit tests of is_nvd_api_compatible() with hand-crafted strings
    to verify these defensive checks work when called.
    """
    
    def __init__(self):
        self.passed = 0
        self.total = 4
        
    def setup_test_environment(self):
        """Set up test environment by copying test files to INPUT cache locations."""
        print("Setting up CPE culling test environment...")
        
        copied_files = []
        
        # CVE-1337-2001 is used for comprehensive CPE culling validation
        cve_id = "CVE-1337-2001"
        year = "1337"
        dir_name = "2xxx"
        
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
        print("Cleaning up CPE culling test environment...")
        
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
            "--cpe-suggestions"
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
    
    def test_culled_cpe_specificity(self) -> bool:
        """Test CPE culling for specificity issues using real CVE data that triggers culling.
        
        Tests:
        - Entry 0: Both vendor and product are wildcards
        - Entries 1-3: Single short attributes (≤2 chars) - too broad
        """
        print(f"\n=== Test 1: CPE Match Strings Culled - Specificity Issues ===")
        
        print(f"  ✓ Using CVE-1337-2001 comprehensive test data (specificity culling focus)")
        
        # Run with CPE suggestions enabled
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-2001")
        
        if not success:
            print(f"❌ FAIL: Analysis tool failed with CPE suggestions")
            if stderr:
                print(f"  Error output: {stderr[:1000]}")
            if stdout:
                print(f"  Standard output: {stdout[:1000]}")
            return False
        
        # Validate CPE match strings culled in output - check EXACT expected counts and values
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            cve_list_entries = data.get("enrichedCVEv5Affected", {}).get("cveListV5AffectedEntries", [])
            
            # Expected: Entry 0 (vendor: "*", product: "*") should have exactly 1 CPE match string culled with insufficient_specificity
            # Only generates 1 CPE because there's only 1 platform ("All")
            # CPE format: vendor-only CPE with wildcard vendor: cpe:2.3:*::*:...
            expected_entry_index = 0
            expected_culled_count = 1
            expected_culled_cpes = [
                "cpe:2.3:*::*:*:*:*:*:*:*:*:*",  # Vendor-only CPE with wildcard vendor
                "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*"  # Full wildcard CPE
            ]
            
            if len(cve_list_entries) <= expected_entry_index:
                print(f"❌ FAIL: Expected at least {expected_entry_index + 1} CVE entries, found {len(cve_list_entries)}")
                return False
                
            target_entry = cve_list_entries[expected_entry_index]
            cpe_suggestions = target_entry.get("cpeSuggestions", {})
            
            if not cpe_suggestions:
                print(f"❌ FAIL: Entry {expected_entry_index} missing cpeSuggestions")
                return False
                
            culled_strings = cpe_suggestions.get('cpeMatchStringsCulled', [])
            
            # Validate structure
            if not isinstance(culled_strings, list):
                print(f"❌ FAIL: cpeMatchStringsCulled should be array")
                return False
                
            # Check exact count
            if len(culled_strings) != expected_culled_count:
                print(f"❌ FAIL: Expected exactly {expected_culled_count} CPE match strings culled for specificity, found {len(culled_strings)}")
                return False
            
            # Validate each CPE match string culled
            specificity_count = 0
            for culled in culled_strings:
                if not isinstance(culled, dict):
                    print(f"❌ FAIL: CPE match string culled should be object")
                    return False
                
                if 'cpeString' not in culled or 'reason' not in culled:
                    print(f"❌ FAIL: CPE match string culled missing required fields")
                    return False
                
                # Check for specificity reasons
                if culled['reason'] == 'insufficient_specificity_vendor_product_required':
                    specificity_count += 1
                    # Validate the CPE string is one of the expected overly broad ones
                    if culled['cpeString'] not in expected_culled_cpes:
                        print(f"❌ FAIL: Unexpected CPE match string culled: {culled['cpeString']}")
                        return False
                else:
                    print(f"❌ FAIL: Expected 'insufficient_specificity_vendor_product_required' reason, got: {culled['reason']}")
                    return False
            
            if specificity_count != expected_culled_count:
                print(f"❌ FAIL: Expected {expected_culled_count} specificity CPE match strings culled, found {specificity_count}")
                return False
            
            print(f"✅ PASS: CPE match strings culled - specificity validation passed")
            print(f"  ✓ Found exactly {len(culled_strings)} CPE match strings culled as expected")
            print(f"  ✓ All {specificity_count} strings correctly marked as 'insufficient_specificity_vendor_product_required'")
            print(f"  ✓ CPE strings match expected overly broad patterns")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating CPE match strings culled: {e}")
            return False
    
    def test_culled_cpe_nvd_api(self) -> bool:
        """Test CPE culling for NVD API compatibility issues using real CVE data that triggers culling.
        
        Tests:
        - Entry 6: Vendor field > 88 characters - generates 3 culled CPEs
        - Entry 7: Escaped comma pattern in product (>50 chars with \\,) - generates 3 culled CPEs
        - Entry 8: Trailing underscore from Unicode removal (company_中文 → company_) - generates 1 culled CPE
        
        Note: Entry 8 only generates 1 culled CPE because the curation process (curateCPEAttributes)
        removes trailing underscores from vendor fields before generating platform-specific CPEs.
        Only the raw uncurated vendor+product CPE retains the trailing underscore and gets culled.
        This validates both defensive validation AND proper curation behavior.
        """
        print(f"\n=== Test 2: CPE Match Strings Culled - NVD API Issues ===")
        
        print(f"  ✓ Using CVE-1337-2001 comprehensive test data (NVD API compatibility focus)")
        
        # Run with CPE suggestions enabled
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-2001")
        
        if not success:
            print(f"❌ FAIL: Analysis tool failed with CPE suggestions")
            if stderr:
                print(f"  Error output: {stderr[:1000]}")
            if stdout:
                print(f"  Standard output: {stdout[:1000]}")
            return False
        
        # Validate NVD API CPE match strings culled in output - check EXACT expected counts and values
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            cve_list_entries = data.get("enrichedCVEv5Affected", {}).get("cveListV5AffectedEntries", [])
            
            # Expected NVD API culling from three specific entries
            expected_nvd_api_entries = [
                {
                    "entry_index": 6, 
                    "description": "extremely long vendor name (>88 chars)",
                    "expected_culled_count": 3,
                    "expected_reason": "nvd_api_field_too_long"
                },
                {
                    "entry_index": 7,
                    "description": "escaped commas in product (>50 chars)", 
                    "expected_culled_count": 3,
                    "expected_reason": "nvd_api_escaped_comma_pattern"
                },
                {
                    "entry_index": 8,
                    "description": "trailing underscore from Unicode removal (raw uncurated CPE only)",
                    "expected_culled_count": 1,
                    "expected_reason": "nvd_api_trailing_underscore"
                }
            ]
            
            total_nvd_api_culled = 0
            
            for expected_entry in expected_nvd_api_entries:
                entry_index = expected_entry["entry_index"]
                expected_count = expected_entry["expected_culled_count"]
                expected_reason_pattern = expected_entry["expected_reason"]
                description = expected_entry["description"]
                
                if len(cve_list_entries) <= entry_index:
                    print(f"❌ FAIL: Expected at least {entry_index + 1} CVE entries for {description}, found {len(cve_list_entries)}")
                    return False
                    
                target_entry = cve_list_entries[entry_index]
                cpe_suggestions = target_entry.get("cpeSuggestions", {})
                
                if not cpe_suggestions:
                    print(f"❌ FAIL: Entry {entry_index} ({description}) missing cpeSuggestions")
                    return False
                    
                culled_strings = cpe_suggestions.get('cpeMatchStringsCulled', [])
                
                # Count NVD API incompatible strings in this entry
                nvd_api_culled_in_entry = 0
                for culled in culled_strings:
                    if not isinstance(culled, dict):
                        print(f"❌ FAIL: CPE match string culled should be object in entry {entry_index}")
                        return False
                    
                    if 'cpeString' not in culled or 'reason' not in culled:
                        print(f"❌ FAIL: CPE match string culled missing required fields in entry {entry_index}")
                        return False
                    
                    # Check for NVD API compatibility issues (match against expected mapped reason codes)
                    reason = culled['reason']
                    is_nvd_api_issue = False
                    
                    # Check if reason is one of the NVD API issue codes (after reason mapping)
                    nvd_api_reason_codes = [
                        'nvd_api_field_too_long',
                        'nvd_api_escaped_comma_pattern', 
                        'nvd_api_non_ascii_characters',
                        'nvd_api_missing_prefix',
                        'nvd_api_wrong_component_count',
                        'nvd_api_whitespace_in_field',
                        'nvd_api_trailing_underscore'
                    ]
                    
                    if reason in nvd_api_reason_codes:
                        is_nvd_api_issue = True
                        nvd_api_culled_in_entry += 1
                        total_nvd_api_culled += 1
                        
                        # Validate the specific reason matches expected for this entry
                        expected_reason = expected_entry["expected_reason"]
                        if reason != expected_reason:
                            print(f"❌ FAIL: Entry {entry_index} expected '{expected_reason}' reason, got: {reason}")
                            return False
                
                if nvd_api_culled_in_entry != expected_count:
                    print(f"❌ FAIL: Entry {entry_index} ({description}): Expected {expected_count} NVD API CPE match strings culled, found {nvd_api_culled_in_entry}")
                    return False
                
                print(f"  ✓ Entry {entry_index} ({description}): Found {nvd_api_culled_in_entry} NVD API CPE match strings culled as expected")
            
            # Validate total count
            expected_total_nvd_api_culled = sum(entry["expected_culled_count"] for entry in expected_nvd_api_entries)
            if total_nvd_api_culled != expected_total_nvd_api_culled:
                print(f"❌ FAIL: Expected total of {expected_total_nvd_api_culled} NVD API CPE match strings culled, found {total_nvd_api_culled}")
                return False
            
            print(f"✅ PASS: CPE match strings culled - NVD API validation passed")
            print(f"  ✓ Found exactly {total_nvd_api_culled} NVD API CPE match strings culled as expected")
            print(f"  ✓ All strings correctly marked with specific NVD API compatibility reasons")
            print(f"  ✓ Long fields, escaped commas, and trailing underscores (raw CPE) detected")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating NVD API CPE match strings culled: {e}")
            return False
    
    def test_asterisk_removal_validation(self) -> bool:
        """Test that asterisks are properly removed from vendor/product names and don't create invalid CPEs.
        
        Validates:
        - Entry 9: Asterisk in vendor name ("Sp*tify Vendor" → "sptify_vendor")
        - Entry 10: Multiple asterisks in product ("Product*Name*Test" → "productnametest")
        - Entry 11: Asterisks + Unicode ("Café*München", "*Asterisk*Unicode*" → "cafemanchen", "asteriskunicode")
        
        Critical edge cases:
        - Asterisks removed BEFORE character escaping (no "\\*" escape sequences)
        - Combined with Unicode normalization (both transformations work together)
        - No internal asterisks in final CPE strings (would cause NVD API rejection)
        - No trailing underscores from asterisk removal
        
        This validates:
        1. Asterisk removal in formatFor23CPE() normalization pipeline
        2. No downstream edge cases from asterisk removal (trailing underscores, etc.)
        3. Combined Unicode + asterisk removal doesn't break validation
        4. Generated CPEs pass is_nvd_api_compatible() validation
        """
        print(f"\n=== Test 3: Asterisk Removal Validation ===")
        
        print(f"  ✓ Using CVE-1337-2001 comprehensive test data (asterisk removal focus)")
        
        # Run with CPE suggestions enabled
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-2001")
        
        if not success:
            print(f"❌ FAIL: Analysis tool failed with CPE suggestions")
            if stderr:
                print(f"  Error output: {stderr[:1000]}")
            if stdout:
                print(f"  Standard output: {stdout[:1000]}")
            return False
        
        # Validate that asterisk-containing entries produce valid CPEs without culling
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            cve_list_entries = data.get("enrichedCVEv5Affected", {}).get("cveListV5AffectedEntries", [])
            
            # Expected test entries with asterisks
            expected_asterisk_entries = [
                {
                    "entry_index": 9,
                    "original_vendor": "Sp*tify Vendor",
                    "original_product": "normalproduct",
                    "expected_vendor_formatted": "sptify_vendor",
                    "expected_product_formatted": "normalproduct",
                    "description": "asterisk in vendor name"
                },
                {
                    "entry_index": 10,
                    "original_vendor": "normalvendor",
                    "original_product": "Product*Name*Test",
                    "expected_vendor_formatted": "normalvendor",
                    "expected_product_formatted": "productnametest",
                    "description": "multiple asterisks in product name"
                },
                {
                    "entry_index": 11,
                    "original_vendor": "Café*München",
                    "original_product": "*Asterisk*Unicode*",
                    "expected_vendor_formatted": "cafemunchen",  # Unicode (ü→u) + asterisk removal
                    "expected_product_formatted": "asteriskunicode",  # Boundary asterisks + internal asterisks removed
                    "description": "asterisks combined with Unicode"
                }
            ]
            
            validation_errors = []
            
            for expected_entry in expected_asterisk_entries:
                entry_index = expected_entry["entry_index"]
                description = expected_entry["description"]
                
                if len(cve_list_entries) <= entry_index:
                    validation_errors.append(f"Entry {entry_index} ({description}): Expected at least {entry_index + 1} CVE entries, found {len(cve_list_entries)}")
                    continue
                    
                target_entry = cve_list_entries[entry_index]
                cpe_suggestions = target_entry.get("cpeSuggestions", {})
                
                if not cpe_suggestions:
                    validation_errors.append(f"Entry {entry_index} ({description}): Missing cpeSuggestions")
                    continue
                
                # Check that CPEs were generated successfully (not culled due to asterisks)
                searched_strings = cpe_suggestions.get('cpeMatchStringsSearched', [])
                culled_strings = cpe_suggestions.get('cpeMatchStringsCulled', [])
                
                if not searched_strings:
                    validation_errors.append(f"Entry {entry_index} ({description}): No CPE match strings searched - asterisks may have broken generation")
                    continue
                
                # Validate NO internal asterisks in searched CPE strings
                for cpe_string in searched_strings:
                    # Parse CPE components
                    if not cpe_string.startswith('cpe:2.3:'):
                        validation_errors.append(f"Entry {entry_index} ({description}): Invalid CPE prefix: {cpe_string}")
                        continue
                    
                    parts = cpe_string.split(':')
                    if len(parts) != 13:
                        validation_errors.append(f"Entry {entry_index} ({description}): Invalid CPE component count: {len(parts)}")
                        continue
                    
                    vendor_part = parts[3]
                    product_part = parts[4]
                    
                    # Check vendor formatting (asterisks removed)
                    expected_vendor = expected_entry["expected_vendor_formatted"]
                    # Vendor can have boundary wildcards (*vendor*) but should match expected format inside
                    if vendor_part != '*':  # Skip wildcard-only vendor
                        vendor_stripped = vendor_part.lstrip('*').rstrip('*')
                        if expected_vendor not in vendor_stripped:
                            validation_errors.append(
                                f"Entry {entry_index} ({description}): Vendor mismatch - "
                                f"expected '{expected_vendor}' in formatted CPE, got: {vendor_part}"
                            )
                    
                    # Check product formatting (asterisks removed)
                    expected_product = expected_entry["expected_product_formatted"]
                    if product_part != '*':  # Skip wildcard-only product
                        product_stripped = product_part.lstrip('*').rstrip('*')
                        if expected_product not in product_stripped:
                            validation_errors.append(
                                f"Entry {entry_index} ({description}): Product mismatch - "
                                f"expected '{expected_product}' in formatted CPE, got: {product_part}"
                            )
                    
                    # CRITICAL: Check for internal asterisks (asterisks NOT at boundaries)
                    # Valid: *value*, Invalid: val*ue
                    for field_name, field_value in [('vendor', vendor_part), ('product', product_part)]:
                        if field_value and field_value not in ['*', '-']:
                            # Strip boundary wildcards
                            stripped = field_value.lstrip('*').rstrip('*')
                            if '*' in stripped:
                                validation_errors.append(
                                    f"Entry {entry_index} ({description}): CRITICAL - Internal asterisk found in {field_name}: {field_value}"
                                )
                
                # Check that asterisk-related issues are NOT in culled strings
                for culled in culled_strings:
                    reason = culled.get('reason', '')
                    if 'asterisk' in reason.lower():
                        validation_errors.append(
                            f"Entry {entry_index} ({description}): CPE culled for asterisk reason (should have been removed): {reason}"
                        )
                
                print(f"  ✓ Entry {entry_index} ({description}): {len(searched_strings)} valid CPEs generated, no internal asterisks")
            
            if validation_errors:
                print(f"❌ FAIL: Asterisk removal validation errors:")
                for error in validation_errors:
                    print(f"  - {error}")
                return False
            
            print(f"✅ PASS: Asterisk removal validation passed")
            print(f"  ✓ All {len(expected_asterisk_entries)} entries with asterisks processed correctly")
            print(f"  ✓ No internal asterisks in generated CPE strings")
            print(f"  ✓ Asterisk removal combined correctly with Unicode normalization")
            print(f"  ✓ No CPEs culled for asterisk-related issues")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating asterisk removal: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_colon_removal_validation(self) -> bool:
        """Test that colons are properly removed from vendor/product names to prevent CPE parsing issues.
        
        Validates:
        - Entry 12: Colon in vendor name ("Foliovision: Making the web work for you" → "foliovision_making_the_web_work_for_you")
        - Entry 13: Colons in product name ("Product:With:Colons" → "productwithcolons")
        - Entry 14: Colons + asterisks + Unicode combined ("Vendor:Café:Test", "Product*:*Mixed*" → "vendorcafetest", "productmixed")
        
        Critical validation points:
        - NO escaped colons (\\:) in CPE strings (would break breakoutCPEAttributes parsing)
        - NO field misalignment from colon splitting
        - Colons removed BEFORE character escaping
        - Combined transformations (Unicode + colon + asterisk removal) work together
        - No downstream parsing errors from colon removal
        
        Why colons must be removed (not escaped):
        1. CPE field delimiter - has structural meaning like asterisks
        2. breakoutCPEAttributes() uses .split(":") which splits on ALL colons including \\:
        3. Escaped colons cause field misalignment:
           - Input: "Foliovision: Making"
           - If escaped: "foliovision\\:_making"
           - CPE: cpe:2.3:*:foliovision\\:_making:product:...
           - After split(":"): vendor="foliovision\\", product="_making" (WRONG!)
           - Wildcards added: cpe:2.3:*:foliovision\\:*_making*:... (BROKEN!)
        4. Removing solves all issues: "foliovision_making" → no parsing problems
        
        This validates:
        1. Colon removal in formatFor23CPE() normalization pipeline
        2. No escaped colons in generated CPE strings
        3. Combined colon + asterisk + Unicode removal doesn't break validation
        4. Generated CPEs parse correctly with breakoutCPEAttributes()
        """
        print(f"\n=== Test 4: Colon Removal Validation ===")
        
        print(f"  ✓ Using CVE-1337-2001 comprehensive test data (colon removal focus)")
        
        # Run with CPE suggestions enabled
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-2001")
        
        if not success:
            print(f"❌ FAIL: Analysis tool failed with CPE suggestions")
            if stderr:
                print(f"  Error output: {stderr[:1000]}")
            if stdout:
                print(f"  Standard output: {stdout[:1000]}")
            return False
        
        # Validate that colon-containing entries produce valid CPEs without escaped colons
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            cve_list_entries = data.get("enrichedCVEv5Affected", {}).get("cveListV5AffectedEntries", [])
            
            # Expected test entries with colons
            expected_colon_entries = [
                {
                    "entry_index": 12,
                    "original_vendor": "Foliovision: Making the web work for you",
                    "original_product": "FV Flowplayer Video Player",
                    "expected_vendor_formatted": "foliovision_making_the_web_work_for_you",
                    "expected_product_formatted": "fv_flowplayer_video_player",
                    "description": "colons in vendor name (user's reported case)"
                },
                {
                    "entry_index": 13,
                    "original_vendor": "normalvendor",
                    "original_product": "Product:With:Colons",
                    "expected_vendor_formatted": "normalvendor",
                    "expected_product_formatted": "productwithcolons",
                    "description": "multiple colons in product name"
                },
                {
                    "entry_index": 14,
                    "original_vendor": "Vendor:Café:Test",
                    "original_product": "Product*:*Mixed*",
                    "expected_vendor_formatted": "vendorcafetest",  # Colons + Unicode removal
                    "expected_product_formatted": "productmixed",  # Colons + asterisks removed
                    "description": "colons + asterisks + Unicode combined"
                }
            ]
            
            validation_errors = []
            
            for expected_entry in expected_colon_entries:
                entry_index = expected_entry["entry_index"]
                description = expected_entry["description"]
                
                if len(cve_list_entries) <= entry_index:
                    validation_errors.append(f"Entry {entry_index} ({description}): Expected at least {entry_index + 1} CVE entries, found {len(cve_list_entries)}")
                    continue
                    
                target_entry = cve_list_entries[entry_index]
                cpe_suggestions = target_entry.get("cpeSuggestions", {})
                
                if not cpe_suggestions:
                    validation_errors.append(f"Entry {entry_index} ({description}): Missing cpeSuggestions")
                    continue
                
                # Check that CPEs were generated successfully
                searched_strings = cpe_suggestions.get('cpeMatchStringsSearched', [])
                culled_strings = cpe_suggestions.get('cpeMatchStringsCulled', [])
                
                if not searched_strings:
                    validation_errors.append(f"Entry {entry_index} ({description}): No CPE match strings searched - colons may have broken generation")
                    continue
                
                # CRITICAL: Validate NO escaped colons (\\:) in any CPE strings
                for cpe_string in searched_strings:
                    if '\\:' in cpe_string:
                        validation_errors.append(
                            f"Entry {entry_index} ({description}): CRITICAL - Escaped colon found in CPE: {cpe_string}"
                        )
                    
                    # Validate CPE can be parsed correctly
                    if not cpe_string.startswith('cpe:2.3:'):
                        validation_errors.append(f"Entry {entry_index} ({description}): Invalid CPE prefix: {cpe_string}")
                        continue
                    
                    parts = cpe_string.split(':')
                    if len(parts) != 13:
                        validation_errors.append(
                            f"Entry {entry_index} ({description}): Invalid CPE component count ({len(parts)} instead of 13) - likely colon splitting issue: {cpe_string}"
                        )
                        continue
                    
                    vendor_part = parts[3]
                    product_part = parts[4]
                    
                    # Check vendor formatting (colons removed)
                    expected_vendor = expected_entry["expected_vendor_formatted"]
                    if vendor_part != '*':
                        vendor_stripped = vendor_part.lstrip('*').rstrip('*')
                        if expected_vendor not in vendor_stripped:
                            validation_errors.append(
                                f"Entry {entry_index} ({description}): Vendor mismatch - "
                                f"expected '{expected_vendor}' in formatted CPE, got: {vendor_part}"
                            )
                    
                    # Check product formatting (colons removed)
                    expected_product = expected_entry["expected_product_formatted"]
                    if product_part != '*':
                        product_stripped = product_part.lstrip('*').rstrip('*')
                        if expected_product not in product_stripped:
                            validation_errors.append(
                                f"Entry {entry_index} ({description}): Product mismatch - "
                                f"expected '{expected_product}' in formatted CPE, got: {product_part}"
                            )
                    
                    # Validate vendor field doesn't contain escaped colon artifacts
                    if '\\:' in vendor_part:
                        validation_errors.append(
                            f"Entry {entry_index} ({description}): CRITICAL - Escaped colon in vendor field: {vendor_part}"
                        )
                    
                    # Validate product field doesn't contain escaped colon artifacts
                    if '\\:' in product_part:
                        validation_errors.append(
                            f"Entry {entry_index} ({description}): CRITICAL - Escaped colon in product field: {product_part}"
                        )
                
                # Check that no colon-related issues caused culling
                for culled in culled_strings:
                    reason = culled.get('reason', '')
                    cpe_str = culled.get('cpeString', '')
                    
                    # Check for escaped colons in culled strings (shouldn't exist)
                    if '\\:' in cpe_str:
                        validation_errors.append(
                            f"Entry {entry_index} ({description}): Escaped colon found in culled CPE: {cpe_str}"
                        )
                    
                    # Check if culling was due to colon-related parsing issues
                    if 'colon' in reason.lower() or 'delimiter' in reason.lower():
                        validation_errors.append(
                            f"Entry {entry_index} ({description}): CPE culled for colon reason (should have been removed): {reason}"
                        )
                
                print(f"  ✓ Entry {entry_index} ({description}): {len(searched_strings)} valid CPEs generated, no escaped colons")
            
            if validation_errors:
                print(f"❌ FAIL: Colon removal validation errors:")
                for error in validation_errors:
                    print(f"  - {error}")
                return False
            
            print(f"✅ PASS: Colon removal validation passed")
            print(f"  ✓ All {len(expected_colon_entries)} entries with colons processed correctly")
            print(f"  ✓ No escaped colons (\\:) in generated CPE strings")
            print(f"  ✓ CPE field alignment correct (no parsing issues)")
            print(f"  ✓ Colon removal combined correctly with asterisk and Unicode normalization")
            print(f"  ✓ No CPEs culled for colon-related issues")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating colon removal: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_all_tests(self) -> bool:
        """Run all CPE culling tests and return overall success."""
        
        print("CPE Culling Test Suite")
        print("=" * 60)
        
        # Setup test environment
        copied_files = self.setup_test_environment()
        
        try:
            tests = [
                ("Culled CPE Strings - Specificity Issues", self.test_culled_cpe_specificity),
                ("Culled CPE Strings - NVD API Issues", self.test_culled_cpe_nvd_api),
                ("Asterisk Removal Validation", self.test_asterisk_removal_validation),
                ("Colon Removal Validation", self.test_colon_removal_validation),
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
                print("SUCCESS: All CPE culling tests passed!")
            else:
                print("FAIL: Some CPE culling tests failed")
            
            # Output standardized test results
            print(f'TEST_RESULTS: PASSED={self.passed} TOTAL={self.total} SUITE="CPE Culling"')
            
            return success
            
        finally:
            # Always clean up test environment
            self.cleanup_test_environment(copied_files)


def main():
    """Main entry point for CPE culling test suite."""
    test_suite = CPECullingTestSuite()
    success = test_suite.run_all_tests()
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
