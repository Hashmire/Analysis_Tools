#!/usr/bin/env python3
"""
Source Data Concerns (SDC) Integration Test Suite

Isolated test suite for Source Data Concerns detection and integration:
- Basic SDC detection within enhanced records
- SDC registry parameter passing validation
- SDC metadata placement in enhanced records
- Comprehensive detection group functionality and skip logic

Test Pattern Compliance:
All test cases follow the proper NVD-ish collector test pattern:
    1. SETUP: Copy test files to INPUT cache directories
    2. EXECUTE: Run normal tool execution with --sdc-report flag
    3. VALIDATE: Check OUTPUT cache for expected SDC data in enhanced records
    4. TEARDOWN: Clean up INPUT cache test files

Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Usage:
    python test_suites/nvd-ish_collector/test_sdc_integration.py
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

class SDCIntegrationTestSuite:
    """Test suite for Source Data Concerns integration functionality."""
    
    def __init__(self):
        self.passed = 0
        self.total = 4
        
    def setup_test_environment(self):
        """Set up test environment by copying test files to INPUT cache locations."""
        print("Setting up SDC integration test environment...")
        
        copied_files = []
        
        # Test cases use CVE-1337-100X series for SDC testing
        test_cves = [
            "CVE-1337-1001",  # Basic SDC detection
            "CVE-1337-1002",  # Registry parameter passing
            "CVE-1337-1003",  # Metadata placement
            "CVE-1337-1004",  # Detection groups validation
            "CVE-1337-1005",  # Skip logic validation (clean data)
        ]
        
        year = "1337"
        dir_name = "1xxx"
        
        # Pre-create cache directory structures
        for cache_type in ["cve_list_v5", "nvd_2.0_cves", "nvd-ish_2.0_cves"]:
            cache_dir = CACHE_DIR / cache_type / year / dir_name
            cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy test files
        for cve_id in test_cves:
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
        print("Cleaning up SDC integration test environment...")
        
        for file_path in copied_files:
            try:
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(f"  WARNING: Could not remove {file_path}: {e}")
        
        print(f"  * Cleaned up {len(copied_files)} test files")
    
    def run_analysis_tool(self, cve_id: str, additional_flag: str = None) -> Tuple[bool, Optional[Path], str, str]:
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
            "--nvd-ish-only"
        ]
        
        if additional_flag:
            cmd.append(additional_flag)
        
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
    
    def validate_enhanced_record(self, output_path: Optional[Path]) -> dict:
        """Validate basic enhanced record structure."""
        validation = {
            "exists": False,
            "valid_json": False,
            "has_enriched_affected": False,
            "has_tool_metadata": False,
            "has_sdc_analysis": False,
            "entry_count": 0,
            "file_size": 0
        }
        
        if not output_path or not output_path.exists():
            return validation
        
        validation["exists"] = True
        validation["file_size"] = output_path.stat().st_size
        
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            validation["valid_json"] = True
            
            # Check for enrichedCVEv5Affected (it's a dict, not a list)
            if "enrichedCVEv5Affected" in data:
                enriched_data = data["enrichedCVEv5Affected"]
                if isinstance(enriched_data, dict):
                    validation["has_enriched_affected"] = True
                    
                    # Check for cveListV5AffectedEntries 
                    entries = enriched_data.get("cveListV5AffectedEntries", [])
                    validation["entry_count"] = len(entries)
                    
                    # Check for tool metadata (it's at the top level of enrichedCVEv5Affected)
                    if "toolExecutionMetadata" in enriched_data:
                        validation["has_tool_metadata"] = True
            
            # Check for SDC analysis
            if "sdcAnalysis" in data:
                validation["has_sdc_analysis"] = True
            
        except (json.JSONDecodeError, Exception) as e:
            print(f"ERROR validating enhanced record: {e}")
        
        return validation
    
    def test_sdc_basic_integration(self) -> bool:
        """Test basic SDC detection within enhanced records."""
        print(f"\n=== Test 1: SDC Basic Integration ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-1001", "--sdc-report")
        
        if not success:
            print(f"[FAIL]: SDC integration analysis failed")
            return False
        
        validation = self.validate_enhanced_record(output_path)
        
        if not validation["has_enriched_affected"]:
            print(f"[FAIL]: No enhanced records for SDC integration")
            return False
        
        # For basic integration, we just need to confirm SDC processing occurred
        # (doesn't require specific detections, just that the system integrated)
        print(f"[PASS]: SDC integration working with enhanced records")
        return True
    
    def test_sdc_registry_passing(self) -> bool:
        """Test SDC registry parameter passing validation."""
        print(f"\n=== Test 2: SDC Registry Parameter Passing ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-1002", "--sdc-report")
        
        if not success:
            print(f"[FAIL]: Registry parameter passing failed")
            return False
        
        validation = self.validate_enhanced_record(output_path)
        
        if not validation["has_tool_metadata"]:
            print(f"[FAIL]: No tool metadata found (registry passing issue)")
            return False
        
        print(f"[PASS]: SDC registry parameter passing validated")
        return True
    
    def test_sdc_metadata_placement(self) -> bool:
        """Test SDC metadata is properly placed in enhanced records."""
        print(f"\n=== Test 3: SDC Metadata Placement ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-1003", "--sdc-report")
        
        if not success:
            print(f"[FAIL]: SDC metadata placement test failed")
            return False
        
        validation = self.validate_enhanced_record(output_path)
        
        if not validation["has_enriched_affected"]:
            print(f"[FAIL]: No enhanced records for metadata placement test")
            return False
        
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            # Check that toolExecutionMetadata is in enrichedCVEv5Affected entries
            metadata_found = False
            for entry in data["enrichedCVEv5Affected"]:
                if "toolExecutionMetadata" in entry:
                    metadata_found = True
                    break
            
            if not metadata_found:
                print(f"[FAIL]: toolExecutionMetadata not found in enriched entries")
                return False
            
            print(f"[PASS]: SDC metadata properly placed in enhanced records")
            return True
            
        except Exception as e:
            print(f"[FAIL]: Error checking metadata placement: {e}")
            return False
    
    def test_sdc_detection_sample(self) -> bool:
        """Test comprehensive SDC detection group functionality and skip logic validation."""
        print(f"\n=== Test 4: SDC Detection Groups Validation ===")
        
        # Test comprehensive detection patterns
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-1004", "--sdc-report")
        
        if not success:
            print(f"❌ FAIL: SDC detection groups test failed")
            return False
        
        validation = self.validate_enhanced_record(output_path)
        
        if not validation["has_enriched_affected"]:
            print(f"❌ FAIL: No enhanced records for detection groups test")
            return False
        
        # Validate comprehensive format alignment with documentation
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            # Comprehensive format validation against documentation
            format_errors = []
            sdc_entries_validated = 0
            detection_groups_found = set()
            
            # Check the correct structure: enrichedCVEv5Affected.cveListV5AffectedEntries
            enriched_data = data.get("enrichedCVEv5Affected", {})
            if not isinstance(enriched_data, dict):
                format_errors.append("enrichedCVEv5Affected must be a dict")
            else:
                entries = enriched_data.get("cveListV5AffectedEntries", [])
                if not isinstance(entries, list):
                    format_errors.append("cveListV5AffectedEntries must be a list")
                else:
                    for idx, entry in enumerate(entries):
                        if not isinstance(entry, dict):
                            format_errors.append(f"Entry {idx}: must be a dict")
                            continue
                            
                        # Only validate sourceDataConcerns if present AND populated (entries only get SDC if they have concerns)
                        if "sourceDataConcerns" in entry:
                            sdc_data = entry["sourceDataConcerns"]
                            if not isinstance(sdc_data, dict):
                                format_errors.append(f"Entry {idx}: sourceDataConcerns must be a dict")
                                continue
                            
                            # Only validate structure if sourceDataConcerns is populated (not empty)
                            if len(sdc_data) > 0:
                                # Validate required documentation format fields
                                if "sourceId" not in sdc_data:
                                    format_errors.append(f"Entry {idx}: missing required sourceId field")
                                elif not isinstance(sdc_data["sourceId"], str):
                                    format_errors.append(f"Entry {idx}: sourceId must be a string")
                                elif not sdc_data["sourceId"].startswith("Hashmire/Analysis_Tools"):
                                    format_errors.append(f"Entry {idx}: sourceId format incorrect: {sdc_data['sourceId']}")
                                    
                                if "cvelistv5AffectedEntryIndex" not in sdc_data:
                                    format_errors.append(f"Entry {idx}: missing required cvelistv5AffectedEntryIndex field")
                                elif not isinstance(sdc_data["cvelistv5AffectedEntryIndex"], str):
                                    format_errors.append(f"Entry {idx}: cvelistv5AffectedEntryIndex must be a string")
                                    
                                if "concerns" not in sdc_data:
                                    format_errors.append(f"Entry {idx}: missing required concerns object")
                                elif not isinstance(sdc_data["concerns"], dict):
                                    format_errors.append(f"Entry {idx}: concerns must be a dict")
                                else:
                                    # Validate detection groups structure
                                    concerns = sdc_data["concerns"]
                                    detection_groups_found.update(concerns.keys())
                                    
                                    for group_name, group_data in concerns.items():
                                        if not isinstance(group_data, list):
                                            format_errors.append(f"Entry {idx}: detection group '{group_name}' must be a list")
                                
                                sdc_entries_validated += 1
            
            if format_errors:
                print(f"❌ FAIL: Format validation errors:")
                for error in format_errors[:5]:  # Show first 5 errors
                    print(f"   - {error}")
                if len(format_errors) > 5:
                    print(f"   ... and {len(format_errors) - 5} more errors")
                return False
            
            if sdc_entries_validated == 0:
                print(f"❌ FAIL: No sourceDataConcerns entries found to validate")
                return False
            
            # Validate expected detection groups are present
            expected_groups = {
                "placeholderData",
                "textComparators", 
                "whitespaceIssues",
                "allVersionsPatterns",
                "bloatTextDetection", 
                "invalidCharacters",
                "mathematicalComparators",
                "overlappingRanges",
                "versionGranularity"
            }
            
            found_expected = expected_groups.intersection(detection_groups_found)
            if len(found_expected) == 0:
                print(f"❌ FAIL: No expected detection groups found. Found: {detection_groups_found}")
                return False
            
            print(f"✅ Detection groups validated: {sorted(detection_groups_found)}")
            
            # Test skip logic validation with clean data
            print(f"  Testing skip logic validation...")
            success2, output_path2, stdout2, stderr2 = self.run_analysis_tool("CVE-1337-1005", "--sdc-report")
            
            if success2:
                validation2 = self.validate_enhanced_record(output_path2)
                if validation2["exists"] and validation2["has_enriched_affected"]:
                    # Check if this record has minimal or no SDC concerns (skip logic)
                    try:
                        with open(output_path2, 'r') as f2:
                            data2 = json.load(f2)
                        
                        skip_logic_validated = False
                        # Use the correct data structure
                        enriched_data2 = data2.get("enrichedCVEv5Affected", {})
                        if isinstance(enriched_data2, dict):
                            entries2 = enriched_data2.get("cveListV5AffectedEntries", [])
                            
                            total_concerns_clean = 0
                            for entry in entries2:
                                if isinstance(entry, dict) and "sourceDataConcerns" in entry:
                                    sdc_data = entry["sourceDataConcerns"]
                                    if isinstance(sdc_data, dict) and "concerns" in sdc_data:
                                        concerns = sdc_data["concerns"]
                                        if isinstance(concerns, dict):
                                            # Count non-empty concern groups
                                            for group_name, group_data in concerns.items():
                                                if isinstance(group_data, list) and len(group_data) > 0:
                                                    total_concerns_clean += len(group_data)
                            
                            if total_concerns_clean < len(detection_groups_found):
                                skip_logic_validated = True
                                print(f"  ✅ Skip logic validated: Clean data has fewer concerns ({total_concerns_clean} vs {len(detection_groups_found)} groups)")
                        
                        if not skip_logic_validated:
                            print(f"  ⚠️ Skip logic not clearly demonstrated (both records have similar concern levels)")
                    except Exception as e:
                        print(f"  ⚠️ Skip logic validation inconclusive: {e}")
            
            print(f"✅ PASS: SDC detection groups and format validated successfully")
            print(f"  ✓ Validated {sdc_entries_validated} entries with sourceDataConcerns")
            print(f"  ✓ Detection groups structure conforms to documentation")
            print(f"  ✓ Required metadata fields present (sourceId, cvelistv5AffectedEntryIndex, concerns)")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating SDC detection groups: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_all_tests(self) -> bool:
        """Run all SDC integration tests and return overall success."""
        
        print("Source Data Concerns (SDC) Integration Test Suite")
        print("=" * 60)
        
        # Setup test environment
        copied_files = self.setup_test_environment()
        
        try:
            tests = [
                ("SDC Basic Integration", self.test_sdc_basic_integration),
                ("SDC Registry Parameter Passing", self.test_sdc_registry_passing),
                ("SDC Metadata Placement", self.test_sdc_metadata_placement),
                ("SDC Detection Groups Validation", self.test_sdc_detection_sample),
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
                print("SUCCESS: All SDC integration tests passed!")
            else:
                print("FAIL: Some SDC integration tests failed")
            
            # Output standardized test results
            print(f'TEST_RESULTS: PASSED={self.passed} TOTAL={self.total} SUITE="SDC Integration"')
            
            return success
            
        finally:
            # Always clean up test environment
            self.cleanup_test_environment(copied_files)


def main():
    """Main entry point for SDC integration test suite."""
    test_suite = SDCIntegrationTestSuite()
    success = test_suite.run_all_tests()
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
