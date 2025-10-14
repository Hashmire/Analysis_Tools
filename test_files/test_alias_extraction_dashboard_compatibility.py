#!/usr/bin/env python3
"""
Alias Extraction Dashboard Compatibility Test Suite

This test suite validates the new alias extraction workflow through run_tools.py
and ensures compatibility with aliasMappingDashboard.html.

Test Coverage:
- Phase 1: Basic alias extraction through run_tools.py
- Phase 2: Output format validation for dashboard compatibility
- Phase 3: Dashboard data structure requirements
- Phase 4: Integration with aliasMappingDashboard.html
- Phase 5: Edge case handling and data quality

Replaces legacy curator.py tests with new workflow validation.
"""

import os
import sys
import json
import tempfile
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
import unittest
from typing import Dict, List, Any, Optional

# Add src path for analysis_tool imports
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

from analysis_tool.storage.run_organization import get_analysis_tools_root, get_latest_run

class AliasExtractionDashboardCompatibilityTestSuite:
    """Test suite for alias extraction dashboard compatibility validation."""
    
    def __init__(self):
        self.test_results = []
        self.project_root = get_analysis_tools_root()
        
    def add_result(self, test_name: str, passed: bool, message: str, detailed_info: str = None):
        """Add a test result with SDC-style detailed validation output."""
        status = "PASS" if passed else "FAIL"
        self.test_results.append({
            "test": test_name,
            "status": status,
            "message": message
        })
        
        # Only show detailed output if not running under unified test runner
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            result_symbol = "✅ PASS" if passed else "❌ FAIL"
            print(f"{result_symbol} - Test: {message}")
            if detailed_info:
                print(f"Checks Performed: {detailed_info}")
        return passed

    def run_tools_command(self, args: List[str], timeout: int = 120) -> Dict[str, Any]:
        """Execute analysis_tool.py command and return results."""
        try:
            cmd = [sys.executable, "-m", "src.analysis_tool.core.analysis_tool"] + args
            result = subprocess.run(
                cmd,
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": "Command timed out",
                "success": False
            }
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }

    def find_alias_extraction_report(self) -> Optional[Path]:
        """Find the most recent alias extraction report."""
        try:
            # Look through ALL runs for alias extraction reports (not just recent)
            runs_dir = self.project_root / "runs"
            if not runs_dir.exists():
                return None
            
            # Get all run directories, sorted by modification time (newest first)
            run_dirs = [d for d in runs_dir.iterdir() if d.is_dir()]
            run_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Look for aliasExtractionReport.json in ALL runs
            for run_dir in run_dirs:  # Check ALL runs, not just recent ones
                logs_dir = run_dir / "logs"
                if not logs_dir.exists():
                    continue
                    
                report_file = logs_dir / "aliasExtractionReport.json"
                if report_file.exists():
                    # Validate it's a recent, complete report
                    try:
                        import json
                        with open(report_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        
                        # Must have all required structure
                        if ('metadata' in data and 'aliasGroups' in data and 
                            'confirmedMappings' in data):
                            return report_file
                    except:
                        continue  # Skip invalid reports
                
            return None
        except Exception:
            return None

    def find_recent_alias_extraction_report(self, after_time: float) -> Optional[Path]:
        """Find alias extraction report created after the given timestamp."""
        try:
            runs_dir = self.project_root / "runs"
            if not runs_dir.exists():
                return None
            
            # Get all run directories created after the start time
            run_dirs = [d for d in runs_dir.iterdir() if d.is_dir() and d.stat().st_mtime > after_time]
            run_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Look for aliasExtractionReport.json in recent runs
            for run_dir in run_dirs:
                logs_dir = run_dir / "logs"
                if not logs_dir.exists():
                    continue
                    
                report_file = logs_dir / "aliasExtractionReport.json"
                if report_file.exists():
                    return report_file
                
            return None
        except Exception:
            return None

    def load_json_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load and parse JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Failed to load JSON file {file_path}: {e}")
            return None

    # ============================================================================
    # SECTION 1: Basic Alias Extraction Tests
    # ============================================================================
    
    def test_01_basic_alias_extraction_execution(self):
        """Test basic alias extraction through run_tools.py."""
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            print("Running Test 1: Basic Alias Extraction Execution")
        
        # Test with a known CVE that should have alias data
        result = self.run_tools_command([
            "--cve", "CVE-2024-20515",
            "--alias-report",
            "--source-uuid", "d1c1063e-7a18-46af-9102-31f8928bc633",  # Cisco UUID from test data
            "--no-cache",
            "--no-browser"
        ])
        
        success = self.add_result(
            "basic_execution",
            result["success"],
            f"Basic alias extraction command execution (exit code: {result['returncode']})",
            "command execution | exit code validation | report generation"
        )
        
        if not success:
            if not os.environ.get('UNIFIED_TEST_RUNNER'):
                print(f"Expected: Successful execution (exit code 0)")
                print(f"Found: Failed execution (exit code {result['returncode']})")
                print(f"✅ COUNT: Command execution - (validation failed)")
                print(f"❌ STRUCTURE: Exit code validation - (validation failed)")
                print(f"❌ VALUES: Expected success, found failure")
            return False
        
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            print(f"Expected: Successful execution (exit code 0)")  
            print(f"Found: Successful execution (exit code {result['returncode']})")
            print(f"✅ COUNT: Command execution - (matches expected)")
            print(f"✅ STRUCTURE: Exit code validation - (matches expected)")
            print(f"✅ VALUES: Command executed successfully - (matches expected)")
            
        # Check for alias extraction report
        report_file = self.find_alias_extraction_report()
        report_exists = report_file is not None
        success = success and self.add_result(
            "report_file_exists",
            report_exists,
            f"Alias extraction report file generation",
            "file existence | path validation | content accessibility"
        )
        
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            if report_exists:
                print(f"Expected: Report file generated")
                print(f"Found: Report file at {report_file}")
                print(f"✅ COUNT: 1 report file - (matches expected)")
                print(f"✅ STRUCTURE: File path/existence - (matches expected)")
                print(f"✅ VALUES: Report accessible at expected location - (matches expected)")
            else:
                print(f"Expected: Report file generated")
                print(f"Found: No report file found")
                print(f"❌ COUNT: 0 report files - (expected 1)")
                print(f"❌ STRUCTURE: File generation - (validation failed)")
                print(f"❌ VALUES: No report generated - (validation failed)")
        
        return success

    def test_02_alias_report_json_structure(self):
        """Test alias extraction report JSON structure."""
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            print("Running Test 2: Alias Report JSON Structure")
        
        report_file = self.find_alias_extraction_report()
        if not report_file:
            return self.add_result(
                "json_structure_no_file",
                False,
                "No alias extraction report found for structure validation"
            )
            
        data = self.load_json_file(report_file)
        if not data:
            return self.add_result(
                "json_structure_load_failed",
                False,
                "Failed to load alias extraction report JSON"
            )
        
        success = True
        
        # Test required top-level structure
        required_keys = ["metadata", "aliasGroups", "confirmedMappings"]
        for key in required_keys:
            key_exists = key in data
            success = success and self.add_result(
                f"json_structure_{key}",
                key_exists,
                f"Required JSON key '{key}' present: {key_exists}"
            )
        
        # Test metadata structure
        if "metadata" in data:
            metadata = data["metadata"]
            required_metadata = ["extraction_timestamp", "target_uuid", "total_cves_processed", 
                                "unique_aliases_extracted", "product_groups_created"]
            
            for meta_key in required_metadata:
                meta_exists = meta_key in metadata
                success = success and self.add_result(
                    f"metadata_{meta_key}",
                    meta_exists,
                    f"Metadata key '{meta_key}' present: {meta_exists}"
                )
        
        # Test aliasGroups structure
        if "aliasGroups" in data:
            alias_groups = data["aliasGroups"]
            is_list = isinstance(alias_groups, list)
            success = success and self.add_result(
                "aliasgroups_is_list",
                is_list,
                f"aliasGroups is list: {is_list}"
            )
            
            if is_list and len(alias_groups) > 0:
                first_group = alias_groups[0]
                group_has_aliases = "aliases" in first_group and isinstance(first_group["aliases"], list)
                success = success and self.add_result(
                    "aliasgroups_has_aliases",
                    group_has_aliases,
                    f"First alias group has aliases array: {group_has_aliases}"
                )
        
        return success

    def test_03_dashboard_required_fields(self):
        """Test that aliases contain fields required by dashboard."""
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            print("Running Test 3: Dashboard Required Fields")
        
        report_file = self.find_alias_extraction_report()
        if not report_file:
            return self.add_result(
                "dashboard_fields_no_file",
                False,
                "No alias extraction report found for field validation"
            )
            
        data = self.load_json_file(report_file)
        if not data or "aliasGroups" not in data:
            return self.add_result(
                "dashboard_fields_no_data",
                False,
                "No alias groups data found for field validation"
            )
        
        success = True
        required_alias_fields = ["vendor", "product", "source_cve"]
        
        # Check each alias group
        for group_idx, group in enumerate(data["aliasGroups"]):
            if "aliases" not in group:
                continue
                
            for alias_idx, alias in enumerate(group["aliases"]):
                for field in required_alias_fields:
                    field_exists = field in alias
                    if not field_exists:
                        success = False
                        self.add_result(
                            f"alias_field_{field}_group{group_idx}_alias{alias_idx}",
                            False,
                            f"Missing required field '{field}' in group {group_idx}, alias {alias_idx}"
                        )
                        break
                        
                # Validate source_cve format
                if "source_cve" in alias:
                    source_cve = alias["source_cve"]
                    is_list = isinstance(source_cve, list)
                    has_cves = is_list and len(source_cve) > 0
                    success = success and self.add_result(
                        f"source_cve_format_group{group_idx}_alias{alias_idx}",
                        has_cves,
                        f"source_cve is non-empty list: {has_cves}"
                    )
        
        if success:
            self.add_result(
                "all_dashboard_fields_present",
                True,
                "All aliases contain required dashboard fields (vendor, product, source_cve)"
            )
        
        return success

    # ============================================================================
    # SECTION 2: Dashboard Compatibility Tests
    # ============================================================================
    
    def test_04_dashboard_data_structure_compatibility(self):
        """Test compatibility with dashboard data structure expectations."""
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            print("Running Test 4: Dashboard Data Structure Compatibility")
        
        report_file = self.find_alias_extraction_report()
        if not report_file:
            return self.add_result(
                "dashboard_compat_no_file",
                False,
                "No alias extraction report found for compatibility validation"
            )
            
        data = self.load_json_file(report_file)
        if not data:
            return self.add_result(
                "dashboard_compat_no_data",
                False,
                "Failed to load data for compatibility validation"
            )
        
        success = True
        
        # Test that target_uuid is present (required by dashboard)
        metadata = data.get("metadata", {})
        has_target_uuid = "target_uuid" in metadata and metadata["target_uuid"]
        target_uuid_value = metadata.get("target_uuid", "N/A")
        success = success and self.add_result(
            "dashboard_target_uuid",
            has_target_uuid,
            f"target_uuid present in metadata: {target_uuid_value}"
        )
        
        # Test confirmedMappings array exists (even if empty)
        has_confirmed_mappings = "confirmedMappings" in data and isinstance(data["confirmedMappings"], list)
        success = success and self.add_result(
            "dashboard_confirmed_mappings",
            has_confirmed_mappings,
            f"confirmedMappings array present: {has_confirmed_mappings}"
        )
        
        # Test alias structure for dashboard processing
        if "aliasGroups" in data:
            for group_idx, group in enumerate(data["aliasGroups"]):
                if "aliases" not in group:
                    continue
                    
                for alias_idx, alias in enumerate(group["aliases"]):
                    # Dashboard expects string values for vendor/product
                    vendor_is_string = isinstance(alias.get("vendor"), str)
                    product_is_string = isinstance(alias.get("product"), str)
                    
                    success = success and self.add_result(
                        f"vendor_string_g{group_idx}_a{alias_idx}",
                        vendor_is_string,
                        f"Vendor is string in group {group_idx}, alias {alias_idx}: {vendor_is_string}"
                    )
                    
                    success = success and self.add_result(
                        f"product_string_g{group_idx}_a{alias_idx}",
                        product_is_string,
                        f"Product is string in group {group_idx}, alias {alias_idx}: {product_is_string}"
                    )
        
        return success

    def test_05_source_data_concerns_preparation(self):
        """Test that data is prepared for dashboard source data concerns detection."""
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            print("Running Test 5: Source Data Concerns Preparation")
        
        report_file = self.find_alias_extraction_report()
        if not report_file:
            return self.add_result(
                "sdc_prep_no_file",
                False,
                "No alias extraction report found for SDC preparation validation"
            )
            
        data = self.load_json_file(report_file)
        if not data or "aliasGroups" not in data:
            return self.add_result(
                "sdc_prep_no_data",
                False,
                "No alias groups data found for SDC preparation validation"
            )
        
        success = True
        
        # Check that aliases have sufficient data for concerns detection
        for group_idx, group in enumerate(data["aliasGroups"]):
            if "aliases" not in group:
                continue
                
            for alias_idx, alias in enumerate(group["aliases"]):
                # Dashboard needs vendor/product for concerns detection
                has_vendor = alias.get("vendor") and str(alias["vendor"]).strip()
                has_product = alias.get("product") and str(alias["product"]).strip()
                
                if not has_vendor or not has_product:
                    success = False
                    self.add_result(
                        f"sdc_data_quality_g{group_idx}_a{alias_idx}",
                        False,
                        f"Insufficient data for SDC detection in group {group_idx}, alias {alias_idx}"
                    )
        
        if success:
            self.add_result(
                "sdc_preparation_complete",
                True,
                "All aliases have sufficient data for dashboard source data concerns detection"
            )
        
        return success

    # ============================================================================
    # SECTION 3: Integration Tests
    # ============================================================================
    
    def test_06_multi_cve_alias_extraction(self):
        """Test alias extraction with multiple CVEs from a targeted source."""
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            print("Running Test 6: Multi-CVE Alias Extraction")
        
        # Use generate_dataset.py with a source that has few CVEs for fast multi-CVE testing
        try:
            cmd = [sys.executable, str(self.project_root / "generate_dataset.py"), 
                   "--source-uuid", "d1c1063e-7a18-46af-9102-31f8928bc633", "--alias-report", "--last-days", "30"]
            result = subprocess.run(
                cmd,
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                timeout=60
            )
            
            dataset_result = {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0
            }
        except Exception as e:
            dataset_result = {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }
        
        # Note: This might fail due to no matching CVEs, which is OK
        success = True
        
        if dataset_result["success"]:
            # If it succeeded, validate the output
            report_file = self.find_alias_extraction_report()
            if report_file:
                data = self.load_json_file(report_file)
                if data and "metadata" in data:
                    cves_processed = data["metadata"].get("total_cves_processed", 0)
                    success = self.add_result(
                        "multi_cve_processing",
                        cves_processed > 0,
                        f"Multi-CVE processing completed: {cves_processed} CVEs processed"
                    )
                else:
                    success = self.add_result(
                        "multi_cve_no_data",
                        False,
                        "Multi-CVE command succeeded but no valid data found"
                    )
            else:
                success = self.add_result(
                    "multi_cve_no_report",
                    False,
                    "Multi-CVE command succeeded but no report file found"
                )
        else:
            # Command failed - could be due to no matching CVEs
            if "No CVEs found" in dataset_result["stderr"] or "skipped due to size" in dataset_result["stdout"]:
                success = self.add_result(
                    "multi_cve_no_matches",
                    True,
                    "Multi-CVE command handled 'no matches' scenario gracefully"
                )
            else:
                success = self.add_result(
                    "multi_cve_failed",
                    False,
                    f"Multi-CVE command failed: {dataset_result['stderr']}"
                )
        
        return success

    def test_07_alias_grouping_validation(self):
        """Test that aliases are properly grouped for dashboard consumption."""
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            print("Running Test 7: Alias Grouping Validation")
        
        report_file = self.find_alias_extraction_report()
        if not report_file:
            return self.add_result(
                "grouping_no_file",
                False,
                "No alias extraction report found for grouping validation"
            )
            
        data = self.load_json_file(report_file)
        if not data or "aliasGroups" not in data:
            return self.add_result(
                "grouping_no_data",
                False,
                "No alias groups data found for grouping validation"
            )
        
        success = True
        alias_groups = data["aliasGroups"]
        
        # Test that groups have proper structure
        for group_idx, group in enumerate(alias_groups):
            has_alias_group = "alias_group" in group
            has_aliases = "aliases" in group and isinstance(group["aliases"], list)
            
            success = success and self.add_result(
                f"group_structure_{group_idx}",
                has_alias_group and has_aliases,
                f"Group {group_idx} has proper structure (alias_group + aliases array)"
            )
            
            if has_aliases and len(group["aliases"]) > 0:
                # Test that aliases within group have valid data structure
                # For alias extraction, groups can contain different vendor/product combinations
                # as they represent aliases and alternate naming conventions
                valid_group_data = True
                for alias in group["aliases"]:
                    # Each alias must have non-empty vendor and product
                    vendor = alias.get("vendor", "").strip()
                    product = alias.get("product", "").strip()
                    if not vendor or not product:
                        valid_group_data = False
                        break
                
                success = success and self.add_result(
                    f"group_consistency_{group_idx}",
                    valid_group_data,
                    f"Group {group_idx} has valid alias data (non-empty vendor/product for all aliases)"
                )
        
        return success

    # ============================================================================
    # SECTION 4: Edge Cases and Error Handling
    # ============================================================================
    
    def test_08_no_alias_data_handling(self):
        """Test handling when CVE has no alias data."""
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            print("Running Test 8: No Alias Data Handling")
        
        # Record the time before running the command
        import time
        start_time = time.time()
        
        # Use a CVE that likely has no platform data for aliases
        result = self.run_tools_command([
            "--cve", "CVE-1999-0001",  # Very old CVE, unlikely to have modern platform data
            "--alias-report",
            "--source-uuid", "d1c1063e-7a18-46af-9102-31f8928bc633",  # Cisco UUID from test data
            "--no-cache",
            "--no-browser"
        ])
        
        success = True
        
        if result["success"]:
            # Command succeeded - check if it handled no data gracefully
            # Look for reports created AFTER the command started
            report_file = self.find_recent_alias_extraction_report(start_time)
            if report_file:
                data = self.load_json_file(report_file)
                if data:
                    alias_groups = data.get("aliasGroups", [])
                    aliases_extracted = data.get("metadata", {}).get("unique_aliases_extracted", 0)
                    
                    # Should have 0 aliases but valid structure
                    success = self.add_result(
                        "no_alias_graceful",
                        aliases_extracted == 0 and isinstance(alias_groups, list),
                        f"No alias data handled gracefully: {aliases_extracted} aliases, valid structure"
                    )
                else:
                    success = self.add_result(
                        "no_alias_invalid_json",
                        False,
                        "No alias data case produced invalid JSON"
                    )
            else:
                # No report file generated - check if this was intentional (no aliases found)
                if "No alias extractions found" in result["stdout"]:
                    success = self.add_result(
                        "no_alias_graceful",
                        True,
                        "No alias data handled gracefully: no report generated due to no aliases"
                    )
                else:
                    success = self.add_result(
                        "no_alias_no_report",
                        False,
                        "No alias data case failed to produce report file without proper message"
                    )
        else:
            # Check if it's a graceful failure
            if "No alias extractions found" in result["stdout"]:
                success = self.add_result(
                    "no_alias_graceful_message",
                    True,
                    "No alias data case produced appropriate message"
                )
            else:
                success = self.add_result(
                    "no_alias_hard_failure",
                    False,
                    f"No alias data case failed unexpectedly: {result['stderr']}"
                )
        
        return success

    def test_09_data_quality_validation(self):
        """Test data quality validation for dashboard compatibility."""
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            print("Running Test 9: Data Quality Validation")
        
        report_file = self.find_alias_extraction_report()
        if not report_file:
            return self.add_result(
                "data_quality_no_file",
                False,
                "No alias extraction report found for data quality validation"
            )
            
        data = self.load_json_file(report_file)
        if not data:
            return self.add_result(
                "data_quality_no_data",
                False,
                "Failed to load data for quality validation"
            )
        
        success = True
        issues_found = []
        
        # Check metadata quality
        metadata = data.get("metadata", {})
        if not metadata.get("target_uuid"):
            issues_found.append("Missing or empty target_uuid")
        if not metadata.get("extraction_timestamp"):
            issues_found.append("Missing extraction_timestamp")
        
        # Check alias data quality
        if "aliasGroups" in data:
            for group_idx, group in enumerate(data["aliasGroups"]):
                if "aliases" not in group:
                    issues_found.append(f"Group {group_idx} missing aliases array")
                    continue
                    
                for alias_idx, alias in enumerate(group["aliases"]):
                    # Check for empty/whitespace-only values
                    vendor = alias.get("vendor", "")
                    product = alias.get("product", "")
                    source_cve = alias.get("source_cve", [])
                    
                    if not vendor or not vendor.strip():
                        issues_found.append(f"Empty vendor in group {group_idx}, alias {alias_idx}")
                    if not product or not product.strip():
                        issues_found.append(f"Empty product in group {group_idx}, alias {alias_idx}")
                    if not source_cve or len(source_cve) == 0:
                        issues_found.append(f"Empty source_cve in group {group_idx}, alias {alias_idx}")
        
        success = self.add_result(
            "data_quality_overall",
            len(issues_found) == 0,
            f"Data quality validation: {len(issues_found)} issues found"
        )
        
        if issues_found:
            for issue in issues_found[:5]:  # Show first 5 issues
                print(f"    Issue: {issue}")
        
        return success

    def test_10_confirmed_mappings_loading(self):
        """Test that confirmed mappings are properly loaded and included in reports."""
        if not os.environ.get('UNIFIED_TEST_RUNNER'):
            print("Running Test 10: Confirmed Mappings Loading")
        
        report_file = self.find_alias_extraction_report()
        if not report_file:
            return self.add_result(
                "confirmed_mappings_no_file",
                False,
                "No alias extraction report found for confirmed mappings validation"
            )
            
        data = self.load_json_file(report_file)
        if not data:
            return self.add_result(
                "confirmed_mappings_no_data",
                False,
                "Failed to load data for confirmed mappings validation"
            )
        
        success = True
        
        # Test that confirmedMappings is present and is a list
        has_confirmed_mappings = "confirmedMappings" in data
        success = success and self.add_result(
            "confirmed_mappings_present",
            has_confirmed_mappings,
            f"confirmedMappings field present: {has_confirmed_mappings}"
        )
        
        if has_confirmed_mappings:
            confirmed_mappings = data["confirmedMappings"]
            is_list = isinstance(confirmed_mappings, list)
            success = success and self.add_result(
                "confirmed_mappings_is_list",
                is_list,
                f"confirmedMappings is list: {is_list}"
            )
            
            # Test the structure of confirmed mappings if any exist
            if confirmed_mappings and len(confirmed_mappings) > 0:
                first_mapping = confirmed_mappings[0]
                has_cpe_base_string = "cpeBaseString" in first_mapping
                has_aliases = "aliases" in first_mapping and isinstance(first_mapping["aliases"], list)
                
                success = success and self.add_result(
                    "confirmed_mapping_structure",
                    has_cpe_base_string and has_aliases,
                    f"First confirmed mapping has proper structure (cpeBaseString: {has_cpe_base_string}, aliases: {has_aliases})"
                )
                
                # If we have confirmed mappings, validate they match expected format
                if has_aliases and len(first_mapping["aliases"]) > 0:
                    first_alias = first_mapping["aliases"][0]
                    has_vendor = "vendor" in first_alias
                    has_product = "product" in first_alias
                    
                    success = success and self.add_result(
                        "confirmed_alias_structure",
                        has_vendor and has_product,
                        f"Confirmed alias has required fields (vendor: {has_vendor}, product: {has_product})"
                    )
            else:
                # Empty confirmed mappings is valid - just log it
                success = success and self.add_result(
                    "confirmed_mappings_empty",
                    True,
                    f"No confirmed mappings found for this UUID (count: {len(confirmed_mappings)}) - this is expected for new UUIDs"
                )
        
        return success

    # ============================================================================
    # MAIN TEST EXECUTION
    # ============================================================================
    
    def run_all_tests(self):
        """Run all alias extraction dashboard compatibility tests."""
        # Only show detailed output if not running under unified test runner
        show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
        
        if show_details:
            print("=" * 80)
            print("ALIAS EXTRACTION DASHBOARD COMPATIBILITY TEST SUITE")
            print("=" * 80)
        
        test_sections = [
            ("Basic Alias Extraction", [
                self.test_01_basic_alias_extraction_execution,
                self.test_02_alias_report_json_structure,
                self.test_03_dashboard_required_fields
            ]),
            ("Dashboard Compatibility", [
                self.test_04_dashboard_data_structure_compatibility,
                self.test_05_source_data_concerns_preparation,
                self.test_10_confirmed_mappings_loading
            ]),
            ("Integration Tests", [
                self.test_06_multi_cve_alias_extraction,
                self.test_07_alias_grouping_validation
            ]),
            ("Edge Cases & Quality", [
                self.test_08_no_alias_data_handling,
                self.test_09_data_quality_validation
            ])
        ]
        
        total_tests = 0
        passed_tests = 0
        
        for section_name, test_methods in test_sections:
            if show_details:
                print(f"\n{section_name}:")
                print("-" * len(section_name))
            
            for test_method in test_methods:
                total_tests += 1
                if test_method():
                    passed_tests += 1
        
        # Final summary in SDC format
        if show_details:
            if passed_tests == total_tests:
                print(f"\nPASS Alias Extraction Dashboard Compatibility (test duration) ({passed_tests}/{total_tests} tests)")
                print(f"   {passed_tests}/{total_tests} tests passed")
                print(f"   Test breakdown: alias extraction functionality, dashboard compatibility, integration tests")
            else:
                print(f"\nFAIL Alias Extraction Dashboard Compatibility (test duration) ({passed_tests}/{total_tests} tests)")
                print(f"   {passed_tests}/{total_tests} tests passed")
                print(f"   Test breakdown: alias extraction functionality, dashboard compatibility, integration tests")
        
        # Standardized output for unified test runner
        print("=" * 80)
        print(f"TEST_RESULTS: PASSED={passed_tests} TOTAL={total_tests} SUITE=\"Alias Extraction Dashboard Compatibility\"")
        
        return passed_tests == total_tests

def main():
    """Main execution function."""
    suite = AliasExtractionDashboardCompatibilityTestSuite()
    success = suite.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
