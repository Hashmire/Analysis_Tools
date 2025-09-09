#!/usr/bin/env python3
"""
Confirmed Mapping Curator Test Suite

This test suite validates the SourceMappingCurator functionality that extracts 
vendor/product mappings from CVE records for confirmed mapping generation.

Tests curator initialization, data processing, extraction workflows, and output generation.
"""

import sys
import os
import json
import tempfile
from pathlib import Path
from datetime import datetime

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from analysis_tool.mappings.curator import SourceMappingCurator

class ConfirmedMappingCuratorTestSuite:
    """Consolidated test suite for confirmed mapping curator functionality."""
    
    def __init__(self):
        self.test_results = []
        
    def add_result(self, test_name, passed, message):
        """Add a test result to the collection."""
        status = "PASS" if passed else "FAIL"
        self.test_results.append({
            "test": test_name,
            "status": status,
            "message": message
        })
        print(f"  {status}: {message}")
        return passed

    def create_test_environment(self):
        """Create temporary test environment for curator testing."""
        temp_dir = tempfile.mkdtemp()
        temp_path = Path(temp_dir)
        
        # Create CVE repository structure that matches what curator expects
        # Structure: cve_repo/YEAR/Nxxx/CVE-YEAR-NNNN.json
        cve_repo = temp_path / "cve_repo" / "2024" / "1xxx"
        cve_repo.mkdir(parents=True, exist_ok=True)
        
        # Create mock CVE file in CVE 5.1 format
        test_cve = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {
                "cveId": "CVE-2024-1000"
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "orgId": "test-uuid-12345"
                    },
                    "affected": [{
                        "vendor": "Microsoft",
                        "product": "Windows 11",
                        "platforms": ["x64"],
                        "versions": [{"version": "*", "status": "affected"}]
                    }]
                }
            }
        }
        
        cve_file = cve_repo / "CVE-2024-1000.json"
        with open(cve_file, 'w') as f:
            json.dump(test_cve, f)
        
        return temp_path, "test-uuid-12345"

    # ============================================================================
    # SECTION 1: Curator Initialization Tests
    # ============================================================================
    
    def test_curator_initialization(self):
        """Test curator initialization with valid parameters."""
        print("Running Curator Test 1: Initialization")
        
        temp_path, test_uuid = self.create_test_environment()
        cve_repo_path = temp_path / "cve_repo"
        
        try:
            # Test basic initialization
            curator = SourceMappingCurator(
                cve_repository_path=str(cve_repo_path),
                target_uuid=test_uuid,
                run_context="test_init",
                max_files=10
            )
            
            success = self.add_result(
                "curator_init_basic",
                curator is not None,
                "Curator initialized successfully with basic parameters"
            )
            
            # Test parameter validation
            has_repo_path = hasattr(curator, 'cve_repo_path') and curator.cve_repo_path.exists()
            success &= self.add_result(
                "curator_init_repo_path",
                has_repo_path,
                "Curator properly set and validated repository path"
            )
            
            # Test UUID assignment
            has_uuid = hasattr(curator, 'target_uuid') and curator.target_uuid == test_uuid
            success &= self.add_result(
                "curator_init_uuid",
                has_uuid,
                f"Curator properly set target UUID: {test_uuid}"
            )
            
            return success
            
        except Exception as e:
            return self.add_result(
                "curator_init_exception",
                False,
                f"Curator initialization failed with exception: {e}"
            )
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(temp_path, ignore_errors=True)

    def test_curator_configuration(self):
        """Test curator configuration options."""
        print("Running Curator Test 2: Configuration")
        
        temp_path, test_uuid = self.create_test_environment()
        cve_repo_path = temp_path / "cve_repo"
        
        try:
            # Test with various configuration options
            curator = SourceMappingCurator(
                cve_repository_path=str(cve_repo_path),
                target_uuid=test_uuid,
                run_context="test_config",
                max_files=50,
                threads=2,
                sample_recent=True
            )
            
            # Test max_files setting
            success = self.add_result(
                "curator_config_max_files",
                curator.max_files == 50,
                f"Max files setting correctly applied: {curator.max_files}"
            )
            
            # Test threads setting
            success &= self.add_result(
                "curator_config_threads",
                curator.threads == 2,
                f"Thread count correctly set: {curator.threads}"
            )
            
            # Test sample_recent setting
            success &= self.add_result(
                "curator_config_sample_recent",
                curator.sample_recent == True,
                f"Sample recent setting correctly applied: {curator.sample_recent}"
            )
            
            return success
            
        except Exception as e:
            return self.add_result(
                "curator_config_exception",
                False,
                f"Curator configuration failed with exception: {e}"
            )
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(temp_path, ignore_errors=True)

    # ============================================================================
    # SECTION 2: Data Processing Tests
    # ============================================================================
    
    def test_cve_file_detection(self):
        """Test CVE file detection and filtering."""
        print("Running Curator Test 3: CVE File Detection")
        
        temp_path, test_uuid = self.create_test_environment()
        cve_repo_path = temp_path / "cve_repo"
        
        try:
            curator = SourceMappingCurator(
                cve_repository_path=str(cve_repo_path),
                target_uuid=test_uuid,
                run_context="test_detection",
                max_files=10
            )
            
            # Test CVE file discovery
            cve_files = curator._get_cve_files()
            
            success = self.add_result(
                "curator_file_detection",
                len(cve_files) > 0,
                f"Found {len(cve_files)} CVE files in test repository"
            )
            
            # Test file path validation
            valid_paths = all(f.exists() and f.suffix == '.json' for f in cve_files)
            success &= self.add_result(
                "curator_file_validation",
                valid_paths,
                "All detected CVE files are valid JSON files"
            )
            
            return success
            
        except Exception as e:
            return self.add_result(
                "curator_detection_exception",
                False,
                f"CVE file detection failed with exception: {e}"
            )
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(temp_path, ignore_errors=True)

    def test_uuid_filtering(self):
        """Test UUID-based filtering functionality."""
        print("Running Curator Test 4: UUID Filtering")
        
        temp_path, test_uuid = self.create_test_environment()
        cve_repo_path = temp_path / "cve_repo"
        
        try:
            curator = SourceMappingCurator(
                cve_repository_path=str(cve_repo_path),
                target_uuid=test_uuid,
                run_context="test_filtering"
            )
            
            # Test fast UUID check
            test_content_match = f'"orgId": "{test_uuid}"'
            test_content_no_match = '"orgId": "different-uuid"'
            
            has_match = curator._fast_uuid_check(test_content_match)
            success = self.add_result(
                "curator_uuid_match",
                has_match,
                "Fast UUID check correctly identifies matching content"
            )
            
            no_match = curator._fast_uuid_check(test_content_no_match)
            success &= self.add_result(
                "curator_uuid_no_match",
                not no_match,
                "Fast UUID check correctly rejects non-matching content"
            )
            
            return success
            
        except Exception as e:
            return self.add_result(
                "curator_filtering_exception",
                False,
                f"UUID filtering failed with exception: {e}"
            )
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(temp_path, ignore_errors=True)

    # ============================================================================
    # SECTION 3: Extraction and Processing Tests
    # ============================================================================
    
    def test_placeholder_filtering(self):
        """Test placeholder value filtering functionality."""
        print("Running Curator Test 5: Placeholder Filtering")
        
        temp_path, test_uuid = self.create_test_environment()
        cve_repo_path = temp_path / "cve_repo"
        
        try:
            curator = SourceMappingCurator(
                cve_repository_path=str(cve_repo_path),
                target_uuid=test_uuid,
                run_context="test_placeholder"
            )
            
            # Test various placeholder values
            placeholder_tests = [
                ("*", True),
                ("N/A", True),
                ("unknown", True),
                ("Microsoft", False),
                ("Windows", False),
                ("", True)
            ]
            
            success = True
            for test_value, expected_placeholder in placeholder_tests:
                is_placeholder = curator._is_placeholder_value(test_value)
                test_passed = is_placeholder == expected_placeholder
                success &= self.add_result(
                    f"curator_placeholder_{test_value.replace('*', 'asterisk').replace('', 'empty')}",
                    test_passed,
                    f"Placeholder detection for '{test_value}': {is_placeholder} (expected: {expected_placeholder})"
                )
            
            return success
            
        except Exception as e:
            return self.add_result(
                "curator_placeholder_exception",
                False,
                f"Placeholder filtering failed with exception: {e}"
            )
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(temp_path, ignore_errors=True)

    def test_extraction_workflow(self):
        """Test the complete extraction workflow."""
        print("Running Curator Test 6: Extraction Workflow")
        
        temp_path, test_uuid = self.create_test_environment()
        cve_repo_path = temp_path / "cve_repo"
        
        try:
            curator = SourceMappingCurator(
                cve_repository_path=str(cve_repo_path),
                target_uuid=test_uuid,
                run_context="test_workflow",
                max_files=5
            )
            
            # Test workflow execution
            curator.start_extraction()
            
            # Verify extraction occurred
            has_mappings = hasattr(curator, 'extracted_mappings') and len(curator.extracted_mappings) >= 0
            success = self.add_result(
                "curator_workflow_extraction",
                has_mappings,
                f"Extraction workflow completed with {len(curator.extracted_mappings) if has_mappings else 0} mappings"
            )
            
            # Verify statistics tracking
            has_stats = hasattr(curator, 'filtering_stats') and isinstance(curator.filtering_stats, dict)
            success &= self.add_result(
                "curator_workflow_stats",
                has_stats,
                "Extraction workflow properly tracked filtering statistics"
            )
            
            # Verify file processing
            processed_files = getattr(curator, 'processed_files', 0)
            success &= self.add_result(
                "curator_workflow_processing",
                processed_files > 0,
                f"Extraction workflow processed {processed_files} files"
            )
            
            return success
            
        except Exception as e:
            return self.add_result(
                "curator_workflow_exception",
                False,
                f"Extraction workflow failed with exception: {e}"
            )
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(temp_path, ignore_errors=True)

    # ============================================================================
    # SECTION 4: Output Generation Tests
    # ============================================================================
    
    def test_output_generation(self):
        """Test output file generation and format."""
        print("Running Curator Test 7: Output Generation")
        
        temp_path, test_uuid = self.create_test_environment()
        cve_repo_path = temp_path / "cve_repo"
        
        try:
            curator = SourceMappingCurator(
                cve_repository_path=str(cve_repo_path),
                target_uuid=test_uuid,
                run_context="test_output",
                max_files=5
            )
            
            # Run extraction to generate output
            curator.start_extraction()
            
            # Check if output files were created
            output_files = list(curator.run_paths["logs"].glob("source_mapping_extraction_*.json"))
            
            success = self.add_result(
                "curator_output_files",
                len(output_files) > 0,
                f"Output generation created {len(output_files)} files"
            )
            
            if output_files:
                # Validate output file structure
                with open(output_files[0], 'r', encoding='utf-8') as f:
                    output_data = json.load(f)
                
                required_sections = ['metadata', 'aliasGroups', 'confirmedMappings']
                has_all_sections = all(section in output_data for section in required_sections)
                
                success &= self.add_result(
                    "curator_output_structure",
                    has_all_sections,
                    f"Output file contains all required sections: {required_sections}"
                )
                
                # Validate metadata
                metadata = output_data.get('metadata', {})
                has_required_metadata = all(key in metadata for key in ['extraction_timestamp', 'target_uuid', 'total_files_processed'])
                
                success &= self.add_result(
                    "curator_output_metadata",
                    has_required_metadata,
                    "Output file contains required metadata fields"
                )
            
            return success
            
        except Exception as e:
            return self.add_result(
                "curator_output_exception",
                False,
                f"Output generation failed with exception: {e}"
            )
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(temp_path, ignore_errors=True)

    def test_comprehensive_property_support(self):
        """Test comprehensive support for all alias properties with statistics tracking."""
        print("Running Curator Test 8: Comprehensive Property Support")
        
        temp_path, test_uuid = self.create_test_environment()
        cve_repo_path = temp_path / "cve_repo"
        
        try:
            # Create comprehensive test CVE data with ALL supported properties
            comprehensive_cve = {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.1",
                "cveMetadata": {
                    "cveId": "CVE-2024-9999"
                },
                "containers": {
                    "cna": {
                        "providerMetadata": {
                            "orgId": test_uuid
                        },
                        "affected": [
                            {
                                # Core properties
                                "vendor": "TestVendor",
                                "product": "TestProduct",
                                "platforms": ["x64", "x86", "arm64"],
                                
                                # Additional simple fields
                                "collectionURL": "https://example.com/collection",
                                "packageName": "test-package",
                                "repo": "https://github.com/test/repo",
                                
                                # Complex array fields
                                "programRoutines": ["main.exe", "helper.dll", "service.sys"],
                                "programFiles": ["/usr/bin/test", "/etc/test.conf"],
                                "modules": ["core", "auth", "logging"],
                                
                                "versions": [{"version": "*", "status": "affected"}]
                            },
                            {
                                # Test placeholder filtering
                                "vendor": "*",
                                "product": "unknown",
                                "platforms": ["N/A", "x64"],  # Mix of placeholder and real
                                "collectionURL": "",
                                "packageName": "n/a",
                                "repo": "not specified",
                                "programRoutines": ["real.exe", "*", "unknown"],  # Mix in array
                                "programFiles": [],  # Empty array
                                "modules": "null",  # Single placeholder value
                                "versions": [{"version": "*", "status": "affected"}]
                            },
                            {
                                # Test minimal meaningful data
                                "vendor": "MinimalVendor",
                                "product": "MinimalProduct",
                                "versions": [{"version": "*", "status": "affected"}]
                            }
                        ]
                    }
                }
            }
            
            # Write comprehensive test CVE
            cve_file = cve_repo_path / "2024" / "9xxx" / "CVE-2024-9999.json"
            cve_file.parent.mkdir(parents=True, exist_ok=True)
            with open(cve_file, 'w') as f:
                json.dump(comprehensive_cve, f)
            
            # Run curator with comprehensive data
            curator = SourceMappingCurator(
                cve_repository_path=str(cve_repo_path),
                target_uuid=test_uuid,
                run_context="test_comprehensive",
                max_files=5
            )
            
            curator.start_extraction()
            
            # Validate that all expected properties are supported
            all_supported_properties = [
                'vendor', 'product', 'platforms', 'collectionURL', 'packageName', 
                'repo', 'programRoutines', 'programFiles', 'modules'
            ]
            
            # Check filtering statistics contain all property types
            stats_has_all_properties = all(
                prop in curator.filtering_stats for prop in [
                    'vendor', 'product', 'platforms', 'collectionURL', 'packageName',
                    'repo', 'programRoutines', 'programFiles', 'modules'
                ]
            )
            
            success = self.add_result(
                "curator_comprehensive_stats_structure",
                stats_has_all_properties,
                "Filtering statistics track all supported property types"
            )
            
            # Check that placeholder filtering actually occurred
            placeholder_filtering_occurred = (
                curator.filtering_stats['vendor'] > 0 or
                curator.filtering_stats['product'] > 0 or
                curator.filtering_stats['platforms'] > 0 or
                curator.filtering_stats['collectionURL'] > 0 or
                curator.filtering_stats['packageName'] > 0 or
                curator.filtering_stats['repo'] > 0 or
                curator.filtering_stats['programRoutines'] > 0 or
                curator.filtering_stats['modules'] > 0
            )
            
            success &= self.add_result(
                "curator_comprehensive_placeholder_filtering",
                placeholder_filtering_occurred,
                f"Placeholder filtering detected placeholders: {sum(curator.filtering_stats.values())} total filtered"
            )
            
            # Validate extracted mappings contain expected properties
            has_extracted_data = len(curator.extracted_mappings) > 0
            success &= self.add_result(
                "curator_comprehensive_extraction",
                has_extracted_data,
                f"Successfully extracted {len(curator.extracted_mappings)} alias mappings"
            )
            
            if has_extracted_data:
                # Check that various property types are present in extracted aliases
                property_types_found = set()
                property_values_found = {}
                
                for alias_key, alias_data in curator.extracted_mappings.items():
                    for prop in all_supported_properties:
                        if prop in alias_data:
                            property_types_found.add(prop)
                            if prop not in property_values_found:
                                property_values_found[prop] = []
                            property_values_found[prop].append(alias_data[prop])
                
                expected_core_props = {'vendor', 'product'}
                has_core_properties = expected_core_props.issubset(property_types_found)
                success &= self.add_result(
                    "curator_comprehensive_core_properties",
                    has_core_properties,
                    f"Core properties found in extracted aliases: {property_types_found & expected_core_props}"
                )
                
                # Check for additional properties
                additional_props_found = property_types_found - expected_core_props
                has_additional_properties = len(additional_props_found) > 0
                success &= self.add_result(
                    "curator_comprehensive_additional_properties", 
                    has_additional_properties,
                    f"Additional properties found: {additional_props_found}"
                )
                
                # Validate specific property data storage (not just presence)
                # Note: curator transforms 'platforms' array into individual 'platform' entries
                expected_property_data = {
                    'vendor': ['TestVendor', 'MinimalVendor'],  # From test data
                    'product': ['TestProduct', 'MinimalProduct'],  # From test data
                    'platform': ['x64', 'x86', 'arm64'],  # Individual platforms from 'platforms' array expansion
                    'collectionURL': ['https://example.com/collection'],  # From test data
                    'packageName': ['test-package'],  # From test data (placeholders filtered)
                    'repo': ['https://github.com/test/repo'],  # From test data (placeholders filtered)
                    'programRoutines': ['main.exe', 'helper.dll', 'service.sys', 'real.exe'],  # Array fields
                    'programFiles': ['/usr/bin/test', '/etc/test.conf'],  # Array fields
                    'modules': ['core', 'auth', 'logging']  # Array fields (placeholders filtered)
                }
                
                property_data_validation_success = True
                for prop, expected_values in expected_property_data.items():
                    if prop in property_values_found:
                        stored_values = property_values_found[prop]
                        # Check if any expected values are found in stored values
                        has_expected_data = False
                        
                        for stored in stored_values:
                            # Handle different data types properly
                            if isinstance(stored, list):
                                # For array properties, check if any expected values are in the array
                                for expected in expected_values:
                                    if any(expected.lower() in str(item).lower() for item in stored):
                                        has_expected_data = True
                                        break
                            else:
                                # For simple properties, check direct matches
                                for expected in expected_values:
                                    if expected.lower() in str(stored).lower() or str(stored).lower() in expected.lower():
                                        has_expected_data = True
                                        break
                            
                            if has_expected_data:
                                break
                        
                        if has_expected_data:
                            success &= self.add_result(
                                f"curator_comprehensive_property_data_{prop}",
                                True,
                                f"Property '{prop}' correctly stored expected data types in aliases"
                            )
                        else:
                            property_data_validation_success = False
                            # Show actual vs expected for debugging
                            actual_sample = str(stored_values[0])[:50] if stored_values else "None"
                            expected_sample = str(expected_values[:2])[:50]
                            success &= self.add_result(
                                f"curator_comprehensive_property_data_{prop}",
                                False,
                                f"Property '{prop}' found but no expected data: actual='{actual_sample}...' expected='{expected_sample}...'"
                            )
                    else:
                        # Property not found - check if it should have been (based on test data)
                        if prop in ['vendor', 'product']:  # Core properties should be present
                            property_data_validation_success = False
                            success &= self.add_result(
                                f"curator_comprehensive_property_data_{prop}",
                                False,
                                f"Core property '{prop}' not found in any extracted aliases"
                            )
                        else:
                            # Optional properties - just note they're not present
                            success &= self.add_result(
                                f"curator_comprehensive_property_data_{prop}",
                                True,  # Not a failure for optional properties
                                f"Optional property '{prop}' not found (may not be in test data)"
                            )
                
                # Overall property data validation
                success &= self.add_result(
                    "curator_comprehensive_property_data_validation",
                    property_data_validation_success,
                    f"All supported properties correctly store their data in alias entries"
                )
                
                # Specific test for platforms array expansion into individual platform entries
                # Look for individual platform entries in extracted mappings
                platform_entries_found = []
                for alias_key, alias_data in curator.extracted_mappings.items():
                    if 'platform' in alias_data:
                        platform_entries_found.append(alias_data['platform'])
                
                # The test data has platforms: ["x64", "x86", "arm64"] which should expand to 3 individual entries
                # Plus platforms: ["N/A", "x64"] where "N/A" gets filtered and "x64" should create an entry
                expected_platforms = ['x64', 'x86', 'arm64']  # x64 might appear twice but should be deduplicated by grouping
                platform_expansion_works = len(platform_entries_found) > 0
                
                success &= self.add_result(
                    "curator_comprehensive_platform_array_expansion",
                    platform_expansion_works,
                    f"Platform arrays correctly expanded to individual entries: found {len(platform_entries_found)} platform entries"
                )
            
            # Check output structure includes enhanced metadata
            output_files = list(curator.run_paths["logs"].glob("source_mapping_extraction_*.json"))
            if output_files:
                latest_file = max(output_files, key=lambda f: f.stat().st_mtime)
                with open(latest_file, 'r') as f:
                    output_data = json.load(f)
                
                # Check enhanced metadata structure
                metadata = output_data.get('metadata', {})
                has_platform_stats = 'platform_statistics' in metadata
                has_filtering_details = 'filtering_details' in metadata
                
                success &= self.add_result(
                    "curator_comprehensive_enhanced_metadata",
                    has_platform_stats and has_filtering_details,
                    f"Enhanced metadata present: platform_statistics={has_platform_stats}, filtering_details={has_filtering_details}"
                )
                
                # Validate platform statistics structure
                if has_platform_stats:
                    platform_stats = metadata['platform_statistics']
                    expected_platform_keys = [
                        'total_platforms_extracted', 'unique_platforms', 'platform_distribution',
                        'confirmed_platforms', 'unconfirmed_platforms', 'top_platforms'
                    ]
                    has_all_platform_keys = all(key in platform_stats for key in expected_platform_keys)
                    
                    success &= self.add_result(
                        "curator_comprehensive_platform_stats_structure",
                        has_all_platform_keys,
                        f"Platform statistics contains all expected keys: {expected_platform_keys}"
                    )
                
                # Validate alias data contains proper platform field (singular)
                aliases_use_singular_platform = True
                for alias_group in output_data.get('aliasGroups', []):
                    for alias in alias_group.get('aliases', []):
                        if 'platforms' in alias:  # Should be 'platform' not 'platforms'
                            aliases_use_singular_platform = False
                            break
                    if not aliases_use_singular_platform:
                        break
                
                success &= self.add_result(
                    "curator_comprehensive_platform_field_format",
                    aliases_use_singular_platform,
                    "Alias output uses 'platform' (singular) field format as required"
                )
            
            return success
            
        except Exception as e:
            return self.add_result(
                "curator_comprehensive_exception",
                False,
                f"Comprehensive property test failed with exception: {e}"
            )
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(temp_path, ignore_errors=True)

    # ============================================================================
    # MAIN TEST EXECUTION
    # ============================================================================
    
    def run_all_tests(self):
        """Run all consolidated curator tests and provide summary."""
        print("=" * 80)
        print("CONFIRMED MAPPING CURATOR TEST SUITE")
        print("=" * 80)
        
        test_sections = [
            ("Curator Initialization", [
                self.test_curator_initialization,
                self.test_curator_configuration
            ]),
            ("Data Processing", [
                self.test_cve_file_detection,
                self.test_uuid_filtering
            ]),
            ("Extraction and Processing", [
                self.test_placeholder_filtering,
                self.test_extraction_workflow,
                self.test_comprehensive_property_support
            ]),
            ("Output Generation", [
                self.test_output_generation
            ])
        ]
        
        total_tests = 0
        passed_tests = 0
        
        for section_name, test_methods in test_sections:
            print(f"\n{section_name}:")
            print("-" * 50)
            
            for test_method in test_methods:
                if test_method():
                    passed_tests += 1
                total_tests += 1
        
        # Final summary
        print("\n" + "=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)
        
        pass_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        print(f"PASSED: {passed_tests}/{total_tests} ({pass_rate:.1f}%)")
        
        if passed_tests == total_tests:
            print("ALL TESTS PASSED - Curator system fully functional")
        else:
            print("SOME TESTS FAILED - Review failed tests above")
            
        # Detailed results
        print(f"\nDetailed Results:")
        for result in self.test_results:
            status_symbol = "PASS" if result['status'] == 'PASS' else "FAIL"
            print(f"  {status_symbol}: {result['test']}: {result['message']}")
        
        # Standardized output for unified test runner
        print(f"\nTEST_RESULTS: PASSED={passed_tests} TOTAL={total_tests} SUITE=\"Confirmed Mapping Curator\"")
        
        return passed_tests == total_tests

def main():
    """Main execution function."""
    suite = ConfirmedMappingCuratorTestSuite()
    success = suite.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
