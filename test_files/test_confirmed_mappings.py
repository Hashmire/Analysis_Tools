#!/usr/bin/env python3
"""
Comprehensive test suite for Confirmed Mappings functionality.
Tests the complete data pipeline from mapping file ingestion through HTML generation.

This test suite validates:
1. Mapping file loading and structure validation
2. Confirmed mapping detection and matching logic
3. CPE filtering and culling of less specific mappings
4. Badge generation with correct styling and content
5. Modal content generation with confirmed mapping tabs
6. HTML output validation and error handling
7. Integration with badge modal system

Test Coverage:
- Data ingestion: mapping file loading, JSON structure validation
- Processing: alias matching, CPE filtering, metadata generation
- Badge display: HTML structure, styling, tooltips, modal integration
- Modal content: tab generation, confirmed mapping display
- Edge cases: missing files, malformed data, empty results
"""

import json
import re
import sys
import os
import tempfile
import unittest
from pathlib import Path
from bs4 import BeautifulSoup
from typing import Dict, List, Any
import pandas as pd

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

class ConfirmedMappingsTestSuite:
    def __init__(self):
        self.results = []
        self.passed = 0
        self.failed = 0
        self.temp_files = []
        
    def add_result(self, test_name: str, passed: bool, message: str):
        """Add a test result to the results list."""
        self.results.append({
            'test': test_name,
            'passed': passed,
            'message': message
        })
        if passed:
            self.passed += 1
        else:
            self.failed += 1
            
    def cleanup(self):
        """Clean up temporary files created during testing."""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except:
                pass
        self.temp_files = []

    def create_test_mapping_file(self, mapping_data: Dict) -> str:
        """Create a temporary mapping file for testing."""
        temp_fd, temp_path = tempfile.mkstemp(suffix='.json', prefix='test_mapping_')
        self.temp_files.append(temp_path)
        
        with os.fdopen(temp_fd, 'w') as temp_file:
            json.dump(mapping_data, temp_file, indent=2)
        
        return temp_path

    def create_test_row_data(self, test_case_name: str, **kwargs) -> Dict:
        """Create synthetic row data for testing confirmed mappings scenarios."""
        base_row = {
            'platformEntryMetadata': {
                'dataResource': 'CVEAPI',
                'platformFormatType': 'cveAffectsVersionSingle',
                'confirmedMappings': [],
                'culledConfirmedMappings': [],
                'cpeVersionChecks': [],
                'hasCPEArray': False,
                'cpeBaseStrings': [],
                'cpeCurationTracking': {},
                'unicodeNormalizationDetails': {},
                'unicodeNormalizationApplied': False,
                'duplicateRowIndices': [],
                'platformDataConcern': False
            },
            'sourceID': 'test-cna-f38d906d-7342-40ea-92c1-6c4a2c6478c8',
            'sourceRole': 'CNA',
            'rawPlatformData': {
                'vendor': 'microsoft',
                'product': 'test product',
                'versions': [
                    {
                        'version': '1.0',
                        'status': 'affected'
                    }
                ],
                'defaultStatus': 'unknown'
            },
            'sortedCPEsQueryData': {}
        }
        
        # Apply test-specific modifications
        for key, value in kwargs.items():
            if '.' in key:
                # Handle nested properties like 'rawPlatformData.vendor'
                parts = key.split('.')
                current = base_row
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                current[parts[-1]] = value
            else:
                base_row[key] = value
                
        return base_row

    def create_mock_nvd_source_data(self):
        """Create mock NVD source data for testing."""
        return pd.DataFrame([
            {
                'sourceId': 'test-source-id',
                'name': 'Test Source',
                'contactEmail': 'test@example.com',
                'sourceIdentifiers': ['test@example.com']
            }
        ])

    def initialize_nvd_source_manager(self):
        """Initialize NVD Source Manager with mock data for testing."""
        try:
            from analysis_tool.storage.nvd_source_manager import get_global_source_manager
            
            source_manager = get_global_source_manager()
            mock_nvd_data = self.create_mock_nvd_source_data()
            source_manager.initialize(mock_nvd_data)
            return True
        except Exception as e:
            print(f"Warning: Could not initialize NVD Source Manager: {e}")
            return False

    def test_data_ingestion_imports(self):
        """Test 1: Verify all necessary modules can be imported for data ingestion."""
        try:
            from analysis_tool.core.processData import (
                load_mapping_file, 
                find_confirmed_mappings, 
                process_confirmed_mappings,
                check_alias_match
            )
            from analysis_tool.core.generateHTML import convertRowDataToHTML
            from analysis_tool.storage.run_organization import create_run_directory
            
            self.add_result("DATA_INGESTION_IMPORTS", True, 
                           "All confirmed mappings modules imported successfully")
            return True
        except Exception as e:
            self.add_result("DATA_INGESTION_IMPORTS", False, 
                           f"Failed to import confirmed mappings modules: {str(e)}")
            return False

    def test_mapping_file_loading(self):
        """Test 2: Validate mapping file loading and JSON structure."""
        try:
            from analysis_tool.core.processData import load_mapping_file
            
            # Test loading existing mapping file (Microsoft)
            mapping_data = load_mapping_file('f38d906d-7342-40ea-92c1-6c4a2c6478c8')
            
            if mapping_data and 'confirmedMappings' in mapping_data:
                # Verify structure
                confirmed_mappings = mapping_data['confirmedMappings']
                if isinstance(confirmed_mappings, list) and len(confirmed_mappings) > 0:
                    # Check first mapping structure
                    first_mapping = confirmed_mappings[0]
                    has_cpe_base = 'cpebasestring' in first_mapping or 'cpeBaseString' in first_mapping
                    has_aliases = 'aliases' in first_mapping and isinstance(first_mapping['aliases'], list)
                    
                    if has_cpe_base and has_aliases:
                        self.add_result("MAPPING_FILE_LOADING", True, 
                                       f"Mapping file loaded successfully with {len(confirmed_mappings)} mappings")
                    else:
                        self.add_result("MAPPING_FILE_LOADING", False, 
                                       f"Invalid mapping structure - CPE base: {has_cpe_base}, Aliases: {has_aliases}")
                else:
                    self.add_result("MAPPING_FILE_LOADING", False, 
                                   "Mapping file loaded but confirmedMappings is empty or invalid")
            else:
                # Try with other available mapping files
                test_ids = ['286789f9-fbc2-4510-9f9a-43facdede74c',  # Apple
                           '9a959283-ebb5-44b6-b705-dcc2bbced522',   # IBM
                           '416baaa9-dc9f-4396-8d5f-8c081fb06d67']   # Linux Kernel
                
                success = False
                for test_id in test_ids:
                    test_mapping = load_mapping_file(test_id)
                    if test_mapping and 'confirmedMappings' in test_mapping:
                        success = True
                        break
                
                if success:
                    self.add_result("MAPPING_FILE_LOADING", True, 
                                   "Alternative mapping file loaded successfully")
                else:
                    self.add_result("MAPPING_FILE_LOADING", False, 
                                   "No mapping files could be loaded successfully")
        
        except Exception as e:
            self.add_result("MAPPING_FILE_LOADING", False, 
                           f"Mapping file loading test failed: {str(e)}")

    def test_alias_matching_logic(self):
        """Test 3: Validate alias matching logic requires EXACT property matches."""
        try:
            from analysis_tool.core.processData import check_alias_match
            
            # Test Case 1: Exact vendor/product match (should pass)
            alias1 = {"vendor": "microsoft", "product": "windows"}
            raw_data1 = {"vendor": "microsoft", "product": "windows"}
            match1 = check_alias_match(alias1, raw_data1)
            
            # Test Case 2: Case insensitive exact matching (should pass)
            alias2 = {"vendor": "Microsoft", "product": "Windows"}
            raw_data2 = {"vendor": "microsoft", "product": "windows"}
            match2 = check_alias_match(alias2, raw_data2)
            
            # Test Case 3: Exact match with complex product name (should pass)
            alias3 = {"vendor": "microsoft", "product": "windows 10 version 1809"}
            raw_data3 = {"vendor": "microsoft", "product": "windows 10 version 1809"}
            match3 = check_alias_match(alias3, raw_data3)
            
            # Test Case 4: Partial vendor match (should fail - no partial matching)
            alias4 = {"vendor": "micro", "product": "windows"}
            raw_data4 = {"vendor": "microsoft", "product": "windows"}
            match4 = check_alias_match(alias4, raw_data4)
            
            # Test Case 5: Partial product match (should fail - no partial matching)
            alias5 = {"vendor": "microsoft", "product": "office"}
            raw_data5 = {"vendor": "microsoft", "product": "microsoft office"}
            match5 = check_alias_match(alias5, raw_data5)
            
            # Test Case 6: Complete mismatch (should fail)
            alias6 = {"vendor": "apple", "product": "safari"}
            raw_data6 = {"vendor": "microsoft", "product": "edge"}
            match6 = check_alias_match(alias6, raw_data6)
            
            # Test Case 7: Vendor-only alias with matching vendor (should pass)
            alias7 = {"vendor": "microsoft"}
            raw_data7 = {"vendor": "microsoft", "product": "any_product"}
            match7 = check_alias_match(alias7, raw_data7)
            
            expected_results = [True, True, True, False, False, False, True]
            actual_results = [match1, match2, match3, match4, match5, match6, match7]
            
            if actual_results == expected_results:
                self.add_result("ALIAS_MATCHING_LOGIC", True, 
                               "Alias matching correctly requires exact property matches (no partial matching)")
            else:
                self.add_result("ALIAS_MATCHING_LOGIC", False, 
                               f"Alias matching failed - Expected {expected_results}, Got {actual_results}")
                
        except Exception as e:
            self.add_result("ALIAS_MATCHING_LOGIC", False, 
                           f"Alias matching test failed: {str(e)}")

    def test_confirmed_mappings_detection(self):
        """Test 4: Validate confirmed mappings detection end-to-end."""
        try:
            from analysis_tool.core.processData import find_confirmed_mappings
            
            # Test data that should match Microsoft mapping
            test_raw_data = {
                "vendor": "microsoft", 
                "product": "windows 10 version 1809"
            }
            
            confirmed_mappings = find_confirmed_mappings(test_raw_data, 'f38d906d-7342-40ea-92c1-6c4a2c6478c8')
            
            # Handle both tuple return (mappings, culled) or just mappings list
            if isinstance(confirmed_mappings, tuple):
                mappings, culled = confirmed_mappings
            else:
                mappings = confirmed_mappings if isinstance(confirmed_mappings, list) else []
                culled = []
            
            if mappings and len(mappings) > 0:
                # Verify CPE format
                valid_cpe = any('cpe:2.3:' in mapping for mapping in mappings)
                
                if valid_cpe:
                    self.add_result("CONFIRMED_MAPPINGS_DETECTION", True, 
                                   f"Confirmed mappings detected successfully: {len(mappings)} mappings found")
                else:
                    self.add_result("CONFIRMED_MAPPINGS_DETECTION", False, 
                                   f"Invalid CPE format in confirmed mappings: {mappings}")
            else:
                self.add_result("CONFIRMED_MAPPINGS_DETECTION", False, 
                               "No confirmed mappings detected for matching test data")
                
        except Exception as e:
            self.add_result("CONFIRMED_MAPPINGS_DETECTION", False, 
                           f"Confirmed mappings detection test failed: {str(e)}")

    def test_dataset_processing(self):
        """Test 5: Validate confirmed mappings processing on dataset."""
        try:
            from analysis_tool.core.processData import process_confirmed_mappings
            
            # Create test dataset
            test_data = [{
                'sourceID': 'f38d906d-7342-40ea-92c1-6c4a2c6478c8',
                'sourceRole': 'CNA',
                'rawPlatformData': {
                    'vendor': 'microsoft',
                    'product': 'windows 10 version 1809'
                },
                'platformEntryMetadata': {}
            }]
            
            test_df = pd.DataFrame(test_data)
            processed_df = process_confirmed_mappings(test_df)
            
            # Check if confirmed mappings were added to metadata
            if len(processed_df) > 0:
                metadata = processed_df.iloc[0]['platformEntryMetadata']
                confirmed_mappings = metadata.get('confirmedMappings', [])
                
                if confirmed_mappings:
                    self.add_result("DATASET_PROCESSING", True, 
                                   f"Dataset processing successful: {len(confirmed_mappings)} mappings added")
                else:
                    self.add_result("DATASET_PROCESSING", False, 
                                   "Dataset processing completed but no confirmed mappings added")
            else:
                self.add_result("DATASET_PROCESSING", False, 
                               "Dataset processing returned empty result")
                
        except Exception as e:
            self.add_result("DATASET_PROCESSING", False, 
                           f"Dataset processing test failed: {str(e)}")

    def test_badge_generation(self):
        """Test 6: Validate confirmed mappings badge generation."""
        try:
            from analysis_tool.core.generateHTML import convertRowDataToHTML
            
            # Try to initialize NVD Source Manager
            nvd_initialized = self.initialize_nvd_source_manager()
            
            # Create test row with confirmed mappings
            test_row = self.create_test_row_data(
                "badge_generation_test",
                **{
                    'platformEntryMetadata.confirmedMappings': [
                        'cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*',
                        'cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*'
                    ],
                    'platformEntryMetadata.culledConfirmedMappings': [
                        'cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*'
                    ]
                }
            )
            
            if nvd_initialized:
                html_output = convertRowDataToHTML(test_row, 0)
                soup = BeautifulSoup(html_output, 'html.parser')
                
                # Look for Confirmed Mappings badge
                confirmed_badge = soup.find('span', string=re.compile(r'Confirmed Mappings: \d+'))
                
                if confirmed_badge:
                    # Verify badge styling
                    badge_classes = confirmed_badge.get('class', [])
                    has_success_class = 'bg-success' in badge_classes
                    
                    # Verify tooltip content
                    tooltip = confirmed_badge.get('title', '')
                    has_correct_count = 'Confirmed CPE mappings available (2)' in tooltip
                    has_culled_info = 'Less specific mappings filtered out' in tooltip
                    
                    if has_success_class and has_correct_count and has_culled_info:
                        self.add_result("BADGE_GENERATION", True, 
                                       "Confirmed mappings badge generated correctly with proper styling and content")
                    else:
                        self.add_result("BADGE_GENERATION", False, 
                                       f"Badge issues - Success class: {has_success_class}, Count: {has_correct_count}, Culled: {has_culled_info}")
                else:
                    self.add_result("BADGE_GENERATION", False, 
                                   "Confirmed mappings badge not found in generated HTML")
            else:
                self.add_result("BADGE_GENERATION", False, 
                               "Could not initialize NVD Source Manager for HTML generation test")
                
        except Exception as e:
            self.add_result("BADGE_GENERATION", False, 
                           f"Badge generation test failed: {str(e)}")

    def test_modal_content_generation(self):
        """Test 7: Validate modal content generation for confirmed mappings."""
        try:
            from analysis_tool.core.generateHTML import convertRowDataToHTML
            
            # Try to initialize NVD Source Manager
            nvd_initialized = self.initialize_nvd_source_manager()
            
            # Create test row with confirmed mappings for modal
            test_row = self.create_test_row_data(
                "modal_content_test",
                **{
                    'platformEntryMetadata.confirmedMappings': [
                        'cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*',
                        'cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*'
                    ]
                }
            )
            
            if nvd_initialized:
                html_output = convertRowDataToHTML(test_row, 0)
                
                # Check for modal-related content and confirmed mapping data
                has_modal_trigger = 'data-bs-toggle' in html_output
                has_confirmed_mapping_data = 'confirmedMapping' in html_output
                has_confirmed_badge = 'Confirmed Mappings:' in html_output
                
                # Look for the confirmed mappings in the HTML content
                has_office_mapping = 'microsoft:office:2019' in html_output
                has_windows_mapping = 'microsoft:windows_10_1809' in html_output
                
                if has_confirmed_badge and (has_office_mapping or has_windows_mapping):
                    self.add_result("MODAL_CONTENT_GENERATION", True, 
                                   "Confirmed mappings content available in HTML output")
                else:
                    self.add_result("MODAL_CONTENT_GENERATION", False, 
                                   f"Modal content issues - Badge: {has_confirmed_badge}, Office: {has_office_mapping}, Windows: {has_windows_mapping}")
            else:
                self.add_result("MODAL_CONTENT_GENERATION", False, 
                               "Could not initialize NVD Source Manager for modal content test")
                
        except Exception as e:
            self.add_result("MODAL_CONTENT_GENERATION", False, 
                           f"Modal content generation test failed: {str(e)}")

    def test_html_structure_validation(self):
        """Test 8: Validate HTML content structure with confirmed mappings."""
        try:
            from analysis_tool.core.generateHTML import convertRowDataToHTML
            
            # Try to initialize NVD Source Manager
            nvd_initialized = self.initialize_nvd_source_manager()
            
            test_row = self.create_test_row_data(
                "html_structure_test",
                **{
                    'platformEntryMetadata.confirmedMappings': [
                        'cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*'
                    ]
                }
            )
            
            if nvd_initialized:
                html_output = convertRowDataToHTML(test_row, 0)
                
                # Validate essential HTML content structure
                has_table_structure = '<table' in html_output and '</table>' in html_output
                has_badge_content = 'badge' in html_output
                has_confirmed_mappings = 'Confirmed Mappings:' in html_output
                has_cpe_data = 'cpe:2.3:' in html_output
                
                structure_valid = has_table_structure and has_badge_content and has_confirmed_mappings
                
                if structure_valid:
                    self.add_result("HTML_STRUCTURE_VALIDATION", True, 
                                   "HTML content structure is valid with confirmed mappings")
                else:
                    self.add_result("HTML_STRUCTURE_VALIDATION", False, 
                                   f"HTML structure issues - Table: {has_table_structure}, Badge: {has_badge_content}, Mappings: {has_confirmed_mappings}")
            else:
                self.add_result("HTML_STRUCTURE_VALIDATION", False, 
                               "Could not initialize NVD Source Manager for HTML structure test")
                
        except Exception as e:
            self.add_result("HTML_STRUCTURE_VALIDATION", False, 
                           f"HTML structure validation test failed: {str(e)}")

    def test_edge_cases_and_error_handling(self):
        """Test 9: Validate edge cases and error handling."""
        try:
            from analysis_tool.core.processData import find_confirmed_mappings, load_mapping_file
            
            # Test Case 1: Empty raw data
            empty_result = find_confirmed_mappings({}, 'test-id')
            empty_mappings = empty_result[0] if isinstance(empty_result, tuple) else empty_result
            
            # Test Case 2: Non-existent source ID
            nonexistent_result = find_confirmed_mappings({'vendor': 'test'}, 'nonexistent-id')
            nonexistent_mappings = nonexistent_result[0] if isinstance(nonexistent_result, tuple) else nonexistent_result
            
            # Test Case 3: Malformed vendor/product data
            malformed_result = find_confirmed_mappings({'invalidKey': 'value'}, 'f38d906d-7342-40ea-92c1-6c4a2c6478c8')
            malformed_mappings = malformed_result[0] if isinstance(malformed_result, tuple) else malformed_result
            
            # All edge cases should return empty lists without throwing exceptions
            edge_cases_handled = (
                isinstance(empty_mappings, list) and len(empty_mappings) == 0 and
                isinstance(nonexistent_mappings, list) and len(nonexistent_mappings) == 0 and
                isinstance(malformed_mappings, list) and len(malformed_mappings) == 0
            )
            
            if edge_cases_handled:
                self.add_result("EDGE_CASES_ERROR_HANDLING", True, 
                               "Edge cases handled correctly without exceptions")
            else:
                self.add_result("EDGE_CASES_ERROR_HANDLING", False, 
                               f"Edge case handling failed - Empty: {type(empty_mappings)}, Nonexistent: {type(nonexistent_mappings)}, Malformed: {type(malformed_mappings)}")
                
        except Exception as e:
            self.add_result("EDGE_CASES_ERROR_HANDLING", False, 
                           f"Edge cases test failed with exception: {str(e)}")

    def test_integration_with_badge_modal_system(self):
        """Test 10: Validate integration with badge modal system."""
        try:
            from analysis_tool.core.generateHTML import convertRowDataToHTML
            
            # Try to initialize NVD Source Manager
            nvd_initialized = self.initialize_nvd_source_manager()
            
            test_row = self.create_test_row_data(
                "integration_test",
                **{
                    'platformEntryMetadata.confirmedMappings': [
                        'cpe:2.3:a:test:integration:1.0:*:*:*:*:*:*:*'
                    ]
                }
            )
            
            if nvd_initialized:
                html_output = convertRowDataToHTML(test_row, 0)
                
                # Check for integration elements
                has_badge_content = 'Confirmed Mappings:' in html_output
                has_cpe_content = 'test:integration:1.0' in html_output
                has_bootstrap_modal = 'data-bs-' in html_output
                has_supporting_info = 'Supporting Information' in html_output
                
                integration_indicators = [has_badge_content, has_cpe_content, has_bootstrap_modal, has_supporting_info]
                integration_score = sum(integration_indicators)
                
                if integration_score >= 2:  # At least 2 out of 4 integration indicators
                    self.add_result("BADGE_MODAL_SYSTEM_INTEGRATION", True, 
                                   f"Badge modal system integration functional ({integration_score}/4 indicators)")
                else:
                    self.add_result("BADGE_MODAL_SYSTEM_INTEGRATION", False, 
                                   f"Integration incomplete - Badge: {has_badge_content}, CPE: {has_cpe_content}, Modal: {has_bootstrap_modal}, Support: {has_supporting_info}")
            else:
                self.add_result("BADGE_MODAL_SYSTEM_INTEGRATION", False, 
                               "Could not initialize NVD Source Manager for integration test")
                
        except Exception as e:
            self.add_result("BADGE_MODAL_SYSTEM_INTEGRATION", False, 
                           f"Badge modal system integration test failed: {str(e)}")

    def run_all_tests(self):
        """Run all confirmed mappings tests in sequence."""
        print("🧪 Starting Confirmed Mappings Test Suite")
        print("=" * 60)
        
        # Import test
        if not self.test_data_ingestion_imports():
            print("❌ Critical failure: Cannot import required modules")
            return self.print_results()
        
        # Core functionality tests
        self.test_mapping_file_loading()
        self.test_alias_matching_logic()
        self.test_confirmed_mappings_detection()
        self.test_dataset_processing()
        
        # HTML generation tests
        self.test_badge_generation()
        self.test_modal_content_generation()
        self.test_html_structure_validation()
        
        # Edge cases and integration tests
        self.test_edge_cases_and_error_handling()
        self.test_integration_with_badge_modal_system()
        
        return self.print_results()

    def print_results(self):
        """Print comprehensive test results."""
        print("\n" + "=" * 60)
        # Only show failures for debugging
        if self.failed > 0:
            failures = [result for result in self.results if not result['passed']]
            print(f"\nTest Failures ({len(failures)}):")
            for result in failures:
                print(f"  - {result['test']}: {result['message']}")
        
        # Cleanup
        self.cleanup()
        
        return self.failed == 0

def main():
    """Main function to run the confirmed mappings test suite."""
    test_suite = ConfirmedMappingsTestSuite()
    success = test_suite.run_all_tests()
    
    # STANDARD OUTPUT FORMAT - Required for unified test runner
    total_tests = test_suite.passed + test_suite.failed
    print(f"TEST_RESULTS: PASSED={test_suite.passed} TOTAL={total_tests} SUITE=\"Confirmed Mappings\"")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
