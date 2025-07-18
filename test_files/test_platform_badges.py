#!/usr/bin/env python3
"""
Automated test suite for Platform Entry Notification badges functionality.
Tests that all badges generate correctly with appropriate content for their supported cases.

This test suite validates the new badge modal system integration including:
1. Badge presence and HTML structure with modal integration
2. Badge content and tooltip/modal functionality
3. Badge priority ordering (Danger -> Warning -> Source Data Concern -> Info -> Standard)
4. Modal badge consolidation (Supporting Information badge)
5. JSON Generation Rules badge (replaces old wildcard/update pattern badges)
6. Edge cases and error conditions

Updated for the new badge_modal_system integration that consolidates several badges
into modal-based interactions for better user experience.
"""

import json
import re
import sys
import os
import pandas as pd
from pathlib import Path
from bs4 import BeautifulSoup
from typing import Dict, List, Set, Tuple, Any

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

class PlatformBadgesTestSuite:
    def __init__(self):
        self.results = []
        self.passed = 0
        self.failed = 0
        
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
    
    def create_test_row_data(self, test_case_name: str, **kwargs) -> Dict:
        """Create synthetic row data for testing specific badge scenarios."""
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
            'sourceID': 'test-source-id',
            'sourceRole': 'CNA',
            'rawPlatformData': {
                'vendor': 'Test Vendor',
                'product': 'Test Product',
                'versions': [],
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
    
    def test_badge_generation_import(self):
        """Test that we can import the badge generation functions."""
        try:
            from analysis_tool.generateHTML import convertRowDataToHTML, analyze_version_characteristics
            self.mock_nvd_data = self.create_mock_nvd_source_data()
            self.add_result("IMPORT_FUNCTIONS", True, "Successfully imported badge generation functions")
            return convertRowDataToHTML, analyze_version_characteristics
        except ImportError as e:
            self.add_result("IMPORT_FUNCTIONS", False, f"Failed to import functions: {e}")
            return None, None
    
    def test_confirmed_mappings_badge(self):
        """Test Confirmed Mappings badge (Standard/Success)."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        # Test case 1: Confirmed mappings present
        test_row = self.create_test_row_data(
            "confirmed_mappings",
            **{
                'platformEntryMetadata.confirmedMappings': [
                    'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*',
                    'cpe:2.3:a:vendor:product_alt:*:*:*:*:*:*:*:*'
                ]
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        # Look for Confirmed Mappings badge
        confirmed_badge = soup.find('span', string=re.compile(r'Confirmed Mappings: \d+'))
        if confirmed_badge and 'bg-success' in confirmed_badge.get('class', []):
            tooltip = confirmed_badge.get('title', '')
            if 'Confirmed CPE mappings available (2)' in tooltip:
                self.add_result("CONFIRMED_MAPPINGS_BADGE", True, 
                               "Confirmed mappings badge displays correctly with count and tooltip")
            else:
                self.add_result("CONFIRMED_MAPPINGS_BADGE", False, 
                               f"Confirmed mappings badge tooltip incorrect: {tooltip}")
        else:
            self.add_result("CONFIRMED_MAPPINGS_BADGE", False, 
                           "Confirmed mappings badge not found or incorrect styling")
    
    def test_git_version_type_badge(self):
        """Test git versionType badge (Warning/Danger)."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        # Test case 1: git versionType without ranges (Warning)
        test_row = self.create_test_row_data(
            "git_version_warning",
            **{
                'platformEntryMetadata.platformFormatType': 'cveAffectsVersionSingle',
                'rawPlatformData.versions': [
                    {'version': 'abc123', 'versionType': 'git', 'status': 'affected'}
                ]
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        git_badge = soup.find('span', string='git versionType')
        if git_badge and 'bg-warning' in git_badge.get('class', []):
            self.add_result("GIT_VERSION_WARNING", True, 
                           "git versionType badge shows as warning for single versions")
        else:
            self.add_result("GIT_VERSION_WARNING", False, 
                           "git versionType warning badge not found or incorrect styling")
        
        # Test case 2: git versionType with ranges (Danger)
        test_row_danger = self.create_test_row_data(
            "git_version_danger",
            **{
                'platformEntryMetadata.platformFormatType': 'cveAffectsVersionRange',
                'rawPlatformData.versions': [
                    {'version': '*', 'lessThan': 'abc123', 'versionType': 'git', 'status': 'affected'}
                ]
            }
        )
        
        html_output_danger = convertRowDataToHTML(test_row_danger, self.mock_nvd_data, 0)
        soup_danger = BeautifulSoup(html_output_danger, 'html.parser')
        
        git_badge_danger = soup_danger.find('span', string='git versionType')
        if git_badge_danger and 'bg-danger' in git_badge_danger.get('class', []):
            tooltip = git_badge_danger.get('title', '')
            if 'CRITICAL' in tooltip and 'Range Matching Logic' in tooltip:
                self.add_result("GIT_VERSION_DANGER", True, 
                               "git versionType badge shows as danger for version ranges with correct tooltip")
            else:
                self.add_result("GIT_VERSION_DANGER", False, 
                               f"git versionType danger badge tooltip incorrect: {tooltip}")
        else:
            self.add_result("GIT_VERSION_DANGER", False, 
                           "git versionType danger badge not found or incorrect styling")
    
    def test_no_versions_badge(self):
        """Test CVE Affects Product (No Versions) badge (Danger)."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "no_versions",
            **{
                'platformEntryMetadata.platformFormatType': 'cveAffectsNoVersions',
                'platformEntryMetadata.cpeVersionChecks': [
                    {'field': 'versions', 'status': 'missing'}
                ],
                'rawPlatformData.versions': []
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        no_versions_badge = soup.find('span', string='CVE Affects Product (No Versions)')
        if no_versions_badge and 'bg-danger' in no_versions_badge.get('class', []):
            self.add_result("NO_VERSIONS_BADGE", True, 
                           "No versions badge displays as danger with correct text")
        else:
            self.add_result("NO_VERSIONS_BADGE", False, 
                           "No versions badge not found or incorrect styling")
    
    def test_cve_affected_cpes_badge(self):
        """Test CVE Affected CPES Data badge (now consolidated in Supporting Information)."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "cve_affected_cpes",
            **{
                'platformEntryMetadata.hasCPEArray': True,
                'rawPlatformData.cpes': [
                    'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*',
                    'cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*',
                    'invalid_cpe_string'  # Should be filtered out
                ]
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        # CVE Affected CPES is now part of Supporting Information modal
        supporting_info_badge = soup.find('span', string=re.compile(r'🔍 Supporting Information'))
        if supporting_info_badge and 'modal-badge' in supporting_info_badge.get('class', []):
            # Check if it has the onclick handler for BadgeModalManager
            onclick_attr = supporting_info_badge.get('onclick', '')
            if 'BadgeModalManager.openSupportingInformationModal' in onclick_attr:
                self.add_result("CVE_AFFECTED_CPES_BADGE", True, 
                               "CVE Affected CPES data now correctly integrated into Supporting Information modal")
            else:
                self.add_result("CVE_AFFECTED_CPES_BADGE", False, 
                               f"Supporting Information badge missing modal integration: {onclick_attr}")
        else:
            self.add_result("CVE_AFFECTED_CPES_BADGE", False, 
                           "CVE Affected CPES data not found in Supporting Information badge")
    
    def test_version_changes_badge(self):
        """Test Has Version Changes badge (Warning)."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "version_changes",
            **{
                'rawPlatformData.versions': [
                    {
                        'version': '1.0',
                        'status': 'affected',
                        'changes': [
                            {'at': '2023-01-01', 'status': 'unaffected'}
                        ]
                    }
                ]
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        changes_badge = soup.find('span', string='Has Version Changes')
        if changes_badge and 'bg-warning' in changes_badge.get('class', []):
            tooltip = changes_badge.get('title', '')
            if 'change history' in tooltip:
                self.add_result("VERSION_CHANGES_BADGE", True, 
                               "Version changes badge displays correctly with appropriate tooltip")
            else:
                self.add_result("VERSION_CHANGES_BADGE", False, 
                               f"Version changes badge tooltip incorrect: {tooltip}")
        else:
            self.add_result("VERSION_CHANGES_BADGE", False, 
                           "Version changes badge not found or incorrect styling")
    
    def test_wildcard_patterns_badge(self):
        """Test JSON Generation Rules badge (Warning) - unified modal for wildcard patterns."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "wildcard_patterns",
            **{
                'rawPlatformData.versions': [
                    {'version': '*', 'lessThan': '2.0', 'status': 'affected'},
                    {'version': '1.0.*', 'status': 'affected'}
                ]
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        # Look for the unified JSON Generation Rules badge
        json_rules_badge = soup.find('span', string=re.compile(r'⚙️ JSON Generation Rules'))
        if json_rules_badge and 'modal-badge' in json_rules_badge.get('class', []) and 'bg-warning' in json_rules_badge.get('class', []):
            onclick_attr = json_rules_badge.get('onclick', '')
            tooltip = json_rules_badge.get('title', '')
            
            # Check for proper modal integration and wildcard-specific tooltip content
            if ('BadgeModalManager.openJsonGenerationRulesModal' in onclick_attr and 
                ('Upper Bound' in tooltip or 'wildcard' in tooltip.lower())):
                self.add_result("WILDCARD_PATTERNS_BADGE", True, 
                               "JSON Generation Rules badge (wildcard patterns) displays correctly with unified modal integration")
            else:
                self.add_result("WILDCARD_PATTERNS_BADGE", False, 
                               f"JSON Generation Rules badge missing proper wildcard integration: onclick={onclick_attr}, tooltip={tooltip}")
        else:
            self.add_result("WILDCARD_PATTERNS_BADGE", False, 
                           "JSON Generation Rules badge not found or incorrect styling")
    
    def test_update_patterns_badge(self):
        """Test JSON Generation Rules badge (Warning) - unified modal for update patterns."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "update_patterns",
            **{
                'rawPlatformData.versions': [
                    {'version': '3.0.0 p1', 'status': 'affected'},  # Patch pattern
                    {'version': '3.1.0 p2', 'status': 'affected'},  # Patch pattern
                    {'version': '3.3 Patch 1', 'status': 'affected'},  # Patch pattern
                    {'version': '2.0.0 sp1', 'status': 'affected'},  # Service pack pattern
                    {'version': '1.0.0-hotfix.2', 'status': 'affected'}  # Hotfix pattern
                ]
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        # Look for the unified JSON Generation Rules badge
        json_rules_badge = soup.find('span', string=re.compile(r'⚙️ JSON Generation Rules'))
        if json_rules_badge and 'modal-badge' in json_rules_badge.get('class', []) and 'bg-warning' in json_rules_badge.get('class', []):
            onclick_attr = json_rules_badge.get('onclick', '')
            tooltip = json_rules_badge.get('title', '')
            
            # Check for proper modal integration and update pattern-specific tooltip content
            if ('BadgeModalManager.openJsonGenerationRulesModal' in onclick_attr and 
                ('transformation' in tooltip.lower() or 'update pattern' in tooltip.lower())):
                self.add_result("UPDATE_PATTERNS_BADGE", True, 
                               "JSON Generation Rules badge (update patterns) displays correctly with unified modal integration")
            else:
                self.add_result("UPDATE_PATTERNS_BADGE", False, 
                               f"JSON Generation Rules badge missing proper update pattern integration: onclick={onclick_attr}, tooltip={tooltip}")
        else:
            self.add_result("UPDATE_PATTERNS_BADGE", False, 
                           "JSON Generation Rules badge not found or incorrect styling")
    
    def test_cpe_api_errors_badge(self):
        """Test CPE API Errors badge (now consolidated in Supporting Information)."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "cpe_api_errors",
            sortedCPEsQueryData={
                'cpe:2.3:a:test:invalid:*:*:*:*:*:*:*:*': {
                    'status': 'invalid_cpe',
                    'error_message': 'Invalid CPE format'
                },
                'cpe:2.3:a:test:error:*:*:*:*:*:*:*:*': {
                    'status': 'error',
                    'error_message': 'API timeout'
                },
                'cpe:2.3:a:test:valid:*:*:*:*:*:*:*:*': {
                    'status': 'success',
                    'depFalseCount': 5
                }
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        # CPE API Errors is now part of Supporting Information modal
        supporting_info_badge = soup.find('span', string=re.compile(r'🔍 Supporting Information'))
        if supporting_info_badge and 'modal-badge' in supporting_info_badge.get('class', []):
            # Check if it has the onclick handler for BadgeModalManager
            onclick_attr = supporting_info_badge.get('onclick', '')
            if 'BadgeModalManager.openSupportingInformationModal' in onclick_attr:
                self.add_result("CPE_API_ERRORS_BADGE", True, 
                               "CPE API Errors now correctly integrated into Supporting Information modal")
            else:
                self.add_result("CPE_API_ERRORS_BADGE", False, 
                               f"Supporting Information badge missing modal integration: {onclick_attr}")
        else:
            self.add_result("CPE_API_ERRORS_BADGE", False, 
                           "CPE API Errors not found in Supporting Information badge")
    
    def test_cpe_base_string_searches_badge(self):
        """Test CPE Base String Searches badge (now consolidated in Supporting Information)."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "cpe_base_strings",
            **{
                'platformEntryMetadata.cpeBaseStrings': [
                    'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*',
                    'cpe:2.3:a:vendor:product_alt:*:*:*:*:*:*:*:*'
                ]
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        # CPE Base String Searches is now part of Supporting Information modal
        supporting_info_badge = soup.find('span', string=re.compile(r'🔍 Supporting Information'))
        if supporting_info_badge and 'modal-badge' in supporting_info_badge.get('class', []):
            # Check if it has the onclick handler for BadgeModalManager
            onclick_attr = supporting_info_badge.get('onclick', '')
            if 'BadgeModalManager.openSupportingInformationModal' in onclick_attr:
                self.add_result("CPE_BASE_STRINGS_BADGE", True, 
                               "CPE Base String Searches now correctly integrated into Supporting Information modal")
            else:
                self.add_result("CPE_BASE_STRINGS_BADGE", False, 
                               f"Supporting Information badge missing modal integration: {onclick_attr}")
        else:
            self.add_result("CPE_BASE_STRINGS_BADGE", False, 
                           "CPE Base String Searches not found in Supporting Information badge")
    
    def test_transformations_applied_badge(self):
        """Test Source to CPE Transformations Applied badge (now consolidated in Supporting Information)."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "transformations_applied",
            **{
                'platformEntryMetadata.cpeCurationTracking': {
                    'vendor': [{'original': 'Test Corp', 'curated': 'test_corp'}],
                    'product': [{'original': 'My Product', 'curated': 'my_product'}]
                },
                'platformEntryMetadata.unicodeNormalizationDetails': {
                    'transformations': [
                        {
                            'field': 'vendor',
                            'original': 'Tëst',
                            'normalized': 'Test'
                        }
                    ]
                }
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        # Source to CPE Transformations Applied is now part of Supporting Information modal
        supporting_info_badge = soup.find('span', string=re.compile(r'🔍 Supporting Information'))
        if supporting_info_badge and 'modal-badge' in supporting_info_badge.get('class', []):
            # Check if it has the onclick handler for BadgeModalManager
            onclick_attr = supporting_info_badge.get('onclick', '')
            if 'BadgeModalManager.openSupportingInformationModal' in onclick_attr:
                self.add_result("TRANSFORMATIONS_APPLIED_BADGE", True, 
                               "Source to CPE Transformations Applied now correctly integrated into Supporting Information modal")
            else:
                self.add_result("TRANSFORMATIONS_APPLIED_BADGE", False, 
                               f"Supporting Information badge missing modal integration: {onclick_attr}")
        else:
            self.add_result("TRANSFORMATIONS_APPLIED_BADGE", False, 
                           "Source to CPE Transformations Applied not found in Supporting Information badge")
    
    def test_vendor_na_badge(self):
        """Test Vendor: N/A badge (Source Data Concern)."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "vendor_na",
            **{'rawPlatformData.vendor': 'n/a'}
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        vendor_na_badge = soup.find('span', string='Vendor: N/A')
        if vendor_na_badge and 'bg-sourceDataConcern' in vendor_na_badge.get('class', []):
            self.add_result("VENDOR_NA_BADGE", True, 
                           "Vendor N/A badge displays correctly")
        else:
            self.add_result("VENDOR_NA_BADGE", False, 
                           "Vendor N/A badge not found or incorrect styling")
    
    def test_product_na_badge(self):
        """Test Product: N/A badge (Source Data Concern)."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "product_na",
            **{'rawPlatformData.product': 'N/A'}  # Test case insensitive
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        product_na_badge = soup.find('span', string='Product: N/A')
        if product_na_badge and 'bg-sourceDataConcern' in product_na_badge.get('class', []):
            self.add_result("PRODUCT_NA_BADGE", True, 
                           "Product N/A badge displays correctly")
        else:
            self.add_result("PRODUCT_NA_BADGE", False, 
                           "Product N/A badge not found or incorrect styling")
    
    def test_versions_data_concern_badge(self):
        """Test Versions Data Concern badge (Source Data Concern)."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "versions_data_concern",
            **{
                'rawPlatformData.versions': [
                    {'version': 'before 2.0', 'status': 'affected'},  # Text pattern
                    {'version': '> 1.0', 'status': 'affected'},  # Comparator
                    {'version': 'unknown', 'status': 'affected'}  # Non-specific
                ]
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        versions_concern_badge = soup.find('span', string='Versions Data Concern')
        if versions_concern_badge and 'bg-sourceDataConcern' in versions_concern_badge.get('class', []):
            tooltip = versions_concern_badge.get('title', '')
            if 'formatting issues' in tooltip and 'before' in tooltip:
                self.add_result("VERSIONS_DATA_CONCERN_BADGE", True, 
                               "Versions data concern badge displays correctly with formatting issues")
            else:
                self.add_result("VERSIONS_DATA_CONCERN_BADGE", False, 
                               f"Versions data concern badge tooltip incorrect: {tooltip}")
        else:
            self.add_result("VERSIONS_DATA_CONCERN_BADGE", False, 
                           "Versions data concern badge not found or incorrect styling")
    
    def test_duplicate_entries_badge(self):
        """Test Duplicate Entries Detected badge (Source Data Concern)."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "duplicate_entries",
            **{
                'platformEntryMetadata.duplicateRowIndices': [2, 5, 8]
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        duplicate_badge = soup.find('span', string='Duplicate Entries Detected')
        if duplicate_badge and 'bg-sourceDataConcern' in duplicate_badge.get('class', []):
            tooltip = duplicate_badge.get('title', '')
            if 'row(s): 2, 5, 8' in tooltip:
                self.add_result("DUPLICATE_ENTRIES_BADGE", True, 
                               "Duplicate entries badge displays correctly with row indices")
            else:
                self.add_result("DUPLICATE_ENTRIES_BADGE", False, 
                               f"Duplicate entries badge tooltip incorrect: {tooltip}")
        else:
            self.add_result("DUPLICATE_ENTRIES_BADGE", False, 
                           "Duplicate entries badge not found or incorrect styling")
    
    def test_badge_priority_order(self):
        """Test that badges appear in the correct priority order."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        # Create a row with multiple badge types to test priority ordering
        test_row = self.create_test_row_data(
            "badge_priority_order",
            **{
                'platformEntryMetadata.platformFormatType': 'cveAffectsNoVersions',  # Danger
                'platformEntryMetadata.confirmedMappings': ['cpe:2.3:a:test:test:*:*:*:*:*:*:*:*'],  # Standard
                'platformEntryMetadata.duplicateRowIndices': [2],  # Source Data Concern
                'platformEntryMetadata.hasCPEArray': True,  # Will trigger Supporting Information
                'platformEntryMetadata.cpeBaseStrings': ['cpe:2.3:a:test:test:*:*:*:*:*:*:*:*'],  # Supporting Information
                'rawPlatformData.vendor': 'n/a',  # Source Data Concern
                'rawPlatformData.versions': [
                    {'version': '1.0.*', 'status': 'affected'},  # Warning (JSON Generation Rules)
                    {'version': 'before 2.0', 'status': 'affected'}  # Source Data Concern (Version concern)
                ],
                'rawPlatformData.cpes': ['cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*']  # Supporting Information content
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        # Find all badges in order
        badge_row = soup.find('td', string='Platform Entry Notifications')
        if badge_row:
            next_cell = badge_row.find_next_sibling('td')
            if next_cell:
                badges = next_cell.find_all('span', class_='badge')
                badge_classes = [badge.get('class', []) for badge in badges]
                
                # Check order: Danger -> Warning -> Source Data Concern -> Info -> Standard
                order_correct = True
                last_priority = 10  # Start with high value
                
                for badge_class in badge_classes:
                    current_priority = 0
                    if 'bg-danger' in badge_class:
                        current_priority = 5
                    elif 'bg-warning' in badge_class:
                        current_priority = 4
                    elif 'bg-sourceDataConcern' in badge_class:
                        current_priority = 3
                    elif 'bg-info' in badge_class:
                        current_priority = 2
                    elif 'bg-success' in badge_class or 'bg-secondary' in badge_class:
                        current_priority = 1
                    
                    # Priority should be non-increasing (equal priority is allowed)
                    if current_priority > last_priority:
                        order_correct = False
                        break
                    last_priority = current_priority
                
                if order_correct and len(badges) >= 3:  # Adjusted for modal consolidation
                    # Check for expected badges in the new unified modal system
                    badge_texts = [badge.get_text() for badge in badges]
                    
                    # Expected badges with new modal integration
                    has_no_versions = any('CVE Affects Product (No Versions)' in text for text in badge_texts)
                    has_json_rules = any('JSON Generation Rules' in text for text in badge_texts)
                    has_supporting_info = any('Supporting Information' in text for text in badge_texts)
                    has_vendor_na = any('Vendor: N/A' in text for text in badge_texts)
                    has_versions_concern = any('Versions Data Concern' in text for text in badge_texts)
                    
                    # Should have at least the key badges from the unified modal system
                    expected_count = sum([has_no_versions, has_json_rules, has_supporting_info, has_vendor_na, has_versions_concern])
                    
                    if expected_count >= 3:  # Should have at least 3 of the expected badges
                        self.add_result("BADGE_PRIORITY_ORDER", True, 
                                       f"Badges appear in correct priority order with unified modal system ({len(badges)} badges found)")
                    else:
                        self.add_result("BADGE_PRIORITY_ORDER", False, 
                                       f"Expected unified modal badges not found in sufficient quantity: {badge_texts}")
                else:
                    badge_texts = [badge.get_text() for badge in badges]
                    self.add_result("BADGE_PRIORITY_ORDER", False, 
                                   f"Badge order incorrect or insufficient badges: {badge_texts} (found {len(badges)})")
            else:
                self.add_result("BADGE_PRIORITY_ORDER", False, 
                               "Could not find badge content cell")
        else:
            self.add_result("BADGE_PRIORITY_ORDER", False, 
                           "Could not find Platform Entry Notifications row")
    
    def test_supporting_information_modal_badge(self):
        """Test Supporting Information modal badge integration with standardized header format."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        test_row = self.create_test_row_data(
            "supporting_information_modal",
            **{
                'platformEntryMetadata.hasCPEArray': True,
                'platformEntryMetadata.cpeBaseStrings': [
                    'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*'
                ],
                'platformEntryMetadata.platformFormatType': 'cveAffectsVersionRange',
                'rawPlatformData.vendor': 'TestVendor',
                'rawPlatformData.product': 'TestProduct',
                'rawPlatformData.versions': [
                    {'version': '1.0', 'lessThan': '2.0', 'status': 'affected'}
                ],
                'rawPlatformData.cpes': [
                    'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*'
                ]
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        # Look for the Supporting Information modal badge
        supporting_info_badge = soup.find('span', string=re.compile(r'🔍 Supporting Information'))
        if supporting_info_badge and 'modal-badge' in supporting_info_badge.get('class', []):
            onclick_attr = supporting_info_badge.get('onclick', '')
            
            # Check for proper modal integration with header format
            if 'BadgeModalManager.openSupportingInformationModal' in onclick_attr:
                # Extract the header from the onclick attribute to verify format
                header_match = re.search(r"'([^']*Platform Entry[^']*)'", onclick_attr)
                if header_match:
                    header = header_match.group(1)
                    # Check for standardized header format: "Platform Entry X (CNA, SourceID, Vendor/Product/etc.)"
                    if ('Platform Entry' in header and 
                        ('TestVendor' in header or 'TestProduct' in header) and
                        '(' in header and ')' in header):
                        self.add_result("SUPPORTING_INFORMATION_MODAL_BADGE", True, 
                                       f"Supporting Information modal badge displays correctly with standardized header format: {header}")
                    else:
                        self.add_result("SUPPORTING_INFORMATION_MODAL_BADGE", False, 
                                       f"Supporting Information badge header format incorrect: {header}")
                else:
                    self.add_result("SUPPORTING_INFORMATION_MODAL_BADGE", False, 
                                   "Supporting Information badge missing header in modal integration")
            else:
                self.add_result("SUPPORTING_INFORMATION_MODAL_BADGE", False, 
                               f"Supporting Information badge missing modal integration: {onclick_attr}")
        else:
            self.add_result("SUPPORTING_INFORMATION_MODAL_BADGE", False, 
                           "Supporting Information modal badge not found or incorrect styling")
    
    def test_json_generation_rules_modal_integration(self):
        """Test JSON Generation Rules modal badge integration with standardized header format."""
        convertRowDataToHTML, _ = self.test_badge_generation_import()
        if not convertRowDataToHTML:
            return
            
        # Test with both wildcard and update patterns to ensure unified badge works
        test_row = self.create_test_row_data(
            "json_generation_rules_modal",
            **{
                'rawPlatformData.vendor': 'TestVendor',
                'rawPlatformData.product': 'TestProduct',
                'rawPlatformData.versions': [
                    {'version': '*', 'lessThan': '2.0', 'status': 'affected'},  # Wildcard pattern
                    {'version': '1.0.0 p1', 'status': 'affected'},  # Update pattern
                    {'version': '1.5.*', 'status': 'affected'}  # Another wildcard
                ]
            }
        )
        
        html_output = convertRowDataToHTML(test_row, self.mock_nvd_data, 0)
        soup = BeautifulSoup(html_output, 'html.parser')
        
        # Look for the unified JSON Generation Rules badge
        json_rules_badge = soup.find('span', string=re.compile(r'⚙️ JSON Generation Rules'))
        if json_rules_badge and 'modal-badge' in json_rules_badge.get('class', []) and 'bg-warning' in json_rules_badge.get('class', []):
            onclick_attr = json_rules_badge.get('onclick', '')
            
            # Check for proper modal integration with header format
            if 'BadgeModalManager.openJsonGenerationRulesModal' in onclick_attr:
                # Extract the header from the onclick attribute to verify format
                header_match = re.search(r"'([^']*Platform Entry[^']*)'", onclick_attr)
                if header_match:
                    header = header_match.group(1)
                    # Check for standardized header format: "Platform Entry X (CNA, SourceID, Vendor/Product/etc.)"
                    if ('Platform Entry' in header and 
                        ('TestVendor' in header or 'TestProduct' in header) and
                        '(' in header and ')' in header):
                        
                        # Also check that the badge has appropriate tooltip content
                        tooltip = json_rules_badge.get('title', '')
                        has_wildcard_content = 'Upper Bound' in tooltip or 'wildcard' in tooltip.lower()
                        has_update_content = 'transformation' in tooltip.lower() or 'update pattern' in tooltip.lower()
                        
                        if has_wildcard_content or has_update_content:
                            self.add_result("JSON_GENERATION_RULES_MODAL_INTEGRATION", True, 
                                           f"JSON Generation Rules modal badge displays correctly with standardized header format: {header}")
                        else:
                            self.add_result("JSON_GENERATION_RULES_MODAL_INTEGRATION", False, 
                                           f"JSON Generation Rules badge tooltip missing expected content: {tooltip}")
                    else:
                        self.add_result("JSON_GENERATION_RULES_MODAL_INTEGRATION", False, 
                                       f"JSON Generation Rules badge header format incorrect: {header}")
                else:
                    self.add_result("JSON_GENERATION_RULES_MODAL_INTEGRATION", False, 
                                   "JSON Generation Rules badge missing header in modal integration")
            else:
                self.add_result("JSON_GENERATION_RULES_MODAL_INTEGRATION", False, 
                               f"JSON Generation Rules badge missing modal integration: {onclick_attr}")
        else:
            self.add_result("JSON_GENERATION_RULES_MODAL_INTEGRATION", False, 
                           "JSON Generation Rules badge not found or incorrect styling")
    
    def run_all_tests(self):
        """Run all badge tests."""
        print("🧪 Running Platform Entry Notification Badge Tests...")
        print("=" * 70)
        
        # Test imports first
        self.test_badge_generation_import()
        
        # Test individual badges
        self.test_confirmed_mappings_badge()
        self.test_git_version_type_badge()
        self.test_no_versions_badge()
        self.test_cve_affected_cpes_badge()
        self.test_version_changes_badge()
        self.test_wildcard_patterns_badge()
        self.test_update_patterns_badge()
        self.test_cpe_api_errors_badge()
        self.test_cpe_base_string_searches_badge()
        self.test_transformations_applied_badge()
        self.test_vendor_na_badge()
        self.test_product_na_badge()
        self.test_versions_data_concern_badge()
        self.test_duplicate_entries_badge()
        
        # Test badge ordering
        self.test_badge_priority_order()
        
        # Test new modal system badges
        self.test_supporting_information_modal_badge()
        self.test_json_generation_rules_modal_integration()
        
        # Print results
        print(f"\n📊 Test Results Summary:")
        print(f"✅ Passed: {self.passed}")
        print(f"❌ Failed: {self.failed}")
        print(f"📈 Success Rate: {(self.passed / (self.passed + self.failed) * 100):.1f}%")
        
        if self.failed > 0:
            print(f"\n❌ Failed Tests:")
            for result in self.results:
                if not result['passed']:
                    print(f"  • {result['test']}: {result['message']}")
        
        return self.failed == 0

def main():
    """Main test execution."""
    test_suite = PlatformBadgesTestSuite()
    success = test_suite.run_all_tests()
    
    if success:
        print(f"\n🎉 All badge tests passed!")
        sys.exit(0)
    else:
        print(f"\n💥 Some badge tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
