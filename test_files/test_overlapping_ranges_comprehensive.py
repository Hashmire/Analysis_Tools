#!/usr/bin/env python3
"""
Comprehensive test suite for overlapping ranges detection functionality.
Tests the enhanced field-based grouping logic that considers all CPE Base String fields.

This test suite validates:
1. Basic vendor:product grouping
2. Platform field differentiation (x86 vs arm64)
3. PackageName field separation (Maven artifacts)
4. CollectionURL field distinction (npm vs GitHub)
5. Comprehensive field combinations
6. Semantic version overlap detection
7. Perspective-based descriptions
8. Consolidation suggestions
9. Unbounded range handling
10. Edge cases and error conditions
"""

import json
import re
import sys
import os
import pandas as pd
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

class OverlappingRangesTestSuite:
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
    
    def test_overlapping_ranges_basic_vendor_product(self):
        """Test basic overlapping ranges detection with simple vendor:product grouping."""
        try:
            from analysis_tool.generateHTML import detect_overlapping_ranges
            import pandas as pd
        except ImportError as e:
            self.add_result("OVERLAP_BASIC_IMPORT", False, f"Failed to import required modules: {e}")
            return
        
        # Create test dataframe with overlapping ranges for same vendor:product
        test_data = [
            {
                'rawPlatformData': {
                    'vendor': 'apache',
                    'product': 'tomcat',
                    'versions': [
                        {'version': '*', 'lessThan': '9.0.0', 'status': 'affected'}
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'apache', 
                    'product': 'tomcat',
                    'versions': [
                        {'version': '*', 'lessThan': '8.5.50', 'status': 'affected'}
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'different',
                    'product': 'product',
                    'versions': [
                        {'version': '*', 'lessThan': '1.0.0', 'status': 'affected'}
                    ]
                }
            }
        ]
        
        df = pd.DataFrame(test_data)
        findings = detect_overlapping_ranges(df)
        
        # Should find overlaps between entries 0 and 1 (same vendor:product)
        if len(findings) >= 2 and 0 in findings and 1 in findings:
            # Check that both entries have findings about each other
            entry_0_refs = findings[0][0]['related_table_indices'] if findings[0] else []
            entry_1_refs = findings[1][0]['related_table_indices'] if findings[1] else []
            
            if 1 in entry_0_refs and 0 in entry_1_refs:
                self.add_result("OVERLAP_BASIC_VENDOR_PRODUCT", True,
                               "Basic vendor:product overlap detection working correctly")
            else:
                self.add_result("OVERLAP_BASIC_VENDOR_PRODUCT", False,
                               f"Cross-references incorrect: {entry_0_refs}, {entry_1_refs}")
        else:
            self.add_result("OVERLAP_BASIC_VENDOR_PRODUCT", False,
                           f"Expected overlaps for entries 0,1 but got: {list(findings.keys())}")
    
    def test_overlapping_ranges_platform_field_grouping(self):
        """Test overlapping ranges detection considers platforms field for grouping."""
        try:
            from analysis_tool.generateHTML import detect_overlapping_ranges
            import pandas as pd
        except ImportError as e:
            self.add_result("OVERLAP_PLATFORM_IMPORT", False, f"Failed to import required modules: {e}")
            return
        
        # Test that different platforms create separate groups
        test_data = [
            {
                'rawPlatformData': {
                    'vendor': 'microsoft',
                    'product': 'windows',
                    'platforms': ['x86', 'x64'],
                    'versions': [
                        {'version': '*', 'lessThan': '10.0.0', 'status': 'affected'}
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'microsoft',
                    'product': 'windows', 
                    'platforms': ['arm64'],  # Different platform
                    'versions': [
                        {'version': '*', 'lessThan': '11.0.0', 'status': 'affected'}
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'microsoft',
                    'product': 'windows',
                    'platforms': ['x86', 'x64'],  # Same platforms as entry 0
                    'versions': [
                        {'version': '*', 'lessThan': '9.0.0', 'status': 'affected'}
                    ]
                }
            }
        ]
        
        df = pd.DataFrame(test_data)
        findings = detect_overlapping_ranges(df)
        
        # Should find overlaps between entries 0 and 2 (same platforms)
        # Should NOT find overlaps with entry 1 (different platform)
        if 0 in findings and 2 in findings:
            entry_0_refs = findings[0][0]['related_table_indices'] if findings[0] else []
            entry_2_refs = findings[2][0]['related_table_indices'] if findings[2] else []
            
            # Entry 1 should not have overlaps (different platform)
            entry_1_has_overlaps = 1 in findings
            
            if 2 in entry_0_refs and 0 in entry_2_refs and not entry_1_has_overlaps:
                self.add_result("OVERLAP_PLATFORM_GROUPING", True,
                               "Platform field grouping works correctly - different platforms separated")
            else:
                self.add_result("OVERLAP_PLATFORM_GROUPING", False,
                               f"Platform grouping failed: entry_1_overlaps={entry_1_has_overlaps}, refs=({entry_0_refs},{entry_2_refs})")
        else:
            self.add_result("OVERLAP_PLATFORM_GROUPING", False,
                           f"Expected overlaps for entries 0,2 but got: {list(findings.keys())}")
    
    def test_overlapping_ranges_package_name_grouping(self):
        """Test overlapping ranges detection considers packageName field for grouping."""
        try:
            from analysis_tool.generateHTML import detect_overlapping_ranges
            import pandas as pd
        except ImportError as e:
            self.add_result("OVERLAP_PACKAGE_IMPORT", False, f"Failed to import required modules: {e}")
            return
        
        # Test that different packageNames create separate groups
        test_data = [
            {
                'rawPlatformData': {
                    'vendor': 'org.springframework',
                    'product': 'spring-core',
                    'packageName': 'org.springframework:spring-core',
                    'versions': [
                        {'version': '*', 'lessThan': '5.3.0', 'status': 'affected'}
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'org.springframework',
                    'product': 'spring-core',
                    'packageName': 'org.springframework:spring-boot-starter',  # Different package
                    'versions': [
                        {'version': '*', 'lessThan': '2.5.0', 'status': 'affected'}
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'org.springframework',
                    'product': 'spring-core',
                    'packageName': 'org.springframework:spring-core',  # Same package as entry 0
                    'versions': [
                        {'version': '*', 'lessThan': '5.2.0', 'status': 'affected'}
                    ]
                }
            }
        ]
        
        df = pd.DataFrame(test_data)
        findings = detect_overlapping_ranges(df)
        
        # Should find overlaps between entries 0 and 2 (same packageName)
        # Should NOT find overlaps with entry 1 (different packageName)
        if 0 in findings and 2 in findings:
            entry_0_refs = findings[0][0]['related_table_indices'] if findings[0] else []
            entry_2_refs = findings[2][0]['related_table_indices'] if findings[2] else []
            entry_1_has_overlaps = 1 in findings
            
            if 2 in entry_0_refs and 0 in entry_2_refs and not entry_1_has_overlaps:
                self.add_result("OVERLAP_PACKAGE_GROUPING", True,
                               "PackageName field grouping works correctly")
            else:
                self.add_result("OVERLAP_PACKAGE_GROUPING", False,
                               f"Package grouping failed: entry_1_overlaps={entry_1_has_overlaps}")
        else:
            self.add_result("OVERLAP_PACKAGE_GROUPING", False,
                           f"Expected overlaps for entries 0,2 but got: {list(findings.keys())}")
    
    def test_overlapping_ranges_collection_url_grouping(self):
        """Test overlapping ranges detection considers collectionURL field for grouping."""
        try:
            from analysis_tool.generateHTML import detect_overlapping_ranges
            import pandas as pd
        except ImportError as e:
            self.add_result("OVERLAP_COLLECTION_IMPORT", False, f"Failed to import required modules: {e}")
            return
        
        # Test that different collectionURLs create separate groups
        test_data = [
            {
                'rawPlatformData': {
                    'vendor': 'nodejs',
                    'product': 'lodash',
                    'collectionURL': 'https://registry.npmjs.org/',
                    'versions': [
                        {'version': '*', 'lessThan': '4.17.21', 'status': 'affected'}
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'nodejs',
                    'product': 'lodash',
                    'collectionURL': 'https://github.com/lodash/lodash',  # Different collection
                    'versions': [
                        {'version': '*', 'lessThan': '4.17.20', 'status': 'affected'}
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'nodejs',
                    'product': 'lodash',
                    'collectionURL': 'https://registry.npmjs.org/',  # Same collection as entry 0
                    'versions': [
                        {'version': '*', 'lessThan': '4.17.19', 'status': 'affected'}
                    ]
                }
            }
        ]
        
        df = pd.DataFrame(test_data)
        findings = detect_overlapping_ranges(df)
        
        # Should find overlaps between entries 0 and 2 (same collectionURL)
        if 0 in findings and 2 in findings:
            entry_0_refs = findings[0][0]['related_table_indices'] if findings[0] else []
            entry_2_refs = findings[2][0]['related_table_indices'] if findings[2] else []
            entry_1_has_overlaps = 1 in findings
            
            if 2 in entry_0_refs and 0 in entry_2_refs and not entry_1_has_overlaps:
                self.add_result("OVERLAP_COLLECTION_GROUPING", True,
                               "CollectionURL field grouping works correctly")
            else:
                self.add_result("OVERLAP_COLLECTION_GROUPING", False,
                               f"Collection URL grouping failed: entry_1_overlaps={entry_1_has_overlaps}")
        else:
            self.add_result("OVERLAP_COLLECTION_GROUPING", False,
                           f"Expected overlaps for entries 0,2 but got: {list(findings.keys())}")
    
    def test_overlapping_ranges_comprehensive_field_combinations(self):
        """Test overlapping ranges detection with complex field combinations."""
        try:
            from analysis_tool.generateHTML import detect_overlapping_ranges
            import pandas as pd
        except ImportError as e:
            self.add_result("OVERLAP_COMPREHENSIVE_IMPORT", False, f"Failed to import required modules: {e}")
            return
        
        # Test comprehensive field combinations that should create unique groups
        test_data = [
            {
                'rawPlatformData': {
                    'vendor': 'apache',
                    'product': 'httpd',
                    'platforms': ['linux'],
                    'packageName': 'apache2',
                    'collectionURL': 'https://packages.debian.org/',
                    'versions': [
                        {'version': '*', 'lessThan': '2.4.50', 'status': 'affected'}
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'apache',
                    'product': 'httpd',
                    'platforms': ['linux'],  # Same platform
                    'packageName': 'httpd',   # Different package name
                    'collectionURL': 'https://packages.debian.org/',  # Same collection
                    'versions': [
                        {'version': '*', 'lessThan': '2.4.49', 'status': 'affected'}
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'apache',
                    'product': 'httpd',
                    'platforms': ['linux'],
                    'packageName': 'apache2',  # Same package as entry 0
                    'collectionURL': 'https://packages.debian.org/',
                    'versions': [
                        {'version': '*', 'lessThan': '2.4.48', 'status': 'affected'}
                    ]
                }
            }
        ]
        
        df = pd.DataFrame(test_data)
        findings = detect_overlapping_ranges(df)
        
        # Only entries 0 and 2 should overlap (identical field combinations)
        # Entry 1 should be separate due to different packageName
        if 0 in findings and 2 in findings:
            entry_0_refs = findings[0][0]['related_table_indices'] if findings[0] else []
            entry_2_refs = findings[2][0]['related_table_indices'] if findings[2] else []
            entry_1_has_overlaps = 1 in findings
            
            if 2 in entry_0_refs and 0 in entry_2_refs and not entry_1_has_overlaps:
                self.add_result("OVERLAP_COMPREHENSIVE_FIELDS", True,
                               "Comprehensive field combination grouping works correctly")
            else:
                self.add_result("OVERLAP_COMPREHENSIVE_FIELDS", False,
                               f"Comprehensive field grouping failed: entry_1_overlaps={entry_1_has_overlaps}")
        else:
            self.add_result("OVERLAP_COMPREHENSIVE_FIELDS", False,
                           f"Expected overlaps for entries 0,2 only but got: {list(findings.keys())}")
    
    def test_overlapping_ranges_semantic_version_detection(self):
        """Test semantic version comparison in overlap detection."""
        try:
            from analysis_tool.generateHTML import detect_overlapping_ranges
            import pandas as pd
        except ImportError as e:
            self.add_result("OVERLAP_SEMANTIC_IMPORT", False, f"Failed to import required modules: {e}")
            return
        
        # Test semantic version overlap detection
        test_data = [
            {
                'rawPlatformData': {
                    'vendor': 'test',
                    'product': 'software',
                    'versions': [
                        {'version': '*', 'lessThan': '2.0.0', 'status': 'affected'}  # Covers 1.x.x
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'test',
                    'product': 'software',
                    'versions': [
                        {'version': '1.5.0', 'lessThan': '1.9.0', 'status': 'affected', 'versionType': 'semver'}  # Overlaps with entry 0
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'test',
                    'product': 'software',
                    'versions': [
                        {'version': '3.0.0', 'lessThan': '4.0.0', 'status': 'affected', 'versionType': 'semver'}  # No overlap
                    ]
                }
            }
        ]
        
        df = pd.DataFrame(test_data)
        findings = detect_overlapping_ranges(df)
        
        # Entries 0 and 1 should overlap, entry 2 should not
        if 0 in findings and 1 in findings:
            entry_0_refs = findings[0][0]['related_table_indices'] if findings[0] else []
            entry_1_refs = findings[1][0]['related_table_indices'] if findings[1] else []
            entry_2_has_overlaps = 2 in findings
            
            if 1 in entry_0_refs and 0 in entry_1_refs and not entry_2_has_overlaps:
                self.add_result("OVERLAP_SEMANTIC_VERSION", True,
                               "Semantic version overlap detection works correctly")
            else:
                self.add_result("OVERLAP_SEMANTIC_VERSION", False,
                               f"Semantic version detection failed: entry_2_overlaps={entry_2_has_overlaps}")
        else:
            self.add_result("OVERLAP_SEMANTIC_VERSION", False,
                           f"Expected overlaps for entries 0,1 but got: {list(findings.keys())}")
    
    def test_overlapping_ranges_perspective_descriptions(self):
        """Test perspective-based overlap descriptions."""
        try:
            from analysis_tool.generateHTML import detect_overlapping_ranges
            import pandas as pd
        except ImportError as e:
            self.add_result("OVERLAP_PERSPECTIVE_IMPORT", False, f"Failed to import required modules: {e}")
            return
        
        # Test that descriptions are perspective-based
        test_data = [
            {
                'rawPlatformData': {
                    'vendor': 'test',
                    'product': 'app',
                    'versions': [
                        {'version': '*', 'lessThan': '3.0.0', 'status': 'affected', 'versionType': 'semver'}  # Broader range
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'test',
                    'product': 'app',
                    'versions': [
                        {'version': '1.0.0', 'lessThan': '2.0.0', 'status': 'affected', 'versionType': 'semver'}  # Narrower range
                    ]
                }
            }
        ]
        
        df = pd.DataFrame(test_data)
        findings = detect_overlapping_ranges(df)
        
        if 0 in findings and 1 in findings:
            # Entry 0 should describe containing the narrower range
            entry_0_description = findings[0][0]['range_description']
            # Entry 1 should describe being contained within the broader range
            entry_1_description = findings[1][0]['range_description']
            
            if ('encompasses' in entry_0_description or 'broader' in entry_0_description) and \
               ('within' in entry_1_description or 'contained' in entry_1_description):
                self.add_result("OVERLAP_PERSPECTIVE_DESCRIPTIONS", True,
                               "Perspective-based descriptions work correctly")
            else:
                self.add_result("OVERLAP_PERSPECTIVE_DESCRIPTIONS", False,
                               f"Perspective descriptions incorrect: '{entry_0_description}' vs '{entry_1_description}'")
        else:
            self.add_result("OVERLAP_PERSPECTIVE_DESCRIPTIONS", False,
                           f"Expected findings for both entries but got: {list(findings.keys())}")
    
    def test_overlapping_ranges_consolidation_suggestions(self):
        """Test consolidation suggestions in overlap findings."""
        try:
            from analysis_tool.generateHTML import detect_overlapping_ranges
            import pandas as pd
        except ImportError as e:
            self.add_result("OVERLAP_CONSOLIDATION_IMPORT", False, f"Failed to import required modules: {e}")
            return
        
        # Test consolidation suggestions
        test_data = [
            {
                'rawPlatformData': {
                    'vendor': 'test',
                    'product': 'tool',
                    'versions': [
                        {'version': '1.0.0', 'status': 'affected'}  # Identical version
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'test',
                    'product': 'tool',
                    'versions': [
                        {'version': '1.0.0', 'status': 'affected'}  # Identical version
                    ]
                }
            }
        ]
        
        df = pd.DataFrame(test_data)
        findings = detect_overlapping_ranges(df)
        
        if 0 in findings and 1 in findings:
            suggestion_0 = findings[0][0]['suggestion']
            suggestion_1 = findings[1][0]['suggestion']
            
            # Should have consolidation suggestions
            if 'CONSOLIDATION' in suggestion_0 and 'CONSOLIDATION' in suggestion_1:
                self.add_result("OVERLAP_CONSOLIDATION_SUGGESTIONS", True,
                               "Consolidation suggestions generated correctly")
            else:
                self.add_result("OVERLAP_CONSOLIDATION_SUGGESTIONS", False,
                               f"Missing consolidation suggestions: '{suggestion_0}' / '{suggestion_1}'")
        else:
            self.add_result("OVERLAP_CONSOLIDATION_SUGGESTIONS", False,
                           f"Expected findings for both entries but got: {list(findings.keys())}")
    
    def test_overlapping_ranges_unbounded_range_handling(self):
        """Test handling of unbounded ranges in overlap detection."""
        try:
            from analysis_tool.generateHTML import detect_overlapping_ranges
            import pandas as pd
        except ImportError as e:
            self.add_result("OVERLAP_UNBOUNDED_IMPORT", False, f"Failed to import required modules: {e}")
            return
        
        # Test unbounded range handling
        test_data = [
            {
                'rawPlatformData': {
                    'vendor': 'test',
                    'product': 'service',
                    'versions': [
                        {'version': '*', 'status': 'affected'}  # Completely unbounded
                    ]
                }
            },
            {
                'rawPlatformData': {
                    'vendor': 'test',
                    'product': 'service',
                    'versions': [
                        {'version': '*', 'lessThan': '2.0.0', 'status': 'affected'}  # Upper bounded
                    ]
                }
            }
        ]
        
        df = pd.DataFrame(test_data)
        findings = detect_overlapping_ranges(df)
        
        if 0 in findings and 1 in findings:
            # Entry 0 (unbounded) should describe containing entry 1
            entry_0_description = findings[0][0]['range_description']
            # Entry 1 should describe being contained within entry 0
            entry_1_description = findings[1][0]['range_description']
            
            # Check for proper bounds advisements
            suggestion_0 = findings[0][0]['suggestion']
            suggestion_1 = findings[1][0]['suggestion']
            
            if ('PROPER BOUNDS' in suggestion_0 or 'PROPER BOUNDS' in suggestion_1):
                self.add_result("OVERLAP_UNBOUNDED_HANDLING", True,
                               "Unbounded range handling works correctly")
            else:
                self.add_result("OVERLAP_UNBOUNDED_HANDLING", False,
                               f"Missing proper bounds advisements: '{suggestion_0}' / '{suggestion_1}'")
        else:
            self.add_result("OVERLAP_UNBOUNDED_HANDLING", False,
                           f"Expected findings for both entries but got: {list(findings.keys())}")
    
    def test_overlapping_ranges_edge_cases(self):
        """Test edge cases in overlap detection."""
        try:
            from analysis_tool.generateHTML import detect_overlapping_ranges
            import pandas as pd
        except ImportError as e:
            self.add_result("OVERLAP_EDGE_IMPORT", False, f"Failed to import required modules: {e}")
            return
        
        # Test edge cases
        test_cases = [
            # Case 1: Missing vendor/product (should be skipped)
            {
                'rawPlatformData': {
                    'vendor': '',  # Empty vendor
                    'product': 'test',
                    'versions': [{'version': '1.0.0', 'status': 'affected'}]
                }
            },
            # Case 2: Valid entry that should not find overlaps with invalid entries
            {
                'rawPlatformData': {
                    'vendor': 'valid',
                    'product': 'product',
                    'versions': [{'version': '1.0.0', 'status': 'affected'}]
                }
            },
            # Case 3: Non-specific version values
            {
                'rawPlatformData': {
                    'vendor': 'test',
                    'product': 'app',
                    'versions': [{'version': 'unspecified', 'status': 'affected'}]
                }
            },
            # Case 4: Same vendor/product as case 3 but with real version
            {
                'rawPlatformData': {
                    'vendor': 'test',
                    'product': 'app',
                    'versions': [{'version': '2.0.0', 'status': 'affected'}]
                }
            }
        ]
        
        df = pd.DataFrame(test_cases)
        findings = detect_overlapping_ranges(df)
        
        # Entry 0 should be skipped (empty vendor)
        # Entry 1 should have no overlaps (unique vendor/product)
        # Entries 2 and 3 might overlap depending on handling of non-specific values
        
        entry_0_skipped = 0 not in findings
        entry_1_isolated = 1 not in findings
        
        if entry_0_skipped and entry_1_isolated:
            self.add_result("OVERLAP_EDGE_CASES", True,
                           "Edge cases handled correctly - invalid entries skipped")
        else:
            self.add_result("OVERLAP_EDGE_CASES", False,
                           f"Edge case handling failed: entry_0_skipped={entry_0_skipped}, entry_1_isolated={entry_1_isolated}, findings={list(findings.keys())}")

    def run_all_tests(self) -> bool:
        """Run all overlapping ranges tests."""
        print("🧪 Running Comprehensive Overlapping Ranges Detection Tests...")
        print("=" * 80)
        
        # Test comprehensive field-based grouping
        self.test_overlapping_ranges_basic_vendor_product()
        self.test_overlapping_ranges_platform_field_grouping()
        self.test_overlapping_ranges_package_name_grouping()
        self.test_overlapping_ranges_collection_url_grouping()
        self.test_overlapping_ranges_comprehensive_field_combinations()
        
        # Test semantic version analysis
        self.test_overlapping_ranges_semantic_version_detection()
        
        # Test output quality
        self.test_overlapping_ranges_perspective_descriptions()
        self.test_overlapping_ranges_consolidation_suggestions()
        self.test_overlapping_ranges_unbounded_range_handling()
        
        # Test edge cases
        self.test_overlapping_ranges_edge_cases()
        
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
    test_suite = OverlappingRangesTestSuite()
    success = test_suite.run_all_tests()
    
    if success:
        print(f"\n🎉 All overlapping ranges tests passed!")
        sys.exit(0)
    else:
        print(f"\n💥 Some overlapping ranges tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
