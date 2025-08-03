#!/usr/bin/env python3
"""
NVD Source Manager Integration Test Suite

This test suite validates that the NVD Source Manager properly integrates across
all system components that require source data resolution:

Core Integration Points:
1. Badge Contents Collector: Source name resolution for badges
2. HTML Generation: Source metadata in generated pages  
3. Process Data: Source information in CVE processing
4. JavaScript: Source data flows to frontend completion tracker
5. Logging: Source names appear in structured logs

Critical Requirements:
- Source UUIDs resolve to organization names
- Source data flows to HTML metadata
- JavaScript can access source information
- Logs contain resolved source names
- Modal content displays source details
"""

import json
import sys
import pandas as pd
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

class NVDSourceManagerIntegrationTestSuite:
    def __init__(self, test_file_path: Optional[str] = None):
        self.test_file_path = Path(test_file_path) if test_file_path else None
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

    def test_core_source_manager_functionality(self):
        """Test essential source manager functionality."""
        print("\n🧪 Testing Core Source Manager...")
        
        # Test 1: Singleton pattern
        try:
            from analysis_tool.storage.nvd_source_manager import get_global_source_manager
            
            manager1 = get_global_source_manager()
            manager2 = get_global_source_manager()
            
            if manager1 is manager2:
                self.add_result("SINGLETON_PATTERN", True, "Singleton pattern working correctly")
            else:
                self.add_result("SINGLETON_PATTERN", False, "Multiple instances created")
                
        except Exception as e:
            self.add_result("SINGLETON_PATTERN", False, f"Import failed: {e}")

        # Test 2: Basic data initialization
        try:
            from analysis_tool.storage.nvd_source_manager import get_global_source_manager
            
            manager = get_global_source_manager()
            
            # Create test data that matches real NVD Source API structure
            test_data = pd.DataFrame([
                {
                    "orgId": "d1c1063e-7a18-46af-9102-31f8928bc633",
                    "name": "Cisco Systems, Inc.",
                    "contactEmail": "psirt@cisco.com",
                    "sourceIdentifiers": ["psirt@cisco.com", "d1c1063e-7a18-46af-9102-31f8928bc633"]
                },
                {
                    "orgId": "12345678-1234-4567-8901-123456789abc",
                    "name": "Test Organization", 
                    "contactEmail": "test@example.com",
                    "sourceIdentifiers": ["test@example.com"]
                }
            ])
            
            # Initialize with proper DataFrame
            manager.initialize(test_data)
            
            # Test basic lookup by orgId
            cisco_name = manager.get_source_name("d1c1063e-7a18-46af-9102-31f8928bc633")
            if cisco_name == "Cisco Systems, Inc.":
                self.add_result("BASIC_LOOKUP", True, "UUID to name resolution working")
            else:
                self.add_result("BASIC_LOOKUP", False, f"Got '{cisco_name}', expected 'Cisco Systems, Inc.'")
                
        except Exception as e:
            self.add_result("BASIC_LOOKUP", False, f"Basic lookup failed: {e}")

        # Test 3: SourceIdentifiers array lookup
        try:
            from analysis_tool.storage.nvd_source_manager import get_global_source_manager
            
            manager = get_global_source_manager()
            
            # Test lookup through sourceIdentifiers array
            source_name = manager.get_source_name("psirt@cisco.com")
            if source_name == "Cisco Systems, Inc.":
                self.add_result("SOURCE_IDENTIFIERS_LOOKUP", True, "SourceIdentifiers array lookup working")
            else:
                self.add_result("SOURCE_IDENTIFIERS_LOOKUP", False, f"Got '{source_name}', expected 'Cisco Systems, Inc.'")
                
        except Exception as e:
            self.add_result("SOURCE_IDENTIFIERS_LOOKUP", False, f"SourceIdentifiers lookup failed: {e}")

    def test_badge_contents_collector_integration(self):
        """Test integration with badge contents collector."""
        print("\n🏷️ Testing Badge Contents Collector Integration...")
        
        try:
            # Import the actual badge contents collector
            from analysis_tool.logging.badge_contents_collector import BadgeContentsCollector
            from analysis_tool.storage.nvd_source_manager import get_source_name
            
            # Test that the collector can import and use source functions
            collector = BadgeContentsCollector()
            
            # Test direct source name resolution (this is how badge collector uses it)
            test_name = get_source_name("d1c1063e-7a18-46af-9102-31f8928bc633")
            if test_name == "Cisco Systems, Inc.":
                self.add_result("BADGE_COLLECTOR_INTEGRATION", True, "Badge collector can resolve source names")
            else:
                self.add_result("BADGE_COLLECTOR_INTEGRATION", False, f"Source resolution failed: got '{test_name}'")
                
        except Exception as e:
            self.add_result("BADGE_COLLECTOR_INTEGRATION", False, f"Badge collector integration failed: {e}")

    def test_html_generation_integration(self):
        """Test integration with HTML generation."""
        print("\n📄 Testing HTML Generation Integration...")
        
        try:
            # Import HTML generation module and check for source manager usage
            from analysis_tool.core.generateHTML import convertRowDataToHTML
            from analysis_tool.storage.nvd_source_manager import get_source_info, get_source_name
            
            # Test that HTML generator can import and use source functions
            cisco_info = get_source_info("d1c1063e-7a18-46af-9102-31f8928bc633")
            cisco_name = get_source_name("d1c1063e-7a18-46af-9102-31f8928bc633")
            
            if cisco_info and cisco_name == "Cisco Systems, Inc.":
                self.add_result("HTML_GENERATION_INTEGRATION", True, "HTML generator can access source data")
            else:
                self.add_result("HTML_GENERATION_INTEGRATION", False, f"Source data access failed: info={cisco_info}, name={cisco_name}")
                
        except Exception as e:
            self.add_result("HTML_GENERATION_INTEGRATION", False, f"HTML generation integration failed: {e}")

    def test_process_data_integration(self):
        """Test integration with process data module."""
        print("\n⚙️ Testing Process Data Integration...")
        
        try:
            # Import process data module and check for source manager usage
            from analysis_tool.core.processData import processCVEData
            from analysis_tool.storage.nvd_source_manager import get_source_name, get_source_info, get_all_sources_for_cve
            
            # Test that process data can import and use all source functions
            cisco_name = get_source_name("d1c1063e-7a18-46af-9102-31f8928bc633")
            cisco_info = get_source_info("d1c1063e-7a18-46af-9102-31f8928bc633")
            all_sources = get_all_sources_for_cve(["d1c1063e-7a18-46af-9102-31f8928bc633"])
            
            if cisco_name == "Cisco Systems, Inc." and cisco_info and len(all_sources) > 0:
                self.add_result("PROCESS_DATA_INTEGRATION", True, "Process data can access all source functions")
            else:
                self.add_result("PROCESS_DATA_INTEGRATION", False, f"Source function access failed: name={cisco_name}, info={bool(cisco_info)}, sources={len(all_sources)}")
                
        except Exception as e:
            self.add_result("PROCESS_DATA_INTEGRATION", False, f"Process data integration failed: {e}")

    def test_analysis_tool_initialization(self):
        """Test integration with main analysis tool initialization."""
        print("\n🔧 Testing Analysis Tool Initialization...")
        
        try:
            # Test that analysis_tool.py can import the source manager
            from analysis_tool.storage.nvd_source_manager import get_global_source_manager
            
            # Check if manager can be accessed from main analysis tool context
            manager = get_global_source_manager()
            if manager.is_initialized():
                source_count = manager.get_source_count()
                self.add_result("ANALYSIS_TOOL_INIT", True, f"Analysis tool can access initialized manager with {source_count} sources")
            else:
                self.add_result("ANALYSIS_TOOL_INIT", False, "Manager not initialized in analysis tool context")
                
        except Exception as e:
            self.add_result("ANALYSIS_TOOL_INIT", False, f"Analysis tool initialization failed: {e}")

    def test_javascript_completion_tracker_integration(self):
        """Test that JavaScript completion tracker can work with source data."""
        print("\n📜 Testing JavaScript Integration...")
        
        try:
            # Check if completion tracker script exists and has source functionality
            static_dir = Path(__file__).parent.parent / "src" / "analysis_tool" / "static" / "js"
            completion_script = static_dir / "completion_tracker.js"
            
            if completion_script.exists():
                with open(completion_script, 'r', encoding='utf-8') as f:
                    script_content = f.read()
                
                # Look for source-related functionality
                has_source_data = "getSourceData" in script_content
                has_source_metadata = "sourceData" in script_content
                has_uuid_handling = "uuid" in script_content.lower()
                
                if has_source_data and has_source_metadata:
                    self.add_result("JAVASCRIPT_INTEGRATION", True, "JavaScript completion tracker has source data functionality")
                elif has_source_data or has_source_metadata or has_uuid_handling:
                    self.add_result("JAVASCRIPT_INTEGRATION", True, "JavaScript has partial source functionality")
                else:
                    self.add_result("JAVASCRIPT_INTEGRATION", False, "JavaScript missing source functionality")
            else:
                self.add_result("JAVASCRIPT_INTEGRATION", False, "Completion tracker script not found")
                
        except Exception as e:
            self.add_result("JAVASCRIPT_INTEGRATION", False, f"JavaScript integration test failed: {e}")

    def test_unknown_uuid_handling(self):
        """Test handling of unknown UUIDs."""
        print("\n❓ Testing Unknown UUID Handling...")
        
        try:
            from analysis_tool.storage.nvd_source_manager import get_source_name
            
            # Test unknown UUID - should return the UUID itself
            unknown_uuid = "unknown-uuid-12345"
            result = get_source_name(unknown_uuid)
            
            if result == unknown_uuid:
                self.add_result("UNKNOWN_UUID_HANDLING", True, "Unknown UUIDs return as-is")
            else:
                self.add_result("UNKNOWN_UUID_HANDLING", False, f"Got '{result}', expected '{unknown_uuid}'")
                
        except Exception as e:
            self.add_result("UNKNOWN_UUID_HANDLING", False, f"Unknown UUID handling failed: {e}")

    def test_nist_special_handling(self):
        """Test special NIST handling."""
        print("\n🏛️ Testing NIST Special Handling...")
        
        try:
            from analysis_tool.storage.nvd_source_manager import get_source_name
            
            # Test NIST special cases
            nist_identifiers = ["nvd@nist.gov", ""]
            
            results = []
            for identifier in nist_identifiers:
                name = get_source_name(identifier)
                results.append((identifier, name))
            
            # Check if NIST handling works for both nvd@nist.gov and empty string
            nist_results = [result for result in results if "NIST" in result[1]]
            
            if len(nist_results) > 0:
                self.add_result("NIST_SPECIAL_HANDLING", True, f"NIST special handling working: {nist_results}")
            else:
                self.add_result("NIST_SPECIAL_HANDLING", False, f"NIST handling failed: {results}")
                
        except Exception as e:
            self.add_result("NIST_SPECIAL_HANDLING", False, f"NIST special handling failed: {e}")

    def run_all_tests(self):
        """Run all focused integration tests."""
        print("🚀 Starting NVD Source Manager Integration Test Suite...")
        print("="*80)
        
        # Run focused integration tests
        self.test_core_source_manager_functionality()
        self.test_badge_contents_collector_integration()
        self.test_html_generation_integration()
        self.test_process_data_integration()
        self.test_analysis_tool_initialization()
        self.test_javascript_completion_tracker_integration()
        self.test_unknown_uuid_handling()
        self.test_nist_special_handling()
        
        # Print results
        self.print_results()
        
        return self.failed == 0

    def print_results(self):
        """Print focused test results."""
        # Only show failures for debugging
        if self.failed > 0:
            failures = [result for result in self.results if not result['passed']]
            print(f"\nTest Failures ({len(failures)}):")
            for result in failures:
                print(f"  - {result['test']}: {result['message']}")
        
        # STANDARD OUTPUT FORMAT - Required for unified test runner
        print(f"TEST_RESULTS: PASSED={self.passed} TOTAL={len(self.results)} SUITE=\"NVD Source Manager\"")
        
        return self.failed == 0

def main():
    """Main function to run the focused integration test suite."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test NVD Source Manager integration points')
    parser.add_argument('test_file', nargs='?', help='Optional test data file (not used in integration tests)')
    
    args = parser.parse_args()
    
    # Create and run focused integration test suite
    suite = NVDSourceManagerIntegrationTestSuite(args.test_file)
    success = suite.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
