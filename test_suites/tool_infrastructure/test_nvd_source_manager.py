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
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

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

        # Test 2: Basic data initialization with real-world data structure
        try:
            from analysis_tool.storage.nvd_source_manager import get_global_source_manager
            
            manager = get_global_source_manager()
            
            # Create test data that matches ACTUAL real NVD Source API structure
            # CRITICAL: This reflects the real-world case where orgId can be empty
            # and UUID is only found in sourceIdentifiers array
            test_data = pd.DataFrame([
                {
                    # Real-world Cisco entry structure (orgId empty, UUID in sourceIdentifiers)
                    "orgId": "",  # THIS IS THE KEY ISSUE - real data has empty orgId
                    "name": "Cisco Systems, Inc.",
                    "contactEmail": "psirt@cisco.com",
                    "sourceIdentifiers": ["psirt@cisco.com", "d1c1063e-7a18-46af-9102-31f8928bc633"]
                },
                {
                    # Standard entry - UUID in sourceIdentifiers for proper lookup
                    "orgId": "12345678-1234-4567-8901-123456789abc",
                    "name": "Test Organization", 
                    "contactEmail": "test@example.com",
                    "sourceIdentifiers": ["test@example.com", "12345678-1234-4567-8901-123456789abc"]
                },
                {
                    # Another real-world case - UUID as orgId
                    "orgId": "a1b2c3d4-5678-90ab-cdef-123456789abc",
                    "name": "Test UUID Org",
                    "contactEmail": "uuid@example.com", 
                    "sourceIdentifiers": ["uuid@example.com", "a1b2c3d4-5678-90ab-cdef-123456789abc"]
                }
            ])
            
            # Initialize with proper DataFrame
            manager.initialize(test_data)
            
            # Test lookup by UUID when orgId is EMPTY (real-world Cisco case)
            cisco_name = manager.get_source_name("d1c1063e-7a18-46af-9102-31f8928bc633")
            if cisco_name == "Cisco Systems, Inc.":
                self.add_result("EMPTY_ORGID_LOOKUP", True, "UUID lookup works when orgId is empty")
            else:
                self.add_result("EMPTY_ORGID_LOOKUP", False, f"Got '{cisco_name}', expected 'Cisco Systems, Inc.'")
            
            # Test standard UUID lookup via sourceIdentifiers
            test_name = manager.get_source_name("12345678-1234-4567-8901-123456789abc")
            if test_name == "Test Organization":
                self.add_result("STANDARD_ORGID_LOOKUP", True, "Standard UUID lookup working")
            else:
                self.add_result("STANDARD_ORGID_LOOKUP", False, f"Got '{test_name}', expected 'Test Organization'")
                
        except Exception as e:
            self.add_result("EMPTY_ORGID_LOOKUP", False, f"Empty orgId lookup failed: {e}")
            self.add_result("STANDARD_ORGID_LOOKUP", False, f"Standard lookup failed: {e}")

        # Test 4: get_all_sources_for_cve output structure (CRITICAL for completion tracker)
        try:
            from analysis_tool.storage.nvd_source_manager import get_all_sources_for_cve
            
            # Test the actual function used by processData.py for global CVE metadata
            sources = get_all_sources_for_cve(["d1c1063e-7a18-46af-9102-31f8928bc633", "psirt@cisco.com"])
            
            if len(sources) > 0:
                source = sources[0]
                # Verify the structure matches what completion tracker expects
                # Updated for sourceIdentifiers-based approach (no artificial orgId)
                required_fields = ['name', 'contactEmail', 'sourceIdentifiers']
                has_all_fields = all(field in source for field in required_fields)
                
                if has_all_fields and source['name'] == "Cisco Systems, Inc.":
                    self.add_result("CVE_SOURCES_STRUCTURE", True, f"get_all_sources_for_cve returns proper structure: {list(source.keys())}")
                else:
                    self.add_result("CVE_SOURCES_STRUCTURE", False, f"Structure missing fields or wrong name: {source}")
            else:
                self.add_result("CVE_SOURCES_STRUCTURE", False, "get_all_sources_for_cve returned empty list")
                
        except Exception as e:
            self.add_result("CVE_SOURCES_STRUCTURE", False, f"CVE sources structure test failed: {e}")

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
        print("\n[Badge Contents Collector Integration Test]...")
        
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
        print("\n[Process Data Integration Test]...")
        
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
        """Test JavaScript completion tracker integration with real-world data structures."""
        print("\n📜 Testing JavaScript Completion Tracker Integration...")
        
        try:
            from analysis_tool.storage.nvd_source_manager import get_global_source_manager
            
            manager = get_global_source_manager()
            
            # NOTE: Use the existing test data that was already initialized by test_core_functionality
            # This ensures consistency across all tests and uses the real-world data structure
            # that includes the critical empty orgId case for Cisco
            
            # Test 1: Verify getSourceData() returns proper structure for JavaScript
            try:
                from analysis_tool.storage.nvd_source_manager import get_all_sources_for_cve
                
                # Get sources exactly as processData.py would
                sources = get_all_sources_for_cve(["d1c1063e-7a18-46af-9102-31f8928bc633", "psirt@cisco.com"])
                
                if len(sources) == 0:
                    self.add_result("JS_SOURCE_DATA_AVAILABILITY", False, "No sources returned by get_all_sources_for_cve")
                else:
                    source = sources[0]
                    
                    # Verify structure matches what JavaScript completion tracker expects
                    # Updated for sourceIdentifiers-based approach (no artificial orgId)
                    required_fields = ['name', 'contactEmail', 'sourceIdentifiers']
                    has_all_fields = all(field in source for field in required_fields)
                    
                    if has_all_fields:
                        self.add_result("JS_SOURCE_DATA_STRUCTURE", True, f"Source data has all required fields: {list(source.keys())}")
                        
                        # Test critical case: Cisco Systems structure (no orgId needed)
                        if source['name'] == "Cisco Systems, Inc.":
                            self.add_result("JS_EMPTY_ORGID_CASE", True, "Cisco case properly structured for JavaScript (sourceIdentifiers-based)")
                        else:
                            self.add_result("JS_EMPTY_ORGID_CASE", False, f"Cisco case failed: name='{source['name']}'")
                            
                        # Test sourceIdentifiers array structure
                        if isinstance(source['sourceIdentifiers'], list) and "d1c1063e-7a18-46af-9102-31f8928bc633" in source['sourceIdentifiers']:
                            self.add_result("JS_SOURCE_IDENTIFIERS_ARRAY", True, "SourceIdentifiers array properly formatted")
                        else:
                            self.add_result("JS_SOURCE_IDENTIFIERS_ARRAY", False, f"SourceIdentifiers malformed: {source['sourceIdentifiers']}")
                            
                    else:
                        missing_fields = [field for field in required_fields if field not in source]
                        self.add_result("JS_SOURCE_DATA_STRUCTURE", False, f"Missing required fields: {missing_fields}")
                        
            except Exception as e:
                self.add_result("JS_SOURCE_DATA_AVAILABILITY", False, f"get_all_sources_for_cve failed: {e}")
            
            # Test 2: Simulate JavaScript completion tracker logic
            try:
                # Simulate what completion_tracker.js getSourceById() does
                def simulate_js_getSourceById(source_id, sources_data):
                    """Simulate the JavaScript getSourceById function logic."""
                    for source in sources_data:
                        # Primary lookup by orgId (this was the bug - JavaScript expected sourceId)
                        if source.get('orgId') == source_id:
                            return source['name']
                        
                        # Fallback to sourceIdentifiers array
                        if source_id in source.get('sourceIdentifiers', []):
                            return source['name']
                    
                    return source_id  # Return original if not found
                
                # Get sources for both test cases using existing data
                cisco_sources = get_all_sources_for_cve(["d1c1063e-7a18-46af-9102-31f8928bc633", "psirt@cisco.com"])
                uuid_org_sources = get_all_sources_for_cve(["a1b2c3d4-5678-90ab-cdef-123456789abc"])
                
                # Test the critical case that was failing
                result = simulate_js_getSourceById("d1c1063e-7a18-46af-9102-31f8928bc633", cisco_sources)
                
                if result == "Cisco Systems, Inc.":
                    self.add_result("JS_COMPLETION_TRACKER_LOGIC", True, "JavaScript completion tracker logic resolves UUID to name correctly")
                else:
                    self.add_result("JS_COMPLETION_TRACKER_LOGIC", False, f"JavaScript logic failed: got '{result}', expected 'Cisco Systems, Inc.'")
                    
                # Test standard orgId case with existing test data
                uuid_result = simulate_js_getSourceById("a1b2c3d4-5678-90ab-cdef-123456789abc", uuid_org_sources)
                if uuid_result == "Test UUID Org":
                    self.add_result("JS_STANDARD_CASE_LOGIC", True, "JavaScript logic works for standard orgId cases")
                else:
                    self.add_result("JS_STANDARD_CASE_LOGIC", False, f"Standard case failed: got '{uuid_result}', expected 'Test UUID Org'. Available sources: {uuid_org_sources}")
                    
            except Exception as e:
                self.add_result("JS_COMPLETION_TRACKER_LOGIC", False, f"JavaScript simulation failed: {e}")
                self.add_result("JS_STANDARD_CASE_LOGIC", False, f"JavaScript simulation failed: {e}")
            
            # Test 3: Check JavaScript file exists and has proper functions
            try:
                static_dir = Path(__file__).parent.parent.parent / "src" / "analysis_tool" / "static" / "js"
                completion_script = static_dir / "completion_tracker.js"
                
                if completion_script.exists():
                    with open(completion_script, 'r', encoding='utf-8') as f:
                        script_content = f.read()
                    
                    # Check for critical functions - updated for unified source system
                    has_getSourceById = "getSourceById" in script_content
                    has_getSourceData = "getSourceData" in script_content
                    has_unified_usage = "UnifiedSourceManager" in script_content
                    
                    if has_getSourceById and has_getSourceData and has_unified_usage:
                        self.add_result("JS_COMPLETION_TRACKER_FILE", True, "JavaScript completion tracker file has all required functions")
                    else:
                        missing_parts = []
                        if not has_getSourceById: missing_parts.append("getSourceById")
                        if not has_getSourceData: missing_parts.append("getSourceData") 
                        if not has_unified_usage: missing_parts.append("UnifiedSourceManager usage")
                        self.add_result("JS_COMPLETION_TRACKER_FILE", False, f"JavaScript file missing: {missing_parts}")
                else:
                    self.add_result("JS_COMPLETION_TRACKER_FILE", False, "completion_tracker.js file not found")
                    
            except Exception as e:
                self.add_result("JS_COMPLETION_TRACKER_FILE", False, f"JavaScript file check failed: {e}")
            
        except Exception as e:
            self.add_result("JS_COMPLETION_TRACKER_INTEGRATION", False, f"Integration test setup failed: {e}")

    def test_end_to_end_completion_tracker_pipeline(self):
        """Test the complete pipeline from NVD source data to completion tracker functionality."""
        print("\n🔄 Testing End-to-End Completion Tracker Pipeline...")
        
        try:
            from analysis_tool.storage.nvd_source_manager import get_global_source_manager, get_all_sources_for_cve
            from analysis_tool.core.processData import processCVEData
            
            manager = get_global_source_manager()
            
            # Initialize with EXACT real-world data structure that caused the bug
            real_world_data = pd.DataFrame([
                {
                    # This is EXACTLY how Cisco data appears in real NVD API responses
                    "orgId": "",  # CRITICAL: Empty orgId field
                    "name": "Cisco Systems, Inc.",
                    "contactEmail": "psirt@cisco.com",
                    "sourceIdentifiers": ["psirt@cisco.com", "d1c1063e-7a18-46af-9102-31f8928bc633"]
                },
                {
                    # Standard case for comparison
                    "orgId": "12345678-1234-4567-8901-123456789abc",
                    "name": "Test Organization",
                    "contactEmail": "test@example.com", 
                    "sourceIdentifiers": ["test@example.com", "12345678-1234-4567-8901-123456789abc"]
                }
            ])
            
            manager.initialize(real_world_data)
            
            # Test 1: Verify CVE processing injects correct source metadata
            try:
                mock_cve_data = {
                    "cveMetadata": {
                        "cveId": "CVE-2024-TEST"
                    },
                    "containers": {
                        "cna": {
                            "providerMetadata": {
                                "orgId": "d1c1063e-7a18-46af-9102-31f8928bc633"  # UUID that should resolve to Cisco
                            }
                        }
                    }
                }
                
                # This will trigger get_all_sources_for_cve internally
                processed_data, global_metadata = processCVEData(pd.DataFrame(), mock_cve_data)
                
                # Verify the sourceData structure is properly injected
                if 'sourceData' in global_metadata:
                    source_data = global_metadata['sourceData']
                    
                    if len(source_data) > 0:
                        cisco_source = source_data[0]
                        
                        # Critical test: verify the source resolved correctly
                        if cisco_source.get('name') == "Cisco Systems, Inc.":
                            self.add_result("E2E_CVE_PROCESSING", True, "CVE processing correctly injects Cisco source data")
                            
                            # Verify structure has all fields JavaScript needs
                            # Updated for sourceIdentifiers-based approach (no artificial orgId)
                            required_fields = ['name', 'contactEmail', 'sourceIdentifiers']
                            if all(field in cisco_source for field in required_fields):
                                self.add_result("E2E_METADATA_STRUCTURE", True, "Source metadata has all required fields for JavaScript")
                                
                                # Verify sourceIdentifiers array is present and properly structured
                                if isinstance(cisco_source.get('sourceIdentifiers'), list):
                                    self.add_result("E2E_EMPTY_ORGID_HANDLING", True, "SourceIdentifiers properly handled in end-to-end pipeline")
                                else:
                                    self.add_result("E2E_EMPTY_ORGID_HANDLING", False, f"Expected sourceIdentifiers list, got: {type(cisco_source.get('sourceIdentifiers'))}")
                            else:
                                missing = [f for f in required_fields if f not in cisco_source]
                                self.add_result("E2E_METADATA_STRUCTURE", False, f"Missing fields: {missing}")
                        else:
                            self.add_result("E2E_CVE_PROCESSING", False, f"Expected 'Cisco Systems, Inc.', got: '{cisco_source.get('name')}'")
                    else:
                        self.add_result("E2E_CVE_PROCESSING", False, "No source data returned")
                else:
                    self.add_result("E2E_CVE_PROCESSING", False, "No sourceData in global metadata")
                    
            except Exception as e:
                self.add_result("E2E_CVE_PROCESSING", False, f"CVE processing failed: {e}")
            
            # Test 2: Simulate complete JavaScript completion tracker workflow
            try:
                # Get the same data that would be available to JavaScript
                sources = get_all_sources_for_cve(["d1c1063e-7a18-46af-9102-31f8928bc633"])
                
                def simulate_complete_js_workflow(uuid_to_resolve, source_data):
                    """Simulate the complete JavaScript workflow from UUID to name display."""
                    
                    # Step 1: getSourceData() - simulated
                    if not source_data or len(source_data) == 0:
                        return "No source data available"
                    
                    # Step 2: getSourceById() - simulated (this is where the bug was)
                    for source in source_data:
                        # Primary lookup: orgId (this was broken when JS expected 'sourceId')
                        if source.get('orgId') == uuid_to_resolve:
                            return source['name']
                        
                        # Fallback: sourceIdentifiers array (this saved us)
                        if uuid_to_resolve in source.get('sourceIdentifiers', []):
                            return source['name']
                    
                    # Step 3: If no match, return original UUID (this was the symptom)
                    return uuid_to_resolve
                
                # Test the critical case that was showing UUID instead of name
                result = simulate_complete_js_workflow("d1c1063e-7a18-46af-9102-31f8928bc633", sources)
                
                if result == "Cisco Systems, Inc.":
                    self.add_result("E2E_JS_WORKFLOW", True, "Complete JavaScript workflow resolves UUID to name correctly")
                else:
                    self.add_result("E2E_JS_WORKFLOW", False, f"JavaScript workflow failed: got '{result}', expected 'Cisco Systems, Inc.'")
                
                # Test edge case: what if someone looks up by email
                email_result = simulate_complete_js_workflow("psirt@cisco.com", sources)
                if email_result == "Cisco Systems, Inc.":
                    self.add_result("E2E_EMAIL_LOOKUP", True, "JavaScript workflow handles email lookup correctly")
                else:
                    self.add_result("E2E_EMAIL_LOOKUP", False, f"Email lookup failed: got '{email_result}'")
                    
            except Exception as e:
                self.add_result("E2E_JS_WORKFLOW", False, f"JavaScript workflow simulation failed: {e}")
                self.add_result("E2E_EMAIL_LOOKUP", False, f"Email lookup simulation failed: {e}")
            
            # Test 3: Verify the data structure regression protection
            try:
                # This test ensures we catch future regressions where test data doesn't match real data
                sources = get_all_sources_for_cve(["d1c1063e-7a18-46af-9102-31f8928bc633"])
                
                if len(sources) > 0:
                    source = sources[0]
                    
                    # Critical regression test: ensure we're testing with realistic sourceIdentifiers-based data
                    has_no_orgId = 'orgId' not in source  # No artificial orgId field
                    has_uuid_in_identifiers = "d1c1063e-7a18-46af-9102-31f8928bc633" in source.get('sourceIdentifiers', [])
                    
                    if has_no_orgId and has_uuid_in_identifiers:
                        self.add_result("E2E_REGRESSION_PROTECTION", True, "Test uses realistic data structure (no orgId, UUID in identifiers)")
                    elif not has_no_orgId:
                        self.add_result("E2E_REGRESSION_PROTECTION", False, f"Test data has artificial orgId field (should not exist)")
                    elif not has_uuid_in_identifiers:
                        self.add_result("E2E_REGRESSION_PROTECTION", False, "Test data missing UUID in sourceIdentifiers array")
                    else:
                        self.add_result("E2E_REGRESSION_PROTECTION", False, "Test data structure doesn't match real-world case")
                else:
                    self.add_result("E2E_REGRESSION_PROTECTION", False, "No sources available for regression test")
                    
            except Exception as e:
                self.add_result("E2E_REGRESSION_PROTECTION", False, f"Regression protection test failed: {e}")
                
        except Exception as e:
            self.add_result("E2E_COMPLETION_TRACKER_PIPELINE", False, f"End-to-end pipeline test failed: {e}")

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
        print("\n[NIST Special Handling Test]...")
        
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

    def test_unified_source_architecture_compliance(self):
        """Test that JavaScript modules comply with unified source architecture."""
        print("\n[Unified Source Architecture Compliance Test]...")
        
        # Get the project root directory
        project_root = Path(__file__).parent.parent.parent
        js_dir = project_root / 'src' / 'analysis_tool' / 'static' / 'js'
        
        if not js_dir.exists():
            self.add_result("UNIFIED_ARCHITECTURE", False, f"JavaScript directory not found: {js_dir}")
            return
            
        # Test 1: Completion tracker uses unified approach
        try:
            completion_tracker_file = js_dir / 'completion_tracker.js'
            if not completion_tracker_file.exists():
                self.add_result("COMPLETION_TRACKER_UNIFIED", False, "completion_tracker.js not found")
                return
                
            with open(completion_tracker_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Should use the new unified data extraction function
            has_unified_extract = 'unifiedExtractDataFromTable' in content
            has_fail_fast = 'typeof window.unifiedExtractDataFromTable !== \'function\'' in content
            has_error_handling = 'Check that unified_data_extraction.js is loaded' in content
            
            if has_unified_extract and has_fail_fast and has_error_handling:
                self.add_result("COMPLETION_TRACKER_UNIFIED", True, "Completion tracker uses unified approach with fail-fast")
            else:
                missing = []
                if not has_unified_extract: missing.append("unifiedExtractDataFromTable usage")
                if not has_fail_fast: missing.append("fail-fast check")
                if not has_error_handling: missing.append("proper error handling")
                self.add_result("COMPLETION_TRACKER_UNIFIED", False, f"Missing: {missing}")
                
        except Exception as e:
            self.add_result("COMPLETION_TRACKER_UNIFIED", False, f"Test failed: {e}")
        
        # Test 2: Unified data extraction module exists and is properly integrated
        try:
            unified_extraction_file = js_dir / 'unified_data_extraction.js'
            if not unified_extraction_file.exists():
                self.add_result("CPE_JSON_UNIFIED", False, "unified_data_extraction.js not found")
                return
                
            with open(unified_extraction_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Should export unifiedExtractDataFromTable and backward compatibility alias
            has_unified_export = 'window.unifiedExtractDataFromTable = unifiedExtractDataFromTable' in content
            has_function_def = 'function unifiedExtractDataFromTable(tableIndex)' in content
            has_unified_source_usage = 'window.UnifiedSourceManager.getSourceById' in content
            
            if has_unified_export and has_function_def and has_unified_source_usage:
                self.add_result("CPE_JSON_UNIFIED", True, "Unified data extraction properly implemented")
            else:
                missing = []
                if not has_unified_export: missing.append("unifiedExtractDataFromTable export")
                if not has_function_def: missing.append("function definition")
                if not has_unified_source_usage: missing.append("UnifiedSourceManager usage")
                self.add_result("CPE_JSON_UNIFIED", False, f"Missing: {missing}")
                
        except Exception as e:
            self.add_result("CPE_JSON_UNIFIED", False, f"Test failed: {e}")
        
        # Test 3: No inappropriate direct metadata access
        try:
            js_files = list(js_dir.glob('*.js'))
            allowed_files = {'cpe_json_handler.js', 'provenance_assistance.js'}
            
            violations = {}
            direct_access_patterns = [
                r'metadata\.sourceData\.some',
                r'source\.sourceId(?!\s*enti)(?!\s*\))',
                r'sourceData\.sourceId(?!\s*\|\|)'
            ]
            
            for js_file in js_files:
                if js_file.name in allowed_files:
                    continue
                    
                with open(js_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                file_violations = []
                for pattern in direct_access_patterns:
                    import re
                    matches = re.findall(pattern, content)
                    if matches:
                        file_violations.extend(matches)
                
                if file_violations:
                    violations[js_file.name] = file_violations
            
            if not violations:
                self.add_result("NO_DIRECT_METADATA_ACCESS", True, "No inappropriate direct metadata access found")
            else:
                violation_details = [f"{file}: {patterns}" for file, patterns in violations.items()]
                self.add_result("NO_DIRECT_METADATA_ACCESS", False, f"Violations: {'; '.join(violation_details)}")
                
        except Exception as e:
            self.add_result("NO_DIRECT_METADATA_ACCESS", False, f"Test failed: {e}")
        
        # Test 4: No inappropriate fallback logic
        try:
            js_files = list(js_dir.glob('*.js'))
            allowed_files = {'cpe_json_handler.js', 'modular_rules.js'}
            
            modules_with_fallbacks = {}
            fallback_patterns = [
                r'catch.*fallback(?!.*no fallback)',  # Exclude "no fallback" patterns
                r'else.*fallback(?!.*no fallback)',   # Exclude "no fallback" patterns  
                r'(?<!no\s)fallback\s+approach',      # Exclude "no fallback approach"
                r'backup.*method(?!\s*comment)'       # Exclude backup in comments
            ]
            
            for js_file in js_files:
                if js_file.name in allowed_files:
                    continue
                    
                with open(js_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                file_fallbacks = []
                for pattern in fallback_patterns:
                    import re
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        file_fallbacks.extend(matches)
                
                if file_fallbacks:
                    modules_with_fallbacks[js_file.name] = file_fallbacks
            
            if not modules_with_fallbacks:
                self.add_result("NO_FALLBACK_LOGIC", True, "No inappropriate fallback logic found")
            else:
                fallback_details = [f"{file}: {patterns}" for file, patterns in modules_with_fallbacks.items()]
                self.add_result("NO_FALLBACK_LOGIC", False, f"Fallbacks found: {'; '.join(fallback_details)}")
                
        except Exception as e:
            self.add_result("NO_FALLBACK_LOGIC", False, f"Test failed: {e}")

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
        self.test_end_to_end_completion_tracker_pipeline()
        self.test_unknown_uuid_handling()
        self.test_nist_special_handling()
        self.test_unified_source_architecture_compliance()
        
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
