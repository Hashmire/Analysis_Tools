#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Test Runner for Analysis Tools CVE Analysis System

Runs all test suites with consolidated output organization and comprehensive summary reporting.
All test suites use a standardized output format for consistent parsing.

All test suites MUST output: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"


Environment Variables:
    CONSOLIDATED_TEST_RUN:
        - Automatically set to '1' to enable consolidated directory structure
        - Creates single timestamped directory: runs/TIMESTAMP_run_all_tests/
        - Individual test runs organized as: logs/TIMESTAMP_TEST_SuiteName_context/

Test Data Guidelines:
    - Use vendor-neutral identifiers in test documentation and validation reports
    - Actual test data files may use realistic vendor/product structures for authenticity
    - Documentation should reference "Vendor A", "Vendor B", "Product X", etc.
    - This maintains professional objectivity and avoids appearance of targeting specific companies
    - Test logic validates behavior patterns, not specific vendor characteristics

Standard Test Pattern (Cache-Related Integration Tests):
    All integration tests that interact with cache systems follow the four-phase pattern:
    
    1. SETUP: Inject test data into appropriate cache locations
       - Creates proper cache directory structures as needed:
         * CVE sources: cache/{source}/YYYY/Xxxx/ (nvd_2.0_cves/, cve_list_v5/)
         * Enhanced records: cache/nvd-ish_2.0_cves/
         * CPE data: cache/cpe_base_strings/ (including test-only directories)
       - Injects supporting data into system files:
         * nvd_source_data.json for source resolution
         * Alias mappings for vendor/product identification
       - Copies pre-created test files to INPUT cache directories
    
    2. EXECUTE: Run normal tool execution (not isolated test-file mode)
       - Uses standard module invocation from various relevant entry points:
         * python -m src.analysis_tool.core.analysis_tool --cve CVE-ID --nvd-ish-only
         * python -m src.analysis_tool.core.generate_dataset --file FILEPATH --nvd-ish-only
         * python -m src.analysis_tool.core.harvest_and_process_sources --nvd-ish-only
         * python -m src.analysis_tool.reporting.generate_sdc_report [options]
         * python -m src.analysis_tool.reporting.generate_alias_report [options]
         * python -m src.analysis_tool.reporting.generate_cpeas_automation_report [options]
       - Tool automatically discovers and processes INPUT cache files
    
    3. VALIDATE: Check OUTPUT artifacts for expected results
       - Validates OUTPUT cache content (nvd-ish_2.0_cves/):
         * Enhanced record structure and content
         * Proper data extraction and transformation
         * Cache state isolation
       - Validates run artifacts (runs/TIMESTAMP_*/):
         * Log files contain expected statements
         * Generated reports (HTML/JSON) have correct structure
         * Cache metadata integrity maintained
       - Confirms expected behavior:
         * No cross-contamination between test runs
         * Proper error handling and recovery
    
    4. TEARDOWN: Clean INPUT cache files only (preserve OUTPUT for inspection)
       - Removes test files from INPUT caches (cve_list_v5/, nvd_2.0_cves/)
       - Removes test entries from system files (nvd_source_data.json, alias mappings)
       - Removes test-only directories (e.g., CPE cache test directories)
       - Preserves OUTPUT cache (nvd-ish_2.0_cves/) for post-run inspection
       - Maintains clean test environment between runs

Usage:
    python run_all_tests.py                    # Run all tests with consolidated organization
    python test_suites/test_suite_name.py       # Run individual test in standard mode
"""

import subprocess
import sys
import time
import os
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import List, Dict, Tuple

# Force UTF-8 output encoding for Windows compatibility with Unicode test output
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'replace')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'replace')


def create_consolidated_test_run() -> Tuple[Path, str, Dict]:
    """
    Create a consolidated test run directory for test suite execution.
    
    This creates a single directory under runs/ that will contain
    all individual test runs from a complete test suite execution.
    
    Returns:
        Tuple of (consolidated_run_path, consolidated_run_id, test_environment_info)
    """
    # Import the existing run organization system
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    from analysis_tool.storage.run_organization import get_analysis_tools_root
    
    project_root = get_analysis_tools_root()
    
    # Generate timestamp-based consolidated run ID following standard format
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    consolidated_run_id = f"{timestamp}_run_all_tests"
    
    # Create consolidated run directory directly in runs/ following standard pattern
    runs_root = project_root / "runs"
    runs_root.mkdir(parents=True, exist_ok=True)
    consolidated_run_path = runs_root / consolidated_run_id
    consolidated_run_path.mkdir(parents=True, exist_ok=True)
    
    # Create standard subdirectories
    (consolidated_run_path / "logs").mkdir(exist_ok=True)
    (consolidated_run_path / "generated_pages").mkdir(exist_ok=True)
    
    # Create test environment information
    test_env_info = {
        "consolidated_run_id": consolidated_run_id,
        "consolidated_run_path": str(consolidated_run_path),
        "test_start_time": datetime.now(timezone.utc).isoformat(),
        "test_suite_count": 0,
        "individual_test_runs": [],
        "environment": {
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "platform": os.name,
            "cwd": str(Path.cwd())
        }
    }
    
    return consolidated_run_path, consolidated_run_id, test_env_info


def setup_test_environment(consolidated_run_path: Path, test_env_info: Dict) -> None:
    """
    Set up environment variables to redirect test runs to consolidated directory.
    
    Args:
        consolidated_run_path: Path to the consolidated test run directory
        test_env_info: Test environment information dictionary
    """
    # Set environment variable that individual tests can check
    os.environ['CONSOLIDATED_TEST_RUN'] = '1'
    os.environ['CONSOLIDATED_TEST_RUN_PATH'] = str(consolidated_run_path)
    os.environ['CONSOLIDATED_TEST_RUN_ID'] = test_env_info['consolidated_run_id']
    
    # Set UNIFIED_TEST_RUNNER for backward compatibility with legacy test suites
    # Note: Newer tests don't need this flag - subprocess PIPE automatically suppresses output
    os.environ['UNIFIED_TEST_RUNNER'] = '1'


def finalize_consolidated_test_run(consolidated_run_path: Path, test_env_info: Dict, 
                                  test_results: List[Dict]) -> None:
    """
    Finalize the consolidated test run by saving summary and cleaning up environment.
    
    Args:
        consolidated_run_path: Path to the consolidated test run directory
        test_env_info: Test environment information dictionary
        test_results: List of test suite results
    """
    # Update test environment info with results
    test_env_info["test_end_time"] = datetime.now(timezone.utc).isoformat()
    test_env_info["test_suite_count"] = len(test_results)
    test_env_info["total_individual_tests"] = sum(r.get('tests_total', 0) for r in test_results)
    test_env_info["total_passed_tests"] = sum(r.get('tests_passed', 0) for r in test_results)
    test_env_info["overall_success"] = all(r.get('success', False) for r in test_results)
    test_env_info["test_results_summary"] = test_results
    
    # Calculate test execution time
    start_time = datetime.fromisoformat(test_env_info["test_start_time"])
    end_time = datetime.fromisoformat(test_env_info["test_end_time"])
    test_env_info["total_execution_time_seconds"] = (end_time - start_time).total_seconds()
    
    # Save consolidated test summary
    summary_file = consolidated_run_path / "logs" / "test_execution_summary.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(test_env_info, f, indent=2, ensure_ascii=False)
    
    # Clean up environment variables
    os.environ.pop('CONSOLIDATED_TEST_RUN', None)
    os.environ.pop('CONSOLIDATED_TEST_RUN_PATH', None)
    os.environ.pop('CONSOLIDATED_TEST_RUN_ID', None)


class TestSuiteRunner:
    """Unified test runner that executes all standardized test suites.
    
    All test suites must output a standard results line:
    TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"
    
    This enables reliable parsing and comprehensive reporting.
    """
    
    def __init__(self):
        self.results: List[Dict] = []
        
        # Define all test suites
        self.test_suites = [
            {
                'name': 'Logging System',
                'command': ['python', 'test_suites\\\\tool_infrastructure\\\\test_logging_system.py']
            },
            {
                'name': 'CPE Format Conversion',
                'command': ['python', 'test_suites\\\\tool_infrastructure\\\\test_cpe_format_conversion.py']
            },
            {
                'name': 'Update Patterns',
                'command': ['python', 'test_suites\\\\cpe-as_generation\\\\test_update_patterns.py']
            },
            {
                'name': 'Source Data Concern Badge Data Collector JSON',
                'command': ['python', 'test_suites\\\\\\\\source_data_concerns\\\\\\\\test_source_data_concern_badge_data_collector_json.py']
            },
            {
                'name': 'Source Data Concern Dashboard Webpage',
                'command': ['python', 'test_suites\\\\\\\\source_data_concerns\\\\\\\\test_source_data_concern_dashboard_webpage.py']
            },
            {
                'name': 'Source Data Concern Dashboard',
                'command': ['python', 'test_suites\\\\\\\\source_data_concerns\\\\\\\\test_source_data_concern_dashboard.py']
            },

            # === Source Data Concerns Suite ===
            {
                'name': 'SDC Placeholder Detection',
                'command': ['python', 'test_suites\\\\source_data_concerns\\\\test_sdc_placeholder_detection.py']
            },
            {
                'name': 'SDC Mathematical Comparator Detection',
                'command': ['python', 'test_suites\\\\\\\\source_data_concerns\\\\\\\\test_sdc_mathematical_comparator_detection.py']
            },
            {
                'name': 'SDC Text Comparator Detection',
                'command': ['python', 'test_suites\\\\\\\\source_data_concerns\\\\\\\\test_sdc_text_comparator_detection.py']
            },
            {
                'name': 'SDC All Versions Pattern Detection',
                'command': ['python', 'test_suites\\\\\\\\source_data_concerns\\\\\\\\test_sdc_all_versions_pattern_detection.py']
            },
            {
                'name': 'SDC Bloat Text Detection',
                'command': ['python', 'test_suites\\\\\\\\source_data_concerns\\\\\\\\test_sdc_bloat_text_detection.py']
            },
            {
                'name': 'SDC Version Granularity Detection',
                'command': ['python', 'test_suites\\\\\\\\source_data_concerns\\\\\\\\test_sdc_version_granularity_detection.py']
            },
            {
                'name': 'SDC Whitespace Detection',
                'command': ['python', 'test_suites\\\\\\\\source_data_concerns\\\\\\\\test_sdc_whitespace_detection.py']
            },
            {
                'name': 'SDC Invalid Character Detection',
                'command': ['python', 'test_suites\\\\\\\\source_data_concerns\\\\\\\\test_sdc_invalid_character_detection.py']
            },
                        {
                'name': 'SDC Overlapping Ranges Detection',
                'command': ['python', 'test_suites\\\\\\\\source_data_concerns\\\\\\\\test_sdc_overlapping_ranges_detection.py']
            },
            {
                'name': 'SDC Skip Logic Rules',
                'command': ['python', 'test_suites\\\\\\\\source_data_concerns\\\\\\\\test_sdc_skip_logic_rules.py']
            },
            # === Tool Infrastructure Suite ===
            {
                'name': 'NVD Source Manager',
                'command': ['python', 'test_suites\\\\tool_infrastructure\\\\test_nvd_source_manager.py']
            },
            {
                'name': 'Multi-CVE State Isolation',
                'command': ['python', 'test_suites\\\\tool_infrastructure\\\\test_multi_cve_state_isolation.py']
            },
            {
                'name': 'Confirmed Mapping Manager',
                'command': ['python', 'test_suites\\\\tool_infrastructure\\\\test_confirmed_mapping_manager.py']
            },
            {
                'name': 'CPE Base String Cache Manager',
                'command': ['python', 'test_suites\\\\tool_infrastructure\\\\test_cpe_cache.py']
            },
            {
                'name': 'CPE Cache Proactive Eviction',
                'command': ['python', 'test_suites\\\\tool_infrastructure\\\\test_cpe_cache_eviction.py']
            },
            {
                'name': 'CPE UTF-8 Validation',
                'command': ['python', 'test_suites\\\\tool_infrastructure\\\\test_cpe_utf8_validation.py']
            },
            {
                'name': 'Schema Validation',
                'command': ['python', 'test_suites\\validation\\test_schema_validation.py']
            },
            {
                'name': 'Schema Loading Integration',
                'command': ['python', 'test_suites\\validation\\test_schema_loading_integration.py']
            },
            {
                'name': 'CPE Corruption Prevention',
                'command': ['python', 'test_suites\\tool_infrastructure\\test_cpe_corruption_prevention.py']
            },
            {
                'name': 'CPE Cache Refresh',
                'command': ['python', 'test_suites\\tool_infrastructure\\test_cpe_cache_refresh.py']
            },
            {
                'name': 'NVD Cache Refresh',
                'command': ['python', 'test_suites\\utilities\\test_nvd_cache_refresh.py']
            },
            {
                'name': 'Concurrent API',
                'command': ['python', 'test_suites\\utilities\\test_concurrent_api.py']
            },
            {
                'name': 'NVD Cache Staleness Detection',
                'command': ['python', 'test_suites\\tool_infrastructure\\test_nvd_cache_staleness.py']
            },
            # === NVD-ish Record Processing Flow (Ordered by Execution) ===
            # Step 1: Core record collection and structure
            {
                'name': 'NVD-ish Collector (Core)',
                'command': ['python', 'test_suites\\\\nvd-ish_collector\\\\test_nvd_ish_collector.py']
            },
            # Step 2: Source Data Concerns analysis
            {
                'name': 'NVD-ish SDC Integration',
                'command': ['python', 'test_suites\\\\nvd-ish_collector\\\\test_sdc_integration.py']
            },
            # Step 3: Alias Extraction (extracts vendor/product aliases from source data)
            {
                'name': 'NVD-ish Alias Extraction',
                'command': ['python', 'test_suites\\\\nvd-ish_collector\\\\test_alias_extraction.py']
            },
            # Step 4: CPE Determination (includes confirmed mappings pre-loading and culling)
            {
                'name': 'NVD-ish Confirmed Mappings',
                'command': ['python', 'test_suites\\\\nvd-ish_collector\\\\test_confirmed_mappings.py']
            },
            {
                'name': 'NVD-ish CPE Determination',
                'command': ['python', 'test_suites\\nvd-ish_collector\\test_cpe_determination.py']
            },
            {
                'name': 'NVD-ish CPE Culling',
                'command': ['python', 'test_suites\\\\nvd-ish_collector\\\\test_cpe_culling.py']
            },
            # Step 5: CPE-AS Generation (Final enrichment step)
            {
                'name': 'NVD-ish CPE-AS Integration',
                'command': ['python', 'test_suites\\\\nvd-ish_collector\\\\test_cpe_as_integration.py']
            },
            # === Report Generation Suite ===
            {
                'name': 'CPE-AS Automation Report Generation',
                'command': ['python', 'test_suites\\\\reporting\\\\test_cpeas_automation_report.py']
            },
            # === Alias Mapping Suite ===
            {
                'name': 'Alias Mapping Dashboard',
                'command': ['python', 'test_suites\\\\alias_mappings\\\\test_alias_mapping_dashboard.py']
            }
        ]

    def parse_standard_test_output(self, output: str) -> Dict:
        """Parse standardized test output format.
        
        All test suites now output: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"
        """
        if not output:
            return {'tests_passed': 0, 'tests_total': 0, 'summary': 'No output captured'}
        
        # Look for the standard results line in the entire output (robust against Unicode corruption and line breaks)
        import re
        match = re.search(r'TEST_RESULTS: PASSED=(\d+) TOTAL=(\d+) SUITE="([^"]*)"', output)
        if match:
            passed, total, suite_name = match.groups()
            return {
                'tests_passed': int(passed),
                'tests_total': int(total),
                'suite_name': suite_name,
                'success': int(passed) == int(total),
                'summary': f'{passed}/{total} tests passed'
            }
        
        # Should not happen with standardized test suites
        return {
            'tests_passed': 0,
            'tests_total': 0, 
            'success': False,  # Add default success value
            'summary': 'ERROR: Standard test output format not found'
        }
        
    def run_test_suite(self, suite: Dict) -> Dict:
        """Run a single test suite and return results."""
        print(f"Running {suite['name']}...", flush=True)
        
        start_time = time.time()
        
        try:
            # Set environment to handle Unicode characters in test output
            import os
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            env['UNIFIED_TEST_RUNNER'] = '1'  # Legacy flag for older test suites (redundant - subprocess PIPE suppresses output)
            env['CURRENT_TEST_SUITE'] = suite['name']  # Pass test suite name for better labeling
            
            # Always capture output for parsing, but only show in verbose mode
            result = subprocess.run(
                suite['command'],
                cwd=Path(__file__).parent.parent,  # Project root (one level up from test_suites)
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,  # 5 minute timeout
                env=env,
                encoding='utf-8',
                errors='replace'
            )
            
            execution_time = time.time() - start_time
            success = result.returncode == 0
            
            # Parse the standardized output
            test_info = self.parse_standard_test_output(result.stdout)
            
            # TRANSPARENCY IMPROVEMENT: Always show critical error information
            if not success or not test_info['success']:
                print(f"\nFAILURE in {suite['name']}:")
                
                # Always show stderr for failures (contains critical error info)
                if result.stderr:
                    print(f"Error Details:\n{result.stderr}")
                
                # Show diagnostic stdout if it contains useful info beyond TEST_RESULTS
                if result.stdout:
                    # Extract lines that aren't the TEST_RESULTS line
                    diagnostic_lines = []
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('TEST_RESULTS:'):
                            diagnostic_lines.append(line)
                    
                    if diagnostic_lines:
                        print(f"Diagnostic Output:\n{chr(10).join(diagnostic_lines)}")
                
                # Show non-standard return codes
                if result.returncode not in [0, 1]:
                    print(f"Return Code: {result.returncode}")
                
                print()  # Add spacing after error details
            
            return {
                'name': suite['name'],
                'success': success and test_info['success'],
                'execution_time': execution_time,
                'return_code': result.returncode,
                'tests_passed': test_info['tests_passed'],
                'tests_total': test_info['tests_total'],
                'summary': test_info['summary'],
                'output': '',
                'error': ''
            }
            
        except subprocess.TimeoutExpired:
            return {
                'name': suite['name'],
                'success': False,
                'execution_time': time.time() - start_time,
                'return_code': -1,
                'tests_passed': 0,
                'tests_total': 0,
                'summary': 'Test suite timed out',
                'output': '',
                'error': 'Test suite timed out'
            }
        except Exception as e:
            return {
                'name': suite['name'],
                'success': False,
                'execution_time': time.time() - start_time,
                'return_code': -2,
                'tests_passed': 0,
                'tests_total': 0,
                'summary': f'Execution error: {str(e)}',
                'output': '',
                'error': str(e)
            }
        
    def run_all_tests(self) -> bool:
        """Run all test suites and return overall success."""
        print("Running All Test Suites", flush=True)
        print("=" * 50, flush=True)
        print(flush=True)
        
        # Create consolidated test run directory
        consolidated_run_path, consolidated_run_id, test_env_info = create_consolidated_test_run()
        print(f"Created consolidated test run: {consolidated_run_id}", flush=True)
        print(f"Test artifacts will be consolidated in: {consolidated_run_path}", flush=True)
        print(flush=True)
        
        # Set up test environment for consolidation
        setup_test_environment(consolidated_run_path, test_env_info)
        
        overall_success = True
        total_start_time = time.time()
        
        for suite in self.test_suites:
            result = self.run_test_suite(suite)
            self.results.append(result)
            
            status = "PASS" if result['success'] else "FAIL"
            test_info = f" ({result['tests_passed']}/{result['tests_total']} tests)"
            print(f"{status} {result['name']} ({result['execution_time']:.1f}s){test_info}", flush=True)
            
            if not result['success']:
                overall_success = False
                print(f"   {result['summary']}", flush=True)
        
        total_time = time.time() - total_start_time
        
        # Print detailed summary
        print("\n" + "=" * 50, flush=True)
        print("TEST SUITE SUMMARY", flush=True)
        print("=" * 50, flush=True)
        
        passed_suites = sum(1 for r in self.results if r['success'])
        total_suites = len(self.results)
        
        print(f"Test Suites: {passed_suites}/{total_suites} passed", flush=True)
        print(f"Execution Time: {total_time:.1f} seconds", flush=True)
        
        # Show test details for each suite
        print("\nTest Details:", flush=True)
        for result in self.results:
            status_icon = "PASS" if result['success'] else "FAIL"
            print(f"  {status_icon} {result['name']}: {result['summary']}", flush=True)
        
        # Calculate total test counts
        total_tests_run = sum(result['tests_total'] for result in self.results)
        total_tests_passed = sum(result['tests_passed'] for result in self.results)
        
        print(f"\nIndividual Test Summary:", flush=True)
        print(f"  Total Individual Tests: {total_tests_passed}/{total_tests_run} passed", flush=True)
        
        if overall_success:
            print("\nALL TEST SUITES PASSED!", flush=True)
        else:
            failed_count = total_suites - passed_suites
            print(f"\n{failed_count} TEST SUITE(S) FAILED", flush=True)
            print("\nFailed suites:", flush=True)
            for result in self.results:
                if not result['success']:
                    print(f"  - {result['name']} (return code: {result['return_code']})", flush=True)
        
        print("=" * 50, flush=True)
        
        # Finalize consolidated test run
        finalize_consolidated_test_run(consolidated_run_path, test_env_info, self.results)
        
        return overall_success

def main():
    """Main function with argument validation."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run all Analysis Tools test suites')
    # Note: No arguments are supported by the unified test runner
    # Individual test suites may support their own arguments when run directly
    
    args = parser.parse_args()
    
    runner = TestSuiteRunner()
    success = runner.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    # Enable unbuffered output for real-time display
    import os
    os.environ['PYTHONUNBUFFERED'] = '1'
    main()
