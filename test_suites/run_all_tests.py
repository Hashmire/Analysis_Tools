#!/usr/bin/env python3
"""
Unified Test Runner for Analysis Tools CVE Analysis System

Runs all test suites with consolidated output organization and comprehensive summary reporting.
All test suites use a standardized output format for consistent parsing.

Each test suite outputs: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Consolidated Runs Organization:
    - Creates single timestamped directory: runs/TIMESTAMP_run_all_tests/
    - Individual test runs organized as: logs/TIMESTAMP_TEST_SuiteName_context/
    - Eliminates folder bloat by consolidating all test artifacts
    - Maintains full backward compatibility with existing run organization
    - Test execution summary saved as: logs/test_execution_summary.json

Environment Variables:
    UNIFIED_TEST_RUNNER:
        - Automatically set to '1' when running through this unified runner
        - Controls detailed output suppression in individual test suites
        - When set: test suites show minimal output for clean unified reporting
        - When unset: test suites show detailed output for debugging
    
    CONSOLIDATED_TEST_RUN:
        - Automatically set to '1' to enable consolidated directory structure
        - Individual tests use consolidated-aware path resolution
        - Helper functions in run_organization.py handle path detection

Browser Behavior:
    - Browser auto-opening disabled to prevent multiple tabs during test execution
    - Individual test suites add --no-browser flag when UNIFIED_TEST_RUNNER is set
    - To enable browser opening, run individual test suites directly

Usage:
    python run_all_tests.py                    # Run all tests with consolidated organization
    python test_suites/test_suite_name.py       # Run individual test in standard mode
"""

import subprocess
import sys
import time
import os
import datetime
import json
from pathlib import Path
from typing import List, Dict, Tuple


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
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
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
        "test_start_time": datetime.datetime.now().isoformat(),
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
    
    # Also set the unified test runner flag (already exists)
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
    test_env_info["test_end_time"] = datetime.datetime.now().isoformat()
    test_env_info["test_suite_count"] = len(test_results)
    test_env_info["total_individual_tests"] = sum(r.get('tests_total', 0) for r in test_results)
    test_env_info["total_passed_tests"] = sum(r.get('tests_passed', 0) for r in test_results)
    test_env_info["overall_success"] = all(r.get('success', False) for r in test_results)
    test_env_info["test_results_summary"] = test_results
    
    # Calculate test execution time
    start_time = datetime.datetime.fromisoformat(test_env_info["test_start_time"])
    end_time = datetime.datetime.fromisoformat(test_env_info["test_end_time"])
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
                'name': 'Modular Rules', 
                'command': ['python', 'test_suites\\\\cpe-as_generation\\\\test_modular_rules.py', 'test_suites\\\\cpe-as_generation\\\\testModularRulesEnhanced.json']
            },
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
            {
                'name': 'Update Patterns',
                'command': ['python', 'test_suites\\\\cpe-as_generation\\\\test_update_patterns.py']
            },
            {
                'name': 'Alias Mapping Dashboard',
                'command': ['python', 'test_suites\\\\alias_mappings\\\\test_alias_mapping_dashboard.py']
            },
            {
                'name': 'Alias Extraction Report to Dashboard Compatibility',
                'command': ['python', 'test_suites\\\\alias_mappings\\\\test_alias_extraction_dashboard_compatibility.py']
            },
            {
                'name': 'Provenance Assistance',
                'command': ['python', 'test_suites\\\\cpe-as_generation\\\\test_provenance_assistance.py', 'test_suites\\\\cpe-as_generation\\\\testProvenanceAssistance.json']
            },
            {
                'name': 'NVD Source Manager',
                'command': ['python', 'test_suites\\\\tool_infrastructure\\\\test_nvd_source_manager.py']
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
            {
                'name': 'Support Platform Badges',
                'command': ['python', 'test_suites\\\\other_badges\\\\test_support_platform_badges.py']
            },
            {
                'name': 'Platform Badges',
                'command': ['python', 'test_suites\\\\other_badges\\\\test_platform_badges.py']
            },
            {
                'name': 'NVD-ish Collector',
                'command': ['python', 'test_suites\\\\nvd-ish_collector\\\\test_nvd_ish_collector.py']
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
            'summary': 'ERROR: Standard test output format not found'
        }
        
    def run_test_suite(self, suite: Dict) -> Dict:
        """Run a single test suite and return results."""
        print(f"Running {suite['name']}...")
        
        start_time = time.time()
        
        try:
            # Set environment to handle Unicode characters in test output
            import os
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            env['UNIFIED_TEST_RUNNER'] = '1'  # Signal that we're running under unified test runner
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
        print("Running All Test Suites")
        print("=" * 50)
        print("Browser auto-opening disabled for unified test execution")
        print("   (run individual test suites directly to enable browser opening)")
        print()
        
        # Create consolidated test run directory
        consolidated_run_path, consolidated_run_id, test_env_info = create_consolidated_test_run()
        print(f"Created consolidated test run: {consolidated_run_id}")
        print(f"Test artifacts will be consolidated in: {consolidated_run_path}")
        print()
        
        # Set up test environment for consolidation
        setup_test_environment(consolidated_run_path, test_env_info)
        
        overall_success = True
        total_start_time = time.time()
        
        for suite in self.test_suites:
            result = self.run_test_suite(suite)
            self.results.append(result)
            
            status = "PASS" if result['success'] else "FAIL"
            test_info = f" ({result['tests_passed']}/{result['tests_total']} tests)"
            print(f"{status} {result['name']} ({result['execution_time']:.1f}s){test_info}")
            
            if not result['success']:
                overall_success = False
                print(f"   {result['summary']}")
        
        total_time = time.time() - total_start_time
        
        # Print detailed summary
        print("\n" + "=" * 50)
        print("TEST SUITE SUMMARY")
        print("=" * 50)
        
        passed_suites = sum(1 for r in self.results if r['success'])
        total_suites = len(self.results)
        
        print(f"Test Suites: {passed_suites}/{total_suites} passed")
        print(f"Execution Time: {total_time:.1f} seconds")
        
        # Show test details for each suite
        print("\nTest Details:")
        for result in self.results:
            status_icon = "PASS" if result['success'] else "FAIL"
            print(f"  {status_icon} {result['name']}: {result['summary']}")
        
        # Calculate total test counts
        total_tests_run = sum(result['tests_total'] for result in self.results)
        total_tests_passed = sum(result['tests_passed'] for result in self.results)
        
        print(f"\nIndividual Test Summary:")
        print(f"  Total Individual Tests: {total_tests_passed}/{total_tests_run} passed")
        
        if overall_success:
            print("\nALL TEST SUITES PASSED!")
        else:
            failed_count = total_suites - passed_suites
            print(f"\n{failed_count} TEST SUITE(S) FAILED")
            print("\nFailed suites:")
            for result in self.results:
                if not result['success']:
                    print(f"  - {result['name']} (return code: {result['return_code']})")
        
        print("=" * 50)
        
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
    main()
