#!/usr/bin/env python3
"""
Unified Test Runner for Analysis Tools CVE Analysis System

Runs all test suites and provides comprehensive summary reporting.
All test suites use a standardized output format for consistent parsing.

Each test suite outputs: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Browser Behavior:
- When running through this unified runner, browser auto-opening is disabled 
  to prevent multiple browser tabs from opening during test execution
- To enable browser opening, run individual test suites directly
- This is controlled via the UNIFIED_TEST_RUNNER environment variable

Usage:
    python run_all_tests.py
"""

import subprocess
import sys
import time
from pathlib import Path
from typing import List, Dict

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
                'command': ['python', 'test_files\\test_logging_system.py']
            },
            {
                'name': 'Modular Rules', 
                'command': ['python', 'test_files\\test_modular_rules.py', 'test_files\\testModularRulesEnhanced.json']
            },
            {
                'name': 'Platform Badges',
                'command': ['python', 'test_files\\test_platform_badges.py']
            },
            {
                'name': 'Update Patterns',
                'command': ['python', 'test_files\\test_update_patterns.py']
            },
            {
                'name': 'Confirmed Mappings',
                'command': ['python', 'test_files\\test_confirmed_mappings.py']
            },
            {
                'name': 'Curator',
                'command': ['python', 'test_files\\test_curator.py']
            },
            {
                'name': 'Confirmed Mapping Dashboard',
                'command': ['python', 'test_files\\test_confirmed_mapping_dashboard.py']
            },
            {
                'name': 'Provenance Assistance',
                'command': ['python', 'test_files\\test_provenance_assistance.py', 'test_files\\testProvenanceAssistance.json']
            },
            {
                'name': 'NVD Source Manager',
                'command': ['python', 'test_files\\test_nvd_source_manager.py']
            },
            {
                'name': 'Source Data Concern Badge Data Collector JSON',
                'command': ['python', 'test_files\\test_source_data_concern_badge_data_collector_json.py']
            },
            {
                'name': 'Source Data Concern Dashboard Webpage',
                'command': ['python', 'test_files\\test_source_data_concern_dashboard_webpage.py']
            },
            {
                'name': 'Source Data Concern Dashboard',
                'command': ['python', 'test_files\\test_source_data_concern_dashboard.py']
            }
        ]

    def parse_standard_test_output(self, output: str) -> Dict:
        """Parse standardized test output format.
        
        All test suites now output: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"
        """
        if not output:
            return {'tests_passed': 0, 'tests_total': 0, 'summary': 'No output captured'}
        
        lines = output.strip().split('\n')
        
        # Look for the standard results line (should be the last meaningful line)
        import re
        for line in reversed(lines):
            match = re.match(r'TEST_RESULTS: PASSED=(\d+) TOTAL=(\d+) SUITE="([^"]*)"', line.strip())
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
            
            # Always capture output for parsing, but only show in verbose mode
            result = subprocess.run(
                suite['command'],
                cwd=Path(__file__).parent.parent,  # Project root (one level up from test_files)
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
                print(f"\n❌ FAILURE in {suite['name']}:")
                
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
        print("ℹ️  Browser auto-opening disabled for unified test execution")
        print("   (run individual test suites directly to enable browser opening)")
        print()
        
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
            status_icon = "✓" if result['success'] else "✗"
            print(f"  {status_icon} {result['name']}: {result['summary']}")
        
        # Calculate total test counts
        total_tests_run = sum(result['tests_total'] for result in self.results)
        total_tests_passed = sum(result['tests_passed'] for result in self.results)
        
        print(f"\nIndividual Test Summary:")
        print(f"  Total Individual Tests: {total_tests_passed}/{total_tests_run} passed")
        
        if overall_success:
            print("\n🎉 ALL TEST SUITES PASSED!")
        else:
            failed_count = total_suites - passed_suites
            print(f"\n⚠️  {failed_count} TEST SUITE(S) FAILED")
            print("\nFailed suites:")
            for result in self.results:
                if not result['success']:
                    print(f"  • {result['name']} (return code: {result['return_code']})")
        
        print("=" * 50)
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
