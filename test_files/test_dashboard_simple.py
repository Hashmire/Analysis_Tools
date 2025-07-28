#!/usr/bin/env python3
"""
Dashboard Test
==============

Test suite to validate dashboard functionality by analyzing actual log files
generated from real CVE processing runs. This follows the same pattern as
other test suites - it uses the main analysis tool to generate data and then
validates the dashboard functionality.
"""

import os
import sys
import subprocess
from pathlib import Path

# Add the src directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from analysis_tool.local_dashboard.log_analyzer import LogAnalyzer
from analysis_tool.local_dashboard.generate_local_dashboard import generate_dashboard_html

class DashboardTest:
    """Test class for dashboard functionality using real analysis runs"""
    
    def __init__(self):
        # Find project root (same pattern as other tests)
        current_dir = Path(__file__).parent
        self.project_root = current_dir if (current_dir / "run_tools.py").exists() else current_dir.parent
        self.run_analysis_path = self.project_root / "run_tools.py"
        
        # Use standard runs directory
        self.runs_dir = self.project_root / "runs"
        
        self.test_results = []
    
    def add_result(self, test_name, passed, message=""):
        """Add test result (same pattern as other tests)"""
        self.test_results.append({
            "test": test_name,
            "passed": passed,
            "message": message
        })
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"   {test_name:<30} {status}")
        if message:
            print(f"       📝 {message}")
    
    def generate_test_run(self):
        """Generate a test run using the main analysis tool (same as other tests)"""
        try:
            print("🔄 Generating test run for dashboard analysis...")
            
            # Use a simple CVE for dashboard testing
            cmd = [
                "python", str(self.run_analysis_path),
                "--cve", "CVE-2024-20515",
                "--no-browser",
                "--no-cache"
            ]
            
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                self.add_result("TEST_RUN_GENERATION", False, f"Analysis tool failed: {result.stderr}")
                return False
                
            self.add_result("TEST_RUN_GENERATION", True, "Test run generated successfully")
            return True
            
        except subprocess.TimeoutExpired:
            self.add_result("TEST_RUN_GENERATION", False, "Analysis tool timed out")
            return False
        except Exception as e:
            self.add_result("TEST_RUN_GENERATION", False, f"Error: {e}")
            return False
    
    def find_test_run_directory(self):
        """Find the most recent run directory for testing"""
        if not self.runs_dir.exists():
            self.add_result("FIND_TEST_RUN", False, f"Runs directory not found: {self.runs_dir}")
            return None
            
        # Find runs with CVE-2024-20515 (our test CVE)
        test_runs = sorted([
            d for d in self.runs_dir.iterdir() 
            if d.is_dir() and 'CVE-2024-20515' in d.name
        ], key=lambda x: x.stat().st_mtime, reverse=True)
        
        if not test_runs:
            self.add_result("FIND_TEST_RUN", False, "No CVE-2024-20515 run directories found")
            return None
            
        test_run = test_runs[0]  # Most recent
        self.add_result("FIND_TEST_RUN", True, f"Found test run: {test_run.name}")
        return test_run
    
    def test_log_analyzer(self, run_dir):
        """Test the log analyzer functionality"""
        try:
            log_file = run_dir / "logs" / f"{run_dir.name.split('_')[-1]}.log"
            if not log_file.exists():
                # Try alternative log file naming
                log_files = list((run_dir / "logs").glob("*.log"))
                if not log_files:
                    self.add_result("LOG_ANALYZER", False, f"No log files found in {run_dir / 'logs'}")
                    return False
                log_file = log_files[0]
            
            # Test log analyzer
            analyzer = LogAnalyzer(str(log_file))
            analysis = analyzer.analyze_logs()
            
            if not analysis:
                self.add_result("LOG_ANALYZER", False, "Log analyzer returned empty results")
                return False
            
            # Basic validation of analysis results
            required_keys = ['workflow_stages', 'api_calls', 'performance_metrics']
            missing_keys = [key for key in required_keys if key not in analysis]
            
            if missing_keys:
                self.add_result("LOG_ANALYZER", False, f"Missing analysis keys: {missing_keys}")
                return False
            
            self.add_result("LOG_ANALYZER", True, f"Analyzed log file: {log_file.name}")
            return analysis
            
        except Exception as e:
            self.add_result("LOG_ANALYZER", False, f"Error analyzing logs: {e}")
            return False
    
    def test_dashboard_generation(self, run_dir, analysis):
        """Test dashboard HTML generation"""
        try:
            dashboard_file = run_dir / "dashboard.html"
            
            # Generate dashboard
            success = generate_dashboard_html(analysis, str(dashboard_file))
            
            if not success:
                self.add_result("DASHBOARD_GENERATION", False, "Dashboard generation failed")
                return False
            
            if not dashboard_file.exists():
                self.add_result("DASHBOARD_GENERATION", False, "Dashboard file not created")
                return False
            
            # Basic validation of dashboard content
            content = dashboard_file.read_text()
            required_elements = ['<html', '<head', '<body', 'dashboard']
            missing_elements = [elem for elem in required_elements if elem not in content]
            
            if missing_elements:
                self.add_result("DASHBOARD_GENERATION", False, f"Missing HTML elements: {missing_elements}")
                return False
            
            self.add_result("DASHBOARD_GENERATION", True, f"Generated dashboard: {dashboard_file.name}")
            return True
            
        except Exception as e:
            self.add_result("DASHBOARD_GENERATION", False, f"Error generating dashboard: {e}")
            return False
    
    def run_all_tests(self):
        """Run all dashboard tests"""
        print("🧪 Running Dashboard Test Suite")
        print("=" * 50)
        
        # Step 1: Generate or find test run
        if not self.generate_test_run():
            return False
        
        # Step 2: Find test run directory
        run_dir = self.find_test_run_directory()
        if not run_dir:
            return False
        
        # Step 3: Test log analyzer
        analysis = self.test_log_analyzer(run_dir)
        if not analysis:
            return False
        
        # Step 4: Test dashboard generation
        if not self.test_dashboard_generation(run_dir, analysis):
            return False
        
        # Summary
        passed = sum(1 for result in self.test_results if result["passed"])
        total = len(self.test_results)
        success_rate = (passed / total) * 100 if total > 0 else 0
        
        print(f"\n📊 Test Results Summary:")
        print(f"   ✅ Tests Passed: {passed}")
        print(f"   ❌ Tests Failed: {total - passed}")
        print(f"   📈 Success Rate: {success_rate:.1f}%")
        
        if success_rate == 100:
            print("🎉 All dashboard tests passed!")
            return True
        else:
            print("💥 Some dashboard tests failed!")
            return False

def main():
    """Main test execution"""
    if len(sys.argv) > 1:
        print("Available functionality:")
        print("  - Log analysis of real CVE processing runs")
        print("  - Dashboard HTML generation")
        print("  - Integration with standard runs directory")
        print("Use without arguments to run all tests")
        return
    
    test_suite = DashboardTest()
    success = test_suite.run_all_tests()
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
