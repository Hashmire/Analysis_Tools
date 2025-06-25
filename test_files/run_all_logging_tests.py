#!/usr/bin/env python3
"""
Master test runner for all logging system tests.
Runs both unit tests and integration tests for comprehensive validation.
"""

import sys
import subprocess
from pathlib import Path

def run_test_suite(script_name: str, description: str) -> bool:
    """Run a test suite and return success status."""
    print(f"\n🚀 {description}")
    print("=" * 60)
    
    script_path = Path(__file__).parent / script_name
    
    if not script_path.exists():
        print(f"❌ Test script not found: {script_path}")
        return False
    
    try:
        result = subprocess.run([sys.executable, str(script_path)], 
                              capture_output=False, 
                              text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Error running test suite: {e}")
        return False

def main():
    """Run all logging system test suites."""
    print("🧪 Comprehensive Logging System Test Suite")
    print("Testing standardized logging and reporting system")
    print("=" * 60)
    
    test_suites = [
        ("test_logging_system.py", "Complete Logging System Tests - All 53 Test Cases")
    ]
    
    passed = 0
    failed = 0
    
    for script, description in test_suites:
        if run_test_suite(script, description):
            passed += 1
            print(f"✅ {description} - PASSED")
        else:
            failed += 1
            print(f"❌ {description} - FAILED")
    
    # Overall summary
    print("\n" + "=" * 60)
    print("📊 OVERALL TEST RESULTS")
    print("=" * 60)
    print(f"✅ Test Suites Passed: {passed}")
    print(f"❌ Test Suites Failed: {failed}")
    print(f"📈 Overall Success Rate: {(passed / (passed + failed) * 100):.1f}%")
    
    if failed == 0:
        print("\n🎉 ALL LOGGING TESTS PASSED!")
        print("The standardized logging system is working correctly.")
    else:
        print(f"\n⚠️  {failed} test suite(s) failed.")
        print("Review the output above for details on what needs to be fixed.")
    
    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
