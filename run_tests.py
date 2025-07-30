#!/usr/bin/env python3
"""
Test runner for Analysis Tools
"""
import sys
import os
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

def run_tests():
    """Run all test suites"""
    test_dir = Path(__file__).parent / "test_files"
    
    test_files = [
        "test_logging_system.py",
        "test_modular_rules.py",
        "test_provenance_assistance.py",
        "test_platform_badges.py",
        "test_overlapping_ranges_comprehensive.py"
    ]
    
    print("Running Analysis Tools Test Suite")
    print("=" * 50)
    
    failed_tests = []
    
    for test_file in test_files:
        test_path = test_dir / test_file
        if test_path.exists():
            print(f"\nRunning {test_file}...")
            try:
                result = subprocess.run(
                    [sys.executable, str(test_path)],
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    failed_tests.append(test_file)
                    print(f"❌ {test_file} FAILED")
                    if result.stderr:
                        print(f"   Error: {result.stderr}")
                else:
                    print(f"✅ {test_file} PASSED")
            except Exception as e:
                failed_tests.append(test_file)
                print(f"❌ {test_file} ERROR: {e}")
        else:
            print(f"⚠️  {test_file} not found")
    
    print("\n" + "=" * 50)
    print("Running JSON test files...")
    
    json_tests = [
        "testModularRulesEnhanced.json",
        "testProvenanceAssistance.json",
        "testSourceDataConcerns.json"
    ]
    
    for json_test in json_tests:
        test_path = test_dir / json_test
        if test_path.exists():
            print(f"\nTesting with {json_test}...")
            try:
                result = subprocess.run(
                    [sys.executable, "run_tools.py", "--test-file", str(test_path)],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if result.returncode != 0:
                    failed_tests.append(json_test)
                    print(f"❌ {json_test} FAILED")
                else:
                    print(f"✅ {json_test} PASSED")
            except subprocess.TimeoutExpired:
                failed_tests.append(json_test)
                print(f"❌ {json_test} TIMEOUT")
            except Exception as e:
                failed_tests.append(json_test)
                print(f"❌ {json_test} ERROR: {e}")
    
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    
    total_tests = len(test_files) + len(json_tests)
    passed_tests = total_tests - len(failed_tests)
    
    print(f"Total tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {len(failed_tests)}")
    
    if failed_tests:
        print("\nFailed tests:")
        for test in failed_tests:
            print(f"  - {test}")
        sys.exit(1)
    else:
        print("\n✅ All tests passed!")
        sys.exit(0)

if __name__ == "__main__":
    run_tests()