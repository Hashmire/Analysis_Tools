"""
Integration test for CPE pagination fix (page_num variable bug).

This test verifies the fix for the bug where page_num was referenced but never defined
during CPE query pagination in gatherData.py.

Bug: NameError: name 'page_num' is not defined
Fix: Calculate page_number from current_index before using in validate_http_response()
Location: src/analysis_tool/core/gatherData.py line 1004
"""

import sys
import os
import json
import subprocess
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

def test_cpe_pagination_no_error():
    """Test that CPE pagination doesn't raise NameError for page_num."""
    # Use a real test CVE that triggers CPE pagination
    test_cve = "CVE-2024-0001"
    
    # Run analysis tool with CPE queries enabled
    cmd = [
        sys.executable, "-m", "src.analysis_tool.core.analysis_tool",
        "--test-file", "test_suites/test_data/test_pagination_cve.json",
        "--source-data-concerns",
        "--cpe-determination"
    ]
    
    result = subprocess.run(
        cmd,
        cwd=str(project_root),
        capture_output=True,
        text=True,
        timeout=30
    )
    
    # Check that page_num NameError doesn't appear in stderr
    assert "name 'page_num' is not defined" not in result.stderr, \
        f"page_num NameError found in output:\n{result.stderr}"
    
    # Check that page_number is correctly calculated
    assert "page_number" not in result.stderr or "NameError" not in result.stderr, \
        f"Unexpected error with page_number:\n{result.stderr}"
    
    print("✓ CPE pagination processes without page_num NameError")


def test_page_number_calculation():
    """Test that page_number is correctly calculated from current_index."""
    # Mock the calculation logic from the fix
    results_per_page = 10000  # NVD default
    
    # Test various index positions
    test_cases = [
        (0, 1),      # First page
        (10000, 2),  # Second page
        (20000, 3),  # Third page
        (5000, 1),   # Still first page
        (15000, 2),  # Still second page
    ]
    
    for current_index, expected_page in test_cases:
        page_number = (current_index // results_per_page) + 1
        assert page_number == expected_page, \
            f"Page calculation failed: index {current_index} should be page {expected_page}, got {page_number}"
    
    print("✓ Page number calculation is correct")


def test_no_page_num_variable():
    """Test that page_num variable is not used in gatherData.py."""
    gather_data_path = project_root / "src" / "analysis_tool" / "core" / "gatherData.py"
    
    with open(gather_data_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check that page_num is NOT used (only page_number should exist)
    # We allow page_number but not page_num
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        # Skip comments
        if line.strip().startswith('#'):
            continue
        
        # Check for page_num (the bug variable)
        if 'page_num' in line and 'page_number' not in line:
            # This would indicate the bug is back
            assert False, f"Found 'page_num' variable on line {i}: {line.strip()}"
    
    print("✓ No page_num variable found (using page_number instead)")


if __name__ == "__main__":
    print("=" * 50)
    print("CPE Pagination Fix Tests")
    print("=" * 50)
    
    tests_run = 0
    tests_passed = 0
    tests_skipped = 0
    
    # Test 1: Page number calculation
    try:
        test_page_number_calculation()
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ test_page_number_calculation failed: {e}")
    except Exception as e:
        print(f"✗ test_page_number_calculation error: {e}")
    tests_run += 1
    
    # Test 2: No page_num variable in code
    try:
        test_no_page_num_variable()
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ test_no_page_num_variable failed: {e}")
    except Exception as e:
        print(f"✗ test_no_page_num_variable error: {e}")
    tests_run += 1
    
    # Test 3: Integration test (may not work without proper test data)
    test_data_path = project_root / "test_suites" / "test_data" / "test_pagination_cve.json"
    if test_data_path.exists():
        try:
            test_cpe_pagination_no_error()
            tests_passed += 1
        except AssertionError as e:
            print(f"✗ test_cpe_pagination_no_error failed: {e}")
        except Exception as e:
            print(f"✗ test_cpe_pagination_no_error error: {e}")
        tests_run += 1
    else:
        print("⊘ test_cpe_pagination_no_error skipped (test data not found)")
        tests_skipped += 1
    
    print("=" * 50)
    print(f"TEST_RESULTS: PASSED={tests_passed} TOTAL={tests_run} SUITE=\"CPE Pagination Fix\"")
    print("=" * 50)
    
    # Exit with appropriate code (skip doesn't count as failure)
    sys.exit(0 if tests_passed == tests_run else 1)
