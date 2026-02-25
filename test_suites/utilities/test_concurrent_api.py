#!/usr/bin/env python3
"""
Concurrent API Test Suite

Tests for concurrent NVD API query functionality including:
- NVDRateLimiter: Thread-safe rate limiting with safety buffer
- Concurrent query functions: query_nvd_cves_concurrent, query_nvd_cves_by_modified_date_concurrent
- Error handling: Fail-fast behavior on API failures
- Rate limit enforcement: Smooth pacing and buffer adherence

This test suite validates the concurrent implementation without making actual API calls.
"""

import sys
import os
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from concurrent.futures import ThreadPoolExecutor

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Import modules under test
from src.analysis_tool.core.gatherData import (
    NVDRateLimiter,
    query_nvd_cves_concurrent,
    query_nvd_cves_by_modified_date_concurrent,
    query_nvd_cves_all_concurrent
)
from src.analysis_tool.logging.workflow_logger import get_logger

# Get logger instance for test output
logger = get_logger()


def test_rate_limiter_initialization():
    """Test NVDRateLimiter initialization with proper buffer calculation"""
    print("Testing rate limiter initialization...")
    
    # Test with default parameters (50 req/30s with 10% buffer)
    limiter = NVDRateLimiter(max_requests=50, window_seconds=30, buffer_percent=0.10)
    
    # Verify effective limit calculation
    expected_effective = int(50 * 0.9)  # 45 with 10% buffer
    if limiter.effective_limit != expected_effective:
        print(f"FAILED: Expected effective_limit={expected_effective}, got {limiter.effective_limit}")
        return False
    
    # Verify minimum spacing calculation
    expected_spacing = 30 / 45  # ~0.667 seconds
    if abs(limiter.min_spacing - expected_spacing) > 0.001:
        print(f"FAILED: Expected min_spacing={expected_spacing:.3f}, got {limiter.min_spacing:.3f}")
        return False
    
    logger.info(f"Rate limiter initialized correctly: effective={limiter.effective_limit}, spacing={limiter.min_spacing:.3f}s", group="TEST")
    print("PASSED: Rate limiter initialization")
    return True


def test_rate_limiter_single_threaded():
    """Test basic rate limiter acquire behavior in single-threaded context"""
    print("Testing rate limiter single-threaded acquire...")
    
    # Use small values for fast testing
    # 5 req/2s with 0% buffer = min_spacing of 0.4s
    limiter = NVDRateLimiter(max_requests=5, window_seconds=2, buffer_percent=0.0)
    
    start_time = time.time()
    acquired_times = []
    
    # Acquire 5 permits (will be paced at 0.4s intervals)
    for i in range(5):
        success = limiter.acquire(blocking=True)
        if not success:
            print(f"FAILED: Failed to acquire permit {i+1}")
            return False
        acquired_times.append(time.time() - start_time)
    
    # Verify all acquired with proper pacing (5 permits × 0.4s = ~1.6s)
    if acquired_times[-1] > 2.0:
        print(f"FAILED: Acquiring 5 permits took {acquired_times[-1]:.2f}s (expected < 2s)")
        return False
    
    # Verify current usage
    current, max_limit = limiter.get_current_usage()
    if current != 5:
        print(f"FAILED: Expected 5 active requests, got {current}")
        return False
    
    logger.info(f"Acquired 5 permits in {acquired_times[-1]:.3f}s", group="TEST")
    print("PASSED: Rate limiter single-threaded acquire")
    return True


def test_rate_limiter_blocking_behavior():
    """Test that rate limiter blocks when limit is reached"""
    print("Testing rate limiter blocking behavior...")
    
    # Use small values for fast testing (3 req/1s with 0% buffer = 0.333s min_spacing)
    limiter = NVDRateLimiter(max_requests=3, window_seconds=1, buffer_percent=0.0)
    
    # Acquire all 3 permits (will be paced at 0.333s intervals)
    for i in range(3):
        limiter.acquire(blocking=True)
    
    # Try to acquire 4th permit (should wait for min_spacing)
    start_time = time.time()
    limiter.acquire(blocking=True)
    elapsed = time.time() - start_time
    
    # Should have waited at least min_spacing (0.333s)
    if elapsed < 0.25:  # Allow some tolerance
        print(f"FAILED: Expected blocking delay, but only waited {elapsed:.2f}s")
        return False
    
    logger.info(f"Blocked correctly for {elapsed:.2f}s when limit reached", group="TEST")
    print("PASSED: Rate limiter blocking behavior")
    return True


def test_rate_limiter_thread_safety():
    """Test rate limiter with concurrent access from multiple threads"""
    print("Testing rate limiter thread safety...")
    
    # Use reasonable limits for concurrent testing
    limiter = NVDRateLimiter(max_requests=20, window_seconds=2, buffer_percent=0.1)
    acquired_count = [0]
    lock = threading.Lock()
    
    def acquire_worker():
        """Worker function that acquires a permit"""
        success = limiter.acquire(blocking=True)
        if success:
            with lock:
                acquired_count[0] += 1
    
    # Launch 30 threads trying to acquire permits
    threads = []
    start_time = time.time()
    
    for i in range(30):
        t = threading.Thread(target=acquire_worker)
        threads.append(t)
        t.start()
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    elapsed = time.time() - start_time
    
    # Verify all 30 permits were acquired
    if acquired_count[0] != 30:
        print(f"FAILED: Expected 30 permits acquired, got {acquired_count[0]}")
        return False
    
    # Verify rate limiting occurred (should take at least 2 windows)
    if elapsed < 1.5:
        print(f"FAILED: 30 permits acquired too quickly ({elapsed:.2f}s), rate limiting may not be working")
        return False
    
    logger.info(f"30 concurrent acquires completed in {elapsed:.2f}s", group="TEST")
    print("PASSED: Rate limiter thread safety")
    return True


def test_concurrent_query_success():
    """Test query_nvd_cves_concurrent with successful API responses"""
    print("Testing concurrent query success case...")
    
    # Mock successful API responses
    def mock_api_response(url, headers, context_msg=""):
        """Return mock API data"""
        return {
            'vulnerabilities': [
                {'cve': {'id': f'CVE-2024-{i:05d}'}}
                for i in range(10)  # 10 CVEs per page
            ]
        }
    
    with patch('src.analysis_tool.core.gatherData.query_nvd_cve_page', side_effect=mock_api_response):
        # Test with 3 pages (30 total CVEs)
        limiter = NVDRateLimiter(max_requests=50, window_seconds=30, buffer_percent=0.1)
        
        result = query_nvd_cves_concurrent(
            base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            headers={"apiKey": "test-key"},
            total_results=25,  # Will fetch 2 pages (0-2000, 2000-4000) but only 25 results
            results_per_page=20,
            max_workers=3,
            rate_limiter=limiter,
            context_msg="Test Query"
        )
        
        # Verify results
        if not isinstance(result, list):
            print(f"FAILED: Expected list, got {type(result)}")
            return False
        
        if len(result) != 20:  # 2 pages × 10 CVEs each
            print(f"FAILED: Expected 20 vulnerabilities, got {len(result)}")
            return False
        
        logger.info(f"Concurrent query returned {len(result)} vulnerabilities", group="TEST")
        print("PASSED: Concurrent query success")
        return True


def test_concurrent_query_partial_failure():
    """Test query_nvd_cves_concurrent with some API failures (fail-fast behavior)"""
    print("Testing concurrent query with partial failures...")
    
    call_count = [0]
    
    def mock_api_response_with_failures(url, headers, context_msg=""):
        """Return None for second page to simulate failure"""
        call_count[0] += 1
        if 'startIndex=20' in url:  # Second page fails
            return None
        return {
            'vulnerabilities': [
                {'cve': {'id': f'CVE-2024-{i:05d}'}}
                for i in range(10)
            ]
        }
    
    with patch('src.analysis_tool.core.gatherData.query_nvd_cve_page', side_effect=mock_api_response_with_failures):
        limiter = NVDRateLimiter(max_requests=50, window_seconds=30, buffer_percent=0.1)
        
        # Should raise RuntimeError due to failed page
        try:
            result = query_nvd_cves_concurrent(
                base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers={"apiKey": "test-key"},
                total_results=25,
                results_per_page=20,
                max_workers=3,
                rate_limiter=limiter,
                context_msg="Test Query"
            )
            print("FAILED: Expected RuntimeError for failed page, but succeeded")
            return False
        except RuntimeError as e:
            # Verify error message includes failure details
            error_msg = str(e)
            if "failed" not in error_msg.lower():
                print(f"FAILED: Error message doesn't indicate failure: {error_msg}")
                return False
            
            logger.info(f"Fail-fast correctly raised RuntimeError: {error_msg}", group="TEST")
            print("PASSED: Concurrent query partial failure (fail-fast)")
            return True


def test_concurrent_date_query():
    """Test query_nvd_cves_by_modified_date_concurrent with date filtering"""
    print("Testing concurrent date-filtered query...")
    
    # Use realistic NVD page size (2000) with 4500 total results (3 pages)
    results_per_page = 2000
    
    mock_first_response = {
        'totalResults': 4500,
        'vulnerabilities': [
            {'cve': {'id': f'CVE-2024-{i:05d}'}}
            for i in range(results_per_page)
        ]
    }
    
    mock_second_response = {
        'vulnerabilities': [
            {'cve': {'id': f'CVE-2024-{i+2000:05d}'}}
            for i in range(results_per_page)
        ]
    }
    
    mock_third_response = {
        'vulnerabilities': [
            {'cve': {'id': f'CVE-2024-{i+4000:05d}'}}
            for i in range(500)  # Last page has only 500
        ]
    }
    
    # Mock sequence: initial page + 2 concurrent pages
    mock_responses = [mock_first_response, mock_second_response, mock_third_response]
    
    with patch('src.analysis_tool.core.gatherData.query_nvd_cve_page', side_effect=mock_responses):
        start_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end_date = datetime(2024, 1, 31, tzinfo=timezone.utc)
        
        result = query_nvd_cves_by_modified_date_concurrent(
            start_date=start_date,
            end_date=end_date,
            api_key="test-key",
            max_workers=5
        )
        
        # Verify results
        if not isinstance(result, list):
            print(f"FAILED: Expected list, got {type(result)}")
            return False
        
        if len(result) != 4500:  # 2000 + 2000 + 500
            print(f"FAILED: Expected 4500 vulnerabilities, got {len(result)}")
            return False
        
        logger.info(f"Date-filtered concurrent query returned {len(result)} vulnerabilities", group="TEST")
        print("PASSED: Concurrent date-filtered query")
        return True


def test_concurrent_full_database_query():
    """Test query_nvd_cves_all_concurrent for full database refresh"""
    print("Testing concurrent full database query...")
    
    # Use realistic NVD page size with 3000 total results (2 pages)
    results_per_page = 2000
    
    mock_first_response = {
        'totalResults': 3000,
        'vulnerabilities': [
            {'cve': {'id': f'CVE-2024-{i:05d}'}}
            for i in range(results_per_page)
        ]
    }
    
    mock_second_response = {
        'vulnerabilities': [
            {'cve': {'id': f'CVE-2024-{i+2000:05d}'}}
            for i in range(1000)  # Last page has 1000
        ]
    }
    
    with patch('src.analysis_tool.core.gatherData.query_nvd_cve_page', side_effect=[mock_first_response, mock_second_response]):
        result = query_nvd_cves_all_concurrent(
            api_key="test-key",
            max_workers=10
        )
        
        # Verify results
        if not isinstance(result, list):
            print(f"FAILED: Expected list, got {type(result)}")
            return False
        
        if len(result) != 3000:
            print(f"FAILED: Expected 3000 vulnerabilities, got {len(result)}")
            return False
        
        logger.info(f"Full database concurrent query returned {len(result)} vulnerabilities", group="TEST")
        print("PASSED: Concurrent full database query")
        return True


def test_rate_limiter_safety_buffer():
    """Test that safety buffer is properly enforced"""
    print("Testing rate limiter safety buffer enforcement...")
    
    # 10 req/2s with 20% buffer = 8 effective limit, min_spacing = 2s/8 = 0.25s
    limiter = NVDRateLimiter(max_requests=10, window_seconds=2, buffer_percent=0.2)
    
    if limiter.effective_limit != 8:
        print(f"FAILED: Expected effective_limit=8 (80% of 10), got {limiter.effective_limit}")
        return False
    
    # Acquire 8 permits (will be paced at 0.25s intervals = ~1.75s total)
    start_time = time.time()
    for i in range(8):
        success = limiter.acquire(blocking=True)
        if not success:
            print(f"FAILED: Could not acquire permit {i+1}/8")
            return False
    
    acquire_time = time.time() - start_time
    if acquire_time > 2.5:
        print(f"FAILED: Acquiring 8 permits took {acquire_time:.2f}s (expected < 2.5s)")
        return False
    
    # Verify usage
    current, max_limit = limiter.get_current_usage()
    if current != 8:
        print(f"FAILED: Expected 8 active requests, got {current}")
        return False
    
    if max_limit != 8:
        print(f"FAILED: Expected max_limit=8, got {max_limit}")
        return False
    
    logger.info(f"Safety buffer correctly enforced: {current}/{max_limit} (20% buffer on 10 max)", group="TEST")
    print("PASSED: Rate limiter safety buffer")
    return True


def main():
    """Run all concurrent API tests"""
    print("="*80)
    print("CONCURRENT API TEST SUITE")
    print("="*80)
    
    tests = [
        ("Rate Limiter Initialization", test_rate_limiter_initialization),
        ("Rate Limiter Single-Threaded", test_rate_limiter_single_threaded),
        ("Rate Limiter Blocking", test_rate_limiter_blocking_behavior),
        ("Rate Limiter Thread Safety", test_rate_limiter_thread_safety),
        ("Rate Limiter Safety Buffer", test_rate_limiter_safety_buffer),
        ("Concurrent Query Success", test_concurrent_query_success),
        ("Concurrent Query Fail-Fast", test_concurrent_query_partial_failure),
        ("Concurrent Date Query", test_concurrent_date_query),
        ("Concurrent Full DB Query", test_concurrent_full_database_query),
    ]
    
    results = []
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n[{len(results)+1}/{total}] {test_name}")
        try:
            result = test_func()
            results.append((test_name, result))
            if result:
                passed += 1
        except Exception as e:
            print(f"FAILED: Unexpected exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTEST_RESULTS: PASSED={passed} TOTAL={total} SUITE=\"Concurrent API\"")
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
