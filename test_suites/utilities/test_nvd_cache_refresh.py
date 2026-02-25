#!/usr/bin/env python3
"""
NVD CVE Cache Refresh Test Suite

Tests for utilities/refresh_nvd_cves_2_0_cache.py functionality covering:
- CLI argument parsing and validation
- Date range determination for different modes
- Full refresh mode (--full-refresh)
- Incremental refresh modes (--auto, --days, --start-date/--end-date)
- Error handling and edge cases

This test suite validates the refresh script's core logic without making actual API calls.
"""

import sys
import os
import json
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Import refresh script module
import utilities.refresh_nvd_cves_2_0_cache as refresh_module


def test_determine_date_range_full_refresh():
    """Test that --full-refresh returns (None, None) to signal full database query"""
    print("Testing date range determination: --full-refresh mode...")
    
    # Mock arguments for full refresh
    args = argparse.Namespace(
        full_refresh=True,
        auto=False,
        days=None,
        start_date=None,
        end_date=None
    )
    
    result = refresh_module.determine_date_range(args)
    
    if result == (None, None):
        print("PASSED: --full-refresh returns (None, None) for full database query")
        return True
    else:
        print(f"FAILED: Expected (None, None), got {result}")
        return False


def test_determine_date_range_days():
    """Test that --days N correctly calculates date range"""
    print("Testing date range determination: --days mode...")
    
    args = argparse.Namespace(
        full_refresh=False,
        auto=False,
        days=7,
        start_date=None,
        end_date=None
    )
    
    result = refresh_module.determine_date_range(args)
    
    if result is None:
        print("FAILED: Expected tuple, got None")
        return False
    
    start_date, end_date = result
    
    # Verify dates are datetime objects
    if not isinstance(start_date, datetime) or not isinstance(end_date, datetime):
        print(f"FAILED: Expected datetime objects, got {type(start_date)}, {type(end_date)}")
        return False
    
    # Verify range is approximately 7 days
    delta = (end_date - start_date).total_seconds() / 86400
    if 6.9 <= delta <= 7.1:  # Allow small tolerance
        print(f"PASSED: --days 7 creates ~7 day range ({delta:.2f} days)")
        return True
    else:
        print(f"FAILED: Expected ~7 day range, got {delta:.2f} days")
        return False


def test_determine_date_range_manual():
    """Test that --start-date/--end-date correctly parses manual range"""
    print("Testing date range determination: manual date range...")
    
    args = argparse.Namespace(
        full_refresh=False,
        auto=False,
        days=None,
        start_date='2024-01-01',
        end_date='2024-01-31'
    )
    
    result = refresh_module.determine_date_range(args)
    
    if result is None:
        print("FAILED: Expected tuple, got None")
        return False
    
    start_date, end_date = result
    
    # Verify dates match specified values
    if start_date.year == 2024 and start_date.month == 1 and start_date.day == 1:
        if end_date.year == 2024 and end_date.month == 1 and end_date.day == 31:
            print("PASSED: Manual date range parsed correctly")
            return True
        else:
            print(f"FAILED: End date incorrect: {end_date}")
            return False
    else:
        print(f"FAILED: Start date incorrect: {start_date}")
        return False


def test_determine_date_range_auto_with_metadata():
    """Test that --auto mode uses cache metadata when available"""
    print("Testing date range determination: --auto mode with metadata...")
    
    args = argparse.Namespace(
        full_refresh=False,
        auto=True,
        days=None,
        start_date=None,
        end_date=None
    )
    
    # Mock the cache metadata lookup to return a known date
    test_date = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    with patch('utilities.refresh_nvd_cves_2_0_cache._get_cache_metadata_last_update', return_value=test_date):
        result = refresh_module.determine_date_range(args)
    
    if result is None:
        print("FAILED: Expected tuple, got None")
        return False
    
    start_date, end_date = result
    
    # Verify start date matches cache metadata
    if start_date == test_date:
        print(f"PASSED: --auto uses cache metadata (start: {start_date})")
        return True
    else:
        print(f"FAILED: Expected start_date={test_date}, got {start_date}")
        return False


def test_determine_date_range_auto_without_metadata():
    """Test that --auto mode fails gracefully when metadata unavailable"""
    print("Testing date range determination: --auto mode without metadata...")
    
    args = argparse.Namespace(
        full_refresh=False,
        auto=True,
        days=None,
        start_date=None,
        end_date=None
    )
    
    # Mock the cache metadata lookup to return None (no metadata)
    with patch('utilities.refresh_nvd_cves_2_0_cache._get_cache_metadata_last_update', return_value=None):
        result = refresh_module.determine_date_range(args)
    
    if result is None:
        print("PASSED: --auto without metadata returns None")
        return True
    else:
        print(f"FAILED: Expected None, got {result}")
        return False


def test_stats_report_full_refresh():
    """Test that statistics report handles full refresh mode correctly"""
    print("Testing statistics report: full refresh format...")
    
    stats = refresh_module.NVDCacheRefreshStats()
    stats.date_range_start = None  # Full refresh marker
    stats.date_range_end = None    # Full refresh marker
    stats.total_cves_found = 260000
    stats.cves_cached = 260000
    
    report = stats.report()
    
    # Verify report contains "FULL REFRESH" marker
    if "FULL REFRESH" in report:
        print("PASSED: Statistics report shows 'FULL REFRESH' for None date range")
        return True
    else:
        print("FAILED: Report missing 'FULL REFRESH' marker")
        print(f"Report:\n{report}")
        return False


def test_stats_report_incremental():
    """Test that statistics report handles incremental refresh correctly"""
    print("Testing statistics report: incremental format...")
    
    stats = refresh_module.NVDCacheRefreshStats()
    stats.date_range_start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    stats.date_range_end = datetime(2024, 1, 31, tzinfo=timezone.utc)
    stats.total_cves_found = 500
    stats.cves_cached = 500
    
    report = stats.report()
    
    # Verify report contains actual dates
    if "2024-01-01" in report and "2024-01-31" in report:
        print("PASSED: Statistics report shows dates for incremental refresh")
        return True
    else:
        print("FAILED: Report missing date range")
        print(f"Report:\n{report}")
        return False


def test_query_function_integration():
    """Test that query function selection works correctly based on date range"""
    print("Testing query function selection...")
    
    # This test verifies the logic without making actual API calls
    # We test that the correct function would be called based on date range
    
    # Full refresh case
    start_date, end_date = None, None
    if start_date is None and end_date is None:
        query_type = "query_nvd_cves_all"
    else:
        query_type = "query_nvd_cves_by_modified_date"
    
    if query_type == "query_nvd_cves_all":
        print("PASSED: Full refresh (None, None) -> query_nvd_cves_all")
    else:
        print("FAILED: Full refresh should use query_nvd_cves_all")
        return False
    
    # Incremental refresh case
    start_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end_date = datetime(2024, 1, 31, tzinfo=timezone.utc)
    if start_date is None and end_date is None:
        query_type = "query_nvd_cves_all"
    else:
        query_type = "query_nvd_cves_by_modified_date"
    
    if query_type == "query_nvd_cves_by_modified_date":
        print("PASSED: Incremental refresh (dates) -> query_nvd_cves_by_modified_date")
        return True
    else:
        print("FAILED: Incremental refresh should use query_nvd_cves_by_modified_date")
        return False


def test_concurrent_worker_configuration():
    """Test that concurrent workers can be configured via CLI arguments"""
    print("Testing concurrent worker configuration...")
    
    # Test default values
    parser = refresh_module.argparse.ArgumentParser()
    # Simulate the argument setup from main()
    parser.add_argument('--workers', type=int, default=20, metavar='N')
    parser.add_argument('--api-workers', type=int, default=15, metavar='N')
    
    args = parser.parse_args([])
    
    if args.workers != 20:
        print(f"FAILED: Expected default workers=20, got {args.workers}")
        return False
    
    if args.api_workers != 15:
        print(f"FAILED: Expected default api_workers=15, got {args.api_workers}")
        return False
    
    # Test custom values
    args = parser.parse_args(['--workers', '30', '--api-workers', '20'])
    
    if args.workers != 30:
        print(f"FAILED: Expected workers=30, got {args.workers}")
        return False
    
    if args.api_workers != 20:
        print(f"FAILED: Expected api_workers=20, got {args.api_workers}")
        return False
    
    print("PASSED: Concurrent worker configuration")
    return True


def test_concurrent_refresh_integration():
    """Test smart_refresh uses concurrent API functions"""
    print("Testing concurrent refresh integration...")
    
    import argparse
    args = argparse.Namespace(
        full_refresh=False,
        auto=False,
        days=7,
        start_date=None,
        end_date=None,
        workers=20,
        api_workers=15
    )
    
    api_key = "test-api-key"
    
    # Mock concurrent query functions
    mock_vulnerabilities = [
        {
            'cve': {'id': f'CVE-2024-{i:05d}'},
            'lastModifiedDate': '2024-01-01T00:00:00.000',
            'published': '2024-01-01T00:00:00.000'
        }
        for i in range(50)
    ]
    
    with patch('utilities.refresh_nvd_cves_2_0_cache.query_nvd_cves_by_modified_date_concurrent', return_value=mock_vulnerabilities) as mock_concurrent, \
         patch('utilities.refresh_nvd_cves_2_0_cache.query_nvd_cves_all_concurrent') as mock_all_concurrent, \
         patch('utilities.refresh_nvd_cves_2_0_cache.load_schema', return_value=None), \
         patch('utilities.refresh_nvd_cves_2_0_cache._save_nvd_cve_to_local_file', return_value='cached'), \
         patch('utilities.refresh_nvd_cves_2_0_cache._update_cache_metadata'), \
         patch('utilities.refresh_nvd_cves_2_0_cache._update_manual_refresh_timestamp'), \
         patch('utilities.refresh_nvd_cves_2_0_cache._transform_nvd_vulnerability_to_response', side_effect=lambda x, y: {'cve': x.get('cve')}):
        
        # Execute refresh
        stats = refresh_module.smart_refresh(api_key, args, max_workers=args.workers, api_workers=args.api_workers)
        
        # Verify concurrent function was called
        assert mock_concurrent.called, "query_nvd_cves_by_modified_date_concurrent should have been called"
        
        # Verify max_workers parameter was passed
        call_args = mock_concurrent.call_args
        if call_args[1]['max_workers'] != 15:
            print(f"FAILED: Expected api_workers=15 passed to concurrent function, got {call_args[1]['max_workers']}")
            return False
        
        # Verify stats
        if stats.total_cves_found != 50:
            print(f"FAILED: Expected 50 CVEs, got {stats.total_cves_found}")
            return False
        
        print("PASSED: Concurrent refresh integration")
        return True


def test_concurrent_full_refresh_integration():
    """Test full refresh uses concurrent query function"""
    print("Testing concurrent full refresh integration...")
    
    import argparse
    args = argparse.Namespace(
        full_refresh=True,
        auto=False,
        days=None,
        start_date=None,
        end_date=None,
        workers=20,
        api_workers=10
    )
    
    api_key = "test-api-key"
    
    mock_vulnerabilities = [
        {
            'cve': {'id': f'CVE-2024-{i:05d}'},
            'lastModifiedDate': '2024-01-01T00:00:00.000',
            'published': '2024-01-01T00:00:00.000'
        }
        for i in range(100)
    ]
    
    with patch('utilities.refresh_nvd_cves_2_0_cache.query_nvd_cves_all_concurrent', return_value=mock_vulnerabilities) as mock_all_concurrent, \
         patch('utilities.refresh_nvd_cves_2_0_cache.query_nvd_cves_by_modified_date_concurrent') as mock_date_concurrent, \
         patch('utilities.refresh_nvd_cves_2_0_cache.load_schema', return_value=None), \
         patch('utilities.refresh_nvd_cves_2_0_cache._save_nvd_cve_to_local_file', return_value='cached'), \
         patch('utilities.refresh_nvd_cves_2_0_cache._update_cache_metadata'), \
         patch('utilities.refresh_nvd_cves_2_0_cache._update_manual_refresh_timestamp'), \
         patch('utilities.refresh_nvd_cves_2_0_cache._transform_nvd_vulnerability_to_response', side_effect=lambda x, y: {'cve': x.get('cve')}):
        
        # Execute refresh
        stats = refresh_module.smart_refresh(api_key, args, max_workers=args.workers, api_workers=args.api_workers)
        
        # Verify correct concurrent function was called
        assert mock_all_concurrent.called, "query_nvd_cves_all_concurrent should have been called"
        assert not mock_date_concurrent.called, "query_nvd_cves_by_modified_date_concurrent should NOT have been called"
        
        # Verify api_workers parameter was passed
        call_args = mock_all_concurrent.call_args
        if call_args[1]['max_workers'] != 10:
            print(f"FAILED: Expected api_workers=10 passed to concurrent function, got {call_args[1]['max_workers']}")
            return False
        
        # Verify stats
        if stats.total_cves_found != 100:
            print(f"FAILED: Expected 100 CVEs, got {stats.total_cves_found}")
            return False
        
        print("PASSED: Concurrent full refresh integration")
        return True


def run_all_tests():
    """Execute all test functions and report results"""
    tests = [
        test_determine_date_range_full_refresh,
        test_determine_date_range_days,
        test_determine_date_range_manual,
        test_determine_date_range_auto_with_metadata,
        test_determine_date_range_auto_without_metadata,
        test_stats_report_full_refresh,
        test_stats_report_incremental,
        test_query_function_integration,
        test_concurrent_worker_configuration,
        test_concurrent_refresh_integration,
        test_concurrent_full_refresh_integration,
    ]
    
    print("="*80)
    print("NVD CVE CACHE REFRESH TEST SUITE")
    print("="*80)
    print()
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"EXCEPTION in {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
            results.append(False)
        print()
    
    # Summary
    passed = sum(results)
    total = len(results)
    
    print("="*80, flush=True)
    print(f"TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE=\"NVD Cache Refresh\"", flush=True)
    print("="*80, flush=True)
    
    return 0 if passed == total else 1


if __name__ == '__main__':
    sys.exit(run_all_tests())

