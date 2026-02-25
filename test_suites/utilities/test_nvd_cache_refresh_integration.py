#!/usr/bin/env python3
"""
Quick integration test to verify --full-refresh implementation
Tests the complete flow without making actual API calls
"""

import sys
from pathlib import Path
from unittest.mock import patch, Mock
from datetime import datetime, timezone

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Import the refresh module
import utilities.refresh_nvd_cves_2_0_cache as refresh_module


def test_full_refresh_integration():
    """Test complete --full-refresh flow with mocked API calls"""
    print("Testing complete --full-refresh integration...")
    
    # Create mock arguments
    import argparse
    args = argparse.Namespace(
        full_refresh=True,
        auto=False,
        days=None,
        start_date=None,
        end_date=None
    )
    
    # Mock API key
    api_key = "test-api-key"
    
    # Mock the query_nvd_cves_all function to return test data
    mock_vulnerabilities = [
        {
            'cve': {'id': f'CVE-2024-{i:05d}'},
            'lastModifiedDate': '2024-01-01T00:00:00.000',
            'published': '2024-01-01T00:00:00.000'
        }
        for i in range(100)  # Simulate 100 CVEs
    ]
    
    # Mock all the necessary functions
    with patch('utilities.refresh_nvd_cves_2_0_cache.query_nvd_cves_all', return_value=mock_vulnerabilities) as mock_query_all, \
         patch('utilities.refresh_nvd_cves_2_0_cache.query_nvd_cves_by_modified_date') as mock_query_date, \
         patch('utilities.refresh_nvd_cves_2_0_cache.load_schema', return_value=None), \
         patch('utilities.refresh_nvd_cves_2_0_cache._save_nvd_cve_to_local_file'), \
         patch('utilities.refresh_nvd_cves_2_0_cache._update_cache_metadata'), \
         patch('utilities.refresh_nvd_cves_2_0_cache._update_manual_refresh_timestamp'), \
         patch('utilities.refresh_nvd_cves_2_0_cache._transform_nvd_vulnerability_to_response', side_effect=lambda x, y: {'cve': x.get('cve')}):
        
        # Execute refresh
        stats = refresh_module.smart_refresh(api_key, args)
        
        # Verify query_nvd_cves_all was called (NOT query_nvd_cves_by_modified_date)
        assert mock_query_all.called, "query_nvd_cves_all should have been called"
        assert not mock_query_date.called, "query_nvd_cves_by_modified_date should NOT have been called"
        
        # Verify stats
        assert stats.total_cves_found == 100, f"Expected 100 CVEs, got {stats.total_cves_found}"
        assert stats.date_range_start is None, "Full refresh should have None start date"
        assert stats.date_range_end is None, "Full refresh should have None end date"
        
        print("PASSED: Full refresh integration test")
        print(f"  - query_nvd_cves_all called: {mock_query_all.call_count} time(s)")
        print(f"  - Total CVEs found: {stats.total_cves_found}")
        print(f"  - Date range: {stats.date_range_start} to {stats.date_range_end}")
        return True


def test_incremental_refresh_integration():
    """Test that incremental refresh still uses query_nvd_cves_by_modified_date"""
    print("\nTesting incremental refresh integration...")
    
    # Create mock arguments for --days 7
    import argparse
    args = argparse.Namespace(
        full_refresh=False,
        auto=False,
        days=7,
        start_date=None,
        end_date=None
    )
    
    # Mock API key
    api_key = "test-api-key"
    
    # Mock data
    mock_vulnerabilities = [
        {
            'cve': {'id': f'CVE-2024-{i:05d}'},
            'lastModifiedDate': '2024-01-01T00:00:00.000',
            'published': '2024-01-01T00:00:00.000'
        }
        for i in range(50)  # Simulate 50 CVEs
    ]
    
    # Mock all the necessary functions
    with patch('utilities.refresh_nvd_cves_2_0_cache.query_nvd_cves_all') as mock_query_all, \
         patch('utilities.refresh_nvd_cves_2_0_cache.query_nvd_cves_by_modified_date', return_value=mock_vulnerabilities) as mock_query_date, \
         patch('utilities.refresh_nvd_cves_2_0_cache.load_schema', return_value=None), \
         patch('utilities.refresh_nvd_cves_2_0_cache._save_nvd_cve_to_local_file'), \
         patch('utilities.refresh_nvd_cves_2_0_cache._update_cache_metadata'), \
         patch('utilities.refresh_nvd_cves_2_0_cache._update_manual_refresh_timestamp'), \
         patch('utilities.refresh_nvd_cves_2_0_cache._transform_nvd_vulnerability_to_response', side_effect=lambda x, y: {'cve': x.get('cve')}):
        
        # Execute refresh
        stats = refresh_module.smart_refresh(api_key, args)
        
        # Verify query_nvd_cves_by_modified_date was called (NOT query_nvd_cves_all)
        assert not mock_query_all.called, "query_nvd_cves_all should NOT have been called"
        assert mock_query_date.called, "query_nvd_cves_by_modified_date should have been called"
        
        # Verify stats
        assert stats.total_cves_found == 50, f"Expected 50 CVEs, got {stats.total_cves_found}"
        assert stats.date_range_start is not None, "Incremental refresh should have start date"
        assert stats.date_range_end is not None, "Incremental refresh should have end date"
        
        print("PASSED: Incremental refresh integration test")
        print(f"  - query_nvd_cves_by_modified_date called: {mock_query_date.call_count} time(s)")
        print(f"  - Total CVEs found: {stats.total_cves_found}")
        print(f"  - Date range: {stats.date_range_start} to {stats.date_range_end}")
        return True


if __name__ == '__main__':
    print("="*80)
    print("NVD CACHE REFRESH INTEGRATION TESTS")
    print("="*80)
    
    try:
        result1 = test_full_refresh_integration()
        result2 = test_incremental_refresh_integration()
        
        if result1 and result2:
            print("\n" + "="*80)
            print("ALL INTEGRATION TESTS PASSED")
            print("="*80)
            sys.exit(0)
        else:
            print("\n" + "="*80)
            print("SOME INTEGRATION TESTS FAILED")
            print("="*80)
            sys.exit(1)
    except Exception as e:
        print(f"\nINTEGRATION TEST FAILED WITH EXCEPTION: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
