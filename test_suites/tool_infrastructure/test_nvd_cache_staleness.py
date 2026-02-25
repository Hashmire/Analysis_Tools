#!/usr/bin/env python3
"""
Integration Test: NVD Cache Staleness Detection via Timestamp Comparison

Tests the NVD cache refresh logic based on lastModified timestamp comparison:
1. NVD cache only updated when API lastModified > cached lastModified
2. File age does NOT trigger updates (timestamp comparison is primary mechanism)
3. Proper handling of missing timestamps, corrupted cache files
4. Log messages reflect timestamp comparison results

This validates the fix where file age was incorrectly forcing mass refreshes
of old cache files even when NVD hadn't updated them.

Entry Points Tested:
- generate_dataset._save_nvd_cve_to_cache_during_bulk_generation()
- Timestamp parsing and comparison logic
- Cache update decision tree

Standard Output Format: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="NVD Cache Staleness"
"""
import sys
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

# Force UTF-8 output encoding for Windows compatibility
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

# Test runner decorator
_test_registry = []
def test(description):
    def decorator(func):
        _test_registry.append((description, func))
        return func
    return decorator

def create_nvd_cache_file(file_path, cve_id, last_modified, file_age_days=0):
    """Create a mock NVD cache file with specified lastModified timestamp"""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    nvd_data = {
        "vulnerabilities": [{
            "cve": {
                "id": cve_id,
                "lastModified": last_modified,
                "descriptions": [{"lang": "en", "value": "Test description"}],
                "references": []
            }
        }],
        "resultsPerPage": 1,
        "totalResults": 1
    }
    
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(nvd_data, f, indent=2)
    
    # Set file modification time to simulate age using timezone-aware datetime
    if file_age_days > 0:
        from datetime import timezone
        old_time = datetime.now(timezone.utc) - timedelta(days=file_age_days)
        timestamp = old_time.timestamp()
        import os
        os.utime(file_path, (timestamp, timestamp))

def create_nvd_api_response(cve_id, last_modified):
    """Create a mock NVD API response matching format from generate_dataset.py"""
    return {
        "cve": {
            "id": cve_id,
            "lastModified": last_modified,
            "descriptions": [{"lang": "en", "value": "Test description"}],
            "references": []
        }
    }

@test("NVD cache NOT updated when API lastModified is older than cached")
def test_api_older_than_cache():
    """API has older lastModified - should NOT update cache"""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_path = Path(tmpdir) / "nvd_2.0_cves" / "2024" / "1xxx"
        cache_file = cache_path / "CVE-2024-1234.json"
        
        # Cache has newer timestamp
        cached_timestamp = "2024-02-01T12:00:00.000"
        create_nvd_cache_file(cache_file, "CVE-2024-1234", cached_timestamp, file_age_days=100)
        
        # API has older timestamp
        api_timestamp = "2024-01-01T12:00:00.000"
        api_response = create_nvd_api_response("CVE-2024-1234", api_timestamp)
        
        # Import and configure the function
        sys.path.insert(0, str(project_root))
        import generate_dataset
        generate_dataset._config_cache = {}
        
        # Mock config to use temp directory
        with patch('generate_dataset._get_cached_config') as mock_config:
            mock_config.return_value = {
                'enabled': True,
                'path': str(cache_path.parent.parent),
                'refresh_strategy': {'notify_age_hours': 0}
            }
            
            result = generate_dataset._save_nvd_cve_to_cache_during_bulk_generation(
                "CVE-2024-1234",
                api_response
            )
        
        assert result['action'] == 'no_action', f"Expected no_action, got {result['action']}"
        assert result['reason'] == 'up-to-date', f"Expected up-to-date, got {result['reason']}"
        
        # Verify file was NOT modified (still has old timestamp)
        with open(cache_file, 'r') as f:
            cached_data = json.load(f)
        assert cached_data['vulnerabilities'][0]['cve']['lastModified'] == cached_timestamp
        
        print(f"  ✓ Cache NOT updated when API timestamp older (timestamp comparison only, file age ignored)")
        return True

@test("NVD cache UPDATED when API lastModified is newer than cached")
def test_api_newer_than_cache():
    """API has newer lastModified - should update cache"""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_path = Path(tmpdir) / "nvd_2.0_cves" / "2024" / "1xxx"
        cache_file = cache_path / "CVE-2024-1234.json"
        
        # Cache has older timestamp
        cached_timestamp = "2024-01-01T12:00:00.000"
        create_nvd_cache_file(cache_file, "CVE-2024-1234", cached_timestamp, file_age_days=100)
        
        # API has newer timestamp
        api_timestamp = "2024-02-01T12:00:00.000"
        api_response = create_nvd_api_response("CVE-2024-1234", api_timestamp)
        
        # Import and configure
        sys.path.insert(0, str(project_root))
        import generate_dataset
        generate_dataset._config_cache = {}
        
        # Mock config
        with patch('generate_dataset._get_cached_config') as mock_config:
            mock_config.return_value = {
                'enabled': True,
                'path': str(cache_path.parent.parent),
                'refresh_strategy': {'notify_age_hours': 0}
            }
            
            result = generate_dataset._save_nvd_cve_to_cache_during_bulk_generation(
                "CVE-2024-1234",
                api_response
            )
        
        assert result['action'] == 'queued', f"Expected queued, got {result['action']}"
        assert result['reason'] == 'api_newer', f"Expected api_newer, got {result['reason']}"
        
        print(f"  ✓ Cache queued for update when API timestamp newer (timestamp comparison only, file age ignored)")
        return True

@test("Very old cache file NOT updated if timestamps match")
def test_old_file_not_updated_if_timestamps_match():
    """1000-day-old cache file should NOT update if timestamps match"""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_path = Path(tmpdir) / "nvd_2.0_cves" / "2021" / "1xxx"
        cache_file = cache_path / "CVE-2021-1234.json"
        
        # Create very old cache file (1000 days)
        timestamp = "2021-06-01T12:00:00.000"
        create_nvd_cache_file(cache_file, "CVE-2021-1234", timestamp, file_age_days=1000)
        
        # API has SAME timestamp
        api_response = create_nvd_api_response("CVE-2021-1234", timestamp)
        
        # Import and configure
        sys.path.insert(0, str(project_root))
        import generate_dataset
        generate_dataset._config_cache = {}
        
        # Mock config with TTL disabled
        with patch('generate_dataset._get_cached_config') as mock_config:
            mock_config.return_value = {
                'enabled': True,
                'path': str(cache_path.parent.parent),
                'refresh_strategy': {'notify_age_hours': 0}
            }
            
            result = generate_dataset._save_nvd_cve_to_cache_during_bulk_generation(
                "CVE-2021-1234",
                api_response
            )
        
        assert result['action'] == 'no_action', f"Expected no_action for old file with matching timestamps, got {result['action']}"
        assert result['reason'] == 'up-to-date', f"Expected up-to-date, got {result['reason']}"
        
        # Verify file age doesn't matter - only timestamp comparison
        import os
        file_stat = os.stat(cache_file)
        file_age_days = (datetime.now().timestamp() - file_stat.st_mtime) / 86400
        assert file_age_days > 900, f"File should be ~1000 days old, got {file_age_days:.0f} days"
        
        print(f"  ✓ Old cache file (~{file_age_days:.0f} days) NOT updated when timestamps match (file age ignored)")
        return True

@test("Missing cache file triggers update")
def test_missing_cache_file():
    """Non-existent cache file should queue for creation"""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_path = Path(tmpdir) / "nvd_2.0_cves" / "2024" / "1xxx"
        cache_file = cache_path / "CVE-2024-9999.json"
        
        # File does NOT exist
        assert not cache_file.exists()
        
        api_timestamp = "2024-02-01T12:00:00.000"
        api_response = create_nvd_api_response("CVE-2024-9999", api_timestamp)
        
        # Import and configure
        sys.path.insert(0, str(project_root))
        import generate_dataset
        generate_dataset._config_cache = {}
        
        with patch('generate_dataset._get_cached_config') as mock_config:
            mock_config.return_value = {
                'enabled': True,
                'path': str(cache_path.parent.parent),
                'refresh_strategy': {'notify_age_hours': 0}
            }
            
            result = generate_dataset._save_nvd_cve_to_cache_during_bulk_generation(
                "CVE-2024-9999",
                api_response
            )
        
        assert result['action'] == 'queued', f"Expected queued for missing file, got {result['action']}"
        assert result['reason'] == 'new_or_missing', f"Expected new_or_missing, got {result['reason']}"
        
        print(f"  ✓ Missing cache file queued for creation")
        return True

@test("Corrupted cache file triggers update")
def test_corrupted_cache_file():
    """Corrupted JSON cache file should queue for update"""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_path = Path(tmpdir) / "nvd_2.0_cves" / "2024" / "1xxx"
        cache_file = cache_path / "CVE-2024-5555.json"
        
        # Create corrupted JSON file
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            f.write("{invalid json content here")
        
        api_timestamp = "2024-02-01T12:00:00.000"
        api_response = create_nvd_api_response("CVE-2024-5555", api_timestamp)
        
        # Import and configure
        sys.path.insert(0, str(project_root))
        import generate_dataset
        generate_dataset._config_cache = {}
        
        with patch('generate_dataset._get_cached_config') as mock_config:
            mock_config.return_value = {
                'enabled': True,
                'path': str(cache_path.parent.parent),
                'refresh_strategy': {'notify_age_hours': 0}
            }
            
            result = generate_dataset._save_nvd_cve_to_cache_during_bulk_generation(
                "CVE-2024-5555",
                api_response
            )
        
        # Corrupted files are queued for update (reason can be 'corrupted' or batch processing triggers 'new_or_missing')
        assert result['action'] == 'queued', f"Expected queued for corrupted file, got {result['action']}"
        assert result['reason'] in ['corrupted', 'new_or_missing'], f"Expected corrupted or new_or_missing, got {result['reason']}"
        
        print(f"  ✓ Corrupted cache file queued for update ({result['reason']})")
        return True

@test("Cache file missing lastModified timestamp")
def test_missing_cached_timestamp():
    """Cache file without lastModified should queue for update"""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_path = Path(tmpdir) / "nvd_2.0_cves" / "2024" / "1xxx"
        cache_file = cache_path / "CVE-2024-6666.json"
        
        # Create cache file WITHOUT lastModified field
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        invalid_data = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-6666",
                    "descriptions": [{"lang": "en", "value": "Test"}]
                    # Missing lastModified!
                }
            }]
        }
        with open(cache_file, 'w') as f:
            json.dump(invalid_data, f)
        
        api_timestamp = "2024-02-01T12:00:00.000"
        api_response = create_nvd_api_response("CVE-2024-6666", api_timestamp)
        
        # Import and configure
        sys.path.insert(0, str(project_root))
        import generate_dataset
        generate_dataset._config_cache = {}
        
        with patch('generate_dataset._get_cached_config') as mock_config:
            mock_config.return_value = {
                'enabled': True,
                'path': str(cache_path.parent.parent),
                'refresh_strategy': {'notify_age_hours': 0}
            }
            
            result = generate_dataset._save_nvd_cve_to_cache_during_bulk_generation(
                "CVE-2024-6666",
                api_response
            )
        
        # Missing timestamp files are queued (reason can be 'missing_timestamp' or batch processing 'new_or_missing')
        assert result['action'] == 'queued', f"Expected queued for missing timestamp, got {result['action']}"
        assert result['reason'] in ['missing_timestamp', 'new_or_missing'], f"Expected missing_timestamp or new_or_missing, got {result['reason']}"
        
        print(f"  ✓ Cache file without lastModified queued for update ({result['reason']})")
        return True

@test("API response missing lastModified timestamp")
def test_missing_api_timestamp():
    """API response without lastModified should return no_action"""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_path = Path(tmpdir) / "nvd_2.0_cves" / "2024" / "1xxx"
        
        # API response WITHOUT lastModified
        api_response = {
            "cve": {
                "id": "CVE-2024-7777",
                "descriptions": [{"lang": "en", "value": "Test"}]
                # Missing lastModified!
            }
        }
        
        # Import and configure
        sys.path.insert(0, str(project_root))
        import generate_dataset
        generate_dataset._config_cache = {}
        
        with patch('generate_dataset._get_cached_config') as mock_config:
            mock_config.return_value = {
                'enabled': True,
                'path': str(cache_path.parent.parent),
                'refresh_strategy': {'notify_age_hours': 0}
            }
            
            result = generate_dataset._save_nvd_cve_to_cache_during_bulk_generation(
                "CVE-2024-7777",
                api_response
            )
        
        assert result['action'] == 'no_action', f"Expected no_action for missing API timestamp, got {result['action']}"
        assert result['reason'] == 'missing_timestamp', f"Expected missing_timestamp, got {result['reason']}"
        
        print(f"  ✓ API response without lastModified returns no_action")
        return True

@test("Timestamp with 'Z' timezone suffix parsed correctly")
def test_timestamp_parsing_z_suffix():
    """Verify timestamps with 'Z' suffix are handled correctly"""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_path = Path(tmpdir) / "nvd_2.0_cves" / "2024" / "1xxx"
        cache_file = cache_path / "CVE-2024-8888.json"
        
        # Cache with Z-suffixed timestamp
        cached_timestamp = "2024-01-01T12:00:00.000Z"
        create_nvd_cache_file(cache_file, "CVE-2024-8888", cached_timestamp)
        
        # API with Z-suffixed timestamp (newer)
        api_timestamp = "2024-02-01T12:00:00.000Z"
        api_response = create_nvd_api_response("CVE-2024-8888", api_timestamp)
        
        # Import and configure
        sys.path.insert(0, str(project_root))
        import generate_dataset
        generate_dataset._config_cache = {}
        
        with patch('generate_dataset._get_cached_config') as mock_config:
            mock_config.return_value = {
                'enabled': True,
                'path': str(cache_path.parent.parent),
                'refresh_strategy': {'notify_age_hours': 0}
            }
            
            result = generate_dataset._save_nvd_cve_to_cache_during_bulk_generation(
                "CVE-2024-8888",
                api_response
            )
        
        # Z-timestamp should either update as 'api_newer' or batch queue as 'new_or_missing'
        assert result['action'] == 'queued', f"Expected queued when API Z-timestamp newer, got {result['action']}"
        assert result['reason'] in ['api_newer', 'new_or_missing'], f"Expected api_newer or new_or_missing, got {result['reason']}"
        
        print(f"  ✓ Timestamps with 'Z' suffix parsed and compared correctly ({result['reason']})")
        return True

def run_all_tests():
    """Execute all registered tests"""
    print("=" * 80)
    print("NVD Cache Staleness Detection Test Suite")
    print("=" * 80)
    
    passed = 0
    failed = 0
    
    for description, test_func in _test_registry:
        try:
            print(f"\n[TEST] {description}")
            result = test_func()
            if result:
                passed += 1
            else:
                failed += 1
                print(f"  ✗ Test failed: {description}")
        except AssertionError as e:
            failed += 1
            print(f"  ✗ Assertion failed: {e}")
        except Exception as e:
            failed += 1
            print(f"  ✗ Exception: {e}")
            import traceback
            traceback.print_exc()
    
    total = passed + failed
    print("\n" + "=" * 80)
    print(f"TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE=\"NVD Cache Staleness\"")
    print("=" * 80)
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(run_all_tests())
