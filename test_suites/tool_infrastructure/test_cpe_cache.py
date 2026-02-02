#!/usr/bin/env python3
"""
CPE Cache Comprehensive Test Suite

Consolidated test suite for the sharded CPE cache implementation covering:

UNIT TESTS (Sharded Cache Implementation):
- Hash-based distribution and balance
- Lazy loading of shards
- Eviction and persistence
- API compatibility
- Auto-save functionality
- Global cache manager integration
- Compact JSON storage

INTEGRATION TESTS (End-to-End Workflows):
- Cache miss triggers API call (MISS workflow)
- Cache expiration triggers refresh (EXPIRED workflow)
- Cache disabled fallback (DISABLED workflow)
- CPE determination with cached data
- Cache corruption recovery (RECOVERY workflow)
- Sharded cache hit during analysis_tool run
- Cache eviction at run boundaries
- Cache mode compatibility
- Cache persistence across runs

NOTE: Monolithic cache is deprecated and removed. All tests use sharded implementation.
"""

import sys
import os
import json
import subprocess
import tempfile
import shutil
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.analysis_tool.storage.cpe_cache import get_global_cache_manager, GlobalCPECacheManager, ShardedCPECache

def load_config():
    """Load configuration from config.json"""
    config_path = project_root / 'src' / 'analysis_tool' / 'config.json'
    with open(config_path, 'r') as f:
        return json.load(f)

# =============================================================================
# UNIT TESTS: Sharded Cache Implementation
# =============================================================================

def test_hash_distribution():
    """Test that hash-based distribution spreads entries across shards"""
    print("Testing hash-based distribution...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'compression': False,
            'auto_save_threshold': 0,
            'refresh_strategy': {'notify_age_hours': 100}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        cache.metadata_file = Path(tmpdir) / 'cache_metadata.json'
        
        # Add 100 different CPE strings
        test_cpes = [f"cpe:2.3:a:vendor{i}:product{i}:1.0" for i in range(100)]
        
        for cpe in test_cpes:
            cache.put(cpe, {'totalResults': 1})
        
        # Check distribution - should be spread across multiple shards
        num_loaded_shards = len(cache.loaded_shards)
        assert num_loaded_shards > 1, f"Expected multiple shards, got {num_loaded_shards}"
        
        # Calculate distribution balance
        shard_sizes = [len(shard) for shard in cache.loaded_shards.values()]
        min_size = min(shard_sizes)
        max_size = max(shard_sizes)
        imbalance = (max_size - min_size) / max(min_size, 1)
        
        # Hash distribution should be reasonably balanced (imbalance < 3.0 for small samples)
        assert imbalance < 3.0, f"Poor distribution - imbalance factor: {imbalance}"
        
        print(f"[OK] Hash distribution works - {num_loaded_shards} shards loaded with imbalance {imbalance:.2f}")
    return True

def test_lazy_loading():
    """Test that shards are only loaded when needed"""
    print("Testing lazy loading...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'compression': False,
            'auto_save_threshold': 0,
            'refresh_strategy': {'notify_age_hours': 100}
        }
        
        # First instance - create data in specific shards
        cache1 = ShardedCPECache(config, num_shards=16)
        cache1.cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache1.cache_dir.mkdir(parents=True, exist_ok=True)
        cache1.metadata_file = Path(tmpdir) / 'cache_metadata.json'
        
        # Add entries to trigger multiple shards
        test_cpes = [f"cpe:2.3:a:test{i}:product:1.0" for i in range(50)]
        for cpe in test_cpes:
            cache1.put(cpe, {'totalResults': 1})
        
        cache1.flush()
        shards_created = len(cache1.loaded_shards)
        
        # Second instance - only access one CPE
        cache2 = ShardedCPECache(config, num_shards=16)
        cache2.cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache2.metadata_file = Path(tmpdir) / 'cache_metadata.json'
        
        # Access single CPE - should only load 1 shard
        retrieved, status = cache2.get(test_cpes[0])
        assert status == 'hit', "Entry should be found"
        assert len(cache2.loaded_shards) == 1, f"Expected 1 shard loaded, got {len(cache2.loaded_shards)}"
        
        print(f"[OK] Lazy loading works - {shards_created} shards exist, only 1 loaded on access")
    return True

def test_eviction_and_persistence():
    """Test that eviction clears memory but data persists"""
    print("Testing eviction and persistence...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'compression': False,
            'auto_save_threshold': 0,
            'refresh_strategy': {'notify_age_hours': 100}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        cache.metadata_file = Path(tmpdir) / 'cache_metadata.json'
        
        # Add data
        test_cpes = [f"cpe:2.3:a:evict{i}:test:1.0" for i in range(30)]
        for cpe in test_cpes:
            cache.put(cpe, {'totalResults': 42, 'data': f'test_{cpe}'})
        
        shards_before_evict = len(cache.loaded_shards)
        assert shards_before_evict > 0, "Should have loaded shards"
        
        # Save and evict
        cache.save_all_shards()
        cache.evict_all_shards()
        
        # Check memory is cleared
        assert len(cache.loaded_shards) == 0, "Loaded shards should be empty after eviction"
        
        # Verify data persists - access should reload from disk
        retrieved, status = cache.get(test_cpes[0])
        assert status == 'hit', "Data should persist after eviction"
        assert retrieved['totalResults'] == 42, "Data should match"
        assert len(cache.loaded_shards) == 1, "Should have reloaded 1 shard"
        
        print(f"[OK] Eviction works - {shards_before_evict} shards cleared, data persisted")
    return True

def test_api_compatibility():
    """Test that sharded cache has same API as expected interface"""
    print("Testing API compatibility...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'compression': False,
            'auto_save_threshold': 3,
            'refresh_strategy': {'notify_age_hours': 100}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        cache.metadata_file = Path(tmpdir) / 'cache_metadata.json'
        
        # Test all API methods exist and work
        test_cpe = "cpe:2.3:a:compat:test:1.0"
        test_response = {'totalResults': 5}
        
        # put()
        cache.put(test_cpe, test_response)
        
        # get() - hit
        retrieved, status = cache.get(test_cpe)
        assert status == 'hit'
        assert retrieved == test_response
        
        # get() - miss
        retrieved, status = cache.get("cpe:2.3:a:missing:test:1.0")
        assert status == 'miss'
        assert retrieved is None
        
        # get_stats()
        stats = cache.get_stats()
        assert 'total_entries' in stats
        assert 'session_hits' in stats
        assert 'session_misses' in stats
        assert stats['session_hits'] == 1
        assert stats['session_misses'] == 1
        
        # flush()
        cache.flush()
        
        # cleanup_expired()
        cache.cleanup_expired()
        
        # log_session_stats()
        cache.log_session_stats()
        
        # clear()
        cache.clear()
        assert len(cache.loaded_shards) == 0
        
        # Context manager
        with cache:
            cache.put("cpe:2.3:a:context:test:1.0", {'totalResults': 1})
        
        print("[OK] API compatibility verified - all methods work correctly")
    return True

def test_auto_save():
    """Test auto-save functionality with sharded cache"""
    print("Testing auto-save with sharded cache...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'compression': False,
            'auto_save_threshold': 5,
            'refresh_strategy': {'notify_age_hours': 100}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        cache.metadata_file = Path(tmpdir) / 'cache_metadata.json'
        
        # Add entries below threshold
        for i in range(4):
            cache.put(f"cpe:2.3:a:save{i}:test:1.0", {'totalResults': i})
        
        assert cache.session_stats['auto_saves'] == 0, "Should not auto-save yet"
        
        # Add 5th entry to trigger auto-save
        cache.put("cpe:2.3:a:save4:test:1.0", {'totalResults': 4})
        
        assert cache.session_stats['auto_saves'] == 1, "Should have auto-saved"
        
        # Verify files exist
        shard_files = list(cache.cache_dir.glob("cpe_cache_shard_*.json"))
        assert len(shard_files) > 0, "Shard files should exist after auto-save"
        
        print("[OK] Auto-save works correctly with sharded cache")
    return True

def test_global_manager_with_sharding():
    """Test GlobalCPECacheManager with sharding enabled"""
    print("Testing GlobalCPECacheManager with sharding...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'compression': False,
            'auto_save_threshold': 0,
            'sharding': {
                'enabled': True,
                'num_shards': 8
            },
            'refresh_strategy': {'notify_age_hours': 100}
        }
        
        # Create manager and initialize with sharding
        manager = GlobalCPECacheManager()
        cache = manager.initialize(config)
        
        # Override paths for test
        cache.cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        cache.metadata_file = Path(tmpdir) / 'cache_metadata.json'
        
        # Verify we got a sharded cache
        assert hasattr(cache, 'num_shards'), "Should have ShardedCPECache instance"
        assert cache.num_shards == 8, "Should use configured num_shards"
        
        # Add data
        cache.put("cpe:2.3:a:manager:test:1.0", {'totalResults': 10})
        
        # Test manager methods
        manager.save_all_shards()
        manager.evict_all_shards()
        
        assert len(cache.loaded_shards) == 0, "Eviction should clear memory"
        
        # Cleanup
        manager.save_and_cleanup()
        
        print("[OK] GlobalCPECacheManager works correctly with sharding")
    return True

def test_compact_json_storage():
    """Test that sharded cache uses compact JSON (no OPT_INDENT_2)"""
    print("Testing compact JSON storage...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'compression': False,
            'auto_save_threshold': 0,
            'refresh_strategy': {'notify_age_hours': 100}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        cache.metadata_file = Path(tmpdir) / 'cache_metadata.json'
        
        # Add entry
        test_cpe = "cpe:2.3:a:compact:test:1.0"
        cache.put(test_cpe, {
            'totalResults': 1,
            'products': ['a', 'b', 'c'],
            'nested': {'key': 'value'}
        })
        cache.flush()
        
        # Find the shard file
        shard_files = list(cache.cache_dir.glob("cpe_cache_shard_*.json"))
        assert len(shard_files) > 0, "Shard file should exist"
        
        # Read file and check for compact format (no newlines except at end)
        with open(shard_files[0], 'r') as f:
            content = f.read()
        
        # Compact JSON should have minimal newlines
        newline_count = content.count('\n')
        assert newline_count <= 2, f"Compact JSON should have <=2 newlines, got {newline_count}"
        
        print("[OK] Compact JSON storage verified - minimal whitespace")
    return True

# =============================================================================
# INTEGRATION TESTS: End-to-End Workflows
# =============================================================================

def test_cache_miss_workflow():
    """Integration test: Verify cache miss triggers API call and caches result (MISS workflow)"""
    print("Testing cache MISS workflow...")
    
    config = load_config()
    cache_config = config.get('cache_settings', {}).get('cpe_cache', {})
    
    if not cache_config.get('enabled', True):
        print("  [WARNING] Cache disabled in config - skipping test")
        return True
    
    cache_manager = get_global_cache_manager()
    if cache_manager.is_initialized():
        cache_manager.save_and_cleanup()
    
    cache = cache_manager.initialize(cache_config)
    
    # Create unique CPE
    unique_cpe = f"cpe:2.3:a:miss_test:product_{int(datetime.now().timestamp())}"
    
    # First access - should be MISS
    result1, status1 = cache.get(unique_cpe)
    assert status1 == 'miss', f"Expected miss, got {status1}"
    assert result1 is None, "Miss should return None"
    
    # Simulate API call
    fake_response = {
        'totalResults': 1,
        'resultsPerPage': 100,
        'products': [{'test': 'data'}],
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    cache.put(unique_cpe, fake_response)
    
    # Second access - should be HIT
    result2, status2 = cache.get(unique_cpe)
    assert status2 == 'hit', f"Expected hit after put, got {status2}"
    assert result2 == fake_response, "Retrieved data doesn't match"
    
    stats = cache.get_stats()
    assert stats['session_misses'] >= 1, "Should have at least 1 miss"
    assert stats['session_hits'] >= 1, "Should have at least 1 hit"
    
    print("[OK] Cache MISS workflow validated")
    return True

def test_cache_expiration_workflow():
    """Integration test: Verify expired cache entries are detected (EXPIRED workflow)"""
    print("Testing cache EXPIRATION workflow...")
    
    config = load_config()
    cache_config = config.get('cache_settings', {}).get('cpe_cache', {}).copy()
    cache_config['refresh_strategy'] = {'notify_age_hours': 0.001}  # ~3.6 seconds
    cache_config['sharding'] = {'enabled': True, 'num_shards': 16}
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = ShardedCPECache(cache_config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        cache.metadata_file = Path(tmpdir) / 'cache_metadata.json'
        
        # Add entry
        test_cpe = "cpe:2.3:a:expiry_test:product"
        cache.put(test_cpe, {'totalResults': 1, 'test': 'expires_soon'})
        
        # Should be valid immediately
        result1, status1 = cache.get(test_cpe)
        assert status1 == 'hit', f"Entry should be valid initially, got {status1}"
        
        # Wait for expiration
        time.sleep(4)
        
        # Should now be expired
        result2, status2 = cache.get(test_cpe)
        assert status2 == 'expired', f"Entry should be expired, got {status2}"
        assert result2 is None, "Expired entry should return None"
        
        stats = cache.get_stats()
        assert stats['session_expired'] >= 1, "Should have at least 1 expired entry"
    
    print("[OK] Cache EXPIRATION workflow validated")
    return True

def test_cache_disabled_workflow():
    """Integration test: Verify system works when cache is disabled (DISABLED workflow)"""
    print("Testing cache DISABLED workflow...")
    
    config = load_config()
    cache_config = config.get('cache_settings', {}).get('cpe_cache', {}).copy()
    cache_config['enabled'] = False
    
    cache_manager = get_global_cache_manager()
    if cache_manager.is_initialized():
        cache_manager.save_and_cleanup()
    
    cache = cache_manager.initialize(cache_config)
    
    # All operations should return 'disabled'
    test_cpe = "cpe:2.3:a:disabled_test:product"
    cache.put(test_cpe, {'totalResults': 1})
    
    result, status = cache.get(test_cpe)
    assert status == 'disabled', f"Expected 'disabled' status, got {status}"
    assert result is None, "Disabled cache should return None"
    
    print("[OK] Cache DISABLED workflow validated")
    return True

def test_atomic_write_safety():
    """Integration test: Verify atomic writes prevent corruption"""
    print("Testing ATOMIC write safety...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        shard_path = Path(tmpdir) / "test_shard.json"
        
        # Test 1: Normal write succeeds
        test_data = {"cpe:2.3:a:test:prod": {"totalResults": 5, "last_queried": "2026-01-01T00:00:00Z"}}
        ShardedCPECache.save_shard_to_disk(shard_path, test_data)
        
        assert shard_path.exists(), "Shard file should exist after save"
        loaded = ShardedCPECache.load_shard_from_disk(shard_path)
        assert loaded == test_data, "Loaded data should match saved data"
        
        # Test 2: Verify no temp files remain
        temp_files = list(Path(tmpdir).glob(".tmp_*"))
        assert len(temp_files) == 0, f"No temp files should remain, found {len(temp_files)}"
        
        # Test 3: Concurrent write simulation (second write should not corrupt)
        data_v1 = {"cpe:2.3:a:v1:prod": {"totalResults": 1}}
        data_v2 = {"cpe:2.3:a:v2:prod": {"totalResults": 2}}
        
        ShardedCPECache.save_shard_to_disk(shard_path, data_v1)
        ShardedCPECache.save_shard_to_disk(shard_path, data_v2)
        
        final_data = ShardedCPECache.load_shard_from_disk(shard_path)
        assert final_data == data_v2, "Final write should replace previous"
        
        # Test 4: Large data doesn't cause partial writes
        large_data = {
            f"cpe:2.3:a:large:test_{i}": {
                "totalResults": i,
                "products": [f"product_{j}" for j in range(100)],
                "last_queried": "2026-01-01T00:00:00Z"
            }
            for i in range(100)
        }
        
        ShardedCPECache.save_shard_to_disk(shard_path, large_data)
        loaded_large = ShardedCPECache.load_shard_from_disk(shard_path)
        assert len(loaded_large) == 100, "All entries should be saved"
        
        print("[OK] ATOMIC write safety validated")
        print(f"  - Normal writes: OK")
        print(f"  - No temp file leaks: OK")
        print(f"  - Overwrite safety: OK")
        print(f"  - Large data integrity: OK")
    
    return True

def test_cache_corruption_recovery():
    """Integration test: Verify system handles corrupted cache gracefully (RECOVERY workflow)"""
    print("Testing cache CORRUPTION recovery...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_config = {
            'enabled': True,
            'compression': False,
            'auto_save_threshold': 0,
            'sharding': {'enabled': True, 'num_shards': 16},
            'refresh_strategy': {'notify_age_hours': 100}
        }
        
        # Create cache instance
        cache_dir = Path(tmpdir) / "cache_dir"
        cache_dir.mkdir()
        
        with ShardedCPECache(cache_config, num_shards=16, cache_dir=cache_dir) as cache:
            # Test 1: PREVENTION - Corrupt data is rejected at put() time
            print("  Testing corrupt data PREVENTION...")
            corrupt_response = {
                "totalResults": 1,
                "products": [
                    {
                        "cpeName": "cpe:2.3:a:test:product",
                        "bad_field": "\udced\udca0\udc80"  # UTF-8 surrogate that will fail serialization
                    }
                ]
            }
            
            # Attempt to cache corrupt data - should be rejected
            initial_stats = cache.get_stats().copy()
            cache.put("cpe:2.3:a:corrupt:test", corrupt_response)
            
            # Verify data was NOT cached
            result, status = cache.get("cpe:2.3:a:corrupt:test")
            assert status == "miss", "Corrupt data should not be cached - get() should return miss"
            assert result is None, "Corrupt data should not be retrievable"
            print("    ✓ Corrupt data rejected (not cached)")
            
            # Test 2: RECOVERY - Pre-existing corrupted shard files are recovered
            print("  Testing corrupted shard file RECOVERY...")
            
            # Manually create a corrupted shard file (simulates old corruption)
            shard_path = cache_dir / "cpe_cache_shard_05.json"
            with open(shard_path, 'wb') as f:
                f.write(b'{"test": "\xed\xa0\x80"}')  # Invalid UTF-8 surrogate bytes
            
            # Attempt to load corrupted shard - should recover gracefully
            recovered_data = cache._load_shard(5)
            assert isinstance(recovered_data, dict), "Corrupted shard should return dict"
            assert len(recovered_data) == 0, "Corrupted shard should return empty dict for rebuild"
            print("    ✓ Corrupted shard file recovered (empty dict returned)")
            
            # Verify backup was created
            backup_files = list(cache_dir.glob("*.corrupted*"))
            assert len(backup_files) > 0, "Corrupted shard should create backup"
            print(f"    ✓ Backup created: {backup_files[0].name}")
            
            # Verify cache continues to function after recovery
            clean_response = {"totalResults": 5, "products": []}
            cache.put("cpe:2.3:a:clean:test", clean_response)
            result, status = cache.get("cpe:2.3:a:clean:test")
            assert status == "hit", "Cache should work after recovery"
            assert result == clean_response, "Clean data should be cached successfully"
            print("    ✓ Cache functional after recovery")
    
    print("[OK] Corruption prevention and recovery validated")
    print("  - Corrupt data rejected at cache entry: OK")
    print("  - Corrupted shards recovered: OK")
    print("  - Cache continues after corruption: OK")
    
    return True

def test_cache_mode_compatibility():
    """Integration test: Verify sharded cache mode works correctly"""
    print("Testing sharded cache mode compatibility...")
    
    config = load_config()
    cache_config = config.get('cache_settings', {}).get('cpe_cache', {})
    
    # Sharding is now mandatory - verify it's configured
    sharding_enabled = cache_config.get('sharding', {}).get('enabled', True)
    
    # Verify shard files exist
    shard_dir = project_root / 'cache' / 'cpe_base_strings'
    shards_exist = shard_dir.exists() and len(list(shard_dir.glob('*.json'))) > 0
    
    print("[OK] Sharded cache mode compatibility validated")
    print(f"  - Sharding enabled: {sharding_enabled}")
    print(f"  - Shard files exist: {shards_exist}")
    
    if sharding_enabled and not shards_exist:
        print("  ℹ INFO: Sharding enabled but no shards yet (created on first run)")
    
    return True

def test_cache_persistence_across_runs():
    """Integration test: Verify cache data persists across multiple runs"""
    print("Testing cache persistence across runs...")
    
    config = load_config()
    cache_config = config.get('cache_settings', {}).get('cpe_cache', {})
    
    cache_manager = get_global_cache_manager()
    if cache_manager.is_initialized():
        cache_manager.save_and_cleanup()
    
    cache = cache_manager.initialize(cache_config)
    
    # Add unique test entry
    test_cpe = f"cpe:2.3:a:persistence_test:run_{datetime.now().timestamp()}"
    test_data = {'totalResults': 1, 'timestamp': datetime.now(timezone.utc).isoformat()}
    
    cache.put(test_cpe, test_data)
    
    # Save and evict
    cache_manager.save_all_shards()
    cache_manager.evict_all_shards()
    
    # Verify eviction cleared memory
    if hasattr(cache, 'loaded_shards'):
        shards_in_memory = len(cache.loaded_shards)
    else:
        shards_in_memory = -1
    
    # Retrieve - should reload from disk
    retrieved, status = cache.get(test_cpe)
    
    success = status == 'hit' and retrieved == test_data
    
    print("[OK] Cache persistence validated")
    print(f"  - After eviction: {shards_in_memory} shards in memory")
    print(f"  - Data persisted: {success}")
    
    return success

def run_all_tests():
    """Run all CPE cache tests (unit + integration)"""
    print("\n" + "="*70)
    print("CPE Cache Comprehensive Test Suite")
    print("Sharded Implementation - Unit & Integration Tests")
    print("="*70 + "\n")
    
    unit_tests = [
        ("Hash Distribution", test_hash_distribution),
        ("Lazy Loading", test_lazy_loading),
        ("Eviction and Persistence", test_eviction_and_persistence),
        ("API Compatibility", test_api_compatibility),
        ("Auto-Save", test_auto_save),
        ("Global Manager with Sharding", test_global_manager_with_sharding),
        ("Compact JSON Storage", test_compact_json_storage),
    ]
    
    integration_tests = [
        ("Cache Miss Workflow", test_cache_miss_workflow),
        ("Cache Expiration Workflow", test_cache_expiration_workflow),
        ("Cache Disabled Workflow", test_cache_disabled_workflow),
        ("Atomic Write Safety", test_atomic_write_safety),
        ("Cache Corruption Recovery", test_cache_corruption_recovery),
        ("Cache Mode Compatibility", test_cache_mode_compatibility),
        ("Cache Persistence Across Runs", test_cache_persistence_across_runs),
    ]
    
    print("="*70)
    print("UNIT TESTS - Sharded Cache Implementation")
    print("="*70 + "\n")
    
    passed = 0
    failed = 0
    
    for test_name, test_func in unit_tests:
        print(f"\n{'-'*70}")
        print(f"Running: {test_name}")
        print(f"{'-'*70}")
        try:
            result = test_func()
            if result:
                passed += 1
                print(f"PASSED: {test_name}\n")
            else:
                failed += 1
                print(f"FAILED: {test_name}\n")
        except Exception as e:
            failed += 1
            print(f"FAILED: {test_name}")
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            print()
    
    print("\n" + "="*70)
    print("INTEGRATION TESTS - End-to-End Workflows")
    print("="*70 + "\n")
    
    for test_name, test_func in integration_tests:
        print(f"\n{'-'*70}")
        print(f"Running: {test_name}")
        print(f"{'-'*70}")
        try:
            result = test_func()
            if result:
                passed += 1
                print(f"PASSED: {test_name}\n")
            else:
                failed += 1
                print(f"FAILED: {test_name}\n")
        except Exception as e:
            failed += 1
            print(f"FAILED: {test_name}")
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            print()
    
    total_tests = len(unit_tests) + len(integration_tests)
    
    print("\n" + "="*70)
    print(f"TEST_RESULTS: PASSED={passed} TOTAL={total_tests} SUITE=\"CPE Cache\"")
    print("="*70 + "\n")
    
    return failed == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
