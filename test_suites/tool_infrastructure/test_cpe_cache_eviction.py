#!/usr/bin/env python3
"""
Test suite for CPE cache proactive eviction and memory management.
Validates that memory limits are enforced and data integrity is maintained.
"""

import sys
import os
import tempfile
import shutil
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from analysis_tool.storage.cpe_cache import ShardedCPECache

# Test tracking
tests_run = 0
tests_passed = 0

def test(description):
    """Decorator for test functions"""
    def decorator(func):
        def wrapper():
            global tests_run, tests_passed
            tests_run += 1
            try:
                func()
                tests_passed += 1
                print(f"  PASS: {description}")
                return True
            except AssertionError as e:
                print(f"  FAIL: {description}")
                print(f"    {e}")
                return False
            except Exception as e:
                print(f"  ERROR: {description}")
                print(f"    {type(e).__name__}: {e}")
                return False
        return wrapper
    return decorator


@test("Proactive eviction enforces max_loaded_shards limit")
def test_proactive_eviction_limit():
    """Test that loading new shards triggers eviction when at limit"""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'disabled': False,
            'max_loaded_shards': 3,
            'auto_save_threshold': 100,
            'refresh_strategy': {'notify_age_hours': 12}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cache"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Add entries to 5 different shards
        test_data = {
            'resultsPerPage': 1,
            'totalResults': 1,
            'products': []
        }
        
        # Load shards 0, 1, 2 (should stay in memory)
        cache.put('cpe:2.3:a:test0:*:*:*:*:*:*:*:*:*', test_data)
        cache.put('cpe:2.3:a:test1:*:*:*:*:*:*:*:*:*', test_data)
        cache.put('cpe:2.3:a:test2:*:*:*:*:*:*:*:*:*', test_data)
        
        assert len(cache.loaded_shards) == 3, f"Expected 3 shards loaded, got {len(cache.loaded_shards)}"
        
        # Load shard 3 - should trigger eviction of shard 0
        cache.put('cpe:2.3:a:test3:*:*:*:*:*:*:*:*:*', test_data)
        
        # Should still have max 3 shards
        assert len(cache.loaded_shards) == 3, f"Expected 3 shards after eviction, got {len(cache.loaded_shards)}"
        
        # Load shard 5 - should trigger another eviction
        cache.put('cpe:2.3:a:test5:*:*:*:*:*:*:*:*:*', test_data)
        
        assert len(cache.loaded_shards) == 3, f"Expected 3 shards maintained, got {len(cache.loaded_shards)}"


@test("Proactive eviction saves dirty shards before evicting")
def test_proactive_save_before_evict():
    """Test that shards with unsaved changes are saved before eviction"""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'disabled': False,
            'max_loaded_shards': 2,
            'auto_save_threshold': 100,  # High threshold - prevent auto-save during test
            'refresh_strategy': {'notify_age_hours': 12}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cache"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        
        test_data = {
            'resultsPerPage': 1,
            'totalResults': 1,
            'products': []
        }
        
        # Add to shard 0
        cpe_0 = 'cpe:2.3:a:test0:product:*:*:*:*:*:*:*:*'
        cache.put(cpe_0, test_data)
        shard_0_idx = cache._get_shard_index(cpe_0)
        
        # Add to shard 1
        cpe_1 = 'cpe:2.3:a:test1:product:*:*:*:*:*:*:*:*'
        cache.put(cpe_1, test_data)
        
        assert len(cache.loaded_shards) == 2, "Should have 2 shards loaded"
        
        # Add to shard 3 - should evict oldest shard (shard 0)
        cpe_3 = 'cpe:2.3:a:test3:product:*:*:*:*:*:*:*:*'
        cache.put(cpe_3, test_data)
        
        # Shard 0 should be evicted but saved
        shard_0_file = cache.cache_dir / cache._get_shard_filename(shard_0_idx)
        assert shard_0_file.exists(), f"Evicted shard {shard_0_idx} should be saved to disk"
        
        # Verify data integrity - can reload evicted shard
        retrieved, status = cache.get(cpe_0)
        assert retrieved is not None, "Should be able to retrieve from evicted shard"
        assert status == 'hit', f"Expected cache hit, got {status}"


@test("Memory never exceeds max_loaded_shards limit")
def test_memory_hard_limit():
    """Test that memory is bounded even with many shard accesses"""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'disabled': False,
            'max_loaded_shards': 4,
            'auto_save_threshold': 100,
            'refresh_strategy': {'notify_age_hours': 12}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cache"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        
        test_data = {
            'resultsPerPage': 1,
            'totalResults': 1,
            'products': []
        }
        
        # Access all 16 shards in sequence
        for i in range(16):
            cpe = f'cpe:2.3:a:test{i}:product:*:*:*:*:*:*:*:*'
            cache.put(cpe, test_data)
            
            # Memory should NEVER exceed limit
            assert len(cache.loaded_shards) <= 4, \
                f"Memory limit violated: {len(cache.loaded_shards)} shards loaded (max 4)"
        
        # Final check
        assert len(cache.loaded_shards) == 4, "Should have exactly max_loaded_shards at end"


@test("Auto-save uses incremental save strategy")
def test_autosave_incremental():
    """Test that auto-save only saves changed shards incrementally"""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'disabled': False,
            'max_loaded_shards': 4,
            'auto_save_threshold': 5,  # Low threshold for testing
            'refresh_strategy': {'notify_age_hours': 12}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cache"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        
        test_data = {
            'resultsPerPage': 1,
            'totalResults': 1,
            'products': []
        }
        
        # Add NEW entries to trigger auto-save (not updates to same CPE)
        for i in range(6):  # 6 > threshold of 5
            cpe = f'cpe:2.3:a:vendor{i}:product{i}:*:*:*:*:*:*:*:*'  # Different CPEs
            cache.put(cpe, test_data)
        
        # Auto-save should have triggered
        assert cache.session_stats['auto_saves'] >= 1, \
            f"Auto-save should have triggered, got {cache.session_stats['auto_saves']} auto-saves"
        
        # Should maintain memory limit during auto-save
        assert len(cache.loaded_shards) <= 4, \
            f"Memory limit violated during auto-save: {len(cache.loaded_shards)} shards"


@test("Evicted shards can be reloaded without data loss")
def test_reload_evicted_shard():
    """Test that evicted shards can be reloaded with full data integrity"""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'disabled': False,
            'max_loaded_shards': 2,
            'auto_save_threshold': 100,
            'refresh_strategy': {'notify_age_hours': 12}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cache"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        
        test_data = {
            'resultsPerPage': 1,
            'totalResults': 5,
            'products': [{'test': 'data'}]
        }
        
        # Add to shard 0
        cpe_0 = 'cpe:2.3:a:vendor0:product:*:*:*:*:*:*:*:*'
        cache.put(cpe_0, test_data)
        
        # Add to shard 1
        cpe_1 = 'cpe:2.3:a:vendor1:product:*:*:*:*:*:*:*:*'
        cache.put(cpe_1, test_data)
        
        # Add to shard 3 - evicts shard 0
        cpe_3 = 'cpe:2.3:a:vendor3:product:*:*:*:*:*:*:*:*'
        cache.put(cpe_3, test_data)
        
        # Add to shard 5 - evicts shard 1
        cpe_5 = 'cpe:2.3:a:vendor5:product:*:*:*:*:*:*:*:*'
        cache.put(cpe_5, test_data)
        
        # Now reload shard 0 by accessing it
        retrieved_0, status_0 = cache.get(cpe_0)
        assert status_0 == 'hit', f"Expected hit on reloaded shard, got {status_0}"
        assert retrieved_0 is not None, "Data should be retrievable from reloaded shard"
        assert retrieved_0['totalResults'] == 5, "Data integrity check failed"
        
        # Reload shard 1
        retrieved_1, status_1 = cache.get(cpe_1)
        assert status_1 == 'hit', "Should hit on second reloaded shard"
        assert retrieved_1['totalResults'] == 5, "Data integrity maintained across reload"


@test("Concurrent access to multiple shards with eviction")
def test_concurrent_shard_access():
    """Test realistic pattern with multiple shard accesses"""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'disabled': False,
            'max_loaded_shards': 3,
            'auto_save_threshold': 100,
            'refresh_strategy': {'notify_age_hours': 12}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cache"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        
        test_data = {
            'resultsPerPage': 1,
            'totalResults': 1,
            'products': []
        }
        
        # Simulate realistic access pattern
        access_pattern = [0, 0, 1, 1, 2, 2, 3, 3, 0, 1, 4, 5, 0, 2]
        
        for shard_num in access_pattern:
            cpe = f'cpe:2.3:a:vendor{shard_num}:product:*:*:*:*:*:*:*:*'
            cache.put(cpe, test_data)
            
            # Should never exceed limit
            assert len(cache.loaded_shards) <= 3, \
                f"Limit violated at access {shard_num}: {len(cache.loaded_shards)} shards"
        
        # All data should still be retrievable
        for shard_num in set(access_pattern):
            cpe = f'cpe:2.3:a:vendor{shard_num}:product:*:*:*:*:*:*:*:*'
            retrieved, status = cache.get(cpe)
            assert retrieved is not None, f"Data lost for shard {shard_num}"


# Run tests
print("="*80)
print("CPE CACHE PROACTIVE EVICTION TEST SUITE")
print("="*80)
print()

test_proactive_eviction_limit()
test_proactive_save_before_evict()
test_memory_hard_limit()
test_autosave_incremental()
test_reload_evicted_shard()
test_concurrent_shard_access()

print()
print("="*80)
print(f"Results: {tests_passed}/{tests_run} tests passed")
print("="*80)
print()
print(f"TEST_RESULTS: PASSED={tests_passed} TOTAL={tests_run} SUITE=\"CPE Cache Proactive Eviction\"")

sys.exit(0 if tests_passed == tests_run else 1)
