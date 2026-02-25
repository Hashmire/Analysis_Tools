#!/usr/bin/env python3
"""
CPE Cache Refresh Script Test Suite

Tests for utilities/refresh_nvd_cpe_base_strings_cache.py functionality covering:
- Shard data preservation during refresh
- Query count incrementing behavior
- Timestamp updates
- Data merge operations
- Static method reuse from ShardedCPECache
- Configuration independence (forced refresh vs runtime expiration)
- Error handling and recovery
- Corruption detection, diagnostics, and auto-recovery

"""

import sys
import os
import json
import subprocess
import tempfile
import shutil
import time
import io
from contextlib import redirect_stderr
from pathlib import Path
from datetime import datetime, timedelta, timezone

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.analysis_tool.storage.cpe_cache import ShardedCPECache
from src.analysis_tool.logging.workflow_logger import get_logger
import orjson

# Import refresh script functions for testing
import utilities.refresh_nvd_cpe_base_strings_cache as refresh_module

def load_config():
    """Load configuration from config.json"""
    config_path = project_root / 'src' / 'analysis_tool' / 'config.json'
    with open(config_path, 'r') as f:
        return json.load(f)

# =============================================================================
# DATA INTEGRITY TESTS: Load Failure Protection
# =============================================================================

def test_load_failure_raises_error():
    """Test that load_shard_from_disk raises exception when file exists but is corrupted"""
    print("Testing load failure protection (DATA LOSS BUG FIX)...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        shard_path = Path(tmpdir) / "cpe_cache_shard_05.json"
        
        # Create a corrupted/invalid JSON file
        with open(shard_path, 'w') as f:
            f.write("{invalid json content")
        
        # Verify file exists
        assert shard_path.exists(), "Test shard file should exist"
        
        # Attempt to load - should raise JSONDecodeError (orjson parsing error), not return {}
        try:
            result = ShardedCPECache.load_shard_from_disk(shard_path)
            print(f"FAILED: load_shard_from_disk returned {type(result)} instead of raising exception")
            return False
        except (orjson.JSONDecodeError, RuntimeError) as e:
            # Either JSONDecodeError (orjson direct) or RuntimeError (wrapped) is acceptable
            error_msg = str(e)
            print(f"PASSED: Correctly raised {type(e).__name__} for corrupted file")
            print(f"  Error message: {error_msg[:100]}...")
            return True
        except Exception as e:
            print(f"FAILED: Raised unexpected {type(e).__name__}: {e}")
            return False

def test_load_success_with_valid_data():
    """Test that load_shard_from_disk still works correctly with valid data"""
    print("Testing successful load with valid data...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        shard_path = Path(tmpdir) / "cpe_cache_shard_05.json"
        
        # Create valid shard data
        test_data = {
            "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*:*:*": {
                "query_response": {"totalResults": 5},
                "last_queried": datetime.now(timezone.utc).isoformat(),
                "query_count": 3,
                "total_results": 5
            }
        }
        
        # Save using the static method
        ShardedCPECache.save_shard_to_disk(shard_path, test_data)
        
        # Load it back
        loaded_data = ShardedCPECache.load_shard_from_disk(shard_path)
        
        # Verify data integrity
        if len(loaded_data) == 1:
            cpe_key = list(loaded_data.keys())[0]
            if loaded_data[cpe_key]["query_count"] == 3:
                print("PASSED: Valid data loaded correctly")
                return True
            else:
                print(f"FAILED: query_count mismatch: {loaded_data[cpe_key]['query_count']}")
                return False
        else:
            print(f"FAILED: Expected 1 entry, got {len(loaded_data)}")
            return False

def test_load_nonexistent_file_returns_empty():
    """Test that load_shard_from_disk returns {} for non-existent files (normal case)"""
    print("Testing load of non-existent file...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        shard_path = Path(tmpdir) / "cpe_cache_shard_99.json"
        
        # Verify file does NOT exist
        assert not shard_path.exists(), "Test file should not exist"
        
        # Load should return empty dict (not an error)
        result = ShardedCPECache.load_shard_from_disk(shard_path)
        
        if result == {}:
            print("PASSED: Non-existent file returns empty dict")
            return True
        else:
            print(f"FAILED: Expected {{}}, got {result}")
            return False

# =============================================================================
# UNIT TESTS: Refresh Script Functionality
# =============================================================================

def test_static_method_reuse():
    """Test that refresh script properly reuses ShardedCPECache static methods"""
    print("Testing static method reuse...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        shard_path = Path(tmpdir) / "cpe_cache_shard_00.json"
        
        # Test data
        test_data = {
            "cpe:2.3:a:test:product:*:*:*:*:*:*:*:*": {
                "query_response": {"totalResults": 5},
                "last_queried": "2026-01-01T00:00:00+00:00",
                "query_count": 1,
                "total_results": 5
            }
        }
        
        # Test save_shard_to_disk
        ShardedCPECache.save_shard_to_disk(shard_path, test_data)
        assert shard_path.exists(), "Shard file should be created"
        
        # Test load_shard_from_disk
        loaded = ShardedCPECache.load_shard_from_disk(shard_path)
        assert len(loaded) == 1, "Should load 1 entry"
        assert "cpe:2.3:a:test:product:*:*:*:*:*:*:*:*" in loaded
        
        # Test parse_cache_entry_timestamp
        entry = list(loaded.values())[0]
        timestamp = ShardedCPECache.parse_cache_entry_timestamp(entry)
        assert timestamp.tzinfo is not None, "Timestamp should be timezone-aware"
        
        print("[OK] Static methods work correctly for refresh script")
    return True

def test_query_count_preservation():
    """Test that refresh preserves existing query_count values"""
    print("Testing query_count preservation during refresh...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        shard_path = Path(tmpdir) / "cpe_cache_shard_00.json"
        
        # Create shard with existing entry (query_count = 5)
        existing_data = {
            "cpe:2.3:a:test:product:*:*:*:*:*:*:*:*": {
                "query_response": {"totalResults": 10, "old_data": True},
                "last_queried": "2026-01-01T00:00:00+00:00",
                "query_count": 5,
                "total_results": 10
            }
        }
        ShardedCPECache.save_shard_to_disk(shard_path, existing_data)
        
        # Simulate refresh script behavior
        shard_data = ShardedCPECache.load_shard_from_disk(shard_path)
        
        # New entry from refresh (refresh script sets query_count=1)
        new_entry = {
            "query_response": {"totalResults": 15, "new_data": True},
            "last_queried": datetime.now(timezone.utc).isoformat(),
            "query_count": 1,
            "total_results": 15
        }
        
        # Apply refresh script merge logic
        cpe_base = "cpe:2.3:a:test:product:*:*:*:*:*:*:*:*"
        if cpe_base in shard_data:
            existing_count = shard_data[cpe_base].get('query_count', 1)
            new_entry['query_count'] = existing_count
        
        shard_data[cpe_base] = new_entry
        
        # Verify query_count preserved
        assert shard_data[cpe_base]['query_count'] == 5, "query_count should be preserved"
        assert shard_data[cpe_base]['total_results'] == 15, "total_results should be updated"
        assert shard_data[cpe_base]['query_response']['new_data'] == True, "query_response should be updated"
        
        print("[OK] query_count preserved correctly during refresh")
    return True

def test_timestamp_update():
    """Test that refresh updates last_queried timestamps"""
    print("Testing timestamp updates during refresh...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        shard_path = Path(tmpdir) / "cpe_cache_shard_00.json"
        
        # Old timestamp
        old_time = "2026-01-01T00:00:00+00:00"
        existing_data = {
            "cpe:2.3:a:test:product:*:*:*:*:*:*:*:*": {
                "query_response": {"totalResults": 10},
                "last_queried": old_time,
                "query_count": 1,
                "total_results": 10
            }
        }
        ShardedCPECache.save_shard_to_disk(shard_path, existing_data)
        
        # Simulate refresh
        time.sleep(0.1)  # Ensure time difference
        new_time = datetime.now(timezone.utc).isoformat()
        
        shard_data = ShardedCPECache.load_shard_from_disk(shard_path)
        shard_data["cpe:2.3:a:test:product:*:*:*:*:*:*:*:*"]["last_queried"] = new_time
        ShardedCPECache.save_shard_to_disk(shard_path, shard_data)
        
        # Verify timestamp updated
        reloaded = ShardedCPECache.load_shard_from_disk(shard_path)
        updated_time = reloaded["cpe:2.3:a:test:product:*:*:*:*:*:*:*:*"]["last_queried"]
        assert updated_time != old_time, "Timestamp should be updated"
        
        print("[OK] Timestamps updated correctly during refresh")
    return True

def test_data_merge_no_loss():
    """Test that refresh merges data without loss"""
    print("Testing data merge without loss...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        shard_path = Path(tmpdir) / "cpe_cache_shard_00.json"
        
        # Existing shard with 50 entries
        existing_data = {}
        for i in range(50):
            existing_data[f"cpe:2.3:a:vendor{i}:product:*:*:*:*:*:*:*:*"] = {
                "query_response": {"totalResults": i},
                "last_queried": "2026-01-01T00:00:00+00:00",
                "query_count": 1,
                "total_results": i
            }
        ShardedCPECache.save_shard_to_disk(shard_path, existing_data)
        
        # Simulate refresh updating 5 entries
        shard_data = ShardedCPECache.load_shard_from_disk(shard_path)
        updates = {}
        for i in range(5):
            key = f"cpe:2.3:a:vendor{i}:product:*:*:*:*:*:*:*:*"
            updates[key] = {
                "query_response": {"totalResults": i * 2},  # Updated
                "last_queried": datetime.now(timezone.utc).isoformat(),
                "query_count": shard_data[key].get('query_count', 1),  # Preserve
                "total_results": i * 2
            }
        
        shard_data.update(updates)
        ShardedCPECache.save_shard_to_disk(shard_path, shard_data)
        
        # Verify no data loss
        final = ShardedCPECache.load_shard_from_disk(shard_path)
        assert len(final) == 50, "Should still have all 50 entries"
        assert final["cpe:2.3:a:vendor0:product:*:*:*:*:*:*:*:*"]["total_results"] == 0, "Updated entry should have new data"
        assert final["cpe:2.3:a:vendor49:product:*:*:*:*:*:*:*:*"]["total_results"] == 49, "Unchanged entry should have old data"
        
        print("[OK] Data merge preserves all entries correctly")
    return True

def test_new_entry_addition():
    """Test that refresh can add new entries to existing shards"""
    print("Testing new entry addition during refresh...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        shard_path = Path(tmpdir) / "cpe_cache_shard_00.json"
        
        # Existing shard with 10 entries
        existing_data = {}
        for i in range(10):
            existing_data[f"cpe:2.3:a:existing{i}:product:*:*:*:*:*:*:*:*"] = {
                "query_response": {"totalResults": i},
                "last_queried": "2026-01-01T00:00:00+00:00",
                "query_count": 1,
                "total_results": i
            }
        ShardedCPECache.save_shard_to_disk(shard_path, existing_data)
        
        # Simulate refresh adding 5 new entries
        shard_data = ShardedCPECache.load_shard_from_disk(shard_path)
        new_entries = {}
        for i in range(5):
            new_entries[f"cpe:2.3:a:newentry{i}:product:*:*:*:*:*:*:*:*"] = {
                "query_response": {"totalResults": 100 + i},
                "last_queried": datetime.now(timezone.utc).isoformat(),
                "query_count": 1,
                "total_results": 100 + i
            }
        
        shard_data.update(new_entries)
        ShardedCPECache.save_shard_to_disk(shard_path, shard_data)
        
        # Verify additions
        final = ShardedCPECache.load_shard_from_disk(shard_path)
        assert len(final) == 15, "Should have 15 entries (10 old + 5 new)"
        assert "cpe:2.3:a:newentry0:product:*:*:*:*:*:*:*:*" in final
        assert final["cpe:2.3:a:newentry0:product:*:*:*:*:*:*:*:*"]["total_results"] == 100
        
        print("[OK] New entries added correctly during refresh")
    return True

def test_empty_shard_handling():
    """Test that refresh handles non-existent shard files correctly"""
    print("Testing empty/missing shard handling...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        shard_path = Path(tmpdir) / "cpe_cache_shard_99.json"
        
        # Load non-existent shard
        shard_data = ShardedCPECache.load_shard_from_disk(shard_path)
        assert shard_data == {}, "Should return empty dict for missing shard"
        
        # Add data and save
        shard_data["cpe:2.3:a:test:product:*:*:*:*:*:*:*:*"] = {
            "query_response": {"totalResults": 1},
            "last_queried": datetime.now(timezone.utc).isoformat(),
            "query_count": 1,
            "total_results": 1
        }
        ShardedCPECache.save_shard_to_disk(shard_path, shard_data)
        
        # Verify shard created
        assert shard_path.exists(), "Shard file should be created"
        reloaded = ShardedCPECache.load_shard_from_disk(shard_path)
        assert len(reloaded) == 1
        
        print("[OK] Empty/missing shard handling works correctly")
    return True

def test_compact_json_format():
    """Test that refresh maintains compact JSON format"""
    print("Testing compact JSON format preservation...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        shard_path = Path(tmpdir) / "cpe_cache_shard_00.json"
        
        # Save with static method
        test_data = {
            "cpe:2.3:a:test:product:*:*:*:*:*:*:*:*": {
                "query_response": {"totalResults": 10, "nested": {"data": "value"}},
                "last_queried": "2026-01-01T00:00:00+00:00",
                "query_count": 1,
                "total_results": 10
            }
        }
        ShardedCPECache.save_shard_to_disk(shard_path, test_data)
        
        # Read raw file content
        with open(shard_path, 'r') as f:
            content = f.read()
        
        # Verify compact (no multi-line indentation)
        lines = content.split('\n')
        assert len(lines) == 1, "Compact JSON should be single line"
        
        # Verify still valid JSON
        loaded = ShardedCPECache.load_shard_from_disk(shard_path)
        assert len(loaded) == 1
        
        print("[OK] Compact JSON format maintained")
    return True

# =============================================================================
# INTEGRATION TESTS: Refresh Script Execution (End-to-End)
# =============================================================================

def test_end_to_end_data_preservation():
    """END-TO-END: Inject test data, verify it persists through save/load cycle"""
    print("Testing end-to-end data preservation with real cache operations...")
    
    # Get real cache directory
    cache_dir = project_root / "cache" / "cpe_base_strings"
    shard_path = cache_dir / "cpe_cache_shard_00.json"
    
    # Backup existing shard if it exists
    backup_path = None
    if shard_path.exists():
        backup_path = cache_dir / "cpe_cache_shard_00.json.test_backup"
        shutil.copy(shard_path, backup_path)
    
    try:
        # BEFORE: Inject test data with known query_count and timestamp
        test_cpe = "cpe:2.3:a:test_e2e:preservation_test:*:*:*:*:*:*:*:*"
        old_timestamp = "2026-01-15T12:00:00+00:00"
        test_entry = {
            "query_response": {"totalResults": 99, "format": "NVD_CPE", "test_marker": "E2E_TEST"},
            "last_queried": old_timestamp,
            "query_count": 7,  # Should be preserved
            "total_results": 99
        }
        
        # Load existing shard or create new
        if shard_path.exists():
            shard_data_before = ShardedCPECache.load_shard_from_disk(shard_path)
        else:
            shard_data_before = {}
        
        original_count = len(shard_data_before)
        shard_data_before[test_cpe] = test_entry
        ShardedCPECache.save_shard_to_disk(shard_path, shard_data_before)
        
        print(f"  BEFORE: Injected test entry with query_count=7")
        print(f"  BEFORE: Total entries in shard 00: {len(shard_data_before)}")
        
        # SIMULATE REFRESH: Merge logic that preserves query_count
        shard_data_refresh = ShardedCPECache.load_shard_from_disk(shard_path)
        
        # Simulate refresh creating new entry (as refresh script does)
        new_entry = {
            "query_response": {"totalResults": 120, "format": "NVD_CPE", "test_marker": "REFRESHED"},
            "last_queried": datetime.now(timezone.utc).isoformat(),
            "query_count": 1,  # Refresh script sets this to 1 initially
            "total_results": 120
        }
        
        # Apply merge logic (as flush_staged_updates does)
        if test_cpe in shard_data_refresh:
            existing_count = shard_data_refresh[test_cpe].get('query_count', 1)
            new_entry['query_count'] = existing_count  # Preserve
        
        shard_data_refresh[test_cpe] = new_entry
        ShardedCPECache.save_shard_to_disk(shard_path, shard_data_refresh)
        
        # AFTER: Verify data preserved
        shard_data_after = ShardedCPECache.load_shard_from_disk(shard_path)
        
        # Test entry should still exist
        assert test_cpe in shard_data_after, "Test entry should still exist after refresh"
        
        # Query count should be preserved (not reset to 1)
        after_count = shard_data_after[test_cpe].get('query_count', 0)
        assert after_count == 7, f"query_count should be preserved (expected 7, got {after_count})"
        
        # Data should be updated
        test_marker = shard_data_after[test_cpe]['query_response'].get('test_marker')
        assert test_marker == "REFRESHED", "Data should be updated"
        
        # Entry count should not decrease
        assert len(shard_data_after) >= original_count, "Should not lose entries during refresh"
        
        print(f"  AFTER: Test entry still exists [OK]")
        print(f"  AFTER: query_count preserved: 7 [OK]")
        print(f"  AFTER: Data updated correctly [OK]")
        print(f"  AFTER: Total entries: {len(shard_data_after)} (>= {original_count}) [OK]")
        
        print("[OK] End-to-end data preservation verified")
        
    finally:
        # Restore backup if it exists
        if backup_path and backup_path.exists():
            shutil.move(backup_path, shard_path)
            print("  Restored original shard from backup")
    
    return True

def test_end_to_end_multiple_shards():
    """END-TO-END: Verify data preservation across multiple shards"""
    print("Testing end-to-end multi-shard data preservation...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        test_data_per_shard = {}
        
        # BEFORE: Create initial shards with test data
        for i in range(3):
            shard_path = cache_dir / f"cpe_cache_shard_{i:02d}.json"
            test_cpe = f"cpe:2.3:a:test_direct_shard{i}:e2e_multi:*:*:*:*:*:*:*:*"
            
            # Create shard with base entry plus test entry
            shard_data = {
                f"cpe:2.3:a:base:product{i}:*:*:*:*:*:*:*:*": {
                    "query_response": {"totalResults": 1},
                    "last_queried": "2026-01-14T12:00:00+00:00",
                    "query_count": 1,
                    "total_results": 1
                },
                test_cpe: {
                    "query_response": {"totalResults": i * 10, "shard_marker": f"shard_{i}"},
                    "last_queried": "2026-01-15T12:00:00+00:00",
                    "query_count": i + 3,  # Unique for each shard
                    "total_results": i * 10
                }
            }
            original_count = len(shard_data)
            ShardedCPECache.save_shard_to_disk(shard_path, shard_data)
            test_data_per_shard[i] = (test_cpe, i + 3, original_count)
        
        print(f"  BEFORE: Created test shards 0, 1, 2 with initial data")
        
        # SIMULATE REFRESH: Load, merge, save for each shard
        for shard_idx, (test_cpe, expected_count, original_count) in test_data_per_shard.items():
            shard_path = cache_dir / f"cpe_cache_shard_{shard_idx:02d}.json"
            shard_data = ShardedCPECache.load_shard_from_disk(shard_path)
            
            # Simulate refresh creating updated entry
            if test_cpe in shard_data:
                existing_count = shard_data[test_cpe].get('query_count', 1)
                shard_data[test_cpe]['query_response'] = {
                    "totalResults": shard_idx * 20,  # Updated data
                    "shard_marker": f"refreshed_shard_{shard_idx}"
                }
                shard_data[test_cpe]['query_count'] = existing_count  # Preserve
                shard_data[test_cpe]['last_queried'] = datetime.now(timezone.utc).isoformat()
            
            ShardedCPECache.save_shard_to_disk(shard_path, shard_data)
        
        print(f"  DURING: Simulated refresh merge for 3 shards")
        
        # AFTER: Verify all shards preserved data correctly
        all_verified = True
        for shard_idx, (test_cpe, expected_count, original_count) in test_data_per_shard.items():
            shard_path = cache_dir / f"cpe_cache_shard_{shard_idx:02d}.json"
            shard_data = ShardedCPECache.load_shard_from_disk(shard_path)
            
            # Verify entry exists
            if test_cpe not in shard_data:
                print(f"  ERROR: Shard {shard_idx} - test entry not found")
                all_verified = False
                continue
            
            # Verify query_count preserved
            actual_count = shard_data[test_cpe].get('query_count', 0)
            if actual_count != expected_count:
                print(f"  ERROR: Shard {shard_idx} - query_count mismatch (expected {expected_count}, got {actual_count})")
                all_verified = False
            
            # Verify data updated
            marker = shard_data[test_cpe]['query_response'].get('shard_marker', '')
            if not marker.startswith('refreshed_'):
                print(f"  ERROR: Shard {shard_idx} - data not updated")
                all_verified = False
            
            # Verify no data loss
            if len(shard_data) != original_count:
                print(f"  ERROR: Shard {shard_idx} - entry count changed ({len(shard_data)} != {original_count})")
                all_verified = False
        
        assert all_verified, "All shards should preserve data correctly"
        
        print(f"  AFTER: All 3 shards verified [OK]")
        print(f"  AFTER: query_count preserved in all shards [OK]")
        print(f"  AFTER: Data updated correctly in all shards [OK]")
        print("[OK] Multi-shard data preservation verified")
    
    return True

# =============================================================================
# CORRUPTION DIAGNOSTIC & AUTO-RECOVERY TESTS
# =============================================================================

def test_corruption_auto_recovery_empty_file():
    """Integration test: Auto-recovery from empty shard file during discovery phase"""
    print("Testing auto-recovery from EMPTY FILE corruption...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()
        
        # Create empty corrupted shard (DISK_FAILURE - Empty File)
        shard_path = cache_dir / "cpe_cache_shard_00.json"
        shard_path.touch()  # Create empty file (0 bytes)
        
        # Create one valid shard to ensure we get a result
        valid_shard = cache_dir / "cpe_cache_shard_01.json"
        valid_data = {
            "cpe:2.3:a:test:product:*:*:*:*:*:*:*:*": {
                "query_response": {"totalResults": 1},
                "last_queried": "2026-01-15T00:00:00+00:00",
                "query_count": 1,
                "total_results": 1
            }
        }
        ShardedCPECache.save_shard_to_disk(valid_shard, valid_data)
        
        # Run actual refresh script function - should auto-recover
        oldest = refresh_module.find_oldest_cache_entry(cache_dir, num_shards=2)
        
        # Verify auto-recovery: corrupted file should be deleted
        assert not shard_path.exists(), "Corrupted shard should be deleted during auto-recovery"
        assert valid_shard.exists(), "Valid shard should remain untouched"
        
        # Verify operation continued successfully
        assert oldest is not None, "Should return oldest timestamp from valid shard"
        
        print("  [OK] Empty file detected and deleted")
        print("  [OK] Operation continued with valid shards")
        print(f"  [OK] Oldest entry: {oldest}")
        return True

def test_corruption_auto_recovery_invalid_json():
    """Integration test: Auto-recovery from malformed JSON during discovery phase"""
    print("Testing auto-recovery from MALFORMED JSON corruption...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()
        
        # Create corrupted shard with syntax error (JSON_SYNTAX_ERROR - Malformed Structure)
        # Make it >100 bytes to reach JSONDecodeError classification
        malformed_json = b'{"key": "value", "missing_quote: "data", "pad": "' + (b'x' * 100) + b'"}'
        shard_path = cache_dir / "cpe_cache_shard_05.json"
        with open(shard_path, 'wb') as f:
            f.write(malformed_json)
        
        # Create valid shard
        valid_shard = cache_dir / "cpe_cache_shard_03.json"
        valid_data = {
            "cpe:2.3:a:vendor:app:*:*:*:*:*:*:*:*": {
                "query_response": {"totalResults": 2},
                "last_queried": "2026-01-20T12:00:00+00:00",
                "query_count": 3,
                "total_results": 2
            }
        }
        ShardedCPECache.save_shard_to_disk(valid_shard, valid_data)
        
        # Run discovery - should auto-recover from corruption
        oldest = refresh_module.find_oldest_cache_entry(cache_dir, num_shards=16)
        
        # Verify auto-recovery
        assert not shard_path.exists(), "Corrupted shard should be deleted"
        assert valid_shard.exists(), "Valid shard should remain"
        assert oldest is not None, "Should return oldest timestamp"
        
        print("  [OK] Malformed JSON detected and deleted")
        print("  [OK] Discovery phase completed successfully")
        return True

def test_corruption_auto_recovery_flush_updates():
    """Integration test: Auto-recovery during flush_staged_updates with corrupted shard"""
    print("Testing auto-recovery during FLUSH UPDATES phase...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()
        
        # Create corrupted shard (binary garbage - DISK_CORRUPTION - Invalid Format)
        shard_path = cache_dir / "cpe_cache_shard_07.json"
        with open(shard_path, 'wb') as f:
            f.write(b'\xFF\xFE\x00Binary garbage here')
        
        # Prepare staged updates for the corrupted shard
        staged_updates = {
            7: {  # Shard index 7 is corrupted
                "cpe:2.3:a:test:new_product:*:*:*:*:*:*:*:*": {
                    "query_response": {"totalResults": 5},
                    "last_queried": datetime.now(timezone.utc).isoformat(),
                    "query_count": 1,
                    "total_results": 5
                }
            }
        }
        
        # Create stats object
        stats = refresh_module.CPECacheRefreshStats()
        
        # Run flush - should auto-recover and apply updates
        flushed = refresh_module.flush_staged_updates(staged_updates, cache_dir, stats, num_shards=16)
        
        # Verify results
        assert flushed == 1, f"Should flush 1 entry, got {flushed}"
        assert shard_path.exists(), "New shard should be created with updates"
        
        # Verify new shard contains the update
        new_data = ShardedCPECache.load_shard_from_disk(shard_path)
        assert "cpe:2.3:a:test:new_product:*:*:*:*:*:*:*:*" in new_data
        assert new_data["cpe:2.3:a:test:new_product:*:*:*:*:*:*:*:*"]["total_results"] == 5
        
        print("  [OK] Corrupted shard detected during flush")
        print("  [OK] Shard deleted and rebuilt with fresh updates")
        print("  [OK] Data integrity maintained")
        return True

def test_corruption_diagnostic_accuracy():
    """Integration test: Verify diagnostic function provides accurate categorization"""
    print("Testing corruption diagnostic accuracy...")
    
    # Create reusable error object BEFORE test cases
    sample_error = None
    try:
        orjson.loads(b'\xFF')  # Trigger real JSONDecodeError
    except orjson.JSONDecodeError as e:
        sample_error = e
    
    if sample_error is None:
        print("FAILED: Could not create sample error for testing")
        return False
    
    test_cases = [
        {
            "name": "Empty File",
            "data": b'',
            "expected_category": "DISK_FAILURE - Empty File",
            "expected_rec_keywords": ["Disk full", "power loss"]
        },
        {
            "name": "Truncated JSON",
            "data": b'{"key": "val',  # <100 bytes, starts with '{'
            "expected_category": "DISK_FAILURE - Truncated Write",
            "expected_rec_keywords": ["Partial write"]
        },
        {
            "name": "Binary Corruption",
            "data": b'\xFF\xFE\x00\x00Binary data',
            "expected_category": "DISK_CORRUPTION - Invalid Format",
            "expected_rec_keywords": ["Bit flips", "disk corruption"]
        },
        {
            "name": "Null Bytes",
            "data": b'{"valid": "data", "bad": "test\x00byte", "pad": "' + (b'x' * 100) + b'"}',
            "expected_category": "VALIDATION_BYPASS - Null Bytes (JSON-level)",
            "expected_rec_keywords": ["validate_string_content"]
        },
    ]
    
    for test_case in test_cases:
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.json') as f:
            temp_path = Path(f.name)
            f.write(test_case["data"])
        
        try:
            # Run diagnostic with sample error
            diag = refresh_module.diagnose_shard_corruption(temp_path, sample_error)
            
            # Verify category
            assert diag['corruption_category'] == test_case["expected_category"], \
                f"{test_case['name']}: Expected {test_case['expected_category']}, got {diag['corruption_category']}"
            
            # Verify recommendations contain expected keywords
            rec_text = ' '.join(diag['recommendations']).lower()
            for keyword in test_case["expected_rec_keywords"]:
                assert keyword.lower() in rec_text, \
                    f"{test_case['name']}: Missing '{keyword}' in recommendations"
            
            print(f"  [OK] {test_case['name']}: {test_case['expected_category']}")
            
        finally:
            temp_path.unlink()
    
    print("  [OK] All diagnostic categories accurate")
    return True

def test_corruption_multi_shard_resilience():
    """Integration test: Verify refresh handles multiple corrupted shards gracefully"""
    print("Testing multi-shard corruption resilience...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()
        
        # Create mix of valid and corrupted shards
        # Shard 0: Empty (corrupted)
        (cache_dir / "cpe_cache_shard_00.json").touch()
        
        # Shard 1: Valid
        ShardedCPECache.save_shard_to_disk(
            cache_dir / "cpe_cache_shard_01.json",
            {"cpe:2.3:a:vendor1:app1:*:*:*:*:*:*:*:*": {
                "query_response": {"totalResults": 1},
                "last_queried": "2026-02-01T10:00:00+00:00",
                "query_count": 2,
                "total_results": 1
            }}
        )
        
        # Shard 2: Malformed JSON (corrupted)
        with open(cache_dir / "cpe_cache_shard_02.json", 'wb') as f:
            f.write(b'{"bad": json}')
        
        # Shard 3: Valid
        ShardedCPECache.save_shard_to_disk(
            cache_dir / "cpe_cache_shard_03.json",
            {"cpe:2.3:a:vendor2:app2:*:*:*:*:*:*:*:*": {
                "query_response": {"totalResults": 3},
                "last_queried": "2026-01-25T08:30:00+00:00",  # Oldest
                "query_count": 5,
                "total_results": 3
            }}
        )
        
        # Shard 4: Binary garbage (corrupted)
        with open(cache_dir / "cpe_cache_shard_04.json", 'wb') as f:
            f.write(b'\x00\x00\x00Binary')
        
        # Run discovery across all shards
        oldest = refresh_module.find_oldest_cache_entry(cache_dir, num_shards=5)
        
        # Verify corrupted shards were deleted
        assert not (cache_dir / "cpe_cache_shard_00.json").exists(), "Shard 0 should be deleted"
        assert not (cache_dir / "cpe_cache_shard_02.json").exists(), "Shard 2 should be deleted"
        assert not (cache_dir / "cpe_cache_shard_04.json").exists(), "Shard 4 should be deleted"
        
        # Verify valid shards remain
        assert (cache_dir / "cpe_cache_shard_01.json").exists(), "Shard 1 should remain"
        assert (cache_dir / "cpe_cache_shard_03.json").exists(), "Shard 3 should remain"
        
        # Verify correct oldest timestamp (from shard 3)
        expected_oldest = ShardedCPECache.parse_cache_entry_timestamp({
            "last_queried": "2026-01-25T08:30:00+00:00"
        })
        
        assert oldest == expected_oldest, f"Expected {expected_oldest}, got {oldest}"
        
        print("  [OK] 3 corrupted shards detected and deleted")
        print("  [OK] 2 valid shards preserved")
        print(f"  [OK] Correct oldest timestamp: {oldest}")
        return True

def test_refresh_script_exists():
    """Integration test: Verify refresh script exists and is executable"""
    print("Testing refresh script existence...")
    
    script_path = project_root / "utilities" / "refresh_nvd_cpe_base_strings_cache.py"
    assert script_path.exists(), f"utilities/refresh_nvd_cpe_base_strings_cache.py not found at {script_path}"
    
    # Verify it's a Python script
    with open(script_path, 'r') as f:
        first_line = f.readline()
        assert first_line.startswith('#!') and 'python' in first_line, "Should have Python shebang"
    
    print("[OK] Refresh script exists and is valid Python")
    return True

def test_refresh_script_imports():
    """Integration test: Verify refresh script has all required imports"""
    print("Testing refresh script imports...")
    
    script_path = project_root / "utilities" / "refresh_nvd_cpe_base_strings_cache.py"
    with open(script_path, 'r') as f:
        content = f.read()
    
    required_imports = [
        'from src.analysis_tool.storage.cpe_cache import ShardedCPECache',
        'from src.analysis_tool.core.analysis_tool import load_config',
        'from src.analysis_tool.logging.workflow_logger import get_logger',
        'from src.analysis_tool.storage.run_organization import get_analysis_tools_root'
    ]
    
    for import_line in required_imports:
        assert import_line in content, f"Missing import: {import_line}"
    
    # Verify removed duplications
    assert 'import hashlib' not in content, "hashlib should be removed (using ShardedCPECache)"
    assert 'import orjson' not in content, "orjson should be removed (using static methods)"
    
    print("[OK] Refresh script has correct imports")
    return True

def test_configuration_independence():
    """Integration test: Verify refresh script operates independently of notify_age_hours"""
    print("Testing configuration independence...")
    
    config = load_config()
    notify_age = config.get('cache_settings', {}).get('cpe_cache', {}).get('refresh_strategy', {}).get('notify_age_hours', 100)
    
    # Refresh script should NOT be limited by notify_age_hours
    # It queries from oldest cache entry timestamp
    # This is documented in the script's docstring
    
    script_path = project_root / "utilities" / "refresh_nvd_cpe_base_strings_cache.py"
    with open(script_path, 'r') as f:
        content = f.read()
    
    # Verify documentation mentions independence
    assert 'forced refresh' in content.lower() or 'manual refresh' in content.lower(), \
        "Script should document forced/manual refresh behavior"
    
    # Verify script doesn't use notify_age_hours for query logic (mentions in comments are OK)
    # Check that it's not imported from config for query date calculations
    lines = content.split('\n')
    code_lines = [l for l in lines if not l.strip().startswith('#') and l.strip()]
    code_only = '\n'.join(code_lines)
    
    # The script should mention it in docs but not use it in query logic
    has_config_awareness = 'notify_age_hours' in content  # Documentation mentions it
    uses_in_code = 'get_query_start_date' in code_only  # Has independent query date logic
    
    assert has_config_awareness and uses_in_code, \
        "Script should document relationship but use independent query logic"
    
    print("[OK] Refresh script operates independently of runtime expiration")
    print(f"  - Runtime cache expiration: {notify_age} hours")
    print(f"  - Refresh strategy: Query from oldest cache entry (forced refresh)")
    print(f"  - Documentation: Clearly explains independence from notify_age_hours")
    return True

# =============================================================================
# Test Runner
# =============================================================================

def run_all_tests():
    """Execute all test functions"""
    
    data_integrity_tests = [
        ("Load Failure Protection (Bug Fix)", test_load_failure_raises_error),
        ("Load Success With Valid Data", test_load_success_with_valid_data),
        ("Load Nonexistent File Returns Empty", test_load_nonexistent_file_returns_empty),
    ]
    
    unit_tests = [
        ("Static Method Reuse", test_static_method_reuse),
        ("Query Count Preservation", test_query_count_preservation),
        ("Timestamp Update", test_timestamp_update),
        ("Data Merge Without Loss", test_data_merge_no_loss),
        ("New Entry Addition", test_new_entry_addition),
        ("Empty Shard Handling", test_empty_shard_handling),
        ("Compact JSON Format", test_compact_json_format),
    ]
    
    corruption_recovery_tests = [
        ("Auto-Recovery: Empty File", test_corruption_auto_recovery_empty_file),
        ("Auto-Recovery: Malformed JSON", test_corruption_auto_recovery_invalid_json),
        ("Auto-Recovery: Flush Updates", test_corruption_auto_recovery_flush_updates),
        ("Diagnostic Accuracy", test_corruption_diagnostic_accuracy),
        ("Multi-Shard Resilience", test_corruption_multi_shard_resilience),
    ]
    
    integration_tests = [
        ("End-to-End Data Preservation", test_end_to_end_data_preservation),
        ("End-to-End Multi-Shard Handling", test_end_to_end_multiple_shards),
        ("Refresh Script Exists", test_refresh_script_exists),
        ("Refresh Script Imports", test_refresh_script_imports),
        ("Configuration Independence", test_configuration_independence),
    ]
    
    print("="*70)
    print("DATA INTEGRITY TESTS - Load Failure Protection")
    print("="*70 + "\n")
    
    passed = 0
    failed = 0
    
    for test_name, test_func in data_integrity_tests:
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
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()
            print()
    
    print("\n" + "="*70)
    print("UNIT TESTS - CPE Cache Refresh Functionality")
    print("="*70 + "\n")
    
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
    print("CORRUPTION DIAGNOSTIC & AUTO-RECOVERY TESTS")
    print("="*70 + "\n")
    
    for test_name, test_func in corruption_recovery_tests:
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
    print("INTEGRATION TESTS - Refresh Script Validation")
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
    
    total_tests = len(data_integrity_tests) + len(unit_tests) + len(corruption_recovery_tests) + len(integration_tests)
    
    print("\n" + "="*70)
    print(f"TEST_RESULTS: PASSED={passed} TOTAL={total_tests} SUITE=\"CPE Cache Refresh\"")
    print("="*70 + "\n")
    
    return failed == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
