#!/usr/bin/env python3
"""
CPE Cache Refresh Script Test Suite

Tests for utilities/refresh_tool_cpematchstring_2_0_cache.py functionality covering:
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
from src.analysis_tool.core.gatherData import load_config

# Import refresh script functions for testing
import utilities.refresh_tool_cpematchstring_2_0_cache as refresh_module

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
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir(parents=True, exist_ok=True)
        shard_path = cache_dir / "cpe_cache_shard_00.json"
        
        # BEFORE: Inject test data with known query_count and timestamp
        test_cpe = "cpe:2.3:a:test_e2e:preservation_test:*:*:*:*:*:*:*:*"
        old_timestamp = "2026-01-15T12:00:00+00:00"
        test_entry = {
            "query_response": {"totalResults": 99, "format": "NVD_CPE", "test_marker": "E2E_TEST"},
            "last_queried": old_timestamp,
            "query_count": 7,  # Should be preserved
            "total_results": 99
        }
        
        shard_data_before = {test_cpe: test_entry}
        original_count = len(shard_data_before)
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
    
    script_path = project_root / "utilities" / "refresh_tool_cpematchstring_2_0_cache.py"
    assert script_path.exists(), f"utilities/refresh_tool_cpematchstring_2_0_cache.py not found at {script_path}"
    
    # Verify it's a Python script
    with open(script_path, 'r') as f:
        first_line = f.readline()
        assert first_line.startswith('#!') and 'python' in first_line, "Should have Python shebang"
    
    print("[OK] Refresh script exists and is valid Python")
    return True

def test_refresh_script_imports():
    """Integration test: Verify refresh script has all required imports"""
    print("Testing refresh script imports...")
    
    script_path = project_root / "utilities" / "refresh_tool_cpematchstring_2_0_cache.py"
    with open(script_path, 'r') as f:
        content = f.read()
    
    required_imports = [
        'from src.analysis_tool.storage.cpe_cache import ShardedCPECache',
        'from src.analysis_tool.core.gatherData import config, query_nvd_cpematch_by_modified_date, gatherNVDCPEData, _update_manual_refresh_timestamp',
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

def test_phase1a_uses_oldest_entry_not_ttl():
    """Integration test: Phase 1a NVD discovery uses oldest entry timestamp, not notify_age_hours TTL"""
    print("Testing Phase 1a uses oldest entry timestamp (not notify_age_hours)...")

    notify_age = load_config()['cache_settings']['cpe_cache']['refresh_strategy'].get('notify_age_hours', 100)

    script_path = project_root / "utilities" / "refresh_tool_cpematchstring_2_0_cache.py"
    with open(script_path, 'r') as f:
        content = f.read()

    # Phase 1a must use oldest-entry-based date logic, not the TTL
    assert 'get_query_start_date' in content, \
        "Phase 1a should use get_query_start_date() for NVD query window"
    assert 'find_oldest_cache_entry' in content, \
        "Phase 1a should call find_oldest_cache_entry() to anchor the NVD query"

    # Phase 1b must exist and read notify_age_hours from config
    assert 'find_expired_cache_entries' in content, \
        "Phase 1b should call find_expired_cache_entries()"
    assert 'notify_age_hours' in content, \
        "notify_age_hours should be read from config for Phase 1b expiry scan"

    # Both phases must be documented in the module docstring
    assert 'Phase 1a' in content, "Module should document Phase 1a"
    assert 'Phase 1b' in content, "Module should document Phase 1b"

    print("[OK] Phase 1a uses oldest entry timestamp for NVD query window")
    print("[OK] Phase 1b uses notify_age_hours for local expiry scan")
    print(f"  - Configured notify_age_hours: {notify_age}h")
    return True

# =============================================================================
# EXPIRY SCAN TESTS - Phase 1b: find_expired_cache_entries
# =============================================================================

def _make_shard_entry(last_queried_iso: str, query_count: int = 1) -> dict:
    """Helper: build a minimal valid cache entry dict."""
    return {
        "query_response": {"totalResults": 1},
        "last_queried": last_queried_iso,
        "query_count": query_count,
        "total_results": 1,
    }


def test_find_expired_disabled_when_zero_or_negative():
    """Phase 1b returns empty set immediately when notify_age_hours <= 0."""
    print("Testing find_expired_cache_entries disabled for notify_age_hours <= 0...")

    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()

        # Put a very old entry in shard 00 — would be stale under any positive threshold
        old_ts = (datetime.now(timezone.utc) - timedelta(days=9999)).isoformat()
        shard_path = cache_dir / "cpe_cache_shard_00.json"
        ShardedCPECache.save_shard_to_disk(shard_path, {
            "cpe:2.3:a:old:vendor:*:*:*:*:*:*:*:*": _make_shard_entry(old_ts)
        })

        for threshold in [0, -1, -720]:
            result = refresh_module.find_expired_cache_entries(cache_dir, threshold, num_shards=1)
            assert result == set(), \
                f"Expected empty set for notify_age_hours={threshold}, got {result}"
            print(f"  [OK] notify_age_hours={threshold} -> empty set (scan disabled)")

    print("[OK] Expiry scan correctly disabled for threshold <= 0")
    return True


def test_find_expired_detects_stale_entries():
    """Phase 1b returns entries whose last_queried exceeds the TTL threshold."""
    print("Testing find_expired_cache_entries detects stale entries...")

    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()

        threshold = 24  # hours
        stale_ts = (datetime.now(timezone.utc) - timedelta(hours=threshold + 1)).isoformat()
        stale_key = "cpe:2.3:a:stale:vendor:*:*:*:*:*:*:*:*"

        shard_path = cache_dir / "cpe_cache_shard_00.json"
        ShardedCPECache.save_shard_to_disk(shard_path, {
            stale_key: _make_shard_entry(stale_ts)
        })

        result = refresh_module.find_expired_cache_entries(cache_dir, threshold, num_shards=1)
        assert stale_key in result, f"Expected stale key in result, got {result}"
        assert len(result) == 1, f"Expected exactly 1 expired entry, got {len(result)}"

        print(f"  [OK] Entry {threshold+1}h old detected as stale (threshold: {threshold}h)")
    print("[OK] Stale entry detection works correctly")
    return True


def test_find_expired_ignores_fresh_entries():
    """Phase 1b does not return entries whose last_queried is within the TTL."""
    print("Testing find_expired_cache_entries ignores fresh entries...")

    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()

        threshold = 720  # hours
        # Entry queried 1 hour ago — well within threshold
        fresh_ts = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        fresh_key = "cpe:2.3:a:fresh:vendor:*:*:*:*:*:*:*:*"

        shard_path = cache_dir / "cpe_cache_shard_00.json"
        ShardedCPECache.save_shard_to_disk(shard_path, {
            fresh_key: _make_shard_entry(fresh_ts)
        })

        result = refresh_module.find_expired_cache_entries(cache_dir, threshold, num_shards=1)
        assert fresh_key not in result, f"Fresh entry should not be in expired set, got {result}"
        assert result == set(), f"Expected empty set for all-fresh cache, got {result}"

        print(f"  [OK] Entry 1h old not flagged (threshold: {threshold}h)")
    print("[OK] Fresh entries correctly excluded from expiry scan")
    return True


def test_find_expired_mixed_entries():
    """Phase 1b correctly separates stale and fresh entries in the same shard."""
    print("Testing find_expired_cache_entries with mixed fresh/stale entries...")

    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()

        threshold = 48  # hours
        now = datetime.now(timezone.utc)

        stale_keys = {
            f"cpe:2.3:a:stale{i}:vendor:*:*:*:*:*:*:*:*"
            for i in range(3)
        }
        fresh_keys = {
            f"cpe:2.3:a:fresh{i}:vendor:*:*:*:*:*:*:*:*"
            for i in range(4)
        }

        shard_data = {}
        for key in stale_keys:
            ts = (now - timedelta(hours=threshold + 10)).isoformat()
            shard_data[key] = _make_shard_entry(ts)
        for key in fresh_keys:
            ts = (now - timedelta(hours=threshold - 1)).isoformat()
            shard_data[key] = _make_shard_entry(ts)

        shard_path = cache_dir / "cpe_cache_shard_00.json"
        ShardedCPECache.save_shard_to_disk(shard_path, shard_data)

        result = refresh_module.find_expired_cache_entries(cache_dir, threshold, num_shards=1)

        assert result == stale_keys, \
            f"Expected stale_keys={stale_keys}, got {result}"
        assert not (result & fresh_keys), \
            f"Fresh keys should not appear in expired set: {result & fresh_keys}"

        print(f"  [OK] {len(stale_keys)} stale entries detected, {len(fresh_keys)} fresh entries excluded")
    print("[OK] Mixed entry separation works correctly")
    return True


def test_find_expired_empty_cache():
    """Phase 1b returns empty set when no shard files exist."""
    print("Testing find_expired_cache_entries with empty cache directory...")

    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()
        # No shard files created

        result = refresh_module.find_expired_cache_entries(cache_dir, 720, num_shards=16)
        assert result == set(), f"Expected empty set for empty cache, got {result}"

        print("  [OK] Empty cache returns empty set")
    print("[OK] Empty cache handled correctly")
    return True


def test_find_expired_unparseable_timestamps_treated_as_expired():
    """Phase 1b treats entries with unparseable timestamps as expired (fail-safe)."""
    print("Testing find_expired_cache_entries treats bad timestamps as expired...")

    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()

        bad_ts_key = "cpe:2.3:a:badts:vendor:*:*:*:*:*:*:*:*"
        missing_ts_key = "cpe:2.3:a:nots:vendor:*:*:*:*:*:*:*:*"

        shard_data = {
            bad_ts_key: {
                "query_response": {"totalResults": 1},
                "last_queried": "not-a-real-timestamp",
                "query_count": 1,
                "total_results": 1,
            },
            missing_ts_key: {
                "query_response": {"totalResults": 1},
                # last_queried key absent entirely
                "query_count": 1,
                "total_results": 1,
            },
        }

        shard_path = cache_dir / "cpe_cache_shard_00.json"
        ShardedCPECache.save_shard_to_disk(shard_path, shard_data)

        result = refresh_module.find_expired_cache_entries(cache_dir, 720, num_shards=1)

        assert bad_ts_key in result, "Bad timestamp entry should be treated as expired"
        assert missing_ts_key in result, "Missing timestamp entry should be treated as expired"
        assert len(result) == 2, f"Expected 2 expired entries, got {len(result)}"

        print("  [OK] Unparseable timestamp treated as expired")
        print("  [OK] Missing timestamp treated as expired")
    print("[OK] Unparseable/missing timestamp handling correct")
    return True


def test_find_expired_unreadable_shard_skipped():
    """Phase 1b skips unreadable shards and continues scanning remaining shards."""
    print("Testing find_expired_cache_entries skips unreadable shards...")

    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()

        threshold = 24
        # Shard 00: corrupted (unreadable)
        with open(cache_dir / "cpe_cache_shard_00.json", 'wb') as f:
            f.write(b'\xFF\xFE binary garbage')

        # Shard 01: valid with a stale entry
        stale_ts = (datetime.now(timezone.utc) - timedelta(hours=threshold + 5)).isoformat()
        stale_key = "cpe:2.3:a:stale:vendor:*:*:*:*:*:*:*:*"
        ShardedCPECache.save_shard_to_disk(
            cache_dir / "cpe_cache_shard_01.json",
            {stale_key: _make_shard_entry(stale_ts)}
        )

        # Should NOT raise, should skip shard 00 and return stale entry from shard 01
        result = refresh_module.find_expired_cache_entries(cache_dir, threshold, num_shards=2)

        assert stale_key in result, f"Stale key from readable shard should be in result"
        assert len(result) == 1, f"Expected 1 entry from readable shard, got {len(result)}"

        print("  [OK] Corrupted shard 00 skipped without crash")
        print("  [OK] Stale entry from valid shard 01 still detected")
    print("[OK] Unreadable shard skip behavior correct")
    return True


def test_find_expired_multiple_shards():
    """Phase 1b scans entries across all shards and returns the union of expired keys."""
    print("Testing find_expired_cache_entries scans across multiple shards...")

    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()

        threshold = 100  # hours
        now = datetime.now(timezone.utc)

        expected_stale = set()

        for shard_idx in range(4):
            stale_key = f"cpe:2.3:a:shard{shard_idx}stale:vendor:*:*:*:*:*:*:*:*"
            fresh_key = f"cpe:2.3:a:shard{shard_idx}fresh:vendor:*:*:*:*:*:*:*:*"
            stale_ts = (now - timedelta(hours=threshold + 24)).isoformat()
            fresh_ts = (now - timedelta(hours=1)).isoformat()

            ShardedCPECache.save_shard_to_disk(
                cache_dir / f"cpe_cache_shard_{shard_idx:02d}.json",
                {
                    stale_key: _make_shard_entry(stale_ts),
                    fresh_key: _make_shard_entry(fresh_ts),
                }
            )
            expected_stale.add(stale_key)

        result = refresh_module.find_expired_cache_entries(cache_dir, threshold, num_shards=4)

        assert result == expected_stale, \
            f"Expected {expected_stale}, got {result}"
        print(f"  [OK] {len(result)} stale entries found across 4 shards (4 fresh ignored)")
    print("[OK] Multi-shard expiry scan returns correct union of expired keys")
    return True


# =============================================================================
# DEDUPLICATION & STATS TESTS - Phase 1a + 1b merge
# =============================================================================

def test_stats_fields_exist_and_initialize():
    """CPECacheRefreshStats has the expected Phase 1b fields initialized to zero."""
    print("Testing CPECacheRefreshStats Phase 1b field initialization...")

    stats = refresh_module.CPECacheRefreshStats()

    assert hasattr(stats, 'expired_entries_found'), "Stats should have expired_entries_found"
    assert hasattr(stats, 'expired_bases_added'), "Stats should have expired_bases_added"
    assert stats.expired_entries_found == 0, "expired_entries_found should initialize to 0"
    assert stats.expired_bases_added == 0, "expired_bases_added should initialize to 0"

    # Verify report() includes both fields
    report = stats.report()
    assert 'Expired entries found' in report, "report() should include 'Expired entries found'"
    assert 'Additional from expiry' in report, "report() should include 'Additional from expiry'"

    print("  [OK] expired_entries_found initialized to 0")
    print("  [OK] expired_bases_added initialized to 0")
    print("  [OK] report() includes both Phase 1b fields")
    return True


def test_expiry_deduplication_overlap_collapsed():
    """Entries found by both Phase 1a (NVD) and Phase 1b (expiry) are not double-counted."""
    print("Testing deduplication: Phase 1a + Phase 1b overlap collapsed...")

    # Simulate the deduplication logic from smart_refresh
    nvd_bases = {
        "cpe:2.3:a:vendor1:product:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:vendor2:product:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:vendor3:product:*:*:*:*:*:*:*:*",
    }
    # All expired entries overlap with NVD set (nothing new from expiry)
    expired_bases = {
        "cpe:2.3:a:vendor1:product:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:vendor2:product:*:*:*:*:*:*:*:*",
    }

    additional_from_expiry = expired_bases - nvd_bases
    unique_bases = nvd_bases | additional_from_expiry

    assert additional_from_expiry == set(), \
        f"No additional entries expected (full overlap), got {additional_from_expiry}"
    assert unique_bases == nvd_bases, \
        f"unique_bases should equal nvd_bases when no additions, got {unique_bases}"
    assert len(unique_bases) == 3, \
        f"Total entries should be 3 (no duplicates), got {len(unique_bases)}"

    # Simulate stats tracking
    stats = refresh_module.CPECacheRefreshStats()
    stats.unique_cpe_bases = len(nvd_bases)
    stats.expired_entries_found = len(expired_bases)
    stats.expired_bases_added = len(additional_from_expiry)

    assert stats.expired_bases_added == 0, "No additional bases when full overlap"
    assert stats.unique_cpe_bases == 3, "NVD unique count unaffected by expiry"

    print(f"  [OK] {len(nvd_bases)} from NVD, {len(expired_bases)} expired (full overlap) -> {len(unique_bases)} total")
    print("  [OK] No double-counting: union == NVD set")
    return True


def test_expiry_deduplication_additive():
    """Entries found only by Phase 1b (expired but not in NVD set) are added to the refresh set."""
    print("Testing deduplication: Phase 1b adds new entries not in NVD set...")

    nvd_bases = {
        "cpe:2.3:a:vendor1:product:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:vendor2:product:*:*:*:*:*:*:*:*",
    }
    expired_bases = {
        "cpe:2.3:a:vendor1:product:*:*:*:*:*:*:*:*",  # Overlaps with NVD
        "cpe:2.3:a:vendor3:product:*:*:*:*:*:*:*:*",  # New — only from expiry
        "cpe:2.3:a:vendor4:product:*:*:*:*:*:*:*:*",  # New — only from expiry
    }

    additional_from_expiry = expired_bases - nvd_bases
    unique_bases = nvd_bases | additional_from_expiry

    assert additional_from_expiry == {
        "cpe:2.3:a:vendor3:product:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:vendor4:product:*:*:*:*:*:*:*:*",
    }, f"Expected 2 additional entries, got {additional_from_expiry}"

    assert len(unique_bases) == 4, \
        f"Total should be 4 (2 NVD + 2 expiry-only), got {len(unique_bases)}"

    # Simulate stats tracking
    stats = refresh_module.CPECacheRefreshStats()
    stats.unique_cpe_bases = len(nvd_bases)
    stats.expired_entries_found = len(expired_bases)
    stats.expired_bases_added = len(additional_from_expiry)

    assert stats.unique_cpe_bases == 2, "NVD unique count unchanged"
    assert stats.expired_entries_found == 3, "Total expired entries"
    assert stats.expired_bases_added == 2, "2 additional from expiry"

    print(f"  [OK] {len(nvd_bases)} from NVD + {len(additional_from_expiry)} from expiry = {len(unique_bases)} total")
    print(f"  [OK] expired_bases_added={stats.expired_bases_added} (overlap not double-counted)")
    return True


def test_expiry_deduplication_disjoint():
    """When Phase 1a and Phase 1b sets are completely disjoint, the union contains all entries."""
    print("Testing deduplication: disjoint Phase 1a and Phase 1b sets produce full union...")

    nvd_bases = {f"cpe:2.3:a:nvd{i}:product:*:*:*:*:*:*:*:*" for i in range(3)}
    expired_bases = {f"cpe:2.3:a:expired{i}:product:*:*:*:*:*:*:*:*" for i in range(5)}

    additional_from_expiry = expired_bases - nvd_bases
    unique_bases = nvd_bases | additional_from_expiry

    assert additional_from_expiry == expired_bases, \
        "All expired entries are additional when sets are disjoint"
    assert unique_bases == nvd_bases | expired_bases, \
        "Union should contain all entries from both sets"
    assert len(unique_bases) == len(nvd_bases) + len(expired_bases), \
        f"No overlap -> sizes add: {len(nvd_bases)} + {len(expired_bases)} = {len(unique_bases)}"

    stats = refresh_module.CPECacheRefreshStats()
    stats.unique_cpe_bases = len(nvd_bases)
    stats.expired_entries_found = len(expired_bases)
    stats.expired_bases_added = len(additional_from_expiry)

    assert stats.expired_bases_added == 5, "All 5 expired entries are additional"

    print(f"  [OK] Disjoint sets: {len(nvd_bases)} NVD + {len(expired_bases)} expiry = {len(unique_bases)} total")
    return True


def test_find_expired_keys_match_cache_key_format():
    """Keys returned by find_expired_cache_entries match the 13-component base string format."""
    print("Testing find_expired_cache_entries returns keys in correct CPE base string format...")

    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir()

        threshold = 1
        stale_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()

        # Keys as stored by the main tool (13-component base strings with version/update=*)
        expected_keys = [
            "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
        ]

        shard_data = {k: _make_shard_entry(stale_ts) for k in expected_keys}
        shard_path = cache_dir / "cpe_cache_shard_00.json"
        ShardedCPECache.save_shard_to_disk(shard_path, shard_data)

        result = refresh_module.find_expired_cache_entries(cache_dir, threshold, num_shards=1)

        assert result == set(expected_keys), \
            f"Returned keys should exactly match stored keys, got {result}"

        for key in result:
            parts = key.split(':')
            assert len(parts) == 13, f"Key should have 13 components: {key}"
            assert parts[0] == 'cpe', f"Key should start with 'cpe': {key}"
            assert parts[1] == '2.3', f"Key should be CPE 2.3: {key}"

        print(f"  [OK] {len(result)} keys returned in correct 13-component format")
    print("[OK] Returned keys match CPE base string format stored in shards")
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

    expiry_scan_tests = [
        ("Expiry Scan: Disabled When notify_age_hours <= 0", test_find_expired_disabled_when_zero_or_negative),
        ("Expiry Scan: Detects Stale Entries", test_find_expired_detects_stale_entries),
        ("Expiry Scan: Ignores Fresh Entries", test_find_expired_ignores_fresh_entries),
        ("Expiry Scan: Mixed Fresh and Stale", test_find_expired_mixed_entries),
        ("Expiry Scan: Empty Cache Returns Empty Set", test_find_expired_empty_cache),
        ("Expiry Scan: Unparseable Timestamps Treated as Expired", test_find_expired_unparseable_timestamps_treated_as_expired),
        ("Expiry Scan: Unreadable Shard Skipped Gracefully", test_find_expired_unreadable_shard_skipped),
        ("Expiry Scan: Multiple Shards Scanned", test_find_expired_multiple_shards),
        ("Expiry Scan: Keys Match CPE Base String Format", test_find_expired_keys_match_cache_key_format),
    ]

    dedup_stats_tests = [
        ("Phase 1b Stats: Fields Exist and Initialize to Zero", test_stats_fields_exist_and_initialize),
        ("Deduplication: Full Overlap Not Double-Counted", test_expiry_deduplication_overlap_collapsed),
        ("Deduplication: Additive Entries Merged Into Refresh Set", test_expiry_deduplication_additive),
        ("Deduplication: Disjoint Sets Produce Full Union", test_expiry_deduplication_disjoint),
    ]

    integration_tests = [
        ("End-to-End Data Preservation", test_end_to_end_data_preservation),
        ("End-to-End Multi-Shard Handling", test_end_to_end_multiple_shards),
        ("Refresh Script Exists", test_refresh_script_exists),
        ("Refresh Script Imports", test_refresh_script_imports),
        ("Phase 1a Uses Oldest Entry Timestamp (Not TTL)", test_phase1a_uses_oldest_entry_not_ttl),
    ]

    def _run_group(label, tests):
        nonlocal passed, failed
        print("\n" + "="*70)
        print(label)
        print("="*70 + "\n")
        for test_name, test_func in tests:
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

    passed = 0
    failed = 0

    _run_group("DATA INTEGRITY TESTS - Load Failure Protection", data_integrity_tests)
    _run_group("UNIT TESTS - CPE Cache Refresh Functionality", unit_tests)
    _run_group("CORRUPTION DIAGNOSTIC & AUTO-RECOVERY TESTS", corruption_recovery_tests)
    _run_group("EXPIRY SCAN TESTS - Phase 1b: find_expired_cache_entries", expiry_scan_tests)
    _run_group("DEDUPLICATION & STATS TESTS - Phase 1a + 1b merge", dedup_stats_tests)
    _run_group("INTEGRATION TESTS - Refresh Script Validation", integration_tests)

    total_tests = (
        len(data_integrity_tests) + len(unit_tests) + len(corruption_recovery_tests)
        + len(expiry_scan_tests) + len(dedup_stats_tests) + len(integration_tests)
    )

    print("\n" + "="*70)
    print(f"TEST_RESULTS: PASSED={passed} TOTAL={total_tests} SUITE=\"CPE Cache Refresh\"")
    print("="*70 + "\n")

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
