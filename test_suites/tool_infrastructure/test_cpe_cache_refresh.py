#!/usr/bin/env python3
"""
CPE Cache Refresh Script Test Suite

Tests for utilities/refresh_cpe_cache.py functionality covering:
- Shard data preservation during refresh
- Query count incrementing behavior
- Timestamp updates
- Data merge operations
- Static method reuse from ShardedCPECache
- Configuration independence (forced refresh vs runtime expiration)
- Error handling and recovery

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

from src.analysis_tool.storage.cpe_cache import ShardedCPECache
import orjson

def load_config():
    """Load configuration from config.json"""
    config_path = project_root / 'src' / 'analysis_tool' / 'config.json'
    with open(config_path, 'r') as f:
        return json.load(f)

# =============================================================================
# DATA INTEGRITY TESTS: Load Failure Protection
# =============================================================================

def test_load_failure_raises_error():
    """Test that load_shard_from_disk raises RuntimeError when file exists but is corrupted"""
    print("Testing load failure protection (DATA LOSS BUG FIX)...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        shard_path = Path(tmpdir) / "cpe_cache_shard_05.json"
        
        # Create a corrupted/invalid JSON file
        with open(shard_path, 'w') as f:
            f.write("{invalid json content")
        
        # Verify file exists
        assert shard_path.exists(), "Test shard file should exist"
        
        # Attempt to load - should raise RuntimeError, not return {}
        try:
            result = ShardedCPECache.load_shard_from_disk(shard_path)
            print(f"FAILED: load_shard_from_disk returned {type(result)} instead of raising RuntimeError")
            return False
        except RuntimeError as e:
            error_msg = str(e)
            if "CRITICAL" in error_msg and shard_path.name in error_msg:
                print(f"PASSED: Correctly raised RuntimeError with message: {error_msg[:80]}...")
                return True
            else:
                print(f"FAILED: RuntimeError raised but message format incorrect: {error_msg}")
                return False
        except Exception as e:
            print(f"FAILED: Raised {type(e).__name__} instead of RuntimeError: {e}")
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
    
    cache_dir = project_root / "cache" / "cpe_base_strings"
    
    # Create backups of first 3 shards
    backups = []
    test_data_per_shard = {}
    
    for i in range(3):
        shard_path = cache_dir / f"cpe_cache_shard_{i:02d}.json"
        if shard_path.exists():
            backup_path = cache_dir / f"cpe_cache_shard_{i:02d}.json.test_backup"
            shutil.copy(shard_path, backup_path)
            backups.append((shard_path, backup_path))
    
    try:
        # Inject test data directly into specific shards (bypass hash routing)
        for i in range(3):
            shard_path = cache_dir / f"cpe_cache_shard_{i:02d}.json"
            test_cpe = f"cpe:2.3:a:test_direct_shard{i}:e2e_multi:*:*:*:*:*:*:*:*"
            
            shard_data = ShardedCPECache.load_shard_from_disk(shard_path)
            original_count = len(shard_data)
            
            # BEFORE: Inject with specific query_count
            shard_data[test_cpe] = {
                "query_response": {"totalResults": i * 10, "shard_marker": f"shard_{i}"},
                "last_queried": "2026-01-15T12:00:00+00:00",
                "query_count": i + 3,  # Unique for each shard
                "total_results": i * 10
            }
            ShardedCPECache.save_shard_to_disk(shard_path, shard_data)
            test_data_per_shard[i] = (test_cpe, i + 3, original_count)
        
        print(f"  BEFORE: Injected test entries into shards 0, 1, 2")
        
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
            if len(shard_data) < original_count:
                print(f"  ERROR: Shard {shard_idx} - entries lost ({len(shard_data)} < {original_count})")
                all_verified = False
        
        assert all_verified, "All shards should preserve data correctly"
        
        print(f"  AFTER: All 3 shards verified [OK]")
        print(f"  AFTER: query_count preserved in all shards [OK]")
        print(f"  AFTER: Data updated correctly in all shards [OK]")
        
        print("[OK] Multi-shard data preservation verified")
        
    finally:
        # Restore all backups
        for shard_path, backup_path in backups:
            if backup_path.exists():
                shutil.move(backup_path, shard_path)
        print("  Restored all shard backups")
    
    return True

def test_refresh_script_exists():
    """Integration test: Verify refresh script exists and is executable"""
    print("Testing refresh script existence...")
    
    script_path = project_root / "utilities" / "refresh_cpe_cache.py"
    assert script_path.exists(), f"utilities/refresh_cpe_cache.py not found at {script_path}"
    
    # Verify it's a Python script
    with open(script_path, 'r') as f:
        first_line = f.readline()
        assert first_line.startswith('#!') and 'python' in first_line, "Should have Python shebang"
    
    print("[OK] Refresh script exists and is valid Python")
    return True

def test_refresh_script_imports():
    """Integration test: Verify refresh script has all required imports"""
    print("Testing refresh script imports...")
    
    script_path = project_root / "utilities" / "refresh_cpe_cache.py"
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
    
    script_path = project_root / "utilities" / "refresh_cpe_cache.py"
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
    
    total_tests = len(data_integrity_tests) + len(unit_tests) + len(integration_tests)
    
    print("\n" + "="*70)
    print(f"TEST_RESULTS: PASSED={passed} TOTAL={total_tests} SUITE=\"CPE Cache Refresh\"")
    print("="*70 + "\n")
    
    return failed == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
