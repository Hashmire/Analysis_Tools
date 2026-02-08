"""
Test Suite: CPE UTF-8 Validation (Surrogate Pair Prevention)

Purpose: Verify that CPE responses with invalid UTF-8 (surrogate pairs, etc.) 
         are REJECTED before caching to prevent shard corruption.

Bug History:
- Issue: NVD API occasionally returns data with UTF-8 surrogate pairs
- Symptom: Shards saved successfully but fail to load with "surrogates not allowed" error
- Root Cause: orjson.dumps() accepts surrogates, but orjson.loads() rejects them
- Fix: Round-trip validation (dumps → loads) in validate_orjson_serializable()
        + upstream validation in processData.py before cache.put()

Test Coverage:
1. test_valid_cpe_response_caches - Normal data passes validation and caches
2. test_surrogate_pair_rejected_before_cache - Surrogate pairs caught, not cached
3. test_invalid_utf8_rejected_before_cache - Other UTF-8 issues caught
4. test_corrupted_shard_not_created - Verify no shard file created for bad data
"""

import sys
import os
import tempfile
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.analysis_tool.core.schema_validator import validate_cpe_data, NVDSchemaValidationError
from src.analysis_tool.storage.cpe_cache import ShardedCPECache
import orjson

# Test decorator
def test(description):
    """Simple test decorator for consistent output"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            print(f"\n{'='*60}")
            print(f"TEST: {description}")
            print('='*60)
            try:
                result = func(*args, **kwargs)
                if result:
                    print(f"✓ PASS: {description}")
                else:
                    print(f"✗ FAIL: {description}")
                return result
            except AssertionError as e:
                print(f"✗ FAIL: {description}")
                print(f"  Assertion: {e}")
                return False
            except Exception as e:
                print(f"✗ ERROR: {description}")
                print(f"  Exception: {type(e).__name__}: {e}")
                return False
        return wrapper
    return decorator

# =============================================================================
# UTF-8 VALIDATION TESTS
# =============================================================================

@test("Valid CPE response passes validation and can be cached")
def test_valid_cpe_response_caches():
    """Test that normal CPE responses pass validation"""
    
    # Create valid CPE API response
    valid_response = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "products": [
            {
                "cpe": {
                    "cpeName": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                    "cpeNameId": "12345678-1234-1234-1234-123456789ABC",
                    "titles": [{"title": "Test Product", "lang": "en"}]
                }
            }
        ]
    }
    
    # Test 1: Validation should succeed
    try:
        validated = validate_cpe_data(valid_response, "cpe:2.3:a:vendor:product:*", schema=None)
        print("  ✓ validate_cpe_data() accepted valid response")
    except NVDSchemaValidationError as e:
        print(f"  ✗ validate_cpe_data() rejected valid data: {e}")
        return False
    
    # Test 2: Should be serializable
    try:
        serialized = orjson.dumps(validated)
        deserialized = orjson.loads(serialized)
        print("  ✓ Round-trip serialization successful")
    except Exception as e:
        print(f"  ✗ Round-trip failed: {e}")
        return False
    
    # Test 3: Cache should accept it
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            'enabled': True,
            'max_loaded_shards': 4,
            'auto_save_threshold': 0,
            'refresh_strategy': {'notify_age_hours': 100}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache.cache_dir.mkdir(parents=True, exist_ok=True)
        
        cpe_string = "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"
        cache.put(cpe_string, validated)
        
        # Verify it was cached
        retrieved, status = cache.get(cpe_string)
        assert status == 'hit', f"Expected cache hit, got {status}"
        print(f"  ✓ Data successfully cached and retrieved")
    
    return True

@test("Surrogate pairs are rejected BEFORE caching")
def test_surrogate_pair_rejected_before_cache():
    """Test that UTF-8 surrogate pairs are caught by validation"""
    
    # Create CPE response with surrogate pair (invalid UTF-8)
    # This simulates the exact corruption we saw in production
    corrupt_response = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "products": [
            {
                "cpe": {
                    "cpeName": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                    "cpeNameId": "12345678-1234-1234-1234-123456789ABC",
                    "titles": [
                        {
                            "title": "Test \uD800Product",  # High surrogate (invalid)
                            "lang": "en"
                        }
                    ]
                }
            }
        ]
    }
    
    # Test 1: Validation should REJECT this
    validation_failed = False
    try:
        validate_cpe_data(corrupt_response, "cpe:2.3:a:vendor:product:*", schema=None)
        print("  ✗ validate_cpe_data() FAILED to reject surrogate pair!")
        return False
    except NVDSchemaValidationError as e:
        error_msg = str(e)
        if "surrogate" in error_msg.lower() or "utf-8" in error_msg.lower():
            print(f"  ✓ validate_cpe_data() correctly rejected: {error_msg[:100]}")
            validation_failed = True
        else:
            print(f"  ? Rejected but unexpected error: {error_msg[:100]}")
            return False
    
    # Test 2: Verify orjson behavior (dumps succeeds, loads fails)
    try:
        serialized = orjson.dumps(corrupt_response)
        print("  ✓ orjson.dumps() accepted surrogate (expected)")
        
        # This should fail
        try:
            orjson.loads(serialized)
            print("  ✗ orjson.loads() SHOULD HAVE failed on surrogate!")
            return False
        except Exception as e:
            if "surrogate" in str(e).lower():
                print(f"  ✓ orjson.loads() correctly rejected surrogate: {str(e)[:80]}")
            else:
                print(f"  ? orjson.loads() failed but unexpected error: {str(e)[:80]}")
    except Exception as e:
        print(f"  ? orjson.dumps() failed unexpectedly: {e}")
    
    return validation_failed

@test("Various invalid UTF-8 sequences are rejected")
def test_invalid_utf8_rejected_before_cache():
    """Test that various UTF-8 encoding issues are caught"""
    
    test_cases = [
        ("Low surrogate", {"title": "Test \uDC00Product"}),  # Low surrogate
        ("Surrogate pair", {"title": "Test \uD800\uDC00Product"}),  # Surrogate pair
        ("High surrogate alone", {"title": "\uDBFFProduct"}),  # High surrogate
    ]
    
    all_rejected = True
    
    for test_name, invalid_data in test_cases:
        response = {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "products": [
                {
                    "cpe": {
                        "cpeName": "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*",
                        "cpeNameId": "test-uuid",
                        "titles": [invalid_data]
                    }
                }
            ]
        }
        
        try:
            validate_cpe_data(response, "test_cpe", schema=None)
            print(f"  ✗ {test_name}: NOT rejected (should have been)")
            all_rejected = False
        except NVDSchemaValidationError:
            print(f"  ✓ {test_name}: Correctly rejected")
    
    return all_rejected

@test("Corrupted shard files are NOT created on validation failure")
def test_corrupted_shard_not_created():
    """Verify that validation prevents corrupted files from being written"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cpe_base_strings"
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        config = {
            'enabled': True,
            'max_loaded_shards': 4,
            'auto_save_threshold': 0,  # Disable auto-save for this test
            'refresh_strategy': {'notify_age_hours': 100}
        }
        
        cache = ShardedCPECache(config, num_shards=16)
        cache.cache_dir = cache_dir
        
        # Create response with surrogate pair
        corrupt_response = {
            "resultsPerPage": 1,
            "totalResults": 1,
            "products": [
                {
                    "cpe": {
                        "cpeName": "cpe:2.3:a:test:bad:1.0:*:*:*:*:*:*:*",
                        "titles": [{"title": "Bad \uD800Data"}]
                    }
                }
            ]
        }
        
        # Test 1: Validation should prevent caching
        cpe_string = "cpe:2.3:a:test:bad:*:*:*:*:*:*:*:*"
        try:
            validated = validate_cpe_data(corrupt_response, cpe_string, schema=None)
            # If we got here, validation didn't work
            print("  ✗ Validation FAILED - corrupt data passed through")
            return False
        except NVDSchemaValidationError:
            print("  ✓ Validation correctly rejected corrupt data")
        
        # Test 2: Verify cache.put() was never called (data not in cache)
        retrieved, status = cache.get(cpe_string)
        assert status == 'miss', f"Data should NOT be cached, got status: {status}"
        print("  ✓ Data correctly NOT cached")
        
        # Test 3: Save cache and verify shard file integrity
        cache.save_all_shards()
        
        # Check all shard files
        shard_files = list(cache_dir.glob("cpe_cache_shard_*.json"))
        corrupt_found = False
        
        for shard_file in shard_files:
            try:
                with open(shard_file, 'rb') as f:
                    shard_data = orjson.loads(f.read())
                # Successfully loaded - check if corrupt data is in it
                if cpe_string in shard_data:
                    print(f"  ✗ Corrupt data found in {shard_file.name}!")
                    corrupt_found = True
            except Exception as e:
                print(f"  ✗ Shard {shard_file.name} is corrupted: {e}")
                corrupt_found = True
        
        if not corrupt_found:
            print(f"  ✓ All {len(shard_files)} shard files are valid (no corruption)")
        
        return not corrupt_found

# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

def main():
    """Run all UTF-8 validation tests"""
    
    print("\n" + "="*60)
    print("CPE UTF-8 Validation Test Suite")
    print("Purpose: Prevent surrogate pair corruption in cache shards")
    print("="*60)
    
    tests = [
        test_valid_cpe_response_caches,
        test_surrogate_pair_rejected_before_cache,
        test_invalid_utf8_rejected_before_cache,
        test_corrupted_shard_not_created,
    ]
    
    results = []
    for test_func in tests:
        result = test_func()
        results.append(result)
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    passed = sum(results)
    total = len(results)
    print(f"Tests Passed: {passed}/{total}")
    
    # Standardized output for test runner
    print(f"\nTEST_RESULTS: PASSED={passed} TOTAL={total} SUITE=\"CPE UTF-8 Validation\"")
    
    if passed == total:
        print("\n✓ ALL TESTS PASSED - UTF-8 validation is working correctly")
        print("  Surrogate pairs will be rejected BEFORE caching")
        print("  No corrupted shards will be created")
        return 0
    else:
        print(f"\n✗ {total - passed} TEST(S) FAILED")
        print("  WARNING: System may still create corrupted cache shards!")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
