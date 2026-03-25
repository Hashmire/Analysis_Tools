#!/usr/bin/env python3
"""
Integration Test: CVE List V5 Cache Staleness Detection

Tests the CVE List V5 cache check logic in generate_dataset.py:
1. Fast path: NVD lastModified <= last_manual_update → current, zero file I/O
2. Fallback TTL: file age vs notify_age_hours when fast path is unavailable
3. new_or_missing: file does not yet exist
4. path_resolution_failed: config path is unresolvable
5. error: unexpected exception returns no_action

Entry Points Tested:
- generate_dataset._save_cve_list_v5_to_cache_during_bulk_generation()

Standard Output Format: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="CVE List V5 Cache Staleness"
"""
import sys
import json
import os
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

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


def create_v5_cache_file(file_path, cve_id, file_age_hours=0):
    """Create a minimal CVE List V5 cache file, optionally aged."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    v5_data = {
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
        "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Test"}]}}
    }
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(v5_data, f, indent=2)

    if file_age_hours > 0:
        old_time = datetime.now(timezone.utc) - timedelta(hours=file_age_hours)
        ts = old_time.timestamp()
        os.utime(file_path, (ts, ts))


def make_config(repo_path, last_manual_update=None, notify_age_hours=168):
    """Build a minimal cve_list_v5 config dict for mocking."""
    cfg = {
        'path': str(repo_path),
        'refresh_strategy': {
            'notify_age_hours': notify_age_hours
        }
    }
    if last_manual_update is not None:
        cfg['refresh_strategy']['last_manual_update'] = last_manual_update
    return cfg


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@test("File missing → queued as new_or_missing")
def test_missing_file():
    """Non-existent cache file should be queued for creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "cve_list_v5"

        import generate_dataset
        generate_dataset._config_cache = {}

        with patch('generate_dataset._get_cached_config') as mock_cfg:
            mock_cfg.return_value = make_config(repo_path)

            result = generate_dataset._save_cve_list_v5_to_cache_during_bulk_generation(
                "CVE-2024-1234",
                nvd_last_modified="2024-06-01T12:00:00.000Z"
            )

        assert result['action'] == 'queued', f"Expected queued, got {result['action']}"
        assert result['reason'] == 'new_or_missing', f"Expected new_or_missing, got {result['reason']}"
        print("  ✓ Missing file queued as new_or_missing")
        return True


@test("Fast path: NVD timestamp <= last_manual_update → current, no_action")
def test_fast_path_current():
    """NVD lastModified is older than last_manual_update — file is current without TTL check."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "cve_list_v5"
        cache_file = repo_path / "2024" / "1xxx" / "CVE-2024-1234.json"
        # File exists but is very old (would fail TTL check if fast path didn't short-circuit)
        create_v5_cache_file(cache_file, "CVE-2024-1234", file_age_hours=9999)

        import generate_dataset
        generate_dataset._config_cache = {}

        # last_manual_update is AFTER the NVD timestamp — fast path should fire
        with patch('generate_dataset._get_cached_config') as mock_cfg:
            mock_cfg.return_value = make_config(
                repo_path,
                last_manual_update="2025-01-01T00:00:00+00:00",
                notify_age_hours=1  # TTL is 1h — file would be stale without fast path
            )

            result = generate_dataset._save_cve_list_v5_to_cache_during_bulk_generation(
                "CVE-2024-1234",
                nvd_last_modified="2024-06-01T12:00:00.000Z"
            )

        assert result['action'] == 'no_action', f"Expected no_action, got {result['action']}"
        assert result['reason'] == 'current_by_last_manual_update', \
            f"Expected current_by_last_manual_update, got {result['reason']}"
        print("  ✓ Fast path fired: NVD timestamp <= last_manual_update → current_by_last_manual_update")
        return True


@test("Fast path bypassed: NVD timestamp > last_manual_update → falls through to TTL")
def test_fast_path_bypassed_falls_to_ttl():
    """NVD lastModified is newer than last_manual_update — fast path does not fire, TTL decides."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "cve_list_v5"
        cache_file = repo_path / "2024" / "1xxx" / "CVE-2024-1234.json"
        # File is fresh (10 hours old), TTL is 168h — within TTL
        create_v5_cache_file(cache_file, "CVE-2024-1234", file_age_hours=10)

        import generate_dataset
        generate_dataset._config_cache = {}

        # last_manual_update is BEFORE the NVD timestamp — fast path bypassed
        with patch('generate_dataset._get_cached_config') as mock_cfg:
            mock_cfg.return_value = make_config(
                repo_path,
                last_manual_update="2023-01-01T00:00:00+00:00",
                notify_age_hours=168
            )

            result = generate_dataset._save_cve_list_v5_to_cache_during_bulk_generation(
                "CVE-2024-1234",
                nvd_last_modified="2024-06-01T12:00:00.000Z"
            )

        assert result['action'] == 'no_action', f"Expected no_action (within TTL), got {result['action']}"
        assert result['reason'] == 'up-to-date', f"Expected up-to-date, got {result['reason']}"
        print("  ✓ Fast path bypassed (NVD newer), file within TTL → up-to-date")
        return True


@test("No last_manual_update in config → TTL fallback used, file within TTL → up-to-date")
def test_no_last_manual_update_within_ttl():
    """When last_manual_update is absent, falls through to TTL. File is fresh."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "cve_list_v5"
        cache_file = repo_path / "2024" / "1xxx" / "CVE-2024-1234.json"
        create_v5_cache_file(cache_file, "CVE-2024-1234", file_age_hours=10)

        import generate_dataset
        generate_dataset._config_cache = {}

        # No last_manual_update key at all
        with patch('generate_dataset._get_cached_config') as mock_cfg:
            mock_cfg.return_value = make_config(repo_path, notify_age_hours=168)

            result = generate_dataset._save_cve_list_v5_to_cache_during_bulk_generation(
                "CVE-2024-1234",
                nvd_last_modified="2024-06-01T12:00:00.000Z"
            )

        assert result['action'] == 'no_action', f"Expected no_action, got {result['action']}"
        assert result['reason'] == 'up-to-date', f"Expected up-to-date, got {result['reason']}"
        print("  ✓ No last_manual_update, file within TTL (10h < 168h) → up-to-date")
        return True


@test("TTL exceeded → queued as stale")
def test_ttl_exceeded_stale():
    """File older than notify_age_hours (and fast path unavailable) → queued as stale."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "cve_list_v5"
        cache_file = repo_path / "2024" / "1xxx" / "CVE-2024-1234.json"
        # File is 200 hours old, TTL is 168h
        create_v5_cache_file(cache_file, "CVE-2024-1234", file_age_hours=200)

        import generate_dataset
        generate_dataset._config_cache = {}

        with patch('generate_dataset._get_cached_config') as mock_cfg:
            mock_cfg.return_value = make_config(repo_path, notify_age_hours=168)

            result = generate_dataset._save_cve_list_v5_to_cache_during_bulk_generation(
                "CVE-2024-1234",
                nvd_last_modified=None  # No fast path available
            )

        assert result['action'] == 'queued', f"Expected queued, got {result['action']}"
        assert result['reason'] == 'stale', f"Expected stale, got {result['reason']}"
        age = result.get('age_hours', 0)
        ttl = result.get('ttl_hours', 0)
        assert age > ttl, f"Expected age ({age:.1f}h) > TTL ({ttl}h)"
        print(f"  ✓ File aged {age:.1f}h > TTL {ttl}h → queued as stale")
        return True


@test("No nvd_last_modified provided → fast path skipped, TTL decides")
def test_no_nvd_last_modified_uses_ttl():
    """nvd_last_modified=None disables the fast path entirely; TTL is the only gate."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "cve_list_v5"
        cache_file = repo_path / "2024" / "1xxx" / "CVE-2024-1234.json"
        # File is fresh — within TTL
        create_v5_cache_file(cache_file, "CVE-2024-1234", file_age_hours=5)

        import generate_dataset
        generate_dataset._config_cache = {}

        with patch('generate_dataset._get_cached_config') as mock_cfg:
            mock_cfg.return_value = make_config(
                repo_path,
                last_manual_update="2025-01-01T00:00:00+00:00",  # Would fire fast path if nvd_dt provided
                notify_age_hours=168
            )

            # No nvd_last_modified — fast path is skipped regardless of last_manual_update
            result = generate_dataset._save_cve_list_v5_to_cache_during_bulk_generation(
                "CVE-2024-1234",
                nvd_last_modified=None
            )

        assert result['action'] == 'no_action', f"Expected no_action, got {result['action']}"
        assert result['reason'] == 'up-to-date', f"Expected up-to-date, got {result['reason']}"
        print("  ✓ nvd_last_modified=None skips fast path, file within TTL → up-to-date")
        return True


@test("Fast path: unparseable timestamps fall through to TTL")
def test_fast_path_unparseable_timestamp_fallback():
    """If either timestamp is unparseable, fast path silently falls through to TTL."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "cve_list_v5"
        cache_file = repo_path / "2024" / "1xxx" / "CVE-2024-1234.json"
        create_v5_cache_file(cache_file, "CVE-2024-1234", file_age_hours=10)

        import generate_dataset
        generate_dataset._config_cache = {}

        with patch('generate_dataset._get_cached_config') as mock_cfg:
            mock_cfg.return_value = make_config(
                repo_path,
                last_manual_update="NOT-A-VALID-DATE",
                notify_age_hours=168
            )

            result = generate_dataset._save_cve_list_v5_to_cache_during_bulk_generation(
                "CVE-2024-1234",
                nvd_last_modified="ALSO-NOT-A-DATE"
            )

        # Fast path fails gracefully; TTL check runs and file is within TTL
        assert result['action'] == 'no_action', f"Expected no_action, got {result['action']}"
        assert result['reason'] == 'up-to-date', f"Expected up-to-date, got {result['reason']}"
        print("  ✓ Unparseable timestamps silently fall through to TTL → up-to-date")
        return True


@test("path_resolution_failed → no_action")
def test_path_resolution_failed():
    """When _resolve_cve_cache_file_path returns None, function returns no_action."""
    import generate_dataset
    generate_dataset._config_cache = {}

    # _resolve_cve_cache_file_path is imported inside the function body from gatherData,
    # so we must patch its source module — not an attribute on generate_dataset.
    with patch('generate_dataset._get_cached_config') as mock_cfg, \
         patch('src.analysis_tool.core.gatherData._resolve_cve_cache_file_path', return_value=None):

        mock_cfg.return_value = make_config("/nonexistent/path")

        result = generate_dataset._save_cve_list_v5_to_cache_during_bulk_generation(
            "CVE-2024-9999",
            nvd_last_modified="2024-06-01T12:00:00.000Z"
        )

    assert result['action'] == 'no_action', f"Expected no_action, got {result['action']}"
    assert result['reason'] == 'path_resolution_failed', \
        f"Expected path_resolution_failed, got {result['reason']}"
    print("  ✓ path_resolution_failed → no_action")
    return True


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_tests():
    """Execute all registered tests."""
    print("=" * 80)
    print("CVE List V5 Cache Staleness Detection Test Suite")
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
    print(f"TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE=\"CVE List V5 Cache Staleness\"")
    print("=" * 80)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
