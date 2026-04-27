#!/usr/bin/env python3
"""
Config System Test Suite

Two complementary areas of coverage:

GOLD COPY INTEGRITY (config.json structure):
- JSON parses successfully from disk
- All required top-level sections present
- application: toolname (str), version (semver X.Y.Z)
- cache_settings: all 4 cache types + nvd_ish_output + confirmed_mappings;
        each cache type has refresh_strategy;
        notify_age_hours is positive wherever present;
        last_manual_update (cve_list_v5) is non-empty and valid ISO 8601
        (epoch sentinel 1970-01-01 is noted as committed default but not failed)
        nvd_ish_output: non-empty path and description (enabled/attribution_source/format/version derived in get_nvd_ish_config)
        confirmed_mappings: non-empty path (always enabled)
- api: api_key non-empty string, timeout positivity, retry bounds, all endpoint
        keys, https:// URL format, all schema keys
- logging: enabled (bool), level (valid set);
        progress: (removed — always-on behavior, not config-driven)
        Report sections (sdc_report, alias_report, cpeas_automation_report):
        progress_interval is a positive int
- Gold copy values: every field pinned to its exact committed value — catches
        accidental edits, drifted paths, stale epoch sentinels, or wrong URLs
        on any commit

LOADING PIPELINE (gatherData.py canonical loader + 9 helpers):
- load_config() returns a non-empty dict
- Memoization: two calls without force_reload return the same object identity
- force_reload=True returns a fresh dict (different identity, same key set)
- TEST_NVD_API_DISABLED env var: retry counts become 0; restored after test
- get_nvd_ish_config() returns merged result with tool_name + tool_version
        matching application config
"""

import sys
import os
import json
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.analysis_tool.core.gatherData import (
    load_config,
    get_nvd_ish_config,
)

# =============================================================================
# Constants: expected structure enforced against config.json
# =============================================================================

REQUIRED_TOP_LEVEL_SECTIONS = [
    'application', 'cache_settings', 'logging', 'harvest_and_process_sources', 'api',
]

REQUIRED_CACHE_TYPES = ['cpe_cache', 'nvd_source_data', 'cve_list_v5', 'nvd_2_0_cve']

REQUIRED_API_ENDPOINT_KEYS = [
    'public_ip', 'cve_list', 'nvd_cves', 'nvd_sources', 'nvd_cpes', 'nvd_cpematch',
]

REQUIRED_API_SCHEMA_KEYS = [
    'nvd_cpes_2_0', 'nvd_cves_2_0', 'nvd_source_2_0', 'cve_cve_5_2',
]

VALID_LOG_LEVELS = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}

REPORT_SECTIONS = ['sdc_report', 'alias_report', 'cpeas_automation_report']


# =============================================================================
# Test Suite
# =============================================================================

class TestConfigSystem:
    """Validates config.json gold copy integrity and the canonical loading pipeline."""

    def __init__(self):
        self.tests_passed = 0
        self.tests_total = 0
        self.test_results: list = []

    def add_result(self, test_name: str, passed: bool, message: str = "") -> None:
        """Record a single test assertion result."""
        self.tests_total += 1
        if passed:
            self.tests_passed += 1
            status = "[PASS]"
        else:
            status = "[FAIL]"
        line = f"{status} - {test_name}"
        if message:
            line += f": {message}"
        print(line)
        self.test_results.append({'test': test_name, 'passed': passed, 'message': message})

    # =========================================================================
    # GOLD COPY INTEGRITY
    # =========================================================================

    def test_config_file_valid_json(self):
        """Test 1: config.json exists on disk and parses as valid JSON."""
        print("\nTest 1: config.json Valid JSON")
        print("-" * 50)
        config_path = project_root / "config.json"
        self.add_result("config.json file exists", config_path.is_file(), str(config_path))
        if not config_path.is_file():
            return
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.add_result(
                "config.json parses as valid JSON",
                isinstance(data, dict),
                f"top-level type: {type(data).__name__}",
            )
        except json.JSONDecodeError as e:
            self.add_result("config.json parses as valid JSON", False, f"JSONDecodeError: {e}")
        except Exception as e:
            self.add_result("config.json parses as valid JSON", False, f"Unexpected error: {e}")

    def test_required_top_level_sections(self):
        """Test 2: All required top-level sections are present in config.json."""
        print("\nTest 2: Required Top-Level Sections")
        print("-" * 50)
        try:
            config = load_config()
            missing = [s for s in REQUIRED_TOP_LEVEL_SECTIONS if s not in config]
            self.add_result(
                "All required top-level sections present",
                len(missing) == 0,
                f"Missing: {missing}" if missing
                else f"{len(REQUIRED_TOP_LEVEL_SECTIONS)} sections verified",
            )
        except Exception as e:
            self.add_result("Required top-level sections", False, f"Error: {e}")

    def test_application_section(self):
        """Test 3: application section has non-empty toolname and semver-like version."""
        print("\nTest 3: application Section")
        print("-" * 50)
        try:
            config = load_config()
            app = config.get('application', {})
            self.add_result(
                "application.toolname is a non-empty string",
                isinstance(app.get('toolname'), str) and bool(app.get('toolname')),
                repr(app.get('toolname')),
            )
            version = app.get('version', '')
            self.add_result(
                "application.version is a non-empty string",
                isinstance(version, str) and bool(version),
                repr(version),
            )
            parts = version.split('.')
            self.add_result(
                "application.version follows X.Y.Z semver format",
                len(parts) == 3 and all(p.isdigit() for p in parts),
                repr(version),
            )
        except Exception as e:
            self.add_result("application section", False, f"Error: {e}")

    def test_cache_settings_section(self):
        """Test 4: cache_settings — presence, refresh_strategy structure, notify_age_hours positivity,
        ISO 8601 validity for any date fields, nvd_ish_output and confirmed_mappings sub-sections."""
        print("\nTest 4: cache_settings Section")
        print("-" * 50)
        try:
            config = load_config()
            cache = config.get('cache_settings', {})
            missing_types = [t for t in REQUIRED_CACHE_TYPES if t not in cache]
            self.add_result(
                "All required cache types present",
                len(missing_types) == 0,
                f"Missing: {missing_types}" if missing_types
                else f"{len(REQUIRED_CACHE_TYPES)} cache types verified",
            )
            for cache_type in REQUIRED_CACHE_TYPES:
                if cache_type not in cache:
                    continue
                entry = cache[cache_type]
                self.add_result(
                    f"cache_settings.{cache_type} has refresh_strategy dict",
                    isinstance(entry.get('refresh_strategy'), dict),
                    repr(type(entry.get('refresh_strategy')).__name__),
                )

            # notify_age_hours must be a positive number wherever it appears
            for cache_type in REQUIRED_CACHE_TYPES:
                if cache_type not in cache:
                    continue
                strategy = cache[cache_type].get('refresh_strategy', {})
                if 'notify_age_hours' not in strategy:
                    continue
                val = strategy['notify_age_hours']
                self.add_result(
                    f"cache_settings.{cache_type}.refresh_strategy.notify_age_hours is a positive number",
                    isinstance(val, (int, float)) and val > 0,
                    repr(val),
                )

            # Date fields in refresh_strategy must be non-empty and valid ISO 8601.
            # The epoch sentinel '1970-01-01T00:00:00+00:00' is the committed default for
            # last_manual_update and is a valid state; it is noted in the test output but
            # does not cause a failure.
            for cache_type in REQUIRED_CACHE_TYPES:
                if cache_type not in cache:
                    continue
                strategy = cache[cache_type].get('refresh_strategy', {})
                if 'last_manual_update' not in strategy:
                    continue
                date_str = strategy['last_manual_update']
                self.add_result(
                    f"cache_settings.{cache_type}.refresh_strategy.last_manual_update is a non-empty string",
                    isinstance(date_str, str) and bool(date_str),
                    repr(date_str),
                )
                if not (isinstance(date_str, str) and date_str):
                    continue
                try:
                    dt = datetime.fromisoformat(date_str)
                    epoch_utc = datetime(1970, 1, 1, tzinfo=timezone.utc)
                    dt_utc = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                    is_epoch = dt_utc == epoch_utc
                    epoch_note = " [committed default epoch sentinel — cache not yet manually refreshed]" if is_epoch else ""
                    self.add_result(
                        f"cache_settings.{cache_type}.refresh_strategy.last_manual_update is valid ISO 8601",
                        True,
                        f"{repr(date_str)}{epoch_note}",
                    )
                except (ValueError, TypeError) as exc:
                    self.add_result(
                        f"cache_settings.{cache_type}.refresh_strategy.last_manual_update is valid ISO 8601",
                        False,
                        f"Parse error: {exc} — value: {repr(date_str)}",
                    )

            # nvd_ish_output is now nested under cache_settings
            # enabled/attribution_source/format/version are derived in get_nvd_ish_config(), not stored in config
            nvo = cache.get('nvd_ish_output', {})
            self.add_result(
                "cache_settings.nvd_ish_output.path is a non-empty string",
                isinstance(nvo.get('path'), str) and bool(nvo.get('path')),
                repr(nvo.get('path')),
            )

            # confirmed_mappings is now nested under cache_settings
            cm = cache.get('confirmed_mappings', {})
            self.add_result(
                "cache_settings.confirmed_mappings.path is a non-empty string",
                isinstance(cm.get('path'), str) and bool(cm.get('path')),
                repr(cm.get('path')),
            )

        except Exception as e:
            self.add_result("cache_settings section", False, f"Error: {e}")

    def test_api_section(self):
        """Test 5: api section — api_key type, timeouts, retry bounds, endpoints, schemas."""
        print("\nTest 5: api Section")
        print("-" * 50)
        try:
            config = load_config()
            api = config.get('api', {})

            # api_key must be a string. The gold copy commits an empty string so each
            # developer supplies their own key — leaving it empty falls back to
            # unauthenticated NVD rate limits (6 s/request vs 1 s/request).
            api_key_val = api.get('api_key', '')
            self.add_result(
                "api.api_key is a string",
                isinstance(api_key_val, str),
                repr(type(api_key_val).__name__),
            )
            # Informational warning only — not a counted assertion.
            # The gold copy intentionally ships with an empty key; this notice
            # reminds developers running a populated config that the key is live.
            if isinstance(api_key_val, str) and api_key_val.strip():
                print("[INFO]  - api.api_key is populated (non-empty)")
            else:
                print("[WARN]  - api.api_key is EMPTY — tool will use unauthenticated "
                      "6 s/request rate limits until a key is configured")

            # Timeouts must be positive numbers
            timeouts = api.get('timeouts', {})
            for key in ('public_ip', 'nvd_api', 'cve_org'):
                val = timeouts.get(key)
                self.add_result(
                    f"api.timeouts.{key} is a positive number",
                    isinstance(val, (int, float)) and val > 0,
                    repr(val),
                )

            # Retry counts and delays must be non-negative numbers
            retry = api.get('retry', {})
            for key in ('max_attempts_nvd', 'max_attempts_cpe',
                        'delay_with_key', 'delay_without_key',
                        'page_delay_with_key', 'page_delay_without_key'):
                val = retry.get(key)
                self.add_result(
                    f"api.retry.{key} is a non-negative number",
                    isinstance(val, (int, float)) and val >= 0,
                    repr(val),
                )

            # All required endpoint keys present
            endpoints = api.get('endpoints', {})
            missing_eps = [k for k in REQUIRED_API_ENDPOINT_KEYS if k not in endpoints]
            self.add_result(
                "All required api.endpoints keys present",
                len(missing_eps) == 0,
                f"Missing: {missing_eps}" if missing_eps
                else f"{len(REQUIRED_API_ENDPOINT_KEYS)} endpoint keys verified",
            )

            # Every endpoint URL must use https://
            for ep_key, url in endpoints.items():
                self.add_result(
                    f"api.endpoints.{ep_key} uses https://",
                    isinstance(url, str) and url.startswith('https://'),
                    repr(url),
                )

            # All required schema keys present
            schemas = api.get('schemas', {})
            missing_schemas = [k for k in REQUIRED_API_SCHEMA_KEYS if k not in schemas]
            self.add_result(
                "All required api.schemas keys present",
                len(missing_schemas) == 0,
                f"Missing: {missing_schemas}" if missing_schemas
                else f"{len(REQUIRED_API_SCHEMA_KEYS)} schema keys verified",
            )
        except Exception as e:
            self.add_result("api section", False, f"Error: {e}")

    def test_logging_section(self):
        """Test 6: logging section — enabled bool, valid level, and nested progress/report sub-sections."""
        print("\nTest 6: logging Section")
        print("-" * 50)
        try:
            config = load_config()
            log = config.get('logging', {})

            self.add_result(
                "logging.enabled is bool",
                isinstance(log.get('enabled'), bool),
                repr(log.get('enabled')),
            )

            level = log.get('level', '')
            self.add_result(
                f"logging.level is in valid set ({', '.join(sorted(VALID_LOG_LEVELS))})",
                level in VALID_LOG_LEVELS,
                repr(level),
            )

            # progress sub-section removed — show_progress/show_eta/show_timing are always-on

            # report sections are now nested under logging
            for section in REPORT_SECTIONS:
                val = log.get(section, {}).get('progress_interval')
                self.add_result(
                    f"logging.{section}.progress_interval is a positive int",
                    isinstance(val, int) and val > 0,
                    repr(val),
                )
        except Exception as e:
            self.add_result("logging section", False, f"Error: {e}")

    def test_nvd_ish_output_section(self):
        """Test 7: cache_settings.nvd_ish_output — non-empty path and description.
        enabled/attribution_source/format/version are derived in get_nvd_ish_config()."""
        print("\nTest 7: cache_settings.nvd_ish_output Section")
        print("-" * 50)
        try:
            config = load_config()
            nvo = config.get('cache_settings', {}).get('nvd_ish_output', {})

            self.add_result(
                "cache_settings.nvd_ish_output.path is a non-empty string",
                isinstance(nvo.get('path'), str) and bool(nvo.get('path')),
                repr(nvo.get('path')),
            )
            self.add_result(
                "cache_settings.nvd_ish_output.description is a non-empty string",
                isinstance(nvo.get('description'), str) and bool(nvo.get('description')),
                repr(nvo.get('description')),
            )
        except Exception as e:
            self.add_result("cache_settings.nvd_ish_output section", False, f"Error: {e}")

    def test_report_sections(self):
        """Test 8: sdc_report, alias_report, cpeas_automation_report (under logging) have positive progress_interval."""
        print("\nTest 8: Report Sections")
        print("-" * 50)
        try:
            config = load_config()
            for section in REPORT_SECTIONS:
                val = config.get('logging', {}).get(section, {}).get('progress_interval')
                self.add_result(
                    f"{section}.progress_interval is a positive int",
                    isinstance(val, int) and val > 0,
                    repr(val),
                )
        except Exception as e:
            self.add_result("Report sections", False, f"Error: {e}")

    def test_gold_copy_intended_values(self):
        """Test 9: Every field in config.json compared to its exact intended gold copy value.

        Acts as a living specification. Any committed change to config.json that
        is not intentional will produce a named FAIL, preventing silent value
        drift between commits (wrong paths, stale epoch sentinels, wrong URLs,
        forgotten version bumps, altered rate-limit tuning, etc.).
        """
        print("\nTest 9: Gold Copy Intended Values")
        print("-" * 50)
        try:
            config = load_config()

            def chk(dotted_path, expected):
                """Assert an exact value at a dot-delimited config path."""
                parts = dotted_path.split('.')
                node = config
                for part in parts:
                    if not isinstance(node, dict) or part not in node:
                        self.add_result(
                            f"{dotted_path} == {expected!r}",
                            False,
                            "key not found in config",
                        )
                        return
                    node = node[part]
                self.add_result(
                    f"{dotted_path} == {expected!r}",
                    node == expected,
                    repr(node) if node == expected else f"actual: {node!r}",
                )

            # -- application -------------------------------------------------------
            chk('application.toolname', 'Hashmire/Analysis_Tools')
            chk('application.version',  '0.4.0')

            # -- cache_settings.cpe_cache ------------------------------------------
            chk('cache_settings.cpe_cache.auto_save_threshold',  50)
            chk('cache_settings.cpe_cache.max_loaded_shards',    16)
            chk('cache_settings.cpe_cache.description',          'NVD CPE API responses with per-entry expiration, sharding for better scaling across organizational dataset volume')
            chk('cache_settings.cpe_cache.sharding.num_shards',  16)
            chk('cache_settings.cpe_cache.refresh_strategy.notify_age_hours', 720)

            # -- cache_settings.nvd_source_data ------------------------------------
            chk('cache_settings.nvd_source_data.filename',                        'nvd_source_data.json')
            chk('cache_settings.nvd_source_data.description',                     'NVD source organization data, derived from the NVD /source/ API')
            chk('cache_settings.nvd_source_data.refresh_strategy.notify_age_hours', 168)

            # -- cache_settings.cve_list_v5 ----------------------------------------
            chk('cache_settings.cve_list_v5.path',                                    'cache/cve_list_v5')
            chk('cache_settings.cve_list_v5.description',                             'CVE List V5 repository with per-file tracking')
            chk('cache_settings.cve_list_v5.refresh_strategy.last_manual_update',     '1970-01-01T00:00:00+00:00')
            chk('cache_settings.cve_list_v5.refresh_strategy.notify_age_hours',       720)

            # -- cache_settings.nvd_2_0_cve ----------------------------------------
            chk('cache_settings.nvd_2_0_cve.path',                            'cache/nvd_2.0_cves')
            chk('cache_settings.nvd_2_0_cve.description',                     'NVD CVE 2.0 API responses cache with per-file tracking')
            chk('cache_settings.nvd_2_0_cve.refresh_strategy.field_path',     '$.vulnerabilities.*.cve.lastModified')

            # -- cache_settings.nvd_ish_output ------------------------------------
            # enabled/attribution_source/format/version are derived in get_nvd_ish_config(), not stored in config
            chk('cache_settings.nvd_ish_output.path',        'cache/nvd-ish_2.0_cves')
            chk('cache_settings.nvd_ish_output.description', 'Enhanced NVD 2.0 format records with integrated CVE List V5 data and analysis tool processing outputs')

            # -- cache_settings.confirmed_mappings --------------------------------
            chk('cache_settings.confirmed_mappings.path',        'cache/alias_mappings')
            chk('cache_settings.confirmed_mappings.description', 'Confirmed CPE base string mappings for platform entries')

            # -- logging -----------------------------------------------------------
            chk('logging.enabled', True)
            chk('logging.level',   'DEBUG')

            # -- logging.progress removed (always-on, not config-driven)

            # -- harvest_and_process_sources ---------------------------------------
            chk('harvest_and_process_sources.max_cves_per_source', 30000)
            chk('harvest_and_process_sources.quiet_individual',    False)

            # -- api.api_key -------------------------------------------------------
            # Gold copy ships with an empty key; each developer fills in their own.
            # This is informational only — a populated key on a local machine is
            # expected. Do NOT commit a real key to the repo.
            _api_key_val = config.get('api', {}).get('api_key', '')
            if _api_key_val:
                print("[INFO]  - api.api_key is populated (local key configured — do not commit)")
                print("TEST_WARNING: config.json is not in default state - api_key is populated (do not commit to repo)")
            else:
                print("[INFO]  - api.api_key is empty (gold copy state)")

            # -- api.timeouts ------------------------------------------------------
            chk('api.timeouts.public_ip', 5)
            chk('api.timeouts.nvd_api',   120)
            chk('api.timeouts.cve_org',   120)

            # -- api.retry ---------------------------------------------------------
            chk('api.retry.max_attempts_nvd',       10)
            chk('api.retry.max_attempts_cpe',       10)
            chk('api.retry.delay_with_key',         0)
            chk('api.retry.delay_without_key',      6)
            chk('api.retry.page_delay_with_key',    1)
            chk('api.retry.page_delay_without_key', 1)

            # -- api.endpoints -----------------------------------------------------
            chk('api.endpoints.public_ip',    'https://api.ipify.org')
            chk('api.endpoints.cve_list',     'https://cveawg.mitre.org/api/cve/')
            chk('api.endpoints.nvd_cves',     'https://services.nvd.nist.gov/rest/json/cves/2.0/')
            chk('api.endpoints.nvd_sources',  'https://services.nvd.nist.gov/rest/json/source/2.0/')
            chk('api.endpoints.nvd_cpes',     'https://services.nvd.nist.gov/rest/json/cpes/2.0')
            chk('api.endpoints.nvd_cpematch', 'https://services.nvd.nist.gov/rest/json/cpematch/2.0')

            # -- api.schemas -------------------------------------------------------
            chk('api.schemas.nvd_cpes_2_0',   'https://csrc.nist.gov/schema/nvd/api/2.0/cpe_api_json_2.0.schema')
            chk('api.schemas.nvd_cves_2_0',   'https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema')
            chk('api.schemas.nvd_source_2_0', 'https://csrc.nist.gov/schema/nvd/api/2.0/source_api_json_2.0.schema')
            chk('api.schemas.cve_cve_5_2',    'https://raw.githubusercontent.com/CVEProject/cve-schema/refs/heads/main/schema/docs/CVE_Record_Format_bundled.json')

            # -- report sections (under logging) -----------------------------------
            chk('logging.sdc_report.progress_interval',              2000)
            chk('logging.alias_report.progress_interval',            2000)
            chk('logging.cpeas_automation_report.progress_interval', 2000)

        except Exception as e:
            self.add_result("Gold copy intended values", False, f"Error: {e}")

    # =========================================================================
    # LOADING PIPELINE
    # =========================================================================

    def test_load_config_returns_dict(self):
        """Test 10: load_config() returns a non-empty dict."""
        print("\nTest 10: load_config() Returns Dict")
        print("-" * 50)
        try:
            config = load_config()
            self.add_result(
                "load_config() returns dict",
                isinstance(config, dict),
                f"type: {type(config).__name__}",
            )
            self.add_result(
                "load_config() returns non-empty dict",
                bool(config),
                f"keys: {len(config)}",
            )
        except Exception as e:
            self.add_result("load_config() basic", False, f"Error: {e}")

    def test_load_config_memoization(self):
        """Test 11: Repeated load_config() calls (no force_reload) return the same object."""
        print("\nTest 11: load_config() Memoization")
        print("-" * 50)
        try:
            first = load_config()
            second = load_config()
            self.add_result(
                "Repeated load_config() calls return same object identity",
                first is second,
                "identity check passed" if first is second
                else "FAIL: got different objects — cache is not working",
            )
        except Exception as e:
            self.add_result("Memoization check", False, f"Error: {e}")

    def test_load_config_force_reload(self):
        """Test 12: force_reload=True bypasses cache and returns a structurally identical fresh object."""
        print("\nTest 12: force_reload=True")
        print("-" * 50)
        try:
            cached = load_config()
            fresh = load_config(force_reload=True)
            self.add_result(
                "force_reload=True returns a different object (cache bypassed)",
                fresh is not cached,
                "fresh object returned" if fresh is not cached
                else "FAIL: same object — force_reload had no effect",
            )
            self.add_result(
                "force_reload=True result has the same top-level key set",
                isinstance(fresh, dict) and set(fresh.keys()) == set(cached.keys()),
                f"keys_match={set(fresh.keys()) == set(cached.keys())}",
            )
        except Exception as e:
            self.add_result("force_reload check", False, f"Error: {e}")

    def test_test_nvd_api_disabled_mutation(self):
        """Test 13: TEST_NVD_API_DISABLED env var zeroes out retry counts; cache is restored after."""
        print("\nTest 13: TEST_NVD_API_DISABLED Mutation")
        print("-" * 50)
        try:
            # Capture baseline retry values from unmodified config
            normal_config = load_config()
            normal_max_nvd = normal_config['api']['retry']['max_attempts_nvd']
            normal_max_cpe = normal_config['api']['retry']['max_attempts_cpe']
            self.add_result(
                "Baseline config has positive retry counts",
                normal_max_nvd > 0 and normal_max_cpe > 0,
                f"max_attempts_nvd={normal_max_nvd}, max_attempts_cpe={normal_max_cpe}",
            )

            # Apply mutation
            os.environ['TEST_NVD_API_DISABLED'] = '1'
            try:
                mutated = load_config(force_reload=True)
                self.add_result(
                    "TEST_NVD_API_DISABLED sets max_attempts_nvd to 0",
                    mutated['api']['retry']['max_attempts_nvd'] == 0,
                    repr(mutated['api']['retry']['max_attempts_nvd']),
                )
                self.add_result(
                    "TEST_NVD_API_DISABLED sets max_attempts_cpe to 0",
                    mutated['api']['retry']['max_attempts_cpe'] == 0,
                    repr(mutated['api']['retry']['max_attempts_cpe']),
                )
            finally:
                # Always restore: clear env var and reload clean config into cache
                os.environ.pop('TEST_NVD_API_DISABLED', None)
                restored = load_config(force_reload=True)

            self.add_result(
                "Retry counts restored to positive values after cleanup",
                restored['api']['retry']['max_attempts_nvd'] > 0,
                repr(restored['api']['retry']['max_attempts_nvd']),
            )
        except Exception as e:
            self.add_result("TEST_NVD_API_DISABLED mutation", False, f"Error: {e}")
            # Guarantee cleanup even if test logic throws
            os.environ.pop('TEST_NVD_API_DISABLED', None)
            load_config(force_reload=True)

    def test_get_nvd_ish_config_merged_fields(self):
        """Test 17: get_nvd_ish_config() merges tool_name + tool_version from application."""
        print("\nTest 17: get_nvd_ish_config() Merged Fields")
        print("-" * 50)
        try:
            result = get_nvd_ish_config()
            self.add_result(
                "get_nvd_ish_config() returns dict",
                isinstance(result, dict),
                f"type: {type(result).__name__}",
            )
            self.add_result(
                "get_nvd_ish_config() contains 'path' from nvd_ish_output",
                'path' in result and bool(result.get('path')),
                repr(result.get('path')),
            )
            self.add_result(
                "get_nvd_ish_config() contains merged 'tool_name'",
                'tool_name' in result and bool(result['tool_name']),
                repr(result.get('tool_name')),
            )
            self.add_result(
                "get_nvd_ish_config() contains merged 'tool_version'",
                'tool_version' in result and bool(result['tool_version']),
                repr(result.get('tool_version')),
            )
            # Merged values must match their sources in application config
            app = load_config()['application']
            self.add_result(
                "tool_name matches application.toolname",
                result.get('tool_name') == app.get('toolname'),
                f"'{result.get('tool_name')}' == '{app.get('toolname')}'",
            )
            self.add_result(
                "tool_version matches application.version",
                result.get('tool_version') == app.get('version'),
                f"'{result.get('tool_version')}' == '{app.get('version')}'",
            )
        except Exception as e:
            self.add_result("get_nvd_ish_config()", False, f"Error: {e}")

    # =========================================================================
    # Runner
    # =========================================================================

    def run_all_tests(self) -> bool:
        """Execute every test method in order and return True if all pass."""
        print("=" * 60)
        print("Config System Test Suite")
        print("=" * 60)

        # Gold copy integrity
        self.test_config_file_valid_json()
        self.test_required_top_level_sections()
        self.test_application_section()
        self.test_cache_settings_section()
        self.test_api_section()
        self.test_logging_section()
        self.test_nvd_ish_output_section()
        self.test_report_sections()
        self.test_gold_copy_intended_values()

        # Loading pipeline
        self.test_load_config_returns_dict()
        self.test_load_config_memoization()
        self.test_load_config_force_reload()
        self.test_test_nvd_api_disabled_mutation()
        self.test_get_nvd_ish_config_merged_fields()

        print("\n" + "=" * 60)
        print(f"Results: {self.tests_passed}/{self.tests_total} passed")
        print("=" * 60)
        return self.tests_passed == self.tests_total


def main():
    suite = TestConfigSystem()
    success = suite.run_all_tests()
    print(f'\nTEST_RESULTS: PASSED={suite.tests_passed} TOTAL={suite.tests_total} SUITE="Config System"')
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
