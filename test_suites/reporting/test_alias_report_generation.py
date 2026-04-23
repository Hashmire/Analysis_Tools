#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Suite: Alias Report Generation

Validates NVD CPE Base String tracking, CVE year grouping, and topNvdCpeBaseStrings
aggregation in the alias extraction report generator.

Tests target:
    - _extract_nvd_cpe_base_strings(): pure logic, no I/O
    - extract_aliases_from_record(): file read + extraction
    - AliasReportBuilder: topNvdCpeBaseStrings aggregation via finalize()
    - Alias_Mapping_Report_Template.html: JS function and structure validation
    - scan_nvd_ish_cache(): cache directory scanning
    - calculate_alias_statistics(): statistics computation from report data
    - validate_report_statistics(): cross-file index vs report consistency check
    - Full pipeline (four-phase subprocess): inject → generate_alias_report subprocess →
      validate run output artifacts → teardown INPUT cache

Usage:
    python test_suites/reporting/test_alias_report_generation.py
"""

import json
import sys
import shutil
from pathlib import Path
from typing import Any, Dict, List

# Force UTF-8 output encoding for Windows compatibility
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

# ---------------------------------------------------------------------------
# Cache path constants (temp_test_caches convention used across all test suites)
# ---------------------------------------------------------------------------
CACHE_DIR = project_root / "cache"
# NVD-ish JSON records injected here as test input (isolated from production nvd-ish_2.0_cves/)
TEST_NVD_ISH_INPUT_DIR = CACHE_DIR / "temp_test_caches" / "alias_report_nvdish_input"
# Report output files (index.json, per-source .json) written here for validation tests
TEST_REPORT_OUTPUT_DIR = CACHE_DIR / "temp_test_caches" / "alias_report_output"
# Subprocess integration test uses a flat name: --custom-cache rejects paths containing / or \
TEST_SUBPROCESS_CACHE_NAME = "alias_report_test_nvdish_input"
TEST_SUBPROCESS_CACHE_DIR = CACHE_DIR / TEST_SUBPROCESS_CACHE_NAME

from src.analysis_tool.reporting.generate_alias_report import (
    _extract_nvd_cpe_base_strings,
    extract_aliases_from_record,
    AliasReportBuilder,
    scan_nvd_ish_cache,
    calculate_alias_statistics,
    validate_report_statistics,
    _is_alias_non_actionable,
    _build_alias_dedup_key,
)


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class _MockMappingManager:
    """Minimal mapping manager stub for finalize() tests."""

    def is_initialized(self) -> bool:
        return True

    def get_mappings_for_source(self, source_id: str) -> List[Dict]:
        return []

    def get_mapping_info(self, source_id: str):
        return None


class _MockConfirmedMappingManager:
    """Mapping manager stub that returns a fixed confirmed alias list for a specific source ID."""

    def __init__(self, source_id: str, confirmed_aliases: List[Dict]):
        self._source_id = source_id
        self._confirmed_aliases = confirmed_aliases

    def is_initialized(self) -> bool:
        return True

    def get_mappings_for_source(self, source_id: str) -> List[Dict]:
        if source_id == self._source_id:
            return [{'aliases': self._confirmed_aliases}]
        return []

    def get_mapping_info(self, source_id: str):
        if source_id == self._source_id:
            return {
                'cnaId': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                'mappings': [{'aliases': self._confirmed_aliases}]
            }
        return None


# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

# A minimal alias with only vendor+product (most basic valid shape)
ALIAS_MINIMAL = {
    'vendor': 'vendor_a',
    'product': 'product_x',
}

# An affected entry that carries one alias and no SDC concerns
ENTRY_WITH_ALIAS: Dict = {
    'originAffectedEntry': {
        'sourceId': 'test-source-uuid-0001',
        'vendor': 'Vendor A',
        'product': 'Product X',
    },
    'aliasExtraction': {
        'aliases': [ALIAS_MINIMAL],
    },
}

# ---------------------------------------------------------------------------
# Pipeline integration test fixtures (test_25)
# Use CVE-1337-XXXX IDs and mirrored-cache nesting, matching the
# test_cpeas_automation_report.py convention.
# ---------------------------------------------------------------------------

TEST_CVE_1337_0025: Dict = {
    'id': 'CVE-1337-0025',
    'configurations': [{
        'nodes': [{
            'cpeMatch': [
                {
                    'criteria': 'cpe:2.3:a:pipe_vendor:pipe_product:1.0:*:*:*:*:*:*:*',
                    'vulnerable': True,
                },
            ]
        }]
    }],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': 'test-source-pipeline-0001'},
            'aliasExtraction': {
                'aliases': [{'vendor': 'pipe_vendor', 'product': 'pipe_product'}],
            },
        }]
    },
}

TEST_CVE_1337_0026: Dict = {
    'id': 'CVE-1337-0026',
    'configurations': [{
        'nodes': [{
            'cpeMatch': [
                {
                    'criteria': 'cpe:2.3:a:pipe_vendor:pipe_product:2.0:*:*:*:*:*:*:*',
                    'vulnerable': True,
                },
            ]
        }]
    }],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': 'test-source-pipeline-0001'},
            'aliasExtraction': {
                'aliases': [{'vendor': 'pipe_vendor', 'product': 'pipe_product_v2'}],
            },
        }]
    },
}

# ---------------------------------------------------------------------------
# by_year accuracy test fixtures (tests 28-33)
# Each test uses a unique source ID and alias fields to prevent cross-test
# deduplication collisions.  Source IDs use the 'yr-test-src-NN' convention.
# ---------------------------------------------------------------------------

# ── Test 28: two distinct CVE years, same alias ────────────────────────────
_SRC_28 = 'yr-test-src-28'
_ALIAS_28_A = {'vendor': 'yr28_vendor', 'product': 'yr28_product'}

# ── Test 29: alias spanning two years + exclusive alias in later year ──────
_SRC_29 = 'yr-test-src-29'
_ALIAS_29_A = {'vendor': 'yr29_vendor_a', 'product': 'yr29_product_a'}
_ALIAS_29_B = {'vendor': 'yr29_vendor_b', 'product': 'yr29_product_b'}

# ── Test 30: confirmed alias tracked per year ──────────────────────────────
_SRC_30 = 'yr-test-src-30'
_ALIAS_30_A = {'vendor': 'yr30_vendor_a', 'product': 'yr30_product_a'}  # confirmed
_ALIAS_30_B = {'vendor': 'yr30_vendor_b', 'product': 'yr30_product_b'}  # unconfirmed

# ── Test 31: concern flag tracked per year ────────────────────────────────
_SRC_31 = 'yr-test-src-31'
_ALIAS_31_CONCERNS = {'vendor': 'yr31_concerns_vendor', 'product': 'yr31_concerns_product'}
_ALIAS_31_CLEAN    = {'vendor': 'yr31_clean_vendor',    'product': 'yr31_clean_product'}

# sourceDataConcerns structure (concern field 'vendor' → matches alias vendor value)
_SDC_CONCERNS_FOR_31 = {
    'concerns': {
        'versionType': [{'field': 'vendor', 'sourceValue': 'yr31_concerns_vendor'}]
    }
}

# ── Test 32: comprehensive — confirmed+concerns, unconfirmed+concerns, three years
_SRC_32 = 'yr-test-src-32'
_ALIAS_32_A = {'vendor': 'yr32_vendor_a', 'product': 'yr32_product_a'}  # confirmed, has concerns
_ALIAS_32_B = {'vendor': 'yr32_vendor_b', 'product': 'yr32_product_b'}  # unconfirmed, no concerns
_ALIAS_32_C = {'vendor': 'yr32_vendor_c', 'product': 'yr32_product_c'}  # unconfirmed, has concerns

_SDC_CONCERNS_FOR_32_A = {
    'concerns': {
        'versionType': [{'field': 'vendor', 'sourceValue': 'yr32_vendor_a'}]
    }
}
_SDC_CONCERNS_FOR_32_C = {
    'concerns': {
        'versionType': [{'field': 'vendor', 'sourceValue': 'yr32_vendor_c'}]
    }
}

# ── Test 33: subprocess — two CVEs from years 2023 and 2025 ──────────────
TEST_CVE_2023_3301: Dict = {
    'id': 'CVE-2023-3301',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': 'test-source-pipeline-0001'},
            'aliasExtraction': {
                'aliases': [{'vendor': 'by_year_vendor', 'product': 'by_year_product_2023'}],
            },
        }]
    },
}

TEST_CVE_2025_3301: Dict = {
    'id': 'CVE-2025-3301',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': 'test-source-pipeline-0001'},
            'aliasExtraction': {
                'aliases': [{'vendor': 'by_year_vendor', 'product': 'by_year_product_2025'}],
            },
        }]
    },
}


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestAliasReportGeneration:
    """Test alias report generation with exact validation."""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results: List[str] = []
        self._template_content: str = None  # lazy-loaded
        self._index_template_content: str = None  # lazy-loaded

    # ------------------------------------------------------------------
    # Assertion helpers
    # ------------------------------------------------------------------

    def assert_equals(self, test_name: str, expected: Any, actual: Any, context: str = "") -> bool:
        if expected == actual:
            self.passed += 1
            self.results.append(f"PASS: {test_name}")
            print(f"  PASS {test_name}")
            return True
        self.failed += 1
        msg = f"FAIL: {test_name}\n    Expected: {expected!r}\n    Actual:   {actual!r}"
        if context:
            msg += f"\n    Context: {context}"
        self.results.append(msg)
        print(f"  FAIL {test_name}")
        print(f"    Expected: {expected!r}")
        print(f"    Actual:   {actual!r}")
        if context:
            print(f"    Context: {context}")
        return False

    def assert_true(self, test_name: str, value: bool, context: str = "") -> bool:
        return self.assert_equals(test_name, True, bool(value), context)

    def assert_in(self, test_name: str, item: Any, container: Any, context: str = "") -> bool:
        if item in container:
            self.passed += 1
            self.results.append(f"PASS: {test_name}")
            print(f"  PASS {test_name}")
            return True
        self.failed += 1
        msg = f"FAIL: {test_name}\n    {item!r} not found in container"
        if context:
            msg += f"\n    Context: {context}"
        self.results.append(msg)
        print(f"  FAIL {test_name}")
        print(f"    {item!r} not found in container")
        if context:
            print(f"    Context: {context}")
        return False

    # ------------------------------------------------------------------
    # Setup / teardown helpers
    # ------------------------------------------------------------------

    def _inject_nvdish_record(self, record: Dict, batch: str = "8xxx") -> Path:
        """Inject one NVD-ish test record into the named test input cache at 1337/<batch>/.

        Mirrors the temp_test_caches naming convention used across all test suites.
        Returns the path to the written file for passing to extract_aliases_from_record().
        """
        target_dir = TEST_NVD_ISH_INPUT_DIR / "1337" / batch
        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = target_dir / f"{record['id']}.json"
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(record, f)
        return file_path

    def _inject_raw_file(self, filename: str, content: str, batch: str = "9xxx") -> Path:
        """Inject raw content (possibly invalid JSON) into the named test input cache.

        Used for error-path tests where the file must exist but be corrupt.
        Returns the path to the written file.
        """
        target_dir = TEST_NVD_ISH_INPUT_DIR / "1337" / batch
        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = target_dir / filename
        file_path.write_text(content, encoding='utf-8')
        return file_path

    def _remove_injected_file(self, file_path: Path):
        """Remove a single injected test file (TEARDOWN for single-file tests)."""
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception as e:
            print(f"  WARNING: Could not remove {file_path}: {e}")

    def setup_nvdish_test_cache(self, fixtures: List[Dict], batch: str = "0xxx") -> Path:
        """Write NVD-ish test fixture records into the named temp test cache.

        Mirrors the real nvd-ish_2.0_cves/ structure (year/batch/) under
        temp_test_caches so that scan_nvd_ish_cache() reads only controlled
        test data — no production records can enter or be poisoned.

        Returns the root cache path to pass directly to scan_nvd_ish_cache().
        """
        target_dir = TEST_NVD_ISH_INPUT_DIR / "1337" / batch
        target_dir.mkdir(parents=True, exist_ok=True)
        for record in fixtures:
            file_path = target_dir / f"{record['id']}.json"
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(record, f)
        return TEST_NVD_ISH_INPUT_DIR

    def teardown_nvdish_test_cache(self):
        """Remove the entire NVD-ish test input cache directory (TEARDOWN for scan tests)."""
        if TEST_NVD_ISH_INPUT_DIR.exists():
            shutil.rmtree(TEST_NVD_ISH_INPUT_DIR)

    def setup_subprocess_test_cache(self, fixtures: List[Dict], batch: str = "0xxx") -> None:
        """SETUP: Inject fixture files into the flat subprocess test cache.

        Uses a flat top-level directory name (no separators) so that
        --custom-cache accepts it per the path-traversal security check.
        Mirrors the real nvd-ish_2.0_cves/ structure (year/batch/) for
        scan_nvd_ish_cache() compatibility.
        """
        for record in fixtures:
            year = record.get('id', 'CVE-0000-0000').split('-')[1]
            target_dir = TEST_SUBPROCESS_CACHE_DIR / year / batch
            target_dir.mkdir(parents=True, exist_ok=True)
            cve_id = record.get('id', 'CVE-UNKNOWN')
            file_path = target_dir / f"{cve_id}.json"
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(record, f, indent=2, ensure_ascii=False)

    def teardown_subprocess_test_cache(self) -> None:
        """TEARDOWN: Remove flat subprocess INPUT cache only; run output preserved for inspection."""
        if TEST_SUBPROCESS_CACHE_DIR.exists():
            shutil.rmtree(TEST_SUBPROCESS_CACHE_DIR)

    def setup_report_output_dir(self) -> Path:
        """Create the named test report output directory for JSON output validation tests."""
        TEST_REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        return TEST_REPORT_OUTPUT_DIR

    def teardown_report_output_dir(self):
        """Remove the test report output directory."""
        if TEST_REPORT_OUTPUT_DIR.exists():
            shutil.rmtree(TEST_REPORT_OUTPUT_DIR)

    def _load_template(self) -> str:
        if self._template_content is None:
            template_path = (
                project_root
                / "src"
                / "analysis_tool"
                / "static"
                / "templates"
                / "Alias_Mapping_Report_Template.html"
            )
            with open(template_path, 'r', encoding='utf-8') as f:
                self._template_content = f.read()
        return self._template_content

    def _load_index_template(self) -> str:
        if self._index_template_content is None:
            template_path = (
                project_root
                / "src"
                / "analysis_tool"
                / "static"
                / "templates"
                / "Alias_Mapping_Index_Template.html"
            )
            with open(template_path, 'r', encoding='utf-8') as f:
                self._index_template_content = f.read()
        return self._index_template_content

    # ------------------------------------------------------------------
    # Builder factory helpers
    # ------------------------------------------------------------------

    def _make_builder(self) -> AliasReportBuilder:
        """Create builder with mock managers (no real I/O)."""
        return AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockMappingManager(),
        )

    def _cpe_base_from_criteria(self, criteria: str) -> str:
        """Normalize a versioned criteria string to a base string."""
        parts = criteria.split(':')
        return ':'.join(parts[:5]) + ':*:*:*:*:*:*:*:*'

    def _add_cve_with_cpes(
        self,
        builder: AliasReportBuilder,
        cve_id: str,
        criteria_list: List[str],
        alias_override: Dict = None,
    ):
        """Add CVE aliases to builder with CPE base strings derived from criteria_list."""
        nvd_cpe_set = {self._cpe_base_from_criteria(c) for c in criteria_list}
        alias = alias_override or ALIAS_MINIMAL
        entry = {
            'originAffectedEntry': {
                'sourceId': 'test-source-uuid-0001',
            },
            'aliasExtraction': {
                'aliases': [alias],
            },
        }
        builder.add_cve_aliases(cve_id, [entry], nvd_cpe_set)

    # ==================================================================
    # GROUP 1: _extract_nvd_cpe_base_strings() unit tests
    # ==================================================================

    def test_01_empty_configurations_returns_empty_set(self):
        """Test 1: Empty configurations list → empty set."""
        print("\nTest 1: Empty configurations returns empty set")
        result = _extract_nvd_cpe_base_strings([])
        self.assert_equals("Result type is set", set, type(result))
        self.assert_equals("Result is empty", 0, len(result))

    def test_02_vulnerable_false_excluded(self):
        """Test 2: cpeMatch entries with vulnerable=False are excluded."""
        print("\nTest 2: vulnerable=False entries are excluded")
        configs = [{
            'nodes': [{
                'cpeMatch': [
                    {'criteria': 'cpe:2.3:a:vendor_a:product_x:1.0:*:*:*:*:*:*:*', 'vulnerable': False},
                ]
            }]
        }]
        result = _extract_nvd_cpe_base_strings(configs)
        self.assert_equals("vulnerable=False excluded", 0, len(result))

    def test_03_versioned_criteria_normalized_to_base(self):
        """Test 3: Versioned criteria normalized to 5-part base + wildcards."""
        print("\nTest 3: Versioned criteria normalized to base string")
        configs = [{
            'nodes': [{
                'cpeMatch': [
                    {'criteria': 'cpe:2.3:a:vendor_a:product_x:1.2.3:*:*:*:*:*:*:*', 'vulnerable': True},
                ]
            }]
        }]
        result = _extract_nvd_cpe_base_strings(configs)
        expected_base = 'cpe:2.3:a:vendor_a:product_x:*:*:*:*:*:*:*:*'
        self.assert_equals("Exactly one base string produced", 1, len(result))
        self.assert_in("Correct base string present", expected_base, result)

    def test_04_multiple_versions_same_product_deduplicated(self):
        """Test 4: Multiple versioned criteria for same product → single base string."""
        print("\nTest 4: Multiple versions of same product deduplicated")
        configs = [{
            'nodes': [{
                'cpeMatch': [
                    {'criteria': 'cpe:2.3:a:vendor_a:product_x:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
                    {'criteria': 'cpe:2.3:a:vendor_a:product_x:2.0:*:*:*:*:*:*:*', 'vulnerable': True},
                    {'criteria': 'cpe:2.3:a:vendor_a:product_x:3.0:*:*:*:*:*:*:*', 'vulnerable': True},
                ]
            }]
        }]
        result = _extract_nvd_cpe_base_strings(configs)
        self.assert_equals("Deduplicated to one base string", 1, len(result))

    def test_05_short_criteria_skipped(self):
        """Test 5: Criteria that don't conform to CPE 2.3 format (13 components) are skipped."""
        print("\nTest 5: Non-conforming criteria skipped gracefully")
        configs = [{
            'nodes': [{
                'cpeMatch': [
                    {'criteria': 'cpe:2.3:a:vendor_a', 'vulnerable': True},   # 4 parts
                    {'criteria': 'invalid_string', 'vulnerable': True},
                    {'criteria': '', 'vulnerable': True},
                ]
            }]
        }]
        result = _extract_nvd_cpe_base_strings(configs)
        self.assert_equals("Non-conforming criteria produce empty set", 0, len(result))

    def test_06_mixed_vulnerable_flags(self):
        """Test 6: Mixed vulnerable flags — only True entries counted."""
        print("\nTest 6: Mixed vulnerable flags — only True entries counted")
        configs = [{
            'nodes': [{
                'cpeMatch': [
                    {'criteria': 'cpe:2.3:a:vendor_a:product_x:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
                    {'criteria': 'cpe:2.3:a:vendor_b:product_y:1.0:*:*:*:*:*:*:*', 'vulnerable': False},
                    {'criteria': 'cpe:2.3:a:vendor_c:product_z:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
                ]
            }]
        }]
        result = _extract_nvd_cpe_base_strings(configs)
        self.assert_equals("Two vulnerable=True entries → 2 base strings", 2, len(result))
        self.assert_in("vendor_a base string present",
                       'cpe:2.3:a:vendor_a:product_x:*:*:*:*:*:*:*:*', result)
        self.assert_in("vendor_c base string present",
                       'cpe:2.3:a:vendor_c:product_z:*:*:*:*:*:*:*:*', result)
        self.assert_true("vendor_b NOT in result",
                         'cpe:2.3:a:vendor_b:product_y:*:*:*:*:*:*:*:*' not in result)

    def test_07_multiple_nodes_and_configs(self):
        """Test 7: Entries across multiple nodes and config blocks are all collected."""
        print("\nTest 7: Multiple nodes and config blocks collected")
        configs = [
            {
                'nodes': [{
                    'cpeMatch': [
                        {'criteria': 'cpe:2.3:a:vendor_a:product_x:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
                    ]
                }]
            },
            {
                'nodes': [
                    {
                        'cpeMatch': [
                            {'criteria': 'cpe:2.3:a:vendor_b:product_y:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
                        ]
                    },
                    {
                        'cpeMatch': [
                            {'criteria': 'cpe:2.3:a:vendor_c:product_z:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
                        ]
                    },
                ]
            }
        ]
        result = _extract_nvd_cpe_base_strings(configs)
        self.assert_equals("Three base strings from multiple nodes/configs", 3, len(result))

    # ==================================================================
    # GROUP 2: extract_aliases_from_record() file I/O tests
    # ==================================================================

    def test_08_extract_returns_three_tuple_on_success(self):
        """Test 8: extract_aliases_from_record returns (cve_id, entries, set) on success."""
        print("\nTest 8: Returns 3-tuple on successful read")
        record = {
                'id': 'CVE-1337-8001',
                'configurations': [{
                    'nodes': [{
                        'cpeMatch': [
                            {'criteria': 'cpe:2.3:a:vendor_a:product_x:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
                        ]
                    }]
                }],
                'enrichedCVEv5Affected': {
                    'cveListV5AffectedEntries': [ENTRY_WITH_ALIAS]
                }
            }
        file_path = self._inject_nvdish_record(record, batch='8xxx')
        try:
            cve_id, entries, nvd_cpe_set = extract_aliases_from_record(file_path)

            self.assert_equals("CVE ID returned correctly", 'CVE-1337-8001', cve_id)
            self.assert_equals("One entry returned", 1, len(entries))
            self.assert_equals("nvd_cpe_set is a set", set, type(nvd_cpe_set))
            self.assert_equals("nvd_cpe_set has one base string", 1, len(nvd_cpe_set))
            self.assert_in("Correct CPE base string in set",
                           'cpe:2.3:a:vendor_a:product_x:*:*:*:*:*:*:*:*', nvd_cpe_set)
        finally:
            self._remove_injected_file(file_path)

    def test_09_malformed_json_returns_none_tuple(self):
        """Test 9: Malformed JSON returns (None, [], set())."""
        print("\nTest 9: Malformed JSON returns error tuple")
        file_path = self._inject_raw_file('CVE-1337-9bad.json', '{invalid json content}', batch='9xxx')
        try:
            cve_id, entries, nvd_cpe_set = extract_aliases_from_record(file_path)

            self.assert_equals("CVE ID is None on bad JSON", None, cve_id)
            self.assert_equals("Entries empty on bad JSON", [], entries)
            self.assert_equals("NVD CPE set empty on bad JSON", set(), nvd_cpe_set)
        finally:
            self._remove_injected_file(file_path)

    def test_10_no_enriched_returns_empty_entries_with_cpe_set(self):
        """Test 10: No enrichedCVEv5Affected → entries=[], but configurations CPE set populated."""
        print("\nTest 10: No enrichedCVEv5Affected returns empty entries, CPE set still populated")
        record = {
            'id': 'CVE-1337-8010',
            'configurations': [{
                'nodes': [{
                    'cpeMatch': [
                        {'criteria': 'cpe:2.3:a:vendor_a:product_x:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
                    ]
                }]
            }]
            # No enrichedCVEv5Affected key at all
        }
        file_path = self._inject_nvdish_record(record, batch='8xxx')
        try:
            cve_id, entries, nvd_cpe_set = extract_aliases_from_record(file_path)

            self.assert_equals("CVE ID returned with no enriched data", 'CVE-1337-8010', cve_id)
            self.assert_equals("Entries empty without enrichedCVEv5Affected", [], entries)
            self.assert_equals("CPE set populated from configurations", 1, len(nvd_cpe_set))
        finally:
            self._remove_injected_file(file_path)

    def test_11_no_configurations_returns_empty_cpe_set(self):
        """Test 11: No configurations key → nvd_cpe_set is empty set."""
        print("\nTest 11: No configurations key returns empty NVD CPE set")
        record = {
            'id': 'CVE-1337-8011',
            'enrichedCVEv5Affected': {
                'cveListV5AffectedEntries': [ENTRY_WITH_ALIAS]
            }
            # No configurations key
        }
        file_path = self._inject_nvdish_record(record, batch='8xxx')
        try:
            cve_id, entries, nvd_cpe_set = extract_aliases_from_record(file_path)

            self.assert_equals("CVE ID returned", 'CVE-1337-8011', cve_id)
            self.assert_equals("NVD CPE set empty when no configurations", set(), nvd_cpe_set)
        finally:
            self._remove_injected_file(file_path)

    # ==================================================================
    # GROUP 3: AliasReportBuilder.topNvdCpeBaseStrings aggregation
    # ==================================================================

    def test_12_single_cve_single_cpe(self):
        """Test 12: Single CVE with one CPE base → topNvdCpeBaseStrings list has cveCount=1."""
        print("\nTest 12: Single CVE single CPE")
        builder = self._make_builder()
        self._add_cve_with_cpes(
            builder, 'CVE-2024-0001',
            ['cpe:2.3:a:vendor_a:product_x:1.0:*:*:*:*:*:*:*']
        )

        reports = builder.finalize()
        org = 'test-source-uuid-0001'
        self.assert_true("Source present in finalize output", org in reports)
        if org in reports:
            groups = reports[org]['aliasGroups']
            self.assert_true("At least one alias group", len(groups) > 0)
            if groups:
                aliases = groups[0].get('aliases', [])
                self.assert_true("At least one alias in group", len(aliases) > 0)
                if aliases:
                    top_cpes = aliases[0]['topNvdCpeBaseStrings']
                    self.assert_equals("One CPE entry", 1, len(top_cpes))
                    if top_cpes:
                        self.assert_equals("cveCount is 1", 1, top_cpes[0]['cveCount'])
                        self.assert_equals(
                            "cpeBaseString correct",
                            'cpe:2.3:a:vendor_a:product_x:*:*:*:*:*:*:*:*',
                            top_cpes[0]['cpeBaseString']
                        )

    def test_13_two_cves_same_alias_same_cpe_counts_two(self):
        """Test 13: Two CVEs with same alias both referencing same CPE base → cveCount=2 (per-alias)."""
        print("\nTest 13: Two CVEs same alias same CPE → cveCount=2")
        builder = self._make_builder()

        # Use the SAME alias (ALIAS_MINIMAL default) for both CVEs so they merge
        # into one alias entry with source_cve=[CVE-2024-0001, CVE-2024-0002].
        # The per-alias topNvdCpeBaseStrings should then report cveCount=2.
        cpe_base = 'cpe:2.3:a:vendor_a:product_x:*:*:*:*:*:*:*:*'

        self._add_cve_with_cpes(builder, 'CVE-2024-0001',
                                ['cpe:2.3:a:vendor_a:product_x:1.0:*:*:*:*:*:*:*'])
        self._add_cve_with_cpes(builder, 'CVE-2024-0002',
                                ['cpe:2.3:a:vendor_a:product_x:2.0:*:*:*:*:*:*:*'])

        reports = builder.finalize()
        org = 'test-source-uuid-0001'
        self.assert_true("Source present in finalize output", org in reports)
        if org in reports:
            # Gather topNvdCpeBaseStrings from every alias across all groups
            all_entries: List[Dict] = []
            for group in reports[org]['aliasGroups']:
                for alias in group.get('aliases', []):
                    all_entries.extend(alias.get('topNvdCpeBaseStrings', []))

            matching = [e for e in all_entries if e['cpeBaseString'] == cpe_base]
            self.assert_true("CPE base string found in at least one alias", len(matching) > 0)
            if matching:
                # The merged alias holds both CVEs → cveCount must be 2
                max_count = max(e['cveCount'] for e in matching)
                self.assert_equals("cveCount is 2 for shared CPE (same alias, two CVEs)", 2, max_count)

    def test_14_top_5_cap_enforced(self):
        """Test 14: More than 5 distinct CPE base strings → only top 5 returned."""
        print("\nTest 14: Top-5 cap enforced")
        builder = self._make_builder()

        # 7 distinct criteria → 7 distinct base strings, all from one CVE
        criteria_list = [
            f'cpe:2.3:a:vendor_a:product_{i}:1.0:*:*:*:*:*:*:*'
            for i in range(7)
        ]
        self._add_cve_with_cpes(builder, 'CVE-2024-0001', criteria_list)

        reports = builder.finalize()
        org = 'test-source-uuid-0001'
        self.assert_true("Source present in finalize output", org in reports)
        if org in reports:
            groups = reports[org]['aliasGroups']
            self.assert_true("At least one alias group", len(groups) > 0)
            if groups:
                aliases = groups[0].get('aliases', [])
                self.assert_true("At least one alias in group", len(aliases) > 0)
                if aliases:
                    top_cpes = aliases[0]['topNvdCpeBaseStrings']
                    self.assert_equals("Exactly 5 CPEs returned (top-5 cap)", 5, len(top_cpes))

    def test_15_no_cpe_data_produces_empty_top_cpes(self):
        """Test 15: CVE with no NVD configuration data → topNvdCpeBaseStrings is []."""
        print("\nTest 15: No NVD configuration data → empty topNvdCpeBaseStrings")
        builder = self._make_builder()
        # Add CVE with empty CPE set (no configurations data)
        builder.add_cve_aliases('CVE-2024-0001', [ENTRY_WITH_ALIAS], set())

        reports = builder.finalize()
        org = 'test-source-uuid-0001'
        self.assert_true("Source present in finalize output", org in reports)
        if org in reports:
            groups = reports[org]['aliasGroups']
            self.assert_true("At least one alias group", len(groups) > 0)
            if groups:
                aliases = groups[0].get('aliases', [])
                self.assert_true("At least one alias in group", len(aliases) > 0)
                if aliases:
                    top_cpes = aliases[0]['topNvdCpeBaseStrings']
                    self.assert_equals("Empty topNvdCpeBaseStrings when no CPE data", [], top_cpes)

    def test_16_cpe_sorted_by_count_descending(self):
        """Test 16: CPEs with different cveCount values are sorted descending (per-alias)."""
        print("\nTest 16: CPE entries sorted by cveCount descending")
        builder = self._make_builder()

        base_a = 'cpe:2.3:a:vendor_a:product_a:*:*:*:*:*:*:*:*'
        base_b = 'cpe:2.3:a:vendor_b:product_b:*:*:*:*:*:*:*:*'
        base_c = 'cpe:2.3:a:vendor_c:product_c:*:*:*:*:*:*:*:*'

        # Use ENTRY_WITH_ALIAS (same alias key) for all 3 CVEs so they merge into
        # one alias entry. base_a in 3 CVEs, base_b in 2, base_c in 1.
        builder.add_cve_aliases('CVE-2024-0001', [ENTRY_WITH_ALIAS], {base_a, base_b, base_c})
        builder.add_cve_aliases('CVE-2024-0002', [ENTRY_WITH_ALIAS], {base_a, base_b})
        builder.add_cve_aliases('CVE-2024-0003', [ENTRY_WITH_ALIAS], {base_a})

        reports = builder.finalize()
        org = 'test-source-uuid-0001'
        self.assert_true("Source present in finalize output", org in reports)
        if org in reports:
            for group in reports[org]['aliasGroups']:
                for alias in group.get('aliases', []):
                    top_cpes = alias['topNvdCpeBaseStrings']
                    counts = [e['cveCount'] for e in top_cpes]
                    self.assert_equals(
                        "CPEs sorted descending within alias",
                        sorted(counts, reverse=True),
                        counts
                    )

            # Verify expected per-alias counts (the merged alias sees all 3 CVEs)
            all_entries_by_cpe: Dict[str, int] = {}
            for group in reports[org]['aliasGroups']:
                for alias in group.get('aliases', []):
                    for entry in alias['topNvdCpeBaseStrings']:
                        cpe = entry['cpeBaseString']
                        all_entries_by_cpe[cpe] = max(
                            all_entries_by_cpe.get(cpe, 0), entry['cveCount']
                        )

            self.assert_equals("base_a count is 3", 3, all_entries_by_cpe.get(base_a, 0))
            self.assert_equals("base_b count is 2", 2, all_entries_by_cpe.get(base_b, 0))
            self.assert_equals("base_c count is 1", 1, all_entries_by_cpe.get(base_c, 0))

    # ==================================================================
    # GROUP 4: Template content validation
    # ==================================================================

    def test_17_template_has_groupCvesByYear(self):
        """Test 17: Template contains groupCvesByYear JavaScript function."""
        print("\nTest 17: Template has groupCvesByYear function")
        template = self._load_template()
        self.assert_in("groupCvesByYear function defined", "function groupCvesByYear", template)

    def test_18_template_has_generateCveGroupsHtml(self):
        """Test 18: Template contains generateCveGroupsHtml JavaScript function."""
        print("\nTest 18: Template has generateCveGroupsHtml function")
        template = self._load_template()
        self.assert_in("generateCveGroupsHtml function defined", "function generateCveGroupsHtml", template)

    def test_19_template_propagates_topNvdCpeBaseStrings_in_loadData(self):
        """Test 19: loadData() reads topNvdCpeBaseStrings from the individual alias object."""
        print("\nTest 19: topNvdCpeBaseStrings from alias in loadData")
        template = self._load_template()
        self.assert_in(
            "topNvdCpeBaseStrings from alias in loadData",
            "topNvdCpeBaseStrings: alias.topNvdCpeBaseStrings || []",
            template
        )

    def test_20_template_has_nvd_cpe_section_at_both_render_sites(self):
        """Test 20: Both detailsDiv render sites and CSS include nvd-cpe-section class."""
        print("\nTest 20: Both render sites include nvd-cpe-section")
        template = self._load_template()
        count = template.count('nvd-cpe-section')
        # Expected occurrences: CSS definition + 2 conditional render blocks
        self.assert_true(
            f"nvd-cpe-section appears at least 3 times (CSS + 2 render sites), found {count}",
            count >= 3
        )

    def test_21_template_conditional_hides_when_empty(self):
        """Test 21: NVD CPE section uses a guard condition to hide when array is empty."""
        print("\nTest 21: Conditional guard hides section when topNvdCpeBaseStrings is empty")
        template = self._load_template()
        self.assert_in(
            "Conditional check for non-empty array",
            "alias.topNvdCpeBaseStrings && alias.topNvdCpeBaseStrings.length > 0",
            template
        )

    # ==================================================================
    # GROUP 4c: New template element validation (filter-active signal, ratio card, index columns)
    # ==================================================================

    def test_37_source_template_has_aliasRatio_element(self):
        """Test 37: Source report template contains the aliasRatio stat card element."""
        print("\nTest 37: Source template has id='aliasRatio' stat card")
        template = self._load_template()
        self.assert_in("aliasRatio element defined", 'id="aliasRatio"', template)

    def test_38_source_template_has_updateFilterActiveSignal(self):
        """Test 38: Source report template contains the updateFilterActiveSignal JS function."""
        print("\nTest 38: Source template has updateFilterActiveSignal function")
        template = self._load_template()
        self.assert_in("updateFilterActiveSignal function defined", "function updateFilterActiveSignal", template)

    def test_39_source_template_filters_active_class_toggled(self):
        """Test 39: Source report template uses filters-active CSS class in toggle logic."""
        print("\nTest 39: Source template toggles filters-active CSS class")
        template = self._load_template()
        self.assert_in("filters-active class referenced in JS", "filters-active", template)

    def test_40_source_template_stat_card_order(self):
        """Test 40: Stat cards appear in order totalCVEs → totalAliases → aliasRatio."""
        print("\nTest 40: Source template stat card order totalCVEs → totalAliases → aliasRatio")
        template = self._load_template()
        idx_cves = template.find('id="totalCVEs"')
        idx_aliases = template.find('id="totalAliases"')
        idx_ratio = template.find('id="aliasRatio"')
        self.assert_true(
            "totalCVEs appears before totalAliases",
            idx_cves != -1 and idx_aliases != -1 and idx_cves < idx_aliases
        )
        self.assert_true(
            "totalAliases appears before aliasRatio",
            idx_aliases != -1 and idx_ratio != -1 and idx_aliases < idx_ratio
        )

    def test_41_source_template_has_alias_sets_per_cve_label(self):
        """Test 41: Source report template contains the 'Alias Sets / CVE' stat label."""
        print("\nTest 41: Source template has 'Alias Sets / CVE' label")
        template = self._load_template()
        self.assert_in("Alias Sets / CVE label defined", "Alias Sets / CVE", template)

    def test_42_index_template_has_unique_alias_sets_column(self):
        """Test 42: Index template table header contains 'Unique Alias Sets' column."""
        print("\nTest 42: Index template has 'Unique Alias Sets' column header")
        index_template = self._load_index_template()
        self.assert_in("Unique Alias Sets column header defined", "Unique Alias Sets", index_template)

    def test_43_index_template_has_unique_cves_column(self):
        """Test 43: Index template table header contains 'Unique CVEs' column."""
        print("\nTest 43: Index template has 'Unique CVEs' column header")
        index_template = self._load_index_template()
        self.assert_in("Unique CVEs column header defined", "Unique CVEs", index_template)

    def test_44_source_template_has_aliasFieldSelections_element(self):
        """Test 44: Source report template contains the aliasFieldSelections container div."""
        print("\nTest 44: Source template has id='aliasFieldSelections' container")
        template = self._load_template()
        self.assert_in("aliasFieldSelections container defined", 'id="aliasFieldSelections"', template)

    def test_45_source_template_has_renderAliasFieldCheckboxes(self):
        """Test 45: Source report template contains the renderAliasFieldCheckboxes JS function."""
        print("\nTest 45: Source template has renderAliasFieldCheckboxes function")
        template = self._load_template()
        self.assert_in("renderAliasFieldCheckboxes function defined", "function renderAliasFieldCheckboxes", template)

    def test_46_source_template_has_aliasEntryMap_variable(self):
        """Test 46: Source report template declares the aliasEntryMap tracking variable."""
        print("\nTest 46: Source template has aliasEntryMap variable")
        template = self._load_template()
        self.assert_in("aliasEntryMap variable declared", "aliasEntryMap", template)

    def test_22_non_wildcard_edition_preserved_in_base_string(self):
        """Test 22: Only version and update are wildcarded; all other attributes are preserved."""
        print("\nTest 22: Non-wildcard edition/language preserved, only version+update wildcarded")
        # criteria: cpe:2.3:a:vendor_a:product_x:1.0:sp1:community:-:*:*:*:*
        # version = 1.0 (index 5) → wildcard
        # update  = sp1 (index 6) → wildcard
        # edition = community (index 7) → preserved
        # language = - (index 8) → preserved
        configs = [{
            'nodes': [{
                'cpeMatch': [
                    {
                        'criteria': 'cpe:2.3:a:vendor_a:product_x:1.0:sp1:community:-:*:*:*:*',
                        'vulnerable': True
                    },
                ]
            }]
        }]
        result = _extract_nvd_cpe_base_strings(configs)
        expected_base = 'cpe:2.3:a:vendor_a:product_x:*:*:community:-:*:*:*:*'
        self.assert_equals("Exactly one base string produced", 1, len(result))
        self.assert_in("Edition and language preserved in base string", expected_base, result)
        # Confirm the old (incorrect) all-wildcards form is NOT produced
        wrong_base = 'cpe:2.3:a:vendor_a:product_x:*:*:*:*:*:*:*:*'
        self.assert_true(
            "All-wildcards base string NOT produced when edition/language set",
            wrong_base not in result
        )

    def test_23_file_io_preserves_non_wildcard_target_sw(self):
        """Test 23: extract_aliases_from_record() preserves non-wildcard target_sw via file I/O."""
        print("\nTest 23: File I/O path preserves non-wildcard target_sw attribute")
        # criteria has version=1.0 and update=sp1 (both → wildcarded),
        # but target_sw=windows (index 10) must be preserved.
        record = {
            'id': 'CVE-1337-8023',
            'configurations': [{
                'nodes': [{
                    'cpeMatch': [
                        {
                            'criteria': 'cpe:2.3:a:vendor_a:product_x:1.0:sp1:*:*:*:windows:*:*',
                            'vulnerable': True
                        },
                    ]
                }]
            }],
            'enrichedCVEv5Affected': {
                'cveListV5AffectedEntries': [ENTRY_WITH_ALIAS]
            }
        }
        file_path = self._inject_nvdish_record(record, batch='8xxx')
        try:
            cve_id, entries, nvd_cpe_set = extract_aliases_from_record(file_path)

            expected_base = 'cpe:2.3:a:vendor_a:product_x:*:*:*:*:*:windows:*:*'
            wrong_base   = 'cpe:2.3:a:vendor_a:product_x:*:*:*:*:*:*:*:*'

            self.assert_equals("One base string produced via file I/O", 1, len(nvd_cpe_set))
            self.assert_in("target_sw=windows preserved through file I/O", expected_base, nvd_cpe_set)
            self.assert_true(
                "All-wildcards form NOT produced when target_sw is set",
                wrong_base not in nvd_cpe_set
            )
        finally:
            self._remove_injected_file(file_path)

    def test_24_criteria_over_13_components_rejected(self):
        """Test 24: Criteria with more than 13 components are rejected (new validate_cpe_23_format behavior)."""
        print("\nTest 24: Criteria with >13 components rejected by validate_cpe_23_format")
        # Old code accepted anything with ≥ 5 parts; new code requires exactly 13.
        # 14-component CPE (extra trailing field) must be skipped.
        configs = [{
            'nodes': [{
                'cpeMatch': [
                    # Valid 13-component entry — should be accepted
                    {
                        'criteria': 'cpe:2.3:a:vendor_a:product_x:1.0:*:*:*:*:*:*:*',
                        'vulnerable': True
                    },
                    # 14-component entry — must be rejected by new validation
                    {
                        'criteria': 'cpe:2.3:a:vendor_a:product_y:1.0:*:*:*:*:*:*:*:extra',
                        'vulnerable': True
                    },
                ]
            }]
        }]
        result = _extract_nvd_cpe_base_strings(configs)
        # Only the valid entry should produce output
        self.assert_equals("Only 1 base string produced (14-component entry rejected)", 1, len(result))
        self.assert_in(
            "Valid 13-component base string present",
            'cpe:2.3:a:vendor_a:product_x:*:*:*:*:*:*:*:*',
            result
        )
        self.assert_true(
            "14-component entry NOT in result",
            'cpe:2.3:a:vendor_a:product_y:*:*:*:*:*:*:*:*' not in result
        )

    # ==================================================================
    # GROUP 4b: _is_alias_non_actionable() unit tests
    # ==================================================================

    def test_24b_non_actionable_all_placeholders(self):
        """Test 24b: _is_alias_non_actionable() returns True when all identity fields are placeholders."""
        print("\nTest 24b: _is_alias_non_actionable — all placeholder fields")
        self.assert_true("n/a vendor+product is non-actionable",
                         _is_alias_non_actionable({'vendor': 'n/a', 'product': 'n/a'}))
        self.assert_true("unspecified vendor+product is non-actionable",
                         _is_alias_non_actionable({'vendor': 'unspecified', 'product': 'unspecified'}))
        self.assert_true("empty vendor+product is non-actionable",
                         _is_alias_non_actionable({'vendor': '', 'product': ''}))
        self.assert_true("None vendor (absent) is non-actionable",
                         _is_alias_non_actionable({}))
        self.assert_true("source_cve-only alias is non-actionable",
                         _is_alias_non_actionable({'source_cve': ['CVE-2024-0001']}))

    def test_24c_non_actionable_returns_false_for_actionable(self):
        """Test 24c: _is_alias_non_actionable() returns False when any identity field has real data."""
        print("\nTest 24c: _is_alias_non_actionable — actionable aliases return False")
        self.assert_true("real vendor+product is actionable",
                         not _is_alias_non_actionable({'vendor': 'vendor_a', 'product': 'product_x'}))
        self.assert_true("real packageName is actionable",
                         not _is_alias_non_actionable({'packageName': 'real-package'}))
        self.assert_true("real collectionURL is actionable",
                         not _is_alias_non_actionable({'collectionURL': 'https://example.com/pkg'}))
        self.assert_true("real repo is actionable",
                         not _is_alias_non_actionable({'repo': 'https://github.com/org/repo'}))
        self.assert_true("non-empty modules list is actionable",
                         not _is_alias_non_actionable({'modules': ['mod_a', 'mod_b']}))
        self.assert_true("non-empty programFiles list is actionable",
                         not _is_alias_non_actionable({'programFiles': ['file.exe']}))
        self.assert_true("n/a vendor but real product is actionable",
                         not _is_alias_non_actionable({'vendor': 'n/a', 'product': 'real_product'}))

    def test_24d_dedup_key_unchanged_for_non_actionable(self):
        """Test 24d: _build_alias_dedup_key() still produces a non-empty key for non-actionable aliases."""
        print("\nTest 24d: dedup key still built for non-actionable aliases (identity and actionability are orthogonal)")
        alias = {'vendor': 'n/a', 'product': 'n/a', 'source_cve': ['CVE-2024-0001']}
        key = _build_alias_dedup_key(alias)
        # The key must be non-empty (dedup is not affected by non-actionability)
        self.assert_true("dedup key is non-empty for n/a alias", len(key) > 0)
        self.assert_true("dedup key contains 'product'", 'product' in key)
        self.assert_true("dedup key contains 'vendor'", 'vendor' in key)
        # source_cve must be excluded from the key
        self.assert_true("dedup key does not contain 'source_cve'", 'source_cve' not in key)

    def test_34_by_year_non_actionable_count(self):
        """Test 34: finalize() tracks non_actionable_count per year in by_year."""
        print("\nTest 34: by_year non_actionable_count tracked per year")
        _SRC_34 = 'yr-test-src-34'
        _ALIAS_34_ACTION = {'vendor': 'yr34_vendor', 'product': 'yr34_product'}
        _ALIAS_34_NA     = {'vendor': 'n/a',         'product': 'n/a'}

        # SETUP: actionable alias on 2024, non-actionable alias on 2024 + 2025
        builder = AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockMappingManager(),
        )
        entry_action_2024 = {
            'originAffectedEntry': {'sourceId': _SRC_34},
            'aliasExtraction': {'aliases': [_ALIAS_34_ACTION]},
        }
        entry_na_2024 = {
            'originAffectedEntry': {'sourceId': _SRC_34},
            'aliasExtraction': {'aliases': [_ALIAS_34_NA]},
        }
        entry_na_2025 = {
            'originAffectedEntry': {'sourceId': _SRC_34},
            'aliasExtraction': {'aliases': [_ALIAS_34_NA]},
        }
        builder.add_cve_aliases('CVE-2024-3401', [entry_action_2024, entry_na_2024], nvd_cpe_set=set())
        builder.add_cve_aliases('CVE-2025-3401', [entry_na_2025], nvd_cpe_set=set())

        # EXECUTE
        reports = builder.finalize()
        by_year = reports[_SRC_34]['metadata']['by_year']

        # VALIDATE
        self.assert_true("by_year has '2024'", '2024' in by_year)
        self.assert_true("by_year has '2025'", '2025' in by_year)
        self.assert_equals("2024 non_actionable_count == 1", 1, by_year['2024']['non_actionable_count'])
        self.assert_equals("2024 unconfirmed_count == 1 (actionable only)", 1, by_year['2024']['unconfirmed_count'])
        self.assert_equals("2025 non_actionable_count == 1", 1, by_year['2025']['non_actionable_count'])
        self.assert_equals("2025 unconfirmed_count == 0", 0, by_year['2025']['unconfirmed_count'])
        # Coverage denominator for 2024 = confirmed(0) + unconfirmed(1) = 1; non-actionable excluded
        self.assert_equals("2024 confirmed_coverage_pct == 0.0 (denominator excludes NA)",
                           0.0, by_year['2024']['confirmed_coverage_pct'])

        # TEARDOWN
        builder = None

    def test_35_confirmed_cna_id_present_when_mapping_file_loaded(self):
        """Test 35: finalize() sets confirmed_cna_id in metadata when an existing mapping file is loaded."""
        print("\nTest 35: confirmed_cna_id present in metadata when existing mapping file loaded")
        _SRC_35 = 'test-source-uuid-0035'
        _ALIAS_35 = {'vendor': 'vendor_35', 'product': 'product_35'}
        _EXPECTED_CNA_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

        builder = AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockConfirmedMappingManager(_SRC_35, []),
        )
        entry = {
            'originAffectedEntry': {'sourceId': _SRC_35},
            'aliasExtraction': {'aliases': [_ALIAS_35]},
        }
        builder.add_cve_aliases('CVE-2024-3500', [entry], nvd_cpe_set=set())
        reports = builder.finalize()

        org_metadata = list(reports.values())[0]['metadata']
        self.assert_true(
            "confirmed_cna_id key present in metadata",
            'confirmed_cna_id' in org_metadata
        )
        self.assert_equals(
            "confirmed_cna_id matches existing file cnaId",
            _EXPECTED_CNA_ID,
            org_metadata['confirmed_cna_id']
        )

    def test_36_confirmed_cna_id_none_when_no_mapping_file(self):
        """Test 36: finalize() sets confirmed_cna_id to None in metadata when no existing mapping file is loaded."""
        print("\nTest 36: confirmed_cna_id is None in metadata when no existing mapping file")
        _SRC_36 = 'test-source-uuid-0036'
        _ALIAS_36 = {'vendor': 'vendor_36', 'product': 'product_36'}

        builder = AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockMappingManager(),
        )
        entry = {
            'originAffectedEntry': {'sourceId': _SRC_36},
            'aliasExtraction': {'aliases': [_ALIAS_36]},
        }
        builder.add_cve_aliases('CVE-2024-3600', [entry], nvd_cpe_set=set())
        reports = builder.finalize()

        org_metadata = list(reports.values())[0]['metadata']
        self.assert_true(
            "confirmed_cna_id key present in metadata",
            'confirmed_cna_id' in org_metadata
        )
        self.assert_equals(
            "confirmed_cna_id is None when no file loaded",
            None,
            org_metadata['confirmed_cna_id']
        )

    # ==================================================================
    # GROUP 5: subprocess EXECUTE (four-phase), calculate_alias_statistics,
    #          validate_report_statistics
    # ==================================================================

    def test_25_full_pipeline_subprocess_execute(self):
        """Test 25: Four-phase — inject fixtures → subprocess generate_alias_report → validate run output → teardown input."""
        import subprocess
        print("\nTest 25: Full pipeline subprocess EXECUTE (four-phase pattern)")

        # PHASE 1 — SETUP: inject two CVE fixtures into the flat subprocess test cache
        self.setup_subprocess_test_cache([TEST_CVE_1337_0025, TEST_CVE_1337_0026], batch='0xxx')

        try:
            # PHASE 2 — EXECUTE: run the report generator as a real subprocess
            result = subprocess.run(
                ['python', '-m', 'src.analysis_tool.reporting.generate_alias_report',
                 '--custom-cache', TEST_SUBPROCESS_CACHE_NAME],
                cwd=str(project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120,
            )

            self.assert_equals("subprocess exit code 0", 0, result.returncode)
            if result.returncode != 0:
                print(f"  stderr: {result.stderr[:500]}")

            # PHASE 3 — VALIDATE: locate run ID in stdout, then check output artifacts
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in subprocess stdout", run_id is not None)

            if run_id:
                run_dir = project_root / "runs" / run_id
                self.assert_true("Run directory created on disk", run_dir.exists())

                logs_dir = run_dir / "logs"
                index_file = logs_dir / "aliasExtractionReport_index.json"
                self.assert_true("JSON index file produced in logs/", index_file.exists())

                if index_file.exists():
                    with open(index_file, 'r', encoding='utf-8') as f:
                        index_data = json.load(f)

                    self.assert_true("index has 'sources' key", 'sources' in index_data)
                    self.assert_true(
                        "index has at least one source",
                        len(index_data.get('sources', [])) >= 1
                    )

                    source_names = [s.get('source_name', '') for s in index_data.get('sources', [])]
                    self.assert_true(
                        "test-source-pipeline-0001 appears in index sources",
                        'test-source-pipeline-0001' in source_names
                    )

                    # Validate per-source JSON report file
                    report_files = list(logs_dir.glob(
                        "aliasExtractionReport_test-source-pipeline-0001_*.json"
                    ))
                    self.assert_true("Per-source report file written to logs/", len(report_files) >= 1)

                    if report_files:
                        with open(report_files[0], 'r', encoding='utf-8') as f:
                            report_data = json.load(f)

                        self.assert_true("report has 'metadata' key", 'metadata' in report_data)
                        self.assert_true("report has 'aliasGroups' key", 'aliasGroups' in report_data)
                        self.assert_true(
                            "report has 'confirmedMappings' key", 'confirmedMappings' in report_data
                        )
                        self.assert_true(
                            "unique_aliases_extracted >= 1",
                            report_data.get('metadata', {}).get('unique_aliases_extracted', 0) >= 1
                        )
                        self.assert_true(
                            "total_cves_processed >= 1",
                            report_data.get('metadata', {}).get('total_cves_processed', 0) >= 1
                        )

        finally:
            # PHASE 4 — TEARDOWN: remove INPUT cache only; run output preserved for inspection
            self.teardown_subprocess_test_cache()

    def test_26_calculate_alias_statistics_pure_unconfirmed(self):
        """Test 26: calculate_alias_statistics() with pure unconfirmed input computes correct stats."""
        print("\nTest 26: calculate_alias_statistics() with pure unconfirmed data")
        report_data = {
            'aliasGroups': [
                {
                    'alias_group': 'product',
                    'aliases': [
                        {'vendor': 'vendor_a', 'product': 'product_x'},
                        {'vendor': 'vendor_b', 'product': 'product_y'},
                    ],
                }
            ],
            'confirmedMappings': []
        }
        stats = calculate_alias_statistics(report_data)
        self.assert_equals("total_unique_aliases is 2", 2, stats['total_unique_aliases'])
        self.assert_equals("confirmed_count is 0", 0, stats['confirmed_count'])
        self.assert_equals("confirmed_coverage_pct is 0.0", 0.0, stats['confirmed_coverage_pct'])
        self.assert_equals("unconfirmed_count is 2", 2, stats['unconfirmed_count'])
        self.assert_equals("unconfirmed_with_concerns_count is 0", 0,
                           stats['unconfirmed_with_concerns_count'])
        self.assert_equals("non_actionable_count is 0", 0, stats['non_actionable_count'])

    def test_26b_calculate_alias_statistics_with_non_actionable(self):
        """Test 26b: calculate_alias_statistics() excludes non-actionable aliases from coverage denominator."""
        print("\nTest 26b: calculate_alias_statistics() non-actionable excluded from denominator")
        # 1 confirmed, 1 actionable unconfirmed, 1 non-actionable (all-placeholder vendor+product)
        report_data = {
            'aliasGroups': [
                {
                    'alias_group': 'group',
                    'aliases': [
                        {'vendor': 'vendor_a', 'product': 'product_x'},   # actionable unconfirmed
                        {'vendor': 'n/a',      'product': 'n/a'},          # non-actionable
                    ],
                }
            ],
            'confirmedMappings': [
                {'aliases': [{'vendor': 'vendor_b', 'product': 'product_y'}]},  # confirmed
            ]
        }
        stats = calculate_alias_statistics(report_data)
        # total = 1 confirmed + 1 actionable unconfirmed + 1 non-actionable = 3
        self.assert_equals("total_unique_aliases is 3", 3, stats['total_unique_aliases'])
        self.assert_equals("confirmed_count is 1", 1, stats['confirmed_count'])
        # confirmed_coverage_pct = 1 / (1+1) = 50.0  (denominator excludes non-actionable)
        self.assert_equals("confirmed_coverage_pct is 50.0", 50.0, stats['confirmed_coverage_pct'])
        self.assert_equals("unconfirmed_count is 1", 1, stats['unconfirmed_count'])
        self.assert_equals("non_actionable_count is 1", 1, stats['non_actionable_count'])

    def test_26c_calculate_alias_statistics_all_confirmed_reaches_100(self):
        """Test 26c: 100% coverage reachable when all actionable aliases are confirmed."""
        print("\nTest 26c: calculate_alias_statistics() 100% coverage when all actionable confirmed")
        # 2 confirmed, 1 non-actionable — coverage should be 100%
        report_data = {
            'aliasGroups': [
                {
                    'alias_group': 'group',
                    'aliases': [
                        {'vendor': 'vendor_a', 'product': 'product_x'},
                        {'vendor': 'vendor_b', 'product': 'product_y'},
                        {'vendor': 'unspecified', 'product': 'unspecified'},  # non-actionable
                    ],
                }
            ],
            'confirmedMappings': [
                {'aliases': [
                    {'vendor': 'vendor_a', 'product': 'product_x'},
                    {'vendor': 'vendor_b', 'product': 'product_y'},
                ]},
            ]
        }
        stats = calculate_alias_statistics(report_data)
        self.assert_equals("total_unique_aliases is 3", 3, stats['total_unique_aliases'])
        self.assert_equals("confirmed_count is 2", 2, stats['confirmed_count'])
        self.assert_equals("unconfirmed_count is 0", 0, stats['unconfirmed_count'])
        self.assert_equals("non_actionable_count is 1", 1, stats['non_actionable_count'])
        self.assert_equals("confirmed_coverage_pct is 100.0", 100.0, stats['confirmed_coverage_pct'])

    def test_27_validate_report_statistics_aligned(self):
        """Test 27: validate_report_statistics() returns zero mismatches for consistent file pair."""
        print("\nTest 27: validate_report_statistics() — aligned index + report files")
        temp_dir = self.setup_report_output_dir()
        try:
            report_filename = 'aliasExtractionReport_TestOrg_test_sou.json'

            # Per-source report: 2 clean, unconfirmed aliases
            report_data = {
                'metadata': {
                    'source_id': 'test-source-validate-0001',
                    'source_name': 'TestOrg',
                    'unique_aliases_extracted': 2,
                    'alias_groups_confirmed': 0,
                    'total_cves_processed': 2,
                },
                'aliasGroups': [
                    {
                        'alias_group': 'product',
                        'aliases': [
                            {'vendor': 'vendor_a', 'product': 'product_x'},
                            {'vendor': 'vendor_b', 'product': 'product_y'},
                        ],
                        'topNvdCpeBaseStrings': []
                    }
                ],
                'confirmedMappings': []
            }
            with open(temp_dir / report_filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f)

            # Index: values that match what validate_report_statistics() will recalculate
            # (2 unconfirmed, 0 confirmed, 0 concerns, 0 non-actionable)
            index_data = {
                'metadata': {},
                'sources': [{
                    'source_name': 'TestOrg',
                    'report_file': report_filename,
                    'total_unique_aliases': 2,
                    'confirmed_count': 0,
                    'confirmed_coverage_pct': 0.0,
                    'confirmed_with_concerns_count': 0,
                    'unconfirmed_with_concerns_count': 0,
                    'non_actionable_count': 0,
                }]
            }
            index_file = temp_dir / 'aliasExtractionReport_index.json'
            with open(index_file, 'w', encoding='utf-8') as f:
                json.dump(index_data, f)

            result = validate_report_statistics(index_file, temp_dir)

            self.assert_equals("total_sources is 1", 1, result['total_sources'])
            self.assert_equals("aligned_sources is 1", 1, result['aligned_sources'])
            self.assert_equals("mismatched_sources is 0", 0, result['mismatched_sources'])
            self.assert_equals("mismatches list is empty", [], result['mismatches'])
        finally:
            self.teardown_report_output_dir()

    # ==================================================================
    # GROUP 6: per-year alias statistics (tests 28-33)
    # Four-phase pattern: SETUP → EXECUTE → VALIDATE → TEARDOWN
    # ==================================================================

    def test_28_by_year_cves_count_two_distinct_years(self):
        """Test 28: same alias on CVEs from two distinct years → cves and unique_aliases both equal 1 per year."""
        print("\nTest 28: by_year cves count across two distinct years")

        # SETUP
        builder = AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockMappingManager(),
        )
        entry_2024 = {
            'originAffectedEntry': {'sourceId': _SRC_28},
            'aliasExtraction': {'aliases': [_ALIAS_28_A]},
        }
        entry_2025 = {
            'originAffectedEntry': {'sourceId': _SRC_28},
            'aliasExtraction': {'aliases': [_ALIAS_28_A]},
        }
        builder.add_cve_aliases('CVE-2024-2801', [entry_2024], nvd_cpe_set=set())
        builder.add_cve_aliases('CVE-2025-2801', [entry_2025], nvd_cpe_set=set())

        # EXECUTE
        reports = builder.finalize()
        by_year = reports[_SRC_28]['metadata']['by_year']

        # VALIDATE
        self.assert_true("by_year has '2024' key", '2024' in by_year)
        self.assert_true("by_year has '2025' key", '2025' in by_year)
        self.assert_equals("exactly 2 year keys", 2, len(by_year))
        self.assert_equals("2024 cves == 1", 1, by_year['2024']['cves'])
        self.assert_equals("2024 unique_aliases == 1", 1, by_year['2024']['unique_aliases'])
        self.assert_equals("2024 unconfirmed_count == 1", 1, by_year['2024']['unconfirmed_count'])
        self.assert_equals("2025 cves == 1", 1, by_year['2025']['cves'])
        self.assert_equals("2025 unique_aliases == 1", 1, by_year['2025']['unique_aliases'])
        self.assert_equals("2025 unconfirmed_count == 1", 1, by_year['2025']['unconfirmed_count'])

        # TEARDOWN
        builder = None

    def test_29_by_year_unique_aliases_alias_spanning_years(self):
        """Test 29: alias spanning two years + exclusive alias in later year → unique_aliases diverge correctly."""
        print("\nTest 29: by_year unique_aliases — alias spanning years plus year-exclusive alias")

        # SETUP
        builder = AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockMappingManager(),
        )
        entry_a_2024 = {
            'originAffectedEntry': {'sourceId': _SRC_29},
            'aliasExtraction': {'aliases': [_ALIAS_29_A]},
        }
        entry_a_2025 = {
            'originAffectedEntry': {'sourceId': _SRC_29},
            'aliasExtraction': {'aliases': [_ALIAS_29_A]},
        }
        entry_b_2025 = {
            'originAffectedEntry': {'sourceId': _SRC_29},
            'aliasExtraction': {'aliases': [_ALIAS_29_B]},
        }
        builder.add_cve_aliases('CVE-2024-2901', [entry_a_2024], nvd_cpe_set=set())
        builder.add_cve_aliases('CVE-2025-2901', [entry_a_2025], nvd_cpe_set=set())
        builder.add_cve_aliases('CVE-2025-2902', [entry_b_2025], nvd_cpe_set=set())

        # EXECUTE
        reports = builder.finalize()
        by_year = reports[_SRC_29]['metadata']['by_year']

        # VALIDATE
        self.assert_equals("2024 cves == 1", 1, by_year['2024']['cves'])
        self.assert_equals("2025 cves == 2", 2, by_year['2025']['cves'])
        self.assert_equals("2024 unique_aliases == 1 (alias_a only)", 1, by_year['2024']['unique_aliases'])
        self.assert_equals("2025 unique_aliases == 2 (alias_a + alias_b)", 2, by_year['2025']['unique_aliases'])
        self.assert_equals("2024 unconfirmed_count == 1", 1, by_year['2024']['unconfirmed_count'])
        self.assert_equals("2025 unconfirmed_count == 2", 2, by_year['2025']['unconfirmed_count'])
        self.assert_equals("2024 confirmed_count == 0", 0, by_year['2024']['confirmed_count'])
        self.assert_equals("2025 confirmed_count == 0", 0, by_year['2025']['confirmed_count'])

        # TEARDOWN
        builder = None

    def test_30_by_year_confirmed_count_per_year(self):
        """Test 30: confirmed alias tracked per year — coverage pct reflects per-year alias mix."""
        print("\nTest 30: by_year confirmed_count and confirmed_coverage_pct per year")

        # SETUP: alias_a confirmed (appears 2024+2025), alias_b unconfirmed (2024 only)
        builder = AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockConfirmedMappingManager(
                source_id=_SRC_30,
                confirmed_aliases=[_ALIAS_30_A],
            ),
        )
        entry_a_2024 = {
            'originAffectedEntry': {'sourceId': _SRC_30},
            'aliasExtraction': {'aliases': [_ALIAS_30_A]},
        }
        entry_b_2024 = {
            'originAffectedEntry': {'sourceId': _SRC_30},
            'aliasExtraction': {'aliases': [_ALIAS_30_B]},
        }
        entry_a_2025 = {
            'originAffectedEntry': {'sourceId': _SRC_30},
            'aliasExtraction': {'aliases': [_ALIAS_30_A]},
        }
        builder.add_cve_aliases('CVE-2024-3001', [entry_a_2024], nvd_cpe_set=set())
        builder.add_cve_aliases('CVE-2024-3002', [entry_b_2024], nvd_cpe_set=set())
        builder.add_cve_aliases('CVE-2025-3001', [entry_a_2025], nvd_cpe_set=set())

        # EXECUTE
        reports = builder.finalize()
        by_year = reports[_SRC_30]['metadata']['by_year']

        # VALIDATE
        self.assert_true("by_year has '2024'", '2024' in by_year)
        self.assert_true("by_year has '2025'", '2025' in by_year)
        self.assert_equals("2024 cves == 2", 2, by_year['2024']['cves'])
        self.assert_equals("2024 unique_aliases == 2", 2, by_year['2024']['unique_aliases'])
        self.assert_equals("2024 confirmed_count == 1 (alias_a)", 1, by_year['2024']['confirmed_count'])
        self.assert_equals("2024 confirmed_coverage_pct == 50.0", 50.0, by_year['2024']['confirmed_coverage_pct'])
        self.assert_equals("2024 unconfirmed_count == 1 (alias_b)", 1, by_year['2024']['unconfirmed_count'])
        self.assert_equals("2025 cves == 1", 1, by_year['2025']['cves'])
        self.assert_equals("2025 unique_aliases == 1 (alias_a only)", 1, by_year['2025']['unique_aliases'])
        self.assert_equals("2025 confirmed_count == 1", 1, by_year['2025']['confirmed_count'])
        self.assert_equals("2025 confirmed_coverage_pct == 100.0", 100.0, by_year['2025']['confirmed_coverage_pct'])
        self.assert_equals("2025 unconfirmed_count == 0", 0, by_year['2025']['unconfirmed_count'])

        # TEARDOWN
        builder = None

    def test_31_by_year_concern_flags_per_year(self):
        """Test 31: SDC concern flag tracked per year — concern in 2024, clean in 2025."""
        print("\nTest 31: by_year unconfirmed_with_concerns scoped to correct year")

        # SETUP: alias_with_concerns on 2024 CVE, clean alias on 2025 CVE
        builder = AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockMappingManager(),
        )
        entry_concerns_2024 = {
            'originAffectedEntry': {'sourceId': _SRC_31},
            'aliasExtraction': {'aliases': [_ALIAS_31_CONCERNS]},
            'sourceDataConcerns': _SDC_CONCERNS_FOR_31,
        }
        entry_clean_2025 = {
            'originAffectedEntry': {'sourceId': _SRC_31},
            'aliasExtraction': {'aliases': [_ALIAS_31_CLEAN]},
        }
        builder.add_cve_aliases('CVE-2024-3101', [entry_concerns_2024], nvd_cpe_set=set())
        builder.add_cve_aliases('CVE-2025-3101', [entry_clean_2025], nvd_cpe_set=set())

        # EXECUTE
        reports = builder.finalize()
        by_year = reports[_SRC_31]['metadata']['by_year']

        # VALIDATE
        self.assert_equals("2024 unconfirmed_count == 1", 1, by_year['2024']['unconfirmed_count'])
        self.assert_equals("2024 unconfirmed_with_concerns_count == 1",
                           1, by_year['2024']['unconfirmed_with_concerns_count'])
        self.assert_equals("2024 unconfirmed_with_concerns_pct == 100.0",
                           100.0, by_year['2024']['unconfirmed_with_concerns_pct'])
        self.assert_equals("2025 unconfirmed_count == 1", 1, by_year['2025']['unconfirmed_count'])
        self.assert_equals("2025 unconfirmed_with_concerns_count == 0",
                           0, by_year['2025']['unconfirmed_with_concerns_count'])
        self.assert_equals("2025 unconfirmed_with_concerns_pct == 0.0",
                           0.0, by_year['2025']['unconfirmed_with_concerns_pct'])
        self.assert_equals("2024 confirmed_with_concerns_count == 0",
                           0, by_year['2024']['confirmed_with_concerns_count'])
        self.assert_equals("2025 confirmed_with_concerns_count == 0",
                           0, by_year['2025']['confirmed_with_concerns_count'])

        # TEARDOWN
        builder = None

    def test_32_by_year_comprehensive_stats_three_years(self):
        """Test 32: comprehensive by_year stats — confirmed+concerns, unconfirmed, unconfirmed+concerns across 3 years."""
        print("\nTest 32: by_year comprehensive stats across 2023, 2024, and 2025")

        # SETUP: alias_a (confirmed, has concerns) on 2023+2024;
        #        alias_b (unconfirmed, no concerns)  on 2023 only;
        #        alias_c (unconfirmed, has concerns) on 2024+2025.
        builder = AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockConfirmedMappingManager(
                source_id=_SRC_32,
                confirmed_aliases=[_ALIAS_32_A],
            ),
        )
        entry_a_2023 = {
            'originAffectedEntry': {'sourceId': _SRC_32},
            'aliasExtraction': {'aliases': [_ALIAS_32_A]},
            'sourceDataConcerns': _SDC_CONCERNS_FOR_32_A,
        }
        entry_b_2023 = {
            'originAffectedEntry': {'sourceId': _SRC_32},
            'aliasExtraction': {'aliases': [_ALIAS_32_B]},
        }
        entry_a_2024 = {
            'originAffectedEntry': {'sourceId': _SRC_32},
            'aliasExtraction': {'aliases': [_ALIAS_32_A]},
            'sourceDataConcerns': _SDC_CONCERNS_FOR_32_A,
        }
        entry_c_2024 = {
            'originAffectedEntry': {'sourceId': _SRC_32},
            'aliasExtraction': {'aliases': [_ALIAS_32_C]},
            'sourceDataConcerns': _SDC_CONCERNS_FOR_32_C,
        }
        entry_c_2025 = {
            'originAffectedEntry': {'sourceId': _SRC_32},
            'aliasExtraction': {'aliases': [_ALIAS_32_C]},
            'sourceDataConcerns': _SDC_CONCERNS_FOR_32_C,
        }
        builder.add_cve_aliases('CVE-2023-3201', [entry_a_2023, entry_b_2023], nvd_cpe_set=set())
        builder.add_cve_aliases('CVE-2024-3201', [entry_a_2024, entry_c_2024], nvd_cpe_set=set())
        builder.add_cve_aliases('CVE-2025-3201', [entry_c_2025], nvd_cpe_set=set())

        # EXECUTE
        reports = builder.finalize()
        by_year = reports[_SRC_32]['metadata']['by_year']

        # VALIDATE — 2023: alias_a (confirmed+concerns) + alias_b (unconfirmed, clean)
        self.assert_equals("2023 cves == 1", 1, by_year['2023']['cves'])
        self.assert_equals("2023 unique_aliases == 2", 2, by_year['2023']['unique_aliases'])
        self.assert_equals("2023 confirmed_count == 1", 1, by_year['2023']['confirmed_count'])
        self.assert_equals("2023 confirmed_coverage_pct == 50.0", 50.0, by_year['2023']['confirmed_coverage_pct'])
        self.assert_equals("2023 confirmed_with_concerns_count == 1",
                           1, by_year['2023']['confirmed_with_concerns_count'])
        self.assert_equals("2023 confirmed_with_concerns_pct == 100.0",
                           100.0, by_year['2023']['confirmed_with_concerns_pct'])
        self.assert_equals("2023 unconfirmed_count == 1", 1, by_year['2023']['unconfirmed_count'])

        # VALIDATE — 2024: alias_a (confirmed+concerns) + alias_c (unconfirmed+concerns)
        self.assert_equals("2024 cves == 1", 1, by_year['2024']['cves'])
        self.assert_equals("2024 unique_aliases == 2", 2, by_year['2024']['unique_aliases'])
        self.assert_equals("2024 confirmed_count == 1", 1, by_year['2024']['confirmed_count'])
        self.assert_equals("2024 confirmed_coverage_pct == 50.0", 50.0, by_year['2024']['confirmed_coverage_pct'])
        self.assert_equals("2024 confirmed_with_concerns_count == 1",
                           1, by_year['2024']['confirmed_with_concerns_count'])
        self.assert_equals("2024 confirmed_with_concerns_pct == 100.0",
                           100.0, by_year['2024']['confirmed_with_concerns_pct'])
        self.assert_equals("2024 unconfirmed_count == 1", 1, by_year['2024']['unconfirmed_count'])
        self.assert_equals("2024 unconfirmed_with_concerns_count == 1",
                           1, by_year['2024']['unconfirmed_with_concerns_count'])
        self.assert_equals("2024 unconfirmed_with_concerns_pct == 100.0",
                           100.0, by_year['2024']['unconfirmed_with_concerns_pct'])

        # VALIDATE — 2025: alias_c only (unconfirmed+concerns)
        self.assert_equals("2025 cves == 1", 1, by_year['2025']['cves'])
        self.assert_equals("2025 unique_aliases == 1", 1, by_year['2025']['unique_aliases'])
        self.assert_equals("2025 confirmed_count == 0", 0, by_year['2025']['confirmed_count'])
        self.assert_equals("2025 unconfirmed_count == 1", 1, by_year['2025']['unconfirmed_count'])
        self.assert_equals("2025 unconfirmed_with_concerns_count == 1",
                           1, by_year['2025']['unconfirmed_with_concerns_count'])

        # TEARDOWN
        builder = None

    def test_33_four_phase_subprocess_by_year_in_json_output(self):
        """Test 33: Four-phase subprocess — CVEs from 2023+2025 → by_year has both years in index.json."""
        import subprocess
        print("\nTest 33: by_year in subprocess JSON index — two non-contiguous years (2023 and 2025)")

        # SETUP: inject CVEs from two non-contiguous years (no 2024 CVEs)
        self.setup_subprocess_test_cache(
            [TEST_CVE_2023_3301, TEST_CVE_2025_3301],
            batch='0xxx',
        )

        try:
            # EXECUTE: generate_alias_report as real subprocess
            result = subprocess.run(
                ['python', '-m', 'src.analysis_tool.reporting.generate_alias_report',
                 '--custom-cache', TEST_SUBPROCESS_CACHE_NAME],
                cwd=str(project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120,
            )

            self.assert_equals("subprocess exit code 0", 0, result.returncode)
            if result.returncode != 0:
                print(f"  stderr: {result.stderr[:500]}")

            # VALIDATE: locate run directory from stdout, then inspect index.json by_year
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in stdout", run_id is not None)

            if run_id:
                index_file = project_root / "runs" / run_id / "logs" / "aliasExtractionReport_index.json"
                self.assert_true("index.json exists", index_file.exists())

                if index_file.exists():
                    with open(index_file, 'r', encoding='utf-8') as f:
                        index_data = json.load(f)

                    # Locate the test pipeline source entry
                    src_entry = next(
                        (s for s in index_data.get('sources', [])
                         if s.get('source_name') == 'test-source-pipeline-0001'),
                        None,
                    )
                    self.assert_true("test-source-pipeline-0001 entry found in index", src_entry is not None)

                    if src_entry is not None:
                        by_year = src_entry.get('by_year', {})
                        self.assert_true("by_year has '2023' key", '2023' in by_year)
                        self.assert_true("by_year has '2025' key", '2025' in by_year)
                        self.assert_true("by_year does NOT have '2024' key", '2024' not in by_year)
                        self.assert_equals("2023 cves == 1", 1, by_year['2023']['cves'])
                        self.assert_equals("2025 cves == 1", 1, by_year['2025']['cves'])
                        self.assert_equals("2023 unique_aliases == 1", 1, by_year['2023']['unique_aliases'])
                        self.assert_equals("2025 unique_aliases == 1", 1, by_year['2025']['unique_aliases'])
                        required_keys = {
                            'cves', 'unique_aliases', 'confirmed_count', 'confirmed_coverage_pct',
                            'confirmed_with_concerns_count', 'confirmed_with_concerns_pct',
                            'unconfirmed_count', 'unconfirmed_with_concerns_count',
                            'unconfirmed_with_concerns_pct',
                        }
                        self.assert_true(
                            "2023 by_year entry has all required keys",
                            required_keys.issubset(by_year['2023'].keys()),
                        )
                        self.assert_true(
                            "2025 by_year entry has all required keys",
                            required_keys.issubset(by_year['2025'].keys()),
                        )

        finally:
            # TEARDOWN: remove injected cache; run output preserved for inspection
            self.teardown_subprocess_test_cache()

    # ==================================================================
    # Test runner
    # ==================================================================

    def run_all(self) -> bool:
        """Execute all tests in order and print results."""
        print("=" * 60)
        print("Test Suite: Alias Report Generation")
        print("=" * 60)

        self.test_01_empty_configurations_returns_empty_set()
        self.test_02_vulnerable_false_excluded()
        self.test_03_versioned_criteria_normalized_to_base()
        self.test_04_multiple_versions_same_product_deduplicated()
        self.test_05_short_criteria_skipped()
        self.test_06_mixed_vulnerable_flags()
        self.test_07_multiple_nodes_and_configs()
        self.test_08_extract_returns_three_tuple_on_success()
        self.test_09_malformed_json_returns_none_tuple()
        self.test_10_no_enriched_returns_empty_entries_with_cpe_set()
        self.test_11_no_configurations_returns_empty_cpe_set()
        self.test_12_single_cve_single_cpe()
        self.test_13_two_cves_same_alias_same_cpe_counts_two()
        self.test_14_top_5_cap_enforced()
        self.test_15_no_cpe_data_produces_empty_top_cpes()
        self.test_16_cpe_sorted_by_count_descending()
        self.test_17_template_has_groupCvesByYear()
        self.test_18_template_has_generateCveGroupsHtml()
        self.test_19_template_propagates_topNvdCpeBaseStrings_in_loadData()
        self.test_20_template_has_nvd_cpe_section_at_both_render_sites()
        self.test_21_template_conditional_hides_when_empty()
        self.test_22_non_wildcard_edition_preserved_in_base_string()
        self.test_23_file_io_preserves_non_wildcard_target_sw()
        self.test_24_criteria_over_13_components_rejected()
        self.test_24b_non_actionable_all_placeholders()
        self.test_24c_non_actionable_returns_false_for_actionable()
        self.test_24d_dedup_key_unchanged_for_non_actionable()
        self.test_25_full_pipeline_subprocess_execute()
        self.test_26_calculate_alias_statistics_pure_unconfirmed()
        self.test_26b_calculate_alias_statistics_with_non_actionable()
        self.test_26c_calculate_alias_statistics_all_confirmed_reaches_100()
        self.test_27_validate_report_statistics_aligned()
        self.test_28_by_year_cves_count_two_distinct_years()
        self.test_29_by_year_unique_aliases_alias_spanning_years()
        self.test_30_by_year_confirmed_count_per_year()
        self.test_31_by_year_concern_flags_per_year()
        self.test_32_by_year_comprehensive_stats_three_years()
        self.test_33_four_phase_subprocess_by_year_in_json_output()
        self.test_34_by_year_non_actionable_count()
        self.test_35_confirmed_cna_id_present_when_mapping_file_loaded()
        self.test_36_confirmed_cna_id_none_when_no_mapping_file()
        self.test_37_source_template_has_aliasRatio_element()
        self.test_38_source_template_has_updateFilterActiveSignal()
        self.test_39_source_template_filters_active_class_toggled()
        self.test_40_source_template_stat_card_order()
        self.test_41_source_template_has_alias_sets_per_cve_label()
        self.test_42_index_template_has_unique_alias_sets_column()
        self.test_43_index_template_has_unique_cves_column()
        self.test_44_source_template_has_aliasFieldSelections_element()
        self.test_45_source_template_has_renderAliasFieldCheckboxes()
        self.test_46_source_template_has_aliasEntryMap_variable()

        total = self.passed + self.failed
        print("\n" + "=" * 60)
        print(f"Results: {self.passed}/{total} passed")
        if self.failed:
            print("\nFailed tests:")
            for r in self.results:
                if r.startswith("FAIL"):
                    print(f"  {r}")
        print("=" * 60)
        print(f'TEST_RESULTS: PASSED={self.passed} TOTAL={total} SUITE="Alias Report Generation"')
        return self.failed == 0


if __name__ == "__main__":
    suite = TestAliasReportGeneration()
    success = suite.run_all()
    sys.exit(0 if success else 1)
