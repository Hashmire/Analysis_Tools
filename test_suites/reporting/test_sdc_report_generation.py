#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Suite: SDC Report Generation — by_year Feature

Validates that SDCReportBuilder correctly accumulates per-year statistics used
by the CVE-YYYY filter on the SDC Index dashboard.

Tests target:
    - Year extraction from CVE IDs during add_cve() accumulation
    - by_year bucket accuracy: cves, total_entries, entries_with_concerns
    - Multi-CVE accumulation within a single year bucket
    - Cross-year partitioning into separate year buckets
    - CVE count idempotency guard (is_new_cve) within by_year
    - Per-source isolation of by_year tracking
    - Derivability of entries_without_concerns from stored data
    - Year-filter aggregation consistency across sources
    - Integration pipeline: scan_nvd_ish_cache + builder produces correct by_year

Usage:
    python test_suites/reporting/test_sdc_report_generation.py
"""

import json
import subprocess
import sys
import shutil
from pathlib import Path
from typing import Dict, List, Any

# Force UTF-8 output encoding for Windows compatibility
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from src.analysis_tool.reporting.generate_sdc_report import (
    SDCReportBuilder,
    scan_nvd_ish_cache,
    extract_sdc_from_record,
)

# ---------------------------------------------------------------------------
# Cache path constants (temp_test_caches convention used across all test suites)
# ---------------------------------------------------------------------------
CACHE_DIR = project_root / "cache"
# NVD-ish JSON records injected here as test input (isolated from production nvd-ish_2.0_cves/)
TEST_NVD_ISH_INPUT_DIR = CACHE_DIR / "temp_test_caches" / "sdc_report_nvdish_input"
# Subprocess integration test uses a flat name: --custom-cache rejects paths containing / or \
TEST_SUBPROCESS_CACHE_NAME = "sdc_report_test_nvdish_input"
TEST_SUBPROCESS_CACHE_DIR = CACHE_DIR / TEST_SUBPROCESS_CACHE_NAME

# ---------------------------------------------------------------------------
# Shared unit-test data constants
# ---------------------------------------------------------------------------
SOURCE_A = 'test-source-sdc-aaaa'
SOURCE_B = 'test-source-sdc-bbbb'

# Pipeline integration test source (subprocess, test_20)
PIPELINE_SOURCE_ID = 'test-source-sdc-pipeline-0001'

# ---------------------------------------------------------------------------
# Pipeline integration test fixtures (test_20)
# Use CVE-1337-XXXX IDs following the temp_test_caches convention used across
# all test suites.  Year extracted from the CVE ID will be '1337'.
# ---------------------------------------------------------------------------

# CVE-1337-0051: 1 concern entry + 1 clean entry for PIPELINE_SOURCE_ID
TEST_CVE_1337_SDC_A: Dict = {
    'id': 'CVE-1337-0051',
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [
            {
                'originAffectedEntry': {
                    'sourceId': PIPELINE_SOURCE_ID,
                    'vendor': 'PipeVendor',
                    'product': 'PipeProductA',
                },
                'sourceDataConcerns': {
                    'concerns': {
                        'Placeholder Detection': [
                            {'field': 'vendor', 'sourceValue': 'n/a', 'detectedValue': 'n/a'}
                        ]
                    }
                },
            },
            {
                'originAffectedEntry': {
                    'sourceId': PIPELINE_SOURCE_ID,
                    'vendor': 'PipeVendor',
                    'product': 'PipeProductB',
                },
                'sourceDataConcerns': {},  # clean entry
            },
        ]
    },
}

# CVE-1337-0052: 1 concern entry for PIPELINE_SOURCE_ID
TEST_CVE_1337_SDC_B: Dict = {
    'id': 'CVE-1337-0052',
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [
            {
                'originAffectedEntry': {
                    'sourceId': PIPELINE_SOURCE_ID,
                    'vendor': 'PipeVendor',
                    'product': 'PipeProductC',
                },
                'sourceDataConcerns': {
                    'concerns': {
                        'Placeholder Detection': [
                            {'field': 'product', 'sourceValue': 'n/a', 'detectedValue': 'n/a'}
                        ]
                    }
                },
            },
        ]
    },
}


def _concern_entry(source_id: str = SOURCE_A) -> Dict:
    """Minimal NVD-ish affected entry that carries one SDC concern."""
    return {
        'originAffectedEntry': {
            'sourceId': source_id,
            'vendor': 'ExampleVendor',
            'product': 'ExampleProduct',
        },
        'sourceDataConcerns': {
            'concerns': {
                'Placeholder Detection': [
                    {'field': 'vendor', 'sourceValue': 'n/a', 'detectedValue': 'n/a'}
                ]
            }
        },
    }


def _clean_entry(source_id: str = SOURCE_A) -> Dict:
    """Minimal NVD-ish affected entry with no SDC concerns."""
    return {
        'originAffectedEntry': {
            'sourceId': source_id,
            'vendor': 'CleanVendor',
            'product': 'CleanProduct',
        },
        'sourceDataConcerns': {},
    }


def _nvd_ish_record(cve_id: str, entries: List[Dict]) -> Dict:
    """Wrap entries into a minimal NVD-ish record for file-based tests."""
    return {
        'id': cve_id,
        'enrichedCVEv5Affected': {
            'cveListV5AffectedEntries': entries,
        },
    }


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestSDCReportByYear:
    """Test suite covering by_year accumulation in SDCReportBuilder."""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results: List[str] = []
        self._index_template_content: str = None  # lazy-loaded

    # ── Assertion helpers ───────────────────────────────────────────────────

    def assert_equals(self, test_name: str, expected: Any, actual: Any, context: str = '') -> bool:
        if expected == actual:
            self.passed += 1
            self.results.append(f'PASS: {test_name}')
            print(f'  PASS {test_name}')
            return True
        self.failed += 1
        msg = f'FAIL: {test_name}\n    Expected: {expected!r}\n    Actual:   {actual!r}'
        if context:
            msg += f'\n    Context: {context}'
        self.results.append(msg)
        print(f'  FAIL {test_name}')
        print(f'    Expected: {expected!r}')
        print(f'    Actual:   {actual!r}')
        if context:
            print(f'    Context: {context}')
        return False

    def assert_true(self, test_name: str, condition: bool, context: str = '') -> bool:
        return self.assert_equals(test_name, True, condition, context)

    def assert_structure(self, test_name: str, data: Dict, required_keys: List[str], context: str = '') -> bool:
        missing = [k for k in required_keys if k not in data]
        if not missing:
            self.passed += 1
            self.results.append(f'PASS: {test_name}')
            print(f'  PASS {test_name}')
            return True
        self.failed += 1
        msg = f'FAIL: {test_name}\n    Missing keys: {missing}'
        if context:
            msg += f'\n    Context: {context}'
        self.results.append(msg)
        print(f'  FAIL {test_name}')
        print(f'    Missing keys: {missing}')
        return False

    def assert_in(self, test_name: str, item: Any, container: Any, context: str = '') -> bool:
        if item in container:
            self.passed += 1
            self.results.append(f'PASS: {test_name}')
            print(f'  PASS {test_name}')
            return True
        self.failed += 1
        msg = f'FAIL: {test_name}\n    {item!r} not found in container'
        if context:
            msg += f'\n    Context: {context}'
        self.results.append(msg)
        print(f'  FAIL {test_name}')
        print(f'    {item!r} not found in container')
        if context:
            print(f'    Context: {context}')
        return False

    # ── Helper: fetch year bucket or empty dict ──────────────────────────────

    @staticmethod
    def _year_stats(builder: SDCReportBuilder, source_id: str, year: str) -> Dict:
        return dict(builder.sources[source_id]['by_year'].get(year, {}))

    # ── Setup / teardown helpers (temp_test_caches convention) ──────────────

    def setup_nvdish_test_cache(self, fixtures: List[Dict], batch: str = '0xxx') -> Path:
        """Write NVD-ish test fixture records into the isolated temp test cache.

        Mirrors the real nvd-ish_2.0_cves/ directory structure (year/batch/) under
        temp_test_caches so that scan_nvd_ish_cache() reads only controlled test data.
        Returns the root cache path to pass directly to scan_nvd_ish_cache().
        """
        target_dir = TEST_NVD_ISH_INPUT_DIR / '1337' / batch
        target_dir.mkdir(parents=True, exist_ok=True)
        for record in fixtures:
            file_path = target_dir / f"{record['id']}.json"
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(record, f)
        return TEST_NVD_ISH_INPUT_DIR

    def teardown_nvdish_test_cache(self) -> None:
        """Remove the entire NVD-ish test input cache directory (TEARDOWN for scan tests)."""
        if TEST_NVD_ISH_INPUT_DIR.exists():
            shutil.rmtree(TEST_NVD_ISH_INPUT_DIR)

    def setup_subprocess_test_cache(self, fixtures: List[Dict], batch: str = '0xxx') -> None:
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
            file_path = target_dir / f'{cve_id}.json'
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(record, f, indent=2, ensure_ascii=False)

    def teardown_subprocess_test_cache(self) -> None:
        """TEARDOWN: Remove flat subprocess INPUT cache only; run output preserved for inspection."""
        if TEST_SUBPROCESS_CACHE_DIR.exists():
            shutil.rmtree(TEST_SUBPROCESS_CACHE_DIR)

    # ── Template loading helper ──────────────────────────────────────────────

    def _load_index_template(self) -> str:
        """Load the SDC Source Index template for content validation tests."""
        if self._index_template_content is None:
            template_path = (
                project_root
                / 'src'
                / 'analysis_tool'
                / 'static'
                / 'templates'
                / 'SDC_Source_Index_Template.html'
            )
            with open(template_path, 'r', encoding='utf-8') as f:
                self._index_template_content = f.read()
        return self._index_template_content

    # ── Single-file injection helpers (mirrors alias test_08-11 pattern) ────────

    def _inject_nvdish_record(self, record: Dict, batch: str = '8xxx') -> Path:
        """Inject one NVD-ish record into the isolated test input cache at 1337/<batch>/.

        Returns the path to the written file for passing to extract_sdc_from_record().
        """
        target_dir = TEST_NVD_ISH_INPUT_DIR / '1337' / batch
        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = target_dir / f"{record['id']}.json"
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(record, f)
        return file_path

    def _inject_raw_file(self, filename: str, content: str, batch: str = '9xxx') -> Path:
        """Inject raw content (possibly invalid JSON) into the isolated test input cache.

        Used for error-path tests where the file must exist but be corrupt.
        """
        target_dir = TEST_NVD_ISH_INPUT_DIR / '1337' / batch
        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = target_dir / filename
        file_path.write_text(content, encoding='utf-8')
        return file_path

    def _remove_injected_file(self, file_path: Path) -> None:
        """Remove a single injected test file (TEARDOWN for single-file tests)."""
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception as e:
            print(f'  WARNING: Could not remove {file_path}: {e}')

    # ── Tests 1–4: Year extraction from CVE ID ───────────────────────────────

    def test_year_2024_extraction(self):
        """Test 1: CVE-2024-XXXX produces year bucket '2024'."""
        print('\nTest 1: Year extraction — CVE-2024-XXXX')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2024-00001', [_concern_entry(SOURCE_A)])
        self.assert_true(
            "CVE-2024 creates '2024' bucket",
            '2024' in builder.sources[SOURCE_A]['by_year'],
        )

    def test_year_2025_extraction(self):
        """Test 2: CVE-2025-XXXX produces year bucket '2025'."""
        print('\nTest 2: Year extraction — CVE-2025-XXXX')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2025-12345', [_concern_entry(SOURCE_A)])
        self.assert_true(
            "CVE-2025 creates '2025' bucket",
            '2025' in builder.sources[SOURCE_A]['by_year'],
        )

    def test_year_unknown_malformed_id(self):
        """Test 3: Malformed CVE ID (not starting with 'CVE-') falls back to 'Unknown'."""
        print('\nTest 3: Year extraction — malformed ID')
        builder = SDCReportBuilder()
        builder.add_cve('NOT-A-CVE-ID', [_concern_entry(SOURCE_A)])
        self.assert_true(
            "Malformed ID creates 'Unknown' bucket",
            'Unknown' in builder.sources[SOURCE_A]['by_year'],
        )
        self.assert_equals(
            "No spurious year key from malformed ID",
            False,
            any(k not in ('Unknown',) for k in builder.sources[SOURCE_A]['by_year']),
        )

    def test_year_unknown_short_id(self):
        """Test 4: Short CVE ID with only 2 segments ('CVE-2024') falls back to 'Unknown'."""
        print('\nTest 4: Year extraction — short ID (two segments only)')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2024', [_concern_entry(SOURCE_A)])
        self.assert_true(
            "Short ID 'CVE-2024' creates 'Unknown' bucket",
            'Unknown' in builder.sources[SOURCE_A]['by_year'],
        )

    # ── Tests 5–8: Single CVE by_year bucket values ──────────────────────────

    def test_single_cve_concern_only(self):
        """Test 5: Single CVE with 3 concern entries — cves=1, total=3, with_concerns=3."""
        print('\nTest 5: Single CVE — concern entries only')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2024-00010', [
            _concern_entry(SOURCE_A),
            _concern_entry(SOURCE_A),
            _concern_entry(SOURCE_A),
        ])
        y = self._year_stats(builder, SOURCE_A, '2024')
        self.assert_equals('cves == 1',               1, y.get('cves'))
        self.assert_equals('total_entries == 3',       3, y.get('total_entries'))
        self.assert_equals('entries_with_concerns == 3', 3, y.get('entries_with_concerns'))

    def test_single_cve_clean_only(self):
        """Test 6: Single CVE with 4 clean entries — cves=1, total=4, with_concerns=0."""
        print('\nTest 6: Single CVE — clean entries only')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2024-00020', [
            _clean_entry(SOURCE_A),
            _clean_entry(SOURCE_A),
            _clean_entry(SOURCE_A),
            _clean_entry(SOURCE_A),
        ])
        y = self._year_stats(builder, SOURCE_A, '2024')
        self.assert_equals('cves == 1',               1, y.get('cves'))
        self.assert_equals('total_entries == 4',       4, y.get('total_entries'))
        self.assert_equals('entries_with_concerns == 0', 0, y.get('entries_with_concerns'))

    def test_single_cve_mixed_entries(self):
        """Test 7: Single CVE with 2 concern + 3 clean — total=5, with_concerns=2."""
        print('\nTest 7: Single CVE — mixed concern + clean entries')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2024-00030', [
            _concern_entry(SOURCE_A),
            _concern_entry(SOURCE_A),
            _clean_entry(SOURCE_A),
            _clean_entry(SOURCE_A),
            _clean_entry(SOURCE_A),
        ])
        y = self._year_stats(builder, SOURCE_A, '2024')
        self.assert_equals('cves == 1',               1, y.get('cves'))
        self.assert_equals('total_entries == 5',       5, y.get('total_entries'))
        self.assert_equals('entries_with_concerns == 2', 2, y.get('entries_with_concerns'))

    def test_without_concerns_derivable(self):
        """Test 8: entries_without_concerns derivable as total_entries − entries_with_concerns."""
        print('\nTest 8: Derive entries_without_concerns')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2024-00040', [
            _concern_entry(SOURCE_A),
            _concern_entry(SOURCE_A),
            _clean_entry(SOURCE_A),
            _clean_entry(SOURCE_A),
            _clean_entry(SOURCE_A),
        ])
        y = self._year_stats(builder, SOURCE_A, '2024')
        derived_without = y.get('total_entries', 0) - y.get('entries_with_concerns', 0)
        self.assert_equals(
            'derived entries_without_concerns == 3',
            3,
            derived_without,
        )

    # ── Tests 9–11: Multi-CVE accumulation ───────────────────────────────────

    def test_multi_cve_same_year_accumulates(self):
        """Test 9: Two CVEs in the same year — cves=2, totals aggregate correctly."""
        print('\nTest 9: Multi-CVE — same year')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2024-00050', [_concern_entry(SOURCE_A), _concern_entry(SOURCE_A)])
        builder.add_cve('CVE-2024-00051', [_concern_entry(SOURCE_A), _clean_entry(SOURCE_A)])
        y = self._year_stats(builder, SOURCE_A, '2024')
        self.assert_equals('cves == 2',               2, y.get('cves'))
        self.assert_equals('total_entries == 4',       4, y.get('total_entries'))
        self.assert_equals('entries_with_concerns == 3', 3, y.get('entries_with_concerns'))

    def test_multi_cve_different_years_partition(self):
        """Test 10: CVEs from 2024 and 2025 land in separate year buckets."""
        print('\nTest 10: Multi-CVE — different year buckets')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2024-00060', [_concern_entry(SOURCE_A), _concern_entry(SOURCE_A)])
        builder.add_cve('CVE-2025-00060', [_concern_entry(SOURCE_A)])
        y2024 = self._year_stats(builder, SOURCE_A, '2024')
        y2025 = self._year_stats(builder, SOURCE_A, '2025')
        self.assert_equals('2024 cves == 1',           1, y2024.get('cves'))
        self.assert_equals('2024 total_entries == 2',  2, y2024.get('total_entries'))
        self.assert_equals('2025 cves == 1',           1, y2025.get('cves'))
        self.assert_equals('2025 total_entries == 1',  1, y2025.get('total_entries'))
        self.assert_equals('exactly 2 year keys',      2, len(builder.sources[SOURCE_A]['by_year']))

    def test_cve_count_not_double_counted(self):
        """Test 11: Calling add_cve twice with the same CVE ID — cves stays at 1."""
        print('\nTest 11: CVE count idempotency (is_new_cve guard)')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2024-00070', [_concern_entry(SOURCE_A)])
        builder.add_cve('CVE-2024-00070', [_concern_entry(SOURCE_A)])  # duplicate call
        y = self._year_stats(builder, SOURCE_A, '2024')
        self.assert_equals(
            'cves remains 1 despite duplicate add_cve call',
            1,
            y.get('cves'),
        )

    # ── Tests 12–13: Per-source isolation ─────────────────────────────────────

    def test_multi_source_independent_buckets(self):
        """Test 12: SOURCE_A and SOURCE_B each accumulate independent by_year buckets."""
        print('\nTest 12: Per-source isolation — independent by_year')
        builder = SDCReportBuilder()
        # 1 CVE with 1 entry for A and 2 entries for B
        builder.add_cve('CVE-2024-00080', [
            _concern_entry(SOURCE_A),
            _clean_entry(SOURCE_B),
            _clean_entry(SOURCE_B),
        ])
        ya = self._year_stats(builder, SOURCE_A, '2024')
        yb = self._year_stats(builder, SOURCE_B, '2024')
        # SOURCE_A: 1 concern entry
        self.assert_equals('SOURCE_A cves == 1',                 1, ya.get('cves'))
        self.assert_equals('SOURCE_A total_entries == 1',        1, ya.get('total_entries'))
        self.assert_equals('SOURCE_A entries_with_concerns == 1', 1, ya.get('entries_with_concerns'))
        # SOURCE_B: 2 clean entries
        self.assert_equals('SOURCE_B cves == 1',                 1, yb.get('cves'))
        self.assert_equals('SOURCE_B total_entries == 2',        2, yb.get('total_entries'))
        self.assert_equals('SOURCE_B entries_with_concerns == 0', 0, yb.get('entries_with_concerns'))

    def test_multi_source_no_cross_contamination(self):
        """Test 13: SOURCE_A by_year is unaffected when entries belonging to SOURCE_B are added."""
        print('\nTest 13: Per-source isolation — no cross-contamination')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2024-00090', [_concern_entry(SOURCE_A)])
        builder.add_cve('CVE-2025-00090', [_concern_entry(SOURCE_B)])
        # SOURCE_A should only have a 2024 bucket; no 2025 bucket
        self.assert_true(
            'SOURCE_A has 2024 bucket',
            '2024' in builder.sources[SOURCE_A]['by_year'],
        )
        self.assert_equals(
            'SOURCE_A has no 2025 bucket',
            False,
            '2025' in builder.sources[SOURCE_A]['by_year'],
        )
        # SOURCE_B should only have a 2025 bucket; no 2024 bucket
        self.assert_true(
            'SOURCE_B has 2025 bucket',
            '2025' in builder.sources[SOURCE_B]['by_year'],
        )
        self.assert_equals(
            'SOURCE_B has no 2024 bucket',
            False,
            '2024' in builder.sources[SOURCE_B]['by_year'],
        )

    # ── Tests 14–15: Year-filter aggregation consistency ─────────────────────

    def test_year_filter_aggregation_matches_source_totals(self):
        """Test 14: Summing all by_year cves for a source equals total_cves_processed."""
        print('\nTest 14: Year-filter aggregation — sum of by_year cves == total_cves_processed')
        builder = SDCReportBuilder()
        # 5 CVEs across 3 years
        builder.add_cve('CVE-2023-01000', [_concern_entry(SOURCE_A)])
        builder.add_cve('CVE-2024-01001', [_concern_entry(SOURCE_A)])
        builder.add_cve('CVE-2024-01002', [_concern_entry(SOURCE_A)])
        builder.add_cve('CVE-2025-01003', [_concern_entry(SOURCE_A)])
        builder.add_cve('CVE-2025-01004', [_concern_entry(SOURCE_A)])

        by_year = builder.sources[SOURCE_A]['by_year']
        sum_cves = sum(stats['cves'] for stats in by_year.values())
        total_cves = builder.sources[SOURCE_A]['metadata']['total_cves_processed']

        self.assert_equals(
            'sum of by_year cves == metadata total_cves_processed',
            total_cves,
            sum_cves,
        )

        # Also check that summing entries matches total_platform_entries
        sum_entries = sum(stats['total_entries'] for stats in by_year.values())
        total_entries = builder.sources[SOURCE_A]['metadata']['total_platform_entries']
        self.assert_equals(
            'sum of by_year total_entries == metadata total_platform_entries',
            total_entries,
            sum_entries,
        )

    def test_year_filter_zero_for_missing_year(self):
        """Test 15: Accessing a year not in by_year returns empty / zero stats."""
        print('\nTest 15: Year-filter — missing year returns zero stats')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2025-02000', [_concern_entry(SOURCE_A)])
        # SOURCE_A has no 2022 data
        y = self._year_stats(builder, SOURCE_A, '2022')
        self.assert_equals(
            'missing year returns empty dict (no key)',
            {},
            y,
            context='by_year.get("2022", {}) should be {}',
        )
        # Template simulation: ys.get('cves', 0) → 0 for missing year
        simulated_cves = y.get('cves', 0)
        self.assert_equals(
            'missing year simulated cves == 0',
            0,
            simulated_cves,
        )

    # ── Test 16: Integration pipeline ────────────────────────────────────────

    def test_integration_scan_and_builder_pipeline(self):
        """Test 16: scan_nvd_ish_cache + builder pipeline — by_year is correctly populated."""
        print('\nTest 16: Integration — scan_nvd_ish_cache + builder pipeline')
        record_2024 = _nvd_ish_record('CVE-2024-09990', [
            _concern_entry(SOURCE_A),
            _concern_entry(SOURCE_A),
            _clean_entry(SOURCE_A),
        ])
        record_2025 = _nvd_ish_record('CVE-2025-09991', [
            _concern_entry(SOURCE_A),
            _clean_entry(SOURCE_A),
            _clean_entry(SOURCE_A),
        ])
        cache_path = self.setup_nvdish_test_cache([record_2024, record_2025])
        try:
            # Scan and process
            json_files = scan_nvd_ish_cache(cache_path)
            self.assert_equals('scanned 2 files', 2, len(json_files))

            builder = SDCReportBuilder()
            for jf in json_files:
                cve_id, entries = extract_sdc_from_record(jf)
                if cve_id and entries:
                    builder.add_cve(cve_id, entries)

            # Verify by_year structure present and correct
            self.assert_true(
                'SOURCE_A exists in builder',
                SOURCE_A in builder.sources,
            )
            self.assert_structure(
                'by_year dict has 2024 and 2025 keys',
                builder.sources[SOURCE_A]['by_year'],
                ['2024', '2025'],
            )

            y2024 = self._year_stats(builder, SOURCE_A, '2024')
            self.assert_equals('2024 cves == 1',                 1, y2024.get('cves'))
            self.assert_equals('2024 total_entries == 3',         3, y2024.get('total_entries'))
            self.assert_equals('2024 entries_with_concerns == 2', 2, y2024.get('entries_with_concerns'))

            y2025 = self._year_stats(builder, SOURCE_A, '2025')
            self.assert_equals('2025 cves == 1',                 1, y2025.get('cves'))
            self.assert_equals('2025 total_entries == 3',         3, y2025.get('total_entries'))
            self.assert_equals('2025 entries_with_concerns == 1', 1, y2025.get('entries_with_concerns'))

            # Verify the serialization logic (mirrors index_data build in generate_report)
            serialized_by_year = {
                year: {
                    'cves': stats['cves'],
                    'total_entries': stats['total_entries'],
                    'entries_with_concerns': stats['entries_with_concerns'],
                }
                for year, stats in sorted(
                    builder.sources[SOURCE_A]['by_year'].items(),
                    key=lambda x: x[0],
                    reverse=True,
                )
            }
            year_keys = list(serialized_by_year.keys())
            self.assert_equals(
                'serialized by_year keys sorted descending',
                ['2025', '2024'],
                year_keys,
            )
            self.assert_structure(
                'each serialized year entry has required keys',
                serialized_by_year['2024'],
                ['cves', 'total_entries', 'entries_with_concerns'],
            )

        finally:
            self.teardown_nvdish_test_cache()

    # ==================================================================
    # GROUP 3: SDC Index template content validation
    # ==================================================================

    def test_17_template_has_IndexYearFilter(self):
        """Test 17: SDC Index template contains the IndexYearFilter object."""
        print('\nTest 17: Template has IndexYearFilter object')
        template = self._load_index_template()
        self.assert_in('IndexYearFilter object defined', 'IndexYearFilter', template)

    def test_18_template_has_toggleIndexYearPill(self):
        """Test 18: SDC Index template contains the toggleIndexYearPill function."""
        print('\nTest 18: Template has toggleIndexYearPill function')
        template = self._load_index_template()
        self.assert_in(
            'toggleIndexYearPill function defined',
            'function toggleIndexYearPill',
            template,
        )

    def test_19_template_has_applyIndexFilters(self):
        """Test 19: SDC Index template contains the applyIndexFilters function."""
        print('\nTest 19: Template has applyIndexFilters function')
        template = self._load_index_template()
        self.assert_in(
            'applyIndexFilters function defined',
            'function applyIndexFilters',
            template,
        )

    # ==================================================================
    # GROUP 4: subprocess EXECUTE (four-phase) — full pipeline validation
    # ==================================================================

    def test_20_full_pipeline_subprocess_execute(self):
        """Test 20: Four-phase — inject fixtures → subprocess generate_sdc_report → validate run output → teardown input.

        Fixture arithmetic (deterministic):
          CVE-1337-0051: 1 concern entry + 1 clean entry  → total_entries=2, entries_with_concerns=1
          CVE-1337-0052: 1 concern entry                  → total_entries=1, entries_with_concerns=1
          ─────────────────────────────────────────────────────────────────────────────────────────────
          Combined for PIPELINE_SOURCE_ID:
            total_cves_processed      = 2
            total_platform_entries    = 3
            entries_with_concerns     = 2
            entries_without_concerns  = 1
            concern_type_counts       = [{'concern_type': 'Placeholder Detection', 'count': 2}]
          by_year['1337']:
            cves                      = 2
            total_entries             = 3
            entries_with_concerns     = 2
        """
        print('\nTest 20: Full pipeline subprocess EXECUTE (four-phase pattern)')

        # PHASE 1 — SETUP: inject two CVE fixtures into the flat subprocess test cache.
        self.setup_subprocess_test_cache(
            [TEST_CVE_1337_SDC_A, TEST_CVE_1337_SDC_B], batch='0xxx'
        )

        try:
            # PHASE 2 — EXECUTE: run the report generator as a real subprocess
            result = subprocess.run(
                [
                    'python', '-m', 'src.analysis_tool.reporting.generate_sdc_report',
                    '--custom-cache', TEST_SUBPROCESS_CACHE_NAME,
                ],
                cwd=str(project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120,
            )

            self.assert_equals('subprocess exit code 0', 0, result.returncode)
            if result.returncode != 0:
                print(f'  stderr: {result.stderr[:500]}')

            # PHASE 3 — VALIDATE: locate run ID in stdout, then check output artifacts
            run_id = None
            for line in result.stdout.splitlines():
                if line.strip().startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true('Run ID present in subprocess stdout', run_id is not None)

            if run_id:
                run_dir = project_root / 'runs' / run_id
                self.assert_true('Run directory created on disk', run_dir.exists())

                logs_dir = run_dir / 'logs'
                self.assert_true('logs/ subdirectory exists', logs_dir.exists())

                index_file = logs_dir / 'sourceDataConcernReport_index.json'
                self.assert_true('JSON index file produced in logs/', index_file.exists())

                if index_file.exists():
                    with open(index_file, 'r', encoding='utf-8') as f:
                        index_data = json.load(f)

                    # ── Index metadata values ────────────────────────────────
                    meta = index_data.get('metadata', {})
                    self.assert_equals(
                        'index.metadata.total_cves_processed == 2',
                        2, meta.get('total_cves_processed'),
                    )
                    self.assert_equals(
                        'index.metadata.total_sources == 1',
                        1, meta.get('total_sources'),
                    )
                    self.assert_equals(
                        "index.metadata.status == 'completed'",
                        'completed', meta.get('status'),
                    )

                    # ── Exactly one source in the index ─────────────────────
                    sources = index_data.get('sources', [])
                    self.assert_equals(
                        'index has exactly 1 source entry',
                        1, len(sources),
                    )

                    # ── Locate the pipeline test source ─────────────────────
                    pipeline_source = next(
                        (s for s in sources if s.get('source_id') == PIPELINE_SOURCE_ID),
                        None,
                    )
                    self.assert_true(
                        f'pipeline source {PIPELINE_SOURCE_ID} present in index',
                        pipeline_source is not None,
                    )

                    if pipeline_source is not None:
                        # ── Per-source aggregate values in index entry ───────
                        self.assert_equals(
                            'index source total_cves_processed == 2',
                            2, pipeline_source.get('total_cves_processed'),
                        )
                        self.assert_equals(
                            'index source total_platform_entries == 3',
                            3, pipeline_source.get('total_platform_entries'),
                        )
                        self.assert_equals(
                            'index source entries_with_concerns == 2',
                            2, pipeline_source.get('entries_with_concerns'),
                        )
                        self.assert_equals(
                            'index source entries_without_concerns == 1',
                            1, pipeline_source.get('entries_without_concerns'),
                        )

                        # ── concern_type_counts in index entry ───────────────
                        ctc = pipeline_source.get('concern_type_counts', [])
                        self.assert_equals(
                            'index source concern_type_counts has 1 entry',
                            1, len(ctc),
                        )
                        if ctc:
                            self.assert_equals(
                                "concern_type is 'Placeholder Detection'",
                                'Placeholder Detection', ctc[0].get('concern_type'),
                            )
                            self.assert_equals(
                                'Placeholder Detection count == 2',
                                2, ctc[0].get('count'),
                            )

                        # ── by_year values ───────────────────────────────────
                        by_year = pipeline_source.get('by_year', {})
                        self.assert_equals(
                            "by_year has exactly 1 year key ('1337')",
                            ['1337'], list(by_year.keys()),
                        )

                        y = by_year.get('1337', {})
                        self.assert_equals(
                            'by_year[1337].cves == 2',
                            2, y.get('cves'),
                        )
                        self.assert_equals(
                            'by_year[1337].total_entries == 3',
                            3, y.get('total_entries'),
                        )
                        self.assert_equals(
                            'by_year[1337].entries_with_concerns == 2',
                            2, y.get('entries_with_concerns'),
                        )

                    # ── Per-source report file ───────────────────────────────
                    source_id_short = PIPELINE_SOURCE_ID[:8]
                    report_files = list(
                        logs_dir.glob(f'sourceDataConcernReport_*_{source_id_short}.json')
                    )
                    self.assert_equals(
                        'exactly 1 per-source report file written to logs/',
                        1, len(report_files),
                    )

                    if report_files:
                        with open(report_files[0], 'r', encoding='utf-8') as f:
                            report_data = json.load(f)

                        # ── Per-source report metadata values ────────────────
                        rmeta = report_data.get('metadata', {})
                        self.assert_equals(
                            'report metadata.source_id == PIPELINE_SOURCE_ID',
                            PIPELINE_SOURCE_ID, rmeta.get('source_id'),
                        )
                        self.assert_equals(
                            'report metadata.total_cves_processed == 2',
                            2, rmeta.get('total_cves_processed'),
                        )
                        self.assert_equals(
                            'report metadata.total_platform_entries == 3',
                            3, rmeta.get('total_platform_entries'),
                        )
                        self.assert_equals(
                            'report metadata.entries_with_concerns == 2',
                            2, rmeta.get('entries_with_concerns'),
                        )
                        rctc = rmeta.get('concern_type_counts', [])
                        self.assert_equals(
                            'report concern_type_counts has 1 entry',
                            1, len(rctc),
                        )
                        if rctc:
                            self.assert_equals(
                                "report concern_type is 'Placeholder Detection'",
                                'Placeholder Detection', rctc[0].get('concern_type'),
                            )
                            self.assert_equals(
                                'report Placeholder Detection count == 2',
                                2, rctc[0].get('count'),
                            )

                        # ── cve_data entries ─────────────────────────────────
                        cve_data = report_data.get('cve_data', [])
                        self.assert_equals(
                            'report cve_data has exactly 2 CVE entries',
                            2, len(cve_data),
                        )
                        cve_ids_in_report = {entry.get('cve_id') for entry in cve_data}
                        self.assert_equals(
                            'cve_data contains CVE-1337-0051',
                            True, 'CVE-1337-0051' in cve_ids_in_report,
                        )
                        self.assert_equals(
                            'cve_data contains CVE-1337-0052',
                            True, 'CVE-1337-0052' in cve_ids_in_report,
                        )

                        # ── Per-CVE concern content fidelity ─────────────────
                        # CVE-1337-0051 fixture: 1 concern entry (vendor=PipeVendor,
                        #   product=PipeProductA, Placeholder Detection on 'vendor' field)
                        #   + 1 clean entry (PipeProductB) → platform_entry_id=CVE-1337-0051_entry_0
                        cve_51 = next(
                            (c for c in cve_data if c.get('cve_id') == 'CVE-1337-0051'), None
                        )
                        self.assert_true(
                            'CVE-1337-0051 cve_data entry located', cve_51 is not None
                        )
                        if cve_51 is not None:
                            m51 = cve_51.get('cve_metadata', {})
                            self.assert_equals(
                                'CVE-1337-0051 cve_metadata.total_platform_entries == 2',
                                2, m51.get('total_platform_entries'),
                            )
                            self.assert_equals(
                                'CVE-1337-0051 cve_metadata.entries_with_concerns == 1',
                                1, m51.get('entries_with_concerns'),
                            )
                            ctc51 = m51.get('concern_type_counts', [])
                            self.assert_equals(
                                'CVE-1337-0051 cve concern_type_counts has 1 entry',
                                1, len(ctc51),
                            )
                            if ctc51:
                                self.assert_equals(
                                    "CVE-1337-0051 concern_type == 'Placeholder Detection'",
                                    'Placeholder Detection', ctc51[0].get('concern_type'),
                                )
                                self.assert_equals(
                                    'CVE-1337-0051 Placeholder Detection count == 1',
                                    1, ctc51[0].get('count'),
                                )

                            pe51 = cve_51.get('platform_entries', [])
                            self.assert_equals(
                                'CVE-1337-0051 has exactly 1 platform_entry (concern entries only)',
                                1, len(pe51),
                            )
                            if pe51:
                                e51 = pe51[0]
                                self.assert_equals(
                                    'CVE-1337-0051 platform_entry_id',
                                    'CVE-1337-0051_entry_0', e51.get('platform_entry_id'),
                                )
                                self.assert_equals(
                                    "CVE-1337-0051 entry vendor == 'PipeVendor'",
                                    'PipeVendor', e51.get('vendor'),
                                )
                                self.assert_equals(
                                    "CVE-1337-0051 entry product == 'PipeProductA'",
                                    'PipeProductA', e51.get('product'),
                                )
                                self.assert_equals(
                                    'CVE-1337-0051 entry total_concerns == 1',
                                    1, e51.get('total_concerns'),
                                )
                                self.assert_equals(
                                    "CVE-1337-0051 entry concern_types == ['Placeholder Detection']",
                                    ['Placeholder Detection'], e51.get('concern_types'),
                                )
                                self.assert_equals(
                                    'CVE-1337-0051 entry concern_breakdown',
                                    {'Placeholder Detection': 1}, e51.get('concern_breakdown'),
                                )
                                cd51 = e51.get('concerns_detail', [])
                                self.assert_equals(
                                    'CVE-1337-0051 concerns_detail has 1 entry',
                                    1, len(cd51),
                                )
                                if cd51:
                                    self.assert_equals(
                                        "CVE-1337-0051 concerns_detail[0].concern_type",
                                        'Placeholder Detection', cd51[0].get('concern_type'),
                                    )
                                    indiv51 = cd51[0].get('concerns', [])
                                    self.assert_equals(
                                        'CVE-1337-0051 individual concerns list has 1 item',
                                        1, len(indiv51),
                                    )
                                    if indiv51:
                                        self.assert_equals(
                                            "CVE-1337-0051 concern field == 'vendor'",
                                            'vendor', indiv51[0].get('field'),
                                        )
                                        self.assert_equals(
                                            "CVE-1337-0051 concern sourceValue == 'n/a'",
                                            'n/a', indiv51[0].get('sourceValue'),
                                        )

                            cpe51 = cve_51.get('clean_platform_entries', [])
                            self.assert_equals(
                                'CVE-1337-0051 has 1 clean_platform_entry',
                                1, len(cpe51),
                            )
                            if cpe51:
                                self.assert_equals(
                                    'CVE-1337-0051 clean entry cleanPlatformCount == 1',
                                    1, cpe51[0].get('cleanPlatformCount'),
                                )

                        # CVE-1337-0052 fixture: 1 concern entry (vendor=PipeVendor,
                        #   product=PipeProductC, Placeholder Detection on 'product' field)
                        #   + 0 clean entries
                        cve_52 = next(
                            (c for c in cve_data if c.get('cve_id') == 'CVE-1337-0052'), None
                        )
                        self.assert_true(
                            'CVE-1337-0052 cve_data entry located', cve_52 is not None
                        )
                        if cve_52 is not None:
                            m52 = cve_52.get('cve_metadata', {})
                            self.assert_equals(
                                'CVE-1337-0052 cve_metadata.total_platform_entries == 1',
                                1, m52.get('total_platform_entries'),
                            )
                            self.assert_equals(
                                'CVE-1337-0052 cve_metadata.entries_with_concerns == 1',
                                1, m52.get('entries_with_concerns'),
                            )

                            pe52 = cve_52.get('platform_entries', [])
                            self.assert_equals(
                                'CVE-1337-0052 has exactly 1 platform_entry',
                                1, len(pe52),
                            )
                            if pe52:
                                e52 = pe52[0]
                                self.assert_equals(
                                    "CVE-1337-0052 entry vendor == 'PipeVendor'",
                                    'PipeVendor', e52.get('vendor'),
                                )
                                self.assert_equals(
                                    "CVE-1337-0052 entry product == 'PipeProductC'",
                                    'PipeProductC', e52.get('product'),
                                )
                                self.assert_equals(
                                    'CVE-1337-0052 entry total_concerns == 1',
                                    1, e52.get('total_concerns'),
                                )
                                cd52 = e52.get('concerns_detail', [])
                                self.assert_equals(
                                    'CVE-1337-0052 concerns_detail has 1 entry',
                                    1, len(cd52),
                                )
                                if cd52:
                                    indiv52 = cd52[0].get('concerns', [])
                                    self.assert_equals(
                                        'CVE-1337-0052 individual concerns list has 1 item',
                                        1, len(indiv52),
                                    )
                                    if indiv52:
                                        self.assert_equals(
                                            "CVE-1337-0052 concern field == 'product'",
                                            'product', indiv52[0].get('field'),
                                        )
                                        self.assert_equals(
                                            "CVE-1337-0052 concern sourceValue == 'n/a'",
                                            'n/a', indiv52[0].get('sourceValue'),
                                        )

                            cpe52 = cve_52.get('clean_platform_entries', [])
                            self.assert_equals(
                                'CVE-1337-0052 has 0 clean_platform_entries',
                                0, len(cpe52),
                            )

        finally:
            # PHASE 4 — TEARDOWN: remove INPUT cache only; run output preserved for inspection
            self.teardown_subprocess_test_cache()

    # ==================================================================
    # GROUP 3: extract_sdc_from_record() isolation tests
    # ==================================================================

    def test_21_extract_sdc_happy_path_returns_cve_id_and_entries(self):
        """Test 21: extract_sdc_from_record returns (cve_id, entries) on a well-formed record."""
        print('\nTest 21: extract_sdc_from_record — happy path')
        record = {
            'id': 'CVE-1337-8021',
            'enrichedCVEv5Affected': {
                'cveListV5AffectedEntries': [
                    {
                        'originAffectedEntry': {
                            'sourceId': SOURCE_A,
                            'vendor': 'ExtractVendor',
                            'product': 'ExtractProduct',
                        },
                        'sourceDataConcerns': {
                            'concerns': {
                                'Placeholder Detection': [
                                    {'field': 'vendor', 'sourceValue': 'n/a', 'detectedValue': 'n/a'}
                                ]
                            }
                        },
                    },
                    {
                        'originAffectedEntry': {
                            'sourceId': SOURCE_A,
                            'vendor': 'CleanVendor',
                            'product': 'CleanProduct',
                        },
                        'sourceDataConcerns': {},
                    },
                ]
            },
        }
        file_path = self._inject_nvdish_record(record, batch='8xxx')
        try:
            cve_id, entries = extract_sdc_from_record(file_path)
            self.assert_equals('cve_id returned correctly', 'CVE-1337-8021', cve_id)
            self.assert_equals('2 entries returned', 2, len(entries))
            self.assert_equals(
                'first entry vendor field preserved',
                'ExtractVendor',
                entries[0].get('originAffectedEntry', {}).get('vendor'),
            )
        finally:
            self._remove_injected_file(file_path)

    def test_22_extract_sdc_missing_id_returns_none_tuple(self):
        """Test 22: extract_sdc_from_record returns (None, []) when the record has no 'id' field."""
        print('\nTest 22: extract_sdc_from_record — missing id')
        # Write file manually (no 'id' key → cannot use _inject_nvdish_record)
        record = {'enrichedCVEv5Affected': {'cveListV5AffectedEntries': [_concern_entry(SOURCE_A)]}}
        target_dir = TEST_NVD_ISH_INPUT_DIR / '1337' / '8xxx'
        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = target_dir / 'no-id-record-0022.json'
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(record, f)
        try:
            cve_id, entries = extract_sdc_from_record(file_path)
            self.assert_equals('cve_id is None when id field missing', None, cve_id)
            self.assert_equals('entries is [] when id field missing', [], entries)
        finally:
            self._remove_injected_file(file_path)

    def test_23_extract_sdc_missing_enriched_returns_empty_entries(self):
        """Test 23: extract_sdc_from_record returns (cve_id, []) when enrichedCVEv5Affected absent."""
        print('\nTest 23: extract_sdc_from_record — missing enrichedCVEv5Affected')
        record = {'id': 'CVE-1337-8023'}  # No enrichedCVEv5Affected key
        file_path = self._inject_nvdish_record(record, batch='8xxx')
        try:
            cve_id, entries = extract_sdc_from_record(file_path)
            self.assert_equals('cve_id returned when enriched absent', 'CVE-1337-8023', cve_id)
            self.assert_equals('entries is [] when enriched absent', [], entries)
        finally:
            self._remove_injected_file(file_path)

    def test_24_extract_sdc_malformed_json_returns_none_tuple(self):
        """Test 24: extract_sdc_from_record returns (None, []) on malformed JSON."""
        print('\nTest 24: extract_sdc_from_record — malformed JSON')
        file_path = self._inject_raw_file('CVE-1337-9bad.json', '{invalid json content here}', batch='9xxx')
        try:
            cve_id, entries = extract_sdc_from_record(file_path)
            self.assert_equals('cve_id is None on bad JSON', None, cve_id)
            self.assert_equals('entries is [] on bad JSON', [], entries)
        finally:
            self._remove_injected_file(file_path)

    # ==================================================================
    # GROUP 4: SDCReportBuilder.finalize() output schema
    # ==================================================================

    def test_25_finalize_metadata_schema_and_concern_aggregation(self):
        """Test 25: finalize() produces correct per-source metadata schema and concern aggregation.

        Fixture: 1 CVE with 1 concern entry (Placeholder Detection on vendor)
                 + 1 clean entry for SOURCE_A.
        Expected finalized metadata:
            source_id                = SOURCE_A
            source_name              = SOURCE_A  (no source_manager → UUID fallback)
            report_scope             = 'Platform Entry Notifications - Source Data Concerns Only'
            status                   = 'completed'
            total_cves_processed     = 1
            total_platform_entries   = 2
            entries_with_concerns    = 1
            concern_type_counts      = [{'concern_type': 'Placeholder Detection', 'count': 1}]
        """
        print('\nTest 25: finalize() — metadata schema and concern aggregation')
        builder = SDCReportBuilder()
        builder.add_cve('CVE-2024-09925', [
            {
                'originAffectedEntry': {
                    'sourceId': SOURCE_A,
                    'vendor': 'FinalVendor',
                    'product': 'FinalProduct',
                },
                'sourceDataConcerns': {
                    'concerns': {
                        'Placeholder Detection': [
                            {'field': 'vendor', 'sourceValue': 'n/a', 'detectedValue': 'n/a'}
                        ]
                    }
                },
            },
            _clean_entry(SOURCE_A),
        ])
        reports = builder.finalize()

        self.assert_true('SOURCE_A present in finalize output', SOURCE_A in reports)
        if SOURCE_A in reports:
            report = reports[SOURCE_A]
            self.assert_true("report has 'metadata' key", 'metadata' in report)
            self.assert_true("report has 'cve_data' key", 'cve_data' in report)

            meta = report['metadata']
            self.assert_equals('metadata.source_id', SOURCE_A, meta.get('source_id'))
            self.assert_equals(
                'metadata.source_name falls back to source_id when no source_manager',
                SOURCE_A, meta.get('source_name'),
            )
            self.assert_equals(
                'metadata.report_scope',
                'Platform Entry Notifications - Source Data Concerns Only',
                meta.get('report_scope'),
            )
            self.assert_equals("metadata.status == 'completed'", 'completed', meta.get('status'))
            self.assert_true('metadata.run_started_at is present', bool(meta.get('run_started_at')))
            self.assert_true('metadata.last_updated is present', bool(meta.get('last_updated')))
            self.assert_equals('metadata.total_cves_processed == 1', 1, meta.get('total_cves_processed'))
            self.assert_equals('metadata.total_platform_entries == 2', 2, meta.get('total_platform_entries'))
            self.assert_equals('metadata.entries_with_concerns == 1', 1, meta.get('entries_with_concerns'))

            ctc = meta.get('concern_type_counts', [])
            self.assert_equals('concern_type_counts has exactly 1 entry', 1, len(ctc))
            if ctc:
                self.assert_equals(
                    "concern_type is 'Placeholder Detection'",
                    'Placeholder Detection', ctc[0].get('concern_type'),
                )
                self.assert_equals('Placeholder Detection count == 1', 1, ctc[0].get('count'))

            # global_metadata updated by finalize()
            self.assert_equals(
                'global_metadata.total_sources == 1 after finalize',
                1, builder.global_metadata.get('total_sources'),
            )
            self.assert_equals(
                "global_metadata.status == 'completed' after finalize",
                'completed', builder.global_metadata.get('status'),
            )

    # ── Runner ───────────────────────────────────────────────────────────────
    def run_all_tests(self) -> int:
        print('=' * 70)
        print('SDC Report Generation — by_year Feature Test Suite')
        print('=' * 70)

        self.test_year_2024_extraction()
        self.test_year_2025_extraction()
        self.test_year_unknown_malformed_id()
        self.test_year_unknown_short_id()
        self.test_single_cve_concern_only()
        self.test_single_cve_clean_only()
        self.test_single_cve_mixed_entries()
        self.test_without_concerns_derivable()
        self.test_multi_cve_same_year_accumulates()
        self.test_multi_cve_different_years_partition()
        self.test_cve_count_not_double_counted()
        self.test_multi_source_independent_buckets()
        self.test_multi_source_no_cross_contamination()
        self.test_year_filter_aggregation_matches_source_totals()
        self.test_year_filter_zero_for_missing_year()
        self.test_integration_scan_and_builder_pipeline()
        self.test_17_template_has_IndexYearFilter()
        self.test_18_template_has_toggleIndexYearPill()
        self.test_19_template_has_applyIndexFilters()
        self.test_21_extract_sdc_happy_path_returns_cve_id_and_entries()
        self.test_22_extract_sdc_missing_id_returns_none_tuple()
        self.test_23_extract_sdc_missing_enriched_returns_empty_entries()
        self.test_24_extract_sdc_malformed_json_returns_none_tuple()
        self.test_25_finalize_metadata_schema_and_concern_aggregation()
        self.test_20_full_pipeline_subprocess_execute()

        print('\n' + '=' * 70)
        total = self.passed + self.failed
        print(f'TEST_RESULTS: PASSED={self.passed} TOTAL={total} SUITE="SDC Report Generation"')
        print('=' * 70)
        return 0 if self.failed == 0 else 1


def main():
    tester = TestSDCReportByYear()
    sys.exit(tester.run_all_tests())


if __name__ == '__main__':
    main()
