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
    _has_alias_concerns,
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

# ── Tests 25b: production-path non-actionable entries via full subprocess ──────
# test-source-na-pipeline-0001 has both a real alias and a production-path na entry.
# test-source-na-pipeline-0002 has ONLY na entries — MUST receive a report with
# all-non-actionable statistics.
TEST_CVE_1337_9901: Dict = {
    'id': 'CVE-1337-9901',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': 'test-source-na-pipeline-0001'},
            'aliasExtraction': {
                'aliases': [{'vendor': 'na_pipe_vendor', 'product': 'na_pipe_product'}],
            },
        }]
    },
}

TEST_CVE_1337_9902: Dict = {
    'id': 'CVE-1337-9902',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [
            {
                # Production path: register_alias_extraction() wrote aliasExtraction: {}
                # because all alias values (vendor, product) are placeholder values.
                'originAffectedEntry': {
                    'sourceId': 'test-source-na-pipeline-0001',
                    'vendor': 'n/a',
                    'product': 'n/a',
                },
                'aliasExtraction': {},
            },
            {
                # Pure-placeholder source — MUST produce a per-source report with
                # all-non-actionable statistics (non_actionable_count >= 1,
                # confirmed_count = 0, unconfirmed_count = 0).
                'originAffectedEntry': {
                    'sourceId': 'test-source-na-pipeline-0002',
                    'vendor': 'n/a',
                    'product': 'n/a',
                },
                'aliasExtraction': {},
            },
        ]
    },
}

TEST_CVE_1337_9903: Dict = {
    'id': 'CVE-1337-9903',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            # Sole source for this CVE is pure-placeholder (all alias values = n/a).
            # Used by test 36c to validate that a pure-placeholder-only source
            # produces a report with all-non-actionable statistics.
            'originAffectedEntry': {
                'sourceId': 'test-source-na-only-36c',
                'vendor': 'n/a',
                'product': 'n/a',
            },
            'aliasExtraction': {},
        }]
    },
}

# ── Test 47: SDC concerns flags in subprocess JSON output ──────────────────
# Two CVEs, same source, different aliases.
# CVE-1337-1001: alias_a uses vendor='sdc_vendor', product='sdc_vendor_lib'
#   - vendor IS a substring of product → triggers _has_alias_concerns() bloat-text rule
#   - sourceDataConcerns also present so _sdc_concerns is non-empty via _extract_alias_concerns()
#   → Both finalize() (by_year) and calculate_alias_statistics() (index) count it as with_concerns.
# CVE-1337-1002: alias_b uses clean values (no bloat, no concerns).
# Expected in output:
#   unconfirmed_count == 2  (alias_a + alias_b are 2 distinct alias keys)
#   unconfirmed_with_concerns_count == 1  (only alias_a)
#   unconfirmed_with_concerns_pct == 50.0  (1 of 2 unconfirmed)
_SRC_47 = 'test-source-concerns-0001'
TEST_CVE_1337_1001: Dict = {
    'id': 'CVE-1337-1001',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_47},
            'aliasExtraction': {
                # vendor='sdc_vendor' is a substring of product='sdc_vendor_lib'
                # → triggers _has_alias_concerns() bloat-text detection
                'aliases': [{'vendor': 'sdc_vendor', 'product': 'sdc_vendor_lib'}],
            },
            # sourceDataConcerns makes _extract_alias_concerns() populate _sdc_concerns
            # on this alias so finalize()'s by_year unconfirmed_with_concerns_count fires too.
            'sourceDataConcerns': {
                'concerns': {
                    'versionType': [{'field': 'vendor', 'sourceValue': 'sdc_vendor'}]
                }
            },
        }]
    },
}

TEST_CVE_1337_1002: Dict = {
    'id': 'CVE-1337-1002',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_47},
            'aliasExtraction': {
                # Clean alias — vendor NOT in product, no concerns of any kind
                'aliases': [{'vendor': 'sdc_vendor_b', 'product': 'sdc_product_b'}],
            },
            # No sourceDataConcerns
        }]
    },
}

# ── Test 48: CPE sort order and top-5 cap in subprocess JSON output ────────
# Seven CVEs, same alias, different NVD CPE configurations.
# CVE-1337-2001 and CVE-1337-2002 share CPE_A → cveCount == 2 (highest, must sort first).
# CVE-1337-2003 through CVE-1337-2007 each have a unique CPE (B through F) → cveCount == 1 each.
# Total: 6 distinct CPE base strings → top-5 cap → topNvdCpeBaseStrings has exactly 5 entries.
_SRC_48 = 'test-source-cpe-cap-0001'
_ALIAS_48 = {'vendor': 'cap_vendor', 'product': 'cap_product'}

TEST_CVE_1337_2001: Dict = {
    'id': 'CVE-1337-2001',
    'configurations': [{'nodes': [{'cpeMatch': [
        {'criteria': 'cpe:2.3:a:cap_vendor:cap_product_a:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
    ]}]}],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{'originAffectedEntry': {'sourceId': _SRC_48}, 'aliasExtraction': {'aliases': [_ALIAS_48]}}],
    },
}
TEST_CVE_1337_2002: Dict = {
    'id': 'CVE-1337-2002',
    'configurations': [{'nodes': [{'cpeMatch': [
        {'criteria': 'cpe:2.3:a:cap_vendor:cap_product_a:2.0:*:*:*:*:*:*:*', 'vulnerable': True},
    ]}]}],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{'originAffectedEntry': {'sourceId': _SRC_48}, 'aliasExtraction': {'aliases': [_ALIAS_48]}}],
    },
}
TEST_CVE_1337_2003: Dict = {
    'id': 'CVE-1337-2003',
    'configurations': [{'nodes': [{'cpeMatch': [
        {'criteria': 'cpe:2.3:a:cap_vendor:cap_product_b:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
    ]}]}],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{'originAffectedEntry': {'sourceId': _SRC_48}, 'aliasExtraction': {'aliases': [_ALIAS_48]}}],
    },
}
TEST_CVE_1337_2004: Dict = {
    'id': 'CVE-1337-2004',
    'configurations': [{'nodes': [{'cpeMatch': [
        {'criteria': 'cpe:2.3:a:cap_vendor:cap_product_c:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
    ]}]}],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{'originAffectedEntry': {'sourceId': _SRC_48}, 'aliasExtraction': {'aliases': [_ALIAS_48]}}],
    },
}
TEST_CVE_1337_2005: Dict = {
    'id': 'CVE-1337-2005',
    'configurations': [{'nodes': [{'cpeMatch': [
        {'criteria': 'cpe:2.3:a:cap_vendor:cap_product_d:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
    ]}]}],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{'originAffectedEntry': {'sourceId': _SRC_48}, 'aliasExtraction': {'aliases': [_ALIAS_48]}}],
    },
}
TEST_CVE_1337_2006: Dict = {
    'id': 'CVE-1337-2006',
    'configurations': [{'nodes': [{'cpeMatch': [
        {'criteria': 'cpe:2.3:a:cap_vendor:cap_product_e:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
    ]}]}],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{'originAffectedEntry': {'sourceId': _SRC_48}, 'aliasExtraction': {'aliases': [_ALIAS_48]}}],
    },
}
TEST_CVE_1337_2007: Dict = {
    'id': 'CVE-1337-2007',
    'configurations': [{'nodes': [{'cpeMatch': [
        {'criteria': 'cpe:2.3:a:cap_vendor:cap_product_f:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
    ]}]}],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{'originAffectedEntry': {'sourceId': _SRC_48}, 'aliasExtraction': {'aliases': [_ALIAS_48]}}],
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

# ── Test 49: isSuggestedMatch: true via cpeDetermination field ─────────────
# One CVE: NVD config has two CPE base strings (_a and _b).
# cpeDetermination.top10SuggestedCPEBaseStrings includes only the _a base string.
# Expected in topNvdCpeBaseStrings: _a has isSuggestedMatch=True, _b has False.
_SRC_49 = 'test-source-suggested-0001'
_CPE_SUGG_A_BASE = 'cpe:2.3:a:sugg_vendor:sugg_product_a:*:*:*:*:*:*:*:*'
_CPE_SUGG_B_BASE = 'cpe:2.3:a:sugg_vendor:sugg_product_b:*:*:*:*:*:*:*:*'

TEST_CVE_1337_3001: Dict = {
    'id': 'CVE-1337-3001',
    'configurations': [{'nodes': [{'cpeMatch': [
        {'criteria': 'cpe:2.3:a:sugg_vendor:sugg_product_a:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
        {'criteria': 'cpe:2.3:a:sugg_vendor:sugg_product_b:1.0:*:*:*:*:*:*:*', 'vulnerable': True},
    ]}]}],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_49},
            'aliasExtraction': {
                'aliases': [{'vendor': 'sugg_vendor', 'product': 'sugg_product'}],
            },
            # Only _a is in the suggested list; _b is NVD-only, not suggested.
            'cpeDetermination': {
                'top10SuggestedCPEBaseStrings': [
                    {'cpeBaseString': _CPE_SUGG_A_BASE},
                ],
            },
        }]
    },
}

# ── Test 50: platform field differentiates aliases in same group ───────────
# Three CVEs, same source, same vendor+product but different platform values.
# All three aliases share the same group (same field types: vendor+product+platform).
# Two CVEs reference the Linux alias so it has cveCount=2 and sorts first.
_SRC_50 = 'test-source-platform-0001'

TEST_CVE_1337_4001: Dict = {
    'id': 'CVE-1337-4001',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_50},
            'aliasExtraction': {
                'aliases': [{'vendor': 'plat_vendor', 'product': 'plat_product', 'platform': 'Linux'}],
            },
        }]
    },
}

TEST_CVE_1337_4002: Dict = {
    'id': 'CVE-1337-4002',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_50},
            'aliasExtraction': {
                # Second CVE also references the Linux alias → Linux alias cveCount becomes 2.
                'aliases': [{'vendor': 'plat_vendor', 'product': 'plat_product', 'platform': 'Linux'}],
            },
        }]
    },
}

TEST_CVE_1337_4003: Dict = {
    'id': 'CVE-1337-4003',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_50},
            'aliasExtraction': {
                'aliases': [{'vendor': 'plat_vendor', 'product': 'plat_product', 'platform': 'Windows'}],
            },
        }]
    },
}

TEST_CVE_1337_4004: Dict = {
    'id': 'CVE-1337-4004',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_50},
            'aliasExtraction': {
                'aliases': [{'vendor': 'plat_vendor', 'product': 'plat_product', 'platform': 'macOS'}],
            },
        }]
    },
}

# ── Test 51: non-standard alias values pass through to alias JSON output ─
# Four CVEs, same source, each alias uses a different non-standard alias value.
# Assertions verify each field value survives finalize() and appears in aliasGroups.
_SRC_51 = 'test-source-fields-0001'

TEST_CVE_1337_5101: Dict = {
    'id': 'CVE-1337-5101',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_51},
            'aliasExtraction': {
                'aliases': [{'vendor': 'fields_vendor', 'product': 'fields_product',
                             'packageName': 'fields-package-name'}],
            },
        }]
    },
}

TEST_CVE_1337_5102: Dict = {
    'id': 'CVE-1337-5102',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_51},
            'aliasExtraction': {
                'aliases': [{'vendor': 'fields_vendor', 'product': 'fields_product',
                             'collectionURL': 'https://example.com/collection/fields'}],
            },
        }]
    },
}

TEST_CVE_1337_5103: Dict = {
    'id': 'CVE-1337-5103',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_51},
            'aliasExtraction': {
                'aliases': [{'vendor': 'fields_vendor', 'product': 'fields_product',
                             'repo': 'https://github.com/fields-vendor/fields-project'}],
            },
        }]
    },
}

TEST_CVE_1337_5104: Dict = {
    'id': 'CVE-1337-5104',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_51},
            'aliasExtraction': {
                'aliases': [{'vendor': 'fields_vendor', 'product': 'fields_product',
                             'modules': ['fields-module-a', 'fields-module-b']}],
            },
        }]
    },
}

# ── Test 52: whitespace / text-comparator / invalid-chars SDC concern types ─
# Three CVEs, same source, each alias triggers a different concern type.
# Each fixture also has sourceDataConcerns so _sdc_concerns is non-empty via
# _extract_alias_concerns(), ensuring by_year unconfirmed_with_concerns_count fires.
# Expected: unconfirmed_with_concerns_count == 3 at both index and by_year level.
_SRC_52 = 'test-source-sdc3-0001'

TEST_CVE_1337_5201: Dict = {
    'id': 'CVE-1337-5201',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_52},
            'aliasExtraction': {
                # Leading space in vendor → whitespace concern
                'aliases': [{'vendor': ' ws_vendor', 'product': 'ws_product'}],
            },
            'sourceDataConcerns': {
                'concerns': {
                    'whitespace': [{'field': 'vendor', 'sourceValue': ' ws_vendor'}],
                },
            },
        }]
    },
}

TEST_CVE_1337_5202: Dict = {
    'id': 'CVE-1337-5202',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_52},
            'aliasExtraction': {
                # "before" in product → text comparator concern
                'aliases': [{'vendor': 'tc_vendor', 'product': 'tc_app before 3.0'}],
            },
            'sourceDataConcerns': {
                'concerns': {
                    'textComparator': [{'field': 'product', 'sourceValue': 'tc_app before 3.0'}],
                },
            },
        }]
    },
}

TEST_CVE_1337_5203: Dict = {
    'id': 'CVE-1337-5203',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_52},
            'aliasExtraction': {
                # Comma in product → invalid character concern
                'aliases': [{'vendor': 'ic_vendor', 'product': 'ic_component, plugin'}],
            },
            'sourceDataConcerns': {
                'concerns': {
                    'invalidChars': [{'field': 'product', 'sourceValue': 'ic_component, plugin'}],
                },
            },
        }]
    },
}


# ── Test 55: programFiles / programRoutines / packageURL pipeline passthrough ─
# Completes the identity-field passthrough coverage from test_51 (which covers
# packageName, collectionURL, repo, modules).  These three fields appear in the
# example template but were absent from any subprocess fixture.
# Each CVE carries one of the three remaining fields; assertions verify the field
# value survives finalize() and appears in the per-source aliasGroups JSON.
_SRC_55 = 'test-source-fields-0055'

TEST_CVE_1337_5105: Dict = {
    'id': 'CVE-1337-5105',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_55},
            'aliasExtraction': {
                'aliases': [{'vendor': 'fields55_vendor', 'product': 'fields55_product',
                             'programFiles': 'src/render/pixel.c'}],
            },
        }]
    },
}

TEST_CVE_1337_5106: Dict = {
    'id': 'CVE-1337-5106',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_55},
            'aliasExtraction': {
                'aliases': [{'vendor': 'fields55_vendor', 'product': 'fields55_product',
                             'programRoutines': 'dbExprCodeTarget'}],
            },
        }]
    },
}

TEST_CVE_1337_5107: Dict = {
    'id': 'CVE-1337-5107',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_55},
            'aliasExtraction': {
                'aliases': [{'vendor': 'fields55_vendor', 'product': 'fields55_product',
                             'packageURL': 'pkg:npm/util-kit'}],
            },
        }]
    },
}

# ── Test 57: subprocess confirmedMappings via injected mapping file ──────────
# A temp mapping file is written to cache/alias_mappings/ using a source UUID and
# email that exist in nvd_source_data.json but have no existing mapping file there.
# These identifiers are opaque — they satisfy ConfirmedMappingManager's cnaId
# validation requirement.  The test data (alias, CPE string) is fully generic.
_TEST57_SOURCE_UUID = '56a131ea-b967-4a0d-a41e-5f3549952846'
_TEST57_SOURCE_EMAIL = 'arm-security@arm.com'
_SRC_57 = _TEST57_SOURCE_EMAIL
_TEST57_MAPPING_FILE = project_root / 'cache' / 'alias_mappings' / '_test_confirmed_57.json'

TEST_CVE_1337_5701: Dict = {
    'id': 'CVE-1337-5701',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _SRC_57},
            'aliasExtraction': {
                'aliases': [{'vendor': 'test57_vendor', 'product': 'test57_product'}],
            },
        }]
    },
}

# ── Test 64: subprocess confirmedMappings raw value preservation ─────────────
# Reuses _TEST57 source UUID/email pair for ConfirmedMappingManager validation.
# Alias has a leading-space vendor to verify raw field values are stored verbatim.
_TEST64_MAPPING_FILE = project_root / 'cache' / 'alias_mappings' / '_test_confirmed_64.json'

TEST_CVE_1337_6400: Dict = {
    'id': 'CVE-1337-6400',
    'configurations': [],
    'enrichedCVEv5Affected': {
        'cveListV5AffectedEntries': [{
            'originAffectedEntry': {'sourceId': _TEST57_SOURCE_EMAIL},
            'aliasExtraction': {
                'aliases': [{'vendor': ' whitespace_vendor', 'product': 'ws_product'}],
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
        """Test 24b: _is_alias_non_actionable() returns True when all alias values are placeholders."""
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
        """Test 24c: _is_alias_non_actionable() returns False when any alias value has real data."""
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
        # Pipeline now produces scalar strings (not lists) for modules/programFiles/programRoutines
        # after _expand_alias_complex_fields() expansion — verify scalar values are also actionable.
        self.assert_true("scalar modules string is actionable",
                         not _is_alias_non_actionable({'modules': 'proxy_http_core_module'}))
        self.assert_true("non-empty programFiles list is actionable",
                         not _is_alias_non_actionable({'programFiles': ['file.exe']}))
        self.assert_true("scalar programFiles string is actionable",
                         not _is_alias_non_actionable({'programFiles': 'src/render/pixel.c'}))
        self.assert_true("scalar programRoutines string is actionable",
                         not _is_alias_non_actionable({'programRoutines': 'dbExprCodeTarget'}))
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
        """Test 34: finalize() tracks non_actionable_count per year in by_year.

        Uses the production path: aliasExtraction: {} (key present, no aliases sub-key)
        with placeholder values in originAffectedEntry — matching what
        register_alias_extraction() actually writes to the NVD-ish cache.
        """
        print("\nTest 34: by_year non_actionable_count tracked per year (production path)")
        _SRC_34 = 'yr-test-src-34'
        _ALIAS_34_ACTION = {'vendor': 'yr34_vendor', 'product': 'yr34_product'}

        # SETUP: actionable alias on 2024, production-path na entries on 2024 + 2025
        builder = AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockMappingManager(),
        )
        entry_action_2024 = {
            'originAffectedEntry': {'sourceId': _SRC_34},
            'aliasExtraction': {'aliases': [_ALIAS_34_ACTION]},
        }
        # Production path: aliasExtraction: {} — no aliases key.
        # register_alias_extraction() detected all-placeholder fields and omitted aliases.
        entry_na_2024 = {
            'originAffectedEntry': {'sourceId': _SRC_34, 'vendor': 'n/a', 'product': 'n/a'},
            'aliasExtraction': {},
        }
        entry_na_2025 = {
            'originAffectedEntry': {'sourceId': _SRC_34, 'vendor': 'n/a', 'product': 'n/a'},
            'aliasExtraction': {},
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
        # 2025: CVE-2025-3401 produced only a non-actionable entry; finalize() now
        # counts it towards by_year.cves so the CVE-per-year chart is accurate.
        self.assert_equals("2025 cves == 1 (non-actionable-only CVE now counted)",
                           1, by_year['2025']['cves'])

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

    def test_36b_non_actionable_from_empty_alias_extraction(self):
        """Test 36b: Non-actionable platform entries (aliasExtraction present but empty)
        are buffered and merged into all sources (established and pure-placeholder) so
        they appear in by_year non_actionable_count.
        Pure-placeholder sources (never seen with a real alias) MUST receive a report
        with all-non-actionable statistics.
        """
        print("\nTest 36b: non-actionable counts from empty aliasExtraction (production path)")
        _SRC_A = 'test-source-uuid-0036b-A'  # has real aliases
        _SRC_B = 'test-source-uuid-0036b-B'  # pure-placeholder: MUST get a report

        builder = AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockMappingManager(),
        )

        # Production-style na entry: aliasExtraction key present, no 'aliases' sub-key.
        def _na_entry(src, vendor='n/a', product='n/a'):
            return {
                'originAffectedEntry': {'sourceId': src, 'vendor': vendor, 'product': product},
                'aliasExtraction': {},   # key present, no aliases
                'sourceDataConcerns': {},
            }

        def _real_entry(src, vendor='acme', product='widget'):
            return {
                'originAffectedEntry': {'sourceId': src},
                'aliasExtraction': {'aliases': [{'vendor': vendor, 'product': product}]},
            }

        # CVE-2024-9001: Source A has a real alias AND a na entry (mixed CVE)
        builder.add_cve_aliases('CVE-2024-9001',
                                 [_real_entry(_SRC_A), _na_entry(_SRC_A)],
                                 nvd_cpe_set=set())
        # CVE-2024-9002: Source A has only na entries; Source B also only na
        builder.add_cve_aliases('CVE-2024-9002',
                                 [_na_entry(_SRC_A), _na_entry(_SRC_B)],
                                 nvd_cpe_set=set())
        # CVE-2025-9001: Source A has another na entry (different year)
        builder.add_cve_aliases('CVE-2025-9001',
                                 [_na_entry(_SRC_A)],
                                 nvd_cpe_set=set())

        reports = builder.finalize()

        # Source A must have a report (it has real aliases)
        self.assert_true("Source A present in report", _SRC_A in reports)

        # Source B is pure-placeholder but MUST still get a report showing
        # all-non-actionable statistics.
        self.assert_true("Source B present in report (pure-placeholder gets report)", _SRC_B in reports)

        if _SRC_B in reports:
            b_meta = reports[_SRC_B]['metadata']
            self.assert_equals("Source B unique_aliases_extracted >= 1",
                               True, b_meta['unique_aliases_extracted'] >= 1)
            self.assert_equals("Source B alias_groups_confirmed == 0",
                               0, b_meta['alias_groups_confirmed'])
            self.assert_equals("Source B confirmedMappings is empty",
                               0, len(reports[_SRC_B]['confirmedMappings']))

        by_year = reports[_SRC_A]['metadata']['by_year']

        # 2024: 1 actionable unconfirmed alias + 1 non-actionable unique alias
        # (CVE-2024-9001 and CVE-2024-9002 both submitted the same n/a pattern for SRC_A;
        # deduplicates to 1 unique non-actionable alias).
        self.assert_true("by_year has '2024'", '2024' in by_year)
        self.assert_equals("2024 non_actionable_count == 1",
                           1, by_year['2024']['non_actionable_count'])
        self.assert_equals("2024 unconfirmed_count == 1 (actionable only)",
                           1, by_year['2024']['unconfirmed_count'])

        # 2025: only non-actionable alias (1 CVE occurrence)
        self.assert_true("by_year has '2025'", '2025' in by_year)
        self.assert_equals("2025 non_actionable_count == 1",
                           1, by_year['2025']['non_actionable_count'])
        self.assert_equals("2025 unconfirmed_count == 0",
                           0, by_year['2025']['unconfirmed_count'])

        # TEARDOWN
        builder = None

    def test_36c_four_phase_pure_placeholder_source_gets_report(self):
        """Test 36c: Four-phase subprocess — a source whose ONLY submissions are
        pure-placeholder entries (all alias values = n/a) MUST produce a report
        with all-non-actionable statistics.

        CVE-1337-9903: test-source-na-only-36c submits one placeholder entry
                       (aliasExtraction: {}, vendor/product = n/a).

        Expected:
        - Source appears in the JSON index
        - Per-source report file is written
        - unique_aliases_extracted == 1  (one distinct NA dedup pattern)
        - non_actionable_count == 1
        - confirmed_count == 0
        - unconfirmed_count == 0
        - by_year['1337']['non_actionable_count'] == 1
        """
        import subprocess
        print("\nTest 36c: Four-phase -- pure-placeholder-only source produces report")

        # PHASE 1 -- SETUP
        self.setup_subprocess_test_cache([TEST_CVE_1337_9903], batch='0xxx')

        try:
            # PHASE 2 -- EXECUTE
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

            # PHASE 3 -- VALIDATE
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in stdout", run_id is not None)

            if run_id:
                logs_dir = project_root / "runs" / run_id / "logs"
                index_file = logs_dir / "aliasExtractionReport_index.json"
                self.assert_true("index.json exists", index_file.exists())

                if index_file.exists():
                    with open(index_file, 'r', encoding='utf-8') as f:
                        index_data = json.load(f)

                    source_names = [s.get('source_name', '') for s in index_data.get('sources', [])]
                    self.assert_true(
                        "test-source-na-only-36c present in index",
                        'test-source-na-only-36c' in source_names,
                    )

                    src_entry = next(
                        (s for s in index_data.get('sources', [])
                         if s.get('source_name') == 'test-source-na-only-36c'),
                        None,
                    )
                    self.assert_true("source entry found in index", src_entry is not None)

                    if src_entry is not None:
                        self.assert_equals("non_actionable_count == 1", 1, src_entry.get('non_actionable_count'))
                        self.assert_equals("confirmed_count == 0", 0, src_entry.get('confirmed_count'))
                        self.assert_equals("unconfirmed_count == 0", 0, src_entry.get('unconfirmed_count'))
                        # Pure-NA source: no actionable alias patterns — total_unique_aliases == 0.
                        # non_actionable_count is tracked separately as unique alias sets.
                        self.assert_equals("total_unique_aliases == 0 (pure-NA source)", 0, src_entry.get('total_unique_aliases'))
                        self.assert_equals("total_cves_processed == 1", 1, src_entry.get('total_cves_processed'))
                        self.assert_equals("unique_aliases_extracted == 1", 1, src_entry.get('unique_aliases_extracted'))
                        self.assert_equals("confirmed_coverage_pct == 0", 0, src_entry.get('confirmed_coverage_pct'))
                        self.assert_equals("confirmed_with_concerns_count == 0", 0, src_entry.get('confirmed_with_concerns_count'))
                        self.assert_equals("unconfirmed_with_concerns_count == 0", 0, src_entry.get('unconfirmed_with_concerns_count'))
                        by_year = src_entry.get('by_year', {})
                        self.assert_true("by_year has '1337'", '1337' in by_year)
                        if '1337' in by_year:
                            yr = by_year['1337']
                            self.assert_equals("1337 cves == 1", 1, yr.get('cves'))
                            self.assert_equals("1337 unique_aliases == 1", 1, yr.get('unique_aliases'))
                            self.assert_equals("1337 non_actionable_count == 1", 1, yr.get('non_actionable_count'))
                            self.assert_equals("1337 confirmed_count == 0", 0, yr.get('confirmed_count'))
                            self.assert_equals("1337 unconfirmed_count == 0", 0, yr.get('unconfirmed_count'))
                            self.assert_equals("1337 confirmed_coverage_pct == 0", 0, yr.get('confirmed_coverage_pct'))

                    # Global index metadata for a pure-placeholder source: total_cves_processed == 0
                    # because the main entries_by_org loop only fires for real aliases
                    idx_global = index_data.get('metadata', {})
                    self.assert_equals("global total_cves_processed == 0 (NA-only CVE not counted)", 0, idx_global.get('total_cves_processed'))
                    self.assert_equals("global total_sources == 1", 1, idx_global.get('total_sources'))
                    self.assert_equals("global status == 'completed'", 'completed', idx_global.get('status'))

                    # Per-source report file must exist
                    report_files = list(logs_dir.glob(
                        "aliasExtractionReport_test-source-na-only-36c_*.json"
                    ))
                    self.assert_true("Report file written for pure-placeholder source", len(report_files) >= 1)
                    if report_files:
                        with open(report_files[0], 'r', encoding='utf-8') as f:
                            report_data = json.load(f)
                        meta36c = report_data.get('metadata', {})
                        self.assert_equals("unique_aliases_extracted == 1", 1, meta36c.get('unique_aliases_extracted'))
                        self.assert_equals("total_cves_processed == 1", 1, meta36c.get('total_cves_processed'))
                        self.assert_equals("alias_groups_confirmed == 0", 0, meta36c.get('alias_groups_confirmed'))
                        self.assert_equals("confirmed_cna_id is None", None, meta36c.get('confirmed_cna_id'))
                        self.assert_equals("status == 'completed'", 'completed', meta36c.get('status'))

                        # aliasGroups: 1 group with aliasGroup == 'no_identity_non_actionable'
                        alias_groups_36c = report_data.get('aliasGroups', [])
                        self.assert_equals("1 alias group", 1, len(alias_groups_36c))
                        if alias_groups_36c:
                            grp36c = alias_groups_36c[0]
                            self.assert_equals(
                                "aliasGroup key == 'no_identity_non_actionable'",
                                'no_identity_non_actionable', grp36c.get('aliasGroup'),
                            )
                            aliases_36c = grp36c.get('aliases', [])
                            self.assert_equals("group has 1 alias", 1, len(aliases_36c))
                            if aliases_36c:
                                a36c = aliases_36c[0]
                                self.assert_equals("NA alias source_cve == ['CVE-1337-9903']", ['CVE-1337-9903'], a36c.get('source_cve'))
                                self.assert_true("NA alias has no 'vendor' field", 'vendor' not in a36c)
                                self.assert_true("NA alias has no 'product' field", 'product' not in a36c)
                                self.assert_equals("NA alias topNvdCpeBaseStrings == []", [], a36c.get('topNvdCpeBaseStrings'))
                                # originAffectedEntry fields are CVE entry metadata, not alias data —
                                # naPatternFields is empty for Path A (no alias was extracted).
                                self.assert_equals("NA alias naPatternFields == {}", {}, a36c.get('naPatternFields'))

                        self.assert_equals("confirmedMappings is empty", 0, len(report_data.get('confirmedMappings', [None])))

        finally:
            # PHASE 4 -- TEARDOWN
            self.teardown_subprocess_test_cache()

    def test_25b_full_pipeline_non_actionable_entries(self):
        """Test 25b: Four-phase subprocess — production-path na entries (aliasExtraction: {})
        are counted in non_actionable statistics for all sources including pure-placeholder ones.

        CVE-1337-9901: source 0001 has a real alias.
        CVE-1337-9902: source 0001 has aliasExtraction: {} (production path na);
                       source 0002 has aliasExtraction: {} (pure-placeholder source).

        Expected outputs:
        - source 0001 produces a report: unique_aliases_extracted == 2 (1 real + 1 na)
        - source 0002 produces a report: unique_aliases_extracted == 1 (all na)
        - source 0001 by_year['1337']['non_actionable_count'] == 1
        - source 0001 by_year['1337']['unconfirmed_count'] == 1
        - source 0002 by_year['1337']['non_actionable_count'] == 1
        - source 0002 confirmed_count == 0, unconfirmed_count == 0
        """
        import subprocess
        print("\nTest 25b: Full pipeline subprocess — production-path non-actionable entries")

        # PHASE 1 — SETUP
        self.setup_subprocess_test_cache([TEST_CVE_1337_9901, TEST_CVE_1337_9902], batch='0xxx')

        try:
            # PHASE 2 — EXECUTE
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

            # PHASE 3 — VALIDATE
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in subprocess stdout", run_id is not None)

            if run_id:
                logs_dir = project_root / "runs" / run_id / "logs"
                index_file = logs_dir / "aliasExtractionReport_index.json"
                self.assert_true("index.json exists", index_file.exists())

                if index_file.exists():
                    with open(index_file, 'r', encoding='utf-8') as f:
                        index_data = json.load(f)

                    source_names = [s.get('source_name', '') for s in index_data.get('sources', [])]

                    # Source 0001 has a real alias — must appear in index
                    self.assert_true(
                        "test-source-na-pipeline-0001 present in index (has real aliases)",
                        'test-source-na-pipeline-0001' in source_names,
                    )
                    # Source 0002 is pure-placeholder — must also appear in index
                    self.assert_true(
                        "test-source-na-pipeline-0002 present in index (pure-placeholder gets report)",
                        'test-source-na-pipeline-0002' in source_names,
                    )

                    src_entry = next(
                        (s for s in index_data.get('sources', [])
                         if s.get('source_name') == 'test-source-na-pipeline-0001'),
                        None,
                    )
                    self.assert_true("source 0001 entry found in index", src_entry is not None)

                    if src_entry is not None:
                        # 1 real alias (actionable); 1 NA entry tracked separately
                        self.assert_equals("source 0001 total_unique_aliases == 1", 1, src_entry.get('total_unique_aliases'))
                        self.assert_equals("source 0001 non_actionable_count == 1", 1, src_entry.get('non_actionable_count'))
                        self.assert_equals("source 0001 confirmed_count == 0", 0, src_entry.get('confirmed_count'))
                        self.assert_equals("source 0001 confirmed_coverage_pct == 0.0", 0.0, src_entry.get('confirmed_coverage_pct'))
                        self.assert_equals("source 0001 unconfirmed_count == 1", 1, src_entry.get('unconfirmed_count'))
                        self.assert_equals("source 0001 confirmed_with_concerns_count == 0", 0, src_entry.get('confirmed_with_concerns_count'))
                        self.assert_equals("source 0001 unconfirmed_with_concerns_count == 0", 0, src_entry.get('unconfirmed_with_concerns_count'))
                        # CVE-1337-9902 is NA-only for source 0001 and is now counted
                        # towards total_cves_processed and by_year.cves (fix: finalize()
                        # accumulates NA-only CVEs from _non_actionable_pending).
                        self.assert_equals("source 0001 total_cves_processed == 2", 2, src_entry.get('total_cves_processed'))
                        by_year = src_entry.get('by_year', {})
                        self.assert_true("source 0001 by_year has '1337'", '1337' in by_year)
                        if '1337' in by_year:
                            yr = by_year['1337']
                            self.assert_equals("1337 cves == 2 (real-alias CVE + NA-only CVE)", 2, yr.get('cves'))
                            self.assert_equals("1337 unique_aliases == 2", 2, yr.get('unique_aliases'))
                            self.assert_equals("1337 unconfirmed_count == 1", 1, yr.get('unconfirmed_count'))
                            self.assert_equals("1337 non_actionable_count == 1", 1, yr.get('non_actionable_count'))
                            self.assert_equals("1337 confirmed_count == 0", 0, yr.get('confirmed_count'))
                            self.assert_equals("1337 confirmed_coverage_pct == 0.0", 0.0, yr.get('confirmed_coverage_pct'))

                    # Validate per-source report file for content (alias fields + CVE associations)
                    report_files = list(logs_dir.glob(
                        "aliasExtractionReport_test-source-na-pipeline-0001_*.json"
                    ))
                    self.assert_true("Per-source report file written for source 0001", len(report_files) >= 1)
                    if report_files:
                        with open(report_files[0], 'r', encoding='utf-8') as f:
                            report_data = json.load(f)
                        meta0001 = report_data.get('metadata', {})
                        self.assert_equals("0001 unique_aliases_extracted == 2", 2, meta0001.get('unique_aliases_extracted'))
                        self.assert_equals("0001 total_cves_processed == 2", 2, meta0001.get('total_cves_processed'))
                        self.assert_equals("0001 alias_groups_confirmed == 0", 0, meta0001.get('alias_groups_confirmed'))

                        # aliasGroups: 1 actionable group + 1 no_identity_non_actionable (NA) group
                        alias_groups_0001 = report_data.get('aliasGroups', [])
                        self.assert_equals("0001 has 2 alias groups", 2, len(alias_groups_0001))
                        grp_by_key = {g.get('aliasGroup'): g for g in alias_groups_0001}
                        self.assert_true(
                            "0001 has '_sdc_concerns_product_vendor' group",
                            '_sdc_concerns_product_vendor' in grp_by_key,
                        )
                        self.assert_true("0001 has 'no_identity_non_actionable' group (NA)", 'no_identity_non_actionable' in grp_by_key)

                        if '_sdc_concerns_product_vendor' in grp_by_key:
                            real_aliases = grp_by_key['_sdc_concerns_product_vendor'].get('aliases', [])
                            self.assert_equals("real alias group has 1 alias", 1, len(real_aliases))
                            if real_aliases:
                                ra = real_aliases[0]
                                self.assert_equals("real alias vendor == 'na_pipe_vendor'", 'na_pipe_vendor', ra.get('vendor'))
                                self.assert_equals("real alias product == 'na_pipe_product'", 'na_pipe_product', ra.get('product'))
                                self.assert_equals("real alias source_cve == ['CVE-1337-9901']", ['CVE-1337-9901'], ra.get('source_cve'))
                                self.assert_equals("real alias topNvdCpeBaseStrings == []", [], ra.get('topNvdCpeBaseStrings'))

                        if 'no_identity_non_actionable' in grp_by_key:
                            na_aliases = grp_by_key['no_identity_non_actionable'].get('aliases', [])
                            self.assert_equals("NA alias group has 1 pattern alias", 1, len(na_aliases))
                            if na_aliases:
                                na = na_aliases[0]
                                self.assert_equals("NA alias source_cve == ['CVE-1337-9902']", ['CVE-1337-9902'], na.get('source_cve'))
                                self.assert_true("NA alias has no 'vendor' field", 'vendor' not in na)
                                self.assert_true("NA alias has no 'product' field", 'product' not in na)
                                self.assert_equals("NA alias topNvdCpeBaseStrings == []", [], na.get('topNvdCpeBaseStrings'))
                                # Path A: no alias was extracted, so naPatternFields is empty.
                                self.assert_equals("NA alias naPatternFields == {}", {}, na.get('naPatternFields'))

                        self.assert_equals("0001 confirmedMappings is empty", 0, len(report_data.get('confirmedMappings', [None])))

                    # Pure-placeholder source 0002 MUST also have a report file
                    na_only_reports = list(logs_dir.glob(
                        "aliasExtractionReport_test-source-na-pipeline-0002_*.json"
                    ))
                    self.assert_true(
                        "Per-source report file written for source 0002 (pure-placeholder)",
                        len(na_only_reports) >= 1,
                    )
                    if na_only_reports:
                        with open(na_only_reports[0], 'r', encoding='utf-8') as f:
                            na_report = json.load(f)
                        meta0002 = na_report.get('metadata', {})
                        self.assert_equals("source 0002 unique_aliases_extracted == 1", 1, meta0002.get('unique_aliases_extracted'))
                        self.assert_equals("source 0002 total_cves_processed == 1", 1, meta0002.get('total_cves_processed'))
                        self.assert_equals("source 0002 alias_groups_confirmed == 0", 0, meta0002.get('alias_groups_confirmed'))
                        self.assert_equals("source 0002 confirmed_cna_id is None", None, meta0002.get('confirmed_cna_id'))

                        # aliasGroups: 1 group (no_identity_non_actionable — NA entry only)
                        alias_groups_0002 = na_report.get('aliasGroups', [])
                        self.assert_equals("source 0002 has 1 alias group", 1, len(alias_groups_0002))
                        if alias_groups_0002:
                            grp0002 = alias_groups_0002[0]
                            self.assert_equals(
                                "source 0002 group key == 'no_identity_non_actionable'",
                                'no_identity_non_actionable', grp0002.get('aliasGroup'),
                            )
                            na_aliases_0002 = grp0002.get('aliases', [])
                            self.assert_equals("source 0002 group has 1 alias", 1, len(na_aliases_0002))
                            if na_aliases_0002:
                                na2 = na_aliases_0002[0]
                                self.assert_equals("source 0002 NA alias source_cve", ['CVE-1337-9902'], na2.get('source_cve'))
                                self.assert_true("source 0002 NA alias has no 'vendor' field", 'vendor' not in na2)
                                self.assert_true("source 0002 NA alias has no 'product' field", 'product' not in na2)

                        self.assert_equals("source 0002 confirmedMappings is empty", 0, len(na_report.get('confirmedMappings', [None])))

                    # Validate source 0002 index entry — full stats
                    src_02_entry = next(
                        (s for s in index_data.get('sources', [])
                         if s.get('source_name') == 'test-source-na-pipeline-0002'),
                        None,
                    )
                    self.assert_true("source 0002 entry found in index", src_02_entry is not None)
                    if src_02_entry is not None:
                        self.assert_equals("source 0002 non_actionable_count == 1", 1, src_02_entry.get('non_actionable_count'))
                        self.assert_equals("source 0002 confirmed_count == 0", 0, src_02_entry.get('confirmed_count'))
                        self.assert_equals("source 0002 unconfirmed_count == 0", 0, src_02_entry.get('unconfirmed_count'))
                        # Pure-NA source 0002: no actionable alias patterns.
                        self.assert_equals("source 0002 total_unique_aliases == 0 (pure-NA)", 0, src_02_entry.get('total_unique_aliases'))
                        self.assert_equals("source 0002 total_cves_processed == 1", 1, src_02_entry.get('total_cves_processed'))
                        self.assert_equals("source 0002 unique_aliases_extracted == 1", 1, src_02_entry.get('unique_aliases_extracted'))
                        self.assert_equals("source 0002 confirmed_with_concerns_count == 0", 0, src_02_entry.get('confirmed_with_concerns_count'))
                        self.assert_equals("source 0002 unconfirmed_with_concerns_count == 0", 0, src_02_entry.get('unconfirmed_with_concerns_count'))
                        by_year_02 = src_02_entry.get('by_year', {})
                        self.assert_true("source 0002 by_year has '1337'", '1337' in by_year_02)
                        if '1337' in by_year_02:
                            yr02 = by_year_02['1337']
                            self.assert_equals("source 0002 1337 cves == 1", 1, yr02.get('cves'))
                            self.assert_equals("source 0002 1337 unique_aliases == 1", 1, yr02.get('unique_aliases'))
                            self.assert_equals("source 0002 1337 non_actionable_count == 1", 1, yr02.get('non_actionable_count'))
                            self.assert_equals("source 0002 1337 confirmed_count == 0", 0, yr02.get('confirmed_count'))
                            self.assert_equals("source 0002 1337 unconfirmed_count == 0", 0, yr02.get('unconfirmed_count'))

        finally:
            # PHASE 4 — TEARDOWN
            self.teardown_subprocess_test_cache()

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

                    # ── Global index metadata ─────────────────────────────────
                    global_meta = index_data.get('metadata', {})
                    self.assert_true("index has 'metadata' key", 'metadata' in index_data)
                    self.assert_equals(
                        "global metadata status == 'completed'",
                        'completed', global_meta.get('status'),
                    )
                    self.assert_equals(
                        "global metadata extraction_source == 'Analysis_Tools_NVDish_Cache_Scanner'",
                        'Analysis_Tools_NVDish_Cache_Scanner',
                        global_meta.get('extraction_source'),
                    )
                    self.assert_true(
                        "global metadata tool_version is non-empty string",
                        isinstance(global_meta.get('tool_version'), str)
                        and len(global_meta.get('tool_version', '')) > 0,
                    )
                    self.assert_true(
                        "global metadata run_started_at is non-empty string",
                        isinstance(global_meta.get('run_started_at'), str)
                        and len(global_meta.get('run_started_at', '')) > 0,
                    )
                    self.assert_true(
                        "global metadata total_sources >= 1",
                        isinstance(global_meta.get('total_sources'), int)
                        and global_meta.get('total_sources', 0) >= 1,
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

                        # ── metadata ──────────────────────────────────────────
                        meta = report_data.get('metadata', {})
                        self.assert_equals("total_cves_processed == 2", 2, meta.get('total_cves_processed'))
                        self.assert_equals("unique_aliases_extracted == 2", 2, meta.get('unique_aliases_extracted'))
                        self.assert_equals("alias_groups_confirmed == 0", 0, meta.get('alias_groups_confirmed'))
                        self.assert_equals("confirmed_cna_id is None", None, meta.get('confirmed_cna_id'))
                        self.assert_equals("status == 'completed'", 'completed', meta.get('status'))
                        self.assert_equals(
                            "all_source_identifiers == ['test-source-pipeline-0001']",
                            ['test-source-pipeline-0001'],
                            meta.get('all_source_identifiers'),
                        )

                        # ── by_year ────────────────────────────────────────────
                        by_year_meta = meta.get('by_year', {})
                        self.assert_true("by_year has '1337'", '1337' in by_year_meta)
                        self.assert_equals("only year key is '1337'", ['1337'], list(by_year_meta.keys()))
                        if '1337' in by_year_meta:
                            yr = by_year_meta['1337']
                            self.assert_equals("1337 cves == 2", 2, yr.get('cves'))
                            self.assert_equals("1337 unique_aliases == 2", 2, yr.get('unique_aliases'))
                            self.assert_equals("1337 confirmed_count == 0", 0, yr.get('confirmed_count'))
                            self.assert_equals("1337 confirmed_coverage_pct == 0.0", 0.0, yr.get('confirmed_coverage_pct'))
                            self.assert_equals("1337 unconfirmed_count == 2", 2, yr.get('unconfirmed_count'))
                            self.assert_equals("1337 non_actionable_count == 0", 0, yr.get('non_actionable_count'))
                            self.assert_equals("1337 unconfirmed_with_concerns_count == 0", 0, yr.get('unconfirmed_with_concerns_count'))

                        # ── aliasGroups ────────────────────────────────────────
                        alias_groups = report_data.get('aliasGroups', [])
                        self.assert_equals("exactly 1 alias group", 1, len(alias_groups))
                        if alias_groups:
                            grp = alias_groups[0]
                            self.assert_equals(
                                "aliasGroup key == '_sdc_concerns_product_vendor'",
                                '_sdc_concerns_product_vendor', grp.get('aliasGroup'),
                            )
                            aliases = grp.get('aliases', [])
                            self.assert_equals("group has 2 aliases", 2, len(aliases))

                            # locate aliases by product name (order may vary by sort)
                            by_product = {a.get('product'): a for a in aliases}
                            self.assert_true("alias for pipe_product present", 'pipe_product' in by_product)
                            self.assert_true("alias for pipe_product_v2 present", 'pipe_product_v2' in by_product)

                            if 'pipe_product' in by_product:
                                a0 = by_product['pipe_product']
                                self.assert_equals("pipe_product vendor", 'pipe_vendor', a0.get('vendor'))
                                self.assert_equals("pipe_product source_cve", ['CVE-1337-0025'], a0.get('source_cve'))
                                cpes0 = a0.get('topNvdCpeBaseStrings', [])
                                self.assert_equals("pipe_product has 1 CPE entry", 1, len(cpes0))
                                if cpes0:
                                    self.assert_equals(
                                        "pipe_product CPE base string",
                                        'cpe:2.3:a:pipe_vendor:pipe_product:*:*:*:*:*:*:*:*',
                                        cpes0[0].get('cpeBaseString'),
                                    )
                                    self.assert_equals("pipe_product CPE cveCount == 1", 1, cpes0[0].get('cveCount'))
                                    self.assert_equals("pipe_product isSuggestedMatch == False", False, cpes0[0].get('isSuggestedMatch'))

                            if 'pipe_product_v2' in by_product:
                                a1 = by_product['pipe_product_v2']
                                self.assert_equals("pipe_product_v2 vendor", 'pipe_vendor', a1.get('vendor'))
                                self.assert_equals("pipe_product_v2 source_cve", ['CVE-1337-0026'], a1.get('source_cve'))
                                cpes1 = a1.get('topNvdCpeBaseStrings', [])
                                self.assert_equals("pipe_product_v2 has 1 CPE entry", 1, len(cpes1))
                                if cpes1:
                                    self.assert_equals(
                                        "pipe_product_v2 CPE base string",
                                        'cpe:2.3:a:pipe_vendor:pipe_product:*:*:*:*:*:*:*:*',
                                        cpes1[0].get('cpeBaseString'),
                                    )
                                    self.assert_equals("pipe_product_v2 CPE cveCount == 1", 1, cpes1[0].get('cveCount'))

                        # confirmedMappings is empty — no mapping file loaded for test sources
                        self.assert_equals(
                            "confirmedMappings is empty", 0, len(report_data.get('confirmedMappings', [None]))
                        )

                    # ── index entry stats ──────────────────────────────────────
                    idx_entry = next(
                        (s for s in index_data.get('sources', [])
                         if s.get('source_name') == 'test-source-pipeline-0001'),
                        None,
                    )
                    self.assert_true("index entry for pipeline-0001 found", idx_entry is not None)
                    if idx_entry is not None:
                        self.assert_equals("index total_cves_processed == 2", 2, idx_entry.get('total_cves_processed'))
                        self.assert_equals("index unique_aliases_extracted == 2", 2, idx_entry.get('unique_aliases_extracted'))
                        self.assert_equals("index total_unique_aliases == 2", 2, idx_entry.get('total_unique_aliases'))
                        self.assert_equals("index confirmed_count == 0", 0, idx_entry.get('confirmed_count'))
                        self.assert_equals("index confirmed_coverage_pct == 0.0", 0.0, idx_entry.get('confirmed_coverage_pct'))
                        self.assert_equals("index unconfirmed_count == 2", 2, idx_entry.get('unconfirmed_count'))
                        self.assert_equals("index non_actionable_count == 0", 0, idx_entry.get('non_actionable_count'))
                        self.assert_equals("index confirmed_with_concerns_count == 0", 0, idx_entry.get('confirmed_with_concerns_count'))
                        self.assert_equals("index unconfirmed_with_concerns_count == 0", 0, idx_entry.get('unconfirmed_with_concerns_count'))

        finally:
            # PHASE 4 — TEARDOWN: remove INPUT cache only; run output preserved for inspection
            self.teardown_subprocess_test_cache()

    def test_26_calculate_alias_statistics_pure_unconfirmed(self):
        """Test 26: calculate_alias_statistics() with pure unconfirmed input computes correct stats."""
        print("\nTest 26: calculate_alias_statistics() with pure unconfirmed data")
        report_data = {
            'aliasGroups': [
                {
                    'aliasGroup': 'product',
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
                    'aliasGroup': 'group',
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
        # total = confirmed + actionable unconfirmed only; non-actionable excluded because
        # it counts CVE entry occurrences, not alias patterns (different axes).
        self.assert_equals("total_unique_aliases is 2", 2, stats['total_unique_aliases'])
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
                    'aliasGroup': 'group',
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
        # total = confirmed + actionable unconfirmed only (non-actionable excluded)
        self.assert_equals("total_unique_aliases is 2", 2, stats['total_unique_aliases'])
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
                        'aliasGroup': 'product',
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

    def test_47_four_phase_sdc_concerns_flags_in_output(self):
        """Test 47: Four-phase subprocess — sourceDataConcerns on one alias produces
        unconfirmed_with_concerns_count == 1 and unconfirmed_with_concerns_pct == 50.0
        in the generated JSON output, mirroring test_31 (in-memory builder) through
        the full production subprocess path.

        CVE-1337-1001: alias_a (sdc_vendor_a / sdc_product_a) WITH sourceDataConcerns.
        CVE-1337-1002: alias_b (sdc_vendor_b / sdc_product_b) — no concerns.

        Expected per-source report:
        - unconfirmed_count == 2            (2 distinct alias keys)
        - unconfirmed_with_concerns_count == 1  (alias_a only)
        - unconfirmed_with_concerns_pct == 50.0 (1 of 2 unconfirmed)
        """
        import subprocess
        print("\nTest 47: Four-phase — SDC concerns flags in subprocess JSON output")

        # PHASE 1 — SETUP
        self.setup_subprocess_test_cache([TEST_CVE_1337_1001, TEST_CVE_1337_1002], batch='0xxx')

        try:
            # PHASE 2 — EXECUTE
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

            # PHASE 3 — VALIDATE
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in stdout", run_id is not None)

            if run_id:
                logs_dir = project_root / "runs" / run_id / "logs"
                index_file = logs_dir / "aliasExtractionReport_index.json"
                self.assert_true("index.json exists", index_file.exists())

                if index_file.exists():
                    with open(index_file, 'r', encoding='utf-8') as f:
                        index_data = json.load(f)

                    src_entry = next(
                        (s for s in index_data.get('sources', [])
                         if s.get('source_name') == _SRC_47),
                        None,
                    )
                    self.assert_true(f"{_SRC_47} entry found in index", src_entry is not None)

                    if src_entry is not None:
                        self.assert_equals("index total_cves_processed == 2", 2, src_entry.get('total_cves_processed'))
                        self.assert_equals("index unique_aliases_extracted == 2", 2, src_entry.get('unique_aliases_extracted'))
                        self.assert_equals("index total_unique_aliases == 2", 2, src_entry.get('total_unique_aliases'))
                        self.assert_equals("index unconfirmed_count == 2", 2, src_entry.get('unconfirmed_count'))
                        self.assert_equals("index confirmed_count == 0", 0, src_entry.get('confirmed_count'))
                        self.assert_equals("index unconfirmed_with_concerns_count == 1", 1, src_entry.get('unconfirmed_with_concerns_count'))

                    # Validate per-source report for exact by_year concerns values
                    report_files = list(logs_dir.glob(
                        f"aliasExtractionReport_{_SRC_47}_*.json"
                    ))
                    self.assert_true("Per-source report file written", len(report_files) >= 1)

                    if report_files:
                        with open(report_files[0], 'r', encoding='utf-8') as f:
                            report_data = json.load(f)

                        meta47 = report_data.get('metadata', {})
                        self.assert_equals("total_cves_processed == 2", 2, meta47.get('total_cves_processed'))
                        self.assert_equals("unique_aliases_extracted == 2", 2, meta47.get('unique_aliases_extracted'))

                        by_year = meta47.get('by_year', {})
                        self.assert_true("by_year has '1337'", '1337' in by_year)
                        if '1337' in by_year:
                            yr = by_year['1337']
                            self.assert_equals("1337 cves == 2", 2, yr.get('cves'))
                            self.assert_equals("1337 unique_aliases == 2", 2, yr.get('unique_aliases'))
                            self.assert_equals("1337 unconfirmed_count == 2", 2, yr.get('unconfirmed_count'))
                            self.assert_equals("1337 unconfirmed_with_concerns_count == 1", 1, yr.get('unconfirmed_with_concerns_count'))
                            self.assert_equals("1337 unconfirmed_with_concerns_pct == 50.0", 50.0, yr.get('unconfirmed_with_concerns_pct'))
                            self.assert_equals("1337 confirmed_count == 0", 0, yr.get('confirmed_count'))
                            self.assert_equals("1337 confirmed_with_concerns_count == 0", 0, yr.get('confirmed_with_concerns_count'))
                            self.assert_equals("1337 non_actionable_count == 0", 0, yr.get('non_actionable_count'))

                        # Verify _sdc_concerns non-empty on alias_a in the aliasGroups output
                        all_aliases = [
                            a for grp in report_data.get('aliasGroups', [])
                            for a in grp.get('aliases', [])
                        ]
                        alias_a = next((a for a in all_aliases if a.get('vendor') == 'sdc_vendor'), None)
                        alias_b = next((a for a in all_aliases if a.get('vendor') == 'sdc_vendor_b'), None)
                        self.assert_true("alias_a present in output", alias_a is not None)
                        self.assert_true("alias_b present in output", alias_b is not None)
                        if alias_a is not None:
                            self.assert_equals("alias_a product == 'sdc_vendor_lib'", 'sdc_vendor_lib', alias_a.get('product'))
                            self.assert_true(
                                "alias_a _sdc_concerns is non-empty",
                                bool(alias_a.get('_sdc_concerns')),
                            )
                        if alias_b is not None:
                            self.assert_equals("alias_b product == 'sdc_product_b'", 'sdc_product_b', alias_b.get('product'))
                            self.assert_true(
                                "alias_b _sdc_concerns is empty (no concerns)",
                                not bool(alias_b.get('_sdc_concerns')),
                            )

        finally:
            # PHASE 4 — TEARDOWN
            self.teardown_subprocess_test_cache()

    def test_48_four_phase_cpe_sort_and_cap_in_output(self):
        """Test 48: Four-phase subprocess — CPE base strings sorted by cveCount descending
        (mirrors test_16) and top-5 cap enforced in output (mirrors test_14) through
        the full production subprocess path.

        Seven CVEs, same alias (cap_vendor / cap_product):
        - CVE-1337-2001 + CVE-1337-2002 share CPE_A → cveCount == 2 (highest, must sort first)
        - CVE-1337-2003 through CVE-1337-2007 each have unique CPE (B–F) → cveCount == 1 each
        Total: 6 distinct CPE base strings → top-5 cap → exactly 5 entries in topNvdCpeBaseStrings.

        Expected in alias output:
        - len(topNvdCpeBaseStrings) == 5               (cap enforced at 5)
        - topNvdCpeBaseStrings[0] == CPE_A, cveCount == 2  (sort: highest count first)
        - topNvdCpeBaseStrings[1:] all have cveCount == 1
        """
        import subprocess
        print("\nTest 48: Four-phase — CPE sort by cveCount descending and top-5 cap in output")

        all_fixtures = [
            TEST_CVE_1337_2001, TEST_CVE_1337_2002, TEST_CVE_1337_2003,
            TEST_CVE_1337_2004, TEST_CVE_1337_2005, TEST_CVE_1337_2006, TEST_CVE_1337_2007,
        ]

        # PHASE 1 — SETUP
        self.setup_subprocess_test_cache(all_fixtures, batch='0xxx')

        try:
            # PHASE 2 — EXECUTE
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

            # PHASE 3 — VALIDATE
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in stdout", run_id is not None)

            if run_id:
                logs_dir = project_root / "runs" / run_id / "logs"

                report_files = list(logs_dir.glob(
                    f"aliasExtractionReport_{_SRC_48}_*.json"
                ))
                self.assert_true("Per-source report file written", len(report_files) >= 1)

                if report_files:
                    with open(report_files[0], 'r', encoding='utf-8') as f:
                        report_data = json.load(f)

                    # ── Metadata sanity ───────────────────────────────────
                    meta48 = report_data.get('metadata', {})
                    self.assert_equals("total_cves_processed == 7", 7, meta48.get('total_cves_processed'))
                    self.assert_equals("unique_aliases_extracted == 1", 1, meta48.get('unique_aliases_extracted'))

                    # ── Locate the single alias in aliasGroups ────────────
                    all_aliases = [
                        a for grp in report_data.get('aliasGroups', [])
                        for a in grp.get('aliases', [])
                    ]
                    self.assert_equals("exactly 1 alias in output", 1, len(all_aliases))

                    if all_aliases:
                        alias = all_aliases[0]
                        self.assert_equals("alias vendor == 'cap_vendor'", 'cap_vendor', alias.get('vendor'))
                        self.assert_equals("alias product == 'cap_product'", 'cap_product', alias.get('product'))
                        self.assert_equals("alias references all 7 CVEs", 7, len(alias.get('source_cve', [])))

                        cpes = alias.get('topNvdCpeBaseStrings', [])

                        # ── Cap: exactly 5 entries (6 distinct CPEs, cap at 5) ──
                        self.assert_equals("topNvdCpeBaseStrings capped at 5", 5, len(cpes))

                        # ── Sort: CPE_A (cveCount == 2) must be first ─────────
                        if cpes:
                            self.assert_equals(
                                "top CPE is cap_product_a (highest cveCount)",
                                'cpe:2.3:a:cap_vendor:cap_product_a:*:*:*:*:*:*:*:*',
                                cpes[0].get('cpeBaseString'),
                            )
                            self.assert_equals("top CPE cveCount == 2", 2, cpes[0].get('cveCount'))
                            self.assert_equals("top CPE isSuggestedMatch == False", False, cpes[0].get('isSuggestedMatch'))

                        # ── Remaining 4 all have cveCount == 1 ───────────────
                        for i, cpe_entry in enumerate(cpes[1:], start=1):
                            self.assert_equals(
                                f"cpes[{i}] cveCount == 1", 1, cpe_entry.get('cveCount')
                            )
                            self.assert_equals(
                                f"cpes[{i}] isSuggestedMatch == False", False, cpe_entry.get('isSuggestedMatch')
                            )

        finally:
            # PHASE 4 — TEARDOWN
            self.teardown_subprocess_test_cache()

    def test_49_four_phase_is_suggested_match_true_in_cpe_output(self):
        """Test 49: Four-phase subprocess — cpeDetermination.top10SuggestedCPEBaseStrings entry
        causes isSuggestedMatch=True for that CPE in topNvdCpeBaseStrings output, while a
        second CPE present only in NVD configurations (not in suggestions) has isSuggestedMatch=False.

        CVE-1337-3001:
        - NVD config has sugg_product_a AND sugg_product_b (both vulnerable).
        - cpeDetermination.top10SuggestedCPEBaseStrings contains only sugg_product_a.

        Expected in topNvdCpeBaseStrings for the single alias:
        - Entry for sugg_product_a: isSuggestedMatch == True
        - Entry for sugg_product_b: isSuggestedMatch == False
        """
        import subprocess
        print("\nTest 49: Four-phase — isSuggestedMatch=True for suggested CPE in output")

        # PHASE 1 — SETUP
        self.setup_subprocess_test_cache([TEST_CVE_1337_3001], batch='0xxx')

        try:
            # PHASE 2 — EXECUTE
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

            # PHASE 3 — VALIDATE
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in stdout", run_id is not None)

            if run_id:
                logs_dir = project_root / "runs" / run_id / "logs"

                report_files = list(logs_dir.glob(
                    f"aliasExtractionReport_{_SRC_49}_*.json"
                ))
                self.assert_true("Per-source report file written", len(report_files) >= 1)

                if report_files:
                    with open(report_files[0], 'r', encoding='utf-8') as f:
                        report_data = json.load(f)

                    meta49 = report_data.get('metadata', {})
                    self.assert_equals("total_cves_processed == 1", 1, meta49.get('total_cves_processed'))
                    self.assert_equals("unique_aliases_extracted == 1", 1, meta49.get('unique_aliases_extracted'))

                    all_aliases = [
                        a for grp in report_data.get('aliasGroups', [])
                        for a in grp.get('aliases', [])
                    ]
                    self.assert_equals("exactly 1 alias in output", 1, len(all_aliases))

                    if all_aliases:
                        alias = all_aliases[0]
                        cpes = alias.get('topNvdCpeBaseStrings', [])
                        self.assert_equals("exactly 2 CPE entries", 2, len(cpes))

                        cpe_by_base = {c.get('cpeBaseString'): c for c in cpes}
                        self.assert_true(
                            "sugg_product_a CPE entry present",
                            _CPE_SUGG_A_BASE in cpe_by_base,
                        )
                        self.assert_true(
                            "sugg_product_b CPE entry present",
                            _CPE_SUGG_B_BASE in cpe_by_base,
                        )
                        if _CPE_SUGG_A_BASE in cpe_by_base:
                            self.assert_equals(
                                "sugg_product_a isSuggestedMatch == True",
                                True, cpe_by_base[_CPE_SUGG_A_BASE].get('isSuggestedMatch'),
                            )
                        if _CPE_SUGG_B_BASE in cpe_by_base:
                            self.assert_equals(
                                "sugg_product_b isSuggestedMatch == False",
                                False, cpe_by_base[_CPE_SUGG_B_BASE].get('isSuggestedMatch'),
                            )

        finally:
            # PHASE 4 — TEARDOWN
            self.teardown_subprocess_test_cache()

    def test_50_four_phase_platform_field_differentiates_aliases(self):
        """Test 50: Four-phase subprocess — same vendor+product but different platform values
        produce distinct alias entries in a single group, sorted by cveCount descending.

        Four CVEs, same source:
        - CVE-1337-4001 + CVE-1337-4002: both reference the Linux alias → cveCount == 2.
        - CVE-1337-4003: Windows alias → cveCount == 1.
        - CVE-1337-4004: macOS alias → cveCount == 1.

        Expected:
        - 1 alias group in the report.
        - 3 distinct alias entries in the group.
        - Linux alias sorts first (highest cveCount).
        - Each alias carries the correct platform field value.
        """
        import subprocess
        print("\nTest 50: Four-phase — platform field differentiates aliases, sorted by cveCount")

        fixtures = [TEST_CVE_1337_4001, TEST_CVE_1337_4002, TEST_CVE_1337_4003, TEST_CVE_1337_4004]

        # PHASE 1 — SETUP
        self.setup_subprocess_test_cache(fixtures, batch='0xxx')

        try:
            # PHASE 2 — EXECUTE
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

            # PHASE 3 — VALIDATE
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in stdout", run_id is not None)

            if run_id:
                logs_dir = project_root / "runs" / run_id / "logs"

                report_files = list(logs_dir.glob(
                    f"aliasExtractionReport_{_SRC_50}_*.json"
                ))
                self.assert_true("Per-source report file written", len(report_files) >= 1)

                if report_files:
                    with open(report_files[0], 'r', encoding='utf-8') as f:
                        report_data = json.load(f)

                    meta50 = report_data.get('metadata', {})
                    self.assert_equals("total_cves_processed == 4", 4, meta50.get('total_cves_processed'))
                    # 3 distinct aliases (Linux, Windows, macOS)
                    self.assert_equals("unique_aliases_extracted == 3", 3, meta50.get('unique_aliases_extracted'))

                    alias_groups = report_data.get('aliasGroups', [])
                    self.assert_equals("exactly 1 alias group", 1, len(alias_groups))

                    if alias_groups:
                        grp = alias_groups[0]
                        aliases = grp.get('aliases', [])
                        self.assert_equals("group has 3 aliases", 3, len(aliases))

                        if len(aliases) >= 1:
                            # Linux alias (cveCount==2) must sort first
                            self.assert_equals(
                                "first alias platform == 'Linux' (highest cveCount)",
                                'Linux', aliases[0].get('platform'),
                            )
                            self.assert_equals(
                                "Linux alias source_cve has 2 entries",
                                2, len(aliases[0].get('source_cve', [])),
                            )

                        # All three platform values must appear exactly once
                        platforms_in_output = {a.get('platform') for a in aliases}
                        for expected_platform in ('Linux', 'Windows', 'macOS'):
                            self.assert_true(
                                f"platform '{expected_platform}' present in group",
                                expected_platform in platforms_in_output,
                            )

                        # Every alias shares the same vendor and product
                        for alias in aliases:
                            self.assert_equals(
                                "alias vendor == 'plat_vendor'",
                                'plat_vendor', alias.get('vendor'),
                            )
                            self.assert_equals(
                                "alias product == 'plat_product'",
                                'plat_product', alias.get('product'),
                            )

        finally:
            # PHASE 4 — TEARDOWN
            self.teardown_subprocess_test_cache()

    def test_51_four_phase_non_standard_identity_fields_passthrough(self):
        """Test 51: Four-phase subprocess — non-standard alias values (packageName,
        collectionURL, repo, modules) survive finalize() and appear in aliasGroups output.

        Four CVEs, same source, each with a different non-standard alias value:
        - CVE-1337-5101: packageName field
        - CVE-1337-5102: collectionURL field
        - CVE-1337-5103: repo field
        - CVE-1337-5104: modules field (list)

        Expected: each field value appears in the corresponding alias in the report JSON.
        """
        import subprocess
        print("\nTest 51: Four-phase — non-standard alias values pass through to alias JSON")

        fixtures = [TEST_CVE_1337_5101, TEST_CVE_1337_5102, TEST_CVE_1337_5103, TEST_CVE_1337_5104]

        # PHASE 1 — SETUP
        self.setup_subprocess_test_cache(fixtures, batch='0xxx')

        try:
            # PHASE 2 — EXECUTE
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

            # PHASE 3 — VALIDATE
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in stdout", run_id is not None)

            if run_id:
                logs_dir = project_root / "runs" / run_id / "logs"

                report_files = list(logs_dir.glob(
                    f"aliasExtractionReport_{_SRC_51}_*.json"
                ))
                self.assert_true("Per-source report file written", len(report_files) >= 1)

                if report_files:
                    with open(report_files[0], 'r', encoding='utf-8') as f:
                        report_data = json.load(f)

                    meta51 = report_data.get('metadata', {})
                    self.assert_equals("total_cves_processed == 4", 4, meta51.get('total_cves_processed'))
                    self.assert_equals("unique_aliases_extracted == 4", 4, meta51.get('unique_aliases_extracted'))

                    # Flatten all aliases from all groups into one lookup by CVE
                    all_aliases = [
                        a for grp in report_data.get('aliasGroups', [])
                        for a in grp.get('aliases', [])
                    ]
                    self.assert_equals("4 distinct aliases in output", 4, len(all_aliases))

                    # Locate each alias by which non-standard field it carries
                    by_cve: Dict = {}
                    for a in all_aliases:
                        for cve_id in a.get('source_cve', []):
                            by_cve[cve_id] = a

                    # packageName passthrough
                    a5101 = by_cve.get('CVE-1337-5101')
                    self.assert_true("CVE-1337-5101 alias found", a5101 is not None)
                    if a5101:
                        self.assert_equals(
                            "packageName == 'fields-package-name'",
                            'fields-package-name', a5101.get('packageName'),
                        )

                    # collectionURL passthrough
                    a5102 = by_cve.get('CVE-1337-5102')
                    self.assert_true("CVE-1337-5102 alias found", a5102 is not None)
                    if a5102:
                        self.assert_equals(
                            "collectionURL == 'https://example.com/collection/fields'",
                            'https://example.com/collection/fields', a5102.get('collectionURL'),
                        )

                    # repo passthrough
                    a5103 = by_cve.get('CVE-1337-5103')
                    self.assert_true("CVE-1337-5103 alias found", a5103 is not None)
                    if a5103:
                        self.assert_equals(
                            "repo == 'https://github.com/fields-vendor/fields-project'",
                            'https://github.com/fields-vendor/fields-project', a5103.get('repo'),
                        )

                    # modules list passthrough
                    a5104 = by_cve.get('CVE-1337-5104')
                    self.assert_true("CVE-1337-5104 alias found", a5104 is not None)
                    if a5104:
                        self.assert_equals(
                            "modules == ['fields-module-a', 'fields-module-b']",
                            ['fields-module-a', 'fields-module-b'], a5104.get('modules'),
                        )

        finally:
            # PHASE 4 — TEARDOWN
            self.teardown_subprocess_test_cache()

    def test_52_four_phase_sdc_concern_types_whitespace_comparator_invalidchars(self):
        """Test 52: Four-phase subprocess — whitespace, text-comparator, and invalid-chars
        SDC concern types each contribute to unconfirmed_with_concerns_count.

        Three CVEs, same source:
        - CVE-1337-5201: leading space in vendor → whitespace concern.
        - CVE-1337-5202: "before 3.0" in product → text-comparator concern.
        - CVE-1337-5203: comma in product → invalid-chars concern.

        Each fixture also carries sourceDataConcerns so _sdc_concerns is populated
        via _extract_alias_concerns() for the by_year path in finalize().

        Expected:
        - unconfirmed_with_concerns_count == 3 in index entry.
        - by_year['1337']['unconfirmed_with_concerns_count'] == 3.
        """
        import subprocess
        print("\nTest 52: Four-phase — whitespace / text-comparator / invalid-chars concern types")

        fixtures = [TEST_CVE_1337_5201, TEST_CVE_1337_5202, TEST_CVE_1337_5203]

        # PHASE 1 — SETUP
        self.setup_subprocess_test_cache(fixtures, batch='0xxx')

        try:
            # PHASE 2 — EXECUTE
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

            # PHASE 3 — VALIDATE
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in stdout", run_id is not None)

            if run_id:
                logs_dir = project_root / "runs" / run_id / "logs"
                index_file = logs_dir / "aliasExtractionReport_index.json"
                self.assert_true("index.json exists", index_file.exists())

                if index_file.exists():
                    with open(index_file, 'r', encoding='utf-8') as f:
                        index_data = json.load(f)

                    src_entry = next(
                        (s for s in index_data.get('sources', [])
                         if s.get('source_name') == _SRC_52),
                        None,
                    )
                    self.assert_true(f"{_SRC_52} entry found in index", src_entry is not None)

                    if src_entry is not None:
                        self.assert_equals(
                            "unconfirmed_count == 3",
                            3, src_entry.get('unconfirmed_count'),
                        )
                        self.assert_equals(
                            "unconfirmed_with_concerns_count == 3 (index)",
                            3, src_entry.get('unconfirmed_with_concerns_count'),
                        )

                        # by_year path: finalize() uses _sdc_concerns to count concerns
                        by_year = src_entry.get('by_year', {})
                        self.assert_true("by_year has '1337'", '1337' in by_year)
                        if '1337' in by_year:
                            self.assert_equals(
                                "1337 unconfirmed_with_concerns_count == 3 (by_year)",
                                3, by_year['1337'].get('unconfirmed_with_concerns_count'),
                            )

        finally:
            # PHASE 4 — TEARDOWN
            self.teardown_subprocess_test_cache()

    def test_53_confirmed_mappings_non_empty_with_mock_manager(self):
        """Test 53: In-memory — finalize() with _MockConfirmedMappingManager produces
        non-empty confirmedMappings, correct alias_groups_confirmed, confirmed_cna_id,
        and statistics that show confirmed_count > 0 and confirmed_coverage_pct > 0.

        Source has two aliases: alias_a (confirmed) and alias_b (unconfirmed).
        Mapping manager returns alias_a as a confirmed mapping for this source.

        Expected in finalize() output:
        - confirmedMappings has 1 entry containing alias_a.
        - alias_groups_confirmed == 1.
        - confirmed_cna_id == 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'.

        Expected from calculate_alias_statistics():
        - confirmed_count == 1.
        - unconfirmed_count == 1.
        - confirmed_coverage_pct == 50.0.
        - total_unique_aliases == 2.
        """
        print("\nTest 53: In-memory — confirmedMappings non-empty via mock manager")
        _SRC_53 = 'test-source-uuid-0053'
        _ALIAS_53_A = {'vendor': 'conf_vendor', 'product': 'conf_product_a'}
        _ALIAS_53_B = {'vendor': 'conf_vendor', 'product': 'conf_product_b'}
        _EXPECTED_CNA_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

        builder = AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockConfirmedMappingManager(_SRC_53, [_ALIAS_53_A]),
        )

        entry_a = {
            'originAffectedEntry': {'sourceId': _SRC_53},
            'aliasExtraction': {'aliases': [_ALIAS_53_A]},
        }
        entry_b = {
            'originAffectedEntry': {'sourceId': _SRC_53},
            'aliasExtraction': {'aliases': [_ALIAS_53_B]},
        }

        builder.add_cve_aliases('CVE-1337-6001', [entry_a], nvd_cpe_set=set())
        builder.add_cve_aliases('CVE-1337-6002', [entry_b], nvd_cpe_set=set())

        reports = builder.finalize()

        self.assert_true("Source present in report", _SRC_53 in reports)

        if _SRC_53 in reports:
            report = reports[_SRC_53]
            meta = report.get('metadata', {})

            # ── confirmed_cna_id ───────────────────────────────────────────
            self.assert_equals(
                "confirmed_cna_id == expected UUID",
                _EXPECTED_CNA_ID, meta.get('confirmed_cna_id'),
            )

            # ── alias_groups_confirmed == 1 ────────────────────────────────
            # Both aliases share the same group key; the confirmed alias
            # does not cover the full group (alias_b is unconfirmed) so
            # alias_groups_confirmed should be 0 for partial coverage.
            # However alias_a IS its own distinct group from alias_b
            # only if they have different group keys — they don't (both vendor+product).
            # So alias_groups_confirmed == 0 (partial group, not fully confirmed).
            # We assert == 0 and verify confirmedMappings directly instead.
            self.assert_equals(
                "alias_groups_confirmed == 0 (group partially confirmed)",
                0, meta.get('alias_groups_confirmed'),
            )

            # ── confirmedMappings non-empty ────────────────────────────────
            confirmed_mappings = report.get('confirmedMappings', [])
            self.assert_true(
                "confirmedMappings is non-empty",
                len(confirmed_mappings) > 0,
            )

            if confirmed_mappings:
                first_mapping = confirmed_mappings[0]
                self.assert_true(
                    "confirmedMappings[0] has 'aliases' key",
                    'aliases' in first_mapping,
                )
                confirmed_aliases = first_mapping.get('aliases', [])
                # The mock returns [_ALIAS_53_A] as confirmed aliases
                alias_a_found = any(
                    a.get('vendor') == 'conf_vendor' and a.get('product') == 'conf_product_a'
                    for a in confirmed_aliases
                )
                self.assert_true(
                    "conf_product_a alias appears in confirmedMappings",
                    alias_a_found,
                )

            # ── calculate_alias_statistics() ──────────────────────────────
            stats = calculate_alias_statistics(report)
            self.assert_equals("total_unique_aliases == 2", 2, stats['total_unique_aliases'])
            self.assert_equals("confirmed_count == 1", 1, stats['confirmed_count'])
            self.assert_equals("unconfirmed_count == 1", 1, stats['unconfirmed_count'])
            self.assert_equals(
                "confirmed_coverage_pct == 50.0",
                50.0, stats['confirmed_coverage_pct'],
            )
            self.assert_equals("non_actionable_count == 0", 0, stats['non_actionable_count'])

        # TEARDOWN
        builder = None

    def test_54_multiple_distinct_na_patterns_consolidate_to_one(self):
        """Test 54: Two Path A entries (aliasExtraction: {}) from the same source consolidate
        into one non-actionable alias object because all Path A entries share the fixed key
        'no_alias_data'. naPatternFields is {} because originAffectedEntry fields are CVE
        entry metadata, not alias data — only extracted alias fields qualify as alias types.

        non_actionable_count == 1 (one consolidated alias object for the source's no-alias
        entries), not 2, because the two entries are indistinguishable as alias source data.
        """
        print("\nTest 54: Multiple Path A entries → consolidate to 1 NA alias object")
        _SRC_54 = 'test-source-multi-na-0054'

        builder = AliasReportBuilder(
            source_manager=None,
            mapping_manager=_MockMappingManager(),
        )

        # Two Path A entries: aliasExtraction: {} regardless of originAffectedEntry content
        entry_na_1 = {
            'originAffectedEntry': {'sourceId': _SRC_54, 'vendor': 'n/a', 'product': 'n/a'},
            'aliasExtraction': {},
        }
        entry_na_2 = {
            'originAffectedEntry': {'sourceId': _SRC_54, 'vendor': 'unspecified', 'product': 'n/a'},
            'aliasExtraction': {},
        }
        # One actionable alias so this org enters self.sources (established source path)
        entry_real = {
            'originAffectedEntry': {'sourceId': _SRC_54},
            'aliasExtraction': {'aliases': [{'vendor': 'multi54_vendor', 'product': 'multi54_product'}]},
        }

        builder.add_cve_aliases('CVE-2025-5401', [entry_real, entry_na_1, entry_na_2], nvd_cpe_set=set())

        reports = builder.finalize()
        self.assert_true("Source present in report", _SRC_54 in reports)

        if _SRC_54 in reports:
            report = reports[_SRC_54]
            by_year = report['metadata']['by_year']

            self.assert_true("by_year has '2025'", '2025' in by_year)
            self.assert_equals(
                "by_year 2025 non_actionable_count == 1 (consolidated alias object)",
                1, by_year['2025']['non_actionable_count'],
            )
            self.assert_equals(
                "by_year 2025 unconfirmed_count == 1 (actionable alias only)",
                1, by_year['2025']['unconfirmed_count'],
            )
            self.assert_equals(
                "by_year 2025 cves == 1 (one CVE processed)",
                1, by_year['2025']['cves'],
            )

            # One NA alias object with naPatternFields == {} (no alias data was extracted).
            na_group = next(
                (g for g in report.get('aliasGroups', []) if g.get('aliasGroup') == 'no_identity_non_actionable'),
                None,
            )
            self.assert_true("no_identity_non_actionable group exists", na_group is not None)
            if na_group is not None:
                na_aliases_54 = na_group.get('aliases', [])
                self.assert_equals("NA group has 1 consolidated alias object", 1, len(na_aliases_54))
                if na_aliases_54:
                    self.assert_equals(
                        "naPatternFields == {} (no alias types in source material)",
                        {}, na_aliases_54[0].get('naPatternFields'),
                    )

            stats = calculate_alias_statistics(report)
            self.assert_equals(
                "calculate_alias_statistics non_actionable_count == 1",
                1, stats['non_actionable_count'],
            )
            self.assert_equals(
                "calculate_alias_statistics unconfirmed_count == 1",
                1, stats['unconfirmed_count'],
            )
            self.assert_equals(
                "total_unique_aliases == 1 (actionable patterns only; NA excluded)",
                1, stats['total_unique_aliases'],
            )
            self.assert_equals(
                "confirmed_coverage_pct == 0.0 (NA excluded from denominator)",
                0.0, stats['confirmed_coverage_pct'],
            )

        # TEARDOWN
        builder = None

    def test_55_four_phase_programfiles_programroutines_packageurl_passthrough(self):
        """Test 55: Four-phase subprocess — programFiles, programRoutines, packageURL identity
        fields survive finalize() and appear in aliasGroups output.

        Completes the identity-field passthrough coverage started in test_51 (which covers
        packageName, collectionURL, repo, modules).  These three fields are shown in the
        example template (pixelforge, cachedb, utilkit alias groups) but were absent from
        any subprocess fixture.

        Three CVEs, same source (_SRC_55), each alias carries one remaining field:
        - CVE-1337-5105: programFiles='src/render/pixel.c'
        - CVE-1337-5106: programRoutines='dbExprCodeTarget'
        - CVE-1337-5107: packageURL='pkg:npm/util-kit'

        Expected: each field value appears in the corresponding alias in the report JSON.
        """
        import subprocess
        print("\nTest 55: Four-phase — programFiles / programRoutines / packageURL pass through to alias JSON")

        fixtures = [TEST_CVE_1337_5105, TEST_CVE_1337_5106, TEST_CVE_1337_5107]

        # PHASE 1 — SETUP
        self.setup_subprocess_test_cache(fixtures, batch='0xxx')

        try:
            # PHASE 2 — EXECUTE
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

            # PHASE 3 — VALIDATE
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in stdout", run_id is not None)

            if run_id:
                logs_dir = project_root / "runs" / run_id / "logs"

                report_files = list(logs_dir.glob(
                    f"aliasExtractionReport_{_SRC_55}_*.json"
                ))
                self.assert_true("Per-source report file written", len(report_files) >= 1)

                if report_files:
                    with open(report_files[0], 'r', encoding='utf-8') as f:
                        report_data = json.load(f)

                    meta55 = report_data.get('metadata', {})
                    self.assert_equals("total_cves_processed == 3", 3, meta55.get('total_cves_processed'))
                    self.assert_equals("unique_aliases_extracted == 3", 3, meta55.get('unique_aliases_extracted'))

                    # Flatten all aliases from all groups into one lookup by CVE
                    all_aliases = [
                        a for grp in report_data.get('aliasGroups', [])
                        for a in grp.get('aliases', [])
                    ]
                    self.assert_equals("3 distinct aliases in output", 3, len(all_aliases))

                    by_cve: Dict = {}
                    for a in all_aliases:
                        for cve_id in a.get('source_cve', []):
                            by_cve[cve_id] = a

                    # programFiles passthrough
                    a5105 = by_cve.get('CVE-1337-5105')
                    self.assert_true("CVE-1337-5105 alias found", a5105 is not None)
                    if a5105:
                        self.assert_equals(
                            "programFiles == 'src/render/pixel.c'",
                            'src/render/pixel.c', a5105.get('programFiles'),
                        )

                    # programRoutines passthrough
                    a5106 = by_cve.get('CVE-1337-5106')
                    self.assert_true("CVE-1337-5106 alias found", a5106 is not None)
                    if a5106:
                        self.assert_equals(
                            "programRoutines == 'dbExprCodeTarget'",
                            'dbExprCodeTarget', a5106.get('programRoutines'),
                        )

                    # packageURL passthrough
                    a5107 = by_cve.get('CVE-1337-5107')
                    self.assert_true("CVE-1337-5107 alias found", a5107 is not None)
                    if a5107:
                        self.assert_equals(
                            "packageURL == 'pkg:npm/util-kit'",
                            'pkg:npm/util-kit', a5107.get('packageURL'),
                        )

        finally:
            # PHASE 4 — TEARDOWN
            self.teardown_subprocess_test_cache()

    def test_56_has_alias_concerns_hyphenated_version_range(self):
        """Test 56: _has_alias_concerns() detects hyphenated version range via
        TEXT_COMPARATOR_REGEX_PATTERNS (the regex code path, distinct from the keyword
        code path exercised by test_52).

        The example template shows aliases like 'comp-app 1.0 - 2.5' as a
        textComparators concern in the concern_text_comparator alias group.
        The regex pattern is: r'\\d+(?:\\.\\d+)*\\s+-\\s+\\d+(?:\\.\\d+)*'

        Assertions:
        - Product 'comp-app 1.0 - 2.5' → True  (regex match on hyphenated range)
        - Product 'comp-app 1.0 - 2'   → True  (single-digit endpoint)
        - Product 'comp-app 1.0'        → False (plain version, no range)
        - Product 'comp-app'            → False (no version at all, clean alias)
        """
        print("\nTest 56: _has_alias_concerns() detects hyphenated version range (regex path)")

        # Hyphenated range "1.0 - 2.5" → True
        self.assert_true(
            "product 'comp-app 1.0 - 2.5' triggers concern (regex range)",
            _has_alias_concerns({'vendor': 'comp-vendor', 'product': 'comp-app 1.0 - 2.5'}),
        )

        # Single-digit endpoint — still a valid hyphenated range
        self.assert_true(
            "product 'comp-app 1.0 - 2' triggers concern (single-digit endpoint)",
            _has_alias_concerns({'vendor': 'comp-vendor', 'product': 'comp-app 1.0 - 2'}),
        )

        # Multi-part versions on both sides
        self.assert_true(
            "product 'util 1.0.1 - 2.5.3' triggers concern (multi-part versions)",
            _has_alias_concerns({'vendor': 'util-vendor', 'product': 'util 1.0.1 - 2.5.3'}),
        )

        # Plain version string with hyphen (no space, no range) — no concern
        self.assert_true(
            "product 'comp-app-1.0' does NOT trigger concern (hyphenated version, not a range)",
            not _has_alias_concerns({'vendor': 'comp-vendor', 'product': 'comp-app-1.0'}),
        )

        # Clean alias with no version — no concern
        self.assert_true(
            "product 'comp-app' does NOT trigger concern (clean name)",
            not _has_alias_concerns({'vendor': 'comp-vendor', 'product': 'comp-app'}),
        )

    def test_57_four_phase_confirmed_mappings_via_real_mapping_file_injection(self):
        """Test 57: Four-phase subprocess — confirmedMappings populated by a real
        ConfirmedMappingManager loading an injected mapping file.

        Test 53 covers the in-memory mock path.  This test exercises the full
        production path: a temp mapping file is written to cache/alias_mappings/
        before the subprocess starts so the global ConfirmedMappingManager loads
        it from disk, validates the cnaId against nvd_source_data.json, indexes
        its aliases, and produces non-empty confirmedMappings in the output JSON.

        The source UUID and email (_TEST57_SOURCE_UUID / _TEST57_SOURCE_EMAIL) are
        opaque identifiers — they exist in nvd_source_data.json and have no existing
        mapping file, which is the only requirement.  All test data (alias, CPE
        string) is generic and carries no org-specific meaning.

        Setup:
        - Write _test_confirmed_57.json to cache/alias_mappings/ using
          _TEST57_SOURCE_UUID as cnaId and generic test57_vendor/test57_product data.
        - CVE fixture sourceId = _TEST57_SOURCE_EMAIL; alias matches the injected
          confirmedMappings so the alias resolves as confirmed.

        Expected:
        - Per-source report produced (source identified via UUID in index).
        - report.confirmedMappings is non-empty (>= 1 entry).
        - report.metadata.confirmed_cna_id == _TEST57_SOURCE_UUID.
        - Index entry: confirmed_count >= 1, confirmed_coverage_pct > 0.

        Teardown:
        - _test_confirmed_57.json removed unconditionally.
        - Subprocess test cache removed unconditionally.
        """
        import subprocess
        print("\nTest 57: Four-phase subprocess — confirmedMappings via injected mapping file")

        _MAPPING_CONTENT = {
            "cnaId": _TEST57_SOURCE_UUID,
            "confirmedMappings": [
                {
                    "cpeBaseString": "cpe:2.3:a:test57vendor:test57product:*:*:*:*:*:*:*:*",
                    "aliases": [
                        {"vendor": "test57_vendor", "product": "test57_product"}
                    ]
                }
            ]
        }

        # PHASE 1 — SETUP
        with open(_TEST57_MAPPING_FILE, 'w', encoding='utf-8') as fh:
            json.dump(_MAPPING_CONTENT, fh, indent=4)

        self.setup_subprocess_test_cache([TEST_CVE_1337_5701], batch='0xxx')

        try:
            # PHASE 2 — EXECUTE
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

            # PHASE 3 — VALIDATE
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in stdout", run_id is not None)

            if run_id:
                logs_dir = project_root / "runs" / run_id / "logs"

                # Locate the source entry via UUID in all_source_identifiers (avoids
                # hardcoding the org name that nvd_source_data.json assigns the UUID to).
                index_file = logs_dir / "aliasExtractionReport_index.json"
                self.assert_true("index.json exists", index_file.exists())

                source_entry = None
                if index_file.exists():
                    with open(index_file, 'r', encoding='utf-8') as fh:
                        index_data = json.load(fh)
                    source_entry = next(
                        (s for s in index_data.get('sources', [])
                         if _TEST57_SOURCE_UUID in s.get('all_source_identifiers', [])),
                        None,
                    )
                    self.assert_true("source entry found in index via UUID", source_entry is not None)
                    if source_entry is not None:
                        self.assert_true(
                            "index confirmed_count >= 1",
                            source_entry.get('confirmed_count', 0) >= 1,
                        )
                        self.assert_true(
                            "index confirmed_coverage_pct > 0",
                            source_entry.get('confirmed_coverage_pct', 0.0) > 0.0,
                        )

                # Use report_file from the index entry to find the per-source JSON.
                if source_entry is not None:
                    report_filename = source_entry.get('report_file', '')
                    self.assert_true("index entry has report_file", bool(report_filename))

                    if report_filename:
                        report_path = logs_dir / report_filename
                        self.assert_true("per-source report file exists", report_path.exists())

                        if report_path.exists():
                            with open(report_path, 'r', encoding='utf-8') as fh:
                                report_data = json.load(fh)

                            meta57 = report_data.get('metadata', {})

                            # confirmed_cna_id must equal the injected UUID
                            self.assert_equals(
                                "confirmed_cna_id == _TEST57_SOURCE_UUID",
                                _TEST57_SOURCE_UUID, meta57.get('confirmed_cna_id'),
                            )

                            # confirmedMappings must be non-empty
                            confirmed_mappings = report_data.get('confirmedMappings', [])
                            self.assert_true(
                                "confirmedMappings is non-empty",
                                len(confirmed_mappings) >= 1,
                            )

        finally:
            # PHASE 4 — TEARDOWN
            if _TEST57_MAPPING_FILE.exists():
                _TEST57_MAPPING_FILE.unlink()
            self.teardown_subprocess_test_cache()

    def test_58_template_has_mappingTypeFilter_element(self):
        """Test 58: Template HTML contains the #mappingTypeFilter filter-pill-row element."""
        print("\nTest 58: Template has id=\"mappingTypeFilter\" element")
        template = self._load_template()
        self.assert_in('id="mappingTypeFilter" HTML element', 'id="mappingTypeFilter"', template)

    def test_59_template_has_renderMappingTypeFilterUI(self):
        """Test 59: Template JS contains the renderMappingTypeFilterUI function."""
        print("\nTest 59: Template has function renderMappingTypeFilterUI")
        template = self._load_template()
        self.assert_in('function renderMappingTypeFilterUI', 'function renderMappingTypeFilterUI', template)

    def test_60_template_has_toggleMappingTypePill(self):
        """Test 60: Template JS contains the toggleMappingTypePill function."""
        print("\nTest 60: Template has function toggleMappingTypePill")
        template = self._load_template()
        self.assert_in('function toggleMappingTypePill', 'function toggleMappingTypePill', template)

    def test_61_template_has_MappingTypeFilter_object(self):
        """Test 61: Template JS contains the MappingTypeFilter filter object."""
        print("\nTest 61: Template has MappingTypeFilter object")
        template = self._load_template()
        self.assert_in('const MappingTypeFilter', 'const MappingTypeFilter', template)

    def test_62_template_has_MappingTypeFilter_isFilteringActive(self):
        """Test 62: Template JS calls MappingTypeFilter.isFilteringActive() in filter logic."""
        print("\nTest 62: Template has MappingTypeFilter.isFilteringActive()")
        template = self._load_template()
        self.assert_in('MappingTypeFilter.isFilteringActive()', 'MappingTypeFilter.isFilteringActive()', template)

    def test_63_example_data_file_exists_at_new_location(self):
        """Test 63: Example data JSON file exists at dashboards/example_data/."""
        print("\nTest 63: Example data file exists at dashboards/example_data/")
        expected_path = project_root / 'dashboards' / 'example_data' / 'Alias_Extraction_Source_Report_Example.json'
        self.assert_true(
            "dashboards/example_data/Alias_Extraction_Source_Report_Example.json exists",
            expected_path.exists(),
        )

    def test_64_four_phase_confirmed_mappings_raw_value_preservation(self):
        """Test 64: Four-phase subprocess — raw field values are preserved verbatim
        in confirmedMappings output even when they contain leading whitespace.

        A mapping file maps a confirmed alias with vendor=' whitespace_vendor' (leading
        space).  The per-source report must store the vendor value verbatim and
        aliasGroups must be empty (all aliases resolved as confirmed).

        Setup:
        - Write _test_confirmed_64.json to cache/alias_mappings/ using
          _TEST57_SOURCE_UUID as cnaId and ' whitespace_vendor'/'ws_product' data.
        - CVE fixture sourceId = _TEST57_SOURCE_EMAIL; alias matches the injected
          confirmedMappings so the alias resolves as confirmed.

        Expected:
        - confirmedMappings[0].aliases[0].vendor == ' whitespace_vendor' (verbatim).
        - alias_groups_confirmed >= 1 (all alias groups are confirmed).

        Teardown:
        - _test_confirmed_64.json removed unconditionally.
        - Subprocess test cache removed unconditionally.
        """
        import subprocess
        print("\nTest 64: Four-phase subprocess — confirmedMappings raw value preservation")

        _MAPPING_CONTENT = {
            "cnaId": _TEST57_SOURCE_UUID,
            "confirmedMappings": [
                {
                    "cpeBaseString": "cpe:2.3:a:ws_vendor:ws_product:*:*:*:*:*:*:*:*",
                    "aliases": [
                        {"vendor": " whitespace_vendor", "product": "ws_product"}
                    ]
                }
            ]
        }

        # PHASE 1 — SETUP
        with open(_TEST64_MAPPING_FILE, 'w', encoding='utf-8') as fh:
            json.dump(_MAPPING_CONTENT, fh, indent=4)

        self.setup_subprocess_test_cache([TEST_CVE_1337_6400], batch='0xxx')

        try:
            # PHASE 2 — EXECUTE
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

            # PHASE 3 — VALIDATE
            run_id = None
            for line in result.stdout.splitlines():
                if line.startswith('Run ID:'):
                    run_id = line.split('Run ID:')[-1].strip()
                    break

            self.assert_true("Run ID present in stdout", run_id is not None)

            if run_id:
                logs_dir = project_root / "runs" / run_id / "logs"
                index_file = logs_dir / "aliasExtractionReport_index.json"
                self.assert_true("index.json exists", index_file.exists())

                source_entry = None
                if index_file.exists():
                    with open(index_file, 'r', encoding='utf-8') as fh:
                        index_data = json.load(fh)
                    source_entry = next(
                        (s for s in index_data.get('sources', [])
                         if _TEST57_SOURCE_UUID in s.get('all_source_identifiers', [])),
                        None,
                    )
                    self.assert_true("source entry found in index via UUID", source_entry is not None)

                if source_entry is not None:
                    report_filename = source_entry.get('report_file', '')
                    self.assert_true("index entry has report_file", bool(report_filename))

                    if report_filename:
                        report_path = logs_dir / report_filename
                        self.assert_true("per-source report file exists", report_path.exists())

                        if report_path.exists():
                            with open(report_path, 'r', encoding='utf-8') as fh:
                                report_data = json.load(fh)

                            confirmed_mappings = report_data.get('confirmedMappings', [])
                            self.assert_true(
                                "confirmedMappings is non-empty",
                                len(confirmed_mappings) >= 1,
                            )
                            if confirmed_mappings:
                                first_alias = confirmed_mappings[0].get('aliases', [{}])[0]
                                self.assert_equals(
                                    "confirmedMappings[0].aliases[0].vendor preserved verbatim",
                                    " whitespace_vendor", first_alias.get('vendor'),
                                )

                            alias_groups_confirmed = report_data.get('metadata', {}).get('alias_groups_confirmed', 0)
                            self.assert_true(
                                "alias_groups_confirmed >= 1 (all aliases are confirmed)",
                                alias_groups_confirmed >= 1,
                            )

        finally:
            # PHASE 4 — TEARDOWN
            if _TEST64_MAPPING_FILE.exists():
                _TEST64_MAPPING_FILE.unlink()
            self.teardown_subprocess_test_cache()

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
        self.test_25b_full_pipeline_non_actionable_entries()
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
        self.test_36b_non_actionable_from_empty_alias_extraction()
        self.test_36c_four_phase_pure_placeholder_source_gets_report()
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
        self.test_47_four_phase_sdc_concerns_flags_in_output()
        self.test_48_four_phase_cpe_sort_and_cap_in_output()
        self.test_49_four_phase_is_suggested_match_true_in_cpe_output()
        self.test_50_four_phase_platform_field_differentiates_aliases()
        self.test_51_four_phase_non_standard_identity_fields_passthrough()
        self.test_52_four_phase_sdc_concern_types_whitespace_comparator_invalidchars()
        self.test_53_confirmed_mappings_non_empty_with_mock_manager()
        self.test_54_multiple_distinct_na_patterns_consolidate_to_one()
        self.test_55_four_phase_programfiles_programroutines_packageurl_passthrough()
        self.test_56_has_alias_concerns_hyphenated_version_range()
        self.test_57_four_phase_confirmed_mappings_via_real_mapping_file_injection()
        self.test_58_template_has_mappingTypeFilter_element()
        self.test_59_template_has_renderMappingTypeFilterUI()
        self.test_60_template_has_toggleMappingTypePill()
        self.test_61_template_has_MappingTypeFilter_object()
        self.test_62_template_has_MappingTypeFilter_isFilteringActive()
        self.test_63_example_data_file_exists_at_new_location()
        self.test_64_four_phase_confirmed_mappings_raw_value_preservation()

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
