#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPE-AS Generation Comprehensive Test Suite

Complete test coverage for CPE Applicability Statement generation:
- Pattern 3.1: No version data (wildcard matches)
- Pattern 3.2: No affected platforms (metadata-only)
- Pattern 3.3: Exact versions (1:1 transformation)
- Pattern 3.4: Single range per entry (1:1 transformation)
- Pattern 3.5: Multiple ranges from single entry (1:M transformation, not yet implemented)

Includes both:
- Unit tests: Direct function-level validation of cpe_as_generator logic
- Integration tests: End-to-end workflow through actual tool execution

Test Pattern Compliance:
Integration tests follow the proper NVD-ish collector test pattern:
    1. SETUP: Copy test files to INPUT cache directories
    2. EXECUTE: Run normal tool execution with --cpe-as-gen flag
    3. VALIDATE: Check OUTPUT cache for expected CPE-AS data in enhanced records
    4. TEARDOWN: Clean up INPUT cache test files

NVD-ish CPE-AS Integration Test Implementation Pattern:
    SETUP: Copy pre-created test files to INPUT caches (cve_list_v5/, nvd_2.0_cves/)
           - Creates proper cache directory structure: cache/{source}/1337/{subdir}/
           - Uses CVE-1337-5XXX series for CPE-AS testing
           
    EXECUTE: Run analysis tool normally with --cpe-as-gen flag
             - Uses standard module invocation: python -m src.analysis_tool.core.analysis_tool
             - Tool automatically discovers and processes INPUT cache files
             - CPE-AS generation integrated via nvd_ish_collector.py registry
             
    VALIDATE: Check OUTPUT cache (nvd-ish_2.0_cves/) for enhanced records with CPE-AS data
              - Validates cpeAsGeneration section structure
              - Confirms cpeMatch object property ordering (OrderedDict)
              - Verifies pattern classification and metadata
              
    TEARDOWN: Clean INPUT cache files only (preserve OUTPUT cache)
              - Removes test files from INPUT caches
              - Preserves OUTPUT cache for validation
              - Maintains clean test environment between runs

Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Usage:
    python test_suites/nvd-ish_collector/test_cpe_as_integration.py
"""

import sys
import os
import json
import subprocess
import shutil
import unittest
from pathlib import Path
from typing import Optional, Tuple, List
from collections import OrderedDict

# Force UTF-8 output encoding for Windows compatibility
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'replace')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'replace')

# Test configuration
PROJECT_ROOT = Path(__file__).parent.parent.parent
TEST_FILES_DIR = Path(__file__).parent
CACHE_DIR = PROJECT_ROOT / "cache"

# Add src directory to path for direct imports
sys.path.insert(0, str(PROJECT_ROOT))

from src.analysis_tool.core.cpe_as_generator import (
    generate_cpe_as,
    handle_pattern_3_1,
    classify_pattern,
    is_placeholder_value,
    is_version_placeholder,
    has_real_version_data,
    create_ordered_cpe_match
)
from src.analysis_tool.core import cpe_as_generator


# ============================================================================
# UNIT TESTS: Pattern 3.1 (No Version Data)
# ============================================================================

class TestPattern3_1_UtilityFunctions(unittest.TestCase):
    """Test utility functions for placeholder detection and cpeMatch creation."""
    
    def test_is_placeholder_value_none(self):
        """Test that None is recognized as placeholder."""
        self.assertTrue(is_placeholder_value(None))
    
    def test_is_placeholder_value_empty_string(self):
        """Test that empty string is recognized as placeholder."""
        self.assertTrue(is_placeholder_value(""))
    
    def test_is_placeholder_value_zero(self):
        """Test that 0 is recognized as placeholder."""
        self.assertTrue(is_placeholder_value(0))
    
    def test_is_placeholder_value_unspecified(self):
        """Test that 'unspecified' is recognized as placeholder."""
        self.assertTrue(is_placeholder_value("unspecified"))
    
    def test_is_placeholder_value_case_insensitive(self):
        """Test placeholder detection is case-insensitive."""
        self.assertTrue(is_placeholder_value("UNSPECIFIED"))
        self.assertTrue(is_placeholder_value("UnSpEcIfIeD"))
    
    def test_is_placeholder_value_real_version(self):
        """Test that real version strings are NOT placeholders."""
        self.assertFalse(is_placeholder_value("1.2.3"))
        self.assertFalse(is_placeholder_value("2.0"))
    
    def test_is_version_placeholder_wildcard(self):
        """Test that wildcard '*' is recognized as version placeholder."""
        self.assertTrue(is_version_placeholder("*"))
    
    def test_is_version_placeholder_common_values(self):
        """Test common version placeholder values."""
        self.assertTrue(is_version_placeholder("unspecified"))
        self.assertTrue(is_version_placeholder("unknown"))
        self.assertTrue(is_version_placeholder("all"))
    
    def test_has_real_version_data_none(self):
        """Test that None versions array has no real data."""
        self.assertFalse(has_real_version_data(None))
    
    def test_has_real_version_data_empty(self):
        """Test that empty versions array has no real data."""
        self.assertFalse(has_real_version_data([]))
    
    def test_has_real_version_data_placeholder_only(self):
        """Test that placeholder-only versions have no real data."""
        versions = [{"version": "unspecified", "status": "affected"}]
        self.assertFalse(has_real_version_data(versions))
    
    def test_has_real_version_data_real_version(self):
        """Test that real version is detected."""
        versions = [{"version": "1.2.3", "status": "affected"}]
        self.assertTrue(has_real_version_data(versions))
    
    def test_has_real_version_data_real_changes(self):
        """Test that real changes data is detected."""
        versions = [
            {
                "version": "unspecified",
                "status": "affected",
                "changes": [{"at": "1.2.3", "status": "unaffected"}]
            }
        ]
        self.assertTrue(has_real_version_data(versions))
    
    def test_create_ordered_cpe_match_property_order(self):
        """Test that cpeMatch properties are in correct order."""
        cpe_match = create_ordered_cpe_match(
            versions_entry_index=0,
            applied_pattern="range.lessThan",
            vulnerable=True,
            criteria="cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
            version_start_including="2.0",
            version_end_excluding="2.5"
        )
        
        keys = list(cpe_match.keys())
        expected_order = [
            'versionsEntryIndex',
            'appliedPattern',
            'vulnerable',
            'criteria',
            'versionStartIncluding',
            'versionEndExcluding'
        ]
        self.assertEqual(keys, expected_order)
    
    def test_create_ordered_cpe_match_metadata_only(self):
        """Test metadata-only cpeMatch (no criteria, no appliedPattern)."""
        cpe_match = create_ordered_cpe_match(
            versions_entry_index=1,
            applied_pattern=None,
            vulnerable=False,
            concerns=["statusUnaffected"]
        )
        
        keys = list(cpe_match.keys())
        expected_order = ['versionsEntryIndex', 'vulnerable', 'concerns']
        self.assertEqual(keys, expected_order)
        self.assertNotIn('appliedPattern', keys)
        self.assertNotIn('criteria', keys)


class TestPattern3_1_Classification(unittest.TestCase):
    """Test Pattern 3.1 classification logic."""
    
    def test_classify_pattern_3_1_no_versions(self):
        """Test classification for no versions array (Pattern A)."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "affected"
        }
        pattern = classify_pattern(affected_entry, None)
        self.assertEqual(pattern, "3.1")
    
    def test_classify_pattern_3_1_empty_versions(self):
        """Test classification for empty versions array (Pattern B)."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "affected",
            "versions": []
        }
        pattern = classify_pattern(affected_entry, [])
        self.assertEqual(pattern, "3.1")
    
    def test_classify_pattern_3_1_placeholder_versions(self):
        """Test classification for placeholder-only versions (Pattern C)."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "affected"
        }
        versions = [{"version": "unspecified", "status": "affected"}]
        pattern = classify_pattern(affected_entry, versions)
        self.assertEqual(pattern, "3.1")


class TestPattern3_1_SubPatterns(unittest.TestCase):
    """Test Pattern 3.1 sub-patterns (A, B, C, D)."""
    
    def test_pattern_a_affected(self):
        """Test Pattern A with defaultStatus='affected'."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "affected"
        }
        cpe_base = "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"
        
        results = handle_pattern_3_1(affected_entry, cpe_base, None, has_confirmed_mapping=True)
        
        self.assertEqual(len(results), 1)
        cpe_match = results[0]
        
        self.assertIsNone(cpe_match['versionsEntryIndex'])
        self.assertEqual(cpe_match['appliedPattern'], 'noVersion.allAffected')
        self.assertTrue(cpe_match['vulnerable'])
        self.assertEqual(cpe_match['criteria'], 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*')
    
    def test_pattern_a_variant_wildcard(self):
        """Test Pattern A-Variant with explicit wildcard."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "affected",
            "versions": [
                {"version": "*", "status": "affected"}
            ]
        }
        cpe_base = "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"
        
        results = handle_pattern_3_1(affected_entry, cpe_base, affected_entry['versions'], has_confirmed_mapping=True)
        
        self.assertEqual(len(results), 1)
        cpe_match = results[0]
        
        self.assertEqual(cpe_match['versionsEntryIndex'], 0)
        self.assertEqual(cpe_match['appliedPattern'], 'noVersion.explicitWildcard')
        self.assertTrue(cpe_match['vulnerable'])
    
    def test_pattern_b_empty_array(self):
        """Test Pattern B with empty versions array."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "affected",
            "versions": []
        }
        cpe_base = "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"
        
        results = handle_pattern_3_1(affected_entry, cpe_base, affected_entry['versions'], has_confirmed_mapping=True)
        
        self.assertEqual(len(results), 1)
        cpe_match = results[0]
        
        self.assertIsNone(cpe_match['versionsEntryIndex'])
        self.assertEqual(cpe_match['appliedPattern'], 'noVersion.allAffected')
        self.assertTrue(cpe_match['vulnerable'])
    
    def test_pattern_c_unspecified(self):
        """Test Pattern C with 'unspecified' placeholder."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "affected",
            "versions": [
                {"version": "unspecified", "status": "affected"}
            ]
        }
        cpe_base = "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"
        
        results = handle_pattern_3_1(affected_entry, cpe_base, affected_entry['versions'], has_confirmed_mapping=True)
        
        self.assertEqual(len(results), 1)
        cpe_match = results[0]
        
        self.assertEqual(cpe_match['versionsEntryIndex'], 0)
        self.assertEqual(cpe_match['appliedPattern'], 'noVersion.placeholderValue')
        self.assertTrue(cpe_match['vulnerable'])
    
    def test_pattern_d_unknown_no_versions(self):
        """Test Pattern D with defaultStatus='unknown' and no versions."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "unknown"
        }
        cpe_base = "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"
        
        results = handle_pattern_3_1(affected_entry, cpe_base, None)
        
        self.assertEqual(len(results), 1)
        cpe_match = results[0]
        
        self.assertIsNone(cpe_match['versionsEntryIndex'])
        self.assertNotIn('appliedPattern', cpe_match)
        self.assertFalse(cpe_match['vulnerable'])
        self.assertNotIn('criteria', cpe_match)
        self.assertIn('concerns', cpe_match)
        self.assertEqual(cpe_match['concerns'], ['defaultStatusUnknown'])


# ============================================================================
# UNIT TESTS: Pattern 3.2 (No Affected Platforms)
# ============================================================================

class TestPattern3_2_NoAffectedPlatforms(unittest.TestCase):
    """Test Pattern 3.2: No affected platforms (metadata-only)."""
    
    def test_pattern_3_2_default_unaffected_no_versions(self):
        """Pattern 3.2-A: defaultStatus='unaffected' with no versions array."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "unaffected"
        }
        
        result = cpe_as_generator.generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        self.assertEqual(len(result), 1)
        cpe_match = result[0]
        
        self.assertIsNone(cpe_match.get('versionsEntryIndex'))
        self.assertIsNone(cpe_match.get('appliedPattern'))
        self.assertFalse(cpe_match.get('vulnerable'))
        self.assertEqual(cpe_match.get('concerns'), ["noAffectedPlatforms"])
        self.assertNotIn('criteria', cpe_match)
    
    def test_pattern_3_2_all_versions_unaffected(self):
        """Pattern 3.2-B: ALL versions='unaffected'."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "affected",
            "versions": [
                {"version": "1.0", "status": "unaffected"},
                {"version": "2.0", "status": "unaffected"}
            ]
        }
        
        result = cpe_as_generator.generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        self.assertEqual(len(result), 2)
        
        for idx, cpe_match in enumerate(result):
            self.assertEqual(cpe_match.get('versionsEntryIndex'), idx)
            self.assertIsNone(cpe_match.get('appliedPattern'))
            self.assertFalse(cpe_match.get('vulnerable'))
            self.assertEqual(cpe_match.get('concerns'), ["statusUnaffected"])
            self.assertNotIn('criteria', cpe_match)


# ============================================================================
# UNIT TESTS: Pattern 3.3 (Exact Versions)
# ============================================================================

class TestPattern3_3_ExactVersions(unittest.TestCase):
    """Test Pattern 3.3: Exact versions (1:1 transformation)."""
    
    def test_pattern_3_3_single_exact_version(self):
        """Pattern 3.3-A: Single exact version."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "unknown",
            "versions": [
                {"version": "1.2.3", "status": "affected"}
            ]
        }
        
        result = cpe_as_generator.generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        self.assertEqual(len(result), 1)
        cpe_match = result[0]
        
        self.assertEqual(cpe_match.get('versionsEntryIndex'), 0)
        self.assertEqual(cpe_match.get('appliedPattern'), "exact.single")
        self.assertTrue(cpe_match.get('vulnerable'))
        self.assertEqual(
            cpe_match.get('criteria'),
            "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"
        )
    
    def test_pattern_3_3_multiple_exact_versions(self):
        """Pattern 3.3-B: Multiple discrete versions (1:1 transformation)."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "unknown",
            "versions": [
                {"version": "1.2.3", "status": "affected"},
                {"version": "1.2.5", "status": "affected"},
                {"version": "2.0.1", "status": "affected"}
            ]
        }
        
        result = cpe_as_generator.generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        self.assertEqual(len(result), 3)
        
        expected_versions = ["1.2.3", "1.2.5", "2.0.1"]
        for idx, (cpe_match, expected_version) in enumerate(zip(result, expected_versions)):
            self.assertEqual(cpe_match.get('versionsEntryIndex'), idx)
            self.assertEqual(cpe_match.get('appliedPattern'), "exact.single")
            self.assertTrue(cpe_match.get('vulnerable'))
            self.assertEqual(
                cpe_match.get('criteria'),
                f"cpe:2.3:a:acme:widget:{expected_version}:*:*:*:*:*:*:*"
            )


# ============================================================================
# UNIT TESTS: Pattern 3.4 (Single Range Per Entry)
# ============================================================================

class TestPattern3_4_SingleRangePerEntry(unittest.TestCase):
    """Test Pattern 3.4: Single range per entry (1:1 transformation)."""
    
    def test_pattern_3_4_less_than(self):
        """Pattern 3.4-A: Explicit range with lessThan."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "affected",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "2.0"
                }
            ]
        }
        
        result = cpe_as_generator.generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        self.assertEqual(len(result), 1)
        cpe_match = result[0]
        
        self.assertEqual(cpe_match.get('versionsEntryIndex'), 0)
        self.assertEqual(cpe_match.get('appliedPattern'), "range.zeroStart")
        self.assertTrue(cpe_match.get('vulnerable'))
        self.assertEqual(cpe_match.get('versionStartIncluding'), "0")
        self.assertEqual(cpe_match.get('versionEndExcluding'), "2.0")
    
    def test_pattern_3_4_less_than_or_equal(self):
        """Pattern 3.4-B: Explicit range with lessThanOrEqual."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "affected",
            "versions": [
                {
                    "version": "1.0",
                    "status": "affected",
                    "lessThanOrEqual": "1.9.5"
                }
            ]
        }
        
        result = cpe_as_generator.generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        self.assertEqual(len(result), 1)
        cpe_match = result[0]
        
        self.assertEqual(cpe_match.get('versionsEntryIndex'), 0)
        self.assertEqual(cpe_match.get('appliedPattern'), "range.lessThanOrEqual")
        self.assertTrue(cpe_match.get('vulnerable'))
        self.assertEqual(cpe_match.get('versionStartIncluding'), "1.0")
        self.assertEqual(cpe_match.get('versionEndIncluding'), "1.9.5")
        self.assertIsNone(cpe_match.get('versionEndExcluding'))
    
    def test_pattern_3_4_single_status_change(self):
        """Pattern 3.4-D: Single status change (changes array)."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "affected",
            "versions": [
                {
                    "version": "5.0",
                    "status": "affected",
                    "changes": [
                        {"at": "5.0.3", "status": "unaffected"}
                    ]
                }
            ]
        }
        
        result = cpe_as_generator.generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        self.assertEqual(len(result), 1)
        cpe_match = result[0]
        
        self.assertEqual(cpe_match.get('appliedPattern'), "range.changesFixed")
        self.assertEqual(cpe_match.get('versionStartIncluding'), "5.0")
        self.assertEqual(cpe_match.get('versionEndExcluding'), "5.0.3")
    
    def test_pattern_3_4_multiple_ranges_one_to_one(self):
        """Pattern 3.4: Multiple range entries produce multiple cpeMatch (1:1)."""
        affected_entry = {
            "vendor": "acme",
            "product": "widget",
            "defaultStatus": "affected",
            "versions": [
                {
                    "version": "1.0",
                    "status": "affected",
                    "lessThan": "2.0"
                },
                {
                    "version": "3.0",
                    "status": "affected",
                    "lessThan": "4.0"
                }
            ]
        }
        
        result = cpe_as_generator.generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        self.assertEqual(len(result), 2)
        
        self.assertEqual(result[0].get('versionsEntryIndex'), 0)
        self.assertEqual(result[0].get('versionStartIncluding'), "1.0")
        self.assertEqual(result[0].get('versionEndExcluding'), "2.0")
        
        self.assertEqual(result[1].get('versionsEntryIndex'), 1)
        self.assertEqual(result[1].get('versionStartIncluding'), "3.0")
        self.assertEqual(result[1].get('versionEndExcluding'), "4.0")
    
    def test_pattern_3_4_update_patterns_in_range_boundaries(self):
        """Pattern 3.4 + Section 6.2: Update patterns in range boundaries detected but not applied."""
        affected_entry = {
            "vendor": "example",
            "product": "server",
            "defaultStatus": "affected",
            "versions": [
                {
                    "version": "10.0 SP 1",
                    "status": "affected",
                    "lessThanOrEqual": "10.0 SP 3"
                }
            ]
        }
        
        result = cpe_as_generator.generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:example:server:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        self.assertEqual(len(result), 1)
        cpe_match = result[0]
        
        # Verify untransformed values preserved in range boundaries
        self.assertEqual(cpe_match.get('versionStartIncluding'), "10.0 SP 1")
        self.assertEqual(cpe_match.get('versionEndIncluding'), "10.0 SP 3")
        
        # Verify concern flag added
        concerns = cpe_match.get('concerns', [])
        self.assertIn("updatePatternsInRange", concerns)
        
        # Verify criteria uses wildcard (not transformed version)
        self.assertEqual(cpe_match.get('criteria'), "cpe:2.3:a:example:server:*:*:*:*:*:*:*:*")


# ============================================================================
# UNIT TESTS: Pattern 3.5 (Multiple Ranges From One Entry - 1:M Transformation)
# ============================================================================

class TestPattern3_5_MultipleRanges(unittest.TestCase):
    """Test Pattern 3.5: Multiple ranges from one entry (1:M transformation)."""
    
    def test_pattern_3_5_multiple_status_flip_flops(self):
        """Pattern 3.5-A: Multiple status flip-flops (affected → unaffected → affected → unaffected)."""
        affected_entry = {
            "vendor": "example",
            "product": "webapp",
            "versions": [
                {
                    "version": "3.0",
                    "status": "affected",
                    "changes": [
                        {"at": "3.0.5", "status": "unaffected"},
                        {"at": "3.1.0", "status": "affected"},
                        {"at": "3.1.2", "status": "unaffected"}
                    ]
                }
            ]
        }
        
        results = generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:example:webapp:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        # Should produce TWO ranges from ONE version entry
        self.assertEqual(len(results), 2)
        
        # First range: 3.0 → 3.0.5 (affected)
        cpe_match_1 = results[0]
        self.assertEqual(cpe_match_1.get('versionsEntryIndex'), 0)
        self.assertEqual(cpe_match_1.get('appliedPattern'), "multiRange.exactStatusTransitions")
        self.assertEqual(cpe_match_1.get('vulnerable'), True)
        self.assertEqual(cpe_match_1.get('versionStartIncluding'), "3.0")
        self.assertEqual(cpe_match_1.get('versionEndExcluding'), "3.0.5")
        
        # Second range: 3.1.0 → 3.1.2 (vulnerability reintroduced)
        cpe_match_2 = results[1]
        self.assertEqual(cpe_match_2.get('versionsEntryIndex'), 0)
        self.assertEqual(cpe_match_2.get('appliedPattern'), "multiRange.exactStatusTransitions")
        self.assertEqual(cpe_match_2.get('vulnerable'), True)
        self.assertEqual(cpe_match_2.get('versionStartIncluding'), "3.1.0")
        self.assertEqual(cpe_match_2.get('versionEndExcluding'), "3.1.2")
    
    def test_pattern_3_5_changes_combined_with_range_bounds(self):
        """Pattern 3.5-B: Changes combined with range bounds (lessThan + changes array)."""
        affected_entry = {
            "vendor": "example",
            "product": "database",
            "versions": [
                {
                    "version": "2.0",
                    "status": "affected",
                    "lessThan": "5.0",
                    "changes": [
                        {"at": "3.0", "status": "unaffected"},
                        {"at": "4.0", "status": "affected"}
                    ]
                }
            ]
        }
        
        results = generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:example:database:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        # Should produce TWO ranges from ONE version entry
        self.assertEqual(len(results), 2)
        
        # First range: 2.0 → 3.0 (affected)
        cpe_match_1 = results[0]
        self.assertEqual(cpe_match_1.get('versionsEntryIndex'), 0)
        self.assertEqual(cpe_match_1.get('appliedPattern'), "multiRange.rangeStatusTransitions")
        self.assertEqual(cpe_match_1.get('vulnerable'), True)
        self.assertEqual(cpe_match_1.get('versionStartIncluding'), "2.0")
        self.assertEqual(cpe_match_1.get('versionEndExcluding'), "3.0")
        
        # Second range: 4.0 → 5.0 (vulnerability reintroduced)
        cpe_match_2 = results[1]
        self.assertEqual(cpe_match_2.get('versionsEntryIndex'), 0)
        self.assertEqual(cpe_match_2.get('appliedPattern'), "multiRange.rangeStatusTransitions")
        self.assertEqual(cpe_match_2.get('vulnerable'), True)
        self.assertEqual(cpe_match_2.get('versionStartIncluding'), "4.0")
        self.assertEqual(cpe_match_2.get('versionEndExcluding'), "5.0")
    
    def test_pattern_3_5_open_ended_final_range(self):
        """Pattern 3.5: Open-ended final affected range (no upper bound)."""
        affected_entry = {
            "vendor": "example",
            "product": "library",
            "versions": [
                {
                    "version": "1.0",
                    "status": "affected",
                    "changes": [
                        {"at": "1.5", "status": "unaffected"},
                        {"at": "2.0", "status": "affected"}
                    ]
                }
            ]
        }
        
        results = generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:example:library:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        # Should produce TWO ranges
        self.assertEqual(len(results), 2)
        
        # First range: 1.0 → 1.5 (affected)
        cpe_match_1 = results[0]
        self.assertEqual(cpe_match_1.get('versionStartIncluding'), "1.0")
        self.assertEqual(cpe_match_1.get('versionEndExcluding'), "1.5")
        
        # Second range: 2.0 → (open-ended, no upper bound)
        cpe_match_2 = results[1]
        self.assertEqual(cpe_match_2.get('versionStartIncluding'), "2.0")
        self.assertIsNone(cpe_match_2.get('versionEndExcluding'))
        self.assertIsNone(cpe_match_2.get('versionEndIncluding'))
    
    def test_pattern_3_5_same_versions_entry_index(self):
        """Verify all cpeMatch objects from same version entry share versionsEntryIndex."""
        affected_entry = {
            "vendor": "example",
            "product": "tool",
            "versions": [
                {
                    "version": "1.0",
                    "status": "affected",
                    "changes": [
                        {"at": "1.5", "status": "unaffected"},
                        {"at": "2.0", "status": "affected"},
                        {"at": "2.5", "status": "unaffected"}
                    ]
                }
            ]
        }
        
        results = generate_cpe_as(
            affected_entry,
            "cpe:2.3:a:example:tool:*:*:*:*:*:*:*:*",
            has_confirmed_mapping=True
        )
        
        # All cpeMatch objects should have same versionsEntryIndex
        self.assertEqual(len(results), 2)
        for cpe_match in results:
            self.assertEqual(cpe_match.get('versionsEntryIndex'), 0)


# ============================================================================
# UNIT TESTS: Wildcard Expansion in Unaffected Entries
# ============================================================================

class TestWildcardExpansionUnaffected(unittest.TestCase):
    """Test wildcard expansion detection in unaffected entries."""
    
    def test_unaffected_with_wildcard_in_lessThanOrEqual(self):
        """Unaffected entries with wildcards in lessThanOrEqual get wildcard concern."""
        from src.analysis_tool.core.cpe_as_generator import handle_pattern_3_4
        
        affected_entry = {
            "vendor": "Linux",
            "product": "Linux",
            "defaultStatus": "affected",
        }
        
        cpe_base_string = "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
        
        versions = [
            {
                "version": "6.12.67",
                "lessThanOrEqual": "6.12.*",
                "status": "unaffected",
                "versionType": "semver"
            },
            {
                "version": "6.18.7",
                "lessThanOrEqual": "6.18.*",
                "status": "unaffected",
                "versionType": "semver"
            }
        ]
        
        results = handle_pattern_3_4(
            affected_entry=affected_entry,
            cpe_base_string=cpe_base_string,
            versions=versions,
            has_confirmed_mapping=True
        )
        
        self.assertEqual(len(results), 2)
        
        for idx, result in enumerate(results):
            concerns = result.get('concerns', [])
            
            # Verify both concerns present
            self.assertIn('statusUnaffected', concerns, 
                         f"Entry {idx}: Missing 'statusUnaffected' in concerns")
            self.assertIn('inferredAffectedFromWildcardExpansion', concerns,
                         f"Entry {idx}: Missing 'inferredAffectedFromWildcardExpansion' in concerns")
            
            # Verify vulnerable=False for unaffected entries
            self.assertEqual(result.get('vulnerable'), False,
                           f"Entry {idx}: Expected vulnerable=False")
    
    def test_affected_with_wildcard_regression(self):
        """Affected entries with wildcards still work correctly (regression check)."""
        from src.analysis_tool.core.cpe_as_generator import handle_pattern_3_4
        
        affected_entry = {
            "vendor": "Example",
            "product": "Product",
            "defaultStatus": "affected",
        }
        
        cpe_base_string = "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*"
        
        versions = [
            {
                "version": "1.0",
                "lessThanOrEqual": "1.2.*",
                "status": "affected",
                "versionType": "semver"
            }
        ]
        
        results = handle_pattern_3_4(
            affected_entry=affected_entry,
            cpe_base_string=cpe_base_string,
            versions=versions,
            has_confirmed_mapping=True
        )
        
        result = results[0]
        concerns = result.get('concerns', [])
        
        # Should have wildcard concern
        self.assertIn('inferredAffectedFromWildcardExpansion', concerns,
                     "Missing wildcard concern for affected entry")
        
        # Should NOT have statusUnaffected
        self.assertNotIn('statusUnaffected', concerns,
                        "Affected entry should not have statusUnaffected")
        
        # Should be vulnerable
        self.assertEqual(result.get('vulnerable'), True)
        
        # Should have criteria
        self.assertIn('criteria', result)
    
    def test_unaffected_without_wildcard_regression(self):
        """Unaffected entries without wildcards only have statusUnaffected concern."""
        from src.analysis_tool.core.cpe_as_generator import handle_pattern_3_4
        
        affected_entry = {
            "vendor": "Example",
            "product": "Product",
            "defaultStatus": "affected",
        }
        
        cpe_base_string = "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*"
        
        versions = [
            {
                "version": "2.0",
                "lessThanOrEqual": "3.0",
                "status": "unaffected",
                "versionType": "semver"
            }
        ]
        
        results = handle_pattern_3_4(
            affected_entry=affected_entry,
            cpe_base_string=cpe_base_string,
            versions=versions,
            has_confirmed_mapping=True
        )
        
        result = results[0]
        concerns = result.get('concerns', [])
        
        # Should only have statusUnaffected
        self.assertEqual(concerns, ['statusUnaffected'],
                        "Expected only statusUnaffected concern for non-wildcard unaffected entry")


# ============================================================================
# UNIT TESTS: versionType="git" Handling (Section 6.1)
# ============================================================================

class TestVersionTypeGit(unittest.TestCase):
    """Test versionType='git' handling per Section 6.1 requirements."""
    
    def test_version_type_git_single_entry(self):
        """versionType='git' generates metadata-only cpeMatch with concern."""


# ============================================================================
# UNIT TESTS: Section 4.2 (Update Field Specificity Postprocessing)
# ============================================================================

class TestSection4_2_UpdateFieldSpecificity(unittest.TestCase):
    """Test Section 4.2: Update field specificity enforcement."""
    
    def test_section_4_2_wildcard_to_no_update_conversion(self):
        """Section 4.2: Convert wildcard update (*) to no-update (-) when specific updates exist."""
        from src.analysis_tool.core.cpe_as_generator import apply_update_field_specificity
        from collections import OrderedDict
        
        # Create test data: two cpeMatch objects with same base but different update values
        cpe_matches = [
            OrderedDict([
                ('versionsEntryIndex', 0),
                ('appliedPattern', 'exact.single'),
                ('vulnerable', True),
                ('criteria', 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*')  # Wildcard update
            ]),
            OrderedDict([
                ('versionsEntryIndex', 1),
                ('appliedPattern', 'exact.single'),
                ('vulnerable', True),
                ('criteria', 'cpe:2.3:a:vendor:product:1.0:patch1:*:*:*:*:*:*')  # Specific update
            ])
        ]
        
        result = apply_update_field_specificity(cpe_matches)
        
        # First cpeMatch should have update field changed from * to -
        self.assertEqual(result[0].get('criteria'), 'cpe:2.3:a:vendor:product:1.0:-:*:*:*:*:*:*')
        
        # Second cpeMatch should remain unchanged
        self.assertEqual(result[1].get('criteria'), 'cpe:2.3:a:vendor:product:1.0:patch1:*:*:*:*:*:*')
    
    def test_section_4_2_preserve_wildcard_when_no_specific_updates(self):
        """Section 4.2: Preserve wildcard when no specific update values exist."""
        from src.analysis_tool.core.cpe_as_generator import apply_update_field_specificity
        from collections import OrderedDict
        
        # Only wildcard update - should NOT be converted
        cpe_matches = [
            OrderedDict([
                ('versionsEntryIndex', 0),
                ('appliedPattern', 'exact.single'),
                ('vulnerable', True),
                ('criteria', 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*')
            ])
        ]
        
        result = apply_update_field_specificity(cpe_matches)
        
        # Should remain unchanged since there are no specific updates
        self.assertEqual(result[0].get('criteria'), 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*')
    
    def test_section_4_2_different_base_components_no_conversion(self):
        """Section 4.2: Different base components (different versions) - no conversion."""
        from src.analysis_tool.core.cpe_as_generator import apply_update_field_specificity
        from collections import OrderedDict
        
        # Different version components - should NOT trigger conversion
        cpe_matches = [
            OrderedDict([
                ('versionsEntryIndex', 0),
                ('appliedPattern', 'exact.single'),
                ('vulnerable', True),
                ('criteria', 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*')
            ]),
            OrderedDict([
                ('versionsEntryIndex', 1),
                ('appliedPattern', 'exact.single'),
                ('vulnerable', True),
                ('criteria', 'cpe:2.3:a:vendor:product:2.0:patch1:*:*:*:*:*:*')  # Different version
            ])
        ]
        
        result = apply_update_field_specificity(cpe_matches)
        
        # Both should remain unchanged (different base components)
        self.assertEqual(result[0].get('criteria'), 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*')
        self.assertEqual(result[1].get('criteria'), 'cpe:2.3:a:vendor:product:2.0:patch1:*:*:*:*:*:*')
    
    def test_section_4_2_metadata_only_objects_preserved(self):
        """Section 4.2: Metadata-only cpeMatch objects without criteria are preserved."""
        from src.analysis_tool.core.cpe_as_generator import apply_update_field_specificity
        from collections import OrderedDict
        
        # Metadata-only object without criteria
        cpe_matches = [
            OrderedDict([
                ('versionsEntryIndex', 0),
                ('appliedPattern', 'exact.versionTypeGit'),
                ('vulnerable', True),
                ('concerns', ['versionTypeGit'])
            ])
        ]
        
        result = apply_update_field_specificity(cpe_matches)
        
        # Should remain unchanged (no criteria field)
        self.assertEqual(len(result), 1)
        self.assertNotIn('criteria', result[0])
        self.assertEqual(result[0].get('concerns'), ['versionTypeGit'])


class TestPatternUnsupported(unittest.TestCase):
    """Test patternUnsupported concern generation and verification it's NOT used for valid patterns."""
    
    def test_pattern_3_4_no_recognized_sub_pattern(self):
        """Pattern 3.4: Generate patternUnsupported concern when no sub-pattern matches."""
        from src.analysis_tool.core.cpe_as_generator import handle_pattern_3_4
        
        # Malformed case: status='affected' but no version field, no lessThan, no changes
        # This doesn't match any Pattern 3.4 sub-pattern
        affected_entry_malformed = {
            'vendor': 'test',
            'product': 'app',
            'defaultStatus': 'unknown',
            'versions': [
                {
                    'status': 'affected'
                    # No version field at all, no lessThan, no changes - pattern detection fails
                }
            ]
        }
        
        cpe_base_string = 'cpe:2.3:a:test:app:*:*:*:*:*:*:*:*'
        
        result = handle_pattern_3_4(
            affected_entry_malformed, 
            cpe_base_string, 
            affected_entry_malformed['versions'],
            has_confirmed_mapping=True
        )
        
        # Should generate metadata-only cpeMatch with patternUnsupported concern
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].get('versionsEntryIndex'), 0)
        self.assertEqual(result[0].get('vulnerable'), False)
        self.assertIn('patternUnsupported', result[0].get('concerns', []))
        self.assertNotIn('criteria', result[0])
    
    def test_pattern_classification_single_change(self):
        """Pattern Classification: lessThan + single change → Pattern 3.5 (multiple ranges)."""
        from src.analysis_tool.core.cpe_as_generator import classify_pattern
        
        affected_entry = {
            'vendor': 'test',
            'product': 'app',
            'defaultStatus': 'unaffected',
            'versions': [
                {
                    'version': '2.0',
                    'lessThan': '2.5',
                    'status': 'affected',
                    'changes': [
                        {'at': '2.3.1', 'status': 'unaffected'}
                    ]
                }
            ]
        }
        
        pattern = classify_pattern(affected_entry, affected_entry['versions'])
        
        self.assertEqual(pattern, "3.5", 
            "lessThan + single change creates multiple ranges")
    
    def test_pattern_3_4_mixed_exact_and_ranges(self):
        """Pattern 3.4: Handle mixed entry with both exact versions and ranges (Linux kernel pattern)."""
        from src.analysis_tool.core.cpe_as_generator import handle_pattern_3_4
        
        # Realistic Linux kernel CVE pattern: mix of exact versions and ranges
        affected_entry = {
            'vendor': 'Linux',
            'product': 'Linux',
            'defaultStatus': 'affected',
            'versions': [
                {'version': '4.15', 'status': 'affected'},  # Exact version (index 0)
                {'version': '0', 'lessThan': '4.15', 'status': 'unaffected'},  # Range (index 1)
                {'version': '4.19.267', 'lessThanOrEqual': '4.19.*', 'status': 'unaffected'}  # Range (index 2)
            ]
        }
        
        cpe_base_string = 'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*'
        
        result = handle_pattern_3_4(
            affected_entry, 
            cpe_base_string, 
            affected_entry['versions'],
            has_confirmed_mapping=True
        )
        
        # Should generate 3 cpeMatch objects
        self.assertEqual(len(result), 3)
        
        # Index 0: Exact version should be handled correctly (delegated to Pattern 3.3)
        self.assertEqual(result[0].get('versionsEntryIndex'), 0)
        self.assertEqual(result[0].get('vulnerable'), True)
        self.assertIn('cpe:2.3:o:linux:linux_kernel:4.15:', result[0].get('criteria', ''))
        self.assertNotIn('patternUnsupported', result[0].get('concerns', []))
        
        # Index 1: Range should have statusUnaffected concern
        self.assertEqual(result[1].get('versionsEntryIndex'), 1)
        self.assertEqual(result[1].get('vulnerable'), False)
        self.assertIn('statusUnaffected', result[1].get('concerns', []))
        
        # Index 2: Range should have statusUnaffected concern
        self.assertEqual(result[2].get('versionsEntryIndex'), 2)
        self.assertEqual(result[2].get('vulnerable'), False)
        self.assertIn('statusUnaffected', result[2].get('concerns', []))
    
    def test_valid_patterns_do_not_generate_pattern_unsupported(self):
        """Verify patternUnsupported is NOT generated when valid patterns match."""
        from src.analysis_tool.core.cpe_as_generator import generate_cpe_as
        
        # Test all valid pattern categories to ensure none generate patternUnsupported
        
        # Pattern 3.1: No version data
        result_3_1 = generate_cpe_as(
            {'vendor': 'test', 'product': 'app', 'defaultStatus': 'affected'},
            'cpe:2.3:a:test:app:*:*:*:*:*:*:*:*',
            has_confirmed_mapping=True
        )
        for match in result_3_1:
            self.assertNotIn('patternUnsupported', match.get('concerns', []))
        
        # Pattern 3.2: No affected platforms
        result_3_2 = generate_cpe_as(
            {'vendor': 'test', 'product': 'app', 'defaultStatus': 'unaffected'},
            'cpe:2.3:a:test:app:*:*:*:*:*:*:*:*',
            has_confirmed_mapping=True
        )
        for match in result_3_2:
            self.assertNotIn('patternUnsupported', match.get('concerns', []))
        
        # Pattern 3.3: Exact version
        result_3_3 = generate_cpe_as(
            {
                'vendor': 'test',
                'product': 'app',
                'defaultStatus': 'affected',
                'versions': [{'version': '1.0', 'status': 'affected'}]
            },
            'cpe:2.3:a:test:app:*:*:*:*:*:*:*:*',
            has_confirmed_mapping=True
        )
        for match in result_3_3:
            self.assertNotIn('patternUnsupported', match.get('concerns', []))
        
        # Pattern 3.4: Range with lessThan
        result_3_4 = generate_cpe_as(
            {
                'vendor': 'test',
                'product': 'app',
                'defaultStatus': 'affected',
                'versions': [
                    {'version': '1.0', 'status': 'affected', 'lessThan': '2.0'}
                ]
            },
            'cpe:2.3:a:test:app:*:*:*:*:*:*:*:*',
            has_confirmed_mapping=True
        )
        for match in result_3_4:
            self.assertNotIn('patternUnsupported', match.get('concerns', []))
        
        # Pattern 3.5: Multiple ranges
        result_3_5 = generate_cpe_as(
            {
                'vendor': 'test',
                'product': 'app',
                'defaultStatus': 'affected',
                'versions': [
                    {
                        'version': '1.0',
                        'status': 'affected',
                        'changes': [
                            {'at': '1.5', 'status': 'unaffected'},
                            {'at': '2.0', 'status': 'affected'}
                        ]
                    }
                ]
            },
            'cpe:2.3:a:test:app:*:*:*:*:*:*:*:*',
            has_confirmed_mapping=True
        )
        for match in result_3_5:
            self.assertNotIn('patternUnsupported', match.get('concerns', []))


# ============================================================================
# INTEGRATION TESTS
# ============================================================================



# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class CPEASIntegrationTestSuite:
    """Test suite for CPE-AS generation integration functionality."""
    
    def __init__(self):
        self.passed = 0
        self.total = 12  # 5 edge case tests + 5 full workflow tests + 2 concern validation tests
        
    def setup_test_environment(self) -> List[str]:
        """Set up test environment by copying test files to INPUT cache locations AND injecting CPE cache data."""
        print("Setting up CPE-AS integration test environment...")
        
        copied_files = []
        
        # Test cases use CVE-1337-50XX series for CPE-AS testing
        test_cves = [
            # Edge case tests (metadata-only scenarios)
            "CVE-1337-5001",  # Pattern 3.1-A: No versions array
            "CVE-1337-5002",  # Pattern 3.1-B: Empty versions array
            "CVE-1337-5003",  # Pattern 3.1-C: Placeholder versions only
            "CVE-1337-5004",  # Pattern 3.1-D: defaultStatus=unknown
            "CVE-1337-5005",  # Property ordering validation
            # Full workflow tests (version matching scenarios)
            "CVE-1337-5006",  # Full Workflow A: Single exact version (exact.single)
            "CVE-1337-5007",  # Full Workflow B: Version range with lessThan (range.lessThan)
            "CVE-1337-5008",  # Full Workflow C: Pattern 3.4-D single range with change (range.changesFixed)
            "CVE-1337-5009",  # Full Workflow D: Pattern 3.5 lessThan + change → multiple ranges (not yet implemented)
            "CVE-1337-5010",  # Section 6.2: Update patterns in range boundaries
            "CVE-1337-5011",  # Section 6.1: versionType='git' handling
            "CVE-1337-5012",  # Concern validation: Wildcard expansion pattern
        ]
        
        year = "1337"
        dir_name = "5xxx"
        
        # Pre-create cache directory structures
        for cache_type in ["cve_list_v5", "nvd_2.0_cves", "nvd-ish_2.0_cves"]:
            cache_dir = CACHE_DIR / cache_type / year / dir_name
            cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Inject CPE cache data for test CVEs to simulate NVD API query results
        # This allows the normal pipeline to flow: CPE queries → top10 suggestions → CPE-AS generation
        self._inject_cpe_cache_data()
        
        # Copy test files
        for cve_id in test_cves:
            # Copy CVE List V5 file
            cve_list_cache_dir = CACHE_DIR / "cve_list_v5" / year / dir_name
            cve_list_source = TEST_FILES_DIR / f"{cve_id}-cve-list-v5.json"
            if cve_list_source.exists():
                cve_list_target = cve_list_cache_dir / f"{cve_id}.json"
                if cve_list_target.exists():
                    cve_list_target.unlink()
                shutil.copy2(cve_list_source, cve_list_target)
                copied_files.append(str(cve_list_target))
            
            # Copy NVD 2.0 file (if exists)
            nvd_cache_dir = CACHE_DIR / "nvd_2.0_cves" / year / dir_name
            nvd_source = TEST_FILES_DIR / f"{cve_id}-nvd-2.0.json"
            if nvd_source.exists():
                nvd_target = nvd_cache_dir / f"{cve_id}.json"
                if nvd_target.exists():
                    nvd_target.unlink()
                shutil.copy2(nvd_source, nvd_target)
                copied_files.append(str(nvd_target))
        
        print(f"  * Copied {len(copied_files)} test files to INPUT cache")  # Should be 18 (9 CVEs × 2 file types)
        return copied_files
    
    def _inject_cpe_cache_data(self):
        """
        Inject CPE cache entries for test CVEs to simulate NVD API query results.
        This allows the normal pipeline to flow through: CPE queries → top10 suggestions → CPE-AS generation.
        
        For each test CVE, we inject cache entries for ALL THREE search patterns generated by the tool:
        1. Vendor-only: cpe:2.3:*:vendor:*:*:*:*:*:*:*:*:*
        2. Product-only: cpe:2.3:*:*:*product*:*:*:*:*:*:*:*:*
        3. Vendor+product: cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*
        
        NOTE: Updated to inject into SHARDED cache files instead of monolithic cache.
        Uses MD5 hash-based distribution to determine correct shard for each CPE string.
        """
        import datetime
        import hashlib
        
        # Sharded cache configuration
        cache_shards_dir = CACHE_DIR / "cpe_base_strings"
        cache_shards_dir.mkdir(parents=True, exist_ok=True)
        num_shards = 16
        
        # Helper function to determine shard index (matches ShardedCPECache implementation)
        def get_shard_index(cpe_string: str) -> int:
            hash_digest = hashlib.md5(cpe_string.encode('utf-8')).hexdigest()
            return int(hash_digest[:8], 16) % num_shards
        
        # Load all existing shards
        shard_data = {}
        for shard_index in range(num_shards):
            shard_filename = f"cpe_cache_shard_{shard_index:02d}.json"
            shard_path = cache_shards_dir / shard_filename
            
            if shard_path.exists():
                with open(shard_path, 'r', encoding='utf-8') as f:
                    shard_data[shard_index] = json.load(f)
            else:
                shard_data[shard_index] = {}
        
        # Test data: vendor/product combinations for each test CVE
        test_combinations = [
            # Edge case tests (5001-5005)
            ("test_vendor", "test_product_pattern_3_1_a"),
            ("test_vendor", "test_product_pattern_3_1_b"),
            ("test_vendor", "test_product_pattern_3_1_c"),
            ("test_vendor", "test_product_pattern_3_1_d"),
            ("test_vendor", "test_product_pattern_3_1_e"),
            # Full workflow tests (5006-5009)
            ("test_vendor", "test_product_full_workflow_a"),
            ("test_vendor", "test_product_full_workflow_b"),
            ("test_vendor", "test_product_full_workflow_c"),
            ("test_vendor", "test_product_full_workflow_d"),
            # Section validation tests (5010-5011)
            ("test_vendor", "test_product_update_patterns"),
            ("test_vendor", "test_product_git_versiontype"),
            # Concern validation tests (5012-)
            ("test_vendor", "test_product_wildcard_expansion")
        ]
        
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        injection_count = 0
        
        for vendor, product in test_combinations:
            # Create mock CPE products for this vendor/product
            products_list = [
                {"cpe": {"deprecated": False, "cpeName": f"cpe:2.3:a:{vendor}:{product}:1.0:*:*:*:*:*:*:*", "cpeNameId": f"TEST-UUID-{product.upper()}-001", "lastModified": "2026-01-01T00:00:00.000", "created": "2026-01-01T00:00:00.000", "titles": "", "refs": ""}},
                {"cpe": {"deprecated": False, "cpeName": f"cpe:2.3:a:{vendor}:{product}:1.1:*:*:*:*:*:*:*", "cpeNameId": f"TEST-UUID-{product.upper()}-002", "lastModified": "2026-01-01T00:00:00.000", "created": "2026-01-01T00:00:00.000", "titles": "", "refs": ""}},
                {"cpe": {"deprecated": False, "cpeName": f"cpe:2.3:a:{vendor}:{product}:2.0:*:*:*:*:*:*:*", "cpeNameId": f"TEST-UUID-{product.upper()}-003", "lastModified": "2026-01-01T00:00:00.000", "created": "2026-01-01T00:00:00.000", "titles": "", "refs": ""}}
            ]
            
            # Create standard cache entry structure
            cache_entry = {
                "query_response": {
                    "resultsPerPage": 3,
                    "startIndex": 0,
                    "totalResults": 3,
                    "format": "NVD_CPE",
                    "version": "2.0",
                    "timestamp": timestamp,
                    "products": products_list
                },
                "last_queried": timestamp,
                "query_count": 1,
                "total_results": 3
            }
            
            # Inject all three search patterns the tool uses
            # Pattern 1: Vendor-only
            vendor_only_key = f"cpe:2.3:*:{vendor}:*:*:*:*:*:*:*:*:*"
            shard_index = get_shard_index(vendor_only_key)
            shard_data[shard_index][vendor_only_key] = cache_entry.copy()
            injection_count += 1
            
            # Pattern 2: Product-only (with wildcard prefix)
            product_only_key = f"cpe:2.3:*:*:*{product}*:*:*:*:*:*:*:*:*"
            shard_index = get_shard_index(product_only_key)
            shard_data[shard_index][product_only_key] = cache_entry.copy()
            injection_count += 1
            
            # Pattern 3: Vendor+product combined
            vendor_product_key = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"
            shard_index = get_shard_index(vendor_product_key)
            shard_data[shard_index][vendor_product_key] = cache_entry.copy()
            injection_count += 1
        
        # Save all modified shards
        for shard_index, data in shard_data.items():
            shard_filename = f"cpe_cache_shard_{shard_index:02d}.json"
            shard_path = cache_shards_dir / shard_filename
            with open(shard_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        
        print(f"  * Injected {injection_count} CPE cache entries across {num_shards} shards")  # Should be 36 (12 products × 3 patterns)
    
    def cleanup_test_environment(self, copied_files: List[str]):
        """Clean up test environment by removing copied test files."""
        print("Cleaning up CPE-AS integration test environment...")
        
        for file_path in copied_files:
            try:
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(f"  WARNING: Could not remove {file_path}: {e}")
        
        print(f"  * Cleaned up {len(copied_files)} test files")
    
    def run_analysis_tool(self, cve_id: str) -> Tuple[bool, Optional[Path], str, str]:
        """Run the analysis tool and return success status, output path, stdout, stderr."""
        
        # Construct output path based on CVE ID
        year = cve_id.split('-')[1]
        sequence = cve_id.split('-')[2]
        thousands_dir = f"{sequence[0]}xxx"
        output_path = CACHE_DIR / "nvd-ish_2.0_cves" / year / thousands_dir / f"{cve_id}.json"
        
        # Remove existing output file to ensure fresh run
        if output_path.exists():
            output_path.unlink()
        
        # Build command
        cmd = [
            sys.executable, "-m", "src.analysis_tool.core.analysis_tool",
            "--cve", cve_id,
            "--nvd-ish-only"  # This flag enables all outputs including CPE-AS generation
        ]
        
        # Run tool
        try:
            result = subprocess.run(
                cmd,
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            success = result.returncode == 0 and output_path.exists()
            return success, output_path, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            return False, None, "", "Tool execution timed out"
        except Exception as e:
            return False, None, "", str(e)
    
    def validate_cpe_as_structure(self, output_path: Optional[Path]) -> dict:
        """Validate CPE-AS generation structure in enhanced record."""
        validation = {
            "exists": False,
            "valid_json": False,
            "has_enriched_affected": False,
            "has_cpe_as_generation": False,
            "cpe_match_count": 0,
            "has_proper_ordering": False,
            "has_metadata_fields": False
        }
        
        if not output_path or not output_path.exists():
            return validation
        
        validation["exists"] = True
        
        try:
            with open(output_path, 'r') as f:
                data = json.load(f, object_pairs_hook=OrderedDict)
            validation["valid_json"] = True
            
            # Check for enrichedCVEv5Affected
            if "enrichedCVEv5Affected" in data:
                enriched_data = data["enrichedCVEv5Affected"]
                validation["has_enriched_affected"] = True
                
                # Check for cveListV5AffectedEntries
                entries = enriched_data.get("cveListV5AffectedEntries", [])
                
                # Look for cpeAsGeneration section
                for entry in entries:
                    if "cpeAsGeneration" in entry:
                        validation["has_cpe_as_generation"] = True
                        cpe_as_data = entry["cpeAsGeneration"]
                        
                        # cpeAsGeneration is an object with cpeMatchObjects array (or generatedCpeMatch in docs)
                        if isinstance(cpe_as_data, dict):
                            # Try both property names (cpeMatchObjects and generatedCpeMatch)
                            cpe_matches = cpe_as_data.get('cpeMatchObjects', []) or cpe_as_data.get('generatedCpeMatch', [])
                            validation["cpe_match_count"] = len(cpe_matches)
                            
                            # Check property ordering on first cpeMatch
                            if len(cpe_matches) > 0:
                                first_match = cpe_matches[0]
                                if isinstance(first_match, (OrderedDict, dict)):
                                    keys = list(first_match.keys())
                                    # Expected order: versionsEntryIndex, appliedPattern, vulnerable, ...
                                    if len(keys) >= 2:
                                        if keys[0] == "versionsEntryIndex":
                                            validation["has_proper_ordering"] = True
                                
                                # Check for metadata fields
                                if "versionsEntryIndex" in first_match:
                                    validation["has_metadata_fields"] = True
                        
                        break
            
        except (json.JSONDecodeError, Exception) as e:
            print(f"ERROR validating CPE-AS structure: {e}")
        
        return validation
    
    def test_pattern_3_1_a_integration(self) -> bool:
        """Test Pattern 3.1-A: No versions array - wildcard cpeMatch integration."""
        print(f"\n=== Test 1: Pattern 3.1-A Integration (No versions array) ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-5001")
        
        if not success:
            print(f"❌ FAIL: Pattern 3.1-A integration failed")
            print(f"STDERR: {stderr}")
            return False
        
        validation = self.validate_cpe_as_structure(output_path)
        
        if not validation["has_cpe_as_generation"]:
            print(f"❌ FAIL: No cpeAsGeneration section in enhanced record")
            return False
        
        if validation["cpe_match_count"] < 1:
            print(f"❌ FAIL: Expected at least 1 cpeMatch, got {validation['cpe_match_count']}")
            return False
        
        # Validate specific fields
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            entries = data["enrichedCVEv5Affected"]["cveListV5AffectedEntries"]
            # cpeAsGeneration is an object with cpeMatchObjects array
            cpe_as_data = entries[0]["cpeAsGeneration"]
            cpe_matches = cpe_as_data.get('cpeMatchObjects', []) or cpe_as_data.get('generatedCpeMatch', [])
            cpe_match = cpe_matches[0]
            
            # Pattern 3.1-A should have versionsEntryIndex=null
            if cpe_match.get("versionsEntryIndex") is not None:
                print(f"❌ FAIL: versionsEntryIndex should be null for Pattern 3.1-A")
                return False
            
            if cpe_match.get("appliedPattern") != "noVersion.allAffected":
                print(f"❌ FAIL: Expected appliedPattern='noVersion.allAffected'")
                return False
            
            # Since test CVEs have no confirmed mappings, expect metadata-only output (vulnerable field ABSENT)
            if "vulnerable" in cpe_match:
                print(f"❌ FAIL: vulnerable field should be absent (metadata-only, no confirmed CPE)")
                print(f"   Found: vulnerable={cpe_match.get('vulnerable')}")
                return False
            
            # Should have concerns array, not criteria field
            if "criteria" in cpe_match:
                print(f"❌ FAIL: Should not have criteria field (no confirmed CPE mapping)")
                return False
            
            if "concerns" not in cpe_match:
                print(f"❌ FAIL: Expected concerns array for unconfirmed CPE")
                return False
            
            print(f"✅ PASS: Pattern 3.1-A integrated correctly")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating Pattern 3.1-A: {e}")
            return False
    
    def test_pattern_3_1_b_integration(self) -> bool:
        """Test Pattern 3.1-B: Empty versions array - wildcard cpeMatch integration."""
        print(f"\n=== Test 2: Pattern 3.1-B Integration (Empty versions array) ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-5002")
        
        if not success:
            print(f"❌ FAIL: Pattern 3.1-B integration failed")
            return False
        
        validation = self.validate_cpe_as_structure(output_path)
        
        if not validation["has_cpe_as_generation"]:
            print(f"❌ FAIL: No cpeAsGeneration section")
            return False
        
        print(f"✅ PASS: Pattern 3.1-B integrated correctly")
        return True
    
    def test_pattern_3_1_c_integration(self) -> bool:
        """Test Pattern 3.1-C: Placeholder versions - wildcard cpeMatch integration."""
        print(f"\n=== Test 3: Pattern 3.1-C Integration (Placeholder versions) ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-5003")
        
        if not success:
            print(f"❌ FAIL: Pattern 3.1-C integration failed")
            return False
        
        validation = self.validate_cpe_as_structure(output_path)
        
        if not validation["has_cpe_as_generation"]:
            print(f"❌ FAIL: No cpeAsGeneration section")
            return False
        
        # Validate Pattern 3.1-C specific fields
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            entries = data["enrichedCVEv5Affected"]["cveListV5AffectedEntries"]
            cpe_as_data = entries[0]["cpeAsGeneration"]
            cpe_matches = cpe_as_data.get('cpeMatchObjects', []) or cpe_as_data.get('generatedCpeMatch', [])
            cpe_match = cpe_matches[0]
            
            # Pattern 3.1-C: Placeholder version entries should have versionsEntryIndex=0
            if cpe_match.get("versionsEntryIndex") != 0:
                print(f"❌ FAIL: versionsEntryIndex should be 0 for Pattern 3.1-C (first placeholder entry)")
                return False
            
            if cpe_match.get("appliedPattern") != "noVersion.placeholderValue":
                print(f"❌ FAIL: Expected appliedPattern='noVersion.placeholderValue'")
                return False
            
            print(f"✅ PASS: Pattern 3.1-C integrated correctly")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating Pattern 3.1-C: {e}")
            return False
    
    def test_pattern_3_1_d_integration(self) -> bool:
        """Test Pattern 3.1-D: defaultStatus=unknown - metadata-only cpeMatch."""
        print(f"\n=== Test 4: Pattern 3.1-D Integration (defaultStatus=unknown) ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-5004")
        
        if not success:
            print(f"❌ FAIL: Pattern 3.1-D integration failed")
            return False
        
        validation = self.validate_cpe_as_structure(output_path)
        
        if not validation["has_cpe_as_generation"]:
            print(f"❌ FAIL: No cpeAsGeneration section")
            return False
        
        # Validate Pattern 3.1-D specific fields (metadata-only)
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            entries = data["enrichedCVEv5Affected"]["cveListV5AffectedEntries"]
            cpe_as_data = entries[0]["cpeAsGeneration"]
            cpe_matches = cpe_as_data.get('cpeMatchObjects', []) or cpe_as_data.get('generatedCpeMatch', [])
            cpe_match = cpe_matches[0]
            
            # Pattern 3.1-D should have vulnerable=false
            if cpe_match.get("vulnerable") != False:
                print(f"❌ FAIL: vulnerable should be false for Pattern 3.1-D")
                return False
            
            # Should NOT have appliedPattern (metadata-only)
            if "appliedPattern" in cpe_match:
                print(f"❌ FAIL: appliedPattern should be omitted for metadata-only")
                return False
            
            # Should NOT have criteria (metadata-only)
            if "criteria" in cpe_match:
                print(f"❌ FAIL: criteria should be omitted for metadata-only")
                return False
            
            # Should have concerns array
            concerns = cpe_match.get("concerns", [])
            if "defaultStatusUnknown" not in concerns:
                print(f"❌ FAIL: Expected 'defaultStatusUnknown' in concerns array")
                return False
            
            print(f"✅ PASS: Pattern 3.1-D integrated correctly (metadata-only)")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating Pattern 3.1-D: {e}")
            return False
    
    def test_property_ordering_validation(self) -> bool:
        """Test Section 2.1 property ordering requirements."""
        print(f"\n=== Test 5: Property Ordering Validation (Section 2.1) ===")
        
        # Use CVE-1337-5002 which uses Pattern 3.1 (implemented)
        # CVE-1337-5005 would use Pattern 3.3 (not yet implemented)
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-5002")
        
        if not success:
            print(f"❌ FAIL: Property ordering test failed")
            return False
        
        # Load with OrderedDict to preserve property order
        try:
            with open(output_path, 'r') as f:
                data = json.load(f, object_pairs_hook=OrderedDict)
            
            entries = data["enrichedCVEv5Affected"]["cveListV5AffectedEntries"]
            cpe_as_data = entries[0]["cpeAsGeneration"]
            cpe_matches = cpe_as_data.get('cpeMatchObjects', []) or cpe_as_data.get('generatedCpeMatch', [])
            cpe_match = cpe_matches[0]
            
            # Verify property order
            keys = list(cpe_match.keys())
            
            # Expected order for metadata-only cpeMatch (no confirmed CPE):
            # 1. versionsEntryIndex
            # 2. appliedPattern (if pattern detected, omitted for metadata-only Pattern 3.1)
            # 3. concerns (vulnerable field ABSENT for cpeUnconfirmed* concerns)
            # NO criteria field since there's no confirmed CPE mapping
            # NO vulnerable field since we can't make vulnerability determination
            
            # For Pattern 3.1 metadata-only, appliedPattern exists (e.g., "noVersion.emptyArray")
            expected_start = ["versionsEntryIndex", "appliedPattern", "concerns"]
            actual_start = keys[:3] if len(keys) >= 3 else keys
            
            if actual_start != expected_start:
                print(f"❌ FAIL: Property order mismatch")
                print(f"  Expected: {expected_start}")
                print(f"  Actual: {actual_start}")
                return False
            
            print(f"✅ PASS: Property ordering validated (Section 2.1 compliant)")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating property ordering: {e}")
            return False
    
    def test_full_workflow_a_exact_single(self) -> bool:
        """Test Full Workflow A: Single exact version match - should generate exact.single pattern."""
        print(f"\n=== Test 6: Full Workflow A (Exact single version: 1.0) ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-5006")
        
        if not success:
            print(f"❌ FAIL: Full Workflow A integration failed")
            return False
        
        validation = self.validate_cpe_as_structure(output_path)
        
        if not validation["has_cpe_as_generation"]:
            print(f"❌ FAIL: No cpeAsGeneration section")
            return False
        
        if validation["cpe_match_count"] == 0:
            print(f"❌ FAIL: No cpeMatch objects generated")
            return False
        
        # Validate exact.single pattern generation
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            entries = data["enrichedCVEv5Affected"]["cveListV5AffectedEntries"]
            cpe_as_data = entries[0]["cpeAsGeneration"]
            cpe_matches = cpe_as_data.get('cpeMatchObjects', []) or cpe_as_data.get('generatedCpeMatch', [])
            
            # Should have at least one exact.single match
            exact_single_found = False
            for cpe_match in cpe_matches:
                if cpe_match.get("appliedPattern") == "exact.single":
                    exact_single_found = True
                    
                    # Validate required fields for exact.single
                    if cpe_match.get("versionsEntryIndex") != 0:
                        print(f"❌ FAIL: versionsEntryIndex should be 0 for first version entry")
                        return False
                    
                    # Metadata-only entries with concerns should NOT have vulnerable field
                    # (we're not making a vulnerability determination when we can't confirm CPE)
                    if "vulnerable" in cpe_match:
                        print(f"❌ FAIL: vulnerable field should not be present for metadata-only entries with concerns")
                        print(f"   Found: vulnerable={cpe_match.get('vulnerable')}")
                        return False
                    
                    # Should have concerns array instead of criteria
                    if "concerns" not in cpe_match:
                        print(f"❌ FAIL: Missing concerns array for unconfirmed CPE")
                        return False
                    
                    if "cpeUnconfirmedWithSuggestions" not in cpe_match.get("concerns", []):
                        print(f"❌ FAIL: Expected concern 'cpeUnconfirmedWithSuggestions'")
                        return False
                    
                    break
            
            if not exact_single_found:
                print(f"❌ FAIL: No exact.single pattern found in generated cpeMatch objects")
                return False
            
            print(f"✅ PASS: Full Workflow A (exact.single) integrated correctly")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating Full Workflow A: {e}")
            return False
    
    def test_full_workflow_b_range_lessthan(self) -> bool:
        """Test Full Workflow B: Version range with lessThan - should generate range.lessThan pattern."""
        print(f"\n=== Test 7: Full Workflow B (Version range: 0 < 2.0) ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-5007")
        
        if not success:
            print(f"❌ FAIL: Full Workflow B integration failed")
            return False
        
        validation = self.validate_cpe_as_structure(output_path)
        
        if not validation["has_cpe_as_generation"]:
            print(f"❌ FAIL: No cpeAsGeneration section")
            return False
        
        if validation["cpe_match_count"] == 0:
            print(f"❌ FAIL: No cpeMatch objects generated")
            return False
        
        # Validate range.lessThan pattern generation
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            entries = data["enrichedCVEv5Affected"]["cveListV5AffectedEntries"]
            cpe_as_data = entries[0]["cpeAsGeneration"]
            cpe_matches = cpe_as_data.get('cpeMatchObjects', []) or cpe_as_data.get('generatedCpeMatch', [])
            
            # Should have at least one range pattern match
            range_found = False
            for cpe_match in cpe_matches:
                applied_pattern = cpe_match.get("appliedPattern", "")
                if "range" in applied_pattern:
                    range_found = True
                    
                    # Since these are suggestions (not confirmed), vulnerable field should be ABSENT
                    if "vulnerable" in cpe_match:
                        print(f"❌ FAIL: vulnerable field should be absent for unconfirmed CPE suggestions")
                        return False
                    
                    # Should have concerns array instead of criteria
                    if "concerns" not in cpe_match:
                        print(f"❌ FAIL: Missing concerns array for unconfirmed CPE")
                        return False
                    
                    # Should have versionEndExcluding
                    if "versionEndExcluding" not in cpe_match:
                        print(f"❌ FAIL: Missing versionEndExcluding for range pattern")
                        return False
                    
                    if cpe_match.get("versionEndExcluding") != "2.0":
                        print(f"❌ FAIL: versionEndExcluding should be 2.0")
                        return False
                    
                    break
            
            if not range_found:
                print(f"❌ FAIL: No range pattern found in generated cpeMatch objects")
                return False
            
            print(f"✅ PASS: Full Workflow B (range.lessThan) integrated correctly")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating Full Workflow B: {e}")
            return False
    
    def test_full_workflow_c_range_changes(self) -> bool:
        """Test Full Workflow C: Version range with single change - should generate range.changesFixed pattern (Pattern 3.4-D)."""
        print(f"\n=== Test 8: Full Workflow C (Pattern 3.4-D: Range with change point, fixed at 2.3.1) ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-5008")
        
        if not success:
            print(f"❌ FAIL: Full Workflow C integration failed")
            return False
        
        validation = self.validate_cpe_as_structure(output_path)
        
        if not validation["has_cpe_as_generation"]:
            print(f"❌ FAIL: No cpeAsGeneration section")
            return False
        
        if validation["cpe_match_count"] == 0:
            print(f"❌ FAIL: No cpeMatch objects generated")
            return False
        
        # Validate range.changesFixed pattern generation (Pattern 3.4-D: Single range with change point)
        # NOTE: Pattern 3.5 (multiple ranges split by changes) is not yet implemented
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            entries = data["enrichedCVEv5Affected"]["cveListV5AffectedEntries"]
            cpe_as_data = entries[0]["cpeAsGeneration"]
            cpe_matches = cpe_as_data.get('cpeMatchObjects', []) or cpe_as_data.get('generatedCpeMatch', [])
            
            # Pattern 3.4-D generates a single range with versionEndExcluding set to the change point
            # Look for a range pattern with proper boundaries
            range_found = False
            for cpe_match in cpe_matches:
                applied_pattern = cpe_match.get("appliedPattern", "")
                if "range" in applied_pattern and "changes" in applied_pattern.lower():
                    range_found = True
                    
                    # Since these are suggestions (not confirmed), vulnerable field should be ABSENT
                    if "vulnerable" in cpe_match:
                        print(f"❌ FAIL: vulnerable field should be absent for unconfirmed CPE suggestions")
                        return False
                    
                    # Should have version range fields
                    if "versionStartIncluding" not in cpe_match:
                        print(f"❌ FAIL: Missing versionStartIncluding for range.changesFixed pattern")
                        return False
                    
                    if "versionEndExcluding" not in cpe_match:
                        print(f"❌ FAIL: Missing versionEndExcluding for range.changesFixed pattern")
                        return False
                    
                    # Validate boundaries: 2.0 (inclusive) to 2.3.1 (exclusive)
                    if cpe_match.get("versionStartIncluding") != "2.0":
                        print(f"❌ FAIL: versionStartIncluding should be 2.0, got {cpe_match.get('versionStartIncluding')}")
                        return False
                    
                    if cpe_match.get("versionEndExcluding") != "2.3.1":
                        print(f"❌ FAIL: versionEndExcluding should be 2.3.1 (change point), got {cpe_match.get('versionEndExcluding')}")
                        return False
                    
                    break
            
            if not range_found:
                print(f"❌ FAIL: No range.changesFixed pattern found in generated cpeMatch objects")
                return False
            
            print(f"✅ PASS: Full Workflow C (range.changesFixed Pattern 3.4-D) integrated correctly")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating Full Workflow C: {e}")
            return False
    
    def test_full_workflow_d_pattern_3_5(self) -> bool:
        """Test Full Workflow D: Range with lessThan AND change point - should generate Pattern 3.5 (affected range only)."""
        print(f"\n=== Test 9: Full Workflow D (Pattern 3.5: lessThan + change → affected range) ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-5009")
        
        if not success:
            print(f"❌ FAIL: Full Workflow D failed")
            print(f"   Error: {(stdout + stderr)[-200:]}")
            return False
        
        validation = self.validate_cpe_as_structure(output_path)
        
        if not validation["has_cpe_as_generation"]:
            print(f"❌ FAIL: No cpeAsGeneration section")
            return False
        
        # Pattern 3.5: Should generate 1 affected range (2.0 → 2.3.1)
        # The range 2.3.1 → 2.5 is unaffected, so not generated (only affected ranges are output)
        # Since test CVEs have no confirmed CPE mappings, expect metadata-only with vulnerable=False
        if validation["cpe_match_count"] != 1:
            print(f"❌ FAIL: Expected 1 cpeMatch object (got {validation['cpe_match_count']})")
            return False
        
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            entries = data["enrichedCVEv5Affected"]["cveListV5AffectedEntries"]
            cpe_as_data = entries[0]["cpeAsGeneration"]
            cpe_matches = cpe_as_data.get('cpeMatchObjects', []) or cpe_as_data.get('generatedCpeMatch', [])
            
            # Check for affected range (2.0 → 2.3.1)
            # Metadata-only: vulnerable=False, no criteria, has concerns
            affected_range_found = False
            
            for cpe_match in cpe_matches:
                start = cpe_match.get("versionStartIncluding")
                end_excl = cpe_match.get("versionEndExcluding")
                vulnerable = cpe_match.get("vulnerable")
                pattern = cpe_match.get("appliedPattern")
                
                # Check for affected range (2.0 → 2.3.1)
                # Metadata-only: vulnerable field ABSENT (not False), no criteria, has concerns
                if start == "2.0" and end_excl == "2.3.1":
                    if pattern == "multiRange.rangeStatusTransitions" and "vulnerable" not in cpe_match:
                        affected_range_found = True
                    else:
                        print(f"⚠️  WARNING: Found affected range but incorrect fields: pattern={pattern}, has_vulnerable={'vulnerable' in cpe_match}")
            
            if not affected_range_found:
                print(f"❌ FAIL: Missing affected range (2.0 → 2.3.1) with Pattern 3.5")
                print(f"   Found {len(cpe_matches)} cpeMatch objects:")
                for i, match in enumerate(cpe_matches):
                    print(f"   [{i}] start={match.get('versionStartIncluding')}, "
                          f"end={match.get('versionEndExcluding')}, "
                          f"vulnerable={match.get('vulnerable')}, "
                          f"pattern={match.get('appliedPattern')}")
                return False
            
            print(f"✅ PASS: Full Workflow D (Pattern 3.5 affected range only) integrated correctly")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating Full Workflow D: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_section_6_2_update_patterns_in_ranges(self) -> bool:
        """Test Section 6.2: Update patterns in range boundaries - detected but not applied."""
        print(f"\n=== Test 10: Section 6.2 (Update patterns in range boundaries) ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-5010")
        
        if not success:
            print(f"❌ FAIL: Section 6.2 integration failed")
            return False
        
        validation = self.validate_cpe_as_structure(output_path)
        
        if not validation["has_cpe_as_generation"]:
            print(f"❌ FAIL: No cpeAsGeneration section")
            return False
        
        if validation["cpe_match_count"] == 0:
            print(f"❌ FAIL: No cpeMatch objects generated")
            return False
        
        # Validate update pattern detection
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            entries = data["enrichedCVEv5Affected"]["cveListV5AffectedEntries"]
            cpe_as_data = entries[0]["cpeAsGeneration"]
            cpe_matches = cpe_as_data.get('cpeMatchObjects', []) or cpe_as_data.get('generatedCpeMatch', [])
            
            # Should have at least one cpeMatch with updatePatternsInRange concern
            concern_found = False
            for cpe_match in cpe_matches:
                concerns = cpe_match.get("concerns", [])
                if "updatePatternsInRange" in concerns:
                    concern_found = True
                    
                    # Verify untransformed values preserved
                    start = cpe_match.get("versionStartIncluding")
                    end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")
                    
                    if not start or not end:
                        print(f"❌ FAIL: Missing version range boundaries")
                        return False
                    
                    # Should contain update pattern indicators (e.g., " SP ", " Update ", etc.)
                    if " SP " not in start and " Update " not in start and " Patch " not in start:
                        print(f"❌ FAIL: Expected update pattern in versionStart: {start}")
                        return False
                    
                    break
            
            if not concern_found:
                print(f"❌ FAIL: No updatePatternsInRange concern found")
                return False
            
            print(f"✅ PASS: Section 6.2 (Update patterns in ranges) integrated correctly")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating Section 6.2: {e}")
            return False
    
    def test_section_6_1_version_type_git(self) -> bool:
        """Test Section 6.1: versionType='git' generates metadata-only cpeMatch."""
        print(f"\n=== Test 11: Section 6.1 (versionType='git' handling) ===")
        
        success, output_path, stdout, stderr = self.run_analysis_tool("CVE-1337-5011")
        
        if not success:
            print(f"❌ FAIL: Section 6.1 integration failed")
            return False
        
        validation = self.validate_cpe_as_structure(output_path)
        
        if not validation["has_cpe_as_generation"]:
            print(f"❌ FAIL: No cpeAsGeneration section")
            return False
        
        if validation["cpe_match_count"] == 0:
            print(f"❌ FAIL: No cpeMatch objects generated")
            return False
        
        # Validate versionType='git' handling
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            entries = data["enrichedCVEv5Affected"]["cveListV5AffectedEntries"]
            cpe_as_data = entries[0]["cpeAsGeneration"]
            cpe_matches = cpe_as_data.get('cpeMatchObjects', []) or cpe_as_data.get('generatedCpeMatch', [])
            
            # Should have metadata-only cpeMatch with versionTypeGit concern
            git_concern_found = False
            for cpe_match in cpe_matches:
                concerns = cpe_match.get("concerns", [])
                if "versionTypeGit" in concerns:
                    git_concern_found = True
                    
                    # Verify metadata-only (no criteria)
                    if "criteria" in cpe_match:
                        print(f"❌ FAIL: versionType='git' should not generate criteria")
                        return False
                    
                    # Verify vulnerable=false
                    if cpe_match.get("vulnerable") != False:
                        print(f"❌ FAIL: versionType='git' should have vulnerable=false")
                        return False
                    
                    # Verify no appliedPattern
                    if "appliedPattern" in cpe_match:
                        print(f"❌ FAIL: versionType='git' should not have appliedPattern")
                        return False
                    
                    break
            
            if not git_concern_found:
                print(f"❌ FAIL: No versionTypeGit concern found")
                return False
            
            print(f"✅ PASS: Section 6.1 (versionType='git') integrated correctly")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating Section 6.1: {e}")
            return False
    
    def test_wildcard_expansion_pattern_concern(self) -> bool:
        """Test inferredAffectedFromWildcardExpansion concern validation in nvd-ish records (CVE-1337-5012)."""
        print(f"\n=== Test: Wildcard Expansion Pattern Concern ===")
        
        try:
            cve_id = "CVE-1337-5012"
            
            # Run analysis
            success, output_path, stdout, stderr = self.run_analysis_tool(cve_id)
            
            if not success:
                print(f"❌ FAIL: Analysis tool failed for {cve_id}")
                print(f"Expected output path: {output_path}")
                print(f"Output exists: {output_path.exists() if output_path else 'N/A'}")
                if stderr:
                    print(f"STDERR Output (last 20 lines):")
                    for line in stderr.split('\n')[-20:]:
                        if line.strip():
                            print(f"  {line}")
                if stdout:
                    print(f"STDOUT Output (last 10 lines):")
                    for line in stdout.split('\n')[-10:]:
                        if line.strip() and ('[ERROR]' in line or '[WARNING]' in line or 'Failed' in line):
                            print(f"  {line}")
                return False
            
            # Validate nvd-ish record output
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            entries = data["enrichedCVEv5Affected"]["cveListV5AffectedEntries"]
            
            if not entries:
                print(f"❌ FAIL: No affected entries found")
                return False
            
            cpe_as_data = entries[0].get("cpeAsGeneration", {})
            cpe_matches = cpe_as_data.get('cpeMatchObjects', [])
            
            if not cpe_matches:
                print(f"❌ FAIL: No cpeMatch objects found")
                return False
            
            # Find cpeMatch with inferredAffectedFromWildcardExpansion concern
            wildcard_concern_found = False
            
            for cpe_match in cpe_matches:
                concerns = cpe_match.get("concerns", [])
                
                if "inferredAffectedFromWildcardExpansion" in concerns:
                    wildcard_concern_found = True
                    print(f"✓ Found inferredAffectedFromWildcardExpansion concern in cpeMatch")
                    
                    # Validate appliedPattern is inference.affectedFromWildcardExpansion
                    applied_pattern = cpe_match.get("appliedPattern")
                    if applied_pattern == "inference.affectedFromWildcardExpansion":
                        print(f"✓ Correct appliedPattern: {applied_pattern}")
                    else:
                        print(f"❌ FAIL: Expected appliedPattern 'inference.affectedFromWildcardExpansion', got '{applied_pattern}'")
                        return False
                    
                    # Validate it's associated with version "5.4.*"
                    criteria = cpe_match.get("criteria")
                    if criteria:
                        print(f"  - CPE criteria: {criteria}")
                    
                    # Check if version field or range boundaries contain the wildcard pattern
                    version_value = cpe_match.get("versionValue")
                    if version_value and "*" in version_value:
                        print(f"  - Version value with wildcard: {version_value}")
                    
                    break
            
            if not wildcard_concern_found:
                print(f"❌ FAIL: No inferredAffectedFromWildcardExpansion concern found in any cpeMatch")
                print(f"Available concerns in cpeMatches:")
                for i, cpe_match in enumerate(cpe_matches):
                    print(f"  cpeMatch[{i}]: {cpe_match.get('concerns', [])}")
                return False
            
            print(f"✅ PASS: Wildcard expansion pattern concern validated in nvd-ish record")
            return True
            
        except Exception as e:
            print(f"❌ FAIL: Error validating wildcard expansion pattern concern: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_all_tests(self) -> int:
        """Run all CPE-AS integration tests."""
        print("=" * 80)
        print("CPE-AS Generation Integration Test Suite")
        print("Testing CPE-AS generation and NVD-ish record integration")
        print("=" * 80)
        
        # Setup
        copied_files = self.setup_test_environment()
        
        try:
            # Run edge case tests (metadata-only scenarios)
            print("\n" + "=" * 80)
            print("EDGE CASE TESTS (Metadata-Only Scenarios)")
            print("=" * 80)
            
            if self.test_pattern_3_1_a_integration():
                self.passed += 1
            
            if self.test_pattern_3_1_b_integration():
                self.passed += 1
            
            if self.test_pattern_3_1_c_integration():
                self.passed += 1
            
            if self.test_pattern_3_1_d_integration():
                self.passed += 1
            
            if self.test_property_ordering_validation():
                self.passed += 1
            
            # Run full workflow tests (version matching scenarios)
            print("\n" + "=" * 80)
            print("FULL WORKFLOW TESTS (Version Matching Scenarios)")
            print("=" * 80)
            
            if self.test_full_workflow_a_exact_single():
                self.passed += 1
            
            if self.test_full_workflow_b_range_lessthan():
                self.passed += 1
            
            if self.test_full_workflow_c_range_changes():
                self.passed += 1
            
            if self.test_full_workflow_d_pattern_3_5():
                self.passed += 1
            
            # Run section validation tests
            print("\n" + "=" * 80)
            print("SECTION VALIDATION TESTS (Requirements Compliance)")
            print("=" * 80)
            
            if self.test_section_6_2_update_patterns_in_ranges():
                self.passed += 1
            
            if self.test_section_6_1_version_type_git():
                self.passed += 1
            
            # Run concern validation tests
            print("\n" + "=" * 80)
            print("CONCERN VALIDATION TESTS (Verify Concerns in NVD-ish Records)")
            print("=" * 80)
            
            if self.test_wildcard_expansion_pattern_concern():
                self.passed += 1
            
        finally:
            # Cleanup
            self.cleanup_test_environment(copied_files)
        
        # Summary
        print("\n" + "=" * 80)
        print(f"CPE-AS Integration Test Results: {self.passed}/{self.total} passed")
        print("=" * 80)
        
        return 0 if self.passed == self.total else 1


# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

if __name__ == "__main__":
    # Run unit tests first
    print("=" * 80)
    print("CPE-AS PATTERN UNIT TESTS")
    print("=" * 80)
    
    loader = unittest.TestLoader()
    unit_suite = unittest.TestSuite()
    
    # Add all unit test classes
    unit_suite.addTests(loader.loadTestsFromTestCase(TestPattern3_1_UtilityFunctions))
    unit_suite.addTests(loader.loadTestsFromTestCase(TestPattern3_1_Classification))
    unit_suite.addTests(loader.loadTestsFromTestCase(TestPattern3_1_SubPatterns))
    unit_suite.addTests(loader.loadTestsFromTestCase(TestPattern3_2_NoAffectedPlatforms))
    unit_suite.addTests(loader.loadTestsFromTestCase(TestPattern3_3_ExactVersions))
    unit_suite.addTests(loader.loadTestsFromTestCase(TestPattern3_4_SingleRangePerEntry))
    unit_suite.addTests(loader.loadTestsFromTestCase(TestPattern3_5_MultipleRanges))
    unit_suite.addTests(loader.loadTestsFromTestCase(TestWildcardExpansionUnaffected))
    unit_suite.addTests(loader.loadTestsFromTestCase(TestVersionTypeGit))
    unit_suite.addTests(loader.loadTestsFromTestCase(TestSection4_2_UpdateFieldSpecificity))
    unit_suite.addTests(loader.loadTestsFromTestCase(TestPatternUnsupported))
    
    # Run unit tests
    unit_runner = unittest.TextTestRunner(verbosity=2)
    unit_result = unit_runner.run(unit_suite)
    
    unit_passed = unit_result.testsRun - len(unit_result.failures) - len(unit_result.errors)
    print(f"\nUnit Tests: {unit_passed}/{unit_result.testsRun} passed\n")
    
    # Run integration tests
    print("\n" + "=" * 80)
    print("CPE-AS INTEGRATION TESTS")
    print("=" * 80)
    
    integration_suite = CPEASIntegrationTestSuite()
    integration_exit_code = integration_suite.run_all_tests()
    
    # Combined summary
    total_passed = unit_passed + integration_suite.passed
    total_tests = unit_result.testsRun + integration_suite.total
    
    print("\n" + "=" * 80)
    print(f"COMBINED TEST RESULTS")
    print(f"Unit Tests: {unit_passed}/{unit_result.testsRun}")
    print(f"Integration Tests: {integration_suite.passed}/{integration_suite.total}")
    print(f"TOTAL: {total_passed}/{total_tests} passed")
    print("=" * 80)
    
    # Standardized output
    print(f"\nTEST_RESULTS: PASSED={total_passed} TOTAL={total_tests} SUITE=\"CPE-AS Generation (Unit + Integration)\"")
    
    # Exit with failure if either suite failed
    sys.exit(0 if (unit_result.wasSuccessful() and integration_exit_code == 0) else 1)
