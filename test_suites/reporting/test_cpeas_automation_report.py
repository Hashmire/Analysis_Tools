#!/usr/bin/env python3
"""
Test Suite: CPE-AS Automation Report Generation

Validates that nvd-ish cache records produce correct report structure and values.
Tests exact data transformations from source → summary → index.

Usage:
    python test_suites/reporting/test_cpeas_automation_report.py
"""

import json
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from src.analysis_tool.reporting.generate_cpeas_automation_report import (
    CPEASAutomationReportBuilder,
    scan_nvd_ish_cache,
    generate_report
)
from src.analysis_tool.storage.run_organization import get_analysis_tools_root


# Test data: Known nvd-ish records with expected outputs
TEST_CVE_1337_0001 = {
    "id": "CVE-1337-0001",
    "sourceIdentifier": "test@example.com",
    "published": "2024-01-15T10:00:00.000",
    "enrichedCVEv5Affected": {
        "cveListV5AffectedEntries": [
            {
                "originAffectedEntry": {
                    "sourceId": "test-source-uuid-1234",
                    "vendor": "TestVendor",
                    "product": "TestProduct",
                    "platforms": ["Windows"],
                    "versions": [
                        {"version": "1.0.0", "status": "affected"},
                        {"version": "1.1.0", "status": "affected"}
                    ]
                },
                "cpeDetermination": {
                    "confirmedMappings": ["cpe:2.3:a:testvendor:testproduct:*:*:*:*:*:*:*:*"]
                },
                "cpeAsGeneration": {
                    "cpeMatchObjects": [
                        {
                            "criteria": "cpe:2.3:a:testvendor:testproduct:1.0.0:*:*:*:*:*:*:*",
                            "versionStartIncluding": "1.0.0",
                            "appliedPattern": "exact.single",
                            "concerns": []
                        },
                        {
                            "criteria": "cpe:2.3:a:testvendor:testproduct:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "2.0.0",
                            "appliedPattern": "range.lessThan",
                            "concerns": []
                        }
                    ]
                }
            },
            {
                "originAffectedEntry": {
                    "sourceId": "test-source-uuid-1234",
                    "vendor": "TestVendor",
                    "product": "TestProduct2",
                    "platforms": ["Linux"],
                    "versions": [
                        {"version": "3.0.0", "status": "affected"}
                    ]
                },
                "cpeDetermination": {
                    "top10SuggestedCPEBaseStrings": ["cpe:2.3:a:testvendor:testproduct2:*:*:*:*:*:*:*:*"]
                },
                "cpeAsGeneration": {
                    "cpeMatchObjects": [
                        {
                            "criteria": "cpe:2.3:a:testvendor:testproduct2:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "3.1.0",
                            "appliedPattern": "range.lessThan",
                            "concerns": ["cpeUnconfirmedWithSuggestions"]
                        }
                    ]
                }
            }
        ]
    }
}

TEST_CVE_1337_0002 = {
    "id": "CVE-1337-0002",
    "sourceIdentifier": "test@example.com",
    "published": "2024-01-16T10:00:00.000",
    "enrichedCVEv5Affected": {
        "cveListV5AffectedEntries": [
            {
                "originAffectedEntry": {
                    "sourceId": "test-source-uuid-1234",
                    "vendor": "TestVendor",
                    "product": "AnotherProduct",
                    "platforms": [],
                    "versions": []
                },
                "cpeDetermination": {},
                "cpeAsGeneration": {
                    "cpeMatchObjects": [
                        {
                            "criteria": "cpe:2.3:a:testvendor:anotherproduct:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "1.0.0-beta",
                            "appliedPattern": "range.lessThan",
                            "concerns": ["updatePatternsInRange", "cpeUnconfirmedNoSuggestions"]
                        }
                    ]
                }
            }
        ]
    }
}

TEST_CVE_1337_0003 = {
    "id": "CVE-1337-0003",
    "sourceIdentifier": "other@example.com",
    "published": "2024-01-17T10:00:00.000",
    "enrichedCVEv5Affected": {
        "cveListV5AffectedEntries": [
            {
                "originAffectedEntry": {
                    "sourceId": "different-source-uuid-5678",
                    "vendor": "DifferentVendor",
                    "product": "DifferentProduct",
                    "platforms": ["macOS"],
                    "versions": [
                        {"version": "2.0.0", "status": "affected"}
                    ]
                },
                "cpeDetermination": {
                    "confirmedMappings": ["cpe:2.3:a:differentvendor:differentproduct:*:*:*:*:*:*:*:*"]
                },
                "cpeAsGeneration": {
                    "cpeMatchObjects": [
                        {
                            "criteria": "cpe:2.3:a:differentvendor:differentproduct:2.0.0:*:*:*:*:*:*:*",
                            "versionStartIncluding": "2.0.0",
                            "appliedPattern": "exact.single",
                            "concerns": []
                        }
                    ]
                }
            }
        ]
    }
}

# Test data: NonActionable entry (ALL fields are placeholders)
TEST_CVE_1337_0009 = {
    "id": "CVE-1337-0009",
    "sourceIdentifier": "test@example.com",
    "published": "2024-01-23T00:00:00.000",
    "enrichedCVEv5Affected": {
        "cveListV5AffectedEntries": [
            {
                "originAffectedEntry": {
                    "sourceId": "test-source-uuid-1234",
                    "vendor": "n/a",
                    "product": "n/a",
                    "packageName": "",
                    "repo": "",
                    "collectionURL": "",
                    "platforms": [],
                    "versions": [
                        {"version": "n/a", "status": "affected"}
                    ]
                },
                "cpeDetermination": {},
                "cpeAsGeneration": {
                    "cpeMatchObjects": []
                }
            }
        ]
    }
}

# Test data: Placeholder version but REAL vendor/product (NOT nonActionable)
TEST_CVE_1337_0014 = {
    "id": "CVE-1337-0014",
    "sourceIdentifier": "test@example.com",
    "published": "2024-01-28T00:00:00.000",
    "enrichedCVEv5Affected": {
        "cveListV5AffectedEntries": [
            {
                "originAffectedEntry": {
                    "sourceId": "test-source-uuid-1234",
                    "vendor": "linux",
                    "product": "linux_kernel",
                    "packageName": "",
                    "repo": "",
                    "collectionURL": "",
                    "platforms": ["Linux"],
                    "versions": [
                        {"version": "n/a", "status": "affected"}
                    ]
                },
                "cpeDetermination": {
                    "confirmedMappings": ["cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"]
                },
                "cpeAsGeneration": {
                    "cpeMatchObjects": [
                        {
                            "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                            "appliedPattern": "noVersion.placeholderValue",
                            "concerns": []
                        }
                    ]
                }
            }
        ]
    }
}


class TestCPEASAutomationReport:
    """Test CPE-AS Automation Report generation with exact validation."""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.test_cache_dir = None
        self.results = []
    
    def setup_test_cache(self):
        """Create temporary cache with test CVE data."""
        self.test_cache_dir = tempfile.mkdtemp(prefix="test_cpe_report_")
        cache_path = Path(self.test_cache_dir)
        
        # Create nested structure like real cache
        cve1_dir = cache_path / "1337" / "0xxx"
        cve1_dir.mkdir(parents=True, exist_ok=True)
        
        cve2_dir = cache_path / "1337" / "0xxx"
        cve2_dir.mkdir(parents=True, exist_ok=True)
        
        cve3_dir = cache_path / "1337" / "0xxx"
        cve3_dir.mkdir(parents=True, exist_ok=True)
        
        # Write test files
        with open(cve1_dir / "CVE-1337-0001.json", 'w') as f:
            json.dump(TEST_CVE_1337_0001, f)
        
        with open(cve2_dir / "CVE-1337-0002.json", 'w') as f:
            json.dump(TEST_CVE_1337_0002, f)
        
        with open(cve3_dir / "CVE-1337-0003.json", 'w') as f:
            json.dump(TEST_CVE_1337_0003, f)
        
        return cache_path
    
    def teardown_test_cache(self):
        """Clean up temporary cache."""
        if self.test_cache_dir and Path(self.test_cache_dir).exists():
            shutil.rmtree(self.test_cache_dir)
    
    def assert_equals(self, test_name: str, expected: Any, actual: Any, context: str = ""):
        """Assert two values are equal."""
        if expected == actual:
            self.passed += 1
            self.results.append(f"PASS: {test_name}")
            print(f"  PASS {test_name}")
            return True
        else:
            self.failed += 1
            error_msg = f"FAIL: {test_name}\n    Expected: {expected}\n    Actual: {actual}"
            if context:
                error_msg += f"\n    Context: {context}"
            self.results.append(error_msg)
            print(f"  FAIL {test_name}")
            print(f"    Expected: {expected}")
            print(f"    Actual: {actual}")
            if context:
                print(f"    Context: {context}")
            return False
    
    def assert_structure(self, test_name: str, data: Dict, required_keys: list, context: str = ""):
        """Assert dictionary has required keys."""
        missing = [k for k in required_keys if k not in data]
        if not missing:
            self.passed += 1
            self.results.append(f"PASS: {test_name}")
            print(f"  PASS {test_name}")
            return True
        else:
            self.failed += 1
            error_msg = f"FAIL: {test_name}\n    Missing keys: {missing}"
            if context:
                error_msg += f"\n    Context: {context}"
            self.results.append(error_msg)
            print(f"  FAIL {test_name}")
            print(f"    Missing keys: {missing}")
            if context:
                print(f"    Context: {context}")
            return False
    
    def test_builder_basic_grouping(self):
        """Test 1: Basic CVE grouping by source."""
        print("\nTest 1: Basic CVE grouping by source")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0001", TEST_CVE_1337_0001)
        builder.add_cve("CVE-1337-0002", TEST_CVE_1337_0002)
        builder.add_cve("CVE-1337-0003", TEST_CVE_1337_0003)
        
        # Should have 2 sources
        self.assert_equals("Source count", 2, len(builder.sources))
        
        # Check source 1 has correct CVE count
        source1 = builder.sources.get("test-source-uuid-1234")
        self.assert_equals("Source 1 CVE count", 2, len(source1['cve_ids']))
        self.assert_equals("Source 1 metadata CVE count", 2, source1['metadata']['total_cves_processed'])
        
        # Check source 2 has correct CVE count
        source2 = builder.sources.get("different-source-uuid-5678")
        self.assert_equals("Source 2 CVE count", 1, len(source2['cve_ids']))
    
    def test_multi_entry_cve_structure(self):
        """Test 2: Multi-entry CVE structure (CVE-1337-0001 has 2 affected entries)."""
        print("\nTest 2: Multi-entry CVE structure")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0001", TEST_CVE_1337_0001)
        
        source = builder.sources["test-source-uuid-1234"]
        cve_data = source['cve_data']
        
        # Should have 1 CVE entry (not 2 separate entries)
        self.assert_equals("CVE entry count", 1, len(cve_data))
        
        cve = cve_data[0]
        self.assert_equals("CVE ID", "CVE-1337-0001", cve['cve_id'])
        
        # Should have 2 affected entries
        self.assert_equals("Affected entries count", 2, len(cve['affected_entries']))
    
    def test_version_level_extraction(self):
        """Test 3: Version-level data extraction."""
        print("\nTest 3: Version-level data extraction")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0001", TEST_CVE_1337_0001)
        
        source = builder.sources["test-source-uuid-1234"]
        cve = source['cve_data'][0]
        entry1 = cve['affected_entries'][0]
        
        # Check versions array exists and has correct count
        versions = entry1.get('versions', [])
        self.assert_equals("Entry 1 version count", 2, len(versions))
        
        # Check version details
        if len(versions) >= 2:
            v1 = versions[0]
            self.assert_structure("Version 1 structure", v1, ['version', 'cpe_as_status', 'pattern', 'concerns'])
            self.assert_equals("Version 1 pattern", "exact.single", v1.get('pattern'))
            self.assert_equals("Version 1 status", "complete", v1.get('cpe_as_status'))
            self.assert_equals("Version 1 concerns", [], v1.get('concerns'))
            
            v2 = versions[1]
            self.assert_equals("Version 2 pattern", "range.lessThan", v2.get('pattern'))
    
    def test_pattern_usage_frequency(self):
        """Test 4: Pattern usage frequency distribution."""
        print("\nTest 4: Pattern usage frequency distribution")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0001", TEST_CVE_1337_0001)
        
        source = builder.sources["test-source-uuid-1234"]
        cve = source['cve_data'][0]
        entry1 = cve['affected_entries'][0]
        
        # Check pattern_usage is a dict with counts
        pattern_usage = entry1.get('pattern_usage', {})
        self.assert_equals("Pattern usage type", dict, type(pattern_usage))
        self.assert_equals("exact.single count", 1, pattern_usage.get('exact.single', 0))
        self.assert_equals("range.lessThan count", 1, pattern_usage.get('range.lessThan', 0))
    
    def test_cpe_as_breakdown(self):
        """Test 5: CPE-AS breakdown with complete/partial/none counts."""
        print("\nTest 5: CPE-AS breakdown")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0001", TEST_CVE_1337_0001)
        
        source = builder.sources["test-source-uuid-1234"]
        cve = source['cve_data'][0]
        
        # Entry 1: 2 complete (no concerns)
        entry1 = cve['affected_entries'][0]
        breakdown1 = entry1.get('cpe_as_breakdown', {})
        self.assert_equals("Entry 1 complete count", 2, breakdown1.get('complete', 0))
        self.assert_equals("Entry 1 partial count", 0, breakdown1.get('partial', 0))
        self.assert_equals("Entry 1 none count", 0, breakdown1.get('none', 0))
        
        # Entry 2: 1 partial (has concerns)
        entry2 = cve['affected_entries'][1]
        breakdown2 = entry2.get('cpe_as_breakdown', {})
        self.assert_equals("Entry 2 complete count", 0, breakdown2.get('complete', 0))
        self.assert_equals("Entry 2 partial count", 1, breakdown2.get('partial', 0))
        self.assert_equals("Entry 2 none count", 0, breakdown2.get('none', 0))
    
    def test_cve_metadata_rollup(self):
        """Test 6: CVE-level metadata rollup."""
        print("\nTest 6: CVE metadata rollup")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0001", TEST_CVE_1337_0001)
        
        source = builder.sources["test-source-uuid-1234"]
        cve = source['cve_data'][0]
        metadata = cve.get('cve_metadata', {})
        
        # Structure validation
        self.assert_structure("CVE metadata structure", metadata, [
            'total_affected_entries', 'entries_full_automation', 'entries_partial_automation',
            'entries_no_automation', 'total_versions', 'total_cpe_matches',
            'cpe_as_rollup', 'overall_status'
        ])
        
        # Exact values
        self.assert_equals("Total affected entries", 2, metadata.get('total_affected_entries'))
        self.assert_equals("Entries full automation", 1, metadata.get('entries_full_automation'))
        self.assert_equals("Entries partial automation", 1, metadata.get('entries_partial_automation'))
        self.assert_equals("Total versions", 3, metadata.get('total_versions'))
        self.assert_equals("Total CPE matches", 3, metadata.get('total_cpe_matches'))
        
        # Rollup values
        rollup = metadata.get('cpe_as_rollup', {})
        self.assert_equals("CPE-AS rollup complete", 2, rollup.get('complete', 0))
        self.assert_equals("CPE-AS rollup partial", 1, rollup.get('partial', 0))
        self.assert_equals("CPE-AS rollup none", 0, rollup.get('none', 0))
        
        # Overall status
        self.assert_equals("Overall status", "partial", metadata.get('overall_status'))
    
    def test_concerns_aggregation(self):
        """Test 7: Concerns aggregation."""
        print("\nTest 7: Concerns aggregation")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0002", TEST_CVE_1337_0002)
        
        source = builder.sources["test-source-uuid-1234"]
        cve = source['cve_data'][0]
        entry = cve['affected_entries'][0]
        
        concerns = entry.get('concerns_summary', [])
        self.assert_equals("Concerns count", 2, len(concerns))
        self.assert_equals("Has updatePatternsInRange", True, "updatePatternsInRange" in concerns)
        self.assert_equals("Has cpeUnconfirmedNoSuggestions", True, "cpeUnconfirmedNoSuggestions" in concerns)
    
    def test_source_summary_stats(self):
        """Test 8: Source summary statistics."""
        print("\nTest 8: Source summary statistics")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0001", TEST_CVE_1337_0001)
        builder.add_cve("CVE-1337-0002", TEST_CVE_1337_0002)
        
        reports = builder.finalize()
        source_report = reports["test-source-uuid-1234"]
        summary = source_report['summary']
        
        # Structure validation
        self.assert_structure("Summary structure", summary, [
            'total_cves', 'automation_level_stats', 'cpe_determination_stats',
            'cpe_as_stats', 'version_stats', 'top_concerns', 'top_patterns'
        ])
        
        # Total CVEs
        self.assert_equals("Summary total CVEs", 2, summary['total_cves'])
        
        # Automation level stats (CVE-level)
        # CVE-1337-0001: Has 1 confirmedMapping and 1 top10Suggestion → partial
        # CVE-1337-0002: Has 1 entry with nothing (empty cpeDetermination) → none
        auto_stats = summary['automation_level_stats']
        self.assert_equals("Full automation count", 0, auto_stats['full_count'])
        self.assert_equals("Partial automation count", 1, auto_stats['partial_count'])
        self.assert_equals("No automation count", 1, auto_stats['none_count'])
        
        # CPE determination stats (entry-level)
        cpe_det = summary['cpe_determination_stats']
        self.assert_equals("Confirmed mapping count", 1, cpe_det['confirmed_mapping_count'])
        self.assert_equals("Top10 suggestion count", 1, cpe_det['top10_suggestion_count'])
        self.assert_equals("Nothing count", 1, cpe_det['nothing_count'])
        
        # Version stats
        ver_stats = summary['version_stats']
        self.assert_equals("Version complete count", 2, ver_stats['complete_count'])
        self.assert_equals("Version partial count", 2, ver_stats['partial_count'])
        self.assert_equals("Version none count", 0, ver_stats['none_count'])
        
        # Top concerns
        top_concerns = summary['top_concerns']
        self.assert_equals("Top concerns is list", list, type(top_concerns))
        if len(top_concerns) > 0:
            self.assert_structure("Top concern structure", top_concerns[0], ['concern', 'count'])
    
    def test_cpe_determination_confidence(self):
        """Test 9: CPE determination confidence levels."""
        print("\nTest 9: CPE determination confidence")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0001", TEST_CVE_1337_0001)
        
        source = builder.sources["test-source-uuid-1234"]
        cve = source['cve_data'][0]
        
        # Entry 1: confirmedMapping
        entry1 = cve['affected_entries'][0]
        self.assert_equals("Entry 1 CPE confidence", "confirmedMapping", entry1.get('cpe_determination_confidence'))
        
        # Entry 2: top10Suggestion
        entry2 = cve['affected_entries'][1]
        self.assert_equals("Entry 2 CPE confidence", "top10Suggestion", entry2.get('cpe_determination_confidence'))
    
    def test_nothing_cpe_determination(self):
        """Test 10: Nothing CPE determination (no mappings or suggestions)."""
        print("\nTest 10: Nothing CPE determination")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0002", TEST_CVE_1337_0002)
        
        source = builder.sources["test-source-uuid-1234"]
        cve = source['cve_data'][0]
        entry = cve['affected_entries'][0]
        
        self.assert_equals("CPE confidence nothing", "nothing", entry.get('cpe_determination_confidence'))
    
    def test_integration_full_workflow(self):
        """Test 11: Integration test - full workflow with file I/O."""
        print("\nTest 11: Integration test - full workflow")
        
        # Setup test cache
        cache_path = self.setup_test_cache()
        
        try:
            # Scan cache
            json_files = scan_nvd_ish_cache(cache_path)
            self.assert_equals("Scanned file count", 3, len(json_files))
            
            # Build reports
            builder = CPEASAutomationReportBuilder()
            for json_file in json_files:
                with open(json_file, 'r') as f:
                    record = json.load(f)
                cve_id = json_file.stem
                builder.add_cve(cve_id, record)
            
            reports = builder.finalize()
            
            # Validate finalized structure
            self.assert_equals("Reports source count", 2, len(reports))
            
            # Check source 1 final structure
            source1_report = reports.get("test-source-uuid-1234")
            self.assert_structure("Source 1 report structure", source1_report, ['metadata', 'summary', 'cve_data'])
            self.assert_equals("Source 1 CVE data count", 2, len(source1_report['cve_data']))
            
        finally:
            self.teardown_test_cache()
    
    def test_percentage_calculations(self):
        """Test 12: Percentage calculations in summary."""
        print("\nTest 12: Percentage calculations")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0001", TEST_CVE_1337_0001)
        builder.add_cve("CVE-1337-0002", TEST_CVE_1337_0002)
        
        reports = builder.finalize()
        summary = reports["test-source-uuid-1234"]['summary']
        
        # Automation level rates (2 CVEs, 0 full, 2 partial, 0 none)
        auto_stats = summary['automation_level_stats']
        self.assert_equals("Full rate", 0.0, auto_stats['full_rate'])
        self.assert_equals("Partial rate", 50.0, auto_stats['partial_rate'])
        self.assert_equals("None rate", 50.0, auto_stats['none_rate'])
        
        # CPE determination rates (3 entries: 1 confirmed, 1 top10, 1 nothing)
        cpe_det = summary['cpe_determination_stats']
        expected_confirmed_rate = round(1/3 * 100, 1)
        self.assert_equals("Confirmed mapping rate", expected_confirmed_rate, cpe_det['confirmed_mapping_rate'])
    
    def test_non_actionable_detection(self):
        """Test 13: NonActionable detection (all placeholder fields)."""
        print("\nTest 13: NonActionable detection")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0009", TEST_CVE_1337_0009)
        
        source = builder.sources["test-source-uuid-1234"]
        cve = source['cve_data'][0]
        entry = cve['affected_entries'][0]
        
        # Verify nonActionable classification
        self.assert_equals("CPE determination confidence", "nonActionable", entry.get('cpe_determination_confidence'))
        self.assert_equals("Is non-actionable flag", True, entry.get('is_non_actionable', False))
        
        # Verify CPE-AS breakdown
        breakdown = entry.get('cpe_as_breakdown', {})
        self.assert_equals("NonActionable complete count", 0, breakdown.get('complete', 0))
        self.assert_equals("NonActionable partial count", 0, breakdown.get('partial', 0))
        self.assert_equals("NonActionable none count", 0, breakdown.get('none', 0))
        self.assert_equals("NonActionable count", 1, breakdown.get('nonActionable', 0))
        
        # Verify CVE metadata
        metadata = cve.get('cve_metadata', {})
        self.assert_equals("CVE entries_non_actionable", 1, metadata.get('entries_non_actionable', 0))
        self.assert_equals("CVE cpe_det_nonActionable", 1, metadata.get('cpe_det_nonActionable', 0))
        self.assert_equals("CVE overall_status", "nonActionable", metadata.get('overall_status'))
        
        # Verify rollup
        rollup = metadata.get('cpe_as_rollup', {})
        self.assert_equals("Rollup nonActionable", 1, rollup.get('nonActionable', 0))
    
    def test_non_actionable_vs_placeholder_version(self):
        """Test 14: Contrast - placeholder version with REAL alias (NOT nonActionable)."""
        print("\nTest 14: Placeholder version with real alias")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0014", TEST_CVE_1337_0014)
        
        source = builder.sources["test-source-uuid-1234"]
        cve = source['cve_data'][0]
        entry = cve['affected_entries'][0]
        
        # Should NOT be classified as nonActionable (has real vendor/product)
        self.assert_equals("CPE determination confidence", "confirmedMapping", entry.get('cpe_determination_confidence'))
        self.assert_equals("Is non-actionable flag", False, entry.get('is_non_actionable', False))
        
        # Should show success (complete) despite placeholder version
        breakdown = entry.get('cpe_as_breakdown', {})
        self.assert_equals("Complete count", 1, breakdown.get('complete', 0))
        self.assert_equals("NonActionable count", 0, breakdown.get('nonActionable', 0))
        
        # CVE should be full automation
        metadata = cve.get('cve_metadata', {})
        self.assert_equals("Entries full automation", 1, metadata.get('entries_full_automation', 0))
        self.assert_equals("Entries non-actionable", 0, metadata.get('entries_non_actionable', 0))
        self.assert_equals("CVE overall_status", "full", metadata.get('overall_status'))
    
    def test_non_actionable_statistics_exclusion(self):
        """Test 15: NonActionable excluded from automation rates."""
        print("\nTest 15: NonActionable statistics exclusion")
        
        builder = CPEASAutomationReportBuilder()
        # Add 1 partial + 1 none + 1 nonActionable CVE
        builder.add_cve("CVE-1337-0001", TEST_CVE_1337_0001)  # partial (has confirmed + top10)
        builder.add_cve("CVE-1337-0002", TEST_CVE_1337_0002)  # none (no CPE determination)
        builder.add_cve("CVE-1337-0009", TEST_CVE_1337_0009)  # nonActionable
        
        reports = builder.finalize()
        summary = reports["test-source-uuid-1234"]['summary']
        
        # Total CVEs = 3, but actionable = 2 (excludes CVE-1337-0009)
        self.assert_equals("Total CVEs", 3, summary['total_cves'])
        
        # Automation level stats
        auto_stats = summary['automation_level_stats']
        self.assert_equals("Automation nonActionable count", 1, auto_stats['nonActionable_count'])
        
        # Rates should be calculated against actionable CVEs only (2 CVEs)
        # Actionable CVEs: 1 partial + 1 none (CVE-1337-0002)
        # Expected rates: full=0%, partial=50%, none=50%
        self.assert_equals("Full rate (0/2)", 0.0, auto_stats['full_rate'])
        self.assert_equals("Partial rate (1/2)", 50.0, auto_stats['partial_rate'])
        self.assert_equals("None rate (1/2)", 50.0, auto_stats['none_rate'])
        
        # NonActionable rate calculated against total CVEs (1/3)
        expected_na_rate = round(1/3 * 100, 1)
        self.assert_equals("NonActionable rate (1/3)", expected_na_rate, auto_stats['nonActionable_rate'])
        
        # CPE determination stats (3 actionable entries + 1 nonActionable)
        cpe_det = summary['cpe_determination_stats']
        self.assert_equals("CPE det nonActionable count", 1, cpe_det['nonActionable_count'])
        
        # Rates should exclude nonActionable entry (calculated against 3 actionable entries)
        # Entries: 1 confirmed (entry1), 1 top10 (entry2), 1 nothing (entry from CVE-1337-0002)
        expected_confirmed = round(1/3 * 100, 1)
        self.assert_equals("Confirmed rate excludes nonActionable", expected_confirmed, cpe_det['confirmed_mapping_rate'])
    
    def test_non_actionable_data_structure(self):
        """Test 16: NonActionable data structure completeness."""
        print("\nTest 16: NonActionable data structure")
        
        builder = CPEASAutomationReportBuilder()
        builder.add_cve("CVE-1337-0009", TEST_CVE_1337_0009)
        
        reports = builder.finalize()
        source_report = reports["test-source-uuid-1234"]
        cve = source_report['cve_data'][0]
        entry = cve['affected_entries'][0]
        
        # Verify all 4 keys present in breakdown
        breakdown = entry.get('cpe_as_breakdown', {})
        self.assert_structure("Breakdown has all 4 keys", breakdown, 
                            ['complete', 'partial', 'none', 'nonActionable'])
        
        # Verify all 4 keys in rollup
        rollup = cve['cve_metadata'].get('cpe_as_rollup', {})
        self.assert_structure("Rollup has all 4 keys", rollup,
                            ['complete', 'partial', 'none', 'nonActionable'])
        
        # Verify summary statistics include nonActionable
        summary = source_report['summary']
        auto_stats = summary['automation_level_stats']
        self.assert_structure("Automation stats has nonActionable", auto_stats,
                            ['full_count', 'partial_count', 'none_count', 'nonActionable_count'])
        
        cpe_det = summary['cpe_determination_stats']
        self.assert_structure("CPE determination has nonActionable", cpe_det,
                            ['confirmed_mapping_count', 'top10_suggestion_count', 
                             'nothing_count', 'nonActionable_count'])
        
        version_stats = summary['version_stats']
        self.assert_structure("Version stats has nonActionable", version_stats,
                            ['complete_count', 'partial_count', 'none_count', 'nonActionable_count'])
    
    def test_non_actionable_is_completely_method(self):
        """Test 17: Direct testing of _is_completely_non_actionable() method."""
        print("\nTest 17: _is_completely_non_actionable() method")
        
        builder = CPEASAutomationReportBuilder()
        
        # Test case 1: All placeholders (should be nonActionable)
        entry_all_placeholder = {
            "originAffectedEntry": {
                "vendor": "n/a",
                "product": "unspecified",
                "packageName": "",
                "repo": "",
                "collectionURL": "",
                "platforms": [],
                "versions": [{"version": "n/a", "status": "affected"}]
            }
        }
        result1 = builder._is_completely_non_actionable(entry_all_placeholder)
        self.assert_equals("All placeholders = nonActionable", True, result1)
        
        # Test case 2: Real vendor, rest placeholders (should NOT be nonActionable)
        entry_real_vendor = {
            "originAffectedEntry": {
                "vendor": "linux",
                "product": "n/a",
                "packageName": "",
                "repo": "",
                "collectionURL": "",
                "platforms": [],
                "versions": [{"version": "n/a", "status": "affected"}]
            }
        }
        result2 = builder._is_completely_non_actionable(entry_real_vendor)
        self.assert_equals("Real vendor = actionable", False, result2)
        
        # Test case 3: All placeholder alias but real version (should NOT be nonActionable)
        entry_real_version = {
            "originAffectedEntry": {
                "vendor": "n/a",
                "product": "n/a",
                "packageName": "",
                "repo": "",
                "collectionURL": "",
                "platforms": [],
                "versions": [{"version": "1.2.3", "status": "affected"}]
            }
        }
        result3 = builder._is_completely_non_actionable(entry_real_version)
        self.assert_equals("Real version = actionable", False, result3)
        
        # Test case 4: Real platforms (should NOT be nonActionable)
        entry_real_platform = {
            "originAffectedEntry": {
                "vendor": "n/a",
                "product": "n/a",
                "packageName": "",
                "repo": "",
                "collectionURL": "",
                "platforms": ["Windows"],
                "versions": [{"version": "n/a", "status": "affected"}]
            }
        }
        result4 = builder._is_completely_non_actionable(entry_real_platform)
        self.assert_equals("Real platform = actionable", False, result4)
    
    def run_all_tests(self):
        """Run all tests."""
        print("=" * 70)
        print("CPE-AS Automation Report Test Suite")
        print("=" * 70)
        
        self.test_builder_basic_grouping()
        self.test_multi_entry_cve_structure()
        self.test_version_level_extraction()
        self.test_pattern_usage_frequency()
        self.test_cpe_as_breakdown()
        self.test_cve_metadata_rollup()
        self.test_concerns_aggregation()
        self.test_source_summary_stats()
        self.test_cpe_determination_confidence()
        self.test_nothing_cpe_determination()
        self.test_integration_full_workflow()
        self.test_percentage_calculations()
        self.test_non_actionable_detection()
        self.test_non_actionable_vs_placeholder_version()
        self.test_non_actionable_statistics_exclusion()
        self.test_non_actionable_data_structure()
        self.test_non_actionable_is_completely_method()
        
        # Summary
        print("\n" + "=" * 70)
        print(f"TEST_RESULTS: PASSED={self.passed} TOTAL={self.passed + self.failed} SUITE=\"CPE-AS Automation Report\"")
        print("=" * 70)
        
        # Return exit code
        return 0 if self.failed == 0 else 1


def main():
    """Main entry point."""
    tester = TestCPEASAutomationReport()
    exit_code = tester.run_all_tests()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()


