#!/usr/bin/env python3
"""
Source Data Concerns Registry Structure Validation

Validates the generated sourceDataConcernReport.json against the documented
Registry Data Structure patterns from source_data_concerns_enhanced_table.md
"""

import json
import sys
from pathlib import Path

def validate_registry_structure(json_path: str) -> bool:
    """
    Validate the Registry Data Structure compliance in the generated JSON.
    
    Args:
        json_path: Path to the sourceDataConcernReport.json file
        
    Returns:
        True if structure is compliant, False otherwise
    """
    
    print("="*80)
    print("SOURCE DATA CONCERNS REGISTRY STRUCTURE VALIDATION")
    print("="*80)
    print(f"Analyzing: {json_path}")
    print()
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
    except Exception as e:
        print(f"❌ ERROR: Could not read JSON file: {e}")
        return False
    
    # Expected Registry Data Structure patterns from documentation
    expected_patterns = {
        "placeholderData": {
            "documentation_example": {"field": "vendor", "sourceValue": "n/a", "detectedPattern": "n/a"},
            "required_fields": ["field", "sourceValue", "detectedPattern"],
            "detectedPattern_type": "string",
            "pattern_examples": ["n/a", "unknown", "unspecified", "tbd"]
        },
        "versionComparators": {
            "documentation_example": {"field": "version", "sourceValue": "<=1.2.3", "detectedPattern": "<, ="},
            "required_fields": ["field", "sourceValue", "detectedPattern"],
            "detectedPattern_type": "string",
            "pattern_examples": [">=", "<=", "<, ="]
        },
        "versionTextPatterns": {
            "documentation_example": {"field": "version", "sourceValue": "before 2.1.3", "detectedPattern": "before"},
            "required_fields": ["field", "sourceValue", "detectedPattern"],
            "detectedPattern_type": "string",
            "pattern_examples": ["before", "through", "to"]
        },
        "whitespaceIssues": {
            "documentation_example": {
                "field": "vendor", 
                "sourceValue": " apache ", 
                "detectedPattern": {
                    "whitespaceTypes": ["leading", "trailing"], 
                    "replacedText": "!!apache!!"
                }
            },
            "required_fields": ["field", "sourceValue", "detectedPattern"],
            "detectedPattern_type": "object",
            "pattern_keys": ["whitespaceTypes", "replacedText"]
        },
        "invalidCharacters": {
            "documentation_example": {"field": "version", "sourceValue": "1.2.3@build", "detectedPattern": "@"},
            "required_fields": ["field", "sourceValue", "detectedPattern"],
            "detectedPattern_type": "string",
            "pattern_examples": ["@", " ", "<", "="]
        },
        "versionGranularity": {
            "documentation_example": {
                "field": "version", 
                "sourceValue": "1.0.1", 
                "detectedPattern": {"base": "1", "granularity": "3"}
            },
            "required_fields": ["field", "sourceValue", "detectedPattern"],
            "detectedPattern_type": "object",
            "pattern_keys": ["base", "granularity"]
        },
        "overlappingRanges": {
            "documentation_example": {
                "field": "versions", 
                "sourceValue": "versions[2] & versions[3]", 
                "detectedPattern": {
                    "overlapType": "partial_overlap", 
                    "range1Source": "versions[2]", 
                    "range2Source": "versions[3]", 
                    "range1": "2.0.0 to 2.5.0", 
                    "range2": "2.1.0 to 3.0.0"
                }
            },
            "required_fields": ["field", "sourceValue", "detectedPattern"],
            "detectedPattern_type": "object",
            "pattern_keys": ["overlapType", "range1", "range2", "range1Source", "range2Source"]
        }
    }
    
    pattern_alignments = []
    structural_issues = []
    total_validations = 0
    
    # Navigate to platform entries
    cve_data = report_data.get('cve_data', [])
    if not cve_data:
        print("❌ ERROR: No CVE data found in report")
        return False
    
    platform_entries = cve_data[0].get('platform_entries', [])
    if not platform_entries:
        print("❌ ERROR: No platform entries found in CVE data")
        return False
    
    print(f"📊 Found {len(platform_entries)} platform entries to analyze")
    print()
    
    # Analyze pattern alignment for each concern type
    for entry_idx, platform_entry in enumerate(platform_entries):
        entry_id = platform_entry.get('platform_entry_id', f'entry_{entry_idx}')
        concerns_detail = platform_entry.get('concerns_detail', [])
        
        for concern_group in concerns_detail:
            concern_type = concern_group.get('concern_type')
            concerns_list = concern_group.get('concerns', [])
            
            if concern_type not in expected_patterns:
                structural_issues.append(f"⚠️  UNMAPPED CONCERN TYPE: {concern_type} (not in documentation)")
                continue
            
            expected = expected_patterns[concern_type]
            
            for concern_idx, actual_concern in enumerate(concerns_list):
                total_validations += 1
                
                # Create pattern alignment comparison
                alignment = {
                    "concern_type": concern_type,
                    "entry_id": entry_id,
                    "concern_index": concern_idx,
                    "expected_pattern": expected["documentation_example"],
                    "found_pattern": actual_concern,
                    "alignment_issues": [],
                    "structure_matches": True
                }
                
                # Check field alignment
                expected_field_pattern = expected["documentation_example"].get("field", "")
                actual_field = actual_concern.get("field", "")
                if "[" in expected_field_pattern and "[" not in actual_field:
                    alignment["alignment_issues"].append(f"Field pattern mismatch: expected array notation like '{expected_field_pattern}', found '{actual_field}'")
                
                # Check sourceValue alignment
                expected_source_pattern = expected["documentation_example"].get("sourceValue", "")
                actual_source = actual_concern.get("sourceValue", "")
                if "&" in expected_source_pattern and "&" not in actual_source:
                    alignment["alignment_issues"].append(f"SourceValue pattern mismatch: expected range notation like '{expected_source_pattern}', found '{actual_source}'")
                
                # Check detectedPattern structure alignment
                expected_pattern_type = expected.get("detectedPattern_type", "string")
                expected_detected = expected["documentation_example"].get("detectedPattern")
                actual_detected = actual_concern.get("detectedPattern")
                
                if expected_pattern_type == "object":
                    if not isinstance(actual_detected, dict):
                        alignment["alignment_issues"].append(f"DetectedPattern type mismatch: expected object, found {type(actual_detected).__name__}")
                        alignment["structure_matches"] = False
                    else:
                        # Check object keys alignment
                        expected_keys = set(expected_detected.keys()) if isinstance(expected_detected, dict) else set()
                        actual_keys = set(actual_detected.keys())
                        
                        missing_keys = expected_keys - actual_keys
                        extra_keys = actual_keys - expected_keys
                        
                        if missing_keys:
                            alignment["alignment_issues"].append(f"Missing detectedPattern keys: {sorted(missing_keys)}")
                        if extra_keys:
                            alignment["alignment_issues"].append(f"Extra detectedPattern keys: {sorted(extra_keys)}")
                else:
                    if not isinstance(actual_detected, str):
                        alignment["alignment_issues"].append(f"DetectedPattern type mismatch: expected string, found {type(actual_detected).__name__}")
                        alignment["structure_matches"] = False
                
                # Check for missing required fields
                for required_field in expected["required_fields"]:
                    if required_field not in actual_concern:
                        alignment["alignment_issues"].append(f"Missing required field: {required_field}")
                        alignment["structure_matches"] = False
                
                if alignment["alignment_issues"]:
                    alignment["structure_matches"] = False
                
                pattern_alignments.append(alignment)
    
    print()
    print("="*80)
    print("PATTERN ALIGNMENT ANALYSIS")
    print("="*80)
    
    # Group alignments by concern type
    concern_type_alignments = {}
    perfect_alignments = 0
    total_alignments = len(pattern_alignments)
    
    for alignment in pattern_alignments:
        concern_type = alignment["concern_type"]
        if concern_type not in concern_type_alignments:
            concern_type_alignments[concern_type] = {"alignments": [], "perfect": 0, "total": 0}
        
        concern_type_alignments[concern_type]["alignments"].append(alignment)
        concern_type_alignments[concern_type]["total"] += 1
        
        if alignment["structure_matches"] and not alignment["alignment_issues"]:
            concern_type_alignments[concern_type]["perfect"] += 1
            perfect_alignments += 1
    
    # Show detailed pattern comparisons
    for concern_type, data in concern_type_alignments.items():
        perfect_count = data["perfect"]
        total_count = data["total"]
        alignment_rate = (perfect_count / total_count * 100) if total_count > 0 else 0
        
        status = "✅" if alignment_rate == 100 else "⚠️" if alignment_rate >= 50 else "❌"
        print(f"\n{status} **{concern_type}** ({perfect_count}/{total_count} perfect alignments - {alignment_rate:.1f}%)")
        
        # Show first example of expected vs found
        first_alignment = data["alignments"][0]
        expected = first_alignment["expected_pattern"]
        found = first_alignment["found_pattern"]
        
        print(f"   📋 **Expected Pattern (Documentation)**:")
        print(f"      {json.dumps(expected, indent=6)[6:]}")  # Remove first 6 spaces
        
        print(f"   🔍 **Found Pattern (Generated)**:")
        print(f"      {json.dumps(found, indent=6)[6:]}")  # Remove first 6 spaces
        
        # Show alignment issues if any
        if first_alignment["alignment_issues"]:
            print(f"   ⚠️  **Alignment Issues**:")
            for issue in first_alignment["alignment_issues"]:
                print(f"      • {issue}")
        else:
            print(f"   ✅ **Perfect structural alignment**")
        
        # Show additional cases if they have different patterns
        if total_count > 1:
            unique_patterns = set()
            for alignment in data["alignments"]:
                pattern_key = json.dumps(alignment["found_pattern"], sort_keys=True)
                if pattern_key not in unique_patterns and len(unique_patterns) < 2:  # Show max 2 more examples
                    unique_patterns.add(pattern_key)
                    if alignment != first_alignment:
                        print(f"   📝 **Additional Pattern Variant**:")
                        print(f"      {json.dumps(alignment['found_pattern'], indent=6)[6:]}")
    
    # Show structural issues if any
    if structural_issues:
        print(f"\n🚨 **STRUCTURAL ISSUES DETECTED**:")
        for issue in structural_issues:
            print(f"   • {issue}")
    
    print()
    print("="*80)
    print("ALIGNMENT SUMMARY")
    print("="*80)
    print(f"📊 **Pattern Analysis Results**:")
    print(f"   • Total Patterns Analyzed: {total_alignments}")
    print(f"   • Perfect Alignments: {perfect_alignments}")
    print(f"   • Alignment Issues: {total_alignments - perfect_alignments}")
    print(f"   • Overall Alignment Rate: {(perfect_alignments/total_alignments*100):.1f}%")
    print(f"   • Concern Types Covered: {len(concern_type_alignments)}")
    
    if perfect_alignments == total_alignments and not structural_issues:
        print()
        print("🎉 **PERFECT REGISTRY STRUCTURE ALIGNMENT!**")
        print("✅ All generated patterns exactly match documented Registry Data Structure")
        print("✅ All '(Refactored) Badge Generation' entries comply with specification")
    elif perfect_alignments / total_alignments >= 0.8:
        print()
        print("✅ **GOOD REGISTRY STRUCTURE ALIGNMENT**")
        print("✨ Most patterns align well with documentation (minor edge cases detected)")
    else:
        print()
        print("⚠️  **REGISTRY STRUCTURE ALIGNMENT ISSUES**")
        print("❌ Significant discrepancies found between generated and documented patterns")
    
    print("="*80)
    
    return perfect_alignments == total_alignments and not structural_issues

def main():
    """Main function to validate the most recent test output"""
    
    # Find the most recent test run
    runs_dir = Path("runs")
    test_runs = [d for d in runs_dir.iterdir() if d.is_dir() and "TEST_test_source_data_concerns" in d.name]
    
    if not test_runs:
        print("❌ ERROR: No test runs found matching pattern 'TEST_test_source_data_concerns'")
        sys.exit(1)
    
    # Get the most recent run
    latest_run = max(test_runs, key=lambda x: x.stat().st_mtime)
    json_path = latest_run / "logs" / "sourceDataConcernReport.json"
    
    if not json_path.exists():
        print(f"❌ ERROR: sourceDataConcernReport.json not found in {latest_run}")
        sys.exit(1)
    
    # Validate the structure
    success = validate_registry_structure(str(json_path))
    
    # Output standardized test results
    validation_count = 1  # This script performs 1 comprehensive validation
    passed_count = 1 if success else 0
    
    print(f"TEST_RESULTS: PASSED={passed_count} TOTAL={validation_count} SUITE=\"Registry Structure Validation\"")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()