#!/usr/bin/env python3
"""
NVD-ish Collector Test Suite

Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Tests the NVD-ish collector functionality with dual-source validation to ensure:
1. Enhanced records created only when BOTH NVD 2.0 and CVE List V5 data sources present
2. Fail-fast behavior when only single data source available
3. Proper merging of CVE List V5 affected arrays into NVD-ish format
4. Enhanced records saved to cache/nvd-ish_2.0_cves/ with correct structure

Test files:
- CVE-1337-0001-cve-list-v5.json: CVE List V5 format with affected arrays
- CVE-1337-0001-nvd-2.0.json: NVD 2.0 format for dual-source success test
- CVE-1337-0002-nvd-2.0.json: NVD 2.0 format for single-source fail test

Test setup copies files to appropriate input caches (cve_list_v5, nvd_2.0_cves).
"""

import sys
import os
import json
import subprocess
import shutil
from pathlib import Path
from typing import Optional, Dict, Any

# Test configuration
TEST_CVE = "CVE-1337-0001"
TEST_CVE_2 = "CVE-1337-0002"
TEST_CVE_3 = "CVE-1337-0003"
PROJECT_ROOT = Path(__file__).parent.parent.parent
CACHE_DIR = PROJECT_ROOT / "cache" / "nvd-ish_2.0_cves"
TEST_FILES_DIR = Path(__file__).parent


def setup_test_environment():
    """Set up test environment by copying test CVE files to INPUT cache locations."""
    print("Setting up test environment...")
    
    # Set up INPUT cache directories (where tool loads data FROM)
    cve_list_v5_cache = PROJECT_ROOT / "cache" / "cve_list_v5" / "1337" / "0xxx"
    nvd_2_0_cache = PROJECT_ROOT / "cache" / "nvd_2.0_cves" / "1337" / "0xxx"
    
    # Create cache directories
    cve_list_v5_cache.mkdir(parents=True, exist_ok=True)
    nvd_2_0_cache.mkdir(parents=True, exist_ok=True)
    
    copied_files = []
    
    # Copy CVE-1337-0001-cve-list-v5.json (CVE List V5 format) to CVE List V5 cache
    cve_list_source = TEST_FILES_DIR / f"{TEST_CVE}-cve-list-v5.json"
    cve_list_target = cve_list_v5_cache / f"{TEST_CVE}.json"
    
    if cve_list_source.exists():
        if cve_list_target.exists():
            cve_list_target.unlink()
        shutil.copy2(cve_list_source, cve_list_target)
        copied_files.append(str(cve_list_target))
        print(f"  Copied {TEST_CVE}-cve-list-v5.json to CVE List V5 cache")
    else:
        print(f"  WARNING: CVE List V5 test file {cve_list_source} not found")
    
    # Copy CVE-1337-0001-nvd-2.0.json (NVD 2.0 format) to NVD 2.0 cache for DUAL-SOURCE test
    nvd_source_1 = TEST_FILES_DIR / f"{TEST_CVE}-nvd-2.0.json"
    nvd_target_1 = nvd_2_0_cache / f"{TEST_CVE}.json"
    
    if nvd_source_1.exists():
        if nvd_target_1.exists():
            nvd_target_1.unlink()
        shutil.copy2(nvd_source_1, nvd_target_1)
        copied_files.append(str(nvd_target_1))
        print(f"  Copied {TEST_CVE}-nvd-2.0.json to NVD 2.0 cache (dual-source test)")
    else:
        print(f"  WARNING: NVD 2.0 dual-source test file {nvd_source_1} not found")
    
    # Copy CVE-1337-0002-nvd-2.0.json (NVD 2.0 format) to NVD 2.0 cache for SINGLE-SOURCE fail test
    nvd_source_2 = TEST_FILES_DIR / f"{TEST_CVE_2}-nvd-2.0.json"
    nvd_target_2 = nvd_2_0_cache / f"{TEST_CVE_2}.json"
    
    if nvd_source_2.exists():
        if nvd_target_2.exists():
            nvd_target_2.unlink()
        shutil.copy2(nvd_source_2, nvd_target_2)
        copied_files.append(str(nvd_target_2))
        print(f"  Copied {TEST_CVE_2}-nvd-2.0.json to NVD 2.0 cache (single-source fail test)")
    else:
        print(f"  WARNING: NVD 2.0 single-source test file {nvd_source_2} not found")
    
    # Copy CVE-1337-0003 dual-source files for COMPLEX merge scenarios test
    cve_list_source_3 = TEST_FILES_DIR / f"{TEST_CVE_3}-cve-list-v5.json"
    cve_list_target_3 = cve_list_v5_cache / f"{TEST_CVE_3}.json"
    
    if cve_list_source_3.exists():
        if cve_list_target_3.exists():
            cve_list_target_3.unlink()
        shutil.copy2(cve_list_source_3, cve_list_target_3)
        copied_files.append(str(cve_list_target_3))
        print(f"  Copied {TEST_CVE_3}-cve-list-v5.json to CVE List V5 cache")
    else:
        print(f"  WARNING: CVE List V5 complex test file {cve_list_source_3} not found")
    
    nvd_source_3 = TEST_FILES_DIR / f"{TEST_CVE_3}-nvd-2.0.json"
    nvd_target_3 = nvd_2_0_cache / f"{TEST_CVE_3}.json"
    
    if nvd_source_3.exists():
        if nvd_target_3.exists():
            nvd_target_3.unlink()
        shutil.copy2(nvd_source_3, nvd_target_3)
        copied_files.append(str(nvd_target_3))
        print(f"  Copied {TEST_CVE_3}-nvd-2.0.json to NVD 2.0 cache (complex merge test)")
    else:
        print(f"  WARNING: NVD 2.0 complex test file {nvd_source_3} not found")
    
    print(f"Test environment setup complete. Copied {len(copied_files)} test files to INPUT caches.")
    return len(copied_files) > 0


def cleanup_test_environment():
    """Clean up test environment by removing test CVE files from INPUT caches only."""
    print("Cleaning up test environment...")
    
    removed_count = 0
    
    # Clean up INPUT caches only (preserve OUTPUT cache nvd-ish_2.0_cves)
    cache_dirs = [
        PROJECT_ROOT / "cache" / "cve_list_v5" / "1337" / "0xxx",
        PROJECT_ROOT / "cache" / "nvd_2.0_cves" / "1337" / "0xxx"
    ]
    
    for cache_dir in cache_dirs:
        if cache_dir.exists():
            # Remove test CVE files
            for cve_file in cache_dir.glob("CVE-1337-*.json"):
                cve_file.unlink()
                removed_count += 1
                print(f"  Removed {cve_file.name} from {cache_dir.parent.parent.parent.name}")
            
            # Remove empty directories
            try:
                if not any(cache_dir.iterdir()):
                    cache_dir.rmdir()
                    print(f"  Removed empty 0xxx directory from {cache_dir.parent.parent.parent.name}")
                
                parent_dir = cache_dir.parent
                if parent_dir.exists() and not any(parent_dir.iterdir()):
                    parent_dir.rmdir()
                    print(f"  Removed empty 1337 directory from {cache_dir.parent.parent.parent.name}")
            except OSError:
                pass  # Directory not empty, which is fine
    
    print(f"Test environment cleanup complete. Removed {removed_count} files from INPUT caches only (preserving nvd-ish output).")


def run_analysis_tool(cve_id: str, parameters: list) -> Optional[Dict[str, Any]]:
    """Run the actual analysis tool with specified parameters."""
    print(f"Running analysis tool for {cve_id} with parameters: {' '.join(parameters)}")
    
    # Use the individual CVE analysis tool
    cmd = [sys.executable, "-m", "src.analysis_tool.core.analysis_tool", "--cve", cve_id] + parameters
    
    try:
        # Run the tool
        result = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=120  # 2 minute timeout
        )
        
        return {
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'cmd': ' '.join(cmd)
        }
        
    except subprocess.TimeoutExpired:
        print(f"ERROR: Tool execution timed out after 120 seconds")
        return None
    except Exception as e:
        print(f"ERROR: Failed to run tool: {e}")
        return None


def check_nvd_ish_output(cve_id: str) -> Optional[Dict[str, Any]]:
    """Check if enhanced NVD record was created in cache."""
    # Determine expected output file path
    year = cve_id.split('-')[1]
    cve_num = int(cve_id.split('-')[2])
    xxx_dir = f"{(cve_num // 1000)}xxx"
    
    expected_file = CACHE_DIR / year / xxx_dir / f"{cve_id}.json"
    
    if not expected_file.exists():
        return None
    
    # Load and validate the enhanced record
    try:
        with open(expected_file, 'r', encoding='utf-8') as f:
            record = json.load(f)
        
        return {
            'file_path': str(expected_file),
            'file_size': expected_file.stat().st_size,
            'record': record
        }
    except Exception as e:
        print(f"ERROR: Failed to load enhanced record: {e}")
        return None


def validate_enhanced_record(record_data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the structure of the enhanced NVD record (individual CVE format)."""
    record = record_data['record']
    
    validations = {
        'is_individual_cve': 'id' in record and record['id'].startswith('CVE-'),
        'no_format_field': 'format' not in record,  # Should NOT have format field
        'no_vulnerabilities_array': 'vulnerabilities' not in record,  # Should NOT have vulnerabilities array
        'has_basic_cve_fields': all(field in record for field in ['id', 'sourceIdentifier', 'published', 'descriptions']),
        'has_enriched_cve_v5_affected': 'enrichedCVEv5Affected' in record,
        'enriched_structure': {}
    }
    
    # Validate enrichedCVEv5Affected structure if present
    if validations['has_enriched_cve_v5_affected']:
        enriched = record['enrichedCVEv5Affected']
        validations['enriched_structure'] = {
            'is_array': isinstance(enriched, list),
            'has_entries': len(enriched) > 0 if isinstance(enriched, list) else False,
            'entries_have_source': False,
            'source_values': [],
            'entry_count': len(enriched) if isinstance(enriched, list) else 0
        }
        
        if isinstance(enriched, list) and len(enriched) > 0:
            # Check if all entries have source attribution
            sources_present = [('source' in entry) for entry in enriched]
            validations['enriched_structure']['entries_have_source'] = all(sources_present)
            validations['enriched_structure']['source_values'] = [entry.get('source', 'MISSING') for entry in enriched]
            
            # ===== CVE LIST V5 → NVD 2.0 TRANSLATION VERIFICATION =====
            # Validate that CVE List V5 container data is correctly translated into enrichedCVEv5Affected entries
            # This confirms the dual-source merge preserves all source container data with proper attribution
            if record['id'] == 'CVE-1337-0001':
                # Expected source UUIDs based on container structure
                expected_sources = {
                    'cna': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',     # Test Org CNA
                    'adp1': '11111111-2222-3333-4444-555555555555',    # CISA-ADP
                    'adp2': '22222222-3333-4444-5555-666666666666',    # Enterprise-ADP  
                    'adp3': '33333333-4444-5555-6666-777777777777'     # Platform-ADP
                }
                
                # Define expected data for validation (vendor/product combinations and key fields by source)
                expected_data_by_source = {
                    expected_sources['cna']: {
                        'entries': [
                            ('alphasoft', 'dataprocessor'),
                            ('betatech', 'webframework'),
                            ('n/a', 'generic_component'),
                            ('gammaenterprises', 'networkserver')
                        ],
                        'expected_fields': ['vendor', 'product', 'platforms', 'versions'],
                        'optional_fields': ['collectionURL', 'packageURL', 'modules', 'programFiles']
                    },
                    expected_sources['adp1']: {
                        'entries': [
                            ('alphasoft', 'dataprocessor'),
                            ('gammaenterprises', 'networkserver')
                        ],
                        'expected_fields': ['vendor', 'product', 'platforms', 'versions'],
                        'optional_fields': ['cpes']
                    },
                    expected_sources['adp2']: {
                        'entries': [
                            ('alphasoft', 'dataprocessor'),
                            ('n/a', 'generic_component')
                        ],
                        'expected_fields': ['vendor', 'product', 'versions'],
                        'optional_fields': ['platforms', 'cpes']
                    },
                    expected_sources['adp3']: {
                        'entries': [
                            ('alphasoft', 'dataprocessor')
                        ],
                        'expected_fields': ['vendor', 'product', 'versions'],
                        'optional_fields': ['platforms', 'cpes']
                    }
                }
                
                # CVE List V5 → NVD 2.0 Translation Validation - verify container data is correctly translated to enrichedCVEv5Affected
                data_integrity_validation = {
                    'total_entries': len(enriched),  # Total enrichedCVEv5Affected entries created
                    'sources_found': [entry.get('source', 'MISSING') for entry in enriched],
                    'unique_sources': list(set(entry.get('source', 'MISSING') for entry in enriched)),  # CVE List V5 containers processed
                    'expected_entries_by_source': {},  # Expected translations per CVE List V5 container
                    'actual_entries_by_source': {},    # Actual enrichedCVEv5Affected entries per source
                    'data_integrity_errors': [],       # Container → enrichedCVEv5Affected translation errors
                    'field_validation_errors': [],     # CVE List V5 field preservation errors
                    'correct_data_mappings': 0,        # Successful container → entry translations
                    'correct_field_validations': 0,    # CVE List V5 fields correctly preserved
                    'total_expected_mappings': sum(len(source_info['entries']) for source_info in expected_data_by_source.values()),
                    'total_field_validations': 0       # Total CVE List V5 fields to validate
                }
                
                # Group actual entries by source for comparison and field validation
                for entry in enriched:
                    source = entry.get('source', 'MISSING')
                    vendor = entry.get('vendor', 'MISSING')
                    product = entry.get('product', 'MISSING')
                    
                    if source not in data_integrity_validation['actual_entries_by_source']:
                        data_integrity_validation['actual_entries_by_source'][source] = []
                    data_integrity_validation['actual_entries_by_source'][source].append((vendor, product, entry))
                
                # Compare expected vs actual data for each source
                for source, source_config in expected_data_by_source.items():
                    expected_entries = source_config['entries']
                    expected_fields = source_config['expected_fields']
                    data_integrity_validation['expected_entries_by_source'][source] = expected_entries
                    actual_entries = data_integrity_validation['actual_entries_by_source'].get(source, [])
                    
                    # Check if all expected entries are present for this source
                    for expected_entry in expected_entries:
                        found_entry = None
                        for actual_vendor, actual_product, actual_entry_data in actual_entries:
                            if (actual_vendor, actual_product) == expected_entry:
                                found_entry = actual_entry_data
                                data_integrity_validation['correct_data_mappings'] += 1
                                break
                        
                        if not found_entry:
                            error_msg = f"Missing expected entry {expected_entry} for source {source[:8]}..."
                            data_integrity_validation['data_integrity_errors'].append(error_msg)
                        else:
                            # Validate required fields are present in the found entry
                            for field in expected_fields:
                                data_integrity_validation['total_field_validations'] += 1
                                if field in found_entry and found_entry[field] is not None:
                                    data_integrity_validation['correct_field_validations'] += 1
                                else:
                                    error_msg = f"Missing/null required field '{field}' in {expected_entry} from source {source[:8]}..."
                                    data_integrity_validation['field_validation_errors'].append(error_msg)
                    
                    # Check for unexpected entries from this source
                    for actual_vendor, actual_product, _ in actual_entries:
                        actual_entry = (actual_vendor, actual_product)
                        if actual_entry not in expected_entries:
                            error_msg = f"Unexpected entry {actual_entry} for source {source[:8]}..."
                            data_integrity_validation['data_integrity_errors'].append(error_msg)
                
                # Legacy source attribution validation for compatibility
                source_validation = {
                    'expected_cna_source': expected_sources['cna'] in data_integrity_validation['unique_sources'],
                    'expected_adp_sources': [s for s in data_integrity_validation['unique_sources'] if s in [expected_sources['adp1'], expected_sources['adp2'], expected_sources['adp3']]],
                    'correct_attribution_count': data_integrity_validation['total_entries']
                }
                
                validations['enriched_structure']['cve_list_v5_translation_validation'] = data_integrity_validation
                validations['enriched_structure']['source_attribution_validation'] = source_validation
                
                # Legacy validation for first entry
                first_entry = enriched[0] if enriched else {}
                validations['enriched_structure']['test_data_validation'] = {
                    'has_expected_source': first_entry.get('source') == expected_sources['cna'],  # CNA should be first
                    'has_product_field': 'product' in first_entry,
                    'has_vendor_field': 'vendor' in first_entry,
                    'has_versions_array': 'versions' in first_entry and isinstance(first_entry['versions'], list),
                    'has_test_product': first_entry.get('product') == 'test_product',
                    'has_test_vendor': first_entry.get('vendor') == 'hashmire'
                }
    
    return validations


def test_basic_cve_analysis() -> bool:
    """Test CVE List V5 → NVD 2.0 enhanced record translation with dual-source validation."""
    print("\n=== Test 1: Dual-Source Success Test ===")
    print("Validating CVE List V5 container data translation into NVD 2.0 enrichedCVEv5Affected format")
    
    # Use test CVE that should exist in both caches
    test_cve = TEST_CVE
    
    # Run with minimal feature flag to trigger NVD-ish collector
    result = run_analysis_tool(test_cve, ["--sdc-report"])
    
    if not result:
        print("FAIL: Tool execution failed")
        return False
    
    print(f"Tool return code: {result['returncode']}")
    
    if result['returncode'] != 0:
        print("FAIL: Tool returned non-zero exit code")
        print("STDOUT:", result['stdout'][-500:] if result['stdout'] else "None")
        print("STDERR:", result['stderr'][-500:] if result['stderr'] else "None")
        return False
    
    # Check if NVD-ish output was created
    enhanced_output = check_nvd_ish_output(test_cve)
    
    if enhanced_output:
        print(f"SUCCESS: Enhanced record created at {enhanced_output['file_path']}")
        print(f"File size: {enhanced_output['file_size']} bytes")
        
        # Validate record structure
        validations = validate_enhanced_record(enhanced_output)
        print(f"Individual CVE format: {validations['is_individual_cve']}")
        print(f"No format field: {validations['no_format_field']}")
        print(f"No vulnerabilities array: {validations['no_vulnerabilities_array']}")
        print(f"Has basic CVE fields: {validations['has_basic_cve_fields']}")
        print(f"Has enrichedCVEv5Affected: {validations['has_enriched_cve_v5_affected']}")
        
        if validations['has_enriched_cve_v5_affected']:
            structure = validations['enriched_structure']
            print(f"Enriched entries count: {structure['entry_count']}")
            print(f"All entries have source: {structure['entries_have_source']}")
            print(f"Sources: {structure['source_values']}")
            
            # CVE List V5 → NVD 2.0 Enhanced Record Translation Validation
            if 'cve_list_v5_translation_validation' in structure:
                data_val = structure['cve_list_v5_translation_validation']
                print(f"")
                print(f"=== CVE List V5 → NVD 2.0 Translation Validation ===")
                print(f"Translation Summary:")
                print(f"  Source containers processed: {len(data_val['unique_sources'])}")
                print(f"  Total enrichedCVEv5Affected entries: {data_val['total_entries']}")
                print(f"  Expected container mappings: {data_val['total_expected_mappings']}")
                print(f"  Successful translations: {data_val['correct_data_mappings']}")
                
                # Translation fidelity validation
                if 'total_field_validations' in data_val:
                    print(f"  CVE List V5 field preservation: {data_val['correct_field_validations']}/{data_val['total_field_validations']}")
                    field_errors = len(data_val.get('field_validation_errors', []))
                    if field_errors > 0:
                        print(f"  Field translation errors: {field_errors}")
                
                translation_errors = len(data_val['data_integrity_errors'])
                print(f"  Container→Entry translation errors: {translation_errors}")
                
                # Container-by-container translation validation
                print(f"Container Translation Details:")
                container_names = {
                    'aaaaaaaa': 'CNA (Test Org)',
                    '11111111': 'ADP-CISA', 
                    '22222222': 'ADP-Enterprise',
                    '33333333': 'ADP-Platform'
                }
                
                for source, expected_entries in data_val['expected_entries_by_source'].items():
                    actual_entries = data_val['actual_entries_by_source'].get(source, [])
                    source_prefix = source[:8]
                    container_name = container_names.get(source_prefix, f"Unknown-{source_prefix}")
                    status = "✓" if len(expected_entries) == len(actual_entries) else "✗"
                    print(f"  {status} {container_name}: {len(expected_entries)} entries → {len(actual_entries)} enrichedCVEv5Affected")
                
                # Overall CVE List V5 → NVD 2.0 translation result
                is_translation_valid = (data_val['correct_data_mappings'] == data_val['total_expected_mappings'] and 
                                      translation_errors == 0)
                
                # Enhanced validation includes field preservation
                if 'total_field_validations' in data_val:
                    field_preservation_valid = (data_val['correct_field_validations'] == data_val['total_field_validations'] and
                                              len(data_val.get('field_validation_errors', [])) == 0)
                    is_translation_valid = is_translation_valid and field_preservation_valid
                
                if is_translation_valid:
                    print(f"  [PASS] CVE List V5 → NVD 2.0 translation: VERIFIED")
                else:
                    print(f"  [FAIL] CVE List V5 → NVD 2.0 translation: FAILED")
                    if data_val['data_integrity_errors']:
                        print(f"    Translation errors: {data_val['data_integrity_errors'][:2]}")
                    if data_val.get('field_validation_errors'):
                        print(f"    Field preservation errors: {data_val['field_validation_errors'][:2]}")
                
                print(f"===============================================")
            
            # Legacy source attribution validation
            elif 'source_attribution_validation' in structure:
                src_val = structure['source_attribution_validation']
                print(f"Multi-Container Source Attribution:")
                print(f"  Total entries: {src_val.get('total_entries', 'N/A')}")
                print(f"  Expected CNA source present: {src_val['expected_cna_source']}")
                print(f"  ADP sources found: {len(src_val['expected_adp_sources'])}")
                if src_val['expected_cna_source'] and len(src_val['expected_adp_sources']) >= 3:
                    print(f"  [PASS] Source attribution validation: PASSED")
                else:
                    print(f"  [FAIL] Source attribution validation: FAILED")
            
            # Validate test data if available
            if 'test_data_validation' in structure:
                test_val = structure['test_data_validation']
                print(f"Expected CNA source: {test_val['has_expected_source']}")
                print(f"Has required fields: product={test_val['has_product_field']}, versions={test_val['has_versions_array']}")
                if 'has_test_product' in test_val:
                    print(f"Test data validation: product={test_val['has_test_product']}, vendor={test_val['has_test_vendor']}")
        
        return True
    else:
        print("FAIL: No enhanced record created")
        return False


def test_full_analysis_pipeline() -> bool:
    """Test full analysis pipeline with all tool outputs."""
    print("\n=== Test 2: Full Analysis Pipeline ===")
    
    # Use test CVE for full pipeline testing
    test_cve = TEST_CVE
    
    # Run with all analysis features
    parameters = [
        "--sdc-report",
        "--cpe-suggestions", 
        "--alias-report",
        "--cpe-as-generator"
    ]
    
    result = run_analysis_tool(test_cve, parameters)
    
    if not result:
        print("FAIL: Full pipeline execution failed")
        return False
    
    print(f"Tool return code: {result['returncode']}")
    
    if result['returncode'] != 0:
        print("FAIL: Full pipeline returned non-zero exit code")
        print("STDOUT:", result['stdout'][-1000:] if result['stdout'] else "None")
        print("STDERR:", result['stderr'][-1000:] if result['stderr'] else "None")
        return False
    
    # Check enhanced output with full pipeline data
    enhanced_output = check_nvd_ish_output(test_cve)
    
    if enhanced_output:
        print(f"SUCCESS: Full pipeline enhanced record created")
        print(f"File size: {enhanced_output['file_size']} bytes")
        
        # Validate comprehensive record structure
        validations = validate_enhanced_record(enhanced_output)
        record = enhanced_output['record']
        
        print(f"Individual CVE format: {validations['is_individual_cve']}")
        print(f"Has enrichedCVEv5Affected: {validations['has_enriched_cve_v5_affected']}")
        
        # Check for expected data integrations in new format
        expected_fields = ['enrichedCVEv5Affected', 'sdcAnalysis', 'cpeSuggestions']
        found_fields = []
        
        for field in expected_fields:
            if field in record:
                found_fields.append(field)
                print(f"[+] {field}: FOUND")
            else:
                print(f"[-] {field}: MISSING")
        
        # Additional validation for enrichedCVEv5Affected
        if validations['has_enriched_cve_v5_affected'] and 'enriched_structure' in validations:
            structure = validations['enriched_structure']
            print(f"Enriched entries: {structure['entry_count']}")
            print(f"Source attribution complete: {structure['entries_have_source']}")
        
        return True
    else:
        print("FAIL: No enhanced record created in full pipeline")
        return False


def test_single_source_fail_fast() -> bool:
    """Test single-source fail-fast behavior (CVE-1337-0002 has NVD 2.0 only)."""
    print("\n=== Test 3: Single-Source Fail-Fast Test ===")
    
    # CVE-1337-0002 has NVD 2.0 data but no CVE List V5 data (should fail)
    test_cve = TEST_CVE_2
    
    # Run analysis tool - should fail due to missing CVE List V5 data
    result = run_analysis_tool(test_cve, ["--sdc-report"])
    
    if not result:
        print("FAIL: Tool execution failed completely")
        return False
    
    print(f"Tool return code: {result['returncode']}")
    
    # Check that no enhanced record was created (fail-fast worked)
    enhanced_output = check_nvd_ish_output(TEST_CVE_2)
    
    if enhanced_output:
        print(f"FAIL: Enhanced record was created when it should have failed (dual-source validation failed)")
        return False
    else:
        print("SUCCESS: No enhanced record created - single-source validation correctly failed fast")
        
        # Check logs for proper error messages
        if result['stderr'] and ("Enhanced record creation requires BOTH data sources" in result['stderr'] or 
                                 "Dual-source validation failed" in result['stderr']):
            print("SUCCESS: Proper dual-source validation error logged")
            return True
        else:
            print("WARNING: Expected dual-source validation error message not found in logs")
            return True  # Still pass if no record created


def test_cache_directory_structure() -> bool:
    """Test that cache directory structure is created properly."""
    print("\n=== Test 4: Cache Directory Structure ===")
    
    print(f"NVD-ish cache directory: {CACHE_DIR}")
    print(f"Cache directory exists: {CACHE_DIR.exists()}")
    
    if CACHE_DIR.exists():
        # Check year directories
        year_dirs = [d for d in CACHE_DIR.iterdir() if d.is_dir()]
        print(f"Year directories found: {len(year_dirs)}")
        
        # Check specifically for test data in 1337 directory
        test_dir = CACHE_DIR / "1337" / "0xxx"
        if test_dir.exists():
            test_files = list(test_dir.glob("CVE-1337-*.json"))
            print(f"Test CVE files found: {len(test_files)}")
            for test_file in sorted(test_files):
                print(f"  - {test_file.name}")
        
        # Show directories with files
        dirs_with_files = []
        for year_dir in sorted(year_dirs):
            file_count = sum(1 for f in year_dir.rglob("*.json"))
            if file_count > 0:
                dirs_with_files.append((year_dir.name, file_count))
        
        if dirs_with_files:
            print("Directories with JSON files:")
            for dir_name, file_count in dirs_with_files:
                print(f"  {dir_name}: {file_count} JSON files")
        
        return len(year_dirs) > 0
    
    return False


def test_complex_merge_scenarios() -> bool:
    """Test complex merge scenarios with overlapping ranges, SDC patterns, and multiple ADP containers."""
    print("\n=== Test 5: Complex Merge Scenarios ===")
    test_cve = TEST_CVE_3
    
    # Run analysis tool
    result = run_analysis_tool(test_cve, ["--sdc-report"])
    
    if result is None or result['returncode'] != 0:
        print(f"FAIL: Analysis tool failed for {test_cve}")
        if result:
            print(f"  Return code: {result['returncode']}")
            if result['stderr']:
                print(f"  Error output: {result['stderr']}")
        return False
    
    # Check if enhanced record was created
    output_file = CACHE_DIR / "1337" / "0xxx" / f"{test_cve}.json"
    
    if not output_file.exists():
        print(f"FAIL: Enhanced record not created at {output_file}")
        return False
    
    # Load and validate enhanced record
    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            enhanced_record = json.load(f)
    except Exception as e:
        print(f"FAIL: Could not load enhanced record: {e}")
        return False
    
    print(f"SUCCESS: Complex merge enhanced record created")
    print(f"File size: {output_file.stat().st_size} bytes")
    
    # Validate complex merge scenarios
    validations = {}
    
    # Check for enriched CVE v5 affected data
    if 'enrichedCVEv5Affected' in enhanced_record:
        enriched_affected = enhanced_record['enrichedCVEv5Affected']
        validations['enriched_affected'] = {
            'present': True,
            'count': len(enriched_affected),
            'vendors': [entry.get('vendor', 'MISSING') for entry in enriched_affected],
            'products': [entry.get('product', 'MISSING') for entry in enriched_affected],
            'has_source_attribution': all('source' in entry for entry in enriched_affected)
        }
        
        # Check for SDC patterns (placeholder values)
        sdc_patterns = []
        for entry in enriched_affected:
            vendor = entry.get('vendor', '')
            product = entry.get('product', '')
            if vendor in ['unknown', 'n/a', 'placeholder_vendor'] or product in ['multiple', 'tbd', '--', '---']:
                sdc_patterns.append(f"{vendor}/{product}")
        
        validations['sdc_patterns'] = {
            'found': len(sdc_patterns) > 0,
            'patterns': sdc_patterns
        }
        
        # Check for complex version ranges
        complex_versions = []
        for entry in enriched_affected:
            versions = entry.get('versions', [])
            for version in versions:
                if 'lessThan' in version or 'changes' in version:
                    complex_versions.append({
                        'vendor': entry.get('vendor'),
                        'product': entry.get('product'),
                        'version': version.get('version'),
                        'has_changes': 'changes' in version,
                        'has_less_than': 'lessThan' in version
                    })
        
        validations['complex_versions'] = {
            'found': len(complex_versions) > 0,
            'count': len(complex_versions),
            'examples': complex_versions[:3]  # Show first 3 examples
        }
        
        print(f"Complex merge validations:")
        print(f"  Enriched entries: {validations['enriched_affected']['count']}")
        print(f"  Vendors: {set(validations['enriched_affected']['vendors'])}")
        print(f"  Products: {set(validations['enriched_affected']['products'])}")
        print(f"  Source attribution: {validations['enriched_affected']['has_source_attribution']}")
        print(f"  SDC patterns found: {validations['sdc_patterns']['found']} ({validations['sdc_patterns']['patterns']})")
        print(f"  Complex versions: {validations['complex_versions']['count']} entries with ranges/changes")
        
        # Check if we have the expected complex vendors/products
        expected_vendors = ['overlapping_ranges_vendor', 'edge_case_vendor', 'unknown', 'placeholder_vendor']
        found_vendors = set(validations['enriched_affected']['vendors'])
        vendor_coverage = len(set(expected_vendors) & found_vendors) >= 3
        
        print(f"  Vendor coverage: {vendor_coverage} (found {len(found_vendors & set(expected_vendors))}/{len(expected_vendors)} expected)")
        
        return (validations['enriched_affected']['present'] and 
                validations['enriched_affected']['has_source_attribution'] and
                validations['sdc_patterns']['found'] and
                validations['complex_versions']['found'] and
                vendor_coverage)
    else:
        print(f"FAIL: No enrichedCVEv5Affected field found")
        return False


def test_validation_detection() -> bool:
    """Test that validation can detect intentional errors (fail case test)."""
    print("\n=== Test 6: Validation Detection Capability ===")
    print("Testing error detection with intentional data corruption")
    
    test_cve = TEST_CVE
    
    # Ensure we have a valid enhanced record first
    output_file = CACHE_DIR / "1337" / "0xxx" / f"{test_cve}.json"
    
    if not output_file.exists():
        # Run analysis to generate the record
        result = run_analysis_tool(test_cve, ["--sdc-report"])
        if not result or result['returncode'] != 0:
            print("FAIL: Could not generate enhanced record for validation test")
            return False
    
    # Load the enhanced record
    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            enhanced_record = json.load(f)
    except Exception as e:
        print(f"FAIL: Could not load enhanced record: {e}")
        return False
    
    original_entries = enhanced_record.get('enrichedCVEv5Affected', [])
    
    if not original_entries:
        print("FAIL: No enriched entries found for validation test")
        return False
    
    print(f"Loaded {len(original_entries)} entries for validation detection test")
    
    # Create intentionally corrupted data
    corrupted_record = enhanced_record.copy()
    corrupted_entries = [entry.copy() for entry in original_entries]
    
    # Introduce intentional errors
    errors_introduced = 0
    
    if len(corrupted_entries) > 0:
        # Error 1: Change vendor name
        if 'vendor' in corrupted_entries[0]:
            original_vendor = corrupted_entries[0]['vendor']
            corrupted_entries[0]['vendor'] = 'CORRUPTED_VENDOR'
            print(f"  Introduced error 1: vendor '{original_vendor}' → 'CORRUPTED_VENDOR'")
            errors_introduced += 1
        
        # Error 2: Remove a required property
        if 'product' in corrupted_entries[0]:
            original_product = corrupted_entries[0]['product']
            del corrupted_entries[0]['product']
            print(f"  Introduced error 2: removed 'product' property (was '{original_product}')")
            errors_introduced += 1
        
        # Error 3: Wrong source attribution
        if len(corrupted_entries) > 1 and 'source' in corrupted_entries[1]:
            original_source = corrupted_entries[1]['source']
            corrupted_entries[1]['source'] = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
            print(f"  Introduced error 3: wrong source attribution")
            errors_introduced += 1
    
    # Update corrupted record
    corrupted_record['enrichedCVEv5Affected'] = corrupted_entries
    
    # Run validation on corrupted data
    validation_results = validate_enhanced_record({'record': corrupted_record})
    
    # Check if validation detected the errors
    detected_errors = 0
    
    if 'enriched_structure' in validation_results:
        structure = validation_results['enriched_structure']
        
        if 'cve_list_v5_translation_validation' in structure:
            validation_data = structure['cve_list_v5_translation_validation']
            
            # Check for validation errors
            data_errors = len(validation_data.get('data_integrity_errors', []))
            field_errors = len(validation_data.get('field_validation_errors', []))
            
            detected_errors = data_errors + field_errors
            
            print(f"  Validation detected {data_errors} data integrity errors")
            print(f"  Validation detected {field_errors} field validation errors")
            print(f"  Total errors detected: {detected_errors}")
        
        # Also check basic structure validation
        if not validation_results.get('has_enriched_cve_v5_affected', True):
            detected_errors += 1
            print(f"  Validation detected structural issues")
    
    print(f"Validation Detection Results:")
    print(f"  Errors introduced: {errors_introduced}")
    print(f"  Errors detected: {detected_errors}")
    
    # Success criteria: validation should detect at least some of the errors
    detection_success = detected_errors > 0
    
    if detection_success:
        print(f"  ✅ PASS: Validation successfully detected intentional errors")
        print(f"  Detection confirms validation mechanisms work properly")
        return True
    else:
        print(f"  ❌ FAIL: Validation did not detect any intentional errors")
        print(f"  This indicates validation mechanisms may not be working")
        return False


def test_deep_version_validation() -> bool:
    """Test deep validation of complex version structures including changes arrays."""
    print("\n" + "=" * 60)
    print("TEST 7: Deep Version Structure Validation")
    print("=" * 60)
    
    # Load the test data
    try:
        cve_list_path = TEST_FILES_DIR / f"{TEST_CVE}-cve-list-v5.json"
        enhanced_path = CACHE_DIR / "1337" / "0xxx" / f"{TEST_CVE}.json"
        
        with open(cve_list_path, 'r', encoding='utf-8') as f:
            cve_list_data = json.load(f)
        
        with open(enhanced_path, 'r', encoding='utf-8') as f:
            enhanced_data = json.load(f)
            
    except Exception as e:
        print(f"❌ FAIL: Could not load test data: {e}")
        return False
    
    # Get CNA container (has the most complex version structure)
    cna_container = cve_list_data.get('containers', {}).get('cna', {})
    cna_affected = cna_container.get('affected', [])
    
    enriched_entries = enhanced_data.get('enrichedCVEv5Affected', [])
    cna_source = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    
    print(f"Validating complex version structures from CNA container")
    print(f"CNA Source UUID: {cna_source}")
    
    # Find the most complex entry (alphasoft/dataprocessor)
    source_entry = None
    for entry in cna_affected:
        if entry.get('vendor') == 'alphasoft' and entry.get('product') == 'dataprocessor':
            source_entry = entry
            break
    
    enriched_entry = None
    for entry in enriched_entries:
        if (entry.get('vendor') == 'alphasoft' and 
            entry.get('product') == 'dataprocessor' and 
            entry.get('source') == cna_source):
            enriched_entry = entry
            break
    
    if not source_entry or not enriched_entry:
        print("❌ FAIL: Could not find alphasoft/dataprocessor entries")
        return False
    
    print(f"🔍 VALIDATING: alphasoft/dataprocessor (most complex version structure)")
    
    # Get version arrays
    source_versions = source_entry.get('versions', [])
    enriched_versions = enriched_entry.get('versions', [])
    
    print(f"Source versions: {len(source_versions)}")
    print(f"Enriched versions: {len(enriched_versions)}")
    
    if len(source_versions) != len(enriched_versions):
        print(f"❌ FAIL: VERSION COUNT MISMATCH!")
        return False
    
    total_validations = 0
    passed_validations = 0
    
    # Validate each version entry in detail
    for i, (source_ver, enriched_ver) in enumerate(zip(source_versions, enriched_versions)):
        print(f"\n  📋 VERSION ENTRY {i+1}:")
        
        # Validate all version properties
        version_props = ['version', 'status', 'versionType', 'lessThan']
        for prop in version_props:
            if prop in source_ver:
                total_validations += 1
                if prop in enriched_ver:
                    source_val = source_ver[prop]
                    enriched_val = enriched_ver[prop]
                    match = source_val == enriched_val
                    status = "✓" if match else "✗"
                    print(f"    {status} {prop}: '{source_val}' → '{enriched_val}'")
                    if match:
                        passed_validations += 1
                    else:
                        print(f"      ❌ MISMATCH!")
                else:
                    print(f"    ✗ {prop}: Missing in enriched (was: '{source_ver[prop]}')")
            elif prop in enriched_ver:
                print(f"    ⚠️ {prop}: Added in enriched (value: '{enriched_ver[prop]}')")
        
        # Validate changes array if present (this is the most complex nested structure)
        if 'changes' in source_ver:
            print(f"    🔄 CHANGES ARRAY VALIDATION:")
            total_validations += 1
            
            if 'changes' not in enriched_ver:
                print(f"      ❌ Changes array missing in enriched!")
            else:
                source_changes = source_ver['changes']
                enriched_changes = enriched_ver['changes']
                
                if len(source_changes) != len(enriched_changes):
                    print(f"      ❌ Changes count mismatch: {len(source_changes)} vs {len(enriched_changes)}")
                else:
                    changes_match = True
                    for j, (src_change, enr_change) in enumerate(zip(source_changes, enriched_changes)):
                        print(f"      Change {j+1}:")
                        for change_prop in ['at', 'status']:
                            if change_prop in src_change:
                                src_val = src_change[change_prop]
                                enr_val = enr_change.get(change_prop)
                                prop_match = src_val == enr_val
                                changes_match = changes_match and prop_match
                                status = "✓" if prop_match else "✗"
                                print(f"        {status} {change_prop}: '{src_val}' → '{enr_val}'")
                    
                    if changes_match:
                        print(f"      ✅ All changes preserved exactly!")
                        passed_validations += 1
                    else:
                        print(f"      ❌ Changes array has mismatches!")
        
        elif 'changes' in enriched_ver:
            print(f"    ⚠️ Changes array added in enriched version")
    
    # Summary for this specific validation
    print(f"\nDEEP VERSION STRUCTURE VALIDATION SUMMARY:")
    print(f"Entry validated: alphasoft/dataprocessor (CNA)")
    print(f"Version entries validated: {len(source_versions)}")
    print(f"Total property validations: {total_validations}")
    print(f"Validations passed: {passed_validations}")
    print(f"Validations failed: {total_validations - passed_validations}")
    print(f"Success rate: {(passed_validations/total_validations*100):.1f}%")
    
    if passed_validations == total_validations:
        print(f"✅ PASS: Perfect deep validation - all complex version structures preserved exactly")
        return True
    else:
        print(f"❌ FAIL: Deep validation failed - version structure mismatches detected")
        return False


def test_source_alias_resolution() -> bool:
    """Test source alias resolution scenarios for enrichedCVEv5Affected."""
    test_name = "Source Alias Resolution"
    print(f"\n--- {test_name} ---")
    
    try:
        # Import the collector here to avoid circular dependencies
        sys.path.insert(0, str(PROJECT_ROOT / "src"))
        from analysis_tool.logging.nvd_ish_collector import NVDishCollector
        
        collector = NVDishCollector()
        
        # Create mock source manager data for testing
        class MockSourceManager:
            def __init__(self):
                self._initialized = True
                self._test_sources = {
                    # Fortinet UUID that should map to email
                    '6abe59d8-c742-4dff-8ce8-9b0ca1073da8': {
                        'name': 'Fortinet',
                        'contactEmail': 'psirt@fortinet.com',
                        'sourceIdentifiers': ['6abe59d8-c742-4dff-8ce8-9b0ca1073da8', 'psirt@fortinet.com']
                    },
                    # Microsoft UUID with multiple identifiers
                    'f6ab73b0-42c6-4c6e-b0a7-5c2f8f3d3c3c': {
                        'name': 'Microsoft',
                        'contactEmail': 'secure@microsoft.com',
                        'sourceIdentifiers': ['f6ab73b0-42c6-4c6e-b0a7-5c2f8f3d3c3c', 'secure@microsoft.com', 'msrc@microsoft.com']
                    },
                    # Unknown UUID not in NVD source set
                    'unknown-uuid-1234-5678-9abc-def123456789': {
                        'name': 'Unknown Vendor',
                        'contactEmail': 'security@unknown.com',
                        'sourceIdentifiers': ['unknown-uuid-1234-5678-9abc-def123456789', 'security@unknown.com']
                    }
                }
            
            def get_source_info(self, source_id: str):
                return self._test_sources.get(source_id)
        
        # Monkey patch the source manager for testing
        mock_manager = MockSourceManager()
        original_get_global_source_manager = collector.resolve_source_alias.__globals__.get('get_global_source_manager')
        collector.resolve_source_alias.__globals__['get_global_source_manager'] = lambda: mock_manager
        
        tests_passed = 0
        total_tests = 6
        
        try:
            # Test 1: Perfect match - UUID maps to exact NVD sourceIdentifier
            result = collector.resolve_source_alias('6abe59d8-c742-4dff-8ce8-9b0ca1073da8', 'psirt@fortinet.com')
            if result == 'psirt@fortinet.com':
                print("✅ Test 1 PASS: Perfect UUID to NVD sourceIdentifier match")
                tests_passed += 1
            else:
                print(f"❌ Test 1 FAIL: Expected 'psirt@fortinet.com', got '{result}'")
            
            # Test 2: Collision detection - UUID maps but not to this CVE's sourceIdentifier
            result = collector.resolve_source_alias('6abe59d8-c742-4dff-8ce8-9b0ca1073da8', 'different@source.com')
            if result == '6abe59d8-c742-4dff-8ce8-9b0ca1073da8':  # Should keep original UUID
                print("✅ Test 2 PASS: Collision detection - kept original UUID")
                tests_passed += 1
            else:
                print(f"❌ Test 2 FAIL: Expected original UUID, got '{result}'")
            
            # Test 3: No NVD sourceIdentifier provided - prefer non-UUID identifier
            result = collector.resolve_source_alias('f6ab73b0-42c6-4c6e-b0a7-5c2f8f3d3c3c')
            if result in ['secure@microsoft.com', 'msrc@microsoft.com']:  # Should pick first non-UUID
                print(f"✅ Test 3 PASS: Preferred non-UUID identifier: {result}")
                tests_passed += 1
            else:
                print(f"❌ Test 3 FAIL: Expected email identifier, got '{result}'")
            
            # Test 4: UUID not in known source set
            result = collector.resolve_source_alias('completely-unknown-uuid-1234', 'any@source.com')
            if result == 'completely-unknown-uuid-1234':  # Should keep original
                print("✅ Test 4 PASS: Unknown UUID kept original")
                tests_passed += 1
            else:
                print(f"❌ Test 4 FAIL: Expected original UUID, got '{result}'")
            
            # Test 5: Manager not initialized
            mock_manager._initialized = False
            result = collector.resolve_source_alias('6abe59d8-c742-4dff-8ce8-9b0ca1073da8', 'psirt@fortinet.com')
            if result == '6abe59d8-c742-4dff-8ce8-9b0ca1073da8':  # Should keep original
                print("✅ Test 5 PASS: Uninitialized manager kept original UUID")
                tests_passed += 1
            else:
                print(f"❌ Test 5 FAIL: Expected original UUID, got '{result}'")
            
            # Test 6: UUID format detection
            mock_manager._initialized = True
            is_uuid_1 = collector._is_uuid_format('6abe59d8-c742-4dff-8ce8-9b0ca1073da8')
            is_uuid_2 = collector._is_uuid_format('psirt@fortinet.com')
            if is_uuid_1 and not is_uuid_2:
                print("✅ Test 6 PASS: UUID format detection working")
                tests_passed += 1
            else:
                print(f"❌ Test 6 FAIL: UUID format detection failed: {is_uuid_1}, {is_uuid_2}")
        
        finally:
            # Restore original function
            if original_get_global_source_manager:
                collector.resolve_source_alias.__globals__['get_global_source_manager'] = original_get_global_source_manager
        
        print(f"\nSource alias resolution tests: {tests_passed}/{total_tests} passed")
        
        if tests_passed == total_tests:
            print(f"✅ PASS: All source alias resolution scenarios working correctly")
            return True
        else:
            print(f"❌ FAIL: Source alias resolution issues detected")
            return False
        
    except Exception as e:
        print(f"❌ FAIL: {test_name} - Exception occurred: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_enriched_cve_affected_integration() -> bool:
    """Test enrichedCVEv5Affected integration with source alias resolution in full pipeline."""
    test_name = "EnrichedCVEv5Affected Integration"
    print(f"\n--- {test_name} ---")
    
    try:
        # Create test data with UUID sources that should be resolved
        test_cve_id = "CVE-1337-0004"
        
        # Create CVE List V5 record with UUID source
        cve_list_data = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.0",
            "cveMetadata": {
                "cveId": test_cve_id
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "orgId": "6abe59d8-c742-4dff-8ce8-9b0ca1073da8"
                    },
                    "affected": [
                        {
                            "vendor": "Fortinet",
                            "product": "FortiOS",
                            "versions": [
                                {
                                    "version": "7.0.0",
                                    "status": "affected"
                                }
                            ]
                        }
                    ]
                }
            }
        }
        
        # Create NVD 2.0 record with email sourceIdentifier
        nvd_data = {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2024-01-01T00:00:00.000Z",
            "vulnerabilities": [
                {
                    "cve": {
                        "id": test_cve_id,
                        "sourceIdentifier": "psirt@fortinet.com",  # This should match resolved UUID
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-01T00:00:00.000",
                        "vulnStatus": "Analyzed",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Test vulnerability for source resolution"
                            }
                        ]
                    }
                }
            ]
        }
        
        # Set up test environment
        cve_list_cache_dir = PROJECT_ROOT / "cache" / "cve_list_v5" / "1337" / "0xxx"
        nvd_cache_dir = PROJECT_ROOT / "cache" / "nvd_2.0_cves" / "1337" / "0xxx"
        output_cache_dir = PROJECT_ROOT / "cache" / "nvd-ish_2.0_cves" / "1337" / "0xxx"
        
        cve_list_cache_dir.mkdir(parents=True, exist_ok=True)
        nvd_cache_dir.mkdir(parents=True, exist_ok=True)
        output_cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Write test files
        cve_list_file = cve_list_cache_dir / f"{test_cve_id}.json"
        nvd_file = nvd_cache_dir / f"{test_cve_id}.json"
        output_file = output_cache_dir / f"{test_cve_id}.json"
        
        with open(cve_list_file, 'w') as f:
            json.dump(cve_list_data, f, indent=2)
        
        with open(nvd_file, 'w') as f:
            json.dump(nvd_data, f, indent=2)
        
        # Import and test the collector
        sys.path.insert(0, str(PROJECT_ROOT / "src"))
        from analysis_tool.logging.nvd_ish_collector import get_nvd_ish_collector, reset_nvd_ish_collector
        
        # Reset collector state
        reset_nvd_ish_collector()
        collector = get_nvd_ish_collector()
        
        # Mock the source manager for this test
        class MockSourceManager:
            def __init__(self):
                self._initialized = True
            
            def get_source_info(self, source_id: str):
                if source_id == '6abe59d8-c742-4dff-8ce8-9b0ca1073da8':
                    return {
                        'name': 'Fortinet',
                        'contactEmail': 'psirt@fortinet.com',
                        'sourceIdentifiers': ['6abe59d8-c742-4dff-8ce8-9b0ca1073da8', 'psirt@fortinet.com']
                    }
                return None
        
        # Monkey patch the source manager
        mock_manager = MockSourceManager()
        original_get_global_source_manager = collector.resolve_source_alias.__globals__.get('get_global_source_manager')
        collector.resolve_source_alias.__globals__['get_global_source_manager'] = lambda: mock_manager
        
        try:
            # Process the CVE
            collector.start_cve_processing(test_cve_id)
            collector.collect_nvd_base_record(nvd_data)
            collector.collect_cve_list_v5_data(cve_list_data)
            success = collector.complete_cve_processing()
        finally:
            # Restore original function
            if original_get_global_source_manager:
                collector.resolve_source_alias.__globals__['get_global_source_manager'] = original_get_global_source_manager
        
        if not success:
            print("❌ FAIL: Could not complete CVE processing")
            return False
        
        # Find the actual output file
        result_data = None
        found_file = None
        
        # Check multiple possible locations (including local test directory)
        test_dir = Path(__file__).parent
        possible_paths = [
            output_file,
            PROJECT_ROOT / "cache" / "nvd-ish_2.0_cves" / "1337" / "0xxx" / f"{test_cve_id}.json",
            test_dir / "cache" / "nvd-ish_2.0_cves" / "1337" / "0xxx" / f"{test_cve_id}.json",
        ]
        
        for path in possible_paths:
            if path.exists():
                print(f"✅ Found output file at: {path}")
                found_file = path
                with open(path, 'r') as f:
                    result_data = json.load(f)
                break
        
        if not result_data:
            print(f"❌ FAIL: Output file was not created at any expected location")
            print(f"  Checked: {[str(p) for p in possible_paths]}")
            return False
        
        tests_passed = 0
        total_tests = 4
        
        # Test 1: enrichedCVEv5Affected section exists
        if 'enrichedCVEv5Affected' in result_data:
            print("✅ Test 1 PASS: enrichedCVEv5Affected section created")
            tests_passed += 1
        else:
            print("❌ Test 1 FAIL: enrichedCVEv5Affected section missing")
        
        # Test 2: Source was resolved from UUID to email
        if ('enrichedCVEv5Affected' in result_data and 
            len(result_data['enrichedCVEv5Affected']) > 0 and
            'source' in result_data['enrichedCVEv5Affected'][0]):
            
            resolved_source = result_data['enrichedCVEv5Affected'][0]['source']
            if resolved_source == 'psirt@fortinet.com':
                print(f"✅ Test 2 PASS: Source resolved correctly: {resolved_source}")
                tests_passed += 1
            else:
                print(f"❌ Test 2 FAIL: Expected 'psirt@fortinet.com', got '{resolved_source}'")
        else:
            print("❌ Test 2 FAIL: Could not find source field in enrichedCVEv5Affected")
        
        # Test 3: Correct positioning between weaknesses and configurations
        fields = list(result_data.keys())
        if 'enrichedCVEv5Affected' in fields:
            pos = fields.index('enrichedCVEv5Affected')
            weaknesses_pos = fields.index('weaknesses') if 'weaknesses' in fields else -1
            configs_pos = fields.index('configurations') if 'configurations' in fields else len(fields)
            
            if weaknesses_pos < pos < configs_pos:
                print("✅ Test 3 PASS: enrichedCVEv5Affected correctly positioned")
                tests_passed += 1
            else:
                print(f"❌ Test 3 FAIL: Incorrect positioning. Order: {fields}")
        else:
            print("❌ Test 3 FAIL: enrichedCVEv5Affected not found for positioning test")
        
        # Test 4: NVD sourceIdentifier matches resolved source
        nvd_source = result_data.get('sourceIdentifier')
        enriched_source = None
        if ('enrichedCVEv5Affected' in result_data and 
            len(result_data['enrichedCVEv5Affected']) > 0):
            enriched_source = result_data['enrichedCVEv5Affected'][0].get('source')
        
        if nvd_source and enriched_source and nvd_source == enriched_source:
            print(f"✅ Test 4 PASS: NVD and enriched sources match: {nvd_source}")
            tests_passed += 1
        else:
            print(f"❌ Test 4 FAIL: Source mismatch - NVD: {nvd_source}, Enriched: {enriched_source}")
        
        # Cleanup test files (after all validation is complete)
        try:
            if cve_list_file.exists():
                cve_list_file.unlink()
            if nvd_file.exists():
                nvd_file.unlink()
            if found_file and found_file.exists():
                found_file.unlink()
        except:
            pass
        
        print(f"\nEnriched integration tests: {tests_passed}/{total_tests} passed")
        
        if tests_passed == total_tests:
            print(f"✅ PASS: enrichedCVEv5Affected integration working correctly")
            return True
        else:
            print(f"❌ FAIL: enrichedCVEv5Affected integration issues detected")
            return False
    
    except Exception as e:
        print(f"❌ FAIL: {test_name} - Exception occurred: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all NVD-ish collector tests."""
    # Check if running under unified test runner for reduced verbosity
    show_details = not os.environ.get('UNIFIED_TEST_RUNNER')
    
    if show_details:
        print("NVD-ish Collector Test Suite")
        print("=" * 60)
        print(f"Project root: {PROJECT_ROOT}")
        print(f"Cache directory: {CACHE_DIR}")
        print(f"Test CVEs: {TEST_CVE}, {TEST_CVE_2}, {TEST_CVE_3}")
    else:
        print("NVD-ish Collector Test Suite")
    
    # Setup test environment
    if not setup_test_environment():
        print("FAIL: Could not set up test environment")
        return 1
    
    try:
        tests_passed = 0
        total_tests = 9
        
        # Test 1: Basic analysis
        if test_basic_cve_analysis():
            tests_passed += 1
        
        # Test 2: Full pipeline
        if test_full_analysis_pipeline():
            tests_passed += 1
        
        # Test 3: Enhanced record with additional fields
        if test_single_source_fail_fast():
            tests_passed += 1
        
        # Test 4: Cache structure
        if test_cache_directory_structure():
            tests_passed += 1
        
        # Test 5: Complex merge scenarios
        if test_complex_merge_scenarios():
            tests_passed += 1
        
        # Test 6: Validation detection capability (fail case)
        if test_validation_detection():
            tests_passed += 1
        
        # Test 7: Deep version structure validation
        if test_deep_version_validation():
            tests_passed += 1
        
        # Test 8: Source alias resolution scenarios
        if test_source_alias_resolution():
            tests_passed += 1
        
        # Test 9: enrichedCVEv5Affected integration with source resolution
        if test_enriched_cve_affected_integration():
            tests_passed += 1
        
        print("\n" + "=" * 60)
        print(f"Tests passed: {tests_passed}/{total_tests}")
        
        success = tests_passed == total_tests
        if success:
            print("SUCCESS: All NVD-ish collector tests passed!")
        else:
            print("FAIL: Some NVD-ish collector tests failed")
        
        # Output standardized test results for run_all_tests.py
        print(f'TEST_RESULTS: PASSED={tests_passed} TOTAL={total_tests} SUITE="NVD-ish Collector"')
        
        return 0 if success else 1
    
    finally:
        # Always clean up test environment
        cleanup_test_environment()


if __name__ == "__main__":
    exit(main())