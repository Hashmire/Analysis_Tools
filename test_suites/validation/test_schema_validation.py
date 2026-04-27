#!/usr/bin/env python3
"""
Test Suite: Schema Validation

Tests HTTP response validation and schema validation for all supported data sources:
- CPE API 2.0 (NVD)
- CVE API 2.0 (NVD)
- CVE Record V5 (MITRE CVE List)
- Source API 2.0 (NVD)

Covers HTTP transport validation (universal) and schema validation (data-specific).
Schema validation skipped (schema=None) since schemas not guaranteed in test environment.

Standard Output Format: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Schema Validation"
"""
import sys
import json
from pathlib import Path
from unittest.mock import Mock, patch

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from src.analysis_tool.core.gatherData import validate_http_response, HTTPResponseError
from src.analysis_tool.core.schema_validator import (
    validate_against_schema,
    validate_cpe_data,
    validate_cve_data,
    validate_source_data,
    validate_cve_record_v5,
    NVDSchemaValidationError
)

# Test counters
tests_passed = 0
tests_total = 0

def test(description):
    """Decorator for test functions"""
    def decorator(func):
        def wrapper():
            global tests_passed, tests_total
            tests_total += 1
            try:
                func()
                tests_passed += 1
                print(f"  PASS: {description}")
                return True
            except AssertionError as e:
                print(f"  FAIL: {description}")
                print(f"    {e}")
                return False
            except Exception as e:
                print(f"  FAIL: {description}")
                print(f"    Unexpected error: {type(e).__name__}: {e}")
                return False
        return wrapper
    return decorator


# ============================================================================
# HTTP Validation Tests (Universal - applies to all APIs)
# ============================================================================

@test("HTTP - Valid JSON response passes validation")
def test_http_valid():
    response = Mock()
    response.headers = {'content-type': 'application/json'}
    response.content = b'{"key": "value"}'
    response.text = response.content.decode('utf-8')
    response.json = lambda: {"key": "value"}
    
    data = validate_http_response(response, "test")
    assert data["key"] == "value"


@test("HTTP - Invalid Content-Type fails")
def test_http_wrong_content_type():
    response = Mock()
    response.headers = {'content-type': 'text/html'}
    response.content = b'<html>Error</html>'
    
    try:
        validate_http_response(response, "test")
        assert False, "Should have raised HTTPResponseError"
    except HTTPResponseError:
        pass  # Expected


@test("HTTP - Empty response body fails")
def test_http_empty():
    response = Mock()
    response.headers = {'content-type': 'application/json'}
    response.content = b''
    
    try:
        validate_http_response(response, "test")
        assert False, "Should have raised HTTPResponseError"
    except HTTPResponseError:
        pass  # Expected


@test("HTTP - Malformed JSON fails")
def test_http_invalid_json():
    response = Mock()
    response.headers = {'content-type': 'application/json'}
    response.content = b'{"invalid": }'
    response.text = response.content.decode('utf-8')
    response.json = Mock(side_effect=json.JSONDecodeError("Invalid", "", 0))
    
    try:
        validate_http_response(response, "test")
        assert False, "Should have raised HTTPResponseError"
    except HTTPResponseError:
        pass  # Expected


@test("HTTP - JSON array (non-dict) fails")
def test_http_json_array():
    response = Mock()
    response.headers = {'content-type': 'application/json'}
    response.content = b'[1, 2, 3]'
    response.text = response.content.decode('utf-8')
    response.json = lambda: [1, 2, 3]
    
    try:
        validate_http_response(response, "test")
        assert False, "Should have raised HTTPResponseError"
    except HTTPResponseError:
        pass  # Expected


@test("HTTP - Oversized response fails")
def test_http_oversized():
    response = Mock()
    response.headers = {'content-type': 'application/json'}
    response.content = b'x' * (101 * 1024 * 1024)  # 101MB
    
    try:
        validate_http_response(response, "test", max_size_mb=100)
        assert False, "Should have raised HTTPResponseError"
    except HTTPResponseError:
        pass  # Expected


# ============================================================================
# CPE API 2.0 Validation Tests
# ============================================================================

@test("CPE API - Valid response passes validation")
def test_cpe_valid():
    response = Mock()
    response.headers = {'content-type': 'application/json'}
    
    valid_data = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CPE",
        "version": "2.0",
        "timestamp": "2024-01-01T00:00:00.000",
        "products": [{
            "cpe": {
                "deprecated": False,
                "cpeName": "cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*",
                "cpeNameId": "12345678-1234-1234-1234-123456789012",
                "created": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-01T00:00:00.000"
            }
        }]
    }
    
    response.content = json.dumps(valid_data).encode('utf-8')
    response.text = response.content.decode('utf-8')
    response.json = lambda: valid_data
    
    # HTTP validation
    data = validate_http_response(response, "CPE API test")
    # Schema validation (skipped with schema=None)
    data = validate_cpe_data(data, "cpe:2.3:a:test:product:*:*:*:*:*:*:*:*", schema=None)
    assert data["totalResults"] == 1


@test("CPE API - Empty products array is valid")
def test_cpe_empty():
    response = Mock()
    response.headers = {'content-type': 'application/json'}
    
    empty_data = {
        "resultsPerPage": 0,
        "startIndex": 0,
        "totalResults": 0,
        "format": "NVD_CPE",
        "version": "2.0",
        "timestamp": "2024-01-01T00:00:00.000",
        "products": []
    }
    
    response.content = json.dumps(empty_data).encode('utf-8')
    response.text = response.content.decode('utf-8')
    response.json = lambda: empty_data
    
    # HTTP validation
    data = validate_http_response(response, "CPE API test")
    # Schema validation
    data = validate_cpe_data(data, "cpe:2.3:a:nonexistent:*:*:*:*:*:*:*:*:*", schema=None)
    assert data["totalResults"] == 0


# ============================================================================
# CVE API 2.0 Validation Tests
# ============================================================================

@test("CVE API - Valid response passes validation")
def test_cve_valid():
    response = Mock()
    response.headers = {'content-type': 'application/json'}
    
    valid_data = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2024-01-01T00:00:00.000",
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-1337-1234",
                "sourceIdentifier": "test@test.com",
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-01T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "metrics": {},
                "references": []
            }
        }]
    }
    
    response.content = json.dumps(valid_data).encode('utf-8')
    response.text = response.content.decode('utf-8')
    response.json = lambda: valid_data
    
    # HTTP validation
    data = validate_http_response(response, "CVE API test")
    # Schema validation
    data = validate_cve_data(data, "CVE-1337-1234", schema=None)
    assert data["totalResults"] == 1


# ============================================================================
# Source API 2.0 Validation Tests
# ============================================================================

@test("Source API - Valid response passes validation")
def test_source_valid():
    response = Mock()
    response.headers = {'content-type': 'application/json'}
    
    valid_data = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_SOURCE",
        "version": "2.0",
        "timestamp": "2024-01-01T00:00:00.000",
        "sources": [{
            "source": {
                "contactEmail": "test@example.com",
                "name": "Test Source",
                "sourceIdentifier": "test-source"
            }
        }]
    }
    
    response.content = json.dumps(valid_data).encode('utf-8')
    response.text = response.content.decode('utf-8')
    response.json = lambda: valid_data
    
    # HTTP validation
    data = validate_http_response(response, "Source API test")
    # Schema validation
    data = validate_source_data(data, schema=None)
    assert data["totalResults"] == 1


# ============================================================================
# multipleOf Decimal Precision Tests
# ============================================================================

@test("multipleOf - CVSS 4.0 score 5.1 passes multipleOf 0.1 (Decimal fix)")
def test_multiple_of_decimal_precision_passes():
    """Regression test: float 5.1 % 0.1 is non-zero in IEEE 754, causing false failures.
    The Decimal-based validator must accept 5.1 as a valid multiple of 0.1."""
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "baseScore": {"type": "number", "minimum": 4.0, "maximum": 6.9, "multipleOf": 0.1}
        }
    }
    # These are all valid CVSS medium-range scores that would fail under stock jsonschema
    for score in [4.1, 4.2, 5.1, 5.2, 6.1, 6.9]:
        try:
            validate_against_schema({"baseScore": score}, schema, f"test score {score}")
        except NVDSchemaValidationError as e:
            assert False, f"Valid CVSS score {score} incorrectly rejected: {e}"


@test("multipleOf - Non-multiple correctly rejected")
def test_multiple_of_decimal_precision_rejects():
    """Confirm the Decimal validator still rejects values that are genuinely not multiples."""
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "baseScore": {"type": "number", "multipleOf": 0.1}
        }
    }
    try:
        validate_against_schema({"baseScore": 5.15}, schema, "test score 5.15")
        assert False, "5.15 should not be a multiple of 0.1"
    except NVDSchemaValidationError:
        pass  # Expected


# ============================================================================
# CVE Record V5 Validation Tests
# ============================================================================

@test("CVE Record V5 - Missing cveMetadata fails")
def test_cve_record_missing_metadata():
    invalid_record = {
        "containers": {"cna": {"affected": []}}
    }
    
    try:
        validate_cve_record_v5(invalid_record, "CVE-1337-1234", schema=None)
        assert False, "Should have raised NVDSchemaValidationError"
    except NVDSchemaValidationError:
        pass  # Expected


@test("CVE Record V5 - Non-dict type fails")
def test_cve_record_wrong_type():
    try:
        validate_cve_record_v5("not-a-dict", "CVE-1337-1234", schema=None)
        assert False, "Should have raised NVDSchemaValidationError"
    except NVDSchemaValidationError:
        pass  # Expected


@test("CVE Record V5 - Array type fails")
def test_cve_record_array_type():
    try:
        validate_cve_record_v5([], "CVE-1337-1234", schema=None)
        assert False, "Should have raised NVDSchemaValidationError"
    except NVDSchemaValidationError:
        pass  # Expected


# ============================================================================
# Network-call protection tests (validate_against_schema no-registry guard)
# ============================================================================

@test("No-network guard - external $ref + no registry raises NVDSchemaValidationError without invoking validator")
def test_no_network_external_ref_no_registry():
    """When the registry is unavailable and the schema has external $ref URIs,
    validate_against_schema must raise NVDSchemaValidationError immediately
    rather than falling through to _DecimalAwareDraft7Validator.validate(),
    which would rely on implicit jsonschema resolver behaviour and could make
    unintended network calls."""
    schema_with_external_ref = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "cvssData": {"$ref": "https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v4.0.json"}
        }
    }
    data = {"cvssData": {"version": "4.0"}}

    # Track whether the validator's .validate() was ever called
    validate_called = []

    class _SentinelValidator:
        def __init__(self, *args, **kwargs):
            pass
        def validate(self, instance):
            validate_called.append(True)

    with patch("src.analysis_tool.core.gatherData.get_schema_registry", return_value=None), \
         patch("src.analysis_tool.core.schema_validator._DecimalAwareDraft7Validator", _SentinelValidator):
        try:
            validate_against_schema(data, schema_with_external_ref, "test context")
            assert False, "Should have raised NVDSchemaValidationError"
        except NVDSchemaValidationError as e:
            assert "external" in str(e).lower() or "$ref" in str(e).lower() or "registry" in str(e).lower(), \
                f"Error message should explain why validation was skipped: {e}"

    assert not validate_called, \
        "_DecimalAwareDraft7Validator.validate() must NOT be called when schema has external $refs and no registry is available"


@test("No-network guard - no external $refs + no registry validates normally (no false blocking)")
def test_no_network_no_external_refs_validates():
    """When the schema has NO external $ref URIs, validate_against_schema must
    proceed with validation even if no registry is available.  The guard must
    not block schemas that are self-contained."""
    self_contained_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "version": {"type": "string"},
            "score": {"type": "number", "minimum": 0.0, "maximum": 10.0}
        },
        "required": ["version"]
    }

    # Valid data — should pass
    with patch("src.analysis_tool.core.gatherData.get_schema_registry", return_value=None):
        try:
            validate_against_schema({"version": "4.0", "score": 7.5}, self_contained_schema, "test")
        except NVDSchemaValidationError as e:
            assert False, f"Self-contained schema should validate without a registry: {e}"

    # Invalid data — should still raise
    with patch("src.analysis_tool.core.gatherData.get_schema_registry", return_value=None):
        try:
            validate_against_schema({"score": 7.5}, self_contained_schema, "test")  # missing required 'version'
            assert False, "Missing required field should have raised NVDSchemaValidationError"
        except NVDSchemaValidationError:
            pass  # Expected


@test("No-network guard - unexpected validator exception converted to NVDSchemaValidationError (no bare re-raise)")
def test_unexpected_validator_exception_wrapped():
    """Any exception that is neither jsonschema.ValidationError nor jsonschema.SchemaError
    must be converted to NVDSchemaValidationError rather than re-raised unwrapped.
    A bare re-raise would bypass the 'cache without validation' safety nets in callers."""
    self_contained_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object"
    }

    class _BoomValidator:
        def __init__(self, *args, **kwargs):
            pass
        def validate(self, instance):
            raise RuntimeError("Simulated unexpected internal validator error")

    with patch("src.analysis_tool.core.gatherData.get_schema_registry", return_value=None), \
         patch("src.analysis_tool.core.schema_validator._DecimalAwareDraft7Validator", _BoomValidator):
        try:
            validate_against_schema({}, self_contained_schema, "test context")
            assert False, "Should have raised NVDSchemaValidationError"
        except NVDSchemaValidationError as e:
            # Correct: wrapped as a typed, handleable error
            assert "RuntimeError" in str(e) or "unexpected" in str(e).lower(), \
                f"Wrapped error should mention original type: {e}"
        except RuntimeError:
            assert False, "RuntimeError must NOT propagate raw — callers rely on NVDSchemaValidationError"


# ============================================================================
# Run all tests
# ============================================================================

def main():
    """Run all tests and output results"""
    global tests_passed, tests_total
    
    print("=" * 80)
    print("SCHEMA VALIDATION TEST SUITE")
    print("=" * 80)
    print()
    
    # HTTP validation tests
    test_http_valid()
    test_http_wrong_content_type()
    test_http_empty()
    test_http_invalid_json()
    test_http_json_array()
    test_http_oversized()
    
    # CPE API 2.0
    test_cpe_valid()
    test_cpe_empty()
    
    # CVE API 2.0
    test_cve_valid()
    
    # Source API 2.0
    test_source_valid()
    
    # multipleOf Decimal precision
    test_multiple_of_decimal_precision_passes()
    test_multiple_of_decimal_precision_rejects()

    # CVE Record V5
    test_cve_record_missing_metadata()
    test_cve_record_wrong_type()
    test_cve_record_array_type()

    # No-network-call protection (validate_against_schema no-registry guard)
    test_no_network_external_ref_no_registry()
    test_no_network_no_external_refs_validates()
    test_unexpected_validator_exception_wrapped()
    
    print()
    print("=" * 80)
    print(f"Results: {tests_passed}/{tests_total} tests passed")
    print("=" * 80)
    print()
    
    # Standard output format for test runner
    print(f'TEST_RESULTS: PASSED={tests_passed} TOTAL={tests_total} SUITE="Schema Validation"')
    
    sys.exit(0 if tests_passed == tests_total else 1)


if __name__ == "__main__":
    main()
