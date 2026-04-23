#!/usr/bin/env python3
"""
JSON Schema Validation for CVE and CPE Data

Validates API response data against official NVD/CVE schemas.
Logs ERROR-level messages when validation fails.

Architecture:
- HTTP response validation: gatherData.validate_http_response() (transport layer)
- Schema validation: This module (data layer)
- Schema loading: gatherData.py (data gathering)

Schema URLs loaded from config.json api.schemas section.
"""
import json
from decimal import Decimal, InvalidOperation
from typing import Dict, Any, Optional
import jsonschema
from jsonschema.validators import extend as _extend_validator
import orjson

from ..logging.workflow_logger import get_logger

logger = get_logger()


class NVDSchemaValidationError(Exception):
    """Raised when data fails schema validation"""
    pass


def _decimal_multiple_of(validator, divisor, instance, schema):
    """
    Custom multipleOf validator using Decimal arithmetic to avoid IEEE 754 float precision issues.

    jsonschema's built-in multipleOf uses float division, which causes false negatives for
    values like 5.1 / 0.1 ≈ 50.99999999999999 (should be 51). CVSS 4.0 score types define
    multipleOf: 0.1, so valid NVD scores such as 5.1 (MEDIUM) are incorrectly rejected.
    Using str-based Decimal conversion gives exact decimal arithmetic: Decimal('5.1') % Decimal('0.1') == 0.
    """
    if not isinstance(instance, (int, float)):
        return
    try:
        decimal_instance = Decimal(str(instance))
        decimal_divisor = Decimal(str(divisor))
        if decimal_instance % decimal_divisor != Decimal('0'):
            yield jsonschema.ValidationError(
                f"{instance!r} is not a multiple of {divisor!r}"
            )
    except (InvalidOperation, ZeroDivisionError):
        yield jsonschema.ValidationError(
            f"{instance!r} is not a multiple of {divisor!r}"
        )


# Extend Draft7Validator with the Decimal-based multipleOf handler
_DecimalAwareDraft7Validator = _extend_validator(
    jsonschema.Draft7Validator,
    {"multipleOf": _decimal_multiple_of}
)


def validate_against_schema(
    data: Dict[str, Any],
    schema: Optional[Dict[str, Any]],
    context: str
) -> None:
    """
    Validate data against JSON schema.
    
    Uses locally cached external $ref schemas (e.g., CVSS) first. 
    If external schemas failed to download, unresolved $ref will 
    raise ValidationError, surfacing as a schema validation concern.

    Uses Decimal-based multipleOf validation to avoid IEEE 754 float precision
    false negatives (e.g., CVSS 4.0 scores like 5.1 failing multipleOf 0.1).
    
    Args:
        data: Parsed API response data
        schema: JSON schema (None = skip validation)
        context: Description for error messages
    
    Raises:
        NVDSchemaValidationError: If data fails schema validation
    """
    if schema is None:
        return
    
    try:
        # Import here to get access to get_schema_registry
        from .gatherData import get_schema_registry

        # Get registry for external refs (uses locally cached CVSS schemas)
        registry = get_schema_registry()

        # Validate with or without registry depending on availability
        if registry:
            validator = _DecimalAwareDraft7Validator(schema, registry=registry)
            validator.validate(data)
        else:
            _DecimalAwareDraft7Validator(schema).validate(data)
            
    except jsonschema.ValidationError as e:
        error_path = ' -> '.join(str(p) for p in e.path) if e.path else 'root'
        error_msg = f"Schema validation failed at {error_path}: {e.message} - {context}"
        raise NVDSchemaValidationError(error_msg)
    except jsonschema.SchemaError as e:
        logger.error(f"Invalid schema encountered: {e}", group="DATA_PROC")
    except Exception as e:
        # Catch referencing.exceptions.NoSuchResource and similar registry errors
        # (imported lazily to avoid requiring referencing at module load time)
        try:
            from referencing.exceptions import NoSuchResource
            if isinstance(e, NoSuchResource):
                raise NVDSchemaValidationError(
                    f"External schema reference could not be resolved (cached file missing?): {e} - {context}"
                )
        except ImportError:
            pass
        raise


def validate_string_content(data: Any, context: str, path: str = "root") -> None:
    """
    Recursively validate string content for dangerous characters/encoding.
    
    Catches issues that orjson.dumps() might accept but cause problems:
    - Null bytes (\x00)
    - Invalid UTF-8 sequences
    - Control characters that corrupt JSON
    - Windows-1252/CP1252 characters in UTF-8 stream
    
    Args:
        data: Data structure to validate (dict, list, or primitive)
        context: Description for error messages
        path: Current path in data structure for error reporting
    
    Raises:
        NVDSchemaValidationError: If dangerous content found
    """
    if isinstance(data, dict):
        for key, value in data.items():
            validate_string_content(value, context, f"{path}.{key}")
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            validate_string_content(item, context, f"{path}[{idx}]")
    elif isinstance(data, str):
        # Check for null bytes
        if '\x00' in data:
            error_msg = f"Null byte found in string at {path} - {context}"
            raise NVDSchemaValidationError(error_msg)
        
        # Check for problematic control characters (except allowed whitespace)
        dangerous_chars = []
        for char in data:
            code = ord(char)
            # Allow: tab(9), newline(10), carriage return(13), normal printable (32-126, 128+)
            # Reject: Other control chars (0-8, 11-12, 14-31)
            if (code < 32 and code not in (9, 10, 13)):
                dangerous_chars.append((char, code))
        
        if dangerous_chars:
            char_list = ', '.join(f"\\x{code:02x}" for char, code in dangerous_chars[:3])
            error_msg = f"Dangerous control characters in string at {path}: {char_list} - {context}"
            raise NVDSchemaValidationError(error_msg)
        
        # Check for valid UTF-8 encoding by attempting encode/decode
        try:
            data.encode('utf-8', errors='strict')
        except UnicodeEncodeError as e:
            error_msg = f"Invalid UTF-8 in string at {path}: {str(e)[:100]} - {context}"
            raise NVDSchemaValidationError(error_msg)


def validate_orjson_serializable(data: Dict[str, Any], context: str) -> None:
    """
    Validate data is serializable by orjson (required for cache storage).
    
    CRITICAL: Multi-layer validation to catch all corruption types:
    1. Content validation: Scans for null bytes, control chars, invalid UTF-8
    2. Serialization test: Verifies orjson.dumps() succeeds
    3. Round-trip test: Verifies orjson.loads() succeeds (catches surrogates)
    
    Args:
        data: Parsed API response
        context: Description for error messages
    
    Raises:
        NVDSchemaValidationError: If data is not serializable or contains invalid UTF-8
    """
    # LAYER 1: Content validation (catches null bytes, control chars, etc.)
    validate_string_content(data, context)
    
    # LAYER 2: Serialization test
    try:
        serialized = orjson.dumps(data)
    except (orjson.JSONEncodeError, TypeError, ValueError) as e:
        error_msg = f"Data contains non-serializable content: {type(e).__name__}: {str(e)[:200]} - {context}"
        raise NVDSchemaValidationError(error_msg)
    
    # LAYER 3: Round-trip test (catches UTF-8 surrogate pairs)
    try:
        orjson.loads(serialized)
    except (orjson.JSONDecodeError, ValueError) as e:
        error_msg = f"Data contains invalid UTF-8 encoding (surrogates/invalid sequences): {type(e).__name__}: {str(e)[:200]} - {context}"
        raise NVDSchemaValidationError(error_msg)


def validate_cpe_data(
    data: Dict[str, Any],
    query_string: str,
    schema: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Validate CPE API response data against schema.
    
    Args:
        data: Parsed CPE API response (from validate_http_response)
        query_string: CPE query string for context
        schema: CPE API 2.0 schema (None = skip schema validation)
    
    Returns:
        Validated data
    
    Raises:
        NVDSchemaValidationError: If validation fails
    """
    context = f"CPE API query: {query_string}"
    
    validate_against_schema(data, schema, context)
    validate_orjson_serializable(data, context)
    
    return data


def validate_cve_data(
    data: Dict[str, Any],
    cve_id: str,
    schema: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Validate CVE API response data against schema.
    
    Args:
        data: Parsed CVE API response (from validate_http_response)
        cve_id: CVE ID for context
        schema: CVE API 2.0 schema (None = skip schema validation)
    
    Returns:
        Validated data
    
    Raises:
        NVDSchemaValidationError: If validation fails
    """
    context = f"CVE API query: {cve_id}"
    
    validate_against_schema(data, schema, context)
    validate_orjson_serializable(data, context)
    
    return data


def validate_source_data(
    data: Dict[str, Any],
    schema: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Validate Source API response data against schema.
    
    Args:
        data: Parsed Source API response (from validate_http_response)
        schema: Source API 2.0 schema (None = skip schema validation)
    
    Returns:
        Validated data
    
    Raises:
        NVDSchemaValidationError: If validation fails
    """
    context = "Source API query"
    
    validate_against_schema(data, schema, context)
    validate_orjson_serializable(data, context)
    
    return data


def validate_cve_record_v5(
    cve_record: Dict[str, Any],
    cve_id: str,
    schema: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Validate CVE List V5 record data against schema.
    
    Args:
        cve_record: CVE List V5 record data
        cve_id: CVE ID for context
        schema: CVE Record V5 schema (None = skip schema validation)
    
    Returns:
        Validated CVE record data
    
    Raises:
        NVDSchemaValidationError: If record fails validation
    """
    context = f"CVE List V5 record: {cve_id}"
    
    # Basic structure check
    if not isinstance(cve_record, dict):
        error_msg = f"Invalid record type: expected dict, got {type(cve_record).__name__} - {context}"
        raise NVDSchemaValidationError(error_msg)
    
    if 'cveMetadata' not in cve_record:
        error_msg = f"Missing required field: cveMetadata - {context}"
        raise NVDSchemaValidationError(error_msg)
    
    validate_against_schema(cve_record, schema, context)
    validate_orjson_serializable(cve_record, context)
    
    return cve_record

