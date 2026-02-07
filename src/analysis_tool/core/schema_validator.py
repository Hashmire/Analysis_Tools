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
from typing import Dict, Any, Optional

try:
    import jsonschema
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False

try:
    import orjson
    ORJSON_AVAILABLE = True
except ImportError:
    ORJSON_AVAILABLE = False

from ..logging.workflow_logger import get_logger

logger = get_logger()


class NVDSchemaValidationError(Exception):
    """Raised when data fails schema validation"""
    pass


def validate_against_schema(
    data: Dict[str, Any],
    schema: Optional[Dict[str, Any]],
    context: str
) -> None:
    """
    Validate data against JSON schema.
    
    Args:
        data: Parsed API response data
        schema: JSON schema (None = skip validation)
        context: Description for error messages
    
    Raises:
        NVDSchemaValidationError: If data fails schema validation
    """
    if schema is None or not JSONSCHEMA_AVAILABLE:
        return
    
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        error_path = ' -> '.join(str(p) for p in e.path) if e.path else 'root'
        error_msg = f"Schema validation failed at {error_path}: {e.message} - {context}"
        logger.error(error_msg, group="DATA_PROC")
        raise NVDSchemaValidationError(error_msg)
    except jsonschema.SchemaError as e:
        logger.error(f"Invalid schema encountered: {e}", group="DATA_PROC")


def validate_orjson_serializable(data: Dict[str, Any], context: str) -> None:
    """
    Validate data is serializable by orjson (required for cache storage).
    
    Args:
        data: Parsed API response
        context: Description for error messages
    
    Raises:
        NVDSchemaValidationError: If data is not serializable
    """
    if not ORJSON_AVAILABLE:
        # Fallback to standard json
        try:
            json.dumps(data)
        except (TypeError, ValueError) as e:
            error_msg = f"Data not serializable: {type(e).__name__}: {str(e)[:200]} - {context}"
            logger.error(error_msg, group="DATA_PROC")
            raise NVDSchemaValidationError(error_msg)
        return
    
    try:
        orjson.dumps(data)
    except (orjson.JSONEncodeError, TypeError, ValueError) as e:
        error_msg = f"Data contains non-serializable content: {type(e).__name__}: {str(e)[:200]} - {context}"
        logger.error(error_msg, group="DATA_PROC")
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
        logger.error(error_msg, group="DATA_PROC")
        raise NVDSchemaValidationError(error_msg)
    
    if 'cveMetadata' not in cve_record:
        error_msg = f"Missing required field: cveMetadata - {context}"
        logger.error(error_msg, group="DATA_PROC")
        raise NVDSchemaValidationError(error_msg)
    
    validate_against_schema(cve_record, schema, context)
    validate_orjson_serializable(cve_record, context)
    
    return cve_record

