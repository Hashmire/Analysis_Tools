"""
gatherData.py — Data Retrieval, Cache Management, and Orchestration
"""

# Import Python dependencies
import requests
import pandas as pd
import os
import sys
import json
import threading
from time import sleep, time
from pathlib import Path
from typing import Optional, List, Tuple, Any
from datetime import datetime, timezone
from urllib.parse import urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import Analysis Tool
from . import processData

# Import logging and storage utilities
from ..logging.workflow_logger import get_logger
from ..storage.run_organization import get_analysis_tools_root

# Get logger instance
logger = get_logger()


class HTTPResponseError(Exception):
    """Raised when HTTP response fails integrity checks or JSON parsing"""
    pass


class NVDConcurrentCVERateLimiter:
    """
    Thread-safe rate limiter for concurrent NVD /cves/ API queries.

    Coordinates request pacing across all workers in a ThreadPoolExecutor to
    ensure compliance with NVD API rate limits (50 req/30s with key, 5 req/30s
    without key). Not used by sequential paths (CPE, source, single-CVE fetches).

    Tracks requests in a sliding window and enforces minimum per-request spacing
    to smooth bursts across the window and maintain a safety buffer below the
    actual limit.
    """
    
    def __init__(self, max_requests: int = 50, window_seconds: int = 30, buffer_percent: float = 0.10):
        """
        Args:
            max_requests: Maximum requests allowed per window (default: 50 for API key)
            window_seconds: Time window in seconds (default: 30)
            buffer_percent: Safety buffer as fraction (default: 0.10 = 10% buffer)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.buffer_percent = buffer_percent
        
        # Effective limit with safety buffer (e.g., 45 for 50 req/30s with 10% buffer)
        self.effective_limit = int(max_requests * (1.0 - buffer_percent))
        
        # Calculate optimal spacing between requests for smooth distribution
        # e.g., 30s / 45 requests = 0.667 seconds between requests
        self.min_spacing = window_seconds / self.effective_limit if self.effective_limit > 0 else 0
        
        self.requests = []  # List of timestamps
        self.last_request_time = 0.0  # Track last request for minimum spacing
        self.lock = threading.Lock()
        
        logger.debug(
            f"Rate limiter initialized: {max_requests} req/{window_seconds}s "
            f"(effective: {self.effective_limit} with {buffer_percent*100:.0f}% buffer, "
            f"min spacing: {self.min_spacing:.3f}s)",
            group="cve_queries"
        )
    
    def _clean_old_requests(self, current_time: float):
        """Remove requests older than the window (not thread-safe, call with lock)"""
        cutoff = current_time - self.window_seconds
        self.requests = [t for t in self.requests if t > cutoff]
    
    def acquire(self, blocking: bool = True) -> bool:
        """
        Acquire permission to make a request.
        
        Enforces both:
        1. Sliding window limit (effective_limit over window_seconds)
        2. Minimum spacing between requests for smooth distribution
        
        Args:
            blocking: If True, wait until permission granted; if False, return immediately
        
        Returns:
            True if permission granted, False if would exceed rate limit (only when blocking=False)
        """
        while True:
            with self.lock:
                current_time = time()
                self._clean_old_requests(current_time)
                
                # Check 1: Minimum spacing since last request
                time_since_last = current_time - self.last_request_time
                if time_since_last < self.min_spacing:
                    spacing_wait = self.min_spacing - time_since_last
                    if not blocking:
                        return False
                else:
                    spacing_wait = 0
                
                # Check 2: Within effective limit
                if len(self.requests) < self.effective_limit and spacing_wait == 0:
                    self.requests.append(current_time)
                    self.last_request_time = current_time
                    return True
                
                if not blocking:
                    return False
                
                # Calculate total wait time (max of spacing wait and window wait)
                if len(self.requests) >= self.effective_limit:
                    oldest_request = self.requests[0]
                    window_wait = self.window_seconds - (current_time - oldest_request) + 0.01
                    wait_time = max(spacing_wait, window_wait)
                else:
                    wait_time = spacing_wait
            
            # Sleep outside the lock
            if wait_time > 0:
                sleep(min(wait_time, 1.0))  # Sleep in 1s increments max
    
    def get_current_usage(self) -> Tuple[int, int]:
        """Get current request count and effective limit (thread-safe)"""
        with self.lock:
            current_time = time()
            self._clean_old_requests(current_time)
            return len(self.requests), self.effective_limit


def validate_http_response(response: requests.Response, context: str, max_size_mb: int = 100) -> dict:
    """
    Universal HTTP response validator for all API calls.
    
    Validates transport layer (HTTP) and extracts JSON data.
    Generic checks applicable to all NVD/CVE API responses.
    
    Args:
        response: requests.Response object from API call
        context: Description for error messages (e.g., "CVE API query: CVE-2024-1234")
        max_size_mb: Maximum allowed response size in MB (default: 100)
    
    Returns:
        Parsed JSON data as dict
    
    Raises:
        HTTPResponseError: If response fails any integrity check
    
    Example:
        response = requests.get(url, headers=headers)
        data = validate_http_response(response, "NVD CVE API")
    """
    # 0. Check HTTP status code (4xx, 5xx errors)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        status_code = response.status_code
        cf_ray = response.headers.get('CF-RAY', '')
        cf_details = f" [CF-RAY: {cf_ray}]" if cf_ray else ""
        error_msg = f"HTTP {status_code} error: {e}{cf_details} - {context}"
        logger.error(error_msg, group="DATA_PROC")
        raise HTTPResponseError(error_msg) from e
    except Exception as e:
        # Catch any other unexpected errors during status check
        error_msg = f"Unexpected error checking HTTP status: {type(e).__name__}: {e} - {context}"
        logger.error(error_msg, group="DATA_PROC")
        raise HTTPResponseError(error_msg) from e
    
    # 1. Check Content-Type header
    content_type = response.headers.get('content-type', '')
    if 'application/json' not in content_type.lower():
        error_msg = f"Invalid Content-Type: {content_type} (expected application/json) - {context}"
        logger.error(error_msg, group="DATA_PROC")
        raise HTTPResponseError(error_msg)
    
    # 2. Check response size
    content_length = len(response.content)
    max_bytes = max_size_mb * 1024 * 1024
    
    if content_length > max_bytes:
        size_mb = content_length / 1024 / 1024
        error_msg = f"Response too large: {size_mb:.1f}MB (max {max_size_mb}MB) - {context}"
        logger.error(error_msg, group="DATA_PROC")
        raise HTTPResponseError(error_msg)
    
    if content_length == 0:
        error_msg = f"Response body is empty - {context}"
        logger.error(error_msg, group="DATA_PROC")
        raise HTTPResponseError(error_msg)
    
    # 3. Parse JSON
    try:
        data = response.json()
    except json.JSONDecodeError as e:
        error_msg = f"Invalid JSON in response: {e} - {context}"
        logger.error(error_msg, group="DATA_PROC")
        raise HTTPResponseError(error_msg)
    except Exception as e:
        error_msg = f"Failed to parse response: {type(e).__name__}: {e} - {context}"
        logger.error(error_msg, group="DATA_PROC")
        raise HTTPResponseError(error_msg)
    
    # 4. Validate is a dict (NVD APIs always return objects, not arrays)
    if not isinstance(data, dict):
        error_msg = f"Response is not a JSON object (got {type(data).__name__}) - {context}"
        logger.error(error_msg, group="DATA_PROC")
        raise HTTPResponseError(error_msg)
    
    return data

# Load configuration
def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'config.json')
    with open(config_path, 'r') as f:
        config = json.load(f)
    if os.environ.get('TEST_NVD_API_DISABLED'):
        config['api']['retry']['max_attempts_nvd'] = 0
        config['api']['retry']['max_attempts_cpe'] = 0
    return config

config = load_config()
VERSION = config['application']['version']
TOOLNAME = config['application']['toolname']


def build_nvd_api_headers(api_key=None):
    """Build standard NVD API request headers. Pass api_key for authenticated rate limits."""
    headers = {
        "Accept": "application/json",
        "User-Agent": f"{TOOLNAME}/{VERSION}"
    }
    if api_key:
        headers["apiKey"] = api_key
    return headers


# ============================================================================
# Schema Loading Functions (Cache I/O Operations)
# ============================================================================

# In-memory schema cache to avoid repeated downloads
_schema_cache = {}

# Mapping of external ref URLs to local cached filenames
_external_schema_cache = {}

# Cache of RefResolver instances keyed by schema identity (avoids recreating RefResolvers)
_resolver_cache = {}


def _extract_external_refs(schema: dict, base_url_pattern: str = "https://csrc.nist.gov/schema/") -> set:
    """
    Recursively extract external HTTP/HTTPS $ref URLs from a JSON schema.
    
    Args:
        schema: JSON schema dictionary
        base_url_pattern: URL pattern to identify external refs (default: NIST schemas)
    
    Returns:
        Set of external $ref URLs found in the schema
    """
    external_refs = set()
    
    def scan_value(value):
        if isinstance(value, dict):
            # Check if this dict contains a $ref
            if '$ref' in value:
                ref_url = value['$ref']
                # Check if it's an external HTTP/HTTPS URL (not internal #/definitions/...)
                if isinstance(ref_url, str) and ref_url.startswith(('http://', 'https://')):
                    if base_url_pattern in ref_url:
                        external_refs.add(ref_url)
            # Recurse into all values
            for v in value.values():
                scan_value(v)
        elif isinstance(value, list):
            for item in value:
                scan_value(item)
    
    scan_value(schema)
    return external_refs


def _download_external_schema(url: str, schema_dir: Path) -> Optional[Path]:
    """
    Download an external FIRST CVSS schema with proper User-Agent header and cache locally.
    
    NVD blocks requests without browser-like User-Agent headers, so we need to
    set appropriate headers to successfully download external CVSS schemas.
    
    Implements retry logic to handle intermittent network issues and rate limiting.
    
    Schemas are saved to cache/schemas/first_cvss/ subdirectory (FIRST CVSS schemas).
    
    NOTE: Download failures return None and log warnings (not exceptions).
    This allows main schema caching to proceed. Missing external schemas will surface
    during actual validation as NVDSchemaValidationError, providing schema validation
    warnings without preventing data caching (unless critical sections are affected).
    
    Args:
        url: External CVSS schema URL to download (from csrc.nist.gov/schema/nvd/api/2.0/external/)
        schema_dir: Base schema directory (cache/schemas/)
    
    Returns:
        Path to cached schema file, or None if download failed
    """
    try:
        # Extract filename from URL (e.g., cvss-v3.1.json)
        url_filename = url.split('/')[-1]
        
        # Save FIRST CVSS schemas to first_cvss/ subdirectory (no external_ prefix)
        first_cvss_dir = schema_dir / "first_cvss"
        first_cvss_dir.mkdir(parents=True, exist_ok=True)
        cache_path = first_cvss_dir / url_filename
        
        # Check if already cached
        if cache_path.exists():
            logger.debug(f"FIRST CVSS schema already cached: first_cvss/{url_filename}", group="CACHE_MANAGEMENT")
            return cache_path
        
        # Download with browser-like User-Agent to avoid NVD blocking
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        # Retry logic for intermittent failures (NVD rate limiting)
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                logger.debug(f"Downloading external schema: {url} (attempt {attempt}/{max_retries})", group="CACHE_MANAGEMENT")
                response = requests.get(url, headers=headers, timeout=15)
                response.raise_for_status()
                
                # Validate it's valid JSON
                schema_data = response.json()
                
                # Save to cache
                cache_path.write_text(json.dumps(schema_data, indent=2), encoding='utf-8')
                logger.debug(f"FIRST CVSS schema cached: first_cvss/{url_filename}", group="CACHE_MANAGEMENT")
                
                # Store mapping for RefResolver
                _external_schema_cache[url] = cache_path
                
                return cache_path
            except (requests.RequestException, ConnectionResetError) as e:
                if attempt < max_retries:
                    # Wait before retry (exponential backoff)
                    wait_time = 2 ** (attempt - 1)
                    logger.debug(f"Retry {attempt}/{max_retries} in {wait_time}s after error: {e}", group="CACHE_MANAGEMENT")
                    sleep(wait_time)
                else:
                    raise  # Re-raise on final attempt
        
    except Exception as e:
        logger.warning(
            f"Failed to download external schema from {url}: {e}",
            group="CACHE_MANAGEMENT"
        )
        return None


def load_schema(schema_name: str) -> dict:
    """
    Load JSON schema from URL specified in config.json.
    Caches schemas in memory and on disk to avoid repeated downloads.
    
    CRITICAL: Schema files MUST follow naming convention: Source_Endpoint_Version_schema.json
    
    Config.json schema keys define the expected filename (without _schema.json suffix):
    - nvd_cpes_2_0 -> nvd_cpes_2_0_schema.json
    - nvd_cves_2_0 -> nvd_cves_2_0_schema.json
    - nvd_source_2_0 -> nvd_source_2_0_schema.json
    - cve_cve_5_2 -> cve_cve_5_2_schema.json (version validated against schema's dataVersion.default)
    
    For CVE schemas, the version is derived from schema content and MUST match config key.
    This ensures we're using the expected schema version and fail explicitly on version mismatches.
    
    Args:
        schema_name: Schema identifier from config.json (e.g., 'nvd_cpes_2_0', 'cve_cve_5_2')
    
    Returns:
        Parsed JSON schema as dict
    
    Raises:
        ValueError: If schema_name not found in config, version mismatch, or invalid format
        requests.RequestException: If schema download fails
        json.JSONDecodeError: If schema is invalid JSON
    """
    # Check memory cache first
    if schema_name in _schema_cache:
        logger.debug(f"Schema loaded from memory cache: {schema_name}", group="CACHE_MANAGEMENT")
        return _schema_cache[schema_name]
    
    # Get schema URL from config
    if schema_name not in config['api']['schemas']:
        raise ValueError(f"Schema '{schema_name}' not found in config.json api.schemas")
    
    schema_url = config['api']['schemas'][schema_name]
    project_root = get_analysis_tools_root()
    base_schema_dir = project_root / "cache" / "schemas"
    
    # Determine schema source and subdirectory
    # NVD Project schemas
    if schema_name.startswith('nvd_'):
        schema_source_dir = base_schema_dir / "nvd_project"
        schema_source = "nvd_project"
    # CVE Program schemas
    elif schema_name.startswith('cve_'):
        schema_source_dir = base_schema_dir / "cve_program"
        schema_source = "cve_program"
    # Analysis Tool schemas (our own)
    else:
        schema_source_dir = base_schema_dir / "analysis_tool"
        schema_source = "analysis_tool"
    
    # Determine if this is a CVE schema (requires version validation)
    is_cve_schema = schema_name.startswith('cve_cve_')
    
    # Generate expected filename from config key
    schema_filename = f"{schema_name}_schema.json"
    schema_source_dir.mkdir(parents=True, exist_ok=True)
    schema_path = schema_source_dir / schema_filename
    
    # Check disk cache before downloading
    if schema_path.exists():
        try:
            schema_data = json.loads(schema_path.read_text(encoding='utf-8'))
            _schema_cache[schema_name] = schema_data
            logger.debug(f"Schema loaded from disk cache: {schema_filename}", group="CACHE_MANAGEMENT")
            
            # Update schema metadata (ensures cache_metadata.json stays current)
            _update_schema_metadata(schema_name, schema_filename, schema_source)
            
            # Download and cache any external $ref schemas if not already cached
            # NOTE: External schema download failures are logged but don't prevent main schema use.
            external_refs = _extract_external_refs(schema_data)
            if external_refs:
                for ref_url in external_refs:
                    cached_path = _download_external_schema(ref_url, base_schema_dir)
                    if cached_path:
                        _external_schema_cache[ref_url] = cached_path
            
            return schema_data
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(
                f"Failed to load schema from disk cache ({schema_filename}), will re-download: {e}",
                group="CACHE_MANAGEMENT"
            )
    
    # Download schema
    logger.debug(f"Downloading schema: {schema_name} from {schema_url}", group="CACHE_MANAGEMENT")
    
    try:
        response = requests.get(schema_url, timeout=config['api']['timeouts']['nvd_api'])
        response.raise_for_status()
        schema_data = response.json()
        
        # For CVE schemas, validate derived version matches config key
        if is_cve_schema:
            # Extract version from schema: definitions.dataVersion.default (e.g., "5.2.0")
            data_version = schema_data.get('definitions', {}).get('dataVersion', {}).get('default', '')
            if not data_version:
                logger.error("CVE schema missing definitions.dataVersion.default field", group="CACHE_MANAGEMENT")
                sys.exit(1)
            
            # Extract major.minor from version string (e.g., "5.2.0" -> "5_2")
            version_parts = data_version.split('.')
            if len(version_parts) < 2:
                logger.error(f"Invalid CVE schema version format: {data_version}", group="CACHE_MANAGEMENT")
                sys.exit(1)
            
            major, minor = version_parts[0], version_parts[1]
            derived_version = f"{major}.{minor}"
            
            # Extract expected version from config key (e.g., "cve_cve_5_2" -> "5.2")
            expected_parts = schema_name.split('_')[2:]  # Skip "cve_cve_" prefix
            expected_version = '.'.join(expected_parts)
            
            # Validate versions match
            if derived_version != expected_version:
                logger.error(
                    f"Expected CVE schema major.minor version is {expected_version} but schema has "
                    f"dataVersion.default '{data_version}'. CVE record validation may not work properly "
                    f"without expected schema version.",
                    group="CACHE_MANAGEMENT"
                )
                sys.exit(1)
            
            logger.debug(
                f"CVE schema version validated: {data_version} matches expected {expected_version}",
                group="CACHE_MANAGEMENT"
            )
        
        # Save to disk cache
        try:
            schema_source_dir.mkdir(parents=True, exist_ok=True)
            schema_path.write_text(json.dumps(schema_data, indent=2), encoding='utf-8')
            logger.debug(f"Schema saved to disk cache: {schema_source}/{schema_filename}", group="CACHE_MANAGEMENT")
            
            # Update schema metadata in cache_metadata.json
            _update_schema_metadata(schema_name, schema_filename, schema_source)
        except OSError as e:
            logger.warning(f"Failed to save schema to disk ({schema_source}/{schema_filename}): {e}", group="CACHE_MANAGEMENT")
        
        # Cache in memory
        _schema_cache[schema_name] = schema_data
        logger.debug(f"Schema cached in memory: {schema_name}", group="CACHE_MANAGEMENT")
        
        # Download and cache external $ref schemas (e.g., CVSS schemas)
        # NOTE: External schema download failures are logged but don't prevent main schema caching.
        external_refs = _extract_external_refs(schema_data)
        if external_refs:
            logger.debug(
                f"Found {len(external_refs)} external schema references in {schema_name}",
                group="CACHE_MANAGEMENT"
            )
            for ref_url in external_refs:
                cached_path = _download_external_schema(ref_url, base_schema_dir)
                if cached_path:
                    _external_schema_cache[ref_url] = cached_path
        
        return schema_data
        
    except requests.RequestException as e:
        error_msg = f"Failed to download schema '{schema_name}' from {schema_url}: {e}"
        logger.error(error_msg, group="CACHE_MANAGEMENT")
        raise
    except json.JSONDecodeError as e:
        error_msg = f"Invalid JSON in schema '{schema_name}': {e}"
        logger.error(error_msg, group="CACHE_MANAGEMENT")
        raise


def get_schema_ref_resolver(schema: dict) -> Optional[Any]:
    """
    Get or create a cached RefResolver for external schema references.
    
    This prevents jsonschema from attempting to fetch external URLs (which may be
    blocked by NIST's User-Agent filtering) and instead uses pre-downloaded cached schemas.
    
    Args:
        schema: The root schema dictionary
    
    Returns:
        Cached RefResolver instance, or None if no external refs available
    """
    if not _external_schema_cache:
        return None
    
    # Use schema object identity as cache key (same schema dict = same RefResolver)
    schema_id = id(schema)
    
    # Return cached RefResolver if available
    if schema_id in _resolver_cache:
        return _resolver_cache[schema_id]
    
    try:
        # Build store mapping URLs to cached schema data (only done once per schema)
        store = {}
        for url, cache_path in _external_schema_cache.items():
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    store[url] = json.load(f)
                logger.debug(f"Loaded external schema for resolver: {url}", group="CACHE_MANAGEMENT")
            except Exception as e:
                logger.warning(
                    f"Failed to load cached external schema {cache_path}: {e}",
                    group="CACHE_MANAGEMENT"
                )
        
        if not store:
            return None
        
        # Create RefResolver with custom store
        # Note: RefResolver is deprecated in jsonschema 4.18+ but still functional
        # Future enhancement: migrate to referencing library when needed
        import jsonschema
        resolver = jsonschema.RefResolver.from_schema(schema, store=store)
        logger.debug(
            f"Created RefResolver with {len(store)} external schema mappings",
            group="CACHE_MANAGEMENT"
        )
        
        # Cache for future use
        _resolver_cache[schema_id] = resolver
        
        return resolver
        
    except Exception as e:
        logger.warning(f"Failed to create RefResolver: {e}", group="CACHE_MANAGEMENT")
        return None


def _update_schema_metadata(schema_name: str, schema_filename: str, schema_source: str):
    """
    Update schema file metadata in unified cache_metadata.json.
    
    Tracks schema files downloaded and cached locally, including descriptions,
    source attribution, and last modification times for monitoring purposes.
    
    CRITICAL: Uses orjson for compatibility with CPE cache which also writes to this file.
    
    Args:
        schema_name: Schema identifier (e.g., 'cve_cve_5_2', 'nvd_cpes_2_0')
        schema_filename: Schema filename (e.g., 'cve_cve_5_2_schema.json')
        schema_source: Schema source subdirectory (e.g., 'nvd', 'cve_program', 'analysis_tool', 'first')
    """
    try:
        import orjson
        
        project_root = Path(__file__).parent.parent.parent.parent
        schema_path = project_root / "cache" / "schemas" / schema_source / schema_filename
        metadata_file = project_root / "cache" / "cache_metadata.json"
        
        # Schema file must exist
        if not schema_path.exists():
            return
        
        # Get file modification time
        file_stat = schema_path.stat()
        file_mtime = datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc)
        
        # Schema descriptions
        schema_descriptions = {
            'cve_cve_5_2': 'CVE Program - CVE List V5.2 Record Format Schema',
            'nvd_cpes_2_0': 'NVD Project - CPE 2.0 API Response Schema',
            'nvd_cves_2_0': 'NVD Project - CVE 2.0 API Response Schema',
            'nvd_source_2_0': 'NVD Project - Source 2.0 API Response Schema'
        }
        
        # Source descriptions
        source_descriptions = {
            'nvd_project': 'NVD Project (NIST)',
            'cve_program': 'CVE Program (cve.org)',
            'first_cvss': 'FIRST CVSS Schemas',
            'analysis_tool': 'Analysis Tool (local)'
        }
        
        # Load existing metadata using orjson (same as CPE cache)
        metadata = {}
        if metadata_file.exists():
            try:
                with open(metadata_file, 'rb') as f:
                    metadata = orjson.loads(f.read())
            except Exception as e:
                logger.warning(f"Failed to load cache metadata for schema update: {e}", group="CACHE_MANAGEMENT")
                return
        
        # Initialize structure
        if 'datasets' not in metadata:
            metadata['datasets'] = {}
        
        # Update schema metadata with source attribution
        metadata['datasets'][schema_name] = {
            'description': schema_descriptions.get(schema_name, f'Schema file: {schema_filename}'),
            'filename': schema_filename,
            'source': source_descriptions.get(schema_source, schema_source),
            'source_dir': schema_source,
            'last_updated': file_mtime.isoformat()
        }
        
        metadata['last_updated'] = datetime.now(timezone.utc).isoformat()
        
        # Save updated metadata using orjson (same as CPE cache)
        with open(metadata_file, 'wb') as f:
            f.write(orjson.dumps(metadata, option=orjson.OPT_INDENT_2))
        
        logger.debug(f"Updated schema metadata for {schema_name}", group="CACHE_MANAGEMENT")
    except Exception as e:
        logger.warning(f"Could not update schema metadata for {schema_name}: {e}", group="CACHE_MANAGEMENT")


def clear_schema_cache():
    """Clear in-memory schema cache (useful for testing)"""
    global _schema_cache
    _schema_cache = {}
    logger.debug("Schema cache cleared", group="CACHE_MANAGEMENT")


# Session-level cache for config lookups
_config_cache = {}

def _get_cached_config(cache_type):
    """Get cache config with session-level caching to avoid repeated file reads"""
    if cache_type not in _config_cache:
        _config_cache[cache_type] = get_cache_config(cache_type)
    return _config_cache[cache_type]


def _update_cache_metadata(cache_type, repo_path):
    """
    Unified cache metadata updater for all cache types.
    
    Args:
        cache_type: Type of cache ('cve_list_v5', 'nvd_2_0_cve')
        repo_path: Path to the cache directory
    """
    try:
        # Get project root for cache metadata file
        project_root = Path(__file__).parent.parent.parent.parent
        cache_dir = project_root / "cache"
        metadata_file = cache_dir / "cache_metadata.json"
        
        # Count total files - resolve path relative to project root
        if isinstance(repo_path, str):
            cache_path = Path(repo_path)
        else:
            cache_path = repo_path
            
        # If relative path, make it relative to project root
        if not cache_path.is_absolute():
            cache_path = project_root / cache_path
            
        total_files = len(list(cache_path.rglob("*.json"))) if cache_path.exists() else 0
        current_time = datetime.now(timezone.utc)
        
        # Load existing metadata
        metadata = {}
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            except:
                pass
        
        # Initialize structure if needed
        if 'datasets' not in metadata:
            metadata['datasets'] = {}
            
        # Update cache metadata
        cache_data = metadata['datasets'].get(cache_type, {})
        
        # Set creation time if this is the first entry
        if 'created' not in cache_data and total_files > 0:
            cache_data['created'] = current_time.isoformat()
            
        # Get description from config
        description = _get_cached_config(cache_type).get('description', f'{cache_type} cache')
            
        cache_data.update({
            'description': description,
            'directory_path': str(repo_path),
            'last_updated': current_time.isoformat(),
            'total_files': total_files
        })
        
        metadata['datasets'][cache_type] = cache_data
        metadata['last_updated'] = current_time.isoformat()
        
        # Save updated metadata
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2, sort_keys=True)
    except Exception as e:
        logger.warning(f"Could not update {cache_type} cache metadata: {e}", group="CACHE_MANAGEMENT")


def _update_manual_refresh_timestamp(cache_type):
    """
    Update lastManualUpdate timestamp for manual refresh operations.
    
    This is separate from last_updated to distinguish between:
    - Manual refresh operations (lastManualUpdate) - used by refresh scripts to determine query range
    - Automatic pipeline updates (last_updated) - used for cache metadata tracking
    
    Args:
        cache_type: Type of cache ('cpe_cache', 'nvd_2_0_cve', 'cve_list_v5', etc.)
    """
    current_time = datetime.now(timezone.utc)

    if cache_type == 'cve_list_v5':
        try:
            project_root = Path(__file__).parent.parent.parent.parent
            config_file = project_root / "config.json"

            with open(config_file, 'r') as f:
                cfg = json.load(f)

            cfg['cache_settings']['cve_list_v5']['refresh_strategy']['last_manual_update'] = current_time.isoformat()

            with open(config_file, 'w') as f:
                json.dump(cfg, f, indent=4)

            logger.info(f"Updated cve_list_v5 last_manual_update in config.json: {current_time.isoformat()}", group="CACHE_MANAGEMENT")
        except Exception as e:
            logger.warning(f"Could not update cve_list_v5 last_manual_update in config.json: {e}", group="CACHE_MANAGEMENT")
        return

    try:
        # Get project root for cache metadata file
        project_root = Path(__file__).parent.parent.parent.parent
        metadata_file = project_root / "cache" / "cache_metadata.json"
        
        # Load existing metadata
        metadata = {}
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            except:
                logger.warning(f"Failed to load cache metadata for manual update timestamp", group="CACHE_MANAGEMENT")
                return
        
        # Initialize structure if needed
        if 'datasets' not in metadata:
            metadata['datasets'] = {}
        
        if cache_type not in metadata['datasets']:
            logger.warning(f"Cache type {cache_type} not found in metadata - skipping lastManualUpdate", group="CACHE_MANAGEMENT")
            return
        
        # Update lastManualUpdate timestamp
        metadata['datasets'][cache_type]['lastManualUpdate'] = current_time.isoformat()
        metadata['last_updated'] = current_time.isoformat()
        
        # Save updated metadata
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2, sort_keys=True)
        
        logger.info(f"Updated {cache_type} lastManualUpdate timestamp: {current_time.isoformat()}", group="CACHE_MANAGEMENT")
        
    except Exception as e:
        logger.warning(f"Could not update manual refresh timestamp for {cache_type}: {e}", group="CACHE_MANAGEMENT")


def _get_cache_metadata_last_update(cache_type='nvd_2_0_cve') -> Optional[datetime]:
    """
    Read cache metadata to get last manual update timestamp for a cache type.
    
    Args:
        cache_type: Type of cache to query (default: 'nvd_2_0_cve')
    
    Returns:
        Datetime of last manual update (timezone-aware), or None if unavailable
    """
    try:
        project_root = Path(__file__).parent.parent.parent.parent
        metadata_file = project_root / "cache" / "cache_metadata.json"
        
        if not metadata_file.exists():
            return None
        
        with open(metadata_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        
        cache_data = metadata.get('datasets', {}).get(cache_type, {})
        last_update_str = cache_data.get('lastManualUpdate') or cache_data.get('last_updated')
        
        if not last_update_str:
            return None
        
        # Parse ISO format datetime
        last_update = datetime.fromisoformat(last_update_str.replace('Z', '+00:00'))
        return last_update
        
    except Exception as e:
        logger.warning(f"Failed to read cache metadata for {cache_type}: {e}", group="CACHE_MANAGEMENT")
        return None


def _transform_nvd_vulnerability_to_response(vuln_record: dict, cve_id: str) -> dict:
    """
    Transform a single NVD vulnerability record to complete API response format.
    
    When NVD API returns multiple CVEs (e.g., via lastModStartDate query), the response is:
    {vulnerabilities: [vuln1, vuln2, ..., vuln2000]}
    
    This function wraps a single vulnerability record into the standard single-CVE response
    format that matches what NVD returns for individual CVE queries (?cveId=CVE-XXX):
    {vulnerabilities: [single_vuln], resultsPerPage: 1, totalResults: 1, ...}
    
    Args:
        vuln_record: Single vulnerability record from NVD API
        cve_id: CVE ID for logging/validation
    
    Returns:
        Complete NVD API response dict with single vulnerability
    """
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "vulnerabilities": [vuln_record]
    }


def get_cache_config(cache_type):
    """
    Unified cache configuration getter. Fails fast if config is missing or malformed.

    Args:
        cache_type: Type of cache ('cve_list_v5', 'nvd_2_0_cve')

    Returns:
        Cache configuration dictionary from config.json

    Raises:
        RuntimeError: If config cannot be loaded or required cache section is missing
    """
    try:
        config = load_config()
    except Exception as e:
        logger.error(f"Failed to load config file for cache type '{cache_type}': {e}", group="CACHE_MANAGEMENT")
        raise RuntimeError(f"Cannot load config for cache type '{cache_type}': {e}") from e

    if 'cache_settings' not in config:
        msg = f"Config file is missing required 'cache_settings' section (needed for '{cache_type}')"
        logger.error(msg, group="CACHE_MANAGEMENT")
        raise RuntimeError(msg)

    if cache_type not in config['cache_settings']:
        msg = f"Config file 'cache_settings' is missing required '{cache_type}' entry"
        logger.error(msg, group="CACHE_MANAGEMENT")
        raise RuntimeError(msg)

    return config['cache_settings'][cache_type]



def get_public_ip():
    """Get the current public IP address being used by the tool."""
    try:
        response = requests.get(config['api']['endpoints']['public_ip'], 
                              timeout=config['api']['timeouts']['public_ip'])
        return response.text if response.status_code == 200 else "Unknown"
    except Exception as e:
        return f"Could not retrieve IP: {str(e)}"

def _resolve_cve_cache_file_path(cve_id, repo_base_path):
    """
    Unified CVE file path resolver for all cache types.
    CVE-2024-12345 → {repo_base_path}/2024/12xxx/CVE-2024-12345.json
    
    Args:
        cve_id: CVE ID (e.g., "CVE-2024-12345")
        repo_base_path: Base path for cache repository
        
    Returns:
        Path object or None if CVE ID is invalid
    """
    try:
        parts = cve_id.split('-')
        if len(parts) != 3 or parts[0] != 'CVE':
            return None
            
        year = parts[1]
        sequence = parts[2]
        
        # Create directory name based on sequence length
        if len(sequence) == 4:
            dir_name = f"{sequence[0]}xxx"
        elif len(sequence) == 5:
            dir_name = f"{sequence[:2]}xxx"
        elif len(sequence) >= 6:
            dir_name = f"{sequence[:3]}xxx"
        else:
            return None
            
        return Path(repo_base_path) / year / dir_name / f"{cve_id}.json"
    except (IndexError, ValueError):
        return None



def _load_cve_from_local_file(cve_file_path):
    """
    Load CVE record from local JSON file.
    Returns CVE data dict or None if file doesn't exist or is invalid.
    """
    try:
        if not cve_file_path.exists():
            return None
            
        with open(cve_file_path, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
            
        # Validate basic CVE structure
        if 'cveMetadata' in cve_data and 'cveId' in cve_data['cveMetadata']:
            return cve_data
        else:
            logger.warning(f"Invalid CVE structure in local file: {cve_file_path}", group="cve_queries")
            return None
            
    except (json.JSONDecodeError, IOError, UnicodeDecodeError) as e:
        logger.warning(f"Cache file read failed: {cve_file_path} - {e}", group="CACHE_MANAGEMENT")
        return None

def _extract_cache_metadata_value(cache_metadata_path):
    """
    Extract field value from cache_metadata.json file using dot notation.
    
    Args:
        cache_metadata_path: Path like 'cache_metadata.datasets.cve_list_v5.lastManualUpdate'
    
    Returns:
        List of matching values (for consistency with _extract_field_value)
    """
    try:
        # Get project root and load cache metadata
        project_root = Path(__file__).parent.parent.parent.parent
        metadata_file = project_root / "cache" / "cache_metadata.json"
        
        if not metadata_file.exists():
            logger.debug(f"Cache metadata file not found: {metadata_file}", group="CACHE_MANAGEMENT")
            return []
        
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        # Remove 'cache_metadata.' prefix and traverse the path
        path = cache_metadata_path.replace('cache_metadata.', '')
        parts = path.split('.')
        
        current = metadata
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                logger.debug(f"Cache metadata path not found: {cache_metadata_path}", group="CACHE_MANAGEMENT")
                return []
        
        return [current] if current is not None else []
        
    except Exception as e:
        logger.debug(f"Failed to extract cache metadata value for {cache_metadata_path}: {e}", group="CACHE_MANAGEMENT")
        return []

def _extract_field_value(data, simple_path):
    """
    Extract field value from JSON data using simple dot notation.
    Supports basic patterns: field, nested.field, array.*.field
    
    Args:
        data: JSON data structure
        simple_path: Simple path like 'cveMetadata.dateUpdated' or 'vulnerabilities.*.cve.lastModified'
    
    Returns:
        List of matching values
    """
    try:
        if not simple_path or not data:
            return []
            
        # Remove leading $. if present
        path = simple_path.lstrip('$.')
        parts = path.split('.')
        
        def _traverse(obj, parts_remaining):
            if not parts_remaining:
                return [obj] if obj is not None else []
            
            part = parts_remaining[0]
            remaining = parts_remaining[1:]
            
            if part == '*':
                # Wildcard - iterate over array/object values
                if isinstance(obj, list):
                    results = []
                    for item in obj:
                        results.extend(_traverse(item, remaining))
                    return results
                elif isinstance(obj, dict):
                    results = []
                    for item in obj.values():
                        results.extend(_traverse(item, remaining))
                    return results
                else:
                    return []
            else:
                # Regular field access
                if isinstance(obj, dict) and part in obj:
                    return _traverse(obj[part], remaining)
                else:
                    return []
        
        return _traverse(data, parts)
    except Exception:
        return []

def _sync_cvelist_with_nvd_dataset(targetCve):
    """
    Check if CVE List V5 local data needs sync with NVD dataset based on modification dates.
    Args:
        targetCve: CVE ID to check for sync (e.g., "CVE-2024-12345")
    """
    try:
        logger.debug(f"Performing staleness check for {targetCve}: comparing NVD vs cache timestamps", group="CACHE_MANAGEMENT")
        
        # Get NVD data for date comparison
        nvd_data = gatherNVDCVERecord(targetCve)
        if not nvd_data:
            logger.error(
                f"Staleness check skipped for {targetCve}: NVD record not in cache. "
                f"CVE List V5 record may be stale — NVD-ish record generation will also fail.",
                group="CACHE_MANAGEMENT"
            )
            return
        
        # Extract NVD lastModified date using config field path
        nvd_config = _get_cached_config('nvd_2_0_cve')
        nvd_field_path = nvd_config.get('refresh_strategy', {}).get('field_path', '$.vulnerabilities.*.cve.lastModified')
        
        nvd_dates = _extract_field_value(nvd_data, nvd_field_path)
        
        if not nvd_dates:
            logger.warning(f"NVD 2.0 API response missing required lastModified field for {targetCve} (malformed API response)", group="CACHE_MANAGEMENT")
            return
            
        nvd_last_modified = max(nvd_dates)  # Take most recent if multiple matches
        if 'Z' in nvd_last_modified:
            nvd_datetime_str = nvd_last_modified.replace('Z', '+00:00')
        elif '+' not in nvd_last_modified and nvd_last_modified.count(':') >= 2:
            nvd_datetime_str = nvd_last_modified + '+00:00'
        else:
            nvd_datetime_str = nvd_last_modified
        nvd_datetime = datetime.fromisoformat(nvd_datetime_str)
        
        cve_config = _get_cached_config('cve_list_v5')
        local_repo_path = cve_config.get('path', 'cache/cve_list_v5')
        refresh_strategy = cve_config.get('refresh_strategy', {})
        
        last_manual_update_str = refresh_strategy.get('last_manual_update')
        
        if last_manual_update_str:
            # Fast path: last_manual_update is a direct config value — already in memory, no I/O
            if 'Z' in last_manual_update_str:
                lmu_datetime_str = last_manual_update_str.replace('Z', '+00:00')
            elif '+' not in last_manual_update_str and last_manual_update_str.count(':') >= 2:
                lmu_datetime_str = last_manual_update_str + '+00:00'
            else:
                lmu_datetime_str = last_manual_update_str
            lmu_datetime = datetime.fromisoformat(lmu_datetime_str)
            
            if nvd_datetime <= lmu_datetime:
                # NVD has not been modified since the last bulk V5 refresh — record is current
                logger.debug(f"CVE List V5 cache current for {targetCve} (NVD lastModified: {nvd_last_modified} <= last_manual_update: {last_manual_update_str})", group="CACHE_MANAGEMENT")
                return
            
            # NVD was modified after the last bulk refresh — this CVE's V5 record needs updating
            logger.info(f"NVD lastModified newer than CVE List V5 last_manual_update — refreshing {targetCve} (NVD: {nvd_last_modified}, last_manual_update: {last_manual_update_str})", group="CACHE_MANAGEMENT")
            cve_file_path = _resolve_cve_cache_file_path(targetCve, local_repo_path)
            if cve_file_path:
                _refresh_cvelist_from_mitre_api(targetCve, cve_file_path, "NVD newer than last_manual_update")
        
        else:
            # Fallback path: per-CVE JSONPath comparison — load V5 file and compare per-record dates
            cvelist_field_path = refresh_strategy.get('field_path', '$.cveMetadata.dateUpdated')
            cve_file_path = _resolve_cve_cache_file_path(targetCve, local_repo_path)
            if not cve_file_path or not cve_file_path.exists():
                logger.debug(f"No local CVE file exists for sync check: {targetCve}", group="CACHE_MANAGEMENT")
                return
                
            local_data = _load_cve_from_local_file(cve_file_path)
            if not local_data:
                logger.debug(f"Could not load local CVE data for sync check: {targetCve}", group="CACHE_MANAGEMENT")
                return
            
            cvelist_dates = _extract_field_value(local_data, cvelist_field_path)
            
            if not cvelist_dates:
                logger.debug(f"No CVE List V5 date found for {targetCve} using path {cvelist_field_path}", group="DATASET")
                return
                
            cvelist_date_updated = cvelist_dates[0]  # Should be single match
            if 'Z' in cvelist_date_updated:
                cvelist_datetime_str = cvelist_date_updated.replace('Z', '+00:00')
            elif '+' not in cvelist_date_updated and cvelist_date_updated.count(':') >= 2:
                cvelist_datetime_str = cvelist_date_updated + '+00:00'
            else:
                cvelist_datetime_str = cvelist_date_updated
            cvelist_datetime = datetime.fromisoformat(cvelist_datetime_str)
            
            if nvd_datetime > cvelist_datetime:
                logger.info(f"NVD 2.0 API record newer than CVE List V5 cached record - refreshing CVE List V5 cached record for {targetCve} (NVD 2.0 API Record: {nvd_last_modified}, CVE List V5 Cached Record: {cvelist_date_updated})", group="CACHE_MANAGEMENT")
                _refresh_cvelist_from_mitre_api(targetCve, cve_file_path, "NVD newer than cache")
            else:
                logger.debug(f"CVE List V5 cached record current for {targetCve} (NVD 2.0 API Record: {nvd_last_modified}, CVE List V5 Cached Record: {cvelist_date_updated})", group="CACHE_MANAGEMENT")
    
    except Exception as e:
        logger.warning(f"CVE List V5 sync check failed for {targetCve}: {e}", group="CACHE_MANAGEMENT")   
    except Exception as e:
        logger.warning(f"CVE List V5 sync check failed for {targetCve}: {e}", group="CACHE_MANAGEMENT")

def _refresh_cvelist_from_mitre_api(targetCve, local_file_path, refresh_reason="staleness detected", cve_schema=None, update_metadata=True):
    """
    Refresh CVE List V5 local file by fetching fresh data from MITRE CVE API.
    
    Args:
        targetCve: CVE ID to refresh (e.g., "CVE-1337-12345")
        local_file_path: Path object pointing to the local CVE file to update
        refresh_reason: Reason for refresh (default: "staleness detected")
        cve_schema: Optional pre-loaded CVE List V5 schema for validation (to avoid repeated loads)
        update_metadata: Whether to update cache metadata after individual save (default True, set False for batch operations)
    """
    try:
        # Load cache config once for this operation
        cve_config = _get_cached_config('cve_list_v5')
        cve_repo_path = cve_config.get('path', 'cache/cve_list_v5')
        
        # Set the API Endpoint target for direct MITRE API call
        cveOrgJSON = config['api']['endpoints']['cve_list']
        simpleCveRequestUrl = cveOrgJSON + targetCve
        
        # Determine status for logging
        is_new = not local_file_path.exists()
        
        # Make direct API call (bypass local loading)
        r = requests.get(simpleCveRequestUrl, timeout=config['api']['timeouts']['cve_org'])
        fresh_cve_data = validate_http_response(r, f"MITRE CVE API refresh: {targetCve}")

        # Validate with schema if provided
        try:
            from .schema_validator import validate_cve_record_v5
            # Load schema only if not provided (batch operations should pre-load)
            if cve_schema is None:
                cve_schema = load_schema('cve_cve_5_2')
            validated_data = validate_cve_record_v5(fresh_cve_data, targetCve, cve_schema)
            fresh_cve_data = validated_data
        except Exception as validation_error:
            logger.warning(f"CVE List V5 validation failed for {targetCve}: {validation_error} - Caching without validation", group="CACHE_MANAGEMENT")
        
        # Basic integrity checks (keep as fallback)
        processData.integrityCheckCVE("cveIdMatch", targetCve, fresh_cve_data)
        
        # Ensure directory structure exists
        local_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write fresh data to local file
        with open(local_file_path, 'w', encoding='utf-8') as f:
            json.dump(fresh_cve_data, f, indent=2)
        
        # Single-line status logging (similar to NVD cache updates)
        status = "ADDED" if is_new else "UPDATED"
        logger.info(f"CVE 5.x  {targetCve:<20} {status}", group="CACHE_MANAGEMENT")
        
        # Update cache metadata (skip for batch operations - will update once at end)
        if update_metadata:
            _update_cache_metadata('cve_list_v5', cve_repo_path)
        
    except requests.exceptions.RequestException as e:
        logger.info(f"CVE 5.x  {targetCve:<20} ERROR (API error)", group="CACHE_MANAGEMENT")
        logger.error(f"MITRE API refresh failed for {targetCve}: {e}", group="CACHE_MANAGEMENT")
    except (IOError, OSError) as e:
        logger.info(f"CVE 5.x  {targetCve:<20} ERROR (file write)", group="CACHE_MANAGEMENT")
        logger.error(f"File write failed during CVE refresh for {targetCve}: {e}", group="CACHE_MANAGEMENT")
    except Exception as e:
        logger.info(f"CVE 5.x  {targetCve:<20} ERROR", group="CACHE_MANAGEMENT")
        logger.error(f"Unexpected error during CVE refresh for {targetCve}: {e}", group="CACHE_MANAGEMENT")



def _load_nvd_cve_from_local_file(nvd_cve_file_path):
    """
    Load NVD CVE record from local JSON file.
    Returns NVD CVE data dict or None if file doesn't exist or is invalid.
    """
    try:
        if not nvd_cve_file_path.exists():
            return None
            
        with open(nvd_cve_file_path, 'r', encoding='utf-8') as f:
            nvd_data = json.load(f)
            
        # Validate basic NVD CVE structure
        if 'vulnerabilities' in nvd_data and len(nvd_data['vulnerabilities']) > 0:
            return nvd_data
        else:
            logger.warning(f"Invalid NVD CVE structure in local file: {nvd_cve_file_path}", group="cve_queries")
            return None
            
    except (json.JSONDecodeError, IOError, UnicodeDecodeError) as e:
        logger.warning(f"Cannot read local NVD CVE file {nvd_cve_file_path}: {e}", group="cve_queries")
        return None

def _save_nvd_cve_to_local_file(targetCve, nvd_data, cve_schema=None, update_metadata=True):
    """
    Save NVD CVE data to local cache file using same directory structure as CVE List V5.
    
    Performs timestamp comparison to avoid unnecessary writes and validation when cached data is current.
    
    Args:
        targetCve: CVE ID to save (e.g., "CVE-2024-12345")
        nvd_data: NVD API response data to save
        cve_schema: Optional pre-loaded NVD CVE schema for validation (to avoid repeated loads)
        update_metadata: Whether to update cache metadata after individual save (default True, set False for batch operations)
    
    Returns:
        str: Status of operation - "up-to-date" (no write needed), "cached" (new file created),
             "updated" (existing file overwritten), or "failed"
    """
    try:
        nvd_config = _get_cached_config('nvd_2_0_cve')
        
        # Use 'cache/nvd_2.0_cves' as default path (parallel to cve_list_v5)
        nvd_repo_path = nvd_config.get('path', 'cache/nvd_2.0_cves')
        
        nvd_file_path = _resolve_cve_cache_file_path(targetCve, nvd_repo_path)
        if not nvd_file_path:
            logger.warning(f"Could not resolve NVD file path for {targetCve}", group="CACHE_MANAGEMENT")
            return "failed"
        
        # Track whether this is a new cache entry or an update
        file_existed = nvd_file_path.exists()
        
        # Check if cached file already exists and compare lastModified timestamps
        if file_existed:
            try:
                # Load existing cached data
                with open(nvd_file_path, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                
                # Extract lastModified from both cached and new API data
                nvd_field_path = nvd_config.get('refresh_strategy', {}).get('field_path', '$.vulnerabilities.*.cve.lastModified')
                
                cached_dates = _extract_field_value(cached_data, nvd_field_path)
                api_dates = _extract_field_value(nvd_data, nvd_field_path)
                
                if cached_dates and api_dates:
                    cached_last_modified = max(cached_dates)
                    api_last_modified = max(api_dates)
                    
                    # Normalize datetime strings for comparison
                    def normalize_datetime(dt_str):
                        if 'Z' in dt_str:
                            dt_str = dt_str.replace('Z', '+00:00')
                        elif '+' not in dt_str and dt_str.count(':') >= 2:
                            dt_str = dt_str + '+00:00'
                        return datetime.fromisoformat(dt_str)
                    
                    cached_dt = normalize_datetime(cached_last_modified)
                    api_dt = normalize_datetime(api_last_modified)
                    
                    # Skip update if cached version is already current
                    if cached_dt >= api_dt:
                        return "up-to-date"  # Cached data is current, no write needed
                        
            except Exception as comparison_error:
                # If timestamp comparison fails, proceed with update to be safe
                logger.debug(f"Timestamp comparison failed for {targetCve}: {comparison_error} - proceeding with update", group="CACHE_MANAGEMENT")
        
        # Validate NVD CVE data before caching
        try:
            from .schema_validator import validate_cve_data
            # Load schema only if not provided (batch operations should pre-load)
            if cve_schema is None:
                cve_schema = load_schema('nvd_cves_2_0')
            validated_data = validate_cve_data(nvd_data, targetCve, cve_schema)
            nvd_data = validated_data
        except Exception as validation_error:
            logger.warning(f"NVD CVE validation failed for {targetCve}: {validation_error} - Caching without validation", group="CACHE_MANAGEMENT")
            
        # Ensure directory structure exists
        nvd_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write NVD data to local file
        with open(nvd_file_path, 'w', encoding='utf-8') as f:
            json.dump(nvd_data, f, indent=2)
        
        # Update cache metadata (skip for batch operations - will update once at end)
        if update_metadata:
            _update_cache_metadata('nvd_2_0_cve', nvd_repo_path)
        
        # Return appropriate status based on whether file existed
        return "updated" if file_existed else "cached"
        
    except (IOError, OSError) as e:
        logger.warning(f"Failed to save NVD CVE data for {targetCve}: {e}", group="CACHE_MANAGEMENT")
        return "failed"
    except Exception as e:
        logger.warning(f"Unexpected error saving NVD CVE data for {targetCve}: {e}", group="CACHE_MANAGEMENT")
        return "failed"



def gatherCVEListRecord(targetCve):
    """
    Load a CVE List V5 record from the local cache, then fall back to the MITRE API on a
    cache miss. Cache-only path: no staleness checks are performed here; freshness is managed
    upstream by _save_cve_list_v5_to_cache_during_bulk_generation during dataset generation.
    """
    cve_config = _get_cached_config('cve_list_v5')
    cache_path = cve_config.get('path', 'cache/cve_list_v5')
    
    logger.info(f"CVE cache strategy for {targetCve}: path={cache_path}", group="CACHE_MANAGEMENT")
    
    # Always attempt local load first
    local_repo_path = cache_path
    cve_file_path = _resolve_cve_cache_file_path(targetCve, local_repo_path)
    if cve_file_path:
        logger.debug(f"Cache file path resolved: {cve_file_path}", group="CACHE_MANAGEMENT")
        if cve_file_path.exists():
            local_data = _load_cve_from_local_file(cve_file_path)
            if local_data:
                logger.info(f"Cache hit: {targetCve} loaded from {cve_file_path}", group="CACHE_MANAGEMENT")
                return local_data
        # Cache miss — proceed to API fetch
        logger.info(f"Cache miss (file missing): {targetCve} not found at {cve_file_path}", group="CACHE_MANAGEMENT")
    
    # Cache miss or staleness-triggered refresh — fetch from MITRE API
    logger.info(f"Fetching {targetCve} from MITRE API", group="CACHE_MANAGEMENT")
    
    # Direct API fetch
    cveOrgJSON = config['api']['endpoints']['cve_list']
    simpleCveRequestUrl = cveOrgJSON + targetCve
    
    logger.api_call("MITRE CVE API", {"cve_id": targetCve}, group="cve_queries")
    
    try:
        r = requests.get(simpleCveRequestUrl, timeout=config['api']['timeouts']['cve_org'])
        cveRecordDict = validate_http_response(r, f"MITRE CVE API: {targetCve}")

        processData.integrityCheckCVE("cveIdMatch", targetCve, cveRecordDict)
        
        logger.api_response("MITRE CVE API", "Success", group="cve_queries")
        
        # Always persist API response to local cache
        cve_config = _get_cached_config('cve_list_v5')
        try:
            # Validate before caching
            try:
                from .schema_validator import validate_cve_record_v5
                cve_schema = load_schema('cve_cve_5_2')
                validated_data = validate_cve_record_v5(cveRecordDict, targetCve, cve_schema)
                cveRecordDict = validated_data
            except Exception as validation_error:
                logger.warning(f"CVE List V5 validation failed for {targetCve}: {validation_error} - Caching without validation", group="CACHE_MANAGEMENT")
            
            local_repo_path = cve_config.get('path', 'cache/cve_list_v5')
            cve_file_path = _resolve_cve_cache_file_path(targetCve, local_repo_path)
            if cve_file_path:
                # Ensure directory exists
                os.makedirs(os.path.dirname(cve_file_path), exist_ok=True)
                
                # Save to cache
                with open(cve_file_path, 'w') as f:
                    json.dump(cveRecordDict, f, indent=2)
                
                logger.debug(f"API response persisted to cache: {targetCve} at {cve_file_path}", group="CACHE_MANAGEMENT")
                
        except Exception as e:
            logger.warning(f"Failed to save CVE {targetCve} to cache: {e}", group="cve_queries")
        
        return cveRecordDict
    except requests.exceptions.RequestException as e:
        public_ip = get_public_ip()
        logger.error(f"MITRE CVE API request failed: Unable to fetch CVE record for {targetCve} - {e}", group="cve_queries")
        logger.debug(f"Current public IP address: {public_ip}", group="cve_queries")
        
        # Record failed API call in unified dashboard tracking
        try:
            from ..reporting.dataset_contents_collector import record_api_call_unified
            record_api_call_unified("MITRE CVE API", success=False)
        except ImportError:
            pass  # Fallback for testing environments
        
        return None

def gatherCVEListRecordLocal(targetCve):
    """
    Load CVE record from local cache, escalating to full gatherCVEListRecord orchestration
    on cache miss. Does not perform a staleness check — use gatherCVEListRecord directly
    when staleness-driven refresh is required.
    
    Args:
        targetCve: CVE ID to load (e.g., "CVE-2024-12345")
        
    Returns:
        CVE record dict or None if loading fails
    """
    cve_config = _get_cached_config('cve_list_v5')
    local_repo_path = cve_config.get('path', 'cache/cve_list_v5')
    
    cve_file_path = _resolve_cve_cache_file_path(targetCve, local_repo_path)
    if cve_file_path:
        local_data = _load_cve_from_local_file(cve_file_path)
        if local_data:
            logger.info(f"CVE record loaded from local cache: {targetCve}", group="DATASET")
            return local_data
    
    # Cache miss — escalate to full orchestration
    logger.info(f"Cache miss for {targetCve} - escalating to full orchestration", group="CACHE_MANAGEMENT")
    return gatherCVEListRecord(targetCve)

def gatherNVDCVERecord(targetCve):
    """
    Load NVD CVE record from local cache for use in CVE List V5 staleness checks.
    Cache miss is an error — it indicates bulk dataset generation was not run or
    the NVD cache was partially cleared. Downstream NVD-ish record generation will
    also fail for the same CVE, so the root cause is surfaced here as an error.
    """
    nvd_config = _get_cached_config('nvd_2_0_cve')
    nvd_repo_path = nvd_config.get('path', 'cache/nvd_2.0_cves')

    nvd_file_path = _resolve_cve_cache_file_path(targetCve, nvd_repo_path)
    if nvd_file_path:
        local_nvd_data = _load_nvd_cve_from_local_file(nvd_file_path)
        if local_nvd_data:
            logger.debug(f"NVD CVE record loaded from cache: {targetCve}", group="cve_queries")
            return local_nvd_data

    logger.error(
        f"NVD CVE cache miss for {targetCve} — staleness check skipped. "
        f"Run bulk dataset generation to populate the NVD cache.",
        group="cve_queries"
    )
    return None

def _query_nvd_page(url, headers, context_msg, log_group):
    """Shared retry logic for all NVD API single-page queries."""
    max_retries = config['api']['retry']['max_attempts_nvd']

    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, timeout=config['api']['timeouts']['nvd_api'])
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            public_ip = get_public_ip()
            logger.error(f"{context_msg} request failed (Attempt {attempt + 1}/{max_retries}): {e}", group=log_group)
            logger.debug(f"Current public IP address: {public_ip}", group=log_group)

            if hasattr(e, 'response') and e.response is not None:
                if 'message' in e.response.headers:
                    logger.error(f"NVD API Message: {e.response.headers['message']}", group=log_group)
                if hasattr(e.response, 'status_code'):
                    logger.error(f"Response status code: {e.response.status_code}", group=log_group)

            if attempt < max_retries - 1:
                has_api_key = 'apiKey' in headers
                wait_time = config['api']['retry']['delay_with_key'] if has_api_key else config['api']['retry']['delay_without_key']
                logger.info(f"Waiting {wait_time} seconds before retry...", group=log_group)
                sleep(wait_time)
            else:
                logger.error(f"{context_msg} request failed: Maximum retry attempts ({max_retries}) reached", group=log_group)
                return None

    return None


def query_nvd_cve_page(url, headers, context_msg="NVD CVE API"):
    """
    Query NVD CVE API endpoint with retry logic.
    Centralizes all NVD CVE API requests to ensure consistent error handling and retry behavior.

    Args:
        url: Complete NVD CVE API URL with query parameters
        headers: HTTP headers including API key if available
        context_msg: Context message for logging (default: "NVD CVE API")

    Returns:
        dict: API response data, or None if all retries failed
    """
    return _query_nvd_page(url, headers, context_msg, log_group="cve_queries")


def query_nvd_cves_concurrent(
    base_url: str, 
    headers: dict,
    total_results: int,
    results_per_page: int = 2000,
    max_workers: int = 15,
    rate_limiter: Optional[NVDConcurrentCVERateLimiter] = None,
    context_msg: str = "NVD CVE API",
    start_offset: int = 0
) -> List[dict]:
    """
    Fetch NVD CVE pages concurrently using ThreadPoolExecutor.
    
    Makes multiple API requests in parallel while respecting rate limits.
    
    Args:
        base_url: Base URL with query parameters (without startIndex)
        headers: HTTP headers including API key
        total_results: Total number of results to fetch
        results_per_page: Results per page (default: 2000, NVD max)
        max_workers: Maximum concurrent requests (default: 15)
        rate_limiter: NVDConcurrentCVERateLimiter instance (optional, created if not provided)
        context_msg: Context for logging
        start_offset: Starting offset for pagination (default: 0, used when first page already fetched)
    
    Returns:
        List of all vulnerability records
    """
    if rate_limiter is None:
        # Default to 50 req/30s if API key present, 5 req/30s otherwise
        max_requests = 50 if 'apiKey' in headers else 5
        rate_limiter = NVDConcurrentCVERateLimiter(max_requests=max_requests, window_seconds=30)
    
    # Calculate all page offsets starting from start_offset
    page_offsets = list(range(start_offset, start_offset + total_results, results_per_page))
    total_pages = len(page_offsets)
    
    logger.info(f"Fetching {total_results:,} CVEs across {total_pages} pages with {max_workers} concurrent workers", group="cve_queries")
    
    all_vulnerabilities = []
    completed_pages = 0
    failed_pages = []
    
    def fetch_page(start_index: int) -> Tuple[int, Optional[dict]]:
        """Fetch a single page (thread worker function)"""
        # Acquire rate limit permission (blocks if needed)
        rate_limiter.acquire(blocking=True)
        
        # Build URL with pagination
        separator = '&' if '?' in base_url else '?'
        url = f"{base_url}{separator}startIndex={start_index}"
        
        # Query API
        data = query_nvd_cve_page(url, headers, context_msg=context_msg)
        return start_index, data
    
    # Fetch pages concurrently
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all page requests
        future_to_offset = {executor.submit(fetch_page, offset): offset for offset in page_offsets}
        
        # Collect results as they complete
        for future in as_completed(future_to_offset):
            start_index, data = future.result()
            
            if data:
                vulnerabilities = data.get("vulnerabilities", [])
                all_vulnerabilities.extend(vulnerabilities)
                completed_pages += 1
                
                # Log progress
                current, max_req = rate_limiter.get_current_usage()
                logger.info(
                    f"Page {completed_pages}/{total_pages} complete "
                    f"(offset {start_index}, {len(vulnerabilities)} CVEs, "
                    f"rate: {current}/{max_req} req/30s)",
                    group="cve_queries"
                )
            else:
                failed_pages.append(start_index)
                logger.error(f"Failed to fetch page at offset {start_index}", group="cve_queries")
    
    # Fail fast if any pages failed (evidence-based error reporting)
    if failed_pages:
        error_msg = f"Concurrent fetch failed: {len(failed_pages)}/{total_pages} pages failed at offsets {failed_pages[:5]}{'...' if len(failed_pages) > 5 else ''}"
        logger.error(error_msg, group="cve_queries")
        raise RuntimeError(error_msg)
    
    logger.info(f"Concurrent fetch complete: {len(all_vulnerabilities):,} CVE records retrieved", group="cve_queries")
    return all_vulnerabilities


def query_nvd_cves_by_modified_date_concurrent(
    start_date: datetime, 
    end_date: datetime, 
    api_key: Optional[str] = None,
    max_workers: int = 15
) -> List[dict]:
    """
    Query NVD CVE API for CVEs modified within a date range using concurrent requests.
    
    Significantly faster than sequential pagination for large result sets.
    Makes multiple API requests in parallel while respecting rate limits.
    
    Args:
        start_date: Start of date range (timezone-aware datetime)
        end_date: End of date range (timezone-aware datetime)
        api_key: NVD API key (optional, recommended for 50 req/30s limit)
        max_workers: Maximum concurrent requests (default: 15)
    
    Returns:
        List of vulnerability records
    """
    base_url = config['api']['endpoints']['nvd_cves']
    results_per_page = 2000  # NVD API maximum
    
    # Format dates for NVD API
    start_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.999')
    
    headers = build_nvd_api_headers(api_key)
    
    # Create rate limiter
    max_requests = 50 if api_key else 5
    rate_limiter = NVDConcurrentCVERateLimiter(max_requests=max_requests, window_seconds=30)
    
    # First, fetch page 0 to get total results
    logger.info(f"Querying NVD for CVEs modified between {start_date.strftime('%Y-%m-%d')} and {end_date.strftime('%Y-%m-%d')}", group="cve_queries")
    
    rate_limiter.acquire(blocking=True)
    initial_url = f"{base_url}?lastModStartDate={start_str}&lastModEndDate={end_str}&startIndex=0"
    initial_data = query_nvd_cve_page(initial_url, headers, context_msg="NVD CVE API (modified date query)")
    
    if not initial_data:
        logger.error("Initial API query failed", group="cve_queries")
        return []
    
    total_results = initial_data.get("totalResults", 0)
    logger.info(f"NVD reports {total_results:,} CVEs in date range", group="cve_queries")
    
    if total_results == 0:
        return []
    
    # Collect first page
    all_vulnerabilities = initial_data.get("vulnerabilities", [])
    
    # If more pages needed, fetch concurrently
    if total_results > results_per_page:
        # Build base URL for remaining pages
        base_url_with_params = f"{base_url}?lastModStartDate={start_str}&lastModEndDate={end_str}"
        
        # Calculate remaining total (subtract first page already fetched)
        remaining_results = total_results - results_per_page
        
        # Fetch remaining pages concurrently (starting from offset results_per_page)
        remaining_vulnerabilities = query_nvd_cves_concurrent(
            base_url=base_url_with_params,
            headers=headers,
            total_results=remaining_results,
            results_per_page=results_per_page,
            max_workers=max_workers,
            rate_limiter=rate_limiter,
            context_msg="NVD CVE API (modified date query)",
            start_offset=results_per_page
        )
        all_vulnerabilities.extend(remaining_vulnerabilities)
    
    logger.info(f"Date range query complete: {len(all_vulnerabilities):,} CVE records retrieved", group="cve_queries")
    return all_vulnerabilities


def query_nvd_cves_all_concurrent(api_key: Optional[str] = None, max_workers: int = 15) -> List[dict]:
    """
    Query NVD CVE API for ALL CVEs using concurrent requests.
    
    Fetches the entire NVD CVE database using parallel pagination.
    Significantly faster than sequential approach for full database queries.
    
    Args:
        api_key: NVD API key (recommended for 50 req/30s limit vs 5 req/30s)
        max_workers: Maximum concurrent requests (default: 15)
    
    Returns:
        List of all vulnerability records
    """
    base_url = config['api']['endpoints']['nvd_cves']
    results_per_page = 2000  # NVD API maximum
    headers = build_nvd_api_headers(api_key)
    
    # Create rate limiter
    max_requests = 50 if api_key else 5
    rate_limiter = NVDConcurrentCVERateLimiter(max_requests=max_requests, window_seconds=30)
    
    # First, fetch page 0 to get total results
    logger.info("Querying NVD for ALL CVEs (full database)", group="cve_queries")
    logger.warning("This is a FULL DATABASE QUERY - will take several minutes", group="cve_queries")
    
    rate_limiter.acquire(blocking=True)
    initial_url = f"{base_url}?startIndex=0"
    initial_data = query_nvd_cve_page(initial_url, headers, context_msg="NVD CVE API (full database)")
    
    if not initial_data:
        logger.error("Initial API query failed", group="cve_queries")
        return []
    
    total_results = initial_data.get("totalResults", 0)
    logger.info(f"NVD reports {total_results:,} total CVEs in database", group="cve_queries")
    
    if total_results == 0:
        return []
    
    # Estimate time with parallel fetching
    estimated_pages = (total_results + results_per_page - 1) // results_per_page
    # With parallel fetching and rate limiting, estimate based on batches
    batches = (estimated_pages + max_workers - 1) // max_workers
    estimated_seconds = (batches * max_requests / (max_requests / 30))  # Rough estimate
    logger.info(f"Estimated completion: {estimated_seconds/60:.1f} minutes with {max_workers} workers ({estimated_pages} pages)", group="cve_queries")
    
    # Collect first page
    all_vulnerabilities = initial_data.get("vulnerabilities", [])
    
    # If more pages needed, fetch concurrently
    if total_results > results_per_page:
        # Calculate remaining total (subtract first page)
        remaining_results = total_results - results_per_page
        
        # Fetch remaining pages concurrently (starting from offset results_per_page)
        remaining_vulnerabilities = query_nvd_cves_concurrent(
            base_url=base_url,
            headers=headers,
            total_results=remaining_results,
            results_per_page=results_per_page,
            max_workers=max_workers,
            rate_limiter=rate_limiter,
            context_msg="NVD CVE API (full database)",
            start_offset=results_per_page
        )
        all_vulnerabilities.extend(remaining_vulnerabilities)
    
    logger.info(f"Full database query complete: {len(all_vulnerabilities):,} CVE records retrieved", group="cve_queries")
    return all_vulnerabilities


def query_nvd_cpematch_by_modified_date(start_date: datetime, end_date: datetime, api_key: Optional[str] = None) -> List[str]:
    """
    Query NVD CPE Match API for CPE match strings modified within a date range.
    
    Used for CPE cache refresh operations to identify which CPE base strings need
    updating. Automatically paginates through all results (500 per page max).
    
    Filters out match criteria with empty 'matches' arrays (CPEs not in dictionary).
    
    Args:
        start_date: Start of date range (timezone-aware datetime)
        end_date: End of date range (timezone-aware datetime)
        api_key: NVD API key (optional, recommended for better rate limits)
    
    Returns:
        List of CPE match criteria strings (filtered to only those with CPE dictionary entries)
    
    Example:
        from datetime import datetime, timezone, timedelta
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        matches = query_nvd_cpematch_by_modified_date(start, end, api_key="your-key")
    """
    base_url = config['api']['endpoints']['nvd_cpematch']
    
    # Format dates for NVD API (ISO 8601 with timezone)
    start_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000+00:00')
    end_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000+00:00')
    
    headers = build_nvd_api_headers(api_key)
    if api_key:
        logger.debug("Using API key for NVD CPE Match batch query", group="cpe_queries")
    
    all_match_strings = []
    start_index = 0
    total_results = None
    results_per_page = 500  # NVD cpematch API max per page
    
    logger.info(f"Querying NVD CPE Match API for changes {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}", group="cpe_queries")
    
    while total_results is None or start_index < total_results:
        # Build query URL with lastModStartDate/lastModEndDate parameters
        params = {
            'lastModStartDate': start_str,
            'lastModEndDate': end_str,
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }
        url = f"{base_url}?{urlencode(params)}"
        
        logger.debug(f"Fetching page: startIndex={start_index}, totalResults={total_results or '?'}", group="cpe_queries")
        
        # Query API with centralized retry logic
        data = query_nvd_cpematch_page(url, headers, context_msg=f"NVD CPE Match API (startIndex={start_index})")
        
        if not data:
            logger.error(f"API query failed at startIndex {start_index} - aborting", group="cpe_queries")
            break
        
        # Extract total on first page
        if total_results is None:
            total_results = data.get("totalResults", 0)
            logger.info(f"NVD reports {total_results:,} CPE matches modified in date range", group="cpe_queries")
            
            if total_results == 0:
                logger.info("No CPE match strings found in specified date range", group="cpe_queries")
                break
        
        # Extract CPE match strings that have actual CPE dictionary entries
        matches = data.get('matchStrings', [])
        for match_obj in matches:
            match_string_data = match_obj.get('matchString', {})
            
            # Check if this match has actual CPE dictionary entries
            cpe_matches = match_string_data.get('matches', [])
            if not cpe_matches:
                # Skip - this criteria doesn't have any CPE dictionary entries
                continue
            
            # Extract the 'criteria' field which contains the actual CPE string
            cpe_match_string = match_string_data.get('criteria')
            if cpe_match_string:
                all_match_strings.append(cpe_match_string)
        
        logger.debug(f"Collected {len(matches)} match strings (running total: {len(all_match_strings)}/{total_results})", group="cpe_queries")
        
        # Move to next page
        start_index += results_per_page
        
        # Rate limiting between pages (use page-specific delays from config)
        if start_index < total_results:
            delay = config['api']['retry']['page_delay_with_key'] if api_key else config['api']['retry']['page_delay_without_key']
            if delay > 0:
                sleep(delay)
    
    logger.info(f"Batch query complete: {len(all_match_strings):,} CPE match criteria retrieved", group="cpe_queries")
    return all_match_strings


def query_nvd_cpematch_page(url, headers, context_msg="NVD CPE Match API"):
    """
    Query NVD CPE Match API endpoint with retry logic.
    Centralizes all NVD CPE Match API requests for cache refresh operations.

    Args:
        url: Complete NVD CPE Match API URL with query parameters
        headers: HTTP headers including API key if available
        context_msg: Context message for logging (default: "NVD CPE Match API")

    Returns:
        dict: API response data, or None if all retries failed
    """
    return _query_nvd_page(url, headers, context_msg, log_group="cpe_queries")

def gatherNVDSourceData(apiKey):
    def fetch_nvd_data():
        url = config['api']['endpoints']['nvd_sources']
        headers = build_nvd_api_headers(apiKey)
       
        max_retries = config['api']['retry']['max_attempts_nvd']
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers, timeout=config['api']['timeouts']['nvd_api'])
                return validate_http_response(response, "NVD Source API")
            except requests.exceptions.RequestException as e:                
                public_ip = get_public_ip()
                logger.error(f"NVD Sources API request failed: Unable to fetch source entries (Attempt {attempt + 1}/{max_retries}) - {e}", group="cve_queries")
                logger.debug(f"Current public IP address: {public_ip}", group="cve_queries")
                
                if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                    logger.error(f"NVD API Message: {e.response.headers['message']}", group="cve_queries")                
                if attempt < max_retries - 1:
                    wait_time = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                    logger.warning(f"Waiting {wait_time} seconds before retry...", group="cve_queries")
                    sleep(wait_time)
                else:
                    logger.error(f"NVD Sources API request failed: Maximum retry attempts ({max_retries}) reached", group="cve_queries")
                    return None
    
    def create_dataframe():
        data = fetch_nvd_data()
       
        if not data or 'sources' not in data:
            return None
       
        # Create DataFrame directly from the sources list
        df = pd.DataFrame(data['sources'])
       
        return df
   
    return create_dataframe()

def gatherNVDCPEData(apiKey, case, query_string):
    match case:
        case 'cpeMatchString':
            nvd_cpes_url = config['api']['endpoints']['nvd_cpes']
            headers = build_nvd_api_headers(apiKey)
           
            max_retries = config['api']['retry']['max_attempts_cpe']
            if max_retries == 0:
                logger.warning(f"NVD CPE API calls disabled (max_attempts_cpe=0): skipping query for {query_string}", group="cpe_queries")
                return None
            for attempt in range(max_retries):
                try:
                    # Initial request to get total results
                    initial_params = {
                        "cpeMatchString": query_string,
                        "startIndex": 0
                    }
                   
                    # Log the API call before making the request
                    logger.api_call("NVD CPE API", {"cpe_match_string": query_string, "start_index": 0}, group="cpe_queries")
                   
                    response = requests.get(nvd_cpes_url, params=initial_params, headers=headers, timeout=config['api']['timeouts']['nvd_api'])
                    initial_data = validate_http_response(response, f"NVD CPE API: {query_string}")
                   
                    total_results = initial_data.get("totalResults", 0)
                    results_per_page = initial_data.get("resultsPerPage", 0)
                   
                    # Log the API response with result count
                    logger.api_response("NVD CPE API", "Success", count=total_results, group="cpe_queries")
                   
                    # If we already have all results, return initial response
                    if total_results <= results_per_page:
                        logger.debug(f"Single page CPE query completed: {total_results} results for {query_string}", group="cpe_queries")
                        return initial_data
                   
                    # Initialize consolidated results with first batch
                    consolidated_data = initial_data.copy()
                    consolidated_data["products"] = initial_data.get("products", []).copy()
                     # Calculate number of additional requests needed
                    remaining_results = total_results - results_per_page
                    current_index = results_per_page                    
                    logger.info(f"Processing CPE collections: Found {total_results} total results - Collecting all pages...", group="cpe_queries")
                   
                    # Collect remaining pages
                    additional_api_calls = 0
                    while remaining_results > 0:
                        for page_attempt in range(max_retries):
                            try:                                # Add delay to respect rate limits
                                if not headers.get("apiKey"):
                                    sleep(config['api']['retry']['page_delay_without_key'])  # Conservative approach without API key
                                else:
                                    sleep(config['api']['retry']['page_delay_with_key'])  # More aggressive with API key
                               
                                params = {
                                    "cpeMatchString": query_string,
                                    "startIndex": current_index
                                }
                               
                                # Log the paginated API call
                                logger.api_call("NVD CPE API", {"cpe_match_string": query_string, "start_index": current_index}, group="cpe_queries")
                                additional_api_calls += 1
                               
                                response = requests.get(nvd_cpes_url, params=params, headers=headers, timeout=config['api']['timeouts']['nvd_api'])
                                page_number = (current_index // results_per_page) + 1
                                page_data = validate_http_response(response, f"NVD CPE API page {page_number}: {query_string}")
                               
                                # Log the paginated API response
                                page_results = len(page_data.get("products", []))
                                logger.api_response("NVD CPE API", "Success", count=page_results, group="cpe_queries")
                               
                                # Add products from this page to consolidated results
                                if "products" in page_data:
                                    consolidated_data["products"].extend(page_data["products"])
                                 
                                # Update counters
                                results_this_page = len(page_data.get("products", []))
                                remaining_results -= results_this_page
                                current_index += results_per_page
                                 
                                logger.debug(f"Collected {len(consolidated_data['products'])} of {total_results} CPE names...", group="cpe_queries")
                                break
                            except requests.exceptions.RequestException as e:
                                public_ip = get_public_ip()
                                logger.error(f"NVD CPE API paginated request failed: Unable to fetch page data for '{query_string}' (Attempt {page_attempt + 1}/{max_retries}) - {e}", group="cve_queries")
                                logger.debug(f"Current public IP address: {public_ip}", group="cpe_queries")
                                
                                # Log the failed API response
                                logger.api_response("NVD CPE API", "Failed", group="cpe_queries")
                                
                                # Record failed paginated API call in unified dashboard tracking
                                try:
                                    from ..reporting.dataset_contents_collector import record_api_call_unified
                                    record_api_call_unified("NVD CPE API", success=False)
                                except ImportError:
                                    pass  # Fallback for testing environments
                                
                                # Check for message header and display if present - error response
                                if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                                    error_message = e.response.headers['message']
                                    logger.error(f"NVD API Message: {error_message}", group="cve_queries")
                                    
                                    # Don't retry for "Invalid cpeMatchstring parameter" errors
                                    if "Invalid cpeMatchstring parameter" in error_message:
                                        # Log with actionable feedback for validation rule improvements
                                        logger.warning(
                                            f"NVD API rejected CPE string - validation rule needed:\n"
                                            f"  CPE: {query_string}\n"
                                            f"  API Error: {error_message}\n"
                                            f"  Action: Add validation check to is_nvd_api_compatible() in processData.py to catch this pattern",
                                            group="cpe_validation"
                                        )
                                        # Return what we've collected so far
                                        consolidated_data["startIndex"] = 0
                                        consolidated_data["resultsPerPage"] = len(consolidated_data["products"])
                                        consolidated_data["error"] = error_message
                                        consolidated_data["status"] = "invalid_cpe"
                                        return consolidated_data
                                
                                if page_attempt < max_retries - 1:
                                    # Same exponential backoff as initial request error retries.
                                    base_delay = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                                    wait_time = max(base_delay, 2 ** page_attempt)
                                    logger.warning(f"Waiting {wait_time} seconds before retry (backoff attempt {page_attempt + 1})...", group="cpe_queries")
                                    sleep(wait_time)
                                else:
                                    logger.error(f"NVD CPE API paginated request failed: Maximum retry attempts ({max_retries}) reached for page data", group="cve_queries")
                                    return None
                   
                    # Update final counts
                    consolidated_data["startIndex"] = 0
                    consolidated_data["resultsPerPage"] = len(consolidated_data["products"])
                   
                    # Log completion summary for multi-page requests
                    total_api_calls = 1 + additional_api_calls  # Initial call + additional pages
                    logger.info(f"Multi-page CPE query completed: {total_results} results across {total_api_calls} API calls for {query_string}", group="cpe_queries")
                   
                    return consolidated_data
                   
                except requests.exceptions.RequestException as e:
                    public_ip = get_public_ip()
                    logger.error(f"NVD CPE API request failed: Unable to fetch CPE data for '{query_string}' (Attempt {attempt + 1}/{max_retries}) - {e}", group="cve_queries")
                    logger.debug(f"Current public IP address: {public_ip}", group="cpe_queries")
                    
                    # Log the failed API response
                    logger.api_response("NVD CPE API", "Failed", group="cpe_queries")
                    
                    # Record failed API call in unified dashboard tracking
                    try:
                        from ..reporting.dataset_contents_collector import record_api_call_unified
                        record_api_call_unified("NVD CPE API", success=False)
                    except ImportError:
                        pass  # Fallback for testing environments
                    
                    # Check for message header and display if present - error response
                    if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                        error_message = e.response.headers['message']
                        logger.error(f"NVD API Message: {error_message}", group="cve_queries")
                        
                        # Don't retry for "Invalid cpeMatchstring parameter" errors
                        if "Invalid cpeMatchstring parameter" in error_message:
                            # Log with actionable feedback for validation rule improvements
                            logger.warning(
                                f"NVD API rejected CPE string - validation rule needed:\n"
                                f"  CPE: {query_string}\n"
                                f"  API Error: {error_message}\n"
                                f"  Action: Add validation check to is_nvd_api_compatible() in processData.py to catch this pattern",
                                group="cpe_validation"
                            )
                            # Return empty result structure instead of None
                            return {
                                "totalResults": 0,
                                "resultsPerPage": 0,
                                "startIndex": 0,
                                "products": [],
                                "error": error_message,
                                "status": "invalid_cpe"                            }
                    
                    if attempt < max_retries - 1:
                        # Use exponential backoff for error retries regardless of key status.
                        # delay_with_key=0 is intentional for normal paging but wrong for
                        # connection-level errors (e.g. Cloudflare TCP reset under rate limiting).
                        base_delay = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                        wait_time = max(base_delay, 2 ** attempt)
                        logger.warning(f"Waiting {wait_time} seconds before retry (backoff attempt {attempt + 1})...", group="cpe_queries")
                        sleep(wait_time)
                    else:
                        logger.error(f"NVD CPE API request failed: Maximum retry attempts ({max_retries}) reached for '{query_string}'", group="cve_queries")
                        return None
        
        case _:
            return None

def gatherPrimaryDataframe():
    data = {
        'sourceID': '',
        'sourceRole': '',
        'rawPlatformData': [],
        'rawCPEsQueryData': [],
        'sortedCPEsQueryData': [],
        'trimmedCPEsQueryData': [],
        }

    # Create DataFrame
    return pd.DataFrame(data)

def harvestSourceUUIDs(api_key=None):
    """
    Get all source UUIDs, using local cache first.
    Loads from nvd_source_data.json if present and within notify_age_hours threshold;
    falls back to NVD Sources API only on cache miss or staleness.

    Returns:
        tuple: (source_info_list, api_totals_dict)
        where source_info_list is [(source_name, source_uuid, last_modified), ...]
        and api_totals_dict contains counts for reporting
    """
    # --- Cache-first load ---
    source_data_config = config.get('cache_settings', {}).get('nvd_source_data', {})
    notify_age_hours = source_data_config.get('refresh_strategy', {}).get('notify_age_hours', 24)
    cache_filename = source_data_config.get('filename', 'nvd_source_data.json')
    project_root = get_analysis_tools_root()
    cache_file = project_root / 'cache' / cache_filename

    sources = None
    cache_source = None

    if cache_file.exists():
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cached = json.load(f)
            records = cached.get('source_data', [])
            if records and isinstance(records, list):
                created_at_str = cached.get('created_at')
                if created_at_str:
                    created_at = datetime.fromisoformat(created_at_str)
                    if created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=timezone.utc)
                    age_hours = (datetime.now(timezone.utc) - created_at).total_seconds() / 3600
                    if age_hours <= notify_age_hours:
                        sources = records
                        cache_source = f'local cache ({age_hours:.1f}h old)'
                    else:
                        logger.info(
                            f'NVD source data cache is stale ({age_hours:.1f}h old, threshold: {notify_age_hours}h) - fetching from API',
                            group='cve_queries'
                        )
                else:
                    sources = records
                    cache_source = 'local cache (age unknown)'
        except Exception as e:
            logger.warning(f'Failed to load nvd_source_data cache: {e} - fetching from API', group='cve_queries')

    if sources is None:
        try:
            logger.stage_start('Source UUID Harvesting', 'Querying NVD Sources API', group='cve_queries')
            url = config['api']['endpoints']['nvd_sources']
            headers = build_nvd_api_headers(api_key)
            response = requests.get(url, headers=headers, timeout=config['api']['timeouts']['nvd_api'])
            data = validate_http_response(response, 'NVD Source API - harvest UUIDs')
            sources = data.get('sources', [])
            cache_source = 'NVD API'
        except Exception as e:
            logger.error(f'Error fetching source data: {e}', group='cve_queries')
            return None, None
    else:
        logger.stage_start('Source UUID Harvesting', f'Loading from {cache_source}', group='cve_queries')

    try:
        source_info = []
        seen_uuids = set()
        duplicates_found = 0
        no_uuid_sources = []
        
        for source in sources:
            source_name = source.get('name', 'Unknown')
            last_modified = source.get('lastModified', '1970-01-01T00:00:00.000')
            source_identifiers = source.get('sourceIdentifiers', [])
            
            # Find UUID-format identifier (36 characters with dashes)
            uuid_identifier = None
            for identifier in source_identifiers:
                if len(identifier) == 36 and identifier.count('-') == 4:
                    uuid_identifier = identifier
                    break
            
            if uuid_identifier:
                if uuid_identifier in seen_uuids:
                    logger.debug(f"- {source_name}: {uuid_identifier} (DUPLICATE - skipping)", group="cve_queries")
                    duplicates_found += 1
                else:
                    seen_uuids.add(uuid_identifier)
                    source_info.append((source_name, uuid_identifier, last_modified))
                    logger.debug(f"- {source_name}: {uuid_identifier} (modified: {last_modified})", group="cve_queries")
            else:
                no_uuid_sources.append(source_name)
                logger.debug(f"- {source_name}: No UUID identifier found", group="cve_queries")
        
        # Report filtering results
        logger.info(f"Source Filtering Summary:", group="cve_queries")
        logger.info(f"Total sources from {cache_source}: {len(sources)}", group="cve_queries")
        logger.info(f"Sources without UUID: {len(no_uuid_sources)} (filtered out)", group="cve_queries")
        if no_uuid_sources:
            logger.debug(f"   Sources without UUID: {', '.join(no_uuid_sources)}", group="cve_queries")
        logger.info(f"Sources with UUID: {len(sources) - len(no_uuid_sources)}", group="cve_queries")
        if duplicates_found > 0:
            logger.warning(f"Duplicate UUIDs found: {duplicates_found} (filtered out)", group="cve_queries")
        logger.info(f"Unique sources available for processing: {len(source_info)}", group="cve_queries")
        
        # Sort by lastModified descending (newest first)
        source_info.sort(key=lambda x: x[2], reverse=True)
        
        logger.stage_end("Source UUID Harvesting", f"Harvested {len(source_info)} unique source UUIDs (sorted by lastModified, newest first)", group="cve_queries")
        
        api_totals = {
            'total_from_api': len(sources),
            'sources_without_uuid': len(no_uuid_sources),
            'sources_with_uuid': len(sources) - len(no_uuid_sources),
            'duplicates_found': duplicates_found,
            'unique_sources_available': len(source_info)
        }
        
        return source_info, api_totals

    except Exception as e:
        logger.error(f"Error processing source data: {e}", group="cve_queries")
        return None, None


def checkSourceCVECount(source_uuid, api_key, max_count=None, min_count=None):
    """
    Check how many CVEs a source has before processing.
    This is used by harvest scripts to filter sources by CVE count.
    
    Args:
        source_uuid (str): The source UUID to check
        api_key (str): NVD API key for authenticated requests
        max_count (int, optional): Maximum CVE count threshold (skip if exceeded)
        min_count (int, optional): Minimum CVE count threshold (skip if below)
        
    Returns:
        tuple: (count: int, should_skip: bool, skip_reason: str) - Total CVE count, whether to skip, and reason for skipping
    """
    logger.info(f"Checking CVE count for source {source_uuid}...", group="cve_queries")
    
    try:
        url = config['api']['endpoints']['nvd_cves']
        headers = build_nvd_api_headers(api_key)
        
        params = {
            "sourceIdentifier": source_uuid,
            "resultsPerPage": 1  # We only need the total count
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=config['api']['timeouts']['nvd_api'])
        data = validate_http_response(response, f"NVD CVE API - check source count: {source_uuid}")
        total_results = data.get('totalResults', 0)
        
        logger.info(f"Source has {total_results:,} CVE records", group="cve_queries")
        
        # Check max threshold
        if max_count is not None and total_results > max_count:
            logger.warning(f"SKIPPING: Source exceeds maximum threshold of {max_count:,} CVEs ({total_results:,} found)", group="cve_queries")
            return total_results, True, f"Exceeded --max-cves {max_count:,} threshold"
        
        # Check min threshold
        if min_count is not None and total_results < min_count:
            logger.warning(f"SKIPPING: Source below minimum threshold of {min_count:,} CVEs ({total_results:,} found)", group="cve_queries")
            return total_results, True, f"Below --min-cves {min_count:,} threshold"
        
        return total_results, False, None
        
    except Exception as e:
        logger.warning(f"Could not check CVE count for source {source_uuid}: {e}", group="cve_queries")
        logger.info(f"Proceeding with processing", group="cve_queries")
        return 0, False, None
