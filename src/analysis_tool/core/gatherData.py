# Import Python dependencies
import requests
import pandas as pd
import os
import json
from time import sleep
from pathlib import Path

# Import Analysis Tool 
from . import processData

# Import the new logging system
from ..logging.workflow_logger import get_logger, LogGroup

# Get logger instance
logger = get_logger()

# Load configuration
def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)

config = load_config()
VERSION = config['application']['version']
TOOLNAME = config['application']['toolname']

# CONSOLIDATED CACHE CONFIGURATION FUNCTIONS
def _get_cache_defaults(cache_type):
    """Get default configuration for cache type"""
    defaults = {
        'cve_list_v5': {
            'enabled': False,
            'path': 'cache/cve_list_v5',
            'fallback_to_api': True,
            'description': 'CVE List V5 repository with per-file tracking',
            'refresh_strategy': {
                'field_path': '$.cveMetadata.dateUpdated',
                'notify_age_hours': 168
            }
        },
        'nvd_2_0_cve': {
            'enabled': True,
            'path': 'cache/nvd_2.0_cves',
            'filename': 'nvd_2_0_cve.json',
            'description': 'NVD CVE 2.0 API responses cache with per-file tracking',
            'refresh_strategy': {
                'field_path': '$.vulnerabilities.*.cve.lastModified',
                'notify_age_hours': 24
            }
        }
    }
    return defaults.get(cache_type, {})

def _get_cache_descriptions():
    """Get standard descriptions for cache types"""
    return {
        'cve_list_v5': 'CVE List V5 local repository with per-file tracking',
        'nvd_2_0_cve': 'NVD CVE 2.0 API responses with directory organization'
    }

def _update_cache_metadata(cache_type, repo_path):
    """
    Unified cache metadata updater for all cache types.
    
    Args:
        cache_type: Type of cache ('cve_list_v5', 'nvd_2_0_cve')
        repo_path: Path to the cache directory
    """
    try:
        from datetime import datetime
        from pathlib import Path
        
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
        current_time = datetime.now()
        
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
            
        # Get description for this cache type
        descriptions = _get_cache_descriptions()
        description = descriptions.get(cache_type, f'{cache_type} cache')
            
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
            
        logger.debug(f"Updated {cache_type} cache metadata: {total_files} files", group="cache_management")
        
    except Exception as e:
        logger.warning(f"Could not update {cache_type} cache metadata: {e}", group="cache_management")

def get_cache_config(cache_type):
    """
    Unified cache configuration getter.
    
    Args:
        cache_type: Type of cache ('cve_list_v5', 'nvd_2_0_cve')
        
    Returns:
        Cache configuration dictionary with defaults
    """
    try:
        config = load_config()
        return config.get('cache_settings', {}).get(cache_type, _get_cache_defaults(cache_type))
    except Exception as e:
        logger.warning(f"Could not load {cache_type} config, using defaults: {e}", group="cache_management")
        return _get_cache_defaults(cache_type)



def get_public_ip():
    """Get the current public IP address being used by the tool."""
    try:
        response = requests.get(config['api']['endpoints']['public_ip'], 
                              timeout=config['api']['timeouts']['public_ip'])
        return response.text if response.status_code == 200 else "Unknown"
    except Exception as e:        return f"Could not retrieve IP: {str(e)}"

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
        logger.warning(f"Cannot read local CVE file {cve_file_path}: {e}", group="cve_queries")
        return None

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
    Business rule: If NVD lastModified > CVE List V5 dateUpdated, refresh from MITRE API.
    
    Args:
        targetCve: CVE ID to check for sync (e.g., "CVE-2024-12345")
    """
    try:
        from datetime import datetime
        
        # Get NVD data for date comparison
        nvd_data = gatherNVDCVERecord(config.get('api', {}).get('keys', {}).get('nvd_api'), targetCve)
        if not nvd_data:
            logger.debug(f"No NVD data available for sync check: {targetCve}", group="cache_management")
            return
        
        # Extract NVD lastModified date using config field path
        nvd_config = get_cache_config('nvd_2_0_cve')
        nvd_field_path = nvd_config.get('refresh_strategy', {}).get('field_path', '$.vulnerabilities.*.cve.lastModified')
        
        nvd_dates = _extract_field_value(nvd_data, nvd_field_path)
        
        if not nvd_dates:
            logger.warning(f"NVD 2.0 API response missing required lastModified field for {targetCve} (malformed API response)", group="cache_management")
            return
            
        nvd_last_modified = max(nvd_dates)  # Take most recent if multiple matches
        # Handle various datetime formats and ensure timezone awareness
        if 'Z' in nvd_last_modified:
            nvd_datetime_str = nvd_last_modified.replace('Z', '+00:00')
        elif '+' not in nvd_last_modified and nvd_last_modified.count(':') >= 2:
            nvd_datetime_str = nvd_last_modified + '+00:00'
        else:
            nvd_datetime_str = nvd_last_modified
        nvd_datetime = datetime.fromisoformat(nvd_datetime_str)
        
        # Get CVE List V5 local data for comparison
        cve_config = get_cache_config('cve_list_v5')
        local_repo_path = cve_config.get('path', 'cache/cve_list_v5')
        
        cve_file_path = _resolve_cve_cache_file_path(targetCve, local_repo_path)
        if not cve_file_path or not cve_file_path.exists():
            logger.debug(f"No local CVE file exists for sync check: {targetCve}", group="cache_management")
            return
            
        local_data = _load_cve_from_local_file(cve_file_path)
        if not local_data:
            logger.debug(f"Could not load local CVE data for sync check: {targetCve}", group="cache_management")
            return
        
        # Extract CVE List V5 dateUpdated using config field path
        cvelist_field_path = cve_config.get('refresh_strategy', {}).get('field_path', '$.cveMetadata.dateUpdated')
        
        cvelist_dates = _extract_field_value(local_data, cvelist_field_path)
        
        if not cvelist_dates:
            logger.debug(f"No CVE List V5 dateUpdated found for {targetCve}", group="cache_management")
            return
            
        cvelist_date_updated = cvelist_dates[0]  # Should be single match
        # Handle various datetime formats and ensure timezone awareness
        if 'Z' in cvelist_date_updated:
            cvelist_datetime_str = cvelist_date_updated.replace('Z', '+00:00')
        elif '+' not in cvelist_date_updated and cvelist_date_updated.count(':') >= 2:
            cvelist_datetime_str = cvelist_date_updated + '+00:00'
        else:
            cvelist_datetime_str = cvelist_date_updated
        cvelist_datetime = datetime.fromisoformat(cvelist_datetime_str)
        
        # Compare dates and refresh if NVD is newer
        if nvd_datetime > cvelist_datetime:
            logger.info(f"NVD 2.0 API record newer than CVE List V5 cached record - refreshing CVE List V5 cached record for {targetCve} (NVD 2.0 API Record: {nvd_last_modified}, CVE List V5 Cached Record: {cvelist_date_updated})", group="cache_management")
            _refresh_cvelist_from_mitre_api(targetCve, cve_file_path)
        else:
            logger.debug(f"CVE List V5 cached record current for {targetCve} (NVD 2.0 API Record: {nvd_last_modified}, CVE List V5 Cached Record: {cvelist_date_updated})", group="cache_management")
    
    except Exception as e:
        logger.warning(f"CVE List V5 sync check failed for {targetCve}: {e}", group="cache_management")

def _refresh_cvelist_from_mitre_api(targetCve, local_file_path):
    """
    Refresh CVE List V5 local file by fetching fresh data from MITRE CVE API.
    
    Args:
        targetCve: CVE ID to refresh (e.g., "CVE-2024-12345")
        local_file_path: Path object pointing to the local CVE file to update
    """
    try:
        import os
        
        # Set the API Endpoint target for direct MITRE API call
        cveOrgJSON = config['api']['endpoints']['cve_list']
        simpleCveRequestUrl = cveOrgJSON + targetCve
        
        logger.info(f"Refreshing CVE List V5 cached record from MITRE API: {targetCve}", group="cache_management")
        
        # Make direct API call (bypass local loading)
        r = requests.get(simpleCveRequestUrl, timeout=config['api']['timeouts']['cve_org'])
        r.raise_for_status()  
        fresh_cve_data = r.json()

        # Validate fresh data
        processData.integrityCheckCVE("cveIdMatch", targetCve, fresh_cve_data)
        processData.integrityCheckCVE("cveStatusCheck", "REJECTED", fresh_cve_data)
        
        # Ensure directory structure exists
        local_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write fresh data to local file
        with open(local_file_path, 'w', encoding='utf-8') as f:
            json.dump(fresh_cve_data, f, indent=2)
        
        logger.info(f"Updated CVE List V5 cached record: {targetCve}", group="cache_management")
        
        # Update cache metadata
        cve_config = get_cache_config('cve_list_v5')
        cve_repo_path = cve_config.get('path', 'cache/cve_list_v5')
        _update_cache_metadata('cve_list_v5', cve_repo_path)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"MITRE API refresh failed for {targetCve}: {e}", group="cache_management")
    except (IOError, OSError) as e:
        logger.error(f"File write failed during CVE refresh for {targetCve}: {e}", group="cache_management")
    except Exception as e:
        logger.error(f"Unexpected error during CVE refresh for {targetCve}: {e}", group="cache_management")



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

def _save_nvd_cve_to_local_file(targetCve, nvd_data):
    """
    Save NVD CVE data to local cache file using same directory structure as CVE List V5.
    
    Args:
        targetCve: CVE ID to save (e.g., "CVE-2024-12345")
        nvd_data: NVD API response data to save
    """
    try:
        nvd_config = get_cache_config('nvd_2_0_cve')
        if not nvd_config.get('enabled', False):
            return
            
        # Use 'cache/nvd_2.0_cves' as default path (parallel to cve_list_v5)
        nvd_repo_path = nvd_config.get('path', 'cache/nvd_2.0_cves')
        
        nvd_file_path = _resolve_cve_cache_file_path(targetCve, nvd_repo_path)
        if not nvd_file_path:
            logger.warning(f"Could not resolve NVD file path for {targetCve}", group="cache_management")
            return
            
        # Ensure directory structure exists
        nvd_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write NVD data to local file
        with open(nvd_file_path, 'w', encoding='utf-8') as f:
            json.dump(nvd_data, f, indent=2)
        
        logger.debug(f"Updated NVD 2.0 CVE cached record: {targetCve}", group="cache_management")
        
        # Update cache metadata
        _update_cache_metadata('nvd_2_0_cve', nvd_repo_path)
        
    except (IOError, OSError) as e:
        logger.warning(f"Failed to save NVD CVE data for {targetCve}: {e}", group="cache_management")
    except Exception as e:
        logger.warning(f"Unexpected error saving NVD CVE data for {targetCve}: {e}", group="cache_management")



# Update gatherCVEListRecord function
def gatherCVEListRecord(targetCve):
    """
    Main CVE record gathering with config-driven local repository integration.
    Checks local CVE List V5 first (if enabled), with sync detection and API fallback.
    """
    cve_config = get_cache_config('cve_list_v5')
    
    # If local repository is enabled, attempt local loading with sync detection
    if cve_config.get('enabled', False):
        local_repo_path = cve_config.get('path', 'cache/cve_list_v5')
        logger.debug(f"CVE List V5 enabled - attempting local load: {targetCve}", group="cve_queries")
        
        cve_file_path = _resolve_cve_cache_file_path(targetCve, local_repo_path)
        if cve_file_path:
            # Attempt sync with NVD dataset before loading
            _sync_cvelist_with_nvd_dataset(targetCve)
            
            local_data = _load_cve_from_local_file(cve_file_path)
            if local_data:
                logger.info(f"Successfully loaded CVE from local repository: {targetCve}", group="cve_queries")
                return local_data
        
        # Local loading failed - check fallback policy
        if not cve_config.get('fallback_to_api', True):
            logger.error(f"CVE List V5 local load failed and API fallback disabled: {targetCve}", group="cve_queries")
            return None
        
        logger.warning(f"Local CVE load failed for {targetCve} - falling back to MITRE API", group="cve_queries")
    
    # Direct API call (either config disabled or fallback triggered)
    cveOrgJSON = config['api']['endpoints']['cve_list']
    simpleCveRequestUrl = cveOrgJSON + targetCve
    
    logger.api_call("MITRE CVE API", {"cve_id": targetCve}, group="cve_queries")
    
    try:
        r = requests.get(simpleCveRequestUrl, timeout=config['api']['timeouts']['cve_org'])
        r.raise_for_status()  
        cveRecordDict = r.json()

        processData.integrityCheckCVE("cveIdMatch", targetCve, cveRecordDict)
        processData.integrityCheckCVE("cveStatusCheck", "REJECTED", cveRecordDict)
        
        logger.api_response("MITRE CVE API", "Success", group="cve_queries")
        
        return cveRecordDict
    except requests.exceptions.RequestException as e:
        public_ip = get_public_ip()
        logger.error(f"MITRE CVE API request failed: Unable to fetch CVE record for {targetCve} - {e}", group="cve_queries")
        logger.debug(f"Current public IP address: {public_ip}", group="cve_queries")
        
        # Record failed API call in unified dashboard tracking
        try:
            from ..logging.dataset_contents_collector import record_api_call_unified
            record_api_call_unified("MITRE CVE API", success=False)
        except ImportError:
            pass  # Fallback for testing environments
        
        return None

def gatherCVEListRecordLocal(targetCve):
    """
    Load CVE record from local cache with API fallback.
    Uses configured CVE List V5 cache path automatically.
    
    Args:
        targetCve: CVE ID to load (e.g., "CVE-2024-12345")
        
    Returns:
        CVE record dict or None if loading fails
    """
    # Get configured cache path
    cve_config = get_cache_config('cve_list_v5')
    if cve_config.get('enabled', False):
        local_repo_path = cve_config.get('path', 'cache/cve_list_v5')
        logger.debug(f"Using configured CVE List V5 cache: {local_repo_path}", group="cve_queries")
        
        # Attempt local loading first
        logger.debug(f"Attempting local CVE load: {targetCve} from {local_repo_path}", group="cve_queries")
        
        cve_file_path = _resolve_cve_cache_file_path(targetCve, local_repo_path)
        if cve_file_path:
            local_data = _load_cve_from_local_file(cve_file_path)
            if local_data:
                logger.info(f"Successfully loaded CVE from local repository: {targetCve}", group="cve_queries")
                return local_data
        
        # Local loading failed - fall back to API
        logger.warning(f"Local CVE load failed for {targetCve} - falling back to MITRE API", group="cve_queries")
    
    # Always attempt API fallback
    logger.info(f"Using MITRE API for CVE: {targetCve}", group="cve_queries")
    return gatherCVEListRecord(targetCve)

# Using provided CVE-ID, get the CVE data from the NVD API 
def gatherNVDCVERecord(apiKey, targetCve):
    """
    Get CVE data from NVD API with local caching support.
    Checks local NVD cache first (if enabled), then fetches from API and saves to cache.
    """
    nvd_config = get_cache_config('nvd_2_0_cve')
    
    # If NVD cache is enabled, attempt local loading first
    if nvd_config.get('enabled', False):
        nvd_repo_path = nvd_config.get('path', 'cache/nvd_2.0_cves')
        logger.debug(f"NVD CVE cache enabled - attempting local load: {targetCve}", group="cve_queries")
        
        nvd_file_path = _resolve_cve_cache_file_path(targetCve, nvd_repo_path)
        if nvd_file_path:
            local_nvd_data = _load_nvd_cve_from_local_file(nvd_file_path)
            if local_nvd_data:
                logger.debug(f"Successfully loaded NVD 2.0 CVE record from local cache: {targetCve}", group="cve_queries")
                return local_nvd_data
        
        logger.debug(f"NVD 2.0 CVE record not found in local cache - fetching from API: {targetCve}", group="cve_queries")
    
    # Fetch from NVD API
    logger.api_call("NVD CVE API", {"cve_id": targetCve}, group="cve_queries")
   
    url = config['api']['endpoints']['nvd_cves'] + "?cveId=" + targetCve
    headers = {
        "Accept": "application/json",
        "User-Agent": f"{TOOLNAME}/{VERSION}"
    }
      # Only add API key to headers if one was provided
    if apiKey:
        headers["apiKey"] = apiKey
   
    max_retries = config['api']['retry']['max_attempts_nvd']
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, timeout=config['api']['timeouts']['nvd_api'])
            response.raise_for_status()
            logger.api_response("NVD CVE API", "Success", group="cve_queries")
            
            nvd_data = response.json()
            
            # Save to local cache if enabled
            _save_nvd_cve_to_local_file(targetCve, nvd_data)
            
            return nvd_data
        except requests.exceptions.RequestException as e:
            public_ip = get_public_ip()
            logger.error(f"NVD CVE API request failed: Unable to fetch CVE record for {targetCve} (Attempt {attempt + 1}/{max_retries}) - {e}", group="cve_queries")
            logger.debug(f"Current public IP address: {public_ip}", group="cve_queries")            
            if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                logger.error(f"NVD API Message: {e.response.headers['message']}", group="cve_queries")
            
            # Record failed API call in unified dashboard tracking (only once per final failure)
            if attempt == max_retries - 1:  # Only on final attempt
                try:
                    from ..logging.dataset_contents_collector import record_api_call_unified
                    record_api_call_unified("NVD CVE API", success=False)
                except ImportError:
                    pass  # Fallback for testing environments
            
            if attempt < max_retries - 1:
                wait_time = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                logger.warning(f"Waiting {wait_time} seconds before retry...", group="cve_queries")
                sleep(wait_time)
            else:
                logger.error(f"NVD CVE API request failed: Maximum retry attempts ({max_retries}) reached for CVE {targetCve}", group="cve_queries")
                return None
    
# Query NVD /source/ API for data and return a dataframe of the response content
def gatherNVDSourceData(apiKey):
    def fetch_nvd_data():
        url = config['api']['endpoints']['nvd_sources']
        headers = {
            "Accept": "application/json",
            "User-Agent": f"{TOOLNAME}/{VERSION}"
        }
        
        # Only add API key to headers if one was provided
        if apiKey:
            headers["apiKey"] = apiKey
       
        max_retries = config['api']['retry']['max_attempts_nvd']
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                return response.json()
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

# Query the NVD /cpes/ API for information Supported parameters:  cpeMatchString
def gatherNVDCPEData(apiKey, case, query_string):
    match case:
        case 'cpeMatchString':
            nvd_cpes_url = config['api']['endpoints']['nvd_cpes']
            headers = {"user-agent": f"{TOOLNAME}/{VERSION}"}
            
            # Only add API key to headers if one was provided
            if apiKey:
                headers["apiKey"] = apiKey
           
            max_retries = config['api']['retry']['max_attempts_cpe']
            for attempt in range(max_retries):
                try:
                    # Initial request to get total results
                    initial_params = {
                        "cpeMatchString": query_string,
                        "startIndex": 0
                    }
                   
                    # Log the API call before making the request
                    logger.api_call("NVD CPE API", {"cpe_match_string": query_string, "start_index": 0}, group="cpe_queries")
                   
                    response = requests.get(nvd_cpes_url, params=initial_params, headers=headers)
                    response.raise_for_status()
                    
                    initial_data = response.json()
                   
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
                               
                                response = requests.get(nvd_cpes_url, params=params, headers=headers)
                                response.raise_for_status()
                                
                                page_data = response.json()
                               
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
                                    from ..logging.dataset_contents_collector import record_api_call_unified
                                    record_api_call_unified("NVD CPE API", success=False)
                                except ImportError:
                                    pass  # Fallback for testing environments
                                
                                  # Check for message header and display if present - error response
                                if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                                    error_message = e.response.headers['message']
                                    logger.error(f"NVD API Message: {error_message}", group="cve_queries")
                                    
                                    # Don't retry for "Invalid cpeMatchstring parameter" errors
                                    if "Invalid cpeMatchstring parameter" in error_message:
                                        # Note: This should be rare due to early validation in deriveCPEMatchStringList
                                        logger.warning(f"API rejected CPE string (bypassed early validation): {query_string}", group="cpe_queries")
                                        # Return what we've collected so far
                                        consolidated_data["startIndex"] = 0
                                        consolidated_data["resultsPerPage"] = len(consolidated_data["products"])
                                        consolidated_data["error"] = error_message
                                        consolidated_data["status"] = "invalid_cpe"
                                        return consolidated_data
                                
                                if page_attempt < max_retries - 1:
                                    wait_time = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                                    logger.warning(f"Waiting {wait_time} seconds before retry...", group="cpe_queries")
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
                        from ..logging.dataset_contents_collector import record_api_call_unified
                        record_api_call_unified("NVD CPE API", success=False)
                    except ImportError:
                        pass  # Fallback for testing environments
                    
                    # Check for message header and display if present - error response
                    if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                        error_message = e.response.headers['message']
                        logger.error(f"NVD API Message: {error_message}", group="cve_queries")
                        
                        # Don't retry for "Invalid cpeMatchstring parameter" errors
                        if "Invalid cpeMatchstring parameter" in error_message:
                            # Note: This should be rare due to early validation in deriveCPEMatchStringList
                            logger.warning(f"API rejected CPE string (bypassed early validation): {query_string}", group="cpe_queries")
                            # Return empty result structure instead of None
                            return {
                                "totalResults": 0,
                                "resultsPerPage": 0,
                                "startIndex": 0,
                                "products": [],
                                "error": error_message,
                                "status": "invalid_cpe"                            }
                    
                    if attempt < max_retries - 1:
                        wait_time = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                        logger.warning(f"Waiting {wait_time} seconds before retry...", group="cpe_queries")
                        sleep(wait_time)
                    else:
                        logger.error(f"NVD CPE API request failed: Maximum retry attempts ({max_retries}) reached", group="cve_queries")
                        return None
        
        case _:
            return None

# Creates the primary dataframe to be referenced and modified as needed throughout the process
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

def gatherAllCVEIDs(apiKey):
    """
    Gather all CVE IDs from the NVD API with proper retry mechanism.
    
    Args:
        apiKey: NVD API key for authentication
        
    Returns:
        List of all CVE IDs
    """    
    
    base_url = config['api']['endpoints']['nvd_cves']
    headers = {
        "Accept": "application/json",
        "User-Agent": f"{TOOLNAME}/{VERSION}"
    }
    
    # Add API key to headers if provided
    if apiKey:
        headers["apiKey"] = apiKey
    
    params = {
        "startIndex": 0,
    }
    all_cves = []
    total_results = None
    results_per_page = 2000  # Default NVD API page size
    start_index = 0
    
    # Define retry parameters
    max_retries = config['api']['retry']['max_attempts_nvd']
    
    while total_results is None or start_index < total_results:
        params["startIndex"] = start_index
        
        for attempt in range(max_retries):
            try:
                current_page = start_index // results_per_page + 1
                pages_estimate = total_results // results_per_page + 1 if total_results else "?"
                
                if total_results:
                    progress = min(start_index, total_results) / total_results * 100
                    logger.info(f"Processing CVE queries: Page {current_page}/{pages_estimate} ({progress:.1f}%) - {len(all_cves)} CVE records collected so far", group="cve_queries")
                else:
                    logger.info(f"Processing CVE queries: Page {current_page}/? - Determining total count...", group="cve_queries")
                
                response = requests.get(base_url, params=params, headers=headers)
                response.raise_for_status()
                
                data = response.json()
                
                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    logger.info(f"Found {total_results} total results in NVD database", group="cve_queries")
                
                # Extract CVE IDs from current page
                for vuln in data.get("vulnerabilities", []):
                    if "cve" in vuln and "id" in vuln["cve"]:
                        all_cves.append(vuln["cve"]["id"])
                
                # Move to next page
                start_index += results_per_page
                  # Rate limiting
                if not headers.get("apiKey"):
                    sleep(1)  
                else:                    sleep(0)  
                    
                break
                
            except requests.exceptions.RequestException as e:
                public_ip = get_public_ip()
                logger.error(f"NVD CVE list API request failed: Unable to fetch CVE list page {current_page} (Attempt {attempt + 1}/{max_retries}) - {e}", group="cve_queries")
                logger.debug(f"Current public IP address: {public_ip}", group="cve_queries")
                
                # Check for message header and display if present
                if hasattr(e, 'response') and e.response is not None and 'message' in e.response.headers:
                    error_message = e.response.headers['message']
                    logger.error(f"NVD API Message: {error_message}", group="cve_queries")
                
                if attempt < max_retries - 1:
                    wait_time = config['api']['retry']['delay_without_key'] if not apiKey else config['api']['retry']['delay_with_key']
                    logger.warning(f"Waiting {wait_time} seconds before retry...", group="cve_queries")
                    sleep(wait_time)
                else:
                    logger.warning(f"NVD CVE list API request failed: Maximum retry attempts ({max_retries}) reached for page {current_page} - skipping to next page", group="cve_queries")
                    # Move to next page even if failed
                    start_index += results_per_page
    
    logger.info(f"Processing CVE collection completed: {len(all_cves)} CVE records collected", group="cve_queries")
    return all_cves


def load_confirmed_mappings_for_uuid(target_uuid):
    """
    Load confirmed mappings file for the specified target UUID.
    
    Args:
        target_uuid (str): The target UUID to search for in confirmed mapping files
        
    Returns:
        list: List of confirmed mappings, or empty list if none found
        
    Note:
        This function searches the mappings directory for JSON files containing
        the specified cnaId and returns the confirmedMappings array.
    """
    try:
        # Get the mappings directory from config
        config = load_config()
        mappings_dir = Path(__file__).parent.parent / config['confirmed_mappings']['mappings_directory']
        
        if not mappings_dir.exists():
            logger.debug(f"Mappings directory not found: {mappings_dir}", group="data_proc")
            return []
        
        # Search for JSON files containing the target UUID
        for mapping_file in mappings_dir.glob("*.json"):
            try:
                with open(mapping_file, 'r', encoding='utf-8') as f:
                    mapping_data = json.load(f)
                    
                if mapping_data.get('cnaId') == target_uuid:
                    confirmed_mappings = mapping_data.get('confirmedMappings', [])
                    logger.info(f"Found confirmed mappings file: {mapping_file.name} with {len(confirmed_mappings)} mappings", group="data_proc")
                    return confirmed_mappings
                    
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not read mapping file {mapping_file}: {e}", group="data_proc")
                continue
                
        logger.debug(f"No confirmed mappings file found for UUID: {target_uuid}", group="data_proc")
        return []
        
    except Exception as e:
        logger.error(f"Error loading confirmed mappings for UUID {target_uuid}: {e}", group="data_proc")
        return []
