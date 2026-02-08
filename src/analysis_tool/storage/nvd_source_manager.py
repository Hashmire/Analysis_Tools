"""
Global NVD Source Data Manager

This module provides a singleton global manager for NVD source data that loads once
and persists across all CVE processing runs. It follows the same pattern as the
existing GlobalCPECacheManager for consistency.

Features:
- Singleton pattern for global access
- Intelligent cache-aware loading with configurable staleness threshold
- JSON-based cache storage for transparency and debugging
- Automatic cache refresh when stale or missing
- Cross-process cache sharing via unified /cache directory

Configuration:
    Cache staleness threshold is configurable in config.json:
    cache_settings.nvd_source_data.refresh_strategy.notify_age_hours (default: 24)

Recommended Usage:
    # High-level entry points (scripts, main functions) - use get_or_refresh_source_manager
    from .nvd_source_manager import get_or_refresh_source_manager
    
    # Get source manager - handles cache age checking and API refresh automatically
    source_manager = get_or_refresh_source_manager(api_key, log_group="INIT")
    
    # Low-level usage - convenience functions for lookups (no initialization needed)
    from .nvd_source_manager import get_source_name, get_source_info
    
    source_name = get_source_name('some-uuid')
    source_info = get_source_info('some-uuid')

Architecture:
    get_or_refresh_source_manager() orchestrates:
    - Early return if already initialized
    - Cache age checking against config.notify_age_hours threshold
    - Cache refresh from NVD API if stale
    - Automatic cache file creation via initialize()
    - Fail-fast errors if API key missing when refresh needed
"""

from typing import Dict, Any, Optional, List
import pandas as pd
import re
import os
import time
import json
from datetime import datetime, timezone
from pathlib import Path

from ..logging.workflow_logger import get_logger

# Get logger instance
logger = get_logger()

def get_nvd_source_data_config() -> Dict[str, Any]:
    """Get nvd_source_data configuration settings from config.json"""
    try:
        from ..core.processData import load_config
        config = load_config()
        return config.get('cache_settings', {}).get('nvd_source_data', {
            'enabled': True,
            'filename': 'nvd_source_data.json',
            'description': 'NVD source organization data',
            'refresh_strategy': {
                'field_path': '$.created_at',
                'notify_age_hours': 24
            }
        })
    except Exception as e:
        logger.warning(f"Could not load nvd_source_data config, using defaults: {e}", group="CACHE_MANAGEMENT")
        return {
            'enabled': True,
            'filename': 'nvd_source_data.json',
            'description': 'NVD source organization data',
            'refresh_strategy': {
                'field_path': '$.created_at',
                'notify_age_hours': 24
            }
        }

def is_caching_enabled() -> bool:
    """Check if NVD source data caching is enabled in config"""
    config = get_nvd_source_data_config()
    return config.get('enabled', True)

def get_cache_age_threshold() -> float:
    """Get cache age threshold from config (in hours)"""
    config = get_nvd_source_data_config()
    refresh_strategy = config.get('refresh_strategy', {})
    return refresh_strategy.get('notify_age_hours', 24)

def is_cache_stale(age_hours: float) -> bool:
    """Check if cache exceeds configured age threshold"""
    threshold = get_cache_age_threshold()
    return age_hours > threshold

# Global instance
_global_source_manager_instance = None


class GlobalNVDSourceManager:
    """Global NVD source manager that loads once and persists across all CVE processing runs"""
    
    def __init__(self):
        self._source_data = None
        self._source_lookup = {}  # UUID/orgId -> source info lookup
        self._initialized = False
        self._cache_file_path = None  # For localized cache management
    
    def initialize(self, nvd_source_data: pd.DataFrame):
        """Initialize the global source manager with NVD source data"""
        if not self._initialized:
            logger.info("Initializing global NVD source manager - this will happen once per session", group="data_processing")
            self._source_data = nvd_source_data.copy()
            self._build_lookup_tables()
            self._initialized = True
        return self
    
    def _build_lookup_tables(self):
        """Build fast lookup tables for source data"""
        self._source_lookup = {}
        
        for _, source_row in self._source_data.iterrows():
            source_identifiers = source_row.get('sourceIdentifiers', [])
            
            # Create source info using the actual NVD data structure (no artificial orgId)
            source_info = {
                'name': source_row.get('name', 'Unknown'),
                'contactEmail': source_row.get('contactEmail', ''),
                'sourceIdentifiers': source_identifiers
            }
            
            # Add lookup by each sourceIdentifier (UUIDs and emails)
            if isinstance(source_identifiers, list):
                for identifier in source_identifiers:
                    if identifier:
                        self._source_lookup[identifier] = source_info
        
        # Special handling for NIST/NVD
        if 'nvd@nist.gov' not in self._source_lookup:
            nist_info = {
                'name': 'NIST',
                'contactEmail': 'nvd@nist.gov',
                'sourceIdentifiers': ['nvd@nist.gov']
            }
            self._source_lookup['nvd@nist.gov'] = nist_info
            self._source_lookup[''] = nist_info  # Also handle empty string case
    
    def get_source_name(self, source_id: str) -> str:
        """Get source name by ID - returns the source name or raises error if not found"""
        if not self._initialized:
            raise RuntimeError("NVD Source Manager not initialized - call initialize() first")
        
        source_info = self._source_lookup.get(source_id)
        if source_info:
            return source_info['name']
        
        # Legitimate case: source not found in our data - return the ID for display
        return source_id
    
    def get_source_shortname(self, source_id: str) -> str:
        """Get filesystem-safe shortname for source by ID"""
        if not self._initialized:
            raise RuntimeError("NVD Source Manager not initialized - call initialize() first")
        
        source_info = self._source_lookup.get(source_id)
        if source_info:
            return self._create_source_shortname(source_info['name'])
        
        # Fallback for unknown sources - clean the ID itself
        return self._create_source_shortname(source_id)
    
    def _create_source_shortname(self, source_name: str) -> str:
        """
        Convert NVD source names to filesystem-safe shortnames by taking first 13 characters
        Examples:
        - "Adobe Systems Incorporated" -> "Adobe Systems"
        - "Apache Software Foundation" -> "Apache"  
        - "Android (associated with Google Inc. or Open Handset Alliance)" -> "Android"
        - "Cisco Systems, Inc." -> "Cisco Systems"
        - "Brocade Communications Systems, LLC" -> "Brocade"
        """
        if not source_name or source_name == "Unknown":
            return "unknown"
        
        # Take first 13 characters, avoiding word splits if possible
        if len(source_name) <= 13:
            return source_name
        
        # Find last space within first 13 characters to avoid splitting words
        truncated = source_name[:13]
        last_space = truncated.rfind(' ')
        
        # If there's a space and it's not too early, truncate at the space
        if last_space > 9:  # Ensure at least 10 characters
            return source_name[:last_space]
        else:
            return truncated
    
    def get_source_info(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Get full source info by ID"""
        if not self._initialized:
            raise RuntimeError("NVD Source Manager not initialized - call initialize() first")
        
        return self._source_lookup.get(source_id)
    
    def get_all_sources_for_cve(self, used_source_ids: List[str]) -> List[Dict[str, Any]]:
        """Get all source info for a list of source IDs used in a CVE"""
        if not self._initialized:
            raise RuntimeError("NVD Source Manager not initialized - call initialize() first")
        
        sources = []
        
        for source_id in used_source_ids:
            source_info = self._source_lookup.get(source_id)
            if source_info:
                # Return original NVD structure - no artificial orgId field needed
                sources.append(source_info)
        
        return sources
    
    def is_initialized(self) -> bool:
        """Check if source manager is already initialized"""
        return self._initialized
    
    def get_source_count(self) -> int:
        """Get total number of unique source organizations (not lookup table entries)"""
        if not self._initialized:
            return 0
        
        # Count unique source organizations by counting original DataFrame rows
        # Each row represents one organization, regardless of how many lookup keys it has
        return len(self._source_data) if self._source_data is not None else 0
    
    def get_unique_organizations(self) -> Dict[str, str]:
        """
        Get unique organizations (one entry per organization, not per identifier).
        
        Returns a mapping of canonical identifier -> organization name.
        Uses the first sourceIdentifier as the canonical ID for each unique organization.
        
        Returns:
            dict: Mapping of canonical source identifier to organization name
        """
        if not self._initialized:
            return {}
        
        # Track unique organizations by name to avoid duplicates
        unique_orgs = {}
        seen_names = set()
        
        for _, source_row in self._source_data.iterrows():
            org_name = source_row.get('name', 'Unknown')
            source_identifiers = source_row.get('sourceIdentifiers', [])
            
            # Skip if we've already seen this organization
            if org_name in seen_names:
                continue
            
            seen_names.add(org_name)
            
            # Use first identifier as canonical ID for this organization
            if isinstance(source_identifiers, list) and source_identifiers:
                canonical_id = source_identifiers[0]
                unique_orgs[canonical_id] = org_name
        
        return unique_orgs
    
    def create_localized_cache(self, cache_dir: Optional[str] = None) -> str:
        """
        Create a localized cache file for cross-process source data sharing.
        
        This allows harvest scripts to initialize source data once and share it
        across multiple subprocess calls to generate_dataset.py and analysis_tool.py.
        
        Args:
            cache_dir: Optional directory for cache file. If None, uses system temp directory.
            
        Returns:
            str: Path to the created cache file
            
        Raises:
            RuntimeError: If source manager is not initialized
        """
        if not self._initialized:
            raise RuntimeError("Cannot create cache: NVD Source Manager not initialized")
        
        if not is_caching_enabled():
            logger.warning("NVD source data caching disabled in config - skipping cache creation", group="CACHE_MANAGEMENT")
            raise RuntimeError("Cannot create cache: NVD source data caching disabled in config")
        
        # Determine cache directory - use project cache directory like CPE cache
        if cache_dir:
            cache_path = Path(cache_dir)
            cache_path.mkdir(parents=True, exist_ok=True)
        else:
            # Use project root cache directory (same as CPE cache)
            current_file = Path(__file__).resolve()
            project_root = current_file.parent.parent.parent.parent 
            cache_path = project_root / "cache"
            cache_path.mkdir(parents=True, exist_ok=True)
        
        # Use filename from config settings
        config = get_nvd_source_data_config()
        cache_filename = config.get('filename', 'nvd_source_data.json')
        cache_file_path = cache_path / cache_filename
        
        try:
            current_time = datetime.now(timezone.utc)
            
            # Validate source data before caching
            source_data_to_cache = self._source_data
            try:
                # Import schema validation at function level to avoid circular imports
                import sys
                sys.path.insert(0, str(Path(__file__).parent.parent))
                from analysis_tool.core.schema_validator import validate_source_data
                from analysis_tool.core.gatherData import load_schema
                
                # Validate the raw source data before processing
                if self._source_data is not None and len(self._source_data) > 0:
                    source_schema = load_schema('nvd_source_2_0')
                    # Convert first record to dict for validation (schema validates single records)
                    sample_record = self._source_data.iloc[0].to_dict()
                    validate_source_data({'sources': [sample_record]}, source_schema)
            except Exception as validation_error:
                logger.warning(f"NVD source data validation failed: {validation_error} - Caching without validation", group="CACHE_MANAGEMENT")
            
            # Save source data to JSON cache file - handle NaN values properly
            source_data_records = []
            if source_data_to_cache is not None:
                # Convert DataFrame to records and clean NaN values
                for record in source_data_to_cache.to_dict('records'):
                    cleaned_record = {}
                    for key, value in record.items():
                        # Convert NaN/None values to None, which JSON can handle
                        try:
                            if pd.isna(value) or value is None:
                                cleaned_record[key] = None
                            else:
                                cleaned_record[key] = value
                        except (TypeError, ValueError):
                            # Handle array-like values or other types that can't use pd.isna directly
                            if value is None:
                                cleaned_record[key] = None
                            else:
                                # For non-scalar values, convert to list or appropriate JSON-serializable format
                                if hasattr(value, 'tolist'):
                                    cleaned_record[key] = value.tolist()
                                else:
                                    cleaned_record[key] = value
                    source_data_records.append(cleaned_record)
            
            cache_data = {
                'source_data': source_data_records,
                'source_lookup': self._source_lookup,
                'created_at': current_time.isoformat(),
                'process_id': os.getpid(),
                'source_count': len(self._source_data) if self._source_data is not None else 0,  # Count unique sources, not lookup entries
            }
            
            with open(cache_file_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
            
            # Update metadata file
            self._update_cache_metadata(cache_path, current_time)
            
            # Store cache path for cleanup
            self._cache_file_path = str(cache_file_path)
            
            logger.info(f"Created NVD source data cache: {cache_file_path} ({self.get_source_count()} unique sources)", 
                       group="DATASET")
            logger.info(f"Updated unified cache metadata: {cache_path / 'cache_metadata.json'}", group="CACHE_MANAGEMENT")
            
            return str(cache_file_path)
            
        except Exception as e:
            logger.error(f"Failed to create source data cache: {e}", group="CACHE_MANAGEMENT")
            raise RuntimeError(f"Cache creation failed: {e}")
    
    def load_from_cache(self, cache_file_path: str) -> bool:
        """
        Load source data from a localized cache file.
        
        Args:
            cache_file_path: Path to the cache file created by create_localized_cache()
            
        Returns:
            bool: True if successfully loaded, False otherwise
        """
        if not os.path.exists(cache_file_path):
            logger.warning(f"Cache file not found: {cache_file_path}", group="CACHE_MANAGEMENT")
            return False
        
        try:
            # Load JSON cache file
            with open(cache_file_path, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            # Validate cache data structure
            required_keys = ['source_data', 'source_lookup']
            if not all(key in cache_data for key in required_keys):
                logger.warning(f"Invalid JSON cache file structure: {cache_file_path}", group="CACHE_MANAGEMENT")
                return False
            
            # Convert source_data back to DataFrame
            source_data_records = cache_data['source_data']
            if source_data_records:
                self._source_data = pd.DataFrame(source_data_records)
            else:
                self._source_data = pd.DataFrame()
            
            # Rebuild lookup tables with corrected logic (don't use cached lookup)
            self._build_lookup_tables()
            self._initialized = True
            
            # Calculate age from either new or old format
            if 'created_at' in cache_data:
                created_at = datetime.fromisoformat(cache_data['created_at'])
                # Ensure timezone-aware comparison by adding UTC timezone if missing
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                cache_age_hours = (datetime.now(timezone.utc) - created_at).total_seconds() / 3600
            elif 'timestamp' in cache_data:
                cache_age_hours = (time.time() - cache_data['timestamp']) / 3600
            else:
                cache_age_hours = 0.0
            
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load from cache {cache_file_path}: {e}", group="CACHE_MANAGEMENT")
            return False
    
    def _update_cache_metadata(self, cache_path: Path, update_time: datetime) -> None:
        """Update the unified cache metadata file with NVD source data info"""
        metadata_file = cache_path / "cache_metadata.json"
        
        try:
            # Load existing metadata
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            else:
                metadata = {
                    "last_updated": update_time.isoformat(),
                    "datasets": {}
                }
            
            # Update NVD source data metadata
            if "datasets" not in metadata:
                metadata["datasets"] = {}
            
            config = get_nvd_source_data_config()
            nvd_metadata = metadata["datasets"].get("nvd_source_data", {
                "filename": config.get('filename', 'nvd_source_data.json'),
                "created": None,
                "description": config.get('description', 'NVD source organization data for cross-process sharing')
            })
            
            # Update with current information
            if nvd_metadata.get("created") is None:
                nvd_metadata["created"] = update_time.isoformat()
            
            nvd_metadata.update({
                "last_updated": update_time.isoformat(),
                "total_entries": len(self._source_lookup),
                "source_count": len(self._source_lookup)
            })
            
            metadata["datasets"]["nvd_source_data"] = nvd_metadata
            metadata["last_updated"] = update_time.isoformat()
            
            # Save metadata
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2, sort_keys=True)
                
        except Exception as e:
            logger.warning(f"Could not update cache metadata: {e}", group="CACHE_MANAGEMENT")

    def cleanup_cache(self, cache_file_path: Optional[str] = None) -> None:
        """
        Clean up localized cache file.
        
        Args:
            cache_file_path: Specific cache file to clean up. If None, uses stored cache path.
        """
        target_path = cache_file_path or self._cache_file_path
        
        if target_path and os.path.exists(target_path):
            try:
                os.unlink(target_path)
                logger.info(f"Cleaned up cache file: {target_path}", group="CACHE_MANAGEMENT")
                
                if target_path == self._cache_file_path:
                    self._cache_file_path = None
                    
            except Exception as e:
                logger.warning(f"Could not clean up cache file {target_path}: {e}", group="CACHE_MANAGEMENT")
    
    def get_cache_file_path(self) -> Optional[str]:
        """Get the path to the current cache file, if any"""
        return self._cache_file_path


def get_global_source_manager():
    """Get the global source manager instance"""
    global _global_source_manager_instance
    if _global_source_manager_instance is None:
        _global_source_manager_instance = GlobalNVDSourceManager()
    return _global_source_manager_instance


# Convenience functions for easy access throughout the codebase
def get_source_name(source_id: str) -> str:
    """Convenience function to get source name"""
    return get_global_source_manager().get_source_name(source_id)


def get_source_shortname(source_id: str) -> str:
    """Convenience function to get source shortname"""
    return get_global_source_manager().get_source_shortname(source_id)


def get_source_info(source_id: str) -> Optional[Dict[str, Any]]:
    """Convenience function to get source info"""
    return get_global_source_manager().get_source_info(source_id)


def get_all_sources_for_cve(used_source_ids: List[str]) -> List[Dict[str, Any]]:
    """Convenience function to get all sources for a CVE"""
    return get_global_source_manager().get_all_sources_for_cve(used_source_ids)


# Cache management convenience functions
def create_localized_cache(cache_dir: Optional[str] = None) -> str:
    """Convenience function to create a localized cache"""
    return get_global_source_manager().create_localized_cache(cache_dir)


def load_from_cache(cache_file_path: str) -> bool:
    """Convenience function to load from cache"""
    return get_global_source_manager().load_from_cache(cache_file_path)


def cleanup_cache(cache_file_path: Optional[str] = None) -> None:
    """Convenience function to cleanup cache"""
    return get_global_source_manager().cleanup_cache(cache_file_path)


def get_or_refresh_source_manager(api_key: str, log_group: str = "CACHE_MANAGEMENT") -> 'GlobalNVDSourceManager':
    """
    Get the global source manager, using cache or refreshing from NVD API as needed.
    
    This function implements cache management:
    - Returns existing initialized manager if already loaded
    - Checks cache age against threshold configured in config.json
      (cache_settings.nvd_source_data.refresh_strategy.notify_age_hours)
    - Uses existing cache if fresh enough
    - Fetches from NVD API and refreshes cache if stale or missing
    - Fails fast with clear errors if API key missing or network issues occur
    
    Args:
        api_key: NVD API key for fetching fresh data if needed
        log_group: Logger group name for contextualized logging
    
    Returns:
        Initialized GlobalNVDSourceManager instance
        
    Raises:
        ValueError: If API key is missing when refresh is needed
        RuntimeError: If cache is corrupted or initialization fails
        ImportError: If required dependencies (pandas) are not available
    """
    import pandas as pd
    from ..core.gatherData import gatherNVDSourceData
    from datetime import datetime, timezone
    import json
    
    source_manager = get_global_source_manager()
    
    # Return early if already initialized
    if source_manager.is_initialized():
        logger.info(f"Source manager already initialized with {source_manager.get_source_count()} sources", group=log_group)
        return source_manager
    
    # Determine project root and cache paths
    current_file = Path(__file__).resolve()
    project_root = current_file.parent.parent.parent.parent
    cache_file = project_root / "cache" / "nvd_source_data.json"
    cache_metadata_file = project_root / "cache" / "cache_metadata.json"
    
    should_refresh = True
    cache_data = None
    
    # Step 1: Validate cache file structure and schema
    if cache_file.exists():
        logger.info(f"Found existing NVD source cache, validating structure...", group=log_group)
        
        try:
            # Load cache file
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            # Validate required schema fields
            if not cache_data.get('source_data'):
                logger.warning("Cache schema validation failed: missing 'source_data' field", group=log_group)
                should_refresh = True
                cache_data = None
            elif not isinstance(cache_data['source_data'], list):
                logger.warning("Cache schema validation failed: 'source_data' must be a list", group=log_group)
                should_refresh = True
                cache_data = None
            else:
                # Schema is valid - now check age
                logger.info("Cache schema validated successfully", group=log_group)
                
                # Step 2: Check cache age from metadata (now that we know structure is valid)
                if not cache_metadata_file.exists():
                    logger.warning("Cache metadata file not found - treating cache as stale", group=log_group)
                    should_refresh = True
                else:
                    try:
                        with open(cache_metadata_file, 'r') as f:
                            metadata = json.load(f)
                        
                        if 'datasets' not in metadata or 'nvd_source_data' not in metadata['datasets']:
                            logger.warning("Cache metadata missing nvd_source_data entry - treating cache as stale", group=log_group)
                            should_refresh = True
                        else:
                            # Check staleness
                            last_updated = datetime.fromisoformat(metadata['datasets']['nvd_source_data']['last_updated'])
                            if last_updated.tzinfo is None:
                                last_updated = last_updated.replace(tzinfo=timezone.utc)
                            age_hours = (datetime.now(timezone.utc) - last_updated).total_seconds() / 3600
                            threshold = get_cache_age_threshold()
                            
                            if is_cache_stale(age_hours):
                                logger.warning(f"Cache is stale ({age_hours:.1f} hours old, threshold: {threshold}h)", group=log_group)
                                should_refresh = True
                            else:
                                logger.info(f"Cache is fresh (age: {age_hours:.1f} hours, threshold: {threshold}h)", group=log_group)
                                should_refresh = False
                    except Exception as e:
                        logger.warning(f"Metadata validation failed: {e} - treating cache as stale", group=log_group)
                        should_refresh = True
                        
        except json.JSONDecodeError as e:
            logger.warning(f"Cache file is corrupted (invalid JSON): {e}", group=log_group)
            should_refresh = True
            cache_data = None
        except Exception as e:
            logger.warning(f"Unexpected error reading cache: {e}", group=log_group)
            should_refresh = True
            cache_data = None
    
    # Refresh cache if needed (stale, corrupted, or missing)
    if should_refresh:
        if not api_key:
            raise ValueError("NVD API key required to refresh cache but not provided")
        
        logger.info(f"Fetching fresh NVD source data from API...", group=log_group)
        source_data = gatherNVDSourceData(api_key)
        source_manager.initialize(source_data)
        
        # Write refreshed data to cache and update metadata
        logger.info(f"Updating cache with fresh source data...", group=log_group)
        source_manager.create_localized_cache(cache_file.parent)
    else:
        # Use validated cache data
        sources_df = pd.DataFrame(cache_data['source_data'])
        source_manager.initialize(sources_df)
    
    logger.info(f"Source manager initialized with {source_manager.get_source_count()} sources", group=log_group)
    return source_manager
