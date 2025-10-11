"""
Global NVD Source Data Manager

This module provides a singleton global manager for NVD source data that loads once
and persists across all CVE processing runs. It follows the same pattern as the
existing GlobalCPECacheManager for consistency.

Usage:
    from .nvd_source_manager import get_global_source_manager
    
    # Initialize once with NVD source data
    source_manager = get_global_source_manager()
    source_manager.initialize(nvd_source_data)
    
    # Use throughout the codebase
    source_name = source_manager.get_source_name('some-uuid')
    source_info = source_manager.get_source_info('some-uuid')
"""

from typing import Dict, Any, Optional, List
import pandas as pd
import re

from ..logging.workflow_logger import get_logger

# Get logger instance
logger = get_logger()

# Global instance
_global_source_manager_instance = None


class GlobalNVDSourceManager:
    """Global NVD source manager that loads once and persists across all CVE processing runs"""
    
    def __init__(self):
        self._source_data = None
        self._source_lookup = {}  # UUID/orgId -> source info lookup
        self._initialized = False
    
    def initialize(self, nvd_source_data: pd.DataFrame):
        """Initialize the global source manager with NVD source data"""
        if not self._initialized:
            logger.info("Initializing global NVD source manager - this will happen once per session", group="data_processing")
            self._source_data = nvd_source_data.copy()
            self._build_lookup_tables()
            self._initialized = True
            logger.info(f"Global NVD source manager initialized with {len(self._source_lookup)} source entries", group="data_processing")
        return self
    
    def _build_lookup_tables(self):
        """Build fast lookup tables for source data"""
        self._source_lookup = {}
        
        for _, source_row in self._source_data.iterrows():
            source_info = {
                'orgId': source_row.get('orgId', ''),
                'name': source_row.get('name', 'Unknown'),
                'contactEmail': source_row.get('contactEmail', ''),
                'sourceIdentifiers': source_row.get('sourceIdentifiers', [])
            }
            
            # Add lookup by orgId
            org_id = source_row.get('orgId', '')
            if org_id:
                self._source_lookup[org_id] = source_info
            
            # Add lookup by each sourceIdentifier UUID
            source_identifiers = source_row.get('sourceIdentifiers', [])
            if isinstance(source_identifiers, list):
                for uuid in source_identifiers:
                    if uuid:
                        self._source_lookup[uuid] = source_info
        
        # Special handling for NIST/NVD
        if 'nvd@nist.gov' not in self._source_lookup:
            nist_info = {
                'orgId': 'nvd@nist.gov',
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
        added_sources = set()
        
        for source_id in used_source_ids:
            source_info = self._source_lookup.get(source_id)
            if source_info and source_info['orgId'] not in added_sources:
                sources.append(source_info)
                added_sources.add(source_info['orgId'])
        
        return sources
    
    def is_initialized(self) -> bool:
        """Check if source manager is already initialized"""
        return self._initialized
    
    def get_source_count(self) -> int:
        """Get total number of sources loaded"""
        return len(self._source_lookup) if self._initialized else 0


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
