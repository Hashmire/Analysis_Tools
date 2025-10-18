"""
Unified Source Manager

Provides centralized source data management for both Python backend and JavaScript frontend.
This module serves as the single source of truth for all source-related operations.
"""

import json
from typing import Dict, List, Optional, Any
from ..storage.nvd_source_manager import get_global_source_manager

class UnifiedSourceManager:
    """
    Centralized source management system that provides consistent source data
    to both Python backend and JavaScript frontend through unified data structures.
    """
    
    def __init__(self):
        self._source_registry: Dict[str, Dict[str, Any]] = {}
        self._org_to_sources: Dict[str, List[str]] = {}
        self._initialized = False
        self._filter_source_uuid: Optional[str] = None 
        self.initialize() 
    
    def initialize(self) -> None:
        """Initialize the unified source manager with data from global NVD source manager."""
        if self._initialized:
            return
            
        # Load source data from global NVD source manager
        global_manager = get_global_source_manager()
        
        # Ensure the global manager is properly initialized before copying data
        if not global_manager.is_initialized():
            # Global manager not ready - this should not happen if initialization order is correct
            self._initialized = True  # Mark as initialized to prevent infinite recursion
            return
        
        # Build unified registry from global manager data
        # The GlobalNVDSourceManager has _source_lookup which maps IDs to source info
        # It has duplicate entries (same source_info for each sourceIdentifier)
        # We need to deduplicate to avoid storing the same source multiple times
        if hasattr(global_manager, '_source_lookup') and global_manager._source_lookup:
            processed_uuids = set()  # Track unique UUIDs to avoid duplicates
            
            for source_id, source_info in global_manager._source_lookup.items():
                # Skip empty keys
                if not source_id:
                    continue
                
                # ONLY PROCESS UUID KEYS - Skip email addresses and other non-UUID identifiers
                # UUID pattern: 8-4-4-4-12 hexadecimal characters separated by hyphens
                import re
                uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                if not re.match(uuid_pattern, source_id, re.IGNORECASE):
                    continue  # Skip non-UUID keys (emails, etc.)
                    
                # Skip if we've already processed this UUID
                if source_id in processed_uuids:
                    continue
                    
                # Add to processed set to prevent duplicates
                processed_uuids.add(source_id)
                
                # PRESERVE FULL DATA FIDELITY WITH UUID-ONLY STRUCTURE
                # Use UUID as the primary key for JavaScript lookups
                source_data = {
                    'name': source_info.get('name', 'Unknown'),
                    'contactEmail': source_info.get('contactEmail', ''),
                    'sourceIdentifiers': source_info.get('sourceIdentifiers', []),
                    'role': 'CNA'  # Could be enhanced with actual role detection
                }
                
                # Store with UUID as key for JavaScript UUID lookups
                self._source_registry[source_id] = source_data
                
                # Build org to sources mapping using the source_id (UUID) as the org identifier
                if source_id not in self._org_to_sources:
                    self._org_to_sources[source_id] = []
                if source_id not in self._org_to_sources[source_id]:
                    self._org_to_sources[source_id].append(source_id)
        
        self._initialized = True
    
    def get_source_by_id(self, source_id: str) -> Optional[Dict[str, Any]]:
        """
        Get source information by source ID.
        
        Args:
            source_id: The source identifier (UUID)
            
        Returns:
            Dictionary containing source information or None if not found
        """
        if not self._initialized:
            self.initialize()
            
        return self._source_registry.get(source_id)
    
    def get_sources_by_org(self, org_id: str) -> List[Dict[str, Any]]:
        """
        Get all sources for a specific organization.
        
        Args:
            org_id: The organization identifier
            
        Returns:
            List of source dictionaries for the organization
        """
        if not self._initialized:
            self.initialize()
            
        source_ids = self._org_to_sources.get(org_id, [])
        return [self._source_registry[sid] for sid in source_ids if sid in self._source_registry]
    
    def get_all_sources(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all sources in the registry.
        
        Returns:
            Dictionary mapping source IDs to source information
        """
        if not self._initialized:
            self.initialize()
            
        return self._source_registry.copy()
    
    def generate_javascript_data(self) -> str:
        """
        Generate JavaScript code that provides unified source data to the frontend.
        
        Returns:
            JavaScript code string that sets up unified source data
        """
        if not self._initialized:
            self.initialize()
            
        # Create JavaScript-friendly data structures
        js_data = {
            'sourceRegistry': self._source_registry,
            'orgToSources': self._org_to_sources
        }
        
        js_code = f"""
// Unified Source Data - Generated by Python UnifiedSourceManager
window.UNIFIED_SOURCE_DATA = {json.dumps(js_data, indent=2)};

// Unified Source Manager Functions
window.UnifiedSourceManager = {{
    
    /**
     * Get source information by source ID
     * @param {{string}} sourceId - The source identifier (UUID)
     * @returns {{Object|null}} Source information or null if not found
     */
    getSourceById: function(sourceId) {{
        const source = window.UNIFIED_SOURCE_DATA.sourceRegistry[sourceId];
        if (source) {{
            // Add the ID to the returned object since it's stored as the key
            return {{ id: sourceId, ...source }};
        }}
        return null;
    }},
    
    /**
     * Get all sources for a specific organization
     * @param {{string}} orgId - The organization identifier
     * @returns {{Array}} Array of source objects for the organization
     */
    getSourcesByOrg: function(orgId) {{
        const sourceIds = window.UNIFIED_SOURCE_DATA.orgToSources[orgId] || [];
        return sourceIds.map(id => {{
            const source = window.UNIFIED_SOURCE_DATA.sourceRegistry[id];
            return source ? {{ id: id, ...source }} : null;
        }}).filter(Boolean);
    }},
    
    /**
     * Get all sources in the registry
     * @returns {{Object}} Dictionary mapping source IDs to source information
     */
    getAllSources: function() {{
        const result = {{}};
        for (const [id, source] of Object.entries(window.UNIFIED_SOURCE_DATA.sourceRegistry)) {{
            result[id] = {{ id: id, ...source }};
        }}
        return result;
    }},
    
    /**
     * Check if a source ID exists in the registry
     * @param {{string}} sourceId - The source identifier to check
     * @returns {{boolean}} True if source exists, false otherwise
     */
    hasSource: function(sourceId) {{
        return sourceId in window.UNIFIED_SOURCE_DATA.sourceRegistry;
    }},
    
    /**
     * Get contact email for a source
     * @param {{string}} sourceId - The source identifier
     * @returns {{string}} Contact email or empty string if not found
     */
    getSourceContactEmail: function(sourceId) {{
        const source = window.UNIFIED_SOURCE_DATA.sourceRegistry[sourceId];
        return source ? (source.contactEmail || '') : '';
    }},
    
    /**
     * Get all source identifiers for a source
     * @param {{string}} sourceId - The source identifier  
     * @returns {{Array}} Array of source identifiers or empty array if not found
     */
    getSourceIdentifiers: function(sourceId) {{
        const source = window.UNIFIED_SOURCE_DATA.sourceRegistry[sourceId];
        return source ? (source.sourceIdentifiers || []) : [];
    }},
    
    /**
     * Search sources by name (case-insensitive partial match)
     * @param {{string}} searchTerm - The search term
     * @returns {{Array}} Array of matching source objects
     */
    searchSourcesByName: function(searchTerm) {{
        const term = searchTerm.toLowerCase();
        const results = [];
        for (const [id, source] of Object.entries(window.UNIFIED_SOURCE_DATA.sourceRegistry)) {{
            if (source.name.toLowerCase().includes(term)) {{
                results.push({{ id: id, ...source }});
            }}
        }}
        return results;
    }}
}};

console.debug('Unified Source Manager initialized with', Object.keys(window.UNIFIED_SOURCE_DATA.sourceRegistry).length, 'sources - STRICT UUID-only mode');
"""
        
        return js_code
    
    def get_source_count(self) -> int:
        """Get the total number of sources in the registry."""
        if not self._initialized:
            self.initialize()
            
        return len(self._source_registry)
    
    def get_org_count(self) -> int:
        """Get the total number of organizations in the registry."""
        if not self._initialized:
            self.initialize()
            
        return len(self._org_to_sources)
    
    # Source UUID filtering functionality
    
    def set_source_uuid_filter(self, source_uuid: Optional[str]) -> None:
        """Set the source UUID for filtering throughout the processing pipeline.
        
        Args:
            source_uuid: The source UUID to filter by, or None to disable filtering
            
        Note: UUID validation is deferred until the source managers are properly initialized
        to avoid timing issues during early argument parsing.
        """
        self._filter_source_uuid = source_uuid
    
    def get_source_uuid_filter(self) -> Optional[str]:
        """Get the current source UUID filter.
        
        Returns:
            The current source UUID string, or None if no filtering is active
        """
        return self._filter_source_uuid
    
    def clear_source_uuid_filter(self) -> None:
        """Clear the source UUID filter (disable filtering)."""
        self._filter_source_uuid = None
    
    def is_source_uuid_match(self, container_source_id: str) -> bool:
        """Check if a container source ID matches the current filter.
        
        Args:
            container_source_id: The source ID from a CVE container
            
        Returns:
            True if no filter is set or if the source ID matches the filter
        """
        if not self._filter_source_uuid:
            return True  # No filter, accept all
        return container_source_id == self._filter_source_uuid
    
    def should_process_container(self, container: Dict[str, Any]) -> bool:
        """Determine if a CVE container should be processed based on current filter.
        
        Args:
            container: The CVE container data
            
        Returns:
            True if the container should be processed, False if it should be skipped
        """
        if not self._filter_source_uuid:
            return True  # No filter, process all containers
            
        container_source_id = container.get('providerMetadata', {}).get('orgId', '')
        return self.is_source_uuid_match(container_source_id)


# Global singleton instance
_unified_manager_instance: Optional[UnifiedSourceManager] = None

def get_unified_source_manager() -> UnifiedSourceManager:
    """
    Get the global unified source manager instance.
    
    Returns:
        Singleton instance of UnifiedSourceManager
    """
    global _unified_manager_instance
    if _unified_manager_instance is None:
        _unified_manager_instance = UnifiedSourceManager()
    return _unified_manager_instance
