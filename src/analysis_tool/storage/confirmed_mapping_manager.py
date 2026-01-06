"""
Confirmed Mapping Manager - Global singleton for efficient confirmed mapping file management.

This module provides a centralized manager for loading and accessing confirmed mapping files.
Instead of scanning the mappings directory repeatedly, all files are loaded once and indexed
for lookup by source identifier.

Architecture:
- Load all confirmed mapping files once during initialization
- Index by cnaId AND all sourceIdentifiers for the organization
- Validate against NVD source manager to ensure mappings are from known organizations
- Thread-safe singleton pattern for session-wide reuse

Usage:
    from ..storage.confirmed_mapping_manager import get_global_mapping_manager
    
    manager = get_global_mapping_manager()
    if not manager.is_initialized():
        manager.initialize()
    
    mappings = manager.get_mappings_for_source('psirt@adobe.com')
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any

from ..logging.workflow_logger import get_logger
from ..core.gatherData import load_config  # Import early to load configuration upfront

logger = get_logger()

# Global singleton instance
_global_mapping_manager = None


class ConfirmedMappingManager:
    """
    Manager for confirmed mapping files with efficient indexing.
    
    Loads all confirmed mapping files once and provides fast lookup by source identifier.
    Validates all mappings against NVD source manager to ensure organizational attribution.
    """
    
    def __init__(self):
        """Initialize manager (does not load data - call initialize() explicitly)."""
        self._initialized = False
        self._mapping_lookup = {}  # {source_identifier: {'cnaId': str, 'mappings': list, 'file': str, 'org': str}}
        self._files_loaded = []
        self._files_rejected = []
        self._files_used = set()  # Track which files were actually accessed during runtime
        self._source_manager = None
    
    def initialize(self, mappings_dir: Optional[Path] = None, source_manager=None):
        """
        Load and index all confirmed mapping files.
        
        Args:
            mappings_dir: Directory containing mapping JSON files (auto-detected if None)
            source_manager: NVD source manager for validation (auto-loaded if None)
            
        Returns:
            Self for chaining
        """
        if self._initialized:
            logger.debug("Confirmed mapping manager already initialized", group="ALIAS_AUDIT")
            return self
        
        # Auto-detect mappings directory if not provided
        if mappings_dir is None:
            from ..storage.run_organization import get_analysis_tools_root
            config = load_config()  # Already imported at module level
            project_root = get_analysis_tools_root()
            mappings_dir = project_root / config['confirmed_mappings']['mappings_directory']
        
        if not mappings_dir.exists():
            logger.warning(f"Confirmed mappings directory not found: {mappings_dir}", group="ALIAS_AUDIT")
            self._initialized = True
            return self
        
        # Get source manager for validation - REQUIRED for data integrity
        if source_manager is None:
            from ..storage.nvd_source_manager import get_or_refresh_source_manager
            config = load_config()
            api_key = config.get('defaults', {}).get('default_api_key', '')
            
            # get_or_refresh_source_manager() guarantees initialization or raises exception
            self._source_manager = get_or_refresh_source_manager(api_key, log_group="ALIAS_AUDIT")
        else:
            # Verify provided source manager is initialized - fail fast if not
            if not source_manager.is_initialized():
                raise RuntimeError(
                    "source_manager is not initialized - confirmed mapping manager"
                )
            self._source_manager = source_manager
        
        # Load and index all mapping files
        logger.info("Loading all confirmed mapping files...", group="ALIAS_AUDIT")
        
        for mapping_file in sorted(mappings_dir.glob("*.json")):
            self._load_mapping_file(mapping_file)
        
        # Log summary
        total_files = len(self._files_loaded) + len(self._files_rejected)
        logger.info(
            f"Confirmed mapping manager initialized: {len(self._files_loaded)}/{total_files} files loaded, "
            f"{len(self._mapping_lookup)} source identifiers indexed",
            group="ALIAS_AUDIT"
        )
        
        self._initialized = True
        return self
    
    def _load_mapping_file(self, mapping_file: Path):
        """
        Load and index a single confirmed mapping file.
        
        Args:
            mapping_file: Path to JSON mapping file
        """
        try:
            with open(mapping_file, 'r', encoding='utf-8') as f:
                mapping_data = json.load(f)
            
            cna_id = mapping_data.get('cnaId')
            if not cna_id:
                logger.warning(f"Skipping {mapping_file.name}: missing cnaId", group="ALIAS_AUDIT")
                self._files_rejected.append((mapping_file.name, "Missing cnaId"))
                return
            
            confirmed_mappings = mapping_data.get('confirmedMappings', [])
            if not confirmed_mappings:
                logger.debug(f"Skipping {mapping_file.name}: no confirmedMappings", group="ALIAS_AUDIT")
                self._files_rejected.append((mapping_file.name, "No mappings"))
                return
            
            # Validate against NVD source manager (guaranteed to be initialized)
            source_info = self._source_manager.get_source_info(cna_id)
            
            if not source_info:
                logger.warning(
                    f"REJECTED {mapping_file.name}: cnaId {cna_id} not found in NVD source database",
                    group="ALIAS_AUDIT"
                )
                self._files_rejected.append((mapping_file.name, f"Unknown cnaId: {cna_id}"))
                return
            
            # Extract organization info
            org_name = source_info.get('name', 'Unknown')
            source_identifiers = source_info.get('sourceIdentifiers', [])
            
            # Create mapping record
            mapping_record = {
                'cnaId': cna_id,
                'mappings': confirmed_mappings,
                'file': mapping_file.name,
                'org': org_name,
                'count': len(confirmed_mappings)
            }
            
            # Index by ALL sourceIdentifiers for this organization (emails + UUIDs)
            if isinstance(source_identifiers, list):
                for identifier in source_identifiers:
                    if identifier:
                        self._mapping_lookup[identifier] = mapping_record
            
            logger.info(
                f"LOADED {mapping_file.name}: {org_name} ({len(confirmed_mappings)} mappings, "
                f"{len(source_identifiers)} identifiers indexed)",
                group="ALIAS_AUDIT"
            )
            self._files_loaded.append(mapping_file.name)
        
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {mapping_file.name}: {e}", group="ALIAS_AUDIT")
            self._files_rejected.append((mapping_file.name, f"JSON error: {e}"))
        except Exception as e:
            logger.error(f"Error loading {mapping_file.name}: {e}", group="ALIAS_AUDIT")
            self._files_rejected.append((mapping_file.name, f"Error: {e}"))
    
    def get_mappings_for_source(self, source_id: str) -> List[Dict[str, Any]]:
        """
        Get confirmed mappings for a source identifier (email or UUID).
        
        Args:
            source_id: Source identifier (email or UUID)
            
        Returns:
            List of confirmed mapping dictionaries, or empty list if none found
        """
        if not self._initialized:
            raise RuntimeError("Confirmed mapping manager not initialized - call initialize() first")
        
        mapping_record = self._mapping_lookup.get(source_id)
        if mapping_record:
            # Track that this file was actually used
            self._files_used.add(mapping_record['file'])
            return mapping_record['mappings']
        
        return []
    
    def get_mapping_info(self, source_id: str) -> Optional[Dict[str, Any]]:
        """
        Get full mapping record for a source identifier.
        
        Args:
            source_id: Source identifier (email or UUID)
            
        Returns:
            Mapping record dict with cnaId, mappings, file, org, count, or None if not found
        """
        if not self._initialized:
            raise RuntimeError("Confirmed mapping manager not initialized - call initialize() first")
        
        return self._mapping_lookup.get(source_id)
    
    def has_mappings(self, source_id: str) -> bool:
        """
        Check if confirmed mappings exist for a source identifier.
        
        Args:
            source_id: Source identifier (email or UUID)
            
        Returns:
            True if mappings exist, False otherwise
        """
        if not self._initialized:
            return False
        
        return source_id in self._mapping_lookup
    
    def is_initialized(self) -> bool:
        """Check if manager is initialized."""
        return self._initialized
    
    def get_loaded_files_count(self) -> int:
        """Get count of successfully loaded mapping files."""
        return len(self._files_loaded)
    
    def get_rejected_files_count(self) -> int:
        """Get count of rejected mapping files."""
        return len(self._files_rejected)
    
    def get_used_files_count(self) -> int:
        """Get count of mapping files that were actually accessed during runtime."""
        return len(self._files_used)
    
    def get_used_files(self) -> List[str]:
        """Get list of mapping files that were actually used."""
        return sorted(list(self._files_used))
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about loaded mappings.
        
        Returns:
            Dictionary with stats: files_loaded, files_rejected, files_used, identifiers_indexed, etc.
        """
        return {
            'files_loaded': len(self._files_loaded),
            'files_rejected': len(self._files_rejected),
            'files_used': len(self._files_used),
            'identifiers_indexed': len(self._mapping_lookup),
            'loaded_files': self._files_loaded,
            'rejected_files': self._files_rejected,
            'used_files': sorted(list(self._files_used))
        }


def get_global_mapping_manager() -> ConfirmedMappingManager:
    """
    Get the global singleton confirmed mapping manager instance.
    
    Returns:
        Global ConfirmedMappingManager instance
    """
    global _global_mapping_manager
    
    if _global_mapping_manager is None:
        _global_mapping_manager = ConfirmedMappingManager()
    
    return _global_mapping_manager
