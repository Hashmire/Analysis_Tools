#!/usr/bin/env python3
"""
NVD-ish Enhanced Record Collection System

Creates enhanced NVD 2.0 format records by integrating:
1) Base NVD 2.0 CVE record structure
2) CVE List V5 affected arrays with proper source attribution
3) Analysis tool processing outputs (SDC, CPE suggestions, CPE-AS generation)

Output: Individual .json files in cache/nvd-ish_2.0_cves/ following year-based directory structure
Attribution: datatype -> source format with proper provenance tracking

ARCHITECTURE:
- Incremental data collection during processing
- Per-CVE file saves on completion  
- Fail-fast error handling with appropriate logging
- Hybrid integration with existing collectors and processing
- Safe multi-stage file updates to prevent data corruption
"""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import shutil

# Import the structured logging system
try:
    from .workflow_logger import get_logger, LogGroup
    logger = get_logger()
except ImportError:
    # Fallback for testing environments
    logger = None

# Import configuration loader
try:
    from ..core.gatherData import get_cache_config, _resolve_cve_cache_file_path
except ImportError:
    get_cache_config = None
    _resolve_cve_cache_file_path = None

# Import global source manager for attribution and alias mapping
try:
    from ..storage.nvd_source_manager import get_source_name, get_global_source_manager
except ImportError:
    get_source_name = None
    get_global_source_manager = None



class NVDishCollector:
    """
    Collects and integrates data from multiple sources to create enhanced NVD records.
    Operates incrementally during processing and saves individual files per CVE.
    """
    
    def __init__(self):
        self.current_cve_id: Optional[str] = None
        self.current_record: Optional[Dict] = None
        self.processing_metadata: Dict[str, Any] = {}
        
        # Configuration from config.json
        self.config = self._load_config()
        self.attribution_source = self.config.get('attribution_source', 'hashmire/analysis_tools')
        self.output_path = Path(self.config.get('path', 'cache/nvd-ish_2.0_cves'))
        
        # Processing state tracking
        self.data_collected = {
            'nvd_base': False,
            'cve_list_v5': False,
            'sdc_report': False,
            'cpe_suggestions': False,
            'cpe_as_generation': False,
            'tool_execution_metadata': False
        }
        
        # Enhanced record structure building
        self.enriched_record_data = {
            'toolExecutionMetadata': {},
            'cpeSuggestionMetadata': [],
            'cveListV5AffectedEntries': []
        }
        
        # Ensure output directory exists
        self.output_path.mkdir(parents=True, exist_ok=True)
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from config.json"""
        try:
            # Import here to avoid circular dependencies
            from pathlib import Path
            import json
            
            config_path = Path(__file__).parent.parent / "config.json"
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Merge application config with nvd_ish_output config
            app_config = config_data.get('application', {})
            nvd_ish_config = config_data.get('nvd_ish_output', {})
            
            # Combine both sections for easy access
            combined_config = nvd_ish_config.copy()
            combined_config.update({
                'tool_name': app_config.get('toolname', 'Hashmire/Analysis_Tools'),
                'tool_version': app_config.get('version', '0.2.0')
            })
            
            return combined_config
            
        except Exception as e:
            if logger:
                logger.warning(f"Failed to load nvd_ish_output config, using defaults: {e}", group="INIT")
            return {
                'enabled': True,
                'path': 'cache/nvd-ish_2.0_cves',
                'attribution_source': 'hashmire/analysis_tools',
                'format': 'NVD_CVE_Enhanced',
                'version': '2.0'
            }
    
    def resolve_source_alias(self, source_id: str, nvd_source_identifier: str = None) -> str:
        """
        Resolve UUID to the actual sourceIdentifier used in NVD records.
        
        This ensures enrichedCVEv5Affected source values match the exact sourceIdentifier 
        that NVD uses for this CVE, preventing collisions and ensuring accuracy.
        
        Args:
            source_id: Source identifier (UUID or other identifier) 
            nvd_source_identifier: The actual sourceIdentifier from the NVD record for this CVE
            
        Returns:
            NVD sourceIdentifier if found and matches, otherwise original source_id
        """
        if not get_global_source_manager or not source_id:
            return source_id
        
        try:
            # Get the global source manager instance
            source_manager = get_global_source_manager()
            
            if not source_manager._initialized:
                # Manager not initialized, cannot resolve - return original UUID
                if logger:
                    logger.debug(f"enrichedCVEv5Affected source alias resolution skipped - source manager not initialized: {source_id}", group="data_processing")
                return source_id
            
            # Look up the source info
            source_info = source_manager.get_source_info(source_id)
            
            if source_info and 'sourceIdentifiers' in source_info:
                identifiers = source_info['sourceIdentifiers']
                
                # If we have the NVD sourceIdentifier for this CVE, verify it matches
                if nvd_source_identifier:
                    if nvd_source_identifier in identifiers:
                        # Perfect match - this UUID maps to the exact sourceIdentifier NVD uses
                        if logger:
                            logger.debug(f"enrichedCVEv5Affected source {source_id} maps to NVD sourceIdentifier {nvd_source_identifier} (verified)", group="data_processing")
                        return nvd_source_identifier
                    else:
                        # Different source - this is normal for multi-source CVEs (CNA + ADP)
                        # Only log collision if this UUID was expected to map to the NVD sourceIdentifier
                        # (i.e., they should be the same source but have different identifiers)
                        if logger:
                            logger.debug(f"Different source detected: {source_id} maps to {identifiers}, NVD uses {nvd_source_identifier} - preserving original source identifier", group="data_processing")
                        return source_id
                else:
                    # No NVD sourceIdentifier provided - find the most appropriate identifier
                    # Prefer non-UUID identifiers (emails, domains) over UUIDs as they're more human-readable
                    non_uuid_identifiers = [id for id in identifiers if not self._is_uuid_format(id)]
                    if non_uuid_identifiers:
                        resolved = non_uuid_identifiers[0]  # Take first non-UUID
                        if logger:
                            logger.debug(f"enrichedCVEv5Affected source {source_id} resolved to preferred identifier {resolved}", group="data_processing")
                        return resolved
                    else:
                        # Only UUID identifiers available
                        if logger:
                            logger.debug(f"enrichedCVEv5Affected source {source_id} found but only UUID identifiers available: {identifiers}", group="data_processing")
                        return source_id
            
            # NO MATCH: UUID not found in our known source set - keep original UUID
            if logger:
                logger.debug(f"NO MATCH - enrichedCVEv5Affected source {source_id} not found in known NVD source set - keeping original UUID", group="data_processing")
            return source_id
            
        except Exception as e:
            # Fallback to original source_id on any error
            if logger:
                logger.debug(f"enrichedCVEv5Affected source alias resolution failed for {source_id}, using original UUID: {e}", group="data_processing")
            return source_id
    
    def _is_uuid_format(self, identifier: str) -> bool:
        """Check if identifier looks like a UUID format"""
        import re
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return bool(re.match(uuid_pattern, identifier, re.IGNORECASE))
    
    def _create_complete_cpe_suggestions_structure(self, affected_entry_data: Dict = None, cvelistv5_affected_entry_index: str = None) -> Dict:
        """
        Create a complete cpeSuggestions structure with all required fields.
        
        This ensures consistent structure across all cpeSuggestions objects from initial creation,
        preventing the need for retroactive structure normalization.
        
        Args:
            affected_entry_data: Optional affected entry data for context
            cvelistv5_affected_entry_index: Optional affected entry index
            
        Returns:
            Complete cpeSuggestions structure with all required fields
        """
        # Get tool identification information
        tool_name = self.config.get('tool_name', 'Hashmire/Analysis_Tools')
        tool_version = self.config.get('tool_version', '0.2.0')
        source_id = f"{tool_name} v{tool_version}"
        
        # Determine the affected entry index if available
        if cvelistv5_affected_entry_index is None and affected_entry_data:
            cvelistv5_affected_entry_index = affected_entry_data.get('cvelistv5AffectedEntryIndex', 'unknown')
        elif cvelistv5_affected_entry_index is None:
            cvelistv5_affected_entry_index = 'unknown'
        
        return {
            'sourceId': source_id,
            'cvelistv5AffectedEntryIndex': cvelistv5_affected_entry_index,
            'confirmedMappings': [],
            'cpeMatchStringsSearched': [],
            'cpeMatchStringsCulled': [],
            'top10SuggestedCPEBaseStrings': []
        }
    
    def start_cve_processing(self, cve_id: str) -> None:
        """
        Initialize enhanced record collection for a new CVE.
        
        Args:
            cve_id: CVE identifier being processed
        """
        if not self.config.get('enabled', True):
            return
        
        self.current_cve_id = cve_id
        self.current_record = None
        self.processing_metadata = {
            'cveId': cve_id,
            'processingStarted': datetime.now(timezone.utc).isoformat(),
            'processingCompleted': None,
            'dataSources': [],
            'extensionsApplied': []
        }
        
        # Reset data collection state
        for key in self.data_collected:
            self.data_collected[key] = False
        
        # Initialize enhanced record structure, preserving existing toolExecutionMetadata if available
        existing_tool_metadata = self._load_existing_tool_metadata(cve_id)
        self.enriched_record_data = {
            'toolExecutionMetadata': existing_tool_metadata or {},
            'cpeSuggestionMetadata': [],
            'cveListV5AffectedEntries': []
        }
        
        if logger:
            logger.debug(f"Started NVD-ish record collection for {cve_id}", group="data_processing")
    
    def collect_nvd_base_record(self, nvd_record_data: Dict = None) -> None:
        """
        Set the base NVD 2.0 record as foundation for enhancement.
        
        Args:
            nvd_record_data: Complete NVD 2.0 API response data. If None, loads from cache.
        """
        if not self.current_cve_id or not self.config.get('enabled', True):
            return
        
        try:
            # If no record provided, load from cache
            if nvd_record_data is None:
                nvd_record_data = self._load_nvd_cache_record(self.current_cve_id)
                if nvd_record_data is None:
                    if logger:
                        logger.warning(f"No NVD 2.0 record found for {self.current_cve_id}", group="data_processing")
                    # DO NOT create if partial source data - we need real NVD 2.0 data for enhanced records
                    self.data_collected['nvd_base'] = False
                    return
            
            # Since collector runs after all processing is complete, we can work directly with original data
            self.current_record = nvd_record_data
            
            # Update format identification for enhanced records
            if 'format' in self.current_record:
                self.current_record['format'] = self.config.get('format', 'NVD_CVE_Enhanced')
            
            # Initialize enhanced_data structure in the CVE node
            if 'vulnerabilities' in self.current_record and len(self.current_record['vulnerabilities']) > 0:
                cve_data = self.current_record['vulnerabilities'][0]['cve']
                
                # Add enhanced data extensions section
                cve_data['enhanced_data'] = {
                    'format_version': self.config.get('version', '2.0'),
                    'attribution_source': self.config.get('attribution_source', 'hashmire/analysis_tools'),
                    'processing_timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                    'data_sources': {
                        'nvd_2_0': {
                            'source': 'nvd@nist.gov',
                            'timestamp': self.current_record.get('timestamp')
                        }
                    },
                    'integrated_data': {}
                }
            
            # Track data source
            self.processing_metadata['dataSources'].append({
                'type': 'nvdBase',
                'source': 'nvd@nist.gov',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'description': 'Base NVD 2.0 CVE record structure'
            })
            
            self.data_collected['nvd_base'] = True
            
            if logger:
                logger.debug(f"Collected NVD base record for {self.current_cve_id}", group="data_processing")
                
        except Exception as e:
            if logger:
                logger.error(f"Failed to collect NVD base record for {self.current_cve_id}: {e}", group="data_processing")
            # Fail fast as requested
            raise RuntimeError(f"NVD base record collection failed: {e}")
    
    def _load_nvd_cache_record(self, cve_id: str) -> Optional[Dict]:
        """Load NVD 2.0 record from existing cache."""
        try:
            # Parse year from CVE ID (e.g., CVE-2024-50623 -> 2024)
            year = cve_id.split('-')[1] 
            
            # Build cache path relative to project root
            project_root = Path(__file__).parent.parent.parent.parent
            cache_base = project_root / "cache" / "nvd_2.0_cves"
            
            # Determine xxx directory based on CVE number
            cve_num = int(cve_id.split('-')[2])
            xxx_dir = f"{(cve_num // 1000)}xxx"
            
            cache_file = cache_base / year / xxx_dir / f"{cve_id}.json"
            
            if cache_file.exists():
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
                    
        except Exception as e:
            if logger:
                logger.warning(f"Failed to load NVD cache for {cve_id}: {e}", group="data_processing")
        
        return None
    
    def _create_minimal_nvd_record(self, cve_id: str) -> Dict:
        """Create minimal NVD record structure if none exists in cache."""
        return {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            "vulnerabilities": [
                {
                    "cve": {
                        "id": cve_id,
                        "sourceIdentifier": "unknown",
                        "published": "unknown",
                        "lastModified": "unknown",
                        "vulnStatus": "Unknown",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "No NVD 2.0 record available for this CVE."
                            }
                        ]
                    }
                }
            ]
        }
    
    def _load_cve_list_v5_cache_record(self, cve_id: str) -> Optional[Dict]:
        """Load CVE List V5 record from existing cache."""
        try:
            # Parse year from CVE ID (e.g., CVE-2024-50623 -> 2024)
            year = cve_id.split('-')[1] 
            
            # Build cache path relative to project root
            project_root = Path(__file__).parent.parent.parent.parent
            cache_base = project_root / "cache" / "cve_list_v5"
            
            # Determine xxx directory based on CVE number
            cve_num = int(cve_id.split('-')[2])
            xxx_dir = f"{(cve_num // 1000)}xxx"
            
            cache_file = cache_base / year / xxx_dir / f"{cve_id}.json"
            
            if cache_file.exists():
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
                    
        except Exception as e:
            if logger:
                logger.warning(f"Failed to load CVE List V5 cache for {cve_id}: {e}", group="data_processing")
        
        return None
    
    def collect_cve_list_v5_data(self, cve_list_data: Dict = None, source_attribution: Optional[str] = None) -> None:
        """
        Integrate CVE List V5 affected arrays with proper source attribution.
        
        Args:
            cve_list_data: CVE List V5 record data. If None, loads from cache.
            source_attribution: Source orgId from providerMetadata (if available)
        """
        if not self.current_cve_id or not self.config.get('enabled', True):
            return
        
        if not self.current_record:
            if logger:
                logger.warning(f"No base record available for CVE List V5 integration: {self.current_cve_id}", group="data_processing")
            return
        
        # If no record provided, load from cache
        if cve_list_data is None:
            cve_list_data = self._load_cve_list_v5_cache_record(self.current_cve_id)
            if cve_list_data is None:
                if logger:
                    logger.warning(f"No CVE List V5 record found for {self.current_cve_id}", group="data_processing")
                # Mark as missing and return - validation will catch this later
                self.data_collected['cve_list_v5'] = False
                return
        
        try:
            # Extract affected arrays from CVE List V5 structure
            affected_data = self._extract_cve_list_affected_arrays(cve_list_data)
            
            if affected_data:
                # Add enhanced CVE List V5 data with attribution
                if 'vulnerabilities' in self.current_record and len(self.current_record['vulnerabilities']) > 0:
                    cve_node = self.current_record['vulnerabilities'][0]['cve']
                    
                    # Create enhanced affected data section
                    if 'enhanced_data' not in cve_node:
                        cve_node['enhanced_data'] = {}
                    
                    # Build Section II.C: CVE List V5 Affected Entries Analysis per documented format
                    # Each affected entry becomes a complete analysis object with all sub-sections
                    for affected_entry in affected_data:
                        analysis_entry = {
                            # II.C.1. Original Affected Entry
                            'originAffectedEntry': {
                                'sourceId': affected_entry.get('source', 'unknown_source'),
                                'cvelistv5AffectedEntryIndex': f'cve.containers.{affected_entry.get("container_type", "unknown")}.affected.[{affected_entry.get("entry_index", 0)}]',
                                'vendor': affected_entry.get('vendor'),
                                'product': affected_entry.get('product'),
                                'versions': affected_entry.get('versions', []),
                                'platforms': affected_entry.get('platforms', []),
                                'cpes': affected_entry.get('cpes', [])
                            },
                            # II.C.2. Source Data Concerns (placeholder for SDC integration)
                            'sourceDataConcerns': {},
                            # II.C.3. Alias Extraction (placeholder for alias integration)
                            'aliasExtraction': {},
                            # II.C.4. CPE Suggestions (complete structure from initialization)
                            'cpeSuggestions': self._create_complete_cpe_suggestions_structure(
                                affected_entry_data=affected_entry,
                                cvelistv5_affected_entry_index=f'cve.containers.{affected_entry.get("container_type", "unknown")}.affected.[{affected_entry.get("entry_index", 0)}]'
                            ),
                            # II.C.5. CPE-AS Generation Rules (placeholder for CPE-AS integration)
                            'cpeAsGenerationRules': {}
                        }
                        
                        self.enriched_record_data['cveListV5AffectedEntries'].append(analysis_entry)
                    
                    # Store legacy data temporarily for transition
                    cve_node['enhanced_data']['cve_list_v5_affected'] = {
                        'attribution': 'containers.*.affected (CNA + ADP)',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'data': affected_data  # Each entry already has its container's orgId as 'source'
                    }
                    
                    # Track extension application
                    self.processing_metadata['extensionsApplied'].append('enrichedCVEv5Affected')
                    
                    # Extract unique source IDs for metadata tracking
                    unique_sources = list(set(entry.get('source', 'unknown') for entry in affected_data))
                    for source_id in unique_sources:
                        self.processing_metadata['dataSources'].append({
                            'type': 'cveListV5',
                            'source': source_id,
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'description': 'CVE List V5 affected arrays'
                        })
                    
                    self.data_collected['cve_list_v5'] = True
                    
                    if logger:
                        logger.debug(f"Integrated CVE List V5 data for {self.current_cve_id}", group="data_processing")
            else:
                # No affected data found - mark as missing
                self.data_collected['cve_list_v5'] = False
                if logger:
                    logger.warning(f"CVE List V5 record found but contains no affected data for {self.current_cve_id}", group="data_processing")
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to integrate CVE List V5 data for {self.current_cve_id}: {e}", group="data_processing")
            # Fail fast as requested
            raise RuntimeError(f"CVE List V5 integration failed: {e}")
    
    def collect_source_data_concerns_from_registry(self, registry_instance=None) -> None:
        """
        Integrate Source Data Concerns from Platform Entry Notification Registry after badge system processing.
        
        This method should be called after the badge system has run to pull the source data concerns
        and populate them into the cveListV5AffectedEntries structure.
        
        Args:
            registry_instance: Optional registry instance to use instead of the imported one
        """
        if not self.current_cve_id or not self.config.get('enabled', True):
            return
        
        # Registry instance is required for source data concerns integration
        if registry_instance is None:
            if logger:
                logger.warning(f"No registry instance provided - skipping source data concerns integration for {self.current_cve_id}", group="data_processing")
            return
        
        registry = registry_instance
        
        try:
            # Get source data concerns from the registry
            sdc_registry = registry.get('sourceDataConcerns', {})
            

            
            if not sdc_registry:
                if logger:
                    logger.debug(f"No source data concerns found in registry for {self.current_cve_id}", group="data_processing")
                return
            
            # Update existing cveListV5AffectedEntries with source data concerns
            if 'cveListV5AffectedEntries' in self.enriched_record_data:
                updated_entries = []
                
                for entry_idx, analysis_entry in enumerate(self.enriched_record_data['cveListV5AffectedEntries']):
                    # Try to match with registry entries using table_index
                    # The table_index corresponds to the processing order of affected entries
                    registry_entry = sdc_registry.get(entry_idx)
                    
                    if registry_entry:
                        # Extract source data concerns following the documented format
                        concerns_data = registry_entry.get('concerns', {})
                        
                        # Get the tool identification information 
                        tool_name = self.config.get('tool_name', 'Hashmire/Analysis_Tools')
                        tool_version = self.config.get('tool_version', '0.2.0')
                        source_id = f"{tool_name} v{tool_version}"
                        
                        # Get the affected entry index from the originAffectedEntry
                        affected_entry_index = analysis_entry.get('originAffectedEntry', {}).get('cvelistv5AffectedEntryIndex', 'unknown')
                        
                        # Populate the sourceDataConcerns section following documented format
                        analysis_entry['sourceDataConcerns'] = {
                            'sourceId': source_id,
                            'cvelistv5AffectedEntryIndex': affected_entry_index,
                            'concerns': concerns_data
                        }
                        
                        if logger:
                            concern_count = sum(len(v) if isinstance(v, list) else 0 for v in concerns_data.values())
                            logger.debug(f"Integrated source data concerns for affected entry {entry_idx}: {concern_count} concerns", group="data_processing")
                    else:
                        # No concerns found for this entry - leave empty placeholder following documented format
                        tool_name = self.config.get('tool_name', 'Hashmire/Analysis_Tools')
                        tool_version = self.config.get('tool_version', '0.2.0')
                        source_id = f"{tool_name} v{tool_version}"
                        affected_entry_index = analysis_entry.get('originAffectedEntry', {}).get('cvelistv5AffectedEntryIndex', 'unknown')
                        
                        analysis_entry['sourceDataConcerns'] = {
                            'sourceId': source_id,
                            'cvelistv5AffectedEntryIndex': affected_entry_index,
                            'concerns': {}
                        }
                    
                    updated_entries.append(analysis_entry)
                
                # Update the enriched record data
                self.enriched_record_data['cveListV5AffectedEntries'] = updated_entries
                
                # Track the integration in metadata
                self.processing_metadata['extensionsApplied'].append('sourceDataConcernsRegistry')
                self.processing_metadata['dataSources'].append({
                    'type': 'sourceDataConcerns',
                    'source': 'badge_system_registry',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'description': 'Source data concerns from Platform Entry Notification Registry'
                })
                
                if logger:
                    logger.info(f"Successfully integrated source data concerns from registry for {self.current_cve_id}: {len(sdc_registry)} entries processed", group="data_processing")
            else:
                if logger:
                    logger.warning(f"No cveListV5AffectedEntries found to populate with source data concerns for {self.current_cve_id}", group="data_processing")
        
        except Exception as e:
            if logger:
                logger.error(f"Failed to integrate source data concerns from registry for {self.current_cve_id}: {e}", group="data_processing")
            # Continue processing - this is not a critical failure

    def collect_sdc_report_data(self, sdc_concerns_data: Dict, affected_entry_mapping: Optional[Dict] = None) -> None:
        """
        Integrate Source Data Concerns report with proper attribution.
        
        Args:
            sdc_concerns_data: Structured concerns data from badge generation
            affected_entry_mapping: Optional mapping to associate concerns with specific affected entries
        """
        if not self.current_cve_id or not self.config.get('enabled', True):
            return
        
        if not self.current_record:
            if logger:
                logger.warning(f"No base record available for SDC integration: {self.current_cve_id}", group="data_processing")
            return
        
        try:
            if sdc_concerns_data and 'vulnerabilities' in self.current_record:
                cve_node = self.current_record['vulnerabilities'][0]['cve']
                
                if 'enhanced_data' not in cve_node:
                    cve_node['enhanced_data'] = {}
                
                cve_node['enhanced_data']['source_data_concerns'] = {
                    'source': self.attribution_source,
                    'attribution': 'analysis_tools.sdc_report',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'data': sdc_concerns_data,
                    'affected_entry_mapping': affected_entry_mapping
                }
                
                # Track extension application
                self.processing_metadata['extensionsApplied'].append('source_data_concerns')
                self.processing_metadata['dataSources'].append({
                    'type': 'sdc_report',
                    'source': self.attribution_source,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'description': 'Source Data Concerns analysis'
                })
                
                self.data_collected['sdc_report'] = True
                
                if logger:
                    logger.debug(f"Integrated SDC report data for {self.current_cve_id}", group="data_processing")
        
        except Exception as e:
            if logger:
                logger.error(f"Failed to integrate SDC report for {self.current_cve_id}: {e}", group="data_processing")
            # Continue processing other data as requested
    
    def collect_cpe_suggestions_data(self, cpe_suggestions_data: Dict) -> None:
        """
        Integrate CPE suggestions data with proper attribution.
        
        Args:
            cpe_suggestions_data: CPE suggestions and NVD API results
        """
        if not self.current_cve_id or not self.config.get('enabled', True):
            return
        
        if not self.current_record:
            if logger:
                logger.warning(f"No base record available for CPE suggestions integration: {self.current_cve_id}", group="data_processing")
            return
        
        try:
            if cpe_suggestions_data and 'vulnerabilities' in self.current_record:
                cve_node = self.current_record['vulnerabilities'][0]['cve']
                
                if 'enhanced_data' not in cve_node:
                    cve_node['enhanced_data'] = {}
                
                # Store in Section II.B: CPE Suggestion Metadata per documented format
                if isinstance(cpe_suggestions_data, list):
                    # If it's already formatted as cpeSuggestionMetadata array
                    self.enriched_record_data['cpeSuggestionMetadata'] = cpe_suggestions_data
                elif isinstance(cpe_suggestions_data, dict) and 'cpeSuggestionMetadata' in cpe_suggestions_data:
                    # If wrapped in container
                    self.enriched_record_data['cpeSuggestionMetadata'] = cpe_suggestions_data['cpeSuggestionMetadata']
                else:
                    # Transform generic CPE data to documented format
                    # This will need specific implementation based on actual data structure
                    self.enriched_record_data['cpeSuggestionMetadata'] = []
                
                # Store legacy data temporarily for transition
                cve_node['enhanced_data']['cpe_enhancements'] = {
                    'source': self.attribution_source,
                    'attribution': 'analysis_tools.cpe_suggestions',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'data': cpe_suggestions_data
                }
                
                # Track extension application
                self.processing_metadata['extensionsApplied'].append('cpe_enhancements')
                self.processing_metadata['dataSources'].append({
                    'type': 'cpe_suggestions',
                    'source': self.attribution_source,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'description': 'CPE suggestions and NVD API results'
                })
                
                self.data_collected['cpe_suggestions'] = True
                
                if logger:
                    logger.debug(f"Integrated CPE suggestions data for {self.current_cve_id}", group="data_processing")
        
        except Exception as e:
            if logger:
                logger.error(f"Failed to integrate CPE suggestions for {self.current_cve_id}: {e}", group="data_processing")
            # Continue processing other data as requested

    def collect_cpe_suggestions_from_registry(self, registry_instance=None) -> None:
        """
        Integrate CPE suggestions data from Platform Entry Notification Registry.
        
        This method extracts CPE suggestions data stored in the cpeBaseStringSearches
        section of the Platform Entry Notification Registry and populates the
        II.C.4 CPE Suggestions structure in affected entries.
        
        Args:
            registry_instance: Optional registry instance to use instead of the imported one
        """
        if not self.current_cve_id or not self.config.get('enabled', True):
            return
        
        # Registry instance is required for CPE suggestions integration
        if registry_instance is None:
            if logger:
                logger.warning(f"No registry instance provided - skipping CPE suggestions integration for {self.current_cve_id}", group="data_processing")
            return
        
        registry = registry_instance
        
        try:
            # Get CPE searches, culled strings, and top 10 suggestions from separate registries for proper isolation
            cpe_searches_registry = registry.get('cpeBaseStringSearches', {})
            cpe_culled_registry = registry.get('cpeMatchStringsCulled', {})
            top10_cpe_registry = registry.get('top10CPESuggestions', {})
            
            # Debug logging
            if logger:
                logger.debug(f"Registry keys: {list(registry.keys()) if registry else 'None'}", group="data_processing")
                logger.debug(f"CPE searches registry keys: {list(cpe_searches_registry.keys())}", group="data_processing")
                logger.debug(f"CPE culled registry keys: {list(cpe_culled_registry.keys())}", group="data_processing")
                logger.debug(f"Top 10 CPE registry keys: {list(top10_cpe_registry.keys())}", group="data_processing")
            
            if not cpe_searches_registry and not cpe_culled_registry and not top10_cpe_registry:
                if logger:
                    logger.debug(f"No CPE data available in registry for CPE suggestions - {self.current_cve_id}", group="data_processing")
                return
            
            # Process each affected entry to extract CPE suggestions from separate registries
            affected_entries_updated = 0
            
            # Process CPE match strings searched registry
            for table_index, cpe_search_data in cpe_searches_registry.items():
                if logger:
                    logger.debug(f"Processing CPE match strings searched for table_index {table_index}: {len(cpe_search_data.get('used_strings', []))} strings", group="data_processing")
                
                if 'cveListV5AffectedEntries' in self.enriched_record_data:
                    for entry in self.enriched_record_data['cveListV5AffectedEntries']:
                        if self._matches_table_index(entry, table_index):
                            # Ensure complete cpeSuggestions structure exists
                            if 'cpeSuggestions' not in entry:
                                entry['cpeSuggestions'] = self._create_complete_cpe_suggestions_structure(
                                    affected_entry_data=entry.get('originAffectedEntry', {}),
                                    cvelistv5_affected_entry_index=entry.get('originAffectedEntry', {}).get('cvelistv5AffectedEntryIndex', 'unknown')
                                )
                            
                            # Update CPE match strings searched directly
                            used_strings = cpe_search_data.get('used_strings', [])
                            entry['cpeSuggestions']['cpeMatchStringsSearched'].extend(used_strings)
                            affected_entries_updated += 1
                            break
            
            # Process CPE match strings culled registry separately
            for table_index, cpe_culled_data in cpe_culled_registry.items():
                if logger:
                    logger.debug(f"Processing CPE match strings culled for table_index {table_index}: {len(cpe_culled_data.get('culled_strings', []))} strings", group="data_processing")
                
                if 'cveListV5AffectedEntries' in self.enriched_record_data:
                    for entry in self.enriched_record_data['cveListV5AffectedEntries']:
                        if self._matches_table_index(entry, table_index):
                            # Ensure complete cpeSuggestions structure exists
                            if 'cpeSuggestions' not in entry:
                                entry['cpeSuggestions'] = self._create_complete_cpe_suggestions_structure(
                                    affected_entry_data=entry.get('originAffectedEntry', {}),
                                    cvelistv5_affected_entry_index=entry.get('originAffectedEntry', {}).get('cvelistv5AffectedEntryIndex', 'unknown')
                                )
                            
                            # Process culled strings with proper reason mapping
                            culled_strings = cpe_culled_data.get('culled_strings', [])
                            for culled_item in culled_strings:
                                if isinstance(culled_item, dict):
                                    cpe_string = culled_item.get('cpe_string', '')
                                    reason = culled_item.get('reason', 'unspecified_filter')
                                    
                                    # Map internal validation reasons to documented format
                                    reason_mapping = {
                                        'Both vendor and product are wildcards or empty': 'insufficient_specificity_vendor_product_required',
                                        'All components are wildcards': 'all_wildcards_too_broad',
                                        'Not a CPE 2.3 string': 'missing_cpe_prefix',
                                        'Incomplete CPE 2.3 components': 'incomplete_cpe_components',
                                        'Empty CPE string': 'empty_cpe_string',
                                        'Missing CPE 2.3 prefix - NVD API requires \'cpe:2.3:\' prefix': 'nvd_api_missing_prefix',
                                        'Incorrect component count - NVD API expects exactly 13 colon-separated components': 'nvd_api_wrong_component_count',
                                        'unspecified_filter': 'unknown_culling_reason'
                                    }
                                    
                                    # Handle pattern-based reasons with specific subtypes (check patterns first before fallback)
                                    if 'too long' in reason and ('NVD API limit' in reason or 'NVD API rejection' in reason):
                                        mapped_reason = 'nvd_api_field_too_long'  
                                    elif 'escaped commas' in reason:
                                        mapped_reason = 'nvd_api_escaped_comma_pattern'
                                    elif 'non-ASCII characters' in reason:
                                        mapped_reason = 'nvd_api_non_ascii_characters'
                                    elif 'leading or trailing whitespace' in reason:
                                        mapped_reason = 'nvd_api_whitespace_in_field'
                                    elif 'trailing underscore' in reason:
                                        mapped_reason = 'nvd_api_trailing_underscore'
                                    elif 'internal asterisk' in reason:
                                        mapped_reason = 'nvd_api_internal_asterisk'
                                    else:
                                        mapped_reason = reason_mapping.get(reason, 'unknown_culling_reason')
                                    
                                    culled_entry = {
                                        'cpeString': cpe_string,
                                        'reason': mapped_reason
                                    }
                                    entry['cpeSuggestions']['cpeMatchStringsCulled'].append(culled_entry)
                            break
            
            # Process top 10 CPE suggestions registry separately
            for table_index, top10_data in top10_cpe_registry.items():
                if logger:
                    logger.debug(f"Processing top 10 CPE suggestions for table_index {table_index}: {len(top10_data.get('top10SuggestedCPEBaseStrings', []))} suggestions", group="data_processing")
                
                if 'cveListV5AffectedEntries' in self.enriched_record_data:
                    for entry in self.enriched_record_data['cveListV5AffectedEntries']:
                        if self._matches_table_index(entry, table_index):
                            # Ensure complete cpeSuggestions structure exists
                            if 'cpeSuggestions' not in entry:
                                entry['cpeSuggestions'] = self._create_complete_cpe_suggestions_structure(
                                    affected_entry_data=entry.get('originAffectedEntry', {}),
                                    cvelistv5_affected_entry_index=entry.get('originAffectedEntry', {}).get('cvelistv5AffectedEntryIndex', 'unknown')
                                )
                            
                            # Process top 10 suggestions with proper ranking
                            top10_suggestions = top10_data.get('top10SuggestedCPEBaseStrings', [])
                            
                            # Initialize top10SuggestedCPEBaseStrings if not present
                            if 'top10SuggestedCPEBaseStrings' not in entry['cpeSuggestions']:
                                entry['cpeSuggestions']['top10SuggestedCPEBaseStrings'] = []
                            
                            for suggestion in top10_suggestions:
                                if isinstance(suggestion, dict):
                                    cpe_string = suggestion.get('cpeBaseString', '')
                                    rank = suggestion.get('rank', 0)
                                    
                                    if cpe_string:
                                        entry['cpeSuggestions']['top10SuggestedCPEBaseStrings'].append({
                                            'cpeBaseString': cpe_string,
                                            'rank': rank
                                        })
                            
                            affected_entries_updated += 1
                            break
                    
            if affected_entries_updated > 0:
                self.data_collected['cpe_suggestions'] = True
                
                # Track extension application
                if 'cpe_enhancements' not in self.processing_metadata.get('extensionsApplied', []):
                    self.processing_metadata['extensionsApplied'].append('cpe_enhancements')
                
                # Add data source tracking
                self.processing_metadata['dataSources'].append({
                    'type': 'cpe_suggestions_registry',
                    'source': self.attribution_source,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'description': f'CPE suggestions from Platform Entry Notification Registry ({affected_entries_updated} entries)'
                })
                
                if logger:
                    logger.info(f"Integrated CPE suggestions from registry for {affected_entries_updated} affected entries in {self.current_cve_id}", group="data_processing")
            else:
                if logger:
                    logger.debug(f"No CPE suggestions data found in registry for {self.current_cve_id}", group="data_processing")
        
        except Exception as e:
            if logger:
                logger.error(f"Failed to integrate CPE suggestions from registry for {self.current_cve_id}: {e}", group="data_processing")
            # Continue processing other data as requested
    
    def _extract_cpe_suggestions_from_supporting_info(self, supporting_info: Dict, table_index: str, registry_instance: Optional[Dict] = None) -> Optional[Dict]:
        """
        Extract enriched CPE suggestions data from supporting information structure with detailed mapping analysis.
        
        Args:
            supporting_info: Supporting information data from registry
            table_index: Table index for tracking
            registry_instance: Platform Entry Notification Registry instance for additional data access
            
        Returns:
            Dict with enhanced CPE suggestions in II.C.4 format or None if no data
        """
        try:
            # Get the tool identification information following documented format
            tool_name = self.config.get('tool_name', 'Hashmire/Analysis_Tools')
            tool_version = self.config.get('tool_version', '0.2.0')
            source_id = f"{tool_name} v{tool_version}"
            
            cpe_suggestions = {
                'sourceId': source_id,
                'cvelistv5AffectedEntryIndex': f'cve.containers.cna.affected.[{table_index}]',
                'confirmedMappings': [],
                'cpeMatchStringsSearched': [],
                'cpeMatchStringsCulled': []
            }
            
            # Extract data from supporting information tabs
            tabs = supporting_info.get('tabs', [])
            
            for tab in tabs:
                if tab.get('id') == 'search' and tab.get('title') == 'CPE Base Strings Searched':
                    # Extract CPE base strings data with enhanced mapping information
                    items = tab.get('items', [])
                    
                    for item in items:
                        if item.get('type') == 'cpe_searches':
                            # Extract used (heuristic suggestions) and culled CPE strings
                            used_strings = item.get('used_strings', [])
                            culled_strings = item.get('culled_strings', [])
                            
                            # Convert used strings to CPE match strings searched following documented format
                            for cpe_string in used_strings:
                                if isinstance(cpe_string, str):
                                    # Simple array of CPE base strings as per documentation
                                    cpe_suggestions['cpeMatchStringsSearched'].append(cpe_string)
                            
                            # Add culled strings following documented format
                            for culled_item in culled_strings:
                                if isinstance(culled_item, dict):
                                    cpe_string = culled_item.get('cpe_string', '')
                                    reason = culled_item.get('reason', 'unspecified_filter')
                                elif isinstance(culled_item, str):
                                    cpe_string = culled_item
                                    reason = 'legacy_culling_process'
                                else:
                                    continue
                                    
                                if cpe_string:
                                    # Map internal validation reasons to specific, actionable documentation format
                                    reason_mapping = {
                                        # Specificity validation reasons
                                        'Both vendor and product are wildcards or empty': 'insufficient_specificity_vendor_product_required',
                                        'All components are wildcards': 'all_wildcards_too_broad',
                                        'Not a CPE 2.3 string': 'missing_cpe_prefix',
                                        'Incomplete CPE 2.3 components': 'incomplete_cpe_components',
                                        # NVD API compatibility reasons  
                                        'Empty CPE string': 'empty_cpe_string',
                                        'Missing CPE 2.3 prefix - NVD API requires \'cpe:2.3:\' prefix': 'nvd_api_missing_prefix',
                                        'Incorrect component count - NVD API expects exactly 13 colon-separated components': 'nvd_api_wrong_component_count',
                                        # Default reasons
                                        'unspecified_filter': 'unknown_culling_reason',
                                        'legacy_culling_process': 'legacy_filter_no_reason_available'
                                    }
                                    
                                    # Handle pattern-based reasons with specific subtypes (check patterns first before fallback)
                                    if 'Two characters or less' in reason and 'too broad' in reason:
                                        mapped_reason = 'insufficient_specificity_too_short'
                                    elif 'too long' in reason and ('NVD API limit' in reason or 'NVD API rejection' in reason):
                                        mapped_reason = 'nvd_api_field_too_long'  
                                    elif 'escaped commas' in reason:
                                        mapped_reason = 'nvd_api_escaped_comma_pattern'
                                    elif 'non-ASCII characters' in reason:
                                        mapped_reason = 'nvd_api_non_ascii_characters'
                                    elif 'leading or trailing whitespace' in reason:
                                        mapped_reason = 'nvd_api_whitespace_in_field'
                                    elif 'trailing underscore' in reason:
                                        mapped_reason = 'nvd_api_trailing_underscore'
                                    elif 'internal asterisk' in reason:
                                        mapped_reason = 'nvd_api_internal_asterisk'
                                    else:
                                        mapped_reason = reason_mapping.get(reason, 'unknown_culling_reason')
                                    
                                    # Simple structure as per documentation
                                    culled_entry = {
                                        'cpeString': cpe_string,
                                        'reason': mapped_reason
                                    }
                                    cpe_suggestions['cpeMatchStringsCulled'].append(culled_entry)
                
                elif tab.get('id') == 'versions':
                    # Extract confirmed mappings from versions/CPE data
                    items = tab.get('items', [])
                    
                    for item in items:
                        if item.get('type') == 'cpe_data':
                            # Extract CPEs from affected entry data 
                            cpes = item.get('cpes', [])
                            
                            for cpe_string in cpes:
                                if isinstance(cpe_string, str):
                                    # Simple array of CPE base strings as per documentation
                                    cpe_suggestions['confirmedMappings'].append(cpe_string)
                        
                        elif item.get('type') == 'confirmed_mappings':
                            # Extract confirmed mappings from platformEntryMetadata
                            confirmed_cpes = item.get('confirmed_cpes', [])
                            
                            for cpe_string in confirmed_cpes:
                                if isinstance(cpe_string, str):
                                    # Simple array of CPE base strings as per documentation
                                    cpe_suggestions['confirmedMappings'].append(cpe_string)
            
            # Extract top 10 suggested CPE base strings if available
            top10_cpe_registry = registry_instance.get('top10CPESuggestions', {}) if registry_instance else {}
            if top10_cpe_registry and self.current_cve_id in top10_cpe_registry:
                top10_data = top10_cpe_registry[self.current_cve_id]
                
                # Find matching table index entry
                for affected_entry in top10_data.get('affectedEntries', []):
                    if affected_entry.get('index') == table_index:
                        top10_suggestions = affected_entry.get('top10Suggestions', [])
                        
                        # Add top10SuggestedCPEBaseStrings to cpeSuggestions following documented format
                        cpe_suggestions['top10SuggestedCPEBaseStrings'] = []
                        
                        for suggestion in top10_suggestions:
                            if isinstance(suggestion, dict):
                                cpe_string = suggestion.get('cpeBaseString', '')
                                rank = suggestion.get('rank', 0)
                                
                                if cpe_string:
                                    cpe_suggestions['top10SuggestedCPEBaseStrings'].append({
                                        'cpeBaseString': cpe_string,
                                        'rank': rank
                                    })
                        break
            
            # Only return data if we have meaningful content
            total_suggestions = (len(cpe_suggestions['confirmedMappings']) + 
                               len(cpe_suggestions['cpeMatchStringsSearched']) + 
                               len(cpe_suggestions['cpeMatchStringsCulled']) +
                               len(cpe_suggestions.get('top10SuggestedCPEBaseStrings', [])))
            
            if total_suggestions > 0:
                return cpe_suggestions
            else:
                return None
                
        except Exception as e:
            if logger:
                logger.warning(f"Failed to extract CPE suggestions from supporting info for table {table_index}: {e}", group="data_processing")
            return None

    def collect_confirmed_mappings_from_registry(self, registry_instance=None) -> None:
        """
        Integrate confirmed mappings data from Platform Entry Notification Registry.
        
        This method extracts confirmed mappings data from the confirmedMappings
        section of the Platform Entry Notification Registry and populates the
        confirmedMappings arrays in the cpeSuggestions structure.
        
        Args:
            registry_instance: Optional registry instance to use instead of the imported one
        """
        if not self.current_cve_id or not self.config.get('enabled', True):
            return
        
        # Registry instance is required for confirmed mappings integration
        if registry_instance is None:
            if logger:
                logger.warning(f"No registry instance provided - skipping confirmed mappings integration for {self.current_cve_id}", group="data_processing")
            return
        
        registry = registry_instance
        
        try:
            # Get confirmed mappings from the registry
            confirmed_mappings_registry = registry.get('confirmedMappings', {})
            
            # Debug logging
            if logger:
                logger.debug(f"Confirmed mappings registry keys: {list(confirmed_mappings_registry.keys())}", group="data_processing")
            
            if not confirmed_mappings_registry:
                if logger:
                    logger.debug(f"No confirmed mappings available in registry for {self.current_cve_id}", group="data_processing")
                return
            
            # Process each affected entry to add confirmed mappings
            affected_entries_updated = 0
            
            for table_index, confirmed_mappings_data in confirmed_mappings_registry.items():
                if logger:
                    logger.debug(f"Processing confirmed mappings for table_index {table_index}", group="data_processing")
                
                if isinstance(confirmed_mappings_data, dict) and 'confirmedMappings' in confirmed_mappings_data:
                    # Update the corresponding affected entry in enriched record data
                    if 'cveListV5AffectedEntries' in self.enriched_record_data:
                        for entry in self.enriched_record_data['cveListV5AffectedEntries']:
                            # Match by table index 
                            if self._matches_table_index(entry, table_index):
                                # Ensure complete cpeSuggestions structure exists
                                if 'cpeSuggestions' not in entry:
                                    entry['cpeSuggestions'] = self._create_complete_cpe_suggestions_structure(
                                        affected_entry_data=entry.get('originAffectedEntry', {}),
                                        cvelistv5_affected_entry_index=confirmed_mappings_data.get('cvelistv5AffectedEntryIndex', 'unknown')
                                    )
                                
                                # Add confirmed mappings (just the CPE base string list)
                                entry['cpeSuggestions']['confirmedMappings'] = confirmed_mappings_data['confirmedMappings']
                                affected_entries_updated += 1
                                break
            
            if affected_entries_updated > 0:
                self.data_collected['confirmed_mappings'] = True
                
                # Track extension application
                if 'confirmed_mappings' not in self.processing_metadata.get('extensionsApplied', []):
                    self.processing_metadata['extensionsApplied'].append('confirmed_mappings')
                
                # Add data source tracking
                self.processing_metadata['dataSources'].append({
                    'type': 'confirmed_mappings_registry',
                    'source': self.attribution_source,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'description': f'Confirmed mappings from Platform Entry Notification Registry ({affected_entries_updated} entries)'
                })
                
                if logger:
                    logger.info(f"Integrated confirmed mappings from registry for {affected_entries_updated} affected entries in {self.current_cve_id}", group="data_processing")
            else:
                if logger:
                    logger.debug(f"No confirmed mappings data found in registry for {self.current_cve_id}", group="data_processing")
        
        except Exception as e:
            if logger:
                logger.error(f"Failed to integrate confirmed mappings from registry for {self.current_cve_id}: {e}", group="data_processing")
            # Continue processing other data as requested

    def _matches_table_index(self, entry: Dict, table_index: str) -> bool:
        """
        Check if an affected entry matches the given table index.
        
        The table_index from the Platform Entry Notification Registry corresponds
        to the row index during data processing, which should align with the
        entry_index used in the affected entry structure.
        
        Args:
            entry: Affected entry from enriched record data
            table_index: Table index from registry (string or int)
            
        Returns:
            bool: True if the entry matches the table index
        """
        try:
            # Check if entry has table index metadata
            if 'originAffectedEntry' in entry:
                origin_entry = entry['originAffectedEntry']
                
                # Match by cvelistv5AffectedEntryIndex which contains table position information
                entry_index_path = origin_entry.get('cvelistv5AffectedEntryIndex', '')
                
                # Extract numeric index from the affected entry path
                # Format: 'cve.containers.{type}.affected.[{index}]'
                if f'[{table_index}]' in entry_index_path:
                    return True
                
                # Extract the index number and compare directly
                import re
                match = re.search(r'\[(\d+)\]', entry_index_path)
                if match:
                    entry_index = match.group(1)
                    if str(table_index) == str(entry_index):
                        return True
            
            # Alternative: if the table_index is actually numeric, convert and match by position
            # This handles cases where registry uses 0, 1, 2... and entries are in order
            try:
                table_idx_int = int(table_index)
                # This would require knowing the position in the affected entries list
                # For now, we'll rely on the explicit index matching above
            except (ValueError, TypeError):
                pass
            
            return False
            
        except Exception as e:
            if logger:
                logger.debug(f"Error matching table index {table_index} to entry: {e}", group="data_processing")
            return False
    
    def collect_cpe_as_generation_data(self, cpe_as_data: Dict) -> None:
        """
        Integrate CPE Applicability Statements data with proper attribution.
        
        Args:
            cpe_as_data: Extracted CPE-AS data from HTML or processing
        """
        if not self.current_cve_id or not self.config.get('enabled', True):
            return
        
        if not self.current_record:
            if logger:
                logger.warning(f"No base record available for CPE-AS integration: {self.current_cve_id}", group="data_processing")
            return
        
        try:
            if cpe_as_data and 'vulnerabilities' in self.current_record:
                cve_node = self.current_record['vulnerabilities'][0]['cve']
                
                if 'enhanced_data' not in cve_node:
                    cve_node['enhanced_data'] = {}
                
                cve_node['enhanced_data']['cpe_applicability_statements'] = {
                    'source': self.attribution_source,
                    'attribution': 'analysis_tools.cpe_as_generation',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'data': cpe_as_data
                }
                
                # Track extension application
                self.processing_metadata['extensionsApplied'].append('cpe_applicability_statements')
                self.processing_metadata['dataSources'].append({
                    'type': 'cpe_as_generation',
                    'source': self.attribution_source,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'description': 'CPE Applicability Statements'
                })
                
                self.data_collected['cpe_as_generation'] = True
                
                if logger:
                    logger.debug(f"Integrated CPE-AS data for {self.current_cve_id}", group="data_processing")
        
        except Exception as e:
            if logger:
                logger.error(f"Failed to integrate CPE-AS data for {self.current_cve_id}: {e}", group="data_processing")
            # Continue processing other data as requested

    def collect_alias_extraction_from_registry(self, registry_instance=None) -> None:
        """
        Integrate Alias Extraction from Badge Contents Collector.
        
        This method extracts alias data from the badge contents collector that has already
        processed and structured the PENR data. This ensures proper integration with the
        existing alias extraction infrastructure rather than duplicating processing logic.
        
        Args:
            registry_instance: Registry instance (used for compatibility but not primary source)
        """
        if logger:
            logger.debug(f"DEBUG: Starting collect_alias_extraction_from_registry for {self.current_cve_id}", group="data_processing")
            
        if not self.current_cve_id or not self.config.get('enabled', True):
            if logger:
                logger.debug(f"DEBUG: Skipping alias extraction - current_cve_id: {self.current_cve_id}, enabled: {self.config.get('enabled', True)}", group="data_processing")
            return

        try:
            # Import the badge contents collector to get processed alias data
            from ..logging.badge_contents_collector import get_badge_contents_collector
            
            badge_collector = get_badge_contents_collector()
            if not badge_collector or not badge_collector.current_cve_data:
                if logger:
                    logger.debug(f"No badge contents collector data available for alias extraction in {self.current_cve_id}", group="data_processing")
                return
            
            # Get structured alias extraction data from badge contents collector
            alias_extractions = badge_collector.current_cve_data.get('alias_extractions', [])
            
            if logger:
                logger.debug(f"Badge contents collector has {len(alias_extractions)} alias extraction entries", group="data_processing")
                # Debug: Log full badge collector data structure for entry 3
                if alias_extractions and len(alias_extractions) > 3:
                    entry_3_data = alias_extractions[3]
                    logger.debug(f"DEBUG: Entry 3 alias data - table_index: {entry_3_data.get('table_index')}, entry_count: {entry_3_data.get('entry_count')}, alias_data_keys: {list(entry_3_data.get('alias_data', {}).keys())}", group="data_processing")
            
            if not alias_extractions:
                if logger:
                    logger.debug(f"No alias extraction data in badge contents collector for {self.current_cve_id}", group="data_processing")
                    # Debug: Log what IS available in the badge collector
                    if badge_collector.current_cve_data:
                        available_keys = list(badge_collector.current_cve_data.keys())
                        logger.debug(f"DEBUG: Available keys in badge collector current_cve_data: {available_keys}", group="data_processing")
                    else:
                        logger.debug(f"DEBUG: Badge collector current_cve_data is None", group="data_processing")
                return
            
            # Process each affected entry to match with badge collector alias data
            affected_entries_updated = 0
            
            if 'cveListV5AffectedEntries' in self.enriched_record_data:
                for entry_index, entry in enumerate(self.enriched_record_data['cveListV5AffectedEntries']):
                    # Use the enumerated position as the table_index since this matches
                    # the dataframe iterrows() index used during alias extraction
                    table_index = entry_index
                    
                    if logger:
                        origin_entry = entry.get('originAffectedEntry', {})
                        vendor = origin_entry.get('vendor', 'Unknown')
                        product = origin_entry.get('product', 'Unknown')
                        logger.debug(f"Processing entry {entry_index} ({vendor}/{product}) for alias extraction matching", group="data_processing")
                    
                    # Find matching alias extraction data from badge contents collector
                    matching_alias_data = None
                    for alias_entry in alias_extractions:
                        if alias_entry.get('table_index') == table_index:
                            matching_alias_data = alias_entry
                            break
                    
                    if matching_alias_data:
                        # Extract and filter alias data for nvd-ish record
                        alias_data_dict = matching_alias_data.get('alias_data', {})
                        entry_aliases = []
                        
                        # Convert badge collector format to nvd-ish record format
                        for alias_key, alias_details in alias_data_dict.items():
                            filtered_alias = self._filter_badge_collector_alias_data(alias_details)
                            if filtered_alias:
                                entry_aliases.append(filtered_alias)
                        
                        if entry_aliases:
                            # Get the original cvelistv5AffectedEntryIndex from the entry
                            origin_entry = entry.get('originAffectedEntry', {})
                            entry_index_path = origin_entry.get('cvelistv5AffectedEntryIndex', f'unknown_index_{entry_index}')
                            
                            # Get tool identification information following documented format
                            tool_name = self.config.get('tool_name', 'Hashmire/Analysis_Tools')
                            tool_version = self.config.get('tool_version', '0.2.0')
                            source_id = f"{tool_name} v{tool_version}"
                            
                            entry['aliasExtraction'] = {
                                'sourceId': source_id,
                                'cvelistv5AffectedEntryIndex': entry_index_path,
                                'aliases': entry_aliases
                            }
                            
                            affected_entries_updated += 1
                            
                            if logger:
                                logger.debug(f"Added {len(entry_aliases)} filtered aliases for table_index {table_index}", group="data_processing")
            
            if affected_entries_updated > 0:
                self.data_collected['alias_extraction'] = True
                
                # Track extension application
                if 'alias_extraction' not in self.processing_metadata.get('extensionsApplied', []):
                    self.processing_metadata['extensionsApplied'].append('alias_extraction')
                
                # Add data source tracking
                self.processing_metadata['dataSources'].append({
                    'type': 'alias_extraction_badge_collector',
                    'source': self.attribution_source,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'description': f'Alias extraction from Badge Contents Collector ({affected_entries_updated} entries)'
                })
                
                if logger:
                    logger.info(f"Successfully integrated alias extraction from registry for {self.current_cve_id}: {affected_entries_updated} entries updated", group="data_processing")
            else:
                if logger:
                    logger.debug(f"No alias data found for any affected entries in {self.current_cve_id}", group="data_processing")
        
        except Exception as e:
            if logger:
                logger.error(f"Failed to integrate alias extraction from badge contents collector for {self.current_cve_id}: {e}", group="data_processing")
            # Continue processing other data as requested
        except Exception as e:
            if logger:
                logger.error(f"Failed to integrate alias extraction from registry for {self.current_cve_id}: {e}", group="data_processing")
            # Continue processing - this is not a critical failure

    def _filter_badge_collector_alias_data(self, alias_data: Dict) -> Optional[Dict]:
        """
        Filter alias data from badge contents collector format for nvd-ish records.
        
        Applies comprehensive placeholder filtering to ensure only meaningful alias data
        is included in the final NVD-ish records, matching the filtering patterns used
        in the alias extraction report functionality.
        
        Args:
            alias_data: Raw alias data from badge contents collector
            
        Returns:
            Filtered alias data dict or None if no valid data remains after filtering
        """
        if not isinstance(alias_data, dict):
            return None
        
        # Fields to exclude from individual CVE records (report-specific metadata)
        excluded_fields = {'source_cve', '_alias_key'}
        
        # Apply placeholder filtering using the same patterns as the curator system
        filtered = {}
        
        for key, value in alias_data.items():
            # Skip report metadata fields
            if key in excluded_fields:
                continue
                
            # Apply placeholder filtering based on value type
            if isinstance(value, list):
                # Filter placeholder values from arrays
                meaningful_values = [v for v in value if not self._is_placeholder_value(v)]
                if meaningful_values:
                    filtered[key] = meaningful_values
                # If all values in array are placeholders, exclude the entire field
            elif not self._is_placeholder_value(value):
                # Include only non-placeholder string values
                filtered[key] = value
            # If value is placeholder, exclude the entire field
        
        # Only return if we have meaningful content after placeholder filtering
        if filtered and any(v for v in filtered.values() if v):
            return filtered
        
        return None

    def _is_placeholder_value(self, value) -> bool:
        """
        Check if a value is considered a placeholder using the centralized patterns
        from the badge modal system.
        
        Args:
            value: The value to check
            
        Returns:
            True if the value is a placeholder, False otherwise
            
        Raises:
            RuntimeError: If centralized placeholder patterns cannot be loaded (fail fast)
        """
        if not value or value in [None, "", 0]:
            return True
            
        # Convert to string and normalize for checking
        str_value = str(value).lower().strip()
        
        # Import and use the centralized placeholder patterns - fail fast if unavailable
        try:
            from ..core.badge_modal_system import GENERAL_PLACEHOLDER_VALUES
            return str_value in [pattern.lower() for pattern in GENERAL_PLACEHOLDER_VALUES]
        except ImportError as e:
            # Fail fast - no fallback patterns as this is critical infrastructure
            raise RuntimeError(f"Failed to import centralized placeholder patterns: {e}. This is a critical system dependency.")

    def collect_tool_execution_metadata(self, execution_metadata: Dict) -> None:
        """
        Collect tool execution metadata with per-argument timestamps.
        
        Args:
            execution_metadata: Tool execution timestamps and parameters
        """
        if not self.config.get('enabled', True):
            return
        
        try:
            # Start with existing metadata (preserves previous timestamps)
            existing_metadata = self.enriched_record_data.get('toolExecutionMetadata', {})
            
            # Update toolName and toolVersion (these can change)
            tool_metadata = dict(existing_metadata)
            tool_metadata.update({
                'toolName': self.config.get('tool_name', 'Hashmire/Analysis_Tools'),
                'toolVersion': self.config.get('tool_version', '0.2.0')
            })
            
            # Add/update per-argument timestamps if provided
            timestamp_fields = [
                'sourceDataConcerns', 'cpeSuggestions', 'cpeAsGenerationRules',
                'cpeSuggestionMetadata', 'aliasExtraction'
            ]
            
            new_timestamps_added = 0
            for field in timestamp_fields:
                if field in execution_metadata:
                    tool_metadata[field] = execution_metadata[field]
                    new_timestamps_added += 1
            
            # Store merged metadata in enhanced record structure
            self.enriched_record_data['toolExecutionMetadata'] = tool_metadata
            self.data_collected['tool_execution_metadata'] = True
            
            if logger:
                total_timestamps = len([k for k in tool_metadata.keys() if k not in ['toolName', 'toolVersion']])
                logger.debug(f"Collected tool execution metadata for {self.current_cve_id} (+{new_timestamps_added} new, {total_timestamps} total timestamps)", group="data_processing")
        
        except Exception as e:
            if logger:
                logger.error(f"Failed to collect tool execution metadata for {self.current_cve_id}: {e}", group="data_processing")
    
    def complete_cve_processing(self) -> bool:
        """
        Complete processing for current CVE and save enhanced record to file.
        Uses atomic file operations to prevent corruption during multi-stage updates.
        
        Enhanced records require BOTH NVD 2.0 and CVE List V5 data sources.
        
        Returns:
            True if save successful, False otherwise
        """
        if not self.current_cve_id or not self.config.get('enabled', True):
            return False
        
        if not self.current_record:
            if logger:
                logger.warning(f"No record to save for {self.current_cve_id}", group="data_processing")
            return False
        
        # VALIDATION: Enhanced records require BOTH data sources
        has_nvd_data = self.data_collected.get('nvd_base', False)
        has_cve_list_data = self.data_collected.get('cve_list_v5', False)
        
        if not (has_nvd_data and has_cve_list_data):
            missing_sources = []
            if not has_nvd_data:
                missing_sources.append('NVD 2.0')
            if not has_cve_list_data:
                missing_sources.append('CVE List V5')
            
            error_msg = f"Enhanced record creation requires BOTH data sources. Missing: {', '.join(missing_sources)} for {self.current_cve_id}"
            if logger:
                logger.error(error_msg, group="data_processing")
            
            # Fail fast - do not create partial records
            raise RuntimeError(f"Dual-source validation failed: {error_msg}")
        
        if logger:
            logger.debug(f"Dual-source validation passed for {self.current_cve_id}: NVD 2.0 ✓, CVE List V5 ✓", group="data_processing")
        
        try:
            # Create individual CVE entry (not wrapped in vulnerabilities array)
            if 'vulnerabilities' in self.current_record and len(self.current_record['vulnerabilities']) > 0:
                cve_entry = self.current_record['vulnerabilities'][0]['cve'].copy()
                
                # Remove temporary enhanced_data structure
                if 'enhanced_data' in cve_entry:
                    cve_entry.pop('enhanced_data')
                
                # Build the documented enrichedCVEv5Affected structure
                enriched_cve_v5_affected = self.enriched_record_data.copy()
                
                # Apply source alias resolution to Section II.C entries
                nvd_source_identifier = cve_entry.get('sourceIdentifier')
                resolved_cache = {}  # Cache resolutions to avoid duplicate work and logging
                
                for analysis_entry in enriched_cve_v5_affected['cveListV5AffectedEntries']:
                    if 'originAffectedEntry' in analysis_entry and 'sourceId' in analysis_entry['originAffectedEntry']:
                        original_source = analysis_entry['originAffectedEntry']['sourceId']
                        
                        # Check cache first to avoid duplicate resolution and logging
                        if original_source in resolved_cache:
                            resolved_source = resolved_cache[original_source]
                        else:
                            resolved_source = self.resolve_source_alias(original_source, nvd_source_identifier)
                            resolved_cache[original_source] = resolved_source
                        
                        # Update the sourceId with resolved value
                        analysis_entry['originAffectedEntry']['sourceId'] = resolved_source
                
                # Create ordered structure with enrichedCVEv5Affected positioned between weaknesses and configurations
                ordered_entry = {}
                
                # Standard NVD 2.0 field order up to weaknesses
                for field in ['id', 'sourceIdentifier', 'published', 'lastModified', 'vulnStatus', 'cveTags', 
                              'descriptions', 'metrics', 'weaknesses']:
                    if field in cve_entry:
                        ordered_entry[field] = cve_entry[field]
                
                # Insert enrichedCVEv5Affected between weaknesses and configurations per documented format
                ordered_entry['enrichedCVEv5Affected'] = enriched_cve_v5_affected
                
                # Add remaining fields (configurations, references, etc.)
                for field in ['configurations', 'references']:
                    if field in cve_entry:
                        ordered_entry[field] = cve_entry[field]
                
                # Add any other fields that might exist
                for field, value in cve_entry.items():
                    if field not in ordered_entry:
                        ordered_entry[field] = value
                
                # Note: toolExecutionMetadata should only exist within enrichedCVEv5Affected, not at root level
                
                # Set the output record to be just the individual CVE entry
                self.current_record = ordered_entry
            
            # Determine output file path using existing cache structure
            output_file = self._get_output_file_path(self.current_cve_id)
            if not output_file:
                if logger:
                    logger.error(f"Could not determine output path for {self.current_cve_id}", group="data_processing")
                return False
            
            # Ensure parent directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Use atomic file write to prevent corruption
            success = self._atomic_file_write(output_file, self.current_record)
            
            if success and logger:
                extensions = ', '.join(self.processing_metadata.get('extensionsApplied', []))
                logger.info(f"Saved enhanced NVD record: {self.current_cve_id} (extensions: {extensions})", group="data_processing")
            
            return success
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to save enhanced record for {self.current_cve_id}: {e}", group="data_processing")
            return False
        finally:
            # Reset state for next CVE
            self.current_cve_id = None
            self.current_record = None
            self.processing_metadata = {}
    
    def _extract_cve_list_affected_arrays(self, cve_list_data: Dict) -> List[Dict]:
        """Extract affected arrays from CVE List V5 structure with proper source attribution"""
        affected_arrays = []
        
        try:
            if 'containers' in cve_list_data:
                for container_key, container_data in cve_list_data['containers'].items():
                    if container_key == 'adp' and isinstance(container_data, list):
                        # ADP is an array of containers
                        for adp_index, adp_container in enumerate(container_data):
                            if isinstance(adp_container, dict) and 'affected' in adp_container:
                                # Get the source orgId from this ADP container's providerMetadata
                                source_org_id = 'unknown_source'
                                if 'providerMetadata' in adp_container:
                                    source_org_id = adp_container['providerMetadata'].get('orgId', 'unknown_source')
                                
                                # Add source attribution and container metadata to each affected entry from this ADP container
                                for entry_index, affected_entry in enumerate(adp_container['affected']):
                                    affected_with_source = affected_entry.copy()
                                    affected_with_source['source'] = source_org_id
                                    affected_with_source['container_type'] = f'adp[{adp_index}]'
                                    affected_with_source['entry_index'] = entry_index
                                    affected_arrays.append(affected_with_source)
                    elif isinstance(container_data, dict) and 'affected' in container_data:
                        # Regular container (like CNA)
                        # Get the source orgId from this container's providerMetadata
                        source_org_id = 'unknown_source'
                        if 'providerMetadata' in container_data:
                            source_org_id = container_data['providerMetadata'].get('orgId', 'unknown_source')
                        
                        # Add source attribution and container metadata to each affected entry
                        for entry_index, affected_entry in enumerate(container_data['affected']):
                            affected_with_source = affected_entry.copy()
                            affected_with_source['source'] = source_org_id
                            affected_with_source['container_type'] = container_key
                            affected_with_source['entry_index'] = entry_index
                            affected_arrays.append(affected_with_source)
        except Exception as e:
            if logger:
                logger.debug(f"Error extracting CVE List V5 affected arrays: {e}", group="data_processing")
        
        return affected_arrays
    
    def _extract_source_attribution(self, cve_list_data: Dict) -> str:
        """Extract source attribution from CVE List V5 providerMetadata"""
        try:
            if 'containers' in cve_list_data:
                for container_data in cve_list_data['containers'].values():
                    if isinstance(container_data, dict) and 'providerMetadata' in container_data:
                        org_id = container_data['providerMetadata'].get('orgId')
                        if org_id:
                            return org_id
        except Exception:
            pass
        
        return 'unknown_source'
    
    def _get_output_file_path(self, cve_id: str) -> Optional[Path]:
        """Get output file path using existing cache directory structure"""
        try:
            # Use existing cache resolution logic if available
            if _resolve_cve_cache_file_path:
                resolved_path = _resolve_cve_cache_file_path(cve_id, str(self.output_path))
                if resolved_path:
                    return Path(resolved_path)
            
            # Fallback to manual path construction
            # Format: cache/nvd-ish_2.0_cves/YYYY/Xxxx/CVE-YYYY-NNNNN.json
            parts = cve_id.split('-')
            if len(parts) == 3 and parts[0] == 'CVE':
                year = parts[1]
                sequence = parts[2]
                
                # Create directory name based on sequence length (matching NVD cache structure)
                if len(sequence) == 4:
                    subdir = f"{sequence[0]}xxx"
                elif len(sequence) == 5:
                    subdir = f"{sequence[:2]}xxx"
                elif len(sequence) >= 6:
                    subdir = f"{sequence[:3]}xxx"
                else:
                    return None
                
                return self.output_path / year / subdir / f"{cve_id}.json"
            
        except Exception as e:
            if logger:
                logger.error(f"Error determining output path for {cve_id}: {e}", group="data_processing")
        
        return None
    
    def _load_existing_tool_metadata(self, cve_id: str) -> Dict:
        """
        Load existing toolExecutionMetadata from saved file to preserve timestamps across runs.
        
        Args:
            cve_id: CVE identifier to load metadata for
            
        Returns:
            Dict containing existing toolExecutionMetadata, or empty dict if none found
        """
        try:
            output_file = self._get_output_file_path(cve_id)
            if output_file and output_file.exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    existing_record = json.load(f)
                    # Look for toolExecutionMetadata in the correct location: enrichedCVEv5Affected
                    enriched_data = existing_record.get('enrichedCVEv5Affected', {})
                    existing_metadata = enriched_data.get('toolExecutionMetadata', {})
                    if existing_metadata:
                        if logger:
                            logger.debug(f"Loaded existing toolExecutionMetadata for {cve_id} with {len(existing_metadata)-2} timestamp fields", group="data_processing")
                        return existing_metadata
        except Exception as e:
            if logger:
                logger.debug(f"No existing toolExecutionMetadata found for {cve_id}: {e}", group="data_processing")
        
        return {}
    
    def _atomic_file_write(self, file_path: Path, data: Dict) -> bool:
        """
        Atomic file write to prevent corruption during updates.
        Uses temporary file + move operation for safety.
        """
        try:
            # Create temporary file in same directory
            temp_fd, temp_path = tempfile.mkstemp(
                suffix='.tmp', 
                prefix=f'{file_path.stem}_',
                dir=file_path.parent
            )
            
            try:
                # Write data to temporary file
                with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                # Atomic move to final location
                shutil.move(temp_path, file_path)
                return True
                
            except Exception:
                # Clean up temporary file on error
                try:
                    os.unlink(temp_path)
                except:
                    pass
                raise
                
        except Exception as e:
            if logger:
                logger.error(f"Atomic file write failed for {file_path}: {e}", group="data_processing")
            return False


# Global collector instance
_global_nvd_ish_collector = None


def get_nvd_ish_collector() -> NVDishCollector:
    """Get the global NVD-ish collector instance"""
    global _global_nvd_ish_collector
    if _global_nvd_ish_collector is None:
        _global_nvd_ish_collector = NVDishCollector()
    return _global_nvd_ish_collector


def reset_nvd_ish_collector() -> None:
    """Reset the global collector (for testing)"""
    global _global_nvd_ish_collector
    _global_nvd_ish_collector = None


# Convenience functions for easy integration
def start_cve_collection(cve_id: str) -> None:
    """Start enhanced record collection for a CVE"""
    get_nvd_ish_collector().start_cve_processing(cve_id)


def collect_nvd_base(nvd_record_data: Dict) -> None:
    """Collect NVD base record"""
    get_nvd_ish_collector().collect_nvd_base_record(nvd_record_data)


def collect_cve_list_v5(cve_list_data: Dict, source_attribution: Optional[str] = None) -> None:
    """Collect CVE List V5 data"""
    get_nvd_ish_collector().collect_cve_list_v5_data(cve_list_data, source_attribution)


def collect_source_data_concerns_from_registry(registry_instance=None) -> None:
    """Collect Source Data Concerns from Platform Entry Notification Registry"""
    get_nvd_ish_collector().collect_source_data_concerns_from_registry(registry_instance)


def collect_sdc_report(sdc_concerns_data: Dict, affected_entry_mapping: Optional[Dict] = None) -> None:
    """Collect SDC report data"""
    get_nvd_ish_collector().collect_sdc_report_data(sdc_concerns_data, affected_entry_mapping)


def collect_cpe_suggestions(cpe_suggestions_data: Dict) -> None:
    """Collect CPE suggestions data"""
    get_nvd_ish_collector().collect_cpe_suggestions_data(cpe_suggestions_data)


def collect_cpe_suggestions_from_registry(registry_instance=None) -> None:
    """Collect CPE suggestions data from Platform Entry Notification Registry"""
    get_nvd_ish_collector().collect_cpe_suggestions_from_registry(registry_instance)


def collect_confirmed_mappings_from_registry(registry_instance=None) -> None:
    """Collect confirmed mappings data from Platform Entry Notification Registry"""
    get_nvd_ish_collector().collect_confirmed_mappings_from_registry(registry_instance)


def collect_alias_extraction_from_registry(registry_instance=None) -> None:
    """Collect alias extraction data from Platform Entry Notification Registry"""
    get_nvd_ish_collector().collect_alias_extraction_from_registry(registry_instance)


def collect_cpe_as_generation(cpe_as_data: Dict) -> None:
    """Collect CPE-AS generation data"""
    get_nvd_ish_collector().collect_cpe_as_generation_data(cpe_as_data)


def collect_tool_execution_metadata(execution_metadata: Dict) -> None:
    """Collect tool execution metadata"""
    get_nvd_ish_collector().collect_tool_execution_metadata(execution_metadata)


def complete_cve_collection() -> bool:
    """Complete and save enhanced record"""
    return get_nvd_ish_collector().complete_cve_processing()
