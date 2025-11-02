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
from datetime import datetime
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
            'nvdBase': False,
            'cveListV5': False,
            'sdcReport': False,
            'cpeSuggestions': False,
            'cpeAsGeneration': False
        }
        
        # Ensure output directory exists
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        if logger:
            logger.info("NVD-ish collector initialized", group="initialization")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load nvd_ish_output configuration from config.json"""
        try:
            # Import here to avoid circular dependencies
            from pathlib import Path
            import json
            
            config_path = Path(__file__).parent.parent / "config.json"
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            return config_data.get('nvd_ish_output', {})
            
        except Exception as e:
            if logger:
                logger.warning(f"Failed to load nvd_ish_output config, using defaults: {e}", group="initialization")
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
                        # COLLISION DETECTED: UUID found but doesn't map to this CVE's NVD sourceIdentifier
                        if logger:
                            logger.warning(f"COLLISION DETECTED - enrichedCVEv5Affected source {source_id} maps to {identifiers} but NVD uses {nvd_source_identifier} - keeping original UUID", group="data_processing")
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
            'processingStarted': datetime.now().isoformat(),
            'processingCompleted': None,
            'dataSources': [],
            'extensionsApplied': []
        }
        
        # Reset data collection state
        for key in self.data_collected:
            self.data_collected[key] = False
        
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
            
            # Deep copy to avoid modifying original data
            import copy
            self.current_record = copy.deepcopy(nvd_record_data)
            
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
                    'processing_timestamp': datetime.now().isoformat() + 'Z',
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
                'timestamp': datetime.now().isoformat(),
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
            "timestamp": datetime.utcnow().isoformat() + 'Z',
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
                    
                    # Store affected data with individual source attributions already embedded
                    cve_node['enhanced_data']['cve_list_v5_affected'] = {
                        'attribution': 'containers.*.affected (CNA + ADP)',
                        'timestamp': datetime.now().isoformat(),
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
                            'timestamp': datetime.now().isoformat(),
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
                    'timestamp': datetime.now().isoformat(),
                    'data': sdc_concerns_data,
                    'affected_entry_mapping': affected_entry_mapping
                }
                
                # Track extension application
                self.processing_metadata['extensions_applied'].append('source_data_concerns')
                self.processing_metadata['data_sources'].append({
                    'type': 'sdc_report',
                    'source': self.attribution_source,
                    'timestamp': datetime.now().isoformat(),
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
                
                cve_node['enhanced_data']['cpe_enhancements'] = {
                    'source': self.attribution_source,
                    'attribution': 'analysis_tools.cpe_suggestions',
                    'timestamp': datetime.now().isoformat(),
                    'data': cpe_suggestions_data
                }
                
                # Track extension application
                self.processing_metadata['extensions_applied'].append('cpe_enhancements')
                self.processing_metadata['data_sources'].append({
                    'type': 'cpe_suggestions',
                    'source': self.attribution_source,
                    'timestamp': datetime.now().isoformat(),
                    'description': 'CPE suggestions and NVD API results'
                })
                
                self.data_collected['cpe_suggestions'] = True
                
                if logger:
                    logger.debug(f"Integrated CPE suggestions data for {self.current_cve_id}", group="data_processing")
        
        except Exception as e:
            if logger:
                logger.error(f"Failed to integrate CPE suggestions for {self.current_cve_id}: {e}", group="data_processing")
            # Continue processing other data as requested
    
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
                    'timestamp': datetime.now().isoformat(),
                    'data': cpe_as_data
                }
                
                # Track extension application
                self.processing_metadata['extensions_applied'].append('cpe_applicability_statements')
                self.processing_metadata['data_sources'].append({
                    'type': 'cpe_as_generation',
                    'source': self.attribution_source,
                    'timestamp': datetime.now().isoformat(),
                    'description': 'CPE Applicability Statements'
                })
                
                self.data_collected['cpe_as_generation'] = True
                
                if logger:
                    logger.debug(f"Integrated CPE-AS data for {self.current_cve_id}", group="data_processing")
        
        except Exception as e:
            if logger:
                logger.error(f"Failed to integrate CPE-AS data for {self.current_cve_id}: {e}", group="data_processing")
            # Continue processing other data as requested
    
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
                
                # Remove the enhanced_data structure and integrate enriched data directly into CVE entry
                enriched_affected = None
                if 'enhanced_data' in cve_entry:
                    enhanced_data = cve_entry.pop('enhanced_data')
                    
                    # Extract cve_list_v5_affected data for repositioning
                    if 'cve_list_v5_affected' in enhanced_data:
                        cve_list_data = enhanced_data['cve_list_v5_affected']
                        enriched_affected = cve_list_data.get('data', [])  # Each entry already has its container's orgId as 'source'
                        
                        # Apply source alias resolution to match NVD sourceIdentifier patterns
                        nvd_source_identifier = cve_entry.get('sourceIdentifier')
                        resolved_cache = {}  # Cache resolutions to avoid duplicate work and logging
                        
                        for entry in enriched_affected:
                            if 'source' in entry:
                                original_source = entry['source']
                                
                                # Check cache first to avoid duplicate resolution and logging
                                if original_source in resolved_cache:
                                    entry['source'] = resolved_cache[original_source]
                                else:
                                    resolved_source = self.resolve_source_alias(original_source, nvd_source_identifier)
                                    resolved_cache[original_source] = resolved_source
                                    entry['source'] = resolved_source
                
                # Create ordered structure with enrichedCVEv5Affected positioned between weaknesses and configurations
                if enriched_affected:
                    ordered_entry = {}
                    
                    # Standard NVD 2.0 field order up to weaknesses
                    for field in ['id', 'sourceIdentifier', 'published', 'lastModified', 'vulnStatus', 'cveTags', 
                                  'descriptions', 'metrics', 'weaknesses']:
                        if field in cve_entry:
                            ordered_entry[field] = cve_entry[field]
                    
                    # Insert enrichedCVEv5Affected between weaknesses and configurations
                    ordered_entry['enrichedCVEv5Affected'] = enriched_affected
                    
                    # Add remaining fields (configurations, references, etc.)
                    for field in ['configurations', 'references']:
                        if field in cve_entry:
                            ordered_entry[field] = cve_entry[field]
                    
                    # Add any other fields that might exist
                    for field, value in cve_entry.items():
                        if field not in ordered_entry:
                            ordered_entry[field] = value
                    
                    cve_entry = ordered_entry
                
                # Set the output record to be just the individual CVE entry
                self.current_record = cve_entry
            
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
                        for adp_container in container_data:
                            if isinstance(adp_container, dict) and 'affected' in adp_container:
                                # Get the source orgId from this ADP container's providerMetadata
                                source_org_id = 'unknown_source'
                                if 'providerMetadata' in adp_container:
                                    source_org_id = adp_container['providerMetadata'].get('orgId', 'unknown_source')
                                
                                # Add source attribution to each affected entry from this ADP container
                                for affected_entry in adp_container['affected']:
                                    affected_with_source = affected_entry.copy()
                                    affected_with_source['source'] = source_org_id
                                    affected_arrays.append(affected_with_source)
                    elif isinstance(container_data, dict) and 'affected' in container_data:
                        # Regular container (like CNA)
                        # Get the source orgId from this container's providerMetadata
                        source_org_id = 'unknown_source'
                        if 'providerMetadata' in container_data:
                            source_org_id = container_data['providerMetadata'].get('orgId', 'unknown_source')
                        
                        # Add source attribution to each affected entry from this container
                        for affected_entry in container_data['affected']:
                            affected_with_source = affected_entry.copy()
                            affected_with_source['source'] = source_org_id
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
            if len(parts) >= 3:
                year = parts[1]
                number = parts[2]
                
                # Determine subdirectory based on number
                if number.startswith('0'):
                    subdir = '0xxx'
                elif number.startswith('1'):
                    subdir = '1xxx'
                else:
                    # For numbers >= 20000, use appropriate subdirectory
                    subdir = f"{number[0]}xxx"
                
                return self.output_path / year / subdir / f"{cve_id}.json"
            
        except Exception as e:
            if logger:
                logger.error(f"Error determining output path for {cve_id}: {e}", group="data_processing")
        
        return None
    
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


def collect_sdc_report(sdc_concerns_data: Dict, affected_entry_mapping: Optional[Dict] = None) -> None:
    """Collect SDC report data"""
    get_nvd_ish_collector().collect_sdc_report_data(sdc_concerns_data, affected_entry_mapping)


def collect_cpe_suggestions(cpe_suggestions_data: Dict) -> None:
    """Collect CPE suggestions data"""
    get_nvd_ish_collector().collect_cpe_suggestions_data(cpe_suggestions_data)


def collect_cpe_as_generation(cpe_as_data: Dict) -> None:
    """Collect CPE-AS generation data"""
    get_nvd_ish_collector().collect_cpe_as_generation_data(cpe_as_data)


def complete_cve_collection() -> bool:
    """Complete and save enhanced record"""
    return get_nvd_ish_collector().complete_cve_processing()