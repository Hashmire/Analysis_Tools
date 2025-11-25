#!/usr/bin/env python3
"""
Badge Contents Collection System

Simple implementation to collect Platform Entry Notification badge contents
during the main processing pipeline and export to JSON reports
in the existing logs directory structure.

SCOPE: Platform Entry Notifications - Source Data Concerns AND Alias Extraction

SCHEMA STRUCTURE:
{
  "metadata": {
    "run_started_at": "ISO timestamp",
    "total_cves_processed": int,
    "total_platform_entries": int, 
    "entries_with_concerns": int,
    "concern_type_counts": [{"concern_type": "key", "count": int}],
    "status": "in_progress|completed|completed_no_concerns"
  },
  "cve_data": [
    {
      "cve_id": "CVE-YYYY-XXXXX",
      "platform_entries": [
        {
          "platform_entry_id": "entry_N",
          "table_index": int,
          "source_id": "uuid",
          "source_name": "Human Readable Name",
          "total_concerns": int,
          "concern_types": ["concernKey1", "concernKey2"],
          "concern_breakdown": {"concernKey": count},
          "concerns_detail": [
            {
              "concern_type": "concernKey",
              "concerns": [{"field": "...", "value": "...", "context": "...", "message": "..."}]
            }
          ]
        }
      ],
      "cve_metadata": {
        "total_platform_entries": int,
        "entries_with_concerns": int,
        "concern_type_counts": [{"concern_type": "key", "count": int}],
        "processing_timestamp": "ISO timestamp"
      }
    }
  ]
}
"""

import json
import os
import re
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from pathlib import Path

# Import the structured logging system
try:
    from .workflow_logger import get_logger, LogGroup
    logger = get_logger()
except ImportError:
    # Fallback for testing environments
    logger = None

# Import the global source manager for UUID to name resolution
try:
    from ..storage.nvd_source_manager import get_source_name
except ImportError:
    get_source_name = None

# Import confirmed mappings loader from gatherData
try:
    from ..core.gatherData import load_confirmed_mappings_for_uuid
except ImportError:
    load_confirmed_mappings_for_uuid = None

class BadgeContentsCollector:
    """
    Collects Platform Entry Notification badge contents during badge generation.
    Accumulates data across multiple CVEs and exports consolidated JSON report.
    """
    
    def __init__(self):
        self.cve_data: List[Dict] = []  # Array of CVE data objects
        self.consolidated_metadata: Dict[str, Any] = {
            'run_started_at': datetime.now(timezone.utc).isoformat(),
            'total_cves_processed': 0,
            'total_platform_entries': 0,
            'entries_with_concerns': 0,
            'concern_type_counts': []
        }
        self.current_cve_data: Optional[Dict] = None
        self.output_file_path: Optional[str] = None
        
        # Alias report configuration tracking for incremental saves
        self.alias_report_enabled: bool = False
        self.alias_report_source_uuid: Optional[str] = None
        self.alias_report_logs_directory: Optional[str] = None
        
        # NVD-ish only mode configuration for memory optimization
        self.nvd_ish_only_mode: bool = False
        
        # Frequency control for intelligent save operations (aligned with dataset collector)
        self._save_counter = 0
        self._last_save_time = datetime.now(timezone.utc)
        self._save_interval_seconds = 5  # Save every 5 seconds at most
        self._save_every_n_operations = 100  # Or every 100 operations
    
    def configure_alias_reporting(self, logs_directory: str, source_uuid: str) -> None:
        """
        Configure alias reporting for incremental saves during CVE processing.
        
        Args:
            logs_directory: Directory to save alias reports
            source_uuid: Source UUID for alias extraction targeting
        """
        self.alias_report_enabled = True
        self.alias_report_logs_directory = logs_directory
        self.alias_report_source_uuid = source_uuid
        
        if logger:
            logger.info("Badge contents collector configured for alias report incremental saves", group="initialization")
    
    def configure_nvd_ish_only_mode(self, enabled: bool = True) -> None:
        """
        Configure NVD-ish only mode for memory optimization.
        
        When enabled, skips cross-CVE data accumulation for reports while preserving
        per-CVE data collection for NVD-ish enrichment.
        
        Args:
            enabled: Whether to enable NVD-ish only mode
        """
        self.nvd_ish_only_mode = enabled
        
        if logger:
            if enabled:
                logger.info("Badge contents collector configured for NVD-ish only mode (memory optimized)", group="initialization")
            else:
                logger.info("Badge contents collector configured for standard mode (full reporting)", group="initialization")
    
    
    def initialize_output_file(self, logs_directory: str) -> bool:
        """
        Initialize the output JSON file for incremental updates.
        
        Args:
            logs_directory: Path to the logs directory
            
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            # Ensure logs directory exists
            os.makedirs(logs_directory, exist_ok=True)
            
            filename = "sourceDataConcernReport.json"
            self.output_file_path = os.path.join(logs_directory, filename)
            
            # Create initial file structure
            initial_data = {
                'metadata': {
                    **self.consolidated_metadata,
                    'last_updated': datetime.now(timezone.utc).isoformat(),
                    'report_scope': 'Platform Entry Notifications - Source Data Concerns Only',
                    'status': 'in_progress'
                },
                'cve_data': []
            }
            
            with open(self.output_file_path, 'w', encoding='utf-8') as f:
                json.dump(initial_data, f, indent=2, ensure_ascii=False)
            
            if logger:
                logger.info("Badge contents collector initialized", group="initialization")
            return True
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to initialize badge contents collector: {e}", group="initialization")
            return False
    
    def start_cve_processing(self, cve_id: str) -> None:
        """
        Initialize data collection for a new CVE.
        
        Args:
            cve_id: CVE identifier being processed
        """
        self.consolidated_metadata['total_cves_processed'] += 1
        
        # Create new CVE data object and add to array
        self.current_cve_data = {
            'cve_id': cve_id,
            'platform_entries': [],
            'cve_metadata': {
                'total_platform_entries': 0,
                'entries_with_concerns': 0,
                'concern_type_counts': [],
                'processing_timestamp': datetime.now(timezone.utc).isoformat()
            }
        }
        self.cve_data.append(self.current_cve_data)
    
    def complete_cve_processing(self) -> bool:
        """
        Complete processing for the current CVE and save to file.
        Also performs incremental alias report saves if alias reporting is enabled.
        
        Returns:
            True if save successful, False otherwise
        """
        # Check if we have valid CVE data for processing
        if not self.current_cve_data:
            return False
        
        # Perform intelligent SDC save (only if SDC output file is configured)
        sdc_save_success = True
        if self.output_file_path:
            # Use auto-save with frequency control for better performance
            self._auto_save()
            sdc_save_success = True  # Auto-save handles its own error logging
        
        # Perform incremental alias report save if enabled (independent of SDC)
        alias_save_success = True
        if self.alias_report_enabled and self.alias_report_logs_directory and self.alias_report_source_uuid:
            alias_save_success = self._save_incremental_alias_report()
        
        return sdc_save_success and alias_save_success
    
    def _save_to_file(self) -> bool:
        """
        Save current state to the JSON file using atomic write pattern.
        
        Returns:
            True if save successful, False otherwise
        """
        if not self.output_file_path:
            return False
        
        try:
            # Prepare current export data
            export_data = {
                'metadata': {
                    **self.consolidated_metadata,
                    'last_updated': datetime.now(timezone.utc).isoformat(),
                    'report_scope': 'Platform Entry Notifications - Source Data Concerns Only',
                    'status': 'in_progress'
                },
                'cve_data': self.cve_data
            }
            
            # Atomic write: Write to temporary file first, then rename
            os.makedirs(os.path.dirname(self.output_file_path), exist_ok=True)
            temp_file_path = self.output_file_path + '.tmp'
            
            with open(temp_file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            # Atomic rename - prevents readers from seeing partial/corrupted files
            os.replace(temp_file_path, self.output_file_path)
            
            return True
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to save badge contents: {e}", group="badge_generation")
            # Clean up temp file if it exists
            temp_file_path = self.output_file_path + '.tmp' if self.output_file_path else None
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except:
                    pass
            return False
    
    def _auto_save(self, force: bool = False) -> bool:
        """Auto-save data to file with intelligent frequency control (aligned with dataset collector)
        
        Args:
            force: If True, bypass frequency limits and save immediately
            
        Returns:
            True if save successful or skipped (no error), False on error
        """
        if not self.output_file_path:
            return False
            
        try:
            # Increment operation counter
            self._save_counter += 1
            
            # Check if we should save based on frequency controls
            now = datetime.now(timezone.utc)
            time_since_last_save = (now - self._last_save_time).total_seconds()
            
            # Enforce 5-second minimum to prevent I/O waste - primary check
            if time_since_last_save < self._save_interval_seconds and not force:
                return True  # Skip this save - too soon since last save (not an error)
            
            # Additional conditions that allow save (when 5+ seconds have passed or forced)
            should_save = (
                force or  # Forced save
                self._save_counter >= self._save_every_n_operations or  # Hit operation limit
                time_since_last_save >= self._save_interval_seconds  # Hit time limit
            )
            
            if not should_save:
                return True  # Skip this save (not an error)
            
            # Reset counters
            self._save_counter = 0
            self._last_save_time = now
            
            # Perform the save
            return self._save_to_file()
            
        except Exception as e:
            if logger:
                logger.error(f"Auto-save failed: {e}", group="badge_generation")
            return False
    
    def _save_incremental_alias_report(self) -> bool:
        """
        Save incremental alias extraction report during CVE processing.
        Uses the same logic as the final alias report generation but saves incrementally.
        
        Returns:
            True if save successful, False otherwise
        """
        if not self.alias_report_enabled or not self.alias_report_logs_directory or not self.alias_report_source_uuid:
            return True  # Not an error if alias reporting isn't configured
        
        try:
            # Use the existing generate_alias_extraction_report logic but call it incrementally
            alias_report_path = generate_alias_extraction_report(
                self.alias_report_logs_directory, 
                self.alias_report_source_uuid,
                is_final=False  # Mark as incremental save
            )
            
            # Log incremental saves at info level for visibility during large dataset processing
            if alias_report_path and logger:
                logger.info(f"Incremental alias report saved: {os.path.basename(alias_report_path)}", group="data_processing")
            
            return alias_report_path is not None
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to save incremental alias report: {e}", group="badge_generation")
            return False
    
    def collect_source_data_concern(self, table_index: int, source_id: str, vendor: str, product: str,
                                   concerns_data: Dict, concerns_count: int, concern_types: List[str]) -> None:
        """
        Collect Source Data Concerns badge contents during badge generation.
        
        Args:
            table_index: Table index for the platform entry
            source_id: Actual source UUID from the data
            vendor: Vendor name from the platform entry
            product: Product name from the platform entry
            concerns_data: Structured concerns data from badge generation
            concerns_count: Total number of concerns
            concern_types: List of concern type names
        """
        if not self.current_cve_data:
            if logger:
                logger.warning(f"No current CVE set for badge collection - table_index {table_index}", group="badge_generation")
            return
        
        # Validate input data integrity
        if not isinstance(concerns_data, dict):
            if logger:
                logger.error(f"Invalid concerns_data for table_index {table_index}: must be dictionary", group="badge_generation")
            return
            
        if concerns_count < 0:
            if logger:
                logger.error(f"Invalid concerns_count for table_index {table_index}: cannot be negative", group="badge_generation")
            return
        
        # Track consolidated statistics
        self.consolidated_metadata['total_platform_entries'] += 1
        self.current_cve_data['cve_metadata']['total_platform_entries'] += 1
        
        if concerns_count > 0:
            self.consolidated_metadata['entries_with_concerns'] += 1
            self.current_cve_data['cve_metadata']['entries_with_concerns'] += 1
            
            # Count concern types at consolidated level
            for concern_type in concern_types:
                self._increment_concern_type_count(self.consolidated_metadata['concern_type_counts'], concern_type)
            
            # Count concern types at CVE level
            for concern_type in concern_types:
                self._increment_concern_type_count(self.current_cve_data['cve_metadata']['concern_type_counts'], concern_type)
            
            # Convert concerns_data to array format
            concerns_detail_array = self._convert_concerns_to_array(concerns_data)
            
            # Resolve source ID to human-readable name
            source_name = 'Unknown Source'
            if get_source_name and source_id:
                resolved_name = get_source_name(source_id)
                if resolved_name:
                    source_name = resolved_name
                    if logger:
                        logger.debug(f"Source name resolved for concern entry: {source_id} -> {source_name}", group="badge_generation")
                else:
                    if logger:
                        logger.warning(f"Source name resolution failed for concern entry: {source_id}", group="badge_generation")
            else:
                if logger:
                    logger.warning(f"Source name resolution unavailable for concern entry: {source_id}", group="badge_generation")
            
            # Create platform entry object with normalized concern type keys
            concern_type_keys = [self._concern_type_to_key(ct) for ct in concern_types]
            platform_entry = {
                'platform_entry_id': f"entry_{table_index}",
                'table_index': table_index,
                'source_id': source_id,
                'source_name': source_name,  # Add human-readable name
                'vendor': vendor,
                'product': product,
                'total_concerns': concerns_count,
                'concern_types': concern_type_keys,  # Use normalized keys for consistency
                'concern_breakdown': {self._concern_type_to_key(ct): len(concerns_data.get(self._concern_type_to_key(ct), [])) 
                                    for ct in concern_types},
                'concerns_detail': concerns_detail_array
            }
            
            # Add to platform entries array
            self.current_cve_data['platform_entries'].append(platform_entry)
            
            # Trigger intelligent auto-save after collecting data
            self._auto_save()

    def collect_clean_platform_entry(self, source_id: str) -> None:
        """
        Collect a platform entry that has no source data concerns.
        
        Args:
            source_id: Actual source UUID from the data
        """
        if not self.current_cve_data:
            if logger:
                logger.warning(f"No current CVE set for clean platform entry collection - source_id {source_id}", group="badge_generation")
            return
            
        # Track consolidated statistics for clean entries
        self.consolidated_metadata['total_platform_entries'] += 1
        self.current_cve_data['cve_metadata']['total_platform_entries'] += 1
        
        # Initialize clean_platform_entries array if it doesn't exist
        if 'clean_platform_entries' not in self.current_cve_data:
            self.current_cve_data['clean_platform_entries'] = []
        
        # Check if we already have an entry for this source
        existing_entry = None
        for entry in self.current_cve_data['clean_platform_entries']:
            if entry['sourceID'] == source_id:
                existing_entry = entry
                break
        
        if existing_entry:
            # Increment count for existing source
            existing_entry['cleanPlatformCount'] += 1
        else:
            # Resolve source ID to human-readable name (same as concern entries)
            source_name = 'Unknown Source'
            if get_source_name and source_id:
                resolved_name = get_source_name(source_id)
                if resolved_name:
                    source_name = resolved_name
                    if logger:
                        logger.debug(f"Source name resolved for clean entry: {source_id} -> {source_name}", group="badge_generation")
                else:
                    if logger:
                        logger.warning(f"Source name resolution failed for clean entry: {source_id}", group="badge_generation")
            else:
                if logger:
                    logger.warning(f"Source name resolution unavailable for clean entry: {source_id}", group="badge_generation")
            
            # Create new entry for this source with resolved name
            self.current_cve_data['clean_platform_entries'].append({
                'sourceID': source_id,
                'source_name': source_name,  # Add human-readable name
                'cleanPlatformCount': 1
            })
            
        # Trigger intelligent auto-save after collecting data
        self._auto_save()

    def collect_alias_extraction(self, table_index: int, source_id: str, alias_data: Dict, 
                                entry_count: int, cve_id: str = None) -> None:
        """
        Collect Alias Extraction badge contents during badge generation.
        
        This function collects curator-style alias extraction data for the --alias-report
        functionality, following the exact same patterns as the curator system.
        
        Args:
            table_index: Table index for the platform entry
            source_id: Actual source UUID from the data
            alias_data: Dictionary containing alias extraction data from registry
            entry_count: Number of alias entries extracted (for platform expansion)
            cve_id: CVE identifier for source tracking
        """
        if not self.current_cve_data:
            if logger:
                logger.warning(f"No current CVE set for alias collection - table_index {table_index}", group="badge_generation")
            return
        
        # Validate input data integrity
        if not isinstance(alias_data, dict):
            if logger:
                logger.error(f"Invalid alias_data for table_index {table_index}: must be dictionary", group="badge_generation")
            return
            
        if entry_count < 0:
            if logger:
                logger.error(f"Invalid entry_count for table_index {table_index}: cannot be negative", group="badge_generation")
            return
        
        # Track consolidated statistics
        self.consolidated_metadata['total_platform_entries'] += 1
        self.current_cve_data['cve_metadata']['total_platform_entries'] += 1
        
        if entry_count > 0:
            # Initialize alias_extractions array if it doesn't exist
            if 'alias_extractions' not in self.current_cve_data:
                self.current_cve_data['alias_extractions'] = []
            
            # Resolve source ID to human-readable name (consistent with other collectors)
            source_name = 'Unknown Source'
            if get_source_name and source_id:
                resolved_name = get_source_name(source_id)
                if resolved_name:
                    source_name = resolved_name
                    if logger:
                        logger.debug(f"Source name resolved for alias entry: {source_id} -> {source_name}", group="badge_generation")
                else:
                    if logger:
                        logger.warning(f"Source name resolution failed for alias entry: {source_id}", group="badge_generation")
            else:
                if logger:
                    logger.warning(f"Source name resolution unavailable for alias entry: {source_id}", group="badge_generation")
            
            # Create platform entry object following curator patterns
            alias_entry = {
                'platform_entry_id': f"entry_{table_index}",
                'table_index': table_index,
                'source_id': source_id,
                'source_name': source_name,
                'cve_id': cve_id or 'Unknown',
                'entry_count': entry_count,  # Number of aliases extracted (platform expansion count)
                'alias_data': alias_data,    # The actual alias extraction data
                'extraction_timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Add to alias extractions array
            self.current_cve_data['alias_extractions'].append(alias_entry)
            
            # Trigger intelligent auto-save after collecting data
            self._auto_save()
            
            if logger:
                logger.debug(f"Collected alias extraction for table_index {table_index}: {entry_count} entries", group="badge_generation")

    def generate_alias_report(self, logs_directory: str, source_uuid: str, is_final: bool = False) -> Optional[str]:
        """
        Generate curator-compatible alias extraction report (aliasReport.json).
        
        This method creates the exact output format that the curator produces,
        enabling seamless integration with existing Analysis_Tools workflow.
        
        Args:
            logs_directory: Directory to save the alias report
            source_uuid: Source UUID for confirmed mappings matching
            
        Returns:
            Path to generated aliasReport.json file, or None if generation failed
        """
        # Skip report generation in NVD-ish only mode for memory optimization
        if self.nvd_ish_only_mode:
            if logger:
                logger.debug("Skipping alias report generation (NVD-ish only mode)", group="completion")
            return None
            
        try:
            # Collect all alias data from CVE processing
            all_alias_data = {}
            total_extractions = 0
            
            for cve_data in self.cve_data:
                if 'alias_extractions' in cve_data:
                    for extraction in cve_data['alias_extractions']:
                        alias_data = extraction.get('alias_data', {})
                        
                        # Process each alias entry (handling platform expansion)
                        for key, value in alias_data.items():
                            if isinstance(value, dict) and '_alias_key' in value:
                                # Use the curator-style alias key for deduplication
                                alias_key = value['_alias_key']
                                
                                if alias_key not in all_alias_data:
                                    # Create new alias entry without _alias_key (curator format)
                                    clean_alias = {k: v for k, v in value.items() if k != '_alias_key'}
                                    all_alias_data[alias_key] = clean_alias
                                    total_extractions += 1
                                else:
                                    # Merge CVE references if multiple occurrences
                                    existing_cves = all_alias_data[alias_key].get('source_cve', [])
                                    new_cves = value.get('source_cve', [])
                                    combined_cves = list(set(existing_cves + new_cves))
                                    all_alias_data[alias_key]['source_cve'] = combined_cves
            
            if total_extractions == 0:
                if logger:
                    logger.info("No alias extractions found - skipping alias report generation", group="completion")
                return None
            
            # Group aliases by property pattern (curator logic)
            consolidated_groups = {}
            
            for alias_data in all_alias_data.values():
                # Create grouping key based on property types (not values)
                property_types = []
                for key_field in sorted(alias_data.keys()):
                    if key_field != 'source_cve':
                        if isinstance(alias_data[key_field], list):
                            property_types.append(f"{key_field}({len(alias_data[key_field])})")
                        else:
                            property_types.append(key_field)
                
                # Create meaningful group name
                group_key = "_".join(property_types) if property_types else "unknown_properties"
                
                if group_key not in consolidated_groups:
                    consolidated_groups[group_key] = []
                    
                consolidated_groups[group_key].append(alias_data)
            
            # Create alias groups from consolidated groups
            alias_groups = []
            for group_key, aliases in consolidated_groups.items():
                # Sort aliases by CVE count (most referenced first)
                aliases.sort(key=lambda x: len(x.get('source_cve', [])), reverse=True)
                
                alias_groups.append({
                    'alias_group': group_key,
                    'aliases': aliases
                })
            
            # Sort alias groups by total alias count (largest first)
            alias_groups.sort(key=lambda group: -len(group['aliases']))
            
            # Load confirmed mappings for this UUID
            confirmed_mappings = []
            if load_confirmed_mappings_for_uuid and source_uuid:
                confirmed_mappings = load_confirmed_mappings_for_uuid(source_uuid)
                if logger and confirmed_mappings:
                    logger.info(f"Loaded {len(confirmed_mappings)} confirmed mappings for UUID {source_uuid}", group="completion")
                elif logger:
                    logger.debug(f"No confirmed mappings found for UUID {source_uuid}", group="completion")
            
            # Create curator-compatible output structure with status tracking for incremental saves
            output_data = {
                'metadata': {
                    'extraction_timestamp': datetime.now(timezone.utc).isoformat(),
                    'target_uuid': source_uuid,
                    'total_cves_processed': self.consolidated_metadata['total_cves_processed'],
                    'unique_aliases_extracted': len(all_alias_data),
                    'product_groups_created': len(alias_groups),
                    'extraction_source': 'Analysis_Tools_Badge_System',
                    'curator_compatibility': True,
                    'status': 'completed' if is_final else 'in_progress',
                    'run_started_at': self.consolidated_metadata.get('run_started_at', datetime.now(timezone.utc).isoformat())
                },
                'aliasGroups': alias_groups,
                'confirmedMappings': confirmed_mappings  # Now loaded from existing mapping files
            }
            
            # Write alias report file using atomic write to prevent corruption during incremental saves
            os.makedirs(logs_directory, exist_ok=True)
            output_filename = "aliasExtractionReport.json"
            output_path = os.path.join(logs_directory, output_filename)
            
            # Use atomic write pattern (same as dataset collector and SDC collector)
            temp_file_path = output_path + '.tmp'
            with open(temp_file_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            # Atomic rename - prevents readers from seeing partial/corrupted files
            os.replace(temp_file_path, output_path)
            
            if logger:
                logger.info(f"Alias report generated: {len(alias_groups)} groups, {len(all_alias_data)} unique aliases", group="completion")
            
            return output_path
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to generate alias report: {e}", group="completion")
            
            # Clean up temp file if it exists
            temp_file_path = output_path + '.tmp' if 'output_path' in locals() else None
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except:
                    pass
            
            return None
    
    def _increment_concern_type_count(self, concern_counts_array: List[Dict], concern_type: str) -> None:
        """Increment concern type count in array format."""
        # Convert display name to concern type key (e.g., "Placeholder Data" -> "placeholderData")
        concern_type_key = self._concern_type_to_key(concern_type)
        
        # Find existing entry or create new one
        for entry in concern_counts_array:
            if entry['concern_type'] == concern_type_key:
                entry['count'] += 1
                return
        
        # Add new entry if not found
        concern_counts_array.append({
            'concern_type': concern_type_key,
            'count': 1
        })
    
    def _convert_concerns_to_array(self, concerns_data: Dict) -> List[Dict]:
        """Convert concerns_data object to grouped array format to eliminate repetition."""
        concerns_array = []
        
        for concern_type_key, concerns_list in concerns_data.items():
            if concerns_list:  # Only include non-empty concern types
                concern_group = {
                    'concern_type': concern_type_key,
                    'concerns': concerns_list  # Keep original concern objects without adding redundant type field
                }
                concerns_array.append(concern_group)
        
        return concerns_array
    
    def _concern_type_to_key(self, concern_type: str) -> str:
        """Convert concern type display name to data key."""
        mapping = {
            'Placeholder Detection': 'placeholderData',
            'Mathematical Comparator Detection': 'mathematicalComparators',
            'Text Comparator Detection': 'textComparators',
            'Whitespace Detection': 'whitespaceIssues',
            'Invalid Character Detection': 'invalidCharacters',
            'Version Granularity Detection': 'versionGranularity',
            'Overlapping Ranges': 'overlappingRanges',
            'All Versions Pattern Detection': 'allVersionsPatterns',
            'Bloat Text Detection': 'bloatTextDetection'
        }
        if concern_type not in mapping:
            raise ValueError(f"Unknown concern type: '{concern_type}'. Expected one of: {list(mapping.keys())}")
        return mapping[concern_type]
    
    def finalize_report(self) -> Optional[str]:
        """
        Finalize the report by marking it as complete and returning the file path.
        
        Returns:
            Path to the final JSON file, or None if no data was collected
        """
        if not self.output_file_path:
            return None
        
        # Check if we have any CVE data with concerns
        total_entries_with_concerns = sum(
            cve_data['cve_metadata']['entries_with_concerns'] 
            for cve_data in self.cve_data
        )
        
        if total_entries_with_concerns == 0:
            # Still save the file for completeness, but mark it
            self.consolidated_metadata.update({
                'run_completed_at': datetime.now(timezone.utc).isoformat(),
                'report_scope': 'Platform Entry Notifications - Source Data Concerns Only',
                'status': 'completed_no_concerns'
            })
            
            # Force final save with completion metadata
            if not self._auto_save(force=True):
                if logger:
                    logger.error(f"Failed to finalize empty badge contents report", group="completion")
            
            return self.output_file_path
        
        # Update final metadata and mark as complete
        self.consolidated_metadata.update({
            'run_completed_at': datetime.now(timezone.utc).isoformat(),
            'report_scope': 'Platform Entry Notifications - Source Data Concerns Only',
            'status': 'completed'
        })
        
        # Force final save with completion metadata
        if not self._auto_save(force=True):
            if logger:
                logger.error(f"Failed to finalize badge contents report", group="completion")
            return None
        
        # Print final summary
        cves_processed = self.consolidated_metadata['total_cves_processed']
        cves_with_concerns = len([cve for cve in self.cve_data if cve['cve_metadata']['entries_with_concerns'] > 0])
        entries_processed = self.consolidated_metadata['total_platform_entries']
        
        if logger:
            logger.info(f"Badge contents report complete: {cves_with_concerns}/{cves_processed} CVEs with concerns, "
                      f"{total_entries_with_concerns}/{entries_processed} entries with concerns", group="completion")
        
        return self.output_file_path

# Global collector instance
_badge_contents_collector = None

def get_badge_contents_collector() -> BadgeContentsCollector:
    """Get the global badge contents collector instance."""
    global _badge_contents_collector
    if _badge_contents_collector is None:
        _badge_contents_collector = BadgeContentsCollector()
    return _badge_contents_collector

def clear_badge_contents_collector():
    """Clear the global badge contents collector for a new run."""
    global _badge_contents_collector
    _badge_contents_collector = None

def initialize_badge_contents_report(logs_directory: str) -> bool:
    """Initialize the badge contents report file for incremental updates."""
    collector = get_badge_contents_collector()
    return collector.initialize_output_file(logs_directory)

def start_cve_collection(cve_id: str):
    """Initialize badge collection for a new CVE."""
    collector = get_badge_contents_collector()
    collector.start_cve_processing(cve_id)

def complete_cve_collection() -> bool:
    """Complete collection for the current CVE and save to file."""
    collector = get_badge_contents_collector()
    return collector.complete_cve_processing()

def collect_clean_platform_entry(source_id: str) -> None:
    """Collect a platform entry that has no source data concerns."""
    collector = get_badge_contents_collector()
    collector.collect_clean_platform_entry(source_id)

def collect_alias_extraction_data(table_index: int, source_id: str, alias_data: Dict, 
                                 entry_count: int, cve_id: str = None) -> None:
    """
    Collect alias extraction data for the --alias-report functionality.
    
    Args:
        table_index: Table index for the platform entry
        source_id: Actual source UUID from the data
        alias_data: Dictionary containing alias extraction data from registry
        entry_count: Number of alias entries extracted (for platform expansion)
        cve_id: CVE identifier for source tracking
    """
    collector = get_badge_contents_collector()
    collector.collect_alias_extraction(table_index, source_id, alias_data, entry_count, cve_id)

def generate_alias_extraction_report(logs_directory: str, source_uuid: str, is_final: bool = True) -> Optional[str]:
    """
    Generate curator-compatible alias extraction report.
    
    Args:
        logs_directory: Directory to save the alias report
        source_uuid: Source UUID for confirmed mappings matching
        is_final: Whether this is the final report (marks as completed) or incremental (in_progress)
        
    Returns:
        Path to generated aliasReport.json file, or None if generation failed
    """
    collector = get_badge_contents_collector()
    return collector.generate_alias_report(logs_directory, source_uuid, is_final)

def configure_alias_reporting(logs_directory: str, source_uuid: str) -> None:
    """
    Configure alias reporting for incremental saves during CVE processing.
    
    Args:
        logs_directory: Directory to save alias reports  
        source_uuid: Source UUID for alias extraction targeting
    """
    collector = get_badge_contents_collector()
    collector.configure_alias_reporting(logs_directory, source_uuid)

def configure_nvd_ish_only_mode(enabled: bool = True) -> None:
    """
    Configure NVD-ish only mode for memory optimization.
    
    When enabled, skips cross-CVE data accumulation for reports while preserving
    per-CVE data collection for NVD-ish enrichment.
    
    Args:
        enabled: Whether to enable NVD-ish only mode
    """
    collector = get_badge_contents_collector()
    collector.configure_nvd_ish_only_mode(enabled)

def finalize_badge_contents_report() -> Optional[str]:
    """Finalize the badge contents report at the end of a run."""
    collector = get_badge_contents_collector()
    return collector.finalize_report()
