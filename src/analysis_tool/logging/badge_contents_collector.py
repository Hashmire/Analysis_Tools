#!/usr/bin/env python3
"""
Badge Contents Collection System

Simple implementation to collect Platform Entry Notification badge contents
during the main processing pipeline and export to sourceDataConcernReport.json
in the existing logs directory structure.

SCOPE: Platform Entry Notifications only - specifically Source Data Concerns

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
from typing import Dict, List, Any, Optional
from datetime import datetime
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

class BadgeContentsCollector:
    """
    Collects Platform Entry Notification badge contents during badge generation.
    Accumulates data across multiple CVEs and exports consolidated JSON report.
    """
    
    def __init__(self):
        self.cve_data: List[Dict] = []  # Array of CVE data objects
        self.consolidated_metadata: Dict[str, Any] = {
            'run_started_at': datetime.now().isoformat(),
            'total_cves_processed': 0,
            'total_platform_entries': 0,
            'entries_with_concerns': 0,
            'concern_type_counts': []
        }
        self.current_cve_data: Optional[Dict] = None
        self.output_file_path: Optional[str] = None
    
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
                    'last_updated': datetime.now().isoformat(),
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
                'processing_timestamp': datetime.now().isoformat()
            }
        }
        self.cve_data.append(self.current_cve_data)
    
    def complete_cve_processing(self) -> bool:
        """
        Complete processing for the current CVE and save to file.
        
        Returns:
            True if save successful, False otherwise
        """
        if not self.current_cve_data or not self.output_file_path:
            return False
        
        return self._save_to_file()
    
    def _save_to_file(self) -> bool:
        """
        Save current state to the JSON file.
        
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
                    'last_updated': datetime.now().isoformat(),
                    'report_scope': 'Platform Entry Notifications - Source Data Concerns Only',
                    'status': 'in_progress'
                },
                'cve_data': self.cve_data
            }
            
            # Write to JSON file
            with open(self.output_file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to save badge contents: {e}", group="badge_generation")
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
            try:
                export_data = {
                    'metadata': {
                        **self.consolidated_metadata,
                        'run_completed_at': datetime.now().isoformat(),
                        'report_scope': 'Platform Entry Notifications - Source Data Concerns Only',
                        'status': 'completed_no_concerns'
                    },
                    'cve_data': self.cve_data
                }
                
                with open(self.output_file_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                    
            except Exception as e:
                if logger:
                    logger.error(f"Failed to finalize empty badge contents report: {e}", group="completion")
            
            return self.output_file_path
        
        try:
            # Update final metadata and mark as complete
            export_data = {
                'metadata': {
                    **self.consolidated_metadata,
                    'run_completed_at': datetime.now().isoformat(),
                    'report_scope': 'Platform Entry Notifications - Source Data Concerns Only',
                    'status': 'completed'
                },
                'cve_data': self.cve_data
            }
            
            # Write final version to JSON file
            with open(self.output_file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            # Print final summary
            cves_processed = self.consolidated_metadata['total_cves_processed']
            cves_with_concerns = len([cve for cve in self.cve_data if cve['cve_metadata']['entries_with_concerns'] > 0])
            entries_processed = self.consolidated_metadata['total_platform_entries']
            
            if logger:
                logger.info(f"Badge contents report complete: {cves_with_concerns}/{cves_processed} CVEs with concerns, "
                          f"{total_entries_with_concerns}/{entries_processed} entries with concerns", group="completion")
            
            return self.output_file_path
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to finalize badge contents report: {e}", group="completion")
            return None

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

def finalize_badge_contents_report() -> Optional[str]:
    """Finalize the badge contents report at the end of a run."""
    collector = get_badge_contents_collector()
    return collector.finalize_report()
