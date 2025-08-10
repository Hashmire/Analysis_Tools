#!/usr/bin/env python3
"""
Generate Dataset Dashboard Collector

Collects comprehensive metrics for both dataset generation and analysis processing
workflows. Exports to generateDatasetReport.json for dashboard consumption.

SCOPE: Complete workflow tracking - dataset generation + analysis processing

DASHBOARD INTEGRATION: All data structured for generateDatasetDashboard.html consumption
"""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path

# Import the structured logging system
try:
    from .workflow_logger import get_logger, LogGroup
    logger = get_logger()
except ImportError:
    # Fallback for testing environments
    logger = None

class UnifiedDashboardCollector:
    """
    Unified collector for both dataset generation and analysis processing metrics.
    Maintains dashboard-compatible data structure throughout the complete workflow.
    """
    
    def __init__(self):
        self.data = self._initialize_data_structure()
        self.output_file_path: Optional[str] = None
        self.processing_start_time: Optional[datetime] = None
        self.cve_processing_data: Dict[str, Dict] = {}
        self.current_processing_cve: Optional[str] = None
        self.stage_timings: Dict[str, Dict] = {}
        self.api_call_history: List[Dict] = []
        self.current_phase: Optional[Dict] = None
        
        # Initialize missing attributes for tracking
        self.collection_phases: List[Dict] = []
        self.output_files: List[Dict] = []
        
        self.consolidated_metadata = {
            'generated_by': 'unified_dashboard_collector',
            'generation_time': datetime.now().isoformat(),
            'data_source': 'nvd_api',
            'total_api_calls': 0,
            'total_cves_collected': 0,
            'unique_cves_count': 0,
            'run_started_at': datetime.now().isoformat()
        }
        self.dataset_statistics = {
            'cve_distribution': {
                'by_year': {},
                'by_status': {},
                'by_source': {}
            }
        }
        
        # Performance optimization: Reduce auto-save frequency to minimize file locking
        self._save_counter = 0
        self._last_save_time = datetime.now()
        self._save_interval_seconds = 5  # Save every 5 seconds at most
        self._save_every_n_operations = 100  # Or every 100 operations (increased from 50)
        
        # Load and inject configuration data
        self._inject_config_data()
        
        # Install logger hook to capture warnings/errors automatically
        self._install_logger_hook()
    
    def _install_logger_hook(self):
        """Install hooks to automatically capture logger warnings/errors for real-time attribution"""
        try:
            if logger and hasattr(logger, 'warning') and hasattr(logger, 'error'):
                # Store original methods
                original_warning = logger.warning
                original_error = logger.error
                
                # Create wrapper methods that also call our attribution system
                def warning_wrapper(message, *args, **kwargs):
                    # Call original logger method
                    result = original_warning(message, *args, **kwargs)
                    # Also record in our attribution system
                    try:
                        self.record_cve_warning(str(message))
                    except:
                        pass  # Don't break logging if attribution fails
                    return result
                
                def error_wrapper(message, *args, **kwargs):
                    # Call original logger method  
                    result = original_error(message, *args, **kwargs)
                    # Also record in our attribution system
                    try:
                        self.record_cve_error(str(message))
                    except:
                        pass  # Don't break logging if attribution fails
                    return result
                
                # Replace logger methods with wrappers
                logger.warning = warning_wrapper
                logger.error = error_wrapper
                
        except Exception as e:
            # Don't break initialization if logger hook fails
            pass
    
    def _inject_config_data(self):
        """Load configuration from config.json and inject into metadata"""
        try:
            config_path = Path(__file__).parent.parent / "config.json"
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Extract application info
            app_config = config.get('application', {})
            toolname = app_config.get('toolname', 'Analysis_Tools')
            version = app_config.get('version', 'Unknown')
            
            # Inject into metadata
            self.data["metadata"]["toolname"] = toolname
            self.data["metadata"]["version"] = version
            self.data["metadata"]["config_loaded"] = True
            
            # Only log config injection once per session to avoid log spam
            if logger and not hasattr(self.__class__, '_config_logged'):
                logger.info(f"Config injected: {toolname} v{version}", group="initialization")
                self.__class__._config_logged = True
                
        except Exception as e:
            # Fallback values if config loading fails
            self.data["metadata"]["toolname"] = "Analysis_Tools"
            self.data["metadata"]["version"] = "Unknown"
            self.data["metadata"]["config_loaded"] = False
            self.data["metadata"]["config_error"] = str(e)
            
            if logger:
                logger.warning(f"Could not load config for injection: {e}", group="initialization")
    
    def _initialize_data_structure(self) -> Dict[str, Any]:
        """Initialize the unified dashboard data structure"""
        return {
            "metadata": {
                "generated_by": "unified_dashboard_collector",
                "generation_time": datetime.now().isoformat(),
                "log_file": "unified_collection",
                "last_updated": datetime.now().isoformat(),
                "file_size": 0,
                "run_started_at": datetime.now().isoformat(),
                "data_source": "nvd_api",
                "workflow_phase": "dataset_generation"
            },
            "processing": {
                "total_cves": 0,
                "processed_cves": 0,
                "current_cve": None,
                "start_time": None,
                "end_time": None,
                "progress_percentage": 0.0,
                "eta": None,
                "remaining_cves": 0,
                "log_start_time": None,
                "log_end_time": None,
                "mapping_success_rate": 0.0,
                "avg_processing_speed": 0.0,
                "eta_simple": None,
                "files_generated": 0
            },
            "performance": {
                "average_time": 0.0,
                "processing_rate": 0.0,
                "total_runtime": 0.0,
                "wall_clock_time": 0.0,
                "total_time": 0.0,
                "count": 0,
                "min_time": None,
                "max_time": 0.0,
                "active_processing_time": 0.0
            },
            "cache": {
                "total_entries": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "cache_expired": 0,
                "hit_rate": 0.0,
                "api_calls_saved": 0,
                "cache_file_size": 0,
                "cache_file_size_formatted": "0 KB",
                "total_requests": 0
            },
            "api": {
                "total_calls": 0,
                "nvd_cve_calls": 0,
                "mitre_cve_calls": 0,
                "nvd_cpe_calls": 0,
                "successful_calls": 0,
                "failed_calls": 0,
                "call_breakdown": {}
            },
            "log_stats": {
                "total_lines": 0,
                "info_count": 0,
                "debug_count": 0,
                "warning_count": 0,
                "error_count": 0
            },
            "warnings": {
                "api_warnings": [],
                "cache_warnings": [],
                "data_processing_warnings": [],
                "file_system_warnings": [],
                "configuration_warnings": [],
                "other_warnings": []
            },
            "errors": {
                "api_errors": [],
                "processing_errors": [],
                "file_errors": [],
                "system_errors": [],
                "validation_errors": [],
                "other_errors": []
            },
            "file_stats": {
                "files_generated": 0,
                "largest_file_size": 0,
                "smallest_file_size": None,
                "largest_file_name": "",
                "smallest_file_name": "",
                "total_file_size": 0,
                "average_file_size": 0.0,
                "detailed_files": []
            },
            "speed_stats": {
                "fastest_cve_time": None,
                "slowest_cve_time": 0.0,
                "fastest_cve_id": "",
                "slowest_cve_id": "",
                "total_processing_time": 0.0,
                "cves_with_timing": 0
            },
            "mapping_stats": {
                "total_mappings_found": 0,
                "platform_entries_with_mappings": 0,
                "mapping_percentage": 0.0,
                "largest_mapping_count": 0,
                "largest_mapping_cve": "",
                "total_platform_entries_processed": 0
            },
            "cpe_query_stats": {
                "total_queries": 0,
                "unique_base_strings": 0,
                "avg_results_per_query": 0.0,
                "max_results_single_query": 0,
                "total_results": 0,
                "top_queries": [],
                "top_cves_by_searches": [],
                "top_queries_by_results": [],
                "query_details": {}  # {base_string: {"count": X, "total_results": Y, "cves": [...]}}
            },
            "bloat_analysis": {
                "enabled": True,
                "files_analyzed": 0,
                "total_bloat_potential": 0.0,
                "average_severity": 0.0,
                "detailed_reports_generated": [],
                "total_bloat_size": 0.0,
                "average_bloat_percentage": 0.0
            }
        }

    # =============================================================================
    # Core Processing Methods (Dataset & Analysis Tool Integration)  
    # =============================================================================
    
    def start_processing_run(self, total_cves: int):
        """Initialize processing run with CVE count"""
        try:
            self.processing_start_time = datetime.now()
            self.data["processing"]["total_cves"] = total_cves
            self.data["processing"]["remaining_cves"] = total_cves
            self.data["processing"]["start_time"] = self.processing_start_time.isoformat()
            self.data["metadata"]["run_started_at"] = self.processing_start_time.isoformat()
            
            # Reset counters for new run
            self.data["processing"]["processed_cves"] = 0
            self.data["processing"]["progress_percentage"] = 0.0
            
            # Force save at start of processing run for immediate status visibility
            self._auto_save(force=True)
            
        except Exception as e:
            logger.error(f"Failed to start processing run: {e}", group="data_processing")

    def start_cve_processing(self, cve_id: str):
        """Start processing a specific CVE"""
        try:
            self.data["processing"]["current_cve"] = cve_id
            self.current_processing_cve = cve_id  # Set the current processing CVE for log entry attribution
            self.current_cve_start_time = datetime.now()
            
            # Track CVE processing timeline for log analysis
            if not hasattr(self, 'cve_processing_timeline'):
                self.cve_processing_timeline = []
            
            self.cve_processing_timeline.append({
                'cve_id': cve_id,
                'start_time': self.current_cve_start_time.isoformat(),
                'end_time': None
            })
            
            # Update progress tracking
            processed = self.data["processing"]["processed_cves"]
            total = self.data["processing"]["total_cves"]
            if total > 0:
                self.data["processing"]["progress_percentage"] = round((processed / total) * 100, 2)
                self.data["processing"]["remaining_cves"] = total - processed
                
                # Update ETA using unified calculation
                self._update_eta()
            
            # Force auto-save for critical CVE milestone
            self._auto_save(force=True)
            
            if logger:
                logger.debug(f"Started CVE processing: {cve_id} (Progress: {self.data['processing']['progress_percentage']}%)", group="data_processing")
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to start CVE processing for {cve_id}: {e}", group="data_processing")

    def finish_cve_processing(self, cve_id: str):
        """Complete processing for a specific CVE"""
        try:
            if hasattr(self, 'current_cve_start_time') and self.current_cve_start_time:
                processing_time = (datetime.now() - self.current_cve_start_time).total_seconds()
                
                # Update performance stats
                self.data["performance"]["count"] += 1
                self.data["performance"]["total_time"] += processing_time
                self.data["performance"]["active_processing_time"] = self.data["performance"]["total_time"]
                self.data["performance"]["average_time"] = self.data["performance"]["total_time"] / self.data["performance"]["count"]
                
                # Calculate wall clock time (total elapsed time from start)
                if self.processing_start_time:
                    wall_clock_elapsed = (datetime.now() - self.processing_start_time).total_seconds()
                    self.data["performance"]["wall_clock_time"] = wall_clock_elapsed
                    self.data["performance"]["total_runtime"] = wall_clock_elapsed
                    
                    # Calculate overhead (wall clock - active processing)
                    active_time = self.data["performance"]["active_processing_time"]
                    self.data["performance"]["overhead_time"] = max(0, wall_clock_elapsed - active_time)
                
                # Track min/max
                if self.data["performance"]["min_time"] is None or processing_time < self.data["performance"]["min_time"]:
                    self.data["performance"]["min_time"] = processing_time
                if processing_time > self.data["performance"]["max_time"]:
                    self.data["performance"]["max_time"] = processing_time
                
                # Update speed stats
                if (self.data["speed_stats"]["fastest_cve_time"] is None or 
                    processing_time < self.data["speed_stats"]["fastest_cve_time"]):
                    self.data["speed_stats"]["fastest_cve_time"] = processing_time
                    self.data["speed_stats"]["fastest_cve_id"] = cve_id
                
                if processing_time > self.data["speed_stats"]["slowest_cve_time"]:
                    self.data["speed_stats"]["slowest_cve_time"] = processing_time
                    self.data["speed_stats"]["slowest_cve_id"] = cve_id
                
                self.data["speed_stats"]["total_processing_time"] += processing_time
                self.data["speed_stats"]["cves_with_timing"] += 1
            
            # Update processed count
            self.data["processing"]["processed_cves"] += 1
            processed = self.data["processing"]["processed_cves"]
            total = self.data["processing"]["total_cves"]
            
            if total > 0:
                self.data["processing"]["progress_percentage"] = round((processed / total) * 100, 2)
                self.data["processing"]["remaining_cves"] = total - processed
                
                # Update ETA using unified calculation
                self._update_eta()
                
                # Calculate processing rate (CVEs per second, converted to CVEs per hour)
                if self.data["performance"]["total_time"] > 0:
                    rate_per_second = processed / self.data["performance"]["total_time"]
                    self.data["performance"]["processing_rate"] = rate_per_second * 3600  # Convert to per hour
            
            self.current_cve_start_time = None
            self.current_processing_cve = None  # Clear the current processing CVE
            
            # Update timeline end time
            if hasattr(self, 'cve_processing_timeline'):
                for timeline_entry in reversed(self.cve_processing_timeline):
                    if timeline_entry['cve_id'] == cve_id and timeline_entry['end_time'] is None:
                        timeline_entry['end_time'] = datetime.now().isoformat()
                        break
            
            # Force auto-save for critical CVE completion milestone
            self._auto_save(force=True)
            
            if logger:
                logger.debug(f"Finished CVE processing: {cve_id} (Progress: {self.data['processing']['progress_percentage']}%)", group="data_processing")
        
        except Exception as e:
            if logger:
                logger.error(f"Failed to finish CVE processing for {cve_id}: {e}", group="data_processing")

    def get_current_cve_processing_time(self) -> Optional[float]:
        """Get the current processing time for the active CVE, if any."""
        if hasattr(self, 'current_cve_start_time') and self.current_cve_start_time:
            return (datetime.now() - self.current_cve_start_time).total_seconds()
        return None

    # ========================================================================
    # STREAMLINED EVENT ATTRIBUTION - Direct at Source
    # ========================================================================
    
    def record_cve_warning(self, message: str, category: str = "data_processing_warnings"):
        """Record a warning directly associated with the current CVE (STREAMLINED)"""
        warning_entry = {
            "timestamp": datetime.now().isoformat(),
            "message": message.strip(),
            "cve_id": self.current_processing_cve or "system",
            "level": "warning"
        }
        
        # Ensure category exists
        if category not in self.data["warnings"]:
            self.data["warnings"][category] = []
            
        self.data["warnings"][category].append(warning_entry)
        
        # Auto-save for real-time dashboard updates
        self._auto_save()

    def record_cve_error(self, message: str, category: str = "processing_errors"):
        """Record an error directly associated with the current CVE (STREAMLINED)"""
        error_entry = {
            "timestamp": datetime.now().isoformat(),
            "message": message.strip(), 
            "cve_id": self.current_processing_cve or "system",
            "level": "error"
        }
        
        # Ensure category exists
        if category not in self.data["errors"]:
            self.data["errors"][category] = []
            
        self.data["errors"][category].append(error_entry)
        
        # Auto-save for real-time dashboard updates
        self._auto_save()

    def record_cve_info(self, message: str, category: str = "processing_info"):
        """Record informational event directly associated with the current CVE (STREAMLINED)"""
        # Add info tracking if needed for dashboard
        if "info_events" not in self.data:
            self.data["info_events"] = {}
            
        if category not in self.data["info_events"]:
            self.data["info_events"][category] = []
            
        info_entry = {
            "timestamp": datetime.now().isoformat(),
            "message": message.strip(),
            "cve_id": self.current_processing_cve or "system",
            "level": "info"
        }
        
        self.data["info_events"][category].append(info_entry)
        self._auto_save()

    def record_api_call(self, api_type: str, success: bool = True, response_time: float = 0.0):
        """Record API call statistics"""
        try:
            # Update total calls
            self.data["api"]["total_calls"] += 1
            
            # Update specific API type
            if api_type not in self.data["api"]["call_breakdown"]:
                self.data["api"]["call_breakdown"][api_type] = {"count": 0, "success": 0, "failed": 0}
            
            self.data["api"]["call_breakdown"][api_type]["count"] += 1
            
            # Update success/failure counts
            if success:
                self.data["api"]["successful_calls"] += 1
                self.data["api"]["call_breakdown"][api_type]["success"] += 1
            else:
                self.data["api"]["failed_calls"] += 1
                self.data["api"]["call_breakdown"][api_type]["failed"] += 1
            
            # Update API type specific counters
            if "cve" in api_type.lower():
                if "nvd" in api_type.lower():
                    self.data["api"]["nvd_cve_calls"] += 1
                elif "mitre" in api_type.lower():
                    self.data["api"]["mitre_cve_calls"] += 1
            elif "cpe" in api_type.lower():
                self.data["api"]["nvd_cpe_calls"] += 1
            
            self._auto_save()
            
        except Exception as e:
            logger.error(f"Failed to record API call for {api_type}: {e}", group="data_processing")

    def record_cache_activity(self, cache_result: str, cache_size: int = 0, api_calls_saved: int = 0):
        """
        Record cache activity statistics
        
        Args:
            cache_result (str): 'hit', 'miss', or 'expired'
            cache_size (int): Current cache size in bytes
            api_calls_saved (int): Number of API calls saved (only for hits)
        """
        try:
            self.data["cache"]["total_requests"] += 1
            
            if cache_result == 'hit':
                self.data["cache"]["cache_hits"] += 1
                if api_calls_saved > 0:
                    self.data["cache"]["api_calls_saved"] += api_calls_saved
            elif cache_result == 'miss':
                self.data["cache"]["cache_misses"] += 1
            elif cache_result == 'expired':
                self.data["cache"]["cache_expired"] += 1
                # Expired entries don't save API calls since they require refresh
            else:
                logger.warning(f"Unknown cache result type: {cache_result}", group="data_processing")
                return
            
            # Update cache file size if provided (separate from entry count)
            if cache_size > 0:
                self.data["cache"]["cache_file_size"] = cache_size
                
                # Format file size
                if cache_size < 1024:
                    self.data["cache"]["cache_file_size_formatted"] = f"{cache_size} B"
                elif cache_size < 1024 * 1024:
                    self.data["cache"]["cache_file_size_formatted"] = f"{cache_size / 1024:.1f} KB"
                else:
                    self.data["cache"]["cache_file_size_formatted"] = f"{cache_size / (1024 * 1024):.1f} MB"
            
            # Calculate hit rate (only true hits count toward hit rate)
            total_requests = self.data["cache"]["total_requests"]
            if total_requests > 0:
                self.data["cache"]["hit_rate"] = round((self.data["cache"]["cache_hits"] / total_requests) * 100, 2)
            
            # Always update cache statistics to get current total_entries count
            self.update_cache_statistics()
            
            self._auto_save()
            
        except Exception as e:
            logger.error(f"Failed to record cache activity: {e}", group="data_processing")

    def update_cache_statistics(self):
        """Update cache statistics with actual cache data from CPE cache"""
        try:
            from ..storage.cpe_cache import get_global_cache_manager
            
            cache_manager = get_global_cache_manager()
            if cache_manager.is_initialized():
                cache = cache_manager.get_cache()
                cache_stats = cache.get_stats()
                
                # Update total entries from actual cache count
                self.data["cache"]["total_entries"] = cache_stats['total_entries']
                
                # Update session statistics if available
                if 'session_hits' in cache_stats:
                    self.data["cache"]["session_hits"] = cache_stats['session_hits']
                if 'session_misses' in cache_stats:
                    self.data["cache"]["session_misses"] = cache_stats['session_misses']
                if 'session_api_calls_saved' in cache_stats:
                    self.data["cache"]["session_api_calls_saved"] = cache_stats['session_api_calls_saved']
                
                self._auto_save()
                
        except Exception as e:
            logger.debug(f"Failed to update cache statistics: {e}", group="data_processing")

    def update_cache_file_size(self, cache_file_path: Optional[str] = None):
        """
        Update cache file size by checking the actual cache file on disk.
        
        Args:
            cache_file_path: Optional path to cache file. If not provided, will try to find it.
        """
        try:
            if cache_file_path is None:
                # Try to find the cache file using common patterns
                from ..storage.run_organization import get_analysis_tools_root
                project_root = get_analysis_tools_root()
                
                possible_cache_paths = [
                    os.path.join(project_root, "src", "cache", "cpe_cache.json"),
                    os.path.join(project_root, "cache", "cpe_cache.json"),
                    os.path.join(project_root, "runs", "cache", "cpe_cache.json")
                ]
                
                cache_file_path = None
                for path in possible_cache_paths:
                    if os.path.exists(path):
                        cache_file_path = path
                        break
            
            if cache_file_path and os.path.exists(cache_file_path):
                file_size_bytes = os.path.getsize(cache_file_path)
                
                self.data["cache"]["cache_file_size"] = file_size_bytes
                
                # Format file size for display
                if file_size_bytes < 1024:
                    self.data["cache"]["cache_file_size_formatted"] = f"{file_size_bytes} B"
                elif file_size_bytes < 1024 * 1024:
                    self.data["cache"]["cache_file_size_formatted"] = f"{file_size_bytes / 1024:.1f} KB"
                elif file_size_bytes < 1024 * 1024 * 1024:
                    self.data["cache"]["cache_file_size_formatted"] = f"{file_size_bytes / (1024 * 1024):.1f} MB"
                else:
                    self.data["cache"]["cache_file_size_formatted"] = f"{file_size_bytes / (1024 * 1024 * 1024):.1f} GB"
                
                if logger:
                    logger.debug(f"Updated cache file size: {self.data['cache']['cache_file_size_formatted']}", group="data_processing")
                
                self._auto_save()
            else:
                if logger:
                    logger.warning(f"Cache file not found at expected locations", group="data_processing")
                
        except Exception as e:
            if logger:
                logger.error(f"Failed to update cache file size: {e}", group="data_processing")

    def record_mapping_activity(self, mappings_found: int, platform_entries: int):
        """Record platform mapping statistics"""
        try:
            self.data["mapping_stats"]["total_mappings_found"] += mappings_found
            self.data["mapping_stats"]["total_platform_entries_processed"] += platform_entries
            
            if mappings_found > 0:
                self.data["mapping_stats"]["platform_entries_with_mappings"] += 1
                
                # Track largest mapping count
                if mappings_found > self.data["mapping_stats"]["largest_mapping_count"]:
                    self.data["mapping_stats"]["largest_mapping_count"] = mappings_found
                    if self.data["processing"]["current_cve"]:
                        self.data["mapping_stats"]["largest_mapping_cve"] = self.data["processing"]["current_cve"]
            
            # Calculate mapping percentage
            total_entries = self.data["mapping_stats"]["total_platform_entries_processed"]
            if total_entries > 0:
                entries_with_mappings = self.data["mapping_stats"]["platform_entries_with_mappings"]
                self.data["mapping_stats"]["mapping_percentage"] = round((entries_with_mappings / total_entries) * 100, 2)
            
            self._auto_save()
            
        except Exception as e:
            logger.error(f"Failed to record mapping activity: {e}", group="data_processing")

    def record_cpe_query(self, base_string: str, result_count: int, cve_id: str = None):
        """
        Record CPE query details for analytics - stores only essential data for top lists
        
        Args:
            base_string (str): The CPE base string that was queried
            result_count (int): Number of results returned by the query
            cve_id (str): Associated CVE ID (optional)
        """
        try:
            # Update basic stats
            self.data["cpe_query_stats"]["total_queries"] += 1
            self.data["cpe_query_stats"]["total_results"] += result_count
            
            # Track max results
            if result_count > self.data["cpe_query_stats"]["max_results_single_query"]:
                self.data["cpe_query_stats"]["max_results_single_query"] = result_count
            
            # Use temporary tracking for efficient top list generation (no CVE arrays stored)
            if not hasattr(self, '_temp_query_tracking'):
                self._temp_query_tracking = {}
                self._temp_cve_tracking = {}
            
            # Track base string stats without storing CVE arrays
            if base_string not in self._temp_query_tracking:
                self._temp_query_tracking[base_string] = {
                    "count": 0,
                    "total_results": 0,
                    "max_single_query_results": 0,
                    "cve_ids": set()  # Track CVE IDs associated with this base string
                }
                self.data["cpe_query_stats"]["unique_base_strings"] += 1
            
            query_track = self._temp_query_tracking[base_string]
            query_track["count"] += 1
            query_track["total_results"] += result_count
            
            # Track the maximum result count from any single query for this base string
            if result_count > query_track["max_single_query_results"]:
                query_track["max_single_query_results"] = result_count
            
            # Associate CVE ID with this base string
            if cve_id:
                query_track["cve_ids"].add(cve_id)
            
            # Track CVE search counts efficiently
            if cve_id:
                if cve_id not in self._temp_cve_tracking:
                    self._temp_cve_tracking[cve_id] = {"search_count": 0, "total_results": 0}
                self._temp_cve_tracking[cve_id]["search_count"] += 1
                self._temp_cve_tracking[cve_id]["total_results"] += result_count
            
            # Update averages
            total_queries = self.data["cpe_query_stats"]["total_queries"]
            total_results = self.data["cpe_query_stats"]["total_results"]
            if total_queries > 0:
                self.data["cpe_query_stats"]["avg_results_per_query"] = round(total_results / total_queries, 1)
            
            # Generate top lists immediately from temp data (no periodic delay needed)
            self._update_cpe_top_lists_from_temp()
            
            self._auto_save()
            
        except Exception as e:
            logger.error(f"Failed to record CPE query: {e}", group="data_processing")

    def _update_cpe_top_lists_from_temp(self):
        """Generate top lists immediately from temporary tracking data"""
        try:
            if not hasattr(self, '_temp_query_tracking'):
                return
                
            # Generate top queries by result count (using max single-query results, not cumulative)
            top_queries_by_results = []
            for base_string, details in self._temp_query_tracking.items():
                # Convert CVE set to sorted list and limit to first 5 for display
                cve_list = list(details.get("cve_ids", set()))
                cve_list.sort()  # Sort CVE IDs alphabetically
                display_cves = cve_list[:5]  # Show first 5 CVEs
                
                # Format CVE IDs with URLs for HTML display
                cve_links = []
                for cve_id in display_cves:
                    cve_url = f"https://hashmire.github.io/cpeApplicabilityGeneratorPages/generated_pages/{cve_id}.html"
                    cve_links.append(f'<a href="{cve_url}" target="_blank">{cve_id}</a>')
                
                # Create display text with truncation indicator if needed
                cve_display = ", ".join(cve_links)
                if len(cve_list) > 5:
                    cve_display += f" <span class='text-muted'>(+{len(cve_list) - 5} more)</span>"
                
                top_queries_by_results.append({
                    "base_string": base_string,
                    "total_results": details["max_single_query_results"],  # Use max single query, not cumulative
                    "query_count": details["count"],
                    "cve_ids": display_cves,  # Raw CVE list for any non-HTML usage
                    "cve_display": cve_display,  # HTML-formatted CVE links for dashboard
                    "total_cve_count": len(cve_list),  # Total number of associated CVEs
                    "source": "API"  # NVD CPE API queries
                })
            
            # Sort by total results descending and keep top 20
            top_queries_by_results.sort(key=lambda x: x["total_results"], reverse=True)
            self.data["cpe_query_stats"]["top_queries_by_results"] = top_queries_by_results[:20]
            
            # Generate top CVEs by search count
            if hasattr(self, '_temp_cve_tracking'):
                top_cves_by_searches = []
                for cve_id, data in self._temp_cve_tracking.items():
                    top_cves_by_searches.append({
                        "cve_id": cve_id,
                        "search_count": data["search_count"],
                        "total_results": data["total_results"]
                    })
                
                # Sort by search count descending and keep top 20
                top_cves_by_searches.sort(key=lambda x: x["search_count"], reverse=True)
                self.data["cpe_query_stats"]["top_cves_by_searches"] = top_cves_by_searches[:20]
            
            # Generate top queries by count (legacy format for backward compatibility)
            top_queries = []
            for base_string, details in self._temp_query_tracking.items():
                top_queries.append({
                    "base_string": base_string,
                    "query_count": details["count"]
                })
            top_queries.sort(key=lambda x: x["query_count"], reverse=True)
            self.data["cpe_query_stats"]["top_queries"] = top_queries[:20]
            
            # Store only top 10 query details for dashboard (no CVE arrays)
            query_details = {}
            for entry in top_queries_by_results[:10]:
                query_details[entry["base_string"]] = {
                    "count": entry["query_count"],
                    "total_results": entry["total_results"]
                    # No CVE arrays stored - massive space savings
                }
            self.data["cpe_query_stats"]["query_details"] = query_details
            
        except Exception as e:
            logger.error(f"Failed to update CPE top lists from temp data: {e}", group="data_processing")

    def _update_cpe_top_lists(self):
        """Update the top CPE queries and CVE lists for dashboard display"""
        try:
            # Use temporary tracking if available (new approach), otherwise fall back to query_details
            if hasattr(self, '_temp_query_tracking') and self._temp_query_tracking:
                self._update_cpe_top_lists_from_temp()
                return
                
            # Legacy fallback for backward compatibility
            query_details = self.data["cpe_query_stats"]["query_details"]
            
            # Query details should already be serializable (using lists not sets)
            # Generate top queries by result count
            top_queries_by_results = []
            for base_string, details in query_details.items():
                top_queries_by_results.append({
                    "base_string": base_string,
                    "total_results": details["total_results"],
                    "query_count": details["count"]
                })
            
            # Sort by total results descending
            top_queries_by_results.sort(key=lambda x: x["total_results"], reverse=True)
            self.data["cpe_query_stats"]["top_queries_by_results"] = top_queries_by_results[:20]
            
            # Generate top CVEs by search count (only if CVE data exists)
            cve_search_counts = {}
            for base_string, details in query_details.items():
                if "cves" in details:  # Check if CVE data exists
                    for cve_id in details["cves"]:
                        if cve_id not in cve_search_counts:
                            cve_search_counts[cve_id] = {"search_count": 0, "total_results": 0}
                        cve_search_counts[cve_id]["search_count"] += 1
                        cve_search_counts[cve_id]["total_results"] += details["total_results"]
            
            top_cves_by_searches = []
            for cve_id, data in cve_search_counts.items():
                top_cves_by_searches.append({
                    "cve_id": cve_id,
                    "search_count": data["search_count"],
                    "total_results": data["total_results"]
                })
            
            # Sort by search count descending
            top_cves_by_searches.sort(key=lambda x: x["search_count"], reverse=True)
            self.data["cpe_query_stats"]["top_cves_by_searches"] = top_cves_by_searches[:20]
            
            # Also update the legacy top_queries format for backward compatibility
            top_queries = []
            for base_string, details in query_details.items():
                top_queries.append({
                    "base_string": base_string,
                    "query_count": details["count"]
                })
            top_queries.sort(key=lambda x: x["query_count"], reverse=True)
            self.data["cpe_query_stats"]["top_queries"] = top_queries[:20]
            
        except Exception as e:
            logger.error(f"Failed to update CPE top lists: {e}", group="data_processing")

    def finalize_cpe_stats(self):
        """Finalize CPE statistics at the end of processing"""
        try:
            self._update_cpe_top_lists()
            self._auto_save()
        except Exception as e:
            logger.error(f"Failed to finalize CPE stats: {e}", group="data_processing")

    def record_stage_start(self, stage_name: str):
        """Record the start of a processing stage"""
        try:
            # Initialize stages structure if not present
            if "stages" not in self.data:
                self.data["stages"] = {}
                
            if stage_name not in self.data["stages"]:
                self.data["stages"][stage_name] = {
                    "started": None,
                    "completed": None,
                    "status": "pending",
                    "duration": 0.0
                }
            
            self.data["stages"][stage_name]["started"] = datetime.now().isoformat()
            self.data["stages"][stage_name]["status"] = "in_progress"
            
            self._auto_save()
            
        except Exception as e:
            logger.error(f"Failed to record stage start for {stage_name}: {e}", group="data_processing")

    def record_stage_end(self, stage_name: str):
        """Record the end of a processing stage"""
        try:
            end_time = datetime.now()
            
            # Initialize if not present
            if "stages" not in self.data:
                self.data["stages"] = {}
            if stage_name not in self.data["stages"]:
                self.data["stages"][stage_name] = {
                    "started": None,
                    "completed": None,
                    "status": "pending",
                    "duration": 0.0
                }
            
            self.data["stages"][stage_name]["completed"] = end_time.isoformat()
            self.data["stages"][stage_name]["status"] = "completed"
            
            # Calculate duration if we have start time
            if self.data["stages"][stage_name]["started"]:
                try:
                    start_time = datetime.fromisoformat(self.data["stages"][stage_name]["started"])
                    duration = (end_time - start_time).total_seconds()
                    self.data["stages"][stage_name]["duration"] = duration
                except ValueError:
                    logger.warning(f"Could not parse start time for stage {stage_name}", group="data_processing")
            
            self._auto_save()
            
        except Exception as e:
            logger.error(f"Failed to record stage end for {stage_name}: {e}", group="data_processing")

    # =============================================================================
    # Helper Methods
    # =============================================================================
    
    def update_log_statistics(self):
        """Update log statistics by analyzing the current log file and extracting warning/error entries"""
        try:
            # Get log file path from workflow logger if available
            if logger and hasattr(logger, 'current_log_path') and logger.current_log_path:
                log_file_path = logger.current_log_path
                
                if os.path.exists(log_file_path):
                    with open(log_file_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                    
                    # Count different log levels and extract warning/error entries
                    info_count = 0
                    debug_count = 0
                    warning_count = 0
                    error_count = 0
                    
                    warnings_found = []
                    errors_found = []
                    
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                            
                        # Count log levels
                        if '[INFO]' in line:
                            info_count += 1
                        elif '[DEBUG]' in line:
                            debug_count += 1
                        elif '[WARNING]' in line:
                            warning_count += 1
                            warnings_found.append(line)
                        elif '[ERROR]' in line:
                            error_count += 1
                            errors_found.append(line)
                    
                    # Update log stats
                    self.data["log_stats"]["total_lines"] = len(lines)
                    self.data["log_stats"]["info_count"] = info_count
                    self.data["log_stats"]["debug_count"] = debug_count
                    self.data["log_stats"]["warning_count"] = warning_count
                    self.data["log_stats"]["error_count"] = error_count
                    
                    # STREAMLINED: Skip complex log parsing - use direct attribution instead
                    if warnings_found or errors_found:
                        if logger:
                            logger.debug(f"Found {len(warnings_found)} warnings and {len(errors_found)} errors - using direct attribution", group="data_processing")
                        
                        # IMPORTANT: Do NOT re-parse log entries - this overwrites the detailed CVE-specific
                        # categorization that was built up during real-time processing with direct attribution.
                        # The real-time system is more accurate than post-processing log file parsing.
                        
                        # Just update the log stats counts without disturbing the detailed categorized data
                        if logger:
                            logger.debug(f"Preserving {sum(len(entries) for entries in self.data['warnings'].values())} warnings and {sum(len(entries) for entries in self.data['errors'].values())} errors from real-time attribution", group="data_processing")
                    
        except Exception as e:
            if logger:
                logger.debug(f"Failed to update log statistics: {e}", group="data_processing")

    # ========================================================================
    # DATASET GENERATION TRACKING (Streamlined)
    # ========================================================================
    
    def start_collection_phase(self, phase_name: str):
        """Start a new collection phase for dataset generation"""
        try:
            phase = {
                'name': phase_name,
                'start_time': datetime.now().isoformat(),
                'cves_processed': 0,
                'progress': 0.0
            }
            self.collection_phases.append(phase)
            self.current_phase = phase
            
            if logger:
                logger.debug(f"Started collection phase: {phase_name}", group="data_processing")
                
        except Exception as e:
            if logger:
                logger.debug(f"Failed to start collection phase: {e}", group="data_processing")

    def _parse_log_entry(self, log_line, level):
        """Parse a single log entry and extract structured information"""
        try:
            import re
            
            # Parse log line format: [YYYY-MM-DD HH:MM:SS] [LEVEL] message
            timestamp_pattern = r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]'
            level_pattern = r'\[(WARNING|ERROR)\]'
            
            timestamp_match = re.search(timestamp_pattern, log_line)
            level_match = re.search(level_pattern, log_line)
            
            if not timestamp_match or not level_match:
                return None
                
            timestamp = timestamp_match.group(1)
            message = log_line.split('] ', 2)[-1] if '] ' in log_line else log_line
            
            # Extract CVE context using multiple strategies
            cve_id = self._extract_cve_context(message, timestamp)
            
            return {
                "timestamp": timestamp,
                "level": level,
                "message": message.strip(),
                "cve_id": cve_id,
                "raw_line": log_line
            }
            
        except Exception as e:
            return None

    def _extract_cve_context(self, message, timestamp):
        """Extract CVE context using multiple strategies"""
        import re
        
        # Strategy 1: Direct CVE ID in message (highest priority)
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_match = re.search(cve_pattern, message)
        if cve_match:
            return cve_match.group(0)
        
        # Strategy 2: Look for processing context clues in the message
        processing_patterns = [
            (r'Processing ([A-Z][A-Z\-0-9]+)', r'CVE-\d{4}-\d{4,7}'),  # "Processing CVE-XXXX-XXXX"
            (r'Gathering data for ([A-Z][A-Z\-0-9]+)', r'CVE-\d{4}-\d{4,7}'),  # "Gathering data for CVE-XXXX-XXXX"
            (r'Started CVE processing: ([A-Z][A-Z\-0-9]+)', r'CVE-\d{4}-\d{4,7}'),  # Direct CVE processing messages
            (r'([A-Z][A-Z\-0-9]+) has invalid', r'CVE-\d{4}-\d{4,7}'),  # "CVE-XXXX-XXXX has invalid..."
            (r'([A-Z][A-Z\-0-9]+) is in REJECTED', r'CVE-\d{4}-\d{4,7}'),  # "CVE-XXXX-XXXX is in REJECTED..."
        ]
        
        for pattern, cve_format in processing_patterns:
            match = re.search(pattern, message)
            if match:
                potential_cve = match.group(1)
                if re.match(cve_format, potential_cve):
                    return potential_cve
        
        # Strategy 3: Use CVE processing timeline to match timestamp windows (MOST ACCURATE)
        # This handles cases where messages occur during CVE processing but don't contain CVE IDs
        cve_from_timeline = self._match_timestamp_to_cve(timestamp)
        if cve_from_timeline:
            return cve_from_timeline
        
        # Strategy 4: Use current processing context as fallback (if timeline matching fails)
        if self.current_processing_cve:
            return self.current_processing_cve
        elif self.data["processing"]["current_cve"]:
            return self.data["processing"]["current_cve"]
        
        # Debug: Log when we can't match a CVE for analysis
        if hasattr(self, 'logger') and self.logger:
            timeline_count = len(getattr(self, 'cve_processing_timeline', []))
            current_cve = self.current_processing_cve or self.data["processing"]["current_cve"] or "None"
            timeline_info = ""
            if hasattr(self, 'cve_processing_timeline') and self.cve_processing_timeline:
                recent_cves = [entry.get('cve_id', 'unknown') for entry in self.cve_processing_timeline[-3:]]
                timeline_info = f", recent_timeline_cves={recent_cves}"
            self.logger.debug(f"No CVE match for log at {timestamp}: current_cve={current_cve}, timeline_entries={timeline_count}{timeline_info}, message_preview={message[:50]}...", group="data_processing")
        
        # Strategy 5: Default to unknown for system-wide messages
        return "unknown"

    def _match_timestamp_to_cve(self, timestamp):
        """Match a log timestamp to a CVE based on processing timeline"""
        try:
            from datetime import datetime
            
            # Parse the log timestamp
            log_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            
            # Check if we have CVE processing timeline data
            if not hasattr(self, 'cve_processing_timeline'):
                return None
            
            if not self.cve_processing_timeline:
                return None
            
            # Sort timeline entries by start time (newest first for best match)
            sorted_timeline = []
            for timeline_entry in self.cve_processing_timeline:
                if 'start_time' in timeline_entry and 'cve_id' in timeline_entry:
                    try:
                        start_time_str = timeline_entry['start_time']
                        # Handle ISO format with or without timezone
                        if 'Z' in start_time_str:
                            start_time_str = start_time_str.replace('Z', '+00:00')
                        if '+' in start_time_str or start_time_str.endswith('Z'):
                            entry_start = datetime.fromisoformat(start_time_str)
                            # Remove timezone info for comparison
                            if entry_start.tzinfo:
                                entry_start = entry_start.replace(tzinfo=None)
                        else:
                            entry_start = datetime.fromisoformat(start_time_str)
                        
                        sorted_timeline.append({
                            'cve_id': timeline_entry['cve_id'],
                            'start_time': entry_start
                        })
                    except (ValueError, KeyError):
                        continue
            
            # Sort by start time (newest first)
            sorted_timeline.sort(key=lambda x: x['start_time'], reverse=True)
            
            # Find the best match - the most recent CVE processing that started before this log
            for entry in sorted_timeline:
                entry_start = entry['start_time']
                
                if entry_start <= log_time:
                    # Check that the log occurred within a reasonable time window
                    time_diff = (log_time - entry_start).total_seconds()
                    # Use more reasonable time window - 10 minutes for dataset generation context
                    if time_diff <= 600:  # Within 10 minutes of CVE processing start
                        return entry['cve_id']
            
            return None
            
        except Exception as e:
            # Debug: Log the exception to understand what's going wrong
            if hasattr(self, 'logger') and self.logger:
                self.logger.debug(f"Timeline matching error for timestamp {timestamp}: {e}", group="data_processing")
            return None

    def _categorize_warning(self, message):
        """Categorize warning messages into appropriate sub-categories"""
        message_lower = message.lower()
        
        # CPE-specific warnings (moved from other_warnings to data_processing_warnings)
        if any(keyword in message_lower for keyword in ['overly broad cpe detected', 'invalid cpe match string detected']):
            return "data_processing_warnings"
        
        # API-related warnings
        elif any(keyword in message_lower for keyword in ['api', 'rate limit', 'timeout', 'request', 'response']):
            return "api_warnings"
        
        # Cache-related warnings  
        elif any(keyword in message_lower for keyword in ['cache', 'expired', 'miss', 'hit rate']):
            return "cache_warnings"
        
        # File system warnings
        elif any(keyword in message_lower for keyword in ['file', 'disk', 'space', 'permission', 'directory']):
            return "file_system_warnings"
        
        # Configuration warnings
        elif any(keyword in message_lower for keyword in ['config', 'setting', 'parameter', 'deprecated']):
            return "configuration_warnings"
        
        # Data processing warnings
        elif any(keyword in message_lower for keyword in ['processing', 'parse', 'format', 'data', 'field']):
            return "data_processing_warnings"
        
        else:
            return "other_warnings"

    def _categorize_error(self, message):
        """Categorize error messages into appropriate sub-categories"""
        message_lower = message.lower()
        
        # API-related errors
        if any(keyword in message_lower for keyword in ['api', 'request failed', 'connection', 'authentication', 'network']):
            return "api_errors"
        
        # File-related errors
        elif any(keyword in message_lower for keyword in ['file not found', 'read', 'write', 'permission denied', 'io error']):
            return "file_errors"
        
        # System errors
        elif any(keyword in message_lower for keyword in ['memory', 'system', 'dependency', 'import', 'module']):
            return "system_errors"
        
        # Validation errors
        elif any(keyword in message_lower for keyword in ['validation', 'schema', 'invalid', 'malformed', 'corrupt']):
            return "validation_errors"
        
        # Processing errors
        elif any(keyword in message_lower for keyword in ['processing', 'failed to', 'error in', 'exception']):
            return "processing_errors"
        
        else:
            return "other_errors"

    def _consolidate_log_entries(self):
        """Consolidate similar log entries per CVE to reduce storage and improve readability"""
        try:
            # Consolidate warnings
            for category in self.data["warnings"]:
                self.data["warnings"][category] = self._consolidate_entries_by_cve(
                    self.data["warnings"][category]
                )
            
            # Consolidate errors
            for category in self.data["errors"]:
                self.data["errors"][category] = self._consolidate_entries_by_cve(
                    self.data["errors"][category]
                )
                
        except Exception as e:
            if logger:
                logger.debug(f"Failed to consolidate log entries: {e}", group="data_processing")

    def _consolidate_entries_by_cve(self, entries):
        """Consolidate entries by CVE ID first, then by error category within each CVE"""
        if not entries:
            return []
            
        try:
            import re
            cve_groups = {}
            
            for entry in entries:
                # Handle both raw entries and already consolidated entries
                if "cve_subcategories" in entry:
                    # This is already a consolidated entry, skip re-consolidation
                    continue
                    
                if "message" not in entry:
                    # Invalid entry structure, skip
                    continue
                    
                cve_id = entry.get("cve_id", "unknown")
                message = entry["message"]
                timestamp = entry.get("timestamp", "")
                
                # Determine the error category based on message content
                category = self._determine_error_category(message)
                
                # Group by CVE ID first
                if cve_id not in cve_groups:
                    cve_groups[cve_id] = {
                        "cve_id": cve_id,
                        "total_count": 0,
                        "first_occurrence": timestamp,
                        "last_occurrence": timestamp,
                        "cve_subcategories": {}
                    }
                
                cve_group = cve_groups[cve_id]
                cve_group["total_count"] += 1
                
                # Update timestamps
                if timestamp:
                    if not cve_group["first_occurrence"] or timestamp < cve_group["first_occurrence"]:
                        cve_group["first_occurrence"] = timestamp
                    if timestamp > cve_group["last_occurrence"]:
                        cve_group["last_occurrence"] = timestamp
                
                # Group by category within the CVE
                if category not in cve_group["cve_subcategories"]:
                    cve_group["cve_subcategories"][category] = {
                        "category": category,
                        "count": 0,
                        "messages": [],
                        "first_occurrence": timestamp,
                        "last_occurrence": timestamp
                    }
                
                subcategory = cve_group["cve_subcategories"][category]
                subcategory["count"] += 1
                
                # Update subcategory timestamps
                if timestamp:
                    if not subcategory["first_occurrence"] or timestamp < subcategory["first_occurrence"]:
                        subcategory["first_occurrence"] = timestamp
                    if timestamp > subcategory["last_occurrence"]:
                        subcategory["last_occurrence"] = timestamp
                
                # Store unique messages (limit to 5 per subcategory to prevent bloat)
                if message not in subcategory["messages"] and len(subcategory["messages"]) < 5:
                    subcategory["messages"].append(message)
            
            # Convert to list and sort by total count descending, then by CVE ID
            result = list(cve_groups.values())
            result.sort(key=lambda x: (-x["total_count"], x["cve_id"]))
            
            # Add back any already-consolidated entries that we skipped
            already_consolidated = [entry for entry in entries if "cve_subcategories" in entry]
            result.extend(already_consolidated)
            
            # Limit to top 30 CVEs per category to prevent excessive data
            return result[:30]
            
        except Exception as e:
            if logger:
                logger.debug(f"Failed to consolidate entries by CVE: {str(e)}", group="data_processing")
            return entries[:50]  # Fallback: just limit the original entries

    def _determine_error_category(self, message):
        """Determine the error category based on message content"""
        message_lower = message.lower()
        
        # API-related
        if any(keyword in message_lower for keyword in ['api', 'request failed', 'connection', 'authentication', 'network', 'rate limit', 'timeout']):
            return "API Issues"
        
        # File-related
        elif any(keyword in message_lower for keyword in ['file not found', 'read', 'write', 'permission denied', 'io error', 'disk', 'space']):
            return "File System Issues"
        
        # Cache-related
        elif any(keyword in message_lower for keyword in ['cache', 'expired', 'miss', 'hit rate']):
            return "Cache Issues"
        
        # Processing/Data
        elif any(keyword in message_lower for keyword in ['processing', 'parse', 'format', 'data', 'field', 'validation', 'schema', 'invalid', 'malformed']):
            return "Data Processing Issues"
        
        # System/Configuration
        elif any(keyword in message_lower for keyword in ['memory', 'system', 'dependency', 'import', 'module', 'config', 'setting', 'parameter']):
            return "System/Config Issues"
        
        else:
            return "Other Issues"

    def _update_eta(self):
        """Update ETA calculation - single source of truth used by both progress and detailed sections"""
        processing = self.data["processing"]
        performance = self.data["performance"]
        
        remaining_cves = processing.get("remaining_cves", 0)
        processed_cves = processing.get("processed_cves", 0)
        average_time = performance.get("average_time", 0)
        
        if remaining_cves == 0:
            # Processing complete
            processing["eta"] = "Complete"
            processing["eta_simple"] = "Complete"
        elif remaining_cves > 0 and average_time > 0:
            # Calculate time remaining
            estimated_seconds = remaining_cves * average_time
            remaining_time_str = str(timedelta(seconds=int(estimated_seconds)))
            
            # Calculate ETA timestamp
            eta_timestamp = datetime.now() + timedelta(seconds=estimated_seconds)
            eta_time_str = eta_timestamp.strftime("%H:%M:%S")
            
            # Store both formats
            processing["eta"] = f"{remaining_time_str} (ETA: {eta_time_str})"
            processing["eta_simple"] = remaining_time_str
        elif processed_cves > 0 and average_time > 0:
            # Show processing speed when remaining calculation not possible
            processing["eta"] = f"~{average_time:.1f}s per CVE"
            processing["eta_simple"] = f"~{average_time:.1f}s per CVE"
        else:
            # No timing data available yet
            processing["eta"] = "Calculating..."
            processing["eta_simple"] = "Calculating..."

    def _auto_save(self, force: bool = False):
        """Auto-save data to file with intelligent frequency control
        
        Args:
            force: If True, bypass frequency limits and save immediately
        """
        if not self.output_file_path:
            return
            
        try:
            # Increment operation counter
            self._save_counter += 1
            
            # Check if we should save based on frequency controls
            now = datetime.now()
            time_since_last_save = (now - self._last_save_time).total_seconds()
            
            # Enforce 5-second minimum to prevent I/O waste - primary check
            if time_since_last_save < self._save_interval_seconds:
                return  # Skip this save - too soon since last save
            
            # Additional conditions that allow save (when 5+ seconds have passed)
            should_save = (
                force or  # Forced save (but still respects 5-second minimum above)
                self._save_counter >= self._save_every_n_operations or  # Hit operation limit
                time_since_last_save >= self._save_interval_seconds  # Hit time limit (redundant but clear)
            )
            
            if not should_save:
                return  # Skip this save
            
            # Reset counters
            self._save_counter = 0
            self._last_save_time = now
            
            # Update log statistics before saving
            self.update_log_statistics()
            
            # Calculate file_stats from detailed_files to avoid double counting
            detailed_files = self.data["file_stats"]["detailed_files"]
            self.data["file_stats"]["files_generated"] = len(detailed_files)
            self.data["file_stats"]["total_file_size"] = sum(f.get("file_size", 0) for f in detailed_files)
            
            # Set processing.files_generated to match file_stats for consistency
            self.data["processing"]["files_generated"] = self.data["file_stats"]["files_generated"]
            
            # Always use the unified data structure for real-time updates
            self.save_to_file(self.output_file_path)
            
        except Exception as e:
            if logger:
                logger.error(f"Auto-save failed: {e}", group="data_processing")
    
    def initialize_output_file(self, logs_directory: str) -> bool:
        """
        Initialize the output JSON file for incremental updates.
        
        Args:
            logs_directory: Path to the logs directory
            
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            self.output_file_path = os.path.join(logs_directory, "generateDatasetReport.json")
            
            # Create initial empty report
            initial_data = {
                'metadata': {
                    **self.consolidated_metadata,
                    'report_scope': 'Dataset Generation Metrics and Statistics',
                    'status': 'in_progress'
                },
                'collection_phases': [],
                'dataset_statistics': self.dataset_statistics,
                'output_files': []
            }
            
            # Use atomic write for initial file creation
            temp_file_path = self.output_file_path + '.tmp'
            with open(temp_file_path, 'w', encoding='utf-8') as f:
                json.dump(initial_data, f, indent=2, ensure_ascii=False)
            os.replace(temp_file_path, self.output_file_path)
            
            if logger:
                logger.info(f"Dataset contents report initialized: {self.output_file_path}", group="initialization")
            
            return True
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to initialize dataset contents report: {e}", group="initialization")
            return False
    
    # =============================================================================
    # Dataset Generation Methods (Backward Compatibility)
    # =============================================================================
    
    def start_collection_phase(self, phase_name: str, data_source: str = "nvd_api"):
        """Start a new collection phase for dataset generation"""
        try:
            # Update metadata with phase information
            self.data["metadata"]["workflow_phase"] = phase_name
            self.data["metadata"]["data_source"] = data_source
            self.data["metadata"]["last_updated"] = datetime.now().isoformat()
            
            # Create current phase tracking
            self.current_phase = {
                "name": phase_name,
                "data_source": data_source,
                "start_time": datetime.now(),
                "api_calls": 0,
                "files_generated": 0,
                "cves_processed": 0
            }
            
            # Force save at phase start for immediate workflow visibility
            self._auto_save(force=True)
            logger.info(f"Starting collection phase: {phase_name}", group="collection")
            
        except Exception as e:
            logger.error(f"Failed to start collection phase {phase_name}: {e}", group="collection")
    
    def record_api_call_dataset(self, cves_returned: int = 0, rate_limited: bool = False):
        """
        Dataset-specific API call recording (backward compatibility)
        
        Args:
            cves_returned: Number of CVEs returned by this API call
            rate_limited: Whether this call hit rate limiting
        """
        try:
            # Use the unified API recording method
            self.record_api_call("dataset_api", success=not rate_limited)
            
            # Update dataset-specific tracking
            if self.current_phase:
                self.current_phase["api_calls"] += 1
                self.current_phase["cves_processed"] += cves_returned
            
            # Update processing stats
            if cves_returned > 0:
                self.data["processing"]["total_cves"] = max(
                    self.data["processing"]["total_cves"], 
                    self.data["processing"]["processed_cves"] + cves_returned
                )
                
            self._auto_save()
            
        except Exception as e:
            logger.error(f"Failed to record dataset API call: {e}", group="collection")
    
    def record_error(self, error_message: str):
        """Record an error during processing - now handled by log parsing system"""
        try:
            # Actual error tracking is done through log file parsing in update_log_statistics()
            # This method just logs the error
            if logger:
                logger.error(error_message, group="collection")
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to record error: {e}", group="collection")
    
    def update_cve_statistics(self, cve_data: Dict[str, Any]):
        """
        Update CVE distribution statistics.
        
        Args:
            cve_data: CVE record data for statistical analysis
        """
        # Extract year from CVE ID (e.g., CVE-2024-12345 -> 2024)
        cve_id = cve_data.get('cve_id', '')
        if cve_id and cve_id.startswith('CVE-'):
            year = cve_id.split('-')[1]
            self.dataset_statistics['cve_distribution']['by_year'][year] = \
                self.dataset_statistics['cve_distribution']['by_year'].get(year, 0) + 1
        
        # Update status distribution
        status = cve_data.get('status', 'unknown')
        self.dataset_statistics['cve_distribution']['by_status'][status] = \
            self.dataset_statistics['cve_distribution']['by_status'].get(status, 0) + 1
        
        # Update source distribution
        source = cve_data.get('source', 'unknown')
        self.dataset_statistics['cve_distribution']['by_source'][source] = \
            self.dataset_statistics['cve_distribution']['by_source'].get(source, 0) + 1
    
    def complete_collection_phase(self) -> bool:
        """
        Complete the current collection phase and save to file.
        
        Returns:
            True if save successful, False otherwise
        """
        if not self.current_phase or not self.output_file_path:
            return False
        
        # Mark phase as completed
        self.current_phase['completed_at'] = datetime.now().isoformat()
        
        # Add to phases list
        self.collection_phases.append(self.current_phase)
        self.current_phase = None
        
        # Force save at phase completion for immediate workflow visibility
        self._auto_save(force=True)
        return self._save_to_file()
    
    def record_output_file(self, filename: str, file_path: str, cve_count: int, 
                          cve_id: str = None, dataframe_rows: int = None, 
                          processing_time: float = None, bloat_analysis: dict = None):
        """Record information about a generated output file
        
        Args:
            filename: Name of the generated file
            file_path: Full path to the generated file
            cve_count: Number of CVEs in the file (1 for individual CVE files)
            cve_id: Specific CVE ID for individual CVE files
            dataframe_rows: Number of platform entries/dataframe rows processed
            processing_time: Time spent processing this specific file
            bloat_analysis: Detailed bloat analysis data
        """
        try:
            # Get file size if file exists
            file_size = 0
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
            
            output_record = {
                'filename': filename,
                'path': file_path,
                'cve_count': cve_count,
                'file_size': file_size,
                'created_at': datetime.now().isoformat()
            }
            
            # Add enhanced fields for individual CVE files
            if cve_id:
                output_record['cve_id'] = cve_id
            if dataframe_rows is not None:
                output_record['dataframe_rows'] = dataframe_rows
            if processing_time is not None:
                output_record['processing_time'] = processing_time
            if bloat_analysis:
                output_record['bloat_analysis'] = bloat_analysis
            
            # Add to both new and old structures for compatibility
            self.output_files.append(output_record)
            self.data["file_stats"]["detailed_files"].append(output_record)
            
            # Keep only top 20 files by size to prevent bloat in large datasets
            # Dashboard shows "Top 20 Files" table
            if len(self.data["file_stats"]["detailed_files"]) > 20:
                # Sort by file size descending and keep top 20
                self.data["file_stats"]["detailed_files"].sort(key=lambda x: x.get('file_size', 0), reverse=True)
                self.data["file_stats"]["detailed_files"] = self.data["file_stats"]["detailed_files"][:20]
            
            # Update file stats - values will be calculated from detailed_files in _auto_save
            
            # Update size tracking
            if file_size > self.data["file_stats"]["largest_file_size"]:
                self.data["file_stats"]["largest_file_size"] = file_size
                self.data["file_stats"]["largest_file_name"] = filename
            
            if (self.data["file_stats"]["smallest_file_size"] is None or 
                file_size < self.data["file_stats"]["smallest_file_size"]):
                self.data["file_stats"]["smallest_file_size"] = file_size
                self.data["file_stats"]["smallest_file_name"] = filename
            
            # Calculate average
            files_count = self.data["file_stats"]["files_generated"]
            if files_count > 0:
                self.data["file_stats"]["average_file_size"] = self.data["file_stats"]["total_file_size"] / files_count
            
            # Update consolidated metadata for backward compatibility
            self.consolidated_metadata['unique_cves_count'] = cve_count
            
            if logger:
                logger.info(f"Recorded output file: {filename} with {cve_count} CVEs", group="collection")
            
            # Update current phase if active
            if self.current_phase:
                self.current_phase["files_generated"] += 1
            
            self._auto_save()
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to record output file {filename}: {e}", group="collection")

    def save_to_file(self, file_path: str) -> str:
        """Save the unified dashboard data to file using atomic write to prevent file locking"""
        try:
            # Update metadata before saving
            self.data["metadata"]["last_updated"] = datetime.now().isoformat()
            self.data["metadata"]["file_size"] = len(json.dumps(self.data, indent=2))
            
            # Add log file info if available
            if logger and hasattr(logger, 'current_log_path'):
                self.data["metadata"]["log_file"] = logger.current_log_path
                
                # Perform enhanced log analysis before saving final data
                try:
                    self.update_log_statistics()
                    if logger:
                        logger.debug("Enhanced log analysis completed and integrated into dashboard data", group="completion")
                except Exception as log_error:
                    if logger:
                        logger.error(f"Enhanced log analysis failed: {log_error}", group="completion")
            
            # Atomic write: Write to temporary file first, then rename
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            temp_file_path = file_path + '.tmp'
            
            # Write to temporary file
            with open(temp_file_path, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
            
            # Atomic rename - this is a single filesystem operation
            # Dashboard readers will either see old complete file or new complete file
            # Never a partial/corrupted file
            os.replace(temp_file_path, file_path)
            
            # Update file path
            self.output_file_path = file_path
            
            if logger:
                current_cve = self.data["processing"].get("current_cve", "None")
                progress = self.data["processing"].get("progress_percentage", 0.0)
                # Reduce logging frequency - only log dashboard saves at progress milestones
                if progress % 10.0 < 0.1 or progress >= 100.0:  # Log every 10% and at completion
                    logger.debug(f"Dashboard data saved: {file_path} (CVE: {current_cve}, Progress: {progress}%)", group="data_processing")
            
            return file_path
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to save dashboard data to {file_path}: {e}", group="completion")
            # Clean up temp file if it exists
            temp_file_path = file_path + '.tmp'
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except:
                    pass
            return None
    
    def _save_to_file(self) -> bool:
        """
        Save current state to the JSON file using unified data structure.
        
        Returns:
            True if save successful, False otherwise
        """
        if not self.output_file_path:
            return False
        
        try:
            # Use the unified save method to maintain real-time updates
            result = self.save_to_file(self.output_file_path)
            return result is not None
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to save dataset contents: {e}", group="dataset_generation")
            return False
    
    def finalize_report(self) -> Optional[str]:
        """
        Finalize the dataset contents report at the end of a generation run.
        
        Returns:
            Path to the finalized report file, or None if failed
        """
        if not self.output_file_path:
            return None
        
        # Complete any active phase
        if self.current_phase:
            self.complete_collection_phase()
        
        try:
            # Get log file path from workflow logger if available
            log_file_path = None
            if logger and hasattr(logger, 'current_log_path'):
                log_file_path = logger.current_log_path
            
            # Update final metadata and mark as complete
            export_data = {
                'metadata': {
                    **self.consolidated_metadata,
                    'run_completed_at': datetime.now().isoformat(),
                    'report_scope': 'Dataset Generation Metrics and Statistics',
                    'status': 'completed'
                },
                'collection_phases': self.collection_phases,
                'dataset_statistics': self.dataset_statistics,
                'output_files': self.output_files
            }
            
            # Add log file path if available
            if log_file_path:
                export_data['metadata']['log_file'] = log_file_path
            
            # Write final version to JSON file using atomic write
            temp_file_path = self.output_file_path + '.tmp'
            with open(temp_file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            os.replace(temp_file_path, self.output_file_path)
            
            # Print final summary
            total_cves = self.consolidated_metadata['total_cves_collected']
            total_calls = self.consolidated_metadata['total_api_calls']
            phases_count = len(self.collection_phases)
            
            if logger:
                logger.info(f"Dataset generation report complete: {total_cves} CVEs collected, "
                          f"{total_calls} API calls, {phases_count} phases", group="completion")
            
            return self.output_file_path
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to finalize dataset contents report: {e}", group="completion")
            return None

# Global collector instance
_dataset_contents_collector = None

def get_dataset_contents_collector() -> UnifiedDashboardCollector:
    """Get the global dataset contents collector instance."""
    global _dataset_contents_collector
    if _dataset_contents_collector is None:
        _dataset_contents_collector = UnifiedDashboardCollector()
    return _dataset_contents_collector

def clear_dataset_contents_collector():
    """Clear the global dataset contents collector for a new run."""
    global _dataset_contents_collector
    _dataset_contents_collector = None

def initialize_dataset_contents_report(logs_directory: str) -> bool:
    """Initialize the dataset contents report file for incremental updates."""
    collector = get_dataset_contents_collector()
    return collector.initialize_output_file(logs_directory)

def start_collection_phase(phase_name: str, data_source: str = "nvd_api"):
    """Initialize dataset collection for a new phase."""
    collector = get_dataset_contents_collector()
    collector.start_collection_phase(phase_name, data_source)

def record_api_call(cves_returned: int = 0, rate_limited: bool = False):
    """Record an API call during dataset generation."""
    collector = get_dataset_contents_collector()
    collector.record_api_call_dataset(cves_returned, rate_limited)

def record_output_file(filename: str, file_path: str, cve_count: int, 
                       cve_id: str = None, dataframe_rows: int = None, 
                       processing_time: float = None, bloat_analysis: dict = None):
    """Record information about a generated output file."""
    collector = get_dataset_contents_collector()
    collector.record_output_file(filename, file_path, cve_count, cve_id, 
                                dataframe_rows, processing_time, bloat_analysis)

def get_current_cve_processing_time() -> Optional[float]:
    """Get the current processing time for the active CVE, if any."""
    collector = get_dataset_contents_collector()
    return collector.get_current_cve_processing_time()

def finalize_dataset_contents_report() -> Optional[str]:
    """Finalize the dataset contents report at the end of a generation run."""
    collector = get_dataset_contents_collector()
    
    # Update cache file size before finalizing
    try:
        collector.update_cache_file_size()
    except Exception as e:
        if logger:
            logger.warning(f"Could not update cache file size during finalization: {e}", group="completion")
    
    # Finalize CPE statistics
    try:
        collector.finalize_cpe_stats()
    except Exception as e:
        if logger:
            logger.warning(f"Could not finalize CPE statistics: {e}", group="completion")
    
    return collector.finalize_report()

# =============================================================================
# Analysis Tool Integration Functions (from realtime_dashboard_collector)
# =============================================================================

def start_processing_run(total_cves: int):
    """Start processing run with CVE count"""
    collector = get_dataset_contents_collector()
    collector.start_processing_run(total_cves)

def start_cve_processing(cve_id: str):
    """Start processing a specific CVE"""
    collector = get_dataset_contents_collector()
    collector.start_cve_processing(cve_id)

def finish_cve_processing(cve_id: str):
    """Complete processing for a CVE"""
    collector = get_dataset_contents_collector()
    collector.finish_cve_processing(cve_id)

def record_api_call_unified(api_type: str, success: bool = True, response_time: float = 0.0):
    """Record API call statistics"""
    collector = get_dataset_contents_collector()
    collector.record_api_call(api_type, success, response_time)

def record_cache_activity(cache_result: str, cache_size: int = 0, api_calls_saved: int = 0):
    """
    Record cache activity statistics
    
    Args:
        cache_result (str): 'hit', 'miss', or 'expired'
        cache_size (int): Current cache size in bytes
        api_calls_saved (int): Number of API calls saved (only for hits)
    """
    collector = get_dataset_contents_collector()
    collector.record_cache_activity(cache_result, cache_size, api_calls_saved)

def update_cache_statistics():
    """Update cache statistics with actual cache data from CPE cache"""
    collector = get_dataset_contents_collector()
    collector.update_cache_statistics()

def update_cache_file_size(cache_file_path: Optional[str] = None):
    """Update cache file size by checking the actual cache file on disk"""
    collector = get_dataset_contents_collector()
    collector.update_cache_file_size(cache_file_path)

def record_mapping_activity(mappings_found: int, platform_entries: int):
    """Record platform mapping statistics"""
    collector = get_dataset_contents_collector()
    collector.record_mapping_activity(mappings_found, platform_entries)

def record_cpe_query(base_string: str, result_count: int, cve_id: str = None):
    """
    Record CPE query details for analytics
    
    Args:
        base_string (str): The CPE base string that was queried
        result_count (int): Number of results returned by the query
        cve_id (str): Associated CVE ID (optional)
    """
    collector = get_dataset_contents_collector()
    collector.record_cpe_query(base_string, result_count, cve_id)

def finalize_cpe_stats():
    """Finalize CPE statistics at the end of processing"""
    collector = get_dataset_contents_collector()
    collector.finalize_cpe_stats()

def save_dashboard_data(file_path: str) -> str:
    """Save dashboard data to file"""
    collector = get_dataset_contents_collector()
    return collector.save_to_file(file_path)

def record_stage_start(stage_name: str):
    """Record the start of a processing stage"""
    collector = get_dataset_contents_collector()
    collector.record_stage_start(stage_name)

def record_stage_end(stage_name: str):
    """Record the end of a processing stage"""
    collector = get_dataset_contents_collector()
    collector.record_stage_end(stage_name)

def initialize_dashboard_collector(logs_directory: str) -> bool:
    """Initialize the dashboard collector with output directory"""
    try:
        collector = get_dataset_contents_collector()
        output_file = os.path.join(logs_directory, "generateDatasetReport.json")
        collector.output_file_path = output_file
        
        # Create initial file with unified data structure
        result = collector.save_to_file(output_file)
        
        if logger:
            logger.info(f"Dashboard collector initialized: {output_file}", group="initialization")
        
        return result is not None
        
    except Exception as e:
        if logger:
            logger.error(f"Failed to initialize dashboard collector: {e}", group="initialization")
        return False
