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
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Import the structured logging system
try:
    from .workflow_logger import get_logger, LogGroup
    logger = get_logger()
except ImportError:
    # GRACEFUL DEGRADATION: Testing environment compatibility
    # Allows collector to function without logger dependency in test scenarios
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
            'generation_time': datetime.now(timezone.utc).isoformat(),
            'data_source': 'nvd_api',
            'total_api_calls': 0,
            'total_cves_collected': 0,
            'unique_cves_count': 0,
            'run_started_at': datetime.now(timezone.utc).isoformat()
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
        self._last_save_time = datetime.now(timezone.utc)
        self._save_interval_seconds = 5  # Save every 5 seconds at most
        self._save_every_n_operations = 100  # Or every 100 operations (increased from 50)
        
        # Initialize temporary tracking dictionaries
        self._temp_query_tracking = {}
        self._temp_cve_tracking = {}
        
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
                logger.info(f"Configuration File Loaded:  {toolname} v{version}", group="INIT")
                self.__class__._config_logged = True
                
        except Exception as e:
            # GRACEFUL DEGRADATION: Dashboard metadata defaults for presentation layer
            # Provides safe display values when config.json is unavailable (non-critical functionality)
            self.data["metadata"]["toolname"] = "Analysis_Tools"
            self.data["metadata"]["version"] = "Unknown"
            self.data["metadata"]["config_loaded"] = False
            self.data["metadata"]["config_error"] = str(e)
            
            if logger:
                logger.warning(f"Could not load config for injection: {e}", group="INIT")
    
    def _json_datetime_handler(self, obj):
        """
        JSON serialization handler for datetime objects.
        Converts datetime objects to ISO format strings for JSON serialization.
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    def _initialize_data_structure(self) -> Dict[str, Any]:
        """Initialize the unified dashboard data structure"""
        return {
            "metadata": {
                "generated_by": "unified_dashboard_collector",
                "generation_time": datetime.now(timezone.utc).isoformat(),
                "log_file": "unified_collection",
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "file_size": 0,
                "run_started_at": datetime.now(timezone.utc).isoformat(),
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
                "median_file_size": 0.0,
                "file_sizes": [],  # Store individual file sizes for median calculation
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
            self.processing_start_time = datetime.now(timezone.utc)
            self.data["processing"]["total_cves"] = total_cves
            self.data["processing"]["remaining_cves"] = total_cves
            self.data["processing"]["start_time"] = self.processing_start_time.isoformat()
            self.data["metadata"]["run_started_at"] = self.processing_start_time.isoformat()
            
            # Reset counters for new run
            self.data["processing"]["processed_cves"] = 0
            self.data["processing"]["progress_percentage"] = 0.0
            
            
        except Exception as e:
            logger.error(f"Failed to start processing run: {e}", group="data_processing")

    def start_cve_processing(self, cve_id: str):
        """Start processing a specific CVE"""
        try:
            self.data["processing"]["current_cve"] = cve_id
            self.current_processing_cve = cve_id  # Set the current processing CVE for log entry attribution
            self.current_cve_start_time = datetime.now(timezone.utc)
            
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
                progress_pct = round((processed / total) * 100, 2)
                self.data["processing"]["progress_percentage"] = progress_pct
                self.data["processing"]["remaining_cves"] = total - processed
                
                # Update ETA using unified calculation
                self._update_eta()
            
            # Force auto-save for critical CVE milestone
            self._auto_save(force=True)
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to start CVE processing for {cve_id}: {e}", group="data_processing")

    def finish_cve_processing(self, cve_id: str, skipped: bool = False):
        """Complete processing for a specific CVE"""
        try:
            if hasattr(self, 'current_cve_start_time') and self.current_cve_start_time:
                processing_time = (datetime.now(timezone.utc) - self.current_cve_start_time).total_seconds()
                
                # Only update performance stats for actually processed CVEs (not rejected/skipped)
                # Rejected CVEs would skew timing statistics since they exit immediately
                if not skipped:
                    self.data["performance"]["count"] += 1
                    self.data["performance"]["total_time"] += processing_time
                    self.data["performance"]["active_processing_time"] = self.data["performance"]["total_time"]
                    self.data["performance"]["average_time"] = self.data["performance"]["total_time"] / self.data["performance"]["count"]
                    
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
                
                # Always calculate wall clock time regardless of skipped status
                if self.processing_start_time:
                    wall_clock_elapsed = (datetime.now(timezone.utc) - self.processing_start_time).total_seconds()
                    self.data["performance"]["wall_clock_time"] = wall_clock_elapsed
                    self.data["performance"]["total_runtime"] = wall_clock_elapsed
                    
                    # Calculate overhead (wall clock - active processing)
                    active_time = self.data["performance"]["active_processing_time"]
                    self.data["performance"]["overhead_time"] = max(0, wall_clock_elapsed - active_time)
            
            # Always update processed count - rejected CVEs were still "processed" from workflow perspective
            self.data["processing"]["processed_cves"] += 1
            processed = self.data["processing"]["processed_cves"]
            total = self.data["processing"]["total_cves"]
            
            if total > 0:
                # Calculate progress percentage - should match main analysis tool calculation
                progress_pct = round((processed / total) * 100, 2)
                
                # Warn if progress exceeds 100% (indicates a bug in progress tracking)
                if progress_pct > 100.0:
                    logger.warning(f"Progress tracking bug detected: processed={processed}, total={total}, progress={progress_pct}% - this indicates finish_cve_processing is being called more than once per CVE", group="data_processing")
                
                self.data["processing"]["progress_percentage"] = progress_pct
                self.data["processing"]["remaining_cves"] = max(0, total - processed)  # Ensure remaining doesn't go negative
                
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
                        timeline_entry['end_time'] = datetime.now(timezone.utc).isoformat()
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
            return (datetime.now(timezone.utc) - self.current_cve_start_time).total_seconds()
        return None

    def update_cve_affected_entries_count(self, cve_id: str, affected_entries_count: int):
        """Update the final affected entries count for a CVE after all processing is complete"""
        try:
            # Update the temp tracking with the final accurate count
            if cve_id in self._temp_cve_tracking:
                self._temp_cve_tracking[cve_id]["affected_entries"] = affected_entries_count
                
                if logger:
                    logger.debug(f"Updated final affected entries count for {cve_id}: {affected_entries_count}", group="data_processing")
                
                # Regenerate top lists with updated data
                self._update_cpe_top_lists_from_temp()
                
        except Exception as e:
            if logger:
                logger.error(f"Failed to update affected entries count for {cve_id}: {e}", group="data_processing")

    # ========================================================================
    # STREAMLINED EVENT ATTRIBUTION - Direct at Source
    # ========================================================================
    
    def record_cve_warning(self, message: str, category: str = "data_processing_warnings"):
        """Record a warning directly associated with the current CVE (STREAMLINED)"""
        warning_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message.strip(),
            "cve_id": self.current_processing_cve or "system",
            "level": "warning"
        }
        
        # Ensure category exists
        if category not in self.data["warnings"]:
            self.data["warnings"][category] = []
            
        self.data["warnings"][category].append(warning_entry)
        

    def record_cve_error(self, message: str, category: str = "processing_errors"):
        """Record an error directly associated with the current CVE (STREAMLINED)"""
        error_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message.strip(), 
            "cve_id": self.current_processing_cve or "system",
            "level": "error"
        }
        
        # Ensure category exists
        if category not in self.data["errors"]:
            self.data["errors"][category] = []
            
        self.data["errors"][category].append(error_entry)
        

    def record_cve_info(self, message: str, category: str = "processing_info"):
        """Record informational event directly associated with the current CVE (STREAMLINED)"""
        # Add info tracking if needed for dashboard
        if "info_events" not in self.data:
            self.data["info_events"] = {}
            
        if category not in self.data["info_events"]:
            self.data["info_events"][category] = []
            
        info_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message.strip(),
            "cve_id": self.current_processing_cve or "system",
            "level": "info"
        }
        
        self.data["info_events"][category].append(info_entry)

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
                
                
        except Exception as e:
            logger.debug(f"Failed to update cache statistics: {e}", group="data_processing")

    def update_cache_file_size(self, cache_file_path: Optional[str] = None):
        """
        Update cache file size by checking the actual cache file on disk.
        
        Args:
            cache_file_path: Optional path to cache file. If not provided, will get it from cache manager.
            
        """
        try:
            if cache_file_path is None:
                # Get the cache file path from the global cache manager
                from ..storage.cpe_cache import get_global_cache_manager
                cache_manager = get_global_cache_manager()
                
                if not cache_manager.is_initialized():
                    # Cache not initialized - this is expected when called from generate_dataset
                    # after analysis_tool has completed. Skip the update silently.
                    if logger:
                        logger.debug("CPE cache not initialized - skipping cache file size update (expected in dataset generation context)", group="completion")
                    return
                    
                cache = cache_manager.get_cache()
                cache_file_path = str(cache.cache_file)
            
            if not cache_file_path:
                if logger:
                    logger.debug("No CPE cache file path available - skipping cache file size update", group="completion")
                return
                
            if not os.path.exists(cache_file_path):
                if logger:
                    logger.debug(f"CPE cache file does not exist at {cache_file_path} - skipping cache file size update", group="completion")
                return
            
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
                
        except Exception as e:
            if logger:
                logger.error(f"Failed to update CPE cache file size: {e}", group="data_processing")
            raise  # Re-raise to fail fast

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
            
            
        except Exception as e:
            logger.error(f"Failed to record mapping activity: {e}", group="data_processing")

    def record_cpe_query(self, base_string: str, result_count: int, cve_id: str = None, platform_entry_count: int = None):
        """
        Record CPE query details for analytics - stores only essential data for top lists
        
        Args:
            base_string (str): The CPE base string that was queried
            result_count (int): Number of results returned by the query
            cve_id (str): Associated CVE ID (optional)
            platform_entry_count (int): Number of platform entries for this CVE (optional)
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
                    self._temp_cve_tracking[cve_id] = {
                        "search_count": 0, 
                        "total_results": 0,
                        "affected_entries": 0
                    }
                self._temp_cve_tracking[cve_id]["search_count"] += 1
                self._temp_cve_tracking[cve_id]["total_results"] += result_count
                
                # Track platform entries (affected entries) - only set once per CVE
                if platform_entry_count is not None and self._temp_cve_tracking[cve_id]["affected_entries"] == 0:
                    self._temp_cve_tracking[cve_id]["affected_entries"] = platform_entry_count
            
            # Update averages
            total_queries = self.data["cpe_query_stats"]["total_queries"]
            total_results = self.data["cpe_query_stats"]["total_results"]
            if total_queries > 0:
                self.data["cpe_query_stats"]["avg_results_per_query"] = round(total_results / total_queries, 1)
            
            # Generate top lists immediately from temp data (no periodic delay needed)
            self._update_cpe_top_lists_from_temp()
            
            
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
                    "total_cve_count": len(cve_list)  # Total number of associated CVEs
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
                        "total_results": data["total_results"],
                        "affected_entries": data.get("affected_entries", 0)
                    })
                
                # Sort by search count descending and keep top 20
                top_cves_by_searches.sort(key=lambda x: x["search_count"], reverse=True)
                self.data["cpe_query_stats"]["top_cves_by_searches"] = top_cves_by_searches[:20]
            
            # Generate top queries by count
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
                
            # Legacy data structure support
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
            
            # Also update the top_queries format
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
            
            self.data["stages"][stage_name]["started"] = datetime.now(timezone.utc).isoformat()
            self.data["stages"][stage_name]["status"] = "in_progress"
            
        except Exception as e:
            logger.error(f"Failed to record stage start for {stage_name}: {e}", group="data_processing")

    def record_stage_end(self, stage_name: str):
        """Record the end of a processing stage"""
        try:
            end_time = datetime.now(timezone.utc)
            
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
                            warnings_count = sum(len(entries) for entries in self.data['warnings'].values() if isinstance(entries, list))
                            errors_count = sum(len(entries) for entries in self.data['errors'].values() if isinstance(entries, list))
                            logger.debug(f"Preserving {warnings_count} warnings and {errors_count} errors from real-time attribution", group="data_processing")
                    
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
                'start_time': datetime.now(timezone.utc).isoformat(),
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
            eta_timestamp = datetime.now(timezone.utc) + timedelta(seconds=estimated_seconds)
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
            now = datetime.now(timezone.utc)
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
                logger.info("Generate Dataset Report initialized: /logs/generateDatasetReport.json", group="INIT")
            
            return True
            
        except Exception as e:
            if logger:
                logger.error(f"Generate Dataset report file initialization failed: {e}", group="INIT")
            return False
    
    # =============================================================================
    # Dataset Generation Methods
    # =============================================================================
    
    def start_collection_phase(self, phase_name: str, data_source: str = "nvd_api"):
        """Start a new collection phase for dataset generation"""
        try:
            # Update metadata with phase information
            self.data["metadata"]["workflow_phase"] = phase_name
            self.data["metadata"]["data_source"] = data_source
            self.data["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
            
            # Create current phase tracking
            self.current_phase = {
                "name": phase_name,
                "data_source": data_source,
                "start_time": datetime.now(timezone.utc),
                "api_calls": 0,
                "files_generated": 0,
                "cves_processed": 0
            }
            
            logger.info(f"Starting NVD 2.0 and CVE List v5 record cache preparation phase", group="CACHE_MANAGEMENT")
            
        except Exception as e:
            logger.error(f"Failed to start collection phase {phase_name}: {e}", group="INIT")
    
    def update_cve_discovery_progress(self, current_count: int, total_count: int, matched_cves: int = 0):
        """Update progress during CVE list generation phase"""
        try:
            if total_count > 0:
                progress_pct = (current_count / total_count) * 100
                self.data["processing"]["progress_percentage"] = round(progress_pct, 1)
                self.data["processing"]["current_cve"] = f"Discovering CVEs: {matched_cves} found"
                self.data["processing"]["eta_simple"] = f"Scanning {current_count}/{total_count} CVEs"
                
                
        except Exception as e:
            logger.error(f"Failed to update CVE discovery progress: {e}", group="collection")
    
    def record_api_call_dataset(self, cves_returned: int = 0, rate_limited: bool = False):
        """
        Dataset-specific API call recording
        
        Args:
            cves_returned: Number of CVEs returned by this API call
            rate_limited: Whether this call hit rate limiting
        """
        try:
            # Use the unified API recording method with proper NVD CVE API identifier
            self.record_api_call("NVD CVE API", success=not rate_limited)
            
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
                
            
        except Exception as e:
            logger.error(f"Failed to record dataset API call: {e}", group="collection")
    
    def record_error(self, error_message: str):
        """Record an error during processing - handled by real-time logging system"""
        try:
            # Error tracking is handled in real-time through record_cve_error()
            # This method just logs the error for immediate visibility
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
        self.current_phase['completed_at'] = datetime.now(timezone.utc).isoformat()
        
        # Add to phases list
        self.collection_phases.append(self.current_phase)
        self.current_phase = None
        
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
                'created_at': datetime.now(timezone.utc).isoformat()
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
            
            # Update size tracking
            if file_size > self.data["file_stats"]["largest_file_size"]:
                self.data["file_stats"]["largest_file_size"] = file_size
                self.data["file_stats"]["largest_file_name"] = filename
            
            if (self.data["file_stats"]["smallest_file_size"] is None or 
                file_size < self.data["file_stats"]["smallest_file_size"]):
                self.data["file_stats"]["smallest_file_size"] = file_size
                self.data["file_stats"]["smallest_file_name"] = filename
            
            # Store file size for median calculation
            self.data["file_stats"]["file_sizes"].append(file_size)
            
            # Calculate median file size
            files_count = self.data["file_stats"]["files_generated"]
            if files_count > 0:
                import statistics
                self.data["file_stats"]["median_file_size"] = statistics.median(self.data["file_stats"]["file_sizes"])
            
            # Update consolidated metadata
            self.consolidated_metadata['unique_cves_count'] = cve_count
            
            
            # Update current phase if active
            if self.current_phase:
                self.current_phase["files_generated"] += 1
            
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to record output file {filename}: {e}", group="collection")

    def save_to_file(self, file_path: str) -> str:
        """Save the unified dashboard data to file using atomic write to prevent file locking"""
        try:
            # Update metadata before saving
            self.data["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
            self.data["metadata"]["file_size"] = len(json.dumps(self.data, indent=2))
            
            # Add log file info if available
            if logger and hasattr(logger, 'current_log_path'):
                self.data["metadata"]["log_file"] = logger.current_log_path
            
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
                status = self.data["metadata"].get("status", "")
                
                # Skip logging for final "completed" saves to avoid duplicate messages
                # Reduce logging frequency - only log dashboard saves at progress milestones (skip initialization at 0%)
                if status != "completed" and progress > 0 and (progress % 10.0 < 0.1 or progress >= 100.0):  # Log every 10% and at completion
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
            # Update final metadata
            self.data["metadata"]["run_completed_at"] = datetime.now(timezone.utc).isoformat()
            self.data["metadata"]["report_scope"] = "Dataset Generation Metrics and Statistics"
            self.data["metadata"]["status"] = "completed"
            self.data["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
            
            # Add log file path if available
            if logger and hasattr(logger, 'current_log_path'):
                self.data["metadata"]["log_file"] = logger.current_log_path
            
            # Use the standard save_to_file method to save the complete data structure
            return self.save_to_file(self.output_file_path)
            
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

def update_total_cves(total_cves: int):
    """Update the total CVE count to synchronize with actual processing count"""
    collector = get_dataset_contents_collector()
    if collector:
        collector.data["processing"]["total_cves"] = total_cves
        collector.data["processing"]["remaining_cves"] = total_cves - collector.data["processing"]["processed_cves"]

def start_cve_processing(cve_id: str):
    """Start processing a specific CVE"""
    collector = get_dataset_contents_collector()
    collector.start_cve_processing(cve_id)

def update_cve_affected_entries_count(cve_id: str, affected_entries_count: int):
    """Update the final affected entries count for a CVE after all processing is complete"""
    collector = get_dataset_contents_collector()
    collector.update_cve_affected_entries_count(cve_id, affected_entries_count)

def finish_cve_processing(cve_id: str, skipped: bool = False):
    """Complete processing for a CVE"""
    collector = get_dataset_contents_collector()
    collector.finish_cve_processing(cve_id, skipped)

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

def record_cpe_query(base_string: str, result_count: int, cve_id: str = None, platform_entry_count: int = None):
    """
    Record CPE query details for analytics
    
    Args:
        base_string (str): The CPE base string that was queried
        result_count (int): Number of results returned by the query
        cve_id (str): Associated CVE ID (optional)  
        platform_entry_count (int): Number of platform entries for this CVE (optional)
    """
    collector = get_dataset_contents_collector()
    collector.record_cpe_query(base_string, result_count, cve_id, platform_entry_count)

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

def update_cve_discovery_progress(current_count: int, total_count: int, matched_cves: int = 0):
    """Update progress during CVE list generation phase"""
    collector = get_dataset_contents_collector()
    collector.update_cve_discovery_progress(current_count, total_count, matched_cves)
def _set_tracked_properties_for_mode(collector, processing_mode: str, cache_disabled: bool = False, cache_disable_reason: str = None):
    """Set tracked properties for each data section based on processing mode"""
    # Default all sections to tracked for full mode
    is_full_mode = processing_mode == "full"
    is_sdc_only = processing_mode == "sdc-only"
    is_test_mode = processing_mode == "test"
    
    # Cache section - set tracking and note based on disable reason
    collector.data["cache"]["tracked"] = is_full_mode and not cache_disabled
    if cache_disabled or not is_full_mode:
        # Set specific note based on disable reason
        if cache_disable_reason == "manual":
            collector.data["cache"]["note"] = "Cache manually disabled with --no-cache flag"
        elif cache_disable_reason == "sdc-only" or is_sdc_only:
            collector.data["cache"]["note"] = "Cache automatically disabled - CPE features disabled (--sdc-only)"
        elif cache_disable_reason == "test-file" or is_test_mode:
            collector.data["cache"]["note"] = "Cache automatically disabled for test file mode (--test-file)"
        else:
            collector.data["cache"]["note"] = "Cache functionality disabled"
    
    # API section - limited tracking in sdc-only (only MITRE CVE API)
    collector.data["api"]["tracked"] = True  # Always track API calls
    collector.data["api"]["tracking_note"] = {
        "full": "All API calls tracked",
        "sdc-only": "NVD /cpe/ API calls skipped - CPE features disabled",
        "test": "Limited API calls in test mode"
    }.get(processing_mode, "API tracking enabled")
    
    # File stats - not tracked in sdc-only (no HTML files generated)
    collector.data["file_stats"]["tracked"] = not is_sdc_only
    if is_sdc_only:
        collector.data["file_stats"]["note"] = "HTML file generation skipped - CPE features disabled"
    
    # CPE query stats - not tracked in sdc-only (no CPE queries)
    collector.data["cpe_query_stats"]["tracked"] = is_full_mode
    if is_sdc_only:
        collector.data["cpe_query_stats"]["note"] = "CPE queries skipped - CPE features disabled"
    
    # Mapping stats - not tracked in sdc-only (no confirmed mappings)
    collector.data["mapping_stats"]["tracked"] = is_full_mode
    if is_sdc_only:
        collector.data["mapping_stats"]["note"] = "Confirmed mappings skipped - CPE features disabled"
    
    # Performance, processing, log_stats, warnings, errors always tracked
    collector.data["performance"]["tracked"] = True
    collector.data["processing"]["tracked"] = True
    collector.data["log_stats"]["tracked"] = True
    collector.data["warnings"]["tracked"] = True
    collector.data["errors"]["tracked"] = True
    
    # Speed stats - always tracked (measures CVE processing speed)
    collector.data["speed_stats"]["tracked"] = True
    
    # Bloat analysis - deprecated functionality, always set to false
    collector.data["bloat_analysis"]["tracked"] = False
    collector.data["bloat_analysis"]["note"] = "Bloat analysis is deprecated and disabled"

def initialize_dashboard_collector(logs_directory: str, processing_mode: str = "full", cache_disabled: bool = False, cache_disable_reason: str = None) -> bool:
    """Initialize the dashboard collector with output directory and processing mode
    
    Args:
        logs_directory: Path to logs directory
        processing_mode: Processing mode ('full', 'sdc-only', 'test')
        cache_disabled: Whether cache is disabled
        cache_disable_reason: Reason for cache being disabled ('manual', 'sdc-only', 'test-file')
    """
    try:
        collector = get_dataset_contents_collector()
        
        # Set processing mode for tracked property management
        collector.processing_mode = processing_mode
        output_file = os.path.join(logs_directory, "generateDatasetReport.json")
        collector.output_file_path = output_file
        
        # Check if existing data exists from dataset generation phase
        file_existed = os.path.exists(output_file)
        if file_existed:
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
                
                # Preserve dataset generation metrics while transitioning to analysis phase
                if "api" in existing_data and existing_data["api"].get("nvd_cve_calls", 0) > 0:
                    # Merge existing API statistics
                    collector.data["api"]["nvd_cve_calls"] = existing_data["api"].get("nvd_cve_calls", 0)
                    collector.data["api"]["total_calls"] = existing_data["api"].get("total_calls", 0)
                    collector.data["api"]["successful_calls"] = existing_data["api"].get("successful_calls", 0)
                    collector.data["api"]["failed_calls"] = existing_data["api"].get("failed_calls", 0)
                    
                    # Preserve call breakdown if it exists
                    if "call_breakdown" in existing_data["api"]:
                        collector.data["api"]["call_breakdown"].update(existing_data["api"]["call_breakdown"])
                    
                    if logger:
                        logger.info(f"Preserved dataset generation metrics: {collector.data['api']['nvd_cve_calls']} NVD CVE calls", group="INIT")
                
                # Preserve collection phases from dataset generation
                if "collection_phases" in existing_data:
                    collector.collection_phases = existing_data["collection_phases"]
                
                # Update metadata to indicate transition to analysis phase
                collector.data["metadata"]["workflow_phase"] = "analysis_processing"
                collector.data["metadata"]["previous_phase"] = "dataset_generation"
                
            except (json.JSONDecodeError, KeyError) as e:
                if logger:
                    logger.warning(f"Could not parse existing dashboard data, starting fresh: {e}", group="INIT")
        
        # Add processing mode metadata
        collector.data["metadata"]["processing_mode"] = processing_mode
        collector.data["metadata"]["processing_mode_description"] = {
            "full": "Complete analysis with NVD CPE API calls and HTML generation",
            "sdc-only": "Source Data Concerns analysis only - skips NVD CPE API calls and HTML generation",
            "test": "Test mode with local test files"
        }.get(processing_mode, "Unknown processing mode")
        
        # Set tracked properties based on processing mode
        _set_tracked_properties_for_mode(collector, processing_mode, cache_disabled, cache_disable_reason)
        
        # Save the potentially merged data
        result = collector.save_to_file(output_file)
        
        if logger:
            if file_existed:
                logger.info("Generate Dataset Report: Already initialized", group="INIT")
            else:
                logger.info("Generate Dataset Report initialized: /logs/generateDatasetReport.json", group="INIT")
        
        return result is not None
        
    except Exception as e:
        if logger:
            logger.error(f"Failed to initialize dashboard collector: {e}", group="INIT")
        return False
