#!/usr/bin/env python3
"""
Hashmire/Analysis_Tools Dashboard Data Generator
Parses log files and generates JSON data for the dashboard
"""

import json
import re
import os
import glob
from datetime import datetime, timedelta
from pathlib import Path
import argparse

def get_analysis_tools_root():
    """Get the absolute path to the Analysis_Tools project root"""
    current_file = Path(__file__).resolve()
    # Navigate up from src/analysis_tool/utilities/log_analyzer.py to Analysis_Tools/
    # log_analyzer.py -> utilities/ -> analysis_tool/ -> src/ -> Analysis_Tools/
    return current_file.parent.parent.parent.parent

def resolve_log_directory(log_dir_param):
    """Resolve log directory - if relative, try run-specific first, then project root"""
    if os.path.isabs(log_dir_param):
        return log_dir_param
    else:
        project_root = get_analysis_tools_root()
        
        # For run-based structure, try to find the most recent run's logs directory
        runs_dir = project_root / "runs"
        if runs_dir.exists():
            # Find most recent run directory
            run_dirs = [d for d in runs_dir.iterdir() if d.is_dir()]
            if run_dirs:
                # Sort by creation time (most recent first)
                run_dirs.sort(key=lambda x: x.stat().st_ctime, reverse=True)
                latest_run_logs = run_dirs[0] / "logs"
                if latest_run_logs.exists():
                    return str(latest_run_logs)
        
        # Fallback to old global logs directory
        return str(project_root / log_dir_param)

def resolve_output_path(output_file):
    """Resolve output file path - absolute paths only, no fallback behavior"""
    if os.path.isabs(output_file):
        return output_file
    else:
        raise RuntimeError(f"Relative output path '{output_file}' not supported - unified runs structure requires absolute paths. "
                          "The main analysis tool should provide the full run-specific path.")

class LogAnalyzer:
    def __init__(self, log_directory="logs"):
        self.log_directory = resolve_log_directory(log_directory)
        self.data = {}
        self.current_processing_cve = None  # Track current CVE being processed
        self.all_log_messages = []  # Store all log messages for additional analysis
        self.current_cpe_query_string = None  # Track current CPE query string for result association
        self.processed_files = set()  # Track files to prevent double-counting
        self.cve_processing_data = {}  # Track detailed processing data for each CVE
    
    def format_file_size(self, size_bytes):
        """Format file size in human-readable format (B, KB, MB, GB)"""
        if size_bytes is None:
            return "0 B"
        
        if size_bytes >= 1024**3:  # GB
            return f"{size_bytes / (1024**3):.1f} GB"
        elif size_bytes >= 1024**2:  # MB
            return f"{size_bytes / (1024**2):.1f} MB"
        elif size_bytes >= 1024:  # KB
            return f"{size_bytes / 1024:.1f} KB"
        else:  # Bytes
            return f"{size_bytes} B"
    
    def _get_effectiveness_rating(self, space_savings):
        """Get effectiveness rating based on space savings percentage"""
        if space_savings >= 80:
            return "🔥 Excellent"
        elif space_savings >= 60:
            return "⚡ Very Good"
        elif space_savings >= 40:
            return "📊 Good"
        elif space_savings >= 20:
            return "📋 Moderate"
        else:
            return "⚠️ Low"
        
    def find_latest_log(self):
        """Find the most recent log file"""
        log_pattern = os.path.join(self.log_directory, "*.log")
        log_files = glob.glob(log_pattern)
        
        if not log_files:
            return None
            
        # Sort by modification time, newest first
        log_files.sort(key=os.path.getmtime, reverse=True)
        return log_files[0]
    
    def parse_log_file(self, log_file_path):
        """Parse a log file and extract relevant metrics"""
        # Store log file path for later use
        self.current_log_file = log_file_path
        
        if not os.path.exists(log_file_path):
            raise FileNotFoundError(f"Log file not found: {log_file_path}")
        
        with open(log_file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Initialize data structure
        self.data = {
            "metadata": {
                "log_file": log_file_path,
                "last_updated": datetime.now().isoformat(),
                "file_size": os.path.getsize(log_file_path)
            },
            "processing": {
                "total_cves": 0,
                "processed_cves": 0,
                "current_cve": None,
                "start_time": None,
                "end_time": None,
                "progress_percentage": 0,
                "eta": None,
                "remaining_cves": 0
            },
            "performance": {
                "processing_times": [],
                "average_time": 0,
                "processing_rate": 0,
                "total_runtime": 0
            },
            "cache": {
                "total_entries": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "hit_rate": 0,
                "api_calls_saved": 0,
                "cache_file_size": 0,
                "cache_file_size_formatted": "0 KB"
            },
            "api": {
                "total_calls": 0,
                "nvd_cve_calls": 0,
                "mitre_cve_calls": 0,
                "nvd_cpe_calls": 0,
                "successful_calls": 0,
                "failed_calls": 0,
                "call_breakdown": {}  # Added for detailed API call categorization
            },
            "log_stats": {
                "total_lines": len(lines),
                "info_count": 0,
                "debug_count": 0,
                "warning_count": 0,
                "error_count": 0
            },
            "file_stats": {
                "files_generated": 0,
                "largest_file_size": 0,
                "smallest_file_size": None,
                "largest_file_name": "",
                "smallest_file_name": "",
                "total_file_size": 0,
                "average_file_size": 0,
                "detailed_files": []  # List of detailed file info for top files table
            },
            "deduplication_stats": {
                "total_entries": 0,
                "templated_entries": 0,
                "direct_entries": 0,
                "overall_space_savings": 0.0,
                "templates_generated": 0,
                "data_types": {},  # Per data type breakdown
                "most_effective_type": "",
                "most_effective_savings": 0.0,
                "performance_boost_estimate": 0.0
            },
            "speed_stats": {
                "fastest_cve_time": None,
                "slowest_cve_time": 0,
                "fastest_cve_id": "",
                "slowest_cve_id": "",
                "total_processing_time": 0,
                "cves_with_timing": 0
            },
            "mapping_stats": {
                "total_mappings_found": 0,
                "platform_entries_with_mappings": 0,
                "mapping_percentage": 0,
                "largest_mapping_count": 0,
                "largest_mapping_cve": ""
            },
            "cpe_query_stats": {
                "total_cpe_queries": 0,        # Cumulative count of CPE queries across all CVEs processed
                "largest_query_results": 0,    # Highest number of unique CPE strings generated for a single CVE
                "largest_query_cve": "",       # CVE ID that had the largest number of unique CPE strings
                "largest_query_time": 0,
                "total_cpe_results": 0,
                "average_results_per_query": 0,
                "total_query_time": 0,
                "average_query_time": 0,
                "top_queries": [],             # List of top 10 largest queries with detailed stats (by unique strings)
                "top_result_queries": []       # List of top 10 individual queries by result count (NEW)
            },
            "bloat_analysis": {
                "enabled": True,
                "files_analyzed": 0,
                "total_bloat_potential": 0.0,
                "average_severity": 0.0,
                "top_bloat_files": [],        # Top 10 files by bloat potential
                "detailed_reports_generated": []  # List of CVEs with detailed markdown reports
            },
            "recent_activity": [],
            "errors": [],
            "warnings": [],
            "stages": {
                "initialization": {"started": None, "completed": None, "duration": 0, "status": "not_started"},
                "cve_queries": {"started": None, "completed": None, "duration": 0, "status": "not_started"},
                "unique_cpe": {"started": None, "completed": None, "duration": 0, "status": "not_started"},
                "cpe_queries": {"started": None, "completed": None, "duration": 0, "status": "not_started"},
                "confirmed_mappings": {"started": None, "completed": None, "duration": 0, "status": "not_started"},
                "page_generation": {"started": None, "completed": None, "duration": 0, "status": "not_started"}
            },
            "resource_warnings": {
                "cache_bloat_warnings": 0,
                "memory_warnings": 0,
                "large_file_warnings": 0,
                "global_state_warnings": 0
            }
        }
        
        self._parse_lines(lines)
        self._calculate_derived_metrics()
        
        return self.data
    
    def _parse_lines(self, lines):
        """Parse individual log lines"""
        # Clear previous log messages
        self.all_log_messages = []
        
        # Track actual log start and end times from headers
        log_start_time = None
        log_end_time = None
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Parse log header information
            if line.startswith('# Started:'):
                start_match = re.search(r'# Started: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if start_match:
                    try:
                        log_start_time = datetime.strptime(start_match.group(1), '%Y-%m-%d %H:%M:%S')
                        self.data["processing"]["log_start_time"] = log_start_time.isoformat()
                    except ValueError:
                        pass
                continue
            
            # Parse log completion information  
            if line.startswith('# Completed:'):
                end_match = re.search(r'# Completed: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if end_match:
                    try:
                        log_end_time = datetime.strptime(end_match.group(1), '%Y-%m-%d %H:%M:%S')
                        self.data["processing"]["log_end_time"] = log_end_time.isoformat()
                    except ValueError:
                        pass
                continue
            
            if not line or line.startswith('#'):
                continue
                
            # Check for banner lines first (workflow stages)
            banner_match = re.match(r'\[([^\]]+)\]\s*===\s*(Starting|Completed)\s+([^-]+)\s*-\s*(.*)\s*===', line)
            if banner_match:
                timestamp_str, action, stage_name, description = banner_match.groups()
                try:
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
                
                # Parse workflow stage performance using existing logic
                full_message = f"{action} {stage_name.strip()}"
                self._parse_stage_performance(action, stage_name.strip(), timestamp_str, timestamp)
                continue
                
            # Extract timestamp and log level for regular lines
            timestamp_match = re.match(r'\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.*)', line)
            if not timestamp_match:
                continue
                
            timestamp_str, level, message = timestamp_match.groups()
            
            # Store all log messages for additional analysis
            self.all_log_messages.append(message)
            
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                continue
            
            # Update log level counts
            level_lower = level.lower()
            if level_lower == "info":
                self.data["log_stats"]["info_count"] += 1
            elif level_lower == "debug":
                self.data["log_stats"]["debug_count"] += 1
            elif level_lower == "warning" or level_lower == "warn":
                self.data["log_stats"]["warning_count"] += 1
            elif level_lower == "error":
                self.data["log_stats"]["error_count"] += 1
            
            # Store recent activity (last 10 entries)
            if len(self.data["recent_activity"]) < 10:
                self.data["recent_activity"].insert(0, {
                    "timestamp": timestamp_str,
                    "level": level_lower,
                    "message": message
                })
            
            # Parse specific message types
            self._parse_message(timestamp, level, message)
    
    def _extract_timestamp(self, message):
        """Extract timestamp from a log message"""
        # This will extract from the message context, but we might already have it
        # For now, return None as we'll get timestamp from the calling context
        return None
    
    def _parse_message(self, timestamp, level, message):
        """Parse specific message types for metrics"""
        
        # Start time detection
        if ("Started:" in message or "Starting CVE analysis" in message or 
            "Processing CVE 1/" in message or "Begin processing" in message) and self.data["processing"]["start_time"] is None:
            self.data["processing"]["start_time"] = timestamp.isoformat()
        
        # Total CVE count
        total_match = re.search(r'Processing (\d+) CVE records', message)
        if total_match:
            self.data["processing"]["total_cves"] = int(total_match.group(1))
        
        # Current CVE processing
        current_match = re.search(r'Processing CVE (\d+)/(\d+) \(([^)]+)\)', message)
        if current_match:
            current_num, total_num, cve_id = current_match.groups()
            self.data["processing"]["processed_cves"] = int(current_num)
            self.data["processing"]["total_cves"] = int(total_num)
            self.data["processing"]["current_cve"] = cve_id
            self.current_processing_cve = cve_id  # Track current CVE for context
            self.data["processing"]["progress_percentage"] = (int(current_num) / int(total_num)) * 100
            self.data["processing"]["remaining_cves"] = int(total_num) - int(current_num)
            
            # Initialize tracking data for this CVE
            if cve_id not in self.cve_processing_data:
                self.cve_processing_data[cve_id] = {
                    "start_time": timestamp,
                    "end_time": None,
                    "processing_time": 0,
                    "file_size": 0,
                    "file_name": "",
                    "dataframe_rows": 0
                }
        
        # Processing time for individual CVEs
        time_match = re.search(r'Successfully processed ([^\s]+) in ([\d.]+)s', message)
        if time_match:
            cve_id, time_str = time_match.groups()
            processing_time = float(time_str)
            self.data["performance"]["processing_times"].append(processing_time)
            
            # Track speed statistics
            self.data["speed_stats"]["total_processing_time"] += processing_time
            self.data["speed_stats"]["cves_with_timing"] += 1
            
            # Update CVE processing data
            if cve_id in self.cve_processing_data:
                self.cve_processing_data[cve_id]["end_time"] = timestamp
                self.cve_processing_data[cve_id]["processing_time"] = processing_time
            
            # Track fastest CVE
            if (self.data["speed_stats"]["fastest_cve_time"] is None or 
                processing_time < self.data["speed_stats"]["fastest_cve_time"]):
                self.data["speed_stats"]["fastest_cve_time"] = processing_time
                self.data["speed_stats"]["fastest_cve_id"] = cve_id
            
            # Track slowest CVE
            if processing_time > self.data["speed_stats"]["slowest_cve_time"]:
                self.data["speed_stats"]["slowest_cve_time"] = processing_time
                self.data["speed_stats"]["slowest_cve_id"] = cve_id
                
            # Clear current processing CVE when processing completes
            if cve_id == self.current_processing_cve:
                self.current_processing_cve = None
        
        # Cache information
        cache_loaded_match = re.search(r'cache loaded: (\d+) entries', message)
        if cache_loaded_match:
            self.data["cache"]["total_entries"] = int(cache_loaded_match.group(1))
        
        # Cache session statistics (more accurate)
        cache_session_match = re.search(r'CPE cache: (\d+)/(\d+) session hits \(([\d.]+)%\)', message)
        if cache_session_match:
            hits, total, hit_rate = cache_session_match.groups()
            # Only use session stats if there was actual cache activity
            if int(hits) > 0 or int(total) > 0:
                self.data["cache"]["cache_hits"] = int(hits)
                self.data["cache"]["cache_misses"] = int(total) - int(hits)
                self.data["cache"]["hit_rate"] = float(hit_rate)
                self.data["cache"]["api_calls_saved"] = int(hits)
        
        # Cache lifetime statistics  
        cache_lifetime_match = re.search(r'CPE cache lifetime: ([\d.]+)% hit rate, (\d+) API calls saved', message)
        if cache_lifetime_match:
            hit_rate, calls_saved = cache_lifetime_match.groups()
            # Only update if we don't have session stats (session stats are more recent)
            if self.data["cache"]["hit_rate"] == 0:
                self.data["cache"]["hit_rate"] = float(hit_rate)
                self.data["cache"]["api_calls_saved"] = int(calls_saved)
        
        # Cache size
        cache_size_match = re.search(r'CPE cache size: (\d+) entries', message)
        if cache_size_match:
            self.data["cache"]["total_entries"] = int(cache_size_match.group(1))
        
        # Updated cache patterns for new logging format
        cache_hit_match = re.search(r'Cache hit for CPE:.*?NVD CPE API call avoided', message)
        cache_miss_match = re.search(r'Cache miss for CPE:.*?Making API call', message)
        cache_expired_match = re.search(r'Cache expired for CPE:.*?Making API call', message)
        
        # Only count individual cache events if we don't have session summary
        cache_session_match = re.search(r'Cache session performance: (\d+) hits, (\d+) misses, (\d+) expired, ([\d.]+)% hit rate, (\d+) new entries', message)
        if cache_session_match:
            # Use session stats as authoritative cache metrics
            session_hits = int(cache_session_match.group(1))
            session_misses = int(cache_session_match.group(2))
            session_expired = int(cache_session_match.group(3))
            session_hit_rate = float(cache_session_match.group(4))
            new_entries = int(cache_session_match.group(5))
            
            # Only update with session stats if there was actual activity
            if session_hits > 0 or session_misses > 0 or session_expired > 0:
                # Update with authoritative session stats
                self.data["cache"]["cache_hits"] = session_hits
                self.data["cache"]["cache_misses"] = session_misses + session_expired
                self.data["cache"]["hit_rate"] = session_hit_rate
                self.data["cache"]["new_entries"] = new_entries
        elif cache_hit_match:
            self.data["cache"]["cache_hits"] += 1
        elif cache_miss_match or cache_expired_match:
            self.data["cache"]["cache_misses"] += 1
        
        # Updated CPE completion pattern for new format
        # This captures the summary line for each CVE's CPE query processing
        cpe_completion_match = re.search(r'CPE queries completed: (\d+) total queries \((\d+) cache hits, (\d+) API calls, ([\d.]+)% cache hit rate\)', message)
        if cpe_completion_match:
            total_queries = int(cpe_completion_match.group(1))
            cache_hits_summary = int(cpe_completion_match.group(2))
            api_calls_summary = int(cpe_completion_match.group(3))
            hit_rate = float(cpe_completion_match.group(4))
            
            # Accumulate CPE query stats instead of overwriting (each CVE has its own completion message)
            self.data["cpe_query_stats"]["total_cpe_queries"] += total_queries
            # Accumulate cache stats as well
            self.data["cache"]["cache_hits"] += cache_hits_summary
            # Keep the most recent hit rate (or we could calculate a weighted average)
            self.data["cache"]["hit_rate"] = hit_rate
        
        # Parse cache lifetime statistics
        cache_lifetime_match = re.search(r'CPE cache lifetime: ([\d.]+)% hit rate, (\d+) API calls saved', message)
        if cache_lifetime_match:
            hit_rate, calls_saved = cache_lifetime_match.groups()
            self.data["cache"]["hit_rate"] = float(hit_rate)
            self.data["cache"]["api_calls_saved"] = int(calls_saved)
        
        # API calls - Updated to match real log patterns
        if "API Call:" in message or "API call:" in message:
            self.data["api"]["total_calls"] += 1
            # Don't assume success here - wait for actual response
            if "NVD CVE API" in message or "NVD CVE lookup" in message:
                self.data["api"]["nvd_cve_calls"] += 1
            elif "MITRE CVE API" in message:
                self.data["api"]["mitre_cve_calls"] += 1
            elif ("NVD CPE API" in message or "NVD CPE search" in message or 
                  "NVD CPE validation" in message):
                self.data["api"]["nvd_cpe_calls"] += 1
        
        # Failed API calls
        if "API call failed:" in message or "API Call failed:" in message:
            self.data["api"]["total_calls"] += 1
            self.data["api"]["failed_calls"] += 1
            if "NVD CVE API" in message or "NVD CVE lookup" in message:
                self.data["api"]["nvd_cve_calls"] += 1
            elif "MITRE CVE API" in message:
                self.data["api"]["mitre_cve_calls"] += 1
            elif ("NVD CPE API" in message or "NVD CPE search" in message or 
                  "NVD CPE validation" in message):
                self.data["api"]["nvd_cpe_calls"] += 1
        
        # API responses
        if "API Response:" in message:
            if "Success" in message:
                self.data["api"]["successful_calls"] += 1
            else:
                self.data["api"]["failed_calls"] += 1
        
        # Error and warning tracking with CVE context
        # First try to find CVE ID in the message itself
        cve_context_match = re.search(r'(CVE-\d{4}-\d+)', message)
        cve_id = cve_context_match.group(1) if cve_context_match else None
        
        # If no CVE ID found in message, use the current processing CVE
        if cve_id is None and self.current_processing_cve is not None:
            cve_id = self.current_processing_cve
        
        if level.lower() == "error":
            self.data["errors"].append({
                "timestamp": timestamp.isoformat(),
                "message": message,
                "level": level.lower(),
                "cve_id": cve_id
            })
        elif level.lower() == "warning" or level.lower() == "warn":
            self.data["warnings"].append({
                "timestamp": timestamp.isoformat(),
                "message": message,
                "level": "warning",
                "cve_id": cve_id
            })
        
        # Mapping statistics tracking - accumulate data from all CVE processing events
        mapping_stats_match = re.search(r'Confirmed mappings statistics: (\d+)/(\d+) platform entries \(([\d.]+)% hit rate\), (\d+) total mappings found', message)
        
        if mapping_stats_match:
            # Parse individual CVE mapping statistics and accumulate them
            successful_mappings = int(mapping_stats_match.group(1))
            total_processed = int(mapping_stats_match.group(2)) 
            hit_rate = float(mapping_stats_match.group(3))
            total_mappings = int(mapping_stats_match.group(4))
            
            # Track platform entries for current CVE
            if self.current_processing_cve and self.current_processing_cve in self.cve_processing_data:
                self.cve_processing_data[self.current_processing_cve]["dataframe_rows"] = total_processed
            
            # Accumulate the statistics across all CVEs (like we do for CPE queries)
            self.data["mapping_stats"]["platform_entries_with_mappings"] += successful_mappings
            self.data["mapping_stats"]["total_mappings_found"] += total_mappings
            
            # Track total platform entries processed for percentage calculation
            if "total_platform_entries_processed" not in self.data["mapping_stats"]:
                self.data["mapping_stats"]["total_platform_entries_processed"] = 0
            self.data["mapping_stats"]["total_platform_entries_processed"] += total_processed
            
            # Recalculate the overall percentage based on accumulated data
            total_processed_overall = self.data["mapping_stats"]["total_platform_entries_processed"]
            total_with_mappings = self.data["mapping_stats"]["platform_entries_with_mappings"]
            
            if total_processed_overall > 0:
                self.data["mapping_stats"]["mapping_percentage"] = (total_with_mappings / total_processed_overall) * 100
            else:
                self.data["mapping_stats"]["mapping_percentage"] = 0.0
        
        # Remove individual mapping tracking to prevent accumulation issues
        # mapping_found_match = re.search(r'Found (\d+) confirmed mappings for (CVE-\d{4}-\d+)', message)
        # mapping_platform_match = re.search(r'Found (\d+) confirmed mappings for platform entry (\d+)', message)
        
        # CPE Generation Results pattern - extracts unique CPE strings identified
        cpe_generation_match = re.search(r'\[CPE Generation Results\]: Affected Array Entries Processed=(\d+), Unique Match Strings Identified=(\d+)', message)
        if cpe_generation_match:
            affected_entries = int(cpe_generation_match.group(1))
            unique_strings = int(cpe_generation_match.group(2))
            
            # Track detailed query information for this CVE
            if self.current_processing_cve:
                query_info = {
                    "cve_id": self.current_processing_cve,
                    "unique_strings": unique_strings,
                    "affected_entries": affected_entries,
                    "strings_per_entry": round(unique_strings / affected_entries, 2) if affected_entries > 0 else 0,
                    "timestamp": timestamp.strftime('%Y-%m-%d %H:%M:%S') if timestamp else "Unknown"
                }
                
                # Add to top queries list and maintain top 10
                self.data["cpe_query_stats"]["top_queries"].append(query_info)
                # Sort by unique_strings descending and keep top 10
                self.data["cpe_query_stats"]["top_queries"].sort(key=lambda x: x["unique_strings"], reverse=True)
                self.data["cpe_query_stats"]["top_queries"] = self.data["cpe_query_stats"]["top_queries"][:10]
            
            # Track the unique strings identified for this CVE
            if unique_strings > self.data["cpe_query_stats"]["largest_query_results"]:
                self.data["cpe_query_stats"]["largest_query_results"] = unique_strings
                if self.current_processing_cve:
                    self.data["cpe_query_stats"]["largest_query_cve"] = self.current_processing_cve
        
        # CPE Query statistics tracking
        cpe_query_match = re.search(r'Processing CPE collections: Found (\d+) total results', message)
        cpe_timing_match = re.search(r'CPE query completed in ([\d.]+)s', message)
        
        if cpe_query_match:
            total_results = int(cpe_query_match.group(1))
            self.data["cpe_query_stats"]["total_cpe_queries"] += 1
            self.data["cpe_query_stats"]["total_cpe_results"] += total_results
            
            # Track largest query
            if total_results > self.data["cpe_query_stats"]["largest_query_results"]:
                self.data["cpe_query_stats"]["largest_query_results"] = total_results
                # Use current CVE context if available
                if self.current_processing_cve:
                    self.data["cpe_query_stats"]["largest_query_cve"] = self.current_processing_cve
        
        # Track CPE query timing if available
        if cpe_timing_match:
            query_time = float(cpe_timing_match.group(1))
            self.data["cpe_query_stats"]["total_query_time"] += query_time
            
            # Track longest query time
            if query_time > self.data["cpe_query_stats"]["largest_query_time"]:
                self.data["cpe_query_stats"]["largest_query_time"] = query_time
        
        # NEW: Track individual CPE API query results
        # First, check for CPE API calls to capture the query string
        cpe_api_call_match = re.search(r"API Call: NVD CPE API with params: \{'cpe_match_string': '([^']+)'", message)
        if cpe_api_call_match:
            self.current_cpe_query_string = cpe_api_call_match.group(1)
        
        # Also capture query strings from cache hit messages
        cache_hit_match = re.search(r'Cache hit for CPE: ([^-]+) - NVD CPE API call avoided', message)
        if cache_hit_match:
            self.current_cpe_query_string = cache_hit_match.group(1).strip()
        
        # Track CPE query results from multiple sources:
        # 1. API Response pattern: "API Response: NVD CPE API - Success (X results)"
        cpe_api_result_match = re.search(r'API Response: NVD CPE API - Success \((\d+) results\)', message)
        
        # 2. Cache hit with result count: "Cache hit for CPE: [query] - NVD CPE API call avoided (X results)"
        cache_hit_result_match = re.search(r'Cache hit for CPE: ([^-]+) - NVD CPE API call avoided \((\d+) results\)', message)
        
        # 3. Processing results pattern: "Processing X CPE query results for table Y"
        # 4. Skipping deprecated pattern: "Skipping cpe:2.3:... - all X results deprecated"
        cpe_processing_match = re.search(r'Processing (\d+) CPE query results for table \d+', message)
        cpe_deprecated_match = re.search(r'Skipping ([^-]+) - all (\d+) results deprecated', message)
        
        result_count = None
        query_string = None
        
        if cpe_api_result_match:
            result_count = int(cpe_api_result_match.group(1))
            query_string = self.current_cpe_query_string
        elif cache_hit_result_match:
            result_count = int(cache_hit_result_match.group(2))
            query_string = cache_hit_result_match.group(1).strip()
        elif cpe_processing_match:
            result_count = int(cpe_processing_match.group(1))
            query_string = self.current_cpe_query_string
        elif cpe_deprecated_match:
            result_count = int(cpe_deprecated_match.group(2))
            query_string = cpe_deprecated_match.group(1).strip()
        
        if result_count is not None:
            # Determine the source of this result
            source = "unknown"
            if cpe_api_result_match:
                source = "api"
            elif cache_hit_result_match:
                source = "cache"
            elif cpe_processing_match or cpe_deprecated_match:
                source = "cache"  # Processing results come from cached data
            
            # Store individual query result information
            result_info = {
                "result_count": result_count,
                "query_string": query_string or "Unknown",
                "cve_id": self.current_processing_cve or "Unknown",
                "source": source,
                "timestamp": timestamp.strftime('%Y-%m-%d %H:%M:%S') if timestamp else "Unknown"
            }
            
            # Add to top result queries list and maintain top 10
            self.data["cpe_query_stats"]["top_result_queries"].append(result_info)
            # Sort by result_count descending and keep top 10
            self.data["cpe_query_stats"]["top_result_queries"].sort(key=lambda x: x["result_count"], reverse=True)
            self.data["cpe_query_stats"]["top_result_queries"] = self.data["cpe_query_stats"]["top_result_queries"][:10]
        
        # File generation tracking
        file_generated_match = re.search(r'File Generated: (.+\.html)', message)
        file_size_audit_match = re.search(r'File size normal: ([^(]+) \(([\d.]+)(KB|MB|GB)\)', message)
        
        # File generation tracking
        file_generated_match = re.search(r'File Generated: (.+\.html)(?:\s*\(Size:\s*([\d.]+)\s*(KB|MB|GB)\))?', message)
        file_size_audit_match = re.search(r'File size normal: ([^(]+) \(([\d.]+)(KB|MB|GB)\)', message)
        
        # Large file detection patterns
        large_file_match = re.search(r'Large output file detected: ([^(]+) \(([\d.]+)(KB|MB|GB) > [\d.]+KB\)', message)
        extremely_large_file_match = re.search(r'Extremely large file: ([^(]+) \(([\d.]+)(KB|MB|GB)\)', message)
        
        if file_generated_match:
            file_path = file_generated_match.group(1).strip()
            file_name = os.path.basename(file_path)  # Extract just the filename for deduplication
            
            # Extract CVE ID from filename (e.g., CVE-2024-1234.html -> CVE-2024-1234)
            cve_match = re.search(r'(CVE-\d{4}-\d+)', file_name)
            cve_id = cve_match.group(1) if cve_match else self.current_processing_cve
            
            # Only count if we haven't processed this file before
            if file_name not in self.processed_files:
                self.data["file_stats"]["files_generated"] += 1
                self.processed_files.add(file_name)
            
            file_size = None
            
            # If size is provided in the message, use it
            if len(file_generated_match.groups()) >= 3 and file_generated_match.group(2):  # Size value exists
                size_str = file_generated_match.group(2)
                unit = file_generated_match.group(3)
                
                # Convert size to bytes
                size_value = float(size_str)
                if unit == 'KB':
                    file_size = int(size_value * 1024)
                elif unit == 'MB':
                    file_size = int(size_value * 1024 * 1024)
                elif unit == 'GB':
                    file_size = int(size_value * 1024 * 1024 * 1024)
                else:
                    file_size = int(size_value)  # Assume bytes
            else:
                # Size not in log message, try to get it from the actual file
                try:
                    if os.path.exists(file_path):
                        file_size = os.path.getsize(file_path)
                except (OSError, IOError):
                    # If we can't get the file size, skip it but continue processing
                    pass
            
            # If we have a valid file size, update statistics
            if file_size is not None:
                # Update CVE processing data with file info
                if cve_id and cve_id in self.cve_processing_data:
                    self.cve_processing_data[cve_id]["file_size"] = file_size
                    self.cve_processing_data[cve_id]["file_name"] = file_name
                
                # Update file size statistics
                self._update_file_size_stats(file_name, file_size)
        elif file_size_audit_match:
            # Parse file size audit messages - this is our authoritative source for file sizes
            file_name, size_str, unit = file_size_audit_match.groups()
            file_name = file_name.strip()
            
            # Only count if we haven't processed this file before
            if file_name not in self.processed_files:
                self.data["file_stats"]["files_generated"] += 1
                self.processed_files.add(file_name)
            
            # Convert size to bytes
            size_value = float(size_str)
            if unit == 'KB':
                file_size = int(size_value * 1024)
            elif unit == 'MB':
                file_size = int(size_value * 1024 * 1024)
            elif unit == 'GB':
                file_size = int(size_value * 1024 * 1024 * 1024)
            else:
                file_size = int(size_value)  # Assume bytes if no unit
            
            # Update file size statistics
            self._update_file_size_stats(file_name, file_size)
        
        # Handle large file detection patterns
        elif large_file_match or extremely_large_file_match:
            # Use the appropriate match
            match = large_file_match or extremely_large_file_match
            file_name, size_str, unit = match.groups()
            file_name = file_name.strip()
            
            # Extract CVE ID from filename
            cve_match = re.search(r'(CVE-\d{4}-\d+)', file_name)
            cve_id = cve_match.group(1) if cve_match else self.current_processing_cve
            
            # Only count if we haven't processed this file before
            if file_name not in self.processed_files:
                self.data["file_stats"]["files_generated"] += 1
                self.processed_files.add(file_name)
            
            # Convert size to bytes
            size_value = float(size_str)
            if unit == 'KB':
                file_size = int(size_value * 1024)
            elif unit == 'MB':
                file_size = int(size_value * 1024 * 1024)
            elif unit == 'GB':
                file_size = int(size_value * 1024 * 1024 * 1024)
            else:
                file_size = int(size_value)  # Assume bytes if no unit
            
            # Update CVE processing data with file info (this might be the most accurate size)
            if cve_id and cve_id in self.cve_processing_data:
                self.cve_processing_data[cve_id]["file_size"] = file_size
                self.cve_processing_data[cve_id]["file_name"] = file_name
            
            # Update size statistics (this might be the most accurate size info we have)
            self._update_file_size_stats(file_name, file_size)
        
        # Resource warning tracking
        resource_warning_patterns = {
            "cache_bloat": r"Global state bloat detected.*Large CPE cache",
            "memory_warning": r"Memory warning|Low memory|Memory usage high", 
            "large_file": r"File size (warning|large|excessive)",
            "global_state": r"Global state bloat|Global state warning"
        }
        
        for warning_type, pattern in resource_warning_patterns.items():
            if re.search(pattern, message, re.IGNORECASE):
                if warning_type == "cache_bloat":
                    self.data["resource_warnings"]["cache_bloat_warnings"] += 1
                elif warning_type == "memory_warning":
                    self.data["resource_warnings"]["memory_warnings"] += 1
                elif warning_type == "large_file":
                    self.data["resource_warnings"]["large_file_warnings"] += 1
                elif warning_type == "global_state":
                    self.data["resource_warnings"]["global_state_warnings"] += 1
        
        # CPE validation warning tracking
        overly_broad_cpe_match = re.search(r'Overly broad CPE detected, skipping: (.+?) - (.+)', message)
        if overly_broad_cpe_match:
            cpe_string = overly_broad_cpe_match.group(1)
            reason = overly_broad_cpe_match.group(2)
            # Track this in resource warnings for dashboard visibility
            if "overly_broad_cpe_warnings" not in self.data["resource_warnings"]:
                self.data["resource_warnings"]["overly_broad_cpe_warnings"] = 0
            self.data["resource_warnings"]["overly_broad_cpe_warnings"] += 1
        
        # Invalid CPE string warning tracking (for API-level rejections)
        invalid_cpe_match = re.search(r'Skipping invalid CPE match string: (.+)', message)
        if invalid_cpe_match:
            cpe_string = invalid_cpe_match.group(1)
            # Track this in resource warnings for dashboard visibility
            if "invalid_cpe_warnings" not in self.data["resource_warnings"]:
                self.data["resource_warnings"]["invalid_cpe_warnings"] = 0
            self.data["resource_warnings"]["invalid_cpe_warnings"] += 1
        
        # Parse template deduplication effectiveness logs
        # Pattern: "Template analysis for {data_type}: {total} total, {templated} templated, {direct} direct, {space_savings}% space savings"
        dedup_match = re.search(r'Template analysis for ([^:]+): (\d+) total, (\d+) templated, (\d+) direct, ([\d.]+)% space savings', message)
        if dedup_match:
            data_type, total_str, templated_str, direct_str, savings_str = dedup_match.groups()
            
            total_entries = int(total_str)
            templated_entries = int(templated_str) 
            direct_entries = int(direct_str)
            space_savings = float(savings_str)
            
            # Update overall statistics
            dedup_stats = self.data["deduplication_stats"]
            dedup_stats["total_entries"] += total_entries
            dedup_stats["templated_entries"] += templated_entries
            dedup_stats["direct_entries"] += direct_entries
            
            # Track per data type
            dedup_stats["data_types"][data_type] = {
                "total_entries": total_entries,
                "templated_entries": templated_entries,
                "direct_entries": direct_entries,
                "space_savings": space_savings,
                "effectiveness_rating": self._get_effectiveness_rating(space_savings)
            }
            
            # Track most effective type
            if space_savings > dedup_stats["most_effective_savings"]:
                dedup_stats["most_effective_type"] = data_type
                dedup_stats["most_effective_savings"] = space_savings
        
        # Count templates generated (look for template creation logs)
        template_creation_match = re.search(r'([^_]+)_template_\d+', message)
        if template_creation_match and 'templates' in message.lower():
            self.data["deduplication_stats"]["templates_generated"] += 1
    
    def _parse_stage_performance(self, action, stage_name, timestamp_str, timestamp_obj):
        """Parse workflow stage performance information"""
        # Map stage names to our data structure keys
        stage_map = {
            "Initialization": "initialization",
            "CVE Queries": "cve_queries",
            "Unique CPE Generation": "unique_cpe",
            "CPE Queries": "cpe_queries", 
            "Confirmed Mappings": "confirmed_mappings",
            "Page Generation": "page_generation"
        }
        
        stage_key = stage_map.get(stage_name)
        if not stage_key:
            return
            
        stage_data = self.data["stages"][stage_key]
        
        if action == "Starting":
            stage_data["started"] = timestamp_str
            stage_data["status"] = "in_progress"
        elif action == "Completed":
            stage_data["completed"] = timestamp_str
            stage_data["status"] = "completed"
            
            # Calculate duration if we have both start and end times
            if stage_data["started"]:
                try:
                    start_time = datetime.strptime(stage_data["started"], '%Y-%m-%d %H:%M:%S')
                    duration = (timestamp_obj - start_time).total_seconds()
                    stage_data["duration"] = round(duration, 2)
                except ValueError:
                    pass
    
    def _analyze_stage_performance(self):
        """Analyze stage performance and identify bottlenecks"""
        stages = self.data["stages"]
        
        # Calculate total workflow time and identify bottlenecks
        completed_durations = []
        longest_stage = {"name": "", "duration": 0}
        incomplete_stages = []
        
        for stage_name, stage_data in stages.items():
            if stage_data["status"] == "completed":
                completed_durations.append(stage_data["duration"])
                if stage_data["duration"] > longest_stage["duration"]:
                    longest_stage = {"name": stage_name, "duration": stage_data["duration"]}
            elif stage_data["status"] == "in_progress":
                incomplete_stages.append(stage_name)
        
        # Add performance summary to data
        if not hasattr(self.data, "stage_analysis"):
            self.data["stage_analysis"] = {}
            
        self.data["stage_analysis"] = {
            "total_stages": len(stages),
            "completed_stages": len(completed_durations),
            "incomplete_stages": len(incomplete_stages),
            "total_workflow_time": round(sum(completed_durations), 2),
            "average_stage_time": round(sum(completed_durations) / len(completed_durations), 2) if completed_durations else 0,
            "longest_stage": longest_stage,
            "incomplete_stage_list": incomplete_stages,
            "stage_efficiency": round((len(completed_durations) / len(stages)) * 100, 1) if stages else 0
        }
        
        # Set status for stages that started but never completed 
        for stage_name, stage_data in stages.items():
            if stage_data["started"] and not stage_data["completed"]:
                stage_data["status"] = "incomplete"
    
    def _calculate_dashboard_metrics(self):
        """Calculate additional metrics needed for dashboard validation"""
        
        # Mapping success rate calculation
        if self.data["processing"]["processed_cves"] > 0:
            # Try to extract mapping success rate from confirmed mappings log messages
            # Look for patterns like "Found X confirmed mappings" vs total processed
            mapping_entries = 0
            entries_with_mappings = 0
            
            # Count confirmed mapping statistics from logs if available
            for message in self.all_log_messages:
                if "confirmed mappings statistics:" in message.lower():
                    # Extract hit rate from pattern like "5/10 platform entries (50.0% hit rate)"
                    import re
                    match = re.search(r'(\d+)/(\d+) platform entries \((\d+\.?\d*)% hit rate\)', message)
                    if match:
                        entries_with_mappings = int(match.group(1))
                        total_entries = int(match.group(2))
                        hit_rate = float(match.group(3))
                        # Store in processing data
                        self.data["processing"]["mapping_success_rate"] = hit_rate
                        break
            
            # If no mapping statistics found in logs, set default
            if "mapping_success_rate" not in self.data["processing"]:
                self.data["processing"]["mapping_success_rate"] = 0
        
        # Average processing speed (CVEs per hour)
        if (self.data["performance"]["total_runtime"] > 0 and 
            self.data["processing"]["processed_cves"] > 0):
            runtime_hours = self.data["performance"]["total_runtime"] / 3600
            self.data["processing"]["avg_processing_speed"] = self.data["processing"]["processed_cves"] / runtime_hours
        else:
            self.data["processing"]["avg_processing_speed"] = 0
        
        # API call breakdown - categorize API calls by type
        call_breakdown = {}
        for message in self.all_log_messages:
            if "API call:" in message:
                # Extract API call type
                if "NVD CPE search" in message:
                    call_breakdown["nvd_cpe_search"] = call_breakdown.get("nvd_cpe_search", 0) + 1
                elif "NVD CVE lookup" in message:
                    call_breakdown["nvd_cve_lookup"] = call_breakdown.get("nvd_cve_lookup", 0) + 1
                elif "NVD CPE validation" in message:
                    call_breakdown["nvd_cpe_validation"] = call_breakdown.get("nvd_cpe_validation", 0) + 1
                elif "NVD source data" in message:
                    call_breakdown["nvd_source_data"] = call_breakdown.get("nvd_source_data", 0) + 1
                elif "NVD rate limit" in message:
                    call_breakdown["nvd_rate_limit"] = call_breakdown.get("nvd_rate_limit", 0) + 1
                else:
                    call_breakdown["other"] = call_breakdown.get("other", 0) + 1
        
        self.data["api"]["call_breakdown"] = call_breakdown
        
        # Ensure all required metrics exist with defaults
        if "mapping_success_rate" not in self.data["processing"]:
            self.data["processing"]["mapping_success_rate"] = 0
        if "avg_processing_speed" not in self.data["processing"]:
            self.data["processing"]["avg_processing_speed"] = 0
        
        # Calculate deduplication effectiveness metrics
        dedup_stats = self.data["deduplication_stats"]
        if dedup_stats["total_entries"] > 0:
            # Calculate overall space savings
            dedup_stats["overall_space_savings"] = (
                dedup_stats["templated_entries"] / dedup_stats["total_entries"] * 100
            )
            
            # Estimate performance boost (rough estimate: 5-15% boost based on space savings)
            dedup_stats["performance_boost_estimate"] = (
                dedup_stats["overall_space_savings"] * 0.15
            )  # Conservative estimate: 15% of space savings translates to performance boost
    
    def _integrate_bloat_analysis(self):
        """Integrate bloat detection analysis into dashboard data"""
        bloat_stats = self.data["bloat_analysis"]
        
        try:
            # Import bloat detection framework
            import sys
            current_dir = os.path.dirname(__file__)
            sys.path.insert(0, current_dir)
            from bloat_detection_framework import BloatDetectionFramework
            
            bloat_framework = BloatDetectionFramework()
            
            # Use existing detailed_files list - this is already the top 20 files by size
            # No need for threshold checks, just analyze all files in the detailed list
            files_to_analyze = self.data["file_stats"]["detailed_files"]
            
            bloat_results = []
            total_bloat = 0
            reports_generated = []
            
            print(f"Analyzing {len(files_to_analyze)} files from Top Generated Files by Size...")
            
            for file_info in files_to_analyze:
                cve_id = file_info["cve_id"]
                
                # Try to find the actual HTML file
                html_file = None
                from pathlib import Path
                project_root = get_analysis_tools_root()
                
                # For run-based structure, look in the same run as the log file
                potential_paths = []
                
                # If we're analyzing a run-specific log, look in that run's generated_pages
                if "runs/" in self.log_directory:
                    # Extract run directory from log directory path
                    # e.g., "E:/Git/Analysis_Tools/runs/2025-07-28_08-30-33_testExamples/logs" 
                    # becomes "E:/Git/Analysis_Tools/runs/2025-07-28_08-30-33_testExamples/generated_pages"
                    log_path = Path(self.log_directory)
                    if log_path.parent.name != "runs":  # This is a specific run directory
                        run_dir = log_path.parent
                        potential_paths.append(run_dir / "generated_pages" / f"{cve_id}.html")
                
                # Also try run-based paths (most recent run)
                runs_dir = project_root / "runs"
                if runs_dir.exists():
                    # Find most recent run directory
                    run_dirs = [d for d in runs_dir.iterdir() if d.is_dir()]
                    if run_dirs:
                        # Sort by creation time (most recent first)
                        run_dirs.sort(key=lambda x: x.stat().st_ctime, reverse=True)
                        potential_paths.append(run_dirs[0] / "generated_pages" / f"{cve_id}.html")
                
                # Fallback to legacy paths
                potential_paths.extend([
                    project_root / "generated_pages" / f"{cve_id}.html",
                    project_root / "test_output" / f"{cve_id}.html"
                ])
                
                for path_obj in potential_paths:
                    if path_obj.exists():
                        html_file = path_obj
                        break
                
                if html_file:
                    try:
                        print(f"  Analyzing {cve_id}...")
                        analysis = bloat_framework.analyze_file(html_file)
                        if analysis and analysis.actual_bloat_size > 0:
                            # Create summary for dashboard - combine bloat_sources AND repetitive_structures
                            all_bloat_sources = []
                            
                            # Add generic bloat patterns from bloat_sources
                            for name, data in analysis.bloat_sources.items():
                                all_bloat_sources.append((name, {
                                    "total_size": data["total_size"],
                                    "percentage": data["percentage"],
                                    "description": data.get("description", "Unknown"),
                                    "source_type": "generic_pattern"
                                }))
                            
                            # Add specific ID patterns from repetitive_structures (these are often more actionable!)
                            if hasattr(analysis, 'repetitive_structures') and analysis.repetitive_structures:
                                # ALWAYS INCLUDE: Show ALL ID patterns for top 5 list (no percentage filtering)
                                all_structures = list(analysis.repetitive_structures.items())
                                # Sort by total size and take top 10 for inclusion
                                top_structures = sorted(all_structures, 
                                                      key=lambda x: x[1].get('total_size', 0), 
                                                      reverse=True)[:10]  # Get more for potential inclusion
                                
                                for structure_name, struct_data in top_structures:
                                    # Extract clean ID prefix for display
                                    id_prefix = struct_data.get('id_prefix', structure_name.replace('id_pattern_', ''))
                                    display_name = f"ID Pattern: {id_prefix}_X"
                                    
                                    all_bloat_sources.append((display_name, {
                                        "total_size": struct_data["total_size"],
                                        "percentage": struct_data["percentage"],
                                        "description": f"{struct_data['count']} elements with pattern '{id_prefix}_X' (Range: {struct_data.get('id_range', 'N/A')})",
                                        "source_type": "id_pattern",
                                        "savings_potential": struct_data.get("adjusted_potential_savings", 0),
                                        "element_count": struct_data["count"]
                                        }))
                            
                            # SMART BLOAT DETECTION: Check if ID patterns dominate the bloat
                            id_pattern_size = sum(data["total_size"] for name, data in all_bloat_sources if data.get("source_type") == "id_pattern")
                            generic_pattern_size = sum(data["total_size"] for name, data in all_bloat_sources if data.get("source_type") == "generic_pattern")
                            total_identified_bloat = id_pattern_size + generic_pattern_size
                            
                            # If ID patterns account for >70% of identified bloat, simplify generic patterns
                            id_pattern_dominance = (id_pattern_size / total_identified_bloat) * 100 if total_identified_bloat > 0 else 0
                            
                            if id_pattern_dominance > 70:
                                # Filter out small generic patterns, keep only the largest one as representative
                                generic_patterns = [(name, data) for name, data in all_bloat_sources if data.get("source_type") == "generic_pattern"]
                                if generic_patterns:
                                    largest_generic = max(generic_patterns, key=lambda x: x[1]["total_size"])
                                    # Replace with a simplified "catch-all" entry
                                    all_bloat_sources = [(name, data) for name, data in all_bloat_sources if data.get("source_type") != "generic_pattern"]
                                    all_bloat_sources.append(("Generic HTML Patterns", {
                                        "total_size": generic_pattern_size,
                                        "percentage": (generic_pattern_size / analysis.total_size) * 100,
                                        "description": f"Various generic bloat patterns (largest: {largest_generic[0]})",
                                        "source_type": "catch_all",
                                        "savings_potential": generic_pattern_size,
                                        "element_count": len(generic_patterns)
                                    }))
                            
                            # Add unaccounted bloat tracker if there's significant missing bloat
                            unaccounted_bloat = analysis.actual_bloat_size - total_identified_bloat
                            if unaccounted_bloat > (analysis.actual_bloat_size * 0.05):  # If >5% unaccounted
                                all_bloat_sources.append(("Untracked Bloat", {
                                    "total_size": unaccounted_bloat,
                                    "percentage": (unaccounted_bloat / analysis.total_size) * 100,
                                    "description": f"Bloat not captured by current detection patterns (~{unaccounted_bloat/1024/1024:.1f} MB)",
                                    "source_type": "untracked",
                                    "savings_potential": unaccounted_bloat,
                                    "element_count": 1
                                }))
                            
                            # Sort ALL sources by total size and take top 5
                            top_bloat_sources = sorted(all_bloat_sources, key=lambda x: x[1]["total_size"], reverse=True)[:5]
                            
                            # Calculate bloat percentage of file size for prioritization
                            bloat_percentage = (analysis.actual_bloat_size / analysis.total_size) * 100 if analysis.total_size > 0 else 0
                            
                            bloat_summary = {
                                "cve_id": cve_id,
                                "file_size": file_info["file_size"],
                                "bloat_percentage": round(bloat_percentage, 1),
                                "actual_bloat_size": analysis.actual_bloat_size,
                                "top_5_sources": [
                                    {
                                        "name": name,
                                        "type": data.get("description", "Unknown"),
                                        "reduction_mb": round(data["total_size"] / (1024 * 1024), 2),
                                        "reduction_percent": round(data["percentage"], 1),
                                        "source_category": data.get("source_type", "unknown"),
                                        "savings_potential_mb": round(data.get("savings_potential", data["total_size"]) / (1024 * 1024), 2) if data.get("savings_potential") else round(data["total_size"] / (1024 * 1024), 2),
                                        "element_count": data.get("element_count", 1)
                                    }
                                    for name, data in top_bloat_sources
                                ]
                            }
                            bloat_results.append(bloat_summary)
                            total_bloat += analysis.actual_bloat_size
                            
                            # Use same output directory as dashboard data
                            # Determine output directory based on log file location or json_file attribute
                            if hasattr(self, 'json_file') and self.json_file:
                                output_dir = Path(self.json_file).parent
                            else:
                                # Derive from log file location when running without dashboard generation
                                log_path = Path(self.current_log_file) if hasattr(self, 'current_log_file') else Path(".")
                                log_parent = log_path.parent.parent  # Go up from logs/ to run directory
                                output_dir = log_parent / "reports"
                            output_dir.mkdir(parents=True, exist_ok=True)
                            
                            # Generate detailed markdown report  
                            markdown_report_path = output_dir / f"bloat_analysis_{cve_id}.md"
                            
                            # Create individual JSON report (markdown disabled for now)
                            single_file_results = {cve_id: analysis}
                            from pathlib import Path
                            # Change extension to .json since we're not generating markdown
                            json_report_path = str(markdown_report_path).replace('.md', '.json')
                            bloat_framework._write_report(single_file_results, Path(json_report_path))
                            
                            reports_generated.append(cve_id)
                            print(f"    ✓ Generated report: {json_report_path}")
                            
                    except Exception as e:
                        # Continue processing other files if one fails
                        print(f"  Warning: Bloat analysis failed for {cve_id}: {e}")
                        continue
                else:
                    print(f"  Warning: HTML file not found for {cve_id}")
            
            # Update bloat analysis stats
            bloat_stats["files_analyzed"] = len(files_to_analyze)
            bloat_stats["total_bloat_size"] = total_bloat
            bloat_stats["average_bloat_percentage"] = (sum(result["bloat_percentage"] for result in bloat_results) / len(bloat_results)) if bloat_results else 0.0
            bloat_stats["top_bloat_files"] = sorted(bloat_results, key=lambda x: x["bloat_percentage"], reverse=True)[:10]
            bloat_stats["detailed_reports_generated"] = reports_generated
            
            # Add bloat analysis data to file details
            bloat_lookup = {result["cve_id"]: result for result in bloat_results}
            for file_info in self.data["file_stats"]["detailed_files"]:
                cve_id = file_info["cve_id"]
                if cve_id in bloat_lookup:
                    file_info["bloat_analysis"] = bloat_lookup[cve_id]
                else:
                    file_info["bloat_analysis"] = {"status": "analysis_failed"}
            
            print(f"✓ Bloat analysis complete: {len(bloat_results)} files analyzed, {len(reports_generated)} reports generated")
                    
        except ImportError as e:
            print(f"Warning: Bloat detection framework not available: {e}")
            bloat_stats["enabled"] = False
        except Exception as e:
            print(f"Warning: Bloat analysis integration failed: {e}")
            bloat_stats["enabled"] = False
    
    def _calculate_derived_metrics(self):
        """Calculate derived metrics from parsed data"""
        
        # Calculate processing time statistics and replace raw data with summary
        if self.data["performance"]["processing_times"]:
            processing_times = self.data["performance"]["processing_times"]
            
            # Calculate summary statistics
            total_time = sum(processing_times)
            count = len(processing_times)
            avg_time = total_time / count
            min_time = min(processing_times)
            max_time = max(processing_times)
            
            # Calculate median
            sorted_times = sorted(processing_times)
            if count % 2 == 0:
                median_time = (sorted_times[count//2 - 1] + sorted_times[count//2]) / 2
            else:
                median_time = sorted_times[count//2]
            
            # Replace the massive array with summary statistics
            self.data["performance"] = {
                "average_time": avg_time,
                "total_time": total_time,
                "count": count,
                "min_time": min_time,
                "max_time": max_time,
                "median_time": median_time,
                "processing_rate": 0,  # Will be calculated below
                "total_runtime": 0     # Will be calculated below
            }
        
        # Cache hit rate (only calculate if not already set from log parsing)
        if self.data["cache"]["hit_rate"] == 0:
            total_cache_ops = self.data["cache"]["cache_hits"] + self.data["cache"]["cache_misses"]
            if total_cache_ops > 0:
                self.data["cache"]["hit_rate"] = (self.data["cache"]["cache_hits"] / total_cache_ops) * 100
                self.data["cache"]["api_calls_saved"] = self.data["cache"]["cache_hits"]
        
        # Add total_requests field for dashboard validation
        self.data["cache"]["total_requests"] = self.data["cache"]["cache_hits"] + self.data["cache"]["cache_misses"]
        
        # Add files_generated to processing section for dashboard validation
        self.data["processing"]["files_generated"] = self.data["file_stats"]["files_generated"]
        
        # Processing rate and runtime - use actual wall clock time when available
        actual_wall_clock_time = None
        
        # Calculate actual wall clock time from log start/end if available
        if (self.data["processing"].get("log_start_time") and 
            self.data["processing"].get("log_end_time")):
            try:
                start_time = datetime.fromisoformat(self.data["processing"]["log_start_time"])
                end_time = datetime.fromisoformat(self.data["processing"]["log_end_time"])
                actual_wall_clock_time = (end_time - start_time).total_seconds()
                self.data["performance"]["total_runtime"] = actual_wall_clock_time
                self.data["performance"]["wall_clock_time"] = actual_wall_clock_time
            except (ValueError, TypeError):
                pass
        
        # If we have processing times but no wall clock time, use sum of processing times as fallback
        if (actual_wall_clock_time is None and 
            self.data["performance"].get("total_time")):
            # Use sum of actual processing times as fallback
            total_processing_time = self.data["performance"]["total_time"]
            self.data["performance"]["total_runtime"] = total_processing_time
            self.data["performance"]["active_processing_time"] = total_processing_time
            
            # Calculate processing rate from average time per CVE
            avg_time = self.data["performance"]["average_time"]
            if avg_time > 0:
                self.data["performance"]["processing_rate"] = 60 / avg_time  # CVEs per minute
        elif actual_wall_clock_time and self.data["processing"]["processed_cves"] > 0:
            # Calculate processing rate from wall clock time
            self.data["performance"]["processing_rate"] = (self.data["processing"]["processed_cves"] / actual_wall_clock_time) * 60  # CVEs per minute
            
            # Also track active processing time for comparison
            if self.data["performance"].get("total_time"):
                active_time = self.data["performance"]["total_time"]
                self.data["performance"]["active_processing_time"] = active_time
                overhead_time = actual_wall_clock_time - active_time
                self.data["performance"]["overhead_time"] = overhead_time
                self.data["performance"]["overhead_percentage"] = (overhead_time / actual_wall_clock_time) * 100 if actual_wall_clock_time > 0 else 0
        elif self.data["processing"]["start_time"]:
            # Fallback to estimated wall clock time if no log headers available
            start_time = datetime.fromisoformat(self.data["processing"]["start_time"])
            current_time = datetime.now()
            runtime_seconds = (current_time - start_time).total_seconds()
            self.data["performance"]["total_runtime"] = runtime_seconds
            
            if runtime_seconds > 0 and self.data["processing"]["processed_cves"] > 0:
                self.data["performance"]["processing_rate"] = (self.data["processing"]["processed_cves"] / runtime_seconds) * 60  # CVEs per minute
        
        # ETA calculation and formatting
        if (self.data["processing"]["processed_cves"] >= self.data["processing"]["total_cves"] and 
            self.data["processing"]["total_cves"] > 0):
            # Job completed
            self.data["processing"]["eta_simple"] = "Completed"
        elif (self.data["performance"]["processing_rate"] > 0 and 
            self.data["processing"]["remaining_cves"] > 0):
            eta_minutes = self.data["processing"]["remaining_cves"] / self.data["performance"]["processing_rate"]
            eta_time = datetime.now() + timedelta(minutes=eta_minutes)
            self.data["processing"]["eta"] = eta_time.isoformat()
            
            # Create simple ETA format for dashboard
            if eta_minutes < 1:
                self.data["processing"]["eta_simple"] = "< 1 min"
            elif eta_minutes < 60:
                self.data["processing"]["eta_simple"] = f"{int(eta_minutes)} min"
            elif eta_minutes < 1440:  # Less than 24 hours
                hours = int(eta_minutes / 60)
                mins = int(eta_minutes % 60)
                self.data["processing"]["eta_simple"] = f"{hours}h {mins}m"
            else:
                days = int(eta_minutes / 1440)
                hours = int((eta_minutes % 1440) / 60)
                self.data["processing"]["eta_simple"] = f"{days}d {hours}h"
        else:
            self.data["processing"]["eta_simple"] = "Unknown"
        
        # File statistics calculations
        if self.data["file_stats"]["files_generated"] > 0:
            self.data["file_stats"]["average_file_size"] = (
                self.data["file_stats"]["total_file_size"] / 
                self.data["file_stats"]["files_generated"]
            )
        
        # Create detailed files list for dashboard table
        detailed_files = []
        for cve_id, cve_data in self.cve_processing_data.items():
            if cve_data["file_name"] and cve_data["file_size"] > 0:
                detailed_files.append({
                    "cve_id": cve_id,
                    "file_name": cve_data["file_name"],
                    "file_size": cve_data["file_size"],
                    "file_size_formatted": self.format_file_size(cve_data["file_size"]),
                    "dataframe_rows": cve_data["dataframe_rows"],
                    "processing_time": cve_data["processing_time"],
                    "processing_time_formatted": f"{cve_data['processing_time']:.2f}s"
                })
        
        # Sort by file size descending and keep top 20
        detailed_files.sort(key=lambda x: x["file_size"], reverse=True)
        self.data["file_stats"]["detailed_files"] = detailed_files[:20]
        
        # Mapping statistics calculations - only calculate if not already set from log parsing
        if (self.data["processing"]["processed_cves"] > 0 and 
            self.data["mapping_stats"]["mapping_percentage"] == 0):
            # Only calculate if we didn't get authoritative percentage from log
            self.data["mapping_stats"]["mapping_percentage"] = (
                self.data["mapping_stats"]["platform_entries_with_mappings"] / 
                self.data["processing"]["processed_cves"]
            ) * 100
        
        # CPE Query statistics calculations
        if self.data["cpe_query_stats"]["total_cpe_queries"] > 0:
            self.data["cpe_query_stats"]["average_results_per_query"] = (
                self.data["cpe_query_stats"]["total_cpe_results"] / 
                self.data["cpe_query_stats"]["total_cpe_queries"]
            )
            
            if self.data["cpe_query_stats"]["total_query_time"] > 0:
                self.data["cpe_query_stats"]["average_query_time"] = (
                    self.data["cpe_query_stats"]["total_query_time"] / 
                    self.data["cpe_query_stats"]["total_cpe_queries"]
                )
        
        # Post-process top result queries to group CVEs by query string
        self._process_top_result_queries()
        
        # Stage performance analysis
        self._analyze_stage_performance()
        
        # Calculate additional dashboard metrics
        self._calculate_dashboard_metrics()
        
        # Integrate bloat analysis
        self._integrate_bloat_analysis()
        
        # Cache file size calculation
        try:
            # Look for cache file in common locations
            cache_paths = [
                "cache/cpe_cache.json", 
                "cpe_cache.json"
            ]
            
            for cache_path in cache_paths:
                if os.path.exists(cache_path):
                    cache_size = os.path.getsize(cache_path)
                    self.data["cache"]["cache_file_size"] = cache_size
                    
                    # Format file size
                    if cache_size >= 1024 * 1024 * 1024:  # >= 1GB
                        size_gb = cache_size / (1024 * 1024 * 1024)
                        self.data["cache"]["cache_file_size_formatted"] = f"{size_gb:.1f} GB"
                    elif cache_size >= 1024 * 1024:  # >= 1MB
                        size_mb = cache_size / (1024 * 1024)
                        self.data["cache"]["cache_file_size_formatted"] = f"{size_mb:.1f} MB"
                    else:  # < 1MB
                        size_kb = cache_size / 1024
                        self.data["cache"]["cache_file_size_formatted"] = f"{size_kb:.1f} KB"
                    break
            else:
                # No cache file found
                self.data["cache"]["cache_file_size_formatted"] = "Not found"
        except Exception as e:
            self.data["cache"]["cache_file_size_formatted"] = "Error reading"
    
    def save_json(self, output_file="dashboard_data.json"):
        """Save parsed data as JSON"""
        output_path = resolve_output_path(output_file)
        
        # Store the output path for use by bloat analysis
        self.json_file = output_path
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, default=str)
        
        print(f"Dashboard data saved to: {output_path}")
        return output_path
    
    def print_summary(self):
        """Print a summary of the analysis"""
        print("\n" + "="*60)
        print("{HASHMIRE/ANALYSIS_TOOLS} - LOG ANALYSIS SUMMARY")
        print("="*60)
        
        processing = self.data["processing"]
        performance = self.data["performance"]
        cache = self.data["cache"]
        api = self.data["api"]
        
        print(f"📊 Processing Status:")
        print(f"   Total CVEs: {processing['total_cves']:,}")
        print(f"   Processed: {processing['processed_cves']:,}")
        print(f"   Progress: {processing['progress_percentage']:.2f}%")
        print(f"   Current: {processing.get('current_cve', 'N/A')}")
        
        print(f"\n⚡ Performance:")
        print(f"   Average Time: {performance['average_time']:.2f}s per CVE")
        print(f"   Processing Rate: {performance['processing_rate']:.1f} CVEs/min")
        print(f"   Total Runtime: {performance['total_runtime']:.0f}s")
        
        print(f"\n💾 Cache Performance:")
        print(f"   Total Entries: {cache['total_entries']:,}")
        print(f"   Hit Rate: {cache['hit_rate']:.1f}%")
        print(f"   API Calls Saved: {cache['api_calls_saved']:,}")
        
        print(f"\n🌐 API Usage:")
        print(f"   Total Calls: {api['total_calls']:,}")
        print(f"   Successful: {api['successful_calls']:,}")
        print(f"   Failed: {api['failed_calls']:,}")
        
        print(f"\n📁 File Generation:")
        file_stats = self.data["file_stats"]
        print(f"   Files Generated: {file_stats['files_generated']:,}")
        if file_stats['files_generated'] > 0:
            print(f"   Average File Size: {self.format_file_size(file_stats['average_file_size'])}")
            if file_stats['largest_file_size'] > 0:
                print(f"   Largest File: {file_stats['largest_file_name']} ({self.format_file_size(file_stats['largest_file_size'])})")
            if file_stats['smallest_file_size'] is not None:
                print(f"   Smallest File: {file_stats['smallest_file_name']} ({self.format_file_size(file_stats['smallest_file_size'])})")
        
        print(f"\n🔗 Mapping Statistics:")
        mapping_stats = self.data["mapping_stats"]
        if "total_platform_entries_processed" in mapping_stats and mapping_stats["total_platform_entries_processed"] > 0:
            print(f"   Platform Entries: {mapping_stats['total_platform_entries_processed']:,}")
            print(f"   With Mappings: {mapping_stats['platform_entries_with_mappings']:,}")
            print(f"   Success Rate: {mapping_stats['mapping_percentage']:.2f}%")
            print(f"   Total Mappings: {mapping_stats['total_mappings_found']:,}")
        else:
            print(f"   No mapping data available")
        
        if self.data["errors"]:
            print(f"\n❌ Errors: {len(self.data['errors'])} found")
        else:
            print(f"\n✅ No errors detected")
        
        print("="*60)
    
    def _process_top_result_queries(self):
        """Process top result queries to group CVEs by query string and track sources"""
        if not self.data["cpe_query_stats"]["top_result_queries"]:
            return
        
        # Group queries by query_string and aggregate CVEs and sources
        query_groups = {}
        for query_result in self.data["cpe_query_stats"]["top_result_queries"]:
            query_string = query_result["query_string"]
            cve_id = query_result["cve_id"]
            result_count = query_result["result_count"]
            source = query_result.get("source", "unknown")
            
            if query_string not in query_groups:
                query_groups[query_string] = {
                    "query_string": query_string,
                    "max_result_count": result_count,
                    "cve_ids": [],
                    "total_queries": 0,
                    "sources": set(),  # Track unique sources
                    "timestamps": []
                }
            
            # Update max result count for this query string
            if result_count > query_groups[query_string]["max_result_count"]:
                query_groups[query_string]["max_result_count"] = result_count
            
            # Add CVE ID if not already present and limit to 5
            if cve_id not in query_groups[query_string]["cve_ids"] and len(query_groups[query_string]["cve_ids"]) < 5:
                query_groups[query_string]["cve_ids"].append(cve_id)
            
            # Track sources
            query_groups[query_string]["sources"].add(source)
            
            query_groups[query_string]["total_queries"] += 1
            query_groups[query_string]["timestamps"].append(query_result["timestamp"])
        
        # Convert to list and sort by max result count
        processed_queries = []
        for query_string, group_data in query_groups.items():
            # Determine combined source
            sources = list(group_data["sources"])
            if len(sources) > 1:
                combined_source = "both"
            elif "api" in sources:
                combined_source = "api"
            elif "cache" in sources:
                combined_source = "cache"
            else:
                combined_source = "unknown"
            
            # Get the most recent timestamp for this query group
            latest_timestamp = max(group_data["timestamps"]) if group_data["timestamps"] else "Unknown"
            
            processed_queries.append({
                "query_string": query_string,
                "result_count": group_data["max_result_count"],
                "cve_ids": group_data["cve_ids"],
                "cve_count": len(group_data["cve_ids"]),
                "total_queries": group_data["total_queries"],
                "source": combined_source,
                "sources_detail": sources,  # Keep individual sources for reference
                "timestamp": latest_timestamp
            })
        
        # Sort by result count and keep top 10
        processed_queries.sort(key=lambda x: x["result_count"], reverse=True)
        self.data["cpe_query_stats"]["top_result_queries"] = processed_queries[:10]

    def _update_file_size_stats(self, file_name, file_size):
        """Update file size statistics for a given file"""
        # Add to total file size
        self.data["file_stats"]["total_file_size"] += file_size
        
        # Track largest file
        if file_size > self.data["file_stats"]["largest_file_size"]:
            self.data["file_stats"]["largest_file_size"] = file_size
            self.data["file_stats"]["largest_file_name"] = file_name
        
        # Track smallest file
        if (self.data["file_stats"]["smallest_file_size"] is None or 
            file_size < self.data["file_stats"]["smallest_file_size"]):
            self.data["file_stats"]["smallest_file_size"] = file_size
            self.data["file_stats"]["smallest_file_name"] = file_name

def main():
    parser = argparse.ArgumentParser(description='Analyze Hashmire/Analysis_Tools logs and generate dashboard data')
    parser.add_argument('--log-dir', default='logs', help='Directory containing log files')
    parser.add_argument('--log-file', help='Specific log file to analyze')
    parser.add_argument('--output', default='dashboard_data.json', help='Output JSON file')
    parser.add_argument('--summary', action='store_true', help='Print summary to console')
    parser.add_argument('--no-local-dashboard', action='store_true', help='Skip local dashboard generation')
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer(args.log_dir)
    
    try:
        if args.log_file:
            log_file = args.log_file
        else:
            log_file = analyzer.find_latest_log()
            
        if not log_file:
            print("No log files found!")
            return 1
        
        print(f"Analyzing log file: {log_file}")
        
        # Auto-resolve output path if relative path provided
        output_path = args.output
        if not os.path.isabs(output_path):
            # Extract run directory from log file path and construct reports path
            from pathlib import Path
            log_path = Path(log_file)
            if 'runs' in log_path.parts:
                # Find the run directory in the path
                run_dir_index = None
                for i, part in enumerate(log_path.parts):
                    if part == 'runs' and i + 1 < len(log_path.parts):
                        run_dir_index = i + 1
                        break
                
                if run_dir_index is not None:
                    # Construct run directory path
                    run_dir_parts = log_path.parts[:run_dir_index + 1]
                    run_dir = Path(*run_dir_parts)
                    reports_dir = run_dir / 'reports'
                    reports_dir.mkdir(exist_ok=True)
                    output_path = str(reports_dir / output_path)
                    print(f"Auto-resolved output path: {output_path}")
        
        data = analyzer.parse_log_file(log_file)
        
        # Save JSON data
        analyzer.save_json(output_path)
        
        # Auto-generate local dashboard
        if not args.no_local_dashboard:
            try:
                from pathlib import Path
                import subprocess
                
                # Generate local dashboard automatically
                output_dir = Path(output_path).parent
                local_dashboard = output_dir / "local_dashboard.html"
                
                print(f"Auto-generating local dashboard: {local_dashboard}")
                result = subprocess.run([
                    'python', 'src/analysis_tool/local_dashboard/generate_local_dashboard.py',
                    '--input', output_path,
                    '--output', str(local_dashboard)
                ], capture_output=True, text=True, encoding='utf-8', errors='replace')
                
                if result.returncode == 0:
                    print(f"✅ Local dashboard updated: {local_dashboard}")
                else:
                    print(f"⚠️  Warning: Failed to generate local dashboard: {result.stderr}")
                    
            except Exception as e:
                print(f"⚠️  Warning: Could not auto-generate local dashboard: {e}")
        
        # Print summary if requested
        if args.summary:
            analyzer.print_summary()
        
        return 0
        
    except Exception as e:
        print(f"Error analyzing log file: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
