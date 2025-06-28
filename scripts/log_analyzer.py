#!/usr/bin/env python3
"""
CVE Analysis Tool Dashboard Data Generator
Parses log files and generates JSON data for the dashboard
"""

import json
import re
import os
import glob
from datetime import datetime, timedelta
from pathlib import Path
import argparse

class LogAnalyzer:
    def __init__(self, log_directory="logs"):
        self.log_directory = log_directory
        self.data = {}
        self.current_processing_cve = None  # Track current CVE being processed
        
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
                "failed_calls": 0
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
                "average_file_size": 0
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
                "cves_with_mappings": 0,
                "mapping_percentage": 0,
                "largest_mapping_count": 0,
                "largest_mapping_cve": ""
            },
            "cpe_query_stats": {
                "total_cpe_queries": 0,
                "largest_query_results": 0,
                "largest_query_cve": "",
                "largest_query_time": 0,
                "total_cpe_results": 0,
                "average_results_per_query": 0,
                "total_query_time": 0,
                "average_query_time": 0
            },
            "recent_activity": [],
            "errors": [],
            "warnings": [],
            "stages": {
                "initialization": {"started": False, "completed": False},
                "cve_queries": {"started": False, "completed": False},
                "unique_cpe": {"started": False, "completed": False},
                "cpe_queries": {"started": False, "completed": False},
                "confirmed_mappings": {"started": False, "completed": False},
                "page_generation": {"started": False, "completed": False}
            }
        }
        
        self._parse_lines(lines)
        self._calculate_derived_metrics()
        
        return self.data
    
    def _parse_lines(self, lines):
        """Parse individual log lines"""
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Extract timestamp and log level
            timestamp_match = re.match(r'\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.*)', line)
            if not timestamp_match:
                continue
                
            timestamp_str, level, message = timestamp_match.groups()
            
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
        
        # Processing time for individual CVEs
        time_match = re.search(r'Successfully processed ([^)]+) in ([\d.]+)s', message)
        if time_match:
            cve_id, time_str = time_match.groups()
            processing_time = float(time_str)
            self.data["performance"]["processing_times"].append(processing_time)
            
            # Track speed statistics
            self.data["speed_stats"]["total_processing_time"] += processing_time
            self.data["speed_stats"]["cves_with_timing"] += 1
            
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
        
        # Cache hits/misses (legacy, less accurate)
        if "Cache hit for CPE:" in message and cache_session_match is None:
            self.data["cache"]["cache_hits"] += 1
        elif "Cache miss for CPE:" in message and cache_session_match is None:
            self.data["cache"]["cache_misses"] += 1
        
        # Parse cache statistics from audit checkpoints
        cache_stats_match = re.search(r'CPE cache: (\d+)/(\d+) session hits \(([\d.]+)%\)', message)
        if cache_stats_match:
            hits, total, percentage = cache_stats_match.groups()
            self.data["cache"]["cache_hits"] = int(hits)
            total_attempts = int(total)
            self.data["cache"]["cache_misses"] = total_attempts - int(hits)
            self.data["cache"]["hit_rate"] = float(percentage)
        
        # Parse cache lifetime statistics
        cache_lifetime_match = re.search(r'CPE cache lifetime: ([\d.]+)% hit rate, (\d+) API calls saved', message)
        if cache_lifetime_match:
            hit_rate, calls_saved = cache_lifetime_match.groups()
            self.data["cache"]["hit_rate"] = float(hit_rate)
            self.data["cache"]["api_calls_saved"] = int(calls_saved)
        
        # API calls
        if "API Call:" in message:
            self.data["api"]["total_calls"] += 1
            if "NVD CVE API" in message:
                self.data["api"]["nvd_cve_calls"] += 1
            elif "MITRE CVE API" in message:
                self.data["api"]["mitre_cve_calls"] += 1
            elif "NVD CPE API" in message:
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
        
        # Mapping statistics tracking
        mapping_found_match = re.search(r'Found (\d+) confirmed mappings for (CVE-\d{4}-\d+)', message)
        mapping_platform_match = re.search(r'Found (\d+) confirmed mappings for platform entry (\d+)', message)
        mapping_stats_match = re.search(r'Confirmed mappings statistics: (\d+)/(\d+) entries \(([\d.]+)% hit rate\), (\d+) total mappings found', message)
        
        if mapping_found_match:
            mapping_count, cve_id = mapping_found_match.groups()
            mapping_count = int(mapping_count)
            
            if mapping_count > 0:
                self.data["mapping_stats"]["total_mappings_found"] += mapping_count
                self.data["mapping_stats"]["cves_with_mappings"] += 1
                
                # Track largest mapping count
                if mapping_count > self.data["mapping_stats"]["largest_mapping_count"]:
                    self.data["mapping_stats"]["largest_mapping_count"] = mapping_count
                    self.data["mapping_stats"]["largest_mapping_cve"] = cve_id
        elif mapping_platform_match:
            # Track platform entry mappings
            mapping_count = int(mapping_platform_match.group(1))
            if mapping_count > 0:
                self.data["mapping_stats"]["total_mappings_found"] += mapping_count
        elif mapping_stats_match:
            # Parse the statistics summary - accumulate instead of overwrite
            entries_with_mappings, total_entries, hit_rate, total_mappings = mapping_stats_match.groups()
            total_mappings = int(total_mappings)
            entries_with_mappings = int(entries_with_mappings)
            
            # Only count if there are actual mappings
            if total_mappings > 0:
                self.data["mapping_stats"]["total_mappings_found"] += total_mappings
                self.data["mapping_stats"]["cves_with_mappings"] += entries_with_mappings
        
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
        
        # File generation tracking
        file_generated_match = re.search(r'File Generated: (.+\.html)$', message)
        file_size_audit_match = re.search(r'File size normal: ([^(]+) \(([\d.]+)(KB|MB|GB)\)', message)
        
        if file_generated_match:
            file_path = file_generated_match.group(1)
            file_name = os.path.basename(file_path)
            
            # Count the file generation
            self.data["file_stats"]["files_generated"] += 1
            
            # Try to get file size if the file exists
            try:
                file_size = os.path.getsize(file_path)
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
            except (OSError, FileNotFoundError):
                # File doesn't exist yet, skip size tracking for now
                pass
        elif file_size_audit_match:
            # Parse file size audit messages - only update size info, don't count files again
            file_name, size_str, unit = file_size_audit_match.groups()
            file_name = file_name.strip()
            
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
            
            # Only update size information, don't count files again
            # Track largest file
            if file_size > self.data["file_stats"]["largest_file_size"]:
                self.data["file_stats"]["largest_file_size"] = file_size
                self.data["file_stats"]["largest_file_name"] = file_name
            
            # Track smallest file
            if (self.data["file_stats"]["smallest_file_size"] is None or 
                file_size < self.data["file_stats"]["smallest_file_size"]):
                self.data["file_stats"]["smallest_file_size"] = file_size
                self.data["file_stats"]["smallest_file_name"] = file_name
            
            # Track largest file
            if file_size > self.data["file_stats"]["largest_file_size"]:
                self.data["file_stats"]["largest_file_size"] = file_size
                self.data["file_stats"]["largest_file_name"] = file_name
            
            # Track smallest file
            if (self.data["file_stats"]["smallest_file_size"] is None or 
                file_size < self.data["file_stats"]["smallest_file_size"]):
                self.data["file_stats"]["smallest_file_size"] = file_size
                self.data["file_stats"]["smallest_file_name"] = file_name
        
        # Stage tracking
        stage_patterns = {
            "initialization": r"Starting Initialization|Completed Initialization",
            "cve_queries": r"Starting CVE Queries|Completed CVE Queries",
            "unique_cpe": r"Starting Unique CPE Generation|Completed Unique CPE Generation", 
            "cpe_queries": r"Starting CPE Queries|Completed CPE Queries",
            "confirmed_mappings": r"Starting Confirmed Mappings|Completed Confirmed Mappings",
            "page_generation": r"Starting Page Generation|Completed Page Generation"
        }
        
        for stage, pattern in stage_patterns.items():
            if re.search(pattern, message):
                if "Starting" in message:
                    self.data["stages"][stage]["started"] = True
                elif "Completed" in message:
                    self.data["stages"][stage]["completed"] = True
    
    def _calculate_derived_metrics(self):
        """Calculate derived metrics from parsed data"""
        
        # Average processing time
        if self.data["performance"]["processing_times"]:
            self.data["performance"]["average_time"] = sum(self.data["performance"]["processing_times"]) / len(self.data["performance"]["processing_times"])
        
        # Cache hit rate (only calculate if not already set from log parsing)
        if self.data["cache"]["hit_rate"] == 0:
            total_cache_ops = self.data["cache"]["cache_hits"] + self.data["cache"]["cache_misses"]
            if total_cache_ops > 0:
                self.data["cache"]["hit_rate"] = (self.data["cache"]["cache_hits"] / total_cache_ops) * 100
                self.data["cache"]["api_calls_saved"] = self.data["cache"]["cache_hits"]
        
        # Processing rate and runtime - use actual processing times, not wall clock time
        if self.data["performance"]["processing_times"]:
            # Use sum of actual processing times for accurate runtime
            total_processing_time = sum(self.data["performance"]["processing_times"])
            self.data["performance"]["total_runtime"] = total_processing_time
            
            # Calculate processing rate from average time per CVE
            avg_time = total_processing_time / len(self.data["performance"]["processing_times"])
            if avg_time > 0:
                self.data["performance"]["processing_rate"] = 60 / avg_time  # CVEs per minute
        elif self.data["processing"]["start_time"]:
            # Fallback to wall clock time if no processing times available
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
        
        # Mapping statistics calculations
        if self.data["processing"]["processed_cves"] > 0:
            self.data["mapping_stats"]["mapping_percentage"] = (
                self.data["mapping_stats"]["cves_with_mappings"] / 
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
        
        # Cache file size calculation
        try:
            # Look for cache file in common locations
            cache_paths = [
                "src/analysis_tool/cache/cpe_cache.json",
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
    
    def save_json(self, output_file="reports/dashboard_data.json"):
        """Save parsed data as JSON"""
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, default=str)
        
        print(f"Dashboard data saved to: {output_file}")
        return output_file
    
    def print_summary(self):
        """Print a summary of the analysis"""
        print("\n" + "="*60)
        print("CVE ANALYSIS TOOL - LOG ANALYSIS SUMMARY")
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
        
        if self.data["errors"]:
            print(f"\n❌ Errors: {len(self.data['errors'])} found")
        else:
            print(f"\n✅ No errors detected")
        
        print("="*60)

def main():
    parser = argparse.ArgumentParser(description='Analyze CVE Analysis Tool logs and generate dashboard data')
    parser.add_argument('--log-dir', default='logs', help='Directory containing log files')
    parser.add_argument('--log-file', help='Specific log file to analyze')
    parser.add_argument('--output', default='reports/dashboard_data.json', help='Output JSON file')
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
        data = analyzer.parse_log_file(log_file)
        
        # Save JSON data
        analyzer.save_json(args.output)
        
        # Auto-generate local dashboard
        if not args.no_local_dashboard:
            try:
                from pathlib import Path
                import subprocess
                
                # Generate local dashboard automatically
                output_dir = Path(args.output).parent
                local_dashboard = output_dir / "local_dashboard.html"
                
                print(f"Auto-generating local dashboard: {local_dashboard}")
                result = subprocess.run([
                    'python', 'scripts/generate_local_dashboard.py',
                    '--input', args.output,
                    '--output', str(local_dashboard)
                ], capture_output=True, text=True)
                
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
