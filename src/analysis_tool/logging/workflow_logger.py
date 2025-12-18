#!/usr/bin/env python3
"""
Centralized Logging Utility for Analysis Tool

This module provides organized logging functionality with groupings for different
workflow stages of the CVE analysis pipeline.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone, timezone
from enum import Enum
from typing import Optional, Dict, Any
from pathlib import Path


class LogLevel(Enum):
    """Log level enumeration"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class LogGroup(Enum):
    """Log group enumeration for workflow stages"""
    HARVEST = "HARVEST"
    DATASET = "DATASET"
    CACHE_MANAGEMENT = "CACHE_MANAGEMENT"
    INIT = "INIT"
    CVE_QUERY = "CVE_QUERY"
    UNIQUE_CPE = "UNIQUE_CPE"
    CPE_QUERY = "CPE_QUERY"
    BADGE_GEN = "BADGE_GEN"
    PAGE_GEN = "PAGE_GEN"
    DATA_PROC = "DATA_PROC"


class WorkflowLogger:
    """Centralized logger for the analysis tool workflow"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the logger with configuration"""
        self.config = self._load_config(config_path)
        self.logging_config = self.config.get('logging', {})
        self.enabled = self.logging_config.get('enabled', True)
        self.level = LogLevel(self.logging_config.get('level', 'INFO'))
        self.format_string = self.logging_config.get('format', '[{timestamp}] [{level}] {message}')
        self.groups = self.logging_config.get('groups', {})
        
        # File logging setup
        self.log_file = None
        self.current_log_path = None  # Track current log file path
        self.log_directory = self._get_logs_directory()
        # Color mapping for console output (if terminal supports colors)
        self.colors = {
            'blue': '\033[94m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'cyan': '\033[96m',
            'magenta': '\033[95m',
            'white': '\033[97m',
            'red': '\033[91m',
            'bright_red': '\033[91m',
            'reset': '\033[0m'
        }
        
        # Check if we should use colors (avoid colors in non-interactive terminals)
        self.use_colors = sys.stdout.isatty() and os.name != 'nt'  # Disable on Windows for now
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from config.json"""
        if config_path is None:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
        
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load config file {config_path}: {e}")
            return {}
    
    def _get_logs_directory(self):
        """Get the logs directory path. Returns None if not set.
        
        Note: This should be set explicitly using set_run_logs_directory() before
        starting file logging. The logger no longer defaults to a global logs directory
        to ensure logs are organized within run-specific directories.
        """
        return None
    
    def set_run_logs_directory(self, run_logs_path: str):
        """Update the logs directory to use run-specific path"""
        self.log_directory = run_logs_path
        # If file logging is active, we need to restart it with new path
        if hasattr(self, 'file_handler') and self.file_handler:
            # Close current handler
            self.file_handler.close()
            logger = logging.getLogger('workflow')
            logger.removeHandler(self.file_handler)
            
            # Restart with new path
            if hasattr(self, '_current_params'):
                self.start_file_logging(self._current_params)
    
    def _should_log(self, level: LogLevel, group: LogGroup) -> bool:
        """Determine if we should log based on level and group settings"""
        if not self.enabled:
            return False
        # Check if group is enabled
        group_key = group.value if hasattr(group, 'value') else group
        group_config = self.groups.get(group_key, {})
        if not group_config.get('enabled', True):
            return False
        
        # Check log level hierarchy
        level_hierarchy = {
            LogLevel.DEBUG: 0,
            LogLevel.INFO: 1,
            LogLevel.WARNING: 2,
            LogLevel.ERROR: 3
        }
        
        return level_hierarchy[level] >= level_hierarchy[self.level]
    
    def _get_timestamp(self) -> str:
        """Get formatted timestamp"""
        return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    
    def _format_message(self, level: LogLevel, group: LogGroup, message: str) -> str:
        """Format the log message"""
        formatted = self.format_string.format(
            timestamp=self._get_timestamp(),
            level=level.value,
            message=message
        )
        
        # Add colors if supported (use group color for stage banners only)
        if self.use_colors and ("===" in message):  # Only colorize stage banners
            group_key = group.value if hasattr(group, 'value') else group
            group_config = self.groups.get(group_key, {})
            color = self.colors.get(group_config.get('color', 'white'), '')
            reset = self.colors['reset']
            formatted = f"{color}{formatted}{reset}"
        
        return formatted
    
    def _format_banner(self, group: LogGroup, message: str) -> str:
        """Format stage banners without log level prefix for cleaner visual separation"""
        formatted = f"[{self._get_timestamp()}] {message}"
        
        # Add colors if supported
        if self.use_colors:
            group_key = group.value if hasattr(group, 'value') else group
            group_config = self.groups.get(group_key, {})
            color = self.colors.get(group_config.get('color', 'white'), '')
            reset = self.colors['reset']
            formatted = f"{color}{formatted}{reset}"
        
        return formatted
    
    def _log_banner(self, group: str, message: str):
        """Log a stage banner without log level prefix"""
        if not self.enabled:
            return
        
        # Check group filtering
        group_config = self.groups.get(group, {})
        if not group_config.get('enabled', True):
            return
          # Use banner formatting instead of standard message formatting
        formatted = self._format_banner(group, message)
        self._print_message(formatted)
    
    def log(self, level: LogLevel, group: str, message: str):
        """Log a message with specified level and group"""
        # Convert string group to LogGroup enum if needed
        if isinstance(group, str):
            group_mapping = {
                "harvest": LogGroup.HARVEST,
                "dataset": LogGroup.DATASET,
                "cache_managemnet": LogGroup.CACHE_MANAGEMENT,
                "initialization": LogGroup.INIT,
                "init": LogGroup.INIT,
                "cve_query": LogGroup.CVE_QUERY,
                "cve_queries": LogGroup.CVE_QUERY,
                "unique_cpe": LogGroup.UNIQUE_CPE,
                "cpe_query": LogGroup.CPE_QUERY,
                "cpe_queries": LogGroup.CPE_QUERY,
                "badge_gen": LogGroup.BADGE_GEN,
                "badge_generation": LogGroup.BADGE_GEN,
                "page_gen": LogGroup.PAGE_GEN,
                "page_generation": LogGroup.PAGE_GEN,
                "data_proc": LogGroup.DATA_PROC,
                "data_processing": LogGroup.DATA_PROC
            }
            group_enum = group_mapping.get(group.lower(), LogGroup.INIT)
        else:
            group_enum = group            
        if self._should_log(level, group_enum):
            formatted_message = self._format_message(level, group_enum, message)
            self._print_message(formatted_message)
    
    def debug(self, message: str, group: str = "initialization"):
        """Log a debug message"""
        self.log(LogLevel.DEBUG, group, message)
        
        # Track cache activity and CPE query statistics
        try:
            from ..reporting.dataset_contents_collector import get_dataset_contents_collector
            collector = get_dataset_contents_collector()
            
            # Track cache hits with result count
            if "Cache hit for CPE:" in message and "results)" in message:
                import re
                match = re.search(r'\((\d+) results\)', message)
                if match:
                    result_count = int(match.group(1))
                    
                    # Update CPE query statistics for cache hits
                    collector.data["cpe_query_stats"]["total_queries"] += 1
                    collector.data["cpe_query_stats"]["total_results"] += result_count
                    
                    # Update averages
                    total_queries = collector.data["cpe_query_stats"]["total_queries"]
                    total_results = collector.data["cpe_query_stats"]["total_results"]
                    if total_queries > 0:
                        collector.data["cpe_query_stats"]["avg_results_per_query"] = total_results / total_queries
                        
                    # Update max results
                    if result_count > collector.data["cpe_query_stats"]["max_results_single_query"]:
                        collector.data["cpe_query_stats"]["max_results_single_query"] = result_count
                    
                    # Record cache activity
                    collector.record_cache_activity('hit')
                    collector._auto_save()
                    
            # Track cache misses
            elif "Cache miss for CPE:" in message and "Making API call" in message:
                collector.record_cache_activity('miss')
                collector._auto_save()
                
            # Track cache expired entries  
            elif "Cache expired for CPE:" in message and "Making API call" in message:
                collector.record_cache_activity('expired')
                collector._auto_save()
                
        except Exception as e:
            # Don't break logging if dashboard collector fails
            pass
    
    def info(self, message: str, group: str = "initialization"):
        """Log an info message"""
        self.log(LogLevel.INFO, group, message)
    
    def warning(self, message: str, group: str = "initialization"):
        """Log a warning message"""
        self.log(LogLevel.WARNING, group, message)
    
    def error(self, message: str, group: str = "data_processing"):
        """Log an error message"""
        self.log(LogLevel.ERROR, group, message)
    
    def stage_start(self, stage_name: str, details: str = "", group: str = "initialization"):
        """Log the start of a major workflow stage"""
        extra = f" - {details}" if details else ""
        self._log_banner(group, f"=== Starting {stage_name}{extra} ===")
    
    def stage_end(self, stage_name: str, details: str = "", group: str = "initialization"):
        """Log the end of a major workflow stage"""
        extra = f" - {details}" if details else ""
        self._log_banner(group, f"=== Completed {stage_name}{extra} ===")
    
    def stage_progress(self, current: int, total: int, item: str = "", group: str = "initialization"):
        """Log progress within a stage"""
        progress_pct = (current / total * 100) if total > 0 else 0
        item_info = f" ({item})" if item else ""
        self.info(f"Progress: {current}/{total} ({progress_pct:.1f}%){item_info}", group=group)
    
    def api_call(self, endpoint: str, params: Dict[str, Any] = None, group: str = "cve_queries"):
        """Log an API call"""
        params_str = f" with params: {params}" if params else ""
        self.info(f"API Call: {endpoint}{params_str}", group=group)
        
        # Also record in dashboard collector for real-time statistics
        try:
            from ..reporting.dataset_contents_collector import record_api_call_unified
            record_api_call_unified(endpoint, success=True)
        except Exception as e:
            # Don't break logging if dashboard collector fails
            pass
    
    def api_response(self, endpoint: str, status: str, count: int = None, group: str = "cve_queries"):
        """Log an API response"""
        count_str = f" ({count} results)" if count is not None else ""
        self.info(f"API Response: {endpoint} - {status}{count_str}", group=group)
        
        # Update dashboard collector with response details
        try:
            from ..reporting.dataset_contents_collector import get_dataset_contents_collector
            collector = get_dataset_contents_collector()
            
            # Record CPE query statistics if this is a CPE API response
            if "CPE API" in endpoint and count is not None:
                if "total_queries" not in collector.data["cpe_query_stats"]:
                    collector.data["cpe_query_stats"]["total_queries"] = 0
                collector.data["cpe_query_stats"]["total_queries"] += 1
                collector.data["cpe_query_stats"]["total_results"] += count
                
                # Update averages
                total_queries = collector.data["cpe_query_stats"]["total_queries"]
                total_results = collector.data["cpe_query_stats"]["total_results"]
                if total_queries > 0:
                    collector.data["cpe_query_stats"]["avg_results_per_query"] = total_results / total_queries
                    
                # Update max results
                if count > collector.data["cpe_query_stats"]["max_results_single_query"]:
                    collector.data["cpe_query_stats"]["max_results_single_query"] = count
                
                collector._auto_save()
                
        except Exception as e:
            # Don't break logging if dashboard collector fails
            pass
    
    def data_summary(self, operation: str, group: str = "data_processing", **kwargs):
        """Log a data operation summary"""
        details = ", ".join([f"{k}={v}" for k, v in kwargs.items()])
        self.info(f"[{operation}]: {details}", group=group)
    
    def file_operation(self, operation: str, filepath: str, details: str = "", group: str = "page_generation"):
        """Log a file operation"""
        extra = f" - {details}" if details else ""
        self.info(f"File {operation}: {filepath}{extra}", group=group)
        
        # Update dashboard collector if this is a file generation
        if operation.lower() in ['generated', 'created', 'saved'] and filepath.endswith('.html'):
            try:
                from ..reporting.dataset_contents_collector import get_dataset_contents_collector
                collector = get_dataset_contents_collector()
                
                # Update file generation count
                collector.data["processing"]["files_generated"] += 1
                collector.data["file_stats"]["files_generated"] += 1
                
                # Update file size info if file exists
                if os.path.exists(filepath):
                    file_size = os.path.getsize(filepath)
                    collector.data["file_stats"]["total_file_size"] += file_size
                    
                    # Update size tracking
                    if file_size > collector.data["file_stats"]["largest_file_size"]:
                        collector.data["file_stats"]["largest_file_size"] = file_size
                        collector.data["file_stats"]["largest_file_name"] = os.path.basename(filepath)
                    
                    if (collector.data["file_stats"]["smallest_file_size"] is None or 
                        file_size < collector.data["file_stats"]["smallest_file_size"]):
                        collector.data["file_stats"]["smallest_file_size"] = file_size
                        collector.data["file_stats"]["smallest_file_name"] = os.path.basename(filepath)
                    
                    # Store file size for median calculation
                    if "file_sizes" not in collector.data["file_stats"]:
                        collector.data["file_stats"]["file_sizes"] = []
                    collector.data["file_stats"]["file_sizes"].append(file_size)
                    
                    # Calculate median file size
                    files_count = collector.data["file_stats"]["files_generated"]
                    if files_count > 0:
                        import statistics
                        collector.data["file_stats"]["median_file_size"] = statistics.median(collector.data["file_stats"]["file_sizes"])
                
                collector._auto_save()
                
            except Exception as e:
                # Don't break logging if dashboard collector fails
                pass
    
    def _print_message(self, message: str):
        """Print a message with proper encoding handling"""
        try:
            print(message, flush=True)
        except UnicodeEncodeError:
            # Handle Unicode encoding errors by replacing problematic characters
            safe_message = message.encode('ascii', errors='replace').decode('ascii')
            print(safe_message, flush=True)
        
        # Also write to log file if file logging is enabled
        if self.log_file:
            try:
                # Write without colors for file output
                clean_message = self._strip_ansi_codes(message)
                self.log_file.write(clean_message + '\n')
                self.log_file.flush()
            except Exception as e:
                # Don't let file logging errors break the main functionality
                print(f"Warning: Failed to write to log file: {e}")
    
    def _strip_ansi_codes(self, text: str) -> str:
        """Remove ANSI color codes from text for clean file output"""
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    def start_file_logging(self, run_parameters: str):
        """Start logging to a file with date and parameter-based filename
        
        Note: You must call set_run_logs_directory() before calling this method
        to specify where logs should be written. If file logging is already active for the same file, this is a no-op.
        """
        if not self.enabled:
            return
        
        if not self.log_directory:
            print("Warning: Cannot start file logging - no log directory set. Call set_run_logs_directory() first.")
            return
            
        try:
            # Create logs directory if it doesn't exist
            os.makedirs(self.log_directory, exist_ok=True)
            
            # Generate filename with date and parameters
            date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
            
            # Clean parameter string for filename (remove invalid characters)
            import re
            clean_params = re.sub(r'[<>:"/\\|?*]', '_', run_parameters)
            clean_params = clean_params.replace(' ', '_')
            
            filename = f"{date_str}_{clean_params}.log"
            log_path = os.path.join(self.log_directory, filename)
            
            # If file logging is already active for this same file, don't reinitialize
            if self.log_file and self.current_log_path == log_path:
                print(f"[{self._get_timestamp()}] [DEBUG] File logging already active for: {log_path}")
                return
            
            # Close existing log file if switching to a different file
            if self.log_file and self.current_log_path != log_path:
                self.stop_file_logging()
            
            # Store current log path for access by other components
            self.current_log_path = log_path
            
            # Check if file already exists (append mode) or create new (write mode with header)
            file_exists = os.path.exists(log_path)
            
            if file_exists:
                # Append to existing file
                self.log_file = open(log_path, 'a', encoding='utf-8')
                self.log_file.write(f"\n# Logging resumed: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.log_file.write(f"# Parameters: {run_parameters}\n\n")
            else:
                # Create new file with header
                self.log_file = open(log_path, 'w', encoding='utf-8')
                
            self.log_file.flush()
            
            print(f"[{self._get_timestamp()}] [INFO] Logging to file: {log_path}")
            
        except Exception as e:
            print(f"Warning: Failed to start file logging: {e}")
            self.log_file = None
    
    def stop_file_logging(self):
        """Stop file logging and close the log file"""
        if self.log_file:
            try:
                # Write footer to log file
                self.log_file.write(f"\n# " + "="*50 + "\n")
                self.log_file.write(f"# Completed: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}\\n")
                self.log_file.write(f"# End of log\n")
                self.log_file.close()
                self.log_file = None
                self.current_log_path = None  # Clear log path when stopped
            except Exception as e:
                print(f"Warning: Failed to close log file properly: {e}")


# Global logger instance
_logger_instance = None


def get_logger() -> WorkflowLogger:
    """Get the global logger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = WorkflowLogger()
    return _logger_instance


def reinitialize_logger(config_path: Optional[str] = None):
    """Reinitialize the global logger with new config"""
    global _logger_instance
    _logger_instance = WorkflowLogger(config_path)


# Convenience functions for direct access to common logging operations
def log_cve_query(message: str):
    """Log CVE query message"""
    get_logger().info(message, group="cve_query")


def log_unique_cpe(message: str):
    """Log unique CPE generation message"""
    get_logger().info(message, group="unique_cpe")


def log_cpe_query(message: str):
    """Log CPE query message"""
    get_logger().info(message, group="cpe_query")


def log_badge_gen(message: str):
    """Log badge generation message"""
    get_logger().info(message, group="badge_gen")


def log_page_gen(message: str):
    """Log page generation message"""
    get_logger().info(message, group="page_gen")


def log_data_proc(message: str):
    """Log data processing message"""
    get_logger().info(message, group="data_proc")


# Stage management convenience functions
def start_cve_queries(details: str = ""):
    """Mark the start of CVE queries stage"""
    get_logger().stage_start("Gathering CVE Record", details, group="cve_query")


def end_cve_queries(details: str = ""):
    """Mark the end of CVE queries stage"""
    get_logger().stage_end("Gathering CVE Record", details, group="cve_query")


def start_unique_cpe_generation(details: str = ""):
    """Mark the start of unique CPE generation stage"""
    get_logger().stage_start("Unique CPE Generation", details, group="unique_cpe")


def end_unique_cpe_generation(details: str = ""):
    """Mark the end of unique CPE generation stage"""
    get_logger().stage_end("Unique CPE Generation", details, group="unique_cpe")


def start_cpe_queries(details: str = ""):
    """Mark the start of CPE queries stage"""
    get_logger().stage_start("CPE Queries", details, group="cpe_query")


def end_cpe_queries(details: str = ""):
    """Mark the end of CPE queries stage"""
    get_logger().stage_end("CPE Queries", details, group="cpe_query")


def start_confirmed_mappings(details: str = ""):
    """Mark the start of confirmed mappings processing stage"""
    get_logger().stage_start("Confirmed Mappings", details, group="badge_gen")


def end_confirmed_mappings(details: str = ""):
    """Mark the end of confirmed mappings processing stage"""
    get_logger().stage_end("Confirmed Mappings", details, group="badge_gen")


def start_page_generation(details: str = ""):
    """Mark the start of page generation stage"""
    get_logger().stage_start("Page Generation", details, group="page_gen")


def end_page_generation(details: str = ""):
    """Mark the end of page generation stage"""
    get_logger().stage_end("Page Generation", details, group="page_gen")


def start_audit(details: str = ""):
    """Mark the start of CVE record processing audit stage"""
    get_logger().stage_start("CVE Record Processing Audit", details, group="CVE_QUERY")


def end_audit(details: str = ""):
    """Mark the end of CVE record processing audit stage"""
    get_logger().stage_end("CVE Record Processing Audit", details, group="CVE_QUERY")


if __name__ == "__main__":
    # Test the logging system
    logger = get_logger()
    
    print("Testing the logging system:")
    print()
    
    # Test each group and level
    for group in LogGroup:
        group_name = group.value.lower()
        logger.info(f"Testing {group_name} group", group=group_name)
        logger.warning(f"Warning message for {group_name}", group=group_name)
        logger.error(f"Error message for {group_name}", group=group_name)
    
    print()
    print("Testing stage management:")
    start_cve_queries("CVE-2024-20515")
    logger.info("Querying MITRE CVE database", group="cve_queries")
    logger.info("Querying NVD CVE API", group="cve_queries")
    end_cve_queries("Retrieved CVE data")

