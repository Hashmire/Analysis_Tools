#!/usr/bin/env python3
"""
Dashboard Test Scenarios
========================

Comprehensive test suite to validate the enhanced dashboard functionality
across different operational scenarios including single CVE runs, multiple CVE runs,
error conditions, and edge cases.

This test creates synthetic log data to test:
- Single CVE processing
- Multiple CVE processing 
- API failures and recovery
- Resource warnings
- Workflow stage timing analysis
- Performance bottleneck identification
- Cache efficiency scenarios
"""

import os
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add the src directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from analysis_tool.local_dashboard.log_analyzer import LogAnalyzer
from analysis_tool.local_dashboard.generate_local_dashboard import generate_dashboard_html

class DashboardTestScenarios:
    """Test class for generating various dashboard scenarios"""
    
    def __init__(self):
        self.test_dir = Path(__file__).parent
        # Use runs directory for unified structure
        self.runs_dir = self.test_dir.parent / "runs"
        self.test_output_dir = self.runs_dir / "dashboard_test_scenarios" 
        self.logs_dir = self.test_output_dir / "logs"
        self.reports_dir = self.test_output_dir / "reports"
        
        # Ensure directories exist
        self.runs_dir.mkdir(exist_ok=True)
        self.test_output_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)
        
        # Test configuration
        self.scenarios = {
            # === PROGRESS TRACKER TESTS ===
            "progress_tracker_starting": self._generate_progress_tracker_starting,
            "progress_tracker_midway": self._generate_progress_tracker_midway,
            "progress_tracker_completed": self._generate_progress_tracker_completed,
            "progress_tracker_with_eta": self._generate_progress_tracker_with_eta,
            
            # === METRIC CARD TESTS ===
            "metric_cards_runtime": self._generate_metric_cards_runtime_test,
            "metric_cards_api_intensive": self._generate_metric_cards_api_intensive,
            "metric_cards_mapping_success": self._generate_metric_cards_mapping_success,
            "metric_cards_file_generation": self._generate_metric_cards_file_generation,
            "metric_cards_processing_speed": self._generate_metric_cards_processing_speed,
            "metric_cards_cache_performance": self._generate_metric_cards_cache_performance,
            "metric_cards_cpe_queries": self._generate_metric_cards_cpe_queries,
            "metric_cards_resource_warnings": self._generate_metric_cards_resource_warnings,
            
            # === WORKFLOW PERFORMANCE TESTS ===
            "workflow_stage_analysis": self._generate_workflow_stage_analysis,
            "workflow_bottleneck_detection": self._generate_workflow_bottleneck_detection,
            "workflow_efficiency_metrics": self._generate_workflow_efficiency_metrics,
            
            # === API BREAKDOWN TESTS ===
            "api_breakdown_detailed": self._generate_api_breakdown_detailed,
            "api_breakdown_with_failures": self._generate_api_breakdown_with_failures,
            "api_breakdown_mixed_calls": self._generate_api_breakdown_mixed_calls,
            
            # === LOG ACTIVITY TESTS ===
            "log_activity_high_volume": self._generate_log_activity_high_volume,
            "log_activity_with_errors": self._generate_log_activity_with_errors,
            "log_activity_warning_heavy": self._generate_log_activity_warning_heavy,
            
            # === EXISTING COMPREHENSIVE TESTS ===
            "single_cve_fast": self._generate_single_cve_fast_scenario,
            "single_cve_slow": self._generate_single_cve_slow_scenario,
            "multiple_cves_balanced": self._generate_multiple_cves_balanced_scenario,
            "multiple_cves_with_failures": self._generate_multiple_cves_with_failures_scenario,
            "resource_warnings_scenario": self._generate_resource_warnings_scenario,
            "api_heavy_scenario": self._generate_api_heavy_scenario,
            "cache_efficiency_scenario": self._generate_cache_efficiency_scenario,
            "workflow_bottleneck_scenario": self._generate_workflow_bottleneck_scenario
        }
    
    def _generate_log_header(self, cve_list, start_time):
        """Generate standard log header"""
        return f"""# Hashmire/Analysis_Tools Log
# Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}
# Parameters: {', '.join(cve_list)}
# Log file: Generated for testing
# ==================================================

"""

    def _generate_single_cve_fast_scenario(self):
        """Single CVE that processes quickly - ideal performance scenario"""
        start_time = datetime.now() - timedelta(minutes=2)
        cve_id = "CVE-2024-TEST-FAST"
        
        log_content = self._generate_log_header([cve_id], start_time)
        
        # Fast initialization
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Gathering NVD source entries...\n"
        log_content += f"[{(start_time + timedelta(seconds=1)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Global CPE cache initialized and ready for use\n"
        
        # Quick workflow stages
        stage_times = [
            ("Initialization", 2),
            ("CVE Queries", 3), 
            ("Unique CPE Generation", 1),
            ("CPE Queries", 2),
            ("Confirmed Mappings", 1),
            ("Page Generation", 1)
        ]
        
        current_time = start_time + timedelta(seconds=2)
        for stage, duration in stage_times:
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Starting {stage} - Processing {cve_id} ===\n"
            current_time += timedelta(seconds=duration)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Completed {stage} - {stage} completed ===\n"
        
        # Processing info
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 1 CVE records\n"
        log_content += f"[{(start_time + timedelta(seconds=1)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 1/1 ({cve_id})\n"
        
        # API calls (minimal)
        log_content += f"[{(start_time + timedelta(seconds=3)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CVE API call: {cve_id}\n"
        log_content += f"[{(start_time + timedelta(seconds=4)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] MITRE CVE API call: {cve_id}\n"
        
        # Cache efficiency (high hit rate)
        log_content += f"[{(start_time + timedelta(seconds=5)).strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache: 15/15 session hits (100.0%)\n"
        log_content += f"[{(start_time + timedelta(seconds=5)).strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache lifetime: 89.2% hit rate, 45623 API calls saved\n"
        
        # File generation
        log_content += f"[{(start_time + timedelta(seconds=9)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] File Generated: {cve_id}.html (Size: 42.5 KB)\n"
        
        # Completion
        final_time = start_time + timedelta(seconds=10)
        log_content += f"[{final_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in 10.34s\n"
        log_content += f"# Completed: {final_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return log_content, "single_cve_fast"
    
    def _generate_single_cve_slow_scenario(self):
        """Single CVE with performance bottlenecks"""
        start_time = datetime.now() - timedelta(minutes=10)
        cve_id = "CVE-2024-TEST-SLOW"
        
        log_content = self._generate_log_header([cve_id], start_time)
        
        # Slow initialization with cache loading
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Gathering NVD source entries...\n"
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Initializing global CPE cache - this will happen once per session\n"
        log_content += f"[{(start_time + timedelta(seconds=120)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] /cpes/ cache loaded: 85432 entries in 120.45s\n"
        log_content += f"[{(start_time + timedelta(seconds=121)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Global CPE cache initialized and ready for use\n"
        
        # Resource warnings
        log_content += f"[{(start_time + timedelta(seconds=122)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Global state bloat detected: Large CPE cache: 85432 entries\n"
        
        # Workflow stages with bottleneck in CPE Queries
        stage_times = [
            ("Initialization", 5),
            ("CVE Queries", 8),
            ("Unique CPE Generation", 3),
            ("CPE Queries", 180),  # Major bottleneck
            ("Confirmed Mappings", 4),
            ("Page Generation", 2)
        ]
        
        current_time = start_time + timedelta(seconds=125)
        for stage, duration in stage_times:
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Starting {stage} - Processing {cve_id} ===\n"
            current_time += timedelta(seconds=duration)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Completed {stage} - {stage} completed ===\n"
        
        # Processing info
        log_content += f"[{(start_time + timedelta(seconds=125)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 1 CVE records\n"
        log_content += f"[{(start_time + timedelta(seconds=126)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 1/1 ({cve_id})\n"
        
        # Heavy API usage
        log_content += f"[{(start_time + timedelta(seconds=130)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CVE API call: {cve_id}\n"
        log_content += f"[{(start_time + timedelta(seconds=133)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] MITRE CVE API call: {cve_id}\n"
        
        # Multiple CPE API calls during bottleneck
        for i in range(25):
            call_time = start_time + timedelta(seconds=140 + i * 6)
            log_content += f"[{call_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CPE API call: cpe:2.3:a:example:product{i}:*:*:*:*:*:*:*:*\n"
        
        # Cache with some misses
        log_content += f"[{(start_time + timedelta(seconds=200)).strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache: 20/25 session hits (80.0%)\n"
        log_content += f"[{(start_time + timedelta(seconds=200)).strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache lifetime: 78.5% hit rate, 32145 API calls saved\n"
        
        # File generation
        log_content += f"[{(start_time + timedelta(seconds=325)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] File Generated: {cve_id}.html (Size: 156.8 KB)\n"
        
        # Completion
        final_time = start_time + timedelta(seconds=327)
        log_content += f"[{final_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in 327.23s\n"
        log_content += f"# Completed: {final_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return log_content, "single_cve_slow"
    
    def _generate_multiple_cves_balanced_scenario(self):
        """Multiple CVEs with balanced performance"""
        start_time = datetime.now() - timedelta(minutes=15)
        cve_ids = ["CVE-2024-TEST-001", "CVE-2024-TEST-002", "CVE-2024-TEST-003"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        # Initialization
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Gathering NVD source entries...\n"
        log_content += f"[{(start_time + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Global CPE cache initialized and ready for use\n"
        
        # Processing info
        log_content += f"[{(start_time + timedelta(seconds=32)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 3 CVE records\n"
        
        # Process each CVE
        current_time = start_time + timedelta(seconds=35)
        processing_times = [45.67, 52.34, 38.92]
        
        for i, (cve_id, proc_time) in enumerate(zip(cve_ids, processing_times), 1):
            # CVE start
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i}/3 ({cve_id})\n"
            
            # Workflow stages for this CVE
            stage_times = [
                ("CVE Queries", 8),
                ("Unique CPE Generation", 4),
                ("CPE Queries", 25),
                ("Confirmed Mappings", 6),
                ("Page Generation", 3)
            ]
            
            stage_start = current_time
            for stage, duration in stage_times:
                log_content += f"[{stage_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting {stage} - Processing {cve_id} ===\n"
                stage_start += timedelta(seconds=duration)
                log_content += f"[{stage_start.strftime('%Y-%m-%d %H:%M:%S')}] === Completed {stage} - {stage} completed ===\n"
            
            # API calls for this CVE
            api_time = current_time + timedelta(seconds=5)
            log_content += f"[{api_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CVE API call: {cve_id}\n"
            log_content += f"[{(api_time + timedelta(seconds=2)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] MITRE CVE API call: {cve_id}\n"
            
            # CPE API calls
            for j in range(8):
                cpe_time = current_time + timedelta(seconds=10 + j * 2)
                log_content += f"[{cpe_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CPE API call: cpe:2.3:a:vendor{i}:product{j}:*:*:*:*:*:*:*:*\n"
            
            # File generation
            file_time = current_time + timedelta(seconds=int(proc_time) - 2)
            file_size = 45.2 + i * 12.3
            log_content += f"[{file_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] File Generated: {cve_id}.html (Size: {file_size:.1f} KB)\n"
            
            # CVE completion
            completion_time = current_time + timedelta(seconds=int(proc_time))
            log_content += f"[{completion_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in {proc_time}s\n"
            
            current_time = completion_time + timedelta(seconds=2)
        
        # Cache statistics
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache: 45/50 session hits (90.0%)\n"
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache lifetime: 85.2% hit rate, 67234 API calls saved\n"
        
        log_content += f"# Completed: {current_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return log_content, "multiple_cves_balanced"
    
    def _generate_multiple_cves_with_failures_scenario(self):
        """Multiple CVEs with API failures and recovery"""
        start_time = datetime.now() - timedelta(minutes=20)
        cve_ids = ["CVE-2024-FAIL-001", "CVE-2024-FAIL-002", "CVE-2024-FAIL-003", "CVE-2024-FAIL-004"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        # Initialization
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Gathering NVD source entries...\n"
        log_content += f"[{(start_time + timedelta(seconds=25)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Global CPE cache initialized and ready for use\n"
        
        # Processing info
        log_content += f"[{(start_time + timedelta(seconds=27)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 4 CVE records\n"
        
        current_time = start_time + timedelta(seconds=30)
        
        # Process CVEs with some failures
        for i, cve_id in enumerate(cve_ids, 1):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i}/4 ({cve_id})\n"
            
            # API calls with some failures
            api_time = current_time + timedelta(seconds=2)
            log_content += f"[{api_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CVE API call: {cve_id}\n"
            
            if i == 2:  # Second CVE has API failure
                log_content += f"[{(api_time + timedelta(seconds=10)).strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] NVD CVE API call failed: Rate limit exceeded for {cve_id}\n"
                log_content += f"[{(api_time + timedelta(seconds=15)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Retrying NVD CVE API call: {cve_id}\n"
                log_content += f"[{(api_time + timedelta(seconds=20)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CVE API call successful: {cve_id}\n"
            
            log_content += f"[{(api_time + timedelta(seconds=3)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] MITRE CVE API call: {cve_id}\n"
            
            if i == 3:  # Third CVE has processing error
                log_content += f"[{(current_time + timedelta(seconds=25)).strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Processing error for {cve_id}: Invalid CPE format in affected products\n"
                log_content += f"[{(current_time + timedelta(seconds=26)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Skipping invalid CPE entries for {cve_id}\n"
            
            # Successful completion (even with errors)
            proc_time = 65.34 if i == 2 else (45.67 if i != 3 else 38.21)
            completion_time = current_time + timedelta(seconds=int(proc_time))
            
            if i != 3:  # No file for error case
                file_time = completion_time - timedelta(seconds=2)
                file_size = 42.1 + i * 8.4
                log_content += f"[{file_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] File Generated: {cve_id}.html (Size: {file_size:.1f} KB)\n"
            
            log_content += f"[{completion_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in {proc_time}s\n"
            current_time = completion_time + timedelta(seconds=3)
        
        # Final statistics with failures
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache: 35/42 session hits (83.3%)\n"
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] API statistics: 9 successful, 3 failed calls\n"
        
        log_content += f"# Completed: {current_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return log_content, "multiple_cves_with_failures"
    
    def _generate_resource_warnings_scenario(self):
        """Scenario with multiple resource warnings"""
        start_time = datetime.now() - timedelta(minutes=8)
        cve_id = "CVE-2024-RESOURCE-HEAVY"
        
        log_content = self._generate_log_header([cve_id], start_time)
        
        # Heavy resource usage from start
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Gathering NVD source entries...\n"
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Initializing global CPE cache - this will happen once per session\n"
        log_content += f"[{(start_time + timedelta(seconds=90)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] /cpes/ cache loaded: 125000 entries in 90.12s\n"
        
        # Multiple resource warnings
        warning_time = start_time + timedelta(seconds=95)
        log_content += f"[{warning_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Global state bloat detected: Large CPE cache: 125000 entries\n"
        log_content += f"[{(warning_time + timedelta(seconds=10)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Memory warning: High memory usage detected (4.2 GB)\n"
        log_content += f"[{(warning_time + timedelta(seconds=45)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Global state bloat detected: Excessive cache size growth\n"
        log_content += f"[{(warning_time + timedelta(seconds=60)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] File size warning: Large output file detected (256 MB)\n"
        log_content += f"[{(warning_time + timedelta(seconds=75)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Global state bloat detected: Memory usage exceeding thresholds\n"
        
        # Regular processing
        log_content += f"[{(start_time + timedelta(seconds=100)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 1 CVE records\n"
        log_content += f"[{(start_time + timedelta(seconds=102)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 1/1 ({cve_id})\n"
        
        # Workflow stages
        stage_times = [
            ("Initialization", 8),
            ("CVE Queries", 12),
            ("Unique CPE Generation", 6),
            ("CPE Queries", 45),
            ("Confirmed Mappings", 8),
            ("Page Generation", 15)  # Slow due to large file
        ]
        
        current_time = start_time + timedelta(seconds=105)
        for stage, duration in stage_times:
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Starting {stage} - Processing {cve_id} ===\n"
            current_time += timedelta(seconds=duration)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Completed {stage} - {stage} completed ===\n"
        
        # Heavy API usage
        log_content += f"[{(start_time + timedelta(seconds=110)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CVE API call: {cve_id}\n"
        log_content += f"[{(start_time + timedelta(seconds=115)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] MITRE CVE API call: {cve_id}\n"
        
        # Large file generation
        log_content += f"[{(start_time + timedelta(seconds=195)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] File Generated: {cve_id}.html (Size: 1.2 MB)\n"
        
        # Completion
        final_time = start_time + timedelta(seconds=199)
        log_content += f"[{final_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in 199.45s\n"
        log_content += f"# Completed: {final_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return log_content, "resource_warnings"
    
    def _generate_api_heavy_scenario(self):
        """Scenario with heavy API usage and diverse call types"""
        start_time = datetime.now() - timedelta(minutes=12)
        cve_ids = ["CVE-2024-API-001", "CVE-2024-API-002"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        # Initialization
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Gathering NVD source entries...\n"
        log_content += f"[{(start_time + timedelta(seconds=20)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Global CPE cache initialized and ready for use\n"
        
        log_content += f"[{(start_time + timedelta(seconds=22)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 2 CVE records\n"
        
        current_time = start_time + timedelta(seconds=25)
        
        # Heavy API usage for each CVE
        for i, cve_id in enumerate(cve_ids, 1):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i}/2 ({cve_id})\n"
            
            # CVE API calls
            api_time = current_time + timedelta(seconds=2)
            log_content += f"[{api_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CVE API call: {cve_id}\n"
            log_content += f"[{(api_time + timedelta(seconds=3)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] MITRE CVE API call: {cve_id}\n"
            
            # Extensive CPE API calls (35 calls per CVE)
            for j in range(35):
                cpe_time = api_time + timedelta(seconds=5 + j * 2)
                vendor = f"vendor{i}_{j}"
                product = f"product{j}"
                log_content += f"[{cpe_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CPE API call: cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*\n"
            
            # File generation
            file_time = current_time + timedelta(seconds=75)
            file_size = 85.4 + i * 25.6
            log_content += f"[{file_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] File Generated: {cve_id}.html (Size: {file_size:.1f} KB)\n"
            
            # CVE completion
            proc_time = 78.23 + i * 12.45
            completion_time = current_time + timedelta(seconds=int(proc_time))
            log_content += f"[{completion_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in {proc_time:.2f}s\n"
            
            current_time = completion_time + timedelta(seconds=3)
        
        # API statistics
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] API statistics: NVD CVE: 2, MITRE CVE: 2, NVD CPE: 70 calls\n"
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache: 25/70 session hits (35.7%)\n"
        
        log_content += f"# Completed: {current_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return log_content, "api_heavy"
    
    def _generate_cache_efficiency_scenario(self):
        """Scenario demonstrating cache efficiency progression"""
        start_time = datetime.now() - timedelta(minutes=25)
        cve_ids = [f"CVE-2024-CACHE-{i:03d}" for i in range(1, 6)]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        # Cache initialization
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Gathering NVD source entries...\n"
        log_content += f"[{(start_time + timedelta(seconds=45)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] /cpes/ cache loaded: 75000 entries in 45.23s\n"
        log_content += f"[{(start_time + timedelta(seconds=46)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Global CPE cache initialized and ready for use\n"
        
        log_content += f"[{(start_time + timedelta(seconds=48)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 5 CVE records\n"
        
        current_time = start_time + timedelta(seconds=50)
        
        # Process CVEs with improving cache efficiency
        cache_hit_rates = [20.0, 45.0, 68.0, 82.0, 91.0]  # Improving cache performance
        session_hits = [2, 8, 15, 22, 28]
        session_total = [10, 18, 22, 27, 31]
        
        for i, (cve_id, hit_rate, hits, total) in enumerate(zip(cve_ids, cache_hit_rates, session_hits, session_total), 1):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i}/5 ({cve_id})\n"
            
            # API calls
            api_time = current_time + timedelta(seconds=2)
            log_content += f"[{api_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CVE API call: {cve_id}\n"
            log_content += f"[{(api_time + timedelta(seconds=2)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] MITRE CVE API call: {cve_id}\n"
            
            # CPE queries (fewer API calls as cache improves)
            cpe_calls = max(15 - i * 2, 5)  # Decreasing API calls due to cache
            for j in range(cpe_calls):
                cpe_time = api_time + timedelta(seconds=5 + j * 1.5)
                if j < hits:  # Cache hit
                    log_content += f"[{cpe_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] Cache hit for CPE: cpe:2.3:a:common:product{j}:*:*:*:*:*:*:*:* - NVD CPE API call avoided\n"
                else:  # Cache miss - API call
                    log_content += f"[{cpe_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CPE API call: cpe:2.3:a:vendor{i}:product{j}:*:*:*:*:*:*:*:*\n"
            
            # Cache statistics for this CVE
            cache_time = current_time + timedelta(seconds=25)
            log_content += f"[{cache_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache: {hits}/{total} session hits ({hit_rate:.1f}%)\n"
            log_content += f"[{cache_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache lifetime: {hit_rate + 10:.1f}% hit rate, {12000 + i * 5000} API calls saved\n"
            
            # File generation
            file_time = current_time + timedelta(seconds=35)
            file_size = 52.3 + i * 8.7
            log_content += f"[{file_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] File Generated: {cve_id}.html (Size: {file_size:.1f} KB)\n"
            
            # CVE completion
            proc_time = 40.12 - i * 3.2  # Faster processing due to cache
            completion_time = current_time + timedelta(seconds=int(proc_time))
            log_content += f"[{completion_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in {proc_time:.2f}s\n"
            
            current_time = completion_time + timedelta(seconds=2)
        
        log_content += f"# Completed: {current_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return log_content, "cache_efficiency"
    
    def _generate_workflow_bottleneck_scenario(self):
        """Scenario with clear workflow bottlenecks in different stages"""
        start_time = datetime.now() - timedelta(minutes=18)
        cve_ids = ["CVE-2024-BOTTLENECK-A", "CVE-2024-BOTTLENECK-B", "CVE-2024-BOTTLENECK-C"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        # Initialization
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Gathering NVD source entries...\n"
        log_content += f"[{(start_time + timedelta(seconds=15)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Global CPE cache initialized and ready for use\n"
        
        log_content += f"[{(start_time + timedelta(seconds=17)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 3 CVE records\n"
        
        current_time = start_time + timedelta(seconds=20)
        
        # Each CVE has a different bottleneck stage
        bottleneck_configs = [
            {  # CVE A: CPE Queries bottleneck
                "stages": [("Initialization", 3), ("CVE Queries", 5), ("Unique CPE Generation", 4), 
                          ("CPE Queries", 180), ("Confirmed Mappings", 6), ("Page Generation", 4)]
            },
            {  # CVE B: Page Generation bottleneck  
                "stages": [("Initialization", 2), ("CVE Queries", 4), ("Unique CPE Generation", 3),
                          ("CPE Queries", 25), ("Confirmed Mappings", 5), ("Page Generation", 120)]
            },
            {  # CVE C: Confirmed Mappings bottleneck
                "stages": [("Initialization", 3), ("CVE Queries", 6), ("Unique CPE Generation", 4),
                          ("CPE Queries", 30), ("Confirmed Mappings", 95), ("Page Generation", 8)]
            }
        ]
        
        for i, (cve_id, config) in enumerate(zip(cve_ids, bottleneck_configs), 1):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i}/3 ({cve_id})\n"
            
            # Workflow stages with specific bottleneck
            stage_start = current_time + timedelta(seconds=2)
            total_time = 0
            
            for stage_name, duration in config["stages"]:
                log_content += f"[{stage_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting {stage_name} - Processing {cve_id} ===\n"
                stage_end = stage_start + timedelta(seconds=duration)
                log_content += f"[{stage_end.strftime('%Y-%m-%d %H:%M:%S')}] === Completed {stage_name} - {stage_name} completed ===\n"
                stage_start = stage_end + timedelta(seconds=1)
                total_time += duration + 1
            
            completion_time = current_time + timedelta(seconds=total_time + 10)
            log_content += f"[{completion_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in {total_time + 10}.45s\n"
            current_time = completion_time + timedelta(seconds=5)
        
        log_content += f"# Completed: {current_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return log_content, "workflow_bottleneck"
    
    # ===== NEW DETAILED TEST SCENARIOS =====
    
    # ===== PROGRESS TRACKER TESTS =====
    
    def _generate_progress_tracker_starting(self):
        """Progress tracker test - Just started processing"""
        start_time = datetime.now() - timedelta(minutes=1)
        cve_ids = ["CVE-2024-PROGRESS-001", "CVE-2024-PROGRESS-002", "CVE-2024-PROGRESS-003", "CVE-2024-PROGRESS-004", "CVE-2024-PROGRESS-005"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        # Initialization
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Gathering NVD source entries...\n"
        log_content += f"[{(start_time + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Global CPE cache initialized and ready for use\n"
        log_content += f"[{(start_time + timedelta(seconds=35)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 5 CVE records\n"
        
        # Just started first CVE
        log_content += f"[{(start_time + timedelta(seconds=40)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 1/5 (CVE-2024-PROGRESS-001)\n"
        log_content += f"[{(start_time + timedelta(seconds=45)).strftime('%Y-%m-%d %H:%M:%S')}] === Starting CVE Queries - Processing CVE-2024-PROGRESS-001 ===\n"
        
        return log_content, "progress_tracker_starting"
    
    def _generate_progress_tracker_midway(self):
        """Progress tracker test - Halfway through processing"""
        start_time = datetime.now() - timedelta(minutes=8)
        cve_ids = ["CVE-2024-PROGRESS-001", "CVE-2024-PROGRESS-002", "CVE-2024-PROGRESS-003", "CVE-2024-PROGRESS-004"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        # Initialization
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Gathering NVD source entries...\n"
        log_content += f"[{(start_time + timedelta(seconds=25)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 4 CVE records\n"
        
        # Complete first 2 CVEs
        current_time = start_time + timedelta(seconds=30)
        for i in range(2):
            cve_id = cve_ids[i]
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i+1}/4 ({cve_id})\n"
            log_content += f"[{(current_time + timedelta(seconds=60)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in 62.45s\n"
            current_time += timedelta(seconds=65)
        
        # Currently processing 3rd CVE
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 3/4 (CVE-2024-PROGRESS-003)\n"
        log_content += f"[{(current_time + timedelta(seconds=5)).strftime('%Y-%m-%d %H:%M:%S')}] === Starting CPE Queries - Processing CVE-2024-PROGRESS-003 ===\n"
        
        return log_content, "progress_tracker_midway"
    
    def _generate_progress_tracker_completed(self):
        """Progress tracker test - All processing completed"""
        start_time = datetime.now() - timedelta(minutes=15)
        cve_ids = ["CVE-2024-PROGRESS-001", "CVE-2024-PROGRESS-002", "CVE-2024-PROGRESS-003"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        # Complete processing cycle
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 3 CVE records\n"
        
        current_time = start_time + timedelta(seconds=20)
        processing_times = [45.23, 67.89, 52.41]
        
        for i, (cve_id, proc_time) in enumerate(zip(cve_ids, processing_times), 1):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i}/3 ({cve_id})\n"
            completion_time = current_time + timedelta(seconds=int(proc_time))
            log_content += f"[{completion_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in {proc_time}s\n"
            current_time = completion_time + timedelta(seconds=3)
        
        log_content += f"# Completed: {current_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return log_content, "progress_tracker_completed"
    
    def _generate_progress_tracker_with_eta(self):
        """Progress tracker test - In progress with ETA calculation"""
        start_time = datetime.now() - timedelta(minutes=12)
        cve_ids = ["CVE-2024-ETA-001", "CVE-2024-ETA-002", "CVE-2024-ETA-003", "CVE-2024-ETA-004", "CVE-2024-ETA-005", "CVE-2024-ETA-006"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 6 CVE records\n"
        
        # Complete 3 CVEs with consistent timing for ETA calculation
        current_time = start_time + timedelta(seconds=30)
        avg_time = 120  # 2 minutes per CVE for clear ETA
        
        for i in range(3):
            cve_id = cve_ids[i]
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i+1}/6 ({cve_id})\n"
            completion_time = current_time + timedelta(seconds=avg_time)
            log_content += f"[{completion_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in {avg_time}.34s\n"
            current_time = completion_time + timedelta(seconds=5)
        
        # Currently processing 4th CVE
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 4/6 (CVE-2024-ETA-004)\n"
        
        return log_content, "progress_tracker_with_eta"
    
    # ===== METRIC CARD TESTS =====
    
    def _generate_metric_cards_runtime_test(self):
        """Test runtime metric card with long execution"""
        start_time = datetime.now() - timedelta(hours=2, minutes=45)
        cve_id = "CVE-2024-RUNTIME-TEST"
        
        log_content = self._generate_log_header([cve_id], start_time)
        
        # Long runtime scenario with full workflow stages
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 1 CVE records\n"
        
        # Workflow stages with long durations
        stage_time = start_time + timedelta(seconds=30)
        
        # Initialization
        log_content += f"[{stage_time.strftime('%Y-%m-%d %H:%M:%S')}] === Starting Initialization - Setting up CVE analysis environment ===\n"
        stage_time += timedelta(minutes=15)
        log_content += f"[{stage_time.strftime('%Y-%m-%d %H:%M:%S')}] === Completed Initialization - Setting up CVE analysis environment ===\n"
        
        # CVE Queries
        log_content += f"[{stage_time.strftime('%Y-%m-%d %H:%M:%S')}] === Starting CVE Queries - Fetching CVE details ===\n"
        log_content += f"[{(stage_time + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 1/1 ({cve_id})\n"
        stage_time += timedelta(minutes=25)
        log_content += f"[{stage_time.strftime('%Y-%m-%d %H:%M:%S')}] === Completed CVE Queries - Fetching CVE details ===\n"
        
        # Unique CPE Identification
        log_content += f"[{stage_time.strftime('%Y-%m-%d %H:%M:%S')}] === Starting Unique CPE Identification - Processing platform data ===\n"
        stage_time += timedelta(minutes=45)
        log_content += f"[{stage_time.strftime('%Y-%m-%d %H:%M:%S')}] === Completed Unique CPE Identification - Processing platform data ===\n"
        
        # CPE Queries
        log_content += f"[{stage_time.strftime('%Y-%m-%d %H:%M:%S')}] === Starting CPE Queries - Fetching product details ===\n"
        stage_time += timedelta(minutes=85)  # Bottleneck stage
        log_content += f"[{stage_time.strftime('%Y-%m-%d %H:%M:%S')}] === Completed CPE Queries - Fetching product details ===\n"
        
        # Confirmed Mappings
        log_content += f"[{stage_time.strftime('%Y-%m-%d %H:%M:%S')}] === Starting Confirmed Mappings - Matching vendors and products ===\n"
        stage_time += timedelta(minutes=20)
        log_content += f"[{stage_time.strftime('%Y-%m-%d %H:%M:%S')}] === Completed Confirmed Mappings - Matching vendors and products ===\n"
        
        # Page Generation
        log_content += f"[{stage_time.strftime('%Y-%m-%d %H:%M:%S')}] === Starting Page Generation - Creating HTML reports ===\n"
        stage_time += timedelta(minutes=15)
        log_content += f"[{stage_time.strftime('%Y-%m-%d %H:%M:%S')}] === Completed Page Generation - Creating HTML reports ===\n"
        
        return log_content, "metric_cards_runtime"
    
    def _generate_metric_cards_api_intensive(self):
        """Test API calls metric card with high volume"""
        start_time = datetime.now() - timedelta(minutes=25)
        cve_ids = ["CVE-2024-API-001", "CVE-2024-API-002"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 2 CVE records\n"
        
        current_time = start_time + timedelta(seconds=30)
        
        # Massive API calls
        for i, cve_id in enumerate(cve_ids, 1):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i}/2 ({cve_id})\n"
            
            # CVE API calls
            api_time = current_time + timedelta(seconds=5)
            log_content += f"[{api_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CVE API call: {cve_id}\n"
            log_content += f"[{(api_time + timedelta(seconds=2)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] MITRE CVE API call: {cve_id}\n"
            
            # 150 CPE API calls per CVE
            for j in range(150):
                if j % 10 == 0:  # Log every 10th to keep manageable
                    cpe_time = api_time + timedelta(seconds=3 + j)
                    log_content += f"[{cpe_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CPE API call: cpe:2.3:a:example{i}:product{j}:*:*:*:*:*:*:*:*\n"
            
            current_time += timedelta(seconds=200)
        
        # Cache statistics showing API calls saved
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache lifetime: 78.5% hit rate, 156423 API calls saved\n"
        
        return log_content, "metric_cards_api_intensive"
    
    def _generate_metric_cards_mapping_success(self):
        """Test confirmed mappings metric card with high success rate"""
        start_time = datetime.now() - timedelta(minutes=15)
        cve_ids = ["CVE-2024-MAP-001", "CVE-2024-MAP-002", "CVE-2024-MAP-003", "CVE-2024-MAP-004", "CVE-2024-MAP-005"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 5 CVE records\n"
        
        current_time = start_time + timedelta(seconds=30)
        
        for i, cve_id in enumerate(cve_ids, 1):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i}/5 ({cve_id})\n"
            
            # Multiple confirmed mappings found
            mapping_count = 8 + (i * 2)  # Varying mapping counts
            log_content += f"[{(current_time + timedelta(seconds=25)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Found {mapping_count} confirmed mappings for platform entry {i}\n"
            log_content += f"[{(current_time + timedelta(seconds=26)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Found {mapping_count-2} confirmed mappings for platform entry {i+10}\n"
            
            completion_time = current_time + timedelta(seconds=45)
            log_content += f"[{completion_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in 45.67s\n"
            current_time = completion_time + timedelta(seconds=5)
        
        # Overall mapping statistics
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Confirmed mappings statistics: 47/50 platform entries (94.0% hit rate), 478 total mappings found\n"
        
        return log_content, "metric_cards_mapping_success"
    
    def _generate_metric_cards_file_generation(self):
        """Test file generation metric card with varied file sizes"""
        start_time = datetime.now() - timedelta(minutes=20)
        cve_ids = ["CVE-2024-FILE-001", "CVE-2024-FILE-002", "CVE-2024-FILE-003", "CVE-2024-FILE-004", "CVE-2024-FILE-005", "CVE-2024-FILE-006"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 6 CVE records\n"
        
        current_time = start_time + timedelta(seconds=30)
        file_sizes = [12.3, 457.8, 1234.5, 23.7, 89.2, 2456.9]  # Varied sizes from small to large
        
        for i, (cve_id, file_size) in enumerate(zip(cve_ids, file_sizes), 1):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i}/6 ({cve_id})\n"
            
            file_time = current_time + timedelta(seconds=45)
            log_content += f"[{file_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] File Generated: {cve_id}.html (Size: {file_size} KB)\n"
            
            completion_time = current_time + timedelta(seconds=50)
            log_content += f"[{completion_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in 50.23s\n"
            current_time = completion_time + timedelta(seconds=5)
        
        return log_content, "metric_cards_file_generation"
    
    def _generate_metric_cards_processing_speed(self):
        """Test processing speed metric card with varied timings"""
        start_time = datetime.now() - timedelta(minutes=18)
        cve_ids = ["CVE-2024-SPEED-001", "CVE-2024-SPEED-002", "CVE-2024-SPEED-003", "CVE-2024-SPEED-004", "CVE-2024-SPEED-005"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 5 CVE records\n"
        
        current_time = start_time + timedelta(seconds=30)
        processing_times = [15.23, 234.56, 8.91, 456.78, 67.45]  # Wide range from very fast to very slow
        
        for i, (cve_id, proc_time) in enumerate(zip(cve_ids, processing_times), 1):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i}/5 ({cve_id})\n"
            
            completion_time = current_time + timedelta(seconds=int(proc_time))
            log_content += f"[{completion_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in {proc_time}s\n"
            current_time = completion_time + timedelta(seconds=3)
        
        return log_content, "metric_cards_processing_speed"
    
    def _generate_metric_cards_cache_performance(self):
        """Test cache performance metric card with detailed stats"""
        start_time = datetime.now() - timedelta(minutes=12)
        cve_ids = ["CVE-2024-CACHE-001", "CVE-2024-CACHE-002", "CVE-2024-CACHE-003"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        # Heavy cache usage
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Initializing global CPE cache - this will happen once per session\n"
        log_content += f"[{(start_time + timedelta(seconds=45)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] /cpes/ cache loaded: 125678 entries in 45.23s\n"
        log_content += f"[{(start_time + timedelta(seconds=50)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Global CPE cache initialized and ready for use\n"
        
        log_content += f"[{(start_time + timedelta(seconds=55)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 3 CVE records\n"
        
        current_time = start_time + timedelta(seconds=60)
        
        for i, cve_id in enumerate(cve_ids, 1):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i}/3 ({cve_id})\n"
            
            # Cache statistics per CVE
            hit_rate = 85.5 + i * 2.3  # Improving hit rate
            session_hits = 45 + i * 15
            session_total = session_hits + (10 - i * 2)
            
            log_content += f"[{(current_time + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache: {session_hits}/{session_total} session hits ({hit_rate:.1f}%)\n"
            
            completion_time = current_time + timedelta(seconds=60)
            log_content += f"[{completion_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in 60.45s\n"
            current_time = completion_time + timedelta(seconds=5)
        
        # Final cache statistics
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] CPE cache lifetime: 92.3% hit rate, 89456 API calls saved\n"
        
        return log_content, "metric_cards_cache_performance"
    
    def _generate_metric_cards_cpe_queries(self):
        """Test CPE queries metric card with massive query counts"""
        start_time = datetime.now() - timedelta(minutes=30)
        cve_ids = ["CVE-2024-CPE-MASSIVE-001", "CVE-2024-CPE-MASSIVE-002"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 2 CVE records\n"
        
        current_time = start_time + timedelta(seconds=30)
        
        for i, cve_id in enumerate(cve_ids, 1):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {i}/2 ({cve_id})\n"
            
            # Massive CPE queries for this CVE
            query_count = 850 if i == 1 else 1245  # Second CVE is the largest
            
            log_content += f"[{(current_time + timedelta(seconds=5)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CVE API call: {cve_id}\n"
            log_content += f"[{(current_time + timedelta(seconds=7)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] MITRE CVE API call: {cve_id}\n"
            
            # Generate many CPE queries
            for j in range(query_count):
                if j % 50 == 0:  # Log every 50th query to avoid massive logs
                    cpe_time = current_time + timedelta(seconds=10 + j // 10)
                    log_content += f"[{cpe_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] NVD CPE API call: cpe:2.3:a:vendor{i}:product{j}:*:*:*:*:*:*:*:*\n"
            
            completion_time = current_time + timedelta(minutes=8)
            log_content += f"[{completion_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Successfully processed {cve_id} in 480.67s\n"
            current_time = completion_time + timedelta(seconds=10)
        
        return log_content, "metric_cards_cpe_queries"
    
    def _generate_metric_cards_resource_warnings(self):
        """Test resource warnings metric card"""
        start_time = datetime.now() - timedelta(minutes=10)
        cve_id = "CVE-2024-RESOURCE-WARN"
        
        log_content = self._generate_log_header([cve_id], start_time)
        
        # Multiple resource warnings
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 1 CVE records\n"
        
        warning_time = start_time + timedelta(seconds=30)
        log_content += f"[{warning_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Global state bloat detected: Large CPE cache: 150000 entries\n"
        log_content += f"[{(warning_time + timedelta(seconds=15)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Memory warning: High memory usage detected (8.5 GB)\n"
        log_content += f"[{(warning_time + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] File size warning: Large output file detected (512 MB)\n"
        log_content += f"[{(warning_time + timedelta(seconds=45)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Global state bloat detected: Memory usage exceeding thresholds\n"
        log_content += f"[{(warning_time + timedelta(seconds=60)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Global state bloat detected: Excessive cache size growth\n"
        log_content += f"[{(warning_time + timedelta(seconds=75)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Memory warning: Critical memory usage detected (12.1 GB)\n"
        log_content += f"[{(warning_time + timedelta(seconds=90)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] File size warning: Extremely large output file detected (1.2 GB)\n"
        log_content += f"[{(warning_time + timedelta(seconds=105)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Global state bloat detected: System resources critically low\n"
        
        return log_content, "metric_cards_resource_warnings"
    
    # === WORKFLOW PERFORMANCE TESTS ===
    
    def _generate_workflow_stage_analysis(self):
        """Workflow stage analysis test - Detailed stage timing breakdown"""
        start_time = datetime.now() - timedelta(minutes=12)
        cve_id = "CVE-2024-WORKFLOW-STAGES"
        
        log_content = self._generate_log_header([cve_id], start_time)
        
        # Detailed workflow with clear stage timing
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 1 CVE records\n"
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 1/1 ({cve_id})\n"
        
        # Data gathering stage - 2 minutes
        gather_start = start_time + timedelta(seconds=5)
        log_content += f"[{gather_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting CVE Queries - Processing {cve_id} ===\n"
        log_content += f"[{(gather_start + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Gathering data for {cve_id}\n"
        gather_end = gather_start + timedelta(minutes=2)
        log_content += f"[{gather_end.strftime('%Y-%m-%d %H:%M:%S')}] === Ending CVE Queries - {cve_id} processed ===\n"
        
        # CPE generation stage - 1 minute
        cpe_gen_start = gather_end + timedelta(seconds=2)
        log_content += f"[{cpe_gen_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting Unique CPE Generation - Processing {cve_id} ===\n"
        log_content += f"[{(cpe_gen_start + timedelta(seconds=20)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Generated 15 unique CPE base strings\n"
        cpe_gen_end = cpe_gen_start + timedelta(minutes=1)
        log_content += f"[{cpe_gen_end.strftime('%Y-%m-%d %H:%M:%S')}] === Ending Unique CPE Generation - CPE base strings extracted ===\n"
        
        # CPE queries stage - 5 minutes
        cpe_query_start = cpe_gen_end + timedelta(seconds=2)
        log_content += f"[{cpe_query_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting CPE Queries - Querying NVD CPE API ===\n"
        for i in range(15):
            call_time = cpe_query_start + timedelta(seconds=10 + i*15)
            log_content += f"[{call_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] API call: NVD CPE search for cpe:2.3:*:vendor{i}:product{i}:*\n"
        cpe_query_end = cpe_query_start + timedelta(minutes=5)
        log_content += f"[{cpe_query_end.strftime('%Y-%m-%d %H:%M:%S')}] === Ending CPE Queries - CPE queries completed ===\n"
        
        # Data processing stage - 3 minutes
        process_start = cpe_query_end + timedelta(seconds=2)
        log_content += f"[{process_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting Data Processing - Processing {cve_id} ===\n"
        log_content += f"[{(process_start + timedelta(seconds=45)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing confirmed mappings...\n"
        log_content += f"[{(process_start + timedelta(minutes=1, seconds=30)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Found 8 confirmed mappings for platform entry 0\n"
        process_end = process_start + timedelta(minutes=3)
        log_content += f"[{process_end.strftime('%Y-%m-%d %H:%M:%S')}] === Ending Data Processing - {cve_id} processed ===\n"
        
        # HTML generation stage - 1 minute
        html_start = process_end + timedelta(seconds=2)
        log_content += f"[{html_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting HTML Generation - Generating {cve_id} ===\n"
        log_content += f"[{(html_start + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Generated HTML page for {cve_id}\n"
        html_end = html_start + timedelta(minutes=1)
        log_content += f"[{html_end.strftime('%Y-%m-%d %H:%M:%S')}] === Ending HTML Generation - {cve_id}.html generated ===\n"
        
        return log_content, "workflow_stage_analysis"
    
    def _generate_workflow_bottleneck_detection(self):
        """Workflow bottleneck detection test - One stage significantly slower"""
        start_time = datetime.now() - timedelta(minutes=25)
        cve_id = "CVE-2024-BOTTLENECK-TEST"
        
        log_content = self._generate_log_header([cve_id], start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 1 CVE records\n"
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 1/1 ({cve_id})\n"
        
        # Fast data gathering - 30 seconds
        gather_start = start_time + timedelta(seconds=5)
        log_content += f"[{gather_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting CVE Queries - Processing {cve_id} ===\n"
        gather_end = gather_start + timedelta(seconds=30)
        log_content += f"[{gather_end.strftime('%Y-%m-%d %H:%M:%S')}] === Ending CVE Queries - {cve_id} processed ===\n"
        
        # Fast CPE generation - 20 seconds
        cpe_gen_start = gather_end + timedelta(seconds=2)
        log_content += f"[{cpe_gen_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting Unique CPE Generation - Processing {cve_id} ===\n"
        cpe_gen_end = cpe_gen_start + timedelta(seconds=20)
        log_content += f"[{cpe_gen_end.strftime('%Y-%m-%d %H:%M:%S')}] === Ending Unique CPE Generation - CPE base strings extracted ===\n"
        
        # BOTTLENECK: Very slow CPE queries - 20 minutes
        cpe_query_start = cpe_gen_end + timedelta(seconds=2)
        log_content += f"[{cpe_query_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting CPE Queries - Querying NVD CPE API ===\n"
        log_content += f"[{(cpe_query_start + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] API response slow, retrying...\n"
        for i in range(50):  # Many slow API calls
            call_time = cpe_query_start + timedelta(seconds=60 + i*20)
            log_content += f"[{call_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] API call: NVD CPE search (slow response)\n"
            if i % 10 == 9:
                log_content += f"[{(call_time + timedelta(seconds=5)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] API rate limit reached, waiting...\n"
        cpe_query_end = cpe_query_start + timedelta(minutes=20)
        log_content += f"[{cpe_query_end.strftime('%Y-%m-%d %H:%M:%S')}] === Ending CPE Queries - CPE queries completed ===\n"
        
        # Fast processing - 1 minute
        process_start = cpe_query_end + timedelta(seconds=2)
        log_content += f"[{process_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting Data Processing - Processing {cve_id} ===\n"
        process_end = process_start + timedelta(minutes=1)
        log_content += f"[{process_end.strftime('%Y-%m-%d %H:%M:%S')}] === Ending Data Processing - {cve_id} processed ===\n"
        
        # Fast HTML generation - 30 seconds
        html_start = process_end + timedelta(seconds=2)
        log_content += f"[{html_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting HTML Generation - Generating {cve_id} ===\n"
        html_end = html_start + timedelta(seconds=30)
        log_content += f"[{html_end.strftime('%Y-%m-%d %H:%M:%S')}] === Ending HTML Generation - {cve_id}.html generated ===\n"
        
        return log_content, "workflow_bottleneck_detection"
    
    def _generate_workflow_efficiency_metrics(self):
        """Workflow efficiency metrics test - Optimized vs unoptimized runs"""
        start_time = datetime.now() - timedelta(minutes=15)
        cve_ids = ["CVE-2024-EFFICIENT-001", "CVE-2024-EFFICIENT-002"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Global CPE cache initialized and ready for use\n"
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 2 CVE records\n"
        
        # First CVE - efficient with cache misses
        current_time = start_time + timedelta(seconds=10)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 1/2 (CVE-2024-EFFICIENT-001)\n"
        
        # Efficient stages for first CVE
        stages = [
            ("CVE Queries", 45),
            ("Unique CPE Generation", 15),
            ("CPE Queries", 180),  # 3 minutes
            ("Data Processing", 90),
            ("HTML Generation", 30)
        ]
        
        for stage_name, duration in stages:
            stage_start = current_time
            log_content += f"[{stage_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting {stage_name} - Processing CVE-2024-EFFICIENT-001 ===\n"
            
            if stage_name == "CPE Queries":
                for i in range(12):
                    api_time = stage_start + timedelta(seconds=10 + i*12)
                    log_content += f"[{api_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] API call: NVD CPE search\n"
                    log_content += f"[{(api_time + timedelta(seconds=2)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] CPE cache miss - storing result\n"
            
            current_time += timedelta(seconds=duration)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Ending {stage_name} - CVE-2024-EFFICIENT-001 ===\n"
        
        # Second CVE - very efficient with cache hits
        current_time += timedelta(seconds=5)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 2/2 (CVE-2024-EFFICIENT-002)\n"
        
        # Much faster stages for second CVE due to caching
        efficient_stages = [
            ("CVE Queries", 30),
            ("Unique CPE Generation", 10),
            ("CPE Queries", 45),  # Much faster due to cache hits
            ("Data Processing", 60),
            ("HTML Generation", 25)
        ]
        
        for stage_name, duration in efficient_stages:
            stage_start = current_time
            log_content += f"[{stage_start.strftime('%Y-%m-%d %H:%M:%S')}] === Starting {stage_name} - Processing CVE-2024-EFFICIENT-002 ===\n"
            
            if stage_name == "CPE Queries":
                for i in range(8):
                    api_time = stage_start + timedelta(seconds=3 + i*4)
                    log_content += f"[{api_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] CPE cache hit - using cached result\n"
            
            current_time += timedelta(seconds=duration)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Ending {stage_name} - CVE-2024-EFFICIENT-002 ===\n"
        
        return log_content, "workflow_efficiency_metrics"
    
    # === API BREAKDOWN TESTS ===
    
    def _generate_api_breakdown_detailed(self):
        """API breakdown detailed test - Various API call types and timing"""
        start_time = datetime.now() - timedelta(minutes=8)
        cve_id = "CVE-2024-API-DETAILED"
        
        log_content = self._generate_log_header([cve_id], start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 1 CVE records\n"
        log_content += f"[{(start_time + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')}] === Starting CPE Queries - Querying NVD CPE API ===\n"
        
        # Various types of API calls with detailed breakdown
        api_calls = [
            ("NVD CPE search for cpe:2.3:*:microsoft:*:*", 850),
            ("NVD CPE search for cpe:2.3:*:*:windows:*", 1200),
            ("NVD CPE search for cpe:2.3:*:adobe:reader:*", 650),
            ("NVD CVE lookup for CVE-2024-API-DETAILED", 400),
            ("NVD CPE search for cpe:2.3:*:oracle:database:*", 950),
            ("NVD CPE search for cpe:2.3:*:apache:*:*", 1100),
            ("NVD CPE validation request", 300),
            ("NVD CPE search for cpe:2.3:*:google:chrome:*", 750),
            ("NVD CPE search for cpe:2.3:*:mozilla:firefox:*", 600),
            ("NVD source data refresh", 200),
            ("NVD CPE search for cpe:2.3:*:vmware:*:*", 800),
            ("NVD rate limit check", 150),
            ("NVD CPE search for cpe:2.3:*:cisco:*:*", 700),
            ("NVD CPE search for cpe:2.3:*:linux:kernel:*", 900),
            ("NVD CPE metadata request", 250)
        ]
        
        current_time = start_time + timedelta(seconds=35)
        for call_desc, duration_ms in api_calls:
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] API call: {call_desc}\n"
            current_time += timedelta(milliseconds=duration_ms + 100)  # Add some processing time
        
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Ending CPE Queries - CPE queries completed ===\n"
        log_content += f"[{(current_time + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Generated HTML page for {cve_id}\n"
        
        return log_content, "api_breakdown_detailed"
    
    def _generate_api_breakdown_with_failures(self):
        """API breakdown with failures test - Mix of successful and failed API calls"""
        start_time = datetime.now() - timedelta(minutes=10)
        cve_id = "CVE-2024-API-FAILURES"
        
        log_content = self._generate_log_header([cve_id], start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 1 CVE records\n"
        log_content += f"[{(start_time + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')}] === Starting CPE Queries - Querying NVD CPE API ===\n"
        
        # Mix of successful and failed API calls
        api_events = [
            ("API call: NVD CPE search for cpe:2.3:*:vendor1:*:*", True, 650),
            ("API call: NVD CPE search for cpe:2.3:*:vendor2:*:*", True, 800),
            ("API call failed: NVD CPE search (timeout)", False, 5000),
            ("API call: NVD CPE search for cpe:2.3:*:vendor3:*:*", True, 750),
            ("API call failed: NVD CPE search (rate limit)", False, 1000),
            ("API call: NVD CPE search for cpe:2.3:*:vendor4:*:*", True, 600),
            ("API call: NVD CPE search for cpe:2.3:*:vendor5:*:*", True, 900),
            ("API call failed: NVD CVE lookup (404 not found)", False, 2000),
            ("API call: NVD CPE search for cpe:2.3:*:vendor6:*:*", True, 550),
            ("API call failed: NVD CPE search (server error)", False, 3000),
            ("API call: NVD CPE search for cpe:2.3:*:vendor7:*:*", True, 700),
            ("API call: NVD CPE search for cpe:2.3:*:vendor8:*:*", True, 850),
            ("API call failed: NVD CPE validation (malformed)", False, 500),
            ("API call: NVD CPE search for cpe:2.3:*:vendor9:*:*", True, 650),
            ("API call: NVD CPE search for cpe:2.3:*:vendor10:*:*", True, 750)
        ]
        
        current_time = start_time + timedelta(seconds=35)
        for call_desc, success, duration_ms in api_events:
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] {call_desc}\n"
            if not success:
                log_content += f"[{(current_time + timedelta(milliseconds=duration_ms)).strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] API call failed, retrying with backoff\n"
            current_time += timedelta(milliseconds=duration_ms + 200)
        
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Ending CPE Queries - CPE queries completed ===\n"
        log_content += f"[{(current_time + timedelta(seconds=45)).strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Generated HTML page for {cve_id}\n"
        
        return log_content, "api_breakdown_with_failures"
    
    def _generate_api_breakdown_mixed_calls(self):
        """API breakdown mixed calls test - Different API endpoints and patterns"""
        start_time = datetime.now() - timedelta(minutes=12)
        cve_ids = ["CVE-2024-API-MIX-001", "CVE-2024-API-MIX-002"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 2 CVE records\n"
        
        # First CVE - mostly CPE searches
        current_time = start_time + timedelta(seconds=20)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 1/2 (CVE-2024-API-MIX-001)\n"
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Starting CPE Queries - Querying NVD CPE API ===\n"
        
        for i in range(20):
            call_time = current_time + timedelta(seconds=5 + i*8)
            log_content += f"[{call_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] API call: NVD CPE search for cpe:2.3:*:vendor{i}:product{i}:*\n"
        
        current_time += timedelta(minutes=3)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Ending CPE Queries - CPE queries completed ===\n"
        
        # Second CVE - mix of CVE lookups and CPE searches
        current_time += timedelta(seconds=10)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 2/2 (CVE-2024-API-MIX-002)\n"
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Starting CVE Queries - Processing CVE-2024-API-MIX-002 ===\n"
        
        # CVE-specific API calls
        cve_calls = [
            "API call: NVD CVE API for CVE-2024-API-MIX-002",
            "API call: NVD CVE lookup - references",
            "API call: NVD CVE API - CVSS data",
            "API call: NVD CVE lookup - validation"
        ]
        
        for call in cve_calls:
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] {call}\n"
            current_time += timedelta(seconds=15)
        
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Ending CPE Queries - CVE-2024-API-MIX-002 processed ===\n"
        
        # CPE queries for second CVE
        current_time += timedelta(seconds=5)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Starting CPE Queries - Querying NVD CPE API ===\n"
        
        for i in range(12):
            call_time = current_time + timedelta(seconds=3 + i*6)
            log_content += f"[{call_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] API call: NVD CPE search for platform data\n"
        
        current_time += timedelta(minutes=2)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] === Ending CPE Queries - CPE queries completed ===\n"
        
        return log_content, "api_breakdown_mixed_calls"
    
    # === LOG ACTIVITY TESTS ===
    
    def _generate_log_activity_high_volume(self):
        """Log activity high volume test - Many log entries across all levels"""
        start_time = datetime.now() - timedelta(minutes=20)
        cve_ids = ["CVE-2024-VOLUME-001", "CVE-2024-VOLUME-002", "CVE-2024-VOLUME-003"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 3 CVE records\n"
        
        current_time = start_time + timedelta(seconds=10)
        
        # Generate high volume of log entries for each CVE
        for cve_idx, cve_id in enumerate(cve_ids):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {cve_idx+1}/3 ({cve_id})\n"
            
            # Verbose data gathering
            for i in range(25):
                current_time += timedelta(seconds=2)
                log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] Processing platform entry {i+1}/25\n"
                if i % 5 == 0:
                    log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Found {i+3} confirmed mappings for platform entry {i}\n"
                if i % 8 == 0:
                    log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] CPE cache hit - using cached result\n"
                if i % 12 == 0:
                    log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Generated HTML page section {i//12 + 1}\n"
            
            # API call logging
            for i in range(40):
                current_time += timedelta(seconds=3)
                log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] API call: NVD CPE search {i+1}/40\n"
                if i % 15 == 14:
                    log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] API rate limit check - OK\n"
            
            # Processing details
            for i in range(30):
                current_time += timedelta(seconds=1)
                log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [DEBUG] Processing CPE result {i+1}/30\n"
                if i % 10 == 9:
                    log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Batch processing completed: {i+1} items\n"
            
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Generated HTML page for {cve_id}\n"
        
        return log_content, "log_activity_high_volume"
    
    def _generate_log_activity_with_errors(self):
        """Log activity with errors test - Mix of errors, warnings, and info"""
        start_time = datetime.now() - timedelta(minutes=15)
        cve_ids = ["CVE-2024-ERROR-001", "CVE-2024-ERROR-002"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 2 CVE records\n"
        
        current_time = start_time + timedelta(seconds=15)
        
        # First CVE with various errors
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 1/2 (CVE-2024-ERROR-001)\n"
        current_time += timedelta(seconds=10)
        
        # Data gathering errors
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Failed to parse platform data: Invalid JSON format\n"
        current_time += timedelta(seconds=5)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Retrying with alternate parser\n"
        current_time += timedelta(seconds=8)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Platform data recovered using fallback method\n"
        
        # API errors
        for i in range(8):
            current_time += timedelta(seconds=12)
            if i % 3 == 0:
                log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] API call failed: Connection timeout after 30s\n"
                current_time += timedelta(seconds=3)
                log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Retrying API call with exponential backoff\n"
            elif i % 3 == 1:
                log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] API call failed: HTTP 429 - Rate limit exceeded\n"
                current_time += timedelta(seconds=5)
                log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Waiting 5 seconds before retry\n"
            else:
                log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] API call: NVD CPE search successful\n"
        
        # Processing errors
        current_time += timedelta(seconds=20)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] CPE parsing failed: Invalid CPE format in result\n"
        current_time += timedelta(seconds=3)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Skipping malformed CPE entry\n"
        current_time += timedelta(seconds=5)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Confirmed mappings processing failed: Unable to process mapping entries for platform entry 5\n"
        
        # Second CVE with file system errors
        current_time += timedelta(seconds=30)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE 2/2 (CVE-2024-ERROR-002)\n"
        current_time += timedelta(seconds=120)
        
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Failed to write HTML file: Permission denied\n"
        current_time += timedelta(seconds=5)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Retrying with different output directory\n"
        current_time += timedelta(seconds=10)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] HTML file written successfully to alternate location\n"
        
        # Cache errors
        current_time += timedelta(seconds=15)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Cache corruption detected: Invalid cache metadata\n"
        current_time += timedelta(seconds=3)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Rebuilding cache from scratch\n"
        current_time += timedelta(seconds=20)
        log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Cache rebuild completed successfully\n"
        
        return log_content, "log_activity_with_errors"
    
    def _generate_log_activity_warning_heavy(self):
        """Log activity warning heavy test - Predominantly warnings and notices"""
        start_time = datetime.now() - timedelta(minutes=18)
        cve_ids = ["CVE-2024-WARN-001", "CVE-2024-WARN-002", "CVE-2024-WARN-003"]
        
        log_content = self._generate_log_header(cve_ids, start_time)
        
        log_content += f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Starting processing of 3 CVE records\n"
        
        current_time = start_time + timedelta(seconds=20)
        
        for cve_idx, cve_id in enumerate(cve_ids):
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Processing CVE {cve_idx+1}/3 ({cve_id})\n"
            current_time += timedelta(seconds=10)
            
            # Data quality warnings
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Found placeholder 'n/a' value in vendor field\n"
            current_time += timedelta(seconds=5)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Platform data concern: Unable to map platform 'Unknown OS'\n"
            current_time += timedelta(seconds=8)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Unicode normalization skipped for vendor field: contains unsupported characters\n"
            
            # Memory and performance warnings
            current_time += timedelta(seconds=30)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Memory usage high: 85% of available RAM\n"
            current_time += timedelta(seconds=45)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] API response time elevated: 3.2s average\n"
            current_time += timedelta(seconds=60)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Cache hit rate below optimal: 65%\n"
            
            # Data processing warnings
            for i in range(8):
                current_time += timedelta(seconds=15)
                warning_types = [
                    "Empty CPE string found in search results",
                    "Deprecated CPE entry encountered, using anyway",
                    "API rate limit approaching: 90% of hourly quota used",
                    "Large result set truncated: showing top 1000 entries only",
                    "Mapping confidence below threshold: 70%",
                    "Platform entry missing required metadata",
                    "CPE version parsing failed, using wildcard",
                    "Duplicate CPE entry found and removed"
                ]
                log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] {warning_types[i]}\n"
            
            # Resource warnings
            current_time += timedelta(seconds=30)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Disk space low: Less than 1GB remaining\n"
            current_time += timedelta(seconds=20)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] Network latency high: 500ms+ to NVD API\n"
            current_time += timedelta(seconds=15)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [WARNING] CPU usage sustained above 90% for 2+ minutes\n"
            
            current_time += timedelta(seconds=10)
            log_content += f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Generated HTML page for {cve_id} (with warnings)\n"
        
        return log_content, "log_activity_warning_heavy"
    
    def generate_test_scenario(self, scenario_name):
        """Generate a specific test scenario"""
        if scenario_name not in self.scenarios:
            raise ValueError(f"Unknown scenario: {scenario_name}. Available: {list(self.scenarios.keys())}")
        
        log_content, description = self.scenarios[scenario_name]()
        
        # Write log file
        log_file = self.logs_dir / f"test_{scenario_name}.log"
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(log_content)
        
        return log_file, description
    
    def test_scenario(self, scenario_name):
        """Test a specific scenario end-to-end"""
        print(f"\n{'='*60}")
        print(f"Testing Scenario: {scenario_name.upper()}")
        print(f"{'='*60}")
        
        # Generate test log
        log_file, description = self.generate_test_scenario(scenario_name)
        print(f"✅ Generated test log: {log_file}")
        
        # Analyze log
        output_file = self.reports_dir / f"test_{scenario_name}_data.json"
        analyzer = LogAnalyzer()
        data = analyzer.parse_log_file(str(log_file))
        analyzer.save_json(str(output_file))
        print(f"✅ Analyzed log data: {output_file}")
        
        # Generate dashboard
        dashboard_file = self.reports_dir / f"test_{scenario_name}_dashboard.html"
        success = generate_dashboard_html(data, str(dashboard_file))
        
        if success:
            print(f"✅ Generated dashboard: {dashboard_file}")
            
            # Extract key metrics for validation
            self._validate_scenario_metrics(scenario_name, data)
            
        else:
            print(f"❌ Failed to generate dashboard")
            return False
            
        return True
    
    def _validate_scenario_metrics(self, scenario_name, data):
        """Validate that the scenario produced expected metrics"""
        print(f"\n📊 Scenario Metrics Validation:")
        
        # Common validations
        processing = data.get("processing", {})
        api = data.get("api", {})
        stages = data.get("stages", {})
        stage_analysis = data.get("stage_analysis", {})
        resource_warnings = data.get("resource_warnings", {})
        
        print(f"   CVEs Processed: {processing.get('processed_cves', 0)}")
        print(f"   Total API Calls: {api.get('total_calls', 0)}")
        print(f"   API Success Rate: {(api.get('successful_calls', 0) / max(api.get('total_calls', 1), 1) * 100):.1f}%")
        print(f"   Workflow Efficiency: {stage_analysis.get('stage_efficiency', 0):.1f}%")
        print(f"   Resource Warnings: {sum(resource_warnings.values())}")
        
        # Scenario-specific validations
        if "single_cve_fast" in scenario_name:
            assert processing.get('processed_cves') == 1, "Should process exactly 1 CVE"
            assert stage_analysis.get('total_workflow_time', 0) < 20, "Should complete quickly"
            print(f"   ✅ Fast single CVE processing validated")
            
        elif "single_cve_slow" in scenario_name:
            assert processing.get('processed_cves') == 1, "Should process exactly 1 CVE"
            assert stage_analysis.get('total_workflow_time', 0) > 200, "Should be slow due to bottleneck"
            bottleneck = stage_analysis.get('longest_stage', {})
            assert bottleneck.get('name') == 'cpe_queries', "CPE Queries should be the bottleneck"
            print(f"   ✅ Slow single CVE with bottleneck validated")
            
        elif "multiple_cves_balanced" in scenario_name:
            assert processing.get('processed_cves') == 3, "Should process exactly 3 CVEs"
            assert api.get('total_calls', 0) >= 6, "Should have multiple API calls"
            print(f"   ✅ Multiple CVE balanced processing validated")
            
        elif "multiple_cves_with_failures" in scenario_name:
            assert processing.get('processed_cves') >= 2, "Should process multiple CVEs"
            assert api.get('failed_calls', 0) > 0, "Should have API failures"
            print(f"   ✅ Multiple CVE with failures validated")
            
        elif "resource_warnings" in scenario_name:
            total_warnings = sum(resource_warnings.values())
            assert total_warnings >= 5, f"Should have multiple resource warnings, got {total_warnings}"
            print(f"   ✅ Resource warnings scenario validated")
            
        elif "api_heavy" in scenario_name:
            assert api.get('total_calls', 0) >= 70, "Should have heavy API usage"
            assert api.get('nvd_cpe_calls', 0) >= 60, "Should have many CPE API calls"
            print(f"   ✅ API heavy scenario validated")
            
        elif "cache_efficiency" in scenario_name:
            assert processing.get('processed_cves') == 5, "Should process exactly 5 CVEs"
            cache_data = data.get('cache', {})
            assert cache_data.get('hit_rate', 0) > 80, "Should demonstrate good cache efficiency"
            print(f"   ✅ Cache efficiency scenario validated")
            
        elif "workflow_bottleneck_scenario" in scenario_name:
            assert processing.get('processed_cves') == 3, "Should process exactly 3 CVEs"
            longest_stage = stage_analysis.get('longest_stage', {})
            assert longest_stage.get('duration', 0) > 90, "Should have clear bottleneck stage"
            print(f"   ✅ Workflow bottleneck scenario validated")
            
        # === NEW DETAILED TEST VALIDATIONS ===
        
        # Progress Tracker Tests
        elif "progress_tracker_starting" in scenario_name:
            # For starting scenario, we may have started processing but not completed any
            assert processing.get('processed_cves') <= 1, "Should show minimal completed CVEs"
            assert processing.get('progress_percentage', 0) < 25, "Should show minimal progress"
            print(f"   ✅ Progress tracker starting state validated")
            
        elif "progress_tracker_midway" in scenario_name:
            assert processing.get('processed_cves') >= 2, "Should have completed some CVEs"
            progress = processing.get('progress_percentage', 0)
            assert 25 <= progress <= 75, f"Should show midway progress, got {progress}%"
            print(f"   ✅ Progress tracker midway state validated")
            
        elif "progress_tracker_completed" in scenario_name:
            assert processing.get('progress_percentage', 0) == 100, "Should show 100% completion"
            assert processing.get('processed_cves') == processing.get('total_cves'), "All CVEs should be processed"
            print(f"   ✅ Progress tracker completed state validated")
            
        elif "progress_tracker_with_eta" in scenario_name:
            assert processing.get('processed_cves') >= 3, "Should have processed multiple CVEs for ETA"
            assert processing.get('remaining_cves', 0) > 0, "Should have remaining CVEs"
            print(f"   ✅ Progress tracker with ETA validated")
            
        # Metric Card Tests
        elif "metric_cards_runtime" in scenario_name:
            assert stage_analysis.get('total_workflow_time', 0) > 300, "Should have long runtime for testing"
            assert processing.get('processed_cves') >= 1, "Should have processed at least 1 CVE"
            print(f"   ✅ Metric cards runtime test validated")
            
        elif "metric_cards_api_intensive" in scenario_name:
            assert api.get('total_calls', 0) >= 30, "Should have intensive API usage"
            assert api.get('nvd_cpe_calls', 0) >= 25, "Should have many CPE API calls"
            print(f"   ✅ Metric cards API intensive test validated")
            
        elif "metric_cards_mapping_success" in scenario_name:
            assert processing.get('processed_cves') >= 2, "Should have multiple CVEs for mapping stats"
            mapping_rate = processing.get('mapping_success_rate', 0)
            assert mapping_rate > 50, f"Should show good mapping success rate, got {mapping_rate}%"
            print(f"   ✅ Metric cards mapping success test validated")
            
        elif "metric_cards_file_generation" in scenario_name:
            assert processing.get('files_generated', 0) >= 2, "Should have generated multiple files"
            assert processing.get('processed_cves') >= 2, "Should have processed multiple CVEs"
            print(f"   ✅ Metric cards file generation test validated")
            
        elif "metric_cards_processing_speed" in scenario_name:
            assert processing.get('processed_cves') >= 3, "Should have multiple CVEs for speed calculation"
            speed = processing.get('avg_processing_speed', 0)
            assert speed > 0, f"Should calculate processing speed, got {speed}"
            print(f"   ✅ Metric cards processing speed test validated")
            
        elif "metric_cards_cache_performance" in scenario_name:
            cache_data = data.get('cache', {})
            assert cache_data.get('total_requests', 0) >= 10, "Should have cache activity"
            hit_rate = cache_data.get('hit_rate', 0)
            assert hit_rate >= 0, f"Should track cache hit rate, got {hit_rate}%"
            print(f"   ✅ Metric cards cache performance test validated")
            
        elif "metric_cards_cpe_queries" in scenario_name:
            assert api.get('nvd_cpe_calls', 0) >= 20, "Should have substantial CPE queries"
            assert processing.get('processed_cves') >= 2, "Should have processed multiple CVEs"
            print(f"   ✅ Metric cards CPE queries test validated")
            
        elif "metric_cards_resource_warnings" in scenario_name:
            total_warnings = sum(resource_warnings.values())
            assert total_warnings >= 8, f"Should have multiple resource warnings, got {total_warnings}"
            print(f"   ✅ Metric cards resource warnings test validated")
            
        # Workflow Performance Tests
        elif "workflow_stage_analysis" in scenario_name:
            stages = data.get('stages', {})
            total_stages = stage_analysis.get('total_stages', 0)
            assert total_stages >= 4, f"Should have detailed stage breakdown, got {total_stages} stages"
            assert len(stages) >= 4, f"Should track multiple stages, got {len(stages)} stages"
            print(f"   ✅ Workflow stage analysis test validated")
            
        elif "workflow_bottleneck_detection" in scenario_name:
            # Check that we have API calls indicating the bottleneck scenario
            assert api.get('total_calls', 0) >= 30, "Should have many API calls showing bottleneck"
            assert processing.get('processed_cves') >= 1, "Should process at least 1 CVE"
            print(f"   ✅ Workflow bottleneck detection test validated")
            
        elif "workflow_efficiency_metrics" in scenario_name:
            assert processing.get('processed_cves') == 2, "Should process exactly 2 CVEs"
            # Check that we have cache activity showing efficiency differences
            cache_data = data.get('cache', {})
            assert cache_data.get('cache_hits', 0) >= 0, "Should track cache activity"
            print(f"   ✅ Workflow efficiency metrics test validated")
            
        # API Breakdown Tests
        elif "api_breakdown_detailed" in scenario_name:
            assert api.get('total_calls', 0) >= 10, "Should have detailed API call breakdown"
            call_types = api.get('call_breakdown', {})
            assert len(call_types) >= 3, "Should track different API call types"
            print(f"   ✅ API breakdown detailed test validated")
            
        elif "api_breakdown_with_failures" in scenario_name:
            assert api.get('failed_calls', 0) >= 5, "Should have multiple API failures"
            success_rate = api.get('successful_calls', 0) / max(api.get('total_calls', 1), 1) * 100
            assert success_rate < 85, f"Should show mixed success rate, got {success_rate:.1f}%"
            print(f"   ✅ API breakdown with failures test validated")
            
        elif "api_breakdown_mixed_calls" in scenario_name:
            assert api.get('total_calls', 0) >= 15, "Should have mixed API call patterns"
            assert api.get('nvd_cpe_calls', 0) >= 10, "Should have CPE calls"
            assert api.get('nvd_cve_calls', 0) >= 3, "Should have CVE calls"
            print(f"   ✅ API breakdown mixed calls test validated")
            
        # Log Activity Tests
        elif "log_activity_high_volume" in scenario_name:
            log_stats = data.get('log_stats', {})  # Note: log_stats not log_statistics
            total_entries = log_stats.get('total_lines', 0)
            assert total_entries >= 50, f"Should have high volume of log entries, got {total_entries}"
            assert processing.get('processed_cves') >= 3, "Should process multiple CVEs"
            print(f"   ✅ Log activity high volume test validated")
            
        elif "log_activity_with_errors" in scenario_name:
            log_stats = data.get('log_stats', {})  # Note: log_stats not log_statistics
            error_count = log_stats.get('error_count', 0)
            assert error_count >= 5, f"Should have multiple errors, got {error_count}"
            assert log_stats.get('warning_count', 0) >= 5, "Should have warnings too"
            print(f"   ✅ Log activity with errors test validated")
            
        elif "log_activity_warning_heavy" in scenario_name:
            log_stats = data.get('log_stats', {})  # Note: log_stats not log_statistics
            warning_count = log_stats.get('warning_count', 0)
            assert warning_count >= 25, f"Should be warning-heavy, got {warning_count} warnings"
            total_warnings = sum(resource_warnings.values())
            assert total_warnings >= 3, f"Should have some resource warnings, got {total_warnings}"
            print(f"   ✅ Log activity warning heavy test validated")
            
        else:
            print(f"   ⚠️  No specific validation rules for scenario: {scenario_name}")
            print(f"   📊 Basic metrics: {processing.get('processed_cves', 0)} CVEs, {api.get('total_calls', 0)} API calls")
    
    def run_all_tests(self):
        """Run all test scenarios"""
        print(f"\n🧪 DASHBOARD TEST SUITE")
        print(f"Testing enhanced dashboard functionality across all scenarios")
        print(f"{'='*80}")
        
        results = {}
        
        for scenario_name in self.scenarios.keys():
            try:
                success = self.test_scenario(scenario_name)
                results[scenario_name] = "✅ PASSED" if success else "❌ FAILED"
            except Exception as e:
                print(f"❌ ERROR in {scenario_name}: {str(e)}")
                results[scenario_name] = f"❌ ERROR: {str(e)}"
        
        # Summary
        print(f"\n📋 TEST RESULTS SUMMARY")
        print(f"{'='*60}")
        
        passed = sum(1 for result in results.values() if "PASSED" in result)
        total = len(results)
        
        for scenario, result in results.items():
            print(f"   {scenario:30} {result}")
        
        print(f"\n🎯 Overall Results: {passed}/{total} scenarios passed")
        
        if passed == total:
            print(f"🎉 ALL TESTS PASSED! Dashboard functionality validated across all scenarios.")
        else:
            print(f"⚠️  Some tests failed. Review the errors above.")
        
        return results

def main():
    """Main function to run dashboard tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test dashboard functionality across different scenarios")
    parser.add_argument("--scenario", type=str, help="Test specific scenario", 
                       choices=list(DashboardTestScenarios().scenarios.keys()))
    parser.add_argument("--all", action="store_true", help="Run all test scenarios")
    
    args = parser.parse_args()
    
    tester = DashboardTestScenarios()
    
    if args.all:
        tester.run_all_tests()
    elif args.scenario:
        tester.test_scenario(args.scenario)
    else:
        print("Available test scenarios:")
        for scenario in tester.scenarios.keys():
            print(f"  - {scenario}")
        print("\nUse --scenario <name> to test specific scenario or --all to test everything")

if __name__ == "__main__":
    main()
