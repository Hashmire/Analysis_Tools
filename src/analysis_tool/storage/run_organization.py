"""
Directory organization utilities for run-based output management.
Manages the creation and organization of analysis runs with timestamp-based naming.
"""

import os
import datetime
from pathlib import Path
from typing import Tuple, Optional, List

def _generate_enhanced_context(execution_type: str = None, source_shortname: str = None, 
                              range_spec: str = None, status_list: List[str] = None, 
                              tool_flags: dict = None) -> str:
    """
    Generate enhanced run context following pattern: <execution><source/status/range>_<tools>
    
    Args:
        execution_type: Type of execution (e.g., 'dataset', 'analysis')
        source_shortname: NVD source shortname (e.g., 'adobe', 'microsoft')
        range_spec: Range specification (e.g., 'last_7_days', 'range_2024-01-01_to_2024-01-31')
        status_list: List of CVE statuses (e.g., ['modified', 'published'])
        tool_flags: Dictionary of tool flags with boolean values
        
    Returns:
        Enhanced context string
    """
    context_parts = []
    
    # Add execution type (default to 'run' if not specified)
    if execution_type:
        context_parts.append(execution_type)
    else:
        context_parts.append("run")
    
    # Determine source/status/range component (prioritized in this order)
    if source_shortname:
        context_parts.append(source_shortname)
    elif range_spec:
        context_parts.append(range_spec)
    elif status_list:
        # Join statuses with hyphens and lowercase
        status_str = "_".join([status.lower() for status in status_list])
        context_parts.append(status_str)
    else:
        context_parts.append("general")
    
    base_context = "_".join(context_parts)
    
    # Add tool parameters that are true (only true values)
    if tool_flags:
        tool_parts = []
        for flag_name, flag_value in tool_flags.items():
            if flag_value is True:
                tool_parts.append(flag_name)
        
        if tool_parts:
            return f"{base_context}_{'_'.join(tool_parts)}"
    
    return base_context

def get_analysis_tools_root() -> Path:
    """Get the root directory of the Analysis_Tools project"""
    current_file = Path(__file__).resolve()
    
    # Walk up the directory tree to find the project root
    for parent in current_file.parents:
        if (parent / "run_tools.py").exists():
            return parent
    
    raise RuntimeError("Could not find Analysis_Tools project root")

def create_run_directory(run_context: str = None, is_test: bool = False, 
                        subdirs: List[str] = None, execution_type: str = None,
                        source_shortname: str = None, range_spec: str = None,
                        status_list: List[str] = None, tool_flags: dict = None) -> Tuple[Path, str]:
    """
    Create a new run directory with timestamp-based naming.
    
    Supports enhanced naming pattern: <date><execution><source/status/range>_<tools>
    Also supports consolidated test runs to avoid cluttering the main runs directory.
    When running under CONSOLIDATED_TEST_RUN environment, test runs are created
    within the consolidated test directory structure.
    
    Args:
        run_context: Optional legacy context string (e.g., CVE ID, batch name) to append to timestamp
        is_test: Whether this is a test run (adds 'TEST_' prefix to context)
        subdirs: Optional list of subdirectories to create (defaults to ["generated_pages", "logs"])
        execution_type: Type of execution (e.g., 'dataset', 'analysis') for enhanced naming
        source_shortname: NVD source shortname (e.g., 'adobe', 'microsoft') for enhanced naming
        range_spec: Range specification (e.g., 'last_7_days', 'range_2024-01-01_to_2024-01-31') for enhanced naming
        status_list: List of CVE statuses (e.g., ['modified', 'published']) for enhanced naming
        tool_flags: Dictionary of tool flags with boolean values (e.g., {'sdc': True, 'cpe-sug': False}) for enhanced naming
        
    Returns:
        Tuple of (run_directory_path, run_id)
    """
    import os
    
    # Check if we're in a consolidated test run environment
    if os.environ.get('CONSOLIDATED_TEST_RUN') == '1' and is_test:
        # Create test run within consolidated directory
        consolidated_path = Path(os.environ.get('CONSOLIDATED_TEST_RUN_PATH', ''))
        if consolidated_path.exists():
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            
            # Get current test suite name for better labeling
            current_suite = os.environ.get('CURRENT_TEST_SUITE', '')
            suite_prefix = f"{current_suite.replace(' ', '_')}_" if current_suite else ""
            
            if run_context:
                clean_context = f"TEST_{suite_prefix}{run_context}"
                # Clean the context string for filesystem safety
                clean_context = "".join(c for c in clean_context if c.isalnum() or c in ("-", "_", "."))
                run_id = f"{timestamp}_{clean_context}"
            else:
                clean_context = f"TEST_{suite_prefix}run" if suite_prefix else "TEST_run"
                run_id = f"{timestamp}_{clean_context}"
            
            # Create run directory within consolidated logs directory
            run_path = consolidated_path / "logs" / run_id
            
            # Create subdirectories
            if subdirs is None:
                subdirs = ["generated_pages", "logs"]  # Default for Analysis_Tools
            
            for subdir in subdirs:
                (run_path / subdir).mkdir(parents=True, exist_ok=True)
            
            return run_path, run_id
    
    # Standard run directory creation (existing behavior)
    project_root = get_analysis_tools_root()
    
    # Generate timestamp-based run ID
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    # Use enhanced context generation if parameters are provided
    if any([execution_type, source_shortname, range_spec, status_list, tool_flags]):
        enhanced_context = _generate_enhanced_context(
            execution_type=execution_type,
            source_shortname=source_shortname,
            range_spec=range_spec,
            status_list=status_list,
            tool_flags=tool_flags
        )
        
        # Add test prefix if this is a test run
        if is_test:
            clean_context = f"TEST_{enhanced_context}"
        else:
            clean_context = enhanced_context
            
        # Clean the context string for filesystem safety
        clean_context = "".join(c for c in clean_context if c.isalnum() or c in ("-", "_", "."))
        run_id = f"{timestamp}_{clean_context}"
    elif run_context:
        # Legacy run_context support
        if is_test:
            clean_context = f"TEST_{run_context}"
        else:
            clean_context = run_context
            
        # Clean the context string for filesystem safety
        clean_context = "".join(c for c in clean_context if c.isalnum() or c in ("-", "_", "."))
        run_id = f"{timestamp}_{clean_context}"
    else:
        # Default context based on run type
        if is_test:
            run_id = f"{timestamp}_TEST_run"
        else:
            run_id = timestamp
    
    # Create run directory structure
    run_path = project_root / "runs" / run_id
    
    # Create subdirectories (cache is global, not run-specific)
    if subdirs is None:
        subdirs = ["generated_pages", "logs"]  # Default for Analysis_Tools
    
    for subdir in subdirs:
        (run_path / subdir).mkdir(parents=True, exist_ok=True)
    
    return run_path, run_id

def get_current_run_paths(run_id: str) -> dict:
    """
    Get standardized paths for a specific run.
    
    Supports consolidated test runs to match the create_run_directory behavior.
    
    Args:
        run_id: The run identifier
        
    Returns:
        Dictionary with keys: generated_pages, logs, cache (global)
    """
    import os
    
    # Check if we're in a consolidated test run environment
    if os.environ.get('CONSOLIDATED_TEST_RUN') == '1':
        consolidated_path = Path(os.environ.get('CONSOLIDATED_TEST_RUN_PATH', ''))
        if consolidated_path.exists():
            # For consolidated test runs, the run directory is within the consolidated logs directory
            # This matches the create_run_directory behavior exactly
            run_path = consolidated_path / "logs" / run_id
        else:
            # Fallback to standard behavior
            project_root = get_analysis_tools_root()
            run_path = project_root / "runs" / run_id
    else:
        # Standard run directory resolution
        project_root = get_analysis_tools_root()
        run_path = project_root / "runs" / run_id
    
    return {
        "generated_pages": run_path / "generated_pages",
        "logs": run_path / "logs", 
        "cache": get_analysis_tools_root() / "cache",  # Cache is global, not run-specific
        "run_root": run_path
    }

def get_latest_run() -> Optional[Path]:
    """Get the most recent run directory"""
    project_root = get_analysis_tools_root()
    runs_dir = project_root / "runs"
    
    if not runs_dir.exists():
        return None
    
    run_dirs = [d for d in runs_dir.iterdir() if d.is_dir()]
    if not run_dirs:
        return None
    
    # Sort by creation time (most recent first)
    run_dirs.sort(key=lambda x: x.stat().st_ctime, reverse=True)
    return run_dirs[0]

def ensure_run_directory(run_context: str = None, subdirs: List[str] = None) -> Tuple[Path, str]:
    """
    Ensure run directory exists, creating if necessary.
    
    Args:
        run_context: Optional context for the run
        subdirs: Optional list of subdirectories to create
        
    Returns:
        Tuple of (run_directory_path, run_id)
    """
    return create_run_directory(run_context, subdirs=subdirs)


# Consolidated Test Environment Helper Functions
# These functions help tests work in both standard and consolidated test environments

def find_latest_test_run_report(report_filename: str = "sourceDataConcernReport.json") -> Optional[dict]:
    """
    Find and load the latest test run report, handling both standard and consolidated test environments.
    
    Args:
        report_filename: Name of the report file to find (default: sourceDataConcernReport.json)
        
    Returns:
        Dict containing the report data, or None if not found
    """
    import json
    
    try:
        # Check if we're in a consolidated test run environment
        if os.environ.get('CONSOLIDATED_TEST_RUN') == '1':
            consolidated_path = Path(os.environ.get('CONSOLIDATED_TEST_RUN_PATH', ''))
            if consolidated_path.exists():
                # Look in the consolidated test run logs directory
                logs_dir = consolidated_path / "logs"  
                if logs_dir.exists():
                    # Find the most recent test run directory
                    test_run_dirs = [d for d in logs_dir.glob("*TEST_*") if d.is_dir()]
                    if test_run_dirs:
                        latest_run = max(test_run_dirs, key=lambda x: x.stat().st_mtime)
                        report_path = latest_run / "logs" / report_filename
                        
                        if report_path.exists():
                            with open(report_path, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                                print(f"✅ Report found: {report_path}")
                                return data
                        else:
                            print(f"❌ Report not found in consolidated run: {report_path}")
                            return None
                    else:
                        print(f"❌ No test run directories found in consolidated logs: {logs_dir}")
                        return None
                else:
                    print(f"❌ Consolidated logs directory not found: {logs_dir}")
                    return None
            else:
                print(f"❌ Consolidated test path not found: {consolidated_path}")
                return None
        
        # Standard mode - look in main runs directory
        runs_dir = Path(__file__).parent.parent.parent.parent / "runs"
        run_dirs = [d for d in runs_dir.glob("*") if d.is_dir() and not d.name.startswith("run_all_tests")]
        if not run_dirs:
            print("❌ No run directories found")
            return None
            
        latest_run = max(run_dirs, key=lambda x: x.stat().st_mtime)
        report_path = latest_run / "logs" / report_filename
        
        if not report_path.exists():
            print(f"❌ Report not found: {report_path}")
            return None
            
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            print(f"✅ Report found: {report_path}")
            return data
            
    except Exception as e:
        print(f"❌ Error finding report: {e}")
        return None


def get_latest_test_run_directory() -> Optional[Path]:
    """
    Get the latest test run directory, handling both standard and consolidated test environments.
    
    Returns:
        Path to the latest test run directory, or None if not found
    """
    try:
        # Check if we're in a consolidated test run environment
        if os.environ.get('CONSOLIDATED_TEST_RUN') == '1':
            consolidated_path = Path(os.environ.get('CONSOLIDATED_TEST_RUN_PATH', ''))
            if consolidated_path.exists():
                # Look in the consolidated test run logs directory
                logs_dir = consolidated_path / "logs"  
                if logs_dir.exists():
                    # Find the most recent test run directory
                    test_run_dirs = [d for d in logs_dir.glob("*TEST_*") if d.is_dir()]
                    if test_run_dirs:
                        latest_run = max(test_run_dirs, key=lambda x: x.stat().st_mtime)
                        print(f"✅ Latest consolidated test run: {latest_run}")
                        return latest_run
                    else:
                        print(f"❌ No test run directories found in consolidated logs: {logs_dir}")
                        return None
                else:
                    print(f"❌ Consolidated logs directory not found: {logs_dir}")
                    return None
            else:
                print(f"❌ Consolidated test path not found: {consolidated_path}")
                return None
        
        # Standard mode - look in main runs directory
        runs_dir = Path(__file__).parent.parent.parent.parent / "runs"
        run_dirs = [d for d in runs_dir.glob("*") if d.is_dir() and not d.name.startswith("run_all_tests")]
        if not run_dirs:
            print("❌ No run directories found")
            return None
            
        latest_run = max(run_dirs, key=lambda x: x.stat().st_mtime)
        print(f"✅ Latest standard test run: {latest_run}")
        return latest_run
            
    except Exception as e:
        print(f"❌ Error finding latest run directory: {e}")
        return None


def find_curator_output_files(file_pattern: str = "source_mapping_extraction_*.json") -> list:
    """
    Find curator output files in both standard and consolidated test environments.
    
    Args:
        file_pattern: Glob pattern to match curator output files
        
    Returns:
        List of Path objects for matching files
    """
    try:
        # Check if we're in a consolidated test run environment
        if os.environ.get('CONSOLIDATED_TEST_RUN') == '1':
            consolidated_path = Path(os.environ.get('CONSOLIDATED_TEST_RUN_PATH', ''))
            if consolidated_path.exists():
                # Look in consolidated test run logs directory (recursive search)
                logs_dir = consolidated_path / "logs"
                if logs_dir.exists():
                    # Recursively search for curator output files
                    curator_files = []
                    for pattern_file in logs_dir.rglob(file_pattern):
                        curator_files.append(pattern_file)
                    
                    if curator_files:
                        print(f"✅ Found {len(curator_files)} curator files matching '{file_pattern}' in consolidated logs")
                        return curator_files
                    else:
                        print(f"❌ No curator files matching '{file_pattern}' found in consolidated logs: {logs_dir}")
                        return []
                else:
                    print(f"❌ Consolidated logs directory not found: {logs_dir}")
                    return []
            else:
                print(f"❌ Consolidated test path not found: {consolidated_path}")
                return []
        
        # Standard mode - look in main runs directory
        runs_dir = Path(__file__).parent.parent.parent.parent / "runs"
        curator_files = []
        
        # Look through all run directories for curator files
        for run_dir in runs_dir.glob("*"):
            if run_dir.is_dir() and not run_dir.name.startswith(("run_all_tests", "2025-")):
                logs_dir = run_dir / "logs"
                if logs_dir.exists():
                    for pattern_file in logs_dir.glob(file_pattern):
                        curator_files.append(pattern_file)
        
        if curator_files:
            print(f"✅ Found {len(curator_files)} curator files matching '{file_pattern}' in standard runs")
            return curator_files
        else:
            print(f"❌ No curator files matching '{file_pattern}' found in standard runs")
            return []
            
    except Exception as e:
        print(f"❌ Error finding curator files: {e}")
        return []
