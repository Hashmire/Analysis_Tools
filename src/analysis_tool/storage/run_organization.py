"""
Directory organization utilities for run-based output management.
Manages the creation and organization of analysis runs with timestamp-based naming.
"""

import os
import datetime
from pathlib import Path
from typing import Tuple, Optional

def get_analysis_tools_root() -> Path:
    """Get the root directory of the Analysis_Tools project"""
    current_file = Path(__file__).resolve()
    
    # Walk up the directory tree to find the project root
    for parent in current_file.parents:
        if (parent / "run_tools.py").exists():
            return parent
    
    raise RuntimeError("Could not find Analysis_Tools project root")

def create_run_directory(run_context: str = None, is_test: bool = False) -> Tuple[Path, str]:
    """
    Create a new run directory with timestamp-based naming.
    
    Args:
        run_context: Optional context string (e.g., CVE ID, batch name) to append to timestamp
        is_test: Whether this is a test run (adds 'TEST_' prefix to context)
        
    Returns:
        Tuple of (run_directory_path, run_id)
    """
    project_root = get_analysis_tools_root()
    
    # Generate timestamp-based run ID
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    if run_context:
        # Add test prefix if this is a test run
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
    subdirs = ["generated_pages", "logs"]
    for subdir in subdirs:
        (run_path / subdir).mkdir(parents=True, exist_ok=True)
    
    return run_path, run_id

def get_current_run_paths(run_id: str) -> dict:
    """
    Get standardized paths for a specific run.
    
    Args:
        run_id: The run identifier
        
    Returns:
        Dictionary with keys: generated_pages, logs, cache (global)
    """
    project_root = get_analysis_tools_root()
    run_path = project_root / "runs" / run_id
    
    return {
        "generated_pages": run_path / "generated_pages",
        "logs": run_path / "logs", 
        "cache": project_root / "cache",  # Cache is global, not run-specific
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

def ensure_run_directory(run_context: str = None) -> Tuple[Path, str]:
    """
    Ensure run directory exists, creating if necessary.
    
    Args:
        run_context: Optional context for the run
        
    Returns:
        Tuple of (run_directory_path, run_id)
    """
    return create_run_directory(run_context)
