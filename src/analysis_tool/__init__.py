#!/usr/bin/env python3
"""
Analysis Tool Package

This package contains the Hashmire/Analysis_Tools and related utilities.
"""

import json
from pathlib import Path

def _get_version():
    """Get version from config.json"""
    try:
        config_path = Path(__file__).parent / "config.json"
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config.get("application", {}).get("version", "unknown")
    except Exception:
        return "unknown"

__version__ = _get_version()
__author__ = "Hashmire"

# Core modules available for import
__all__ = [
    'analysis_tool',
    'workflow_logger', 
    'cpe_cache',
    'processData',
    'gatherData', 
    'generateHTML',
    'utilities'
]
