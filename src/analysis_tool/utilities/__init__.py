#!/usr/bin/env python3
"""
Analysis Tool Utilities

This module contains utility scripts for the CVE Analysis Tool:
- log_analyzer.py: Parses log files and generates dashboard data
- generate_local_dashboard.py: Creates self-contained HTML dashboards
- generate_dataset.py: Generates CVE datasets from NVD API for analysis
"""

import json
from pathlib import Path

def _get_version():
    """Get version from config.json"""
    try:
        config_path = Path(__file__).parent.parent / "config.json"
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config.get("application", {}).get("version", "unknown")
    except Exception:
        return "unknown"

__version__ = _get_version()
__author__ = "Hashmire"

# Expose utility functions for import
try:
    from .log_analyzer import main as analyze_logs
    from .generate_local_dashboard import main as generate_dashboard
except ImportError:
    # For direct script execution, imports may not be available
    pass
