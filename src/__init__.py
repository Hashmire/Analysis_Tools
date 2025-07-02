#!/usr/bin/env python3
"""
Source Code Package

Contains the main Analysis Tools source code.
"""

import json
import os
from pathlib import Path

def _get_version():
    """Get version from config.json"""
    try:
        config_path = Path(__file__).parent / "analysis_tool" / "config.json"
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config.get("application", {}).get("version", "unknown")
    except Exception:
        return "unknown"

__version__ = _get_version()
__author__ = "Hashmire"
