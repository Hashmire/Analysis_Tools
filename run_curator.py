#!/usr/bin/env python3
"""
Source Mapping Curator Entry Point

This script provides a convenient way to run the Source Mapping Curator from the project root.
It properly sets up the Python path and imports to work with the Analysis_Tools package structure.

Usage:
    python run_curator.py --cve-repo /path/to/cves --uuid target-uuid [--context context_name]

Examples:
    # Extract Microsoft mappings
    python run_curator.py --cve-repo X:\\Git\\cvelistV5\\cves --uuid f38d906d-7342-40ea-92c1-6c4a2c6478c8

    # Extract with custom context
    python run_curator.py --cve-repo X:\\Git\\cvelistV5\\cves --uuid f38d906d-7342-40ea-92c1-6c4a2c6478c8 --context microsoft_q3_2024

Known UUIDs:
    Microsoft: f38d906d-7342-40ea-92c1-6c4a2c6478c8
"""

import sys
import os
from pathlib import Path

# Add the src directory to Python path so we can import the analysis_tool package
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

# Now we can import and run the curator
from analysis_tool.mappings.curator import main

if __name__ == "__main__":
    main()
