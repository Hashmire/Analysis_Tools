#!/usr/bin/env python3
"""
Analysis Tools Entry Point

This script provides a convenient way to run the Hashmire/Analysis_Tools from the project root.
It properly sets up the Python path and imports to work with the package structure.
"""

import sys
import os
from pathlib import Path

# Add the src directory to Python path so we can import the analysis_tool package
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

# Now we can import and run the analysis tool
from analysis_tool.core.analysis_tool import main

if __name__ == "__main__":
    main()
