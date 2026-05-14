#!/usr/bin/env python3
"""
Alias Source Report Example Generator

Regenerates dashboards/Alias_Extraction_Source_Report_Example.html from
dashboards/example_data/Alias_Extraction_Source_Report_Example.json using the
real generation pipeline with CSS inlined for standalone portability.

Usage:
    python -m utilities.generate_alias_source_report_example
"""

import json
import re
import sys
from pathlib import Path

from src.analysis_tool.logging.workflow_logger import get_logger
from src.analysis_tool.storage.run_organization import get_project_root
from src.analysis_tool.reporting.generate_alias_report import generate_alias_html_report

logger = get_logger()

_EXAMPLE_DATA_PATH = "dashboards/example_data/Alias_Extraction_Source_Report_Example.json"
_CSS_PATH = "src/analysis_tool/static/css/alias_mapping_dashboard.css"
_TEMPLATE_PATH = "src/analysis_tool/static/templates/Alias_Mapping_Report_Template.html"
_OUTPUT_PATH = "dashboards/Alias_Extraction_Source_Report_Example.html"
_TOOL_VERSION = "Example"


def main() -> int:
    root = get_project_root()

    data_path = root / _EXAMPLE_DATA_PATH
    css_path = root / _CSS_PATH
    template_path = root / _TEMPLATE_PATH
    output_path = root / _OUTPUT_PATH

    for path in (data_path, css_path, template_path):
        if not path.exists():
            logger.error(f"Required file not found: {path}")
            return 1

    logger.info(f"Loading example data from {data_path.name}")
    report_data = json.loads(data_path.read_text(encoding="utf-8"))

    logger.info("Generating HTML via generate_alias_html_report()")
    generate_alias_html_report(
        report_data=report_data,
        output_path=str(output_path),
        report_template_path=str(template_path),
        tool_version=_TOOL_VERSION,
    )

    # Inline the CSS so the example file is fully standalone
    logger.info("Inlining CSS for standalone portability")
    css_content = css_path.read_text(encoding="utf-8")
    html = output_path.read_text(encoding="utf-8")

    link_tag = '<link rel="stylesheet" href="css/alias_mapping_dashboard.css">'
    style_block = f"<style>\n{css_content}\n</style>"

    if link_tag not in html:
        logger.error("Expected CSS link tag not found in generated HTML — cannot inline")
        return 1

    html = html.replace(link_tag, style_block, 1)

    # Inject example-specific note before the currentData assignment
    data_marker = "let currentData = "
    example_note = (
        "// NOTE: No aliasGroup example for the placeholderValues SDC concern type is included here. "
        "The relevant detection group is retained for the edge case of confirmed mapping .json files "
        "that were manually edited with placeholder values.\n        "
    )
    if data_marker in html:
        html = html.replace(data_marker, example_note + data_marker, 1)
    else:
        logger.warning("currentData marker not found — example note not injected")

    output_path.write_text(html, encoding="utf-8")

    logger.info(f"Written: {output_path} ({output_path.stat().st_size:,} bytes)")
    print(f"Generated: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
