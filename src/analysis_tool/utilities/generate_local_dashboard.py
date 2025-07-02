#!/usr/bin/env python3
"""
Generate a self-contained local dashboard with embedded data
This solves the CORS issue by embedding JSON data directly in the HTML
"""

import json
import os
import argparse
from datetime import datetime
from pathlib import Path

def get_analysis_tools_root():
    """Get the absolute path to the Analysis_Tools project root"""
    current_file = Path(__file__).resolve()
    # Navigate up from src/analysis_tool/utilities/generate_local_dashboard.py to Analysis_Tools/
    # generate_local_dashboard.py -> utilities/ -> analysis_tool/ -> src/ -> Analysis_Tools/
    return current_file.parent.parent.parent.parent

def resolve_input_path(input_file):
    """Resolve input file path - if relative, check reports directory"""
    if os.path.isabs(input_file):
        return input_file
    else:
        return str(get_analysis_tools_root() / "reports" / input_file)

def resolve_output_path(output_file):
    """Resolve output file path - if relative, put in reports directory"""
    if os.path.isabs(output_file):
        return output_file
    else:
        reports_dir = get_analysis_tools_root() / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        return str(reports_dir / output_file)

def load_config():
    """Load tool name and version from config.json"""
    try:
        config_path = Path(__file__).parent.parent / "src" / "analysis_tool" / "config.json"
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        app_config = config.get("application", {})
        toolname = app_config.get("toolname", "UNABLE TO GET TOOL NAME")
        version = app_config.get("version", "UNABLE TO GET VERSION")
        
        # Ensure version has 'v' prefix
        if not version.startswith('v'):
            version = f"v{version}"
            
        return toolname, version
    except Exception as e:
        print(f"Warning: Could not load config.json: {e}")
        return "UNABLE TO GET TOOL NAME", "UNABLE TO GET VERSION"

def load_dashboard_data(json_file):
    """Load dashboard data from JSON file"""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Dashboard data file not found: {json_file}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in dashboard data file: {e}")
        return None

def generate_dashboard_html(data, output_file):
    """Generate HTML dashboard with embedded data"""
    
    
    # Load tool information from config
    TOOL_NAME, TOOL_VERSION = load_config()
    
    # HTML template with embedded CSS and JavaScript (all braces escaped for format())
    html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{tool_name} {tool_version} - Local Dashboard</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }}

        .header {{
            background: linear-gradient(45deg, #2c3e50, #34495e);
            color: white;
            padding: 10px;
            text-align: center;
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
        }}

        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}

        .status-bar {{
            background: #3498db;
            color: white;
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}

        .status-item {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .status-indicator {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #27ae60;
        }}

        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 25px;
            padding: 15px 30px;
        }}

        .metric-card {{
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
            border-left: 5px solid;
            position: relative;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}

        .metric-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        }}

        .metric-card.clickable {{
            cursor: pointer;
        }}

        .metric-card.clickable:hover {{
            transform: translateY(-7px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }}

        .metric-card.clickable::after {{
            content: '👆 Click for details';
            position: absolute;
            bottom: 8px;
            right: 12px;
            font-size: 0.7em;
            color: #3498db;
            font-weight: 600;
            opacity: 0;
            transition: opacity 0.3s ease;
            background: rgba(255, 255, 255, 0.9);
            padding: 2px 6px;
            border-radius: 3px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}

        .metric-card.clickable:hover::after {{
            opacity: 1;
        }}

        .metric-card::before {{
            content: '';
            position: absolute;
            top: 20px;
            right: 20px;
            font-size: 2em;
            opacity: 0.3;
        }}

        .metric-card.processing {{ 
            border-left-color: #3498db; 
        }}
        .metric-card.processing::before {{ content: '📊'; }}

        .metric-card.performance {{ 
            border-left-color: #2ecc71; 
        }}
        .metric-card.performance::before {{ content: '⚡'; }}

        .metric-card.api {{ 
            border-left-color: #27ae60; 
        }}
        .metric-card.api::before {{ content: '🌐'; }}

        .metric-card.system {{ 
            border-left-color: #1abc9c; 
        }}
        .metric-card.system::before {{ content: '⏱️'; }}

        .metric-card.speed {{ 
            border-left-color: #f39c12; 
        }}
        .metric-card.speed::before {{ content: '⚡'; }}

        .metric-card.mappings {{ 
            border-left-color: #8e44ad; 
        }}
        .metric-card.mappings::before {{ content: '🔗'; }}

        .metric-card.cache {{ 
            border-left-color: #9b59b6; 
        }}
        .metric-card.cache::before {{ content: '💾'; }}

        .metric-card.files {{ 
            border-left-color: #16a085; 
        }}
        .metric-card.files::before {{ content: '📄'; }}

        .metric-card.cpe {{ 
            border-left-color: #e67e22; 
        }}
        .metric-card.cpe::before {{ content: '🔍'; }}

        .metric-title {{
            font-size: 1.1em;
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 10px;
        }}

        .metric-value {{
            font-size: 2.2em;
            font-weight: 700;
            color: #34495e;
            margin-bottom: 5px;
        }}

        .metric-subtitle {{
            font-size: 0.9em;
            color: #7f8c8d;
            line-height: 1.4;
        }}

        .progress-section {{
            background: white;
            margin: 15px 30px;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
        }}

        .progress-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}

        .progress-title {{
            font-size: 1.3em;
            font-weight: 600;
            color: #2c3e50;
        }}

        .progress-percentage {{
            font-size: 1.1em;
            font-weight: 600;
            color: #27ae60;
        }}

        .progress-bar {{
            width: 100%;
            height: 20px;
            background: #ecf0f1;
            border-radius: 10px;
            overflow: hidden;
            position: relative;
        }}

        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #27ae60, #2ecc71);
            border-radius: 10px;
            position: relative;
            transition: width 0.3s ease;
        }}

        .progress-fill::after {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: repeating-linear-gradient(
                45deg,
                transparent,
                transparent 10px,
                rgba(255, 255, 255, 0.1) 10px,
                rgba(255, 255, 255, 0.1) 20px
            );
            animation: float 2s linear infinite;
        }}

        @keyframes float {{
            0% {{ background-position: 0 0; }}
            100% {{ background-position: 50px 50px; }}
        }}

        .details-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin: 20px 0;
        }}

        .detail-section {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
        }}

        .detail-section h3 {{
            font-size: 1.1em;
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }}

        .stat-item {{
            background: white;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #e9ecef;
        }}

        .stat-label {{
            font-size: 0.85em;
            color: #6c757d;
            margin-bottom: 5px;
        }}

        .stat-value {{
            font-size: 1.3em;
            font-weight: 600;
            color: #2c3e50;
        }}

        .log-section {{
            margin: 20px 0;
        }}

        .log-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}

        .log-stat {{
            text-align: center;
            padding: 15px;
            background: white;
            border-radius: 8px;
            border: 1px solid #e9ecef;
        }}

        .log-stat .number {{
            font-size: 1.8em;
            font-weight: 700;
            display: block;
            margin: 0 8px;
        }}

        .log-stat .label {{
            font-size: 0.8em;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .recent-activity {{
            background: white;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            border: 1px solid #e9ecef;
        }}

        .activity-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #e9ecef;
            font-weight: 600;
            color: #2c3e50;
        }}

        .log-entry {{
            padding: 12px 20px;
            border-bottom: 1px solid #f8f9fa;
            border-left: 4px solid transparent;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
        }}

        .log-entry:last-child {{
            border-bottom: none;
        }}

        .log-entry.info {{ border-left-color: #3498db; }}
        .log-entry.debug {{ border-left-color: #95a5a6; }}
        .log-entry.warning {{ border-left-color: #f39c12; }}
        .log-entry.error {{ border-left-color: #e74c3c; }}

        .log-meta {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }}

        .timestamp {{
            color: #6c757d;
            font-size: 0.8em;
        }}

        .level {{
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7em;
            font-weight: 600;
            text-transform: uppercase;
            margin: 0 8px;
        }}

        .level.info {{ background: #3498db; color: white; }}
        .level.debug {{ background: #6c757d; color: white; }}
        .level.warning {{ background: #f39c12; color: white; }}
        .level.error {{ background: #e74c3c; color: white; }}

        .log-message {{
            color: #2c3e50;
            line-height: 1.4;
        }}

        .clickable-log-stat {{
            cursor: pointer;
            transition: background-color 0.2s ease;
        }}

        .clickable-log-stat:hover {{
            background-color: #e9ecef !important;
        }}

        .log-details {{
            display: none;
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
        }}

        .log-details.warnings {{
            border-left-color: #f39c12;
        }}

        .log-details h4 {{
            margin-bottom: 10px;
            color: #2c3e50;
        }}

        .log-entry-detail {{
            background: white;
            margin-bottom: 8px;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.8em;
            border-left: 3px solid #e74c3c;
        }}

        .log-entry-detail.warning {{
            border-left-color: #f39c12;
        }}

        .log-entry-detail .timestamp {{
            color: #6c757d;
            font-size: 0.75em;
        }}

        .footer {{
            background: #2c3e50;
            color: white;
            padding: 5px;
            text-align: center;
            font-size: 0.9em;
        }}

        @media (max-width: 768px) {{
            .container {{
                margin: 10px;
                border-radius: 10px;
            }}

            .header {{
                padding: 20px;
            }}

            .header h1 {{
                font-size: 1.8em;
            }}

            .metrics-grid {{
                grid-template-columns: 1fr;
                padding: 15px 30px;
                gap: 20px;
            }}

            .status-bar {{
                flex-direction: column;
                align-items: stretch;
                gap: 10px;
            }}

            .details-grid {{
                grid-template-columns: 1fr;
            }}

            .log-stats {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
    <script>
        function toggleLogDetails(type) {{
            const detailsElement = document.getElementById(type + '-details');
            if (detailsElement.style.display === 'none' || detailsElement.style.display === '') {{
                detailsElement.style.display = 'block';
            }} else {{
                detailsElement.style.display = 'none';
            }}
        }}
        
        function showAllLogEntries(button) {{
            // Find the parent container
            const container = button.parentElement;
            
            // Show all hidden log entries in this container
            const extraEntries = container.querySelectorAll('.log-entry-extra');
            extraEntries.forEach(entry => {{
                entry.style.display = 'block';
            }});
            
            // Hide the "Show All" button
            button.style.display = 'none';
        }}
        
        function scrollToSection(sectionId) {{
            const element = document.getElementById(sectionId);
            if (element) {{
                element.scrollIntoView({{
                    behavior: 'smooth',
                    block: 'start'
                }});
                
                // Add a brief highlight effect
                element.style.transition = 'background-color 0.5s ease';
                element.style.backgroundColor = 'rgba(52, 152, 219, 0.1)';
                setTimeout(() => {{
                    element.style.backgroundColor = '';
                }}, 1000);
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{tool_name} {tool_version} Dataset Processing Dashboard</h1>
            <p>Real-time monitoring and analytics</p>
        </div>

        <div class="status-bar">
            <div class="status-item">
                <div class="status-indicator"></div>
                <span>Generated: {generation_time} ({time_elapsed})</span>
            </div>
            <div class="status-item">
                <div class="status-indicator"></div>
                <span>Log: {log_file_display} ({file_size_display})</span>
            </div>
        </div>

        <!-- Overall Progress at the top -->
        <div class="progress-section">
            <div class="progress-header">
                <div class="progress-title">Overall Progress</div>
                <div class="progress-percentage">{progress_percent}</div>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {progress_percent}"></div>
            </div>
            <div style="margin-top: 15px; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; text-align: center;">
                <div>
                    <div style="font-size: 1.5em; font-weight: bold; color: #27ae60;">{processed_cves}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Processed</div>
                </div>
                <div>
                    <div style="font-size: 1.5em; font-weight: bold; color: #3498db;">{remaining_cves}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Remaining</div>
                </div>
                <div>
                    <div style="font-size: 1.5em; font-weight: bold; color: #e67e22;">{total_cves}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Total CVEs</div>
                </div>
                <div>
                    <div style="font-size: 1.5em; font-weight: bold; color: #9b59b6;">{eta_simple}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">ETA</div>
                </div>
            </div>
        </div>

        <!-- Key metrics only -->
        <div class="metrics-grid">
            <div class="metric-card system clickable" onclick="scrollToSection('workflow-performance')">
                <div class="metric-title">Runtime</div>
                <div class="metric-value">{runtime}</div>
                <div class="metric-subtitle">Total execution time<br>
                    Currently processing: <strong>{current_cve}</strong></div>
            </div>

            <div class="metric-card api clickable" onclick="scrollToSection('api-performance')">
                <div class="metric-title">API Calls</div>
                <div class="metric-value">{api_calls}</div>
                <div class="metric-subtitle">Total API requests made<br>
                    Cache saved <strong>{calls_saved}</strong> calls</div>
            </div>

            <div class="metric-card mappings">
                <div class="metric-title">Confirmed Mappings</div>
                <div class="metric-value">{mapping_percentage}</div>
                <div class="metric-subtitle">CVEs with mappings<br>
                    <strong>{total_mappings}</strong> total mappings found</div>
            </div>

            <div class="metric-card files clickable" onclick="scrollToSection('file-analysis')">
                <div class="metric-title">Generated Files</div>
                <div class="metric-value">{files_generated}</div>
                <div class="metric-subtitle">HTML pages created<br>
                    Largest: <strong>{largest_file}</strong> | Smallest: <strong>{smallest_file}</strong></div>
            </div>

            <div class="metric-card speed clickable" onclick="scrollToSection('workflow-performance')">
                <div class="metric-title">Processing Speed</div>
                <div class="metric-value">{average_speed}s</div>
                <div class="metric-subtitle">Average per CVE<br>
                    Fastest: <strong>{fastest_cve_time}s</strong> | Slowest: <strong>{slowest_cve_time}s</strong></div>
            </div>

            <div class="metric-card cache">
                <div class="metric-title">Cache Performance</div>
                <div class="metric-value">{cache_hit_rate}</div>
                <div class="metric-subtitle">Hit rate<br>
                    <strong>{cache_entries}</strong> total entries | <strong>{cache_file_size}</strong></div>
            </div>

            <div class="metric-card cpe clickable" onclick="scrollToSection('cpe-breakdown')">
                <div class="metric-title">CPE Base String Queries</div>
                <div class="metric-value">{total_cpe_queries}</div>
                <div class="metric-subtitle">
                    Most CPE Base String searched: <strong>{largest_cpe_query}</strong> <br>
                    Most CPE Name results: <strong>{top_result_count}</strong> </div>
            </div>
            
            {resource_warnings_card}
        </div>

        <!-- Workflow Performance Analysis -->
        <div id="workflow-performance" class="progress-section">
            <h3>⚡ Workflow Performance Analysis</h3>
            {stages_progress}
        </div>

        <!-- API Performance Breakdown -->
        <div id="api-performance" class="progress-section">
            <h3>🌐 API Performance Breakdown</h3>
            {api_breakdown}
        </div>

        <!-- CPE Query Breakdown -->
        <div id="cpe-breakdown" class="progress-section">
            <h3>🔍 Top CPE Base String Query Breakdown</h3>
            {cpe_breakdown}
        </div>

        <!-- Detailed Files Analysis -->
        <div id="file-analysis" class="progress-section">
            <h3>📁 Generated Files Analysis</h3>
            {detailed_files}
        </div>

        <!-- Log Activity Summary -->
        <div id="log-activity" class="progress-section">
            <h3>📝 Log Activity Summary</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0;">
                <div style="text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    <div style="font-size: 1.3em; font-weight: bold; color: #2c3e50;">{total_lines}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Total Log Lines</div>
                </div>
                <div style="text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    <div style="font-size: 1.3em; font-weight: bold; color: #6c757d;">{debug_count}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Debug Messages</div>
                </div>
                <div style="text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    <div style="font-size: 1.3em; font-weight: bold; color: #3498db;">{info_count}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Info Messages</div>
                </div>
                <div class="clickable-log-stat" style="text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px;" onclick="toggleLogDetails('warnings')">
                    <div style="font-size: 1.3em; font-weight: bold; color: #f39c12;">{warning_count}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Warnings (click to view)</div>
                </div>
                <div class="clickable-log-stat" style="text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px;" onclick="toggleLogDetails('errors')">
                    <div style="font-size: 1.3em; font-weight: bold; color: #e74c3c;">{error_count}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Errors (click to view)</div>
                </div>
            </div>
            
            <!-- Warning details -->
            <div id="warnings-details" class="log-details warnings">
                <h4>⚠️ Warning Messages</h4>
                {warning_details}
            </div>
            
            <!-- Error details -->
            <div id="errors-details" class="log-details">
                <h4>❌ Error Messages</h4>
                {error_details}
            </div>
        </div>

        <div class="footer">
            <p>{tool_name} {tool_version} Dashboard | Generated {generation_time}</p>
        </div>
    </div>
</body>
</html>'''

    # Extract and format data
    processing = data.get("processing", {})
    performance = data.get("performance", {})
    cache = data.get("cache", {})
    api = data.get("api", {})
    log_stats = data.get("log_stats", {})
    file_stats = data.get("file_stats", {})
    speed_stats = data.get("speed_stats", {})
    mapping_stats = data.get("mapping_stats", {})
    stages = data.get("stages", [])
    recent_activity = data.get("recent_activity", [])
    errors = data.get("errors", [])
    warnings = data.get("warnings", [])

    # Format values
    def format_number(value, decimal_places=0):
        if value is None:
            return "--"
        if decimal_places == 0:
            return f"{int(value):,}"
        else:
            return f"{float(value):,.{decimal_places}f}"

    def format_percentage(value):
        if value is None:
            return "--"
        return f"{float(value):.1f}%"

    def format_runtime(seconds):
        if seconds is None:
            return "--"
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"

    def format_file_size_short(size_bytes):
        if size_bytes is None or size_bytes == 0:
            return "--"
        for unit in ['B', 'KB', 'MB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.0f}{unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f}GB"

    # Extract resource warnings
    resource_warnings = data.get("resource_warnings", {})
    
    # Generate enhanced stages performance HTML
    stages_html = ""
    stage_analysis = data.get("stage_analysis", {})
    
    if stages:
        # Performance summary header
        total_workflow_time = stage_analysis.get("total_workflow_time", 0)
        completed_stages = stage_analysis.get("completed_stages", 0)
        total_stages = stage_analysis.get("total_stages", 0)
        longest_stage = stage_analysis.get("longest_stage", {})
        
        stages_html += f'''
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; text-align: center;">
                <div>
                    <div style="font-size: 1.2em; font-weight: bold; color: #2c3e50;">{total_workflow_time}s</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Total Time</div>
                </div>
                <div>
                    <div style="font-size: 1.2em; font-weight: bold; color: #2c3e50;">{completed_stages}/{total_stages}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Completed</div>
                </div>
                <div>
                    <div style="font-size: 1.2em; font-weight: bold; color: #e74c3c;">{longest_stage.get("name", "N/A").replace("_", " ").title()}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Bottleneck ({longest_stage.get("duration", 0)}s)</div>
                </div>
            </div>
        </div>
        '''
        
        # Individual stage details
        stages_html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">'
        for stage_name, stage_data in stages.items():
            status = stage_data.get("status", "not_started")
            duration = stage_data.get("duration", 0)
            started = stage_data.get("started")
            completed = stage_data.get("completed")
            
            # Status styling
            if status == "completed":
                status_color = "#27ae60"
                status_text = f"✅ Completed ({duration}s)"
            elif status == "in_progress":
                status_color = "#f39c12" 
                status_text = "🔄 In Progress"
            elif status == "incomplete":
                status_color = "#e74c3c"
                status_text = "❌ Incomplete"
            else:
                status_color = "#6c757d"
                status_text = "⏸️ Not Started"
            
            # Performance indicator
            perf_indicator = ""
            if status == "completed" and duration > 0:
                if duration == longest_stage.get("duration", 0):
                    perf_indicator = ' <span style="color: #e74c3c; font-size: 0.8em;">🐌 BOTTLENECK</span>'
                elif duration < stage_analysis.get("average_stage_time", 0):
                    perf_indicator = ' <span style="color: #27ae60; font-size: 0.8em;">⚡ FAST</span>'
            
            stages_html += f'''
                <div class="stat-item" style="border-left: 4px solid {status_color};">
                    <div class="stat-label">{stage_name.replace("_", " ").title()}{perf_indicator}</div>
                    <div class="stat-value" style="font-size: 0.9em; color: {status_color};">{status_text}</div>
                    {f'<div style="font-size: 0.8em; color: #6c757d; margin-top: 5px;">Started: {started}</div>' if started else ''}
                    {f'<div style="font-size: 0.8em; color: #6c757d;">Completed: {completed}</div>' if completed else ''}
                </div>
            '''
        stages_html += '</div>'
    else:
        stages_html = '<p style="color: #6c757d; text-align: center;">No stage data available</p>'

    # Generate API breakdown HTML
    api = data.get("api", {})
    api_breakdown_html = ""
    
    if api:
        total_calls = api.get("total_calls", 0)
        successful_calls = api.get("successful_calls", 0)
        failed_calls = api.get("failed_calls", 0)
        success_rate = (successful_calls / total_calls * 100) if total_calls > 0 else 0
        
        # API call breakdown by type
        nvd_cve_calls = api.get("nvd_cve_calls", 0)
        mitre_cve_calls = api.get("mitre_cve_calls", 0)
        nvd_cpe_calls = api.get("nvd_cpe_calls", 0)
        
        api_breakdown_html = f'''
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; text-align: center;">
                <div>
                    <div style="font-size: 1.2em; font-weight: bold; color: #2c3e50;">{total_calls}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Total Calls</div>
                </div>
                <div>
                    <div style="font-size: 1.2em; font-weight: bold; color: #27ae60;">{success_rate:.1f}%</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Success Rate</div>
                </div>
                <div>
                    <div style="font-size: 1.2em; font-weight: bold; color: #e74c3c;">{failed_calls}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Failed Calls</div>
                </div>
            </div>
        </div>
        
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
            <div class="stat-item" style="border-left: 4px solid #3498db;">
                <div class="stat-label">NVD CVE API</div>
                <div class="stat-value" style="font-size: 0.9em; color: #3498db;">🔍 {nvd_cve_calls} calls</div>
                <div style="font-size: 0.8em; color: #6c757d; margin-top: 5px;">CVE vulnerability data</div>
            </div>
            
            <div class="stat-item" style="border-left: 4px solid #9b59b6;">
                <div class="stat-label">MITRE CVE API</div>
                <div class="stat-value" style="font-size: 0.9em; color: #9b59b6;">🛡️ {mitre_cve_calls} calls</div>
                <div style="font-size: 0.8em; color: #6c757d; margin-top: 5px;">CVE metadata and references</div>
            </div>
            
            <div class="stat-item" style="border-left: 4px solid #e67e22;">
                <div class="stat-label">NVD CPE API</div>
                <div class="stat-value" style="font-size: 0.9em; color: #e67e22;">⚙️ {nvd_cpe_calls} calls</div>
                <div style="font-size: 0.8em; color: #6c757d; margin-top: 5px;">Common Platform Enumeration</div>
            </div>
        </div>
        '''
    else:
        api_breakdown_html = '<p style="color: #6c757d; text-align: center;">No API data available</p>'

    # Generate CPE query breakdown HTML
    cpe_stats = data.get("cpe_query_stats", {})
    cpe_breakdown_html = ""
    
    if cpe_stats and (cpe_stats.get("top_queries") or cpe_stats.get("top_result_queries")):
        top_queries = cpe_stats.get("top_queries", [])[:10]  # Ensure max 10
        top_result_queries = cpe_stats.get("top_result_queries", [])[:10]  # Ensure max 10
        total_queries = cpe_stats.get("total_cpe_queries", 0)
        
        # Get top result count for summary
        top_result_count = top_result_queries[0]["result_count"] if top_result_queries else 0
        top_result_query_string = top_result_queries[0]["query_string"] if top_result_queries else "N/A"
        
        # Summary stats
        cpe_breakdown_html = f'''
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; text-align: center;">
                <div>
                    <div style="font-size: 1.2em; font-weight: bold; color: #2c3e50;">{total_queries}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Unique Search Strings</div>
                </div>
                <div>
                    <div style="font-size: 1.2em; font-weight: bold; color: #34495e;">{top_queries[0]["unique_strings"] if top_queries else 0}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Largest Query</div>
                </div>
                <div>
                    <div style="font-size: 1.2em; font-weight: bold; color: #9b59b6;">{top_result_count}</div>
                    <div style="color: #6c757d; font-size: 0.9em;">Most Results</div>
                </div>
            </div>
        </div>
        
        <h4 style="margin: 20px 0 15px 0; color: #2c3e50;">📊 Top CVE Records by Number of Search Strings</h4>
        <div style="overflow-x: auto; margin-bottom: 30px;">
            <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <thead style="background: #34495e; color: white;">
                    <tr>
                        <th style="padding: 12px; text-align: left;">Rank</th>
                        <th style="padding: 12px; text-align: left;">CVE ID</th>
                        <th style="padding: 12px; text-align: center;">Unique Strings</th>
                        <th style="padding: 12px; text-align: center;">Affected Entries</th>
                        <th style="padding: 12px; text-align: center;">Strings/Entry</th>
                        <th style="padding: 12px; text-align: left;">Processed</th>
                    </tr>
                </thead>
                <tbody>
        '''
        
        for i, query in enumerate(top_queries, 1):
            # Determine row color based on query size
            if query["unique_strings"] >= 50:
                row_color = "#fff5f5"  # Light red for very large queries
                icon = "🔥"
            elif query["unique_strings"] >= 20:
                row_color = "#fffaf0"  # Light orange for large queries  
                icon = "⚡"
            elif query["unique_strings"] >= 10:
                row_color = "#f0fff4"  # Light green for medium queries
                icon = "📊"
            else:
                row_color = "#f8f9fa"  # Light gray for small queries
                icon = "📋"
                
            cpe_breakdown_html += f'''
                    <tr style="background: {row_color}; border-bottom: 1px solid #dee2e6;">
                        <td style="padding: 12px; font-weight: bold; color: #2c3e50;">{icon} #{i}</td>
                        <td style="padding: 12px;">
                            <code style="background: rgba(52, 73, 94, 0.1); padding: 2px 6px; border-radius: 3px; font-size: 0.9em;">{query["cve_id"]}</code>
                        </td>
                        <td style="padding: 12px; text-align: center; font-weight: bold; color: #e67e22;">{query["unique_strings"]}</td>
                        <td style="padding: 12px; text-align: center;">{query["affected_entries"]}</td>
                        <td style="padding: 12px; text-align: center;">{query["strings_per_entry"]}</td>
                        <td style="padding: 12px; font-size: 0.9em; color: #6c757d;">{query["timestamp"]}</td>
                    </tr>
            '''
        
        cpe_breakdown_html += '''
                </tbody>
            </table>
        </div>
        '''
        
        # Add top result queries table
        if top_result_queries:
            cpe_breakdown_html += '''
        <h4 style="margin: 20px 0 15px 0; color: #2c3e50;">🔍 Top Queries by Result Count</h4>
        <div style="overflow-x: auto; margin-bottom: 20px;">
            <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <thead style="background: #8e44ad; color: white;">
                    <tr>
                        <th style="padding: 12px; text-align: left;">Rank</th>
                        <th style="padding: 12px; text-align: left;">Query String</th>
                        <th style="padding: 12px; text-align: center;">Results</th>
                        <th style="padding: 12px; text-align: left;">CVE IDs</th>
                        <th style="padding: 12px; text-align: center;">Queries</th>
                        <th style="padding: 12px; text-align: center;">Source</th>
                    </tr>
                </thead>
                <tbody>
            '''
            
            for i, result_query in enumerate(top_result_queries, 1):
                # Determine row color based on result count
                result_count = result_query["result_count"]
                if result_count >= 1000:
                    row_color = "#fff0f5"  # Light pink for very large results
                    icon = "🚀"
                elif result_count >= 500:
                    row_color = "#f0f8ff"  # Light blue for large results
                    icon = "📈"
                elif result_count >= 100:
                    row_color = "#f0fff0"  # Light green for medium results
                    icon = "📊"
                else:
                    row_color = "#f8f9fa"  # Light gray for small results
                    icon = "📋"
                
                # Format CVE IDs with truncation if > 5
                cve_ids = result_query["cve_ids"]
                if len(cve_ids) > 5:
                    cve_display = ", ".join(cve_ids[:5]) + f", +{len(cve_ids)-5} more"
                else:
                    cve_display = ", ".join(cve_ids)
                
                # Format query string with truncation if too long
                query_string = result_query["query_string"]
                if len(query_string) > 40:
                    query_display = query_string[:37] + "..."
                else:
                    query_display = query_string
                
                # Format source with appropriate styling
                source = result_query.get("source", "unknown")
                source_display = ""
                source_color = ""
                if source == "api":
                    source_display = "🌐 API"
                    source_color = "#3498db"
                elif source == "cache":
                    source_display = "💾 Cache"
                    source_color = "#9b59b6"
                elif source == "both":
                    source_display = "🔄 Both"
                    source_color = "#e67e22"
                else:
                    source_display = "❓ Unknown"
                    source_color = "#95a5a6"
                
                cpe_breakdown_html += f'''
                        <tr style="background: {row_color}; border-bottom: 1px solid #dee2e6;">
                            <td style="padding: 12px; font-weight: bold; color: #2c3e50;">{icon} #{i}</td>
                            <td style="padding: 12px;">
                                <code style="background: rgba(142, 68, 173, 0.1); padding: 2px 6px; border-radius: 3px; font-size: 0.85em;" title="{query_string}">{query_display}</code>
                            </td>
                            <td style="padding: 12px; text-align: center; font-weight: bold; color: #8e44ad;">{result_count:,}</td>
                            <td style="padding: 12px; font-size: 0.85em; color: #2c3e50;">{cve_display}</td>
                            <td style="padding: 12px; text-align: center;">{result_query["total_queries"]}</td>
                            <td style="padding: 12px; text-align: center; font-weight: bold; color: {source_color};">{source_display}</td>
                        </tr>
                '''
            
            cpe_breakdown_html += '''
                    </tbody>
                </table>
            </div>
            '''
        else:
            cpe_breakdown_html += '''
        <h4 style="margin: 20px 0 15px 0; color: #2c3e50;">🔍 Top Queries by Result Count</h4>
        <div style="padding: 20px; text-align: center; background: #f8f9fa; border-radius: 8px; color: #6c757d;">
            No result data available - this data is only captured when actual API calls are made (not cache hits)
        </div>
        '''
        
        cpe_breakdown_html += '''
        <div style="margin-top: 15px; padding: 10px; background: #e8f4fd; border-left: 4px solid #3498db; border-radius: 4px;">
            <p style="margin: 0; font-size: 0.9em; color: #2c3e50;">
                <strong>💡 Interpretation:</strong> CVEs with more unique strings typically have more complex platform data (multiple vendors, products, or architectures) 
                requiring comprehensive CPE search coverage. The "Strings/Entry" ratio shows search strategy efficiency.
                <br><strong>Note:</strong> These metrics track the number of unique search strings queried against the /cpes/ API, not the number of results returned per query.
            </p>
        </div>
        '''
    else:
        cpe_breakdown_html = '<p style="color: #6c757d; text-align: center;">No CPE query data available</p>'

    # Generate detailed files HTML  
    file_stats = data.get("file_stats", {})
    detailed_files_html = ""
    
    detailed_files = file_stats.get("detailed_files", [])
    if detailed_files:
        detailed_files_html = f'''
        <h4 style="margin: 20px 0 15px 0; color: #2c3e50;">📁 Top Generated Files by Size</h4>
        <div style="overflow-x: auto; margin-bottom: 30px;">
            <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <thead style="background: #16a085; color: white;">
                    <tr>
                        <th style="padding: 12px; text-align: left;">Rank</th>
                        <th style="padding: 12px; text-align: left;">CVE ID</th>
                        <th style="padding: 12px; text-align: center;">File Size</th>
                        <th style="padding: 12px; text-align: center;">Platform Entries</th>
                        <th style="padding: 12px; text-align: center;">Processing Time</th>
                    </tr>
                </thead>
                <tbody>
        '''
        
        for i, file_info in enumerate(detailed_files, 1):
            # Determine row color based on file size
            file_size_bytes = file_info["file_size"]
            if file_size_bytes >= 10 * 1024 * 1024:  # 10MB+
                row_color = "#fff5f5"  # Light red for extremely large files
                rank_icon = "🔥"
            elif file_size_bytes >= 5 * 1024 * 1024:  # 5MB+
                row_color = "#fffaf0"  # Light orange for very large files
                rank_icon = "⚡"
            elif file_size_bytes >= 1 * 1024 * 1024:  # 1MB+
                row_color = "#f0fff4"  # Light green for large files
                rank_icon = "📊"
            else:
                row_color = "#f8f9fa"  # Light gray for normal files
                rank_icon = "📋"
                
            detailed_files_html += f'''
                    <tr style="background: {row_color}; border-bottom: 1px solid #dee2e6;">
                        <td style="padding: 12px; font-weight: bold; color: #2c3e50;">{rank_icon} #{i}</td>
                        <td style="padding: 12px;">
                            <code style="background: rgba(22, 160, 133, 0.1); padding: 2px 6px; border-radius: 3px; font-size: 0.9em;">{file_info["cve_id"]}</code>
                        </td>
                        <td style="padding: 12px; text-align: center; font-weight: bold; color: #16a085;">{file_info["file_size_formatted"]}</td>
                        <td style="padding: 12px; text-align: center;">{file_info["dataframe_rows"]}</td>
                        <td style="padding: 12px; text-align: center; color: #e67e22;">{file_info["processing_time_formatted"]}</td>
                    </tr>
            '''
        
        detailed_files_html += '''
                </tbody>
            </table>
        </div>
        
        <div style="margin-top: 15px; padding: 10px; background: #eafaf1; border-left: 4px solid #16a085; border-radius: 4px;">
            <p style="margin: 0; font-size: 0.9em; color: #2c3e50;">
                <strong>💡 File Analysis:</strong> Larger files typically indicate CVEs with more complex platform data, vendor variations, or extensive version ranges. 
                Platform entries show the complexity of affected systems, while processing time reflects both data complexity and system performance.
                <br><strong>Note:</strong> File sizes include HTML formatting, styling, and complete vulnerability analysis data.
            </p>
        </div>
        '''
    else:
        detailed_files_html = '''
        <h4 style="margin: 20px 0 15px 0; color: #2c3e50;">📁 Top Generated Files by Size</h4>
        <p style="color: #6c757d; text-align: center;">No detailed file data available</p>
        '''

    # Generate resource warnings HTML
    resource_warnings_html = ""
    total_warnings = sum(resource_warnings.values()) if resource_warnings else 0
    
    if total_warnings > 0:
        resource_warnings_html = f'''
            <div class="metric-card warning" style="border-left-color: #e67e22;">
                <div class="metric-title">Resource Warnings</div>
                <div class="metric-value" style="color: #e67e22;">{total_warnings}</div>
                <div class="metric-subtitle">
                    Cache Bloat: {resource_warnings.get("cache_bloat_warnings", 0)}<br>
                    Memory: {resource_warnings.get("memory_warnings", 0)}<br>
                    Large Files: {resource_warnings.get("large_file_warnings", 0)}<br>
                    Global State: {resource_warnings.get("global_state_warnings", 0)}
                </div>
            </div>
        '''
    else:
        resource_warnings_html = f'''
            <div class="metric-card success" style="border-left-color: #27ae60;">
                <div class="metric-title">Resource Health</div>
                <div class="metric-value" style="color: #27ae60;">Good</div>
                <div class="metric-subtitle">No resource warnings detected</div>
            </div>
        '''
    
    # Generate recent activity HTML
    recent_activity_html = ""
    if recent_activity:
        for entry in recent_activity[:10]:  # Show last 10 entries
            level = entry.get("level", "info").lower()
            timestamp = entry.get("timestamp", "")
            message = entry.get("message", "")
            recent_activity_html += f'''
                <div class="log-entry {level}">
                    <div class="log-meta">
                        <span class="timestamp">{timestamp}</span>
                        <span class="level {level}">{level}</span>
                    </div>
                    <div class="log-message">{message}</div>
                </div>
            '''
    else:
        recent_activity_html = '<div style="padding: 20px; text-align: center; color: #6c757d;">No recent activity data available</div>'

    # Generate warning and error details
    def generate_log_details(log_entries, max_entries=20):
        if not log_entries:
            return '<div style="padding: 10px; color: #6c757d; text-align: center;">No entries found</div>'
        
        # Sort entries: CVE-related first, then by timestamp (newest first)
        sorted_entries = sorted(log_entries, key=lambda x: (
            x.get("cve_id") is None,  # CVE entries first (False sorts before True)
            -datetime.fromisoformat(x.get("timestamp", "1970-01-01T00:00:00")).timestamp()  # Newest first
        ))
        
        total_entries = len(sorted_entries)
        show_all = total_entries <= max_entries
        
        html = ""
        for i, entry in enumerate(sorted_entries):
            timestamp = entry.get("timestamp", "")
            message = entry.get("message", "")
            cve_id = entry.get("cve_id")
            
            # Format timestamp
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                formatted_time = dt.strftime("%H:%M:%S")
            except:
                formatted_time = timestamp
            
            # Format message: Start with CVE ID link if available, then the message
            if cve_id:
                cve_link = f'<a href="https://hashmire.github.io/cpeApplicabilityGeneratorPages/generated_pages/{cve_id}.html" target="_blank" style="color: #3498db; text-decoration: none; font-weight: bold;">{cve_id}</a>'
                # Remove CVE ID from message if it's already there to avoid duplication
                clean_message = message.replace(cve_id, "").strip()
                if clean_message.startswith(":") or clean_message.startswith("-"):
                    clean_message = clean_message[1:].strip()
                formatted_message = f"{cve_link}: {clean_message}"
            else:
                formatted_message = message
            
            entry_class = "warning" if "warning" in entry.get("level", "").lower() else "error"
            
            # Hide entries beyond max_entries initially
            style_attr = ' style="display: none;"' if i >= max_entries else ''
            extra_class = ' log-entry-extra' if i >= max_entries else ''
            
            html += f'''
                <div class="log-entry-detail {entry_class}{extra_class}"{style_attr}>
                    <div class="timestamp">{formatted_time}</div>
                    <div>{formatted_message}</div>
                </div>
            '''
        
        # Add "Show All" button if there are more entries
        if not show_all:
            remaining = total_entries - max_entries
            html += f'''
                <div class="show-all-button" style="text-align: center; padding: 15px; margin: 10px 0; background: #f8f9fa; border-radius: 8px; cursor: pointer;" onclick="showAllLogEntries(this)">
                    <div style="color: #3498db; font-weight: bold;">Show All {total_entries} Entries</div>
                    <div style="color: #6c757d; font-size: 0.9em;">({remaining} more entries)</div>
                </div>
            '''
        
        return html
    
    warning_details = generate_log_details(warnings)
    error_details = generate_log_details(errors)

    # Prepare generation info
    generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data_timestamp = data.get("metadata", {}).get("last_updated", generation_time)
    log_file_path = data.get("metadata", {}).get("log_file", "Unknown")
    file_size_bytes = data.get("metadata", {}).get("file_size", 0)
    
    # Format log file name (extract just the filename)
    if log_file_path and log_file_path != "Unknown":
        log_file_display = Path(log_file_path).name
    else:
        log_file_display = "Unknown"
    
    # Format file size
    def format_file_size(size_bytes):
        if size_bytes == 0 or size_bytes == "Unknown":
            return "Unknown"
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    file_size_display = format_file_size(file_size_bytes)
    
    # Calculate time elapsed since data generation
    def calculate_time_elapsed(data_timestamp, current_time):
        try:
            if data_timestamp and data_timestamp != current_time:
                data_dt = datetime.fromisoformat(data_timestamp.replace('Z', '+00:00'))
                current_dt = datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")
                elapsed = current_dt - data_dt
                
                total_seconds = int(elapsed.total_seconds())
                if total_seconds < 60:
                    return f"{total_seconds}s ago"
                elif total_seconds < 3600:
                    minutes = total_seconds // 60
                    return f"{minutes}m ago"
                else:
                    hours = total_seconds // 3600
                    minutes = (total_seconds % 3600) // 60
                    return f"{hours}h {minutes}m ago"
            return "just now"
        except:
            return "unknown"
    
    time_elapsed = calculate_time_elapsed(data_timestamp, generation_time)

    # Handle ISO timestamp format
    if data_timestamp and data_timestamp != generation_time:
        try:
            dt = datetime.fromisoformat(data_timestamp.replace('Z', '+00:00'))
            data_timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass

    # Fill template
    html_content = html_template.format(
        tool_name=TOOL_NAME,
        tool_version=TOOL_VERSION,
        generation_time=generation_time,
        time_elapsed=time_elapsed,
        log_file_display=log_file_display,
        file_size_display=file_size_display,
        total_cves=format_number(processing.get("total_cves")),
        processed_cves=format_number(processing.get("processed_cves")),
        remaining_cves=format_number(processing.get("remaining_cves")),
        cache_entries=format_number(cache.get("total_entries")),
        cache_hit_rate=format_percentage(cache.get("hit_rate", 0)),
        api_calls=format_number(api.get("total_calls")),
        runtime=format_runtime(performance.get("total_runtime")),
        progress_percent=format_percentage(processing.get("progress_percentage", 0)),
        current_cve=processing.get("current_cve", "--"),
        eta_simple=processing.get("eta_simple", "--"),
        calls_saved=format_number(cache.get("api_calls_saved")),
        files_generated=format_number(file_stats.get("files_generated", 0)),
        largest_file=format_file_size_short(file_stats.get("largest_file_size", 0)),
        smallest_file=format_file_size_short(file_stats.get("smallest_file_size", 0)),
        average_speed=format_number(performance.get("average_time", 0), 2),
        fastest_cve_time=format_number(speed_stats.get("fastest_cve_time", 0), 2),
        slowest_cve_time=format_number(speed_stats.get("slowest_cve_time", 0), 2),
        mapping_percentage=format_percentage(mapping_stats.get("mapping_percentage", 0)),
        total_mappings=format_number(mapping_stats.get("total_mappings_found", 0)),
        cache_file_size=cache.get("cache_file_size_formatted", "Not found"),
        total_cpe_queries=format_number(data.get("cpe_query_stats", {}).get("total_cpe_queries", 0)),
        largest_cpe_query=format_number(data.get("cpe_query_stats", {}).get("largest_query_results", 0)),
        largest_cve_query_cve=data.get("cpe_query_stats", {}).get("largest_query_cve", "N/A"),
        top_result_count=format_number(data.get("cpe_query_stats", {}).get("top_result_queries", [{}])[0].get("result_count", 0) if data.get("cpe_query_stats", {}).get("top_result_queries", []) else 0),
        top_result_query=(data.get("cpe_query_stats", {}).get("top_result_queries", [{}])[0].get("query_string", "N/A")[:30] + ("..." if len(data.get("cpe_query_stats", {}).get("top_result_queries", [{}])[0].get("query_string", "")) > 30 else "")) if data.get("cpe_query_stats", {}).get("top_result_queries", []) else "N/A",
        info_count=format_number(log_stats.get("info_count", 0)),
        debug_count=format_number(log_stats.get("debug_count", 0)),
        warning_count=format_number(log_stats.get("warning_count", 0)),
        error_count=format_number(log_stats.get("error_count", 0)),
        total_lines=format_number(log_stats.get("total_lines", 0)),
        warning_details=warning_details,
        error_details=error_details,
        resource_warnings_card=resource_warnings_html,
        stages_progress=stages_html,
        api_breakdown=api_breakdown_html,
        cpe_breakdown=cpe_breakdown_html,
        detailed_files=detailed_files_html
    )

    # Write HTML file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return True
    except Exception as e:
        print(f"Error writing HTML file: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Generate local CVE analysis dashboard')
    parser.add_argument('--input', '-i', 
                       default='dashboard_data.json',
                       help='Input JSON data file (default: dashboard_data.json from reports/)')
    parser.add_argument('--output', '-o', 
                       default='local_dashboard.html',
                       help='Output HTML file (default: local_dashboard.html in reports/)')
    
    args = parser.parse_args()
    
    print("Generating local dashboard...")
    
    # Resolve paths
    input_path = resolve_input_path(args.input)
    output_path = resolve_output_path(args.output)
    
    # Load data
    data = load_dashboard_data(input_path)
    if data is None:
        print("❌ Failed to load dashboard data")
        return 1
    
    # Generate HTML
    if generate_dashboard_html(data, output_path):
        print(f"Local dashboard generated: {output_path}")
        print(f"Open the file directly in your browser to view the dashboard")
        return 0
    else:
        print("Error generating dashboard")
        return 1

if __name__ == "__main__":
    exit(main())
