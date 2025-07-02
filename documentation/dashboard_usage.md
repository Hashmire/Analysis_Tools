# Hashmire/Analysis_Tools Dashboard

A refreshable, real-time dashboard that provides insights and statistics from Hashmire/Analysis_Tools log files.

## 📋 Overview

The dashboard system consists of several components that work together to provide real-time monitoring of the Hashmire/Analysis_Tools:

- **Log Analyzer** (`src/analysis_tool/utilities/log_analyzer.py`) - Parses log files and extracts metrics
- **Local Dashboard** (`reports/local_dashboard.html`) - Self-contained HTML with embedded data (works with local files)
- **Dashboard Generator** (`src/analysis_tool/utilities/generate_local_dashboard.py`) - Creates local dashboard with embedded data
- **Update Scripts** - Automated scripts to keep the dashboard current

## 🚀 Quick Start

### Method 1: Automatic Integration (Recommended)

The dashboard is **automatically integrated** into the Hashmire/Analysis_Tools workflow:

```bash
# Run the Hashmire/Analysis_Tools normally - dashboard updates automatically!
cd src/analysis_tool
python analysis_tool.py [your normal CVE analysis arguments]

# 📊 Open reports/local_dashboard.html to watch real-time progress
# 🔄 Data refreshes automatically every 100 CVEs during processing
# ✅ Final update occurs at completion
```

**Real-time Monitoring:**

1. **Start**: Dashboard created with initial data
2. **During Processing**: JSON updates every 100 CVEs (dashboard auto-refreshes)
3. **Completion**: Final data update with complete results

### Method 2: Manual Dashboard Generation

```bash
# Generate dashboard from existing log data
python src/analysis_tool/utilities/log_analyzer.py --summary

# The local dashboard (reports/local_dashboard.html) is automatically updated
# Open reports/local_dashboard.html directly in your browser
```

### Method 3: JSON Data Only

```bash
# Generate only JSON data without local dashboard
python src/analysis_tool/utilities/log_analyzer.py --summary --no-local-dashboard
```

## 📊 Dashboard Features

### Real-time Metrics

- **Processing Statistics**: Total CVEs, processed count, progress percentage
- **Performance Metrics**: Processing rate, average time per CVE, total runtime
- **Cache Analytics**: CPE cache size, hit rate, API calls saved
- **System Status**: Current CVE being processed, ETA, remaining work

### Visual Components

- **Progress Bars**: Overall completion, cache efficiency
- **Stage Tracker**: Current processing stage (Init → CVE Data → CPE Gen → etc.)
- **Log Statistics**: Breakdown of DEBUG/INFO/WARNING/ERROR messages
- **Recent Activity**: Live feed of recent log entries
- **Warning/Error Drilldown**: Every event is linked to the relevant CVE file for fast troubleshooting

### Interactive Features

- **Show All**: Expand to view all warning/error events
- **Responsive Design**: Works on desktop and mobile devices

## 📁 File Structure

```text
Analysis_Tools/
├── src/analysis_tool/utilities/
│   ├── log_analyzer.py          # Main log parsing script
│   ├── generate_local_dashboard.py # Dashboard HTML generator
├── generated_pages/             # Main HTML vulnerability reports
├── test_output/                 # Test-generated HTML files
├── reports/
│   ├── local_dashboard.html     # Self-contained local dashboard
│   ├── dashboard_data.json      # Generated data file
├── logs/
│   └── *.log                    # Hashmire/Analysis_Tools log files
├── cache/                       # CPE cache files
├── datasets/                    # Generated CVE datasets
└── temp/                        # Temporary files
```

## 🔧 Configuration

### Local Dashboard Generator

The local dashboard generator creates a self-contained HTML file with embedded data, perfect for local file access without CORS issues:

```bash
python src/analysis_tool/utilities/generate_local_dashboard.py --help

Options:
  --input FILE, -i FILE    Input JSON data file (default: reports/dashboard_data.json)
  --output FILE, -o FILE   Output HTML file (default: reports/local_dashboard.html)
```

**Benefits of Local Dashboard:**

- 📁 Works directly from local files (no web server needed)
- 🚀 No CORS or network security restrictions
- 📱 Fully responsive and mobile-friendly
- 💾 Self-contained (all data embedded in HTML)

### Log Analyzer Options

```bash
python src/analysis_tool/utilities/log_analyzer.py --help

Options:
  --log-dir DIRECTORY     Directory containing log files (default: logs)
  --log-file FILE         Specific log file to analyze
  --output FILE           Output JSON file (default: reports/dashboard_data.json)
  --summary              Print summary to console
```

### Dashboard Data Format

The `dashboard_data.json` file contains structured data including:

- Processing metrics (total CVEs, progress, timing)
- Performance statistics (rates, averages, runtime)
- Cache information (size, hit rates, efficiency)
- API usage (call counts, success/failure rates)
- Log statistics (message counts by level)
- Recent activity (latest log entries)
- All warning/error events with CVE links

### Enhanced Dashboard Features

The dashboard now includes several advanced analysis sections:

**🔍 Interactive Elements:**

- **Clickable metric cards** that smoothly scroll to detailed sections
- **Visual indicators** for performance bottlenecks and fast operations
- **Hover tooltips** providing additional context

**⚡ Workflow Performance Analysis:**

- **Stage timing breakdown** with duration tracking for each workflow stage
- **Bottleneck detection** automatically identifies the slowest stages
- **Efficiency metrics** showing completion rates and progress
- **Performance indicators** (BOTTLENECK, FAST markers) for quick assessment

**🌐 API Performance Breakdown:**

- **Detailed API call analysis** by type (NVD CVE, MITRE CVE, NVD CPE)
- **Success rate tracking** with failed call monitoring
- **Call volume analysis** showing API usage patterns

**🔍 CPE Query Analysis:**

- **Top CVE records by complexity** ranked by number of unique search strings
- **Top queries by result count** showing which queries return the most data
- **Source tracking** (API vs Cache) for performance optimization
- **Query efficiency metrics** for search strategy analysis

**⚠️ Resource Monitoring:**

- **Resource warnings detection** for cache bloat and memory issues
- **System health indicators** tracking performance warnings
- **File size monitoring** for large output detection
- **Global state tracking** for system stability

## 🔄 Automated Updates

The dashboard is **automatically integrated** into the main CVE analysis workflow:

- **At startup**: Dashboard created immediately with initial/existing data  
- **Every 100 CVEs**: Dashboard JSON data is updated silently in the background
- **Real-time monitoring**: Open the HTML dashboard to watch progress live
- **At completion**: Final dashboard update with complete results
- **Zero configuration**: Works out of the box with existing CVE analysis runs

**Benefits:**

- 📊 **Immediate feedback**: Dashboard available as soon as CVE processing starts
- 📈 **Live updates**: Watch progress in real-time
- 🚀 **No setup required**: Automatic integration with zero configuration
- 💾 **Works offline**: Local dashboard requires no web server

## 🎯 Use Cases

- **Real-time Performance Monitoring**: Monitor processing performance with live workflow stage analysis
- **Bottleneck Identification**: Automatically identify performance bottlenecks with stage timing analysis
- **Resource Health Monitoring**: Track resource warnings and system health indicators
- **API Usage Analysis**: Detailed breakdown of API calls by type with success rate tracking
- **Cache Efficiency Optimization**: Monitor cache performance and identify optimization opportunities
- **Query Performance Analysis**: Analyze CPE query complexity and result patterns
- **Error Detection and Troubleshooting**: View detailed log activity and error tracking as it happens
- **Long-running Job Tracking**: Track progress of extensive CVE analysis runs with accurate ETAs
- **Historical Performance Reporting**: Generate comprehensive performance reports from log data
- **Interactive Data Exploration**: Click through dashboard sections for detailed analysis

## 📝 Notes

- Dashboard updates automatically every 100 CVEs during processing
- Log analyzer processes the most recent log file by default
- All timestamps are displayed in local time zone
- Progress calculations are based on the "Processing CVE X/Y" log entries
- Cache statistics track CPE dictionary cache performance
- Error detection includes both explicit ERROR level logs and failed API responses
- Every warning/error event is linked to the relevant CVE file for fast troubleshooting

---

For more information about the Hashmire/Analysis_Tools itself, see the main project documentation.
