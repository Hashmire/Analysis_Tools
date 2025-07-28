# Hashmire/Analysis_Tools Dashboard

A real-time dashboard that provides insights and statistics from Hashmire/Analysis_Tools processing runs.

## 📋 Overview

The dashboard system provides real-time monitoring of Hashmire/Analysis_Tools workflows:

- **Global Dashboard** (`dashboards/index.html`) - Project-wide monitoring dashboard
- **Run-specific Reports** - Individual run analysis within `runs/[timestamp]/reports/`
- **Log Analysis** - Comprehensive log parsing and metrics extraction
- **Real-time Updates** - Live progress monitoring during processing

## 🚀 Quick Start

### Method 1: Automatic Integration (Recommended)

The dashboard updates automatically during Hashmire/Analysis_Tools workflows:

```bash
# Run Hashmire/Analysis_Tools - dashboard updates automatically
python run_tools.py --cve CVE-2024-20515

# Generate datasets - dashboard updates automatically  
python generate_dataset.py --last-days 30

# Open dashboards/index.html to monitor system-wide activity
# Individual run data available in runs/[timestamp]/reports/
```

**Real-time Monitoring:**

1. **Start**: Dashboard initialized with run data
2. **During Processing**: Updates consistently as data is processed
3. **Completion**: Final update with complete results
4. **Run Isolation**: Each run maintains separate dashboard data

### Method 2: Run-specific Analysis

```bash
# Analyze specific run data
# Run data automatically contained in runs/[timestamp]/reports/

# Open specific run reports for detailed analysis
# Each run maintains isolated dashboard data
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
├── run_tools.py                 # Main CVE analysis entry point
├── generate_dataset.py          # Dataset generation entry point
├── src/analysis_tool/
│   └── local_dashboard/         # Dashboard utilities
├── runs/                       # All analysis outputs (unified structure)
│   └── [timestamp]_[context]/  # Individual run directories
│       ├── generated_pages/    # HTML vulnerability reports
│       ├── logs/              # Run-specific log files
│       └── reports/           # Dashboard data for this run
├── dashboards/                 # Global dashboard files
│   └── index.html             # Project-wide monitoring dashboard
└── cache/                     # Shared CPE cache
```

## 🔧 Configuration

### Dashboard Data Structure

Dashboard data is maintained within each run directory:

```text
runs/[timestamp]_[context]/
├── reports/
│   ├── dashboard_data.json     # Run-specific dashboard data
│   └── [other_reports]         # Additional analysis reports
└── logs/                       # Run-specific logs
```

**Benefits of Run-isolated Dashboards:**

- 📁 Complete run isolation prevents data mixing
- 🚀 Fast access to specific run results
- 📱 Self-contained analysis for each workflow
- 💾 Historical run data preservation

### Dashboard Data Format

Dashboard data within each run includes:

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

The dashboard integrates automatically with all Analysis Tools workflows:

- **At startup**: Dashboard initialized with run data
- **Real-time monitoring**: Open dashboards to watch progress live
- **At completion**: Final dashboard update with complete results
- **Run isolation**: Each run maintains separate dashboard data

**Benefits:**

- 📊 **Immediate feedback**: Dashboard available as soon as processing starts
- 📈 **Live updates**: Watch progress in real-time
- 🚀 **No setup required**: Automatic integration with zero configuration
- 💾 **Run isolation**: Complete separation of run data
- 🔍 **Historical analysis**: Access any previous run's dashboard data

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
- All run data is isolated in run-specific directories  
- Global dashboard provides system-wide monitoring
- All timestamps are displayed in local time zone
- Progress calculations based on processing log entries
- Cache statistics track CPE dictionary cache performance
- Error detection includes both ERROR level logs and failed API responses
- Every warning/error event is linked to the relevant CVE file for fast troubleshooting
- Run-specific dashboards provide detailed analysis for individual workflows

---

For more information about the Hashmire/Analysis_Tools system, see the main project documentation.
