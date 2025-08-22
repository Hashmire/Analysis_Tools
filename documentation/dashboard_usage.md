# Real-time Dashboard System

Real-time monitoring for CVE analysis and dataset generation workflows with automatic data collection and interactive visualization.

## Dashboard Types

### 1. Dataset Generation Dashboard (`dashboards/generateDatasetDashboard.html`)

- **Real-time progress tracking** during CVE processing with ETA calculations
- **Performance metrics** including processing speeds, cache hit rates, API statistics
- **Error monitoring** with categorized warnings/errors attributed to specific CVE records
- **File**: Load `generateDatasetReport.json` from any run's `logs/` directory

### 2. Source Data Concern Dashboard (`dashboards/sourceDataConcernDashboard.html`)

- **Data quality monitoring** for source data integrity issues
- **Badge system integration** with interactive concern visualization
- **File**: Load `sourceDataConcernReport.json` from any run's `logs/` directory

### 3. Main Dashboard Hub (`dashboards/index.html`)

- **Run history browser** for accessing previous analysis results
- **System overview** with project-wide monitoring
- **Quick access** to recent runs and specialized dashboards

## Automatic Data Collection

### Automatic Integration

Dashboard data collection requires no manual setup:

```bash
# CVE analysis - dashboard data generated automatically
python run_tools.py --cve CVE-2024-20515

# Dataset generation - real-time monitoring available  
python generate_dataset.py --last-days 30

# Dashboard files automatically saved to:
# runs/[timestamp]_[context]/logs/generateDatasetReport.json
# runs/[timestamp]_[context]/logs/sourceDataConcernReport.json
```

### Real-time Updates

- **Live data collection** during processing with 5-second update intervals
- **Automatic file updates** using atomic operations to prevent corruption
- **CVE attribution** for warnings/errors captured in real-time

## File Structure

Each analysis run creates dashboard files:

```text
runs/[timestamp]_[context]/
├── logs/
│   ├── generateDatasetReport.json    # Main dashboard data
│   ├── sourceDataConcernReport.json  # Data quality concerns
│   └── [timestamp]_[context].log     # Detailed processing log
└── generated_pages/                  # HTML vulnerability reports
```

## Dashboard Usage

### Loading Data

1. **Open dashboard** in browser:
   - **Generate Dataset Dashboard**: `dashboards/generateDatasetDashboard.html`  
   - **Source Data Concern Dashboard**: `dashboards/sourceDataConcernDashboard.html`
2. **Select JSON file** from any run's `logs/` directory using file picker:
   - For Generate Dataset Dashboard: Load `generateDatasetReport.json`
   - For Source Data Concern Dashboard: Load `sourceDataConcernReport.json`
3. **Load dashboard** data automatically displays with interactive sections
4. **Use refresh button** to reload the same file with updated data

### Dashboard Data Structure

The **Generate Dataset Dashboard** loads `generateDatasetReport.json` containing:

- **Processing metrics** (total CVE records, progress, current CVE, ETA)
- **Performance data** (processing rates, timing, cache hit rates)
- **API statistics** (call counts, success rates, breakdowns by API type)
- **Warnings/errors** (categorized by type, attributed to specific CVE records)
- **File generation stats** (sizes, counts, completion rates)

The **Source Data Concern Dashboard** loads `sourceDataConcernReport.json` containing:

- **Platform entry analysis** (source data integrity issues by entry)
- **Concern categorization** (vendor mismatches, missing data, format issues)
- **Source attribution** (concerns linked to specific NVD source providers)
- **CVE-level aggregation** (concern patterns across vulnerability records)

## Key Features

**Generate Dataset Dashboard:**

- **Real-time progress tracking** with accurate ETA calculations during CVE processing
- **Error attribution** linking warnings/errors to specific CVE records being processed
- **Cache performance monitoring** with hit rates and API call savings
- **Interactive performance sections** with clickable metrics and detailed analysis

**Source Data Concern Dashboard:**

- **Data quality monitoring** for platform entry source data integrity issues
- **Concern categorization** by type with drill-down capabilities
- **Source provider analysis** identifying problematic NVD data sources
- **CVE-level investigation** tools for quality assurance workflows

**Both Dashboards:**

- **Responsive design** works on desktop and mobile devices
- **File-based loading** with automatic refresh capabilities
- **Interactive data exploration** with search and filtering features

## Source Data Concerns Dashboard

### Purpose

The Source Data Concerns Dashboard (`dashboards/sourceDataConcernDashboard.html`) provides specialized monitoring for data quality issues found in platform entries during CVE analysis.

### Data Source

Loads `sourceDataConcernReport.json` files from run directories containing:

- **Platform entry analysis** with source data integrity issues
- **Concern categorization** by type (vendor mismatches, missing data, format issues)
- **Source attribution** linking concerns to specific NVD source providers
- **CVE-level aggregation** showing concern patterns across vulnerability records

### Dashboard Features

**Statistical Overview:**

- Total CVE records processed
- Platform entries analyzed
- Total concerns identified
- Unique data sources with issues
- Entries with concerns
- Distinct concern types found

**Interactive Data Exploration:**

- **Source provider analysis** with concern breakdowns by NVD source
- **CVE-level drill-down** showing platform entries with specific concerns
- **Concern type filtering** to focus on specific data quality issues
- **Search functionality** to locate specific CVE records or sources

**Visual Components:**

- Statistical cards with concern counts and percentages
- Concern type distribution charts
- Source provider quality metrics
- Platform entry concern details with contextual information

### Usage

1. **Open dashboard** in browser: `dashboards/sourceDataConcernDashboard.html`
2. **Load data file** using file picker to select `sourceDataConcernReport.json` from any run
3. **Review statistics** for overall data quality assessment
4. **Explore sources** to identify problematic data providers
5. **Investigate specific concerns** using search and filtering features

---

**Usage Summary:**

- **Generate Dataset Dashboard**: Open `dashboards/generateDatasetDashboard.html`, load `generateDatasetReport.json` files for CVE processing monitoring
- **Source Data Concern Dashboard**: Open `dashboards/sourceDataConcernDashboard.html`, load `sourceDataConcernReport.json` files for data quality analysis
