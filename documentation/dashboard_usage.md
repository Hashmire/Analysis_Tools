# Dashboard System

Monitoring dashboards for monitoring processing progress, performance and source data concerns.

## Dashboard Types

### 1. Dataset Generation Dashboard (`dashboards/generateDatasetDashboard.html`)

- **Progress tracking** during CVE processing with ETA calculations
- **Performance metrics** including processing speeds, cache hit rates, API statistics
- **Error monitoring** with categorized warnings/errors attributed to specific CVE records
- **File**: Load `generateDatasetReport.json` from any run's `logs/` directory

### 2. Source Data Concern Dashboard (`dashboards/sourceDataConcernDashboard.html`)

- **Data quality monitoring** for source data integrity issues
- **Badge system integration** with interactive concern visualization
- **File**: Load `sourceDataConcernReport.json` from any run's `logs/` directory

## Automatic Data Collection

### Automatic Integration

Dashboard data collection requires no manual setup:

```bash
# CVE analysis - dashboard data generated automatically
python run_tools.py --cve CVE-2024-20515

# Dataset generation - monitoring available  
python generate_dataset.py --last-days 30

# Dashboard files automatically saved to:
# runs/[timestamp]_[context]/logs/generateDatasetReport.json
# runs/[timestamp]_[context]/logs/sourceDataConcernReport.json
```

## File Structure

Each run creates dashboard files:

```text
runs/[timestamp]_[context]/
├── logs/
│   ├── generateDatasetReport.json    
│   └── sourceDataConcernReport.json  
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
- **Source attribution** (concerns linked to specific CVE data contributors)
- **CVE-level aggregation** (concern patterns across vulnerability records)

