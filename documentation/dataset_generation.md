# Dataset Generation

The `generate_dataset.py` utility provides intelligent dataset management capabilities with unified runs structure integration.

## Features

### 1. Date-based CVE Filtering

Query CVEs based on their `lastModified` date using NVD API parameters:

- `--last-days N` - CVEs modified in the last N days (max 120)
- `--start-date` and `--end-date` - CVEs modified within a specific date range

**Examples:**

```bash
# CVEs modified in the last 30 days
python generate_dataset.py --last-days 30

# CVEs modified in January 2024
python generate_dataset.py --start-date 2024-01-01 --end-date 2024-01-31
```

### 2. Differential Updates

Generate datasets containing only CVEs that have changed since your last run:

```bash
# Generate dataset for CVEs modified since the last run
python generate_dataset.py --since-last-run
```

### 3. Run Tracking

All dataset generation runs are tracked in run-specific directories under `runs/[timestamp]_[context]/`. View your history:

```bash
# Show when the last dataset generation occurred
python generate_dataset.py --show-last-run
```

### 4. Integrated Processing

The analysis tool runs automatically after dataset generation by default:

```bash
# Generate dataset and analyze it (default behavior)
python generate_dataset.py --last-days 7

# Skip analysis if you only want the dataset
python generate_dataset.py --last-days 7 --no-analysis
```

## Unified Runs Structure

All dataset generation outputs are contained in run-specific directories:

```bash
# Traditional status-based generation - analysis runs automatically
python generate_dataset.py --statuses "Received" "Awaiting Analysis"

# Test mode - analysis runs automatically  
python generate_dataset.py --test-mode

# Legacy behavior: skip analysis if you only want dataset generation
python generate_dataset.py --test-mode --no-analysis
```

### Output Structure

Each dataset generation creates a timestamped run directory:

```text
runs/[timestamp]_[context]/
├── datasets/           # Generated dataset files
│   ├── dataset_tracker.json  # Run tracking metadata
│   └── [output_files]         # CVE dataset files
├── logs/              # Generation logs
├── generated_pages/   # HTML reports (if analysis enabled)
└── reports/          # Dashboard data (if analysis enabled)
```

## Real-time Monitoring

The dataset generation process provides real-time monitoring through an integrated dashboard system:

### Dashboard Access

When running `generate_dataset.py`, the system automatically:

- Starts real-time data collection in the background
- Generates a live dashboard accessible at `dashboards/generateDatasetDashboard.html`
- Updates progress, timing, and statistics every 5 seconds

### Dashboard Features

- **Progress Tracking**: Real-time progress updates with accurate ETA calculations
- **Warning/Error Attribution**: Links warnings and errors to specific processing stages
- **Resource Monitoring**: Tracks processing rates, API usage, and system performance
- **File Status**: Shows current files being processed and completion statistics

### Viewing the Dashboard

1. Open `dashboards/generateDatasetDashboard.html` in your browser during dataset generation
2. The dashboard automatically refreshes to show current progress
3. Use the refresh button to manually update the view or switch between different run files

## Date Range Limitations

- Maximum date range: 120 consecutive days (NVD API limitation)
- Dates can be in YYYY-MM-DD format or full ISO format
- The system automatically handles URL encoding and timezone offsets

## Tracking File Format

The tracking system creates `dataset_tracker.json` within each run directory with this structure:

```json
{
  "last_full_pull": "2024-07-02T10:30:00.000000",
  "run_history": [
    {
      "run_id": "status_based_20240702_103000",
      "run_type": "status_based",
      "timestamp": "2024-07-02T10:30:00.000000",
      "cve_count": 150,
      "output_file": "runs/[timestamp]/datasets/cve_dataset.txt"
    }
  ]
}
```

## Common Workflows

**Initial Setup:**

```bash
# Generate your first dataset for recent CVEs (analysis runs automatically)
python generate_dataset.py --last-days 30 --output initial_dataset.txt
```

**Regular Updates:**

```bash
# Daily/weekly differential updates (analysis runs automatically)
python generate_dataset.py --since-last-run

# Skip re-analysis if only updating dataset
python generate_dataset.py --since-last-run --no-analysis
```

**Investigating Specific Periods:**

```bash
# Analyze CVEs from a specific incident timeframe
python generate_dataset.py --start-date 2024-06-01 --end-date 2024-06-15 --output incident_analysis.txt
```

## Entry Point Usage

**Important:** Use `generate_dataset.py` from the project root directory. All outputs are automatically organized in the unified runs structure.
