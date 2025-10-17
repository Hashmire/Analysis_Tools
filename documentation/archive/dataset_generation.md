# Dataset Generation

The `generate_dataset.py` utility generates CVE datasets from NVD API with integrated analysis workflow.

## Command-Line Options

### Date-based Filtering

Query CVEs by `lastModified` date:

```bash
# CVEs modified in the last N days (max 120)
python generate_dataset.py --last-days 30

# CVEs modified within date range  
python generate_dataset.py --start-date 2024-01-01 --end-date 2024-01-31

# CVEs modified since last run
python generate_dataset.py --since-last-run
```

### Status-based Filtering (Default)

```bash
# Default: CVEs with statuses "Received", "Awaiting Analysis", "Undergoing Analysis"
python generate_dataset.py

# Custom statuses
python generate_dataset.py --statuses "Received" "Modified"
```

### Analysis Integration

Analysis runs automatically unless disabled:

```bash
# Generate dataset and run analysis (default)
python generate_dataset.py --last-days 7

# Generate dataset only
python generate_dataset.py --last-days 7 --no-analysis

# Pass options to analysis tool
python generate_dataset.py --last-days 7 --external-assets
```

### Information Commands

```bash
# Show when last dataset generation occurred
python generate_dataset.py --show-last-run
```

## Output Structure

Each dataset generation creates a timestamped run directory:

```text
runs/[timestamp]_[context]/
├── logs/
│   ├── dataset_tracker.json  # Run tracking metadata
│   ├── cve_dataset.txt        # Generated dataset
│   ├── workflow_log.json      # Real-time dashboard data
│   └── dashboard_data.json    # Additional monitoring data
└── generated_pages/           # HTML reports (if analysis enabled)
```

## Real-time Dashboard

During dataset generation:

- **Dashboard:** Open `dashboards/generateDatasetDashboard.html` in browser
- **Updates:** Automatic refresh every 5 seconds
- **Features:** Progress tracking, ETA calculations, error attribution, processing statistics

## Limitations

- **Date Range:** Maximum 120 consecutive days (NVD API limitation)
- **Date Format:** YYYY-MM-DD or full ISO format
- **Run Directory:** All outputs go to `runs/[timestamp]_[context]/` structure

## Common Usage Examples

```bash
# Generate initial dataset for recent CVEs
python generate_dataset.py --last-days 30

# Daily differential updates  
python generate_dataset.py --since-last-run

# Analyze specific time period
python generate_dataset.py --start-date 2024-06-01 --end-date 2024-06-15

# Dataset only (no analysis)
python generate_dataset.py --since-last-run --no-analysis
```

## Run Tracking

The system creates `dataset_tracker.json` in each run's `logs/` directory:

```json
{
  "last_full_pull": "2024-07-02T10:30:00.000000",
  "run_history": [
    {
      "run_id": "status_based_20240702_103000",
      "run_type": "status_based", 
      "timestamp": "2024-07-02T10:30:00.000000",
      "cve_count": 150,
      "output_file": "runs/[timestamp]/logs/cve_dataset.txt"
    }
  ]
}
```

---

**Entry Point:** Use `python generate_dataset.py` from project root
