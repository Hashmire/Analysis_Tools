# Dataset Generation Enhancement

The `generate_dataset.py` utility includes intelligent dataset management capabilities while maintaining full backward compatibility.

## Features

### 1. Date-based CVE Filtering

Query CVEs based on their `lastModified` date using NVD API parameters:

- `--last-days N` - CVEs modified in the last N days (max 120)
- `--start-date` and `--end-date` - CVEs modified within a specific date range

**Examples:**

```bash
# CVEs modified in the last 30 days
python -m src.analysis_tool.utilities.generate_dataset --last-days 30

# CVEs modified in January 2024
python -m src.analysis_tool.utilities.generate_dataset --start-date 2024-01-01 --end-date 2024-01-31
```

### 2. Differential Updates

Generate datasets containing only CVEs that have changed since your last run:

```bash
# Generate dataset for CVEs modified since the last run
python -m src.analysis_tool.utilities.generate_dataset --since-last-run
```

### 3. Run Tracking

All dataset generation runs are automatically tracked in `datasets/dataset_tracker.json`. View your history:

```bash
# Show when the last dataset generation occurred
python -m src.analysis_tool.utilities.generate_dataset --show-last-run
```

### 4. Integrated Processing

Automatically run the analysis tool after dataset generation:

```bash
# Generate dataset and immediately analyze it
python -m src.analysis_tool.utilities.generate_dataset --last-days 7 --run-analysis --api-key YOUR_KEY
```

## Backward Compatibility

All existing functionality remains unchanged:

```bash
# Traditional status-based generation still works exactly as before
python -m src.analysis_tool.utilities.generate_dataset --statuses "Received" "Awaiting Analysis"
python -m src.analysis_tool.utilities.generate_dataset --test-mode
```

## Date Range Limitations

- Maximum date range: 120 consecutive days (NVD API limitation)
- Dates can be in YYYY-MM-DD format or full ISO format
- The system automatically handles URL encoding and timezone offsets

## Tracking File Format

The tracking system creates `datasets/dataset_tracker.json` with this structure:

```json
{
  "last_full_pull": "2024-07-02T10:30:00.000000",
  "run_history": [
    {
      "run_id": "status_based_20240702_103000",
      "run_type": "status_based",
      "timestamp": "2024-07-02T10:30:00.000000",
      "cve_count": 150,
      "output_file": "/path/to/datasets/cve_dataset.txt"
    }
  ]
}
```

## Common Workflows

**Initial Setup:**

```bash
# Generate your first dataset for recent CVEs
python -m src.analysis_tool.utilities.generate_dataset --last-days 30 --output initial_dataset.txt --run-analysis
```

**Regular Updates:**

```bash
# Daily/weekly differential updates
python -m src.analysis_tool.utilities.generate_dataset --since-last-run --run-analysis
```

**Investigating Specific Periods:**

```bash
# Analyze CVEs from a specific incident timeframe
python -m src.analysis_tool.utilities.generate_dataset --start-date 2024-06-01 --end-date 2024-06-15 --output incident_analysis.txt
```

## Migration from Previous Versions

No migration needed. The enhanced version:

- Maintains all existing command-line options
- Automatically starts tracking from the first run
- Works with all existing scripts and workflows
