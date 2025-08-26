# Vulnerability Analysis and Enrichment Tools

Tools for processing CVE records and generating CPE Applicability Statements. Processes CVE data from MITRE and NVD APIs to create interactive HTML reports for CPE matching and configuration generation.

## Overview

### CPE Applicability Generator

Processes CVE records to generate CPE Applicability Statements:

- Ingests CVE information from CVE List and NVD APIs
- Extracts CPE attribute values from affected product data
- Queries NVD /cpes/ API for matching CPE Names
- Processes results to identify relevant CPE Base String values
- Generates HTML reports for user review and selection
- Produces CPE Applicability Statements (configurations) from selected CPE Base Strings

### Features

- **Dashboards** for monitoring processing progress, performance and source data concerns
- **Caching system** reduces API calls by caching responses locally
- **Rules engine** for automated CPE Applicability Statement JSON generation
- **Interactive Modal System** for display of contextual data to assist with user review
- **Unified runs structure** maintains all output in timestamped run directories
- **Comprehensive test suites** for validating functionality

All generated datasets are tracked in run-specific directories under `runs/[timestamp]_[context]/logs/` with metadata for future differential updates.

## Documentation

- [Badge and Modal System Reference](documentation/badge_modal_system_reference.md) - Complete badge/modal system documentation
- [CPE Caching System](documentation/cpes_api_caching_system.md) - Cache configuration and management
- [Logging System](documentation/logging_system.md) - Structured logging patterns and configuration
- [Dashboard Usage](documentation/dashboard_usage.md) - On demand dashboard system and usage
- [Dataset Generation](documentation/dataset_generation.md) - Dataset generation methodology and capabilities

### Test Documentation

- [Test Suites Overview](documentation/README.md) - Comprehensive test documentation

## Examples

The complete collection of generated pages is maintained at [Hashmire/cpeApplicabilityGeneratorPages](https://github.com/Hashmire/cpeApplicabilityGeneratorPages).  

To access a specific CVE analysis page, use the following URL pattern:

```text
https://hashmire.github.io/cpeApplicabilityGeneratorPages/generated_pages/[CVE-ID].html
```

_Note: Not all CVEs are currently present in the dataset._

## Usage

### Single CVE Commands

```bash
# Single CVE analysis
python run_tools.py --cve CVE-2024-20515

# Multiple CVEs from file
python run_tools.py --file testExamples.txt

# Test file processing
python run_tools.py --test-file test_files/testModularRulesEnhanced.json

# Disable cache for testing
python run_tools.py --cve CVE-2024-20515 --no-cache
```

### Dataset Generation

```bash
# Traditional status-based generation
python generate_dataset.py --statuses "Received" "Awaiting Analysis"

# Generate dataset for CVEs modified in the last 30 days
python generate_dataset.py --last-days 30

# Generate dataset for specific date range
python generate_dataset.py --start-date 2024-01-01 --end-date 2024-01-31
```

All dataset outputs are isolated in run-specific directories under `runs/[timestamp]_[context]/logs/`.

## Dashboards

The system includes two monitoring dashboards:

- **Dataset Generation Dashboard** (`dashboards/generateDatasetDashboard.html`) - Monitors dataset generation progress with processing statistics and ETA calculations
- **Source Data Concern Dashboard** (`dashboards/sourceDataConcernDashboard.html`) - Tracks data quality concerns
