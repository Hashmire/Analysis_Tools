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
- Provides downloadable JSON configurations

### Features

- **CPE caching system** reduces API calls by caching responses locally
- **Interactive Modal System** with comprehensive badge/modal integration for data quality analysis
- **Source Data Concerns Analysis** with 10 specialized tabs for data quality assessment
- **Dashboard** for monitoring processing progress and performance
- **Rules engine** for automated JSON generation
- **Comprehensive test suites** for validating functionality including 100% coverage modal testing
- **Package repository detection** for various platforms
- **Unified runs structure** maintains all output in timestamped run directories

## Project Structure

```text
Analysis_Tools/
├── run_tools.py                 # Main entry point for all analysis
├── generate_dataset.py          # Dataset generation entry point
├── src/analysis_tool/           # Core application
│   ├── core/
│   │   └── analysis_tool.py     # Main analysis engine
│   ├── storage/
│   │   └── run_organization.py  # Run directory management
│   ├── local_dashboard/         # Dashboard utilities
│   ├── static/js/               # Frontend modules
│   ├── mappings/                # Vendor-specific mappings
│   ├── config.json             # Configuration
│   └── requirements.txt        # Dependencies
├── runs/                       # All analysis outputs (unified structure)
│   └── [timestamp]_[context]/  # Individual run directories
│       ├── generated_pages/    # HTML reports for this run
│       ├── logs/              # Run-specific logs
│       ├── reports/           # Dashboard data for this run
│       └── datasets/          # Dataset files for this run
├── test_files/                 # Test suites and test data
├── documentation/              # Guides and references
├── dashboards/                # Global dashboard files
└── cache/                     # Shared CPE data cache
```

### Generate Dataset Usage Examples

```bash
# Traditional status-based generation
python generate_dataset.py --statuses "Received" "Awaiting Analysis"

# Generate dataset for CVEs modified in the last 30 days
python generate_dataset.py --last-days 30

# Generate dataset for specific date range
python generate_dataset.py --start-date 2024-01-01 --end-date 2024-01-31

# Generate differential dataset since last run
python generate_dataset.py --since-last-run

# Generate dataset and immediately run analysis
python generate_dataset.py --last-days 7 --run-analysis

# Show when the last dataset generation occurred
python generate_dataset.py --show-last-run
```

All generated datasets are tracked in run-specific directories under `runs/[timestamp]_[context]/datasets/` with metadata for future differential updates.

## Documentation

- [Badge and Modal System Reference](documentation/badge_modal_system_reference.md) - Complete badge/modal system documentation
- [CPE Caching System](documentation/cpes_api_caching_system.md) - Cache configuration and management
- [Logging System](documentation/logging_system.md) - Structured logging patterns and configuration
- [Dashboard Usage](documentation/dashboard_usage.md) - Dashboard setup and usage

### Test Documentation

- [Test Suites Overview](documentation/README.md) - Comprehensive test documentation

## Examples

Examples demonstrating different CVE data patterns:  

[Single CPE Match String:  CVE-2024-12355](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-12355)  
[Many CPE Match Strings:  CVE-2024-20359](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-20359)  
[MongoDB cpes Array Data:  CVE-2024-3371](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-3371)  
[Package Name:  CVE-2023-5541](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2023-5541)  
[Fortinet + ~Duplicate ADP:  CVE-2023-41842](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2023-41842)  
[GitHub + changes Array Data:  CVE-2024-2469](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-2469)  
[Linux Kernel:  CVE-2022-48655](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2022-48655)  
[Microsoft Simple:  CVE-2024-21389](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-21389)  
[Microsoft Many Rows:  CVE-2024-0057](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-0057)  
[Unhelpful versions Array Data:  CVE-2023-33009](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2023-33009)  
[Update Attribute Information in versions Array Data:  CVE-2024-20515](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-20515)  
[Platforms Array Data:  CVE-2024-20698](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-20698)  

The full dataset of generated pages can be found at [Hashmire/cpeApplicabilityGeneratorPages](https://github.com/Hashmire/cpeApplicabilityGeneratorPages).

Access specific CVE records using: `https://hashmire.github.io/cpeApplicabilityGeneratorPages/generated_pages/<CVE-ID>.html`

## Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/Hashmire/Analysis_Tools.git
   cd Analysis_Tools
   ```

2. Install dependencies:

   ```bash
   cd src/analysis_tool
   pip install -r requirements.txt
   ```

3. Run the tool:

   ```bash
   # From project root directory
   python run_tools.py --help
   ```

**Important:** Use `run_tools.py` from the project root for CVE analysis. Use `generate_dataset.py` from the project root for dataset generation. Do not run `analysis_tool.py` directly.

## Usage

### Basic Commands

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

Generate CVE datasets for analysis:

```bash
# Traditional status-based generation
python generate_dataset.py --statuses "Received" "Awaiting Analysis"

# Generate dataset for recent CVEs and analyze them
python generate_dataset.py --last-days 30 --run-analysis

# Generate differential dataset since last run
python generate_dataset.py --since-last-run --run-analysis
```

All dataset outputs are isolated in run-specific directories under `runs/[timestamp]_[context]/datasets/`.

### Dashboard

The tool includes a dashboard that updates during processing:

```bash
# Run analysis (dashboard updates automatically)
python run_tools.py [arguments]

# Open dashboards/index.html in browser for monitoring

# Analysis outputs including logs are contained in runs/[timestamp]_[context]/ directories
```

## Performance

### CPE Caching

- Caches NVD API responses locally to reduce repeat calls
- 12-hour cache refresh
- Automatic cache management and cleanup

### Configuration

Cache settings in `src/analysis_tool/config.json`:

```json
"cache": {
    "enabled": true,
    "max_age_hours": 12,
    "auto_cleanup": true
}
```

## Testing

### Test Suites

- **Platform Badge Tests** (62 tests) - Complete badge system including Source Data Concerns modal integration
- **Modular Rules** (16 tests) - JSON generation rules and wildcard processing
- **Provenance Assistance** (10 tests) - Package repository detection
- **Logging System** (53 tests) - Structured logging validation
- **Dashboard Scenarios** (29 scenarios) - Dashboard functionality

### Source Data Concerns Modal System

The platform badges include a comprehensive **Source Data Concerns** modal with 10 specialized tabs:

1. **Placeholder Data** - Detects vendor/product placeholder values (n/a, not applicable, etc.)
2. **Version Text Patterns** - Identifies text-based version indicators (beta, nightly, before, after)
3. **Version Comparators** - Finds mathematical operators in version strings (>, <, >=)
4. **Version Granularity** - Spots inconsistent version part counts within same base version
5. **Wildcard Branches** - Validates wildcard pattern routing (routes to JSON Generation Rules)
6. **CPE Array Concerns** - Detects empty or malformed CPE arrays
7. **Duplicate Entries** - Tracks duplicate row consolidation
8. **Platform Data Concerns** - Identifies misaligned vendor/product data patterns
9. **Missing Affected Products** - Detects CVEs with no products marked as affected
10. **Overlapping Ranges** - Identifies version ranges that overlap within same CPE Base String

**Real CVE Pattern Validation**: Detection patterns based on production CVE analysis (CVE-2024-20515, CVE-1337-99997)

### Running Tests

```bash
# Complete integrated test suite (includes Source Data Concerns modal tests)
python test_files/test_platform_badges.py

# Individual test suites
python test_files/test_modular_rules.py test_files/testModularRulesEnhanced.json
python test_files/test_provenance_assistance.py test_files/testProvenanceAssistance.json
python test_files/test_logging_system.py
python test_files/test_dashboard_scenarios.py --all

# All logging tests
python test_files/run_all_logging_tests.py
```
