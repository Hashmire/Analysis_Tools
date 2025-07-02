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

- CPE caching system reduces API calls by caching responses locally
- Dashboard for monitoring processing progress and performance
- Rules engine for automated JSON generation
- Test suites for validating functionality
- Package repository detection for various platforms

## Project Structure

```text
Analysis_Tools/
├── run_tools.py                 # Main entry point
├── src/analysis_tool/           # Core application
│   ├── analysis_tool.py         # Main analysis engine
│   ├── config.json             # Configuration
│   ├── requirements.txt        # Dependencies
│   ├── utilities/              # Dashboard and log utilities
│   ├── static/js/              # Frontend modules
│   └── mappings/               # Vendor-specific mappings
├── generated_pages/            # Production HTML reports
├── test_output/                # Test-generated files
├── test_files/                 # Test suites and data
├── documentation/              # Guides and references
├── cache/                      # CPE data cache
├── logs/                       # Analysis logs
└── reports/                    # Dashboard data
```

## Documentation

- [Dashboard Usage](documentation/dashboard_usage.md) - Dashboard setup and usage
- [CPE Caching System](documentation/cpes_api_caching_system.md) - Cache configuration
- [Logging System](documentation/logging_system.md) - Logging configuration
- [Modular Rules Test Suite](documentation/modular_rules_test_suite.md) - JSON generation testing
- [Provenance Assistance Test Suite](documentation/provenance_assistance_test_suite.md) - Platform detection testing

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

**Important:** Use `run_tools.py` from the project root. Do not run `analysis_tool.py` directly.

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

Generate CVE datasets from NVD API for bulk analysis:

```bash
# Generate dataset with specific vulnerability statuses
python -m src.analysis_tool.utilities.generate_dataset --output my_dataset.txt

# With API key for higher rate limits
python -m src.analysis_tool.utilities.generate_dataset --api-key YOUR_API_KEY --output my_dataset.txt

# Test mode (limit to 100 CVEs)
python -m src.analysis_tool.utilities.generate_dataset --test-mode --output test_dataset.txt

# Then analyze the generated dataset
python run_tools.py --file my_dataset.txt
```

### Dashboard

The tool includes a dashboard that updates during processing:

```bash
# Run analysis (dashboard updates automatically)
python run_tools.py [arguments]

# Open reports/local_dashboard.html in browser for monitoring

# Generate dashboard from existing logs
python src/analysis_tool/utilities/log_analyzer.py --summary
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

- **Modular Rules** (14 tests) - JSON generation rules and wildcard processing
- **Provenance Assistance** (10 tests) - Package repository detection
- **Logging System** (53 tests) - Structured logging validation
- **Dashboard Scenarios** (29 scenarios) - Dashboard functionality

### Running Tests

```bash
# Individual test suites
python test_files/test_modular_rules.py test_files/testModularRulesEnhanced.json
python test_files/test_provenance_assistance.py test_files/testProvenanceAssistance.json
python test_files/test_logging_system.py
python test_files/test_dashboard_scenarios.py --all

# All logging tests
python test_files/run_all_logging_tests.py
```
