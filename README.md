# Vulnerability Analysis and Enrichment Tools

Tools for processing CVE records and generating CPE Applicability Statements. Processes CVE data from MITRE and NVD APIs to create interactive HTML reports for CPE matching and configuration generation.

## Overview

**Understanding the Problem Space**:

For comprehensive insight into the challenges this tool addresses, see [CPE Automation Challenges](documentation/cpe_automation_challenges.md).

**Dashboard Quick Links**:  

- [Alias Mapping Dashboard](https://hashmire.github.io/Analysis_Tools/dashboards/aliasMappingDashboard.html)
- [Source Data Concerns Dashboard](https://hashmire.github.io/Analysis_Tools/dashboards/sourceDataConcernDashboard.html)
- [Generate Dataset Dashboard](https://hashmire.github.io/Analysis_Tools/dashboards/generateDatasetDashboard.html)

### CPE Applicability Generator

Processes CVE records to generate CPE Applicability Statements:

- Ingests CVE information from CVE List and NVD APIs
- Extracts CPE attribute values from affected product data
- Queries NVD /cpes/ API for matching CPE Names
- Processes results to identify relevant CPE Base String values
- Generates HTML reports for user review and selection
- Produces CPE Applicability Statements (configurations) from selected CPE Base Strings


## Documentation

- [CPE Automation Challenges](documentation/cpe_automation_challenges.md) - Problem domains, solutions, and codebase architecture
- [Badge and Modal System Reference](documentation/badge_modal_system_reference.md) - Complete badge/modal system documentation
- [CPE Caching System](documentation/cpes_api_caching_system.md) - Cache configuration and management
- [Logging System](documentation/logging_system.md) - Structured logging patterns and configuration
- [Dashboard Usage](documentation/dashboard_usage.md) - Dashboard system and usage
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

