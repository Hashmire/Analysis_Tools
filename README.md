# Vulnerability Analysis and Enrichment Tools

Tools for processing CVE records to generate enriched NVD-ish records with CPE determination, source data quality analysis, alias extraction, and CPE Applicability Statement generation. Processes CVE data from CVE List and NVD APIs, storing structured enrichment data for flexible report generation and vulnerability intelligence.

## Overview

**Understanding the Problem Space**:

For comprehensive insight into the challenges this tool addresses, see [CPE Automation Challenges](documentation/cpe_automation_challenges.md).

**Dashboard Quick Links**:  

- [Alias Mapping Dashboard](https://hashmire.github.io/Alias_Mapping_Reports/)
- [Source Data Concerns Dashboard](https://hashmire.github.io/SDC_Reports/)
- [CPE-AS Automation Dashboard](https://hashmire.github.io/cpeApplicabilityGeneratorPages/)

### Core Capabilities

**NVD-ish Record Generation**: Processes CVE records to create enriched structured data with comprehensive platform intelligence:

- Ingests CVE data from CVE List v5 and NVD 2.0 APIs
- Performs CPE Base String determination via heuristics, confirmed mappings, and NVD CPE Dictionary queries
- Detects source data quality concerns (placeholders, overlapping ranges, invalid characters, etc.)
- Extracts platform aliases for curator integration
- Generates CPE Applicability Statements with version range normalization and update pattern handling
- Stores enriched data as NVD-ish JSON records in persistent cache

**Report Generation**: Produces multiple report types from NVD-ish record cache:

- **Source Data Concern Reports**: Detailed dashboards for data quality review by source
- **Alias Extraction Reports**: Platform alias mappings for curator validation
- **CPE-AS Automation Reports**: Generated CPE configurations with platform match criteria

## Documentation

### Architecture & Systems

- [CPE Automation Challenges](documentation/cpe_automation_challenges.md) - Problem domains, solutions, and codebase architecture
- [CPE Cache Reference](documentation/cpe_cache_reference.md) - Sharded CPE cache architecture and refresh strategies
- [Logging System](documentation/logging_system.md) - Structured logging patterns and configuration
- [Dataset Generation](documentation/dataset_generation.md) - Dataset generation methodology and capabilities

### NVD-ish Records & Enrichment

- [NVD-ish Record Example](documentation/nvd-ish_record_example.md) - Complete NVD-ish record structure and format
- [NVD-ish CPE Determination](documentation/nvd-ish_cpe_determination.md) - CPE Base String determination methodology
- [NVD-ish CPE-AS Generation](documentation/nvd-ish_cpe-as_generation.md) - CPE Applicability Statement generation rules
- [Source Data Concerns](documentation/source_data_concerns_enhanced_table.md) - Complete SDC detection specifications

## Usage

### Single CVE Processing

```bash
# Process single CVE with all features (SDC, CPE determination, alias extraction, CPE-AS)
python -m src.analysis_tool.core.analysis_tool CVE-2024-1234 \
    --source-data-concerns \
    --cpe-determination \
    --alias-extraction \
    --cpe-as-generation

# Quick processing with defaults (SDC only)
python -m src.analysis_tool.core.analysis_tool CVE-2024-1234
```

Outputs are stored in `runs/[timestamp]_analysis_[CVE-ID]_[features]/`

### Batch Source Harvesting

```bash
# Harvest CVEs from specific sources and generate NVD-ish records
python harvest_and_process_sources.py \
    --sources "Microsoft Corporation" "Google Inc." \
    --record-type nvd-ish

# Harvest by source UUID
python harvest_and_process_sources.py \
    --sources "8254265b-2729-46b6-b9e3-3dfca2d5bfca" \
    --record-type nvd-ish
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

### Report Generation

```bash
# Alias Mapping Report (from NVD-ish cache)
python -m src.analysis_tool.reporting.generate_alias_report

# Source Data Concerns Report  
python -m src.analysis_tool.reporting.generate_sdc_report

# CPE-AS Automation Report
python -m src.analysis_tool.reporting.generate_cpe_as_report

# Use existing dataset run directory (any report type)
python -m src.analysis_tool.reporting.generate_alias_report \
    --run-id 2025-12-01_10-30-00_dataset_last_7_days_nvd-ish

# Filter by source (any report type)
python -m src.analysis_tool.reporting.generate_sdc_report \
    --source-filter "Microsoft Corporation"
```

Reports generate per-source JSON files and interactive HTML dashboards in `runs/[timestamp]_[report_type]/logs/`

### NVD-ish Cache Location

Enriched NVD-ish records are stored in: `cache/nvd-ish_2.0_cves/`

Run-specific outputs are isolated in: `runs/[timestamp]_[context]/`
