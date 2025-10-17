# Logging System

## Overview

The Analysis_Tools system uses standardized logging with consistent terminology, formatting, and severity levels. All logging is validated by a 53-test suite.

## Core Principles

- **Consistent terminology** for CVE/CPE data and operations
- **Standardized message formats** for parsing and readability  
- **Appropriate severity levels** based on operational impact
- **Organized grouping** for filtering and analysis

## Terminology Standards

Use these standardized terms:

| **Correct** | **Avoid** | **Context** |
|---|---|---|
| CVE records | entries, items, data | API/database references |
| CPE names | products, items | API results |
| CPE match strings | strings, queries | Query operations |
| CPE base strings | bases, base CPEs | Generated search strings |
| gathering, collecting, processing | other variants | Operations |

## Message Formats

### Progress Messages

```text
Processing {operation}: {current}/{total} ({percentage:.1f}%) - {context}
```

### Error Messages

```text
{Component} {operation} failed: {specific_reason} - {context}
```

### API Messages

```text
{API_NAME} call: {operation_description}
{API_NAME} response: {status}
```

## Log Levels

| **Level** | **Use For** | **Example** |
|-----------|-------------|-------------|
| **INFO** | Workflow progress, completion | `"Processing 100 CVE records..."` |
| **DEBUG** | Technical details, diagnostics | `"Current IP: 192.168.1.1"` |
| **WARNING** | Recoverable issues, retries | `"Retrying after rate limit"` |
| **ERROR** | Critical failures, blocking issues | `"API request failed: Max retries"` |

## Log Groups

| **Group** | **Purpose** |
|-----------|-------------|
| `initialization` | Application startup, configuration, command-line processing |
| `cve_queries` | CVE data collection, API calls, progress tracking |
| `cpe_queries` | CPE data collection, dictionary queries, API calls |
| `unique_cpe` | CPE generation, base string creation, uniqueness processing |
| `data_processing` | Data transformation, validation, parsing operations |
| `badge_gen` | UI badge generation, metadata processing, confirmed mappings |
| `page_generation` | HTML generation, file creation, template processing |

**Note:** Error messages are assigned to the appropriate workflow stage group where the error occurred.

## Specialized Logging Methods

**Data Summary:** `logger.data_summary(operation, group, **kwargs)`

```python
logger.data_summary("CPE Generation Results", group="unique_cpe", 
                   **{"Affected Array Entries Processed": 25, 
                      "Unique Match Strings Identified": 10})
```

**API Operations:**

```python
logger.api_call("NVD CVE API", {"cve_id": "CVE-2024-1234"}, group="cve_queries")
logger.api_response("MITRE CVE API", "Success", group="cve_queries")
```

**File Operations:**

```python
logger.file_operation("Generated", "/path/to/output.html", group="page_generation")
```

## File Logging

The system automatically saves all terminal output to run-specific log files:

- **Location:** `runs/[timestamp]/logs/` directories
- **Naming:** `YYYY.MM.DD_<parameter>.log` (e.g., `2025.06.25_CVE-2024-1234.log`)
- **Content:** Complete output with ANSI color codes stripped
- **Headers:** Timestamps and run parameters for tracking

## Real-time Dashboard Integration

The logging system integrates with real-time dashboard monitoring:

- **Data Collection:** `dataset_contents_collector.py` monitors log files during dataset generation
- **Updates:** Dashboard data refreshes every 5 seconds using atomic file operations  
- **Features:** Progress tracking, error analysis, ETA calculations, system status
- **Access:** Open `dashboards/generateDatasetDashboard.html` during dataset generation

## Usage Examples

```python
# Progress logging
logger.info("Processing CVE queries: 25/100 (25.0%) - 25 CVE records collected", group="cve_queries")

# Error logging  
logger.error("NVD CVE API request failed: Connection timeout - CVE-2024-1234", group="cve_queries")

# API logging
logger.api_call("NVD CPE API", {"cpe_match": "cpe:2.3:*:apache:*"}, group="cpe_queries")
logger.api_response("MITRE CVE API", "Success", group="cve_queries")

# File operations
logger.file_operation("Generated", "/path/to/CVE-2024-1234.html", group="page_generation")
```

## Testing and Validation

The logging system includes a comprehensive 53-test suite that validates all aspects:

```bash
# Run complete logging test suite
python test_files/test_logging_system.py

# Run all tests via master runner  
python test_files/run_all_tests.py
```

**Test coverage includes:**

- Terminology standardization (4 tests)
- Format compliance (4 tests)
- Log level appropriateness (4 tests)
- Group organization (17 tests)
- Audit boundary enforcement (24 tests)

## Quick Reference

| **Component** | **Standard** |
|---------------|-------------|
| **CVE Data** | CVE records (not entries/items) |
| **CPE Data** | CPE names, match strings, base strings |
| **Operations** | gathering, collecting, processing |
| **Progress** | `Processing X: current/total (percent%)` |
| **Errors** | `Component operation failed: reason - context` |
| **Groups** | initialization, cve_queries, cpe_queries, unique_cpe, data_processing, badge_gen, page_generation |

---

**Test Suite:** 53 tests validating all logging functionality  
**Documentation:** Current as of August 2025
