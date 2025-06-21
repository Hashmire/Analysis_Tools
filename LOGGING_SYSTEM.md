# Analysis Tool - Enhanced Logging System

## Overview

The Analysis Tool now includes a comprehensive logging system organized into workflow-based groups. This replaces the previous scattered `print()` statements with a structured, configurable logging approach that provides better visibility into the processing pipeline.

## Logging Groups

The logging system organizes messages into 8 major workflow groups:

### 1. **INIT** - Initialization
- **Purpose**: System startup, configuration loading, primary dataframe creation
- **Color**: Blue
- **Examples**:
  - Loading configuration files
  - Creating primary dataframe
  - Validating CVE ID format
  - System readiness checks

### 2. **CVE_QUERY** - CVE Queries  
- **Purpose**: CVE record retrieval from MITRE, NVD CVE API, source data gathering
- **Color**: Green
- **Examples**:
  - MITRE CVE API calls
  - NVD CVE API requests
  - NVD Source API queries
  - API response processing

### 3. **UNIQUE_CPE** - Unique CPE Generation
- **Purpose**: CPE base string extraction, deduplication, validation
- **Color**: Yellow  
- **Examples**:
  - Extracting CPE strings from CVE data
  - Processing NVD configuration data
  - Deduplicating CPE base strings
  - CPE format validation

### 4. **CPE_QUERY** - CPE Queries
- **Purpose**: NVD CPE API queries, product matching, result processing
- **Color**: Cyan
- **Examples**:
  - NVD CPE API requests
  - Product search queries
  - Query result processing
  - API rate limiting handling

### 5. **BADGE_GEN** - Badge Generation
- **Purpose**: Status badges, confirmation mapping, result categorization
- **Color**: Magenta
- **Examples**:
  - Processing confirmed mappings
  - Generating status badges
  - Categorizing products
  - Applying local mappings

### 6. **PAGE_GEN** - Page Generation
- **Purpose**: HTML generation, template processing, file output
- **Color**: White
- **Examples**:
  - Converting dataframe to HTML
  - Applying CSS/JavaScript
  - Generating final HTML files
  - File operations

### 7. **DATA_PROC** - Data Processing
- **Purpose**: Data transformation, validation, cleanup operations
- **Color**: Red
- **Examples**:
  - Dataframe transformations
  - Data validation
  - Column cleanup
  - Format conversions

### 8. **ERROR_HANDLE** - Error Handling
- **Purpose**: Exception handling, retry logic, error recovery
- **Color**: Bright Red
- **Examples**:
  - API error handling
  - Network timeout recovery
  - Data validation errors
  - Retry mechanisms

## Configuration

The logging system is configured via `config.json`:

```json
{
  "logging": {
    "enabled": true,
    "level": "INFO",
    "format": "[{timestamp}] [{group}] [{level}] {message}",
    "groups": {
      "INIT": {
        "name": "Initialization",
        "description": "System startup, configuration loading, primary dataframe creation",
        "enabled": true,
        "color": "blue"
      },
      // ... other groups
    }
  }
}
```

## Usage Examples

### Basic Logging
```python
from workflow_logger import get_logger, LogGroup

logger = get_logger()
logger.info(LogGroup.CVE_QUERY, "Starting CVE data retrieval")
logger.warning(LogGroup.ERROR_HANDLE, "API rate limit approaching")
logger.error(LogGroup.ERROR_HANDLE, "Network timeout occurred")
```

### Stage Management
```python
from workflow_logger import start_cve_queries, end_cve_queries

start_cve_queries("CVE-2024-20515")
# ... processing ...
end_cve_queries("Data retrieved successfully")
```

### Progress Tracking
```python
logger.stage_progress(LogGroup.CPE_QUERY, 15, 28, "cpe:2.3:a:apache:httpd:*")
```

### API Call Logging
```python
logger.api_call(LogGroup.CVE_QUERY, "NVD CVE API", {"cve_id": "CVE-2024-20515"})
logger.api_response(LogGroup.CVE_QUERY, "NVD CVE API", "Success", 1)
```

### Data Summaries
```python
logger.data_summary(LogGroup.UNIQUE_CPE, "Deduplication",
                   total_cpe_strings=63, unique_cpe_strings=28)
```

### File Operations
```python
logger.file_operation(LogGroup.PAGE_GEN, "Generated", 
                     "generated_pages/CVE-2024-20515.html",
                     "1.2MB HTML file")
```

## Key Features

1. **Organized Output**: Messages are grouped by workflow stage for easier debugging
2. **Configurable**: Enable/disable groups and set log levels via configuration
3. **Color Coding**: Visual differentiation of message types (when supported)
4. **Timestamps**: All messages include precise timestamps
5. **Structured Data**: Consistent formatting for data summaries and progress
6. **API Tracking**: Dedicated logging for API calls and responses
7. **File Operations**: Dedicated logging for file creation and operations
8. **Error Context**: Enhanced error logging with context and recovery information

## Benefits

1. **Better Debugging**: Easily filter and follow specific workflow stages
2. **Progress Visibility**: Clear indication of processing progress and bottlenecks
3. **Performance Monitoring**: Track API calls, timing, and data volumes
4. **Error Isolation**: Quickly identify which stage encountered issues
5. **Maintainability**: Centralized logging configuration and consistent formatting
6. **Scalability**: Easy to add new log groups or modify existing ones

## Migration from Old Logging

The system maintains backward compatibility while gradually replacing old `print()` statements:

**Old:**
```python
print(f"[INFO] Processing {cve_id}...")
print(f"[ERROR] Failed to process: {error}")
```

**New:**
```python
logger.info(LogGroup.INIT, f"Processing {cve_id}")
logger.error(LogGroup.ERROR_HANDLE, f"Failed to process: {error}")
```

## Testing

Run the demonstration script to see the logging system in action:

```bash
python test_logging.py
```

This will show examples of all logging groups and features in a simulated CVE processing workflow.
