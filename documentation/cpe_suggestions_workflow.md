# CPE Suggestions Workflow Process

- [CPE Suggestions Workflow Process](#cpe-suggestions-workflow-process)
  - [Overview](#overview)
  - [Architecture Flow](#architecture-flow)
  - [Stage 1: Platform Entry Creation](#stage-1-platform-entry-creation)
    - [Input Data Structure](#input-data-structure)
    - [Processing Steps](#processing-steps)
    - [Output: Platform Entry Row (Legacy DataFrame)](#output-platform-entry-row-legacy-dataframe)
  - [Stage 2: CPE Base String Generation](#stage-2-cpe-base-string-generation)
    - [2.1 Affected Entry to CPE Attribute Mappings](#21-affected-entry-to-cpe-attribute-mappings)
      - [Property-to-Attribute Transformation Matrix](#property-to-attribute-transformation-matrix)
      - [Supported Field Processing](#supported-field-processing)
    - [2.2 CPE Base String Generation and Validation Pipeline](#22-cpe-base-string-generation-and-validation-pipeline)
      - [2.2.1 Complete CPE Base String Generation Enumeration](#221-complete-cpe-base-string-generation-enumeration)
      - [2.2.2 Transformation Functions](#222-transformation-functions)
      - [2.2.3 Attribute Curation Details by Type](#223-attribute-curation-details-by-type)
      - [2.2.4 Validation and Culling Checks](#224-validation-and-culling-checks)
      - [2.2.5 Final Output Structure](#225-final-output-structure)
      - [Complete Generation Example (Organized by Specificity)](#complete-generation-example-organized-by-specificity)
  - [Stage 3: NVD /cpes/ API Query \& Processing](#stage-3-nvd-cpes-api-query--processing)
    - [3.1 CPE Cache Flow](#31-cpe-cache-flow)
    - [3.2 NVD API Query Process](#32-nvd-api-query-process)
    - [3.3 Response Processing](#33-response-processing)
      - [3.3.1 Data Extraction Pipeline](#331-data-extraction-pipeline)
      - [3.3.2 Data Consolidation and Aggregation](#332-data-consolidation-and-aggregation)
        - [3.3.2.1 Version Matching Logic](#3321-version-matching-logic)
        - [3.3.2.2 Reference Data Aggregation](#3322-reference-data-aggregation)
      - [3.3.3 Affected Entry to Query String Mapping](#333-affected-entry-to-query-string-mapping)
      - [3.3.4 Output Data Structure](#334-output-data-structure)
  - [Stage 4: Top 10 CPE Suggestions Generation](#stage-4-top-10-cpe-suggestions-generation)
    - [4.1 Data Consolidation](#41-data-consolidation)
      - [4.1.1 Per-Affected-Entry Processing](#411-per-affected-entry-processing)
      - [4.1.2 Base String Deduplication and Metadata Consolidation](#412-base-string-deduplication-and-metadata-consolidation)
      - [4.1.3 Statistical Aggregation](#413-statistical-aggregation)
      - [4.1.4 Output Structure per Affected Entry](#414-output-structure-per-affected-entry)
    - [4.2 Ranking Algorithm](#42-ranking-algorithm)
      - [4.2.1 Sorting Process](#421-sorting-process)
  - [Stage 5: Confirmed Mappings Detection](#stage-5-confirmed-mappings-detection)
    - [5.1 Confirmed Mappings Processing Pipeline](#51-confirmed-mappings-processing-pipeline)
      - [5.1.1 Mapping File Detection and Loading](#511-mapping-file-detection-and-loading)
      - [5.1.2 Alias Set Extraction from Affected Entry](#512-alias-set-extraction-from-affected-entry)
      - [5.1.3 Alias Matching and Comparison Logic](#513-alias-matching-and-comparison-logic)
      - [5.1.4 CPE Base String Specificity Filtering](#514-cpe-base-string-specificity-filtering)
  - [Stage 6: NVD-ish Record Integration](#stage-6-nvd-ish-record-integration)
    - [6.1 Data Collection and Assembly](#61-data-collection-and-assembly)
  - [Final Output: Complete cpeSuggestions Structure](#final-output-complete-cpesuggestions-structure)

## Overview

This document details the complete workflow process that transforms CVE List V5 affected array data into the cpeSuggestions content in NVD-ish records. The process involves multiple transformation stages, API queries, and data consolidation steps.

## Architecture Flow

```
CVE List V5 Affected Entry
    ↓
1. Platform Entry Creation
    ↓
2. CPE Base String Generation
    ↓
3. NVD /cpes/ API Query & Processing
    ↓
4. Top 10 CPE Suggestions Generation
    ↓
5. Confirmed Mappings Detection
    ↓
6. NVD-ish Record Integration
    ↓
Final cpeSuggestions Structure
```

---

## Stage 1: Platform Entry Creation

**Location**: `src/analysis_tool/core/processData.py` → `processCVEData()`

### Input Data Structure
```json
{
  "vendor": "example_vendor",
  "product": "example_product",
  "versions": [
    {
      "version": "1.0.0",
      "status": "affected",
      "lessThan": "1.2.5"
    }
  ],
  "platforms": ["windows", "linux"]
}
```

### Processing Steps

1. **Affected Entry Iteration**: Process each affected entry in CNA/ADP containers
2. **Platform Entry Metadata Creation**: Generate structured metadata for downstream processing

### Output: Platform Entry Row (Legacy DataFrame)

```python
{
    'sourceID': 'security@example-vendor.com',
    'sourceRole': 'CNA',
    'rawPlatformData': {affected_entry_copy},
    'platformEntryMetadata': {
        'dataResource': 'CVEAPI',
        'platformFormatType': 'vendor_product_versions',
        'hasCPEArray': False,
        'cpeBaseStrings': [],  # Populated in Stage 2
        'cpeVersionChecks': [version_objects],
        'duplicateRowIndices': []
    },
    'rawCPEsQueryData': [],
    'sortedCPEsQueryData': [],
    'trimmedCPEsQueryData': []
}
```

**Key Functions**:
- `processCVEData()`: Main entry point
- `determine_platform_format_type()`: Categorizes affected entry structure
- `create_product_key()`: Generates unique keys for duplicate detection

---

## Stage 2: CPE Base String Generation

**Location**: `src/analysis_tool/core/processData.py` → `suggestCPEData()`

### 2.1 Affected Entry to CPE Attribute Mappings

#### Property-to-Attribute Transformation Matrix

| Affected Entry Property | CPE Attribute Target | Processing Function | Example Transform |
|------------------------|---------------------|--------------------|--------------------|
| `vendor` | vendor | Direct mapping | `"microsoft"` |
| `product` | product | Direct mapping | `"windows_server"` |
| `platforms` | targetHW | Supported value mapping | `["x64", "x86"]` → Generate base string per array value |
| `packageName` | vendor/product | Scoped package parsing | `"@angular/core"` → `"angular"` + `"core"` |
| `cpes` | vendor/product/etc | CPE string parsing | `"cpe:2.3:a:apache:kafka:2.8.0:*:*:*:*:*:*:*"` → Multiple search variants |

**Note**: `collectionURL` and `repo` fields are **not currently supported** in the CPE suggestions process. While these fields are collected in platform data, they are not processed for CPE generation. Future enhancement could add URL parsing to extract vendor/product components from repository URLs.

#### Supported Field Processing

**Step 1: Primary Property Detection**

```python
# Direct vendor/product mapping (highest priority)
if 'vendor' in platform_data and 'product' in platform_data:
    vendor_value = platform_data['vendor']
    product_value = platform_data['product']
```

**Step 2: PackageName Parsing**

```python
# Scoped package: "@angular/core" → vendor="angular", product="core"
if package_name.startswith('@'):
    vendor_value, product_value = package_name[1:].split('/')
```

**Step 3: Platforms Array Processing**

```python
# Process platforms array to generate architecture-specific CPE variants
if 'platforms' in platform_data and isinstance(platform_data['platforms'], list):
    platforms = platform_data['platforms']
    
    for platform_item in platforms:
        platform_string = platform_item.lower() if isinstance(platform_item, str) else ""
        
        # Skip placeholder values (n/a, unknown, etc.)
        is_placeholder = platform_string in [v.lower() for v in GENERAL_PLACEHOLDER_VALUES]
        if is_placeholder:
            continue  # Skip mapping attempt for placeholder values
        
        # Supported platform patterns generate CPE base strings:
        if "32-bit" in platform_string or "x32" in platform_string or "x86" in platform_string:
            targetHW = "x86"
            rawMatchString = f"cpe:2.3:*:{vendor}:{product}:*:*:*:*:*:*:{targetHW}:*"
            cpeBaseStrings.append(constructSearchString(breakoutCPEAttributes(rawMatchString), "baseQuery"))
            
        elif "64-bit" in platform_string or "x64" in platform_string or "x86_64" in platform_string:
            targetHW = "x64" 
            rawMatchString = f"cpe:2.3:*:{vendor}:{product}:*:*:*:*:*:*:{targetHW}:*"
            cpeBaseStrings.append(constructSearchString(breakoutCPEAttributes(rawMatchString), "baseQuery"))
        
        # Platform validation and mapping:
        # ONLY architecture platforms generate CPE strings (mapped to targetHW field):
        #   'x86', 'x86_64', 'x64', 'arm', 'arm64', '32-bit', '64-bit' → targetHW values
        # Other values throw warnings for proper support mapping review
```

**Step 4: Placeholder Detection & Validation**

```python
# Uses GENERAL_PLACEHOLDER_VALUES from badge_modal_system.py
GENERAL_PLACEHOLDER_VALUES = [
    'unspecified', 'unknown', 'none', 'undefined', 'various',
    'n/a', 'not available', 'not applicable', 'unavailable',
    'na', 'nil', 'tbd', 'to be determined', 'pending',
    'not specified', 'not determined', 'not known', 'not listed',
    'not provided', 'missing', 'empty', 'null', '-',
    'see references', 'see advisory', 'check', 'noted', 'all'
]

if vendor_value.lower() in [v.lower() for v in GENERAL_PLACEHOLDER_VALUES]:
    return []  # Skip CPE generation for placeholder values
```

### 2.2 CPE Base String Generation and Validation Pipeline

For each supported platform architecture, a complete CPE base string generation and validation pipeline occurs:

#### 2.2.1 Complete CPE Base String Generation Enumeration

> **Important**: The examples below represent common enumeration patterns but do not include all possible combinations. The system generates CPE base strings for **all enumeration combinations of all present affected entry properties** as defined in Section 2.1. Each affected entry with different property combinations (vendor, product, packageName, platforms, cpes) will generate its unique set of CPE Base Strings based on available data.

The system generates CPE base strings organized by specificity level, from least to most specific:

**Single Attribute Patterns (Least Specific)**:

- **vendor-only**: `cpe:2.3:*:vendor:*:*:*:*:*:*:*:*:*:*`
- **product-only**: `cpe:2.3:*:*:*product*:*:*:*:*:*:*:*:*`
- **packageName-only**: `cpe:2.3:*:*:*package_name*:*:*:*:*:*:*:*:*`
- **packageName (unique case)** (GroupId-only): `cpe:2.3:*:group_id:*:*:*:*:*:*:*:*:*:*`
- **packageName (unique case)** (ArtifactId-only): `cpe:2.3:*:*:*artifact_id*:*:*:*:*:*:*:*:*`

*Enumeration: 1-5 patterns per entry based on available fields*

**Dual Attribute Patterns (Moderate Specificity)**:

- **vendor + product**: `cpe:2.3:*:vendor:*product*:*:*:*:*:*:*:*:*`
- **vendor + packageName**: `cpe:2.3:*:vendor:*packageName*:*:*:*:*:*:*:*:*`
- **packageName (unique case)**: `cpe:2.3:*:group_id:*artifact_id*:*:*:*:*:*:*:*:*`
- **CVE Affected CPE** (exact): `cpe:2.3:a:alphasoft:dataprocessor:*:*:*:*:*:*:*:*`
- **CVE Affected CPE** (wildcarded): `cpe:2.3:a:alphasoft:*dataprocessor*:*:*:*:*:*:*:*:*`

*Enumeration: 2-5 patterns per entry based on data combinations*

**Triple Attribute Patterns (High Specificity)**:

- **vendor + product + Architecture**: `cpe:2.3:*:vendor:*product*:*:*:*:*:*:*:x64:*`
- **vendor + packageName + Architecture**: `cpe:2.3:*:vendor:*package*:*:*:*:*:*:*:x86:*`
- **packageName (unique case) + Architecture**: `cpe:2.3:*:group_id:*artifact_id*:*:*:*:*:*:*:x64:*`

*Enumeration: (Dual patterns) × (Number of supported architectures)*

#### 2.2.2 Transformation Functions

Each CPE undergoes multiple transformation stages:

- **`breakoutCPEAttributes()`**: Parses CPE strings into component dictionary with validation for malformed entries
- **`constructSearchString()`**: Converts components to "baseQuery" format with wildcarded product fields (`*product*`) for broader NVD matching
- **`curateCPEAttributes()`**: Applies vendor/product normalization including vendor prefix removal, version pattern cleaning, and suffix trimming

#### 2.2.3 Attribute Curation Details by Type

**vendor Curation (`curateCPEAttributes('vendor')`)**:

- **Company Aliases**: `apache_software_foundation` → `apache`
- **Inc/Corporation Removal**: `microsoft_inc` → `microsoft`
- **Inc. with Period**: `apple_inc.` → `apple`
- **Trailing Cleanup**: Remove leftover underscores and formatting

**product Curation (`curateCPEAttributes('product')`)**:

- **Vendor Prefix Removal**: `apache_tomcat` → `tomcat`
- **Software Suffix Removal**: `notepad_software` → `notepad`
- **Version Suffix Removal**: `firefox_version` → `firefox`
- **Plugin Suffix Removal**: `jquery_plugin` → `jquery`
- **Version Number Patterns**: `chrome_95.0.1` → `chrome`
- **Version Keywords**: `office_version_2019` → `office`
- **Version Abbreviations**: `nodejs_v18.2` → `nodejs`

**vendorProduct Curation (`curateCPEAttributes('vendorProduct')`)**:

- **Vendor/Product Duplication**: `"apache"` + `"apache/kafka"` → `"apache"` + `"kafka"`
- **Escaped Slash Handling**: `"lunary-ai"` + `"lunary-ai\/lunary"` → `"lunary-ai"` + `"lunary"`
- **Vendor Underscore Prefix**: `"microsoft"` + `"microsoft_office"` → `"microsoft"` + `"office"`
- **All product-level curations applied**: Plus software/version/plugin suffix removal

**platform Curation (`curateCPEAttributes('platform')`)**:

- **Architecture Mapping**: `"x86_64"` → `"x64"`, `"32-bit"` → `"x86"`
- **ARM Variants**: `"arm64"` → `"arm64"`, `"arm"` → `"arm"`
- **Returns Success Flag**: `(mapped_value, True)` or `(original_value, False)`

**packageName Processing (Colon-Delimited)**:

- **GroupId Extraction**: `"org.apache:kafka"` → GroupId: `"org.apache"`
- **ArtifactId Extraction**: `"org.apache:kafka"` → ArtifactId: `"kafka"`
- **Multiple CPE Generation**: Creates vendor-only, product-only, and combined patterns

#### 2.2.4 Validation and Culling Checks

Each generated CPE undergoes comprehensive validation before inclusion:

**NVD API Compatibility (`is_nvd_api_compatible()`)**:
- ✅ Must start with `cpe:2.3:` prefix
- ✅ Must have exactly 13 colon-separated components
- ✅ No non-ASCII characters in any field
- ✅ Vendor/product fields under 100 characters
- ✅ No complex escaped comma patterns in long fields
- ❌ **Culled** if any check fails with reason logged

**Specificity Validation (`validate_cpe_specificity()`)**:
- ✅ Must have at least vendor OR product specified (not both wildcards)
- ✅ Cannot be completely wildcarded
- ✅ Single populated attributes must be longer than 2 characters
- ❌ **Culled** if insufficient specificity with detailed reason

**Deduplication Process (`deriveCPEMatchStringList()`)**:
- Collects all validated CPE strings from all entries
- Converts to set for automatic deduplication
- Returns unique list for NVD API queries

#### 2.2.5 Final Output Structure

| Example | Generated CPE Base String | Status |
|--------------|---------------------------|---------|
| `raw`        | `cpe:2.3:*:raw_vendor:raw_product:*:*:*:*:*:*:*:*` | ✅ Validated |
| `curated`      | `cpe:2.3:*:curated_vendor:curated_product:*:*:*:*:*:*:mapped_targetHW:*` | ✅ Validated |
| `culled`      | `cpe:2.3:*:*:b:*:*:*:*:*:*:*:*` | ❌ Culled: "Two characters or less 'b' in only populated attribute 'product'" |

**Result Storage**:
- `cpeBaseStrings`: Array of validated, unique CPE strings ready for NVD queries
- `culledCpeBaseStrings`: Array of rejected CPE strings with specific culling reasons for transparency

#### Complete Generation Example (Organized by Specificity)

```python
# Input: {
#   "vendor": "apache", 
#   "product": "apache_kafka", 
#   "packageName": "org.apache:kafka", 
#   "platforms": ["x64", "x86"],
#   "cpes": ["cpe:2.3:a:apache:kafka:2.8.0:*:*:*:*:*:*:*"]
#   # Note: collectionURL and repo fields are not processed for CPE generation
# }

# SINGLE ATTRIBUTE PATTERNS (5 patterns):
[
  "cpe:2.3:*:apache:*:*:*:*:*:*:*:*:*:*",              # vendor-only
  "cpe:2.3:*:*:*kafka*:*:*:*:*:*:*:*:*",               # product-only (curated)
  "cpe:2.3:*:*:*apache_kafka*:*:*:*:*:*:*:*:*",        # product-only (raw)
  "cpe:2.3:*:org.apache:*:*:*:*:*:*:*:*:*:*",          # packageName GroupId-only
  "cpe:2.3:*:*:*kafka*:*:*:*:*:*:*:*:*"                # packageName ArtifactId-only
]

# DUAL ATTRIBUTE PATTERNS (7 patterns):
[
  "cpe:2.3:*:apache:*apache_kafka*:*:*:*:*:*:*:*:*",   # vendor + product (raw)
  "cpe:2.3:*:apache:*kafka*:*:*:*:*:*:*:*:*",          # vendor + product (curated)
  "cpe:2.3:*:apache:*kafka*:*:*:*:*:*:*:*:*",          # vendor + packageName
  "cpe:2.3:*:org.apache:*kafka*:*:*:*:*:*:*:*:*",      # packageName GroupId + ArtifactId
  # CPE Array Processing (from cpes: ["cpe:2.3:a:apache:kafka:2.8.0:*:*:*:*:*:*:*"]):
  "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*",            # Exact CPE (version wildcarded)
  "cpe:2.3:a:apache:*kafka*:*:*:*:*:*:*:*:*"           # Wildcarded product search
]

# TRIPLE ATTRIBUTE PATTERNS (14 patterns = 7 dual × 2 architectures):

# x64 Architecture Variants:
[
  "cpe:2.3:*:apache:*apache_kafka*:*:*:*:*:*:*:x64:*",   # vendor + product (raw) + x64
  "cpe:2.3:*:apache:*kafka*:*:*:*:*:*:*:x64:*",          # vendor + product (curated) + x64
  "cpe:2.3:*:apache:*kafka*:*:*:*:*:*:*:x64:*",          # vendor + packageName + x64
  "cpe:2.3:*:org.apache:*kafka*:*:*:*:*:*:*:x64:*",      # packageName GroupId + ArtifactId + x64
  "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:x64:*",            # Exact CPE + x64
  "cpe:2.3:a:apache:*kafka*:*:*:*:*:*:*:x64:*",          # Wildcarded product search + x64
  "cpe:2.3:*:apache:*apache_kafka*:*:*:*:*:*:*:x64:*"    # vendor + product (raw) + x64
]

# x86 Architecture Variants:
[
  "cpe:2.3:*:apache:*apache_kafka*:*:*:*:*:*:*:x86:*",   # vendor + product (raw) + x86
  "cpe:2.3:*:apache:*kafka*:*:*:*:*:*:*:x86:*",          # vendor + product (curated) + x86
  "cpe:2.3:*:apache:*kafka*:*:*:*:*:*:*:x86:*",          # vendor + packageName + x86
  "cpe:2.3:*:org.apache:*kafka*:*:*:*:*:*:*:x86:*",      # packageName GroupId + ArtifactId + x86
  "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:x86:*",            # Exact CPE + x86
  "cpe:2.3:a:apache:*kafka*:*:*:*:*:*:*:x86:*",          # Wildcarded product search + x86
  "cpe:2.3:*:apache:*apache_kafka*:*:*:*:*:*:*:x86:*"    # vendor + product (raw) + x86
]

# TOTAL: 19 unique CPE base strings
# Note: packageName processing handles colon-delimited formats (Maven, npm, etc.) by splitting
#       into GroupId and ArtifactId components for comprehensive coverage
```

---

## Stage 3: NVD /cpes/ API Query & Processing

**Location**: `src/analysis_tool/core/processData.py` → `bulkQueryandProcessNVDCPEs()`

### 3.1 CPE Cache Flow

1. **Cache Check**: Query local cache for previous results
2. **API Call**: Make NVD /cpes/ API call if cache miss/expired
3. **Cache Storage**: Store successful API responses

### 3.2 NVD API Query Process

**API Endpoint**: `gatherData.gatherNVDCPEData(apiKey, "cpeMatchString", query_string)`

**Query Parameters**:
- `cpeMatchString`: CPE base string to search
- `resultsPerPage`: 2000 (maximum)
- Pagination handling for large result sets

**API Response Structure**:
```json
{
  "resultsPerPage": 2000,
  "startIndex": 0,
  "totalResults": 156,
  "format": "NVD_CPE",
  "version": "2.0",
  "timestamp": "2024-11-10T20:30:45.123",
  "products": [
    {
      "cpe": {
        "cpeName": "cpe:2.3:a:example_vendor:example_product:2.1.4:*:*:*:*:*:*:*",
        "deprecated": false,
        "created": "2024-01-15T15:20:10.000",
        "lastModified": "2024-01-15T15:20:10.000"
      }
    }
  ]
}
```

### 3.3 Response Processing

**Location**: `analyzeBaseStrings()` in `src/analysis_tool/core/processData.py`

This stage performs comprehensive data extraction, consolidation, and mapping between NVD 2.0 /cpes/ API responses and affected entry data from CVE List V5 records.

#### 3.3.1 Data Extraction Pipeline

**API Response Structure Processing**:
```python
# Input: NVD API /cpes/ response
{
  "totalResults": 156,
  "resultsPerPage": 2000,
  "products": [
    {
      "cpe": {
        "cpeName": "cpe:2.3:a:apache:kafka:2.8.0:*:*:*:*:*:*:*",
        "deprecated": false,
        "created": "2024-01-15T15:20:10.000",
        "lastModified": "2024-01-15T15:20:10.000",
        "refs": [
          {"ref": "https://kafka.apache.org", "type": "Vendor"}
        ]
      }
    }
  ]
}

# Processing: Extract and normalize CPE components
for product in json_response["products"]:
    cpe_name = product["cpe"]["cpeName"]
    cpe_attributes = breakoutCPEAttributes(cpe_name)
    base_cpe_name = constructSearchString(cpe_attributes, "base")
```

#### 3.3.2 Data Consolidation and Aggregation

**Base String Aggregation**:
- **Purpose**: Group all CPE products by their base string (version/update wildcarded)
- **Key Transformation**: `cpe:2.3:a:apache:kafka:2.8.0:*:*:*:*:*:*:*` → `cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*`

**Statistical Accumulation**:
```python
base_strings = defaultdict(lambda: {
    "depTrueCount": 0,      # Count of deprecated CPE entries for this base
    "depFalseCount": 0,     # Count of active CPE entries for this base
    "versionsFound": 0,     # Total version matches found
    "versionsFoundContent": [],  # Detailed version match objects
    "references": []        # Aggregated reference data with frequency tracking
})
```

##### 3.3.2.1 Version Matching Logic

**Input Mapping**: Each affected entry contains `cpeVersionChecks` derived from version constraints. Version checks are performed against **ALL** CPE Names (both active and deprecated):
```python
# Example from affected entry processing
cpeVersionChecks = [
    {"version": "2.8.0"},
    {"lessThan": "3.0.0"},
    {"lessThanOrEqual": "2.8.5"}
]
```

##### 3.3.2.2 Reference Data Aggregation

**Reference Extraction**: Only from non-deprecated CPE products to avoid outdated provenance data
```python
if not product["cpe"]["deprecated"] and 'refs' in product['cpe']:
    for ref in product['cpe']['refs']:
        ref_url = ref.get('ref', '')
        ref_type = ref.get('type', 'Unknown')
        
        # Frequency tracking for duplicate references
        existing_ref = find_existing_reference(ref_url, ref_type)
        if existing_ref:
            existing_ref['frequency'] += 1
        else:
            add_new_reference(ref_url, ref_type, frequency=1)
```

#### 3.3.3 Affected Entry to Query String Mapping

**Location**: `bulkQueryandProcessNVDCPEs()` in `src/analysis_tool/core/processData.py`

**Purpose**: Track which affected entries contain relevant CPE Base String query results.

**Mapping Structure Example**:
```python
# Example mapping between CPE query strings and affected entry indices
row_query_mapping = {
    "cpe:2.3:*:apache:*kafka*:*:*:*:*:*:*:*:*": [0, 2, 5],       # 3 entries interested
    "cpe:2.3:*:apache:*:*:*:*:*:*:*:*:*:*": [0, 1, 2, 5],       # 4 entries interested  
    "cpe:2.3:*:*:*kafka*:*:*:*:*:*:*:*:*": [0, 2],              # 2 entries interested
    "cpe:2.3:*:microsoft:*office*:*:*:*:*:*:*:*:*": [1, 3, 4],  # 3 entries interested
    "cpe:2.3:*:org.apache:*kafka*:*:*:*:*:*:*:*:*": [2]         # 1 entry interested
}

# Benefits:
# - Single API call per unique CPE Base String
# - Entry-specific version matching against same NVD 2.0 /cpes/ API content
```

**Processing Flow**: For each unique CPE base string, the system queries the NVD API once and applies entry-specific version constraints to generate tailored results for each interested affected entry.

#### 3.3.4 Output Data Structure

> **Notes**:  
> The `query_analysis_results` structure shown below represents the internal processing format with `base_strings` as a container object. This will be transformed into the final NVD-ish `cpeSuggestionMetadata` array format where each CPE base string becomes a separate object with `cpeBaseString` as a property.  
> This metadata provides transparency into the analysis process, data quality metrics and contextually relevant data for each CPE suggestion. See [II.B. CPE Suggestion Metadata (NVD /cpes/ API Query Results)](nvd-ish_record_example.md#iib-cpe-suggestion-metadata-nvd-cpes-api-query-results).



**Consolidated Response Structure**:
```python
# Per-query statistics from analyzeBaseStrings() for single CPE base string query
query_analysis_results = {
    "base_strings": {
        # Each base string represents version-wildcarded grouping of CPE products from the query
        "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*": {
            "depTrueCount": 5,       # Deprecated CPE products for this version-wildcarded base
            "depFalseCount": 142,    # Active CPE products for this version-wildcarded base
            "versionsFound": 2,      # Count of version matches for this base
            "versionsFoundContent": [
                {"version": "cpe:2.3:a:apache:kafka:2.8.0:*:*:*:*:*:*:*"},
                {"lessThan": "cpe:2.3:a:apache:kafka:3.0.0:*:*:*:*:*:*:*"}
            ],
            "references": [
                {"url": "https://kafka.apache.org", "type": "Vendor", "frequency": 3},
                {"url": "https://github.com/apache/kafka", "type": "Advisory", "frequency": 1}
            ]
        },
        "cpe:2.3:a:apache:kafka_client:*:*:*:*:*:*:*": {
            "depTrueCount": 2,       # Different product variant found in same query
            "depFalseCount": 28,     # Active CPE products for this variant
            "versionsFound": 0,      # No version matches for this variant
            "versionsFoundContent": [],
            "references": []
        }
    }
}

# Row-specific results mapping query results to affected entries
row_specific_results = {
    0: query_analysis_results,  # Results for affected entry 0 from this query
    1: query_analysis_results,  # Results for affected entry 1 from this query  
    # ... additional entry mappings for entries interested in this CPE base string
}
```

---

## Stage 4: Top 10 CPE Suggestions Generation

**Location**: `src/analysis_tool/core/processData.py` → `reduceToTop10()`

### 4.1 Data Consolidation

**Function**: `consolidateBaseStrings()`

**Purpose**: Transform per-query analysis results from Stage 3 into consolidated CPE suggestion metadata for each affected entry (dataframe row), preparing data for ranking and final selection.

#### 4.1.1 Per-Affected-Entry Processing

**Processing Scope**: Each affected entry is processed individually to consolidate its unique set of CPE query results.

**Input Data Sources**:
```python
# For each affected entry row:
row_data = {
    'sortedCPEsQueryData': {
        # Multiple query results from Stage 3
        "cpe:2.3:*:apache:*kafka*:*:*:*:*:*:*:*:*": {
            "base_strings": {...},  # analyzeBaseStrings() output
            "total_deprecated": 7,
            "total_active": 170
        },
        "cpe:2.3:*:*:*kafka*:*:*:*:*:*:*:*:*": {
            "base_strings": {...},
            "total_deprecated": 12,
            "total_active": 89
        }
        # ... additional query results for this affected entry
    },
    'platformEntryMetadata': {
        'cpeVersionChecks': [...],  # Version constraints from affected entry
        'cpeSourceTypes': [...],    # Source type tracking
        'cpeBaseStrings': [...]     # Original generated CPE base strings
    }
}
```

#### 4.1.2 Base String Deduplication and Metadata Consolidation

**Consolidation Process**:

1. **Cross-Query Deduplication**  
   **Confidence Measurement through Search Source Diversity**: Count how many different CPE base string search queries returned the same result (`searchCount`) as a confidence indicator. When multiple independent search strategies discover the same CPE base string, it increases confidence the suggestion is relevant.
   
   ```python
   # Example: Same base string discovered through multiple independent searches
   # Query 1 (vendor+product): "cpe:2.3:*:apache:*kafka*:*:*:*:*:*:*:*:*" 
   # Query 2 (product-only): "cpe:2.3:*:*:*kafka*:*:*:*:*:*:*:*:*"
   # Query 3 (packageName-only): "cpe:2.3:*:*:*kafka*:*:*:*:*:*:*:*:*"
   # All discover: "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*"
   ```

2. **Search Source Value Tracking**  
   **Confidence Measurement through Search Source Specificity**: Identify the searchSource categories that returned analysis results. When results are available from a search source that is considered more valuable (e.g., `cpes` array data vs raw vendor extraction), it increases confidence the suggestion is relevant.
   
   **Search Source Hierarchy Examples** (ranked by value/specificity):
   - `searchSourcecveAffectedCPEsArray` --> (explicit CVE `cpes` arrays)  
   - `searchSourcevendorproduct` --> (vendor + product combinations)
   - `searchSourceproduct` --> (product-only searches)
   - `searchSourcevendor` --> (vendor-only searches)
   
   ```
   # These fields drive composite_priority ranking: primary_priority + secondary_priority
   # Higher value sources receive better ranking positions in final top 10 selection
   ```

3. **Version Match Validation and Deduplication**
   
   **Function**: `compare_versions()`
   
   **Purpose**: **Validate and refine** the existing `versionsFoundContent` data that was populated during Stage 3 (`analyzeBaseStrings()`). This consolidation step ensures version match consistency across merged base strings and deduplicates version matches. Version matches between the affected entry content and the CPE Names increases confidence the suggestion is relevant.

#### 4.1.3 Statistical Aggregation

**Metadata Consolidation**:
- **Count Aggregation**: `depTrueCount` and `depFalseCount` are preserved from the original query that first discovered each base string
- **Reference Frequency**: Reference URLs maintain frequency tracking from Stage 3 processing
- **Version Match Preservation**: `versionsFoundContent` arrays are carried forward for subsequent version comparison processing
- **Source Diversity Tracking**: `searchCount` indicates how many different generation methods found the same base string

#### 4.1.4 Output Structure per Affected Entry

**Consolidated Structure Example**:
```python
# Result for single affected entry after consolidation
unique_base_strings = {
    "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*": {
        # Preserved from original analyzeBaseStrings() output
        "depTrueCount": 5,
        "depFalseCount": 142,
        "versionsFound": 2,
        "versionsFoundContent": [...],
        "references": [...],
        
        # Added during consolidation
        "searchCount": 3,  # Found through 3 different generation methods
        "searchSourcevendor": "cpe:2.3:*:apache:*:*:*:*:*:*:*:*:*:*",
        "searchSourcevendorproduct": "cpe:2.3:*:apache:*kafka*:*:*:*:*:*:*:*:*",
        "searchSourcecveAffectedCPEsArray": "cpe:2.3:a:apache:kafka:2.8.0:*:*:*:*:*:*:*"
    },
    "cpe:2.3:a:apache:kafka_client:*:*:*:*:*:*:*:*": {
        "depTrueCount": 2,
        "depFalseCount": 28,
        "versionsFound": 0,
        "versionsFoundContent": [],
        "references": [],
        "searchCount": 1,
        "searchSourceproduct": "cpe:2.3:*:*:*kafka*:*:*:*:*:*:*:*:*"
    }
    # ... additional base strings for this affected entry
}
```

### 4.2 Ranking Algorithm

**Function**: `sort_base_strings()`

**Purpose**: Sort consolidated CPE base strings to identify the Top 10 most relevant suggestions for each affected entry.

#### 4.2.1 Sorting Process

**Sort Key Calculation**: Each CPE base string gets a 7-tuple score. **Lower values rank higher**.

```python
# Step 1: Calculate source type priority (0-13)
has_cpes_array = any(key.startswith('searchSourcecveAffectedCPEsArray'))
has_vendor_product = any(key.startswith('searchSourcevendorproduct'))
has_product = any(key.startswith('searchSourceproduct'))
has_vendor = any(key.startswith('searchSourcevendor'))

primary = 0 if has_cpes_array else 10  # CVE cpes = 0, Generated = 10
if has_vendor_product: secondary = 0
elif has_product: secondary = 1  
elif has_vendor: secondary = 2
else: secondary = 3

composite_priority = primary + secondary  # Final: 0-13

# Step 2: Calculate deprecation metrics
dep_true_count = attributes.get('depTrueCount', 0)
dep_false_count = attributes.get('depFalseCount', 0)
total_results = dep_true_count + dep_false_count

all_deprecated = (dep_false_count == 0 and dep_true_count > 0)
deprecation_ratio = dep_true_count / total_results if total_results > 0 else 1.0

# Step 3: Create final sort key
sort_key = (
  composite_priority,                    # 1. Source priority (0=CVE cpes+vendor+product, 13=Generated+other)
  all_deprecated,                        # 2. Has active CPEs? (False=good, True=bad)
  deprecation_ratio,                     # 3. Deprecated ratio (0.0=all active, 1.0=all deprecated)
  -dep_false_count,                      # 4. Active CPE count (more is better)
  -attributes.get('searchCount', 0),     # 5. Search source diversity (more is better)
  -attributes.get('versionsFound', 0),   # 6. Version matches (more is better)
  -total_results                         # 7. Total CPE volume (more is better)
)
```

**Output**: Top 10 entries from sorted results become the final CPE suggestions.

---

## Stage 5: Confirmed Mappings Detection

**Location**: `src/analysis_tool/core/processData.py`

**Purpose**: Detect and validate authoritative, human-verified CPE mappings for affected entries using external mapping files and alias matching logic.

This stage operates as an independent feature within the `--cpe-suggestions` processing pipeline, providing confirmed CPE base strings that represent verified mappings for specific vendor/product combinations.

### 5.1 Confirmed Mappings Processing Pipeline

**Functions**: `find_confirmed_mappings()`, `extract_confirmed_mappings_for_affected_entry()`, `process_confirmed_mappings()`

#### 5.1.1 Mapping File Detection and Loading

**Function**: `load_mapping_file(source_id)`

1. **Configuration Check**: Verify `confirmed_mappings.enabled` is true in config
2. **File Discovery**: Search the configured mappings directory for JSON files
3. **CNA ID Matching**: Load and check each file for matching `cnaId` field
4. **Structure Validation**: Ensure the mapping file contains a `confirmedMappings` array

#### 5.1.2 Alias Set Extraction from Affected Entry

**Function**: `extract_confirmed_mappings_for_affected_entry()` in `src/analysis_tool/core/processData.py`

Extract alias data from CVE List V5 affected entry fields into `raw_platform_data` structure for matching:
- **Primary Fields**: `vendor`, `product`, `platforms` (used in alias matching)
- **Additional Fields**: `modules`, `packageName`, `repo`, `programRoutines`, `programFiles`, `collectionURL` (extracted but not used in current matching logic)

#### 5.1.3 Alias Matching and Comparison Logic

**Function**: `check_alias_match(alias, raw_platform_data)` in `src/analysis_tool/core/processData.py`

**Matching Logic**: The confirmed mappings system uses an exact-match approach with comprehensive placeholder filtering:

1. **Required Field Validation**: Check `vendor` and `product` for exact matches (case-insensitive, normalized)
2. **Placeholder Filtering**: CVE data containing `GENERAL_PLACEHOLDER_VALUES` is excluded from matching before comparison
3. **Optional Platform Validation**: Check `platform` (singular) field against `platforms` array, filtering out placeholder platforms
4. **Exact Matching Only**: No partial or fuzzy matching - "office" ≠ "microsoft office"
5. **Case-Insensitive**: "Microsoft" matches "microsoft"

#### 5.1.4 CPE Base String Specificity Filtering

**Function**: `filter_most_specific_cpes(confirmed_cpe_bases)`

1. **Collect Matches**: Gather all `cpeBaseString` values where aliases matched
2. **Specificity Comparison**: Use `is_more_specific_than()` to compare CPE components
3. **Culling Process**: Remove less specific CPE base strings to avoid redundancy
4. **Result Separation**: Return filtered confirmed mappings and track culled mappings

---

## Stage 6: NVD-ish Record Integration

**Location**: `src/analysis_tool/logging/nvd_ish_collector.py`

**Purpose**: Convert all CPE suggestion processing results (Top 10, confirmed mappings, searched/culled strings) into the final NVD-ish record structure.

### 6.1 Data Collection and Assembly

The collector integrates multiple data sources into the final `cpeSuggestions` structure:

---

## Final Output: Complete cpeSuggestions Structure

```json
{
  "cpeSuggestions": {
    "sourceId": "Hashmire/Analysis_Tools v0.2.0",
    "cvelistv5AffectedEntryIndex": "cve.containers.cna.affected.[0]",
    "top10SuggestedCPEBaseStrings": [
      {
        "cpeBaseString": "cpe:2.3:a:example_vendor:example_product:*:*:*:*:*:*:*:*",
        "rank": "1"
      },
      {
        "cpeBaseString": "cpe:2.3:a:example_vendor:*:*:*:*:*:*:*:*:*",
        "rank": "2"
      }
    ],
    "confirmedMappings": [
      "cpe:2.3:a:example_vendor:example_product:*:*:*:*:*:*:*:*",
      "cpe:2.3:a:example_vendor:*:*:*:*:*:*:*:*:*"
    ],
    "cpeMatchStringsSearched": [
      "cpe:2.3:a:example_vendor:example_product:*:*:*:*:*:*:*:*",
      "cpe:2.3:a:example_vendor:*:*:*:*:*:*:*:*:*",
      "cpe:2.3:*:example_vendor:example_product:*:*:*:*:*:*:*:*",
      "cpe:2.3:a:*:example_product:*:*:*:*:*:*:*:*"
    ],
    "cpeMatchStringsCulled": [
      {
        "cpeString": "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*",
        "reason": "insufficient_specificity_vendor_product_required"
      },
      {
        "cpeString": "cpe:2.3:*:extremely_long_vendor_name_that_exceeds_one_hundred_characters:*:*:*:*:*:*:*:*:*",
        "reason": "nvd_api_field_too_long"
      }
    ]
  }
}