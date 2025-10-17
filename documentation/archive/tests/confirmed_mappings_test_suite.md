# Confirmed Mappings Test Suite

## **📊 Overview**

Validates the complete confirmed mappings data pipeline with **10 test cases** from mapping file ingestion through HTML generation.

**Purpose:** Ensures alias matching logic, badge generation, modal content creation, and integration with the badge modal system.

## **🚀 Execution**

### **Unified Runner (Recommended):**
```bash
python test_files\run_all_tests.py
```

### **Individual Execution:**
```bash
python test_files\test_confirmed_mappings.py
```

## **🎯 Core Validation Areas**

### **Data Ingestion & Processing**
- Mapping file loading with JSON structure validation
- Module imports from `analysis_tool.core.processData`
- End-to-end confirmed mappings detection and dataset processing

### **Alias Matching Logic**
- **Exact property matching** (vendor/product) with case-insensitive comparison
- **No partial matching** allowed - prevents false positives
- CPE culling functionality through end-to-end detection

### **HTML Generation & Integration**
- Badge creation with proper styling and tooltips
- Modal content generation with confirmed mapping tabs
- Integration with badge modal system
- Generated confirmed mappings in badge content and modal data

### **Edge Cases & Error Handling**
- Empty data and malformed entries
- Non-existent source IDs and missing files
- Error recovery and graceful degradation

## **✅ Success Criteria**

- **100% pass rate** required (10/10 tests)
- **Critical import test** must pass before other tests execute
- **Exact alias matching** validation with no false positives
- **Complete HTML integration** with badge and modal systems

## **🔧 Implementation Details**

**Test Framework:** Custom test suite with NVD source manager integration
**Dependencies:** Confirmed mappings modules, badge modal system, temporary file management
**Coverage:** Complete data pipeline from ingestion through HTML output

For comprehensive test case details and mapping file structure requirements, see the test file source code.
- **Expected Outcome**: 100% test success rate with comprehensive confirmed mappings functionality

---

## Test Categories

### 1. Data Ingestion and Structure Validation

#### Test 1: Module Imports (`DATA_INGESTION_IMPORTS`)

**Purpose**: Verifies all necessary modules can be imported for confirmed mappings functionality.

**Modules Tested**:
- `load_mapping_file` - Loads mapping JSON files by source ID
- `find_confirmed_mappings` - Detects confirmed mappings for platform data
- `process_confirmed_mappings` - Processes dataset with confirmed mappings
- `check_alias_match` - Validates alias matching logic
- `convertRowDataToHTML` - Generates HTML with confirmed mappings badges
- `create_run_directory` - Creates organized output directories

**Expected Behavior**: All imports succeed without exceptions.

#### Test 2: Mapping File Loading (`MAPPING_FILE_LOADING`)

**Purpose**: Validates mapping file structure and content.

**Test Scenarios**:
- **Primary**: Microsoft mapping file (`f38d906d-7342-40ea-92c1-6c4a2c6478c8`)
- **Fallback**: Apple, IBM, Linux Kernel mapping files
- **Structure Validation**: `confirmedMappings` array with `cpebasestring` and `aliases`

**Expected Behavior**: Mapping file loads with valid structure containing confirmed mappings array.

**Validation Points**:
- JSON file loads successfully
- Contains `confirmedMappings` array
- Each mapping has CPE base string and aliases array
- Reports number of mappings found

### 2. Alias Matching Logic

#### Test 3: Alias Matching Validation (`ALIAS_MATCHING_LOGIC`)

**Purpose**: Validates exact property matching requirements for alias detection.

**Test Cases**:

```json
{
  "exact_match": {
    "alias": {"vendor": "microsoft", "product": "windows"},
    "raw_data": {"vendor": "microsoft", "product": "windows"},
    "expected": true
  },
  "case_insensitive": {
    "alias": {"vendor": "Microsoft", "product": "Windows"},
    "raw_data": {"vendor": "microsoft", "product": "windows"},
    "expected": true
  },
  "partial_vendor_fail": {
    "alias": {"vendor": "micro", "product": "windows"},
    "raw_data": {"vendor": "microsoft", "product": "windows"},
    "expected": false
  },
  "partial_product_fail": {
    "alias": {"vendor": "microsoft", "product": "office"},
    "raw_data": {"vendor": "microsoft", "product": "microsoft office"},
    "expected": false
  }
}
```

**Expected Behavior**: Only exact property matches succeed (case-insensitive).

**Critical Rule**: No partial matching allowed - "office" does not match "microsoft office".

### 3. End-to-End Processing

#### Test 3: Confirmed Mappings Detection (`CONFIRMED_MAPPINGS_DETECTION`)

**Purpose**: Validates complete confirmed mappings detection workflow.

**Test Data**:
```json
{
  "vendor": "microsoft",
  "product": "windows 10 version 1809"
}
```

**Expected Behavior**: Returns confirmed mappings with valid CPE 2.3 format strings.

#### Test 4: Dataset Processing (`DATASET_PROCESSING`)

**Purpose**: Tests confirmed mappings processing on DataFrame datasets.

**Process**:

1. Create test DataFrame with platform data
2. Process through `process_confirmed_mappings`
3. Verify confirmed mappings added to `platformEntryMetadata`

**Expected Behavior**: Confirmed mappings appear in processed dataset metadata.

### 4. HTML Generation and Badge System

#### Test 5: Badge Generation (`BADGE_GENERATION`)

**Purpose**: Validates confirmed mappings badge creation with proper styling and content.

**Test Conditions**:
- 2 confirmed mappings
- 1 culled confirmed mapping
- Success badge styling (`bg-success`)
- Tooltip with count and culled information

**Expected Elements**:
- Badge text: "Confirmed Mappings: 2"
- Tooltip: "Confirmed CPE mappings available (2) - Less specific mappings filtered out"
- Success styling class

#### Test 6: Modal Content Generation (`MODAL_CONTENT_GENERATION`)

**Purpose**: Tests modal content creation for confirmed mappings display.

**Test Data**: CPE mappings for Microsoft Office 2019 and Windows 10 1809

**Expected Behavior**:

- Modal trigger elements present
- Confirmed mapping data included in HTML
- CPE strings appear in content

#### Test 7: HTML Structure Validation (`HTML_STRUCTURE_VALIDATION`)

**Purpose**: Validates overall HTML structure with confirmed mappings.

**Validation Points**:

- Table structure present
- Badge content included
- Confirmed mappings text
- CPE data format

### 5. Edge Cases and Integration

#### Test 8: Edge Cases and Error Handling (`EDGE_CASES_ERROR_HANDLING`)

**Purpose**: Tests error handling for malformed or missing data.

**Edge Cases**:

- Empty raw data (`{}`)
- Non-existent source ID
- Malformed vendor/product data

**Expected Behavior**: All cases return empty arrays without throwing exceptions.

#### Test 9: Badge Modal System Integration (`BADGE_MODAL_SYSTEM_INTEGRATION`)

**Purpose**: Validates integration with the broader badge modal system.

**Integration Indicators**:

- Badge content presence
- CPE content inclusion
- Bootstrap modal attributes
- Supporting information integration

**Success Criteria**: At least 2 out of 4 integration indicators present.

---

## Key Technical Details

### Alias Matching Requirements

- **Exact Property Matching**: All specified alias properties must match exactly
- **Case Insensitive**: Matching ignores case differences
- **No Partial Matching**: "office" does not match "microsoft office"
- **Vendor-Only Aliases**: Supported for broad vendor matching

### CPE Culling Integration

CPE culling functionality is validated through:

- **End-to-End Detection**: Tests confirm that `find_confirmed_mappings` returns both mappings and culled results
- **Badge Tooltips**: Validation that "Less specific mappings filtered out" appears in tooltip text
- **Integration Testing**: Confirmed mappings appear correctly in HTML generation pipeline

The core CPE filtering logic in `processData.py` implements scope-aware filtering to prevent inappropriate cross-vendor comparisons.

### Test Suite Execution

The test suite runs in sequence with dependency checking:

1. **Import Validation** - Must pass for subsequent tests
2. **Core Functionality** - Mapping files, alias matching, confirmed mappings detection
3. **Processing Pipeline** - Dataset processing and integration
4. **HTML Generation** - Badges, modals, structure validation
5. **Edge Cases** - Error handling and integration testing

## Expected Output

**Success**: All 10 tests pass with comprehensive confirmed mappings functionality

**Key Success Indicators**:

- ✅ Alias matching requires exact matches
- ✅ CPE culling functionality validated through end-to-end detection and tooltips
- ✅ Badges generated with proper styling and tooltips
- ✅ Modal content includes confirmed mapping data
- ✅ Edge cases handled without exceptions

**Test Results Format**:

```bash
📊 SUMMARY:
   Total Tests: 10
   ✅ Passed: 10
   ❌ Failed: 0
   📈 Success Rate: 100.0%
```

## Debugging

If tests fail:

1. **Import Failures**: Check Python path and module structure
2. **Mapping File Issues**: Verify mapping files exist in `src/analysis_tool/mappings/`
3. **CPE Culling Failures**: Check `is_more_specific_than` logic for scope validation
4. **HTML Generation Issues**: Ensure NVD Source Manager initializes correctly
5. **Integration Problems**: Verify badge modal system components are functional

The test suite provides detailed failure messages indicating which specific components need attention.
