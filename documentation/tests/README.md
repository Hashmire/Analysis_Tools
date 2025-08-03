# 🧪 Test Documentation

Test suite documentation for the Analysis Tools CVE analysis system.

## **🚀 Unified Test Runner**

The recommended way to run all tests is using the unified test runner:

```bash
python test_files\run_all_tests.py
```

**Options:**
- `--verbose` or `-v`: Show detailed test output and error messages

**Features:**
- Executes all 6 test suites automatically
- Provides comprehensive summary reporting
- Enhanced error transparency for debugging
- Standardized output parsing across all suites
- Individual test count aggregation (161 total tests)

## **📊 Test Suite Overview**

| **Test Suite** | **Tests** | **Purpose** |
|:---------------|:----------|:------------|
| **Logging System** | 53 | Structured logging and workflow validation |
| **Modular Rules** | 16 | JSON generation rules and HTML validation |
| **Platform Badges** | 67 | Badge/modal system, data quality validation, and overlapping ranges detection |
| **Confirmed Mappings** | 10 | Confirmed mappings pipeline and data flow |
| **Provenance Assistance** | 10 | CPE provenance functionality and HTML generation |
| **NVD Source Manager** | 10 | Source data integration and resolution |

**Total: 166 individual tests** - All must maintain 100% pass rate.

## **🔧 Individual Test Suite Execution**

For debugging specific issues, test suites can be run individually:

```bash
# Core system validation
python test_files\test_logging_system.py                                              # 53 tests
python test_files\test_platform_badges.py                                             # 67 tests

# HTML generation and processing  
python test_files\test_modular_rules.py test_files\testModularRulesEnhanced.json     # 16 tests
python test_files\test_provenance_assistance.py test_files\testProvenanceAssistance.json  # 10 tests

# Data pipeline validation
python test_files\test_confirmed_mappings.py                                          # 10 tests
python test_files\test_nvd_source_manager.py                                          # 10 tests
```

## **📋 Test Output Format**

All test suites use standardized output format for unified runner compatibility:

```
TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"
```

**Error Reporting:**
- **Success**: Clean, minimal output
- **Failures**: Automatic display of diagnostic information including:
  - Error details from stderr
  - Diagnostic output from stdout
  - Specific test failure information
  - Return codes for subprocess issues

## **🎯 Testing Guidelines**

### **Before Making Changes:**
1. Run `python test_files\run_all_tests.py` to establish baseline
2. Make changes following copilot instructions
3. Re-run `python test_files\run_all_tests.py` to verify no regressions

### **Debugging Test Failures:**
1. Use `python test_files\run_all_tests.py --verbose` for detailed output
2. Run individual test suite for focused debugging
3. Check generated HTML files in `runs/` directories for validation issues

### **Adding New Tests:**
1. Follow existing standardized output pattern
2. Include new test suite in `test_files\run_all_tests.py` configuration
3. Update test counts in documentation
4. Verify unified runner integration

## **📚 Individual Test Suite Documentation**

All individual test suite documentation has been simplified to focus on core validation areas and unified runner integration:

- `logging_test_suite.md` - Structured logging system validation (53 tests)
- `modular_rules_test_suite.md` - JSON generation rules and HTML validation (16 tests)
- `platform_badges_test_suite.md` - Badge/modal system and data quality validation (62 tests)
- `confirmed_mappings_test_suite.md` - Data pipeline and mapping validation (10 tests)  
- `provenance_assistance_test_suite.md` - CPE provenance and HTML generation (10 tests)
- `nvd_source_manager_test_suite.md` - Source data integration testing (10 tests)

**Documentation Pattern:**
- **📊 Overview** - Purpose and test count
- **🚀 Execution** - Unified runner + individual execution
- **🎯 Core Validation Areas** - Key functionality groups (3-4 sections)
- **✅ Success Criteria** - Pass rate requirements and critical validations
- **🔧 Implementation Details** - Framework and dependencies (minimal)
