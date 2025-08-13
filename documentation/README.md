# 📚 Analysis Tools Documentation

This directory contains comprehensive documentation for the Hashmire/Analysis_Tools system.

## 📁 Documentation Structure

### **General Documentation** (this directory)

- **System Architecture & Features**
- **Usage Guides**  
- **API References**
- **Implementation Details**

---

## 📄 Documentation Files

| File | Purpose |
|------|---------|
| `badge_modal_system_reference.md` | Complete badge and modal system implementation reference |
| `cpes_api_caching_system.md` | CPE API caching implementation and performance optimization |
| `dashboard_usage.md` | Real-time dashboard system comprehensive usage guide |
| `dataset_generation.md` | Dataset generation methodology and capabilities |
| `logging_system.md` | Structured logging system architecture and patterns |

## 🏗️ Architecture Overview

The Analysis Tools system follows a unified runs structure where all outputs are contained in timestamped run directories:

```text
runs/[timestamp]_[context]/
├── generated_pages/    # HTML reports for this run
├── logs/              # Run-specific logs  
├── reports/           # Dashboard data for this run
└── logs/              # All data files, tracking, and monitoring
```

### Key Components

- **Entry Points**: `run_tools.py` (CVE analysis), `generate_dataset.py` (dataset generation)
- **Core Engine**: `src/analysis_tool/core/analysis_tool.py`
- **Run Management**: `src/analysis_tool/storage/run_organization.py`
- **Dashboard System**: `dashboards/` (real-time monitoring system)
- **Dashboard Data Collection**: `src/analysis_tool/logging/dataset_contents_collector.py`
- **Shared Cache**: `cache/` directory for CPE API responses

### Testing

All test suites maintain 100% pass rate requirements with complete integration:

- **Source Data Concern Badge Data Collector JSON** (101 tests) - Complete badge contents collection system
- **Platform Badge Tests** (67 tests) - Complete badge system validation  
- **Modular Rules** (16 tests) - JSON generation rules
- **Logging System** (53 tests) - Structured logging validation
- **Confirmed Mappings** (10 tests) - Complete confirmed mappings pipeline validation
- **Provenance Assistance** (10 tests) - Package repository detection
- **NVD Source Manager** (10 tests) - Source data integration and resolution
- **Source Data Concern Dashboard Webpage** (90 tests) - Standalone dashboard validation
- **Source Data Concern Dashboard** (157 tests) - Complete dashboard integration testing

**Total: 514 tests across 9 test suites**

Execute all tests: `python test_files\run_all_tests.py`
