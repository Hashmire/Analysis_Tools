# CPE Cache System - Reference Documentation

**Version**: 3.0  
**Date**: February 2026  
**Status**: Production

---

## Overview

The CPE cache system provides persistent storage and retrieval of NVD CPE API responses to minimize redundant API calls during CVE analysis. The system uses a sharded architecture with hash-based distribution, lazy loading, and proactive memory management.

**Architecture**: 16-shard distributed cache (compact JSON format)  
**Memory Management**: Proactive eviction with configurable memory limits  
**Data Integrity**: 4-layer validation prevents corrupted data from entering cache

---

## Architecture Components

### 1. Sharded Cache Storage
Hash-based distributed cache with lazy loading and compact JSON persistence.

### 2. Data Validation System
4-layer validation (HTTP → JSON → Schema → Serialization) ensures only valid NVD data enters cache.

### 3. Memory Management
Proactive eviction maintains configurable shard limits to prevent memory exhaustion during processing.

### 4. Manual Refresh Tool
Standalone script (`refresh_nvd_cpe_base_strings_cache.py`) for controlled cache updates independent of runtime expiration settings.

---

## Sharded Cache Architecture

### Hash-Based Shard Distribution

**Implementation**: See [src/analysis_tool/storage/cpe_cache.py](../src/analysis_tool/storage/cpe_cache.py)
- `ShardedCPECache._get_shard_index()` - MD5 hash-based shard routing
- `ShardedCPECache._get_shard_filename()` - Shard file naming convention

**Shard Distribution**:
- MD5 hash-based distribution assists with more even distribution across shards

**File Structure**:
```
cache/
  cpe_base_strings/
    cpe_cache_shard_00.json
    cpe_cache_shard_01.json
    ...
    cpe_cache_shard_15.json
  cache_metadata.json        (shard count, last modified)
```

**Key Benefits**:
1. **Lazy Loading**: Only load shards containing requested CPE strings
2. **Fast Access**: Load individual shards in ~0.1s as needed
3. **Memory Management**: Proactive eviction enforces hard memory limits (default: 4 shards max)
4. **Scalability**: System handles large cache sizes without memory exhaustion
5. **Data Integrity**: NVD schema validation prevents corrupted data from entering cache

---

### Proactive Memory Eviction

**Implementation**: See [src/analysis_tool/storage/cpe_cache.py](../src/analysis_tool/storage/cpe_cache.py) `_load_shard()` method
- **Hard Memory Limit**: Enforces `max_loaded_shards` limit (default: 4)
- **Proactive Strategy**: Checks limit BEFORE loading new shard (prevents spikes)
- **Dirty Shard Handling**: Saves shards with unsaved changes before eviction
- **Run-Boundary Cleanup**: Additional eviction at end of dataset generation runs

**Memory Management Example**:
```
Processing Run (default: max 4 shards in memory):
  Load shard 0 (CPE batch 1)
  Load shard 3 (CPE batch 2)
  Load shard 7 (CPE batch 3)
  Load shard 11 (CPE batch 4)
  
  Attempt to load shard 5:
    → Memory limit reached (4/4 shards loaded)
    → Save shard 0 if dirty
    → Evict shard 0 from memory
    → Load shard 5 (now 4/4 shards: 3,7,11,5)
  
  Continue processing...
  
  End of run:
    → Save all dirty shards
    → Evict all shards
    → Memory freed for next run
```

**Configuration**:
```json
{
  "cache_settings": {
    "cpe_cache": {
      "max_loaded_shards": 4  // Default: 4 (~1.2GB memory)
    }
  }
}
```


---

## Cache Implementation

**Core Class**: `ShardedCPECache` in [src/analysis_tool/storage/cpe_cache.py](../src/analysis_tool/storage/cpe_cache.py)

**Key Methods**:
- `get()` - Retrieve cache entry with lazy shard loading
- `put()` - Store cache entry with validation and proactive eviction
- `_load_shard()` - Lazy load with proactive memory limit enforcement
- `save_all_shards()` - Persist loaded shards to disk (skips clean shards)
- `save_changed_shards_only()` - Efficient save for end-of-run cleanup
- `evict_all_shards()` - Clear memory while keeping singleton alive
- `load_shard_from_disk()` - Static method for external shard loading
- `save_shard_to_disk()` - Static method for external shard saving

**Data Validation**: `validate_nvd_cpe_response()` in [src/analysis_tool/core/schema_validator.py](../src/analysis_tool/core/schema_validator.py)
- 4-layer validation: HTTP integrity → JSON parsing → NVD schema → orjson serialization
- Prevents corrupted data from NVD API entering cache
- Used in `gatherData.py` at API boundary (lines 856, 920)

**Global Manager**: `GlobalCPECacheManager` - Singleton wrapper for session-level cache management

---

## Manual Cache Refresh Script

**Script**: [utilities/refresh_nvd_cpe_base_strings_cache.py](../utilities/refresh_nvd_cpe_base_strings_cache.py)  
**Purpose**: Standalone forced refresh of oldest cached CPE base strings independent of runtime expiration settings

### Refresh Process

**Phase 1: Discovery**
- Scans all shards to find oldest timestamp
- Queries NVD `/cpematch/2.0` API for changes since oldest entry
- Automatically handles corrupted shards (logs diagnostics, deletes, continues)

**Phase 2: Selective Refresh**
- Only refreshes CPE base strings that changed at NVD
- Retrieves full metadata from `/cpes/2.0` API

**Phase 3: Finalize**
- Merges updates while preserving query_count statistics
- Persists changes to appropriate shards
- Automatically handles corrupted shards during merge (logs diagnostics, rebuilds)

### Automatic Corruption Recovery

The script includes reactive corruption handling that activates when shard loading fails:

**Detection & Diagnosis**:
- Detects JSON syntax errors, UTF-8 encoding issues, truncated files, disk corruption
- Categorizes corruption type (NVD API errors, validation bypasses, disk failures)
- Logs detailed diagnostics (file size, corruption category, error details, recommendations)

**Recovery Actions**:
- Auto-deletes corrupted shards to allow clean rebuild
- Continues refresh operation with remaining valid shards
- Rebuilt shards contain only CPE entries modified since oldest valid entry

**Note**: Deleted shard data is permanently lost. For full recovery, consider periodic backups of `cache/cpe_base_strings/`.

### Implementation Details

**Key Functions**:
- `find_oldest_cache_entry()` - Scans shards to find oldest timestamp (Phase 1)
- `query_cpematch_changes()` - Queries NVD change tracking API (Phase 1)
- `extract_unique_cpe_bases()` - Extracts unique CPE base strings (Phase 1)
- `query_nvd_cpes_api()` - Retrieves full metadata from CPE API (Phase 2)
- `flush_staged_updates()` - Merges updates while preserving statistics (Phase 3)
- `diagnose_shard_corruption()` - Analyzes corruption cause and provides diagnostics
- `log_corruption_diagnostics()` - Logs detailed corruption information before recovery

### Usage

```bash
# Run cache refresh (requires NVD API key configured in config.json)
python -m utilities.refresh_nvd_cpe_base_strings_cache
```

**Requirements**:
- Valid NVD API key in `src/analysis_tool/config.json` (`default_api_key` setting)
- Existing cache directory: `cache/cpe_base_strings/`

---

## Configuration

**Configuration File**: [src/analysis_tool/config.json](../src/analysis_tool/config.json)

**Relevant Settings**:
```json
{
  "cache_settings": {
    "cpe_cache": {
      "enabled": true,
      "sharding": {
        "num_shards": 16
      },
      "max_loaded_shards": 4,
      "auto_save_threshold": 50,
      "refresh_strategy": {
        "notify_age_hours": 0
      }
    }
  }
}
```

**Key Parameters**:
- `enabled`: Enable/disable CPE caching (default: true)
- `num_shards`: Number of shard files (default: 16)
- `max_loaded_shards`: Memory limit in shards (default: 4 ≈ 1.2GB)
- `auto_save_threshold`: Trigger auto-save after N new entries (default: 50)
- `notify_age_hours`: Runtime expiration threshold (recommended: 0 to disable auto-refresh)

### File Locations

**CPE Cache Storage**:
- `cache/cpe_base_strings/cpe_cache_shard_00.json` through `cpe_cache_shard_15.json` - Individual cache shards
- `cache/cache_metadata.json` - Shard metadata (count, timestamps)

**NVD Schema Cache**:
- `cache/nvd_schemas/cpe_api_2.0_schema.json` - CPE API schema (auto-downloaded from NVD)
- `cache/nvd_schemas/cve_api_2.0_schema.json` - CVE API schema (auto-downloaded from NVD)

**Scripts**:
- [utilities/refresh_nvd_cpe_base_strings_cache.py](../utilities/refresh_nvd_cpe_base_strings_cache.py) - Manual cache refresh utility
- [utilities/refresh_nvd_cves_2_0_cache.py](../utilities/refresh_nvd_cves_2_0_cache.py) - Manual NVD CVE cache refresh utility
- [src/analysis_tool/core/schema_validator.py](../src/analysis_tool/core/schema_validator.py) - Validation implementation

### Testing

**Test Suites**:
- [test_suites/tool_infrastructure/test_cpe_cache.py](../test_suites/tool_infrastructure/test_cpe_cache.py) - Cache functionality (13 tests)
- [test_suites/tool_infrastructure/test_cpe_cache_eviction.py](../test_suites/tool_infrastructure/test_cpe_cache_eviction.py) - Proactive eviction (6 tests)
- [test_suites/validation/test_nvd_schema_validation.py](../test_suites/validation/test_nvd_schema_validation.py) - Data validation (21 tests)

**Run Tests**:
```bash
python test_suites/tool_infrastructure/test_cpe_cache.py
python test_suites/tool_infrastructure/test_cpe_cache_eviction.py
python test_suites/validation/test_nvd_schema_validation.py
```

---

## Error Handling

**Implementation**: See [src/analysis_tool/storage/cpe_cache.py](../src/analysis_tool/storage/cpe_cache.py)

### Load Failures
**Behavior**: `load_shard_from_disk()` raises `RuntimeError` if shard file exists but cannot be loaded (corruption, I/O error).

**Recovery**: Investigate and repair corrupted shard file, then retry operation.

### Save Failures
**Behavior**: `save_shard_to_disk()` logs warnings but does not raise exceptions. Cache remains in memory for retry on next save attempt.

**Rationale**: Transient I/O errors should not terminate long-running analysis. Data persists in memory until successful save.
