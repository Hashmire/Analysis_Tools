# CPE Cache System - Reference Documentation

**Version**: 3.0  
**Date**: February 2026  
**Status**: Production

---

## Overview

The CPE cache system provides persistent storage and retrieval of NVD CPE API responses to minimize redundant API calls during CVE analysis. The system uses a sharded architecture with hash-based distribution, lazy loading, and run-boundary memory management.

**Architecture**: 16-shard distributed cache (compact JSON format)  
**Memory Management**: Lazy loading with automatic eviction between processing runs

---

## Architecture Components

### 1. Sharded Cache Storage
Hash-based distributed cache with lazy loading and compact JSON persistence.

### 2. Manual Refresh Tool
Standalone script (`refresh_cpe_cache.py`) for controlled cache updates independent of runtime expiration settings.



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
3. **Memory Management**: Run-boundary eviction clears memory between processing runs
4. **Scalability**: System handles large cache sizes without memory exhaustion

---

### Run-Boundary Eviction

**Implementation**: See [generate_dataset.py](../generate_dataset.py) lines ~1175-1191
- Automatic save and eviction at end of each dataset generation run
- Keeps singleton alive while freeing shard data from memory

**Processing Pattern (harvest workflow example)**:
```
Run 1 - Source A (Altium):
  Load shards 0,3,7 → Process CVEs → Save shards → Evict → Memory freed
  
Run 2 - Source B (GitHub):  
  Load shards 1,4,8 → Process CVEs → Save shards → Evict → Memory freed
  
Run 3 - Source C (GitLab):
  Load shards 2,5,9 → Process CVEs → Save shards → Evict → Memory freed
```

**Also applies to other modes**:
```
Run 1 - Last 7 days:
  Load shards 2,5,8,11 → Process CVEs → Save shards → Evict → Memory freed
  
Run 2 - Last 30 days:
  Load shards 0,1,3,7,9 → Process CVEs → Save shards → Evict → Memory freed
```
  
**Eviction Trigger**: Automatic at end of each generate_dataset run

**Applies to all processing modes**: --source-uuid (harvest workflow), --last-days, --start-date/--end-date, etc.

---

## Cache Implementation

**Core Class**: `ShardedCPECache` in [src/analysis_tool/storage/cpe_cache.py](../src/analysis_tool/storage/cpe_cache.py)

**Key Methods**:
- `get()` - Retrieve cache entry with lazy shard loading
- `put()` - Store cache entry in appropriate shard
- `save_all_shards()` - Persist loaded shards to disk
- `evict_all_shards()` - Clear memory while keeping singleton alive
- `load_shard_from_disk()` - Static method for external shard loading
- `save_shard_to_disk()` - Static method for external shard saving

**Global Manager**: `GlobalCPECacheManager` - Singleton wrapper for session-level cache management

---

## Manual Cache Refresh Script

**Script**: [utilities/refresh_cpe_cache.py](../utilities/refresh_cpe_cache.py)  
**Purpose**: Standalone forced refresh of oldest cached CPE base strings independent of runtime expiration settings

**Implementation Details**:
- `find_oldest_cache_entry()` - Scans all shards to find oldest timestamp
- `query_cpematch_changes()` - Queries NVD `/cpematch/2.0` API for changes
- `extract_unique_cpe_bases()` - Extracts unique CPE base strings from results
- `query_nvd_cpes_api()` - Retrieves full metadata from `/cpes/2.0` API
- `flush_staged_updates()` - Merges updates while preserving query_count statistics

### Recommended Strategy

**Configuration Approach**:
- Set `notify_age_hours: 0` (never auto-refresh) OR high value (e.g., `8760` = 365 days)
- Run `python -m utilities.refresh_cpe_cache` periodically as needed (manual control)
- Avoids wasteful time-based refreshes during normal CVE processing

**Why Manual Refresh**:
1. **Efficiency**: Time-based auto-refresh (`notify_age_hours`) triggers on EVERY cache access after expiration, causing redundant API calls
2. **Control**: Manual script processes oldest entries once, updates timestamps, prevents repeat refreshes
3. **Resource Management**: Run during off-hours/low-activity periods instead of mid-analysis

**Usage**:
```powershell
# Run manual refresh
python -m utilities.refresh_cpe_cache
```

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
- `notify_age_hours`: Runtime expiration threshold (recommended: 0 to disable auto-refresh)

### File Locations

**Cache Files**: `cache/cpe_base_strings/cpe_cache_shard_*.json`  
**Metadata**: `cache/cache_metadata.json`  
**Refresh Script**: [utilities/refresh_cpe_cache.py](../utilities/refresh_cpe_cache.py)

---

## Additional References

### Related Documentation
- [source_data_concerns_enhanced_table.md](e:\Git\Analysis_Tools\documentation\source_data_concerns_enhanced_table.md) - Broader data quality context
- [tool_parameter_execution_matrix.md](e:\Git\Analysis_Tools\documentation\tool_parameter_execution_matrix.md) - Entry point behavior

### NVD API References
- [CPE Match API 2.0](https://nvd.nist.gov/developers/cpematch-2.0)
- [CPE API 2.0](https://nvd.nist.gov/developers/cpe-2.0)
- [API Rate Limits](https://nvd.nist.gov/developers/start-here)

---

## Error Handling

**Implementation**: See [src/analysis_tool/storage/cpe_cache.py](../src/analysis_tool/storage/cpe_cache.py)

### Load Failures
**Behavior**: `load_shard_from_disk()` raises `RuntimeError` if shard file exists but cannot be loaded (corruption, I/O error).

**Recovery**: Investigate and repair corrupted shard file, then retry operation.

### Save Failures
**Behavior**: `save_shard_to_disk()` logs warnings but does not raise exceptions. Cache remains in memory for retry on next save attempt.

**Rationale**: Transient I/O errors should not terminate long-running analysis. Data persists in memory until successful save.

---

## Testing

**Test Suite**: [test_suites/tool_infrastructure/test_cpe_cache_refresh.py](../test_suites/tool_infrastructure/test_cpe_cache_refresh.py)

**Coverage**:
- Data integrity protection (load failure handling)
- Static method reuse validation
- Query count preservation across refreshes
- Timestamp update verification
- Data merge operations without loss
- EnExternal References
- [NVD CPE Match API 2.0](https://nvd.nist.gov/developers/cpematch-2.0)
- [NVD CPE API 2.0](https://nvd.nist.gov/developers/cpe-2.0)
- [NVD API Rate Limits](https://nvd.nist.gov/developers/start-here)

