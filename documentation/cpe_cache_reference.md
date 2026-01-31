# CPE Cache Sharding - Reference Documentation

**Version**: 3.0  
**Date**: January 30, 2026  
**Status**: Production Implementation  

---

## Executive Summary

This document provides reference documentation for the production CPE cache sharding implementation. The sharded architecture solves CPE cache scaling issues that previously caused Python crashes at 1.5GB+ file sizes, implementing hash-based distribution, lazy loading, run-boundary eviction, and compact JSON storage.

**Implementation**: ~516 MB sharded cache system (16 shards, ~32 MB each, compact JSON format) with automatic memory management  
**Replaces**: 910 MB monolithic cache file (20,683 entries), 76.4% formatting overhead (deprecated and disabled)

---

## Problem Statement

### Core Issues

1. **Memory Bloat** - 910 MB cache file growing toward 1.5-2 GB causing Python crashes
2. **Formatting Overhead** - `orjson.OPT_INDENT_2` adds 394 MB (76.4%) of whitespace
3. **Unbounded Growth** - No size limits or eviction mechanisms
4. **Monolithic Loading** - Entire cache loaded into memory at session start
5. **Stale Data** - Time-based expiration (`notify_age_hours`) doesn't track actual NVD changes

---

## Solution Overview

**Feature 1: Sharded Cache Architecture** (PRODUCTION)  
Hash-based sharded cache implementation with compact JSON storage, lazy loading, and run-boundary eviction.

**Feature 2: Smart Cache Refresh Strategy** (FUTURE ENHANCEMENT)  
Intelligent refresh of expired entries using NVD change tracking APIs to avoid unnecessary API calls. Design documented for future implementation.

---

## Feature 1: Sharded Cache Architecture

### Hash-Based Shard Distribution

**Architecture**: Split cache into 16 shards using MD5 hash of CPE string

```python
import hashlib

def get_shard_index(cpe_string: str, num_shards: int = 16) -> int:
    """Determine shard index using MD5 hash"""
    hash_digest = hashlib.md5(cpe_string.encode('utf-8')).hexdigest()
    return int(hash_digest[:8], 16) % num_shards

def get_shard_filename(shard_index: int) -> str:
    """Get filename for specific shard"""
    return f"cpe_cache_shard_{shard_index:02d}.json"
```

**Shard Distribution** (proven via analysis):
- **Hash-based**: 1227-1351 entries per shard (0.028 imbalance factor)
- **Alphabetical**: 20,683 in one shard, 0 in others (1.414 imbalance factor)
- **Result**: Hash sharding is **50.9× better balanced**

**File Structure**:
```
cache/
  cpe_base_strings/
    cpe_cache_shard_00.json  (~32 MB, ~1,292 entries, compact JSON)
    cpe_cache_shard_01.json  (~32 MB, ~1,292 entries, compact JSON)
    ...
    cpe_cache_shard_15.json  (~32 MB, ~1,292 entries, compact JSON)
  cache_metadata.json        (shard count, last modified)
```

**Why Sharding Helps**:
1. **Lazy Loading**: Only load shards containing requested CPE strings
2. **Faster Startup**: Load 1-2 shards in 0.1s vs 10-30s for full 910 MB file
3. **Memory Management**: Enable run-boundary eviction to clear memory between dataset runs
4. **Parallel I/O**: Future optimization for concurrent shard loading

---

### Run-Boundary Eviction

**Natural Eviction Point**: End of each generate_dataset run (commonly between sources in harvest workflow, but also applies to --last-days and other modes)

```python
# In generate_dataset.py at completion (~line 1010)
# After dataset generation completes for one source
try:
    from src.analysis_tool.storage.cpe_cache import get_global_cache_manager
    cpe_cache_manager = get_global_cache_manager()  # CPE base string cache
    
    # Save all loaded CPE cache shards to disk
    cpe_cache_manager.save_all_shards()
    
    # Clear loaded CPE cache shard data from memory (keeps singleton alive)
    cpe_cache_manager.evict_all_shards()
    
    logger.info(
        f"CPE base string cache shards saved and evicted - memory cleared for next run",
        group="CACHE"
    )
except Exception as e:
    logger.warning(f"CPE cache shard eviction failed: {e}", group="CACHE")
```

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

**Memory Cap**: ~12 shards loaded × ~32 MB = **~384 MB max** vs current 910 MB monolithic  
**Why It Works**: Each generate_dataset run is independent data processing with natural boundary points at completion

**Applies to all modes**: Works with --source-uuid (harvest workflow), --last-days, --start-date/--end-date, etc.

---

### ShardedCPECache Class Implementation

```python
class ShardedCPECache:
    """Hash-based sharded CPE cache with lazy loading and eviction"""
    
    def __init__(self, cache_dir: Path, num_shards: int = 16):
        self.cache_dir = cache_dir / "cpe_base_strings"
        self.cache_dir.mkdir(exist_ok=True)
        self.num_shards = num_shards
        self.loaded_shards = {}  # {shard_index: cache_data}
        self.unsaved_changes = {}  # {shard_index: count}
        
    def _get_shard_index(self, cpe_string: str) -> int:
        """Hash CPE string to shard index"""
        hash_digest = hashlib.md5(cpe_string.encode('utf-8')).hexdigest()
        return int(hash_digest[:8], 16) % self.num_shards
    
    def _load_shard(self, shard_index: int) -> dict:
        """Lazy load single shard into memory"""
        if shard_index in self.loaded_shards:
            return self.loaded_shards[shard_index]
        
        shard_path = self.cache_dir / f"cpe_cache_shard_{shard_index:02d}.json"
        if shard_path.exists():
            with open(shard_path, 'rb') as f:
                self.loaded_shards[shard_index] = orjson.loads(f.read())
        else:
            self.loaded_shards[shard_index] = {}
        
        return self.loaded_shards[shard_index]
    
    def get(self, cpe_string: str) -> dict | None:
        """Get cache entry (loads shard if needed)"""
        shard_index = self._get_shard_index(cpe_string)
        shard_data = self._load_shard(shard_index)
        return shard_data.get(cpe_string)
    
    def put(self, cpe_string: str, cache_entry: dict) -> None:
        """Store cache entry in appropriate shard"""
        shard_index = self._get_shard_index(cpe_string)
        shard_data = self._load_shard(shard_index)
        
        is_new = cpe_string not in shard_data
        shard_data[cpe_string] = cache_entry
        
        if is_new:
            self.unsaved_changes[shard_index] = self.unsaved_changes.get(shard_index, 0) + 1
    
    def save_all_shards(self) -> None:
        """Save all loaded shards to disk using compact JSON"""
        for shard_index, shard_data in self.loaded_shards.items():
            shard_path = self.cache_dir / f"cpe_cache_shard_{shard_index:02d}.json"
            with open(shard_path, 'wb') as f:
                f.write(orjson.dumps(shard_data))  # Compact JSON (no OPT_INDENT_2)
        
        self.unsaved_changes.clear()
    
    def evict_all_shards(self) -> None:
        """Clear all shards from memory (singleton stays alive)"""
        self.loaded_shards.clear()
```

---

## Feature 2: Cache Refresh Strategy (Future Enhancement)

### Overview

**Status**: Design documentation for future implementation

Intelligently refresh expired cache entries using NVD change tracking APIs instead of blindly refreshing all old entries.

### Problem with Current Approach

- **Time-Based Expiration**: 100-hour TTL triggers refresh based on age alone
- **Runtime Blocking**: Expired entries discovered during CVE processing cause synchronous API calls
- **Wasted Refreshes**: Many cached CPE entries unchanged at NVD but refreshed anyway

### Smart Refresh Solution

**Three-Phase Workflow**:

#### Phase 1: Discover What Changed at NVD
```
1. Scan local cache to find oldest entry (last_queried timestamp)
2. Query /cpematch/ API with lastModStartDate = oldest entry
3. Collect all CPE match strings from paginated results
4. Extract unique CPE base strings (strip version/update)
```

#### Phase 2: Refresh Changed CPE Data
```
5. For each unique CPE base string:
   a. Query /cpes/ API: ?cpeMatchString=<base_string>
   b. Transform response using existing cache logic
   c. Stage update in temporary structure
6. Every 5 minutes: Flush staged updates to actual cache
```

#### Phase 3: Finalize and Persist
```
7. Final flush of remaining staged updates
8. Save updated cache to disk with metadata
9. Generate refresh statistics and report
```

### API Endpoints

**Discovery**: `https://services.nvd.nist.gov/rest/json/cpematch/2.0`
- Parameters: `lastModStartDate`, `lastModEndDate`, `resultsPerPage=2000`
- Returns: All CPE matches modified in date range

**Refresh**: `https://services.nvd.nist.gov/rest/json/cpes/2.0`
- Parameters: `cpeMatchString=<cpe_base_string>`
- Returns: Full CPE details for specific base string

### Implementation: refresh_cpe_cache.py

```python
#!/usr/bin/env python3
"""
Smart CPE Cache Refresh - NVD change-based refresh strategy
"""

def find_oldest_cache_entry(cache: ShardedCPECache) -> datetime:
    """Scan all shards to find oldest last_queried timestamp"""
    oldest = datetime.now(timezone.utc)
    
    for shard_index in range(cache.num_shards):
        shard_data = cache._load_shard(shard_index)
        for entry_data in shard_data.values():
            last_queried = datetime.fromisoformat(entry_data['last_queried'])
            if last_queried < oldest:
                oldest = last_queried
    
    return oldest

def query_cpematch_changes(api_key: str, start_date: datetime, end_date: datetime) -> List[str]:
    """Query NVD /cpematch/ API for CPE changes in date range"""
    # Implement pagination and rate limiting
    # Return list of all CPE match strings found
    pass

def extract_unique_cpe_bases(match_strings: List[str]) -> Set[str]:
    """Extract CPE base strings (remove version/update)"""
    bases = set()
    for match in match_strings:
        # Strip version components: cpe:2.3:a:vendor:product:1.0 → cpe:2.3:a:vendor:product
        parts = match.split(':')
        if len(parts) >= 5:
            base = ':'.join(parts[:5])
            bases.add(base)
    return bases

def smart_refresh(api_key: str, cache: ShardedCPECache) -> dict:
    """Execute smart refresh using NVD change detection"""
    # Phase 1: Discovery
    oldest_entry = find_oldest_cache_entry(cache)
    logger.info(f"Oldest cache entry: {oldest_entry}")
    
    changed_matches = query_cpematch_changes(api_key, oldest_entry, datetime.now(timezone.utc))
    logger.info(f"NVD reports {len(changed_matches)} changed CPE matches")
    
    unique_bases = extract_unique_cpe_bases(changed_matches)
    logger.info(f"Unique CPE base strings to refresh: {len(unique_bases)}")
    
    # Phase 2: Selective Refresh
    refreshed = 0
    for cpe_base in unique_bases:
        response = query_nvd_cpes_api(api_key, cpe_base)
        cache.put(cpe_base, response)
        refreshed += 1
        
        # Auto-save every 5 minutes
        if refreshed % 50 == 0:
            cache.save_all_shards()
    
    # Phase 3: Finalize
    cache.save_all_shards()
    
    return {'refreshed': refreshed, 'total_changed': len(changed_matches)}
```

### CLI Interface

```bash
# Smart refresh (change-based)
python refresh_cpe_cache.py --api-key YOUR_KEY --mode smart

# Full refresh (all expired entries)
python refresh_cpe_cache.py --api-key YOUR_KEY --mode full

# Dry run (show what would be refreshed)
python refresh_cpe_cache.py --api-key YOUR_KEY --mode smart --dry-run
```

---

## Success Metrics

### Quantitative Targets

1. **File Size**: ~516 MB total across all shards (~32 MB per shard, compact JSON format)
2. **Memory Usage**: ~384 MB max loaded shards (vs 910 MB+ monolithic) with eviction
3. **Startup Time**: <1s for initial shard loading (vs 10-30s full cache)
4. **Refresh Efficiency**: >60% fewer API calls vs full expiry-based refresh
5. **Data Loss Protection**: Auto-save every 50 entries (configurable)
6. **Data Integrity**: 100% - all legitimate cache data preserved

### Qualitative Goals

1. **No Crashes**: Python handles cache operations without memory errors
2. **Clean Integration**: Sharded cache works seamlessly with existing workflows
3. **Maintainable**: Clear architecture with separation of concerns
4. **Observable**: Comprehensive logging and statistics

---

## Risk Mitigation

### Risk 1: Hash Distribution Imbalance
**Mitigation**: Pre-validated with real data (50.9× better than alphabetical)

### Risk 2: Eviction Timing Issues
**Mitigation**: Natural run boundaries at generate_dataset completion provide safe eviction points

### Risk 3: NVD API Rate Limits
**Mitigation**: Existing rate limiting logic, exponential backoff on 429 responses

---

## Integration Points

### Modified Files
- `src/analysis_tool/storage/cpe_cache.py` - Priority 1, sharding implementation
- `src/analysis_tool/config.json` - New configuration settings
- `generate_dataset.py` - Run-boundary eviction integration at line ~1010

### New Files
- `src/analysis_tool/storage/sharded_cpe_cache.py` - ShardedCPECache class
- `refresh_cpe_cache.py` - Smart refresh script

### Test Files
- `test_files/test_cpe_sharding.py` - Hash distribution validation
- `test_files/test_shard_eviction.py` - Memory management verification
- `test_files/test_smart_refresh.py` - Refresh strategy validation

---

## References

### Existing Documentation
- [cpe_cache_refresh_strategy.md](e:\Git\Analysis_Tools\documentation\cpe_cache_refresh_strategy.md) - Original refresh strategy design
- [cpe_automation_challenges.md](e:\Git\Analysis_Tools\documentation\cpe_automation_challenges.md) - CPE complexity context
- [tool_parameter_execution_matrix.md](e:\Git\Analysis_Tools\documentation\tool_parameter_execution_matrix.md) - Entry point behavior

### NVD API References
- [CPE Match API 2.0](https://nvd.nist.gov/developers/cpematch-2.0)
- [CPE API 2.0](https://nvd.nist.gov/developers/cpe-2.0)
- [API Rate Limits](https://nvd.nist.gov/developers/start-here)

---

**Document Owner**: Analysis Tools Development Team  
**Last Updated**: January 30, 2026  
**Status**: Production - Sharded Cache Active, Smart Refresh Pending
