# CPE Cache System

High-performance caching system for NVD CPE API responses that dramatically reduces processing time by storing and reusing CPE lookups across CVE analysis runs.

## Performance Benefits

- **70-90% reduction in API calls** for large datasets due to CPE overlap between CVE records
- **Significantly faster processing** - reduces analysis time from days to hours for large datasets
- **Optimized JSON operations** using orjson library for 5-10x faster serialization
- **Global cache persistence** across multiple analysis runs and sessions
- **Real-time dashboard integration** with cache performance monitoring

## How It Works

1. **Cache Check**: Before making NVD CPE API calls, system checks local cache for existing data
2. **Cache Hit**: If found and not expired, cached response is used immediately (API call avoided)
3. **Cache Miss**: If not found or expired, API call is made and response is cached
4. **Automatic Management**: Cache automatically handles expiration, cleanup, and persistence

## Configuration

Cache settings in `src/analysis_tool/config.json`:

```json
"cache": {
    "enabled": true,              // Enable/disable caching system
    "directory": "cache",         // Cache directory name  
    "max_age_hours": 12,         // Hours before entries expire (12 hours default)
    "max_size_mb": 500,           // Maximum cache size limit
    "compression": false,         // Enable gzip compression for cache files
    "validation_on_startup": true, // Validate cache integrity on startup
    "auto_cleanup": true          // Automatically clean expired entries
}
```

## Cache Storage

**Location**: `src/cache/` directory (global, not run-specific)

**Files**:

- `cpe_cache.json` - Main cache with CPE string → API response mappings
- `cache_metadata.json` - Statistics, timestamps, and performance data

**Benefits of Global Storage**:

- Cache persists across all analysis runs and sessions
- Single CVE analysis contributes to cache for future batch processing
- Cumulative performance improvements over time

## Cache Performance

### Session Statistics

Real-time logging during analysis runs:

```text
[INFO] Cache session performance: 1,847 hits, 423 misses, 81.4% hit rate, 423 new entries
[INFO] Cache session saved 1,847 API calls this run
[INFO] /cpes/ cache loaded: 2,270 entries in 0.15s
```

### Lifetime Statistics

Cumulative performance across all runs:

```text
[INFO] Cache lifetime performance: 78.5% hit rate, 15,234 API calls saved
```

### Dashboard Integration

Cache metrics automatically integrate with the **Generate Dataset Dashboard**:

- **Real-time cache hit/miss tracking** during processing
- **API call savings quantification** with live counters
- **Cache file size monitoring** and growth tracking
- **Performance attribution** by processing stage

Access via `dashboards/generateDatasetDashboard.html` during analysis runs.

## Cache Entry Structure

Each cached CPE response contains:

```json
{
  "cpe:2.3:a:microsoft:windows": {
    "query_response": { /* Complete NVD CPE API response */ },
    "last_queried": "2025-08-22T10:30:00Z",
    "query_count": 15,
    "total_results": 245,
    "cache_version": "1.0"
  }
}
```

## Cache Management

### Automatic Expiration

- **Default expiration**: 12 hours (configurable via `max_age_hours`)
- **Automatic cleanup**: Expired entries removed when accessed
- **Fresh data guarantee**: Ensures CPE data stays reasonably current

### Performance Impact by Run Type

**First Run**: Full API calls for all unique CPE strings
**Subsequent Runs**: High cache hit rates (70-95% depending on dataset overlap)
**Long-term Benefits**: Cumulative performance improvements across all analysis workflows

### Global Cache Manager

The system uses a `GlobalCPECacheManager` that:

- **Loads once per session** - cache persists across multiple CVE analyses
- **Automatic persistence** - saves cache data on completion
- **Error resilience** - handles corrupted cache files gracefully
- **Memory optimization** - efficient in-memory data structures

## Usage

The cache system integrates automatically with existing workflows:

```bash
# Cache benefits all analysis types automatically
python run_tools.py --cve CVE-2024-20515     # Single CVE analysis
python run_tools.py --file dataset.txt       # Batch processing
python generate_dataset.py --last-days 30    # Dataset generation
```

**No configuration changes required** - cache system works transparently with existing commands.
