# CPE Caching System Documentation

## Overview

The CPE Caching System dramatically reduces processing time for large CVE dataset analysis by storing NVD `/cpes/` API responses locally and reusing them across multiple CVE records.

## Benefits

- **70-90% reduction in API calls** for large datasets due to CPE overlap between CVE records
- **Significantly faster processing** - estimated reduction from 2.5+ days to hours for ~25,000 CVE records
- **Network efficiency** - reduced bandwidth usage and API rate limit pressure
- **Offline capability** - previously queried CPEs available without network access
- **No file size impact** - cache stored separately from individual CVE record outputs

## Configuration

The cache system is configured in `config.json`:

```json
"cache": {
    "enabled": true,           // Enable/disable caching
    "directory": "cache",      // Cache directory name
    "max_age_hours": 12,       // Hours before cache entries expire (12 hours)
    "max_size_mb": 500,        // Maximum cache size (future use)
    "compression": false,      // Enable gzip compression for cache files
    "validation_on_startup": true,  // Validate cache on startup
    "auto_cleanup": true       // Automatically clean expired entries
}
```

## Cache Refresh Strategy

The cache uses an **aggressive 12-hour refresh strategy** to ensure data freshness:

- **Cache entries expire after 12 hours** - optimal for operational use
- **Automatic refresh on access** - expired entries are automatically replaced with fresh API calls
- **Ideal for long periods between runs** - ensures fresh data even for quarterly/annual processing
- **Balance between performance and freshness** - significant speedup while maintaining data quality

## How It Works

1. **Cache Check**: Before making an NVD API call, the system checks if the CPE string already exists in the local cache
2. **Cache Hit**: If found and not expired, the cached response is used immediately
3. **Cache Miss**: If not found, the API call is made and the response is cached for future use
4. **Cache Storage**: Cache data is stored in `cache/` directory in the project root

## Cache Files

- `cpe_cache.json` - Main cache containing CPE string → API response mappings
- `cache_metadata.json` - Cache statistics and metadata
- Cache files are excluded from version control via `.gitignore`

## Cache Entry Structure

Each cache entry contains:

```json
{
  "cpe:2.3:a:microsoft:windows": {
    "query_response": { /* Full NVD API response */ },
    "last_queried": "2025-06-21T10:30:00Z",
    "query_count": 15,
    "total_results": 245,
    "cache_version": "1.0"
  }
}
```

## Performance Monitoring

The system provides detailed cache performance logging and real-time dashboard integration:

### Console Logging

- **Session Performance**: Hit/miss ratios for current run
- **Lifetime Performance**: Cumulative statistics across all runs
- **API Calls Saved**: Total number of API calls avoided through caching

Example log output:

```text
[INFO] Cache session performance: 1,847 hits, 423 misses, 81.4% hit rate, 423 new entries
[INFO] Cache lifetime performance: 78.5% hit rate, 15,234 API calls saved
```

### Real-time Dashboard Integration

Cache performance metrics are automatically integrated into the real-time dashboard during dataset generation:

- **API Usage Statistics**: Live tracking of cache hits/misses and API rate limiting
- **Performance Metrics**: Real-time cache efficiency and processing speed
- **Resource Monitoring**: API quota usage and rate limiting status
- **Processing Attribution**: Cache performance linked to specific processing stages

Access live cache monitoring through `dashboards/generateDatasetDashboard.html` during dataset generation.

## Usage

The caching system is automatically integrated into the existing workflow. No changes to existing commands or usage patterns are required.

### Bulk Processing

When processing large datasets, the cache will automatically:

1. Load existing cache data at startup
2. Check cache before each API call
3. Store new responses for future use
4. Log performance statistics
5. Save updated cache data when complete

### Single CVE Processing

Even single CVE processing benefits from the cache by:

- Using previously cached CPE data from other CVE records
- Contributing new CPE data to the cache for future use

## Cache Management

### Automatic Refresh (12-Hour Strategy)

- **Aggressive Refresh**: Cache entries automatically expire after 12 hours
- **Fresh Data Guarantee**: Ensures CPE data is relatively current
- **Automatic Cleanup**: Expired entries are removed when accessed

### Performance Impact

- **First Run**: Full API calls for all unique CPE strings
- **Same Day Reruns**: High cache hit rates (80-95%)
- **Next Day Runs**: Fresh data with updated CPE information
- **Overall Benefit**: Significant speedup while maintaining data freshness

### Cache Statistics

```python
stats = cache.get_stats()
print(f"Total entries: {stats['total_entries']}")
print(f"Hit rate: {stats['lifetime_hit_rate']}%")
print(f"API calls saved: {stats['api_calls_saved']}")
```