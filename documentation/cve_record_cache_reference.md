# NVD CVE & CVE List V5 Cache System - Reference Documentation

---

## Overview

Per-file cache system for NVD 2.0 CVE records (`cache/nvd_2.0_cves/`) and CVE List V5 records (`cache/cve_list_v5/`). Both caches are populated during bulk dataset generation and kept current through standalone refresh utilities.

Each cache uses a different staleness strategy:
- **NVD 2.0**: Timestamp comparison — API `lastModified` vs cached `lastModified`
- **CVE List V5**: Fast path via `last_manual_update` config field; fallback to file-age TTL (`notify_age_hours`)

---

## Configuration

Both caches are configured under `cache_settings` in `config.json`:

```json
"cve_list_v5": {
    "path": "cache/cve_list_v5",
    "refresh_strategy": {
        "last_manual_update": "1970-01-01T00:00:00+00:00",
        "notify_age_hours": 720
    }
},
"nvd_2_0_cve": {
    "path": "cache/nvd_2.0_cves",
    "refresh_strategy": {
        "field_path": "$.vulnerabilities.*.cve.lastModified"
    }
}
```

`last_manual_update` is set manually after a bulk CVE List V5 refresh to serve as a high-water mark, allowing the fast path to skip file I/O for CVEs that predate it. `notify_age_hours` (default: 720h) is the TTL fallback when the fast path is unavailable.

---

## Bulk Generation Cache Check — `generate_dataset.py`

During bulk operations, every CVE returned by the NVD API is evaluated against both caches before any disk writes occur. Writes are batched in memory and flushed once per NVD API response page, so `_update_cache_metadata` is called at most once per page rather than once per CVE.

**Implementation**: [`generate_dataset.py`](../generate_dataset.py)
- `_save_nvd_cve_to_cache_during_bulk_generation()` — NVD 2.0 staleness check and queue
- `_save_cve_list_v5_to_cache_during_bulk_generation()` — CVE List V5 staleness check and queue
- `_flush_cache_batches()` — drains both queues; called after each page loop and on interrupt

### Cache Check Logic

```mermaid
flowchart LR
    NVD_API["NVD API Response · per CVE<br>id + lastModified in memory"]

    subgraph NVD_CHECK["NVD 2.0 Cache Check"]
        direction TB
        N1{"NVD Cache Config...path resolvable?<br>NVD API Response...lastModified parseable?"}
        N1 -- no --> NE(["no_action"])
        N1 -- yes --> N4{"NVD Cache File<br>exists?"}
        N4 -- no --> NQ_NM["new_or_missing"]
        N4 -- yes --> N5{"NVD Cache File loadable as JSON<br>with valid lastModified?"}
        N5 -- "corrupt / IOError /<br>missing lastModified" --> NQ_BAD["corrupted / missing_timestamp"]
        N5 -- yes --> N7{"NVD API Response...lastModified<br>≤<br>NVD Cache File...lastModified?"}
        N7 -- yes --> NU["up-to-date"]
        N7 -- no --> NQ_S["stale"]
    end

    subgraph V5_CHECK["CVE List V5 Cache Check"]
        direction TB
        V1{"CVE List Cache Config...path<br>resolvable?"}
        V1 -- no --> VE(["no_action"])
        V1 -- yes --> V2{"CVE List Cache File<br>exists?"}
        V2 -- no --> VQ_NM["new_or_missing"]
        V2 -- yes --> V3{"NVD Record...lastModified<br>≤<br>CVE List Cache...last_manual_update?"}
        V3 -- "no / unavailable" --> TTL{"CVE List Record...file_age<br>≥<br>CVE List Cache...notify_age_hours?"}
        TTL -- yes --> VQ_S["stale"]
        V3 -- yes --> V_CUR["current_by_last_manual_update<br>or within notify_age_hours TTL"]
        TTL -- no --> V_CUR
    end

    NVD_API --> N1
    NVD_API --> V1

    NE & VE --> OUT_ERR["⛔ ERROR<br>no cache write"]
    NQ_NM & VQ_NM --> OUT_ADD["🆕 ADDED<br>file created"]
    NQ_BAD & NQ_S & VQ_S --> OUT_UPD["♻️ UPDATED<br>file overwritten"]
    NU & V_CUR --> OUT_CUR["✅ CURRENT<br>no cache write"]
```

### Outcome Reference

| Outcome | Reason(s) | Cache Write |
|---------|-----------|-------------|
| ⛔ ERROR | `path_resolution_failed`, `missing_timestamp`, `timestamp_parse_error`, `error` | No |
| 🆕 ADDED | `new_or_missing` | Yes — file created |
| ♻️ UPDATED | `stale`, `corrupted`, `missing_timestamp` | Yes — file overwritten |
| ✅ CURRENT | `up-to-date`, `current_by_last_manual_update` | No |

---

## Standalone Cache Refresh Utilities

### NVD 2.0 CVE Cache Refresh

**Entry point:** `python -m utilities.refresh_nvd_cves_2_0_cache`

Queries NVD for CVEs modified within a date range and writes/updates cache files using parallel workers. Schema validation (`nvd_cves_2_0`) runs before each write. Cache metadata and `lastManualUpdate` are updated once in Phase 3 rather than per-CVE.

**When to use:** Initial cache population, recovery after API failures, or proactive cache warming as a supplement to `generate_dataset.py`.

| Option | Description |
|---|---|
| *(no args)* / `--auto` | Read last update from `cache_metadata.json` (**default**) |
| `--days N` | Refresh CVEs modified in the last N days |
| `--start-date YYYY-MM-DD --end-date YYYY-MM-DD` | Explicit date range |
| `--full-refresh` | Query entire NVD dataset — no date filter (30–60 min) |
| `--workers N` | Parallel CVE processing workers (default: 20) |
| `--api-workers N` | Concurrent NVD API requests (default: 15) |

```mermaid
flowchart TD
    A([Start]) --> B{Date range source}
    B -->|--auto / default| C[Read cache_metadata.json<br>→ last update timestamp]
    B -->|--days N| D[now − N days → now]
    B -->|--start-date/--end-date| E[Explicit range]
    B -->|--full-refresh| F[All CVEs — no date filter]
    C --> G{Timestamp found?}
    G -->|No| ABORT([ABORT — use --days to recover])
    G -->|Yes| P1
    D & E & F --> P1
    P1[PHASE 1: DISCOVERY<br>NVD API query<br>api_workers concurrent requests] --> CHK{CVEs returned?}
    CHK -->|0| DONE([Cache up to date])
    CHK -->|N CVEs| P2
    P2[PHASE 2: VALIDATION & UPDATE<br>Load nvd_cves_2_0 schema<br>ThreadPoolExecutor — max_workers parallel] --> SAVE[_save_nvd_cve_to_local_file<br>update_metadata=False per CVE]
    SAVE -->|cached| ADD[NVD 2.x  CVE-XXXX  ADDED]
    SAVE -->|updated| UPD[NVD 2.x  CVE-XXXX  UPDATED]
    SAVE -->|up-to-date| CUR[NVD 2.x  CVE-XXXX  CURRENT]
    SAVE -->|failed| ERR[NVD 2.x  CVE-XXXX  ERROR]
    ADD & UPD & CUR & ERR --> P3[PHASE 3: FINALIZE<br>_update_cache_metadata<br>_update_manual_refresh_timestamp]
    P3 --> RPT([Print stats report])
```

### CVE List V5 Cache Refresh

**Entry point:** `python -m utilities.refresh_cve_cvelist_5_2_cache`

Fetches `deltaLog.json` from the CVE Project GitHub repository to identify CVEs changed since a cutoff date, then refreshes only those whose cache files are stale (age ≥ `notify_age_hours` TTL). `last_manual_update` in `config.json` is written automatically in Phase 3 when any CVEs are written; subsequent default runs read this value to narrow the deltaLog scan.

**When to use:** Routine scheduled maintenance and baseline establishment after a fresh clone. CURRENT CVEs (within TTL) are skipped silently — only stale or missing files are fetched from the MITRE API.

| Option | Description |
|---|---|
| *(no args)* | Auto-detect cutoff from `config.json` → `last_manual_update` (**default**) |
| `--days N` | Force cutoff to N days ago regardless of config state |
| `--workers N` | Parallel workers for CVE fetching (default: 20) |

```mermaid
flowchart TD
    A([Start]) --> B{Cutoff date source}
    B -->|--days N| C[now − N days]
    B -->|default| D[Read config.json<br>→ last_manual_update]
    B -->|no config value| E[now − 30 days<br>default fallback]
    C & D & E --> P1
    P1[PHASE 1: DISCOVERY<br>Fetch deltaLog.json<br>from CVE Project GitHub] --> PARSE["For each batch record:<br>skip batch if fetchTime ≤ cutoff<br>→ collect CVE IDs from new[] + updated[]"]
    PARSE --> CHK{CVEs changed?}
    CHK -->|0| DONE([Cache up to date])
    CHK -->|N CVEs| P2
    P2[PHASE 2: VALIDATION & UPDATE<br>Load cve_cve_5_2 schema<br>ThreadPoolExecutor — max_workers parallel] --> LOOP[For each CVE — parallel]
    LOOP --> PATH{Path resolved?}
    PATH -->|Yes| TTL{File age < TTL?}
    TTL -->|Yes| SKIP[CURRENT — counted only, not logged]
    TTL -->|No or missing| MITRE[_refresh_cvelist_from_mitre_api<br>reason: deltaLog change detected]
    MITRE -->|file was missing| RADD[CVE 5.x  CVE-XXXX  ADDED]
    MITRE -->|file was stale| RUPD[CVE 5.x  CVE-XXXX  UPDATED]
    PATH -->|No| ERR[CVE 5.x  CVE-XXXX  ERROR]
    MITRE -->|exception| ERR
    SKIP & RADD & RUPD & ERR --> CHKWRT{Any ADDED or<br>UPDATED?}
    CHKWRT -->|Yes| FIN[PHASE 3: FINALIZE<br>_update_cache_metadata<br>_update_manual_refresh_timestamp]
    CHKWRT -->|No| DONE2([No metadata change])
    FIN & DONE2 --> RPT([Print stats report])
```
