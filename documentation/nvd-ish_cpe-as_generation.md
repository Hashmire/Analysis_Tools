# CPE Applicability Statement Generation

**Document Purpose:** Technical documentation for Python-native CPE-AS generation system integrated with NVD-ish records  
**Created:** January 12, 2026  
**Last Updated:** January 25, 2026  
**Implementation:** `src/analysis_tool/core/cpe_as_generator.py`  
**Tests:** `test_suites/nvd-ish_collector/test_cpe_as_integration.py`  

---

## Table of Contents

1. [Overview](#1-overview)
2. [Input Specification](#2-input-specification)
3. [Pattern Processing](#3-pattern-processing)
4. [Pre and Post Processing](#4-pre-and-post-processing)
5. [NVD-ish Integration](#5-nvd-ish-integration)
6. [Known Limitations](#6-known-limitations)

---

## 1. Overview

### Purpose
The CPE-AS generation system transforms CVE 5.0 affected array entries into NVD-style CPE Applicability Statement JSON using pure Python. This enables automated generation of machine-readable vulnerability configuration data from CVE records.

### System Capabilities
1. **Input Processing**: Accepts CVE 5.0 `affected[]` array entries with CPE base string(s)
2. **Output Generation**: Produces NVD-style `configurations[]` arrays with CPE match objects
3. **NVD-ish Integration**: Embeds generated CPE-AS directly into NVD-ish records during collection
4. **Pattern Recognition**: Applies 5 distinct processing patterns (3.1-3.5) covering version ranges, exact versions, and metadata-only cases
5. **Quality Tracking**: Flags 10 types of data quality concerns for human review

---

## 2. Input Specification

### Required Inputs
1. **CVE 5.0 affected entry** - Single platform from `affected[]` array
2. **CPE base string** - Generated via `badge_modal_system.py` CPE cache
3. **Settings/flags** (optional) - Pattern detection settings

### Affected Entry Field Processing

#### Essential Fields
- `vendor` - Vendor name
- `product` - Product name  
- `defaultStatus` - `affected`, `unaffected`, or `unknown`
- `versions[]` - Array of version constraint objects (may be empty)

#### Optional Fields
- `platforms[]` - Platform identifiers
- `packageName` - Package manager name
- `cpes[]` - Explicit CPE strings
- `repo` - Repository URL
- `programFiles[]` - Affected file paths
- `versions[]` items may contain:
  - `version` - Exact version or wildcard (`*`). May be omitted for open-ended ranges
  - `status` - `affected`, `unaffected`, `unknown`. Defaults to `defaultStatus` when omitted
  - `versionType` - `semver`, `custom`, `git`, etc.
  - `lessThan` - Upper bound (exclusive)
  - `lessThanOrEqual` - Upper bound (inclusive)
  - `changes[]` - Status changes at specific versions

---

## 2.1 cpeMatch Object Property Order

**Implementation Standard**: All cpeMatch objects serialize properties in the following explicit order:

1. `versionsEntryIndex` - Maps to source versions[] array index (0-based, null if no versions array)
2. `appliedPattern` - (Optional) Pattern reference for traceability (e.g., "exact.single", "range.lessThan", "inference.affectedFromWildcardExpansion"). Omitted (null) for truly unknown patterns.
3. `vulnerable` - Boolean indicating vulnerability status (true for affected entries, false for metadata-only entries)
4. `criteria` - (Optional) Full CPE 2.3 formatted string. Omitted for metadata-only objects.
5. `versionStartIncluding` - (Optional) Lower bound version, inclusive
6. `versionStartExcluding` - (Optional) Lower bound version, exclusive
7. `versionEndIncluding` - (Optional) Upper bound version, inclusive
8. `versionEndExcluding` - (Optional) Upper bound version, exclusive
9. `concerns` - (Optional) Array of concern identifiers for metadata-only or flagged entries (e.g., `["statusUnaffected"]`, `["updatePatternsInRange"]`)
10. Additional optional fields (e.g., `updatePattern`) follow core properties

**Rationale**: 
- Consistent property ordering ensures reproducible output and simplifies testing
- Metadata fields (`versionsEntryIndex`, `appliedPattern`) appear first for easy debugging
- Core NVD fields (`vulnerable`, `criteria`) follow immediately
- Version range properties maintain logical grouping (start bounds, then end bounds)
- Concerns array appears after all standard fields for easy visibility

**Example Property Order (Standard cpeMatch)**:
```json
{
  "versionsEntryIndex": 0,
  "appliedPattern": "range.lessThan",
  "vulnerable": true,
  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
  "versionStartIncluding": "2.0",
  "versionEndExcluding": "2.5"
}
```

**Example Property Order (Metadata-only cpeMatch)**:
```json
{
  "versionsEntryIndex": 1,
  "vulnerable": false,
  "concerns": ["statusUnaffected"]
}
```

All examples throughout this document follow this ordering convention.

---

## 3. Pattern Processing

### 3.1 Output Pattern: Single cpeMatch object - No Version

Single cpeMatch with wildcard version (*) when no specific version data is available or all versions are affected.

```json
{
  "versionsEntryIndex": 0,  // Index of versions[] entry, or null if no versions array
  "appliedPattern": "noVersion.allAffected",
  "vulnerable": true,
  "criteria": "cpe:2.3:a:example:cpebasestring:*:*:*:*:*:*:*:*"
}
```

**Note**: `versionsEntryIndex` will be:
- `null` when Pattern A (no versions[] array) is matched
- `0` when Pattern A-Variant (explicit "*"), Pattern C (placeholder version), or Pattern D (defaultStatus="unknown") is matched
- The actual array index for the specific placeholder entry being processed

---

**Pattern A: Explicit "All Versions" via defaultStatus**
```json
{
  "vendor": "acme",
  "product": "widget",
  "defaultStatus": "affected"
  // No versions[] array present
}
```

**Pattern A-Variant: Explicit wildcard version**
```json
{
  "vendor": "acme",
  "product": "widget",
  "defaultStatus": "affected",
  "versions": [
    {"version": "*", "status": "affected"}
  ]
}
```

**Pattern B: Empty versions array**
```json
{
  "vendor": "acme",
  "product": "widget",
  "defaultStatus": "affected",
  "versions": []
}
```

**Pattern C: Only Version Placeholder Values**
```json
{
  "vendor": "acme",
  "product": "widget",
  "defaultStatus": "affected",
  "versions": [
    {"version": "unspecified", "status": "affected"},
    // OR
    {"version": "all", "status": "affected"},
    // OR
    {"version": "n/a", "status": "affected"},
    // OR other placeholder terminology
  ]
}
```

**Pattern C-Variant: Placeholder version AND placeholder changes array**
```json
{
  "vendor": "acme",
  "product": "widget",
  "defaultStatus": "affected",
  "versions": [
    {
      "version": "unspecified",
      "status": "affected",
      "changes": [
        {"at": "unknown", "status": "unaffected"}
      ]
    }
  ]
}
```
**Result**: Still Pattern 3.1 - all version-related data is placeholders

**Pattern D: defaultStatus="unknown" with no/empty versions**
```json
{
  "vendor": "acme",
  "product": "widget",
  "defaultStatus": "unknown"
  // No versions[] array OR versions: []
}
```
**Result**: Metadata-only cpeMatch object  
**Output**:
```json
{
  "versionsEntryIndex": null,
  "vulnerable": false,
  "concerns": ["defaultStatusUnknown"]
}
```

**Logic:**
- **Pattern A**: versions array missing/None → use defaultStatus for vulnerability
- **Pattern A-Variant**: version="*" → use version.status for vulnerability (overrides defaultStatus)
- **Pattern B**: Empty versions[] → treat as Pattern A
- **Pattern C**: All versions are placeholders (AND all changes[].at are placeholders if present) → use version.status for vulnerability
- **Pattern D**: defaultStatus='unknown' → metadata-only cpeMatch with `concerns: ["defaultStatusUnknown"]`
- Output (Patterns A-C): Single cpeMatch with wildcard version (*), vulnerability based on status

**VERSION_PLACEHOLDER_VALUES (Centralized in badge_modal_system.py):**
```python
VERSION_PLACEHOLDER_VALUES = [
    'unspecified', 'unknown', 'none', 'undefined', 'various',
    'n/a', 'not available', 'not applicable', 'unavailable',
    'na', 'nil', 'tbd', 'to be determined', 'pending',
    'not specified', 'not determined', 'not known', 'not listed',
    'not provided', 'missing', 'empty', 'null', '-', 
    'multiple versions', 'see references', 'see advisory', 
    'check', 'noted', 'all'
]
# Total: 28 patterns (case-insensitive)
# JavaScript adds: "*" (wildcard) to this list at runtime
# Note: 'all' included - observed in real CVE data as wildcard indicator
# Note: "0" is NOT a placeholder - treated as literal version value
```

**Analysis:**
- Most common case: source reports product is affected but lacks version specificity
- Can indicate:
  - Product-wide vulnerability (all versions truly affected)
  - Incomplete version information from vendor
  - Placeholder data provided

---

### 3.2 Output Pattern: No affected platforms - Metadata-only cpeMatch

When no platforms are vulnerable/affected, generate a metadata-only cpeMatch object to indicate the condition was processed.

```json
[
  {
    "versionsEntryIndex": 0,
    "vulnerable": false,
    "concerns": ["noAffectedPlatforms"]
  }
]
```

**Pattern A: defaultStatus=affected with only unaffected versions**
```json
{
  "vendor": "acme",
  "product": "widget",
  "defaultStatus": "affected",
  "versions": [
    {"version": "1.0", "status": "unaffected"},
    {"version": "2.0", "status": "unaffected"}
  ]
}
```

**Pattern B: defaultStatus=unaffected (nothing to output)**
```json
{
  "vendor": "acme",
  "product": "widget",
  "defaultStatus": "unaffected"
  // No versions[] or all versions are unaffected
}
```

**Pattern C: Placeholder with unaffected status**
```json
{
  "vendor": "acme",
  "product": "widget",
  "defaultStatus": "affected",
  "versions": [
    {"version": "unspecified", "status": "unaffected"}
  ]
}
```

**Pattern D: defaultStatus='unknown' with all unaffected**
```json
{
  "vendor": "acme",
  "product": "widget",
  "defaultStatus": "unknown",
  "versions": [
    {"version": "1.0", "status": "unaffected"},
    {"version": "2.0", "status": "unaffected"}
  ]
}
```

**Pattern E: Changes array results in immediate unaffected**
```json
{
  "version": "1.0",
  "status": "affected",
  "changes": [
    {"at": "1.0", "status": "unaffected"}
  ]
}
```
**Note**: Change occurs at same version as base → no affected range exists

**Logic:**
- **Pattern A**: defaultStatus='affected' but ALL versions='unaffected' → metadata-only cpeMatch
- **Pattern B**: defaultStatus='unaffected' → metadata-only cpeMatch
- **Pattern C**: Placeholder versions with status='unaffected' → metadata-only cpeMatch
- **Pattern D**: Any defaultStatus with ALL versions='unaffected' → metadata-only cpeMatch
- **Pattern E**: Changes at same version as base (zero-width range) → metadata-only cpeMatch
- All patterns output cpeMatch with `vulnerable: false` and `concerns: ["noAffectedPlatforms"]`
- If ANY version has status='affected' → continue to other categories

**Analysis:**
- Indicates product is NOT vulnerable, or specific versions are not vulnerable
- status='unknown' is handled differently - skip processing and track

---

### 3.3 Output Pattern: Exact versions

One or more cpeMatch objects with exact version values in criteria field (no version range fields).

**Pattern A: Single exact version**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "1.2.3",<br>      "status": "affected"<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "exact.single",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"<br>}</pre> |

**Pattern B: Multiple discrete versions (1:1 transformation)**

| Input Pattern | Output cpeMatch Objects |
|---------------|-------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "1.2.3",<br>      "status": "affected"<br>    },<br>    {<br>      "version": "1.2.5",<br>      "status": "affected"<br>    },<br>    {<br>      "version": "2.0.1",<br>      "status": "affected"<br>    }<br>  ]<br>}</pre> | <pre>[<br>  {<br>    "versionsEntryIndex": 0,<br>    "appliedPattern": "exact.single",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"<br>  },<br>  {<br>    "versionsEntryIndex": 1,<br>    "appliedPattern": "exact.single",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:1.2.5:*:*:*:*:*:*:*"<br>  },<br>  {<br>    "versionsEntryIndex": 2,<br>    "appliedPattern": "exact.single",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:2.0.1:*:*:*:*:*:*:*"<br>  }<br>]</pre> |

**Note**: Three version entries produce three cpeMatch objects (1:1 transformation per entry)

**Pattern C: Mixed affected/unaffected/unknown versions**

| Input Pattern | Output cpeMatch Objects |
|---------------|-------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "1.0",<br>      "status": "affected"<br>    },<br>    {<br>      "version": "1.1",<br>      "status": "unaffected"<br>    },<br>    {<br>      "version": "1.2",<br>      "status": "affected"<br>    },<br>    {<br>      "version": "2.0",<br>      "status": "unknown"<br>    }<br>  ]<br>}</pre> | <pre>[<br>  {<br>    "versionsEntryIndex": 0,<br>    "appliedPattern": "exact.single",<br>    "vulnerable": true,<br>    "criteria": "cpe&#58;2.3&#58;a&#58;vendor&#58;product&#58;1.0&#58;*&#58;*&#58;*&#58;*&#58;*&#58;*&#58;*"<br>  },<br>  {<br>    "versionsEntryIndex": 1,<br>    "vulnerable": false,<br>    "concerns": ["statusUnaffected"]<br>  },<br>  {<br>    "versionsEntryIndex": 2,<br>    "appliedPattern": "exact.single",<br>    "vulnerable": true,<br>    "criteria": "cpe&#58;2.3&#58;a&#58;vendor&#58;product&#58;1.2&#58;*&#58;*&#58;*&#58;*&#58;*&#58;*&#58;*"<br>  },<br>  {<br>    "versionsEntryIndex": 3,<br>    "vulnerable": false,<br>    "concerns": ["statusUnknown"]<br>  }<br>]</pre> |

**Note**: All four version entries produce cpeMatch objects. Affected versions generate full criteria; unaffected and unknown versions produce metadata-only objects with concerns array.

**Pattern D: defaultStatus conflict - version.status takes precedence**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "defaultStatus": "unaffected",<br>  "versions": [<br>    {<br>      "version": "1.2.3",<br>      "status": "affected"<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "exact.single",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"<br>}</pre> |

**Note**: version.status='affected' overrides defaultStatus='unaffected' - produces vulnerable=true output

**Logic (per version entry):**
- **Pattern A**: Single version with status='affected' + NO range operators + NO changes array → output one cpeMatch with criteria
- **Pattern B**: Multiple versions with status='affected' + NO range operators + NO changes arrays → apply Pattern A to each
- **Pattern C**: Mixed status versions → ALL entries produce cpeMatch objects:
  - status='affected' → full cpeMatch with criteria
  - status='unaffected' → metadata-only with `concerns: ["statusUnaffected"]`
  - status='unknown' → metadata-only with `concerns: ["statusUnknown"]`
- **Pattern D**: version.status overrides defaultStatus (affected takes precedence over unaffected default)
- version field populated + status='affected' + NO range operators + NO changes array
- Each pattern application outputs one cpeMatch with version value in criteria attribute

**Analysis:**
- Each version entry is independent and produces a cpeMatch object
- NEVER auto-combine versions into ranges (reflect source material)
- When multiple exact version entries exist in versions[] array: iterate and apply these rules to each independently

**Iteration Example (1:1 transformation):**

| Input Pattern | Output cpeMatch Objects |
|---------------|-------------------------|
| <pre>{<br>  "versions": [<br>    {"version": "1.0", "status": "affected"},<br>    {"version": "2.0", "status": "affected"},<br>    {"version": "3.0", "status": "affected"}<br>  ]<br>}</pre> | <pre>[<br>  {<br>    "versionsEntryIndex": 0,<br>    "appliedPattern": "exact.single",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"<br>  },<br>  {<br>    "versionsEntryIndex": 1,<br>    "appliedPattern": "exact.single",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*"<br>  },<br>  {<br>    "versionsEntryIndex": 2,<br>    "appliedPattern": "exact.single",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:3.0:*:*:*:*:*:*:*"<br>  }<br>]</pre> |

**Note**: Three version entries produce three cpeMatch objects (1:1 transformation per entry)

---

### 3.4 Output Pattern: Single range per entry (1:1 transformation)

Single cpeMatch object with version range properties (versionStartIncluding/Excluding, versionEndIncluding/Excluding).

**Pattern A: Explicit range with lessThan**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "0",<br>      "status": "affected",<br>      "lessThan": "2.0"<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "range.lessThan",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>  "versionStartIncluding": "0",<br>  "versionEndExcluding": "2.0"<br>}</pre> |

**Pattern B: Explicit range with lessThanOrEqual**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "1.0",<br>      "status": "affected",<br>      "lessThanOrEqual": "1.9.5"<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "range.lessThanOrEqual",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>  "versionStartIncluding": "1.0",<br>  "versionEndIncluding": "1.9.5"<br>}</pre> |

**Note on Update Patterns in Ranges**: If range boundaries contain update patterns (e.g., `"10.0 SP 1"` to `"10.0 SP 3"`), current implementation DETECTS but does NOT APPLY transformations. The original untransformed values are used in `versionStartIncluding`/`versionEndExcluding`. This is flagged in metadata with `blocked_by_ranges: true` for visibility.

**Pattern C: Wildcard in lessThanOrEqual (open-ended)**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "1.0",<br>      "status": "affected",<br>      "lessThanOrEqual": "*"<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "range.openEnd",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>  "versionStartIncluding": "1.0"<br>}</pre>|

**Note**: Wildcard upper bound means "all versions from 1.0 onward" - versionEnd field omitted 

**Pattern D: Single status change (changes array)**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "5.0",<br>      "status": "affected",<br>      "changes": [<br>        {<br>          "at": "5.0.3",<br>          "status": "unaffected"<br>        }<br>      ]<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "range.changesFixed",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>  "versionStartIncluding": "5.0",<br>  "versionEndExcluding": "5.0.3"<br>}</pre> |

**Note**: Range from base version to change point

**Pattern D-Variant: Placeholder version with real changes data**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "unspecified",<br>      "status": "affected",<br>      "changes": [<br>        {<br>          "at": "1.2.3",<br>          "status": "unaffected"<br>        }<br>      ]<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "range.placeholderChanges",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>  "versionEndExcluding": "1.2.3"<br>}</pre> |

**Note**: version field is placeholder - versionStart omitted, changes[].at provides end boundary

**Pattern E: Inverse single change (unaffected→affected)**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "1.0",<br>      "status": "unaffected",<br>      "changes": [<br>        {<br>          "at": "1.5",<br>          "status": "affected"<br>        }<br>      ]<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "range.changesIntroduced",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>  "versionStartIncluding": "1.5"<br>}</pre> |

**Note**: Range starts where status changes to affected, no end boundary (open-ended)

**Pattern F: Open-ended beginning (no version field)**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "status": "affected",<br>      "lessThan": "2.0"<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "range.openStart",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>  "versionEndExcluding": "2.0"<br>}</pre> |

**Note**: Everything before 2.0 is affected - versionStart omitted

**Pattern G: Placeholder in upper bound**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "1.0",<br>      "status": "affected",<br>      "lessThan": "unknown"<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "range.placeholderUpperBound",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>  "versionStartIncluding": "1.0"<br>}</pre> |

**Note**: Placeholder in lessThan treated as open-ended - versionEnd omitted

**Pattern H: version="0" special case**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "0",<br>      "status": "affected",<br>      "lessThan": "2.0"<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "range.zeroStart",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>  "versionStartIncluding": "0",<br>  "versionEndExcluding": "2.0"<br>}</pre> |

**Note**: "0" is treated as a **literal version value**, not a placeholder. Current implementation includes "0" NOT in VERSION_PLACEHOLDER_VALUES, so it outputs `versionStartIncluding="0"` explicitly. Infer Affected Ranges also defaults to "0" when no start version is available.

**Pattern I: defaultStatus override - version.status takes precedence**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "defaultStatus": "unaffected",<br>  "versions": [<br>    {<br>      "version": "2.0",<br>      "status": "affected",<br>      "lessThan": "3.0"<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "range.statusOverride",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>  "versionStartIncluding": "2.0",<br>  "versionEndExcluding": "3.0"<br>}</pre> |

**Note**: version.status='affected' overrides defaultStatus='unaffected' - produces vulnerable=true output

**Logic (per version entry):**
- **Status Filtering**: 
  - status='affected' → full cpeMatch with criteria
  - status='unaffected' → metadata-only with `concerns: ["statusUnaffected"]`
  - status='unknown' → metadata-only with `concerns: ["statusUnknown"]`
- **Pattern A-B**: version + lessThan/lessThanOrEqual → range with both start and end boundaries
  - lessThan → versionEndExcluding
  - lessThanOrEqual → versionEndIncluding
- **Pattern C**: Wildcard upper bound → open-ended range (omit versionEnd field)
- **Pattern D/D-Variant**: version + single change → range from version to changes[0].at
  - If base version is placeholder but changes[].at has real data → omit versionStart, use changes data for end
- **Pattern E**: Inverse (unaffected→affected via change) → range starts at changes[0].at, no end
- **Pattern F**: No version field, only lessThan → open-ended beginning (omit versionStart field)
- **Pattern G**: Placeholder in upper bound → treat as open-ended (omit versionEnd field)
- **Pattern H**: version="0" → **TREATED AS LITERAL VALUE** (includes versionStartIncluding="0")
- **Pattern I**: version.status overrides defaultStatus (affected takes precedence)

**Analysis:**
- Each pattern produces one version range output per application (vulnerable=true only)
- Only status='affected' or changes resulting in affected ranges generate output
- Range field combinations:
  - Both start and end: Patterns A, B, D, H, I
  - Start only (open-ended end): Patterns C, G
  - End only (open-ended start): Patterns D-Variant, F
  - Special case: Pattern E starts at change point
- `version` field typically = starting point (inclusive by default)
- Comparison operators (lessThan/lessThanOrEqual) or changes define boundaries
- version.status always overrides defaultStatus
- When multiple range entries exist in versions[] array: iterate and apply these rules to each independently, producing one cpeMatch per range

**Iteration Example (1:1 transformation):**

| Input Pattern | Output cpeMatch Objects |
|---------------|-------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "1.0",<br>      "status": "affected",<br>      "lessThan": "2.0"<br>    },<br>    {<br>      "version": "3.0",<br>      "status": "affected",<br>      "lessThan": "4.0"<br>    }<br>  ]<br>}</pre> | <pre>[<br>  {<br>    "versionsEntryIndex": 0,<br>    "appliedPattern": "range.lessThan",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>    "versionStartIncluding": "1.0",<br>    "versionEndExcluding": "2.0"<br>  },<br>  {<br>    "versionsEntryIndex": 1,<br>    "appliedPattern": "range.lessThan",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>    "versionStartIncluding": "3.0",<br>    "versionEndExcluding": "4.0"<br>  }<br>]</pre> |

**Note**: Two range entries produce two cpeMatch objects (1:1 transformation per entry)

---

### 3.5 Output Pattern: Multiple ranges from one entry (1:M transformation)

Single version entry with multiple status transitions producing multiple ranges.

**Implementation Status**: Not currently implemented in JavaScript - documented for Python implementation requirements.

**Pattern A: Multiple status flip-flops**

| Input Pattern | Output cpeMatch Objects |
|---------------|-------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "3.0",<br>      "status": "affected",<br>      "changes": [<br>        {<br>          "at": "3.0.5",<br>          "status": "unaffected"<br>        },<br>        {<br>          "at": "3.1.0",<br>          "status": "affected"<br>        },<br>        {<br>          "at": "3.1.2",<br>          "status": "unaffected"<br>        }<br>      ]<br>    }<br>  ]<br>}</pre> | <pre>[<br>  {<br>    "versionsEntryIndex": 0,<br>    "appliedPattern": "multiRange.exactStatusTransitions",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>    "versionStartIncluding": "3.0",<br>    "versionEndExcluding": "3.0.5"<br>  },<br>  {<br>    "versionsEntryIndex": 0,<br>    "appliedPattern": "multiRange.exactStatusTransitions",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>    "versionStartIncluding": "3.1.0",<br>    "versionEndExcluding": "3.1.2"<br>  }<br>]</pre> |

**Note**: affected → unaffected → affected → unaffected creates two vulnerable ranges (vulnerability reintroduced)

**Pattern B: Changes combined with range bounds**

| Input Pattern | Output cpeMatch Objects |
|---------------|-------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "2.0",<br>      "status": "affected",<br>      "lessThan": "5.0",<br>      "changes": [<br>        {<br>          "at": "3.0",<br>          "status": "unaffected"<br>        },<br>        {<br>          "at": "4.0",<br>          "status": "affected"<br>        }<br>      ]<br>    }<br>  ]<br>}</pre> | <pre>[<br>  {<br>    "versionsEntryIndex": 0,<br>    "appliedPattern": "multiRange.rangeStatusTransitions",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>    "versionStartIncluding": "2.0",<br>    "versionEndExcluding": "3.0"<br>  },<br>  {<br>    "versionsEntryIndex": 0,<br>    "appliedPattern": "multiRange.rangeStatusTransitions",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>    "versionStartIncluding": "4.0",<br>    "versionEndExcluding": "5.0"<br>  }<br>]</pre> |

**Note**: Changes array splits the overall lessThan range into sub-ranges based on status transitions

**Logic:**
- Process changes array chronologically
- Track status state across transitions (affected ↔ unaffected)
- Create range for each affected segment
- lessThan/lessThanOrEqual defines outer boundary (if present)
- changes[].at values define inner boundaries
- Output: Multiple cpeMatch objects for each affected segment

**Analysis:**
- Single version entry produces MULTIPLE ranges due to status flip-flops
- Requires tracking status state across multiple transitions within one version entry
- Pattern A: Vulnerability was fixed, then reintroduced
- Pattern B: Must reconcile changes array with explicit range bounds
- CVE 5.x schema supports this pattern even if not yet implemented

---

### **Inference and Special Cases**

Patterns requiring version ordering knowledge, inference, or complex interpretation.

---

### 3.6 Output Pattern: Multiple cpeMatch objects - Wildcard expansion

**Implementation Priority**: DEFERRED - Advanced feature with parsing complexity

Wildcard version patterns translated to version ranges.

**Pattern A: Wildcard in lessThanOrEqual**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "5.4.0",<br>      "status": "affected",<br>      "lessThanOrEqual": "5.4.*"<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "inference.affectedFromWildcardExpansion",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>  "versionStartIncluding": "5.4.0",<br>  "versionEndExcluding": "5.5.0"<br>}</pre> |

**Note**: Wildcard "5.4.*" expanded to range [5.4.0, 5.5.0) by incrementing minor version

**Pattern B: Wildcard in version field**

| Input Pattern | Output cpeMatch Object |
|---------------|------------------------|
| <pre>{<br>  "versions": [<br>    {<br>      "version": "2.*",<br>      "status": "affected"<br>    }<br>  ]<br>}</pre> | <pre>{<br>  "versionsEntryIndex": 0,<br>  "appliedPattern": "inference.affectedFromWildcardExpansion",<br>  "vulnerable": true,<br>  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>  "versionStartIncluding": "2.0",<br>  "versionEndExcluding": "3.0"<br>}</pre> |

**Note**: Wildcard "2.*" expanded to range [2.0, 3.0) by incrementing major version

**Logic:**
- Wildcard patterns (e.g., "5.4.*") converted to explicit version ranges
- Extract version prefix before wildcard
- Increment appropriate version component (major, minor, patch)
- Use as versionEnd boundary

**Analysis:**
- Wildcards appear in version, lessThan, or lessThanOrEqual fields
- Expands to ranges rather than enumerating versions
- Leverages version range matching instead of explicit version lists

---

### 3.7 Output Pattern: Multiple cpeMatch objects - Infer Affected Ranges

**Implementation Priority**: DEFERRED - High-risk inference pattern with soundness concerns

Inferred vulnerable ranges from defaultStatus='affected' with unaffected RANGES (not exact versions).

**Applicability Constraint**: Infer Affected Ranges ONLY applies when unaffected versions have range constraints (lessThan, lessThanOrEqual). Exact unaffected versions without range constraints do NOT trigger inferred affected range detection.

**Pattern A: Gaps between unaffected ranges**

| Input Pattern | Output cpeMatch Objects |
|---------------|-------------------------|
| <pre>{<br>  "defaultStatus": "affected",<br>  "versions": [<br>    {<br>      "version": "1.0",<br>      "status": "unaffected",<br>      "lessThan": "2.0"<br>    },<br>    {<br>      "version": "3.0",<br>      "status": "unaffected",<br>      "lessThan": "4.0"<br>    },<br>    {<br>      "version": "5.0",<br>      "status": "unaffected",<br>      "lessThanOrEqual": "6.0"<br>    }<br>  ]<br>}</pre> | <pre>[<br>  {<br>    "versionsEntryIndex": null,<br>    "appliedPattern": "inference.affectedFromUnaffectedRanges",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>    "versionEndExcluding": "1.0"<br>  },<br>  {<br>    "versionsEntryIndex": null,<br>    "appliedPattern": "inference.affectedFromUnaffectedRanges",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>    "versionStartIncluding": "2.0",<br>    "versionEndExcluding": "3.0"<br>  },<br>  {<br>    "versionsEntryIndex": null,<br>    "appliedPattern": "inference.affectedFromUnaffectedRanges",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>    "versionStartIncluding": "4.0",<br>    "versionEndExcluding": "5.0"<br>  },<br>  {<br>    "versionsEntryIndex": null,<br>    "appliedPattern": "inference.affectedFromUnaffectedRanges",<br>    "vulnerable": true,<br>    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",<br>    "versionStartExcluding": "6.0"<br>  }<br>]</pre> |

**Note**: Unaffected ranges: [1.0-2.0), [3.0-4.0), [5.0-6.0]. Gaps filled with affected ranges.

**Logic:**
- defaultStatus='affected' with explicitly unaffected RANGES
- Each unaffected version must have lessThan/lessThanOrEqual
- Extract start/end boundaries from each unaffected range
- Sort ranges by start version
- Create affected ranges in gaps: before first, between pairs, after last
- Requires version ordering knowledge

---

## 4. Pre and Post Processing

Transformations applied before pattern matching (preprocessing) and after output generation (postprocessing).

### 4.1 Update/Patch Pattern Extraction (Preprocessing)

**Implementation Status**: Fully implemented in JavaScript - comprehensive pattern library (500+ lines)

Version strings containing update/patch/service pack indicators must be parsed into base version + update component.

**Supported Term Groups** (standardized output):
- `sp` (Service Pack, SP)
- `patch` (Patch, p)
- `hotfix` (Hotfix, HF)
- `update` (Update)
- `mr` (Maintenance Release, MR)
- `build` (Build)
- `release` (Release)
- `milestone` (Milestone)
- `snapshot` (Snapshot)
- `preview` (Preview)
- `candidate` (Candidate)
- `development` (Development)
- `dp` (Device Pack, DP)

**Pattern Recognition** (each term group supports):
1. Space-separated: `"10.0 SP 1"` → `10.0:sp1`
2. Concatenated: `"7.0.1update2"` → `7.0.1:update2`
3. Dash-notation: `"1.2.3-patch.4"` → `1.2.3:patch4`
4. Flexible separators: `"16.0.0_mr_7"` → `16.0.0:mr7`

**Output**: Base version in criteria position 5, update component in position 6 (normalized: lowercase, no spaces)

**Application Scope**: 
- **Exact versions (Section 3.3)**: Update pattern transformation APPLIED - version split into base + update component
- **Range boundaries (Section 3.4 lessThan/lessThanOrEqual)**: Update pattern transformation DETECTED but NOT APPLIED
  - Transformation flagged in metadata for visibility
  - Original untransformed value used in versionStart/End properties
  - CPE 2.3 spec limitation: no separate update field for range boundary values
  - Future enhancement opportunity: define semantics for update components in ranges

**Current JavaScript Behavior**: Update patterns in range boundaries are detected and logged with `blocked_by_ranges: true` flag, but the original version string is used unchanged for `versionStartIncluding`/`versionEndExcluding` properties.

**Implementation Note**: JavaScript uses regex pattern library with specific-to-general ordering. Python implementation should port this proven logic.

---

### 4.2 CPE Update Field Specificity Enforcement (Postprocessing)

**Implementation Status**: Fully implemented in JavaScript

When multiple cpeMatch objects share the same base CPE components but differ in the update field, enforce non-overlapping specificity.

**Problem**: Version extraction may generate both:
- Generic: `cpe:2.3:a:vendor:product:1.0:*:...` (any update)
- Specific: `cpe:2.3:a:vendor:product:1.0:patch1:...` (specific update)

**Resolution**: Convert wildcard update (`*`) to no-update (`-`) when specific updates exist for same base, ensuring each match has distinct scope

**Example**:

| Before | After |
|---------------------|---------------------|
| `cpe:...:1.0:*:...`<br>`cpe:...:1.0:patch1:...` | `cpe:...:1.0:-:...`<br>`cpe:...:1.0:patch1:...` |

**Logic**:
1. Group cpeMatch objects by base components (excluding update field at position 6)
2. Identify groups with both wildcard (`*`) and specific update values
3. Change wildcard to `-` (no update) to eliminate overlap
4. Preserve all specific update values unchanged

**Application**: Applied after all pattern processing complete, before final output

---

## 5. NVD-ish Integration

### Where CPE-AS Gets Embedded

Generated CPE-AS data is embedded in the NVD-ish record's `enrichedCVEv5Affected.cveListV5AffectedEntries[].cpeAsGeneration` section.  
Each CVE 5.0 `affected[]` entry produces one analysis entry with generated cpeMatch objects.

### Mockup Example



**Output: NVD-ish record with generated CPE-AS** (partial - showing only enrichedCVEv5Affected structure)

```json
{
  "id": "CVE-2024-1234",
  "sourceIdentifier": "cna@example.com",
  "published": "2024-01-15T00:00:00.000",
  "lastModified": "2024-01-15T00:00:00.000",
  "vulnStatus": "Analyzed",
  
  "descriptions": [...],
  "references": [...],
  "metrics": {...},
  
  "enrichedCVEv5Affected": {
    "toolExecutionMetadata": {...},
    "cpeDeterminationMetadata": [...],
    "cveListV5AffectedEntries": [
      {
        "originAffectedEntry": {
          "sourceId": "cna@example.com",
          "cvelistv5AffectedEntryIndex": "cve.containers.cna.affected.[0]",
          "vendor": "example",
          "product": "webapp",
          "defaultStatus": "unaffected",
          "versions": [
            {
              "version": "1.0",
              "status": "affected"
            },
            {
              "version": "2.0",
              "status": "affected",
              "lessThan": "2.5"
            },
            {
              "version": "3.0",
              "status": "affected",
              "changes": [
                {
                  "at": "3.2.1",
                  "status": "unaffected"
                }
              ]
            }
          ]
        },
        "sourceDataConcerns": {...},
        "aliasExtraction": {...},
        "cpeDetermination": {...},
        "cpeAsGeneration": {
          "sourceId": "Hashmire/Analysis_Tools v0.3.0",
          "cvelistv5AffectedEntryIndex": "cve.containers.cna.affected.[0]",
          "generatedCpeMatch": [
            {
              "versionsEntryIndex": 0,
              "appliedPattern": "exact.single",
              "vulnerable": true,
              "criteria": "cpe:2.3:a:example:webapp:1.0:*:*:*:*:*:*:*"
            },
            {
              "versionsEntryIndex": 1,
              "appliedPattern": "range.lessThan",
              "vulnerable": true,
              "criteria": "cpe:2.3:a:example:webapp:*:*:*:*:*:*:*:*",
              "versionStartIncluding": "2.0",
              "versionEndExcluding": "2.5"
            },
            {
              "versionsEntryIndex": 2,
              "appliedPattern": "range.changesFixed",
              "vulnerable": true,
              "criteria": "cpe:2.3:a:example:webapp:*:*:*:*:*:*:*:*",
              "versionStartIncluding": "3.0",
              "versionEndExcluding": "3.2.1"
            }
          ]
        }
      },
      {
        "originAffectedEntry": {
          "sourceId": "cna@example.com",
          "cvelistv5AffectedEntryIndex": "cve.containers.cna.affected.[1]",
          "vendor": "example",
          "product": "library",
          "defaultStatus": "affected",
          "versions": []
        },
        "sourceDataConcerns": {...},
        "aliasExtraction": {...},
        "cpeDetermination": {...},
        "cpeAsGeneration": {
          "sourceId": "Hashmire/Analysis_Tools v0.3.0",
          "cvelistv5AffectedEntryIndex": "cve.containers.cna.affected.[1]",
          "generatedCpeMatch": [
            {
              "versionsEntryIndex": null,
              "appliedPattern": "noVersion.allAffected",
              "vulnerable": true,
              "criteria": "cpe:2.3:a:example:library:*:*:*:*:*:*:*:*"
            }
          ]
        }
      },
      {
        "originAffectedEntry": {
          "sourceId": "cna@example.com",
          "cvelistv5AffectedEntryIndex": "cve.containers.cna.affected.[2]",
          "vendor": "example",
          "product": "server",
          "defaultStatus": "unaffected",
          "versions": [
            {
              "version": "16.0.0 MR 7",
              "status": "affected"
            }
          ]
        },
        "sourceDataConcerns": {...},
        "aliasExtraction": {...},
        "cpeDetermination": {...},
        "cpeAsGeneration": {
          "sourceId": "Hashmire/Analysis_Tools v0.3.0",
          "cvelistv5AffectedEntryIndex": "cve.containers.cna.affected.[2]",
          "generatedCpeMatch": [
            {
              "versionsEntryIndex": 0,
              "appliedPattern": "exact.single",
              "vulnerable": true,
              "criteria": "cpe:2.3:a:example:server:16.0.0:mr7:*:*:*:*:*:*"
            }
          ]
        }
      },
      {
        "originAffectedEntry": {
          "sourceId": "cna@example.com",
          "cvelistv5AffectedEntryIndex": "cve.containers.cna.affected.[3]",
          "vendor": "example",
          "product": "platform",
          "defaultStatus": "affected",
          "versions": [
            {
              "version": "abc123def",
              "versionType": "git",
              "status": "affected"
            },
            {
              "version": "10.0 SP 1",
              "status": "affected",
              "lessThanOrEqual": "10.0 SP 3"
            }
          ]
        },
        "sourceDataConcerns": {...},
        "aliasExtraction": {...},
        "cpeDetermination": {...},
        "cpeAsGeneration": {
          "sourceId": "Hashmire/Analysis_Tools v0.3.0",
          "cvelistv5AffectedEntryIndex": "cve.containers.cna.affected.[3]",
          "generatedCpeMatch": [
            {
              "versionsEntryIndex": 0,
              "concerns": ["versionTypeGit"]
            },
            {
              "versionsEntryIndex": 1,
              "appliedPattern": "range.lessThanOrEqual",
              "vulnerable": true,
              "criteria": "cpe:2.3:a:example:platform:*:*:*:*:*:*:*:*",
              "versionStartIncluding": "10.0 SP 1",
              "versionEndIncluding": "10.0 SP 3",
              "concerns": ["updatePatternsInRange"]
            }
          ]
        }
      }
    ]
  }
}
```

### Pattern-to-Output Mapping

| affected[] Entry | Applied Pattern | cpeMatch Objects in cpeAsGeneration |
|------------------|-----------------|------------------------------------------|
| webapp v1.0 (exact) | Section 3.3 Pattern A | Single exact version: `criteria="...webapp:1.0:..."`, `appliedPattern="exact.single"` |
| webapp v2.0-2.5 (range) | Section 3.4 Pattern A | Single range: `versionStartIncluding="2.0"`, `versionEndExcluding="2.5"`, `appliedPattern="range.lessThan"` |
| webapp v3.0 with change at 3.2.1 | Section 3.4 Pattern D | Single range: `versionStartIncluding="3.0"`, `versionEndExcluding="3.2.1"`, `appliedPattern="range.changesFixed"` |
| library (no versions) | Section 3.1 Pattern A | Single wildcard: `criteria="...library:*:..."`, `appliedPattern="noVersion.allAffected"` |
| server v16.0.0 MR 7 (update pattern) | Section 3.3 Pattern A + Section 4.1 | Exact version with update component: `criteria="...server:16.0.0:mr7:..."`, `appliedPattern="exact.single"` |
| platform git commit (versionType: git) | Section 6.1 | Metadata-only: `versionsEntryIndex=0`, `concerns=["versionTypeGit"]` |
| platform 10.0 SP 1-3 (update in range) | Section 3.4 Pattern B + Section 6.2 | Range with untransformed update patterns: `versionStartIncluding="10.0 SP 1"`, `concerns=["updatePatternsInRange"]` |

### Key Integration Points

1. **One affected entry → One cveListV5AffectedEntries element**: Each platform in CVE 5.0 `affected[]` produces one complete analysis entry
2. **cpeAsGeneration.generatedCpeMatch[]**: Array of cpeMatch objects generated from Section 3 patterns
3. **appliedPattern field**: Each cpeMatch includes pattern reference (e.g., "exact.single", "range.changesFixed", "inference.affectedFromWildcardExpansion") for traceability
4. **versionsEntryIndex field**: Maps to source versions[] array index (0-based, null if no versions array)
5. **concerns field** (optional): Array of known limitation identifiers when automated translation cannot fully represent source data (see Section 6)
6. **Post-processing**: CPE update field specificity enforcement (Section 4.2) applied before storing in generatedCpeMatch[]

---

## 6. Known Limitations

This section catalogs known failure conditions, edge cases, and limitations in CVE 5.x to CPE-AS translation logic. These represent areas where automated translation is not possible, produces incomplete results, or requires human review.

**Documentation Requirements**: All limitations MUST be documented in affected cpeMatch objects via the `concerns[]` array and logged to audit trail with specific CVE ID, affected entry index, and limitation details.

### CPE-AS Concerns Array Enumerations

The `concerns` array in each `cpeMatch` object identifies conditions that may require human review or special handling. These concern identifiers enable programmatic filtering and analysis of potential data quality issues.

| Concern Identifier | Trigger Condition | cpeMatch Type | Notes |
|-------------------|-------------------|---------------|-------|
| **Status-Based Concerns** |
| `statusUnaffected` | `affected.[*].versions[*].status: "unaffected"` | Metadata-only | Version explicitly marked as unaffected |
| `statusUnknown` | `affected.[*].versions[*].status: "unknown"` | Metadata-only | Version status is unknown/unclear |
| `defaultStatusUnknown` | `affected.[*].defaultStatus: "unknown"` | Metadata-only | Default status for entry is unknown |
| `noAffectedPlatforms` | `affected.[*]` has no platforms or all unaffected | Metadata-only | Entry has no platform data |
| **Version Type Concerns** |
| `versionTypeGit` | `affected.[*].versions[*].versionType: "git"` | Metadata-only | Git commit hashes (not semantic versions) |
| **CPE Mapping Concerns** |
| `cpeUnconfirmedWithSuggestions` | No confirmed CPE mapping, but CPE suggestions exist | Metadata-only | Requires manual CPE confirmation |
| `cpeUnconfirmedNoSuggestions` | No confirmed CPE mapping or suggestions | Metadata-only | Requires manual CPE research |
| **Pattern Detection Concerns** |
| `inferredAffectedFromWildcardExpansion` | `affected.[*].versions[*].version` contains `"*"` pattern | Metadata-only or Full | `appliedPattern` = `"inference.affectedFromWildcardExpansion"` |
| `updatePatternsInRange` | `affected.[*].versions[*].lessThan*` contains update patterns | Full cpeMatch | Version boundaries contain update patterns (untransformed) |
| `patternUnsupported` | No recognized pattern matched version entry structure | Metadata-only | `appliedPattern` omitted (null) |

**Implementation Guideline**: All conditions are logged with specific CVE ID, affected entry index, and reason. Multiple concerns may be present in a single `cpeMatch` object's `concerns[]` array.

**Pattern Tracking**: The `appliedPattern` field distinguishes between known patterns with values (like `"inference.affectedFromWildcardExpansion"`) and truly unknown patterns where the field is omitted (null) with `patternUnsupported` concern.

### 6.1 Version Type Git

**Issue**: Certain version ordering schemes cannot be processed with general alphanumeric comparison.

**General Approach**: Every version entry is processed and generates a cpeMatch object. Incompatible version types generate metadata-only cpeMatch objects with concerns rather than being skipped entirely.

**Processing Rules**:
- **`versionType: "git"`**: CANNOT generate valid CPE criteria (commit hashes require graph ordering)
  - Version entry MUST still be processed and generate a cpeMatch object
  - cpeMatch object contains only metadata fields (no `criteria`, no `vulnerable`, no version range fields)
  - MUST include `concerns: ["versionTypeGit"]` to indicate processing limitation
  - An affected entry may contain multiple version entries with different versionTypes
  - Each version entry (regardless of type) produces one cpeMatch object in output


**Failure Condition**: `"versionType": "git"`

**Required Behavior**:
- cpeMatch object MUST be created for the version entry
- cpeMatch object MUST include `versionsEntryIndex` metadata field
- cpeMatch object MUST include `concerns: ["versionTypeGit"]`
- cpeMatch object MUST NOT include `appliedPattern` (no pattern was applied)
- cpeMatch object MUST NOT include `criteria`, `vulnerable`, or version range fields
- Audit log entry MUST be created documenting the limitation
- Other version entries in same affected platform MUST continue processing normally

**Audit Log Format**:
```
"Detected 'versionType': 'git' | Cannot generate CPE criteria | Generated metadata-only cpeMatch | cve.containers.cna.affected.[X].versions[Y]"
```

**Example Scenarios**:

*Scenario 1: Mixed versionTypes within single affected entry*

Input:
```json
{
  "vendor": "example",
  "product": "webapp",
  "versions": [
    {"version": "1.0.0", "status": "affected"},
    {"version": "abc123def", "versionType": "git", "status": "affected"},
    {"version": "2.0.0", "status": "affected"}
  ]
}
```

Output: 3 cpeMatch objects generated
```json
[
  {
    "versionsEntryIndex": 0,
    "appliedPattern": "exact.single",
    "vulnerable": true,
    "criteria": "cpe:2.3:a:example:webapp:1.0.0:*:*:*:*:*:*:*"
  },
  {
    "versionsEntryIndex": 1,
    "concerns": ["versionTypeGit"]
  },
  {
    "versionsEntryIndex": 2,
    "appliedPattern": "exact.single",
    "vulnerable": true,
    "criteria": "cpe:2.3:a:example:webapp:2.0.0:*:*:*:*:*:*:*"
  }
]
```

*Scenario 2: Only git versionType*

Input:
```json
{
  "vendor": "example",
  "product": "library",
  "versions": [
    {"version": "abc123def", "versionType": "git", "status": "affected"}
  ]
}
```

Output: 1 metadata-only cpeMatch object
```json
[
  {
    "versionsEntryIndex": 0,
    "concerns": ["versionTypeGit"]
  }
]
```

---

### 6.2 Update Patterns in Range Boundaries

**Issue**: CPE 2.3 specification lacks mechanism to express update/patch components in range boundary values.

**Failure Condition**: Range boundaries (`lessThan`, `lessThanOrEqual`) contain update pattern indicators (e.g., `"10.0 SP 1"`, `"7.0 Update 3"`)

**Required Behavior**:
- Update pattern MUST be detected and logged as unsupported
- Original untransformed value MUST be used in `versionStartIncluding`/`versionEndExcluding` properties
- cpeMatch object MUST include `"updatePatternsInRange"` in `concerns[]` array
- Audit log entry MUST be created with specific limitation details

**Example**:

Input:
```json
{
  "version": "10.0 SP 1",
  "status": "affected",
  "lessThanOrEqual": "10.0 SP 3"
}
```

Required Output:
```json
{
  "versionsEntryIndex": 0,
  "appliedPattern": "range.lessThanOrEqual",
  "vulnerable": true,
  "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
  "versionStartIncluding": "10.0 SP 1",
  "versionEndIncluding": "10.0 SP 3",
  "concerns": ["updatePatternsInRange"]
}
```

**Audit Log Format**:
```
"Detected update pattern in range boundary for cve.containers.cna.affected.[0].versions[1] | CPE-AS will use untransformed values for boundaries | 
```

**Rationale**: 
- No structured fields for "start at update component X" within a base version
- Update field (position 6 in CPE string) applies to entire criteria, not range boundaries

**Impact**:
- Range boundaries may not match actual CPE naming conventions
- String comparison of `"10.0 SP 1"` vs `"10.0 SP 3"` is unreliable
- Potential for incorrect version range matching
- **Mitigation**: `concerns` array enables automated filtering and manual review workflows

---

### 6.3 Wildcard Expansion in Ranges

**Issue**: Wildcard patterns in range boundaries (e.g., `"lessThanOrEqual": "2.4.*"`) require expansion logic that may not align with vendor versioning schemes.

**Failure Condition**: Range boundary contains wildcard character (`*`) in version string

**Current Behavior**:
- Check for condition and include `inferredAffectedFromWildcardExpansion` in concerns array if identified.

---

### 6.4 Complex Version Semantics

**Issue**: Version strings with non-standard formatting may not parse correctly or compare as expected.

**Examples**:
- Date-based versions: `"2024-01-15"`, `"20240115"`
- Multi-component versions: `"1.2.3.4.5.6"`
- Marketing versions vs technical versions: `"Windows 11"` vs `"10.0.22000"`
- Epoch/revision schemes: `"1:2.3.4-5"`

**Current Behavior**: General alphanumeric comparison without semantic awareness

**Limitations**:
- Date comparison as strings may work accidentally but isn't guaranteed
- Multi-component version ordering may be incorrect beyond 3-4 parts
- Marketing version strings cannot be automatically mapped to technical versions

**Impact**: Incorrect version ordering, potential gaps or overlaps in ranges

**Mitigation**: Leverage versionType field when available, manual review for non-standard schemes

---

