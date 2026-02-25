# Understanding CPE Applicability Generation Challenges

Platform identification is a foundational part of cybersecurity intelligence. However, accurate, reliable and unbias access to this information is not always available to those who may benefit. The community has the ability to empower themselves through collaboration to bring this information together and solidify a more robust baseline of useful and openly available cybersecurity intelligence.

## Overview

The CPE Applicability Generator tool tackles complex challenges in vulnerability analysis, CPE applicability, and platform data quality. Each problem domain has dedicated components within the codebase that work together to provide comprehensive solutions.

---

## Problem Domain 1: CPE Base String Determination

### Problem Description

A common point of friction for organizations attempting to use CPE is that they cannot reliably determine the CPE Base String for their target platform. This is due to inconsistent representation of platforms over their lifecycle, lacking publicly available information regarding a platform, inconsistency of representation within the CPE Dictionary and lacking coverage of CPE Names within the CPE Dictionary.

### Solution Approach

The tool processes provided, relevant platform metadata and identifies the most likely CPE Base String based on data transformations, heuristics and subject matter expert assertions via confirmed mappings.

### Codebase Areas

- **Data Transformations / Heuristics**: The tool gathers relevant data from product/platform related fields to create various CPE Match Criteria representations. These are used to query the NVD /cpes/ API to gather relevant CPE Name data. The CPE Names and associated metadata are then consolidated, reviewed and ordered to derive the top ten most likely CPE Base Strings.  
  *Files*:
  - `src/analysis_tool/core/analysis_tool.py`
  - `src/analysis_tool/core/processData.py`
  - `src/analysis_tool/storage/cpe_cache.py`
- **Confirmed Mappings**: The tool reviews a curated list of alias mappings to drive consistency of CPE Base String identification. Alias mappings are flexible enough to handle multiple datatypes and overlapping identifications. Any organization is able to contribute a known alias mapping, so long as they can provide provenance that the alias data should map to the target CPE Base String and the alias exists in the CVE dataset.  
 *Files*:
  - `src/analysis_tool/mappings/*`
  - `src/analysis_tool/storage/confirmed_mapping_manager.py`
  - `src/analysis_tool/core/processData.py`

---

## Problem Domain 2: Complex Structural Parsing and Specification Needs

### Problem Description
Platform related information is contributed to CVE Records in a relatively structured format. However, there is still a great deal of flexibility in the various ways organizations are able to detail metadata about a platform and the various complicated methods of indicating which versions of that platform are considered vulnerable and which are not. Additionally, there are nuances between the expectations of CVE record data and normative CPE representation (Ex: Update attributes).  

### Solution Approach
The tool translates the information provided within a CVE record and (once a CPE Base String determination is made) converts all available information into the appropriate CPE Applicability Statement (CPE-AS) format.

### Codebase Areas

- **(CPE-AS) JSON Generation Rules**: The tool reviews the various defined CVE record affected array content, determines how to structure the available version data as CPE Match Strings or CPE Match String Ranges, identifies the most direct way to represent affected/unaffected/unknown indicators, leverages any unique conversions for known version types and makes appropriate conversions for cases where update data needs to be extracted into the update attribute of the normative CPE Match Criteria. Each affected entry processed, is consolidated into an NVD-ish enriched record format.  
  *Files*:  
  - `src/analysis_tool/core/processData.py`
  - `src/analysis_tool/core/cpe_as_generator.py`
  - `src/analysis_tool/storage/nvd_ish_collector.py`

---

## Problem Domain 3: Source Data Contribution Usefulness

### Problem Description
Many conditions exist in CVE records that require additional, unnessary parsing by downstream data consumers to enable automation. Even more concerning are the multitude of data contributions that render the information non-actionable. While a large volume of these conditions should be resolved within the operation of the CVE Program and/or CVE Services, many could be rectified by the data contributors (the source) themselves.

### Solution Approach
The tool tracks and identifies a collection of cases that prevent or impede platform related automation efforts, displaying them in a visually digestible dashboard for data contributor and CVE Program review.

### Codebase Areas

- **Source Data Concern Dashboard**: The tool generates a detailed dashboard providing overall Source Data Concern statistics for the CVE records processed. This dashboard also provides searchable, targeted source based statistics enabling overall review and drilldown capabilities directly to the NVD-ish record in question.  
  *Files*:
  - `src/analysis_tool/reporting/generate_sdc_report.py`
  - `src/analysis_tool/logging/badge_contents_collector.py`
  - `dashboards/sourceDataConcernDashboard.html` (example)
- **Source Data Concern Detection & Storage**: The tool analyzes platform entries during processing to detect quality issues, storing findings in the Platform Entry Notification Registry (PENR). This data is then integrated into NVD-ish records and rendered via report generation for data contributor review. Each concern is broken down by problem, data and resolution guidance.  
  *Files*:
  - `src/analysis_tool/core/platform_entry_registry.py`
  - `src/analysis_tool/storage/nvd_ish_collector.py`
  - `src/analysis_tool/reporting/generate_sdc_report.py`

---

## Problem Domain 4: Dataset Generation, Performance, and Scalability

### Problem Description
Creating a complete dataset that represents the entire CVE List within the current toolset can take an incredible amount of time.

### Solution Approach
The tool takes a series of approaches to assist with these issues.

### Codebase Areas

- **Caching System**: The tool caches multiple data sources locally to reduce API calls and improve performance. This includes NVD CPE Dictionary data (sharded architecture), NVD source metadata, and CVE List v5 records. The cache has configurable settings for staleness detection and automatic refresh based on NVD change history endpoints.  
  *Files*:
  - `src/analysis_tool/storage/cpe_cache.py`
  - `src/analysis_tool/storage/nvd_source_manager.py`
  - `cache/cpe_base_strings/*` (sharded CPE cache)
  - `cache/nvd_source_data.json`
  - `cache/cve_list_v5/*`
  - `utilities/refresh_nvd_cpe_base_strings_cache.py`
- **CPE Match String Consolidation & Validation**: The tool consolidates all unique CPE Match Strings during initial data processing to reduce query volume against the NVD /cpes/ API. Additionally, CPE Match Criteria undergo validation and exclusion logic to cull problematic entries (overly broad patterns, known placeholders, invalid formats) preventing wasted processing time on erroneous queries.  
  *Files*:
  - `src/analysis_tool/core/processData.py`
  - `src/analysis_tool/core/platform_entry_registry.py`
- **Dataset Generation & Reporting Architecture**: The tool generates enriched NVD-ish records storing structured CVE data with CPE determination, alias extraction, source data concerns or CPE Applicability Statements data in a persistent cache. This separation of data collection from report generation enables scalable dataset creation (`generate_dataset.py`, `harvest_and_process_sources.py`) and flexible on-demand report generation (SDC reports, alias extraction reports, CPE-AS automation reports) without reprocessing.  
  *Files*:
  - `generate_dataset.py`
  - `harvest_and_process_sources.py`
  - `src/analysis_tool/storage/nvd_ish_collector.py`
  - `cache/nvd-ish_2.0_cves/*`
  - `src/analysis_tool/reporting/generate_sdc_report.py`
  - `src/analysis_tool/reporting/generate_alias_report.py`  - `src/analysis_tool/reporting/generate_cpe_as_report.py`