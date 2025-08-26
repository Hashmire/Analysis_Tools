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
  - `src/analysis_tool/core/gatherData.py`
  - `src/analysis_tool/core/processData.py`
- **Confirmed Mappings**: The tool reviews a curated list of alias mappings to drive consistency of CPE Base String identification. Once a mapping is made, that decision will never need to be made by any system again for that alias. Alias mappings are flexible enough to handle multiple datatypes and overlapping identifications. Any organization is able to contribute a known alias mapping, so long as they can provide provenance that the alias data should map to the target CPE Base String and the alias exists in the CVE dataset.  
 *Files*:
  - `src/analysis_tool/mappings/*`
  - `src/analysis_tool/core/processData.py`
  - `src/analysis_tool/core/badge_modal_system.py`
  - `src/analysis_tool/static/js/badge_modal_system.js`

---

## Problem Domain 2: Complex Structural Parsing and Specification Needs

### Problem Description
Platform related information is contributed to CVE Records in a relatively structured format. However, there is still a great deal of flexibility in the various ways organizations are able to detail metadata about a platform and the various complicated methods of indicating which versions of that platform are considered vulnerable and which are not. Additionally, there are nuances between the expectations of CVE record data and normative CPE representation (Ex: Update attributes).  

### Solution Approach
The tool translates the information provided within a CVE record and (once a CPE Base String determination is made) converts all available information into the appropriate CPE Applicability Statement (CPE-AS) format.

### Codebase Areas

- **(CPE-AS) JSON Generation Rules**: The tool reviews the various defined CVE record affected array content, determines how to structure the available version data as CPE Match Strings or CPE Match String Ranges, identifies the most direct way to represent affected/unaffected/unknown indicators, leverages any unique conversions for known version types and makes appropriate conversions for cases where update data needs to be extracted into the update attribute of the normative CPE Match Criteria. Each affected entry processed, is consolidated into an overall CPE-AS for the CVE record.  
  *Files*:  
  - `src/analysis_tool/core/processData.py`
  - `src/analysis_tool/core/generateHTML.py`
  - `src/analysis_tool/static/js/badge_modal_system.js`

---

## Problem Domain 3: Source Data Contribution Usefulness

### Problem Description
Many conditions exist in CVE records that require additional, unnessary parsing by downstream data consumers to enable automation. Even more concerning are the multitude of data contributions that render the information non-actionable. While a large volume of these conditions should be resolved within the operation of the CVE Program and/or CVE Services, many could be rectified by the data contributors (the source) themselves.

### Solution Approach
The tool tracks and identifies a collection of cases that prevent or impede platform related automation efforts, displaying them in a visually digestible dashboard for data contributor and CVE Program review.

### Codebase Areas

- **Source Data Concern Dashboard**: The tool generates a detailed dashboard providing overall Source Data Concern statistics for the CVE records processed. This dashboard also provides searchable, targeted source based statistics enabling overall review and drilldown capabilities directly to the generated page for the CVE record in question.  
  *Files*:
  - `dashboards/sourceDataConcernDashboard.html`
  - `src/analysis_tool/logging/badge_contents_collector.py`
- **Source Data Concern Badge/Modal**: The tool generates an html page for user assistance of CPE-AS generation. Within each relevant row of the page, a Source Data Concerns Badge/Modal is available. Data contributors can use this to review the exact details of the Source Data Concern for that row. Each concern is broken down by problem, data and resolution guidance.  
  *Files*:
  - `src/analysis_tool/core/badge_modal_system.py`
  - `src/analysis_tool/static/js/badge_modal_system.js`
  - `src/analysis_tool/core/generateHTML.py`

---

## Problem Domain 4: Dataset Generation, Performance, and Scalability

### Problem Description
Creating a complete dataset that represents the entire CVE List within the current toolset can take an incredible amount of time.

### Solution Approach
The tool takes a series of approaches to assist with these issues.

### Codebase Areas

- **Caching System**: The tool reduces NVD /cpes/ API calls by caching responses locally for review during the same run. The cache has configurable settings for how long to reference the cached data before making new queries for the most up-to-date CPE Dictionary data.  
  *Files*:
  - `src/analysis_tool/storage/cpe_cache.py`
  - `src/cache/*`
- **CPE Match String Consolidation**: The tool consolidates all unique CPE Match Strings as part of the initial data generation stage to reduce the volume of queries made against the NVD /cpes/ API or the caching system. Additionally, any problematic CPE Match Criteria are culled to avoid wasted time on overly broad or erroneous queries.  
  *Files*:
  - `src/analysis_tool/core/processData.py`
- **Templating/Filesize Reduction**: The tool reduces the amount of data stored and thus file size within each generated page by leveraging templating techniques and unified data storage. This ensures reasonable dataset size for provisioning within a GitHub repository.  
  *Files*:
  - `src/analysis_tool/core/generateHTML.py`
  - `src/analysis_tool/static/js/badge_modal_system.js`
  - `src/analysis_tool/static/css/*`
