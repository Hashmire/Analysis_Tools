# Vulnerability Enrichment and Intelligence Tool

The Vulnerability Enrichment and Intelligence Tool is intended to serve many needs across the vulnerability management ecosystem. This project is intended to serve as a workspace to generate proof-of-concept interfaces, as various projects mature past this repository they may no longer continue to be supported. 

## Current projects:

**CPE Configuration Builder**

This project is primarily designed to assist with CPE Applicability Statement Enrichment efforts. 

Primary Purpose:
- Ingests CVE information from the CVE List
- Manipulates the data to determine relevant CPE attribute values
- Queries the NVD /cpes/ API for relevant CPE Names
- Processes the data returned to determine the most likely CPE Base String values for each Affected entry
- Displays all relevant information to a user for review
- Enables the user to select the appropriate CPE Base String or provide their own if no valuable results were found
- Generates appropriate CPE Applicability Statements using the selected CPE Base String(s) and the data within the Affected section of the CVE record.

Secondary Purpose(s):
- Provide feedback to CVE record contributors regarding the usefulness of the Affects section data for CPE automation efforts.
- Provide Macro statistics regarding Affected section data.

Examples of the tool interface can be reviewed using the following structure:  
<code>https://hashmire.github.io/Analysis_Tools/docs/[CVE-XXXX-XXXX].html</code>  
All available examples can be found in the /docs/ folder.  

The following examples are USUALLY updated to the latest:  
https://hashmire.github.io/Analysis_Tools/docs/CVE-2024-0057  
https://hashmire.github.io/Analysis_Tools/docs/CVE-2024-20698  
https://hashmire.github.io/Analysis_Tools/docs/CVE-2023-41842  
https://hashmire.github.io/Analysis_Tools/docs/CVE-2024-2469  
https://hashmire.github.io/Analysis_Tools/docs/CVE-2024-21389  
https://hashmire.github.io/Analysis_Tools/docs/CVE-2023-33009  
https://hashmire.github.io/Analysis_Tools/docs/CVE-2024-20359  
https://hashmire.github.io/Analysis_Tools/docs/CVE-2024-4072  
https://hashmire.github.io/Analysis_Tools/docs/CVE-2024-3371  
https://hashmire.github.io/Analysis_Tools/docs/CVE-2022-48655  
https://hashmire.github.io/Analysis_Tools/docs/CVE-2023-5541
