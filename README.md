# Vulnerability Analysis and Enrichment Tools

The Vulnerability Analysis and Enrichment Tools are intended to serve many needs across the vulnerability management ecosystem. This project is intended to serve as a workspace to generate proof-of-concept interfaces, as various projects mature past this repository they may no longer continue to be supported.  

For more detailed information make sure to check out the [Wiki Pages](https://github.com/Hashmire/Analysis_Tools/wiki)

## Current projects

### CPE Applicability Generator

This project is primarily designed to assist with CPE Applicability Statement Enrichment efforts.  

Primary Purpose/Workflow:

- Ingests CVE information from the CVE List
- Manipulates the data to determine relevant CPE attribute values
- Queries the NVD /cpes/ API for relevant CPE Names
- Processes the data returned to determine the most likely CPE Base String values for each Affected entry
- Displays all relevant information to a user for review
- Enables the user to select the appropriate CPE Base String or provide their own if no valuable results were found
- Generates CPE Applicability Statements (configurations) using the selected CPE Base String(s) and the data within the Affected section of the CVE record
- Users can copy/paste or download a file to use the generated content as needed

Secondary Purpose(s):

- Provide feedback to CVE record contributors regarding the usefulness of the Affects section data for CPE automation efforts

The following examples are hosted in this repository and are updated to align with the existing main branch:  

[Single CPE Match String:  CVE-2024-12355](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-12355)  
[Many CPE Match Strings:  CVE-2024-20359](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-20359)  
[MongoDB cpes Array Data:  CVE-2024-3371](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-3371)  
[Package Name:  CVE-2023-5541](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2023-5541)  
[Fortinet + ~Duplicate ADP:  CVE-2023-41842](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2023-41842)  
[GitHub + changes Array Data:  CVE-2024-2469](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-2469)  
[Linux Kernel:  CVE-2022-48655](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2022-48655)  
[Microsoft Simple:  CVE-2024-21389](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-21389)  
[Microsoft Many Rows:  CVE-2024-0057](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-0057)  
[Unhelpful versions Array Data:  CVE-2023-33009](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2023-33009)  
[Update Attribute Information in versions Array Data:  CVE-2024-20515](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-20515)  
[Platforms Array Data:  CVE-2024-20698](https://hashmire.github.io/Analysis_Tools/generated_pages/CVE-2024-20698)  

The full dataset of generated pages can be found at [Hashmire/cpeApplicabilityGeneratorPages](https://github.com/Hashmire/cpeApplicabilityGeneratorPages).

If you want to view a specific CVE record within the generated pages, use the following URL structure: `https://hashmire.github.io/cpeApplicabilityGeneratorPages/generated_pages/<CVE-ID CVE-YYYY-NNNNNN>.html`

## Installation

This tool isn't intended to be run locally, but if desired, the tool can be run locally with the following steps:

1. Clone the repository
2. Install dependencies:

   ```bash
   cd src/analysis_tool
   pip install -r requirements.txt
   ```

3. Run the tool from the project root:

   ```bash
   python run_tools.py --help
   ```

   **Note:** Do not run `analysis_tool.py` directly. Always use the `run_tools.py` entry point script from the project root directory to ensure proper package imports and path resolution.

## Testing

Comprehensive automated test suites are available for validating core functionality:

- **[Provenance Assistance Test Suite](documentation/provenance_assistance_test_suite.md)** - Validates multi-platform package repository detection, WordPress integration, and description/reference assistance
- **[Modular Rules Test Suite](documentation/modular_rules_test_suite.md)** - Validates JSON generation rules, wildcard expansion, version processing, and rule interactions
