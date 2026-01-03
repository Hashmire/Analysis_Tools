# Confirmed Mappings (CPE Base Strings)

This section supports CPE Base String suggestion capabilities. Instead of attempting to derive the most likely CPE Base String by querying the NVD /cpes/ API, the json files contain explicit mappings for data sourced from the CVE List affected array and the relevant CPE Base String for which that data is expected to align.  

These mapping files are intended to be very simplistic and serve as a mechanism to better normalize the CPE representations throughout CVE Applicability Statements. Each JSON file represents a unique source of platform related information, currently based on the CVE Program's CNA and ADP entities.  

Example:  
Using the example JSON snippet below, any time the vendor, product, platform, etc., values from the source information align with what is included in the mapping files, the tool will "short circuit" the process and provide a CPE Moderator assertion of the appropriate CPE Base String.  

When values are matched between the CVE List data and the aliases array, the cpebasetring included in the entry should be associated to the row.  

```json
{
    "cpebasestring": "cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*",
    "aliases": [
        {
            "vendor": "microsoft",
            "product": "windows 10 version 1809"
        },
        {
            "vendor": "microsoft",
            "product": "windows 10 1809"
        }
    ]
}
```

## Source Mapping Curator

The `curator.py` tool automates the extraction of source data mappings from CVE 5.X records to assist in the generation of confirmed mapping files. This tool processes CVE records from specified CNAs/ADPs and extracts platform-specific alias information.

### Usage

Prior to running `curator.py`, a clone of the CVE List 5.X dataset must be available locally to reference with the `--cve-repo` parameter.  
From the project root, use the provided entry point:

```bash
# Extract Microsoft mappings
python run_curator.py --cve-repo X:\Git\cvelistV5\cves --uuid f38d906d-7342-40ea-92c1-6c4a2c6478c8

# Extract with custom context
python run_curator.py --cve-repo /path/to/cves --uuid f38d906d-7342-40ea-92c1-6c4a2c6478c8 --context custom_context
```

### Output

The curator generates a single output file in the run's `logs/` directory:

- `source_mapping_extraction_<uuid>_<timestamp>.json` - Complete extraction results

### Dashboard Integration

Results can be analyzed using the Source Mapping Dashboard at `dashboards/sourceMappingDashboard.html`.  
