# Confirmed Mappings (CPE Base Strings)

This section supports CPE Base String suggestion capabilities. Instead of attempting to derive the most likely CPE Base String by querying the NVD /cpes/ API, the json files contain explicit mappings for data sourced from the CVE List affected array and the relevant CPE Base String for which that data is expected to align.  

These mapping files are intended to be very simplistic and serve as a mechanism to better normalize the CPE representations throughout CVE Applicability Statements. Each JSON file represents a unique source of platform related information, currently based on the CVE Program's CNA and ADP entities.  

Example:  
Using the example JSON snippet below, any time the vendor, product, platform, etc. values from the source information align with what is included in the mapping files, the tool will skip checking the NVD /cpes/ API and instead "short circuit" the process and provide a CPE Moderator assertion of the appropriate CPE Base String.  

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
