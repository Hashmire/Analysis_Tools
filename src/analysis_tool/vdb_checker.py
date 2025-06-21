import requests
from tqdm import tqdm
import sys
import logging
from workflow_logger import WorkflowLogger

# Initialize logger
logger = WorkflowLogger()

# Iterate through our list of locations and append the CVE ID, open each item in a new tab
#### Instead of blindly opening in a new tab, we should try to consolidate the valuable information
####   crawl:   only populate entries for sources that return 200 / have useful data
####   walk:    scrape data from source material and store for redisplay in a roll-up / dashboard view
####   run:     consolidate multiple source materials from same parent source (organization advisory vs CSAF vs CVE List etc.) for redisplay in roll-up / dashboard view


def gatherVDBCheckerData(targetCve):
    # Current list of places to check. 
    # Eventually break this out as something to import (like a settings/config file) 
    supportedSources = {
        "IBM Xforce": "https://exchange.xforce.ibmcloud.com/vulnerabilities/",
        "RedHat Security API": "https://access.redhat.com/hydra/rest/securitydata/",
        "Amazon CVE": "https://alas.aws.amazon.com/cve/html/",
        "SUSE CVE": "https://www.suse.com/security/cve/",
        "Teneble CVE": "https://www.tenable.com/cve/",
        "Microsoft MSRC": "https://msrc.microsoft.com/update-guide/vulnerability/"
    }

    # Initialize some html containers to build the console page
    supportedSourceTableStartHTML = "<table class=\"table table-hover\" id=\"supportedSourceTable\">"
    supportedSourceTableHeadersHTML = "<tr><th>Name & Link</th><th>CVSS v3.x</th><th>CWE</th><th>Notes/Context</th><th>Response Code</th></tr>"
    dataGatherSuccessHTML = ""
    dataGatherFailureHTML = ""
    print ("[INFO]  Gathering supported source intelligence...")
    
      # Each supported source is dumped into a table row for easy visual comparison of tracked datapoints
    for source in tqdm(supportedSources, desc="Processing sources", unit="source"):
        
        allSourceCellHTML = ""

        dataTypeHTMLMap = {
            "nameLink": "<td> - </td>",
            "cvss3x": "<td> - </td>",
            "cwe": "<td> - </td>",
            "notes": "<td> - </td>",
            "responseCode": "<td> - </td>"            }
        
        def getJSONDict():
            try: 
                sourceDataDict = sourceURLData.json()
                return sourceDataDict
            except requests.exceptions.JSONDecodeError as e:
                logger.warning(f"Invalid JSON response from {source}: {e}", group="error_handling")
                return {}  # Return empty dict to prevent None checks
            except Exception as e:
                logger.error(f"Unexpected error parsing JSON from {source}: {e}", group="error_handling")
                return {}

        match source:
            case "RedHat Security API":
                requestURL = supportedSources[source] + "cve/" + targetCve + ".json"
                sourceURLData = requests.get(requestURL)
                sourceData = getJSONDict()
                if "cvss3" in sourceData:
                    dataTypeHTMLMap["cvss3x"] = ("<td>" + sourceData ["cvss3"]["cvss3_scoring_vector"] + "</td>")
                if "cwe" in sourceData:
                    dataTypeHTMLMap["cwe"] = ("<td>" + sourceData["cwe"] + "</td>")
                if "statement" in sourceData: 
                    dataTypeHTMLMap["notes"] = ("<td>" + sourceData["statement"] + "</td>")

            case _:
                requestURL = supportedSources[source] + targetCve
                sourceURLData = requests.get(requestURL)    

        # Source Name as a link to source material
        dataTypeHTMLMap["nameLink"] = "<td><a href=\"" + supportedSources[source] + targetCve + "\" target=\"_blank\">" + source + "</a></td>"
        # Report the error code for troubleshooting and situational awareness
        dataTypeHTMLMap["responseCode"] = "<td>Response Data:  " + str(sourceURLData.status_code) + "</td>"

        # Add the Cell data into the overall row
        for dataType in dataTypeHTMLMap:
            allSourceCellHTML = allSourceCellHTML + dataTypeHTMLMap[dataType]
        
        # Add the sourceRow into proper containerHTML based on success or failure
        if sourceURLData.ok:
            sourceRow = "<tr id=\""+ source.replace(" ", "-") + "\">" + allSourceCellHTML + "</tr>"
            dataGatherSuccessHTML = dataGatherSuccessHTML + sourceRow 
        else:
            sourceRow = "<tr id=\""+ source.replace(" ", "-") + "\" class=\"danger\">" + allSourceCellHTML + "</tr>"
            dataGatherFailureHTML = dataGatherFailureHTML + sourceRow        

        pass

    supportedSourceTableHTML = supportedSourceTableStartHTML + supportedSourceTableHeadersHTML + dataGatherSuccessHTML + dataGatherFailureHTML

    return(supportedSourceTableHTML + "</table>")
