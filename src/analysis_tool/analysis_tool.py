# Import Python dependencies
from pathlib import Path
import os
import webbrowser
from sys import exit
from build_info import GIT_COMMIT, GIT_REPO, VERSION, TOOLNAME
# Import console tab scripts
import gatherData
import processData
import generateHTML

def setOperationMode(modeSetting):
    # Execute Test or User Mode operations based on initial user input
    match modeSetting:
        # User Mode runs the CPE Dictionary Search capability, requesting Vendor and product name input data
        case "1":
            print(f"{TOOLNAME} {VERSION} built from repo {GIT_REPO} at commit {GIT_COMMIT}")
            print("CPE Search Mode Selected!")
            # Prompt for API key after mode selection
            nvdAPIKey = input("Enter NVD API Key (The process will be slower if no key is entered): ").strip()
            print("This mode is unfinished! Please use Enrichment Assistance Mode for now.")
            exit()

        # Enrichment Mode runs both the CVE List CPE Suggester and the VDB Intel Dashboard
        case "2":
            print(f"{TOOLNAME} {VERSION} built from repo {GIT_REPO} at commit {GIT_COMMIT}")
            print("Enrichment Assistance Mode Selected!")
            # Prompt for API key after mode selection
            nvdAPIKey = input("Enter NVD API Key (The process will be slower if no key is entered): ").strip()

            # Gather NVD Source Data for mapping source data later in the process
            nvdSourceData = gatherData.gatherNVDSourceData(nvdAPIKey) 
            
            processActive = True
            while processActive == True:

                # Get CVE-ID from input 
                targetCve = input("Enter CVE-ID (CVE-YYYY-XXXXXXX)")
                
                # Make sure the string is formatted well
                targetCve = targetCve.strip()
                targetCve = targetCve.upper()
                processData.integrityCheckCVE("cveIdFormat", targetCve)
                
                # Create Primary Datasets from external sources and derive useful fields for display
                primaryDataframe = gatherData.gatherPrimaryDataframe()

                # Gather CVE List Record and NVD Dataset Records for the target CVE
                cveRecordData = gatherData.gatherCVEListRecord(targetCve)
                nvdRecordData = gatherData.gatherNVDCVERecord(nvdAPIKey, targetCve)

                # Process the vulnerability record data to extract useful platform related information
                primaryDataframe = processData.processCVEData(primaryDataframe, cveRecordData)             
                primaryDataframe = processData.processNVDRecordData(primaryDataframe, nvdRecordData)

                # Based on the collected information, use the NVD API to gather relevant CPE data
                primaryDataframe = processData.suggestCPEData(nvdAPIKey, primaryDataframe, 1)
                           
                # Do a rough convert of the dataframe to html for debug display
                primaryDataframe = generateHTML.update_cpeQueryHTML_column(primaryDataframe, nvdSourceData)
                
                primaryDataframe = primaryDataframe.drop('sourceID', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('sourceRole', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('rawPlatformData', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('rawCPEsQueryData', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('sortedCPEsQueryData', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('trimmedCPEsQueryData', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('platformEntryMetadata', axis=1, errors='ignore')

                # Get the correct number of columns
                num_cols = len(primaryDataframe.columns)

                # Create appropriate column widths based on number of columns
                if num_cols == 2:
                    col_widths = ['20%', '80%']
                else:
                    # For any other number of columns, calculate evenly
                    col_width = f"{100/num_cols}%"
                    col_widths = [col_width] * num_cols
                    print(f"Warning: {num_cols} columns detected, should be two.")

                # Convert to HTML with correct column spacing
                affectedHtml2 = primaryDataframe.to_html(
                    classes='table table-stripped',
                    col_space=col_widths,
                    escape=False,
                    index=False
                )

                vdbIntelHtml = gatherData.gatherVDBIntel(targetCve)
                # Put all the html together into a main console view
                allConsoleHTML = generateHTML.buildHTMLPage(affectedHtml2, targetCve, vdbIntelHtml)

                # Create html file for CVE, write to it,
                sub_directory = Path(f"{os.getcwd()}{os.sep}analysis_tool_files")
                sub_directory.mkdir(parents=True, exist_ok=True)
                filename = (targetCve + ".html")
                filepath = sub_directory / filename
                with filepath.open("w", encoding="utf-8") as fd:
                    fd.write(allConsoleHTML)
                # Open html file in a new browser tab for viewing. Comment out for testing needs
                webbrowser.open_new_tab(f"file:///{filepath}")
        
        # Test Mode processes a list of arbitrary test CVEs in bulk to assist with Enrichment mode development
        # Version matching as part of cve
        case "9":
            print(f"{TOOLNAME} {VERSION} built from repo {GIT_REPO} at commit {GIT_COMMIT}")
            print("Test Mode Selected!")
            # Prompt for API key after mode selection
            nvdAPIKey = input("Enter NVD API Key (The process will be slower if no key is entered): ").strip()

            # Gather NVD Source Data for mapping source data later in the process
            nvdSourceData = gatherData.gatherNVDSourceData(nvdAPIKey)
            
            def runCVESmokeTests():
                cveSmoke = [
                        "CVE-2024-0057",    # Lots of everything, CPEs included
                        "CVE-2024-20698",   # Windows OS's        | multiple CPEs per entry
                        "CVE-2023-41842",   # Three Entries       | no Changes    | multiple version branches
                        "CVE-2024-2469",    # Single Entry        | has Changes   | multiple version branches
                        "CVE-2024-21389",   # Single Entry, CPE included
                        "CVE-2023-33009",   # Unhelpful Product Name Data
                        "CVE-2024-20359",   # Many Single Version entries per product (Cisco)
                        "CVE-2024-4072",    # product only success
                        "CVE-2024-3371",    # Multiple CNA Provided CPE Check results, culled
                        "CVE-2022-48655",   # Unaffected version range data
                        "CVE-2023-5541",    # CollectionURL + PackageName Combo 
                        "CVE-2023-4438",    # Mozilla Firefox vulnerability with multiple version branches
                        "CVE-2023-29300",   # A vulnerability with CPE array that includes platform information
                        "CVE-2023-23583",   # Jenkins vulnerability with complex version constraints
                        "CVE-2023-38180",   # OpenSSL vulnerability with version range specifications
                        "CVE-2024-1597",    # VMware vulnerability with multiple affected products
                        "CVE-2023-46604",   # Apache ActiveMQ vulnerability with high profile, good for testing priority scoring
                        "CVE-2023-36874",   # Microsoft Office vulnerability with complex platform dependencies
                        "CVE-2022-47966",   # ForgeRock vulnerability with detailed version information
                        "CVE-2023-44487",   # HTTP/2 rapid reset vulnerability that affects many products (good for testing large result sets)
                        "CVE-2023-21608",   # Oracle WebLogic Server vulnerability with multiple version branches and complex metadata
                            # 
                        ]
                for targetCve in cveSmoke: 

                    # Make sure the string is formatted well
                    targetCve = targetCve.strip()
                    targetCve = targetCve.upper()
                    processData.integrityCheckCVE("cveIdFormat", targetCve)
                    
                    # Create Primary Datasets from external sources and derive useful fields for display
                    primaryDataframe = gatherData.gatherPrimaryDataframe()

                    # Gather CVE List Record and NVD Dataset Records for the target CVE
                    cveRecordData = gatherData.gatherCVEListRecord(targetCve)
                    nvdRecordData = gatherData.gatherNVDCVERecord(nvdAPIKey, targetCve)

                    # Process the vulnerability record data to extract useful platform related information
                    primaryDataframe = processData.processCVEData(primaryDataframe, cveRecordData)             
                    primaryDataframe = processData.processNVDRecordData(primaryDataframe, nvdRecordData)
                    
                    # Based on the collected information, use the NVD API to gather relevant CPE data
                    primaryDataframe = processData.suggestCPEData(nvdAPIKey, primaryDataframe, 1)
                            
                    # Do a rough convert of the dataframe to html for debug display
                    primaryDataframe = generateHTML.update_cpeQueryHTML_column(primaryDataframe, nvdSourceData)
                    
                    primaryDataframe = primaryDataframe.drop('sourceID', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('sourceRole', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('rawPlatformData', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('rawCPEsQueryData', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('sortedCPEsQueryData', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('trimmedCPEsQueryData', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('platformEntryMetadata', axis=1, errors='ignore')

                    # Get the correct number of columns
                    num_cols = len(primaryDataframe.columns)

                    # Create appropriate column widths based on number of columns
                    if num_cols == 2:
                        col_widths = ['20%', '80%']
                    else:
                        # For any other number of columns, calculate evenly
                        col_width = f"{100/num_cols}%"
                        col_widths = [col_width] * num_cols
                        print(f"Warning: {num_cols} columns detected, should be two.")

                    # Convert to HTML with correct column spacing
                    affectedHtml2 = primaryDataframe.to_html(
                        classes='table table-stripped',
                        col_space=col_widths,
                        escape=False,
                        index=False
                    )

                    vdbIntelHtml = gatherData.gatherVDBIntel(targetCve)
                    # Put all the html together into a main console view
                    allConsoleHTML = generateHTML.buildHTMLPage(affectedHtml2, targetCve, vdbIntelHtml)

                    # Create html file for CVE, write to it,
                    sub_directory = Path(f"{os.getcwd()}{os.sep}analysis_tool_files")
                    sub_directory.mkdir(parents=True, exist_ok=True)
                    filename = (targetCve + ".html")
                    filepath = sub_directory / filename
                    with filepath.open("w", encoding="utf-8") as fd:
                        fd.write(allConsoleHTML)
                    # Open html file in a new browser tab for viewing. Comment out for testing needs
                    webbrowser.open_new_tab(f"file:///{filepath}")

                
                print("Smoke tests completed... Check browser tabs!")
        
        # General examples for unique cases to handle help identifying regressions, should create real test cases and example files for known needs.
            runCVESmokeTests() 
        case _:
            print("Invalid choice, exiting")
            exit()
    
setOperationMode(input("Select Mode: \n 1 --> CPE Search Mode \n 2 --> Enrichment Assistance Mode \n 9 --> Test Mode \n"))

