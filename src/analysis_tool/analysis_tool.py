# Import Python dependencies
import webbrowser
import os
from pathlib import Path
from sys import exit
from build_info import GIT_COMMIT, GIT_REPO, VERSION, TOOLNAME
# Import console tab scripts
import gatherData
import processData
import generateHTML

# Initial setup of useful global variables
#nvdAPIKey = input("Enter NVD API Key (The process will be slower if no key is entered.)")
nvdAPIKey = '426ecf95-42ac-4c10-afd4-b7ee3d6a2229' # Remove this prior to commit

# Gather NVD Source Data for mapping source data later in the process
nvdSourceData = gatherData.gatherNVDSourceData(nvdAPIKey) 

def setOperationMode(modeSetting):

    # Execute Test or User Mode operations based on initial user input
    match modeSetting:
        # User Mode runs the CPE Dictionary Search capability, requesting Vendor and product name input data
        case "1":
            print(f"[INFO]  {TOOLNAME} {VERSION} built from repo {GIT_REPO} at commit {GIT_COMMIT}")
            print ("[INFO]  CPE Search Mode Selected!")
            print ("[INFO]  This mode is unfinished! Please use Enrichment Assistance Mode for now.")
            exit()

            #processActive = True
            #while processActive == True:
                
                # Get platform input from user (start with CLI, improve later)

            #    allPlatforms = []
            #    platformCount = 1
                
            #    while True:

            #        def getPlatformData():
                        
            #            print (f"[INFO]  Platform {platformCount} Vendor and Product attribute gathering...")
            #            vendorAttributeList = []
            #            productAttributeList = []
            #            while True:
            #                vendorAttributeInput = input("Enter a vendor name (or 'product' when complete):  ")
            #                if vendorAttributeInput == 'product':
            #                    break
            #                vendorAttributeList.append(vendorAttributeInput)

            #            while True:
            #                productAttributeInput = input(f"Enter a product name (or 'done' to complete Platform {platformCount}):  ")
            #                if productAttributeInput == 'done':
            #                    break
            #                productAttributeList.append(productAttributeInput)
                        
            #           allPlatforms.append([vendorAttributeList, productAttributeList])
            #            print (f"Platform {platformCount} Data:  \n {vendorAttributeList} \n {productAttributeList}")

            #        # Start by getting the first platform attributes              
            #        getPlatformData()
            #        platformCount = (platformCount + 1) 
            #        # Offer ability to continue or execute search (scaling concerns due to API limitations)
            #        userDecision = input("Add another platform to search? (y/n)")
            #        if userDecision == 'n':
            #            break      

                # TODO process the list of lists and output to existing processes for ease of use
                #userCPESearchHtml = processData.userCPESearchData(allPlatforms)

                # Put all the html together into a main console view
                #allConsoleHTML = generateHTML.buildHTMLPage(userCPESearchHtml)
            
                # Create html file for CVE, write to it,
                #sub_directory = Path(f"{os.getcwd()}{os.sep}analysis_tool_files")
                #sub_directory.mkdir(parents=True, exist_ok=True)
                #filename = (targetCve + ".html")
                #filepath = sub_directory / filename
                #with filepath.open("w", encoding="utf-8") as fd:
                #    fd.write(allConsoleHTML)
                # Open html file in a new browser tab for viewing. Comment out for testing needs
                #webbrowser.open_new_tab(f"file:///{filepath}") 
        # Enrichment Mode runs both the CVE List CPE Suggester and the VDB Intel Dashboard
        case "2":
            print(f"[INFO]  {TOOLNAME} {VERSION} built from repo {GIT_REPO} at commit {GIT_COMMIT}")
            print ("[INFO]  Enrichment Assistance Mode Selected!")
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
                #  
                ## Added sorting of cpeQueryResults to ensure that the most relevant CPEs are presented first 
                ## Version checks are not occurring as desired, need to revisit analyzeBaseStrings function
                # TODO Add support for cpes array content on CVE records, mirror existing approach
                # TODO Add support for cpeApplicability content on CVE and NVD records, mirror existing approach
                primaryDataframe = processData.suggestCPEData(nvdAPIKey, primaryDataframe, 1)
                           
                # Do a rough convert of the dataframe to html for debug display
                primaryDataframe = generateHTML.update_cpeQueryHTML_column(primaryDataframe)
                
                primaryDataframe = primaryDataframe.drop('dataSource', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('sourceID', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('sourceRole', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('platformFormatType', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('hasCPEArray', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('rawPlatformData', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('cpeBaseStrings', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('cpeVersionChecks', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('rawCPEsQueryData', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('sortedCPEsQueryData', axis=1, errors='ignore')
                primaryDataframe = primaryDataframe.drop('platformStatistics', axis=1, errors='ignore')
                
                affectedHtml2 = primaryDataframe.to_html(classes='table table-stripped', escape=False)

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
            print(f"[INFO]  {TOOLNAME} {VERSION} built from repo {GIT_REPO} at commit {GIT_COMMIT}")
            print ("[INFO]  Test Mode Selected!")
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
                        "CVE-2023-5541"     # CollectionURL + PackageName Combo 
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
                    #  
                    ## Added sorting of cpeQueryResults to ensure that the most relevant CPEs are presented first 
                    ## Version checks are not occurring as desired, need to revisit analyzeBaseStrings function
                    # TODO Add support for cpes array content on CVE records, mirror existing approach
                    # TODO Add support for cpeApplicability content on CVE and NVD records, mirror existing approach
                    primaryDataframe = processData.suggestCPEData(nvdAPIKey, primaryDataframe, 1)

                    # Consolidate the useful data from query results and processing to reduce noise
                    

                    # Do a rough convert of the dataframe to html for debug display
                    # Generate HTML for the culledcpeQueryDataDataset to keep us sane
                    primaryDataframe = generateHTML.update_cpeQueryHTML_column(primaryDataframe)
                    # TODO Enhance this process to also parse through the nested field data for cleaner display
                    primaryDataframe = primaryDataframe.drop('dataSource', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('sourceID', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('sourceRole', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('platformFormatType', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('hasCPEArray', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('rawPlatformData', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('cpeBaseStrings', axis=1, errors='ignore')
                    primaryDataframe = primaryDataframe.drop('cpeVersionChecks', axis=1, errors='ignore')


                    affectedHtml2 = primaryDataframe.to_html()
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

                
                print("[INFO] Smoke tests completed... Check browser tabs!")
        
        # General examples for unique cases to handle help identifying regressions, should create real test cases and example files for known needs.
            runCVESmokeTests() 
        case _:
            print("[FAULT] Invalid choice, exiting")
            exit()
    
setOperationMode(input("Select Mode: \n 1 --> CPE Search Mode \n 2 --> Enrichment Assistance Mode \n"))

