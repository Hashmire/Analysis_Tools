# Import Python dependencies
import pandas as pd
from sys import exit
from build_info import VERSION, TOOLNAME


def convertCPEsQueryDataToHTML(culledcpeQueryDataDataset: pd.DataFrame) -> str:
    
    html = "<table>"
    for key, value in culledcpeQueryDataDataset.items():
        html += f"<tr><td>{key}</td><td>"
        base_strings = value.get('base_strings', {})
        html += "<table>"
        for base_key, base_value in base_strings.items():
            dep_true_count = base_value.get('depTrueCount', 0)
            dep_false_count = base_value.get('depFalseCount', 0)
            versions_found = base_value.get('versionsFound', 0)
            html += f"""
            <tr>
                <td>{base_key}</td>
                <td>
                    <span class="badge badge-warning">depTrueCount: {dep_true_count}</span>
                    <span class="badge badge-primary">depFalseCount: {dep_false_count}</span>
                    <span class="badge badge-success">versionsFound: {versions_found}</span>
                </td>
            </tr>
            """
        html += "</table></td></tr>"
    html += "</table></td></tr>"

    return html.replace('\n', '')

def convertRowDataToHTML(row) -> str:
    has_cpe_array_content = bool(row['hasCPEArray'])

    if row['platformFormatType'] in ['cveAffectsVersionRange', 'cveAffectsVersionSingle']:
        html = f"""
            <table>
                <tr>
                    <td>Data Source</td>
                    <td>{row['dataSource']}</td>
                </tr>
                <tr>
                    <td>Source ID</td>
                    <td>{row['sourceID']}</td>
                </tr>
                <tr>
                    <td>Source Role</td>
                    <td>{row['sourceRole']}</td>
                </tr>
                <tr>
                    <td>Vendor Value</td>
                    <td>{row['rawPlatformData']['vendor']}</td>
                </tr>
                <tr>
                    <td>Product Value</td>
                    <td>{row['rawPlatformData']['product']}</td>
                </tr>
                <tr>       
                    <td>Platform Format Type</td>
                    <td>{row['platformFormatType']}</td>
                </tr>
                <tr>       
                    <td>CPE Array Included</td>
                    <td>{has_cpe_array_content}</td>
                </tr>
                <tr>        
                    <td>Raw Platform Data</td>
                    <td><details><summary>Review rawPlatformData</summary><code>{row['rawPlatformData']}</code></details></td>
                </tr>
            </table>
        """
    else:
        html = f"""
            <table>
                <tr>
                    <td>Data Source</td>
                    <td>{row['dataSource']}</td>
                </tr>
                <tr>
                    <td>Source ID</td>
                    <td>{row['sourceID']}</td>
                </tr>
                <tr>
                    <td>Source Role</td>
                    <td>{row['sourceRole']}</td>
                </tr>
                <tr>       
                    <td>Platform Format Type</td>
                    <td>{row['platformFormatType']}</td>
                </tr>
                <tr>        
                    <td>Raw Platform Data</td>
                    <td><details><summary>Review rawPlatformData</summary><code>{row['rawPlatformData']}</code></details></td>
                </tr>
            </table>
        """
        
    return html.replace('\n', '')


# Update the primaryDataframe with the HTML content for each row
def update_cpeQueryHTML_column(primaryDataframe: pd.DataFrame) -> pd.DataFrame:
    for index, row in primaryDataframe.iterrows():
        
        # Populate the cpeQueryHTML column with HTML content based on the sortedCPEsQueryData column
        sortedCPEsQueryData = row['sortedCPEsQueryData'] 
        html_content = convertCPEsQueryDataToHTML(sortedCPEsQueryData)
        primaryDataframe.at[index, 'cpeQueryHTML'] = html_content

        # Populate the rowDataHTML column with the HTML content based on many columns
        row_html_content = convertRowDataToHTML(row)
        primaryDataframe.at[index, 'rowDataHTML'] = row_html_content

    return primaryDataframe

# Builds a simple html page with Bootstrap 3.4.1 CSS
def buildHTMLPage(affectedHtml, targetCve, vdbIntelHtml = None):
    pageStartHTML = """
                    <!DOCTYPE html> <html lang=\"en\">
                    <head>
                    <!-- Latest compiled and minified CSS -->
                    <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/bootstrap@3.4.1/dist/css/bootstrap.min.css\" integrity=\"sha384-HSMxcRTRxnN+Bdg0JdbxYKrThecOKuH5zCYotlSAcp1+c8xmyTe9GYg1l9a69psu" crossorigin="anonymous">

                    <!-- Optional theme -->
                    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@3.4.1/dist/css/bootstrap-theme.min.css" integrity="sha384-6pzBo3FDv/PJ8r2KRkGHifhEocL+1X2rVCTTkUfGk7/0pbek5mMa1upzvWbrUbOZ" crossorigin="anonymous">

                    <!-- Latest compiled and minified JavaScript -->
                    <script src="https://cdn.jsdelivr.net/npm/bootstrap@3.4.1/dist/js/bootstrap.min.js" integrity="sha384-aJ21OjlMXNL5UyIl/XNwTMqvzeRMZH2w8c5cRVpzpU8Y5bApTppSuUkhZXN0VxHd" crossorigin="anonymous"></script>
                    <style>

                    .cpecriteriamatchestrue {
                        padding: 2px 4px;
                        color: #752bc4;
                        background-color: #0402031a;
                        border-radius: 4px;
                        font-size: 100%;
                    }
                    
                    .cpecriteriamatchesfalse {
                        color: #752bc4;
                        background-color: #0402031a;
                        border-radius: 4px;
                    }
                    
                    .matchesfalsecell{
                        padding-top: 0px;
                        padding-bottom: 0px;
                        font-size: 85%;
                    }
                    
                    .cpecriteriamatched {
                        padding: 2px 4px;
                        font-size: 80%;
                        color: #000;
                        background-color: #0402031a;
                        border-radius: 4px;
                    }
                    
                    .tab {
                    overflow: hidden;
                    border: 1px solid #ccc;
                    background-color: #f1f1f1;
                    }

                    .tab button {
                    background-color: inherit;
                    float: left;
                    border: none;
                    outline: none;
                    cursor: pointer;
                    padding: 14px 16px;
                    transition: 0.3s;
                    }

                    .tab button:hover {
                    background-color: #ddd;
                    }

                    .tab button.active {
                    background-color: #ccc;
                    }

                    .tabcontent {
                    display: none;
                    margin-left: 10px;
                    border: 1px solid #ccc;
                    border-top: none;
                    }

                    </style>
                    </head>
                    <body>
                    """
    pageBodyHeaderHTML =  "<!-- Tool Info Header --><div class=\"header\" style=\"margin-left: 10px;\"><h1>NVD Analysis Intelligence Tool <small>" + TOOLNAME + "  version:  " + VERSION + "</small></h1></div>" 
    pageBodyTabsHTML =  """
                        <!-- Tab links -->
                        <div class="tab">
                        <button class="tablinks" onclick="openCity(event, 'cveListCPESuggester')">CVE List CPE Suggester</button>
                        <button class="tablinks" onclick="openCity(event, 'vdbIntelDashboard')">VDB Intel Dashboard</button>
                        </div>
                        """
    cveIdIndicatorHTML = "<h3 style=\"margin-bottom: 0px; margin-left: 10px;\"><b>" + targetCve + " results</b></h3><hr style=\"margin: 10px; border: 1px solid;\">"
    pageBodyCPESuggesterHTML = ("\n<!-- CVE List CPE Suggester -->\n<div id=\"cveListCPESuggester\" class=\"tabcontent\" style=\"display: block; border-left: 0px;\"><h3>CVE List CPE Suggester</h3>" + affectedHtml + "</div>")
    if vdbIntelHtml == None:
        pageBodyVDBIntelHTML = ("\n<!-- VDB Intel Dashboard -->\n<div id=\"vdbIntelDashboard\" class=\"tabcontent\" style=\"border-left: 0px;\"><h3>VDB Intel Dashboard</h3><p>Basic User Mode does not support VDB Intel Check!</p></div>")
    else:
        pageBodyVDBIntelHTML = ("\n<!-- VDB Intel Dashboard -->\n<div id=\"vdbIntelDashboard\" class=\"tabcontent\" style=\"border-left: 0px;\"><h3>VDB Intel Dashboard</h3>" + vdbIntelHtml + "</div>")
    # Thank you internet for the shortcut, this is copy/pasted and should be reworked to be more customized
    pageBodyJavaScript = """
                    <script>
                    function openCity(evt, cityName) {
                    // Declare all variables
                    var i, tabcontent, tablinks;

                    // Get all elements with class="tabcontent" and hide them
                    tabcontent = document.getElementsByClassName("tabcontent");
                    for (i = 0; i < tabcontent.length; i++) {
                        tabcontent[i].style.display = "none";
                    }

                    // Get all elements with class="tablinks" and remove the class "active"
                    tablinks = document.getElementsByClassName("tablinks");
                    for (i = 0; i < tablinks.length; i++) {
                        tablinks[i].className = tablinks[i].className.replace(" active", "");
                    }

                    // Show the current tab, and add an "active" class to the button that opened the tab
                    document.getElementById(cityName).style.display = "block";
                    evt.currentTarget.className += " active";
                    }
                    </script>
                    """ 
    pageEndHTML =   "</body></html>"
    fullHtml = (pageStartHTML + pageBodyHeaderHTML + pageBodyTabsHTML + cveIdIndicatorHTML + pageBodyCPESuggesterHTML + pageBodyVDBIntelHTML + pageBodyJavaScript + pageEndHTML)
    
    return (fullHtml)
########################