# Import Python dependencies
import pandas as pd
from sys import exit
from build_info import VERSION, TOOLNAME

# Import Analysis Tool 
import processData


def convertRowDataToHTML(row, nvdSourceData: pd.DataFrame) -> str:
    has_cpe_array_content = bool(row.get('hasCPEArray', False))

    html = "<table class=\"table table-hover\">"
    
    # Define the keys and their labels, ensuring rawPlatformData is last
    keys_and_labels = [
        ('dataSource', 'Data Source'),
        ('sourceID', 'Source ID'),
        ('sourceRole', 'Source Role'),
        ('platformFormatType', 'Platform Format Type'),
        ('rawPlatformData', 'Raw Platform Data')
    ]
    
    for key, label in keys_and_labels:
        if key in row:
            value = row[key]
            if key == 'rawPlatformData':
                if 'vendor' in value:
                    html += f"""
                    <tr>
                        <td>Vendor Value</td>
                        <td>{value['vendor']}</td>
                    </tr>
                    """
                if 'product' in value:
                    html += f"""
                    <tr>
                        <td>Product Value</td>
                        <td>{value['product']}</td>
                    </tr>
                    """
                if 'repo' in value:
                    html += f"""
                    <tr>
                        <td>Repo</td>
                        <td>{value['repo']}</td>
                    </tr>
                    """
                if 'collectionUrl' in value:
                    html += f"""
                    <tr>
                        <td>Collection URL</td>
                        <td>{value['collectionUrl']}</td>
                    </tr>
                    """
                if 'packageName' in value:
                    html += f"""
                    <tr>
                        <td>Package Name</td>
                        <td>{value['packageName']}</td>
                    </tr>
                    """
                if 'platforms' in value:
                    html += f"""
                    <tr>
                        <td>Platforms</td>
                        <td>{value['platforms']}</td>
                    </tr>
                    """
                if 'modules' in value:
                    html += f"""
                    <tr>
                        <td>Modules</td>
                        <td>{value['modules']}</td>
                    </tr>
                    """
                if 'programFiles' in value:
                    html += f"""
                    <tr>
                        <td>Program Files</td>
                        <td>{value['programFiles']}</td>
                    </tr>
                    """
                if 'programRoutines' in value:
                    html += f"""
                    <tr>
                        <td>Program Routines</td>
                        <td>{value['programRoutines']}</td>
                    </tr>
                    """
                html += f"""
                <tr>
                    <td>{label}</td>
                    <td><details><summary>Review rawPlatformData</summary><code>{value}</code></details></td>
                </tr>
                """
            elif key == 'platformFormatType':
                if has_cpe_array_content:
                    tooltip_content = "CPE Array Included"
                    value += f" <span title=\"{tooltip_content}\">  &#10003;</span>"
                html += f"""
                <tr>
                    <td>{label}</td>
                    <td>{value}</td>
                </tr>
                """
            elif key == 'sourceID':
                source_info = processData.getNVDSourceDataByUUID(value, nvdSourceData)
                if source_info:
                    name = source_info.get('name', 'N/A')
                    contact_email = source_info.get('contactEmail', 'N/A')
                    source_identifiers = source_info.get('sourceIdentifiers', [])
                    tooltip_content = f"Contact Email: {contact_email} &#013;Source Identifiers: {', '.join(source_identifiers)}"
                    value = f"<span title=\"{tooltip_content}\">{name}</span>"
                html += f"""
                <tr>
                    <td>{label}</td>
                    <td>{value}</td>
                </tr>
                """
            else:
                html += f"""
                <tr>
                    <td>{label}</td>
                    <td>{value}</td>
                </tr>
                """
    
    html += "</table>"
        
    return html.replace('\n', '')

def convertCPEsQueryDataToHTML(sortedCPEsQueryData: dict) -> str:
    html = """
    <table class="table table-hover">
    """
    
    for base_key, base_value in sortedCPEsQueryData.items():
        dep_true_count = base_value.get('depTrueCount', 0)
        dep_false_count = base_value.get('depFalseCount', 0)
        versions_found = base_value.get('versionsFound', 0)
        search_count = base_value.get('searchCount', 0)
        versions_found_content = base_value.get('versionsFoundContent', [])
        
        # Create tooltip content from versionsFoundContent
        tooltip_content = "&#10;".join(
            "&#10;".join(f"{k}: {v}" for k, v in version.items())
            for version in versions_found_content
        )
        
        # Check for the existence of ('search' + recorded_keys_str) keys
        search_keys_badges = ""
        for key in base_value.keys():
            if key.startswith('searchSource'):
                search_keys_badges += f"<span class='badge badge-secondary' title='{base_value[key]}'>{key}</span> "
        
        html += f"""
        <tr">
            <td>{base_key}</td>
            <td>
                <span class="badge badge-warning">depTrueCount: {dep_true_count}</span>
                <span class="badge badge-primary">depFalseCount: {dep_false_count}</span>
                <span class="badge badge-success" title="{tooltip_content}">versionsFound: {versions_found}</span>
                <span class="badge badge-info">searchCount: {search_count}</span>
                {search_keys_badges}
            </td>
        </tr>
        """

    html += """
    </table>
    """

    return html.replace('\n', '')

# Update the primaryDataframe with the HTML content for each row
def update_cpeQueryHTML_column(primaryDataframe, nvdSourceData) -> pd.DataFrame:
    for index, row in primaryDataframe.iterrows():
        
        # Populate the cpeQueryHTML column with HTML content based on the sortedCPEsQueryData column
        sortedCPEsQueryData = row['sortedCPEsQueryData'] 
        html_content = convertCPEsQueryDataToHTML(sortedCPEsQueryData)
        primaryDataframe.at[index, 'cpeQueryHTML'] = html_content

        # Populate the rowDataHTML column with the HTML content based on many columns
        row_html_content = convertRowDataToHTML(row, nvdSourceData)
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