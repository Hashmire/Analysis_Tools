/**
 * Custom CPE Builder functionality
 * Allows users to create custom CPE base strings when automatic suggestions fail
 */

/**
 * Patch the CPE JSON processing function to handle custom CPEs
 */
function patchCpeJsonProcessing() {
    if (window.cpeJsonProcessingPatched) return;
    
    console.log("Patching processVersionDataToCpeMatches to handle custom CPEs");
    
    // Patch processVersionDataToCpeMatches
    if (typeof processVersionDataToCpeMatches === 'function') {
        window.originalProcessVersionDataToCpeMatches = processVersionDataToCpeMatches;
        
        window.processVersionDataToCpeMatches = function(cpeBase, rawPlatformData) {
            // Check if this is a custom CPE
            if (window.customCPEHandlers && window.customCPEHandlers.has(cpeBase)) {
                console.log(`Using custom handler for CPE: ${cpeBase}`);
                
                // Check for missing rawPlatformData
                if (!rawPlatformData) {
                    console.error(`CRITICAL: No rawPlatformData available for custom CPE ${cpeBase}. This may cause issues in JSON generation.`);
                }
                
                const handler = window.customCPEHandlers.get(cpeBase);
                return [handler.createMatch()];
            }
            
            // Use the original function for standard CPEs
            return window.originalProcessVersionDataToCpeMatches(cpeBase, rawPlatformData);
        };
    } else {
        console.error("CRITICAL: processVersionDataToCpeMatches function not found, cannot patch for custom CPEs");
    }
    
    // CRITICAL FIX: Ensure we have a global consolidatedJsons map
    if (typeof window.consolidatedJsons === 'undefined') {
        window.consolidatedJsons = consolidatedJsons || new Map();
    }
    
    // Patch updateConsolidatedJson to use both global tableSelections and consolidatedJsons
    if (typeof updateConsolidatedJson === 'function') {
        window.originalUpdateConsolidatedJson = updateConsolidatedJson;
        
        window.updateConsolidatedJson = function(tableId) {
            try {
                // Use GLOBAL tableSelections instead of local one
                const selectedRows = window.tableSelections.get(tableId);
                
                console.log(`Using global tableSelections for ${tableId} with ${selectedRows ? selectedRows.size : 0} entries`);
                
                if (!selectedRows || selectedRows.size === 0) {
                    console.debug(`No rows selected for table ${tableId}`);
                    
                    // CRITICAL: Update BOTH local and global consolidatedJsons
                    window.consolidatedJsons.set(tableId, null);
                    if (typeof consolidatedJsons !== 'undefined') {
                        consolidatedJsons.set(tableId, null);
                    }
                    
                    // Find the consolidated JSON button
                    const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
                    
                    // Update button
                    if (showButton) {
                        showButton.disabled = true;
                        showButton.textContent = `Show Consolidated JSON (0 selected)`;
                    }
                    
                    // Update JSON display if it's visible
                    updateJsonDisplayIfVisible(tableId);
                    
                    return;
                }
                
                // Extract the table index from the table ID
                const tableIndex = tableId.split('_')[1];
                
                // Extract metadata and raw platform data from the row data table
                const extractedData = extractDataFromTable(tableIndex);
                
                // Process the JSON based on the source
                const json = processJsonBasedOnSource(
                    selectedRows, 
                    extractedData.rawPlatformData, 
                    extractedData.metadata
                );
                
                // CRITICAL: Store the consolidated JSON in BOTH maps
                window.consolidatedJsons.set(tableId, json);
                if (typeof consolidatedJsons !== 'undefined') {
                    consolidatedJsons.set(tableId, json);
                }
                
                console.debug(`Updated consolidated JSON for table ${tableId}`, json);
                
                // Find the consolidated JSON button
                const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
                
                // Update button with selection information
                if (showButton) {
                    const statsStr = getStatisticsString(json, selectedRows.size);
                    
                    // Check if the display is currently visible
                    const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
                    const isVisible = display && !display.classList.contains('collapsed');
                    
                    // Update button text
                    showButton.textContent = isVisible ? 
                        `Hide Consolidated JSON (${statsStr})` : 
                        `Show Consolidated JSON (${statsStr})`;
                    
                    // Update button state
                    showButton.disabled = false;
                    
                    // Update button styling based on display visibility
                    if (isVisible) {
                        showButton.classList.remove('btn-primary');
                        showButton.classList.add('btn-success');
                    } else {
                        showButton.classList.remove('btn-success');
                        showButton.classList.add('btn-primary');
                    }
                }
                
                // Always update the JSON display if it's visible
                updateJsonDisplayIfVisible(tableId);
                
                // Also update the "Export All" button and configurations display
                if (typeof updateExportAllButton === 'function') {
                    updateExportAllButton();
                }
                
                if (typeof updateAllConfigurationsDisplay === 'function') {
                    updateAllConfigurationsDisplay();
                }
                
                return true;
            } catch(e) {
                console.error(`Error updating consolidated JSON for table ${tableId}:`, e);
                return window.originalUpdateConsolidatedJson(tableId);
            }
        };
        
        console.log("Patched updateConsolidatedJson to use global tableSelections");
    }
    
    // CRITICAL FIX: Patch updateJsonDisplayIfVisible to use window.consolidatedJsons
    if (typeof updateJsonDisplayIfVisible === 'function') {
        window.originalUpdateJsonDisplayIfVisible = updateJsonDisplayIfVisible;
        
        window.updateJsonDisplayIfVisible = function(tableId) {
            try {
                const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
                const content = document.getElementById(`consolidatedJsonContent_${tableId}`);
                
                // Use class check instead of style.display
                if (display && content && !display.classList.contains('collapsed')) {
                    // Get the consolidated JSON from GLOBAL map
                    const selectedRows = window.tableSelections.get(tableId);
                    const selectionCount = selectedRows ? selectedRows.size : 0;
                    
                    // Debug log which json source we're using
                    console.log(`Updating JSON display for ${tableId}, selections: ${selectionCount}`);
                    
                    if (!selectedRows || selectedRows.size === 0) {
                        content.textContent = 'No rows selected';
                        return;
                    }
                    
                    // Get the consolidated JSON from GLOBAL map
                    const json = window.consolidatedJsons.get(tableId);
                    console.log(`Found JSON for display:`, json);
                    
                    if (json) {
                        // Format the JSON with indentation for readability
                        content.textContent = JSON.stringify(json, null, 2);
                    } else {
                        content.textContent = 'No JSON available. Please select CPE rows.';
                    }
                    
                    // Also update the button text
                    updateJsonDisplay(tableId, json, selectionCount);
                }
            } catch(e) {
                console.error(`Error updating JSON display for table ${tableId}:`, e);
                return window.originalUpdateJsonDisplayIfVisible(tableId);
            }
        };
        
        console.log("Patched updateJsonDisplayIfVisible to use global consolidatedJsons");
    }
    
    // CRITICAL FIX: Ensure display elements exist
    function ensureJsonDisplayElementsExist(tableId) {
        const jsonContainer = document.getElementById(`jsonContainer_${tableId}`);
        if (!jsonContainer) {
            console.error(`JSON container for ${tableId} not found`);
            return;
        }
        
        const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
        if (!display) {
            console.error(`JSON display for ${tableId} not found`);
            return;
        }
        
        // Make sure the content element exists
        let content = document.getElementById(`consolidatedJsonContent_${tableId}`);
        if (!content) {
            console.log(`Creating missing consolidatedJsonContent for ${tableId}`);
            content = document.createElement('pre');
            content.id = `consolidatedJsonContent_${tableId}`;
            content.className = 'json-content';
            display.appendChild(content);
        }
    }
    
    // Add function to ensure all display elements are properly set up
    document.querySelectorAll('table[id^="matchesTable"]').forEach(table => {
        const tableId = table.id;
        setTimeout(() => ensureJsonDisplayElementsExist(tableId), 100);
    });
    
    // Patch toggleConsolidatedJson to show/hide JSON
    if (typeof toggleConsolidatedJson === 'function') {
        window.originalToggleConsolidatedJson = toggleConsolidatedJson;
        
        window.toggleConsolidatedJson = function(tableId) {
            try {
                const display = document.getElementById(`consolidatedJsonDisplay_${tableId}`);
                const showButton = document.getElementById(`showConsolidatedJson_${tableId}`);
                
                if (!display || !showButton) return;
                
                // Make sure content element exists
                ensureJsonDisplayElementsExist(tableId);
                
                // Get selections from GLOBAL map
                const selectedRows = window.tableSelections.get(tableId);
                const selectionCount = selectedRows ? selectedRows.size : 0;
                
                if (selectionCount > 0) {
                    // Toggle collapsed class
                    display.classList.toggle('collapsed');
                    const isCollapsed = display.classList.contains('collapsed');
                    
                    // Get the JSON from GLOBAL map
                    const json = window.consolidatedJsons.get(tableId);
                    const statsStr = getStatisticsString(json, selectionCount);
                    
                    // Update button text and style
                    showButton.textContent = isCollapsed ? 
                        `Show Consolidated JSON (${statsStr})` : 
                        `Hide Consolidated JSON (${statsStr})`;
                        
                    if (isCollapsed) {
                        showButton.classList.remove('btn-success');
                        showButton.classList.add('btn-primary');
                    } else {
                        showButton.classList.remove('btn-primary');
                        showButton.classList.add('btn-success');
                        
                        // Update the content when showing
                        updateJsonDisplayIfVisible(tableId);
                    }
                } else {
                    // No selections case
                    display.classList.add('collapsed');
                    showButton.textContent = `Show Consolidated JSON (0 selected)`;
                    showButton.classList.remove('btn-success');
                    showButton.classList.add('btn-primary');
                    showButton.disabled = true;
                }
            } catch(e) {
                console.error(`Error in toggleConsolidatedJson for ${tableId}:`, e);
                return window.originalToggleConsolidatedJson(tableId);
            }
        };
        
        console.log("Patched toggleConsolidatedJson for better display handling");
    }
    
    console.log("Custom CPE Builder initialized successfully");
    window.cpeJsonProcessingPatched = true;
}

/**
 * Initialize the Custom CPE Builder UI and functionality
 */
function initializeCustomCPEBuilder() {
    console.log("Initializing Custom CPE Builder...");
    
    // Set up customCPEHandlers if not already defined
    if (typeof window.customCPEHandlers === 'undefined') {
        window.customCPEHandlers = new Map();
    }
    
    // Apply patching for CPE JSON processing
    patchCpeJsonProcessing();
    
    // Find all customCPEBuilder divs and populate them
    const builderContainers = document.querySelectorAll('.customCPEBuilder');
    console.log(`Found ${builderContainers.length} custom CPE builder containers`);
    
    builderContainers.forEach((container, i) => {
        console.log(`Processing container ${i+1}:`, container.id);
        // Only initialize containers that haven't been set up yet
        if (!container.hasAttribute('data-initialized')) {
            console.log(`Populating container ${container.id}`);
            populateCustomCPEBuilder(container);
            container.setAttribute('data-initialized', 'true');
        } else {
            console.log(`Container ${container.id} already initialized`);
        }
    });

    // Set up event delegation for the document to handle future interactions
    document.removeEventListener('input', handleCustomCPEInputEvents); // Remove any existing handlers
    document.removeEventListener('change', handleCustomCPEInputEvents);
    document.removeEventListener('click', handleCustomCPEButtonClicks);
    
    document.addEventListener('input', handleCustomCPEInputEvents);
    document.addEventListener('change', handleCustomCPEInputEvents);
    document.addEventListener('click', handleCustomCPEButtonClicks);
    
    console.log("Custom CPE Builder initialization complete");
}

/**
 * Populate a custom CPE builder container with the necessary form elements
 * @param {HTMLElement} container - The container element to populate
 */
function populateCustomCPEBuilder(container) {
    // Extract index from container ID
    const containerId = container.id;
    const match = containerId.match(/customCPEBuilder-content-(\d+)/);
    
    if (!match || !match[1]) {
        console.error("Could not extract index from container ID:", containerId);
        return;
    }
    
    const index = match[1];
    
    // Create the form HTML
    const formHTML = `
        <div class="row mb-3">
            <div class="col-md-4">
                <label for="custom-cpe-part-${index}" class="form-label">Part</label>
                <select id="custom-cpe-part-${index}" class="form-select custom-cpe-part">
                    <option value="a">Application (a)</option>
                    <option value="o">Operating System (o)</option>
                    <option value="h">Hardware (h)</option>
                </select>
            </div>
            <div class="col-md-8">
                <label for="custom-cpe-vendor-${index}" class="form-label">Vendor</label>
                <input type="text" class="form-control custom-cpe-vendor" id="custom-cpe-vendor-${index}" placeholder="Enter vendor name">
            </div>
        </div>
        <div class="row mb-3">
            <div class="col-md-12">
                <label for="custom-cpe-product-${index}" class="form-label">Product</label>
                <input type="text" class="form-control custom-cpe-product" id="custom-cpe-product-${index}" placeholder="Enter product name">
            </div>
        </div>
        <div class="row mb-3">
            <div class="col-md-4">
                <label for="custom-cpe-target-sw-${index}" class="form-label">Target Software</label>
                <input type="text" class="form-control custom-cpe-target-sw" id="custom-cpe-target-sw-${index}" placeholder="*">
            </div>
            <div class="col-md-4">
                <label for="custom-cpe-target-hw-${index}" class="form-label">Target Hardware</label>
                <input type="text" class="form-control custom-cpe-target-hw" id="custom-cpe-target-hw-${index}" placeholder="*">
            </div>
            <div class="col-md-4">
                <label for="custom-cpe-other-${index}" class="form-label">Other</label>
                <input type="text" class="form-control custom-cpe-other" id="custom-cpe-other-${index}" placeholder="*">
            </div>
        </div>
        <div class="row mb-3">
            <div class="col-md-12">
                <label for="custom-cpe-preview-${index}" class="form-label">CPE Base String Preview</label>
                <div class="input-group">
                    <input type="text" class="form-control custom-cpe-preview" id="custom-cpe-preview-${index}" readonly>
                    <button class="btn btn-outline-secondary copy-cpe-btn" type="button" data-index="${index}">
                        <i class="bi bi-clipboard"></i> Copy
                    </button>
                </div>
                <div class="form-text">This is the CPE base string in the standard CPE 2.3 format</div>
            </div>
        </div>
        <div class="row mt-3">
            <div class="col-12 d-grid">
                <button type="button" class="btn btn-primary apply-custom-cpe-btn" data-index="${index}">
                    Apply Custom CPE
                </button>
            </div>
        </div>
    `;
    
    // Set the HTML content
    container.innerHTML = formHTML;
    
    // Initialize the preview with default values
    updateCustomCPEPreview(index);
}

/**
 * Handle input and change events for custom CPE inputs
 * @param {Event} event - The input or change event
 */
function handleCustomCPEInputEvents(event) {
    // Check if the event originated from one of our input fields
    if (event.target.classList.contains('custom-cpe-part') ||
        event.target.classList.contains('custom-cpe-vendor') ||
        event.target.classList.contains('custom-cpe-product') ||
        event.target.classList.contains('custom-cpe-target-sw') ||
        event.target.classList.contains('custom-cpe-target-hw') ||
        event.target.classList.contains('custom-cpe-other')) {
        
        const idParts = event.target.id.split('-');
        const index = idParts[idParts.length - 1];
        updateCustomCPEPreview(index);
    }
}

/**
 * Handle button clicks for custom CPE buttons
 * @param {Event} event - The click event
 */
function handleCustomCPEButtonClicks(event) {
    // Copy button
    if (event.target.closest('.copy-cpe-btn')) {
        const button = event.target.closest('.copy-cpe-btn');
        const index = button.getAttribute('data-index');
        copyCustomCPEToClipboard(index);
    }
    
    // Apply button
    if (event.target.closest('.apply-custom-cpe-btn')) {
        const button = event.target.closest('.apply-custom-cpe-btn');
        const index = button.getAttribute('data-index');
        applyCustomCPE(index);
    }
}

/**
 * Update the CPE base string preview based on the current form values
 * @param {string} index - The index of the form
 */
function updateCustomCPEPreview(index) {
    // Get form values
    const part = document.getElementById(`custom-cpe-part-${index}`).value;
    const vendor = document.getElementById(`custom-cpe-vendor-${index}`).value;
    const product = document.getElementById(`custom-cpe-product-${index}`).value;
    const targetSw = document.getElementById(`custom-cpe-target-sw-${index}`).value || '*';
    const targetHw = document.getElementById(`custom-cpe-target-hw-${index}`).value || '*';
    const other = document.getElementById(`custom-cpe-other-${index}`).value || '*';
    
    // Format values according to CPE 2.3 rules
    const formattedVendor = formatCPEComponent(vendor);
    const formattedProduct = formatCPEComponent(product);
    const formattedTargetSw = formatCPEComponent(targetSw);
    const formattedTargetHw = formatCPEComponent(targetHw);
    const formattedOther = formatCPEComponent(other);
    
    // Construct CPE base string
    // Format: cpe:2.3:part:vendor:product:*:*:*:*:*:target-sw:target-hw:other
    const cpeBaseString = `cpe:2.3:${part}:${formattedVendor}:${formattedProduct}:*:*:*:*:*:${formattedTargetSw}:${formattedTargetHw}:${formattedOther}`;
    
    // Update preview
    const previewElement = document.getElementById(`custom-cpe-preview-${index}`);
    if (previewElement) {
        previewElement.value = cpeBaseString;
    }
    
    // Update apply button state
    const applyButton = document.querySelector(`.apply-custom-cpe-btn[data-index="${index}"]`);
    if (applyButton) {
        // Only enable if vendor and product are provided
        applyButton.disabled = !formattedVendor || !formattedProduct;
    }
}

/**
 * Format a CPE component according to CPE 2.3 specification
 * @param {string} value - The raw input value
 * @returns {string} - The formatted CPE component
 */
function formatCPEComponent(value) {
    if (!value) return '*';
    
    // Convert to lowercase
    let formatted = value.toLowerCase();
    
    // Replace spaces with underscores
    formatted = formatted.replace(/\s+/g, '_');
    
    // Replace special characters
    formatted = formatted.replace(/[\/\\\(\)\[\]\{\}\!\@\#\$\%\^\&\=\+\|\;\:\"\'\<\>\,\`\~]/g, '_');
    
    // Remove any consecutive underscores
    formatted = formatted.replace(/_{2,}/g, '_');
    
    // Remove leading and trailing underscores
    formatted = formatted.replace(/^_+|_+$/g, '');
    
    return formatted || '*';
}

/**
 * Copy the custom CPE base string to the clipboard
 * @param {string} index - The index of the form
 */
function copyCustomCPEToClipboard(index) {
    const previewElement = document.getElementById(`custom-cpe-preview-${index}`);
    if (previewElement) {
        previewElement.select();
        document.execCommand('copy');
        
        // Show brief visual feedback
        const copyButton = document.querySelector(`.copy-cpe-btn[data-index="${index}"]`);
        const originalHTML = copyButton.innerHTML;
        copyButton.innerHTML = '<i class="bi bi-check"></i> Copied!';
        setTimeout(() => {
            copyButton.innerHTML = originalHTML;
        }, 1500);
    }
}

/**
 * Apply the custom CPE to the selections and matchesTable
 * @param {string} index - The index of the form
 */
function applyCustomCPE(index) {
    const previewElement = document.getElementById(`custom-cpe-preview-${index}`);
    if (!previewElement) return;
    
    const cpeBaseString = previewElement.value;
    
    // Get the tableId
    const tableId = `matchesTable_${index}`;
    
    console.log(`Applying custom CPE for table ${tableId}: ${cpeBaseString}`);
    
    // Normalize CPE string if the function is available
    const normalizedCpeBase = typeof normalizeCpeString === 'function' ? 
        normalizeCpeString(cpeBaseString) : cpeBaseString;
    
    // Register custom CPE handler
    registerCustomCpeHandler(normalizedCpeBase, tableId);
    
    // Create the custom row at the top of the table
    const customRow = addCustomCPERowToTable(tableId, cpeBaseString);
    if (!customRow) {
        console.error("Failed to create custom CPE row");
        return;
    }
    
    // Add to tableSelections directly
    if (!window.tableSelections.has(tableId)) {
        window.tableSelections.set(tableId, new Set());
    }
    
    // CRITICAL: Add the CPE to the selections and add debugging
    window.tableSelections.get(tableId).add(normalizedCpeBase);
    
    // Debug logging to check selections
    console.log(`TRACE: After adding custom CPE to tableSelections`);
    console.log(`TRACE: tableSelections has tableId? ${window.tableSelections.has(tableId)}`);
    console.log(`TRACE: tableSelections.get(tableId) type: ${typeof window.tableSelections.get(tableId)}`);
    console.log(`TRACE: tableSelections.get(tableId) is Set? ${window.tableSelections.get(tableId) instanceof Set}`);
    console.log(`TRACE: tableSelections.get(tableId).size = ${window.tableSelections.get(tableId).size}`);
    console.log(`TRACE: tableSelections.get(tableId) has our CPE? ${window.tableSelections.get(tableId).has(normalizedCpeBase)}`);
    console.log(`TRACE: Current selections for ${tableId}:`, Array.from(window.tableSelections.get(tableId)));
    
    // Make sure the row is marked as selected
    customRow.classList.add('table-active');
    
    try {
        if (typeof updateConsolidatedJson === 'function') {
            console.log(`Calling updateConsolidatedJson for ${tableId}`);
            updateConsolidatedJson(tableId);
            
            // Log if JSON wasn't created
            setTimeout(() => {
                const json = window.consolidatedJsons.get(tableId);
                if (!json) {
                    console.warn(`JSON not created for ${tableId}`);
                    debugCustomCpeJson(tableId, normalizedCpeBase);
                }
            }, 100);
        } else {
            console.error("updateConsolidatedJson function not found");
        }
    } catch (e) {
        console.error("Error calling updateConsolidatedJson:", e);
    }
    
    // Update Export All button
    if (typeof updateExportAllButton === 'function') {
        updateExportAllButton();
    }
    
    // Update all configurations display
    if (typeof updateAllConfigurationsDisplay === 'function') {
        updateAllConfigurationsDisplay();
    }
    
    // Collapse the Custom CPE Builder section
    const collapseElement = document.getElementById(`customCPEBuilderCollapse_${index}`);
    if (collapseElement && typeof bootstrap !== 'undefined' && bootstrap.Collapse) {
        const bsCollapse = new bootstrap.Collapse(collapseElement);
        bsCollapse.hide();
    }
    console.log(`Attempted to apply custom CPE: ${cpeBaseString}`);
}

/**
 * Register a handler for custom CPEs
 * @param {string} cpeBaseString - The normalized CPE base string
 */
function registerCustomCpeHandler(cpeBaseString, tableId) {
    // Get the table index from tableId
    const tableIndex = tableId.split('_')[1];
    
    // Get rawPlatformData for the correct table
    const extractedData = extractDataFromTable(tableIndex);
    const rawPlatformData = extractedData.rawPlatformData;
    
    window.customCPEHandlers.set(cpeBaseString, {
        createMatch: function() {
            // IMPROVEMENT: Create a match object that uses version information
            if (rawPlatformData && rawPlatformData.versions && rawPlatformData.versions.length > 0) {
                // Use the same match creation logic as regular CPEs
                const versionInfo = rawPlatformData.versions[0]; // Use first version as an example
                return createCpeMatchFromVersionInfo(cpeBaseString, versionInfo, true);
            } else {
                // Fallback to basic match if no version info
                return window.createCpeMatchObject(cpeBaseString);
            }
        }
    });
    
    console.log(`Registered custom CPE handler for ${cpeBaseString}`);
}

/**
 * Add a new row to the matchesTable for a custom CPE
 * @param {string} tableId - The ID of the table
 * @param {string} cpeBaseString - The CPE base string
 * @returns {Element|null} - The created row element
 */
function addCustomCPERowToTable(tableId, cpeBaseString) {
    const table = document.getElementById(tableId);
    if (!table) {
        console.error(`Table ${tableId} not found`);
        return null;
    }
    
    const tbody = table.querySelector('tbody');
    if (!tbody) {
        console.error(`Table body not found in ${tableId}`);
        return null;
    }
    
    // Check if row already exists for this CPE
    const existingRows = table.querySelectorAll('tr.cpe-row');
    for (const row of existingRows) {
        if (row.getAttribute('data-cpe-base') === cpeBaseString) {
            console.log(`Row already exists for CPE ${cpeBaseString}`);
            return row; // Return the existing row
        }
    }
    
    console.log(`Adding new row for custom CPE: ${cpeBaseString}`);
    
    // Create the row element
    const row = document.createElement('tr');
    row.className = 'cpe-row table-active'; // Add table-active to visually mark as selected
    row.setAttribute('data-cpe-base', cpeBaseString); // Match the exact attribute used by regular CPE rows
    
    // First cell - CPE string
    const cpeCell = document.createElement('td');
    cpeCell.className = 'text-break';
    cpeCell.textContent = cpeBaseString;
    
    // Extract parts from CPE string for display
    const cpeParts = cpeBaseString.split(':');
    const part = cpeParts[2] || '*';
    const vendor = cpeParts[3] || '*';
    const product = cpeParts[4] || '*';
    
    // Second cell - Match details
    const detailsCell = document.createElement('td');
    detailsCell.innerHTML = `
        <div class="d-flex flex-wrap gap-1 align-items-center">
            <span class="badge rounded-pill bg-warning" title="Custom CPE created manually">Custom CPE</span>
            <div class="badge bg-primary d-inline-flex align-items-center">
                ${vendor}:${product}
            </div>
        </div>
    `;
    
    // Add cells to row
    row.appendChild(cpeCell);
    row.appendChild(detailsCell);
    
    // Add click event handler identical to regular rows to ensure consistent behavior
    row.addEventListener('click', function(event) {
        // Toggle selection
        let cpeBase = row.getAttribute('data-cpe-base');
        cpeBase = normalizeCpeString(cpeBase);
        
        const selections = window.tableSelections.get(tableId);
        
        if (selections.has(cpeBase)) {
            selections.delete(cpeBase);
            row.classList.remove('table-active');
        } else {
            selections.add(cpeBase);
            row.classList.add('table-active');
        }
        
        // Update consolidated JSON
        if (typeof updateConsolidatedJson === 'function') {
            updateConsolidatedJson(tableId);
        }
        
        // Update Export All button
        if (typeof updateExportAllButton === 'function') {
            updateExportAllButton();
        }
        
        // Update all configurations display
        if (typeof updateAllConfigurationsDisplay === 'function') {
            updateAllConfigurationsDisplay();
        }
    });
    
    // Add to the TOP of the table instead of the bottom
    if (tbody.firstChild) {
        tbody.insertBefore(row, tbody.firstChild);
    } else {
        tbody.appendChild(row);
    }
    

    
    console.log(`Added custom CPE row to table ${tableId}`);
    return row;
}

// Make functions available globally
window.initializeCustomCPEBuilder = initializeCustomCPEBuilder;
window.updateCustomCPEPreview = updateCustomCPEPreview;
window.applyCustomCPE = applyCustomCPE;

// Enhanced debug helper
function debugCustomCpeJson(tableId, cpeBaseString) {
    const tableIndex = tableId.split('_')[1];
    const rawDataElement = document.getElementById(`rawPlatformData_${tableIndex}`);
    const rawPlatformData = rawDataElement ? JSON.parse(rawDataElement.textContent || '{}') : null;
    
    console.log(`Debug info for custom CPE in ${tableId}:`, {
        cpeString: cpeBaseString,
        handler: window.customCPEHandlers && window.customCPEHandlers.get(cpeBaseString),
        consolidatedJson: window.consolidatedJsons && window.consolidatedJsons.get(tableId),
        selections: window.tableSelections && window.tableSelections.get(tableId) ? 
            Array.from(window.tableSelections.get(tableId)) : [],
        rawPlatformDataExists: !!rawDataElement,
        rawPlatformDataEmpty: rawDataElement && (!rawDataElement.textContent || rawDataElement.textContent === '{}'),
        tableIndex: tableIndex
    });
    
    if (!rawDataElement) {
        console.error(`CRITICAL ERROR: Missing rawPlatformData_${tableIndex} element. This is required for proper JSON generation.`);
    } else if (!rawDataElement.textContent || rawDataElement.textContent === '{}') {
        console.error(`CRITICAL ERROR: rawPlatformData_${tableIndex} exists but is empty. This is required for proper JSON generation.`);
    }
}

// Automatically initialize the Custom CPE Builder when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM loaded, initializing Custom CPE Builder...");
    initializeCustomCPEBuilder();
});