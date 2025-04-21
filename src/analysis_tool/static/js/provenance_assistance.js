/**
 * Handle description buttons in provenance assistance sections
 */

/**
 * Get CVE description data from the global metadata
 * @returns {Array} Array of description data objects
 */
function getDescriptionData() {
    const metadataDiv = document.getElementById('global-cve-metadata');
    if (!metadataDiv || !metadataDiv.hasAttribute('data-cve-metadata')) {
        return [];
    }
    
    try {
        const metadata = JSON.parse(metadataDiv.getAttribute('data-cve-metadata'));
        return metadata && metadata.descriptionData ? metadata.descriptionData : [];
    } catch (e) {
        console.error('Error parsing CVE metadata:', e);
        return [];
    }
}

/**
 * Create description source cards with language buttons
 * @param {number} rowIndex - The row index
 */
function createDescriptionButtons(rowIndex) {
    const descriptionData = getDescriptionData();
    if (!descriptionData || descriptionData.length === 0) {
        return;
    }
    
    const buttonContainer = document.getElementById(`descriptionButtons_${rowIndex}`);
    if (!buttonContainer) {
        return;
    }
    
    // Hide the description area initially
    const contentArea = document.getElementById(`descriptionContent_${rowIndex}`);
    if (contentArea) {
        contentArea.style.display = 'none';
    }
    
    // Clear existing buttons
    buttonContainer.innerHTML = '';
    
    // Create a card for each source
    descriptionData.forEach((source, sourceIndex) => {
        if (!source.descriptions || source.descriptions.length === 0) {
            return;
        }
        
        // Create a card for this source
        const sourceCard = document.createElement('div');
        sourceCard.className = 'card source-card me-3 mb-3';
        
        // Create the card header (showing only sourceRole)
        const cardHeader = document.createElement('div');
        cardHeader.className = 'card-header py-2';
        cardHeader.innerHTML = `<strong>${source.sourceRole} - Description(s)</strong>`;
        sourceCard.appendChild(cardHeader);
        
        // Create a card body for the language buttons
        const cardBody = document.createElement('div');
        cardBody.className = 'card-body py-2 d-flex flex-wrap gap-1';
        
        // Add language buttons
        source.descriptions.forEach((desc, descIndex) => {
            if (!desc.lang || !desc.value) {
                return;
            }
            
            // Create a unique ID for this description
            const buttonId = `descBtn_${rowIndex}_${sourceIndex}_${descIndex}`;
            
            // Create the language button
            const button = document.createElement('button');
            button.className = 'btn btn-sm btn-outline-secondary language-button';
            button.id = buttonId;
            button.setAttribute('data-source-index', sourceIndex);
            button.setAttribute('data-desc-index', descIndex);
            button.setAttribute('data-row-index', rowIndex);
            button.textContent = desc.lang;
            
            // Add click handler
            button.addEventListener('click', function() {
                toggleDescription(this);
            });
            
            cardBody.appendChild(button);
        });
        
        sourceCard.appendChild(cardBody);
        buttonContainer.appendChild(sourceCard);
    });
}

/**
 * Toggle the selected description visibility
 * @param {Element} button - The clicked button
 */
function toggleDescription(button) {
    // Get indices
    const rowIndex = button.getAttribute('data-row-index');
    const sourceIndex = button.getAttribute('data-source-index');
    const descIndex = button.getAttribute('data-desc-index');
    
    // Get the content area
    const contentArea = document.getElementById(`descriptionContent_${rowIndex}`);
    if (!contentArea) {
        return;
    }
    
    // Check if this button is already active
    const isActive = button.classList.contains('active');
    
    // Clear all active buttons
    const allButtons = document.querySelectorAll(`[id^="descBtn_${rowIndex}_"]`);
    allButtons.forEach(btn => btn.classList.remove('active'));
    
    // If the button was already active, hide the content area and exit
    if (isActive) {
        contentArea.style.display = 'none';
        return;
    }
    
    // Otherwise, mark this button as active
    button.classList.add('active');
    
    // Get description data
    const descriptionData = getDescriptionData();
    if (!descriptionData || descriptionData.length === 0) {
        return;
    }
    
    // Get the specific description
    const source = descriptionData[sourceIndex];
    if (!source || !source.descriptions || !source.descriptions[descIndex]) {
        return;
    }
    
    const description = source.descriptions[descIndex];
    
    // Simple approach - just replace newlines with <br> tags
    const displayText = description.value ? 
        description.value.replace(/\n/g, '<br>') : 
        "(No description provided)";
    
    // Show the description
    contentArea.innerHTML = `
        <h6 class="mb-3 text-muted">
            ${source.sourceRole}: ${source.sourceId} (${description.lang})
        </h6>
        <div class="description-text">
            ${displayText}
        </div>
    `;
    
    // Make the content area visible
    contentArea.style.display = 'block';
}

/**
 * Initialize all provenance assistance sections in the page
 */
function initializeProvenanceAssistance() {
    // Populate description buttons for each row
    const rows = document.querySelectorAll('.cpe-query-container');
    rows.forEach(row => {
        const rowIndex = row.id.replace('cpe-query-container-', '');
        if (rowIndex) {
            createDescriptionButtons(rowIndex);
        }
    });
}

// Initialize when the DOM is loaded
document.addEventListener('DOMContentLoaded', initializeProvenanceAssistance);