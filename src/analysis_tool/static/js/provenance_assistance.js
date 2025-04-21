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
    
    // Create source cards with language buttons
    descriptionData.forEach((source, sourceIndex) => {
        if (!source.descriptions || source.descriptions.length === 0) {
            return;
        }
        
        // Create a card for this source
        const card = document.createElement('div');
        card.className = 'card source-card me-2 mb-2';
        
        // Create the card header
        const header = document.createElement('div');
        header.className = 'card-header py-1';
        header.innerHTML = `<strong>${source.sourceRole} Description(s)</strong>`;
        card.appendChild(header);
        
        // Create the card body
        const body = document.createElement('div');
        
        // If there's only one language, use center alignment like repo cards
        if (source.descriptions.length === 1) {
            body.className = 'card-body py-2 px-2 d-flex align-items-center justify-content-center';
        } else {
            body.className = 'card-body py-2 px-2 d-flex flex-wrap gap-1';
        }
        
        // Create buttons for each language
        source.descriptions.forEach((desc, descIndex) => {
            const button = document.createElement('button');
            button.id = `descBtn_${rowIndex}_${sourceIndex}_${descIndex}`;
            button.className = 'btn btn-sm btn-outline-secondary language-button';
            if (source.descriptions.length > 1 && descIndex < source.descriptions.length - 1) {
                button.className += ' mb-2';  // Add margin bottom except for last button
            }
            button.textContent = desc.lang || 'unknown';
            button.setAttribute('data-row-index', rowIndex);
            button.setAttribute('data-source-index', sourceIndex);
            button.setAttribute('data-desc-index', descIndex);
            button.onclick = function() {
                toggleDescription(this);
            };
            body.appendChild(button);
        });
        
        // Add the body to the card
        card.appendChild(body);
        
        // Add the card to the container
        buttonContainer.appendChild(card);
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
            addProvenanceLinks(rowIndex);
        }
    });
}

/**
 * Add provenance links cards (repository, collection URL) for a row
 * @param {number} rowIndex - The row index
 */
function addProvenanceLinks(rowIndex) {
    // Direct access by ID for rawPlatformData
    const rawDataElement = document.getElementById(`rawPlatformData_${rowIndex}`);
    if (!rawDataElement || !rawDataElement.textContent) {
        return;
    }
    
    let platformData;
    try {
        platformData = JSON.parse(rawDataElement.textContent);
    } catch (e) {
        console.error(`Error parsing platform data for row ${rowIndex}:`, e);
        return;
    }
    
    // Get the links container
    const linksContainer = document.getElementById(`provenanceLinks_${rowIndex}`);
    if (!linksContainer) {
        return;
    }
    
    // Add repository link if available
    if (platformData.repo) {
        // Create a source-card style card for Repository
        const repoCard = document.createElement('div');
        repoCard.className = 'card source-card me-2 mb-2';
        
        // Create the card header
        const repoHeader = document.createElement('div');
        repoHeader.className = 'card-header py-1';
        repoHeader.innerHTML = '<strong>Repository</strong>';
        repoCard.appendChild(repoHeader);
        
        // Create the card body
        const repoBody = document.createElement('div');
        repoBody.className = 'card-body py-2 px-2 d-flex align-items-center justify-content-center';
        
        // Create a button
        const repoButton = document.createElement('button');
        repoButton.className = 'btn btn-sm btn-outline-secondary provenance-button';
        repoButton.textContent = 'Open';
        repoButton.title = platformData.repo;
        repoButton.onclick = function() {
            window.open(platformData.repo, '_blank');
        };
        
        repoBody.appendChild(repoButton);
        repoCard.appendChild(repoBody);
        linksContainer.appendChild(repoCard);
    }
    
    // Add collection URL if both collectionURL and packageName are available
    if (platformData.collectionURL && platformData.packageName) {
        // Create a source-card style card for Collection URL
        const collectionCard = document.createElement('div');
        collectionCard.className = 'card source-card me-2 mb-2';
        
        // Create the card header
        const collectionHeader = document.createElement('div');
        collectionHeader.className = 'card-header py-1';
        collectionHeader.innerHTML = '<strong>Collection URL</strong>';
        collectionCard.appendChild(collectionHeader);
        
        // Create the card body
        const collectionBody = document.createElement('div');
        collectionBody.className = 'card-body py-2 px-2 d-flex flex-column has-multiple-buttons';
        
        // Add URL-only button
        const urlOnlyButton = document.createElement('button');
        urlOnlyButton.className = 'btn btn-sm btn-outline-secondary provenance-button mb-2';
        urlOnlyButton.textContent = 'Collection URL Only';
        urlOnlyButton.title = platformData.collectionURL;
        urlOnlyButton.onclick = function() {
            window.open(platformData.collectionURL, '_blank');
        };
        
        // Add combined URL button
        const combinedButton = document.createElement('button');
        combinedButton.className = 'btn btn-sm btn-outline-secondary provenance-button';
        combinedButton.textContent = 'Combined with Package Name';
        
        // Combine URL and package name
        let combinedUrl = platformData.collectionURL;
        if (!combinedUrl.endsWith('/')) {
            combinedUrl += '/';
        }
        combinedUrl += platformData.packageName;
        
        combinedButton.title = combinedUrl;
        combinedButton.onclick = function() {
            window.open(combinedUrl, '_blank');
        };
        
        // Add buttons to card body
        collectionBody.appendChild(urlOnlyButton);
        collectionBody.appendChild(combinedButton);
        collectionCard.appendChild(collectionBody);
        linksContainer.appendChild(collectionCard);
    }
}

/**
 * Add a link card to the container
 * @param {Element} container - The container to add the card to
 * @param {string} label - The label for the card
 * @param {string} url - The URL to open when clicked
 */
function addLinkCard(container, label, url) {
    // Create the card
    const card = document.createElement('div');
    card.className = 'card link-card me-3 mb-3';
    card.style.cursor = 'pointer';
    card.onclick = function() {
        window.open(url, '_blank');
    };
    
    // Create the card body
    const cardBody = document.createElement('div');
    cardBody.className = 'card-body py-2';
    cardBody.textContent = label;
    
    // Add the card body to the card
    card.appendChild(cardBody);
    
    // Add the card to the container
    container.appendChild(card);
}

// Initialize when the DOM is loaded
document.addEventListener('DOMContentLoaded', initializeProvenanceAssistance);