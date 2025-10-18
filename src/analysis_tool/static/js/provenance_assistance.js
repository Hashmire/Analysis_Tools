/**
 * Handle description buttons in provenance assistance sections
 */

/**
 * Resolve source ID to human-readable display name using unified source system
 * @param {string} sourceId - The source ID (UUID) to resolve
 * @returns {string} Human-readable source name or original ID if not found
 */
function resolveSourceDisplay(sourceId) {
    // Use unified source system - no fallbacks
    if (!window.UnifiedSourceManager) {
        throw new Error("Unified source manager not available for source resolution");
    }
    
    const sourceInfo = window.UnifiedSourceManager.getSourceById(sourceId);
    if (sourceInfo) {
        return sourceInfo.name;
    }
    
    // If not found, return the ID itself (fail gracefully for display purposes)
    console.warn(`Source ${sourceId} not found in unified registry`);
    return sourceId;
}

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
    
    // Wrap all buttons and content in a container that can be collapsed
    buttonContainer.innerHTML = '<div class="description-buttons-container mb-2"></div>';
    const buttonsWrapper = buttonContainer.querySelector('.description-buttons-container');
    
    // Initialize the description area with collapsed class instead of inline style
    const contentArea = document.getElementById(`descriptionContent_${rowIndex}`);
    if (contentArea) {
        contentArea.classList.add('description-content', 'collapsed');
        // Remove any direct style.display setting
        contentArea.style.display = '';
    }
    
    // Clear existing buttons
    buttonsWrapper.innerHTML = '';
    
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
            body.className = 'card-body py-2 px-2 d-flex flex-wrap gap-1 has-multiple-buttons';
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
        buttonsWrapper.appendChild(card);
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
        // Use class toggle for smooth animation
        contentArea.classList.add('collapsed');
        // Remove spacing classes when collapsed
        contentArea.classList.remove('mt-3', 'border-top', 'pt-3');
        return;
    }
    
    // When showing content, add back spacing classes
    contentArea.classList.remove('collapsed');
    contentArea.classList.add('mt-3', 'border-top', 'pt-3');
    
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
    
    // Update the content then show it with animation
    contentArea.innerHTML = `
        <h6 class="mb-3 text-muted">
            ${source.sourceRole}: ${resolveSourceDisplay(source.sourceId)} (${description.lang})
        </h6>
        <div class="description-text">
            ${displayText}
        </div>
    `;
    
    // Remove collapsed class for smooth animation
    contentArea.classList.remove('collapsed');
}

/**
 * Initialize all provenance assistance sections in the page
 */
function setupProvenanceStructure() {
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
 * Add WordPress-specific provenance links if applicable for the row
 * @param {number} rowIndex - The row index
 * @param {object} platformData - The raw platform data for the row
 * @param {Element} linksContainer - The container to add cards to
 */
function addWordPressProvenanceLinks(rowIndex, platformData, linksContainer) {
    // Check if this is WordPress-related based on URL or source ID
    const isWordPressURL = 
        (platformData.collectionURL && platformData.collectionURL.includes('wordpress.org')) || 
        (platformData.repo && platformData.repo.includes('wordpress.org'));
    
    // Identify WordPress-related sources from CVE metadata
    const metadataDiv = document.getElementById('global-cve-metadata');
    let isWordPressSource = false;
    
    if (metadataDiv && metadataDiv.hasAttribute('data-cve-metadata')) {
        try {
            const metadata = JSON.parse(metadataDiv.getAttribute('data-cve-metadata'));
            
            if (metadata && metadata.sourceData && Array.isArray(metadata.sourceData)) {
                // Check if any of the sources used in THIS CVE are WordPress-related
                // Note: metadata.sourceData contains only sources used in this specific CVE
                const wordpressUuids = [
                    'b15e7b5b-3da4-40ae-a43c-f7aa60e62599', // WordFence
                    '1bfdd5d7-9bf6-4a53-96ea-42e2716d7a81'  // WP Scan
                ];
                
                isWordPressSource = metadata.sourceData.some(source => {
                    // Check sourceIdentifiers for WordPress UUIDs (original NVD structure)
                    const sourceIdentifiers = source.sourceIdentifiers || [];
                    
                    return wordpressUuids.some(uuid => sourceIdentifiers.includes(uuid));
                });
            }
        } catch (e) {
            console.error('Error checking WordPress sources:', e);
        }
    }
    
    // Exit if not WordPress-related
    if (!isWordPressURL && !isWordPressSource) {
        return;
    }
    
    // Create a WordPress Platform card
    const wpCard = document.createElement('div');
    wpCard.className = 'card source-card me-2 mb-2';
    
    // Create the card header
    const wpHeader = document.createElement('div');
    wpHeader.className = 'card-header py-1';
    wpHeader.innerHTML = '<strong>WordPress Platform</strong>';
    wpCard.appendChild(wpHeader);
    
    // Create the card body
    const wpBody = document.createElement('div');
    wpBody.className = 'card-body py-2 px-2 d-flex flex-column has-multiple-buttons';
    
    // Add Maintainer Profile button if vendor is available
    if (platformData.vendor) {
        const profileButton = document.createElement('button');
        profileButton.className = 'btn btn-sm btn-outline-secondary provenance-button mb-2';
        profileButton.textContent = 'Maintainer Profile';
        
        const profileUrl = `https://profiles.wordpress.org/${platformData.vendor}/#content-plugins`;
        profileButton.title = profileUrl;
        profileButton.onclick = function() {
            window.open(profileUrl, '_blank');
        };
        
        wpBody.appendChild(profileButton);
    }
    
    // Add Plugin Tracking (Product) button if product is available
    if (platformData.product) {
        const productButton = document.createElement('button');
        productButton.className = 'btn btn-sm btn-outline-secondary provenance-button mb-2';
        productButton.textContent = 'Plugin Tracking (Product)';
        
        const productUrl = `https://plugins.trac.wordpress.org/browser/${platformData.product}`;
        productButton.title = productUrl;
        productButton.onclick = function() {
            window.open(productUrl, '_blank');
        };
        
        wpBody.appendChild(productButton);
        
        // Add Changelog button using product name
        const changelogButton = document.createElement('button');
        changelogButton.className = 'btn btn-sm btn-outline-secondary provenance-button mb-2';
        changelogButton.textContent = 'Plugin Changelog (Product)';
        
        const changelogUrl = `https://wordpress.org/plugins/${platformData.product}/#developers`;
        changelogButton.title = changelogUrl;
        changelogButton.onclick = function() {
            window.open(changelogUrl, '_blank');
        };
        
        wpBody.appendChild(changelogButton);
    }
    
    // Add Plugin Tracking (Package Name) button if packageName is available and different from product
    if (platformData.packageName && 
        (!platformData.product || platformData.packageName !== platformData.product)) {
        
        const packageButton = document.createElement('button');
        packageButton.className = 'btn btn-sm btn-outline-secondary provenance-button mb-2';
        packageButton.textContent = 'Plugin Tracking (Package Name)';
        
        const packageUrl = `https://plugins.trac.wordpress.org/browser/${platformData.packageName}`;
        packageButton.title = packageUrl;
        packageButton.onclick = function() {
            window.open(packageUrl, '_blank');
        };
        
        wpBody.appendChild(packageButton);
        
        // Add Changelog button using packageName if different from product
        const changelogPackageButton = document.createElement('button');
        changelogPackageButton.className = 'btn btn-sm btn-outline-secondary provenance-button mb-2';
        changelogPackageButton.textContent = 'Plugin Changelog (Package)';
        
        const changelogPackageUrl = `https://wordpress.org/plugins/${platformData.packageName}/#developers`;
        changelogPackageButton.title = changelogPackageUrl;
        changelogPackageButton.onclick = function() {
            window.open(changelogPackageUrl, '_blank');
        };
        
        wpBody.appendChild(changelogPackageButton);
    }
    
    // Only add the card if it has any buttons
    if (wpBody.children.length > 0) {
        wpCard.appendChild(wpBody);
        linksContainer.appendChild(wpCard);
    }
}

/**
 * Add Maven-specific provenance links for a row
 * @param {number} rowIndex - The row index
 * @param {object} platformData - The raw platform data for the row
 * @param {Element} linksContainer - The container to add cards to
 */
function addMavenProvenanceLinks(rowIndex, platformData, linksContainer) {
    // Parse the Maven package name (format: groupId:artifactId)
    const packageParts = platformData.packageName.split(':');
    if (packageParts.length < 2) {
        // Fallback to generic handling if not proper Maven format
        addGenericCollectionLinks(rowIndex, platformData, linksContainer);
        return;
    }
    
    const groupId = packageParts[0];
    const artifactId = packageParts[1];
    
    // Create a source-card style card for Maven Repository
    const mavenCard = document.createElement('div');
    mavenCard.className = 'card source-card me-2 mb-2';
    
    // Create the card header
    const mavenHeader = document.createElement('div');
    mavenHeader.className = 'card-header py-1';
    mavenHeader.innerHTML = '<strong>Maven Repository</strong>';
    mavenCard.appendChild(mavenHeader);
    
    // Create the card body
    const mavenBody = document.createElement('div');
    mavenBody.className = 'card-body py-2 px-2 d-flex flex-column has-multiple-buttons';
    
    // Add Official Search Interface button
    const searchButton = document.createElement('button');
    searchButton.className = 'btn btn-sm btn-outline-secondary provenance-button mb-2';
    searchButton.textContent = 'Official Search Interface';
    
    const searchUrl = `https://central.sonatype.com/artifact/${groupId}/${artifactId}`;
    searchButton.title = searchUrl;
    searchButton.onclick = function() {
        window.open(searchUrl, '_blank');
    };
    
    // Add Central Repository button
    const repoButton = document.createElement('button');
    repoButton.className = 'btn btn-sm btn-outline-secondary provenance-button';
    repoButton.textContent = 'Central Repository';
    
    // Convert groupId dots to slashes for repository path
    const groupPath = groupId.replace(/\./g, '/');
    const repoUrl = `https://repo.maven.apache.org/maven2/${groupPath}/${artifactId}/`;
    repoButton.title = repoUrl;
    repoButton.onclick = function() {
        window.open(repoUrl, '_blank');
    };
    
    // Add buttons to card body
    mavenBody.appendChild(searchButton);
    mavenBody.appendChild(repoButton);
    mavenCard.appendChild(mavenBody);
    linksContainer.appendChild(mavenCard);
}

/**
 * Add generic collection URL links for non-Maven repositories
 * @param {number} rowIndex - The row index
 * @param {object} platformData - The raw platform data for the row
 * @param {Element} linksContainer - The container to add cards to
 */
function addGenericCollectionLinks(rowIndex, platformData, linksContainer) {
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
    
    // Add WordPress-specific provenance links if applicable
    addWordPressProvenanceLinks(rowIndex, platformData, linksContainer);
    
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
        // Check if this is a Maven repository using comprehensive detection
        const isMavenRepo = isMavenRepository(platformData.collectionURL, platformData.packageName);
        
        if (isMavenRepo && platformData.packageName.includes(':')) {
            // Handle Maven repository with proper URL generation
            addMavenProvenanceLinks(rowIndex, platformData, linksContainer);
        } else {
            // Handle non-Maven repositories with the original logic
            addGenericCollectionLinks(rowIndex, platformData, linksContainer);
        }
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

// Initialize the provenance assistance module
function processProvenanceMetadata() {
    // Get global CVE metadata if available
    const metadataContainer = document.getElementById('global-cve-metadata');
    if (!metadataContainer) return;
    
    const metadataJson = metadataContainer.getAttribute('data-cve-metadata');
    if (!metadataJson) return;
    
    try {
        const metadata = JSON.parse(metadataJson);
        
        // Get all provenance containers in the document
        const provenanceContainers = document.querySelectorAll('[id^="provenanceCollapse_"]');
        provenanceContainers.forEach(container => {
            // Get the index number from the container ID
            const index = container.id.split('_')[1];
            
            // Process descriptions
            if (metadata.descriptionData && metadata.descriptionData.length > 0) {
                createDescriptionButtons(index);
            }
            
            // Process references - new section
            if (metadata.referencesData && metadata.referencesData.length > 0) {
                createReferenceCards(index, metadata.referencesData);
            }

        });
    } catch (error) {
        console.error('Error processing provenance metadata:', error);
    }
}

/**
 * Create reference cards based on tags
 * @param {number} rowIndex - The row index
 * @param {Array} referencesData - Array of reference data objects
 */
function createReferenceCards(rowIndex, referencesData) {
    console.debug("Creating reference cards for row", rowIndex);
    console.debug("References data:", referencesData);
    
    // Target div where we'll add the reference cards
    const referenceLinksContainer = document.getElementById(`provenanceLinks_${rowIndex}`);
    if (!referenceLinksContainer) {
        console.error(`Container provenanceLinks_${rowIndex} not found!`);
        return;
    }
    
    // Debug: Log ALL tags we find to see what's available
    const allFoundTags = new Set();
    referencesData.forEach(sourceData => {
        (sourceData.references || []).forEach(reference => {
            (reference.tags || []).forEach(tag => {
                allFoundTags.add(tag);
            });
        });
    });
    console.debug("All available tags in the data:", Array.from(allFoundTags));
    
    // Define the tags we're interested in
    const targetTags = ['patch', 'mitigation', 'product', 'issue-tracking'];
    
    // Group references by tag and URL (to handle duplicates)
    const referencesByTag = {};
    targetTags.forEach(tag => referencesByTag[tag] = new Map()); // Map to store by URL
    
    // Track if we found any references with our target tags
    let foundTargetTagReferences = false;
    
    // Process all references from all sources
    referencesData.forEach(sourceData => {
        const sourceId = sourceData.sourceId || 'Unknown';
        const sourceRole = sourceData.sourceRole || 'Unknown';
        const resolvedSourceName = resolveSourceDisplay(sourceId); // Use unified resolution
        
        // Process each reference in this source
        (sourceData.references || []).forEach(reference => {
            const url = reference.url;
            const name = reference.name || url;
            const tags = reference.tags || [];
            
            console.debug(`Processing reference: ${name}, tags:`, tags);
            
            // Only process references that have one of our target tags
            tags.forEach(tag => {
                if (targetTags.includes(tag) && url) {
                    foundTargetTagReferences = true;
                    // Create a unique key for the URL
                    const urlKey = url.toLowerCase();
                    
                    // Check if we've seen this URL before for this tag
                    if (referencesByTag[tag].has(urlKey)) {
                        // Add this source to the existing reference
                        const existingRef = referencesByTag[tag].get(urlKey);
                        existingRef.sources.push({
                            sourceId,
                            sourceRole,
                            resolvedName: resolvedSourceName, // Add resolved name
                            tags: reference.tags || []
                        });
                    } else {
                        // Create a new reference entry
                        referencesByTag[tag].set(urlKey, {
                            url,
                            name,
                            sources: [{
                                sourceId,
                                sourceRole,
                                resolvedName: resolvedSourceName, // Add resolved name
                                tags: reference.tags || []
                            }]
                        });
                    }
                }
            });
        });
    });
    
    if (!foundTargetTagReferences) {
        console.log("No references with patch, mitigation, product, or issue-tracking tags found for row ", rowIndex);
        return;
    }
    
    console.debug("References by tag:", referencesByTag);
    
    // Create a card for each tag that has references
    targetTags.forEach(tag => {
        const references = Array.from(referencesByTag[tag].values());
        if (references.length === 0) return;
        
        console.debug(`Creating card for tag ${tag} with ${references.length} references`);
        
        // Create a source-card style card for consistency
        const card = document.createElement('div');
        card.className = 'card source-card me-2 mb-2';
        
        // Create the card header using the same style as other cards
        const header = document.createElement('div');
        header.className = 'card-header py-1';
        
        // Format the tag name for display (capitalize, replace hyphens)
        const displayName = tag.charAt(0).toUpperCase() + tag.slice(1).replace('-', ' ');
        header.innerHTML = `<strong>${displayName}</strong>`;
        card.appendChild(header);
        
        // Create the card body with consistent styling
        const body = document.createElement('div');
        
        if (references.length === 1) {
            // If there's only one reference, use center alignment like repo cards
            body.className = 'card-body py-2 px-2 d-flex align-items-center justify-content-center';
        } else {
            body.className = 'card-body py-2 px-2 d-flex flex-wrap gap-1';
        }
        
        // Create buttons for each reference
        references.forEach((ref, idx) => {
            const button = document.createElement('button');
            button.className = 'btn btn-sm btn-outline-secondary provenance-button';
            
            // Add margin to all but the last button if there are multiple
            if (references.length > 1 && idx < references.length - 1) {
                button.className += ' mb-2';
            }
            
            // Truncate long names
            const displayName = ref.name.length > 25 
                ? ref.name.substring(0, 22) + '...' 
                : ref.name;
            
            button.textContent = displayName;
            button.onclick = function() {
                window.open(ref.url, '_blank');
            };
            
            // Create comprehensive tooltip with all info
            let tooltip = '';
            
            // Add each source's information to the tooltip
            ref.sources.forEach((source, i) => {
                if (i > 0) tooltip += '\n\n'; // Add spacing between sources
                
                const displayName = source.resolvedName || 'Unknown Source'; // Always use resolved name
                tooltip += `Source: ${source.sourceRole} (${displayName})\n`;
                tooltip += `Name: ${ref.name}\n`;
                tooltip += `URL: ${ref.url}\n`;
                
                if (source.tags && source.tags.length > 0) {
                    tooltip += `Tags: ${source.tags.join(', ')}`;
                }
            });
            
            button.title = tooltip;
            body.appendChild(button);
        });
        
        // Add the body to the card
        card.appendChild(body);
        referenceLinksContainer.appendChild(card);
        console.debug(`Card for tag ${tag} added to container`);
    });
}

/**
 * Toggle provenance description visibility with smooth animation
 * @param {string} buttonId - ID of the toggle button
 */
function toggleProvenanceDescription(buttonId) {
    try {
        const descriptionId = buttonId.replace('toggle_', 'description_');
        const descriptionElement = document.getElementById(descriptionId);
        const button = document.getElementById(buttonId);
        
        if (!descriptionElement || !button) return;
        
        // Toggle the collapsed class for animation
        descriptionElement.classList.toggle('collapsed');
        const isCollapsed = descriptionElement.classList.contains('collapsed');
        
        // Update the button text and styling
        button.textContent = isCollapsed ? 'Show Description' : 'Hide Description';
        if (isCollapsed) {
            button.classList.remove('btn-success');
            button.classList.add('btn-info');
        } else {
            button.classList.remove('btn-info');
            button.classList.add('btn-success');
        }    } catch(e) {
        console.error(`Error toggling provenance description for ${buttonId}:`, e);
    }
}

/**
 * Update provenance collapse state
 * @param {string} tableIndex - The table index
 * @param {boolean} expand - Whether to expand (true) or collapse (false)
 */
function updateProvenanceState(tableIndex, expand) {
    const provenanceCollapse = document.getElementById(`provenanceCollapse_${tableIndex}`);
    const provenanceHeaderArrow = document.querySelector(`#provenanceHeader_${tableIndex} .arrow-icon`);
    
    if (provenanceCollapse) {
        if (expand) {
            provenanceCollapse.classList.add('show');
            if (provenanceHeaderArrow) provenanceHeaderArrow.innerHTML = "&darr;";
        } else {
            provenanceCollapse.classList.remove('show');
            if (provenanceHeaderArrow) provenanceHeaderArrow.innerHTML = "&uarr;";
        }
    }
}

// Combine into a single DOMContentLoaded event listener:
document.addEventListener('DOMContentLoaded', function() {
    // Initialization functions
    setupProvenanceStructure();
    processProvenanceMetadata();
    
    // Initialize provenance description containers
    document.querySelectorAll('[id^="description_"]').forEach(container => {
        container.classList.add('description-container', 'collapsed');
        
        // Find associated button and update its text/style
        const buttonId = container.id.replace('description_', 'toggle_');
        const button = document.getElementById(buttonId);
        if (button) {
            button.textContent = 'Show Description';
            button.classList.add('btn-transition', 'btn-info');
        }
    });
    
    // Also check for description content areas
    document.querySelectorAll('.description-content').forEach(content => {
        // Make sure they have the proper transition classes
        if (!content.classList.contains('collapsed')) {
            content.classList.add('collapsed');
        }
    });
    
    // Add a single mutation observer for provenance collapse sections
    const observer = new MutationObserver((mutations) => {
        mutations.forEach(mutation => {
            if (mutation.attributeName === 'class') {
                const target = mutation.target;
                if (target.id && target.id.startsWith('provenanceCollapse_')) {
                    const index = target.id.split('_')[1];
                    const arrowElement = document.querySelector(`#provenanceHeader_${index} .arrow-icon`);
                    
                    if (arrowElement) {
                        // Use HTML entities and innerHTML instead of Unicode and textContent
                        const isShown = target.classList.contains('show');
                        arrowElement.innerHTML = isShown ? "&darr;" : "&uarr;";
                    }
                }
            }
        });
    });
    
    // Apply the observer to all provenance collapse sections
    const provenanceCollapseSections = document.querySelectorAll('[id^="provenanceCollapse_"]');
    provenanceCollapseSections.forEach(section => {
        observer.observe(section, { attributes: true });
    });
    
    // Initialize all provenance arrow icons with HTML entities
    document.querySelectorAll('#provenanceHeader_\\d+ .arrow-icon').forEach(arrow => {
        const parentHeader = arrow.closest('.card-header');
        if (!parentHeader) return;
        
        const targetId = parentHeader.getAttribute('data-bs-target');
        if (!targetId) return;
        
        const target = document.querySelector(targetId);
        if (!target) return;        
        // Set initial state using HTML entities
        const isShown = target.classList.contains('show');
        arrow.innerHTML = isShown ? "&darr;" : "&uarr;";
    });
});

/**
 * Comprehensive Maven repository detection
 * @param {string} collectionURL - The collection URL to check
 * @param {string} packageName - The package name to verify Maven format
 * @returns {boolean} - True if this appears to be a Maven repository
 */
function isMavenRepository(collectionURL, packageName) {
    if (!collectionURL || !packageName) {
        return false;
    }
    
    const url = collectionURL.toLowerCase();
    
    // Primary Maven repository patterns
    const mavenPatterns = [
        // Official Maven Central
        'repo1.maven.org',
        'repo.maven.apache.org', 
        'central.maven.org',
        'search.maven.org',
        
        // Maven path indicators
        '/maven2/',
        '/maven/',
        '/m2/',
        
        // Common enterprise Maven repository patterns
        '/repository/maven',
        '/artifactory/',
        '/nexus/',
        
        // Sonatype repositories
        'oss.sonatype.org',
        'central.sonatype.com',
        
        // Other Maven-compatible repositories
        'jcenter.bintray.com',
        'jitpack.io',
        'clojars.org',
        
        // Generic Maven repository indicators
        '/libs-release',
        '/libs-snapshot',
        '/maven-public',
        '/maven-central'
    ];
    
    // Check if URL matches any Maven patterns
    const hasKnownMavenPattern = mavenPatterns.some(pattern => url.includes(pattern));
    
    // Additional heuristic: Maven packages typically use groupId:artifactId format
    const hasMavenPackageFormat = packageName.includes(':') && 
                                  packageName.split(':').length >= 2 &&
                                  // Basic validation that it looks like a Maven coordinate
                                  /^[a-zA-Z0-9\-_.]+:[a-zA-Z0-9\-_.]+/.test(packageName);
    
    // Strong indicators (if any of these match, it's likely Maven)
    const strongMavenIndicators = [
        'maven',
        'artifactory',
        'nexus',
        'sonatype'
    ];
    
    const hasStrongIndicator = strongMavenIndicators.some(indicator => url.includes(indicator));
      // Return true if:
    // 1. URL has known Maven patterns, OR
    // 2. URL has strong indicators AND package format looks like Maven
    return hasKnownMavenPattern || 
           (hasStrongIndicator && hasMavenPackageFormat);
}

// =============================================================================
// Global Exports - All window assignments consolidated here
// =============================================================================
window.toggleProvenanceDescription = toggleProvenanceDescription;
window.updateProvenanceState = updateProvenanceState;