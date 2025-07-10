/**
 * Modular Badge Modal System
 * 
 * A configurable, reusable modal system for badges that can be easily extended
 * for different types of badge/modal combinations without code duplication.
 * 
 * Usage:
 * 1. Define modal configuration
 * 2. Create BadgeModal instance
 * 3. Register data and show modal
 */

class BadgeModal {
    constructor(config) {
        this.config = this.validateConfig(config);
        this.modalId = `${this.config.modalType}Modal`;
        this.isVisible = false;
        this.isDragging = false;
        this.dragOffset = { x: 0, y: 0 };
        
        // Store reference to current modal element
        this.modalElement = null;
    }

    /**
     * Validate and set default configuration values
     */
    validateConfig(config) {
        const defaults = {
            modalType: 'generic',
            title: 'Modal',
            icon: '📋',
            size: 'modal-lg',
            maxHeight: '60vh',
            headerColor: '#198754',
            enableDragging: true,
            enableTabs: false,
            showFooter: true,
            footerButtons: [
                { text: 'Close', class: 'btn-outline-secondary', action: 'dismiss' }
            ],
            customCSS: '',
            onShow: null,
            onHide: null,
            onDataLoad: null
        };

        return { ...defaults, ...config };
    }

    /**
     * Register data globally for modal access
     */
    static registerData(modalType, dataKey, data) {
        // Fail fast if BadgeModal class isn't loaded properly
        if (typeof BadgeModal === 'undefined') {
            throw new Error('BadgeModal not available - badge_modal_system.js must be loaded before modal data registration');
        }
        
        if (!window.BADGE_MODAL_DATA) {
            window.BADGE_MODAL_DATA = {};
        }
        if (!window.BADGE_MODAL_DATA[modalType]) {
            window.BADGE_MODAL_DATA[modalType] = {};
        }
        
        // Check if data already exists for this key
        const existingData = window.BADGE_MODAL_DATA[modalType][dataKey];
        if (existingData) {
            // Merge data, preserving confirmedMapping if it exists in either version
            const mergedData = { ...data };
            if (existingData.confirmedMapping && !data.confirmedMapping) {
                mergedData.confirmedMapping = existingData.confirmedMapping;
            } else if (data.confirmedMapping && existingData.confirmedMapping) {
                // Both have confirmedMapping, merge them
                mergedData.confirmedMapping = { ...existingData.confirmedMapping, ...data.confirmedMapping };
            }
            window.BADGE_MODAL_DATA[modalType][dataKey] = mergedData;
        } else {
            window.BADGE_MODAL_DATA[modalType][dataKey] = data;
        }
        
        console.log(`✓ Registered ${modalType} data for key: ${dataKey}`);
    }

    /**
     * Get registered data for this modal type
     * Fails fast if data isn't properly registered - no fallbacks
     */
    getData(dataKey) {
        if (!window.BADGE_MODAL_DATA) {
            throw new Error(`Modal data storage not initialized - BadgeModal.registerData() must be called first`);
        }
        if (!window.BADGE_MODAL_DATA[this.config.modalType]) {
            throw new Error(`No data registered for modal type '${this.config.modalType}' - check BadgeModal.registerData() calls`);
        }
        if (!window.BADGE_MODAL_DATA[this.config.modalType][dataKey]) {
            throw new Error(`No data registered for key '${dataKey}' in modal type '${this.config.modalType}' - check BadgeModal.registerData() calls`);
        }
        
        const retrievedData = window.BADGE_MODAL_DATA[this.config.modalType][dataKey];
        return retrievedData;
    }

    /**
     * Show modal with specific data
     */
    show(dataKey, displayValue, additionalData = {}) {
        // getData() will throw if data isn't registered - fail fast, no fallbacks
        const data = this.getData(dataKey);

        // Remove existing modal if present
        this.hide();

        // Generate modal HTML
        const modalHtml = this.generateModalHTML(data, displayValue, additionalData);

        // Add modal to page
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        this.modalElement = document.getElementById(this.modalId);

        // Setup event listeners
        this.setupEventListeners();

        // Show modal using Bootstrap
        const modal = new bootstrap.Modal(this.modalElement);
        modal.show();
        this.isVisible = true;

        // Call custom onShow callback
        if (this.config.onShow) {
            this.config.onShow(data, displayValue, additionalData);
        }
    }

    /**
     * Hide and remove modal
     */
    hide() {
        if (this.modalElement) {
            const modalInstance = bootstrap.Modal.getInstance(this.modalElement);
            if (modalInstance) {
                modalInstance.hide();
            }
            this.modalElement.remove();
            this.modalElement = null;
        }
        this.isVisible = false;
    }

    /**
     * Generate complete modal HTML structure
     */
    generateModalHTML(data, displayValue, additionalData) {
        const headerHtml = this.generateHeaderHTML(displayValue, additionalData);
        const bodyHtml = this.generateBodyHTML(data, displayValue, additionalData);
        const footerHtml = this.generateFooterHTML();

        return `
            <div class="modal fade" id="${this.modalId}" tabindex="-1" aria-labelledby="${this.modalId}Label" aria-hidden="true">
                <div class="modal-dialog ${this.config.size}">
                    <div class="modal-content" style="max-height: ${this.config.maxHeight}; overflow: hidden;">
                        ${headerHtml}
                        ${bodyHtml}
                        ${this.config.showFooter ? footerHtml : ''}
                    </div>
                </div>
            </div>
            ${this.generateCustomCSS()}
        `;
    }

    /**
     * Generate modal header HTML
     */
    generateHeaderHTML(displayValue, additionalData) {
        const draggableClass = this.config.enableDragging ? 'draggable-header' : '';
        const draggableStyle = this.config.enableDragging ? 'cursor: move;' : '';

        return `
            <div class="modal-header text-white position-sticky ${draggableClass}" 
                 style="top: 0; z-index: 1020; background: linear-gradient(45deg, ${this.config.headerColor}, ${this.adjustColorBrightness(this.config.headerColor, 20)}); ${draggableStyle}">
                <div class="header-content w-100">
                    <div class="d-flex justify-content-between align-items-center mb-1">
                        <h6 class="modal-title mb-0" id="${this.modalId}Label">
                            ${this.config.icon} ${this.config.title}
                        </h6>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" style="cursor: pointer;"></button>
                    </div>
                    ${this.generateHeaderContent(displayValue, additionalData)}
                </div>
            </div>
        `;
    }

    /**
     * Generate custom header content (override in subclasses or config)
     */
    generateHeaderContent(displayValue, additionalData) {
        if (this.config.generateHeaderContent) {
            return this.config.generateHeaderContent(displayValue, additionalData);
        }
        
        return `
            <div class="info-display">
                <div class="display-value mb-1">
                    <code class="text-white bg-dark px-2 py-1 rounded" style="font-size: 0.75rem;">${displayValue}</code>
                </div>
            </div>
        `;
    }

    /**
     * Generate modal body HTML
     */
    generateBodyHTML(data, displayValue, additionalData) {
        if (this.config.enableTabs) {
            return this.generateTabbedBodyHTML(data, displayValue, additionalData);
        } else {
            return this.generateSimpleBodyHTML(data, displayValue, additionalData);
        }
    }

    /**
     * Generate tabbed body content
     */
    generateTabbedBodyHTML(data, displayValue, additionalData) {
        if (!this.config.generateTabsData) {
            console.error('enableTabs is true but generateTabsData function not provided');
            return this.generateSimpleBodyHTML(data, displayValue, additionalData);
        }

        const tabsData = this.config.generateTabsData(data, displayValue, additionalData);
        
        // Determine which tab should be active based on focusTab parameter
        const focusTab = additionalData && additionalData.focusTab;
        let activeTabIndex = 0; // Default to first tab
        
        if (focusTab) {
            const targetTabIndex = tabsData.findIndex(tab => tab.id === focusTab);
            if (targetTabIndex !== -1) {
                activeTabIndex = targetTabIndex;
            }
        }
        
        let tabsHtml = '';
        let tabContentHtml = '';

        tabsData.forEach((tab, index) => {
            const isActive = index === activeTabIndex ? 'active' : '';
            const tabId = `tab-${tab.id}`;
            
            tabsHtml += `
                <li class="nav-item" role="presentation">
                    <button class="nav-link ${isActive}" id="${tabId}-tab" data-bs-toggle="tab" 
                            data-bs-target="#${tabId}" type="button" role="tab">
                        <strong style="font-size: 0.8rem;">${tab.label}</strong>
                        ${tab.badge ? `<span class="badge bg-secondary ms-1" style="font-size: 0.65rem;">${tab.badge}</span>` : ''}
                    </button>
                </li>
            `;
            
            tabContentHtml += `
                <div class="tab-pane fade ${isActive ? 'show active' : ''}" id="${tabId}" role="tabpanel">
                    <div class="p-2" style="max-height: 250px; overflow-y: auto;">
                        ${tab.content}
                    </div>
                </div>
            `;
        });

        return `
            <div class="modal-body p-0">
                <ul class="nav nav-tabs nav-fill bg-light" role="tablist" style="border-bottom: 1px solid #dee2e6;">
                    ${tabsHtml}
                </ul>
                <div class="tab-content">
                    ${tabContentHtml}
                </div>
            </div>
        `;
    }

    /**
     * Generate simple (non-tabbed) body content
     */
    generateSimpleBodyHTML(data, displayValue, additionalData) {
        if (this.config.generateBodyContent) {
            return `
                <div class="modal-body">
                    ${this.config.generateBodyContent(data, displayValue, additionalData)}
                </div>
            `;
        }

        return `
            <div class="modal-body">
                <pre>${JSON.stringify(data, null, 2)}</pre>
            </div>
        `;
    }

    /**
     * Generate modal footer HTML
     */
    generateFooterHTML() {
        let buttonsHtml = '';
        
        this.config.footerButtons.forEach(button => {
            const clickHandler = button.action === 'dismiss' ? 'data-bs-dismiss="modal"' : 
                                button.onclick ? `onclick="${button.onclick}"` : '';
            
            buttonsHtml += `
                <button type="button" class="btn btn-sm ${button.class}" ${clickHandler}>
                    ${button.text}
                </button>
            `;
        });

        return `
            <div class="modal-footer py-1">
                ${buttonsHtml}
            </div>
        `;
    }

    /**
     * Generate custom CSS for this modal type
     */
    generateCustomCSS() {
        const baseCSS = `
            <style id="${this.modalId}-styles">
            #${this.modalId} .draggable-header {
                cursor: move;
                user-select: none;
            }

            #${this.modalId} .draggable-header:active {
                cursor: grabbing;
            }

            #${this.modalId} .modal-content {
                max-height: ${this.config.maxHeight};
                overflow: hidden;
            }

            #${this.modalId} .modal-header {
                background: linear-gradient(45deg, ${this.config.headerColor}, ${this.adjustColorBrightness(this.config.headerColor, 20)});
                border-bottom: none;
                padding: 0.5rem 0.75rem;
            }

            ${this.config.enableTabs ? this.getTabCSS() : ''}
            ${this.config.customCSS}
            </style>
        `;

        return baseCSS;
    }

    /**
     * Get CSS for tabbed interface
     */
    getTabCSS() {
        return `
            #${this.modalId} .nav-tabs {
                background-color: #f8f9fa;
                border-bottom: 1px solid #dee2e6;
                margin: 0;
                min-height: auto;
            }

            #${this.modalId} .nav-tabs .nav-link {
                border: none;
                border-radius: 0;
                padding: 0.375rem 0.5rem;
                font-size: 0.75rem;
                color: #6c757d;
                background-color: transparent;
            }

            #${this.modalId} .nav-tabs .nav-link.active {
                background-color: #fff;
                color: ${this.config.headerColor};
                border-bottom: 2px solid ${this.config.headerColor};
                font-weight: 600;
            }

            #${this.modalId} .nav-tabs .nav-link:hover {
                background-color: #e9ecef;
                border-color: transparent;
            }
        `;
    }

    /**
     * Setup event listeners for dragging and other interactions
     */
    setupEventListeners() {
        if (this.config.enableDragging) {
            this.setupDragging();
        }

        // Clean up modal after it's hidden
        this.modalElement.addEventListener('hidden.bs.modal', () => {
            if (this.config.onHide) {
                this.config.onHide();
            }
            this.modalElement.remove();
            this.modalElement = null;
            this.isVisible = false;
        });
    }

    /**
     * Setup dragging functionality
     */
    setupDragging() {
        const modalDialog = this.modalElement.querySelector('.modal-dialog');
        const modalHeader = this.modalElement.querySelector('.draggable-header');
        
        if (!modalDialog || !modalHeader) return;

        let currentX, currentY, initialX, initialY;

        const dragStart = (e) => {
            // Don't start dragging if clicking on close button
            if (e.target.classList.contains('btn-close') || e.target.closest('.btn-close')) {
                return;
            }
            
            initialX = e.clientX - this.dragOffset.x;
            initialY = e.clientY - this.dragOffset.y;

            if (e.target === modalHeader || modalHeader.contains(e.target)) {
                this.isDragging = true;
                modalDialog.style.transform = `translate(${this.dragOffset.x}px, ${this.dragOffset.y}px)`;
                modalDialog.style.transition = 'none';
            }
        };

        const drag = (e) => {
            if (this.isDragging) {
                e.preventDefault();
                currentX = e.clientX - initialX;
                currentY = e.clientY - initialY;

                this.dragOffset.x = currentX;
                this.dragOffset.y = currentY;

                modalDialog.style.transform = `translate(${currentX}px, ${currentY}px)`;
            }
        };

        const dragEnd = () => {
            if (this.isDragging) {
                initialX = currentX;
                initialY = currentY;
                this.isDragging = false;
                modalDialog.style.transition = '';
            }
        };

        modalHeader.addEventListener('mousedown', dragStart);
        document.addEventListener('mousemove', drag);
        document.addEventListener('mouseup', dragEnd);
    }

    /**
     * Utility function to adjust color brightness
     */
    adjustColorBrightness(hex, percent) {
        // Remove # if present
        hex = hex.replace('#', '');
        
        // Parse RGB values
        const r = parseInt(hex.substr(0, 2), 16);
        const g = parseInt(hex.substr(2, 2), 16);
        const b = parseInt(hex.substr(4, 2), 16);
        
        // Adjust brightness
        const newR = Math.min(255, Math.floor(r * (1 + percent / 100)));
        const newG = Math.min(255, Math.floor(g * (1 + percent / 100)));
        const newB = Math.min(255, Math.floor(b * (1 + percent / 100)));
        
        // Convert back to hex
        return `#${newR.toString(16).padStart(2, '0')}${newG.toString(16).padStart(2, '0')}${newB.toString(16).padStart(2, '0')}`;
    }
}

/**
 * Badge Modal Factory
 * Creates pre-configured modal instances for common use cases
 */
class BadgeModalFactory {
    static createReferencesModal() {
        return new BadgeModal({
            modalType: 'references',
            title: 'CPE Base String References',
            icon: '📋',
            headerColor: '#0d6efd',
            enableTabs: true,
            generateHeaderContent: (displayValue, additionalData) => {
                const totalCount = additionalData.totalCount || 0;
                const typeCount = additionalData.typeCount || 0;
                
                return `
                    <div class="cpe-info-fixed">
                        <div class="cpe-string-compact mb-1">
                            <code class="text-white bg-dark px-2 py-1 rounded" style="font-size: 0.75rem;">${displayValue}</code>
                        </div>
                        <div class="summary-stats-compact">
                            <span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">📊 ${totalCount} refs</span>
                            <span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">🏷️ ${typeCount} types</span>
                        </div>
                    </div>
                `;
            },
            generateTabsData: (data, displayValue, additionalData) => {
                // Sort reference types by predefined order, then frequency
                const typeOrder = ['Vendor', 'Project', 'Product', 'Version', 'ChangeLog', 'Change Log', 'Advisory', 'Unknown'];
                
                const sortedTypes = Object.entries(data).sort((a, b) => {
                    const aIndex = typeOrder.indexOf(a[0]);
                    const bIndex = typeOrder.indexOf(b[0]);
                    
                    if (aIndex !== -1 && bIndex !== -1) {
                        return aIndex - bIndex;
                    }
                    if (aIndex !== -1) return -1;
                    if (bIndex !== -1) return 1;
                    return b[1].total_freq - a[1].total_freq;
                });

                return sortedTypes.map(([refType, typeData]) => ({
                    id: refType.toLowerCase().replace(/[^a-z0-9]/g, ''),
                    label: refType,
                    badge: typeData.refs.length,
                    content: BadgeModalFactory.generateReferenceTabContent(typeData.refs, refType)
                }));
            },
            customCSS: `
                .reference-item-compact {
                    background-color: #f8f9fa;
                    border: 1px solid #e9ecef !important;
                    font-size: 0.75rem;
                    transition: all 0.2s ease;
                    margin-bottom: 0.25rem !important;
                    padding: 0.375rem 0.5rem !important;
                }

                .reference-item-compact:hover {
                    background-color: #e9ecef;
                    border-color: #0d6efd !important;
                    transform: translateY(-1px);
                }

                .reference-link-compact {
                    color: #0d6efd;
                    text-decoration: none;
                    word-break: break-all;
                    font-size: 0.75rem;
                    line-height: 1.2;
                }

                .reference-link-compact:hover {
                    color: #0a58ca;
                    text-decoration: underline;
                }
            `
        });
    }

    static generateReferenceTabContent(refs, refType) {
        let content = `
            <div class="mb-2 pb-1 border-bottom">
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted fw-bold">${refType} References</small>
                    <div>
                        <span class="badge bg-secondary" style="font-size: 0.65rem;">${refs.length} refs</span>
                    </div>
                </div>
            </div>
            <div class="references-compact">
        `;
        
        refs.forEach((ref) => {
            content += `
                <div class="reference-item-compact mb-1 p-2 border rounded" style="font-size: 0.8rem;">
                    <div class="d-flex justify-content-between align-items-center">
                        <div class="reference-link-container flex-grow-1 me-2">
                            <a href="${ref.url}" target="_blank" class="reference-link-compact" title="${ref.url}">
                                ${ref.url.length > 60 ? ref.url.substring(0, 60) + '...' : ref.url}
                            </a>
                        </div>
                        <div class="reference-meta-compact">
                            <span class="badge bg-dark" style="font-size: 0.65rem;">Included ${ref.count} times</span>
                        </div>
                    </div>
                </div>
            `;
        });
        
        content += '</div>';
        return content;
    }

    static createGenericDataModal(config = {}) {
        const defaultConfig = {
            modalType: 'genericData',
            title: 'Data View',
            icon: '📊',
            headerColor: '#0d6efd',
            enableTabs: false,
            generateBodyContent: (data, displayValue) => {
                if (typeof data === 'object') {
                    return `<pre class="language-json">${JSON.stringify(data, null, 2)}</pre>`;
                }
                return `<div class="p-3">${data}</div>`;
            }
        };

        return new BadgeModal({ ...defaultConfig, ...config });
    }

    static createSortingPriorityModal() {
        return new BadgeModal({
            modalType: 'sortingPriority',
            title: 'Sorting Priority Context',
            icon: '📈',
            headerColor: '#6c757d', // Bootstrap secondary gray for informational content
            enableTabs: true,
            generateHeaderContent: (displayValue, additionalData) => {
                const searchCount = additionalData.searchCount || 0;
                const versionCount = additionalData.versionCount || 0;
                const statisticsCount = additionalData.statisticsCount || 0;
                const isConfirmedMapping = additionalData.isConfirmedMapping || false;
                
                return `
                    <div class="cpe-info-fixed">
                        <div class="cpe-string-compact mb-1">
                            <code class="text-white bg-dark px-2 py-1 rounded" style="font-size: 0.75rem;">${displayValue}</code>
                        </div>
                        <div class="summary-stats-compact">
                            ${isConfirmedMapping ? '<span class="badge bg-success ms-1" style="font-size: 0.6rem;">✓ CONFIRMED</span>' : ''}
                            <span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">🔍 ${searchCount} Matched CPE Base String Searches</span>
                            <span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">📋 ${versionCount} version matches</span>
                            ${statisticsCount > 0 ? `<span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">📊 ${statisticsCount} CPE Names Found</span>` : ''}
                        </div>
                    </div>
                `;
            },
            generateTabsData: (data, displayValue, additionalData) => {
                console.log('SortingPriority generateTabsData called with data:', data);
                console.log('data.confirmedMapping:', data.confirmedMapping);
                
                const tabs = [];
                
                // Confirmed Mapping tab (highest priority - first)
                if (data.confirmedMapping) {
                    console.log('Adding confirmed mapping tab');
                    tabs.push({
                        id: 'confirmedMapping',
                        label: 'Confirmed Mapping',
                        badge: '✓',
                        content: BadgeModalFactory.generateConfirmedMappingTabContent(data.confirmedMapping, displayValue)
                    });
                } else {
                    console.log('No confirmed mapping data found in:', data);
                }
                
                // CPE Statistics tab (second priority)
                if (data.statistics) {
                    tabs.push({
                        id: 'statistics',
                        label: 'Statistics',
                        badge: data.statistics.total_cpe_names,
                        content: BadgeModalFactory.generateStatisticsTabContent(data.statistics)
                    });
                }
                
                // CPE Base String Searches tab (third priority)
                if (data.searches && Object.keys(data.searches).length > 0) {
                    tabs.push({
                        id: 'searches',
                        label: 'Relevant Searches',
                        badge: Object.keys(data.searches).length,
                        content: BadgeModalFactory.generateSearchesTabContent(data.searches)
                    });
                }
                
                // Version Matches tab (fourth priority)  
                if (data.versions && data.versions.length > 0) {
                    tabs.push({
                        id: 'versions',
                        label: 'Version Matches',
                        badge: data.versions.length,
                        content: BadgeModalFactory.generateVersionsTabContent(data.versions)
                    });
                }
                
                return tabs;
            },
            customCSS: `
                .sorting-item {
                    background-color: #f8f9fa;
                    border: 1px solid #e9ecef !important;
                    font-size: 0.75rem;
                    transition: all 0.2s ease;
                    margin-bottom: 0.25rem !important;
                    padding: 0.375rem 0.5rem !important;
                }

                .sorting-item:hover {
                    background-color: #e9ecef;
                    border-color: #6c757d !important;
                    transform: translateY(-1px);
                }

                .search-key {
                    color: #495057;
                    font-weight: 600;
                    font-size: 0.75rem;
                }

                .search-value {
                    color: #6c757d;
                    font-size: 0.7rem;
                    font-family: 'Courier New', monospace;
                }

                .version-key {
                    color: #495057;
                    font-weight: 600;
                    font-size: 0.75rem;
                }

                .version-value {
                    color: #6c757d;
                    font-size: 0.7rem;
                }

                .priority-indicator {
                    background-color: #6c757d;
                    color: white;
                    font-size: 0.6rem;
                    padding: 0.1rem 0.3rem;
                    border-radius: 0.25rem;
                    font-weight: bold;
                }
            `
        });
    }

    static generateSearchesTabContent(searches) {
        let content = `
            <div class="mb-2 pb-1 border-bottom">
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted fw-bold">Matched CPE Base String Searches</small>
                    <div>
                        <span class="badge bg-secondary" style="font-size: 0.65rem;">${Object.keys(searches).length} searches</span>
                    </div>
                </div>
            </div>
            <div class="searches-compact">
        `;
        
        // Define search priority order
        const searchPriority = {
            'searchSourcecveAffectedCPEsArray': 1,
            'searchSourcepartvendorproduct': 2, 
            'searchSourcevendorproduct': 3,
            'searchSourceproduct': 4,
            'searchSourcevendor': 5
        };
        
        // Sort searches by priority
        const sortedSearches = Object.entries(searches).sort((a, b) => {
            const aPriority = searchPriority[a[0]] || 999;
            const bPriority = searchPriority[b[0]] || 999;
            return aPriority - bPriority;
        });
        
        sortedSearches.forEach(([searchKey, searchValue], index) => {
            const priority = searchPriority[searchKey] || 999;
            
            // Clean up the search key for display and emphasize search type
            const displayKey = searchKey.replace('searchSource', '').replace(/([A-Z])/g, ' $1').trim();
            
            content += `
                <div class="sorting-item mb-1 p-2 border rounded" style="font-size: 0.8rem;">
                    <div class="d-flex align-items-center justify-content-between">
                        <div class="cpe-name-section me-3" style="flex: 1;">
                            <div class="search-value" style="font-family: 'Courier New', monospace; font-size: 0.7rem; color: #495057; font-weight: 600;">${searchValue}</div>
                        </div>
                        <div class="search-type-section">
                            <span class="badge bg-secondary" style="font-size: 0.7rem; color: white;">${displayKey}</span>
                        </div>
                    </div>
                </div>
            `;
        });
        
        content += '</div>';
        return content;
    }

    static generateVersionsTabContent(versions) {
        let content = `
            <div class="mb-2 pb-1 border-bottom">
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted fw-bold">Version Match Details</small>
                    <div>
                        <span class="badge bg-secondary" style="font-size: 0.65rem;">${versions.length} matches</span>
                    </div>
                </div>
            </div>
            <div class="versions-compact">
        `;
        
        versions.forEach((version, index) => {
            // Find the CPE name in the version object (usually the longest value or one containing "cpe:")
            let cpeName = '';
            let versionType = '';
            let otherFields = {};
            
            Object.entries(version).forEach(([key, value]) => {
                if (value && typeof value === 'string' && value.includes('cpe:')) {
                    cpeName = value;
                } else if (['version', 'lessThan', 'lessThanOrEqual', 'greaterThan', 'greaterThanOrEqual'].includes(key)) {
                    versionType = key;
                } else {
                    otherFields[key] = value;
                }
            });
            
            content += `
                <div class="sorting-item mb-2 p-2 border rounded" style="font-size: 0.8rem;">
                    <div class="d-flex align-items-center justify-content-between">
                        <div class="cpe-name-section me-3" style="min-width: 300px;">
                            <div class="version-value" style="font-family: 'Courier New', monospace; font-size: 0.7rem; color: #495057; font-weight: 600;">${cpeName}</div>
                        </div>
                        <div class="version-type-section">
                            ${versionType ? `<span class="badge bg-success" style="font-size: 0.7rem;">${versionType}</span>` : ''}
                        </div>
                    </div>
            `;
            
            // Display other fields if any
            if (Object.keys(otherFields).length > 0) {
                content += `
                    <div class="additional-fields mt-1 pt-1 border-top" style="border-color: #e9ecef !important;">
                `;
                Object.entries(otherFields).forEach(([key, value]) => {
                    if (value) {
                        content += `
                            <div class="d-flex justify-content-between align-items-center mb-1">
                                <span class="version-key" style="font-size: 0.7rem; color: #6c757d;">${key}:</span>
                                <span class="version-value" style="font-size: 0.7rem; color: #495057;">${value}</span>
                            </div>
                        `;
                    }
                });
                content += `</div>`;
            }
            
            content += `</div>`;
        });
        
        content += '</div>';
        return content;
    }

    static generateConfirmedMappingTabContent(mappingData, cpeBaseString) {
        let content = `
            <div class="mb-3 pb-2 border-bottom">
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted fw-bold">Confirmed CPE Base String Mapping</small>
                    <div>
                        <span class="badge bg-success" style="font-size: 0.65rem;">✓ Verified</span>
                    </div>
                </div>
            </div>
            <div class="confirmed-mapping-compact">
        `;
        
        // Main confirmation card
        content += `
            <div class="sorting-item mb-3 p-3 border rounded" style="background: linear-gradient(135deg, rgba(25, 135, 84, 0.1) 0%, rgba(25, 135, 84, 0.05) 100%); border-color: #198754 !important;">
                <div class="text-center mb-3">
                    <div class="mb-2">
                        <span class="badge bg-success" style="font-size: 1rem; padding: 0.5rem 1rem;">✓ Confirmed Mapping</span>
                    </div>
                    <small class="text-muted fw-bold">This CPE Base String has been verified as a Confirmed Mapping by CPE Moderators and (along with other Confirmed Mappings for the row) should be selected over other CPE Base Strings</small>
                </div>
                
                <div class="mapping-details">
                    <div class="mb-2">
                        <div class="text-center p-2 rounded" style="background-color: rgba(25, 135, 84, 0.1); border: 1px solid rgba(25, 135, 84, 0.3);">
                            <div class="fw-bold text-success mb-1" style="font-size: 0.9rem;">CPE Base String</div>
                            <code class="bg-dark text-white px-2 py-1 rounded" style="font-size: 0.75rem;">${cpeBaseString}</code>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        content += '</div>';
        return content;
    }

    static generateStatisticsTabContent(statistics) {
        let content = `
            <div class="mb-3 pb-2 border-bottom">
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted fw-bold">CPE Base String --> CPE Name Matches</small>
                    <div>
                        <span class="badge bg-secondary" style="font-size: 0.65rem;">${statistics.total_cpe_names} entries</span>
                    </div>
                </div>
            </div>
            <div class="statistics-compact">
        `;
        
        // Main statistics overview card
        content += `
            <div class="sorting-item mb-3 p-3 border rounded" style="background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-color: #6c757d !important;">
                <div class="text-center mb-3">
                    <h4 class="mb-1 text-secondary">${statistics.total_cpe_names}</h4>
                    <small class="text-muted fw-bold">Total CPE Names Found</small>
                </div>
                
                <div class="row g-3">
                    <div class="col-6">
                        <div class="text-center p-2 rounded" style="background-color: rgba(25, 135, 84, 0.1); border: 1px solid rgba(25, 135, 84, 0.3);">
                            <div class="fw-bold text-success mb-1" style="font-size: 1.1rem;">${statistics.final_count}</div>
                            <div class="text-success" style="font-size: 0.8rem; font-weight: 600;">Final (Active)</div>
                            <small class="text-muted d-block mt-1">Currently Relevant CPE Names</small>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="text-center p-2 rounded" style="background-color: rgba(255, 193, 7, 0.1); border: 1px solid rgba(255, 193, 7, 0.3);">
                            <div class="fw-bold text-warning mb-1" style="font-size: 1.1rem;">${statistics.deprecated_count}</div>
                            <div class="text-warning" style="font-size: 0.8rem; font-weight: 600;">Deprecated</div>
                            <small class="text-muted d-block mt-1">Legacy/Obsolete CPE Names</small>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Distribution analysis if there are multiple types
        if (statistics.total_cpe_names > 0) {
            const finalPercentage = Math.round((statistics.final_count / statistics.total_cpe_names) * 100);
            const deprecatedPercentage = Math.round((statistics.deprecated_count / statistics.total_cpe_names) * 100);
            
            content += `
                <div class="sorting-item p-2 border rounded" style="background-color: #f8f9fa;">
                    <div class="row align-items-center">
                        <div class="col-4">
                            <small class="text-muted fw-bold">Distribution Analysis</small>
                        </div>
                        <div class="col-5">
                            <div class="d-flex rounded overflow-hidden" style="height: 8px; background-color: #e9ecef;">
                                <div class="bg-success" style="width: ${finalPercentage}%;"></div>
                                <div class="bg-warning" style="width: ${deprecatedPercentage}%;"></div>
                            </div>
                        </div>
                        <div class="col-3">
                            <div class="d-flex justify-content-end gap-2">
                                <span style="font-size: 0.7rem; color: #198754;">●${finalPercentage}%</span>
                                <span style="font-size: 0.7rem; color: #ffc107;">●${deprecatedPercentage}%</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        content += '</div>';
        return content;
    }

}

/**
 * Clean modal management - no global functions, no fallbacks
 * HTML should call BadgeModalFactory.openReferencesModal() directly
 */

// Initialize global storage
window.BADGE_MODAL_DATA = window.BADGE_MODAL_DATA || {};

// Clean factory method for opening reference modals
class BadgeModalManager {
    static openReferencesModal(baseKeySafe, cpeBaseString, totalCount) {
        const modal = BadgeModalFactory.createReferencesModal();
        
        // Fail fast if no references data is registered at all
        if (!window.BADGE_MODAL_DATA.references) {
            throw new Error('No reference data registered - ensure BadgeModal.registerData("references", ...) calls have executed');
        }
        
        const registeredData = window.BADGE_MODAL_DATA.references[baseKeySafe]; // No optional chaining - fail fast
        if (!registeredData) {
            throw new Error(`No reference data registered for key '${baseKeySafe}' - check BadgeModal.registerData() calls`);
        }
        
        const typeCount = Object.keys(registeredData).length; // Will throw if data is malformed
        
        modal.show(baseKeySafe, cpeBaseString, { totalCount, typeCount });
    }

    static openSortingPriorityModal(baseKeySafe, cpeBaseString, focusTab = 'statistics') {
        const modal = BadgeModalFactory.createSortingPriorityModal();
        
        // Fail fast if no sorting priority data is registered at all
        if (!window.BADGE_MODAL_DATA.sortingPriority) {
            throw new Error('No sorting priority data registered - ensure BadgeModal.registerData("sortingPriority", ...) calls have executed');
        }
        
        const registeredData = window.BADGE_MODAL_DATA.sortingPriority[baseKeySafe]; // No optional chaining - fail fast
        if (!registeredData) {
            throw new Error(`No sorting priority data registered for key '${baseKeySafe}' - check BadgeModal.registerData() calls`);
        }
        
        // Calculate counts for header display
        const searchCount = registeredData.searches ? Object.keys(registeredData.searches).length : 0;
        const versionCount = registeredData.versions ? registeredData.versions.length : 0;
        const statisticsCount = registeredData.statistics ? registeredData.statistics.total_cpe_names : 0;
        const isConfirmedMapping = !!registeredData.confirmedMapping;
        
        // Calculate dynamic tab count to update the badge
        let dynamicTabCount = 0;
        if (isConfirmedMapping) dynamicTabCount++;
        if (registeredData.statistics) dynamicTabCount++;
        if (registeredData.searches && Object.keys(registeredData.searches).length > 0) dynamicTabCount++;
        if (registeredData.versions && registeredData.versions.length > 0) dynamicTabCount++;
        
        // Update the badge text with correct tab count
        const badgeElements = document.querySelectorAll(`[onclick*="openSortingPriorityModal('${baseKeySafe}'"]`);
        badgeElements.forEach(badge => {
            const badgeText = badge.textContent;
            if (badgeText.includes('Sorting Priority Context')) {
                badge.textContent = `📈 Sorting Priority Context (${dynamicTabCount})`;
            }
        });
        
        // Auto-focus confirmed mapping tab if it exists and no specific focus requested
        let actualFocusTab = focusTab;
        if (isConfirmedMapping && focusTab === 'statistics') {
            actualFocusTab = 'confirmedMapping';
        }
        
        modal.show(baseKeySafe, cpeBaseString, { 
            searchCount, 
            versionCount, 
            statisticsCount, 
            isConfirmedMapping,
            focusTab: actualFocusTab 
        });
    }

    static openConfirmedMappingModal(baseKeySafe, cpeBaseString) {
        // Open the sorting priority modal with confirmed mapping tab focused
        return this.openSortingPriorityModal(baseKeySafe, cpeBaseString, 'confirmedMapping');
    }

    /**
     * Update all Sorting Priority Context badge tab counts on page load
     * This ensures that badge counts are always correct from the moment the page loads
     */
    static updateAllBadgeTabCounts() {
        console.log('🔄 Updating all badge tab counts...');
        
        // Find all Sorting Priority Context badges
        const badgeElements = document.querySelectorAll('span.badge[onclick*="openSortingPriorityModal"]');
        let updatedCount = 0;
        
        badgeElements.forEach(badge => {
            try {
                // Extract the baseKeySafe from the onclick attribute
                const onclickStr = badge.getAttribute('onclick');
                const match = onclickStr.match(/openSortingPriorityModal\(['"]([^'"]+)['"]/);
                
                if (!match) {
                    console.warn('Could not extract baseKeySafe from badge onclick:', onclickStr);
                    return;
                }
                
                const baseKeySafe = match[1];
                
                // Check if we have registered data for this key
                if (!window.BADGE_MODAL_DATA || 
                    !window.BADGE_MODAL_DATA.sortingPriority || 
                    !window.BADGE_MODAL_DATA.sortingPriority[baseKeySafe]) {
                    console.warn(`No sorting priority data registered for key '${baseKeySafe}' - skipping badge update`);
                    return;
                }
                
                const registeredData = window.BADGE_MODAL_DATA.sortingPriority[baseKeySafe];
                
                // Calculate dynamic tab count using the same logic as openSortingPriorityModal
                let dynamicTabCount = 0;
                const isConfirmedMapping = !!registeredData.confirmedMapping;
                
                if (isConfirmedMapping) dynamicTabCount++;
                if (registeredData.statistics) dynamicTabCount++;
                if (registeredData.searches && Object.keys(registeredData.searches).length > 0) dynamicTabCount++;
                if (registeredData.versions && registeredData.versions.length > 0) dynamicTabCount++;
                
                // Update the badge text with correct tab count
                const badgeText = badge.textContent;
                if (badgeText.includes('Sorting Priority Context')) {
                    const newText = `📈 Sorting Priority Context (${dynamicTabCount})`;
                    if (badge.textContent !== newText) {
                        badge.textContent = newText;
                        updatedCount++;
                        console.log(`✓ Updated badge for ${baseKeySafe}: ${dynamicTabCount} tabs`);
                    }
                }
                
            } catch (error) {
                console.error('Error updating badge tab count:', error);
            }
        });
        
        console.log(`✅ Badge tab count update complete: ${updatedCount} badges updated out of ${badgeElements.length} found`);
    }

    /**
     * Initialize badge updates when the page loads
     * This ensures all badge counts are correct from the start
     */
    static initializeBadgeUpdates() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                // Add a small delay to ensure all data registration is complete
                setTimeout(() => {
                    BadgeModalManager.updateAllBadgeTabCounts();
                }, 100);
            });
        } else {
            // DOM is already ready, update immediately with a small delay
            setTimeout(() => {
                BadgeModalManager.updateAllBadgeTabCounts();
            }, 100);
        }
    }
}

// Export the manager
window.BadgeModalManager = BadgeModalManager;

// Initialize badge updates on page load
BadgeModalManager.initializeBadgeUpdates();

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { BadgeModal, BadgeModalFactory };
}
