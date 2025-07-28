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
            }
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
                <div class="modal-item-base modal-item-secondary reference-item-compact mb-1 p-2 border rounded" style="font-size: 0.8rem;">
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
            }
        });
    }

    static createWildcardGenerationModal() {
        return new BadgeModal({
            modalType: 'jsonGenerationRules',
            title: 'JSON Generation Rules - Platform Processing',
            icon: '⚙️',
            headerColor: '#ffc107', // Bootstrap warning yellow for JSON generation rules
            enableTabs: true,
            generateHeaderContent: (displayValue, additionalData) => {
                const ruleCount = additionalData.ruleCount || 0;
                const ruleTypes = additionalData.ruleTypes || [];
                
                return `
                    <div class="json-rules-info-fixed">
                        <div class="platform-string-compact mb-1">
                            <code class="text-dark bg-light px-2 py-1 rounded" style="font-size: 0.75rem;">${displayValue}</code>
                        </div>
                        <div class="summary-stats-compact">
                            <span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">⚙️ ${ruleCount} rules</span>
                            <span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">🏷️ ${ruleTypes.length} types</span>
                        </div>
                    </div>
                `;
            },
            generateTabsData: (data, displayValue, additionalData) => {
                const tabs = [];
                
                // Add Wildcard Generation Rules tab
                if (data.wildcardGeneration && data.wildcardGeneration.transformations) {
                    tabs.push({
                        id: 'wildcard',
                        label: 'Wildcard Generation',
                        badge: data.wildcardGeneration.transformations.length,
                        content: BadgeModalFactory.generateWildcardRulesTabContent(data.wildcardGeneration)
                    });
                }
                
                // Add placeholder tabs for other rule types (future expansion)
                if (data.updatePatterns) {
                    tabs.push({
                        id: 'updatepatterns',
                        label: 'Update Patterns',
                        badge: data.updatePatterns.rules ? data.updatePatterns.rules.length : 0,
                        content: BadgeModalFactory.generateUpdatePatternsTabContent(data.updatePatterns)
                    });
                }
                
                if (data.versionRanges) {
                    tabs.push({
                        id: 'versionranges',
                        label: 'Version Ranges',
                        badge: data.versionRanges.rules ? data.versionRanges.rules.length : 0,
                        content: BadgeModalFactory.generateVersionRangesTabContent(data.versionRanges)
                    });
                }
                
                return tabs;
            }
        });
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
            <div class="modal-item-base modal-item-secondary sorting-item mb-3 p-3 border rounded" style="background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-color: #6c757d !important;">
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
                <div class="modal-item-base modal-item-secondary sorting-item p-2 border rounded" style="background-color: #f8f9fa;">
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

    static generateWildcardRulesTabContent(wildcardData) {
        let content = `
            <div class="mb-3 pb-2 border-bottom">
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted fw-bold">Wildcard Pattern Processing - Complete Context</small>
                    <div>
                        <span class="badge bg-warning" style="font-size: 0.65rem;">🔄 ${wildcardData.transformations.length} transformations</span>
                    </div>
                </div>
            </div>
            <div class="wildcard-rules-compact">
        `;
        
        // Overview section - condensed
        content += `
            <div class="modal-item-base modal-item-warning wildcard-item mb-2 p-2">
                <div class="overview-header mb-2 text-center">
                    <small class="text-dark fw-bold">These rules convert wildcard patterns into precise CPE match object version ranges.</small>
                </div>
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted"><strong>Patterns:</strong> ${wildcardData.summary ? wildcardData.summary.total_patterns : wildcardData.transformations.length}</small>
                    <small class="text-muted"><strong>Fields:</strong> ${wildcardData.summary ? wildcardData.summary.fields_affected.length : 1}</small>
                </div>
            </div>
        `;
        
        // Show transformation rules
        content += `
            <div class="transformations-section">
        `;
        
        wildcardData.transformations.forEach((transformation, index) => {
            const inputJson = this.formatJsonWithoutBrackets(transformation.input);
            const outputJson = this.formatJsonWithoutBrackets(transformation.output);
            
            content += `
                <div class="modal-item-base modal-item-warning wildcard-item mb-3">
                    <div class="transformation-header mb-2">
                        <div class="d-flex justify-content-between align-items-center">
                            <small class="fw-bold text-warning">Entry ${index + 1}: ${transformation.derivation_desc || transformation.field_display}</small>
                            <span class="badge bg-warning text-dark" style="font-size: 0.6rem;">${transformation.field}</span>
                        </div>
                    </div>
                    
                    <div class="transformation-content">
                        <div class="row">
                            <div class="col-5">
                                <div class="mb-1">
                                    <small class="fw-bold text-muted">INPUT (Platform JSON):</small>
                                </div>
                                <div class="json-input">
                                    ${inputJson}
                                </div>
                            </div>
                            <div class="col-2 d-flex align-items-center">
                                <div class="transformation-arrow w-100 text-center">
                                    <div class="transformation-icon-medium">→</div>
                                </div>
                            </div>
                            <div class="col-5">
                                <div class="mb-1">
                                    <small class="fw-bold text-success">OUTPUT (CPE Match Object):</small>
                                </div>
                                <div class="json-output">
                                    ${outputJson}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        
        content += '</div></div>';
        return content;
    }

    static formatJsonForDisplay(obj) {
        if (!obj) return 'null';
        
        // Clean JSON formatting without outer brackets for simple objects
        const jsonStr = JSON.stringify(obj, null, 2);
        
        // For simple objects, remove the outer braces and adjust indentation
        if (typeof obj === 'object' && !Array.isArray(obj) && Object.keys(obj).length <= 4) {
            const lines = jsonStr.split('\n');
            if (lines.length <= 6) { // Simple object
                const innerContent = lines.slice(1, -1).map(line => line.substring(2)).join('\n');
                return innerContent || jsonStr;
            }
        }
        
        return jsonStr;
    }

    static formatJsonWithoutBrackets(obj) {
        if (!obj) return 'null';
        
        const jsonStr = JSON.stringify(obj, null, 2);
        
        // Remove outer braces and adjust indentation for all objects
        if (typeof obj === 'object' && !Array.isArray(obj)) {
            const lines = jsonStr.split('\n');
            if (lines.length > 2) {
                const innerContent = lines.slice(1, -1).map(line => line.substring(2)).join('\n');
                return innerContent;
            }
        }
        
        return jsonStr;
    }

    static generateConfirmedMappingTabContent(mappingData, cpeBaseString) {
        let content = `
            <div class="mb-3 pb-2 border-bottom">
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted fw-bold">Confirmed CPE Base String Mapping</small>
                    <div>
                        <span class="badge bg-success badge-verified">✓ Verified</span>
                    </div>
                </div>
            </div>
            <div class="confirmed-mapping-compact">
        `;
        
        // Main confirmation card
        content += `
            <div class="modal-item-base modal-item-secondary sorting-item mb-3 p-3 border rounded">
                <div class="text-center mb-3">
                    <div class="mb-2">
                        <span class="badge bg-success confirmed-mapping-badge">✓ Confirmed Mapping</span>
                    </div>
                    <small class="text-muted fw-bold">This CPE Base String has been verified as a Confirmed Mapping by CPE Moderators and (along with other Confirmed Mappings for the row) should be selected over other CPE Base Strings</small>
                </div>
                
                <div class="mapping-details">
                    <div class="mb-2">
                        <div class="text-center p-2 rounded confirmed-mapping-card">
                            <div class="fw-bold text-success mb-1 cpe-base-string-display">CPE Base String</div>
                            <code class="bg-dark text-white px-2 py-1 rounded cpe-code">${cpeBaseString}</code>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        content += '</div>';
        return content;
    }

    static generateSearchesTabContent(searches) {
        let content = `
            <div class="mb-2 pb-1 border-bottom">
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted fw-bold">Matched CPE Base String Searches</small>
                    <div>
                        <span class="badge bg-secondary badge-count">${Object.keys(searches).length} searches</span>
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
                <div class="modal-item-base modal-item-secondary sorting-item mb-1 p-2 border rounded">
                    <div class="d-flex align-items-center justify-content-between">
                        <div class="cpe-name-section me-3">
                            <div class="search-value">${searchValue}</div>
                        </div>
                        <div class="search-type-section">
                            <span class="badge bg-secondary search-type-badge">${displayKey}</span>
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
                        <span class="badge bg-secondary badge-count">${versions.length} matches</span>
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
                <div class="modal-item-base modal-item-secondary sorting-item mb-2 p-2 border rounded">
                    <div class="d-flex align-items-center justify-content-between">
                        <div class="cpe-name-section-version me-3">
                            <div class="version-value">${cpeName}</div>
                        </div>
                        <div class="version-type-section">
                            ${versionType ? `<span class="badge bg-success version-type-badge">${versionType}</span>` : ''}
                        </div>
                    </div>
            `;
            
            // Display other fields if any
            if (Object.keys(otherFields).length > 0) {
                content += `
                    <div class="additional-fields mt-1 pt-1 border-top">
                `;
                Object.entries(otherFields).forEach(([key, value]) => {
                    if (value) {
                        content += `
                            <div class="d-flex justify-content-between align-items-center mb-1">
                                <span class="version-key">${key}:</span>
                                <span class="version-field-value">${value}</span>
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

    static generateUpdatePatternsTabContent(updatePatternsData) {
        if (!updatePatternsData || !updatePatternsData.transformations || updatePatternsData.transformations.length === 0) {
            return `
                <div class="update-patterns-content p-3">
                    <div class="text-center text-muted">
                        <h6>🔄 Update Patterns Rules</h6>
                        <p>No update pattern transformations available for this entry.</p>
                    </div>
                </div>
            `;
        }

        let content = `
            <div class="mb-3 pb-2 border-bottom">
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted fw-bold">Update Pattern Processing - Complete Context</small>
                    <div>
                        <span class="badge bg-warning badge-count">🔄 ${updatePatternsData.transformations.length} transformations</span>
                    </div>
                </div>
            </div>
            <div class="update-patterns-compact">
        `;
        
        // Overview section
        content += `
            <div class="modal-item-base modal-item-warning update-pattern-item mb-2 p-2">
                <div class="overview-header mb-2 text-center">
                    <small class="text-dark fw-bold">These rules detect version update patterns and split them into base versions and update components.</small>
                </div>
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted"><strong>Transformations:</strong> ${updatePatternsData.transformations.length}</small>
                    <small class="text-muted"><strong>Pattern Types:</strong> ${updatePatternsData.pattern_types ? updatePatternsData.pattern_types.length : 1}</small>
                </div>
            </div>
        `;
        
        // Show transformation rules
        content += `
            <div class="transformations-section">
        `;
        
        updatePatternsData.transformations.forEach((transformation, index) => {
            const inputJson = BadgeModalFactory.formatJsonWithoutBrackets(transformation.input);
            
            // Format output as "base_version   :   update_component"
            const baseVersion = transformation.output.version || '';
            const updateComponent = transformation.output.update || '';
            const outputAttributes = `${baseVersion}   :   ${updateComponent}`;
            
            // Add blocked by ranges warning if applicable
            let warningText = '';
            if (transformation.blocked_by_ranges) {
                warningText = '<div class="alert alert-warning p-2 mb-2" style="font-size: 0.75rem;"><strong>⚠️ Note:</strong> Version ranges detected - Update pattern rules may not be applied in final JSON generation.</div>';
            }
            
            content += `
                <div class="modal-item-base modal-item-warning update-pattern-item mb-3">
                    <div class="transformation-header mb-2">
                        <div class="d-flex justify-content-between align-items-center">
                            <small class="fw-bold text-warning">Entry ${index + 1}: ${transformation.field_display}</small>
                            <span class="badge bg-warning text-dark" style="font-size: 0.6rem;">${transformation.pattern_type || 'update'}</span>
                        </div>
                    </div>
                    
                    ${warningText}
                    
                    <div class="transformation-content">
                        <div class="row">
                            <div class="col-5">
                                <div class="mb-1">
                                    <small class="fw-bold text-muted">INPUT (Original Version):</small>
                                </div>
                                <div class="json-input">
                                    ${inputJson}
                                </div>
                            </div>
                            <div class="col-2 d-flex align-items-center">
                                <div class="transformation-arrow w-100">→</div>
                            </div>
                            <div class="col-5">
                                <div class="mb-1">
                                    <small class="fw-bold text-success">Resulting Attributes (Version : Update):</small>
                                </div>
                                <div class="json-output">
                                    ${outputAttributes}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        
        content += '</div></div>';
        return content;
    }

    static generateVersionRangesTabContent(versionRangesData) {
        return `
            <div class="version-ranges-content p-3">
                <div class="text-center text-muted">
                    <h6>📊 Version Ranges Rules</h6>
                    <p>Version range processing rules will be displayed here when implemented.</p>
                    <small>This tab is reserved for future version range transformation rules.</small>
                </div>
            </div>
        `;
    }



    static createJsonGenerationRulesModal() {
        return new BadgeModal({
            modalType: 'jsonGenerationRules',
            title: 'JSON Generation Rules',
            icon: '⚙️',
            headerColor: '#ffc107',
            enableTabs: true,
            generateHeaderContent: (displayValue, additionalData) => {
                const ruleCount = additionalData.ruleCount || 0;
                const ruleTypes = additionalData.ruleTypes || [];
                
                return `
                    <div class="json-rules-info-fixed">
                        <div class="platform-string-compact mb-1">
                            <code class="text-white bg-dark px-2 py-1 rounded" style="font-size: 0.75rem;">${displayValue}</code>
                        </div>
                        <div class="summary-stats-compact">
                            <span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">⚙️ ${ruleCount} rules</span>
                            <span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">🏷️ ${ruleTypes.length} types</span>
                        </div>
                    </div>
                `;
            },
            generateTabsData: (data, displayValue, additionalData) => {
                const tabs = [];
                
                // Create tabs for each rule type in the data
                if (data.rules && Array.isArray(data.rules)) {
                    data.rules.forEach(rule => {
                        // Format the rule type for display
                        const displayType = rule.type === 'updatePatterns' ? 'Update Patterns' : rule.type;
                        
                        tabs.push({
                            id: rule.type.toLowerCase().replace(/[^a-z0-9]/g, ''),
                            label: displayType,
                            badge: rule.transformations ? rule.transformations.length : 0,
                            content: BadgeModalFactory.generateJsonRuleTabContent(rule)
                        });
                    });
                }
                
                // Add summary tab if there's multiple rule types
                if (data.summary && tabs.length > 1) {
                    tabs.unshift({
                        id: 'summary',
                        label: 'Summary',
                        badge: data.summary.total_rules,
                        content: BadgeModalFactory.generateJsonRuleSummaryTabContent(data.summary)
                    });
                }
                
                return tabs;
            }
        });
    }

    static generateJsonRuleTabContent(rule) {
        // Format the rule type for display
        const displayType = rule.type === 'updatePatterns' ? 'Update Patterns' : rule.type;
        
        // For Update Patterns, use the special formatting
        if (rule.type === 'updatePatterns') {
            // Calculate unique pattern types from transformations
            const uniquePatternTypes = [...new Set(rule.transformations.map(t => t.pattern_type).filter(Boolean))];
            
            return BadgeModalFactory.generateUpdatePatternsTabContent({
                transformations: rule.transformations,
                pattern_types: uniquePatternTypes
            });
        }
        
        let content = `
            <div class="mb-2 pb-1 border-bottom">
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted fw-bold">${displayType} Rule Transformations</small>
                    <div>
                        <span class="badge bg-warning" style="font-size: 0.65rem;">${rule.transformations ? rule.transformations.length : 0} transformations</span>
                    </div>
                </div>
            </div>
        `;
        
        if (rule.description) {
            content += `
                <div class="rule-description mb-3 p-2 bg-light border-start border-warning border-3">
                    <small class="text-muted">${rule.description}</small>
                </div>
            `;
        }
        
        content += '<div class="json-transformations-compact">';
        
        if (rule.transformations && Array.isArray(rule.transformations)) {
            rule.transformations.forEach((transformation, index) => {
                const inputJson = JSON.stringify(transformation.input, null, 2);
                const outputJson = JSON.stringify(transformation.output, null, 2);
                
                content += `
                    <div class="json-rule-item-compact mb-3">
                        <div class="transformation-header mb-2">
                            <div class="d-flex justify-content-between align-items-center">
                                <small class="fw-bold text-warning">Transformation ${index + 1}</small>
                                <span class="badge bg-warning text-dark" style="font-size: 0.6rem;">${displayType}</span>
                            </div>
                        </div>
                        
                        <div class="transformation-content">
                            <div class="row">
                                <div class="col-5">
                                    <div class="mb-1">
                                        <small class="fw-bold text-muted">INPUT:</small>
                                    </div>
                                    <div class="json-input">
                                        ${inputJson}
                                    </div>
                                </div>
                                <div class="col-2 d-flex align-items-center">
                                    <div class="transformation-arrow w-100">→</div>
                                </div>
                                <div class="col-5">
                                    <div class="mb-1">
                                        <small class="fw-bold text-success">OUTPUT:</small>
                                    </div>
                                    <div class="json-output">
                                        ${outputJson}
                                    </div>
                                </div>
                            </div>
                            
                            ${transformation.explanation ? `
                                <div class="explanation-text mt-2">
                                    <strong>Rule Logic:</strong> ${transformation.explanation}
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
            });
        } else {
            content += `
                <div class="text-muted text-center py-3">
                    <em>No transformations available for this rule type.</em>
                </div>
            `;
        }
        
        content += '</div>';
        return content;
    }

    static generateJsonRuleSummaryTabContent(summary) {
        let content = `
            <div class="mb-3 pb-2 border-bottom">
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted fw-bold">JSON Generation Rules Summary</small>
                    <div>
                        <span class="badge bg-warning" style="font-size: 0.65rem;">${summary.total_rules} total rules</span>
                    </div>
                </div>
            </div>
        `;
        
        content += '<div class="summary-content">';
        
        if (summary.rule_types && Array.isArray(summary.rule_types)) {
            content += `
                <div class="mb-3">
                    <h6 class="text-warning">Rule Types Detected:</h6>
                    <div class="rule-types-list">
            `;
            
            summary.rule_types.forEach(ruleType => {
                content += `
                    <span class="badge bg-warning text-dark me-1 mb-1" style="font-size: 0.75rem;">⚙️ ${ruleType}</span>
                `;
            });
            
            content += `
                    </div>
                </div>
            `;
        }
        
        if (summary.description) {
            content += `
                <div class="summary-description p-3 bg-light border border-warning rounded">
                    <small class="text-muted">${summary.description}</small>
                </div>
            `;
        }
        
        content += '</div>';
        return content;
    }

    static createSourceDataConcernsModal() {
        return new BadgeModal({
            modalType: 'sourceDataConcerns',
            title: 'Source Data Concerns',
            icon: '🟪',
            headerColor: '#9C27B0', // Material Design purple that fits with other modal colors
            enableTabs: true,
            generateHeaderContent: (displayValue, additionalData) => {
                const issueCount = additionalData.issueCount || 0;
                const concernTypes = additionalData.concernTypes || [];
                
                return `
                    <div class="source-concerns-info-fixed">
                        <div class="platform-string-compact mb-1">
                            <code class="text-white bg-dark px-2 py-1 rounded" style="font-size: 0.75rem;">${displayValue}</code>
                        </div>
                        <div class="summary-stats-compact">
                            <span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">⚠️ ${issueCount} issues</span>
                            <span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">🔍 ${concernTypes.length} types</span>
                            <span class="badge bg-warning text-dark ms-1" style="font-size: 0.6rem;">LINT Analysis</span>
                        </div>
                    </div>
                `;
            },
            generateTabsData: (data, displayValue, additionalData) => {
                const tabs = [];
                
                // Extract concerns from the data structure and source role from additional data
                const concernsData = data.concerns || {};
                const sourceRole = additionalData?.sourceRole || 'Unknown Source';
                
                // Generate tabs based on the concern types present in data
                if (concernsData.placeholderData && concernsData.placeholderData.length > 0) {
                    tabs.push({
                        id: 'placeholderData',
                        label: 'Placeholder Data Detected',
                        badge: concernsData.placeholderData.length,
                        content: BadgeModalFactory.generateSourceDataConcernTabContent(concernsData.placeholderData, 'placeholderData', sourceRole)
                    });
                }
                
                if (concernsData.versionTextPatterns && concernsData.versionTextPatterns.length > 0) {
                    tabs.push({
                        id: 'versionTextPatterns',
                        label: 'Version Text Patterns',
                        badge: concernsData.versionTextPatterns.length,
                        content: BadgeModalFactory.generateSourceDataConcernTabContent(concernsData.versionTextPatterns, 'versionTextPatterns', sourceRole)
                    });
                }
                
                if (concernsData.versionComparators && concernsData.versionComparators.length > 0) {
                    tabs.push({
                        id: 'versionComparators',
                        label: 'Comparator Patterns',
                        badge: concernsData.versionComparators.length,
                        content: BadgeModalFactory.generateSourceDataConcernTabContent(concernsData.versionComparators, 'versionComparators', sourceRole)
                    });
                }
                
                if (concernsData.versionGranularity && concernsData.versionGranularity.length > 0) {
                    tabs.push({
                        id: 'versionGranularity',
                        label: 'Version Granularity',
                        badge: concernsData.versionGranularity.length,
                        content: BadgeModalFactory.generateSourceDataConcernTabContent(concernsData.versionGranularity, 'versionGranularity', sourceRole)
                    });
                }
                
                if (concernsData.wildcardBranches && concernsData.wildcardBranches.length > 0) {
                    tabs.push({
                        id: 'wildcardBranches',
                        label: 'Wildcard Branches',
                        badge: concernsData.wildcardBranches.length,
                        content: BadgeModalFactory.generateSourceDataConcernTabContent(concernsData.wildcardBranches, 'wildcardBranches', sourceRole)
                    });
                }
                
                if (concernsData.cpeArrayConcerns && concernsData.cpeArrayConcerns.length > 0) {
                    tabs.push({
                        id: 'cpeArrayConcerns',
                        label: 'CPE Array Issues',
                        badge: concernsData.cpeArrayConcerns.length,
                        content: BadgeModalFactory.generateSourceDataConcernTabContent(concernsData.cpeArrayConcerns, 'cpeArrayConcerns', sourceRole)
                    });
                }
                
                if (concernsData.duplicateEntries && concernsData.duplicateEntries.length > 0) {
                    tabs.push({
                        id: 'duplicateEntries',
                        label: 'Duplicate Entries',
                        badge: concernsData.duplicateEntries.length,
                        content: BadgeModalFactory.generateSourceDataConcernTabContent(concernsData.duplicateEntries, 'duplicateEntries', sourceRole)
                    });
                }
                
                if (concernsData.platformDataConcerns && concernsData.platformDataConcerns.length > 0) {
                    tabs.push({
                        id: 'platformDataConcerns',
                        label: 'Platform Data Issues',
                        badge: concernsData.platformDataConcerns.length,
                        content: BadgeModalFactory.generateSourceDataConcernTabContent(concernsData.platformDataConcerns, 'platformDataConcerns', sourceRole)
                    });
                }
                
                if (concernsData.missingAffectedProducts && concernsData.missingAffectedProducts.length > 0) {
                    tabs.push({
                        id: 'missingAffectedProducts',
                        label: 'Missing Affected Products',
                        badge: concernsData.missingAffectedProducts.length,
                        content: BadgeModalFactory.generateSourceDataConcernTabContent(concernsData.missingAffectedProducts, 'missingAffectedProducts', sourceRole)
                    });
                }
                
                if (concernsData.overlappingRanges && concernsData.overlappingRanges.length > 0) {
                    tabs.push({
                        id: 'overlappingRanges',
                        label: 'Overlapping Ranges',
                        badge: concernsData.overlappingRanges.length,
                        content: BadgeModalFactory.generateSourceDataConcernTabContent(concernsData.overlappingRanges, 'overlappingRanges', sourceRole)
                    });
                }
                
                return tabs;
            }
        });
    }

    static createSupportingInformationModal() {
        return new BadgeModal({
            modalType: 'supportingInformation',
            title: 'Supporting Information',
            icon: '🔍',
            headerColor: '#6c757d', // Gray theme
            enableTabs: true,
            generateHeaderContent: (displayValue, additionalData) => {
                const totalItems = additionalData.totalItems || 0;
                const categories = additionalData.categories || [];
                
                return `
                    <div class="supporting-info-fixed">
                        <div class="platform-string-compact mb-1">
                            <code class="text-white bg-dark px-2 py-1 rounded" style="font-size: 0.75rem;">${displayValue}</code>
                        </div>
                        <div class="summary-stats-compact">
                            <span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">📊 ${totalItems} items</span>
                            <span class="badge bg-light text-dark me-1" style="font-size: 0.65rem;">🏷️ ${categories.length} categories</span>
                        </div>
                    </div>
                `;
            },
            generateTabsData: (data, displayValue, additionalData) => {
                const tabs = [];
                
                // Extract table index from displayValue (e.g., "Platform Entry 1 (...)" -> 1)
                let tableIndex = null;
                const indexMatch = displayValue.match(/Platform Entry (\d+)/);
                if (indexMatch) {
                    tableIndex = indexMatch[1];
                }
                
                // Create tabs for each category in the data
                if (data.tabs && Array.isArray(data.tabs)) {
                    data.tabs.forEach(tab => {
                        tabs.push({
                            id: tab.id,
                            label: tab.title,
                            badge: tab.items ? tab.items.length : 0,
                            content: BadgeModalFactory.generateSupportingInfoTabContent(tab, tableIndex)
                        });
                    });
                }
                
                return tabs;
            }
        });
    }

    static generateSupportingInfoTabContent(tab, tableIndex = null) {
        if (!tab.items || tab.items.length === 0) {
            return '<p class="text-muted">No information available</p>';
        }

        let content = `
            <div class="supporting-info-content">
                <div class="mb-3 pb-2 border-bottom">
                    <div class="d-flex justify-content-between align-items-center">
                        <small class="text-muted fw-bold">${tab.title}</small>
                        <div>
                            <span class="badge bg-secondary" style="font-size: 0.65rem;">${tab.items.length} items</span>
                        </div>
                    </div>
                </div>
        `;

        tab.items.forEach(item => {
            content += `
                <div class="modal-item-base modal-item-secondary supporting-item mb-3 p-3 border rounded">
            `;
            
            // Special handling for CPE searches - merge header with badges
            if (item.type === 'cpe_searches') {
                content += `
                    <div class="item-header mb-3">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="mb-0 text-secondary fw-bold">CPE Base String Processing</h6>
                            <div class="search-stats">
                                <span class="badge bg-secondary me-1">${item.used_count || 0} used</span>
                                <span class="badge bg-secondary">${item.culled_count || 0} culled</span>
                            </div>
                        </div>
                        <div class="item-description">
                            <small class="text-muted">${item.details}</small>
                        </div>
                    </div>
                `;
            } else if (item.type === 'versions_structure') {
                // DYNAMIC VERSION DATA RETRIEVAL - Get actual version data from table instead of template
                let versionsArray = [];
                let entryCount = 0;
                
                if (tableIndex !== null) {
                    try {
                        // Use extractDataFromTable function to get platform-specific version data
                        const extractedData = extractDataFromTable(tableIndex);
                        if (extractedData && extractedData.rawPlatformData && extractedData.rawPlatformData.versions) {
                            versionsArray = extractedData.rawPlatformData.versions;
                            entryCount = versionsArray.length;
                        }
                    } catch (error) {
                        console.warn(`Could not extract version data for table ${tableIndex}:`, error);
                        // Fallback to template data if extraction fails
                        versionsArray = item.versions_array || [];
                        entryCount = versionsArray.length;
                    }
                } else {
                    // Fallback to template data if no tableIndex provided
                    versionsArray = item.versions_array || [];
                    entryCount = versionsArray.length;
                }
                
                // Special handling for versions - merge table directly under header (no separate content/details)
                content += `
                    <div class="item-header mb-3">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="mb-0 text-secondary fw-bold">Versions Array Details</h6>
                            <span class="badge bg-secondary">${entryCount} entries</span>
                            ${tableIndex !== null ? `<small class="text-muted">Data from Platform Entry ${tableIndex}</small>` : ''}
                        </div>
                        <div class="item-description">
                            <small class="text-muted">${item.details}</small>
                        </div>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-sm table-striped table-hover">
                            <thead class="table-dark">
                                <tr>
                                    <th style="width: 5%;">#</th>
                                    <th style="width: 25%;">Version</th>
                                    <th style="width: 12%;">Status</th>
                                    <th style="width: 20%;">LessThan</th>
                                    <th style="width: 20%;">LessThanOrEqual</th>
                                    <th style="width: 12%;">VersionType</th>
                                    <th style="width: 6%;">Changes</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                versionsArray.forEach((version, index) => {
                    const versionValue = version.version || '';
                    const status = version.status || '';
                    const lessThan = version.lessThan || '';
                    const lessThanOrEqual = version.lessThanOrEqual || '';
                    const versionType = version.versionType || '';
                    const changes = version.changes ? version.changes.length : 0;
                    
                    content += `
                        <tr>
                            <td class="text-center">${index + 1}</td>
                            <td>${versionValue ? `<code class="text-dark bg-light px-1 rounded">${versionValue}</code>` : ''}</td>
                            <td>${status ? `<span class="badge ${status === 'affected' ? 'bg-danger' : status === 'unaffected' ? 'bg-success' : 'bg-secondary'}">${status}</span>` : ''}</td>
                            <td>${lessThan ? `<code class="text-dark bg-light px-1 rounded">${lessThan}</code>` : ''}</td>
                            <td>${lessThanOrEqual ? `<code class="text-dark bg-light px-1 rounded">${lessThanOrEqual}</code>` : ''}</td>
                            <td>${versionType ? `<span class="badge bg-secondary">${versionType}</span>` : ''}</td>
                            <td class="text-center">${changes > 0 ? changes : ''}</td>
                        </tr>
                    `;
                });
                content += `
                            </tbody>
                        </table>
                    </div>
                `;
            } else if (item.type === 'cpe_api_results') {
                // Handle API results with proper header
                content += `
                    <div class="item-header mb-3">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="mb-0 text-secondary fw-bold">CPE API Query Results</h6>
                            <div class="api-stats">
                                <span class="badge bg-secondary me-1">${item.successful_count || 0} successful</span>
                                <span class="badge bg-danger">${item.errors ? item.errors.length : 0} errors</span>
                            </div>
                        </div>
                        <div class="item-description">
                            <small class="text-muted">${item.details}</small>
                        </div>
                    </div>
                `;
            } else if (item.type === 'source_transformations') {
                // Handle source transformations with proper header
                content += `
                    <div class="item-header mb-3">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="mb-0 text-secondary fw-bold">Source to CPE Transformations</h6>
                            <div class="transformation-stats">
                                <span class="badge bg-secondary">${item.transformations ? item.transformations.length : 0} transformations</span>
                            </div>
                        </div>
                        <div class="item-description">
                            <small class="text-muted">${item.details}</small>
                        </div>
                    </div>
                `;
            } else {
                // Generic item handling
                content += `
                    <div class="item-header mb-3">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="mb-0 text-secondary fw-bold">${item.title}</h6>
                            <span class="badge bg-secondary">${item.content}</span>
                        </div>
                        <div class="item-description">
                            <small class="text-muted">${item.details}</small>
                        </div>
                    </div>
                `;
            }
            
            // Handle different item types with enhanced styling - skip versions_structure as it's handled above
            if (item.type === 'cpe_data' && item.cpes) {
                content += `
                    <div class="cpe-strings-section">
                        <div class="mb-2">
                            <strong class="text-secondary">CPE Strings:</strong>
                        </div>
                        <div class="cpe-strings-grid">
                `;
                item.cpes.forEach(cpe => {
                    content += `
                        <div class="cpe-string-item mb-1">
                            <code class="text-dark bg-light px-2 py-1 rounded border">${cpe}</code>
                        </div>
                    `;
                });
                content += `
                        </div>
                    </div>
                `;
            }

            if (item.type === 'cpe_api_results' && item.errors && item.errors.length > 0) {
                content += `
                    <div class="api-errors-section">
                        <div class="mb-2">
                            <strong class="text-secondary">API Errors:</strong>
                        </div>
                        <div class="api-errors-list">
                `;
                item.errors.forEach(error => {
                    content += `
                        <div class="api-error-item mb-2 p-2 border rounded bg-light">
                            <div class="d-flex justify-content-between align-items-center">
                                <code class="text-dark bg-white px-2 py-1 rounded border">${error.cpe}</code>
                                <span class="badge bg-secondary">${error.status}</span>
                            </div>
                            <div class="error-message mt-1">
                                <small class="text-muted">${error.error}</small>
                            </div>
                        </div>
                    `;
                });
                content += `
                        </div>
                    </div>
                `;
            } else if (item.type === 'cpe_api_results' && item.successful_count > 0) {
                content += `
                    <div class="api-success-section">
                        <div class="mb-2">
                            <strong class="text-secondary">API Success:</strong>
                        </div>
                        <div class="border rounded border-secondary p-2">
                            <small class="text-dark">All ${item.successful_count} CPE API queries completed successfully with no errors.</small>
                        </div>
                    </div>
                `;
            }

            if (item.type === 'cpe_searches' && (item.used_strings || item.culled_strings)) {
                content += `
                    <div class="cpe-searches-section">
                `;
                
                if (item.used_strings && item.used_strings.length > 0) {
                    content += `
                        <div class="used-strings-section mb-3">
                            <div class="mb-2">
                                <div class="d-flex justify-content-between align-items-center">
                                    <strong class="text-secondary">Used CPE Strings:</strong>
                                    <span class="badge bg-secondary">${item.used_strings.length}</span>
                                </div>
                            </div>
                            <div class="used-strings-grid">
                    `;
                    item.used_strings.forEach(cpe => {
                        content += `
                            <div class="used-string-item mb-1">
                                <code class="text-dark bg-light px-2 py-1 rounded border">${cpe}</code>
                            </div>
                        `;
                    });
                    content += `
                            </div>
                        </div>
                    `;
                }

                if (item.culled_strings && item.culled_strings.length > 0) {
                    content += `
                        <div class="culled-strings-section">
                            <div class="mb-2">
                                <div class="d-flex justify-content-between align-items-center">
                                    <strong class="text-secondary">Culled CPE Strings:</strong>
                                    <span class="badge bg-secondary">${item.culled_strings.length}</span>
                                </div>
                            </div>
                            <div class="culled-strings-grid">
                    `;
                    item.culled_strings.forEach(culled => {
                        content += `
                            <div class="culled-string-item mb-2 p-2 border rounded bg-light">
                                <div class="d-flex justify-content-between align-items-center">
                                    <code class="text-dark bg-white px-2 py-1 rounded">${culled.cpe_string}</code>
                                    <span class="badge bg-secondary">${culled.reason}</span>
                                </div>
                            </div>
                        `;
                    });
                    content += `
                            </div>
                        </div>
                    `;
                }
                
                content += `</div>`;
            }

            if (item.type === 'source_transformations' && item.transformations) {
                content += `
                    <div class="transformations-section">
                        <div class="mb-2">
                            <strong class="text-secondary">Applied Transformations:</strong>
                        </div>
                        <div class="transformations-list">
                `;
                item.transformations.forEach(transform => {
                    const statusClass = transform.type === 'unicode_skipped' ? 'border-secondary' : 'border-secondary';
                    const statusBadge = transform.type === 'unicode_skipped' ? 'bg-secondary' : 'bg-secondary';
                    
                    content += `
                        <div class="transformation-item mb-3 p-3 border rounded ${statusClass}">
                            <div class="transformation-header mb-2">
                                <div class="d-flex justify-content-between align-items-center">
                                    <strong class="text-secondary">${transform.category}</strong>
                                    <span class="badge ${statusBadge}">${transform.field}</span>
                                </div>
                            </div>
                            <div class="transformation-content">
                                <div class="row">
                                    <div class="col-5">
                                        <div class="mb-1">
                                            <small class="fw-bold text-muted">Original:</small>
                                        </div>
                                        <code class="text-dark bg-light px-2 py-1 rounded border d-block">${transform.original}</code>
                                    </div>
                                    <div class="col-2 d-flex align-items-center">
                                        <div class="transformation-arrow w-100 text-center">
                                            <div class="text-secondary" style="font-size: 2rem;">→</div>
                                        </div>
                                    </div>
                                    <div class="col-5">
                                        <div class="mb-1">
                                            <small class="fw-bold text-muted">Transformed:</small>
                                        </div>
                                        <code class="text-dark bg-light px-2 py-1 rounded border d-block">${transform.transformed}</code>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                });
                content += `
                        </div>
                    </div>
                `;
            }

            content += `
                </div>
            `;
        });

        content += `</div>`;
        return content;
    }

    static generateSourceDataConcernTabContent(concerns, concernType, sourceRole = 'Unknown Source') {
        if (!concerns || concerns.length === 0) {
            return '<p class="text-muted">No concerns detected</p>';
        }

        let content = `
            <div class="source-data-concerns-content">
                <div class="mb-2 pb-1 border-bottom">
                    <div class="d-flex justify-content-between align-items-center">
                        <small class="text-muted fw-bold">LINT Analysis Results</small>
                        <span class="badge bg-danger" style="font-size: 0.65rem;">${concerns.length} issue${concerns.length > 1 ? 's' : ''}</span>
                    </div>
                </div>
        `;

        concerns.forEach((concern, index) => {
            // Generate issue-specific styling and content
            const issueNumber = index + 1;
            
            content += `
                <div class="source-concern-item mb-2 p-2 border rounded" style="border-left: 4px solid #9C27B0 !important;">
                    <div class="concern-header mb-2">
                        <div class="d-flex justify-content-between align-items-center">
                            <h6 class="mb-0 text-danger fw-bold" style="font-size: 0.9rem;">Issue #${issueNumber}</h6>
                            <span class="badge bg-purple text-white" style="background-color: #9C27B0; font-size: 0.65rem;">${sourceRole.toUpperCase()}</span>
                        </div>
                    </div>
            `;

            // Add concern-specific content based on type
            if (concernType === 'placeholderData') {
                content += BadgeModalFactory.generatePlaceholderDataContent(concern);
            } else if (concernType === 'versionTextPatterns') {
                content += BadgeModalFactory.generateVersionTextPatternsContent(concern);
            } else if (concernType === 'versionComparators') {
                content += BadgeModalFactory.generateVersionComparatorsContent(concern);
            } else if (concernType === 'versionGranularity') {
                content += BadgeModalFactory.generateVersionGranularityContent(concern);
            } else if (concernType === 'wildcardBranches') {
                content += BadgeModalFactory.generateWildcardBranchesContent(concern);
            } else if (concernType === 'cpeArrayConcerns') {
                content += BadgeModalFactory.generateCpeArrayConcernsContent(concern);
            } else if (concernType === 'duplicateEntries') {
                content += BadgeModalFactory.generateDuplicateEntriesContent(concern);
            } else if (concernType === 'platformDataConcerns') {
                content += BadgeModalFactory.generatePlatformDataConcernsContent(concern);
            } else if (concernType === 'missingAffectedProducts') {
                content += BadgeModalFactory.generateMissingAffectedProductsContent(concern);
            } else if (concernType === 'overlappingRanges') {
                content += BadgeModalFactory.generateOverlappingRangesContent(concern);
            } else {
                // Generic concern display
                content += `
                    <div class="concern-content compact-layout">
                        <div class="problem-description mb-1">
                            <strong class="text-danger" style="font-size: 0.85rem;">Problem:</strong>
                            <p class="mb-1" style="font-size: 0.85rem;">${concern.description || 'Data quality issue detected'}</p>
                        </div>
                        <div class="problematic-data mb-1">
                            <strong class="text-warning" style="font-size: 0.85rem;">Data:</strong>
                            <code class="text-dark bg-light px-1 py-1 rounded border d-inline-block mt-1" style="font-size: 0.8rem;">${concern.data || 'N/A'}</code>
                        </div>
                        <div class="resolution-guidance">
                            <strong class="text-success" style="font-size: 0.85rem;">Resolution:</strong>
                            <p class="mb-0 text-muted" style="font-size: 0.8rem;">${concern.guidance || 'Contact source data provider for correction'}</p>
                        </div>
                    </div>
                `;
            }

            content += `</div>`;
        });

        content += `</div>`;
        return content;
    }

    static generatePlaceholderDataContent(concern) {
        return `
            <div class="concern-content compact-layout">
                <div class="problem-description mb-1">
                    <strong class="text-danger" style="font-size: 0.85rem;">Problem:</strong>
                    <span class="ms-2" style="font-size: 0.85rem;">Field contains 'n/a' or 'N/A' preventing proper CPE matching</span>
                </div>
                <div class="problematic-data mb-1">
                    <div class="row g-1">
                        <div class="col-3">
                            <strong class="text-warning" style="font-size: 0.85rem;">Data:</strong>
                        </div>
                        <div class="col-9">
                            <code class="text-dark bg-light px-1 py-1 rounded border me-2" style="font-size: 0.8rem;">${concern.field}</code>
                            <code class="text-dark bg-light px-1 py-1 rounded border" style="font-size: 0.8rem;">${concern.value}</code>
                        </div>
                    </div>
                </div>
                <div class="resolution-guidance">
                    <strong class="text-success" style="font-size: 0.85rem;">Resolution:</strong>
                    <span class="text-muted ms-2" style="font-size: 0.8rem;">Replace with actual ${concern.field} name or descriptive identifier</span>
                </div>
            </div>
        `;
    }

    static generateVersionTextPatternsContent(concern) {
        return `
            <div class="concern-content">
                <div class="problem-description mb-2">
                    <strong class="text-danger">Problem:</strong>
                    <p class="mb-2">${concern.issue || 'Version contains text-based comparison patterns that prevent proper version matching'}</p>
                </div>
                <div class="problematic-data mb-2">
                    <strong class="text-warning">Problematic Data:</strong>
                    <div class="data-display mt-1">
                        <div class="row">
                            <div class="col-3"><strong>Issue Details:</strong></div>
                            <div class="col-9"><code class="text-dark bg-light px-2 py-1 rounded border">${concern.concern}</code></div>
                        </div>
                        <div class="row mt-1">
                            <div class="col-3"><strong>Category:</strong></div>
                            <div class="col-9"><span class="badge bg-warning text-dark">${concern.category}</span></div>
                        </div>
                    </div>
                </div>
                <div class="resolution-guidance">
                    <strong class="text-success">Resolution:</strong>
                    <ul class="mb-0 text-muted">
                        <li>Use structured version ranges with lessThan/lessThanOrEqual fields</li>
                        <li>Replace text descriptions with specific version numbers</li>
                        <li>Extract version number from text-based patterns</li>
                        <li>Use proper version range notation</li>
                    </ul>
                </div>
            </div>
        `;
    }

    static generateVersionComparatorsContent(concern) {
        return `
            <div class="concern-content">
                <div class="problem-description mb-2">
                    <strong class="text-danger">Problem:</strong>
                    <p class="mb-2">Version contains comparison operators that should use structured range fields.</p>
                </div>
                <div class="problematic-data mb-2">
                    <strong class="text-warning">Problematic Data:</strong>
                    <div class="data-display mt-1">
                        <div class="row">
                            <div class="col-3"><strong>Version:</strong></div>
                            <div class="col-9"><code class="text-dark bg-light px-2 py-1 rounded border">${concern.version}</code></div>
                        </div>
                        <div class="row mt-1">
                            <div class="col-3"><strong>Operator:</strong></div>
                            <div class="col-9"><span class="badge bg-warning text-dark">${concern.operator}</span></div>
                        </div>
                    </div>
                </div>
                <div class="resolution-guidance">
                    <strong class="text-success">Resolution:</strong>
                    <ul class="mb-0 text-muted">
                        <li>Use lessThan, lessThanOrEqual, greaterThan, greaterThanOrEqual fields</li>
                        <li>Example: "${concern.version}" → use appropriate range field</li>
                        <li>Separate version number from comparison logic</li>
                    </ul>
                </div>
            </div>
        `;
    }

    static generateVersionGranularityContent(concern) {
        // Parse the concern text to extract version granularity information
        const concernText = concern.concern || '';
        
        // Create simple columnar display for version comparison
        let formattedData = '';
        
        if (concernText.includes('Inconsistent version granularity:')) {
            try {
                // Extract all versions from parentheses and create columnar display
                const versionMatches = concernText.match(/\([^)]+\)/g);
                
                if (versionMatches) {
                    // Extract all individual versions from the parentheses
                    const allVersions = [];
                    versionMatches.forEach(match => {
                        // Remove parentheses and split by comma
                        const versions = match.replace(/[()]/g, '').split(',');
                        versions.forEach(version => {
                            const cleanVersion = version.trim();
                            if (cleanVersion && !allVersions.includes(cleanVersion)) {
                                allVersions.push(cleanVersion);
                            }
                        });
                    });
                    
                    // Create columnar display
                    formattedData = `<div style="font-family: monospace;">`;
                    
                    // Display each version on its own line for easy comparison  
                    allVersions.forEach(version => {
                        formattedData += `<div style="padding: 1px 0;">${version}</div>`;
                    });
                    
                    formattedData += '</div>';
                } else {
                    // Fallback if parsing fails
                    formattedData = `<code style="background: #f8f9fa; padding: 8px; border-radius: 4px; font-size: 0.85rem; display: block; white-space: pre-wrap;">${concernText}</code>`;
                }
            } catch (e) {
                // If parsing fails, use simple formatted text
                formattedData = `<code style="background: #f8f9fa; padding: 8px; border-radius: 4px; font-size: 0.85rem; display: block; white-space: pre-wrap;">${concernText}</code>`;
            }
        } else {
            // For non-standard version granularity concerns, display as-is
            formattedData = `<code style="background: #f8f9fa; padding: 8px; border-radius: 4px; font-size: 0.85rem; display: block; white-space: pre-wrap;">${concernText}</code>`;
        }
        
        return `
            <div class="concern-content compact-layout">
                <div class="problem-description mb-2">
                    <strong class="text-danger" style="font-size: 0.85rem;">Problem:</strong>
                    <span class="ms-2" style="font-size: 0.85rem;">${concern.issue || 'Version granularity issues may affect matching precision.'}</span>
                </div>
                <div class="problematic-data mb-2">
                    <div class="version-data-section">
                        <strong class="text-warning d-block mb-2" style="font-size: 0.85rem;">Granularity Analysis:</strong>
                        ${formattedData}
                    </div>
                </div>
                <div class="resolution-guidance">
                    <strong class="text-success" style="font-size: 0.85rem;">Resolution:</strong>
                    <div class="text-muted ms-2" style="font-size: 0.8rem;">
                        <ul class="mb-0 mt-1">
                            <li>Standardize version format consistency across related versions</li>
                            <li>Use consistent granularity levels (all 2-part or all 3-part within a base version)</li>
                            <li>Consider normalizing version patterns to avoid matching ambiguity</li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
    }

    static generateWildcardBranchesContent(concern) {
        return `
            <div class="concern-content">
                <div class="problem-description mb-2">
                    <strong class="text-danger">Problem:</strong>
                    <p class="mb-2">Multiple overlapping wildcard version branches create ambiguous range definitions.</p>
                </div>
                <div class="problematic-data mb-2">
                    <strong class="text-warning">Problematic Data:</strong>
                    <div class="data-display mt-1">
                        <div class="row">
                            <div class="col-3"><strong>Branches:</strong></div>
                            <div class="col-9">
                                ${concern.branches.map(branch => 
                                    `<code class="text-dark bg-light px-2 py-1 rounded border me-1">${branch}</code>`
                                ).join('')}
                            </div>
                        </div>
                        <div class="row mt-1">
                            <div class="col-3"><strong>Overlap Type:</strong></div>
                            <div class="col-9"><span class="badge bg-warning text-dark">${concern.overlapType}</span></div>
                        </div>
                    </div>
                </div>
                <div class="resolution-guidance">
                    <strong class="text-success">Resolution:</strong>
                    <ul class="mb-0 text-muted">
                        <li>Consolidate overlapping ranges into single, clear range definitions</li>
                        <li>Use specific version ranges instead of multiple wildcard patterns</li>
                        <li>Define non-overlapping version branches</li>
                    </ul>
                </div>
            </div>
        `;
    }

    static generateCpeArrayConcernsContent(concern) {
        return `
            <div class="concern-content">
                <div class="problem-description mb-2">
                    <strong class="text-danger">Problem:</strong>
                    <p class="mb-2">CPE string contains improper version text that violates CPE 2.3 specification.</p>
                </div>
                <div class="problematic-data mb-2">
                    <strong class="text-warning">Problematic Data:</strong>
                    <div class="data-display mt-1">
                        <div class="row">
                            <div class="col-3"><strong>CPE String:</strong></div>
                            <div class="col-9"><code class="text-dark bg-light px-2 py-1 rounded border" style="word-break: break-all;">${concern.cpeString}</code></div>
                        </div>
                        <div class="row mt-1">
                            <div class="col-3"><strong>Issue:</strong></div>
                            <div class="col-9"><span class="badge bg-warning text-dark">${concern.issueType}</span></div>
                        </div>
                    </div>
                </div>
                <div class="resolution-guidance">
                    <strong class="text-success">Resolution:</strong>
                    <ul class="mb-0 text-muted">
                        <li>Use structured version information in versions array instead</li>
                        <li>CPE version field should contain specific version numbers only</li>
                        <li>Remove text patterns like "before", "through", etc. from CPE strings</li>
                    </ul>
                </div>
            </div>
        `;
    }

    static generateDuplicateEntriesContent(concern) {
        return `
            <div class="concern-content">
                <div class="problem-description mb-2">
                    <strong class="text-danger">Problem:</strong>
                    <p class="mb-2">Multiple identical platform configurations found, leading to data redundancy.</p>
                </div>
                <div class="problematic-data mb-2">
                    <strong class="text-warning">Problematic Data:</strong>
                    <div class="data-display mt-1">
                        <div class="row">
                            <div class="col-3"><strong>Duplicate Rows:</strong></div>
                            <div class="col-9">
                                ${concern.duplicateIndices.map(index => 
                                    `<span class="badge bg-secondary me-1">${index}</span>`
                                ).join('')}
                            </div>
                        </div>
                        <div class="row mt-1">
                            <div class="col-3"><strong>Configuration:</strong></div>
                            <div class="col-9"><code class="text-dark bg-light px-2 py-1 rounded border">${concern.configuration}</code></div>
                        </div>
                    </div>
                </div>
                <div class="resolution-guidance">
                    <strong class="text-success">Resolution:</strong>
                    <ul class="mb-0 text-muted">
                        <li>Remove duplicate platform configurations</li>
                        <li>Consolidate identical entries into single platform definition</li>
                        <li>Review source data generation process to prevent duplication</li>
                    </ul>
                </div>
            </div>
        `;
    }

    static generatePlatformDataConcernsContent(concern) {
        return `
            <div class="concern-content">
                <div class="problem-description mb-2">
                    <strong class="text-danger">Problem:</strong>
                    <p class="mb-2">Unexpected platform data structure detected that cannot be processed by current logic.</p>
                </div>
                <div class="problematic-data mb-2">
                    <strong class="text-warning">Problematic Data:</strong>
                    <div class="data-display mt-1">
                        <div class="row">
                            <div class="col-3"><strong>Data Type:</strong></div>
                            <div class="col-9"><span class="badge bg-warning text-dark">${concern.dataType}</span></div>
                        </div>
                        <div class="row mt-1">
                            <div class="col-3"><strong>Issue:</strong></div>
                            <div class="col-9">${concern.issueDescription}</div>
                        </div>
                    </div>
                </div>
                <div class="resolution-guidance">
                    <strong class="text-success">Resolution:</strong>
                    <ul class="mb-0 text-muted">
                        <li>Review platform data structure for compliance with expected schema</li>
                        <li>Contact source data provider for schema clarification</li>
                        <li>May require tool enhancement to support new platform data patterns</li>
                    </ul>
                </div>
            </div>
        `;
    }

    static generateMissingAffectedProductsContent(concern) {
        return `
            <div class="concern-content">
                <div class="problem-description mb-2">
                    <strong class="text-danger">Problem:</strong>
                    <p class="mb-2">CVE record appears to lack explicit affected product information in containers/affected.</p>
                </div>
                <div class="problematic-data mb-2">
                    <strong class="text-warning">Missing Information:</strong>
                    <div class="data-display mt-1">
                        <div class="row">
                            <div class="col-3"><strong>Issue Type:</strong></div>
                            <div class="col-9"><span class="badge bg-warning text-dark">Missing Affected Products</span></div>
                        </div>
                        <div class="row mt-1">
                            <div class="col-3"><strong>Description:</strong></div>
                            <div class="col-9">${concern.description || 'No affected products explicitly listed'}</div>
                        </div>
                    </div>
                </div>
                <div class="resolution-guidance">
                    <strong class="text-success">Resolution:</strong>
                    <ul class="mb-0 text-muted">
                        <li>Verify CVE record contains containers/affected with product information</li>
                        <li>Check if affected products are implied through other fields</li>
                        <li>May require CNA coordination to add missing affected product data</li>
                    </ul>
                </div>
            </div>
        `;
    }

    static generateOverlappingRangesContent(concern) {
        // Generate cross-reference links for related table indices
        const crossRefLinks = concern.related_table_indices && concern.related_table_indices.length > 0 
            ? concern.related_table_indices.map(index => `<a href="#" onclick="event.preventDefault(); document.querySelector('[id^=\\'rowDataTable_${index}\\']').scrollIntoView({behavior: 'smooth', block: 'center'});" class="badge bg-info text-white me-1" style="font-size: 0.7rem; text-decoration: none;">Row ${index}</a>`).join(' ')
            : '<span class="text-muted">None</span>';

        // Format range information for visual display
        const rangeDisplay = concern.affected_ranges && concern.affected_ranges.length > 0
            ? concern.affected_ranges.map(range => {
                // Skip non-specific version values like "unspecified"
                if (range.version) {
                    const versionStr = String(range.version).toLowerCase().trim();
                    const nonSpecificValues = ['unspecified', 'unknown', 'na', 'n/a', '*', 'all', 'any'];
                    if (!nonSpecificValues.includes(versionStr)) {
                        return `<code class="bg-light px-1 rounded">v${range.version}</code>`;
                    }
                }
                
                // Build range description from bounds
                const parts = [];
                if (range.greaterThan) parts.push(`>${range.greaterThan}`);
                else if (range.greaterThanOrEqual) parts.push(`>=${range.greaterThanOrEqual}`);
                
                if (range.lessThan) parts.push(`<${range.lessThan}`);
                else if (range.lessThanOrEqual) parts.push(`<=${range.lessThanOrEqual}`);
                
                return `<code class="bg-light px-1 rounded">${parts.join(' AND ') || 'unbounded'}</code>`;
            }).join(' ⇄ ')
            : '<span class="text-muted">No range details available</span>';

        return `
            <div class="concern-content">
                <div class="problem-description mb-2">
                    <strong class="text-danger">Problem:</strong>
                    <p class="mb-2">${concern.range_description || 'Version ranges overlap and could potentially be consolidated'}</p>
                </div>
                <div class="problematic-data mb-2">
                    <strong class="text-warning">Overlapping Ranges:</strong>
                    <div class="data-display mt-1">
                        <div class="row">
                            <div class="col-3"><strong>Overlap Type:</strong></div>
                            <div class="col-9">
                                <span class="badge ${concern.overlap_type === 'identical' ? 'bg-danger' : concern.overlap_type === 'contains' || concern.overlap_type === 'contained' ? 'bg-warning' : 'bg-info'} text-white" style="font-size: 0.7rem;">
                                    ${concern.overlap_type ? concern.overlap_type.toUpperCase() : 'OVERLAP'}
                                </span>
                            </div>
                        </div>
                        <div class="row mt-1">
                            <div class="col-3"><strong>CPE Base:</strong></div>
                            <div class="col-9"><code class="bg-light px-1 rounded" style="font-size: 0.8rem;">${concern.cpe_base || 'N/A'}</code></div>
                        </div>
                        <div class="row mt-1">
                            <div class="col-3"><strong>Visual Ranges:</strong></div>
                            <div class="col-9" style="font-size: 0.85rem;">${rangeDisplay}</div>
                        </div>
                        <div class="row mt-1">
                            <div class="col-3"><strong>Cross-References:</strong></div>
                            <div class="col-9">${crossRefLinks}</div>
                        </div>
                    </div>
                </div>
                <div class="resolution-guidance">
                    <strong class="text-success">Suggestion:</strong>
                    <p class="mb-0 text-muted" style="font-size: 0.85rem;">${concern.suggestion || 'Review ranges for potential consolidation'}</p>
                </div>
            </div>
        `;
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

    static openWildcardGenerationModal(tableIndex, displayValue) {
        const modal = BadgeModalFactory.createWildcardGenerationModal();
        
        // Fail fast if no JSON generation rules data is registered at all
        if (!window.BADGE_MODAL_DATA.jsonGenerationRules) {
            throw new Error('No JSON generation rules data registered - ensure BadgeModal.registerData("jsonGenerationRules", ...) calls have executed');
        }
        
        const registeredData = window.BADGE_MODAL_DATA.jsonGenerationRules[tableIndex]; // No optional chaining - fail fast
        if (!registeredData) {
            throw new Error(`No JSON generation rules data registered for key '${tableIndex}' - check BadgeModal.registerData() calls`);
        }
        
        // Calculate counts for header display
        let ruleCount = 1; // Currently only wildcard generation rules
        const ruleTypes = ['Wildcard Generation'];
        
        // Add more rule types if they exist in the data
        if (registeredData.updatePatterns) {
            ruleCount++;
            ruleTypes.push('Update Patterns');
        }
        if (registeredData.versionRanges) {
            ruleCount++;
            ruleTypes.push('Version Ranges');
        }
        
        modal.show(tableIndex, displayValue, { ruleCount, ruleTypes });
    }

    static openSupportingInformationModal(tableIndex, displayValue) {
        const modal = BadgeModalFactory.createSupportingInformationModal();
        
        // Fail fast if no supporting information data is registered at all
        if (!window.BADGE_MODAL_DATA.supportingInformation) {
            throw new Error('No supporting information data registered - ensure BadgeModal.registerData("supportingInformation", ...) calls have executed');
        }
        
        const registeredData = window.BADGE_MODAL_DATA.supportingInformation[tableIndex]; // No optional chaining - fail fast
        if (!registeredData) {
            throw new Error(`No supporting information data registered for key '${tableIndex}' - check BadgeModal.registerData() calls`);
        }
        
        // Calculate counts for header display
        const totalItems = registeredData.summary ? registeredData.summary.total_items : 0;
        const categories = registeredData.summary ? registeredData.summary.categories : [];
        
        modal.show(tableIndex, displayValue, { totalItems, categories });
    }

    static openSourceDataConcernsModal(tableIndex, displayValue) {
        const modal = BadgeModalFactory.createSourceDataConcernsModal();
        
        // Fail fast if no source data concerns data is registered at all
        if (!window.BADGE_MODAL_DATA.sourceDataConcerns) {
            throw new Error('No source data concerns data registered - ensure BadgeModal.registerData("sourceDataConcerns", ...) calls have executed');
        }
        
        const registeredData = window.BADGE_MODAL_DATA.sourceDataConcerns[tableIndex]; // No optional chaining - fail fast
        if (!registeredData) {
            throw new Error(`No source data concerns data registered for key '${tableIndex}' - check BadgeModal.registerData() calls`);
        }
        
        // Extract concerns data and source role from the registered structure
        const concernsData = registeredData.concerns || {};
        const sourceRole = registeredData.sourceRole || 'Unknown Source';
        
        // Calculate counts for header display
        let issueCount = 0;
        const concernTypes = [];
        
        if (concernsData.placeholderData && concernsData.placeholderData.length > 0) {
            issueCount += concernsData.placeholderData.length;
            concernTypes.push('Placeholder Data');
        }
        if (concernsData.versionTextPatterns && concernsData.versionTextPatterns.length > 0) {
            issueCount += concernsData.versionTextPatterns.length;
            concernTypes.push('Version Text Patterns');
        }
        if (concernsData.versionComparators && concernsData.versionComparators.length > 0) {
            issueCount += concernsData.versionComparators.length;
            concernTypes.push('Version Comparators');
        }
        if (concernsData.versionGranularity && concernsData.versionGranularity.length > 0) {
            issueCount += concernsData.versionGranularity.length;
            concernTypes.push('Version Granularity');
        }
        if (concernsData.wildcardBranches && concernsData.wildcardBranches.length > 0) {
            issueCount += concernsData.wildcardBranches.length;
            concernTypes.push('Wildcard Branches');
        }
        if (concernsData.cpeArrayConcerns && concernsData.cpeArrayConcerns.length > 0) {
            issueCount += concernsData.cpeArrayConcerns.length;
            concernTypes.push('CPE Array Issues');
        }
        if (concernsData.duplicateEntries && concernsData.duplicateEntries.length > 0) {
            issueCount += concernsData.duplicateEntries.length;
            concernTypes.push('Duplicate Entries');
        }
        if (concernsData.platformDataConcerns && concernsData.platformDataConcerns.length > 0) {
            issueCount += concernsData.platformDataConcerns.length;
            concernTypes.push('Platform Data Issues');
        }
        if (concernsData.missingAffectedProducts && concernsData.missingAffectedProducts.length > 0) {
            issueCount += concernsData.missingAffectedProducts.length;
            concernTypes.push('Missing Affected Products');
        }
        
        modal.show(tableIndex, displayValue, { issueCount, concernTypes, sourceRole });
    }

    static openJsonGenerationRulesModal(tableIndex, displayValue) {
        const modal = BadgeModalFactory.createJsonGenerationRulesModal();
        
        // Fail fast if no JSON generation rules data is registered at all
        if (!window.BADGE_MODAL_DATA.jsonGenerationRules) {
            throw new Error('No JSON generation rules data registered - ensure BadgeModal.registerData("jsonGenerationRules", ...) calls have executed');
        }
        
        const registeredData = window.BADGE_MODAL_DATA.jsonGenerationRules[tableIndex]; // No optional chaining - fail fast
        if (!registeredData) {
            throw new Error(`No JSON generation rules data registered for key '${tableIndex}' - check BadgeModal.registerData() calls`);
        }
        
        // Calculate counts for header display
        const ruleCount = registeredData.summary ? registeredData.summary.total_rules : 0;
        const ruleTypes = registeredData.summary ? registeredData.summary.rule_types : [];
        
        modal.show(tableIndex, displayValue, { ruleCount, ruleTypes });
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
