/**
 * Timestamp Handler
 * Manages the generator timestamp for CPE JSON data and timestamp display
 */

// Module for handling timestamp-related operations
(function() {
    // Store the timestamp globally for use in other modules
    let generatorTimestamp = "";
    
    // Initialize timestamp functionality
    function initTimestampHandler(timestamp) {
        // Store the timestamp globally
        generatorTimestamp = timestamp;
        
        // Format and display the timestamp when the document is ready
        document.addEventListener('DOMContentLoaded', function() {
            formatAndDisplayTimestamp();
        });
    }
    
    // Format and display the timestamp in the user's local timezone
    function formatAndDisplayTimestamp() {
        const timeElement = document.querySelector('#generationTimestamp time');
        if (!timeElement) return;
        
        const utcTime = new Date(generatorTimestamp);
        const options = { 
            year: 'numeric', 
            month: 'short', 
            day: 'numeric', 
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit',
            timeZoneName: 'short' 
        };
        timeElement.textContent = utcTime.toLocaleString(undefined, options);
    }
    
    // Get the stored timestamp
    function getTimestamp() {
        return generatorTimestamp;
    }    
    // =============================================================================
    // Global Exports - All window assignments consolidated here
    // =============================================================================
    window.timestampHandler = {
        init: initTimestampHandler,
        getTimestamp: getTimestamp
    };
})();