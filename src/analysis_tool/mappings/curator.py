#!/usr/bin/env python3
"""
Source Data Mapping Curator

Extracts and consolidates CVE source data mappings from CVE 5.X records to generate
confirmed mapping files for CPE base string suggestion capabilities.

This tool processes CVE records from a specified CNA/ADP and extracts platform-specific
alias information, generating structured mapping data that can be used by the Analysis_Tools
for improved CPE suggestion accuracy.

Performance optimizations fo        print(f"✅ Source mapping extraction completed successfully!")
        print(f"📁 Run directory: {curator.run_path}")
        print(f"📊 Files processed: {curator.processed_files:,}")
        print(f"🎯 Matching CVEs: {curator.matching_cves:,}")
        print(f"📋 Unique aliases: {len(curator.extracted_mappings):,}")
        print(f"⚡ Files skipped (fast filter): {curator.skipped_files:,}")
        print(f"\n🔍 Output file ready for Analysis_Tools integration:")
        
        # Show the actual output file path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"source_mapping_extraction_{args.uuid[:8]}_{timestamp}.json"
        output_path = curator.run_paths["logs"] / output_file
        print(f"📄 {output_path}")
        print(f"\n🌐 Analyze results with: dashboards/sourceMappingDashboard.html")datasets (300k+ files):
- Streaming JSON parsing for memory efficiency
- Early filtering to skip non-matching files quickly
- Batch processing with progress reporting
- Configurable limits and sampling options
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
import concurrent.futures
from threading import Lock

# Add the src directory to Python path for proper imports
project_root = Path(__file__).parent.parent.parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

from analysis_tool.storage.run_organization import create_run_directory, get_analysis_tools_root
from analysis_tool.logging.workflow_logger import WorkflowLogger, LogGroup, LogLevel

class SourceMappingCurator:
    """Main class for curating source data mappings from CVE records"""
    
    def __init__(self, cve_repository_path: str, target_uuid: str, run_context: str = None, 
                 max_files: int = None, threads: int = 4, sample_recent: bool = False):
        """
        Initialize the curator with repository and target parameters.
        
        Args:
            cve_repository_path: Path to the CVE 5.X repository
            target_uuid: UUID of the target CNA/ADP to extract mappings for
            run_context: Optional context for the run (used in directory naming)
            max_files: Optional limit on number of files to process (for testing)
            threads: Number of worker threads for parallel processing
            sample_recent: If True, prioritize recent CVEs for sampling
        """
        self.cve_repo_path = Path(cve_repository_path)
        self.target_uuid = target_uuid
        self.max_files = max_files
        self.threads = threads
        self.sample_recent = sample_recent
        
        # Create run directory following Analysis_Tools patterns (logs only)
        context = run_context or f"source_mapping_{target_uuid[:8]}"
        if max_files:
            context += f"_limit{max_files}"
        
        # Check if we're in a consolidated test environment
        import os
        is_test = os.environ.get('CONSOLIDATED_TEST_RUN') == '1'
        self.run_path, self.run_id = create_run_directory(context, is_test=is_test, subdirs=["logs"])
        
        # Get paths for this run (logs directory only)
        from analysis_tool.storage.run_organization import get_current_run_paths
        self.run_paths = get_current_run_paths(self.run_id)
        
        # Initialize logger
        self.logger = WorkflowLogger()
        
        # Data structures with thread safety
        self.processed_files = 0
        self.matching_cves = 0
        self.skipped_files = 0
        self.extracted_mappings: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()
        
        # Load confirmed mappings for this UUID if available
        self.confirmed_mappings: Dict[str, Any] = self._load_confirmed_mappings()
        
        # Pre-process confirmed mappings into lookup table for O(1) access during batch processing
        self.confirmed_mappings_lookup: Dict[str, str] = {}
        if self.confirmed_mappings and 'confirmedMappings' in self.confirmed_mappings:
            self._build_confirmed_mappings_lookup()
        
        # Detailed filtering statistics
        self.filtering_stats = {
            'vendor': 0,
            'product': 0,
            'platforms': 0,
            'collectionURL': 0,
            'packageName': 0,
            'repo': 0,
            'programRoutines': 0,
            'programFiles': 0,
            'modules': 0,
            'entire_aliases_rejected': 0
        }
        
        # Performance tracking
        self.start_time = None
        self.last_progress_time = None
        
    def _load_confirmed_mappings(self) -> Dict[str, Any]:
        """Load confirmed mappings file for the target UUID if available"""
        mappings_dir = Path(__file__).parent
        
        # Search for JSON files containing the target UUID
        for mapping_file in mappings_dir.glob("*.json"):
            try:
                with open(mapping_file, 'r', encoding='utf-8') as f:
                    mapping_data = json.load(f)
                    
                if mapping_data.get('cnaId') == self.target_uuid:
                    self.log_init(f"Found confirmed mappings file: {mapping_file.name}")
                    return mapping_data
                    
            except (json.JSONDecodeError, IOError) as e:
                self.log_init(f"Warning: Could not read mapping file {mapping_file}: {e}")
                continue
                
        self.log_init("No confirmed mappings file found for this UUID")
        return {}
    
    def _build_confirmed_mappings_lookup(self):
        """
        Build a fast lookup table for confirmed mappings to avoid O(n*m*k) complexity.
        Creates a hash table where key = "vendor:product:platform" and value = CPE base string.
        """
        self.log_init("Building confirmed mappings lookup table for performance optimization")
        
        confirmed_mappings = self.confirmed_mappings['confirmedMappings']
        lookup_count = 0
        
        for mapping in confirmed_mappings:
            cpe_base_string = mapping.get('cpebasestring') or mapping.get('cpeBaseString')
            if not cpe_base_string:
                continue
                
            aliases = mapping.get('aliases', [])
            for confirmed_alias in aliases:
                vendor = confirmed_alias.get('vendor', '').lower()
                product = confirmed_alias.get('product', '').lower()
                platform = confirmed_alias.get('platform', '').lower()
                
                # Create lookup key - use empty string for missing platform
                lookup_key = f"{vendor}:{product}:{platform}"
                self.confirmed_mappings_lookup[lookup_key] = cpe_base_string
                lookup_count += 1
        
        self.log_init(f"Built confirmed mappings lookup table with {lookup_count} entries")
    
    def _alias_matches_confirmed_mapping(self, alias_data: Dict[str, Any]) -> Optional[str]:
        """
        Check if an alias matches any confirmed mapping using fast O(1) lookup table.
        Returns the CPE base string if a match is found, None otherwise.
        """
        if not self.confirmed_mappings_lookup:
            return None
            
        vendor = alias_data.get('vendor', '').lower()
        product = alias_data.get('product', '').lower()
        platform = alias_data.get('platform', '').lower() if 'platform' in alias_data else ''
        
        # Create lookup key matching the format used in _build_confirmed_mappings_lookup
        lookup_key = f"{vendor}:{product}:{platform}"
        
        # O(1) lookup instead of nested loops
        return self.confirmed_mappings_lookup.get(lookup_key)
    
    def _batch_process_confirmed_mappings(self) -> tuple[List[Dict], Dict[str, Dict]]:
        """
        Batch process all extracted mappings to separate confirmed vs unconfirmed aliases.
        This approach processes all aliases at once instead of checking each individually.
        Returns: (confirmed_aliases, unconfirmed_mappings)
        """
        if not self.confirmed_mappings_lookup:
            # No confirmed mappings available - all are unconfirmed
            return [], dict(self.extracted_mappings)
        
        self.log_data_processing(f"Batch processing {len(self.extracted_mappings)} aliases for confirmed mappings")
        
        confirmed_aliases = []
        unconfirmed_mappings = {}
        confirmed_count = 0
        
        for alias_key, alias_data in self.extracted_mappings.items():
            vendor = alias_data.get('vendor', '').lower()
            product = alias_data.get('product', '').lower()
            platform = alias_data.get('platform', '').lower() if 'platform' in alias_data else ''
            
            # Fast O(1) lookup
            lookup_key = f"{vendor}:{product}:{platform}"
            cpe_base_string = self.confirmed_mappings_lookup.get(lookup_key)
            
            if cpe_base_string:
                # This alias matches a confirmed mapping
                confirmed_alias = alias_data.copy()
                confirmed_alias['cpe_base_string'] = cpe_base_string
                confirmed_aliases.append(confirmed_alias)
                confirmed_count += 1
            else:
                # This alias doesn't match any confirmed mapping
                unconfirmed_mappings[alias_key] = alias_data
        
        self.log_data_processing(f"Confirmed mapping batch processing: {confirmed_count} confirmed, {len(unconfirmed_mappings)} unconfirmed")
        return confirmed_aliases, unconfirmed_mappings
        
    def log_init(self, message: str, level: str = "INFO"):
        """Log initialization messages"""
        self.logger.info(message, group="initialization")
        
    def log_data_processing(self, message: str, level: str = "INFO"):
        """Log data processing messages"""
        if level == "WARNING":
            self.logger.warning(message, group="data_processing")
        else:
            self.logger.info(message, group="data_processing")
        
    def start_extraction(self):
        """Start the source mapping extraction process"""
        self.start_time = time.time()
        self.last_progress_time = self.start_time
        
        self.log_init(f"Starting source mapping extraction")
        self.log_init(f"CVE Repository: {self.cve_repo_path}")
        self.log_init(f"Target UUID: {self.target_uuid}")
        self.log_init(f"Run Directory: {self.run_path}")
        self.log_init(f"Output Location: {self.run_paths['logs']}")
        if self.max_files:
            self.log_init(f"Processing limit: {self.max_files:,} files")
        self.log_init(f"Worker threads: {self.threads}")
        
        if not self.cve_repo_path.exists():
            raise ValueError(f"CVE repository path does not exist: {self.cve_repo_path}")
            
        # Process CVE files
        self._process_cve_files()
        
        # Generate output
        self._generate_output()
        
        total_time = time.time() - self.start_time
        self.log_init(f"Source mapping extraction completed in {total_time:.1f}s")
        
    def _is_placeholder_value(self, value: Any) -> bool:
        """
        Check if a value is a placeholder (following sourceDataConcern patterns).
        Returns True if the value should be filtered out as meaningless placeholder data.
        """
        if not value or value in [None, "", 0]:
            return True
            
        # Convert to string and normalize for checking
        str_value = str(value).lower().strip()
        
        # Comprehensive placeholder patterns (based on sourceDataConcern analysis)
        placeholder_patterns = [
            'n/a', 'n\\/a', 'n\\a', 'na', 'unknown', 'unspecified', 'not specified',
            'not applicable', 'none', 'null', 'undefined', '-', '--', '---',
            'tbd', 'to be determined', 'pending', 'missing', 'empty', 'blank',
            'default', 'generic', 'various', 'multiple', 'mixed', 'other',
            'all', 'any', '*', 'no information', 'no data', 'not available',
            'not disclosed', 'confidential', 'redacted', 'vendor', 'product',
            # Platform-specific placeholders
            'all platforms', 'multiple platforms', 'various platforms', 'unspecified platform',
            'all versions', 'multiple versions', 'various versions', 'all systems'
        ]
        
        return str_value in placeholder_patterns
        
    def _is_meaningful_alias(self, vendor: str, product: str, platform: str = None) -> bool:
        """
        Determine if an alias has meaningful data.
        An alias is meaningful if:
        1. BOTH vendor AND product have meaningful data, OR
        2. At least one of vendor/product is meaningful AND platform is meaningful
        
        This is more strict than before to better filter placeholder combinations.
        """
        vendor_meaningful = not self._is_placeholder_value(vendor)
        product_meaningful = not self._is_placeholder_value(product)
        platform_meaningful = platform is None or not self._is_placeholder_value(platform)
        
        # Both vendor and product meaningful (strong case)
        if vendor_meaningful and product_meaningful:
            return True
            
        # One of vendor/product meaningful AND platform meaningful (acceptable case)
        if (vendor_meaningful or product_meaningful) and platform_meaningful:
            return True
            
        # All other cases are not meaningful enough
        return False
        
    def _get_cve_files(self) -> List[Path]:
        """Get list of CVE files to process, with optional sampling/limiting"""
        self.log_data_processing("Scanning CVE repository structure")
        
        all_files = []
        
        # Walk through CVE directory structure (nested by year/thousands)
        for year_dir in sorted(self.cve_repo_path.glob("*"), reverse=self.sample_recent):
            if not year_dir.is_dir() or not year_dir.name.startswith("20"):
                continue
                
            for thousand_dir in sorted(year_dir.glob("*xxx"), reverse=self.sample_recent):
                if not thousand_dir.is_dir():
                    continue
                    
                for cve_file in sorted(thousand_dir.glob("CVE-*.json"), reverse=self.sample_recent):
                    all_files.append(cve_file)
                    
                    # Early exit if we have enough files
                    if self.max_files and len(all_files) >= self.max_files:
                        break
                        
                if self.max_files and len(all_files) >= self.max_files:
                    break
                    
            if self.max_files and len(all_files) >= self.max_files:
                break
        
        if self.max_files:
            all_files = all_files[:self.max_files]
            
        self.log_data_processing(f"Found {len(all_files):,} CVE files to process")
        return all_files
        
    def _process_cve_files(self):
        """Process all CVE files using parallel processing"""
        cve_files = self._get_cve_files()
        
        if not cve_files:
            self.log_data_processing("No CVE files found to process")
            return
            
        self.log_data_processing(f"Processing {len(cve_files):,} CVE files with {self.threads} threads")
        
        # Use ThreadPoolExecutor for parallel processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tasks
            future_to_file = {executor.submit(self._process_cve_file, cve_file): cve_file 
                             for cve_file in cve_files}
            
            # Process completed tasks
            for future in concurrent.futures.as_completed(future_to_file):
                cve_file = future_to_file[future]
                try:
                    future.result()  # This will raise any exception that occurred
                except ValueError as e:
                    # Log data validation errors specifically
                    self.log_data_processing(f"Data validation error in {cve_file}: {e}", "WARNING")
                except Exception as e:
                    # Log unexpected processing errors
                    self.log_data_processing(f"Unexpected error processing {cve_file}: {e}", "WARNING")
                    
                # Update progress every 1000 files or every 5 seconds
                with self._lock:
                    current_time = time.time()
                    if (self.processed_files % 1000 == 0 or 
                        current_time - self.last_progress_time >= 5.0):
                        
                        elapsed = current_time - self.start_time
                        rate = self.processed_files / elapsed if elapsed > 0 else 0
                        eta = (len(cve_files) - self.processed_files) / rate if rate > 0 else 0
                        
                        self.log_data_processing(
                            f"Progress: {self.processed_files:,}/{len(cve_files):,} "
                            f"({self.processed_files/len(cve_files)*100:.1f}%) - "
                            f"{rate:.1f} files/sec - ETA: {eta/60:.1f}min - "
                            f"Matches: {self.matching_cves:,}"
                        )
                        self.last_progress_time = current_time
                        
        final_elapsed = time.time() - self.start_time
        final_rate = self.processed_files / final_elapsed if final_elapsed > 0 else 0
        
        self.log_data_processing(f"Completed processing {self.processed_files:,} files in {final_elapsed:.1f}s")
        self.log_data_processing(f"Average rate: {final_rate:.1f} files/sec")
        self.log_data_processing(f"Found {self.matching_cves:,} CVEs matching target UUID")
        self.log_data_processing(f"Skipped {self.skipped_files:,} files (fast filtering)")
        
    def _fast_uuid_check(self, file_content: str) -> bool:
        """Fast string-based UUID check before JSON parsing"""
        return self.target_uuid in file_content
        
    def _process_cve_file(self, cve_file: Path):
        """Process a single CVE file with optimized performance"""
        with self._lock:
            self.processed_files += 1
            
        try:
            # Read file content first for fast UUID filtering
            with open(cve_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Fast string-based filtering before JSON parsing
            if not self._fast_uuid_check(content):
                with self._lock:
                    self.skipped_files += 1
                return
                
            # Parse JSON only if UUID might be present
            try:
                cve_data = json.loads(content)
            except json.JSONDecodeError as e:
                # Log malformed JSON files for data quality tracking
                self.log_data_processing(f"Malformed JSON in {cve_file}: {e}", "WARNING")
                return
                
            if self._matches_target_uuid(cve_data):
                with self._lock:
                    self.matching_cves += 1
                self._extract_affected_data(cve_data)
                
        except (IOError, UnicodeDecodeError) as e:
            # Log file read errors for visibility
            self.log_data_processing(f"Cannot read file {cve_file}: {e}", "WARNING")
            
    def _matches_target_uuid(self, cve_data: Dict) -> bool:
        """Check if CVE data contains the target UUID"""
        containers = cve_data.get('containers', {})
        
        # Check CNA
        cna = containers.get('cna', {})
        if cna.get('providerMetadata', {}).get('orgId') == self.target_uuid:
            return True
            
        # Check ADP entries
        adp = containers.get('adp', [])
        if isinstance(adp, list):
            for adp_entry in adp:
                if adp_entry.get('providerMetadata', {}).get('orgId') == self.target_uuid:
                    return True
                    
        return False
        
    def _extract_affected_data(self, cve_data: Dict):
        """Extract affected product data from CVE"""
        cve_id = cve_data.get('cveMetadata', {}).get('cveId', 'Unknown')
        containers = cve_data.get('containers', {})
        
        # Process CNA affected data
        cna = containers.get('cna', {})
        affected = cna.get('affected', [])
        
        for affected_item in affected:
            self._process_affected_item(affected_item, cve_id)
            
        # Process ADP affected data  
        adp = containers.get('adp', [])
        if isinstance(adp, list):
            for adp_entry in adp:
                if adp_entry.get('providerMetadata', {}).get('orgId') == self.target_uuid:
                    affected = adp_entry.get('affected', [])
                    for affected_item in affected:
                        self._process_affected_item(affected_item, cve_id)
                        
    def _process_affected_item(self, affected_item: Dict, cve_id: str):
        """Process a single affected item and extract alias information"""
        # Check if we have at least one meaningful property
        meaningful_properties = []
        for prop in ['vendor', 'product', 'platforms', 'modules', 'packageName', 'repo', 'programRoutines', 'programFiles', 'collectionURL']:
            if prop in affected_item and not self._is_placeholder_value(affected_item[prop]):
                meaningful_properties.append(prop)
        
        # Silently skip if no meaningful properties (expected for many CVEs)
        if not meaningful_properties:
            with self._lock:
                self.filtering_stats['entire_aliases_rejected'] += 1
            return
        
        # Extract all available properties (vendor/product may be None)
        vendor = affected_item.get('vendor')
        product = affected_item.get('product')
        
        # Handle platform expansion - break platform arrays into individual entries
        platforms = affected_item.get('platforms', [])
        if not platforms:
            # If no platforms specified, create one entry without platform data
            self._create_alias_entry(affected_item, cve_id, vendor, product, None)
        else:
            # Create separate alias entries for each platform
            for platform in platforms:
                # Skip placeholder platforms
                if not self._is_placeholder_value(platform):
                    self._create_alias_entry(affected_item, cve_id, vendor, product, platform)
                else:
                    with self._lock:
                        self.filtering_stats['platforms'] += 1
            
    def _create_alias_entry(self, affected_item: Dict, cve_id: str, vendor: str = None, product: str = None, platform: str = None):
        """Create or update alias entry for the mapping with placeholder filtering"""
        
        # Batch filtering statistics to minimize locking
        stats_updates = {}
        
        # Filter out placeholder properties and build meaningful alias object
        alias_data = {'source_cve': []}
        
        # Core identification fields - only include if meaningful and not None
        if vendor is not None and not self._is_placeholder_value(vendor):
            alias_data['vendor'] = vendor
        elif vendor is not None and self._is_placeholder_value(vendor):
            stats_updates['vendor'] = stats_updates.get('vendor', 0) + 1
                
        if product is not None and not self._is_placeholder_value(product):
            alias_data['product'] = product  
        elif product is not None and self._is_placeholder_value(product):
            stats_updates['product'] = stats_updates.get('product', 0) + 1
                
        if platform is not None and not self._is_placeholder_value(platform):
            alias_data['platform'] = platform
        
        # Additional CVE 5.X fields - only include if they exist and are meaningful
        # Note: defaultStatus is excluded as it doesn't represent alias data
        additional_fields = ['collectionURL', 'packageName', 'repo']
        
        for field_name in additional_fields:
            if field_name in affected_item:
                field_value = affected_item[field_name]
                if not self._is_placeholder_value(field_value):
                    alias_data[field_name] = field_value
                else:
                    stats_updates[field_name] = stats_updates.get(field_name, 0) + 1
        
        # Handle complex fields (arrays) if they exist and have meaningful content
        for complex_field in ['programRoutines', 'programFiles', 'modules']:
            if complex_field in affected_item:
                field_value = affected_item[complex_field]
                if isinstance(field_value, list):
                    # Filter placeholder values from arrays
                    meaningful_values = [v for v in field_value if not self._is_placeholder_value(v)]
                    if meaningful_values:
                        alias_data[complex_field] = meaningful_values
                    # Count only the individual placeholder values that were filtered out
                    placeholder_count = len([v for v in field_value if self._is_placeholder_value(v)])
                    if placeholder_count > 0:
                        stats_updates[complex_field] = stats_updates.get(complex_field, 0) + placeholder_count
                elif not self._is_placeholder_value(field_value):
                    alias_data[complex_field] = field_value
                else:
                    stats_updates[complex_field] = stats_updates.get(complex_field, 0) + 1
        
        # Only create alias if it has at least some meaningful data (beyond just source_cve)
        if len(alias_data) > 1:  # More than just 'source_cve'
            # Create unique key based on ALL meaningful properties (flexible grouping)
            key_parts = []
            # Sort keys to ensure consistent ordering
            for key_field in sorted(alias_data.keys()):
                if key_field != 'source_cve':  # Exclude source_cve from grouping key
                    key_parts.append(f"{key_field}:{str(alias_data[key_field]).lower()}")
            alias_key = '||'.join(key_parts)
            
            # Store in global mappings with single lock
            with self._lock:
                if alias_key not in self.extracted_mappings:
                    self.extracted_mappings[alias_key] = alias_data.copy()
                    
                # Add CVE reference
                if cve_id not in self.extracted_mappings[alias_key]['source_cve']:
                    self.extracted_mappings[alias_key]['source_cve'].append(cve_id)
                    
                # Update all statistics in one lock
                for stat_key, count in stats_updates.items():
                    self.filtering_stats[stat_key] += count
        else:
            # Alias has no meaningful data beyond CVE reference - skip it
            with self._lock:
                self.filtering_stats['entire_aliases_rejected'] += 1
                # Update any other statistics
                for stat_key, count in stats_updates.items():
                    self.filtering_stats[stat_key] += count
    
    def _generate_standard_confirmed_mappings_format(self, confirmed_aliases: List[Dict]) -> List[Dict]:
        """Generate confirmed mappings in standard format with merged CVE data from extracted aliases"""
        # Start with the original confirmed mappings file structure (if loaded)
        if self.confirmed_mappings and 'confirmedMappings' in self.confirmed_mappings:
            # Create a lookup for CVE data by vendor:product:platform
            cve_data_lookup = {}
            for alias in confirmed_aliases:
                vendor = alias.get('vendor', '').lower()
                product = alias.get('product', '').lower()
                # Handle both 'platform' and 'platforms' fields from extracted data
                platform = alias.get('platform', alias.get('platforms', '')).lower()
                
                # Create multiple lookup keys for flexibility
                keys = [
                    f"{vendor}:{product}:{platform}",           # Full key
                    f"{vendor}:{product}:",                     # Empty platform
                    f"{vendor}:{product}"                       # No platform separator
                ]
                
                # Remove duplicates and empty keys
                keys = list(set(key for key in keys if key and not key.endswith(':')))
                
                for key in keys:
                    if key not in cve_data_lookup:
                        cve_data_lookup[key] = {
                            'source_cve': [],
                            'frequency': 0
                        }
                    
                    # Merge CVE data
                    cve_data_lookup[key]['source_cve'].extend(alias.get('source_cve', []))
                    cve_data_lookup[key]['frequency'] += alias.get('frequency', len(alias.get('source_cve', [])))
            
            # Enhance each confirmed mapping with CVE data
            enhanced_mappings = []
            for mapping in self.confirmed_mappings['confirmedMappings']:
                cpe_string = mapping.get('cpebasestring') or mapping.get('cpeBaseString')
                if not cpe_string:
                    continue
                    
                enhanced_mapping = {
                    'cpebasestring': cpe_string,
                    'aliases': []
                }
                
                for alias in mapping.get('aliases', []):
                    enhanced_alias = {
                        'vendor': alias.get('vendor', ''),
                        'product': alias.get('product', '')
                    }
                    
                    # Add platform if present
                    if alias.get('platform'):
                        enhanced_alias['platform'] = alias.get('platform')
                    
                    # Look up CVE data for this alias - try multiple key combinations
                    vendor = alias.get('vendor', '').lower()
                    product = alias.get('product', '').lower()
                    platform = alias.get('platform', '').lower()
                    
                    # Try different key combinations to match the extracted data
                    possible_keys = [
                        f"{vendor}:{product}:{platform}",           # vendor:product:platform
                        f"{vendor}:{product}:",                     # vendor:product: (empty platform)
                        f"{vendor}:{product}"                       # vendor:product (no platform separator)
                    ]
                    
                    cve_data = None
                    for lookup_key in possible_keys:
                        if lookup_key in cve_data_lookup:
                            cve_data = cve_data_lookup[lookup_key]
                            break
                    
                    if cve_data:
                        # Merge CVE data into the alias
                        enhanced_alias['source_cve'] = sorted(list(set(cve_data['source_cve'])))
                        enhanced_alias['frequency'] = cve_data['frequency']
                    else:
                        # No CVE matches found for this confirmed mapping alias
                        enhanced_alias['source_cve'] = []
                    
                    enhanced_mapping['aliases'].append(enhanced_alias)
                
                enhanced_mappings.append(enhanced_mapping)
                
            return enhanced_mappings
        
        # Fallback: If no confirmed mappings file was loaded, generate from found aliases
        if not confirmed_aliases:
            return []
        
        # Group by CPE base string
        cpe_groups = {}
        for alias in confirmed_aliases:
            cpe_string = alias.get('cpe_base_string', '')
            if not cpe_string:
                continue
                
            if cpe_string not in cpe_groups:
                cpe_groups[cpe_string] = []
                
            # Clean alias for standard format
            clean_alias = {
                'vendor': alias.get('vendor', ''),
                'product': alias.get('product', '')
            }
            
            # Add platform if present
            if alias.get('platform'):
                clean_alias['platform'] = alias.get('platform')
                
            cpe_groups[cpe_string].append(clean_alias)
        
        # Convert to standard format
        standard_mappings = []
        for cpe_string, aliases in cpe_groups.items():
            standard_mappings.append({
                'cpebasestring': cpe_string,
                'aliases': aliases
            })
        
        return standard_mappings
            
    def _calculate_platform_statistics(self, confirmed_aliases, unconfirmed_mappings):
        """Calculate platform distribution statistics for metadata"""
        platform_stats = {
            'total_platforms_extracted': 0,
            'unique_platforms': set(),
            'platform_distribution': {},
            'confirmed_platforms': set(),
            'unconfirmed_platforms': set(),
            'top_platforms': []
        }
        
        # Analyze confirmed aliases
        for alias in confirmed_aliases:
            platform = alias.get('platform')
            if platform and not self._is_placeholder_value(platform):
                platform_norm = platform.lower().strip()
                platform_stats['unique_platforms'].add(platform_norm)
                platform_stats['confirmed_platforms'].add(platform_norm)
                platform_stats['total_platforms_extracted'] += 1
                
                if platform_norm not in platform_stats['platform_distribution']:
                    platform_stats['platform_distribution'][platform_norm] = {
                        'confirmed': 0, 'unconfirmed': 0, 'total': 0
                    }
                platform_stats['platform_distribution'][platform_norm]['confirmed'] += 1
                platform_stats['platform_distribution'][platform_norm]['total'] += 1
        
        # Analyze unconfirmed aliases
        for alias_data in unconfirmed_mappings.values():
            platform = alias_data.get('platform')
            if platform and not self._is_placeholder_value(platform):
                platform_norm = platform.lower().strip()
                platform_stats['unique_platforms'].add(platform_norm)
                platform_stats['unconfirmed_platforms'].add(platform_norm)
                platform_stats['total_platforms_extracted'] += 1
                
                if platform_norm not in platform_stats['platform_distribution']:
                    platform_stats['platform_distribution'][platform_norm] = {
                        'confirmed': 0, 'unconfirmed': 0, 'total': 0
                    }
                platform_stats['platform_distribution'][platform_norm]['unconfirmed'] += 1
                platform_stats['platform_distribution'][platform_norm]['total'] += 1
        
        # Calculate top platforms by total usage
        platform_list = [(platform, stats['total']) for platform, stats in platform_stats['platform_distribution'].items()]
        platform_stats['top_platforms'] = sorted(platform_list, key=lambda x: x[1], reverse=True)[:10]
        
        # Convert sets to lists for JSON serialization
        platform_stats['unique_platforms'] = list(platform_stats['unique_platforms'])
        platform_stats['confirmed_platforms'] = list(platform_stats['confirmed_platforms'])
        platform_stats['unconfirmed_platforms'] = list(platform_stats['unconfirmed_platforms'])
        
        return platform_stats
        
    def _generate_output(self):
        """Generate the final confirmed mappings output with optimized confirmed mapping processing"""
        self.log_data_processing("Generating confirmed mappings output")
        
        # Batch process all aliases for confirmed mappings (deferred until after data collection)
        confirmed_aliases, unconfirmed_mappings = self._batch_process_confirmed_mappings()
        
        # Group unconfirmed aliases by their property pattern (not values) for meaningful organization
        consolidated_groups: Dict[str, List[Dict]] = {}
        
        for alias_data in unconfirmed_mappings.values():
            # Create grouping key based on property types (not values)
            property_types = []
            for key_field in sorted(alias_data.keys()):
                if key_field != 'source_cve':
                    if isinstance(alias_data[key_field], list):
                        property_types.append(f"{key_field}({len(alias_data[key_field])})")
                    else:
                        property_types.append(key_field)
            
            # Create a meaningful group name
            group_key = "_".join(property_types) if property_types else "unknown_properties"
            
            if group_key not in consolidated_groups:
                consolidated_groups[group_key] = []
                
            consolidated_groups[group_key].append(alias_data)
            
        # Create alias groups from consolidated groups
        alias_groups = []
        for group_key, aliases in consolidated_groups.items():
            # Sort aliases by CVE count (most referenced first)
            aliases.sort(key=lambda x: len(x['source_cve']), reverse=True)
            
            alias_groups.append({
                'alias_group': group_key,
                'aliases': aliases
            })
            
        # Sort alias groups by total alias count (largest first)
        alias_groups.sort(key=lambda group: -len(group['aliases']))
        
        # Generate standard confirmed mappings format
        standard_confirmed_mappings = self._generate_standard_confirmed_mappings_format(confirmed_aliases)
        
        # Calculate platform distribution statistics
        platform_stats = self._calculate_platform_statistics(confirmed_aliases, unconfirmed_mappings)
        
        # Create output structure
        output_data = {
            'metadata': {
                'extraction_timestamp': datetime.now().isoformat(),
                'target_uuid': self.target_uuid,
                'cve_repository_path': str(self.cve_repo_path),
                'total_files_processed': self.processed_files,
                'matching_cves_found': self.matching_cves,
                'unique_aliases_extracted': len(self.extracted_mappings),
                'confirmed_mappings_matched': len(confirmed_aliases),
                'placeholder_aliases_filtered': sum(self.filtering_stats.values()),
                'product_groups_created': len(alias_groups),
                'run_id': self.run_id,
                'confirmed_mappings_file_loaded': bool(self.confirmed_mappings),
                'platform_statistics': platform_stats,
                'filtering_details': self.filtering_stats
            },
            'aliasGroups': alias_groups,
            'confirmedMappings': standard_confirmed_mappings
        }
        
        # Write output file to logs directory (single output file only)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"source_mapping_extraction_{self.target_uuid[:8]}_{timestamp}.json"
        output_path = self.run_paths["logs"] / output_filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
            
        self.log_data_processing(f"Output written to: {output_path}")
        self.log_data_processing(f"Generated {len(alias_groups)} product groups with {len(self.extracted_mappings)} unique aliases")
        
        if confirmed_aliases:
            self.log_data_processing(f"Assigned {len(confirmed_aliases)} aliases to confirmed mappings")
        else:
            self.log_data_processing("No aliases matched existing confirmed mappings")


def main():
    """Main entry point for the source mapping curator"""
    parser = argparse.ArgumentParser(
        description="Extract CVE source data mappings for confirmed mapping generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract Microsoft mappings (full dataset - may take hours)
  python curator.py --cve-repo E:\\Git\\cvelistV5\\cves --uuid f38d906d-7342-40ea-92c1-6c4a2c6478c8

  # Extract limited sample (fast testing)
  python curator.py --cve-repo E:\\Git\\cvelistV5\\cves --uuid f38d906d-7342-40ea-92c1-6c4a2c6478c8 --limit 1000

  # Extract recent CVEs only (faster, focuses on current data)
  python curator.py --cve-repo E:\\Git\\cvelistV5\\cves --uuid f38d906d-7342-40ea-92c1-6c4a2c6478c8 --limit 5000 --recent

  # High-performance extraction with more threads
  python curator.py --cve-repo E:\\Git\\cvelistV5\\cves --uuid f38d906d-7342-40ea-92c1-6c4a2c6478c8 --threads 8

Performance Notes:
  - Full dataset (300k+ files): 15-45 minutes depending on hardware
  - Limited samples (1k-10k files): 30 seconds - 2 minutes
  - --recent flag prioritizes newer CVEs for sampling
  - More threads help but may be I/O bound on slower drives

Microsoft UUID: f38d906d-7342-40ea-92c1-6c4a2c6478c8
        """
    )
    
    parser.add_argument(
        '--cve-repo',
        required=True,
        help='Path to the CVE 5.X repository directory'
    )
    
    parser.add_argument(
        '--uuid',
        required=True,
        help='Target CNA/ADP UUID to extract mappings for'
    )
    
    parser.add_argument(
        '--context',
        help='Optional context string for run directory naming'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit number of files to process (useful for testing/sampling)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=4,
        help='Number of worker threads (default: 4)'
    )
    
    parser.add_argument(
        '--recent',
        action='store_true',
        help='Prioritize recent CVEs when sampling (useful with --limit)'
    )
    
    args = parser.parse_args()
    
    try:
        curator = SourceMappingCurator(
            cve_repository_path=args.cve_repo,
            target_uuid=args.uuid,
            run_context=args.context,
            max_files=args.limit,
            threads=args.threads,
            sample_recent=args.recent
        )
        
        print(f"Starting source mapping extraction...")
        if args.limit:
            print(f"Processing limit: {args.limit:,} files")
        if args.recent:
            print(f"Prioritizing recent CVEs")
        print(f"Worker threads: {args.threads}")
        print()
        
        curator.start_extraction()
        
        print(f"\n[SUCCESS] Source mapping extraction completed successfully!")
        print(f"[DIR] Run directory: {curator.run_path}")
        print(f"[STATS] Files processed: {curator.processed_files:,}")
        print(f"[STATS] Matching CVEs: {curator.matching_cves:,}")
        print(f"[STATS] Unique aliases: {len(curator.extracted_mappings):,}")
        
        # Show confirmed mapping statistics
        if curator.confirmed_mappings:
            confirmed_count = sum(1 for alias_data in curator.extracted_mappings.values() 
                                if curator._alias_matches_confirmed_mapping(alias_data))
            print(f"[CONFIRMED] Confirmed mappings loaded: ✓")
            print(f"[CONFIRMED] Aliases matched to confirmed mappings: {confirmed_count:,}")
        else:
            print(f"[CONFIRMED] No confirmed mappings file found")
        
        # Calculate total filtered
        total_filtered = sum(curator.filtering_stats.values())
        print(f"[FILTER] Total placeholder properties filtered: {total_filtered:,}")
        print(f"   |- vendor: {curator.filtering_stats['vendor']:,}")
        print(f"   |- product: {curator.filtering_stats['product']:,}")
        print(f"   |- platforms: {curator.filtering_stats['platforms']:,}")
        print(f"   |- collectionURL: {curator.filtering_stats['collectionURL']:,}")
        print(f"   |- packageName: {curator.filtering_stats['packageName']:,}")
        print(f"   |- repo: {curator.filtering_stats['repo']:,}")
        print(f"   |- programRoutines: {curator.filtering_stats['programRoutines']:,}")
        print(f"   |- programFiles: {curator.filtering_stats['programFiles']:,}")
        print(f"   |- modules: {curator.filtering_stats['modules']:,}")
        print(f"   +- entire aliases rejected: {curator.filtering_stats['entire_aliases_rejected']:,}")
        
        print(f"[PERF] Files skipped (fast filter): {curator.skipped_files:,}")
        print(f"\n[OUTPUT] Output file ready for Analysis_Tools integration:")
        
        # Show the actual output file path - find the most recent file
        logs_dir = curator.run_paths["logs"]
        output_files = list(logs_dir.glob("source_mapping_extraction_*.json"))
        if output_files:
            latest_file = max(output_files, key=lambda f: f.stat().st_mtime)
            print(f"[FILE] {latest_file}")
        
        print(f"\n[DASHBOARD] Analyze results with: dashboards/sourceMappingDashboard.html")
        
    except Exception as e:
        print(f"[ERROR] Error during source mapping extraction: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
