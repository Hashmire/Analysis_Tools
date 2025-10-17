#!/usr/bin/env python3
"""
NVD Source UUID Harvester and Dataset Processor
This script fetches all source UUIDs from the NVD sources API and processes them
through generate_dataset.py with the specified parameters.
"""

import requests
import json
import subprocess
import sys
import argparse
import time
import os
from pathlib import Path


def get_analysis_tools_root():
    """Get the absolute path to the Analysis_Tools project root"""
    current_file = Path(__file__).resolve()
    return current_file.parent


def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'src', 'analysis_tool', 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)


def create_source_data_cache(api_key):
    """
    Create a localized cache of NVD source data for the harvest session.
    This prevents each subprocess from having to reload the same source data.
    """
    print("🔄 Initializing NVD source data cache for harvest session...")
    
    try:
        # Import the source manager
        sys.path.insert(0, str(get_analysis_tools_root() / "src"))
        from analysis_tool.storage.nvd_source_manager import get_global_source_manager, try_load_from_environment_cache
        from analysis_tool.core.gatherData import gatherNVDSourceData
        
        # Check existing cache age and refresh if needed
        source_manager = get_global_source_manager()
        
        # Check if we need to refresh the cache
        should_refresh = True
        if not source_manager.is_initialized():
            # Try to load existing cache first
            if try_load_from_environment_cache():
                print("🔄 Found existing cache, checking age...")
                
                # Check cache age
                from datetime import datetime
                import json
                from pathlib import Path
                
                try:
                    cache_metadata_path = get_analysis_tools_root() / "src" / "cache" / "cache_metadata.json"
                    if cache_metadata_path.exists():
                        with open(cache_metadata_path, 'r') as f:
                            metadata = json.load(f)
                        
                        if 'datasets' in metadata and 'nvd_source_data' in metadata['datasets']:
                            last_updated = datetime.fromisoformat(metadata['datasets']['nvd_source_data']['last_updated'])
                            age_hours = (datetime.now() - last_updated).total_seconds() / 3600
                            
                            if age_hours < 6:  # Cache is less than 6 hours old
                                print(f"✅ Using existing cache (age: {age_hours:.1f} hours)")
                                should_refresh = False
                            else:
                                print(f"⚠️  Cache is {age_hours:.1f} hours old - refreshing")
                except Exception as e:
                    print(f"⚠️  Could not check cache age: {e} - refreshing anyway")
        
        if should_refresh:
            print("🔄 Fetching fresh NVD source data...")
            source_data = gatherNVDSourceData(api_key)
            source_manager.initialize(source_data)
        else:
            print("🔄 Using cached NVD source data")
        
        # Create cache file for cross-process sharing
        cache_file_path = source_manager.create_localized_cache()
        
        print(f"✅ Source data cached: {source_manager.get_source_count()} sources")
        print(f"   Cache file: {cache_file_path}")
        return cache_file_path
        
    except Exception as e:
        print(f"⚠️  Warning: Could not create source data cache: {e}")
        print("   Each subprocess will load source data independently")
        return None


def cleanup_source_data_cache(cache_file_path):
    """Clean up the temporary source data cache file"""
    if cache_file_path:
        try:
            # Use the source manager to clean up properly
            sys.path.insert(0, str(get_analysis_tools_root() / "src"))
            from analysis_tool.storage.nvd_source_manager import cleanup_cache
            
            cleanup_cache(cache_file_path)
            print(f"🗑️  Cleaned up source data cache")
        except Exception as e:
            print(f"⚠️  Warning: Could not clean up cache file: {e}")


def check_source_cve_count(source_uuid, api_key, max_count):
    """
    Check how many CVEs a source has before processing
    Returns tuple: (count, should_skip)
    """
    print(f"  Checking CVE count for source {source_uuid}...")
    
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {}
        if api_key:
            headers["apiKey"] = api_key
        
        params = {
            "sourceIdentifier": source_uuid,
            "resultsPerPage": 1  # We only need the total count
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        total_results = data.get('totalResults', 0)
        
        print(f"  Source has {total_results:,} CVE records")
        
        should_skip = total_results > max_count
        if should_skip:
            print(f"  ⚠️  SKIPPING: Source exceeds maximum threshold of {max_count:,} CVEs ({total_results:,} found)")
        
        return total_results, should_skip
        
    except Exception as e:
        print(f"  ⚠️  Warning: Could not check CVE count for source {source_uuid}: {e}")
        print(f"  Proceeding with processing (assuming under threshold)")
        return 0, False


def harvest_source_uuids():
    """
    Fetch all source UUIDs from the NVD sources API
    Returns a tuple: (source_info_list, api_totals_dict)
    where source_info_list is [(source_name, source_uuid, last_modified), ...]
    and api_totals_dict contains counts for reporting
    """
    print("Harvesting source UUIDs from NVD API...")
    
    try:
        response = requests.get("https://services.nvd.nist.gov/rest/json/source/2.0", timeout=30)
        response.raise_for_status()
        
        data = response.json()
        sources = data.get('sources', [])
        
        print(f"📊 NVD API Report:")
        print(f"   Total sources in API: {len(sources)}")
        
        source_info = []
        seen_uuids = set()
        duplicates_found = 0
        no_uuid_sources = []
        
        for source in sources:
            source_name = source.get('name', 'Unknown')
            last_modified = source.get('lastModified', '1970-01-01T00:00:00.000')
            source_identifiers = source.get('sourceIdentifiers', [])
            
            # Find UUID-format identifier (36 characters with dashes)
            uuid_identifier = None
            for identifier in source_identifiers:
                if len(identifier) == 36 and identifier.count('-') == 4:
                    uuid_identifier = identifier
                    break
            
            if uuid_identifier:
                if uuid_identifier in seen_uuids:
                    print(f"  - {source_name}: {uuid_identifier} (DUPLICATE - skipping)")
                    duplicates_found += 1
                else:
                    seen_uuids.add(uuid_identifier)
                    source_info.append((source_name, uuid_identifier, last_modified))
                    print(f"  - {source_name}: {uuid_identifier} (modified: {last_modified})")
            else:
                no_uuid_sources.append(source_name)
                print(f"  - {source_name}: No UUID identifier found")
        
        # Report filtering results
        print(f"\n📋 Source Filtering Summary:")
        print(f"   Total sources from API: {len(sources)}")
        print(f"   Sources without UUID: {len(no_uuid_sources)} (filtered out)")
        if no_uuid_sources:
            print(f"      Sources without UUID: {', '.join(no_uuid_sources)}")
        print(f"   Sources with UUID: {len(sources) - len(no_uuid_sources)}")
        if duplicates_found > 0:
            print(f"   Duplicate UUIDs found: {duplicates_found} (filtered out)")
        print(f"   Unique sources available for processing: {len(source_info)}")
        
        # Sort by lastModified descending (newest first) to prioritize less prominent sources
        source_info.sort(key=lambda x: x[2], reverse=True)
        
        print(f"\nHarvested {len(source_info)} unique source UUIDs (sorted by lastModified, newest first)")
        
        # Return both the source info and the totals for reporting
        api_totals = {
            'total_from_api': len(sources),
            'sources_without_uuid': len(no_uuid_sources),
            'sources_with_uuid': len(sources) - len(no_uuid_sources),
            'duplicates_found': duplicates_found,
            'unique_sources_available': len(source_info)
        }
        
        return source_info, api_totals
        
    except requests.RequestException as e:
        print(f"Error fetching source data: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response: {e}")
        sys.exit(1)


def run_generate_dataset(source_name, source_uuid, allow_logging=True, cache_file_path=None, **kwargs):
    """
    Run generate_dataset.py for a specific source UUID
    
    Args:
        source_name (str): Human-readable source name for logging
        source_uuid (str): UUID of the source to process
        allow_logging (bool): Whether to allow console logging to pass through
        cache_file_path (str): Path to NVD source data cache file for efficient loading
        **kwargs: All processed parameters to pass to generate_dataset.py
    """
    project_root = get_analysis_tools_root()
    generate_script = project_root / "generate_dataset.py"
    
    # Build command - all parameters have been intelligently processed
    cmd = [
        sys.executable,
        str(generate_script),
        "--api-key", kwargs['api_key'],
        "--source-uuid", source_uuid
    ]
    
    # Add feature flags (only add flags that are true)
    if kwargs['sdc_report']:
        cmd.extend(["--sdc-report"])
    if kwargs['cpe_suggestions']:
        cmd.extend(["--cpe-suggestions"])
    if kwargs['alias_report']:
        cmd.extend(["--alias-report"])
    if kwargs['cpe_as_generator']:
        cmd.extend(["--cpe-as-generator"])
    
    # Add optional parameters only if they exist
    if 'local_cve_repo' in kwargs:
        cmd.extend(["--local-cve-repo", kwargs['local_cve_repo']])
    
    if kwargs.get('external_assets'):
        cmd.extend(["--external-assets"])
    
    if 'statuses' in kwargs:
        cmd.extend(["--statuses"] + kwargs['statuses'])
    
    if 'last_days' in kwargs:
        cmd.extend(["--last-days", str(kwargs['last_days'])])
    
    if 'start_date' in kwargs:
        cmd.extend(["--start-date", kwargs['start_date']])
    
    if 'end_date' in kwargs:
        cmd.extend(["--end-date", kwargs['end_date']])
    
    print(f"\n{'='*60}")
    print(f"Processing source: {source_name}")
    print(f"UUID: {source_uuid}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*60}")
    
    try:
        # Prepare environment with cache path for subprocess
        env = os.environ.copy()
        if cache_file_path:
            env['NVD_SOURCE_CACHE_PATH'] = cache_file_path
            print(f"Using cached source data: {cache_file_path}")
        
        if allow_logging:
            # Allow all output to pass through to console
            result = subprocess.run(cmd, check=True, cwd=project_root, env=env)
        else:
            # Capture output but still show it
            result = subprocess.run(cmd, check=True, cwd=project_root, 
                                  capture_output=False, text=True, env=env)
        
        print(f"[SUCCESS] Successfully processed {source_name}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Error processing {source_name}: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected error processing {source_name}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Harvest NVD source UUIDs and process them through generate_dataset.py"
    )
    
    # Load configuration first to get defaults
    try:
        config = load_config()
        harvest_config = config.get('harvest_and_process_sources', {})
        defaults_config = config.get('defaults', {})
        local_cve_config = config.get('local_cve_repository', {})
    except Exception as e:
        print(f"Warning: Could not load config file: {e}")
        harvest_config = {}
        defaults_config = {}
        local_cve_config = {}
    
    # Tool Output - Feature flags (always pass explicit boolean values)
    output_group = parser.add_argument_group('Tool Output', 'Select which analysis outputs to generate')
    output_group.add_argument(
        "--sdc-report",
        nargs='?',
        const='true',
        choices=['true', 'false'],
        help="Generate Source Data Concerns report (default: false, true if flag provided without value)"
    )
    output_group.add_argument(
        "--cpe-suggestions",
        nargs='?',
        const='true', 
        choices=['true', 'false'],
        help="Generate CPE suggestions via NVD CPE API calls (default: false, true if flag provided without value)"
    )
    output_group.add_argument(
        "--alias-report",
        nargs='?',
        const='true',
        choices=['true', 'false'],
        help="Enable alias report generation for curator functionality (default: false, true if flag provided without value)"
    )
    output_group.add_argument(
        "--cpe-as-generator",
        nargs='?',
        const='true',
        choices=['true', 'false'],
        help="Generate CPE Applicability Statements as interactive HTML pages (default: false, true if flag provided without value)"
    )
    
    # Dataset Generation - Parameters intelligently handled before passing to generate_dataset
    dataset_group = parser.add_argument_group('Dataset Generation', 'Control CVE data selection and dataset creation')
    dataset_group.add_argument(
        "--api-key",
        nargs='?',
        const='CONFIG_DEFAULT',
        help="NVD API key. Use without value to use config default, or provide explicit key"
    )
    dataset_group.add_argument(
        "--local-cve-repo",
        nargs='?',
        const='CONFIG_DEFAULT',
        help="Path to local CVE repository. Use without value to use config default, or provide explicit path"
    )
    dataset_group.add_argument(
        "--external-assets",
        action="store_true",
        help="Enable external assets in analysis"
    )
    dataset_group.add_argument(
        "--statuses",
        nargs='*',
        help="Vulnerability statuses to include"
    )
    dataset_group.add_argument(
        "--last-days",
        type=int,
        help="Generate dataset for CVEs modified in the last N days"
    )
    dataset_group.add_argument(
        "--start-date",
        type=str,
        help="Start date for lastModified filter (YYYY-MM-DD or ISO format)"
    )
    dataset_group.add_argument(
        "--end-date",
        type=str,
        help="End date for lastModified filter (YYYY-MM-DD or ISO format)"
    )
    
    # Harvest Control - Parameters only relevant to this script
    harvest_group = parser.add_argument_group('Harvest Control', 'Control source harvesting behavior')
    harvest_group.add_argument(
        "--quiet-individual",
        action="store_true",
        default=harvest_config.get('quiet_individual', False),
        help=f"Don't show individual generate_dataset.py output (default: {harvest_config.get('quiet_individual', False)})"
    )
    harvest_group.add_argument(
        "--max-cves",
        type=int,
        default=harvest_config.get('max_cves_per_source', 5000),
        help=f"Maximum number of CVEs a source can have before being skipped (default: {harvest_config.get('max_cves_per_source', 5000)})"
    )
    
    args = parser.parse_args()
    
    # === FEATURE FLAG VALIDATION ===
    # Ensure at least one tool output feature is enabled
    feature_flags = ['sdc_report', 'cpe_suggestions', 'alias_report', 'cpe_as_generator']
    enabled_features = []
    
    for flag in feature_flags:
        flag_value = getattr(args, flag, None)
        if flag_value is not None and flag_value.lower() == 'true':
            enabled_features.append(flag.replace('_', '-'))
    
    if not enabled_features:
        print("ERROR: At least one feature must be enabled for harvest processing!")
        print("Available features:")
        print("  --sdc-report               : Generate Source Data Concerns report")
        print("  --cpe-suggestions          : Generate CPE suggestions via NVD CPE API calls")
        print("  --alias-report             : Generate alias report via curator features")
        print("  --cpe-as-generator         : Generate CPE Applicability Statements as interactive HTML pages")
        print()
        print("Example usage:")
        print("  python harvest_and_process_sources.py --sdc-report")
        print("  python harvest_and_process_sources.py --cpe-suggestions --cpe-as-generator")
        sys.exit(1)
    
    # === INTELLIGENT PARAMETER HANDLING ===
    
    # Process Tool Output parameters (always pass explicit boolean values)
    processed_params = {}
    
    # Handle boolean flags - convert to explicit true/false
    for flag in ['sdc_report', 'cpe_suggestions', 'alias_report', 'cpe_as_generator']:
        flag_value = getattr(args, flag, None)
        if flag_value is not None:
            # Parameter provided - convert to boolean and pass with explicit value
            processed_params[flag] = flag_value.lower() == 'true' if isinstance(flag_value, str) else flag_value
        else:
            # No parameter provided - pass as false
            processed_params[flag] = False
    
    # Validate that at least one feature is enabled
    feature_enabled = any(processed_params[flag] for flag in ['sdc_report', 'cpe_suggestions', 'alias_report', 'cpe_as_generator'])
    if not feature_enabled:
        print("ERROR: At least one feature must be enabled for harvest processing!")
        print("Available features:")
        print("  --sdc-report               : Generate Source Data Concerns report")
        print("  --cpe-suggestions          : Generate CPE suggestions via NVD CPE API calls")
        print("  --alias-report             : Generate alias report via curator features")
        print("  --cpe-as-generator         : Generate CPE Applicability Statements as interactive HTML pages")
        print("")
        print("Example usage:")
        print("  python harvest_and_process_sources.py --sdc-report")
        print("  python harvest_and_process_sources.py --cpe-suggestions --cpe-as-generator")
        sys.exit(1)
    
    # Handle API key with intelligent config resolution
    api_key = None
    if args.api_key == 'CONFIG_DEFAULT':
        # Parameter provided without value - check config
        config_key = defaults_config.get('default_api_key')
        if config_key:
            api_key = config_key
        else:
            print("ERROR: API key is required for source harvesting and processing")
            print("No API key found in config.json default_api_key setting")
            print("Either provide --api-key <key> or set default_api_key in config.json")
            sys.exit(1)
    elif args.api_key:
        # Parameter provided with value - validate and use
        api_key = args.api_key
    else:
        # No parameter provided - check config
        config_key = defaults_config.get('default_api_key')
        if config_key:
            api_key = config_key
        else:
            print("ERROR: API key is required for source harvesting and processing")
            print("Either use --api-key parameter or set default_api_key in config.json")
            print("NVD API without a key has severe rate limits that make processing impractical")
            sys.exit(1)
    
    processed_params['api_key'] = api_key
    
    # Handle local CVE repo with intelligent config resolution
    if args.local_cve_repo == 'CONFIG_DEFAULT':
        # Parameter provided without value - check config for path
        config_path = local_cve_config.get('default_path')
        if config_path and os.path.exists(config_path):
            processed_params['local_cve_repo'] = config_path
        elif config_path:
            print(f"ERROR: Local CVE repository path from config does not exist: {config_path}")
            print("Check config.json local_cve_repository.default_path setting")
            sys.exit(1)
        else:
            print("ERROR: Local CVE repository path is required when using --local-cve-repo")
            print("No path found in config.json local_cve_repository.default_path setting")
            sys.exit(1)
    elif args.local_cve_repo:
        # Parameter provided with value - validate and use
        if os.path.exists(args.local_cve_repo):
            processed_params['local_cve_repo'] = args.local_cve_repo
        else:
            print(f"ERROR: Local CVE repository path does not exist: {args.local_cve_repo}")
            sys.exit(1)
    # If no parameter provided, don't pass it (let generate_dataset use its defaults)
    
    # Handle external assets
    if args.external_assets:
        processed_params['external_assets'] = True
    
    # Handle statuses with validation
    if hasattr(args, 'statuses') and args.statuses is not None:
        if len(args.statuses) == 0:
            # Parameter provided but no values - warn and don't pass
            print("WARNING: --statuses parameter provided without values, ignoring. Will default to 'all statuses'")
        else:
            # Validate status values
            valid_statuses = ['Received', 'Awaiting Analysis', 'Undergoing Analysis', 'Modified', 'Published', 'Rejected']
            invalid_statuses = [s for s in args.statuses if s not in valid_statuses]
            if invalid_statuses:
                print(f"ERROR: Invalid status values: {invalid_statuses}")
                print(f"Valid statuses are: {valid_statuses}")
                sys.exit(1)
            processed_params['statuses'] = args.statuses
    
    # Handle date parameters with validation
    for date_param in ['last_days', 'start_date', 'end_date']:
        value = getattr(args, date_param, None)
        if value is not None:
            if date_param == 'last_days':
                if value <= 0:
                    print(f"ERROR: --last-days must be a positive integer, got: {value}")
                    sys.exit(1)
                processed_params[date_param] = value
            elif date_param in ['start_date', 'end_date']:
                # Basic date format validation
                try:
                    from datetime import datetime
                    # Try parsing as YYYY-MM-DD first, then ISO format
                    if len(value) == 10 and value.count('-') == 2:
                        datetime.strptime(value, '%Y-%m-%d')
                    else:
                        datetime.fromisoformat(value.replace('Z', '+00:00'))
                    processed_params[date_param] = value
                except ValueError:
                    print(f"ERROR: Invalid date format for --{date_param.replace('_', '-')}: {value}")
                    print("Use YYYY-MM-DD or ISO format (e.g., 2024-01-01 or 2024-01-01T00:00:00Z)")
                    sys.exit(1)
        # If parameter provided without value, warn and don't pass
        elif hasattr(args, date_param) and getattr(args, date_param) == '':
            print(f"WARNING: --{date_param.replace('_', '-')} parameter provided without value, ignoring")
    
    print(f"Using API key for enhanced rate limits")
    
    print(f"Using API key for enhanced rate limits")
    
    # Harvest source UUIDs
    source_info, api_totals = harvest_source_uuids()
    
    if not source_info:
        print("No source UUIDs found to process")
        sys.exit(1)
    
    # Create localized source data cache for efficient subprocess sharing
    print(f"\n🔧 Preparing NVD source data cache for efficient processing...")
    cache_file_path = create_source_data_cache(processed_params['api_key'])
    
    # Process each source
    print(f"\nStarting to process {len(source_info)} sources...")
    
    successful = 0
    failed = 0
    skipped = 0
    skipped_sources = []  # Track skipped sources with details
    
    for i, (source_name, source_uuid, last_modified) in enumerate(source_info, 1):
        print(f"\n[{i}/{len(source_info)}] Processing {source_name} (modified: {last_modified})...")
        
        # Check CVE count first
        cve_count, should_skip = check_source_cve_count(source_uuid, processed_params['api_key'], args.max_cves)
        
        if should_skip:
            print(f"⏭️  Skipped {source_name} (too many CVEs: {cve_count:,})")
            skipped += 1
            skipped_sources.append((source_name, source_uuid, cve_count))
        else:
            success = run_generate_dataset(
                source_name=source_name,
                source_uuid=source_uuid,
                allow_logging=not args.quiet_individual,
                cache_file_path=cache_file_path,
                **processed_params
            )
            
            if success:
                successful += 1
            else:
                failed += 1
        
        # Small delay between requests to be respectful to the API
        if i < len(source_info):  # Don't delay after the last one
            time.sleep(1)
    
    # Summary
    print(f"\n{'='*60}")
    print(f"PROCESSING COMPLETE")
    print(f"{'='*60}")
    print(f"Total sources from NVD API: {api_totals['total_from_api']}")
    print(f"Sources filtered out (no UUID): {api_totals['sources_without_uuid']}")
    if api_totals['duplicates_found'] > 0:
        print(f"Sources filtered out (duplicates): {api_totals['duplicates_found']}")
    print(f"Sources available for processing: {api_totals['unique_sources_available']}")
    print(f"Sources actually processed: {successful + failed}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Skipped (too many CVEs): {skipped}")
    
    # Report skipped sources details
    if skipped_sources:
        print(f"\n📋 SKIPPED SOURCES REPORT:")
        print(f"The following {len(skipped_sources)} sources were skipped due to exceeding the CVE threshold of {args.max_cves:,}:")
        print(f"{'-'*80}")
        for source_name, source_uuid, cve_count in skipped_sources:
            print(f"• {source_name}")
            print(f"  UUID: {source_uuid}")
            print(f"  CVE Count: {cve_count:,}")
            print()
    
    # Clean up cache file
    if cache_file_path:
        print(f"\n🧹 Cleaning up cache...")
        cleanup_source_data_cache(cache_file_path)
    
    if failed > 0:
        print(f"\n⚠️  {failed} sources failed to process. Check the logs above for details.")
        sys.exit(1)
    else:
        print(f"\n✅ All processable sources completed successfully! ({skipped} sources skipped due to size)")


if __name__ == "__main__":
    main()