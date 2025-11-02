#!/usr/bin/env python3
"""
Automated test suite for provenance assistance functionality.
Tests the generated HTML file against expected outcomes for comprehensive validation.

For detailed documentation on test cases and how to extend this suite, see:
../documentation/provenance_assistance_test_suite.md
"""

import json
import re
import sys
import subprocess
import os
from pathlib import Path
from bs4 import BeautifulSoup
from typing import Dict, List, Set, Tuple

# Add src path for analysis_tool imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
from analysis_tool.storage.run_organization import get_latest_test_run_directory

class ProvenanceAssistanceTestSuite:
    def __init__(self, test_file_path: str):
        self.test_file_path = Path(test_file_path)
        self.html_file_path = None
        self.soup = None
        self.test_data = None
        self.results = []
        self.passed = 0
        self.failed = 0
        
    def generate_html(self):
        """Generate HTML file from test data using the analysis tool."""
        print("🔄 Generating HTML from test data...")
        
        # Get the project root path
        current_dir = Path.cwd()
        project_root = current_dir if (current_dir / "generate_dataset.py").exists() else current_dir.parent
        run_analysis_path = project_root / "src" / "analysis_tool" / "core" / "analysis_tool.py"
        
        if not run_analysis_path.exists():
            self.add_result("HTML_GENERATION", False, f"Analysis tool entry point not found at {run_analysis_path}")
            return False
        
        try:
            # Run the analysis tool to generate HTML using the entry point script
            # Disable cache for faster testing unless specifically testing cache functionality
            cmd = [
                sys.executable, 
                "-m", "src.analysis_tool.core.analysis_tool", 
                "--test-file", 
                str(self.test_file_path.resolve()),
                "--no-cache",
                "--cpe-as-generator", "true",  # Required for HTML generation
                "--sdc-report", "true"  # Required for Source Data Concerns analysis
            ]
            
            # Add --no-browser when running under unified test runner
            if os.environ.get('UNIFIED_TEST_RUNNER') == '1':
                cmd.append("--no-browser")
            
            result = subprocess.run(
                cmd,
                cwd=project_root,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=60
            )
            
            if result.returncode != 0:
                print(f"❌ Analysis tool failed with return code {result.returncode}")
                print(f"STDOUT: {result.stdout}")
                print(f"STDERR: {result.stderr}")
                self.add_result("HTML_GENERATION", False, f"Analysis tool failed: {result.stderr}")
                return False
            
            # Determine the expected HTML file path - test files go to run directories
            cve_id = self.test_data.get('cveMetadata', {}).get('cveId', 'CVE-UNKNOWN')
            
            # Use consolidated-aware helper to find the latest test run directory
            latest_test_run = get_latest_test_run_directory()
            
            if not latest_test_run:
                self.add_result("HTML_GENERATION", False, "No test run directory found")
                return False
                
            # Get the HTML file path
            self.html_file_path = latest_test_run / "generated_pages" / f"{cve_id}.html"
            
            if not self.html_file_path.exists():
                self.add_result("HTML_GENERATION", False, f"Generated HTML file not found: {self.html_file_path}")
                return False
            
            print(f"✅ HTML generated successfully: {self.html_file_path}")
            self.add_result("HTML_GENERATION", True, f"Generated {cve_id}.html")
            return True
            
        except subprocess.TimeoutExpired:
            self.add_result("HTML_GENERATION", False, "Analysis tool timed out")
            return False
        except Exception as e:
            self.add_result("HTML_GENERATION", False, f"Error running analysis tool: {e}")
            return False
    
    def load_files(self):
        """Load and parse HTML and test JSON files."""
        try:
            # Load test data first
            with open(self.test_file_path, 'r', encoding='utf-8') as f:
                self.test_data = json.load(f)
            
            # Generate HTML if it doesn't exist or we don't have a path
            if not self.html_file_path or not self.html_file_path.exists():
                if not self.generate_html():
                    return False
            
            # Load the generated HTML
            with open(self.html_file_path, 'r', encoding='utf-8') as f:
                self.soup = BeautifulSoup(f.read(), 'html.parser')
                
            return True
        except Exception as e:
            self.add_result("FILE_LOADING", False, f"Failed to load files: {e}")
            return False
    
    def add_result(self, test_name: str, passed: bool, details: str = ""):
        """Add a test result."""
        self.results.append({
            'test': test_name,
            'passed': passed,
            'details': details
        })
        if passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def extract_global_metadata(self) -> Dict:
        """Extract global CVE metadata from HTML."""
        metadata_div = self.soup.find('div', id='global-cve-metadata')
        if not metadata_div or not metadata_div.get('data-cve-metadata'):
            return {}        
        try:
            return json.loads(metadata_div['data-cve-metadata'])
        except json.JSONDecodeError:
            return {}
    
    def extract_platform_data(self, row_index: int) -> Dict:
        """Extract platform data for a specific row."""
        data_div = self.soup.find('code', id=f'rawPlatformData_{row_index}')
        if not data_div:
            print(f"DEBUG: Could not find rawPlatformData_{row_index}")
            return {}
        
        try:
            json_text = data_div.get_text()
            print(f"DEBUG: Found platform data for row {row_index}: {json_text[:100]}...")
            return json.loads(json_text)
        except json.JSONDecodeError as e:
            print(f"DEBUG: JSON decode error for row {row_index}: {e}")
            return {}
    
    def count_provenance_containers(self) -> int:
        """Count the number of provenance assistance containers."""
        containers = self.soup.find_all('div', id=re.compile(r'provenanceCollapse_\d+'))
        return len(containers)
    
    def check_javascript_functions_exist(self) -> bool:
        """Check that required JavaScript functions exist in the HTML."""
        html_content = str(self.soup)
        
        required_functions = [
            'isMavenRepository',
            'addMavenProvenanceLinks', 
            'addWordPressProvenanceLinks',
            'addGenericCollectionLinks',
            'addProvenanceLinks',
            'createDescriptionButtons',
            'createReferenceCards',
            'processProvenanceMetadata'
        ]
        
        missing_functions = []
        for func in required_functions:
            if f'function {func}' not in html_content:
                missing_functions.append(func)
        
        return len(missing_functions) == 0, missing_functions
    
    def check_provenance_structure(self) -> bool:
        """Check that provenance assistance structure exists in HTML."""
        container_count = self.count_provenance_containers()
        expected_count = len(self.test_data['containers']['cna']['affected'])
        
        if container_count != expected_count:
            self.add_result("PROVENANCE_STRUCTURE", False, 
                          f"Expected {expected_count} provenance containers, found {container_count}")
            return False
        
        # Check that each container has the required elements
        for i in range(container_count):
            container = self.soup.find('div', id=f'provenanceCollapse_{i}')
            if not container:
                self.add_result("PROVENANCE_STRUCTURE", False, 
                              f"Missing provenance container {i}")
                return False
            
            # Check for required sub-elements
            links_div = container.find('div', id=f'provenanceLinks_{i}')
            desc_div = container.find('div', id=f'descriptionButtons_{i}')
            content_div = container.find('div', id=f'descriptionContent_{i}')
            
            if not all([links_div, desc_div, content_div]):
                self.add_result("PROVENANCE_STRUCTURE", False, 
                              f"Missing required elements in container {i}")
                return False
        
        self.add_result("PROVENANCE_STRUCTURE", True, 
                       f"All {container_count} provenance containers found with required elements")
        return True
    
    def test_global_metadata_structure(self):
        """Test that global CVE metadata is properly structured."""
        metadata = self.extract_global_metadata()
        
        if not metadata:
            self.add_result("GLOBAL_METADATA", False, "No global CVE metadata found")
            return
        
        # Check required fields
        required_fields = ['cveId', 'descriptionData', 'referencesData', 'sourceData']
        missing_fields = [field for field in required_fields if field not in metadata]
        
        if missing_fields:
            self.add_result("GLOBAL_METADATA", False, f"Missing fields: {missing_fields}")
            return
        
        # Check CVE ID
        if metadata['cveId'] != 'CVE-1337-99998':
            self.add_result("GLOBAL_METADATA", False, f"Wrong CVE ID: {metadata['cveId']}")
            return
        
        # Check description data structure
        desc_data = metadata['descriptionData']
        if not isinstance(desc_data, list) or len(desc_data) == 0:
            self.add_result("GLOBAL_METADATA", False, "Invalid description data structure")
            return
        
        # Check reference data structure  
        ref_data = metadata['referencesData']
        if not isinstance(ref_data, list) or len(ref_data) == 0:
            self.add_result("GLOBAL_METADATA", False, "Invalid reference data structure")
            return
        
        self.add_result("GLOBAL_METADATA", True, 
                       f"Global metadata valid with {len(desc_data)} description sources, "
                       f"{len(ref_data)} reference sources")
    
    def test_description_data_completeness(self):
        """Test that description data includes all expected sources and languages."""
        metadata = self.extract_global_metadata()
        if not metadata:
            return
        
        desc_data = metadata.get('descriptionData', [])
        
        # Expected sources and languages
        expected_sources = {
            ('12345678-1234-1234-1234-123456789012', 'CNA'): ['en', 'es', 'fr', 'de'],
            ('87654321-4321-4321-4321-210987654321', 'ADP'): ['en', 'ja'],
            ('b15e7b5b-3da4-40ae-a43c-f7aa60e62599', 'ADP'): ['en']
        }
        
        found_sources = {}
        for source in desc_data:
            source_id = source.get('sourceId', '')
            source_role = source.get('sourceRole', '')
            descriptions = source.get('descriptions', [])
            languages = [desc.get('lang', '') for desc in descriptions]
            
            found_sources[(source_id, source_role)] = languages
        
        # Check each expected source
        for (source_id, role), expected_langs in expected_sources.items():
            if (source_id, role) not in found_sources:
                self.add_result("DESCRIPTION_DATA", False, 
                              f"Missing description source: {source_id} ({role})")
                return
            
            found_langs = found_sources[(source_id, role)]
            if set(found_langs) != set(expected_langs):
                self.add_result("DESCRIPTION_DATA", False, 
                              f"Wrong languages for {source_id}: expected {expected_langs}, found {found_langs}")
                return
        
        self.add_result("DESCRIPTION_DATA", True, 
                       f"All {len(expected_sources)} description sources found with correct languages")
    
    def test_reference_data_completeness(self):
        """Test that reference data includes expected tags and sources."""
        metadata = self.extract_global_metadata()
        if not metadata:
            return
        
        ref_data = metadata.get('referencesData', [])
        
        # Count references by tag across all sources
        tag_counts = {}
        total_refs = 0
        
        target_tags = {'patch', 'mitigation', 'product', 'issue-tracking'}
        
        for source in ref_data:
            references = source.get('references', [])
            for ref in references:
                total_refs += 1
                tags = ref.get('tags', [])
                for tag in tags:
                    if tag in target_tags:
                        tag_counts[tag] = tag_counts.get(tag, 0) + 1
        
        # Check that we have references for all target tags
        missing_tags = target_tags - set(tag_counts.keys())
        if missing_tags:
            self.add_result("REFERENCE_DATA", False, 
                          f"Missing references for tags: {missing_tags}")
            return
        
        # Check minimum counts (should have at least 2 of each type from our test data)
        insufficient_tags = [tag for tag, count in tag_counts.items() if count < 2]
        if insufficient_tags:
            self.add_result("REFERENCE_DATA", False, 
                          f"Insufficient references for tags: {insufficient_tags}")
            return
        
        self.add_result("REFERENCE_DATA", True, 
                       f"Reference data complete: {total_refs} total references, "
                       f"target tags: {dict(tag_counts)}")
    
    def test_platform_data_variety(self):
        """Test that platform data covers all expected scenarios."""
        container_count = self.count_provenance_containers()
        
        maven_repos = []
        non_maven_repos = []
        wordpress_repos = []
        repo_only = []
        
        for i in range(container_count):
            platform_data = self.extract_platform_data(i)
            if not platform_data:
                continue
            
            collection_url = platform_data.get('collectionURL', '')
            package_name = platform_data.get('packageName', '')
            repo = platform_data.get('repo', '')
            
            # Classify repository type based on our test data expectations
            if collection_url and package_name:
                # Apply same logic as JavaScript isMavenRepository function
                url_lower = collection_url.lower()
                maven_patterns = [
                    'repo1.maven.org', 'repo.maven.apache.org', 'central.maven.org',
                    '/maven2/', '/maven/', '/artifactory/', '/nexus/', 
                    'oss.sonatype.org', 'jitpack.io', 'clojars.org'
                ]
                
                has_maven_pattern = any(pattern in url_lower for pattern in maven_patterns)
                has_maven_format = ':' in package_name and len(package_name.split(':')) >= 2
                
                if 'wordpress.org' in url_lower:
                    wordpress_repos.append(i)
                elif has_maven_pattern and has_maven_format:
                    maven_repos.append(i)
                else:
                    non_maven_repos.append(i)
            elif repo and not collection_url:
                repo_only.append(i)
        
        # Validate expected counts based on our test data
        expected_maven = 7  # Apache, Spring, Enterprise, Artifactory, Sonatype, JitPack, Clojars
        expected_non_maven = 4  # PyPI, NPM, RubyGems, NuGet, Go
        expected_wordpress = 2  # WordPress plugins
        
        results = []
        
        if len(maven_repos) < expected_maven:
            results.append(f"Expected at least {expected_maven} Maven repos, found {len(maven_repos)}")
        
        if len(non_maven_repos) < expected_non_maven:
            results.append(f"Expected at least {expected_non_maven} non-Maven repos, found {len(non_maven_repos)}")
        
        if len(wordpress_repos) < expected_wordpress:
            results.append(f"Expected at least {expected_wordpress} WordPress repos, found {len(wordpress_repos)}")
        
        if results:
            self.add_result("PLATFORM_VARIETY", False, "; ".join(results))
        else:
            self.add_result("PLATFORM_VARIETY", True, 
                           f"Platform variety correct: {len(maven_repos)} Maven, "
                           f"{len(non_maven_repos)} non-Maven, {len(wordpress_repos)} WordPress, "
                           f"{len(repo_only)} repo-only")
    
    def test_wordpress_source_detection(self):
        """Test that WordPress sources are properly included."""
        metadata = self.extract_global_metadata()
        if not metadata:
            return
        
        source_data = metadata.get('sourceData', [])
        wordfence_found = False
        
        for source in source_data:
            # Check sourceIdentifiers array for the WordFence UUID
            source_identifiers = source.get('sourceIdentifiers', [])
            
            if isinstance(source_identifiers, list) and 'b15e7b5b-3da4-40ae-a43c-f7aa60e62599' in source_identifiers:
                wordfence_found = True
                break
        
        if not wordfence_found:
            self.add_result("WORDPRESS_DETECTION", False, "WordFence source not found in source data")
        else:
            self.add_result("WORDPRESS_DETECTION", True, "WordFence source properly detected")
    
    def test_javascript_integration(self):
        """Test that JavaScript functions and integration points exist."""
        exists, missing = self.check_javascript_functions_exist()
        
        if not exists:            self.add_result("JAVASCRIPT_FUNCTIONS", False, f"Missing functions: {missing}")
        else:
            self.add_result("JAVASCRIPT_FUNCTIONS", True, "All required JavaScript functions found")
        
        # Check for initialization call
        html_content = str(self.soup)
        if 'processProvenanceMetadata()' not in html_content:
            self.add_result("JAVASCRIPT_INIT", False, "processProvenanceMetadata() initialization not found")
        else:
            self.add_result("JAVASCRIPT_INIT", True, "JavaScript initialization found")
    
    def test_unicode_handling(self):
        """Test that Unicode characters are properly handled."""
        # Look for our Unicode test case
        unicode_found = False
        for i in range(self.count_provenance_containers()):
            platform_data = self.extract_platform_data(i)
            package_name = platform_data.get('packageName', '')
            
            if '测试包' in package_name or 'unicode' in package_name.lower():
                unicode_found = True
                break
        
        if not unicode_found:
            self.add_result("UNICODE_HANDLING", False, "Unicode test case not found")
        else:
            self.add_result("UNICODE_HANDLING", True, "Unicode test case found in platform data")
    
    def run_all_tests(self):
        """Run the complete test suite."""
        print("Starting Provenance Assistance Automated Test Suite")
        print("=" * 60)
        
        try:
            # Load test data first to get CVE ID
            with open(self.test_file_path, 'r', encoding='utf-8') as f:
                self.test_data = json.load(f)
            
            if not self.generate_html():
                print("❌ Failed to generate HTML")
                return False
                
            if not self.load_files():
                print("❌ Failed to load files")
                return False
        except Exception as e:
            print(f"❌ Error in setup: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Structure tests
        self.check_provenance_structure()
        
        # Data completeness tests
        self.test_global_metadata_structure()
        self.test_description_data_completeness()
        self.test_reference_data_completeness()
        self.test_platform_data_variety()
        
        # Feature-specific tests
        self.test_wordpress_source_detection()
        self.test_unicode_handling()
        
        # Integration tests
        self.test_javascript_integration()
        
        return True
    
    def print_summary(self):
        """Print test results summary."""
        total_tests = self.passed + self.failed
        
        # Only show failures for debugging
        if self.failed > 0:
            failures = [result for result in self.results if not result['passed']]
            print(f"\nTest Failures ({len(failures)}):")
            for result in failures:
                print(f"  - {result['test']}: {result['details'] or 'No details'}")
        
        # STANDARD OUTPUT FORMAT - Required for unified test runner
        print(f"TEST_RESULTS: PASSED={self.passed} TOTAL={total_tests} SUITE=\"Provenance Assistance\"")
        
        return self.failed == 0

def main():
    """Main entry point for the test suite."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test provenance assistance functionality')
    parser.add_argument('test_file', help='Test data JSON file')
    
    args = parser.parse_args()
    
    # Validate test file exists
    if not Path(args.test_file).exists():
        print(f"❌ Test file not found: {args.test_file}")
        sys.exit(1)
    
    # Run test suite
    test_suite = ProvenanceAssistanceTestSuite(args.test_file)
    
    if test_suite.run_all_tests():
        success = test_suite.print_summary()
        sys.exit(0 if success else 1)
    else:
        print("❌ Test suite failed to run")
        sys.exit(1)

if __name__ == "__main__":
    main()
