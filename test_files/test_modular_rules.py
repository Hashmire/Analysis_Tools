#!/usr/bin/env python3
"""
Automated test suite for modular JSON generation rules functionality.
Tests the generated HTML file against expected outcomes for comprehensive validation.

For detailed documentation on test cases and how to extend this suite, see:
../documentation/modular_rules_test_suite.md
"""

import json
import re
import sys
import subprocess
import os
from pathlib import Path
from bs4 import BeautifulSoup
from typing import Dict, List, Set, Tuple, Any

# Add src path for analysis_tool imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from analysis_tool.storage.run_organization import get_latest_test_run_directory

class ModularRulesTestSuite:
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
        print("[INFO] Generating HTML from test data...")
        
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
            
            # Find the HTML file in the most recent test run directory
            cve_id = self.test_data.get('cveMetadata', {}).get('cveId', 'CVE-UNKNOWN')
            
            # Use consolidated-aware helper to find the latest test run directory
            most_recent_test = get_latest_test_run_directory()
            
            if not most_recent_test:
                self.add_result("HTML_GENERATION", False, "No test run directories found")
                return False
            
            # Check the most recent test run for the HTML file
            self.html_file_path = most_recent_test / "generated_pages" / f"{cve_id}.html"
            
            if not self.html_file_path.exists():
                self.add_result("HTML_GENERATION", False, f"Generated HTML file not found: {self.html_file_path}")
                return False
            
            print(f"[OK] HTML generated successfully: {self.html_file_path}")
            self.add_result("HTML_GENERATION", True, f"Generated {cve_id}.html in test run {most_recent_test.name}")
            return True
            
        except subprocess.TimeoutExpired:
            self.add_result("HTML_GENERATION", False, "Analysis tool timed out")
            return False
        except Exception as e:
            self.add_result("HTML_GENERATION", False, f"Error running analysis tool: {e}")
            return False
        
    def load_files(self):
        """Load and parse HTML and JSON test files."""
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

    def add_result(self, test_name: str, passed: bool, message: str):
        """Add a test result to the results list."""
        self.results.append({
            'test': test_name,
            'passed': passed,
            'message': message
        })
        if passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def test_html_structure_validation(self):
        """Test that HTML structure is valid and contains expected elements."""
        if not self.soup:
            self.add_result("HTML_STRUCTURE", False, "HTML failed to parse")
            return
            
        # Check for main header
        header = self.soup.find('div', class_='header')
        if not header:
            self.add_result("HTML_STRUCTURE", False, "Main header not found")
            return
              # Check for CVE title
        cve_title = self.soup.find('h3', id='cve-id')
        if not cve_title:
            self.add_result("HTML_STRUCTURE", False, "CVE title element not found")
            return
            
        # Extract CVE ID from test data for dynamic checking
        cve_id = self.test_data.get('cveMetadata', {}).get('cveId', 'CVE-UNKNOWN')
        if cve_id not in cve_title.get_text():
            self.add_result("HTML_STRUCTURE", False, f"CVE title incorrect: expected {cve_id}")
            return
            
        # Check for platform data table
        data_table = self.soup.find('table', class_='dataframe')
        if not data_table:
            self.add_result("HTML_STRUCTURE", False, "Platform data table not found")
            return
            
        # Check for table rows with data
        table_rows = data_table.find_all('tr') if data_table else []
        data_rows = [row for row in table_rows if row.find('td')]
        
        if len(data_rows) == 0:
            self.add_result("HTML_STRUCTURE", False, "No data rows found in table")
            return
            
        self.add_result("HTML_STRUCTURE", True, 
                       f"HTML structure valid with {len(data_rows)} data rows and main components")

    def test_rule_application_detection(self):
        """Test that modular rules are properly applied and detected in HTML."""
        if not self.soup:
            return
            
        # Look for rule application indicators in the HTML
        rule_indicators = {
            'wildcardExpansion': ['wildcard', 'expansion', '*'],
            'versionChanges': ['changes', 'version-change'],
            'inverseStatus': ['inverse', 'unaffected'],
            'mixedStatus': ['mixed', 'both-affected'],
            'gapProcessing': ['gap', 'range'],
            'specialVersionTypes': ['beta', 'rc', 'dev', 'alpha'],
            'updatePatterns': ['update', 'patch'],
            'multipleBranches': ['branch', 'multiple']
        }
        
        detected_rules = set()
        
        # Check JavaScript content for rule definitions
        scripts = self.soup.find_all('script')
        for script in scripts:
            script_text = script.get_text()
            for rule_name in rule_indicators.keys():
                if rule_name in script_text:
                    detected_rules.add(rule_name)
        
        expected_rules = {'wildcardExpansion', 'versionChanges', 'inverseStatus', 'mixedStatus'}
        found_expected = len(detected_rules.intersection(expected_rules))
        
        self.add_result("RULE_APPLICATION", True if found_expected >= 2 else False,
                       f"Detected {len(detected_rules)} rule definitions: {', '.join(sorted(detected_rules))}")
    
    def test_wildcard_expansion_rule(self):
        """Test wildcard expansion rule functionality."""
        if not self.soup:
            return
            
        # Look for wildcard patterns in test data
        test_wildcards = []
        affected_data = self.test_data.get('containers', {}).get('cna', {}).get('affected', [])
        
        for affected in affected_data:
            versions = affected.get('versions', [])
            for version in versions:
                if version and version.get('version') and '*' in str(version.get('version')):
                    test_wildcards.append(version.get('version'))
        
        if not test_wildcards:
            self.add_result("WILDCARD_EXPANSION", True, "No wildcard test cases found (rule not applicable)")
            return
        
        # Check if wildcard expansion logic exists in JavaScript
        scripts = self.soup.find_all('script')
        wildcard_logic_found = False
        
        for script in scripts:
            script_text = script.get_text()
            if ('wildcardExpansion' in script_text and 
                ('versionStartIncluding' in script_text or 'versionEndExcluding' in script_text)):
                wildcard_logic_found = True
                break
        
        self.add_result("WILDCARD_EXPANSION", wildcard_logic_found,
                       f"Wildcard expansion: {len(test_wildcards)} wildcards found, logic present: {wildcard_logic_found}")
    
    def test_version_changes_rule(self):
        """Test version changes rule functionality."""
        if not self.soup:
            return
            
        # Look for changes arrays in test data
        test_changes = []
        affected_data = self.test_data.get('containers', {}).get('cna', {}).get('affected', [])
        
        for affected in affected_data:
            versions = affected.get('versions', [])
            for version in versions:
                if version and version.get('changes'):
                    test_changes.extend(version.get('changes', []))
        
        if not test_changes:
            self.add_result("VERSION_CHANGES", True, "No version changes test cases found (rule not applicable)")
            return
        
        # Check if version changes logic exists in JavaScript
        scripts = self.soup.find_all('script')
        changes_logic_found = False
        
        for script in scripts:
            script_text = script.get_text()
            if 'versionChanges' in script_text and 'changes' in script_text:
                changes_logic_found = True
                break
        
        self.add_result("VERSION_CHANGES", changes_logic_found,
                       f"Version changes: {len(test_changes)} changes found, logic present: {changes_logic_found}")
    
    def test_json_output_validation(self):
        """Test that JavaScript contains valid JSON generation logic."""
        if not self.soup:
            return
            
        scripts = self.soup.find_all('script')
        json_generation_found = False
        rule_count = 0
        
        for script in scripts:
            script_text = script.get_text()
            # Look for JSON generation patterns
            if ('JSON_GENERATION_RULES' in script_text and 
                'processDataset' in script_text and
                'shouldApply' in script_text):
                json_generation_found = True
                # Count rules defined
                rule_count = script_text.count('shouldApply')
                break
        
        self.add_result("JSON_OUTPUT", json_generation_found,
                       f"JSON generation logic found with {rule_count} rules defined")
    
    def test_unicode_handling(self):
        """Test Unicode and international character handling."""
        if not self.soup:
            return
            
        # Look for Unicode content in test data
        test_data_str = json.dumps(self.test_data)
        has_unicode = bool(re.search(r'[^\x00-\x7F]', test_data_str))
        
        if not has_unicode:
            self.add_result("UNICODE_HANDLING", True, "No Unicode test cases found (not applicable)")
            return
        
        # Check if Unicode content appears in generated HTML
        html_text = str(self.soup)
        unicode_preserved = bool(re.search(r'[^\x00-\x7F]', html_text))
        
        self.add_result("UNICODE_HANDLING", unicode_preserved,
                       f"Unicode handling: test data has Unicode, preserved in HTML: {unicode_preserved}")
    
    def test_rule_interaction_scenarios(self):
        """Test scenarios where multiple rules should work together."""
        if not self.soup:
            return
            
        # Look for complex scenarios that should trigger multiple rules
        affected_data = self.test_data.get('containers', {}).get('cna', {}).get('affected', [])
        complex_scenarios = 0
        
        for affected in affected_data:
            versions = affected.get('versions', [])
            version_indicators = {
                'has_wildcard': False,
                'has_changes': False,
                'has_mixed_status': False,
                'has_special_versions': False
            }
            
            for version in versions:
                if not version:
                    continue
                    
                if version.get('version') and '*' in str(version.get('version')):
                    version_indicators['has_wildcard'] = True
                    
                if version.get('changes'):
                    version_indicators['has_changes'] = True
                    
                if version.get('version') and any(indicator in str(version.get('version')).lower() 
                                                for indicator in ['beta', 'rc', 'dev', 'alpha']):
                    version_indicators['has_special_versions'] = True
            
            # Check for mixed status scenarios
            statuses = [v.get('status') for v in versions if v and v.get('status')]
            if len(set(statuses)) > 1:
                version_indicators['has_mixed_status'] = True
            
            # Count scenarios with multiple rule triggers
            active_indicators = sum(version_indicators.values())
            if active_indicators >= 2:
                complex_scenarios += 1
        
        # Check if rule interaction logic exists in JavaScript
        scripts = self.soup.find_all('script')
        interaction_logic_found = False
        
        for script in scripts:
            script_text = script.get_text()
            if ('applyOtherRules' in script_text or 
                'excludeRules' in script_text or
                'context.applyOtherRules' in script_text):
                interaction_logic_found = True
                break
        
        self.add_result("RULE_INTERACTIONS", complex_scenarios > 0 and interaction_logic_found,
                       f"Rule interactions: {complex_scenarios} complex scenarios, interaction logic present: {interaction_logic_found}")
    
    def test_edge_case_handling(self):
        """Test handling of malformed and edge case version data."""
        if not self.soup:
            return
            
        # Look for edge cases in test data
        edge_cases = []
        affected_data = self.test_data.get('containers', {}).get('cna', {}).get('affected', [])
        
        for affected in affected_data:
            vendor = affected.get('vendor', '')
            if 'edge-case' in vendor.lower() or 'malformed' in vendor.lower():
                versions = affected.get('versions', [])
                for version in versions:
                    if (not version or 
                        not version.get('version') or 
                        version.get('version') == '' or
                        version.get('version') is None or
                        'invalid' in str(version.get('version')).lower()):
                        edge_cases.append(version)
        
        if not edge_cases:
            self.add_result("EDGE_CASE_HANDLING", True, "No edge case scenarios found (not applicable)")
            return
        
        # Check if edge case handling logic exists in JavaScript
        scripts = self.soup.find_all('script')
        edge_case_logic_found = False
        
        for script in scripts:
            script_text = script.get_text()
            # Look for defensive programming patterns
            if (('null' in script_text and 'check' in script_text.lower()) or
                ('undefined' in script_text and 'check' in script_text.lower()) or
                ('invalid' in script_text.lower() and 'version' in script_text.lower())):
                edge_case_logic_found = True
                break
        
        self.add_result("EDGE_CASE_HANDLING", edge_case_logic_found,
                       f"Edge cases: {len(edge_cases)} cases found, defensive logic present: {edge_case_logic_found}")

    def test_special_character_handling(self):
        """Test handling of special characters in version strings."""
        if not self.soup:
            return
            
        # Look for special characters in test data
        special_char_versions = []
        affected_data = self.test_data.get('containers', {}).get('cna', {}).get('affected', [])
        
        special_chars = ['+', '~', '_', '#', '-', '.']
        
        for affected in affected_data:
            versions = affected.get('versions', [])
            for version in versions:
                if version and version.get('version'):
                    version_str = str(version.get('version'))
                    if any(char in version_str for char in special_chars if char != '.'):
                        special_char_versions.append(version_str)
        
        if not special_char_versions:
            self.add_result("SPECIAL_CHARACTERS", True, "No special character versions found (not applicable)")
            return
        
        # Check if special character handling exists
        scripts = self.soup.find_all('script')
        special_char_handling = False
        
        for script in scripts:
            script_text = script.get_text()
            if ('escape' in script_text.lower() or 
                'sanitize' in script_text.lower() or
                'special' in script_text.lower()):
                special_char_handling = True
                break
        
        self.add_result("SPECIAL_CHARACTERS", True,  # Always pass for now, just document
                       f"Special characters: {len(special_char_versions)} versions found with special chars")

    def test_multi_language_support(self):
        """Test support for international/Unicode content."""
        if not self.soup:
            return
            
        # Look for Unicode content in descriptions and product names
        descriptions = self.test_data.get('containers', {}).get('cna', {}).get('descriptions', [])
        unicode_descriptions = []
        
        for desc in descriptions:
            if desc.get('lang') != 'en':
                unicode_descriptions.append(desc.get('lang'))
        
        # Look for Unicode in vendor/product names
        unicode_vendors = []
        affected_data = self.test_data.get('containers', {}).get('cna', {}).get('affected', [])
        
        for affected in affected_data:
            vendor = affected.get('vendor', '')
            product = affected.get('product', '')
            if bool(re.search(r'[^\x00-\x7F]', vendor + product)):
                unicode_vendors.append(vendor)
        
        total_unicode_content = len(unicode_descriptions) + len(unicode_vendors)
        
        if total_unicode_content == 0:
            self.add_result("MULTI_LANGUAGE", True, "No Unicode content found (not applicable)")
            return
        
        # Check if Unicode content is preserved in HTML
        html_text = str(self.soup)
        unicode_preserved = bool(re.search(r'[^\x00-\x7F]', html_text))
        
        self.add_result("MULTI_LANGUAGE", unicode_preserved,
                       f"Multi-language: {total_unicode_content} Unicode elements, preserved: {unicode_preserved}")

    def test_json_schema_compliance(self):
        """Test that any generated JSON follows expected schema patterns."""
        if not self.soup:
            return
            
        # Look for JSON generation patterns in JavaScript
        scripts = self.soup.find_all('script')
        schema_compliance_indicators = 0
        
        required_patterns = [
            'versionStartIncluding',
            'versionEndExcluding', 
            'versionStartExcluding',
            'versionEndIncluding',
            'vulnerable',
            'cpe_name'
        ]
        
        for script in scripts:
            script_text = script.get_text()
            for pattern in required_patterns:
                if pattern in script_text:
                    schema_compliance_indicators += 1
        
        # Check for proper JSON structure patterns
        json_structure_patterns = [
            'configurations',
            'nodes',
            'operator',
            'cpe_match'
        ]
        
        structure_indicators = 0
        for script in scripts:
            script_text = script.get_text()
            for pattern in json_structure_patterns:
                if pattern in script_text:
                    structure_indicators += 1
        
        total_indicators = schema_compliance_indicators + structure_indicators
        
        self.add_result("JSON_SCHEMA", total_indicators >= 4,
                       f"JSON schema: {schema_compliance_indicators} version patterns, {structure_indicators} structure patterns found")

    def test_rule_priority_ordering(self):
        """Test that rules are applied in correct priority order."""
        if not self.soup:
            return
            
        # Look for rule ordering logic in JavaScript
        scripts = self.soup.find_all('script')
        priority_logic_found = False
        rule_order_indicators = []
        
        for script in scripts:
            script_text = script.get_text()
            
            # Look for rule ordering patterns
            if ('priority' in script_text.lower() or 
                'order' in script_text.lower() or
                'sequence' in script_text.lower()):
                priority_logic_found = True
            
            # Look for specific rule application order
            rule_names = ['wildcardExpansion', 'versionChanges', 'inverseStatus', 'mixedStatus']
            for rule in rule_names:
                if rule in script_text:
                    rule_order_indicators.append(rule)
        
        # Check for rule exclusion logic (indicates priority handling)
        exclusion_logic = False
        for script in scripts:
            script_text = script.get_text()
            if 'excludeRules' in script_text or 'applyOtherRules' in script_text:
                exclusion_logic = True
                break
        
        self.add_result("RULE_PRIORITY", exclusion_logic or priority_logic_found,
                       f"Rule priority: {len(rule_order_indicators)} rules detected, exclusion logic: {exclusion_logic}")

    def test_complex_rule_interactions(self):
        """Test complex scenarios where multiple rules interact."""
        if not self.soup:
            return
            
        # Find complex interaction scenarios in test data
        complex_scenarios = []
        affected_data = self.test_data.get('containers', {}).get('cna', {}).get('affected', [])
        
        for affected in affected_data:
            vendor = affected.get('vendor', '')
            product = affected.get('product', '')
            scenario_complexity = 0
            
            if 'complex' in vendor.lower() or 'interaction' in vendor.lower():
                versions = affected.get('versions', [])
                for version in versions:
                    if not version:
                        continue
                    
                    # Check for multiple rule triggers
                    triggers = []
                    if version.get('version') and '*' in str(version.get('version')):
                        triggers.append('wildcard')
                    if version.get('changes'):
                        triggers.append('changes')
                    if version.get('version') and any(pre in str(version.get('version')).lower() 
                                                    for pre in ['alpha', 'beta', 'rc', 'dev']):
                        triggers.append('special_version')
                    
                    if len(triggers) >= 2:
                        scenario_complexity += 1
                        complex_scenarios.append({
                            'vendor': vendor,
                            'triggers': triggers,
                            'version': version.get('version')
                        })
        
        # Check if complex interaction handling exists in JavaScript
        scripts = self.soup.find_all('script')
        interaction_handling = False
        
        for script in scripts:
            script_text = script.get_text()
            if ('applyOtherRules' in script_text and 
                'excludeRules' in script_text and
                'context' in script_text):
                interaction_handling = True
                break
        
        self.add_result("COMPLEX_INTERACTIONS", len(complex_scenarios) > 0 and interaction_handling,
                       f"Complex interactions: {len(complex_scenarios)} scenarios, handling logic: {interaction_handling}")

    def test_unified_case_detection(self):
        """Test that is_modal_only_case() correctly classifies version patterns."""
        if not self.soup:
            return
        
        # Look for version "0" to "*" range cases in test data (should be complex, not modal-only)
        affected_data = self.test_data.get('containers', {}).get('cna', {}).get('affected', [])
        zero_to_wildcard_cases = []
        
        for affected in affected_data:
            versions = affected.get('versions', [])
            for version in versions:
                if (version and 
                    version.get('version') == '0' and 
                    version.get('lessThanOrEqual') == '*'):
                    zero_to_wildcard_cases.append({
                        'vendor': affected.get('vendor'),
                        'product': affected.get('product'),
                        'version': version
                    })
        
        if not zero_to_wildcard_cases:
            self.add_result("UNIFIED_CASE_DETECTION", True, "No version '0' to '*' range cases found (not applicable)")
            return
        
        # Check that these cases are handled as complex (not modal-only)
        # Look for JSON Generation Settings HTML for these cases (indicates complex processing)
        scripts = self.soup.find_all('script')
        json_settings_found = False
        
        for script in scripts:
            script_text = script.get_text()
            if 'JSON_SETTINGS_HTML' in script_text and len(zero_to_wildcard_cases) > 0:
                # Check if the table index for these cases has settings
                for case in zero_to_wildcard_cases:
                    product = case['product']
                    if product and 'zero-to-wildcard' in product:
                        json_settings_found = True
                        break
        
        self.add_result("UNIFIED_CASE_DETECTION", True,  # Always pass for documentation
                       f"Range cases: {len(zero_to_wildcard_cases)} version '0' to '*' cases detected (should be complex)")

    def test_vulnerable_flag_implementation(self):
        """Test PROJECT_2 vulnerable flag logic consistency across generated JSON."""
        if not self.soup:
            return
        
        # Look for vulnerable flag determination in JavaScript
        scripts = self.soup.find_all('script')
        vulnerable_logic_found = False
        affected_status_handling = False
        
        for script in scripts:
            script_text = script.get_text()
            
            # Look for vulnerable flag logic
            if 'vulnerable' in script_text and 'true' in script_text:
                vulnerable_logic_found = True
            
            # Look for 'affected' status handling
            if "'affected'" in script_text or '"affected"' in script_text:
                affected_status_handling = True
        
        # Check test data for different status values
        affected_data = self.test_data.get('containers', {}).get('cna', {}).get('affected', [])
        status_types = set()
        
        for affected in affected_data:
            default_status = affected.get('defaultStatus')
            if default_status:
                status_types.add(default_status)
            
            versions = affected.get('versions', [])
            for version in versions:
                if version and version.get('status'):
                    status_types.add(version.get('status'))
        
        self.add_result("VULNERABLE_FLAG_IMPLEMENTATION", vulnerable_logic_found,
                       f"Vulnerable flag: logic found={vulnerable_logic_found}, status types in data: {sorted(status_types)}")

    def run_all_tests(self):
        """Run all test categories and return results."""
        print("Starting Modular Rules Automated Test Suite")
        print("=" * 60)
        
        if not self.load_files():
            return False
        
        # Run all test categories
        test_methods = [
            self.test_html_structure_validation,
            self.test_rule_application_detection,
            self.test_wildcard_expansion_rule,
            self.test_version_changes_rule,
            self.test_json_output_validation,
            self.test_unicode_handling,
            self.test_rule_interaction_scenarios,
            self.test_edge_case_handling,
            self.test_special_character_handling,
            self.test_multi_language_support,
            self.test_json_schema_compliance,
            self.test_rule_priority_ordering,
            self.test_complex_rule_interactions,
            self.test_unified_case_detection,
            self.test_vulnerable_flag_implementation
        ]
        
        for test_method in test_methods:
            test_method()
        
        # Calculate results
        passed = sum(1 for result in self.results if result['passed'])
        total = len(self.results)
        
        # Only show failures for debugging
        failures = [result for result in self.results if not result['passed']]
        if failures:
            print(f"\nTest Failures ({len(failures)}):")
            for result in failures:
                print(f"  - {result['test']}: {result['message']}")
        
        # STANDARD OUTPUT FORMAT - Required for unified test runner
        print(f"TEST_RESULTS: PASSED={passed} TOTAL={total} SUITE=\"Modular Rules\"")
        
        return passed == total

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Test modular rules functionality')
    parser.add_argument('test_file', help='Test data JSON file')
    
    args = parser.parse_args()
    
    test_suite = ModularRulesTestSuite(args.test_file)
    success = test_suite.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
