#!/usr/bin/env python3
"""
Analysis Tools Bloat Detection Framework

A comprehensive framework for identifying and quantifying bloat in the Analysis_Tools
CVE processing system. Focuses on HTML generation inefficiencies, JavaScript duplication,
and template optimization opportunities.

Usage:
    python bloat_detection_framework.py --cve CVE-2024-46886
    python bloat_detection_framework.py --analyze-all --output-report bloat_analysis.json
"""

import os
import json
import re
import sys
import math
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import gzip
import hashlib


@dataclass
class BloatAnalysis:
    """Container for bloat analysis results"""
    file_path: str
    total_size: int
    line_count: int
    bloat_sources: Dict[str, Dict[str, Any]]
    optimization_recommendations: List[Dict[str, Any]]
    template_opportunities: Dict[str, int]
    deduplication_potential: Dict[str, float]
    repetitive_structures: Dict[str, Dict[str, Any]]
    actual_bloat_size: int = 0  # Deduplicated bloat size
    optimization_note: str = ""  # Note about analysis optimizations applied


class BloatDetectionFramework:
    """
    Framework for identifying and analyzing bloat in Analysis_Tools generated files
    """
    
    def __init__(self, analysis_tools_root: str = None, target_directory: str = None):
        """
        Initialize the bloat detection framework
        
        Args:
            analysis_tools_root: Root of Analysis_Tools project (optional)
            target_directory: Direct path to directory containing files to analyze (optional)
        """
        if target_directory:
            # Direct directory mode - analyze any directory of HTML/web files
            self.target_dir = Path(target_directory)
            self.analysis_tools_root = None
            self.generated_pages_dir = self.target_dir
        elif analysis_tools_root:
            # Analysis_Tools project mode
            self.analysis_tools_root = Path(analysis_tools_root)
            self.generated_pages_dir = self.analysis_tools_root / "generated_pages"
            self.target_dir = self.generated_pages_dir
        else:
            # Default to current directory
            self.analysis_tools_root = Path.cwd()
            self.generated_pages_dir = self.analysis_tools_root / "generated_pages"
            self.target_dir = self.generated_pages_dir if self.generated_pages_dir.exists() else self.analysis_tools_root
        
        # Bloat pattern definitions (universal patterns for any generated HTML)
        self.bloat_patterns = {
            'embedded_js_libraries': {
                'pattern': r'(?:class\s+\w+\s*\{.*?\}|function\s+\w+\s*\([^)]*\)\s*\{[^}]{200,}\})',
                'description': 'Large embedded JavaScript library code or functions',
                'optimization': 'Extract to external file with CDN/caching'
            },
            'inline_script_blocks': {
                'pattern': r'<script[^>]*>(?:(?!</script>).){1000,}</script>',
                'description': 'Large inline script blocks',
                'optimization': 'Move to external JS files'
            },
            'repetitive_data_registrations': {
                'pattern': r'(?:window\.\w+\s*=|\.register\w*\(|\.add\w*\()[^;]{100,};',
                'description': 'Repetitive data registration or assignment calls',
                'optimization': 'Use template deduplication or batch operations'
            },
            'badge_modal_data_registrations': {
                'pattern': r'BadgeModal\.registerData\([^)]+,\s*\{[^}]*\}[^;]*;',
                'description': 'Large badge modal data registration calls with JSON payloads',
                'optimization': 'Use batch registration or external data files with lazy loading'
            },
            'platform_notification_registrations': {
                'pattern': r'register_platform_notification_data\([^)]+,\s*\{[^}]*\}[^;]*;',
                'description': 'Platform notification data registration with large payloads',
                'optimization': 'Use batch registration or data compression'
            },
            'cpe_data_registrations': {
                'pattern': r'register_cpe_data\([^)]+,\s*\{[^}]*\}[^;]*;',
                'description': 'CPE reference data registration with large JSON payloads',
                'optimization': 'Use external data files or data compression'
            },
            'duplicate_css_rules': {
                'pattern': r'\.[\w-]+\s*\{[^}]+\}',
                'description': 'Repeated CSS styling rules',
                'optimization': 'Extract common styles to CSS classes'
            },
            'verbose_html_structures': {
                'pattern': r'<(?:div|span|section)[^>]{100,}>',
                'description': 'HTML elements with verbose attribute lists',
                'optimization': 'Simplify attribute usage or use CSS classes'
            },
            'embedded_json_data': {
                'pattern': r'(?:window\.\w+\s*=\s*|var\s+\w+\s*=\s*)\{[^}]{500,}\}',
                'description': 'Large embedded JSON data structures',
                'optimization': 'Load dynamically or use compression'
            },
            'template_expansion_overhead': {
                'pattern': r'(?:Object\.keys\([^)]+\)\.forEach|for\s*\([^)]*in[^)]*\))[^}]{100,}',
                'description': 'Template expansion or iteration code',
                'optimization': 'Pre-expand templates during generation or optimize loops'
            },
            'redundant_error_handling': {
                'pattern': r'(?:try\s*\{[^}]+catch|throw\s+new\s+Error\([^)]+\)|console\.(?:error|warn|log)\([^)]+\)){2,}',
                'description': 'Repetitive error handling or logging code',
                'optimization': 'Use centralized error handling utilities'
            },
            'duplicate_event_handlers': {
                'pattern': r'(?:onclick|onload|onchange|addEventListener)\s*=\s*["\'][^"\']{50,}["\']',
                'description': 'Repetitive inline event handler code',
                'optimization': 'Use event delegation or external handlers'
            },
            'verbose_bootstrap_classes': {
                'pattern': r'class\s*=\s*["\'][^"\']*(?:btn|card|container|row|col)[^"\']{50,}["\']',
                'description': 'Verbose Bootstrap or CSS framework class lists',
                'optimization': 'Create custom CSS classes for common combinations'
            },
            'large_data_tables': {
                'pattern': r'<table(?![^>]*id\s*=\s*["\']matchesTable_\d+["\'])[^>]*>(?:(?!</table>).){5000,}</table>',
                'description': 'Very large HTML tables with extensive data (excluding matchesTable_X)',
                'optimization': 'Use pagination, virtual scrolling, or data compression'
            },
            'repetitive_table_rows': {
                'pattern': r'(?:<tr[^>]*>(?:[^<]*<td[^>]*>[^<]*</td>){3,}[^<]*</tr>){15,}',
                'description': 'Tables with many repetitive rows',
                'optimization': 'Use pagination or virtual scrolling for large datasets'
            },
            'massive_text_blocks': {
                'pattern': r'<(?:p|div|span|td)[^>]*>[^<]{1500,}</(?:p|div|span|td)>',
                'description': 'Very large text content blocks',
                'optimization': 'Consider text truncation with expand/collapse'
            }
        }
        
        # Template deduplication patterns (universal patterns for any template system)
        self.template_patterns = {
            'data_registrations': r'(?:\.register\w*\(|\.add\w*\(|window\.\w+\s*=)[^;]+;',
            'template_references': r'(?:TEMPLATES|_TEMPLATE)\s*[=:][^;]+;',
            'mapping_definitions': r'(?:MAPPINGS|_MAPPING)\s*[=:][^;]+;',
            'configuration_objects': r'(?:CONFIG|SETTINGS|OPTIONS)\s*[=:][^;]+;',
            'repeated_data_structures': r'(?:window\.\w+|var\s+\w+|const\s+\w+)\s*=\s*\{[^}]{100,}\}',
        }

    def analyze_file(self, file_path: Path) -> BloatAnalysis:
        """
        Perform comprehensive bloat analysis on a single HTML file
        
        Args:
            file_path: Path to the HTML file to analyze
            
        Returns:
            BloatAnalysis object with detailed findings
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read file content
        content = file_path.read_text(encoding='utf-8')
        file_size = file_path.stat().st_size
        line_count = len(content.splitlines())
        
        # Initialize analysis result
        bloat_sources = {}
        template_opportunities = {}
        deduplication_potential = {}
        
        # First, find all inline script blocks to map hierarchical relationships
        script_blocks = list(re.finditer(r'<script[^>]*>(.*?)</script>', content, re.DOTALL))
        script_ranges = [(match.start(), match.end()) for match in script_blocks]
        
        # NEW: Track all pattern matches with their ranges to prevent double-counting
        all_pattern_matches = {}
        total_bloat_ranges = []
        
        # PERFORMANCE OPTIMIZATION: Quick check for ID pattern dominance
        # Do a fast preliminary scan for numbered ID patterns
        quick_id_scan = re.findall(r'id="([a-zA-Z][a-zA-Z0-9_-]*?)_(\d+)"', content)
        id_pattern_density = len(quick_id_scan) / (file_size / 1000)  # patterns per KB
        
        # If high ID pattern density (>5 per KB), reduce generic pattern checking intensity
        optimize_for_id_patterns = id_pattern_density > 5
        
        # NEW: Analyze repetitive numbered container structures first for early exit potential
        repetitive_structures = self._analyze_numbered_containers(content, file_size)
        
        # EARLY EXIT: If we find enough significant ID patterns, optimize remaining analysis
        if len(repetitive_structures) >= 3:
            found_id_bloat = sum(data['total_size'] for data in repetitive_structures.values())
            id_bloat_percentage = (found_id_bloat / file_size) * 100
            
            # If ID patterns account for >50% of potential bloat, simplify remaining analysis
            if id_bloat_percentage > 50:
                # Quick remaining pattern scan - only check most critical generic patterns
                critical_patterns = ['very_large_tables', 'excessive_inline_styles', 'repeated_script_blocks']
                quick_bloat_sources = {}
                
                for pattern_name in critical_patterns:
                    if pattern_name in self.bloat_patterns:
                        pattern_config = self.bloat_patterns[pattern_name]
                        matches = list(re.finditer(pattern_config['pattern'], content, re.DOTALL))
                        if matches:
                            total_match_size = sum(len(match.group()) for match in matches)
                            percentage = (total_match_size / file_size) * 100
                            if percentage >= pattern_config.get('min_percentage', 1.0):
                                quick_bloat_sources[pattern_name] = {
                                    'count': len(matches),
                                    'total_size': total_match_size,
                                    'percentage': percentage,
                                    'description': pattern_config['description']
                                }
                
                # NOTE: Don't return here! Let the log analyzer merge ID patterns with generic patterns
                # The log analyzer will handle the smart consolidation based on pattern dominance
                bloat_sources = quick_bloat_sources
                template_opportunities = {}
                
                # Continue to return full results for proper merging
                return BloatAnalysis(
                    file_path=str(file_path),
                    total_size=file_size,
                    line_count=line_count,
                    bloat_sources=bloat_sources,
                    optimization_recommendations={},
                    template_opportunities=template_opportunities,
                    deduplication_potential={},
                    repetitive_structures=repetitive_structures,
                    actual_bloat_size=found_id_bloat + sum(data['total_size'] for data in quick_bloat_sources.values()),
                    optimization_note=f'Analysis optimized due to high ID pattern coverage ({id_bloat_percentage:.1f}%)'
                )
        
        # Continue with full analysis if no early exit
        
        # Analyze each bloat pattern and collect all matches first
        for pattern_name, pattern_config in self.bloat_patterns.items():
            # OPTIMIZATION: Skip some heavy generic patterns if ID patterns dominate
            if optimize_for_id_patterns and pattern_name in ['duplicate_css_rules', 'redundant_error_handling', 'template_expansion_overhead']:
                continue  # Skip these expensive patterns when ID patterns are dominant
                
            matches = list(re.finditer(pattern_config['pattern'], content, re.DOTALL))
            if matches:
                total_match_size = sum(len(match.group()) for match in matches)
                percentage = (total_match_size / file_size) * 100
                
                # Only report patterns that cumulatively account for >1% of file size
                if percentage > 1.0:
                    all_pattern_matches[pattern_name] = {
                        'matches': matches,
                        'config': pattern_config,
                        'total_size': total_match_size,
                        'percentage': percentage
                    }
                    # Collect all ranges for this pattern
                    for match in matches:
                        total_bloat_ranges.append((match.start(), match.end(), pattern_name, len(match.group())))
        
        # Sort ranges by start position and merge overlapping ranges
        total_bloat_ranges.sort(key=lambda x: x[0])
        deduplicated_ranges = self._merge_overlapping_ranges(total_bloat_ranges)
        
        # Calculate actual non-overlapping bloat size
        actual_bloat_size = sum(end - start for start, end, _, _ in deduplicated_ranges)
        
        # Debug output
        total_original_size = sum(data['total_size'] for data in all_pattern_matches.values())
        print(f"🔧 DEBUG: Original total: {total_original_size/1024/1024:.2f}MB, Deduplicated: {actual_bloat_size/1024/1024:.2f}MB, File size: {file_size/1024/1024:.2f}MB")
        
        # Now create bloat_sources with hierarchy information and adjust sizes
        for pattern_name, pattern_data in all_pattern_matches.items():
            matches = pattern_data['matches']
            pattern_config = pattern_data['config']
            
            # Calculate this pattern's contribution to the deduplicated total
            pattern_ranges = [(m.start(), m.end()) for m in matches]
            deduplicated_size = self._calculate_pattern_deduplicated_size(pattern_ranges, deduplicated_ranges)
            adjusted_percentage = (deduplicated_size / file_size) * 100
            
            hierarchy_info = self._analyze_pattern_hierarchy(matches, script_ranges, pattern_name)
            hierarchy_info['deduplicated_size'] = deduplicated_size
            hierarchy_info['overlap_factor'] = pattern_data['total_size'] / deduplicated_size if deduplicated_size > 0 else 1
            
            bloat_sources[pattern_name] = {
                'count': len(matches),
                'total_size': pattern_data['total_size'],  # Original size (may overlap)
                'deduplicated_size': deduplicated_size,   # Size after removing overlaps
                'percentage': adjusted_percentage,         # Percentage based on deduplicated size
                'original_percentage': pattern_data['percentage'], # Original percentage (for reference)
                'description': pattern_config['description'],
                'optimization': pattern_config['optimization'],
                'samples': [match.group()[:200] + '...' if len(match.group()) > 200 
                          else match.group() for match in matches[:3]],
                'hierarchy': hierarchy_info
            }
        
        # Analyze template deduplication opportunities
        for template_type, pattern in self.template_patterns.items():
            matches = list(re.finditer(pattern, content))
            if len(matches) > 1:
                total_size = sum(len(match.group()) for match in matches)
                percentage = (total_size / file_size) * 100
                
                # Only report template patterns that cumulatively account for >1% of file size
                if percentage > 1.0:
                    template_opportunities[template_type] = {
                        'count': len(matches),
                        'total_size': total_size,
                        'deduplication_savings': total_size - len(matches[0].group()),
                        'percentage': percentage
                    }
        
        # Generate optimization recommendations
        recommendations = self._generate_recommendations(bloat_sources, template_opportunities, repetitive_structures)
        
        return BloatAnalysis(
            file_path=str(file_path),
            total_size=file_size,
            line_count=line_count,
            bloat_sources=bloat_sources,
            optimization_recommendations=recommendations,
            template_opportunities=template_opportunities,
            deduplication_potential={},  # Will be calculated properly later
            repetitive_structures=repetitive_structures,
            actual_bloat_size=actual_bloat_size
        )

    def _find_matching_closing_tag(self, content, tag_name, element_start, search_start):
        """Find the matching closing tag for a given opening tag with robust nested element handling."""
        closing_pattern = f'</{tag_name}>'
        
        # Use regex to find all opening tags (with or without attributes) and closing tags
        combined_pattern = rf'<(?:/)?{tag_name}(?:\s+[^>]*)?/?>'
        matches = list(re.finditer(combined_pattern, content[search_start:], re.IGNORECASE))
        
        tag_depth = 1
        element_end = search_start + 1000  # Default fallback
        
        for match in matches:
            actual_pos = search_start + match.start()
            tag_text = match.group()
            
            if tag_text.startswith('</'):
                # Closing tag
                tag_depth -= 1
                if tag_depth == 0:
                    element_end = actual_pos + len(tag_text)
                    break
            elif tag_text.endswith('/>'):
                # Self-closing tag - doesn't affect depth
                continue
            else:
                # Opening tag
                tag_depth += 1
        
        return element_end

    def _analyze_numbered_containers(self, content: str, file_size: int) -> Dict[str, Dict[str, Any]]:
        """
        Analyze repetitive numbered container structures that indicate templating opportunities.
        This identifies patterns like buttonContainer_0, buttonContainer_1, etc.
        
        IMPORTANT: Accounts for existing template deduplication systems (REFERENCES_TEMPLATES, 
        SOURCEDATACONCERNS_TEMPLATES) to avoid misleading savings calculations.
        """
        repetitive_patterns = {}
        
        # Check for existing template systems that already handle deduplication
        has_references_templates = 'window.REFERENCES_TEMPLATES' in content
        has_sourcedataconcerns_templates = 'window.SOURCEDATACONCERNS_TEMPLATES' in content
        has_template_expansion = 'Object.keys(window.' in content and 'forEach(templateId =>' in content
        
        existing_deduplication_coverage = 0
        if has_references_templates:
            existing_deduplication_coverage += 30  # References typically 20-40% of repetitive content
        if has_sourcedataconcerns_templates:
            existing_deduplication_coverage += 10  # Source data concerns typically 5-15%
        if has_template_expansion:
            existing_deduplication_coverage += 5   # Template expansion overhead
            
        # NEW APPROACH: Use generic pattern to capture ALL numbered ID structures, then group by pattern
        generic_numbered_pattern = r'id="([a-zA-Z][a-zA-Z0-9_-]*?)_(\d+)"[^>]*>'
        all_numbered_matches = list(re.finditer(generic_numbered_pattern, content))
        
        # PERFORMANCE OPTIMIZATION: Pre-filter to only significant patterns
        id_pattern_counts = defaultdict(int)
        for match in all_numbered_matches:
            id_prefix = match.group(1)
            id_pattern_counts[id_prefix] += 1
        
        # Only analyze patterns that appear 5+ times (performance optimization)
        significant_patterns = {prefix: count for prefix, count in id_pattern_counts.items() if count >= 5}
        
        if not significant_patterns:
            return repetitive_patterns  # Early return if no significant patterns
        
        # Group matches by their ID prefix pattern (only for significant patterns)
        id_pattern_groups = defaultdict(list)
        for match in all_numbered_matches:
            id_prefix = match.group(1)  # The part before the underscore and number
            
            # Skip non-significant patterns for performance
            if id_prefix not in significant_patterns:
                continue
            id_number = match.group(2)   # The number part
            
            # PERFORMANCE OPTIMIZATION: Use simplified element size estimation
            # Instead of complex tag matching, use a fast heuristic based on content patterns
            start_pos = match.start()
            
            # Look for the opening tag start (look backward for <)
            element_start = content.rfind('<', max(0, start_pos - 200), start_pos)
            if element_start == -1:
                element_start = start_pos
            
            # Use a fast heuristic for element size instead of exact tag matching
            # Look ahead for likely element end (next opening tag or reasonable boundary)
            search_end = min(start_pos + 2000, len(content))  # Limit search scope
            
            # Simple heuristic: find next opening tag or use fixed window
            next_tag_pos = content.find('<', start_pos + 50)  # Skip current tag
            if next_tag_pos != -1 and next_tag_pos < search_end:
                element_end = next_tag_pos
            else:
                element_end = min(start_pos + 800, len(content))  # Default window
            
            # ENHANCED SIZE CALCULATION FOR MATCHESTABLE PATTERNS
            if id_prefix == 'matchesTable':
                # For matchesTable patterns, get the complete table structure
                table_start_pattern = r'<table[^>]*id\s*=\s*["\']' + re.escape(f'{id_prefix}_{id_number}') + r'["\'][^>]*>'
                table_start_match = re.search(table_start_pattern, content[max(0, start_pos - 200):start_pos + 100])
                
                if table_start_match:
                    # Find the actual table start position
                    table_start = max(0, start_pos - 200) + table_start_match.start()
                    
                    # Find the complete table end
                    table_end_pos = content.find('</table>', table_start)
                    if table_end_pos != -1:
                        table_end = table_end_pos + len('</table>')
                        
                        # Get complete table content
                        table_content = content[table_start:table_end]
                        table_size = len(table_content)
                        
                        # Calculate badge/modal overhead within this table
                        badge_modal_pattern = r'onclick="BadgeModalManager\.[^"]*"'
                        badge_matches = re.findall(badge_modal_pattern, table_content)
                        badge_overhead = len(badge_matches) * 100  # Estimate 100 chars per badge JS
                        
                        # Adjust size to exclude badge overhead (should be counted separately)
                        adjusted_table_size = max(table_size - badge_overhead, table_size // 2)  # Minimum 50% of original
                        
                        element_size = adjusted_table_size
                        element_start = table_start
                        element_end = table_end
                        element_content = table_content[:300] + f'...[table with {len(badge_matches)} badges, {table_size} total bytes, {adjusted_table_size} content bytes]'
                    else:
                        # Fallback to heuristic if table end not found
                        element_size = element_end - element_start
                        element_content = content[element_start:min(element_start + 300, element_end)] + '...'
                else:
                    # Fallback to heuristic if table start not found
                    element_size = element_end - element_start
                    element_content = content[element_start:min(element_start + 300, element_end)] + '...'
            else:
                # Use existing heuristic for non-matchesTable patterns
                element_size = element_end - element_start
                element_content = content[element_start:min(element_start + 300, element_end)] + '...' if element_size > 300 else content[element_start:element_end]
            
            # Add to group with accurate size
            id_pattern_groups[id_prefix].append({
                'match': match,
                'id_number': int(id_number) if id_number.isdigit() else 0,
                'element_snippet': element_content[:300] + '...' if len(element_content) > 300 else element_content,
                'size_estimate': element_size,
                'element_start': element_start,
                'element_end': element_end
            })
        
        # Analyze each ID pattern group (PERFORMANCE: analyze top 100 patterns by count to handle ties)
        patterns_by_count = sorted(id_pattern_groups.items(), key=lambda x: len(x[1]), reverse=True)[:100]
        
        for id_prefix, group_matches in patterns_by_count:
            if len(group_matches) >= 3:  # Only analyze patterns with 3+ instances
                # Calculate basic statistics
                total_size = sum(item['size_estimate'] for item in group_matches)
                id_numbers = [item['id_number'] for item in group_matches if item['id_number'] > 0]
                
                # Check if this would impact >1% of file size
                base_potential_savings = total_size - (len(group_matches) * 100) - 200  # Template overhead estimate
                savings_percentage = (base_potential_savings / file_size) * 100
                
                if savings_percentage > 1.0 and base_potential_savings > 5000:
                    # Determine if affected by existing templates (heuristic based on common patterns)
                    affected_by_templates = any(keyword in id_prefix.lower() for keyword in 
                                              ['container', 'modal', 'reference', 'source', 'data'])
                    
                    # Adjust savings based on existing template coverage
                    if affected_by_templates:
                        coverage_factor = existing_deduplication_coverage / 100
                        potential_savings = base_potential_savings * (1 - coverage_factor)
                        deduplication_status = f"Partially deduplicated (existing templates cover ~{existing_deduplication_coverage}%)"
                    else:
                        potential_savings = base_potential_savings
                        deduplication_status = "Not covered by existing template systems"
                    
                    # Create a unique pattern name based on the ID prefix
                    pattern_name = f"id_pattern_{id_prefix}"
                    
                    repetitive_patterns[pattern_name] = {
                        'count': len(group_matches),
                        'total_size': total_size,
                        'percentage': (total_size / file_size) * 100,
                        'id_prefix': id_prefix,
                        'id_range': f"{min(id_numbers)}-{max(id_numbers)}" if id_numbers else "N/A",
                        'id_numbers_found': sorted(id_numbers) if id_numbers else [],
                        'avg_structure_size': total_size // len(group_matches),
                        'raw_potential_savings': max(0, base_potential_savings),
                        'adjusted_potential_savings': max(0, potential_savings),
                        'savings_percentage': (potential_savings / file_size) * 100,
                        'description': f'Repetitive elements with ID pattern "{id_prefix}_X"',
                        'template_recommendation': f'{id_prefix}_X template system',
                        'existing_deduplication_status': deduplication_status,
                        'affected_by_existing_templates': affected_by_templates,
                        'sample_structures': [item['element_snippet'] for item in group_matches[:2]],
                        'pattern_analysis': {
                            'appears_to_be_buttons': 'button' in id_prefix.lower() or 'btn' in id_prefix.lower(),
                            'appears_to_be_containers': 'container' in id_prefix.lower() or 'wrapper' in id_prefix.lower(),
                            'appears_to_be_modals': 'modal' in id_prefix.lower() or 'dialog' in id_prefix.lower(),
                            'appears_to_be_tables': 'table' in id_prefix.lower() or 'row' in id_prefix.lower(),
                            'appears_to_be_forms': 'form' in id_prefix.lower() or 'input' in id_prefix.lower(),
                            'appears_to_be_lists': 'list' in id_prefix.lower() or 'item' in id_prefix.lower(),
                            'id_prefix_length': len(id_prefix),
                            'uses_camelcase': any(c.isupper() for c in id_prefix[1:]) if len(id_prefix) > 1 else False,
                            'uses_underscores': '_' in id_prefix,
                            'numeric_density': len([n for n in id_numbers if n > 0]) / len(group_matches) if group_matches else 0
                        }
                    }
        
        return repetitive_patterns

    def _analyze_pattern_hierarchy(self, matches: List, script_ranges: List[Tuple[int, int]], pattern_name: str) -> Dict[str, Any]:
        """
        Analyze hierarchical relationships between bloat patterns and their containing contexts.
        This reveals when patterns are nested within larger bloat sources (e.g., inside script blocks).
        
        Args:
            matches: List of regex match objects for the pattern
            script_ranges: List of (start, end) tuples for script block positions
            pattern_name: Name of the pattern being analyzed
            
        Returns:
            Dictionary with hierarchy analysis including nested counts and parent relationships
        """
        hierarchy_info = {
            'nested_in_scripts': 0,
            'nested_size_in_scripts': 0,
            'independent_count': 0,
            'independent_size': 0,
            'parent_containers': [],
            'is_primarily_nested': False,
            'nesting_percentage': 0.0
        }
        
        # Don't analyze hierarchy for script blocks themselves to avoid circular reference
        if pattern_name == 'inline_script_blocks':
            hierarchy_info['is_primary_container'] = True
            return hierarchy_info
        
        total_size = 0
        nested_size = 0
        
        for match in matches:
            match_start, match_end = match.span()
            match_size = len(match.group())
            total_size += match_size
            
            # Check if this match is within any script block
            is_nested = False
            for script_start, script_end in script_ranges:
                if script_start <= match_start < script_end and script_start < match_end <= script_end:
                    hierarchy_info['nested_in_scripts'] += 1
                    hierarchy_info['nested_size_in_scripts'] += match_size
                    nested_size += match_size
                    is_nested = True
                    if 'Inline Script Blocks' not in hierarchy_info['parent_containers']:
                        hierarchy_info['parent_containers'].append('Inline Script Blocks')
                    break
            
            if not is_nested:
                hierarchy_info['independent_count'] += 1
                hierarchy_info['independent_size'] += match_size
        
        # Calculate nesting statistics
        if total_size > 0:
            hierarchy_info['nesting_percentage'] = (nested_size / total_size) * 100
            hierarchy_info['is_primarily_nested'] = hierarchy_info['nesting_percentage'] > 50
        
        return hierarchy_info

    def _merge_overlapping_ranges(self, ranges: List[Tuple[int, int, str, int]]) -> List[Tuple[int, int, str, int]]:
        """
        Merge overlapping ranges to prevent double-counting content.
        
        Args:
            ranges: List of (start, end, pattern_name, size) tuples sorted by start position
            
        Returns:
            List of non-overlapping (start, end, primary_pattern, size) tuples
        """
        if not ranges:
            return []
        
        merged = []
        current_start, current_end, primary_pattern, current_size = ranges[0]
        
        for start, end, pattern_name, size in ranges[1:]:
            if start <= current_end:  # Overlapping
                # Extend the current range and keep the primary pattern (usually the largest)
                current_end = max(current_end, end)
                current_size = current_end - current_start
                # Keep the pattern with highest priority (tables > scripts > html > css)
                pattern_priority = {
                    'large_data_tables': 5,
                    'inline_script_blocks': 4,
                    'verbose_html_structures': 3,
                    'repetitive_table_rows': 2,
                    'massive_text_blocks': 1
                }
                if pattern_priority.get(pattern_name, 0) > pattern_priority.get(primary_pattern, 0):
                    primary_pattern = pattern_name
            else:  # Non-overlapping
                merged.append((current_start, current_end, primary_pattern, current_size))
                current_start, current_end, primary_pattern, current_size = start, end, pattern_name, size
        
        merged.append((current_start, current_end, primary_pattern, current_size))
        return merged

    def _calculate_pattern_deduplicated_size(self, pattern_ranges: List[Tuple[int, int]], 
                                           deduplicated_ranges: List[Tuple[int, int, str, int]]) -> int:
        """
        Calculate how much of the deduplicated total this pattern actually contributes.
        
        Args:
            pattern_ranges: List of (start, end) tuples for this pattern's matches
            deduplicated_ranges: List of deduplicated (start, end, primary_pattern, size) tuples
            
        Returns:
            Size in bytes that this pattern contributes to the deduplicated total
        """
        contribution = 0
        for start, end in pattern_ranges:
            for dedup_start, dedup_end, primary_pattern, dedup_size in deduplicated_ranges:
                # Check if this pattern range overlaps with a deduplicated range
                overlap_start = max(start, dedup_start)
                overlap_end = min(end, dedup_end)
                if overlap_start < overlap_end:
                    # This pattern contributes to this deduplicated range
                    overlap_size = overlap_end - overlap_start
                    # Only count full contribution if this range is entirely within the pattern match
                    if dedup_start >= start and dedup_end <= end:
                        contribution += dedup_size
                    else:
                        # Partial contribution based on overlap
                        contribution += overlap_size
                    break  # Each pattern range should only match one deduplicated range
        
        return contribution

    def _generate_recommendations(self, bloat_sources: Dict, template_opportunities: Dict, repetitive_structures: Dict = None) -> List[Dict[str, Any]]:
        """Generate prioritized optimization recommendations with hierarchy awareness"""
        recommendations = []
        
        # Analyze hierarchy relationships to avoid misleading recommendations
        script_based_patterns = []
        independent_patterns = []
        
        # High-impact recommendations based on bloat analysis
        for pattern_name, analysis in bloat_sources.items():
            if analysis['percentage'] > 1:  # Only recommend patterns that have >1% impact
                # Check hierarchy to provide context-aware recommendations
                hierarchy_context = ""
                if 'hierarchy' in analysis:
                    hierarchy = analysis['hierarchy']
                    if hierarchy.get('is_primary_container'):
                        hierarchy_context = " (contains other bloat patterns)"
                        script_based_patterns.append(pattern_name)
                    elif hierarchy.get('is_primarily_nested'):
                        nested_percentage = hierarchy['nesting_percentage']
                        parent_containers = ', '.join(hierarchy['parent_containers'])
                        hierarchy_context = f" ({nested_percentage:.1f}% nested within {parent_containers})"
                        independent_patterns.append(pattern_name)
                    elif hierarchy.get('nested_in_scripts', 0) > 0:
                        nested_count = hierarchy['nested_in_scripts']
                        parent_containers = ', '.join(hierarchy['parent_containers'])
                        hierarchy_context = f" ({nested_count} occurrences within {parent_containers})"
                
                # Adjust impact messaging based on hierarchy
                impact_size_mb = analysis['total_size'] / (1024 * 1024)
                if pattern_name == 'inline_script_blocks':
                    impact_msg = f"Reduce file size by {analysis['percentage']:.1f}% ({impact_size_mb:.2f} MB)"
                    if len(script_based_patterns) > 1:
                        impact_msg += f" - will also resolve nested bloat in other patterns"
                else:
                    impact_msg = f"Reduce file size by {analysis['percentage']:.1f}% ({impact_size_mb:.2f} MB)"
                
                # Prioritize based on impact size rather than arbitrary severity
                priority = 'HIGH' if analysis['percentage'] > 5 else 'MEDIUM'
                
                recommendations.append({
                    'priority': priority,
                    'category': 'Code Structure',
                    'issue': pattern_name.replace('_', ' ').title() + hierarchy_context,
                    'description': analysis['description'],
                    'optimization': analysis['optimization'],
                    'impact': impact_msg,
                    'effort': 'Medium',
                    'hierarchy_aware': True if hierarchy_context else False
                })
        
        # Add hierarchy summary recommendation if there are nested relationships
        if len(script_based_patterns) > 0 and len(independent_patterns) > 0:
            recommendations.insert(0, {
                'priority': 'HIGH',
                'category': 'Hierarchy Strategy',
                'issue': 'Overlapping Bloat Pattern Optimization',
                'description': f'Multiple bloat patterns detected with hierarchical relationships',
                'optimization': f'Prioritize inline script extraction first - will simultaneously resolve {len(independent_patterns)} nested patterns',
                'impact': 'Coordinated optimization prevents double-counting and maximizes efficiency',
                'effort': 'Medium',
                'hierarchy_aware': True,
                'note': 'This strategy recommendation accounts for pattern nesting relationships'
            })
        
        # Template-based recommendations (only significant ones)
        for template_type, analysis in template_opportunities.items():
            if analysis['count'] > 5 and analysis['percentage'] > 1.0:  # Only recommend if >1% impact
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Template Deduplication',
                    'issue': f'Repeated {template_type.replace("_", " ").title()}',
                    'description': f'{analysis["count"]} similar registration patterns found',
                    'optimization': 'Implement template-based deduplication',
                    'impact': f'Potential {analysis["percentage"]:.1f}% reduction ({analysis["deduplication_savings"]/1024/1024:.2f} MB)',
                    'effort': 'Low'
                })
        
        # NEW: Repetitive structure recommendations (only significant ones)
        if repetitive_structures:
            for structure_name, analysis in repetitive_structures.items():
                if analysis['adjusted_potential_savings'] > 10000 and analysis['savings_percentage'] > 1.0:  # Only if >1% impact
                    # Prioritize based on impact size rather than arbitrary severity
                    priority = 'HIGH' if analysis['savings_percentage'] > 5 else 'MEDIUM'
                    
                    # Create description that accounts for existing deduplication
                    if analysis['affected_by_existing_templates']:
                        description = f"{analysis['count']} numbered containers ({analysis['id_range']}) with remaining structural redundancy after existing template deduplication"
                        impact_note = f"Net savings after accounting for existing REFERENCES/SOURCEDATACONCERNS templates"
                    else:
                        description = f"{analysis['count']} numbered containers ({analysis['id_range']}) with identical structure (not covered by existing templates)"
                        impact_note = f"Full templating opportunity - not handled by existing deduplication"
                    
                    recommendations.append({
                        'priority': priority,
                        'category': 'Numbered Container Templating',
                        'issue': f'Repetitive {structure_name.replace("_", " ").title()}',
                        'description': description,
                        'optimization': f"Create template system for {analysis['template_recommendation']}",
                        'impact': f"Realistic {analysis['savings_percentage']:.1f}% reduction ({analysis['adjusted_potential_savings']:,} bytes)",
                        'impact_note': impact_note,
                        'effort': 'Medium',
                        'current_size': f"{analysis['total_size']:,} bytes",
                        'raw_potential_savings': f"{analysis['raw_potential_savings']:,} bytes (before deduplication adjustment)",
                        'existing_deduplication_status': analysis['existing_deduplication_status'],
                        'avg_container_size': f"{analysis['avg_structure_size']:,} bytes"
                    })
        
        # Sort recommendations by priority and impact
        priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        recommendations.sort(key=lambda x: (priority_order.get(x['priority'], 3), 
                                          -float(re.search(r'(\d+\.?\d*)%', x['impact']).group(1) if 
                                                re.search(r'(\d+\.?\d*)%', x['impact']) else 0)))
        
        return recommendations

    def analyze_directory(self, output_file: Optional[Path] = None) -> Dict[str, BloatAnalysis]:
        """
        Analyze the top 5 largest HTML files in the target directory
        
        Args:
            output_file: Optional path to write JSON report
            
        Returns:
            Dictionary mapping file names to BloatAnalysis objects
        """
        results = {}
        
        if not self.target_dir.exists():
            raise FileNotFoundError(f"Target directory not found: {self.target_dir}")
        
        # Get all HTML files and sort by size (largest first)
        all_files = list(self.target_dir.glob("*.html"))
        if not all_files:
            print(f"No HTML files found in {self.target_dir}")
            return results
            
        # Sort by file size (largest first) and take top 5
        files_by_size = sorted(all_files, key=lambda f: f.stat().st_size, reverse=True)
        files_to_analyze = files_by_size[:5]
        
        print(f"Found {len(all_files)} HTML files. Analyzing top 5 largest files...")
        
        for i, file_path in enumerate(files_to_analyze, 1):
            try:
                file_size = file_path.stat().st_size
                file_size_mb = file_size / (1024 * 1024)
                print(f"[{i}/5] Analyzing {file_path.name} ({file_size_mb:.2f} MB)...")
                analysis = self.analyze_file(file_path)
                results[file_path.name] = analysis
                print(f"✓ {file_path.name}: analyzed")
            except Exception as e:
                print(f"✗ Failed to analyze {file_path.name}: {e}")
        
        # Write report if requested
        if output_file:
            self._write_report(results, output_file)
        
        return results

    def _write_report(self, results: Dict[str, BloatAnalysis], output_file: Path):
        """Write comprehensive bloat analysis report - JSON only for now"""
        # Force JSON output until markdown generation is fixed
        self._write_json_report(results, output_file)
    
    def _write_json_report(self, results: Dict[str, BloatAnalysis], output_file: Path):
        """Write comprehensive JSON bloat analysis report"""
        report_data = {}
        
        for file_name, analysis in results.items():
            report_data[file_name] = asdict(analysis)
        
        # Add summary statistics
        total_files = len(results)
        total_size = sum(a.total_size for a in results.values())
        
        report_data['_summary'] = {
            'total_files_analyzed': total_files,
            'total_size_bytes': total_size,
            'average_file_size': total_size // total_files if total_files else 0,
            'optimization_opportunities': sum(len(a.optimization_recommendations) for a in results.values()),
            'analysis_timestamp': json.dumps({'timestamp': 'generated'}),
            'framework_version': '1.0'
        }
        
        output_file.write_text(json.dumps(report_data, indent=2, ensure_ascii=False))
        print(f"\n📊 JSON Report written to: {output_file}")

    def compare_files(self, file1: str, file2: str) -> Dict[str, Any]:
        """Compare bloat between two files"""
        analysis1 = self.analyze_file(Path(file1))
        analysis2 = self.analyze_file(Path(file2))
        
        comparison = {
            'file1': {'name': file1, 'size': analysis1.total_size},
            'file2': {'name': file2, 'size': analysis2.total_size},
            'size_difference': analysis2.total_size - analysis1.total_size,
            'bloat_pattern_comparison': {}
        }
        
        # Compare bloat patterns
        all_patterns = set(analysis1.bloat_sources.keys()) | set(analysis2.bloat_sources.keys())
        for pattern in all_patterns:
            source1 = analysis1.bloat_sources.get(pattern, {'total_size': 0, 'count': 0})
            source2 = analysis2.bloat_sources.get(pattern, {'total_size': 0, 'count': 0})
            
            comparison['bloat_pattern_comparison'][pattern] = {
                'file1_size': source1['total_size'],
                'file2_size': source2['total_size'],
                'size_difference': source2['total_size'] - source1['total_size'],
                'file1_count': source1['count'],
                'file2_count': source2['count']
            }
        
        return comparison

    def get_top_bloat_files(self, results: Dict[str, BloatAnalysis], limit: int = 10) -> List[Tuple[str, BloatAnalysis]]:
        """Get the files with highest total bloat size"""
        sorted_files = sorted(results.items(), key=lambda x: x[1].actual_bloat_size or x[1].total_size, reverse=True)
        return sorted_files[:limit]

    def print_analysis_summary(self, analysis: BloatAnalysis):
        """Print a formatted summary of bloat analysis"""
        print(f"\n🔍 Bloat Analysis: {Path(analysis.file_path).name}")
        file_size_mb = analysis.total_size / (1024 * 1024)
        print(f"📊 File Size: {file_size_mb:.2f} MB ({analysis.total_size:,} bytes, {analysis.line_count:,} lines)")
        
        print(f"\n📋 Bloat Sources ({len(analysis.bloat_sources)}) - Raw Pattern Sizes (with overlap):")
        # Sort bloat sources by total size (descending order)
        sorted_bloat_sources = sorted(analysis.bloat_sources.items(), 
                                    key=lambda x: x[1]['total_size'], reverse=True)
        
        total_raw_size = 0
        total_deduplicated_size = 0
        
        for pattern_name, source_info in sorted_bloat_sources:
            size_mb = source_info['total_size'] / (1024 * 1024)
            deduplicated_size = source_info.get('deduplicated_size', source_info['total_size'])
            deduplicated_mb = deduplicated_size / (1024 * 1024)
            total_raw_size += source_info['total_size']
            total_deduplicated_size += deduplicated_size
            
            print(f"  • {pattern_name.replace('_', ' ').title()}: "
                  f"{size_mb:.2f} MB raw, {deduplicated_mb:.2f} MB effective")
        
        # Show the deduplication summary
        total_raw_mb = total_raw_size / (1024 * 1024)
        actual_bloat_mb = analysis.actual_bloat_size / (1024 * 1024) if hasattr(analysis, 'actual_bloat_size') and analysis.actual_bloat_size > 0 else total_deduplicated_size / (1024 * 1024)
        overlap_mb = total_raw_mb - actual_bloat_mb
        
        print(f"\n📊 Bloat Summary:")
        print(f"  • Raw total (with overlaps): {total_raw_mb:.2f} MB")
        print(f"  • Actual bloat (deduplicated): {actual_bloat_mb:.2f} MB")
        print(f"  • Overlap removed: {overlap_mb:.2f} MB ({overlap_mb/total_raw_mb*100:.1f}% of raw total)")
        
        print(f"\n🔄 Template Opportunities ({len(analysis.template_opportunities)}):")
        for template_type, template_info in analysis.template_opportunities.items():
            size_mb = template_info['total_size'] / (1024 * 1024)
            savings_mb = template_info['deduplication_savings'] / (1024 * 1024)
            print(f"  • {template_type.replace('_', ' ').title()}: "
                  f"{template_info['count']} instances, {size_mb:.2f} MB total, "
                  f"{savings_mb:.2f} MB potential savings ({template_info['percentage']:.1f}% of file)")
        
        # NEW: Show repetitive structures with ID pattern breakdown
        if hasattr(analysis, 'repetitive_structures') and analysis.repetitive_structures:
            print(f"\n🔄 Repetitive ID Pattern Analysis (Accounting for Existing Templates):")
            total_adjusted_savings = 0
            
            # Sort by savings potential for better display
            sorted_structures = sorted(analysis.repetitive_structures.items(), 
                                     key=lambda x: x[1]['adjusted_potential_savings'], reverse=True)
            
            for structure_name, struct_info in sorted_structures:
                if struct_info['adjusted_potential_savings'] > 5000 and struct_info['savings_percentage'] > 1.0:
                    status_icon = "⚠️" if struct_info['affected_by_existing_templates'] else "🆕"
                    total_size_mb = struct_info['total_size'] / (1024 * 1024)
                    savings_mb = struct_info['adjusted_potential_savings'] / (1024 * 1024)
                    
                    # Extract ID prefix for cleaner display
                    id_prefix = struct_info.get('id_prefix', structure_name.replace('id_pattern_', ''))
                    
                    print(f"  {status_icon} ID Pattern '{id_prefix}_X': "
                          f"{struct_info['count']} elements, {total_size_mb:.2f} MB total, "
                          f"{savings_mb:.2f} MB savings ({struct_info['savings_percentage']:.1f}%)")
                    
                    # Show ID range and pattern analysis
                    if 'id_range' in struct_info:
                        print(f"     🔢 ID Range: {struct_info['id_range']}")
                    
                    if 'pattern_analysis' in struct_info:
                        pattern_info = struct_info['pattern_analysis']
                        element_types = []
                        if pattern_info.get('appears_to_be_buttons'): element_types.append("buttons")
                        if pattern_info.get('appears_to_be_containers'): element_types.append("containers")  
                        if pattern_info.get('appears_to_be_modals'): element_types.append("modals")
                        if pattern_info.get('appears_to_be_tables'): element_types.append("tables")
                        if pattern_info.get('appears_to_be_forms'): element_types.append("forms")
                        if pattern_info.get('appears_to_be_lists'): element_types.append("lists")
                        
                        if element_types:
                            print(f"     🎯 Likely Type: {', '.join(element_types)}")
                        
                        # Show naming convention insights
                        naming_info = []
                        if pattern_info.get('uses_camelcase'): naming_info.append("camelCase")
                        if pattern_info.get('uses_underscores'): naming_info.append("snake_case")
                        if naming_info:
                            print(f"     📝 Naming: {', '.join(naming_info)}")
                    
                    if struct_info['affected_by_existing_templates']:
                        print(f"     └─ {struct_info['existing_deduplication_status']}")
                    
                    total_adjusted_savings += struct_info['adjusted_potential_savings']
            
            if total_adjusted_savings > 0:
                total_savings_mb = total_adjusted_savings / (1024 * 1024)
                total_percentage = (total_adjusted_savings / analysis.total_size) * 100
                print(f"\n  📊 Total ID Pattern Template Savings: "
                      f"{total_savings_mb:.2f} MB ({total_percentage:.1f}% of file)")
        
        print(f"\n💡 Optimization Recommendations ({len(analysis.optimization_recommendations)}):")
        for i, rec in enumerate(analysis.optimization_recommendations[:5], 1):
            print(f"  {i}. [{rec['priority']}] {rec['issue']}")
            # Convert byte values in impact string to MB
            impact_text = rec['impact']
            # Replace byte values with MB equivalents
            import re
            byte_matches = re.findall(r'(\d+,?\d*) bytes', impact_text)
            for byte_str in byte_matches:
                byte_val = int(byte_str.replace(',', ''))
                mb_val = byte_val / (1024 * 1024)
                impact_text = impact_text.replace(f"{byte_str} bytes", f"{mb_val:.2f} MB")
            print(f"     {rec['optimization']} - {impact_text}")
            if 'impact_note' in rec:
                print(f"     📝 {rec['impact_note']}")


def main():
    """Main entry point for the bloat detection framework"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Universal bloat detection framework for any generated HTML file')
    parser.add_argument('file', nargs='?', help='Direct path to HTML file to analyze')
    parser.add_argument('--cve', help='Analyze specific CVE file by name (e.g., CVE-2024-46886)')
    parser.add_argument('--analyze-all', action='store_true', help='Analyze the top 5 largest HTML files in directory')
    parser.add_argument('--target-directory', '-t', help='Target directory to analyze (default: generated_pages or current dir)')
    parser.add_argument('--output-report', help='Output file for JSON bloat analysis report')
    parser.add_argument('--compare', nargs=2, help='Compare bloat analysis between two files')
    parser.add_argument('--top', type=int, default=10, help='Show top N bloated files in summary (default: 10)')
    
    args = parser.parse_args()
    
    # Initialize framework with target directory support
    framework = BloatDetectionFramework(target_directory=args.target_directory)
    
    if args.file:
        # Direct file path provided - universal analysis
        file_path = Path(args.file)
        if not file_path.is_absolute():
            file_path = Path.cwd() / file_path
            
        if not file_path.exists():
            print(f"❌ File not found: {file_path}")
            sys.exit(1)
        
        analysis = framework.analyze_file(file_path)
        framework.print_analysis_summary(analysis)
        
        if args.output_report:
            report_path = Path(args.output_report)
            framework._write_report({file_path.name: analysis}, report_path)
            
    elif args.cve:
        # Analyze specific CVE file
        cve_file = framework.target_dir / f"{args.cve}.html"
        if not cve_file.exists():
            print(f"❌ CVE file not found: {cve_file}")
            sys.exit(1)
        
        analysis = framework.analyze_file(cve_file)
        framework.print_analysis_summary(analysis)
        
        if args.output_report:
            report_path = Path(args.output_report)
            framework._write_report({cve_file.name: analysis}, report_path)
    
    elif args.analyze_all:
        # Analyze top 5 largest files
        output_path = Path(args.output_report) if args.output_report else None
        results = framework.analyze_directory(output_path)
        
        # Show summary
        print(f"\n📈 Analysis Summary:")
        print(f"Files analyzed: {len(results)}")
        total_size = sum(a.total_size for a in results.values())
        print(f"Total size: {total_size:,} bytes ({total_size/1024/1024:.1f} MB)")
        
        # Show top bloated files
        if results:
            top_files = framework.get_top_bloat_files(results, args.top)
            print(f"\n🔥 Top {len(top_files)} Most Bloated Files:")
            for i, (filename, analysis) in enumerate(top_files, 1):
                file_size_mb = analysis.total_size / (1024 * 1024)
                bloat_size_mb = (analysis.actual_bloat_size or 0) / (1024 * 1024)
                print(f"{i:2d}. {filename}: {file_size_mb:.2f} MB total, "
                      f"{bloat_size_mb:.2f} MB bloat")
    
    elif args.compare:
        # Compare two files
        comparison = framework.compare_files(args.compare[0], args.compare[1])
        print(f"\n📊 File Comparison:")
        print(f"File 1: {comparison['file1']['name']} - {comparison['file1']['size']:,} bytes")
        print(f"File 2: {comparison['file2']['name']} - {comparison['file2']['size']:,} bytes")
        print(f"Size difference: {comparison['size_difference']:+,} bytes")
    
    else:
        parser.print_help()
        print(f"\nExample usage:")
        print(f"  python bloat_detection_framework.py --analyze-all")
        print(f"    └─ Analyzes the 5 largest HTML files in the directory")
        print(f"  python bloat_detection_framework.py --cve CVE-2024-46886")
        print(f"    └─ Analyzes a specific CVE file by name")
        print(f"  python bloat_detection_framework.py path/to/file.html")
        print(f"    └─ Analyzes any HTML file directly")
        print(f"  python bloat_detection_framework.py --analyze-all --output-report bloat_report.json")
        print(f"    └─ Saves detailed analysis to JSON file")


if __name__ == '__main__':
    main()
