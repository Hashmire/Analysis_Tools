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
    severity_score: float


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
                'severity': 'HIGH',
                'optimization': 'Extract to external file with CDN/caching'
            },
            'inline_script_blocks': {
                'pattern': r'<script[^>]*>(?:(?!</script>).){1000,}</script>',
                'description': 'Large inline script blocks',
                'severity': 'CRITICAL',
                'optimization': 'Move to external JS files'
            },
            'repetitive_data_registrations': {
                'pattern': r'(?:window\.\w+\s*=|\.register\w*\(|\.add\w*\()[^;]{100,};',
                'description': 'Repetitive data registration or assignment calls',
                'severity': 'MEDIUM',
                'optimization': 'Use template deduplication or batch operations'
            },
            'duplicate_css_rules': {
                'pattern': r'\.[\w-]+\s*\{[^}]+\}',
                'description': 'Repeated CSS styling rules',
                'severity': 'MEDIUM',
                'optimization': 'Extract common styles to CSS classes'
            },
            'verbose_html_structures': {
                'pattern': r'<(?:div|span|section)[^>]{100,}>',
                'description': 'HTML elements with verbose attribute lists',
                'severity': 'LOW',
                'optimization': 'Simplify attribute usage or use CSS classes'
            },
            'embedded_json_data': {
                'pattern': r'(?:window\.\w+\s*=\s*|var\s+\w+\s*=\s*)\{[^}]{500,}\}',
                'description': 'Large embedded JSON data structures',
                'severity': 'MEDIUM',
                'optimization': 'Load dynamically or use compression'
            },
            'template_expansion_overhead': {
                'pattern': r'(?:Object\.keys\([^)]+\)\.forEach|for\s*\([^)]*in[^)]*\))[^}]{100,}',
                'description': 'Template expansion or iteration code',
                'severity': 'LOW',
                'optimization': 'Pre-expand templates during generation or optimize loops'
            },
            'redundant_error_handling': {
                'pattern': r'(?:try\s*\{[^}]+catch|throw\s+new\s+Error\([^)]+\)|console\.(?:error|warn|log)\([^)]+\)){2,}',
                'description': 'Repetitive error handling or logging code',
                'severity': 'LOW',
                'optimization': 'Use centralized error handling utilities'
            },
            'duplicate_event_handlers': {
                'pattern': r'(?:onclick|onload|onchange|addEventListener)\s*=\s*["\'][^"\']{50,}["\']',
                'description': 'Repetitive inline event handler code',
                'severity': 'MEDIUM',
                'optimization': 'Use event delegation or external handlers'
            },
            'verbose_bootstrap_classes': {
                'pattern': r'class\s*=\s*["\'][^"\']*(?:btn|card|container|row|col)[^"\']{50,}["\']',
                'description': 'Verbose Bootstrap or CSS framework class lists',
                'severity': 'LOW',
                'optimization': 'Create custom CSS classes for common combinations'
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
        
        # Analyze each bloat pattern with hierarchy tracking
        for pattern_name, pattern_config in self.bloat_patterns.items():
            matches = list(re.finditer(pattern_config['pattern'], content, re.DOTALL))
            if matches:
                total_match_size = sum(len(match.group()) for match in matches)
                percentage = (total_match_size / file_size) * 100
                
                # Only include bloat sources that impact >1% of file size
                if percentage > 1.0:
                    # NEW: Track which matches are inside script blocks
                    hierarchy_info = self._analyze_pattern_hierarchy(matches, script_ranges, pattern_name)
                    
                    bloat_sources[pattern_name] = {
                        'count': len(matches),
                        'total_size': total_match_size,
                        'percentage': percentage,
                        'severity': pattern_config['severity'],
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
                
                # Only include template opportunities that impact >1% of file size
                if percentage > 1.0:
                    template_opportunities[template_type] = {
                        'count': len(matches),
                        'total_size': total_size,
                        'deduplication_savings': total_size - len(matches[0].group()),
                        'percentage': percentage
                    }
        
        # NEW: Analyze repetitive numbered container structures
        repetitive_structures = self._analyze_numbered_containers(content, file_size)
        
        # Generate optimization recommendations
        recommendations = self._generate_recommendations(bloat_sources, template_opportunities, repetitive_structures)
        
        # Calculate severity score
        severity_score = self._calculate_severity_score(bloat_sources)
        
        return BloatAnalysis(
            file_path=str(file_path),
            total_size=file_size,
            line_count=line_count,
            bloat_sources=bloat_sources,
            optimization_recommendations=recommendations,
            template_opportunities=template_opportunities,
            deduplication_potential={},  # Will be calculated properly later
            repetitive_structures=repetitive_structures,
            severity_score=severity_score
        )

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
            
        # Define patterns for common numbered structures (universal patterns)
        numbered_patterns = {
            'button_containers': {
                'pattern': r'id="[^"]*[Bb]utton[^"]*_(\d+)"[^>]*>.*?</(?:div|button)>',
                'description': 'Repetitive button container structures with numbered IDs',
                'template_base': 'buttonContainer_X template',
                'affected_by_existing_templates': False
            },
            'data_tables': {
                'pattern': r'id="[^"]*[Tt]able[^"]*_(\d+)"[^>]*>.*?</table>',
                'description': 'Repetitive data table structures with numbered IDs',
                'template_base': 'dataTable_X template',
                'affected_by_existing_templates': False
            },
            'container_divs': {
                'pattern': r'id="[^"]*[Cc]ontainer[^"]*_(\d+)"[^>]*>.*?</div>',
                'description': 'Repetitive container div structures with numbered IDs',
                'template_base': 'container_X template',
                'affected_by_existing_templates': True
            },
            'header_elements': {
                'pattern': r'id="[^"]*[Hh]eader[^"]*_(\d+)"[^>]*>.*?</(?:div|h[1-6]|header)>',
                'description': 'Repetitive header elements with numbered IDs',
                'template_base': 'header_X template',
                'affected_by_existing_templates': False
            },
            'modal_components': {
                'pattern': r'id="[^"]*[Mm]odal[^"]*_(\d+)"[^>]*>.*?</div>',
                'description': 'Repetitive modal components with numbered IDs',
                'template_base': 'modal_X template',
                'affected_by_existing_templates': True
            },
            'form_elements': {
                'pattern': r'id="[^"]*[Ff]orm[^"]*_(\d+)"[^>]*>.*?</(?:form|div)>',
                'description': 'Repetitive form elements with numbered IDs',
                'template_base': 'form_X template',
                'affected_by_existing_templates': False
            },
            'list_items': {
                'pattern': r'id="[^"]*[Ll]ist[^"]*_(\d+)"[^>]*>.*?</(?:li|ul|ol|div)>',
                'description': 'Repetitive list item structures with numbered IDs',
                'template_base': 'listItem_X template',
                'affected_by_existing_templates': False
            },
            'card_components': {
                'pattern': r'id="[^"]*[Cc]ard[^"]*_(\d+)"[^>]*>.*?</div>',
                'description': 'Repetitive card components with numbered IDs',
                'template_base': 'card_X template',
                'affected_by_existing_templates': False
            },
            'section_blocks': {
                'pattern': r'id="[^"]*[Ss]ection[^"]*_(\d+)"[^>]*>.*?</(?:section|div)>',
                'description': 'Repetitive section blocks with numbered IDs',
                'template_base': 'section_X template',
                'affected_by_existing_templates': False
            },
            'generic_numbered_elements': {
                'pattern': r'id="([a-zA-Z][a-zA-Z0-9_-]*?)_(\d+)"[^>]*>.*?</[^>]+>',
                'description': 'Generic repetitive elements with numbered ID patterns',
                'template_base': 'genericElement_X template',
                'affected_by_existing_templates': True
            }
        }
        
        for pattern_name, pattern_config in numbered_patterns.items():
            # Find all matches and extract the ID numbers
            matches = list(re.finditer(pattern_config['pattern'], content, re.DOTALL))
            
            if len(matches) > 1:
                # Extract ID numbers to confirm they're sequential/numbered
                id_numbers = []
                sample_structures = []
                total_size = 0
                
                for match in matches:
                    id_num = match.group(1)  # The captured number
                    try:
                        id_numbers.append(int(id_num))
                        total_size += len(match.group())
                        if len(sample_structures) < 2:  # Keep first 2 for comparison
                            sample_structures.append(match.group()[:500] + '...' if len(match.group()) > 500 else match.group())
                    except ValueError:
                        # Skip non-numeric matches
                        continue
                
                # Calculate templating potential, accounting for existing deduplication
                if len(matches) >= 3 and len(id_numbers) >= 3:  # Only consider if there are at least 3 valid numeric instances
                    avg_structure_size = total_size // len(matches)
                    template_size_estimate = avg_structure_size + 100  # Template overhead
                    base_potential_savings = total_size - template_size_estimate - (len(matches) * 50)  # 50 bytes per instance
                    
                    # Check if this would impact >1% of file size
                    savings_percentage = (base_potential_savings / file_size) * 100
                    if savings_percentage <= 1.0:
                        continue  # Skip structures that don't have significant impact
                    
                    # Adjust savings based on existing template coverage
                    if pattern_config['affected_by_existing_templates']:
                        # Reduce potential savings because existing templates already handle part of the redundancy
                        coverage_factor = existing_deduplication_coverage / 100
                        actual_remaining_redundancy = base_potential_savings * (1 - coverage_factor)
                        potential_savings = max(0, actual_remaining_redundancy)
                        deduplication_status = f"Partially deduplicated (existing templates cover ~{existing_deduplication_coverage}%)"
                    else:
                        # Full potential savings for structures not covered by existing templates
                        potential_savings = max(0, base_potential_savings)
                        deduplication_status = "Not covered by existing template systems"
                    
                    # Adjust severity based on actual remaining bloat
                    if potential_savings > 100000:  # Increased threshold since we account for existing deduplication
                        severity = 'HIGH'
                    elif potential_savings > 30000:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'
                    
                    repetitive_patterns[pattern_name] = {
                        'count': len(matches),
                        'total_size': total_size,
                        'percentage': (total_size / file_size) * 100,
                        'id_range': f"{min(id_numbers)}-{max(id_numbers)}",
                        'avg_structure_size': avg_structure_size,
                        'raw_potential_savings': max(0, base_potential_savings),
                        'adjusted_potential_savings': potential_savings,
                        'savings_percentage': (potential_savings / file_size) * 100,
                        'description': pattern_config['description'],
                        'template_recommendation': pattern_config['template_base'],
                        'existing_deduplication_status': deduplication_status,
                        'affected_by_existing_templates': pattern_config['affected_by_existing_templates'],
                        'sample_structures': sample_structures,
                        'severity': severity
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

    def _generate_recommendations(self, bloat_sources: Dict, template_opportunities: Dict, repetitive_structures: Dict = None) -> List[Dict[str, Any]]:
        """Generate prioritized optimization recommendations with hierarchy awareness"""
        recommendations = []
        
        # Analyze hierarchy relationships to avoid misleading recommendations
        script_based_patterns = []
        independent_patterns = []
        
        # High-impact recommendations based on bloat analysis
        for pattern_name, analysis in bloat_sources.items():
            if analysis['severity'] in ['CRITICAL', 'HIGH'] and analysis['percentage'] > 1:
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
                
                recommendations.append({
                    'priority': 'HIGH' if analysis['severity'] == 'CRITICAL' else 'MEDIUM',
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
                    priority = 'HIGH' if analysis['severity'] == 'HIGH' else 'MEDIUM'
                    
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

    def _calculate_severity_score(self, bloat_sources: Dict) -> float:
        """
        Calculate severity score (0-100) based on file size impact and optimization potential.
        
        Simple approach: Higher percentages of file bloat = higher severity.
        Accounts for templating/deduplication potential similar to existing systems.
        """
        if not bloat_sources:
            return 0.0
        
        # Sum up all bloat as percentage of file size
        total_bloat_percentage = sum(source['percentage'] for source in bloat_sources.values())
        
        # Simple scaling: direct percentage with slight boost for high-bloat files
        if total_bloat_percentage > 60:
            severity = min(total_bloat_percentage * 1.2, 100)  # High bloat gets small boost
        else:
            severity = total_bloat_percentage
        
        return round(min(severity, 100), 1)

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
                print(f"✓ {file_path.name}: severity {analysis.severity_score:.1f}")
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
        avg_severity = sum(a.severity_score for a in results.values()) / total_files if total_files else 0
        
        report_data['_summary'] = {
            'total_files_analyzed': total_files,
            'total_size_bytes': total_size,
            'average_file_size': total_size // total_files if total_files else 0,
            'average_severity_score': avg_severity,
            'high_severity_files': len([a for a in results.values() if a.severity_score > 50]),
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
            'file1': {'name': file1, 'size': analysis1.total_size, 'severity': analysis1.severity_score},
            'file2': {'name': file2, 'size': analysis2.total_size, 'severity': analysis2.severity_score},
            'size_difference': analysis2.total_size - analysis1.total_size,
            'severity_difference': analysis2.severity_score - analysis1.severity_score,
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
        """Get the files with highest bloat severity scores"""
        sorted_files = sorted(results.items(), key=lambda x: x[1].severity_score, reverse=True)
        return sorted_files[:limit]

    def print_analysis_summary(self, analysis: BloatAnalysis):
        """Print a formatted summary of bloat analysis"""
        file_size_mb = analysis.total_size / (1024 * 1024)
        print(f"\n🔍 Bloat Analysis: {Path(analysis.file_path).name}")
        print(f"📊 File Size: {file_size_mb:.2f} MB ({analysis.total_size:,} bytes, {analysis.line_count:,} lines)")
        print(f"⚠️  Severity Score: {analysis.severity_score:.1f}/100")
        
        print(f"\n📋 Bloat Sources ({len(analysis.bloat_sources)}):")
        # Sort bloat sources by total size (descending order)
        sorted_bloat_sources = sorted(analysis.bloat_sources.items(), 
                                    key=lambda x: x[1]['total_size'], reverse=True)
        
        for pattern_name, source_info in sorted_bloat_sources:
            size_mb = source_info['total_size'] / (1024 * 1024)
            print(f"  • {pattern_name.replace('_', ' ').title()}: "
                  f"{size_mb:.2f} MB ({source_info['percentage']:.1f}% of file) "
                  f"[{source_info['severity']}]")
        
        print(f"\n🔄 Template Opportunities ({len(analysis.template_opportunities)}):")
        for template_type, template_info in analysis.template_opportunities.items():
            size_mb = template_info['total_size'] / (1024 * 1024)
            savings_mb = template_info['deduplication_savings'] / (1024 * 1024)
            print(f"  • {template_type.replace('_', ' ').title()}: "
                  f"{template_info['count']} instances, {size_mb:.2f} MB total, "
                  f"{savings_mb:.2f} MB potential savings ({template_info['percentage']:.1f}% of file)")
        
        # NEW: Show repetitive structures with adjusted calculations (only significant ones)
        if hasattr(analysis, 'repetitive_structures') and analysis.repetitive_structures:
            print(f"\n🔄 Repetitive Container Structures (Accounting for Existing Templates):")
            total_adjusted_savings = 0
            for structure_name, struct_info in analysis.repetitive_structures.items():
                if struct_info['adjusted_potential_savings'] > 5000 and struct_info['savings_percentage'] > 1.0:  # Only show >1% impact
                    status_icon = "⚠️" if struct_info['affected_by_existing_templates'] else "🆕"
                    total_size_mb = struct_info['total_size'] / (1024 * 1024)
                    savings_mb = struct_info['adjusted_potential_savings'] / (1024 * 1024)
                    print(f"  {status_icon} {structure_name.replace('_', ' ').title()}: "
                          f"{struct_info['count']} containers, {total_size_mb:.2f} MB total, "
                          f"{savings_mb:.2f} MB realistic savings ({struct_info['savings_percentage']:.1f}% of file)")
                    if struct_info['affected_by_existing_templates']:
                        print(f"     └─ {struct_info['existing_deduplication_status']}")
                    total_adjusted_savings += struct_info['adjusted_potential_savings']
            
            if total_adjusted_savings > 0:
                total_savings_mb = total_adjusted_savings / (1024 * 1024)
                total_percentage = (total_adjusted_savings / analysis.total_size) * 100
                print(f"\n  📊 Total Realistic Container Template Savings: "
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
        avg_severity = sum(a.severity_score for a in results.values()) / len(results) if results else 0
        print(f"Average severity: {avg_severity:.1f}")
        
        # Show top bloated files
        if results:
            top_files = framework.get_top_bloat_files(results, args.top)
            print(f"\n🔥 Top {len(top_files)} Most Bloated Files:")
            for i, (filename, analysis) in enumerate(top_files, 1):
                file_size_mb = analysis.total_size / (1024 * 1024)
                print(f"{i:2d}. {filename}: {file_size_mb:.2f} MB, "
                      f"severity {analysis.severity_score:.1f}")
    
    elif args.compare:
        # Compare two files
        comparison = framework.compare_files(args.compare[0], args.compare[1])
        print(f"\n📊 File Comparison:")
        print(f"File 1: {comparison['file1']['name']} - {comparison['file1']['size']:,} bytes")
        print(f"File 2: {comparison['file2']['name']} - {comparison['file2']['size']:,} bytes")
        print(f"Size difference: {comparison['size_difference']:+,} bytes")
        print(f"Severity difference: {comparison['severity_difference']:+.1f}")
    
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
