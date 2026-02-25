#!/usr/bin/env python3
"""
CPE Format Conversion Test Suite

Tests the formatFor23CPE() function and related CPE string construction logic
to ensure proper handling of edge cases in vendor/product name conversion.

Critical test cases:
- Whitespace normalization (tabs, newlines, multiple spaces)
- Special character removal (colons, asterisks)
- CPE escaping for allowed special characters
- Non-ASCII character normalization
- Leading/trailing whitespace handling

Test Pattern:
    Each test validates a specific edge case or combination of edge cases
    to ensure the CPE format is NVD API compatible.

Outputs standardized test results: TEST_RESULTS: PASSED=X TOTAL=Y SUITE="Name"

Usage:
    python test_suites/tool_infrastructure/test_cpe_format_conversion.py
"""

import sys
import os
from pathlib import Path

# Force UTF-8 output encoding for Windows compatibility
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from analysis_tool.core.processData import formatFor23CPE

class CPEFormatConversionTestSuite:
    """Test suite for CPE format conversion edge cases."""
    
    def __init__(self):
        self.passed = 0
        self.total = 20
        
    def test_tab_character_normalization(self) -> bool:
        """Test that tab characters are normalized to single underscores."""
        print("\n=== Test 1: Tab Character Normalization ===")
        
        test_cases = [
            {
                "input": "Select Graphist\tGraphist",
                "expected": "select_graphist_graphist",
                "description": "Single tab between words"
            },
            {
                "input": "Product\t\tName",
                "expected": "product_name",
                "description": "Multiple consecutive tabs"
            },
            {
                "input": "\tLeading Tab",
                "expected": "leading_tab",
                "description": "Leading tab (should be stripped)"
            },
            {
                "input": "Trailing Tab\t",
                "expected": "trailing_tab",
                "description": "Trailing tab (should be stripped)"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All tab character normalization tests passed ({len(test_cases)} cases)")
        return True
    
    def test_newline_character_normalization(self) -> bool:
        """Test that newline characters are normalized to single underscores."""
        print("\n=== Test 2: Newline Character Normalization ===")
        
        test_cases = [
            {
                "input": "Line1\nLine2",
                "expected": "line1_line2",
                "description": "Unix newline (\\n)"
            },
            {
                "input": "Line1\r\nLine2",
                "expected": "line1_line2",
                "description": "Windows newline (\\r\\n)"
            },
            {
                "input": "Line1\rLine2",
                "expected": "line1_line2",
                "description": "Mac classic newline (\\r)"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All newline normalization tests passed ({len(test_cases)} cases)")
        return True
    
    def test_multiple_space_collapse(self) -> bool:
        """Test that multiple consecutive spaces collapse to single underscore."""
        print("\n=== Test 3: Multiple Space Collapse ===")
        
        test_cases = [
            {
                "input": "Product  Name",
                "expected": "product_name",
                "description": "Two consecutive spaces"
            },
            {
                "input": "Product   Name",
                "expected": "product_name",
                "description": "Three consecutive spaces"
            },
            {
                "input": "Product        Name",
                "expected": "product_name",
                "description": "Many consecutive spaces"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All multiple space collapse tests passed ({len(test_cases)} cases)")
        return True
    
    def test_mixed_whitespace_normalization(self) -> bool:
        """Test mixed whitespace (spaces, tabs, newlines) normalization."""
        print("\n=== Test 4: Mixed Whitespace Normalization ===")
        
        test_cases = [
            {
                "input": "Product \t Name",
                "expected": "product_name",
                "description": "Space + tab + space"
            },
            {
                "input": "Product\n \t\nName",
                "expected": "product_name",
                "description": "Newline + space + tab + newline"
            },
            {
                "input": "Word1 \t \n \r Word2",
                "expected": "word1_word2",
                "description": "Mixed whitespace between words"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All mixed whitespace normalization tests passed ({len(test_cases)} cases)")
        return True
    
    def test_leading_trailing_whitespace_removal(self) -> bool:
        """Test that leading and trailing whitespace is removed."""
        print("\n=== Test 5: Leading/Trailing Whitespace Removal ===")
        
        test_cases = [
            {
                "input": "  Leading Spaces",
                "expected": "leading_spaces",
                "description": "Leading spaces"
            },
            {
                "input": "Trailing Spaces  ",
                "expected": "trailing_spaces",
                "description": "Trailing spaces"
            },
            {
                "input": "  Both Sides  ",
                "expected": "both_sides",
                "description": "Leading and trailing spaces"
            },
            {
                "input": "\t\tLeading Tabs",
                "expected": "leading_tabs",
                "description": "Leading tabs"
            },
            {
                "input": "Trailing Tabs\t\t",
                "expected": "trailing_tabs",
                "description": "Trailing tabs"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All leading/trailing whitespace removal tests passed ({len(test_cases)} cases)")
        return True
    
    def test_colon_removal(self) -> bool:
        """Test that colons (CPE field delimiters) are removed."""
        print("\n=== Test 6: Colon Removal ===")
        
        test_cases = [
            {
                "input": "Vendor: Name",
                "expected": "vendor_name",
                "description": "Colon as separator"
            },
            {
                "input": "Product:Name:Version",
                "expected": "productnameversion",
                "description": "Multiple colons"
            },
            {
                "input": ":Leading Colon",
                "expected": "leading_colon",
                "description": "Leading colon"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All colon removal tests passed ({len(test_cases)} cases)")
        return True
    
    def test_asterisk_removal(self) -> bool:
        """Test that asterisks (CPE wildcards) are removed."""
        print("\n=== Test 7: Asterisk Removal ===")
        
        test_cases = [
            {
                "input": "Product*Name",
                "expected": "productname",
                "description": "Internal asterisk"
            },
            {
                "input": "*Product",
                "expected": "product",
                "description": "Leading asterisk"
            },
            {
                "input": "Product*",
                "expected": "product",
                "description": "Trailing asterisk"
            },
            {
                "input": "***Product***",
                "expected": "product",
                "description": "Multiple asterisks"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All asterisk removal tests passed ({len(test_cases)} cases)")
        return True
    
    def test_standard_space_conversion(self) -> bool:
        """Test standard space to underscore conversion."""
        print("\n=== Test 8: Standard Space Conversion ===")
        
        test_cases = [
            {
                "input": "Simple Product Name",
                "expected": "simple_product_name",
                "description": "Multiple words with single spaces"
            },
            {
                "input": "A B C D E",
                "expected": "a_b_c_d_e",
                "description": "Single letter words"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All standard space conversion tests passed ({len(test_cases)} cases)")
        return True
    
    def test_lowercase_conversion(self) -> bool:
        """Test that input is converted to lowercase."""
        print("\n=== Test 9: Lowercase Conversion ===")
        
        test_cases = [
            {
                "input": "UPPERCASE",
                "expected": "uppercase",
                "description": "All uppercase"
            },
            {
                "input": "MixedCase",
                "expected": "mixedcase",
                "description": "Mixed case"
            },
            {
                "input": "Product NAME",
                "expected": "product_name",
                "description": "Mixed case with spaces"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All lowercase conversion tests passed ({len(test_cases)} cases)")
        return True
    
    def test_special_character_escaping(self) -> bool:
        """Test CPE special character escaping."""
        print("\n=== Test 10: Special Character Escaping ===")
        
        test_cases = [
            {
                "input": "Product/Name",
                "expected": "product\\/name",
                "description": "Forward slash escaping"
            },
            {
                "input": "Product(Name)",
                "expected": "product\\(name\\)",
                "description": "Parentheses escaping"
            },
            {
                "input": "Product+Name",
                "expected": "product\\+name",
                "description": "Plus sign escaping"
            },
            {
                "input": "Product,Name",
                "expected": "product\\,name",
                "description": "Comma escaping"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All special character escaping tests passed ({len(test_cases)} cases)")
        return True
    
    def test_backslash_escaping(self) -> bool:
        """Test backslash escaping (must be doubled)."""
        print("\n=== Test 11: Backslash Escaping ===")
        
        test_cases = [
            {
                "input": "Product\\Name",
                "expected": "product\\\\name",
                "description": "Single backslash"
            },
            {
                "input": "Path\\To\\Product",
                "expected": "path\\\\to\\\\product",
                "description": "Multiple backslashes"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All backslash escaping tests passed ({len(test_cases)} cases)")
        return True
    
    def test_unicode_normalization(self) -> bool:
        """Test Unicode to ASCII normalization."""
        print("\n=== Test 12: Unicode Normalization ===")
        
        test_cases = [
            {
                "input": "Café",
                "expected": "cafe",
                "description": "Accented character (é → e)"
            },
            {
                "input": "Naïve",
                "expected": "naive",
                "description": "Diaeresis (ï → i)"
            },
            {
                "input": "Über",
                "expected": "uber",
                "description": "Umlaut (Ü → U)"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All Unicode normalization tests passed ({len(test_cases)} cases)")
        return True
    
    def test_real_world_cve_case(self) -> bool:
        """Test real-world CVE case from CVE-2025-66160."""
        print("\n=== Test 13: Real-World CVE Case (CVE-2025-66160) ===")
        
        # Actual product name from CVE-2025-66160
        input_str = "Select Graphist for Elementor\t Graphist for Elementor"
        expected = "select_graphist_for_elementor_graphist_for_elementor"
        
        result = formatFor23CPE(input_str)
        if result != expected:
            print(f"❌ FAIL: CVE-2025-66160 product name conversion")
            print(f"  Input: {repr(input_str)}")
            print(f"  Expected: {expected}")
            print(f"  Got: {result}")
            return False
        
        print(f"✅ PASS: Real-world CVE case handled correctly")
        print(f"  ✓ Tab character normalized to single underscore")
        print(f"  ✓ No double underscores created")
        return True
    
    def test_empty_and_whitespace_only_strings(self) -> bool:
        """Test edge cases with empty or whitespace-only strings.
        
        Updated behavior: Empty results after character removal return '*' to prevent
        consecutive asterisks in CPE strings (e.g., cpe:2.3:*:**:...).
        """
        print("\n=== Test 14: Empty and Whitespace-Only Strings ===")
        
        test_cases = [
            {
                "input": "",
                "expected": "*",
                "description": "Empty string (returns wildcard)"
            },
            {
                "input": "   ",
                "expected": "*",
                "description": "Spaces only (returns wildcard)"
            },
            {
                "input": "\t\t\t",
                "expected": "*",
                "description": "Tabs only (returns wildcard)"
            },
            {
                "input": " \t \n ",
                "expected": "*",
                "description": "Mixed whitespace only (returns wildcard)"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {repr(test_case['expected'])}")
                print(f"  Got: {repr(result)}")
                return False
        
        print(f"✅ PASS: All empty/whitespace-only string tests passed ({len(test_cases)} cases)")
        return True
    
    def test_combined_edge_cases(self) -> bool:
        """Test combinations of multiple edge cases."""
        print("\n=== Test 15: Combined Edge Cases ===")
        
        test_cases = [
            {
                "input": "  Product™: Name\t\twith *Special*   Chars  ",
                "expected": "producttm_name_with_special_chars",
                "description": "Whitespace + symbols + asterisks + colons + trademark (™→tm)"
            },
            {
                "input": "UPPERCASE  \tMIXED\nWHITESPACE",
                "expected": "uppercase_mixed_whitespace",
                "description": "Case + multiple whitespace types"
            },
            {
                "input": " \tVendor/Product\\Name (v1.0)+ ",
                "expected": "vendor\\/product\\\\name_\\(v1.0\\)\\+",
                "description": "Leading/trailing whitespace + special chars + escaping"
            }
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {test_case['expected']}")
                print(f"  Got: {result}")
                return False
        
        print(f"✅ PASS: All combined edge case tests passed ({len(test_cases)} cases)")
        return True
    
    def test_all_cpe_special_characters(self) -> bool:
        """Test all CPE 2.3 special characters that should be escaped."""
        print("\n=== Test 16: All CPE Special Characters ===\n")
        
        # Complete list from cpeEscape dictionary in formatFor23CPE()
        test_cases = [
            {"char": "!", "expected": "\\!", "description": "Exclamation mark"},
            {"char": '"', "expected": '\\"', "description": "Double quote"},
            {"char": "#", "expected": "\\#", "description": "Hash/pound"},
            {"char": "$", "expected": "\\$", "description": "Dollar sign"},
            {"char": "%", "expected": "%", "description": "Percent sign (NOT in cpeEscape - check if handled)"},
            {"char": "&", "expected": "\\&", "description": "Ampersand"},
            {"char": "'", "expected": "\\'", "description": "Single quote"},
            {"char": "(", "expected": "\\(", "description": "Left parenthesis"},
            {"char": ")", "expected": "\\)", "description": "Right parenthesis"},
            {"char": "+", "expected": "\\+", "description": "Plus sign"},
            {"char": ",", "expected": "\\,", "description": "Comma"},
            {"char": "/", "expected": "\\/", "description": "Forward slash"},
            {"char": ";", "expected": "\\;", "description": "Semicolon"},
            {"char": "<", "expected": "\\<", "description": "Less than"},
            {"char": "=", "expected": "\\=", "description": "Equals"},
            {"char": ">", "expected": "\\>", "description": "Greater than"},
            {"char": "?", "expected": "\\?", "description": "Question mark"},
            {"char": "@", "expected": "\\@", "description": "At symbol"},
            {"char": "[", "expected": "\\[", "description": "Left bracket"},
            {"char": "\\", "expected": "\\\\", "description": "Backslash"},
            {"char": "]", "expected": "\\]", "description": "Right bracket"},
            {"char": "^", "expected": "\\^", "description": "Caret"},
            {"char": "`", "expected": "\\`", "description": "Backtick"},
            {"char": "{", "expected": "\\{", "description": "Left brace"},
            {"char": "|", "expected": "\\|", "description": "Pipe"},
            {"char": "}", "expected": "\\}", "description": "Right brace"},
            {"char": "~", "expected": "\\~", "description": "Tilde"},
        ]
        
        failures = []
        for test_case in test_cases:
            result = formatFor23CPE(test_case['char'])
            if result != test_case['expected']:
                failures.append({
                    "char": test_case['char'],
                    "description": test_case['description'],
                    "expected": test_case['expected'],
                    "got": result
                })
        
        if failures:
            print(f"❌ FAIL: {len(failures)} special character(s) not handled correctly:")
            for failure in failures:
                print(f"  {failure['description']} ({repr(failure['char'])}):")
                print(f"    Expected: {repr(failure['expected'])}")
                print(f"    Got: {repr(failure['got'])}")
            return False
        
        print(f"✅ PASS: All CPE special characters handled correctly ({len(test_cases)} chars)")
        print(f"  ✓ All required characters properly escaped")
        print(f"  ✓ Includes all chars from CPE 2.3 specification")
        return True
    
    def test_none_and_null_inputs(self) -> bool:
        """Test handling of None and various null-like inputs.
        
        Updated behavior: Empty string returns '*' to prevent consecutive asterisks.
        """
        print("\n=== Test 17: None and Null-like Inputs ===\n")
        
        # Note: formatFor23CPE() expects string input, but we should verify behavior
        test_cases = []
        
        # Test empty-like string values (actual use cases)
        string_test_cases = [
            {"input": "", "expected": "*", "description": "Empty string (returns wildcard)"},
            {"input": "null", "expected": "null", "description": "String literal 'null'"},
            {"input": "None", "expected": "none", "description": "String literal 'None'"},
            {"input": "N/A", "expected": "n\\/a", "description": "String literal 'N/A'"},
            {"input": "unknown", "expected": "unknown", "description": "String literal 'unknown'"},
        ]
        
        for test_case in string_test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {repr(test_case['expected'])}")
                print(f"  Got: {repr(result)}")
                return False
        
        print(f"✅ PASS: All null-like string inputs handled correctly ({len(string_test_cases)} cases)")
        print(f"  ✓ Empty strings return wildcard '*' (prevents consecutive asterisks)")
        print(f"  ✓ String literals 'null'/'None' converted properly")
        return True
    
    def test_consecutive_special_characters(self) -> bool:
        """Test handling of consecutive and mixed special characters."""
        print("\n=== Test 18: Consecutive Special Characters ===\n")
        
        test_cases = [
            {
                "input": "Product//Name",
                "expected": "product\\/\\/name",
                "description": "Consecutive forward slashes"
            },
            {
                "input": "Product((Name))",
                "expected": "product\\(\\(name\\)\\)",
                "description": "Nested parentheses"
            },
            {
                "input": "Product+++Name",
                "expected": "product\\+\\+\\+name",
                "description": "Multiple plus signs"
            },
            {
                "input": "!@#$%^&*()",
                "expected": "\\!\\@\\#\\$%\\^\\&\\(\\)",
                "description": "All special chars together (note: % not escaped, * removed)"
            },
            {
                "input": "<<<>>>===",
                "expected": "\\<\\<\\<\\>\\>\\>\\=\\=\\=",
                "description": "Consecutive comparison operators"
            },
            {
                "input": "Path\\\\Server",
                "expected": "path\\\\\\\\server",
                "description": "Multiple backslashes (each doubled)"
            },
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {repr(test_case['expected'])}")
                print(f"  Got: {repr(result)}")
                return False
        
        print(f"✅ PASS: All consecutive special character tests passed ({len(test_cases)} cases)")
        print(f"  ✓ Consecutive characters properly escaped")
        print(f"  ✓ No incorrect collapsing or merging")
        return True
    
    def test_percent_sign_handling(self) -> bool:
        """Test percent sign handling - NOT in cpeEscape dict."""
        print("\n=== Test 19: Percent Sign Edge Case ===\n")
        
        # Percent sign is NOT in the cpeEscape dictionary
        # This test verifies current behavior and documents expectations
        test_cases = [
            {
                "input": "Product%Name",
                "expected": "product%name",
                "description": "Percent sign in middle (NOT escaped)"
            },
            {
                "input": "100%",
                "expected": "100%",
                "description": "Percent sign at end (NOT escaped)"
            },
            {
                "input": "%percent%",
                "expected": "%percent%",
                "description": "Multiple percent signs (NOT escaped)"
            },
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"⚠️  WARNING: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {repr(test_case['expected'])}")
                print(f"  Got: {repr(result)}")
                print(f"  Note: Percent signs are NOT in cpeEscape dict - may need to be added")
                return False
        
        print(f"✅ PASS: Percent sign behavior documented ({len(test_cases)} cases)")
        print(f"  ℹ️  Note: % is NOT escaped (not in CPE 2.3 cpeEscape dictionary)")
        print(f"  ℹ️  This is current expected behavior - verify against NVD API requirements")
        return True
    
    def test_empty_string_after_character_removal(self) -> bool:
        """Test that formatFor23CPE returns wildcard '*' for inputs that become empty after character removal.
        
        This prevents consecutive asterisks in CPE strings like cpe:2.3:*:**:*:*:*:*:*:*:*:*:*
        which cause NVD API 404 errors.
        
        Bug Fix Context:
        - formatFor23CPE removes asterisks and colons to prevent CPE format corruption
        - If input contains ONLY those characters, result would be empty
        - constructSearchString wraps product with wildcards: "*" + "" + "*" = "**"
        - Fix: Return "*" for empty results to maintain valid CPE structure
        """
        print("\n=== Test 20: Empty String After Character Removal ===")
        
        test_cases = [
            {
                "input": "*",
                "expected": "*",
                "description": "Single asterisk (becomes empty, return wildcard)"
            },
            {
                "input": "**",
                "expected": "*",
                "description": "Double asterisk (becomes empty, return wildcard)"
            },
            {
                "input": "***",
                "expected": "*",
                "description": "Triple asterisk (becomes empty, return wildcard)"
            },
            {
                "input": ":",
                "expected": "*",
                "description": "Single colon (becomes empty, return wildcard)"
            },
            {
                "input": "::",
                "expected": "*",
                "description": "Double colon (becomes empty, return wildcard)"
            },
            {
                "input": "*:*",
                "expected": "*",
                "description": "Mixed asterisks and colons (becomes empty, return wildcard)"
            },
            {
                "input": "   ",
                "expected": "*",
                "description": "Whitespace only (stripped to empty, return wildcard)"
            },
            {
                "input": "* * *",
                "expected": "*",
                "description": "Asterisks with spaces (becomes empty, return wildcard)"
            },
            {
                "input": ":*:",
                "expected": "*",
                "description": "Colon-asterisk-colon (becomes empty, return wildcard)"
            },
        ]
        
        for test_case in test_cases:
            result = formatFor23CPE(test_case['input'])
            if result != test_case['expected']:
                print(f"❌ FAIL: {test_case['description']}")
                print(f"  Input: {repr(test_case['input'])}")
                print(f"  Expected: {repr(test_case['expected'])}")
                print(f"  Got: {repr(result)}")
                print(f"  ⚠️  This would cause consecutive asterisks in CPE strings!")
                return False
        
        print(f"✅ PASS: All empty string handling tests passed ({len(test_cases)} cases)")
        print(f"  ✓ Empty results after character removal return wildcard '*'")
        print(f"  ✓ Prevents consecutive asterisk bug (cpe:2.3:*:**:...)")
        print(f"  ✓ Maintains valid CPE structure for NVD API compatibility")
        return True
    
    def run_all_tests(self) -> bool:
        """Run all CPE format conversion tests."""
        print("="*70)
        print("CPE Format Conversion Test Suite")
        print("Tests formatFor23CPE() and CPE string construction")
        print("="*70)
        
        tests = [
            ("Tab Character Normalization", self.test_tab_character_normalization),
            ("Newline Character Normalization", self.test_newline_character_normalization),
            ("Multiple Space Collapse", self.test_multiple_space_collapse),
            ("Mixed Whitespace Normalization", self.test_mixed_whitespace_normalization),
            ("Leading/Trailing Whitespace Removal", self.test_leading_trailing_whitespace_removal),
            ("Colon Removal", self.test_colon_removal),
            ("Asterisk Removal", self.test_asterisk_removal),
            ("Standard Space Conversion", self.test_standard_space_conversion),
            ("Lowercase Conversion", self.test_lowercase_conversion),
            ("Special Character Escaping", self.test_special_character_escaping),
            ("Backslash Escaping", self.test_backslash_escaping),
            ("Unicode Normalization", self.test_unicode_normalization),
            ("Real-World CVE Case", self.test_real_world_cve_case),
            ("Empty/Whitespace-Only Strings", self.test_empty_and_whitespace_only_strings),
            ("Combined Edge Cases", self.test_combined_edge_cases),
            ("All CPE Special Characters", self.test_all_cpe_special_characters),
            ("None and Null-like Inputs", self.test_none_and_null_inputs),
            ("Consecutive Special Characters", self.test_consecutive_special_characters),
            ("Percent Sign Edge Case", self.test_percent_sign_handling),
            ("Empty String After Character Removal", self.test_empty_string_after_character_removal),
        ]
        
        passed = 0
        failed = 0
        
        for test_name, test_func in tests:
            try:
                if test_func():
                    passed += 1
                    print(f"Progress: {passed}/{self.total} tests passed")
                else:
                    failed += 1
                    print(f"Progress: {passed}/{self.total} tests passed ({failed} failed)")
            except Exception as e:
                failed += 1
                print(f"\n❌ FAIL: {test_name}")
                print(f"  Exception: {e}")
                import traceback
                traceback.print_exc()
                print(f"Progress: {passed}/{self.total} tests passed ({failed} failed)")
        
        print("\n" + "="*70)
        if failed == 0:
            print(f"SUCCESS: All CPE format conversion tests passed!")
        else:
            print(f"FAILURE: {failed} test(s) failed")
        print(f"TEST_RESULTS: PASSED={passed} TOTAL={self.total} SUITE=\"CPE Format Conversion\"")
        print("="*70)
        
        return failed == 0

def main():
    """Main test runner."""
    test_suite = CPEFormatConversionTestSuite()
    success = test_suite.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
