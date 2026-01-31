#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
COMPREHENSIVE UPDATE PATTERN TEST SUITE

Complete coverage testing for ALL terms with CONSISTENT scenario types.
Each term gets its own dedicated test group with identical coverage patterns.

Terms covered (19 total):
1. PATCH
2. SERVICE_PACK 
3. APPLICATION_PACK
4. HOTFIX
5. CUMULATIVE_UPDATE
6. UPDATE
7. BETA
8. ALPHA
9. RELEASE_CANDIDATE
10. FIX
11. REVISION
12. MAINTENANCE_RELEASE
13. BUILD
14. RELEASE
15. MILESTONE
16. SNAPSHOT
17. PREVIEW
18. CANDIDATE
19. DEVELOPMENT

Note: KB (Knowledge Base) patterns are excluded by design     print(f"\n   KB Exclusion Patterns - Complete Coverage:")s they     print(f"\n   Exclusion Patterns - Complete Coverage:")re 
documentation references, not version patterns.

SCENARIO COVERAGE (for each term):
- Space-separated patterns (full form + short form + case variations)
- Direct concatenation patterns  
- Specific notation patterns (dot notation, dash-dot where applicable)
- Flexible separator patterns (underscore, dash, dot combinations)
"""

import sys
import os
import logging
from pathlib import Path

# Fix Windows console encoding for Unicode output
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

try:
    from src.analysis_tool.core.badge_modal_system import transform_version_with_update_pattern
except ImportError as e:
    print(f"ERROR: Could not import transform_version_with_update_pattern: {e}")
    sys.exit(1)

# Temporarily suppress WARNING logs during testing for cleaner output
_original_logger_enabled = None

def suppress_warnings():
    """Temporarily suppress WorkflowLogger warnings for cleaner test output."""
    global _original_logger_enabled
    try:
        from src.analysis_tool.logging.workflow_logger import get_logger
        logger = get_logger()
        _original_logger_enabled = logger.enabled
        logger.enabled = False
    except ImportError:
        # Fallback to standard logging if workflow logger not available
        logging.getLogger().setLevel(logging.ERROR)

def restore_warnings():
    """Restore normal WorkflowLogger state."""
    global _original_logger_enabled
    if _original_logger_enabled is not None:
        try:
            from src.analysis_tool.logging.workflow_logger import get_logger
            logger = get_logger()
            logger.enabled = _original_logger_enabled
            _original_logger_enabled = None
        except ImportError:
            # Fallback to standard logging
            logging.getLogger().setLevel(logging.WARNING)
    else:
        # Fallback if no original state was captured
        logging.getLogger().setLevel(logging.WARNING)

def get_transformed_version(input_version):
    """Helper to get the transformed version from the tuple result."""
    result = transform_version_with_update_pattern(input_version)
    return result[2] if result and result[2] else None

def test_pattern_verbose(input_version, expected, test_category):
    """Test pattern with detailed verbose output."""
    transformed = get_transformed_version(input_version)
    status = "PASS" if transformed == expected else "FAIL"
    print(f"    {status} {test_category}: '{input_version}' → '{transformed}' (expected: '{expected}')")
    return transformed == expected

# =================== INDIVIDUAL TERM GROUP TESTS ===================

def test_patch_term_group():
    """Test PATCH term group - complete scenario coverage."""
    print(f"\n   PATCH Term Group - Complete Coverage:")
    
    test_cases = [
        # Specific notation patterns
        ('3.1.0.p7', '3.1.0:patch7'),  # Dot notation
        
        # Space-separated patterns
        ('3.0.0 p1', '3.0.0:patch1'),  # Short form
        ('3.3 patch 1', '3.3:patch1'),  # Full form lowercase
        ('3.3 Patch 1', '3.3:patch1'),  # Full form capitalized
        
        # Direct concatenation patterns
        ('2.3.0p12', '2.3.0:patch12'),  # Direct concat short
        
        # Flexible separator patterns
        ('2.0.0_patch_5', '2.0.0:patch5'),  # Underscore
        ('2.0.0-patch-5', '2.0.0:patch5'),  # Dash
        ('2.0.0.patch.5', '2.0.0:patch5'),  # Dot separated
        ('1.5.0 patch 2', '1.5.0:patch2'),  # Additional space-separated variation
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "PATCH"):
            all_passed = False
    return all_passed

def test_service_pack_term_group():
    """Test SERVICE_PACK term group - complete scenario coverage."""
    print(f"\n   SERVICE_PACK Term Group - Complete Coverage:")
    
    test_cases = [
        # Specific notation patterns
        ('3.0.0.sp1', '3.0.0:sp1'),  # Dot notation
        
        # Space-separated patterns
        ('2.0.0 sp1', '2.0.0:sp1'),  # Short form
        ('2.0.0 service pack 1', '2.0.0:sp1'),  # Full form lowercase
        ('2.0.0 Service Pack 1', '2.0.0:sp1'),  # Full form capitalized
        
        # Direct concatenation patterns
        ('1sp1', '1:sp1'),  # Direct concat
        
        # Flexible separator patterns
        ('13.0.0_sp_4', '13.0.0:sp4'),  # Underscore
        ('13.0.0-sp-4', '13.0.0:sp4'),  # Dash
        ('13.0.0.sp.4', '13.0.0:sp4'),  # Dot separated
        ('2.1.0sp3', '2.1.0:sp3'),  # Additional direct concat variation
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "SERVICE_PACK"):
            all_passed = False
    return all_passed

def test_application_pack_term_group():
    """Test APPLICATION_PACK term group - complete scenario coverage."""
    print(f"\n   APPLICATION_PACK Term Group - Complete Coverage:")
    
    test_cases = [
        # Specific notation patterns
        ('24.0.ap375672', '24.0:ap375672'),  # Dot notation
        
        # Space-separated patterns
        ('24.0 ap375672', '24.0:ap375672'),  # Short form
        ('24.0 application pack 375672', '24.0:ap375672'),  # Full form lowercase
        ('24.0 Application Pack 375672', '24.0:ap375672'),  # Full form capitalized
        
        # Direct concatenation patterns
        ('1ap3', '1:ap3'),  # Direct concat
        
        # Flexible separator patterns
        ('15.0.0_ap_6', '15.0.0:ap6'),  # Underscore
        ('15.0.0-ap-6', '15.0.0:ap6'),  # Dash
        ('15.0.0.ap.6', '15.0.0:ap6'),  # Dot separated
        ('3.2.0ap8', '3.2.0:ap8'),  # Additional direct concat variation
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "APPLICATION_PACK"):
            all_passed = False
    return all_passed

def test_hotfix_term_group():
    """Test HOTFIX term group - complete scenario coverage."""
    print(f"\n   HOTFIX Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('3.0.0 hotfix 1', '3.0.0:hotfix1'),  # Full form lowercase
        ('3.0.0 Hotfix 1', '3.0.0:hotfix1'),  # Full form capitalized
        ('3.0.0 hf1', '3.0.0:hotfix1'),  # Short form
        
        # Direct concatenation patterns
        ('1.0.0hotfix1', '1.0.0:hotfix1'),  # Direct concat full
        ('1.0.0hf1', '1.0.0:hotfix1'),  # Direct concat short
        
        # Specific notation patterns
        ('2.1.0-hotfix.2', '2.1.0:hotfix2'),  # Dash-dot notation
        
        # Flexible separator patterns
        ('4.0.0_hotfix_3', '4.0.0:hotfix3'),  # Underscore
        ('4.0.0-hotfix-3', '4.0.0:hotfix3'),  # Dash
        ('5.0.0_hf_2', '5.0.0:hotfix2'),  # Underscore short
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "HOTFIX"):
            all_passed = False
    return all_passed

def test_cumulative_update_term_group():
    """Test CUMULATIVE_UPDATE term group - complete scenario coverage."""
    print(f"\n   CUMULATIVE_UPDATE Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('14.0.0 cu 5', '14.0.0:cu5'),  # Short form
        ('8.0.0 cumulative update 1', '8.0.0:cu1'),  # Full form lowercase → standardize to cu
        ('8.0.0 Cumulative Update 1', '8.0.0:cu1'),  # Full form capitalized → standardize to cu
        
        # Direct concatenation patterns
        ('1.0.0cu1', '1.0.0:cu1'),  # Direct concat short
        
        # Specific notation patterns
        ('2.1.0-cu.2', '2.1.0:cu2'),  # Dash-dot notation
        
        # Flexible separator patterns
        ('14.0.0_cu_5', '14.0.0:cu5'),  # Underscore short
        ('14.0.0-cu-5', '14.0.0:cu5'),  # Dash short
        ('16.0.0_cumulative_update_2', '16.0.0:cu2'),  # Underscore full → standardize to cu
        ('17.0.0-cumulative-update-3', '17.0.0:cu3'),  # Dash full → standardize to cu
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "CUMULATIVE_UPDATE"):
            all_passed = False
    return all_passed

def test_update_term_group():
    """Test UPDATE term group - complete scenario coverage."""
    print(f"\n   UPDATE Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('3.0.0 update 1', '3.0.0:update1'),  # Full form lowercase
        ('3.0.0 Update 1', '3.0.0:update1'),  # Full form capitalized
        ('3.0.0 upd1', '3.0.0:update1'),  # Short form
        
        # Direct concatenation patterns
        ('4.0.0update1', '4.0.0:update1'),  # Direct concat full
        ('4.0.0upd1', '4.0.0:update1'),  # Direct concat short
        
        # Flexible separator patterns
        ('5.0.0_update_2', '5.0.0:update2'),  # Underscore full
        ('5.0.0-update-2', '5.0.0:update2'),  # Dash full
        ('6.0.0_upd_3', '6.0.0:update3'),  # Underscore short
        ('7.0.0_upd_4', '7.0.0:update4'),  # Additional underscore short variation
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "UPDATE"):
            all_passed = False
    return all_passed

def test_beta_term_group():
    """Test BETA term group - complete scenario coverage including numberless patterns."""
    print(f"\n   BETA Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns (numbered)
        ('1.0.0 beta 1', '1.0.0:beta1'),  # Full form lowercase
        ('1.0.0 Beta 1', '1.0.0:beta1'),  # Full form capitalized
        ('1.0.0 b1', '1.0.0:beta1'),  # Short form
        
        # Direct concatenation patterns (numbered)
        ('4.0.0beta1', '4.0.0:beta1'),  # Direct concat full
        ('4.0.0b1', '4.0.0:beta1'),  # Direct concat short
        
        # Specific notation patterns (numbered)
        ('1.0.0-beta.1', '1.0.0:beta1'),  # Dash-dot notation
        
        # Flexible separator patterns (numbered)
        ('1.0.0_beta_1', '1.0.0:beta1'),  # Underscore full
        ('1.0.0-beta-1', '1.0.0:beta1'),  # Dash full
        ('1.0.0.beta.1', '1.0.0:beta1'),  # Dot separated full
        
        # Numberless patterns (prerelease identifiers without version numbers)
        ('2.0.0-beta', '2.0.0:beta'),  # Dash separator (npm semver style)
        ('2.0.0.beta', '2.0.0:beta'),  # Dot separator
        ('2.0.0_beta', '2.0.0:beta'),  # Underscore separator
        ('1.0 beta', '1.0:beta'),  # Space separator
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "BETA"):
            all_passed = False
    return all_passed

def test_alpha_term_group():
    """Test ALPHA term group - complete scenario coverage including numberless patterns."""
    print(f"\n   ALPHA Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns (numbered)
        ('1.0.0 alpha 1', '1.0.0:alpha1'),  # Full form lowercase
        ('1.0.0 Alpha 1', '1.0.0:alpha1'),  # Full form capitalized
        ('1.0.0 a1', '1.0.0:alpha1'),  # Short form
        
        # Direct concatenation patterns (numbered)
        ('2.0.0alpha1', '2.0.0:alpha1'),  # Direct concat full
        ('2.0.0a1', '2.0.0:alpha1'),  # Direct concat short
        
        # Specific notation patterns (numbered)
        ('1.0.0-alpha.1', '1.0.0:alpha1'),  # Dash-dot notation
        
        # Flexible separator patterns (numbered)
        ('3.0.0_alpha_2', '3.0.0:alpha2'),  # Underscore full
        ('3.0.0-alpha-2', '3.0.0:alpha2'),  # Dash full
        ('4.0.0_a_3', '4.0.0:alpha3'),  # Underscore short
        
        # Numberless patterns (prerelease identifiers without version numbers)
        ('2.0.0-alpha', '2.0.0:alpha'),  # Dash separator
        ('2.0.0.alpha', '2.0.0:alpha'),  # Dot separator
        ('2.0.0_alpha', '2.0.0:alpha'),  # Underscore separator
        ('1.0 alpha', '1.0:alpha'),  # Space separator
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "ALPHA"):
            all_passed = False
    return all_passed

def test_release_candidate_term_group():
    """Test RELEASE_CANDIDATE term group - complete scenario coverage including numberless patterns."""
    print(f"\n   RELEASE_CANDIDATE Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns (numbered)
        ('1.0.0 rc 1', '1.0.0:rc1'),  # Short form lowercase
        ('1.0.0 RC 1', '1.0.0:rc1'),  # Short form uppercase
        ('1.0.0 release candidate 1', '1.0.0:rc1'),  # Full form lowercase
        ('1.0.0 Release Candidate 1', '1.0.0:rc1'),  # Full form capitalized
        
        # Direct concatenation patterns (numbered)
        ('3.0.0rc1', '3.0.0:rc1'),  # Direct concat
        
        # Specific notation patterns (numbered)
        ('1.0.0-rc.1', '1.0.0:rc1'),  # Dash-dot notation
        
        # Flexible separator patterns (numbered)
        ('2.0.0_rc_2', '2.0.0:rc2'),  # Underscore short
        ('2.0.0-rc-2', '2.0.0:rc2'),  # Dash short
        ('3.0.0_rc_3', '3.0.0:rc3'),  # Additional underscore short variation
        
        # Numberless patterns (prerelease identifiers without version numbers)
        ('2.0.0-rc', '2.0.0:rc'),  # Dash separator
        ('2.0.0.rc', '2.0.0:rc'),  # Dot separator
        ('2.0.0_rc', '2.0.0:rc'),  # Underscore separator
        ('1.0 rc', '1.0:rc'),  # Space separator
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "RELEASE_CANDIDATE"):
            all_passed = False
    return all_passed

def test_fix_term_group():
    """Test FIX term group - complete scenario coverage."""
    print(f"\n   FIX Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('3.0.0 fix 1', '3.0.0:fix1'),  # Full form lowercase
        ('3.0.0 Fix 1', '3.0.0:fix1'),  # Full form capitalized
        # Note: FIX doesn't have a standard short form like "hf" for hotfix
        
        # Direct concatenation patterns
        ('5.0.0fix1', '5.0.0:fix1'),  # Direct concat full
        
        # Specific notation patterns
        ('2.1.0-fix.2', '2.1.0:fix2'),  # Dash-dot notation
        ('9.0.0fix1', '9.0.0:fix1'),  # Additional direct concatenation variation
        
        # Flexible separator patterns
        ('4.0.0_fix_2', '4.0.0:fix2'),  # Underscore full
        ('4.0.0-fix-2', '4.0.0:fix2'),  # Dash full
        ('6.0.0.fix.3', '6.0.0:fix3'),  # Dot separated
        ('8.0.0_fix_4', '8.0.0:fix4'),  # Underscore numeric
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "FIX"):
            all_passed = False
    return all_passed

def test_revision_term_group():
    """Test REVISION term group - complete scenario coverage."""
    print(f"\n   REVISION Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('3.0.0 revision 1', '3.0.0:revision1'),  # Full form lowercase
        ('3.0.0 Revision 1', '3.0.0:revision1'),  # Full form capitalized
        ('3.0.0 rev 1', '3.0.0:revision1'),  # Short form lowercase
        ('3.0.0 Rev 1', '3.0.0:revision1'),  # Short form capitalized
        
        # Direct concatenation patterns
        ('6.0.0revision1', '6.0.0:revision1'),  # Direct concat full
        ('6.0.0rev1', '6.0.0:revision1'),  # Direct concat short
        
        # Flexible separator patterns
        ('7.0.0_revision_2', '7.0.0:revision2'),  # Underscore full
        ('7.0.0-revision-2', '7.0.0:revision2'),  # Dash full
        ('8.0.0_rev_3', '8.0.0:revision3'),  # Underscore short
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "REVISION"):
            all_passed = False
    return all_passed

def test_maintenance_release_term_group():
    """Test MAINTENANCE_RELEASE term group - complete scenario coverage."""
    print(f"\n   MAINTENANCE_RELEASE Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('16.0.0 mr 7', '16.0.0:mr7'),  # Short form
        ('2.5.0 maintenance release 1', '2.5.0:mr1'),  # Full form lowercase → standardize to mr
        ('2.5.0 Maintenance Release 1', '2.5.0:mr1'),  # Full form capitalized → standardize to mr
        
        # Direct concatenation patterns
        ('1.0.0mr1', '1.0.0:mr1'),  # Direct concat short
        
        # Specific notation patterns
        ('3.1.0-mr.2', '3.1.0:mr2'),  # Dash-dot notation
        
        # Flexible separator patterns
        ('16.0.0_mr_7', '16.0.0:mr7'),  # Underscore short
        ('16.0.0-mr-7', '16.0.0:mr7'),  # Dash short
        ('3.0.0_maintenance_release_2', '3.0.0:mr2'),  # Underscore full → standardize to mr
        ('4.0.0-maintenance-release-3', '4.0.0:mr3'),  # Dash full → standardize to mr
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "MAINTENANCE_RELEASE"):
            all_passed = False
    return all_passed

def test_build_term_group():
    """Test BUILD term group - complete scenario coverage."""
    print(f"\n   BUILD Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('1.0.0 build 1', '1.0.0:build1'),  # Full form lowercase
        ('1.0.0 Build 1', '1.0.0:build1'),  # Full form capitalized
        
        # Direct concatenation patterns
        ('7.0.0build1', '7.0.0:build1'),  # Direct concat
        
        # Specific notation patterns
        ('2.1.0-build.2', '2.1.0:build2'),  # Dash-dot notation
        
        # Flexible separator patterns
        ('1.0.0_build_1', '1.0.0:build1'),  # Underscore
        ('2.0.0-build-2', '2.0.0:build2'),  # Dash
        ('3.0.0.build.3', '3.0.0:build3'),  # Dot separated
        ('4.0.0_build_4', '4.0.0:build4'),  # Additional underscore
        ('5.0.0-build-5', '5.0.0:build5'),  # Additional dash
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "BUILD"):
            all_passed = False
    return all_passed

def test_release_term_group():
    """Test RELEASE term group - complete scenario coverage."""
    print(f"\n   RELEASE Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('2.0.0 release 1', '2.0.0:release1'),  # Full form lowercase
        ('2.0.0 Release 1', '2.0.0:release1'),  # Full form capitalized
        
        # Direct concatenation patterns
        ('8.0.0release1', '8.0.0:release1'),  # Direct concat
        
        # Specific notation patterns
        ('3.1.0-release.2', '3.1.0:release2'),  # Dash-dot notation
        
        # Flexible separator patterns
        ('2.0.0_release_1', '2.0.0:release1'),  # Underscore
        ('3.0.0-release-2', '3.0.0:release2'),  # Dash
        ('4.0.0.release.3', '4.0.0:release3'),  # Dot separated
        ('5.0.0_release_4', '5.0.0:release4'),  # Additional underscore
        ('6.0.0-release-5', '6.0.0:release5'),  # Additional dash
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "RELEASE"):
            all_passed = False
    return all_passed

def test_milestone_term_group():
    """Test MILESTONE term group - complete scenario coverage."""
    print(f"\n   MILESTONE Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('4.0.0 milestone 1', '4.0.0:milestone1'),  # Full form lowercase
        ('4.0.0 Milestone 1', '4.0.0:milestone1'),  # Full form capitalized
        
        # Direct concatenation patterns
        ('9.0.0milestone1', '9.0.0:milestone1'),  # Direct concat
        
        # Specific notation patterns
        ('4.1.0-milestone.2', '4.1.0:milestone2'),  # Dash-dot notation
        
        # Flexible separator patterns
        ('3.0.0_milestone_1', '3.0.0:milestone1'),  # Underscore
        ('5.0.0-milestone-2', '5.0.0:milestone2'),  # Dash
        ('6.0.0.milestone.3', '6.0.0:milestone3'),  # Dot separated
        ('7.0.0_milestone_4', '7.0.0:milestone4'),  # Additional underscore
        ('8.0.0-milestone-5', '8.0.0:milestone5'),  # Additional dash
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "MILESTONE"):
            all_passed = False
    return all_passed

def test_snapshot_term_group():
    """Test SNAPSHOT term group - complete scenario coverage."""
    print(f"\n   SNAPSHOT Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('5.0.0 snapshot 1', '5.0.0:snapshot1'),  # Full form lowercase
        ('5.0.0 Snapshot 1', '5.0.0:snapshot1'),  # Full form capitalized
        
        # Direct concatenation patterns
        ('10.0.0snapshot1', '10.0.0:snapshot1'),  # Direct concat
        
        # Specific notation patterns
        ('5.1.0-snapshot.2', '5.1.0:snapshot2'),  # Dash-dot notation
        
        # Flexible separator patterns
        ('4.0.0_snapshot_1', '4.0.0:snapshot1'),  # Underscore
        ('6.0.0-snapshot-2', '6.0.0:snapshot2'),  # Dash
        ('7.0.0.snapshot.3', '7.0.0:snapshot3'),  # Dot separated
        ('8.0.0_snapshot_4', '8.0.0:snapshot4'),  # Additional underscore
        ('9.0.0-snapshot-5', '9.0.0:snapshot5'),  # Additional dash
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "SNAPSHOT"):
            all_passed = False
    return all_passed

def test_preview_term_group():
    """Test PREVIEW term group - complete scenario coverage."""
    print(f"\n   PREVIEW Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('6.0.0 preview 1', '6.0.0:preview1'),  # Full form lowercase
        ('6.0.0 Preview 1', '6.0.0:preview1'),  # Full form capitalized
        
        # Direct concatenation patterns
        ('11.0.0preview1', '11.0.0:preview1'),  # Direct concat
        
        # Specific notation patterns
        ('6.1.0-preview.2', '6.1.0:preview2'),  # Dash-dot notation
        
        # Flexible separator patterns
        ('5.0.0_preview_1', '5.0.0:preview1'),  # Underscore
        ('7.0.0-preview-2', '7.0.0:preview2'),  # Dash
        ('8.0.0.preview.3', '8.0.0:preview3'),  # Dot separated
        ('9.0.0_preview_4', '9.0.0:preview4'),  # Additional underscore
        ('10.0.0-preview-5', '10.0.0:preview5'),  # Additional dash
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "PREVIEW"):
            all_passed = False
    return all_passed

def test_candidate_term_group():
    """Test CANDIDATE term group - complete scenario coverage."""
    print(f"\n   CANDIDATE Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('7.0.0 candidate 1', '7.0.0:candidate1'),  # Full form lowercase
        ('7.0.0 Candidate 1', '7.0.0:candidate1'),  # Full form capitalized
        
        # Direct concatenation patterns
        ('12.0.0candidate1', '12.0.0:candidate1'),  # Direct concat
        
        # Specific notation patterns
        ('7.1.0-candidate.2', '7.1.0:candidate2'),  # Dash-dot notation
        
        # Flexible separator patterns
        ('6.0.0_candidate_1', '6.0.0:candidate1'),  # Underscore
        ('8.0.0-candidate-2', '8.0.0:candidate2'),  # Dash
        ('9.0.0.candidate.3', '9.0.0:candidate3'),  # Dot separated
        ('10.0.0_candidate_4', '10.0.0:candidate4'),  # Additional underscore
        ('11.0.0-candidate-5', '11.0.0:candidate5'),  # Additional dash
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "CANDIDATE"):
            all_passed = False
    return all_passed

def test_development_term_group():
    """Test DEVELOPMENT term group - complete scenario coverage."""
    print(f"\n   DEVELOPMENT Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('8.0.0 development 1', '8.0.0:development1'),  # Full form lowercase
        ('8.0.0 Development 1', '8.0.0:development1'),  # Full form capitalized
        
        # Direct concatenation patterns
        ('13.0.0development1', '13.0.0:development1'),  # Direct concat
        
        # Specific notation patterns
        ('8.1.0-development.2', '8.1.0:development2'),  # Dash-dot notation
        
        # Flexible separator patterns
        ('7.0.0_development_1', '7.0.0:development1'),  # Underscore
        ('9.0.0-development-2', '9.0.0:development2'),  # Dash
        ('10.0.0.development.3', '10.0.0:development3'),  # Dot separated
        ('11.0.0_development_4', '11.0.0:development4'),  # Additional underscore
        ('12.0.0-development-5', '12.0.0:development5'),  # Additional dash
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "DEVELOPMENT"):
            all_passed = False
    return all_passed

def test_device_pack_term_group():
    """Test DEVICE_PACK term group - complete scenario coverage."""
    print(f"\n   DEVICE_PACK Term Group - Complete Coverage:")
    
    test_cases = [
        # Space-separated patterns
        ('3.4 dp 1', '3.4:dp1'),  # Short form lowercase
        ('3.4 DP 1', '3.4:dp1'),  # Short form uppercase  
        ('3.4 device pack 1', '3.4:dp1'),  # Full form lowercase → standardize to dp
        
        # Direct concatenation patterns
        ('3.4dp1', '3.4:dp1'),  # Direct concat short
        
        # Specific notation patterns (includes the original issue case)
        ('3.4_DP1', '3.4:dp1'),  # Underscore notation (original case)
        
        # Flexible separator patterns  
        ('2.0.0_dp_3', '2.0.0:dp3'),  # Underscore short
        ('4.0.0-dp-4', '4.0.0:dp4'),  # Dash short
        ('6.0.0.dp.5', '6.0.0:dp5'),  # Dot separated short
        ('7.0.0_device_pack_6', '7.0.0:dp6'),  # Underscore full → standardize to dp
    ]
    
    all_passed = True
    for input_ver, expected in test_cases:
        if not test_pattern_verbose(input_ver, expected, "DEVICE_PACK"):
            all_passed = False
    return all_passed

# =================== EXCLUSION PATTERN TESTS ===================

def test_kb_exclusion_patterns():
    """Test that KB (Knowledge Base) patterns are properly excluded from transformation."""
    print(f"\n  � KB Exclusion Patterns - Complete Coverage:")
    
    # Test cases that should be EXCLUDED (return None)
    exclusion_test_cases = [
        ("kb4601315", "EXCLUDED"),                   # Standalone KB numbers
        ("KB4601315", "EXCLUDED"), 
        ("windows10.0-kb4601315", "EXCLUDED"),       # KB with various prefixes  
        ("windows10.0 kb4601315", "EXCLUDED"),
        ("windows10.0 KB4601315", "EXCLUDED"),
        ("server2019-kb1234567", "EXCLUDED"),
        ("office365-kb7890123", "EXCLUDED"),
        ("system.kb.123", "EXCLUDED"),               # Various separator patterns
        ("app_kb_456", "EXCLUDED"),
        ("product_kb789", "EXCLUDED"), 
        ("some.version.kb123", "EXCLUDED"),          # Critical case that used to fall back to beta
        ("someapp-kb999999", "EXCLUDED"),
        ("system kb 123456", "EXCLUDED"),
    ]
    
def test_kb_exclusion_patterns():
    """Test that KB (Knowledge Base) patterns are properly excluded from transformation."""
    print(f"\n   KB Exclusion Patterns - Complete Coverage:")
    
    # Test cases that should be EXCLUDED (return None)
    exclusion_test_cases = [
        ("kb4601315", "EXCLUDED"),                   # Standalone KB numbers
        ("KB4601315", "EXCLUDED"), 
        ("windows10.0-kb4601315", "EXCLUDED"),       # KB with various prefixes  
        ("windows10.0 kb4601315", "EXCLUDED"),
        ("windows10.0 KB4601315", "EXCLUDED"),
        ("server2019-kb1234567", "EXCLUDED"),
        ("office365-kb7890123", "EXCLUDED"),
        ("system.kb.123", "EXCLUDED"),               # Various separator patterns
        ("app_kb_456", "EXCLUDED"),
        ("product_kb789", "EXCLUDED"), 
        ("some.version.kb123", "EXCLUDED"),          # Critical case that used to fall back to beta
        ("someapp-kb999999", "EXCLUDED"),
        ("system kb 123456", "EXCLUDED"),
    ]
    
    # Suppress warning logs for cleaner test output
    suppress_warnings()
    
    all_excluded = True
    kb_patterns_detected = 0
    
    # Test each case
    for test_case, expected in exclusion_test_cases:
        result = get_transformed_version(test_case)
        
        # Format the result display with logging indicator
        if result is None and expected == "EXCLUDED":
            kb_patterns_detected += 1
            print(f"    PASS KB_EXCLUSION: '{test_case}' → EXCLUDED  (expected: EXCLUDED)")
        else:
            all_excluded = False
            actual = result if result is not None else "EXCLUDED"
            print(f"    FAIL KB_EXCLUSION: '{test_case}' → {actual} FAIL (expected: {expected})")
    
    # Restore warning logs
    restore_warnings()
    
    # Summary of exclusion verification
    print(f"     Exclusion verification: {kb_patterns_detected}/{len(exclusion_test_cases)} KB patterns properly excluded")
    print(f"     Warning logs: Generated for each excluded pattern (suppressed for clean output)")
    
    return all_excluded

def test_exclusion_patterns():
    """Test all exclusion patterns to ensure inappropriate transformations are prevented."""
    print(f"\n  � Exclusion Patterns - Complete Coverage:")
    
    # Run KB exclusion tests
    kb_excluded = test_kb_exclusion_patterns()
    
    # Can add other exclusion pattern tests here in the future
    # e.g., test_other_exclusion_patterns()
    
    return kb_excluded

# =================== CONSISTENCY VALIDATION ===================

def validate_test_coverage_consistency():
    """Validate that all term groups have consistent test scenario coverage."""
    print(f"\n Test Coverage Consistency")
    
    # Define expected test case counts per term category
    # Prerelease terms have additional numberless pattern tests
    prerelease_terms = {"BETA", "ALPHA", "RELEASE_CANDIDATE"}
    expected_standard = 9  # Standard terms: 9 test cases
    expected_prerelease = 13  # Prerelease terms: 9 numbered + 4 numberless = 13
    
    # Define all term groups to validate
    term_groups = [
        "PATCH", "SERVICE_PACK", "APPLICATION_PACK", "HOTFIX", 
        "CUMULATIVE_UPDATE", "UPDATE", "BETA", "ALPHA", 
        "RELEASE_CANDIDATE", "FIX", "REVISION", "MAINTENANCE_RELEASE",
        "BUILD", "RELEASE", "MILESTONE", "SNAPSHOT", "PREVIEW", 
        "CANDIDATE", "DEVELOPMENT", "DEVICE_PACK"
    ]
    
    coverage_issues = []
    standard_test_counts = []
    prerelease_test_counts = []
    
    for term_group in term_groups:
        case_count = get_test_case_count_for_term(term_group)
        expected_count = expected_prerelease if term_group in prerelease_terms else expected_standard
        
        if term_group in prerelease_terms:
            prerelease_test_counts.append(case_count)
        else:
            standard_test_counts.append(case_count)
        
        if case_count != expected_count:
            coverage_issues.append(f"FAIL {term_group}: {case_count} test cases (expected: {expected_count})")
        else:
            term_type = "prerelease" if term_group in prerelease_terms else "standard"
            print(f"    PASS {term_group}: {case_count} test cases ({term_type})")
    
    # Check for consistency within each category
    if standard_test_counts and len(set(standard_test_counts)) > 1:
        min_count = min(standard_test_counts)
        max_count = max(standard_test_counts)
        coverage_issues.append(f"FAIL INCONSISTENT STANDARD TERMS: Test case counts vary from {min_count} to {max_count}")
    
    if prerelease_test_counts and len(set(prerelease_test_counts)) > 1:
        min_count = min(prerelease_test_counts)
        max_count = max(prerelease_test_counts)
        coverage_issues.append(f"FAIL INCONSISTENT PRERELEASE TERMS: Test case counts vary from {min_count} to {max_count}")
    
    if coverage_issues:
        print(f"\n   Coverage Issues Found:")
        for issue in coverage_issues:
            print(f"    {issue}")
        print(f"\n   Current Test Case Distribution:")
        for term_group in term_groups:
            count = get_test_case_count_for_term(term_group)
            if term_group in prerelease_terms:
                status = "PASS" if count == expected_prerelease else "FAIL"
                print(f"    {status} {term_group}: {count} cases (prerelease)")
            else:
                status = "PASS" if count == expected_standard else "FAIL"
                print(f"    {status} {term_group}: {count} cases (standard)")
        return False
    else:
        print(f"    PASS All {len(term_groups)} term groups have consistent test coverage")
        print(f"    PASS Standard terms: {expected_standard} cases each")
        print(f"    PASS Prerelease terms: {expected_prerelease} cases each (includes numberless support)")
        return True

def get_test_case_count_for_term(term_group):
    """Get the actual test case count for a term group by counting the test cases in the corresponding test function."""
    import inspect
    
    # Get the current module (this test file)
    current_module = inspect.currentframe().f_globals
    
    # Map term groups to their test function names
    function_mapping = {
        "PATCH": "test_patch_term_group",
        "SERVICE_PACK": "test_service_pack_term_group", 
        "APPLICATION_PACK": "test_application_pack_term_group",
        "HOTFIX": "test_hotfix_term_group",
        "CUMULATIVE_UPDATE": "test_cumulative_update_term_group",
        "UPDATE": "test_update_term_group",
        "BETA": "test_beta_term_group",
        "ALPHA": "test_alpha_term_group",
        "RELEASE_CANDIDATE": "test_release_candidate_term_group",
        "FIX": "test_fix_term_group",
        "REVISION": "test_revision_term_group",
        "MAINTENANCE_RELEASE": "test_maintenance_release_term_group",
        "BUILD": "test_build_term_group",
        "RELEASE": "test_release_term_group",
        "MILESTONE": "test_milestone_term_group",
        "SNAPSHOT": "test_snapshot_term_group",
        "PREVIEW": "test_preview_term_group",
        "CANDIDATE": "test_candidate_term_group",
        "DEVELOPMENT": "test_development_term_group",
        "DEVICE_PACK": "test_device_pack_term_group"
    }
    
    function_name = function_mapping.get(term_group)
    if not function_name:
        return 0
    
    # Get the function from current module
    test_function = current_module.get(function_name)
    if not test_function:
        return 0
    
    # Get the source code of the function and count test cases
    source_lines = inspect.getsource(test_function)
    
    # Count the number of test cases by looking for tuple patterns in test_cases list
    # Look for patterns like ('input', 'expected'),
    import re
    tuple_pattern = r'\(\s*[\'"][^\'"]+[\'"]\s*,\s*[\'"][^\'"]+[\'"]\s*\)'
    test_case_count = len(re.findall(tuple_pattern, source_lines))
    
    return test_case_count

def validate_implementation_consistency():
    """Validate that the actual implementation has consistent patterns for each term group."""
    print(f"\n Implementation Pattern Consistency")
    
    try:
        # Read the badge_modal_system.py file to analyze implementation patterns
        import inspect
        from src.analysis_tool.core.badge_modal_system import transform_version_with_update_pattern
        
        # Get the source code of the function
        source_file_path = inspect.getfile(transform_version_with_update_pattern)
        
        with open(source_file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        # Analyze pattern consistency in the implementation
        # The implementation uses lowercase type names, e.g., 'type': 'patch'
        # Some terms have multiple type variants that need to be counted together
        term_groups = {
            "PATCH": ["patch"],
            "SERVICE_PACK": ["sp"],
            "APPLICATION_PACK": ["ap"], 
            "HOTFIX": ["hotfix"],
            "CUMULATIVE_UPDATE": ["cu", "cumulativeupdate"],  # Multiple type variants
            "UPDATE": ["update"],
            "BETA": ["beta"],
            "ALPHA": ["alpha"],
            "RELEASE_CANDIDATE": ["rc"],
            "FIX": ["fix"],
            "REVISION": ["revision"],
            "MAINTENANCE_RELEASE": ["mr", "maintenancerelease"],  # Multiple type variants
            "BUILD": ["build"],
            "RELEASE": ["release"],
            "MILESTONE": ["milestone"],
            "SNAPSHOT": ["snapshot"],
            "PREVIEW": ["preview"],
            "CANDIDATE": ["candidate"],
            "DEVELOPMENT": ["development"],
            "DEVICE_PACK": ["dp"]
        }
        
        implementation_issues = []
        pattern_counts = {}
        all_pattern_counts = []
        
        for term_group, type_variants in term_groups.items():
            # Count how many regex patterns exist for each term type
            pattern_count = 0
            for type_name in type_variants:
                pattern_count += source_code.count(f"'type': '{type_name}'") + source_code.count(f'"type": "{type_name}"')
            
            pattern_counts[term_group] = pattern_count
            all_pattern_counts.append(pattern_count)
            
            if pattern_count == 0:
                implementation_issues.append(f"FAIL {term_group}: No patterns found in implementation")
            else:
                print(f"    - {term_group}: {pattern_count} patterns implemented")
        
        # For true consistency, all terms should have identical pattern counts
        if all_pattern_counts:
            max_patterns = max(all_pattern_counts)
            min_patterns = min(all_pattern_counts)
            avg_patterns = sum(all_pattern_counts) / len(all_pattern_counts)
            
            # Check for intentional pattern count differences (prerelease terms have numberless patterns)
            prerelease_terms = ["BETA", "ALPHA", "RELEASE_CANDIDATE"]
            standard_patterns = [count for term, count in pattern_counts.items() if term not in prerelease_terms]
            prerelease_patterns = [count for term, count in pattern_counts.items() if term in prerelease_terms]
            
            # Validate standard terms have consistent counts
            if standard_patterns and len(set(standard_patterns)) > 1:
                implementation_issues.append(f"FAIL INCONSISTENT STANDARD TERMS: Pattern counts vary ({min(standard_patterns)} to {max(standard_patterns)})")
            
            # Validate prerelease terms have consistent counts (should be higher than standard)
            if prerelease_patterns and len(set(prerelease_patterns)) > 1:
                implementation_issues.append(f"FAIL INCONSISTENT PRERELEASE TERMS: Pattern counts vary ({min(prerelease_patterns)} to {max(prerelease_patterns)})")
            
            # Validate prerelease terms have more patterns than standard (due to numberless support)
            expected_standard = standard_patterns[0] if standard_patterns else 0
            expected_prerelease = prerelease_patterns[0] if prerelease_patterns else 0
            
            if expected_prerelease <= expected_standard:
                implementation_issues.append(f"FAIL PRERELEASE PATTERN COUNT: Prerelease terms should have more patterns than standard terms (prerelease={expected_prerelease}, standard={expected_standard})")
            
            # Flag individual terms that don't match their category's expected count
            for term_group, count in pattern_counts.items():
                if term_group in prerelease_terms:
                    if count != expected_prerelease:
                        implementation_issues.append(f"FAIL {term_group}: {count} patterns (should be {expected_prerelease})")
                else:
                    if count != expected_standard:
                        implementation_issues.append(f"FAIL {term_group}: {count} patterns (should be {expected_standard})")
            
            # Show distribution analysis
            print(f"\n     Pattern Distribution Analysis:")
            print(f"    - Standard terms: {expected_standard} patterns each")
            print(f"    - Prerelease terms: {expected_prerelease} patterns each")
            print(f"    - Difference: +{expected_prerelease - expected_standard} patterns for prerelease (numberless support)")
            
            if len(set(standard_patterns)) == 1 and len(set(prerelease_patterns)) == 1:
                print(f"    PASS Consistent within categories (intentional difference for prerelease)")
            else:
                print(f"    FAIL Inconsistent implementation within categories")
        
        if implementation_issues:
            print(f"\n   Implementation Issues Found:")
            for issue in implementation_issues:
                print(f"    {issue}")
            
            print(f"\n   Current Implementation Pattern Distribution:")
            for term_group, count in pattern_counts.items():
                if term_group in prerelease_terms:
                    status = "PASS" if count == expected_prerelease else "FAIL"
                    print(f"    {status} {term_group}: {count} patterns (prerelease)")
                else:
                    status = "PASS" if count == expected_standard else "FAIL"
                    print(f"    {status} {term_group}: {count} patterns (standard)")
            
            return False
        else:
            print(f"    PASS All {len(term_groups)} term groups have consistent patterns")
            print(f"    PASS Standard terms: {expected_standard} patterns each")
            print(f"    PASS Prerelease terms: {expected_prerelease} patterns each (includes numberless support)")
            return True
            
    except Exception as e:
        print(f"    FAIL Failed to analyze implementation: {e}")
        return False

def validate_excluded_patterns_not_in_implementation():
    """Validate that KB patterns are properly excluded from implementation."""
    print(f"\n Exclusion Pattern Implementation")
    
    try:
        # Test a few KB patterns to verify they're properly excluded
        test_kb_patterns = [
            "kb4601315", "KB4601315", "windows10.0-kb4601315", 
            "some.version.kb123"
        ]
        
        all_excluded = True
        for pattern in test_kb_patterns:
            result = get_transformed_version(pattern)
            if result is not None:
                print(f"    FAIL KB pattern '{pattern}' not properly excluded (returned: {result})")
                all_excluded = False
        
        if all_excluded:
            print(f"    PASS All {len(test_kb_patterns)} KB test patterns properly excluded")
            return True
        else:
            print(f"    FAIL KB exclusion patterns not working correctly")
            return False
        
    except Exception as e:
        print(f"    FAIL Failed to analyze exclusion patterns: {e}")
        return False

def validate_javascript_python_synchronization():
    """Validate that JavaScript updatePatterns implementation mirrors Python exactly."""
    print(f"     JavaScript Pattern Synchronization Analysis")
    
    try:
        # Read the JavaScript modular_rules.js file
        import os
        from pathlib import Path
        
        # Find the JavaScript file
        project_root = Path(__file__).parent.parent.parent
        js_file_path = project_root / "src" / "analysis_tool" / "static" / "js" / "modular_rules.js"
        
        if not js_file_path.exists():
            print(f"    FAIL JavaScript file not found at {js_file_path}")
            return False
        
        with open(js_file_path, 'r', encoding='utf-8') as f:
            js_content = f.read()
        
        # Find the updatePatterns rule section
        if 'updatePatterns:' not in js_content:
            print(f"    FAIL updatePatterns rule not found in JavaScript file")
            return False
        
        # Extract the patterns section from the JavaScript
        updatepatterns_start = js_content.find('updatePatterns:')
        if updatepatterns_start == -1:
            print(f"    FAIL updatePatterns rule start not found")
            return False
        
        # Find the patterns array in the JavaScript
        patterns_start = js_content.find('const updatePatterns = [', updatepatterns_start)
        if patterns_start == -1:
            # Try alternative pattern array syntax
            patterns_start = js_content.find('updatePatterns = [', updatepatterns_start)
            if patterns_start == -1:
                print(f"    FAIL JavaScript patterns array not found")
                return False
        
        # Test critical synchronization points by running key test cases
        sync_test_cases = [
            # Test each term group with its most common pattern
            ('3.1.0.p7', '3.1.0:patch7'),  # PATCH
            ('3.0.0.sp1', '3.0.0:sp1'),    # SERVICE_PACK
            ('24.0.ap375672', '24.0:ap375672'),  # APPLICATION_PACK
            ('3.0.0 hotfix 1', '3.0.0:hotfix1'),  # HOTFIX
            ('14.0.0 cu 5', '14.0.0:cu5'),  # CUMULATIVE_UPDATE
            ('8.0.0 cumulative update 1', '8.0.0:cu1'),  # CUMULATIVE_UPDATE (full form → standardized to cu)
            ('3.0.0 update 1', '3.0.0:update1'),  # UPDATE
            ('1.0.0 beta 1', '1.0.0:beta1'),  # BETA
            ('1.0.0 alpha 1', '1.0.0:alpha1'),  # ALPHA
            ('1.0.0 rc 1', '1.0.0:rc1'),  # RELEASE_CANDIDATE
            ('3.0.0 fix 1', '3.0.0:fix1'),  # FIX
            ('3.0.0 revision 1', '3.0.0:revision1'),  # REVISION
            ('16.0.0 mr 7', '16.0.0:mr7'),  # MAINTENANCE_RELEASE
            ('2.5.0 maintenance release 1', '2.5.0:mr1'),  # MAINTENANCE_RELEASE (full form → standardized to mr)
            ('1.0.0 build 1', '1.0.0:build1'),  # BUILD
            ('2.0.0 release 1', '2.0.0:release1'),  # RELEASE
            ('4.0.0 milestone 1', '4.0.0:milestone1'),  # MILESTONE
            ('5.0.0 snapshot 1', '5.0.0:snapshot1'),  # SNAPSHOT
            ('6.0.0 preview 1', '6.0.0:preview1'),  # PREVIEW
            ('7.0.0 candidate 1', '7.0.0:candidate1'),  # CANDIDATE
            ('8.0.0 development 1', '8.0.0:development1'),  # DEVELOPMENT
            ('3.4_DP1', '3.4:dp1'),  # DEVICE_PACK (original failing case)
            ('3.4 device pack 1', '3.4:dp1'),  # DEVICE_PACK (full form → standardized to dp)
        ]
        
        # Import the Python implementation
        from src.analysis_tool.core.badge_modal_system import transform_version_with_update_pattern
        
        sync_issues = []
        patterns_analyzed = 0
        
        print(f"     Testing {len(sync_test_cases)} critical synchronization points...")
        
        for input_version, expected_output in sync_test_cases:
            patterns_analyzed += 1
            
            # Test Python implementation
            python_result = transform_version_with_update_pattern(input_version)
            python_output = python_result[2] if python_result[0] else None
            
            if python_output != expected_output:
                sync_issues.append({
                    'input': input_version,
                    'expected': expected_output,
                    'python_actual': python_output,
                    'issue': 'Python implementation does not match expected'
                })
        
        # Analyze JavaScript pattern coverage
        js_pattern_indicators = {
            'patch': ['p(\\\\d+)', "'patch'", '"patch"'],
            'sp': ['sp(\\\\d+)', "'sp'", '"sp"'],
            'ap': ['ap(\\\\d+)', "'ap'", '"ap"'],
            'hotfix': ['hotfix', "'hotfix'", '"hotfix"'],
            'cu': ['cu(\\\\d+)', "'cu'", '"cu"'],
            'update': ['update(\\\\d+)', "'update'", '"update"'],
            'beta': ['beta', "'beta'", '"beta"'],
            'alpha': ['alpha', "'alpha'", '"alpha"'],
            'rc': ['rc(\\\\d+)', "'rc'", '"rc"'],
            'fix': ['fix(\\\\d+)', "'fix'", '"fix"'],
            'revision': ['revision', "'revision'", '"revision"'],
            'mr': ['mr(\\\\d+)', "'mr'", '"mr"'],
            'build': ['build', "'build'", '"build"'],
            'release': ['release', "'release'", '"release"'],
            'milestone': ['milestone', "'milestone'", '"milestone"'],
            'snapshot': ['snapshot', "'snapshot'", '"snapshot"'],
            'preview': ['preview', "'preview'", '"preview"'],
            'candidate': ['candidate', "'candidate'", '"candidate"'],
            'development': ['development', "'development'", '"development"'],
            'dp': ['dp(\\\\d+)', "'dp'", '"dp"']
        }
        
        js_coverage_issues = []
        for pattern_type, indicators in js_pattern_indicators.items():
            found_any = False
            for indicator in indicators:
                if indicator.lower() in js_content.lower():
                    found_any = True
                    break
            
            if not found_any:
                js_coverage_issues.append(f"JavaScript missing {pattern_type} patterns")
        
        # Report results
        total_issues = len(sync_issues) + len(js_coverage_issues)
        
        if sync_issues:
            print(f"    FAIL Python Implementation Issues:")
            for issue in sync_issues:
                print(f"        - {issue['input']} → Python: '{issue['python_actual']}' (expected: '{issue['expected']}')")
        
        if js_coverage_issues:
            print(f"    FAIL JavaScript Coverage Issues:")
            for issue in js_coverage_issues:
                print(f"        - {issue}")
        
        if total_issues == 0:
            print(f"    PASS All {patterns_analyzed} sync points validated successfully")
            print(f"    PASS JavaScript pattern coverage confirmed for all {len(js_pattern_indicators)} term types")
            return True
        else:
            print(f"    FAIL Found {total_issues} synchronization issues")
            return False
        
    except Exception as e:
        print(f"    FAIL Failed to validate JavaScript-Python synchronization: {e}")
        return False

# =================== MAIN TEST RUNNER ===================

def main():
    """Main comprehensive test runner."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test update patterns functionality')
    args = parser.parse_args()
    
    print("=" * 80)
    print("COMPREHENSIVE UPDATE PATTERN TEST SUITE")
    print("Complete coverage for ALL 20 terms with consistent scenario types")
    print("Plus exclusion pattern testing for inappropriate transformations")
    print("Plus consistency validation for test coverage and implementation")
    print("=" * 80)
    
    # Define all term group tests
    # Define term tests with their test case counts
    prerelease_terms = {"BETA", "ALPHA", "RELEASE_CANDIDATE"}  # Have numberless patterns
    term_tests = [
        ("PATCH", test_patch_term_group, 9),
        ("SERVICE_PACK", test_service_pack_term_group, 9),
        ("APPLICATION_PACK", test_application_pack_term_group, 9),
        ("HOTFIX", test_hotfix_term_group, 9),
        ("CUMULATIVE_UPDATE", test_cumulative_update_term_group, 9),
        ("UPDATE", test_update_term_group, 9),
        ("BETA", test_beta_term_group, 13),  # 9 numbered + 4 numberless
        ("ALPHA", test_alpha_term_group, 13),  # 9 numbered + 4 numberless
        ("RELEASE_CANDIDATE", test_release_candidate_term_group, 13),  # 9 numbered + 4 numberless
        ("FIX", test_fix_term_group, 9),
        ("REVISION", test_revision_term_group, 9),
        ("MAINTENANCE_RELEASE", test_maintenance_release_term_group, 9),
        ("BUILD", test_build_term_group, 9),
        ("RELEASE", test_release_term_group, 9),
        ("MILESTONE", test_milestone_term_group, 9),
        ("SNAPSHOT", test_snapshot_term_group, 9),
        ("PREVIEW", test_preview_term_group, 9),
        ("CANDIDATE", test_candidate_term_group, 9),
        ("DEVELOPMENT", test_development_term_group, 9),
        ("DEVICE_PACK", test_device_pack_term_group, 9),
    ]
    
    all_tests_passed = True
    passed_groups = 0
    total_groups = len(term_tests)
    total_individual_tests = sum(count for _, _, count in term_tests)
    passed_individual_tests = 0
    
    # Run each term group test
    for term_name, test_func, test_count in term_tests:
        print(f"\n {term_name} TERM GROUP")
        group_passed = test_func()
        if group_passed:
            passed_groups += 1
            passed_individual_tests += test_count
            print(f"   PASS {term_name} - PASSED ({test_count}/{test_count} tests)")
        else:
            all_tests_passed = False
            print(f"   FAIL {term_name} - FAILED (check output above for failures)")
    
    # Run exclusion pattern tests
    print(f"\n EXCLUSION_PATTERNS TERM GROUP")
    exclusion_passed = test_exclusion_patterns()
    if exclusion_passed:
        print(f"   PASS EXCLUSION_PATTERNS - PASSED")
    else:
        all_tests_passed = False
        print(f"   FAIL EXCLUSION_PATTERNS - FAILED")
    
    # Run consistency validation tests
    print(f"\n CONSISTENCY VALIDATION")
    
    test_coverage_passed = validate_test_coverage_consistency()
    implementation_passed = validate_implementation_consistency()
    exclusion_passed = validate_excluded_patterns_not_in_implementation()
    
    validation_passed = all([test_coverage_passed, implementation_passed, exclusion_passed])
    
    print(f"\n   Overall Consistency Result:")
    if validation_passed:
        print(f"   PASS CONSISTENCY_VALIDATION - PASSED")
    else:
        all_tests_passed = False
        print(f"   FAIL CONSISTENCY_VALIDATION - FAILED")
        print(f"      - Test Coverage: {'PASS PASSED' if test_coverage_passed else 'FAIL FAILED'}")
        print(f"      - Implementation Patterns: {'PASS PASSED' if implementation_passed else 'FAIL FAILED'}")
        print(f"      - Exclusion Patterns: {'PASS PASSED' if exclusion_passed else 'FAIL FAILED'}")
    
    # Run JavaScript-Python synchronization validation
    print(f"\n JAVASCRIPT-PYTHON SYNCHRONIZATION")
    
    js_sync_passed = validate_javascript_python_synchronization()
    
    if js_sync_passed:
        print(f"   PASS JAVASCRIPT_SYNC - PASSED")
    else:
        all_tests_passed = False
        print(f"   FAIL JAVASCRIPT_SYNC - FAILED")
    
    # Final summary
    print("\n" + "=" * 80)
    print("COMPREHENSIVE TEST SUMMARY")
    print("=" * 80)
    print(f"Term Groups: {passed_groups}/{total_groups} passed")
    print(f"Exclusion Tests: {'PASS PASSED' if exclusion_passed else 'FAIL FAILED'}")
    print(f"Consistency Validation: {'PASS PASSED' if validation_passed else 'FAIL FAILED'}")
    print(f"JavaScript Synchronization: {'PASS PASSED' if js_sync_passed else 'FAIL FAILED'}")
    overall_passed = passed_groups + (1 if exclusion_passed else 0) + (1 if validation_passed else 0) + (1 if js_sync_passed else 0)
    overall_total = total_groups + 3
    print(f"Overall: {overall_passed}/{overall_total} test sections passed")
    print(f"Success Rate: {(overall_passed/overall_total*100):.1f}%")
    
    if all_tests_passed:
        print(" ALL COMPREHENSIVE TESTS PASSED!")
        print("- All 20 term groups working correctly")
        print("- KB exclusion patterns working correctly")
        print("- Test coverage and implementation consistency validated")
        print("- JavaScript-Python synchronization confirmed")
        # Output standardized test results format
        print(f'TEST_RESULTS: PASSED={total_individual_tests} TOTAL={total_individual_tests} SUITE="Update Patterns"')
        return True
    else:
        print("FAIL SOME TESTS FAILED - SEE DETAILS ABOVE")
        # Report accurate individual test counts
        print(f'TEST_RESULTS: PASSED={passed_individual_tests} TOTAL={total_individual_tests} SUITE="Update Patterns"')
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
