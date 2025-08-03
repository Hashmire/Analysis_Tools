# Provenance Assistance Test Suite

## 📊 Overview

**10 tests** validating CPE provenance assistance functionality, package repository detection, and HTML generation for CVE analysis pages.

## 🚀 Execution

```bash
# Unified runner (recommended)
python test_files\run_all_tests.py

# Individual execution
python test_files\test_provenance_assistance.py test_files\testProvenanceAssistance.json
```

## 🎯 Core Validation Areas

### **Package Repository Detection**
- Maven artifact pattern recognition from group:artifact coordinates
- npm, PyPI, and generic package repository type detection
- Repository URL parsing and classification

### **Description Assistance**
- Multi-language CNA description button generation
- ADP source handling with proper attribution
- WordPress-specific source detection and centered button layout

### **Reference Card Generation**
- Advisory, report, vendor, and third-party reference type processing
- Proper source attribution and target tag validation
- HTML structure generation for reference display

### **HTML Integration**

- Generated file output validation (test_output/CVE-1337-99998.html)
- Badge/modal system integration for provenance data
- Platform entry structure with 20+ required elements

## ✅ Success Criteria

- **Pass Rate**: 10/10 tests must pass (100% pass rate required)
- **File Generation**: Valid HTML output created in test_output directory
- **Content Validation**: All provenance assistance features properly integrated
- **Unicode Support**: International character handling across all components

## 🔧 Implementation Details

- **Framework**: Python unittest with JSON test case definitions
- **Test Data**: `testProvenanceAssistance.json` with synthetic CVE data
- **Dependencies**: HTML generation system, badge/modal integration, CPE processing
- **Output**: HTML files with embedded provenance assistance features
- **Expected Behavior**: Should create another ADP description card
- **Validation Points**:
  - Should appear as third description source
  - Should include WordPress-specific source detection
  - Single language should use centered button layout

### 2. Reference Assistance Testing

**Test Case R1: CNA References with Target Tags**  

- **Source**: CNA (ProvenanceTestOrg)
- **Target Tags Tested**: patch, issue-tracking, mitigation, product
- **References**:
  - **Patch**: `https://github.com/apache/commons-collections/commit/abc123def456`
  - **Issue Tracking**: `https://github.com/apache/commons-collections/issues/12345`
  - **Mitigation**: `https://security-mitigations.apache.org/commons-collections`
  - **Product**: `https://commons.apache.org/collections/security`
- **Expected Behavior**: Should create reference cards for each target tag type
- **Validation Points**:
  - Each target tag should appear as a separate card
  - Card headers should show capitalized, formatted tag names ("Issue Tracking", "Mitigation", etc.)
  - References without target tags should be ignored

**Test Case R2: ADP References with Overlapping Tags (TechSecurityCorp)**  

- **Source**: ADP (TechSecurityCorp)
- **Overlapping Tags**: Some references share the same tags as CNA references
- **References**:
  - **Patch**: `https://github.com/apache/commons-collections/pull/98765` (different from CNA patch)
  - **Issue Tracking**: `https://bugzilla.redhat.com/show_bug.cgi?id=2024999`  - **Mitigation**: `https://mitre-attack.github.io/attack-mitigations/CVE-1337-99998`
  - **Product + Mitigation**: `https://maven.apache.org/security/CVE-1337-99998` (multi-tag reference)
- **Expected Behavior**: Should consolidate references by tag but show different URLs
- **Validation Points**:
  - Same tags should appear in the same cards but with multiple buttons
  - Multi-tag references should appear in multiple cards
  - Should handle duplicate tag consolidation properly

**Test Case R3: WordPress-Specific ADP References (WordFence)**  

- **Source**: ADP (WordFence)
- **WordPress Integration**: Tests integration with WordPress source detection
- **References**:
  - **Product**: `https://www.wordfence.com/threat-intel/vulnerabilities/CVE-1337-99998`
  - **Patch + Product**: `https://wordpress.org/plugins/vulnerable-plugin/#developers`
  - **Patch**: `https://plugins.trac.wordpress.org/changeset/123456/vulnerable-plugin`
- **Expected Behavior**: Should create reference cards AND trigger WordPress-specific provenance assistance
- **Validation Points**:
  - Should detect WordFence as WordPress-related source
  - Should trigger WordPress provenance assistance for WordPress plugin entries
  - Should handle both reference cards and WordPress platform cards

### 3. Reference Tag Processing and Consolidation

**Test Case R4: Duplicate URL Handling**  

- **Scenario**: Multiple sources referencing the same URL with same or different tags
- **Expected Behavior**: Should consolidate duplicate URLs within the same tag category
- **Validation Points**:
  - Same URL in same tag should appear only once
  - Should track which sources provided the reference
  - Different URLs with same tag should appear as separate buttons

**Test Case R5: Multi-Tag Reference Handling**  

- **Reference Example**: `https://maven.apache.org/security/CVE-1337-99998` (tagged as both "mitigation" and "product")
- **Expected Behavior**: Should appear in both "Mitigation" and "Product" cards
- **Validation Points**:
  - Same URL should appear in multiple cards if it has multiple target tags
  - Button text and functionality should be identical in both cards

**Test Case R6: Non-Target Tag Filtering**  

- **Non-Target Tags**: mailing-list, vendor-advisory, third-party-advisory
- **Expected Behavior**: References with only non-target tags should be ignored
- **Validation Points**:
  - Should not create cards for non-target tags
  - Should only process references that have at least one target tag
  - Mixed tag references should be processed only for their target tags

### 4. Source Role and Provider Integration

**Test Case S1: Multiple Source Roles**  

- **CNA Role**: Primary coordinating authority
- **ADP Roles**: Additional data providers with different specializations
- **Expected Behavior**: Should clearly distinguish between source roles in UI
- **Validation Points**:
  - CNA descriptions should be labeled as "CNA Description(s)"
  - ADP descriptions should be labeled as "ADP Description(s)"
  - Source cards should maintain visual consistency

**Test Case S2: Special Source Detection**  

- **WordFence Source**: Tests special handling for known WordPress security sources
- **Source ID**: `b15e7b5b-3da4-40ae-a43c-f7aa60e62599`
- **Expected Behavior**: Should trigger WordPress-specific provenance assistance
- **Validation Points**:
  - Should detect WordFence by source ID
  - Should trigger WordPress platform assistance for relevant affected entries
  - Should work in combination with reference processing

### 5. Official Maven Central Repositories

**Test Case 1.1: Apache Commons Collections**  

- **Collection URL**: `https://repo1.maven.org/maven2`
- **Package Name**: `org.apache.commons:commons-collections4`
- **Repository**: `https://github.com/apache/commons-collections`
- **Expected Behavior**: Should trigger Maven-specific provenance assistance with proper groupId/artifactId handling
- **Maven Detection**: High confidence (official Maven Central URL + proper Maven coordinate format)

**Test Case 1.2: Spring Framework**  

- **Collection URL**: `https://repo.maven.apache.org/maven2`
- **Package Name**: `org.springframework:spring-core`
- **Repository**: `https://github.com/spring-projects/spring-framework`
- **Expected Behavior**: Should trigger Maven-specific provenance assistance
- **Maven Detection**: High confidence (official Maven repository URL + proper Maven coordinate format)

### 2. Enterprise Maven Repositories

**Test Case 2.1: Nexus Repository**  

- **Collection URL**: `https://nexus.enterprise.com/repository/maven-public`
- **Package Name**: `com.enterprise:internal-utils`
- **Repository**: `https://gitlab.enterprise.com/internal/utils`
- **Expected Behavior**: Should trigger Maven-specific provenance assistance
- **Maven Detection**: High confidence (Nexus in URL + strong Maven indicators + proper Maven coordinate format)

**Test Case 2.2: Artifactory Repository**  

- **Collection URL**: `https://artifactory.mycompany.com/artifactory/libs-release`
- **Package Name**: `com.mycompany:custom-lib`
- **Expected Behavior**: Should trigger Maven-specific provenance assistance
- **Maven Detection**: High confidence (Artifactory in URL + libs-release path + proper Maven coordinate format)

### 3. Maven-Compatible Third-Party Repositories

**Test Case 3.1: Sonatype OSS**  

- **Collection URL**: `https://oss.sonatype.org/content/repositories/releases`
- **Package Name**: `org.sonatype.test:test-artifact`
- **Repository**: `https://github.com/sonatype/test-artifact`
- **Expected Behavior**: Should trigger Maven-specific provenance assistance
- **Maven Detection**: High confidence (Sonatype in URL + proper Maven coordinate format)

**Test Case 3.2: JitPack**  

- **Collection URL**: `https://jitpack.io`
- **Package Name**: `com.github.jitpack-user:github-project`
- **Repository**: `https://github.com/jitpack-user/github-project`
- **Expected Behavior**: Should trigger Maven-specific provenance assistance
- **Maven Detection**: High confidence (JitPack is known Maven-compatible + proper Maven coordinate format)

**Test Case 3.3: Clojars**  

- **Collection URL**: `https://clojars.org/repo`
- **Package Name**: `org.clojure:test-clojure-lib`
- **Repository**: `https://github.com/clojure/test-clojure-lib`
- **Expected Behavior**: Should trigger Maven-specific provenance assistance
- **Maven Detection**: High confidence (Clojars is known Maven-compatible + proper Maven coordinate format)

### 4. Non-Maven Package Repositories

**Test Case 4.1: Python PyPI**  

- **Collection URL**: `https://pypi.org/simple`
- **Package Name**: `vulnerable-package`
- **Repository**: `https://github.com/python-org/vulnerable-package`
- **Expected Behavior**: Should trigger generic collection URL provenance assistance (NOT Maven-specific)
- **Maven Detection**: False (no Maven indicators, single-word package name)

**Test Case 4.2: NPM Registry**  

- **Collection URL**: `https://registry.npmjs.org`
- **Package Name**: `test-npm-package`
- **Repository**: `https://github.com/nodejs-org/test-npm-package`
- **Expected Behavior**: Should trigger generic collection URL provenance assistance (NOT Maven-specific)
- **Maven Detection**: False (no Maven indicators, hyphenated package name typical for NPM)

**Test Case 4.3: RubyGems**  

- **Collection URL**: `https://rubygems.org`
- **Package Name**: `test-gem`
- **Repository**: `https://github.com/ruby-gems-org/test-gem`
- **Expected Behavior**: Should trigger generic collection URL provenance assistance (NOT Maven-specific)
- **Maven Detection**: False (no Maven indicators, hyphenated package name typical for RubyGems)

**Test Case 4.4: NuGet**  

- **Collection URL**: `https://api.nuget.org/v3-flatcontainer`
- **Package Name**: `TestNuGetPackage`
- **Repository**: `https://github.com/nuget-org/TestNuGetPackage`
- **Expected Behavior**: Should trigger generic collection URL provenance assistance (NOT Maven-specific)
- **Maven Detection**: False (no Maven indicators, single word package name typical for NuGet)

### 5. WordPress Platforms

**Test Case 5.1: WordPress Plugin (downloads.wordpress.org)**  

- **Collection URL**: `https://downloads.wordpress.org/plugin`
- **Package Name**: `vulnerable-plugin`
- **Repository**: `https://plugins.svn.wordpress.org/vulnerable-plugin`
- **Expected Behavior**: Should trigger WordPress-specific provenance assistance with Maintainer Profile, Plugin Tracking, and Changelog buttons
- **WordPress Detection**: High confidence (WordPress.org in collection URL)

**Test Case 5.2: WordPress Plugin (wordpress.org/plugins)**  

- **Collection URL**: `https://wordpress.org/plugins`
- **Package Name**: `another-wp-plugin`
- **Expected Behavior**: Should trigger WordPress-specific provenance assistance
- **WordPress Detection**: High confidence (WordPress.org in collection URL)

### 6. Go Modules

**Test Case 6.1: Go Proxy**  

- **Collection URL**: `https://proxy.golang.org`
- **Package Name**: `github.com/go-modules/test-go-module`
- **Repository**: `https://github.com/go-modules/test-go-module`
- **Expected Behavior**: Should trigger generic collection URL provenance assistance (NOT Maven-specific)
- **Maven Detection**: False (no Maven indicators, Go module path format)

### 7. Edge Cases and Complex Scenarios

**Test Case 7.1: Maven-like URL but Non-Maven Package Format**  

- **Collection URL**: `https://custom-repo.example.com/maven-styled`
- **Package Name**: `not.actually:maven.format.but.has.maven.in.url`
- **Repository**: `https://github.com/edge-case-vendor/maven-like-but-not-maven`
- **Expected Behavior**: Should trigger generic collection URL provenance assistance (NOT Maven-specific)
- **Maven Detection**: False (URL has "maven" but package format doesn't follow Maven conventions)
- **Rationale**: Tests that URL keywords alone don't trigger Maven detection without proper package format

**Test Case 7.2: Strong Maven Indicators but Non-Maven Package Format**  

- **Collection URL**: `https://internal.nexus.company.com/repository/custom`
- **Package Name**: `single-word-package`
- **Repository**: `https://github.com/edge-case-vendor-2/has-maven-indicators`
- **Expected Behavior**: Should trigger generic collection URL provenance assistance (NOT Maven-specific)
- **Maven Detection**: False (has strong Maven indicators like "nexus" but package format is not Maven-style)
- **Rationale**: Tests that strong indicators must be combined with proper package format

**Test Case 7.3: Complex Maven Coordinate**  

- **Collection URL**: `https://artifactory.complex.com/artifactory/maven-central`
- **Package Name**: `com.complex:artifact:jar:classifier`
- **Repository**: `https://github.com/complex-case-vendor/complex-maven-case`
- **Expected Behavior**: Should trigger Maven-specific provenance assistance
- **Maven Detection**: High confidence (Artifactory + maven-central + complex but valid Maven coordinate)
- **Rationale**: Tests handling of Maven coordinates with additional classifiers

### 8. Repository-Only Cases

**Test Case 8.1: Repository Without Collection URL**  

- **Repository**: `https://github.com/no-collection-vendor/only-repo-product`
- **Expected Behavior**: Should show only repository provenance links
- **Maven Detection**: N/A (no collection URL to analyze)

**Test Case 8.2: Collection URL Without Package Name**  

- **Collection URL**: `https://example-repo.com/packages`
- **Expected Behavior**: Should not show collection URL provenance links (requires both URL and package name)
- **Maven Detection**: N/A (no package name to analyze)

### 9. Unicode and Special Character Handling

**Test Case 9.1: Unicode in Package Names**  

- **Collection URL**: `https://repo1.maven.org/maven2`
- **Package Name**: `org.unicode:测试包:jar`
- **Repository**: `https://github.com/unicode-test-vendor/unicode-包名`
- **Expected Behavior**: Should trigger Maven-specific provenance assistance with proper Unicode handling
- **Maven Detection**: High confidence (official Maven Central + Maven coordinate format with Unicode)
- **Rationale**: Tests Unicode normalization and handling in Maven coordinates

## Validation Points

### Description Assistance  

The description provenance assistance should correctly handle:  

1. **Multi-Language Support**: Buttons for each available language (en, es, fr, de, ja)
2. **Multiple Sources**: Separate cards for CNA and multiple ADP sources
3. **Source Role Labeling**: Clear indication of "CNA Description(s)" vs "ADP Description(s)"
4. **Button Layout**: Single language uses centered layout, multiple languages use wrapped layout
5. **Content Toggle**: Clicking buttons should properly toggle description content display

### Reference Assistance

The reference provenance assistance should correctly process:

1. **Target Tag Filtering**: Only process references with tags: patch, mitigation, product, issue-tracking
2. **Tag Consolidation**: Group references by tag type into separate cards
3. **Duplicate URL Handling**: Consolidate identical URLs within the same tag category
4. **Multi-Tag References**: Show same URL in multiple cards if it has multiple target tags
5. **Source Attribution**: Track which sources provided each reference
6. **Tag Formatting**: Display formatted tag names ("Issue Tracking" instead of "issue-tracking")

### Maven Repository Detection

The `isMavenRepository()` function should correctly identify Maven repositories based on:

1. **Known Maven patterns**: Official Maven Central URLs, Maven path indicators (/maven2/, /m2/, etc.)
2. **Enterprise Maven patterns**: Nexus, Artifactory paths and identifiers
3. **Strong Maven indicators**: Combined with proper package format validation
4. **Package format validation**: Maven coordinates (groupId:artifactId format with proper structure)

### WordPress Integration

The WordPress detection should work in combination with other features:

1. **Source-Based Detection**: Recognize WordFence and WP Scan by source IDs
2. **URL-Based Detection**: Recognize WordPress.org URLs in collection URLs or repositories
3. **Multi-Feature Integration**: Work alongside description and reference assistance
4. **Platform-Specific Assistance**: Generate appropriate WordPress platform cards when detected

### Provenance Assistance Types

The test validates four main types of provenance assistance:

1. **Description-based**: Language buttons for different source descriptions
2. **Reference-based**: Tag-specific cards for actionable reference links
3. **Maven-specific**: Special handling for Maven repositories with groupId/artifactId awareness
4. **WordPress-specific**: Special handling for WordPress plugins with Maintainer Profile, Plugin Tracking, and Changelog links
5. **Generic collection**: Standard collection URL + package name combination for non-Maven repositories

### Error Prevention

The test ensures that:

- **False positives are avoided**: URLs with Maven keywords but non-Maven package formats don't trigger Maven-specific assistance
- **Proper validation**: Both URL patterns AND package format must align for Maven detection
- **Graceful degradation**: Non-Maven repositories fall back to generic collection URL assistance
- **Reference filtering**: Only actionable reference tags create cards
- **Source consolidation**: Multiple sources providing same references are properly consolidated

## Expected Outcomes

When processing this test file, the generated HTML should demonstrate:

### Description Assistance (Expected)

1. **Multi-source description cards** showing CNA and 2 ADP sources
2. **Language buttons** for en, es, fr, de (CNA) and en, ja (ADP1) and en (ADP2)
3. **Proper source labeling** with "CNA Description(s)" and "ADP Description(s)"
4. **Layout adaptation** with centered buttons for single languages, wrapped layout for multiple

### Reference Assistance (Expected)

1. **Target tag processing** creating cards for patch, mitigation, product, and issue-tracking tags
2. **Multi-source consolidation** showing references from CNA and multiple ADP sources
3. **Duplicate handling** consolidating identical URLs within tag categories
4. **Multi-tag distribution** showing multi-tagged references in multiple cards
5. **Tag filtering** ignoring references with only non-target tags

### Maven Repository Detection (Expected)

1. **Correct Maven detection** for the 7 Maven test cases
2. **Maven-specific assistance** with Official Search Interface and Central Repository buttons
3. **Correct non-Maven handling** for the 4 non-Maven package repositories
4. **Generic collection assistance** for non-Maven repositories

### WordPress Integration (Expected)

1. **WordPress-specific assistance** for the 2 WordPress cases
2. **Source-based detection** recognizing WordFence by source ID
3. **Combined functionality** showing both reference cards AND WordPress platform cards

### Platform Assistance Integration (Expected)

1. **Repository-only assistance** for cases without collection URLs or package names
2. **Proper edge case handling** for the 3 complex scenarios
3. **Unicode handling** for international package names
4. **Multi-feature coordination** where applicable entries show multiple types of assistance

### Visual Consistency (Expected)

1. **Consistent card styling** across all provenance assistance types
2. **Proper button layouts** with appropriate spacing and alignment
3. **Clear visual hierarchy** distinguishing between different assistance types
4. **Responsive design** working properly with different numbers of buttons/cards

## Usage

### Automated Test Suite (Recommended)

The test suite is **self-contained** and automatically generates the required HTML from test data:

```bash
cd test_files
python test_provenance_assistance.py testProvenanceAssistance.json
```

This command will:

1. **Generate HTML**: Automatically create `CVE-1337-99998.html` from the test data
2. **Run Tests**: Execute all 10 automated validation tests
3. **Report Results**: Display comprehensive test results with 100% pass rate expected

### Manual HTML Generation (Optional)

If you need to generate HTML separately for manual inspection:

```bash
cd src/analysis_tool
python analysis_tool.py --test-file "../../test_files/testProvenanceAssistance.json"
```

The generated HTML file will be located at:

```text
E:\Git\Analysis_Tools\test_output\CVE-1337-99998.html
```

### Expected Test Output

```text
Starting Provenance Assistance Automated Test Suite
============================================================
🔄 Generating HTML from test data...
✅ HTML generated successfully: CVE-1337-99998.html
📊 Test Results Summary
============================================================
✅ PASS HTML_GENERATION - Generated CVE-1337-99998.html
✅ PASS PROVENANCE_STRUCTURE - All 20 provenance containers found
✅ PASS GLOBAL_METADATA - Global metadata valid with 3 description sources
✅ PASS DESCRIPTION_DATA - All 3 description sources found with correct languages
✅ PASS REFERENCE_DATA - Reference data complete: 16 total references
✅ PASS PLATFORM_VARIETY - Platform variety correct: 8 Maven, 8 non-Maven, 2 WordPress
✅ PASS WORDPRESS_DETECTION - WordFence source properly detected
✅ PASS UNICODE_HANDLING - Unicode test case found in platform data
✅ PASS JAVASCRIPT_FUNCTIONS - All required JavaScript functions found
✅ PASS JAVASCRIPT_INIT - JavaScript initialization found
============================================================
📈 Overall Results: 10/10 tests passed (100.0%)
🎉 All tests passed! The provenance assistance functionality is working correctly.
```

## Test Verification Instructions

To manually verify that all provenance assistance features are working correctly, follow these steps after generating the HTML:

### Step 1: Open the Generated HTML

```bash
# Navigate to the generated file
E:\Git\Analysis_Tools\test_output\CVE-1337-99998.html
```

### Step 2: Verify Description Assistance

**Check for Description Cards:**  

1. Look for description cards in each platform entry's provenance assistance section
2. Should see **3 separate description source cards**:
   - "CNA Description(s)" (ProvenanceTestOrg)
   - "ADP Description(s)" (TechSecurityCorp)
   - "ADP Description(s)" (WordFence)

**Test Language Buttons:**  

1. **CNA Card**: Should have 4 language buttons (en, es, fr, de)
2. **TechSecurityCorp ADP Card**: Should have 2 language buttons (en, ja)
3. **WordFence ADP Card**: Should have 1 centered language button (en)

**Test Button Functionality:**  

1. Click each language button
2. Verify description content appears/disappears
3. Verify content is in the correct language
4. Verify only one description shows at a time per source

### Step 3: Verify Reference Assistance

**Check for Reference Cards:**
Look for reference cards with these specific tags:

1. **"Patch" Card**: Should show multiple patch references from different sources
2. **"Issue Tracking" Card**: Should show GitHub issues and Bugzilla entries
3. **"Mitigation" Card**: Should show security mitigation resources
4. **"Product" Card**: Should show product-specific security pages

**Test Reference Consolidation:**  

1. Verify that references with the same tag appear in the same card
2. Verify that multi-tagged references appear in multiple cards
3. Verify that non-target tags (mailing-list, vendor-advisory, third-party-advisory) do NOT create cards

**Test Reference Buttons:**  

1. Click each reference button
2. Verify correct URLs open in new tabs
3. Verify button text shows appropriate names or URLs

### Step 4: Verify Maven Repository Detection

**Maven Test Cases (Should show Maven-specific assistance):**  

1. **Row 0**: Apache Commons Collections (repo1.maven.org)
2. **Row 1**: Spring Framework (repo.maven.apache.org)
3. **Row 2**: Enterprise Nexus (nexus.enterprise.com)
4. **Row 3**: Artifactory (artifactory.mycompany.com)
5. **Row 4**: Sonatype OSS (oss.sonatype.org)
6. **Row 5**: JitPack (jitpack.io)
7. **Row 6**: Clojars (clojars.org)

**For each Maven case, verify:**  

- "Maven Repository" card appears
- "Official Search Interface" button links to central.sonatype.com
- "Central Repository" button links to repo.maven.apache.org with correct path

**Non-Maven Test Cases (Should show generic collection assistance):**  

1. **Row 7**: Python PyPI
2. **Row 8**: NPM Registry
3. **Row 9**: RubyGems
4. **Row 10**: NuGet

**For each non-Maven case, verify:**  

- "Collection URL" card appears (NOT "Maven Repository")
- "Collection URL Only" button
- "Combined with Package Name" button

### Step 5: Verify WordPress Integration

**WordPress Test Cases:**  

1. **Row 11**: WordPress Plugin (downloads.wordpress.org)
2. **Row 12**: WordPress Plugin (wordpress.org/plugins)

**For WordPress cases, verify:**  

- "WordPress Platform" card appears
- "Maintainer Profile" button (if vendor present)
- "Plugin Tracking (Product)" button
- "Plugin Changelog (Product)" button
- Additional "Package" buttons if package name differs from product

**WordPress Source Detection:**  

- Verify that entries also show WordPress-specific assistance due to WordFence source detection
- Check that both reference cards AND WordPress platform cards appear together

### Step 6: Verify Edge Cases

**Test Case: Maven-like URL but Non-Maven Package (Row 14)**  

- Should show "Collection URL" card (NOT "Maven Repository")
- URL contains "maven" but package format is not Maven-style

**Test Case: Strong Maven Indicators but Wrong Package Format (Row 15)**  

- Should show "Collection URL" card (NOT "Maven Repository")  
- Has "nexus" in URL but single-word package name

**Test Case: Complex Maven Coordinate (Row 16)**  

- Should show "Maven Repository" card
- Package name has classifier but still valid Maven format

### Step 7: Verify Repository-Only and Incomplete Cases

**Repository-Only Case (Row 17):**  

- Should show only "Repository" card
- No collection URL cards

**Collection-Only Case (Row 18):**  

- Should show no collection URL cards (requires both URL and package name)
- May show repository card if present

### Step 8: Verify Unicode Handling

**Unicode Test Case (Row 19):**  

- Should properly handle Unicode characters in package names
- Should show "Maven Repository" card with Unicode package name
- All buttons should work correctly

### Common Issues to Check For

**Visual Issues:**  

- All cards should have consistent styling
- Buttons should be properly aligned
- No overlapping or misaligned elements
- Cards should be properly spaced

**Functional Issues:**  

- All buttons should be clickable
- URLs should open in new tabs
- Description content should toggle correctly
- No JavaScript errors in browser console

**Logic Issues:**  

- Maven detection should be precise (no false positives/negatives)
- Reference tags should be filtered correctly
- Duplicate references should be handled properly
- Multi-source data should be consolidated appropriately

### Success Criteria

The test passes if:

1. ✅ All 3 description source cards appear with correct language buttons
2. ✅ All 4 reference tag cards appear with appropriate consolidation
3. ✅ 7 Maven cases show Maven-specific assistance
4. ✅ 4 non-Maven cases show generic collection assistance  
5. ✅ 2 WordPress cases show WordPress-specific assistance
6. ✅ 3 edge cases behave as expected
7. ✅ Unicode case handles international characters correctly
8. ✅ All buttons function correctly without errors
9. ✅ Visual layout is consistent and professional
10. ✅ No false positives or missed detections occur

---

## Managing and Extending the Test Suite

### Test Suite Files Overview

The provenance assistance test suite consists of several key files:

**Core Test Files:**  

- `testProvenanceAssistance.json` - The main test data file containing all test cases
- `test_provenance_assistance.py` - Automated test script that validates functionality  
- `testProvenanceAssistance_Documentation.md` - This documentation file
- `../test_output/CVE-1337-99998.html` - Generated HTML output for testing

**Generated Output:**  

- HTML files for tests are generated in `../test_output/` when running test scripts
- HTML files for production are generated in `runs/[timestamp]_[context]/generated_pages/` when running the analysis tool
- The test suite specifically looks for `CVE-1337-99998.html` as the test output

### Adding New Test Cases

#### 1. Adding Platform/Provenance Test Cases

To add a new platform test case to `testProvenanceAssistance.json`:

```json
{
  "vendor": "your-vendor-name",
  "product": "your-product-name", 
  "collectionURL": "https://repository.example.com/path",
  "packageName": "optional-package-name",
  "repo": "optional-repository-url"
}
```

**Platform Types to Consider:**

- **Maven**: Include "maven" in collectionURL or use known Maven repositories
- **Non-Maven**: PyPI, npm, RubyGems, NuGet, Go modules, etc.
- **WordPress**: Include "wordpress" in vendor or collectionURL
- **Edge Cases**: Complex scenarios, partial data, special characters

**Guidelines:**

- Use descriptive vendor/product names that indicate the test purpose
- Include Unicode characters to test internationalization
- Mix complete and partial data scenarios
- Test various repository URL patterns

#### 2. Adding Description Test Cases

To add new description sources in the `descriptions` array:

```json
{
  "lang": "language-code",
  "value": "Description text in the specified language...",
  "supportingMedia": [
    {
      "base64": false,
      "type": "text/html", 
      "value": "HTML formatted description..."
    }
  ]
}
```

Add corresponding entries to `sources`:

```json
{
  "source": {
    "definingOrganization": "Organization Name",
    "dateFiled": "2024-06-15T10:00:00.000Z"
  },
  "descriptions": ["description-array-index"],
  "references": ["reference-array-index"],
  "sourceRole": "CNA"  // or "ADP"
}
```

**Description Testing Guidelines:**

- Test multiple languages per source (en, es, fr, de, ja, etc.)
- Include both CNA and ADP sources
- Test single-language and multi-language scenarios
- Include HTML formatting in supportingMedia when needed

#### 3. Adding Reference Test Cases

To add new references in the `references` array:

```json
{
  "url": "https://example.com/reference-url",
  "name": "Reference display name",
  "tags": ["target-tag-1", "target-tag-2"]
}
```

**Target Tags for Testing:**

- `"patch"` - Code fixes, commits, pull requests
- `"issue-tracking"` - Bug reports, issue trackers
- `"mitigation"` - Security advisories, mitigation guides  
- `"product"` - Product pages, official documentation

**Reference Testing Guidelines:**

- Include references with single and multiple target tags
- Test duplicate URLs across different sources
- Include references with non-target tags (should be ignored)
- Test WordPress-specific reference patterns
- Mix URLs from different domains and platforms

#### 4. Updating Test Validation

When adding new test cases, update the automated test script expectations:

**In `test_provenance_assistance.py`:**

```python
# Update expected counts in test methods
def test_platform_variety(self):
    # Update these counts based on new test cases
    expected_maven = 8      # Increment for new Maven cases
    expected_non_maven = 8  # Increment for new non-Maven cases  
    expected_wordpress = 2  # Increment for new WordPress cases
    # ...

def test_description_data_completeness(self):
    # Update expected sources
    expected_sources = {
        ('ProvenanceTestOrg', 'CNA'): ['en', 'es', 'fr', 'de'],
        ('TechSecurityCorp', 'ADP'): ['en', 'ja'],
        ('WordFence', 'ADP'): ['en']
        # Add new sources here
    }
```

### Running Tests After Changes

#### 1. Regenerate HTML Output

After modifying `testProvenanceAssistance.json`:

```powershell
cd "e:\Git\Analysis_Tools\src\analysis_tool"
python analysis_tool.py "../../test_files/testProvenanceAssistance.json"
```

This generates fresh HTML in `test_output/CVE-1337-99998.html`.

#### 2. Run Automated Test Suite

**Self-Contained Execution (Recommended):**

```powershell
cd "e:\Git\Analysis_Tools\test_files"
python test_provenance_assistance.py testProvenanceAssistance.json
```

This automatically generates the HTML and runs all tests in one command.

**Separate Steps (If Needed):**

```powershell
# Step 1: Generate HTML (optional - done automatically by test script)
cd "e:\Git\Analysis_Tools\src\analysis_tool"
python analysis_tool.py --test-file "../../test_files/testProvenanceAssistance.json"

# Step 2: Run tests
cd "../../test_files"
python test_provenance_assistance.py testProvenanceAssistance.json
```

#### 3. Manual Validation

Open the generated HTML file in a browser to manually verify:

- Visual layout and styling
- Button functionality and interactions
- Correct content display
- No JavaScript errors in browser console

### Test Data Validation Guidelines

#### JSON Structure Validation

Ensure your test JSON follows the CVE 5.1 schema:

```json
{
  "dataType": "CVE_RECORD", 
  "dataVersion": "5.1",
  "cveMetadata": {
    "cveId": "CVE-1337-99998",
    // ... metadata
  },
  "containers": {
    "cna": {
      "affected": [/* platform data */],
      "descriptions": [/* description data */],
      "references": [/* reference data */],
      // ... other CNA data
    },
    "adp": [
      {
        "descriptions": [/* ADP descriptions */],
        "references": [/* ADP references */],
        // ... other ADP data
      }
      // Additional ADP containers
    ]
  }
}
```

#### Data Integrity Checks

Before running tests, verify:

1. **Array Indices**: Sources reference correct array indices for descriptions/references
2. **Required Fields**: All vendors have required `vendor` and `product` fields
3. **URL Formats**: All URLs are properly formatted and valid
4. **Language Codes**: Use valid ISO language codes (en, es, fr, de, ja, etc.)
5. **Tag Consistency**: Reference tags match expected target tags in the test script

### Test Maintenance

#### Regular Maintenance Tasks

1. **Update Dependencies**: Keep BeautifulSoup4 and other dependencies current
2. **Verify Test Coverage**: Ensure new features have corresponding test cases
3. **Update Documentation**: Keep this documentation synchronized with test changes
4. **Review Test Data**: Periodically review test cases for realism and completeness

#### Before Migration to Python

When migrating provenance logic from JavaScript to Python:

1. **Baseline Test**: Run current test suite and document all results
2. **Implementation**: Implement new Python provenance logic
3. **Comparison Test**: Run test suite against new implementation
4. **Regression Analysis**: Compare results and address any differences
5. **Update Tests**: Modify test expectations if behavior intentionally changes

#### Troubleshooting Common Issues

**Test Failures:**

- Verify file paths are correct for your environment
- Check that HTML was regenerated after JSON changes
- Ensure all required dependencies are installed
- Validate JSON syntax with a JSON validator

**Unicode Issues:**

- Ensure files are saved with UTF-8 encoding
- Test Unicode handling in both JSON and HTML output
- Verify browser can display international characters

**Platform Detection Issues:**

- Check collectionURL patterns match detection logic
- Verify vendor/product names don't conflict with detection rules
- Test edge cases thoroughly

### Integration with Development Workflow

#### Git Workflow

```bash
# Before making changes
git checkout -b feature/new-test-cases

# After adding test cases
git add test_files/testProvenanceAssistance.json
git add test_files/testProvenanceAssistance_Documentation.md
git add test_files/test_provenance_assistance.py  # if modified

# Regenerate and test
cd test_files
python test_provenance_assistance.py testProvenanceAssistance.json

# Commit only if tests pass
git commit -m "Add new provenance test cases for [feature description]"
```

#### Continuous Integration

For automated testing in CI/CD:

```yaml
# Example GitHub Actions workflow
- name: Run Provenance Tests
  run: |
    cd test_files
    python test_provenance_assistance.py testProvenanceAssistance.json
```

**Benefits of Self-Contained Tests:**

- Simplified CI/CD pipelines (single command)
- No file dependency management required  
- Automatic HTML generation ensures tests always run against fresh output
- Exit codes provide clear pass/fail status for automation

This comprehensive test suite serves as both a validation tool and a regression baseline for ongoing development of the provenance assistance features.
