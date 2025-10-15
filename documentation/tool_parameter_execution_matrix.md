# Tool Parameter Execution Matrix

This matrix provides a complete reference for understanding how different argument combinations affect the analysis pipeline execution.  
This also shows how the --cpe-as-generator process needs to be refactored to align with the following architecture:

**Process → Collect → Save → Load → Universal Page**  
(This has been effective for the --sdc-report and --alias-report arguements as well as for the generateDatasetReport process.)  

The --cpe-suggestions process should remain broken out to enable a unique process for individual CPE search Criteria related responses.

| Combination | Init | CVE Query | Platform Data | CPE Gen | CPE Query | SDC Proc | CPE Sugg | Alias Ext | Conf Map | Badge Gen | HTML Gen | Browser |
|-------------|------|-----------|---------------|---------|-----------|----------|----------|-----------|----------|-----------|----------|---------|
| **Single Feature Modes** | | | | | | | | | | | | |
| `--sdc-report` | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `--cpe-suggestions` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `--alias-report` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `--cpe-as-generator` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| **Two Feature Combinations** | | | | | | | | | | | | |
| `--sdc-report --cpe-suggestions` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `--sdc-report --alias-report` | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `--sdc-report --cpe-as-generator` | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `--cpe-suggestions --alias-report` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `--cpe-suggestions --cpe-as-generator` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `--alias-report --cpe-as-generator` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Three Feature Combinations** | | | | | | | | | | | | |
| `--sdc-report --cpe-suggestions --alias-report` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `--sdc-report --cpe-suggestions --cpe-as-generator` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `--sdc-report --alias-report --cpe-as-generator` | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `--cpe-suggestions --alias-report --cpe-as-generator` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **All Features** | | | | | | | | | | | | |
| `--sdc-report --cpe-suggestions --alias-report --cpe-as-generator` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
