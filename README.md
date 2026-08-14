# Settings Catalog STIG Delta Analyzer

A PowerShell-based utility for comparing Settings Catalog STIG (Security Technical Implementation Guide) JSON exports and generating detailed delta reports.

## Features

- **Baseline Comparison**: Compare two Settings Catalog JSON exports (e.g., v2r7 vs v2r8)
- **Delta Reporting**: Identifies Added, Removed, and Modified STIG settings
- **Friendly Names**: Translates technical STIG IDs into human-readable category and setting names
- **CSV Export**: Generates structured CSV reports for documentation and auditing
- **Append-Only Logging**: Maintains execution history in a persistent log file
- **Value Translation**: Converts raw policy values (0/1/2/3, true/false) to friendly descriptors

## Supported Formats

- Settings Catalog JSON exports
- DoD STIG Settings Catalog files (e.g., "DoD Windows 11 STIG v2rX Settings Catalog.json")

## Not Supported in v1

- Endpoint Security policy exports
- Security Baselines
- Custom OMA-URI policies
- Compliance policies

## Quick Start Guide

### Prerequisites

- Windows 10 or Windows 11
- PowerShell 5.1 or higher (PowerShell 7+ recommended)
- Two Settings Catalog JSON export files to compare
- Read/Write permissions to the script directory

### Step 1: Prepare Your JSON Files

Before running the script, you need two JSON files exported from your Settings Catalog STIG sources.

**What you need:**
- `baseline.json` - The older version (e.g., DoD Windows 11 STIG v2r7 Settings Catalog.json)
- `current.json` - The newer version (e.g., DoD Windows 11 STIG v2r8 Settings Catalog.json)

**Example file locations:**
```
C:\STIG\DoD Windows 11 STIG v2r7 Settings Catalog.json
C:\STIG\DoD Windows 11 STIG v2r8 Settings Catalog.json
```

### Step 2: Open PowerShell

1. Press `Win + R`
2. Type `powershell`
3. Press Enter

Your PowerShell window should open, showing a prompt like:
```
PS C:\Users\YourUsername>
```

### Step 3: Navigate to Script Directory

Use the `cd` command to navigate to where your scripts are located:

```powershell
cd 'C:\REPO\script_comparison'
```

You should see the prompt change to:
```
PS C:\REPO\script_comparison>
```

### Step 4: Run the Comparison Script

Execute the main comparison script:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File 'Intune-STIG-Delta-Analyzer.ps1'
```

## Detailed Walkthrough: What Happens Next

### Initial Prompt - Baseline File Path

When you run the script, you will see this prompt:

```
Enter the path to the previous STIG JSON file (baseline):
```

**What to enter:**
- Type the full path to your baseline (older) Settings Catalog JSON file
- Use the full file path including the filename and `.json` extension

**Example response:**
```
C:\STIG\DoD Windows 11 STIG v2r7 Settings Catalog.json
```

The script will then confirm:
```
✓ Baseline file found: C:\STIG\DoD Windows 11 STIG v2r7 Settings Catalog.json
File size: 1.2 MB | Settings count: 542
```

### Second Prompt - Current File Path

Next prompt:

```
Enter the path to the current STIG JSON file (target):
```

**What to enter:**
- Type the full path to your current (newer) Settings Catalog JSON file
- Again, include the full path with filename and extension

**Example response:**
```
C:\STIG\DoD Windows 11 STIG v2r8 Settings Catalog.json
```

Confirmation message:
```
✓ Current file found: C:\STIG\DoD Windows 11 STIG v2r8 Settings Catalog.json
File size: 1.3 MB | Settings count: 551
```

### Third Prompt - Troubleshooting Mode

Final prompt:

```
Enable troubleshooting mode for detailed error output? (Y/N):
```

**What to enter:**
- Type `Y` (or just press Enter, then type Y) for detailed troubleshooting information
- Type `N` (or just press Enter, then type N) for normal mode
- Most users should select `N` unless troubleshooting issues

**Example response:**
```
N
```

## Scripts

### Intune-STIG-Delta-Analyzer.ps1

**Purpose:** Main comparison script that analyzes two Settings Catalog JSON files and generates reports.

**What it does:**
1. Loads your two JSON files
2. Compares all settings between them
3. Categorizes differences as Added, Removed, or Modified
4. Translates technical IDs to friendly names
5. Generates three types of output

**Usage:**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File 'Intune-STIG-Delta-Analyzer.ps1'
```

When prompted, provide:
1. Path to previous STIG JSON file (baseline)
2. Path to current STIG JSON file (target)
3. Troubleshooting mode preference (Y/N)

**Output:**
- Console: Color-coded report showing Modified, Added, and Removed items
- CSV: `stig_delta_report.csv` with columns: Status, Category, Setting, PreviousValue, CurrentValue
- Log: `stig_comparison.log` (appended with each execution)

## Configuration Files

### CategoryMappings.json
Maps STIG setting ID keywords to friendly category names (e.g., "audit" → "Auditing").

### FriendlyNameMappings.json
Direct mappings of setting IDs to human-readable setting names.

### TranslationProfiles.json
Value translation profiles for common policy value types:
- **Audit**: Converts 0/1/2/3 to No Auditing/Success/Failure/Success + Failure
- **EnableDisable**: Converts true/false/1/0 to Enabled/Disabled
- **BlockAllow**: Converts true/false to Blocked/Allowed
- **Default**: Generic true/false to Enabled/Disabled

## Example Output

### CSV Report (stig_delta_report.csv)
```
Status,Category,Setting,PreviousValue,CurrentValue
Modified,Auditing,Audit - System - Audit Other System Events,Not Configured,Enabled
Removed,Auditing,Audit - Object Access - Audit File System,Enabled,
Added,Microsoft Defender,Defender - Real-Time Monitoring,Enabled,
```

**How to use the CSV:**
1. Open in Microsoft Excel
2. Use Auto-Filter (Data → AutoFilter) to filter by Status
3. Sort by Category to group related changes
4. Print or email to stakeholders

**Note:** Values with newlines are displayed as multi-line in console output; in CSV and logs, newlines are replaced with `; ` for readability.

### Execution Log (stig_comparison.log)
```
========================================================
Execution Date: 2026-08-12 09:25:47
Previous STIG File: C:\REPO\DoD Windows 11 STIG v2r7 Settings Catalog.json
Current STIG File: C:\REPO\DoD Windows 11 STIG v2r8 Settings Catalog.json
Added Count: 0
Removed Count: 2
Modified Count: 2
Details:
 - Modified | device_vendor_msft_policy_config_audit_system_auditothersystemevents | Previous: Not Configured | Current: Enabled
 - Removed  | device_vendor_msft_policy_config_audit_objectaccess_auditfilesystem | Previous: Enabled
```

**How it works:**
- Appends execution history with each run
- Records date, file names, counts, and details
- Preserved across multiple runs for audit trail purposes
- Setting IDs are preserved in output for technical reference

## Project Structure

```
script_comparison/
├── Intune-STIG-Delta-Analyzer.ps1    (Main comparison script)
├── CategoryMappings.json             (Category name translations)
├── FriendlyNameMappings.json         (Setting ID to name mappings)
├── TranslationProfiles.json          (Value translation profiles)
├── stig_comparison.log               (Execution history log)
├── stig_delta_report.csv             (Latest comparison results)
└── README.md                         (This file)
```

## Troubleshooting

### Enabling Troubleshooting Mode

- PowerShell 5.1 or later
- Windows operating system
- Access to Settings Catalog JSON exports

This will display:
- Detailed error messages
- File parsing information
- Configuration loading status
- Raw setting definition IDs for debugging

### Common Issues
1. Download two STIG JSON exports from Intune Policy Package (month/year) (e.g., v2r7 and v2r8 releases)
2. Execute the delta analyzer script
   - Select the .json file, right click and choose *copy as path*
3. Review the generated CSV and log files
4. Use delta information for STIG update documentation and compliance tracking

**"File not found" error:**
- Verify the file path is correct
- Use the full absolute path
- Ensure filename matches exactly
- Check that you have read permissions

**Execution Policy Error:**
- Use the `-ExecutionPolicy Bypass` flag (already included in commands)

**No differences found:**
- Files may be identical versions
- Files may not be in expected format
- Enable troubleshooting mode for detailed messages

## Future Enhancements

- Endpoint Security policy comparison
- Security Baseline comparison
- POAM (Plan of Action and Milestones) correlation
- Automated DISA/STIG delta validation
- HTML report generation
- Email notification of significant changes

## License

MIT License - See LICENSE file for details

## Support

For issues or feature requests, open an issue in the GitHub repository.
