# Intune STIG Delta Analyzer

A PowerShell-based utility for comparing Intune Settings Catalog STIG (Security Technical Implementation Guide) JSON exports and generating detailed delta reports.

## Features

- **Baseline Comparison**: Compare two Intune Settings Catalog JSON exports (e.g., v2r7 vs v2r8)
- **Delta Reporting**: Identifies Added, Removed, and Modified STIG settings
- **Friendly Names**: Translates technical STIG IDs into human-readable category and setting names
- **CSV Export**: Generates structured CSV reports for documentation and auditing
- **Append-Only Logging**: Maintains execution history in a persistent log file
- **Value Translation**: Converts raw policy values (0/1/2/3, true/false) to friendly descriptors

## Supported Formats

- Intune Settings Catalog JSON exports
- DoD STIG Settings Catalog files (e.g., "DoD Windows 11 STIG v2rX Settings Catalog.json")

## Not Supported in v1

- Endpoint Security policy exports
- Security Baselines
- Custom OMA-URI policies
- Compliance policies

## Scripts

### Intune-STIG-Delta-Analyzer.ps1

Alternative analyzer script with additional configuration and translation profiles.

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

## Future Enhancements

- Endpoint Security policy comparison
- Security Baseline comparison
- POAM (Plan of Action and Milestones) correlation
- Automated DISA/STIG delta validation

## Requirements

- PowerShell 5.1 or later
- Windows operating system
- Access to Settings Catalog JSON exports

## Usage Scenario

1. Download two STIG JSON exports from Intune Policy Package (month/year) (e.g., v2r7 and v2r8 releases)
2. Execute the delta analyzer script
   - Select the .json file, right click and choose *copy as path*
3. Review the generated CSV and log files
4. Use delta information for STIG update documentation and compliance tracking

## Notes

- Values with newlines are displayed as multi-line in console output; in CSV and logs, newlines are replaced with `; ` for readability
- Setting IDs are preserved in output for technical reference
- Log file is append-only, preserving history of all comparisons
- Troubleshooting mode displays raw setting definition IDs for debugging

## License

MIT License - See LICENSE file for details

## Support

For issues or feature requests, open an issue in the repository.
