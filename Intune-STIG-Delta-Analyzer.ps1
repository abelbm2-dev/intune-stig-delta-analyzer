<#
.SYNOPSIS
    Intune STIG Delta Analyzer

.DESCRIPTION
    Compares two Intune Settings Catalog STIG JSON exports and generates
    administrator-friendly delta reports for STIG review.

.VERSION
    1.0

.SUPPORTED
    - Intune Settings Catalog JSON exports

.NOT SUPPORTED IN V1
    - Endpoint Security policy exports
    - Security Baselines
    - Custom OMA-URI policies
    - Compliance policies

.FUTURE ENHANCEMENTS
    - Endpoint Security policy comparison
    - Security Baseline comparison
    - POAM correlation
    - Automated DISA/STIG delta validation

.COMPARISON METHOD
    - Compares settings by settingDefinitionId
    - Displays friendly category and setting names
    - Hides raw Microsoft Graph structure unless troubleshooting mode is enabled
    - Normalizes formatting-only differences before comparison

.OUTPUT
    - Console report
    - CSV report
    - Append-only execution log

.CLM COMPATIBILITY
    Designed to avoid:
    - Reflection
    - Dynamic code execution
    - Add-Type
    - External module dependency
#>

[CmdletBinding()]
param(
    [ValidateSet("None", "Basic", "Deep")]
    [string]$TroubleshootingMode = "None"
)

# ============================================================
# GLOBAL CONFIGURATION
# ============================================================

$ScriptRoot = "C:\Repo\Script_Comparison"
$ReportPath = Join-Path $ScriptRoot "Reports"
$LogPath = Join-Path $ScriptRoot "STIG_Comparison.log"

$CategoryMappingPath = Join-Path $ScriptRoot "CategoryMappings.json"
$FriendlyNameMapPath = Join-Path $ScriptRoot "FriendlyNameMappings.json"
$TranslationProfilePath = Join-Path $ScriptRoot "TranslationProfiles.json"

$Global:CategoryMappings = $null
$Global:FriendlyNameMappings = $null
$Global:TranslationProfiles = $null

# ============================================================
# BASIC HELPERS
# ============================================================

function Test-Blank {
    param(
        [object]$Value
    )

    if ($null -eq $Value) {
        return $true
    }

    $text = "$Value"
    $text = $text -replace "^\s+", ""
    $text = $text -replace "\s+$", ""

    if ($text -eq "") {
        return $true
    }

    return $false
}

function Test-Property {
    param(
        [object]$Object,
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $false
    }

    $property = $Object.PSObject.Properties[$PropertyName]

    if ($null -eq $property) {
        return $false
    }

    return $true
}

function Get-PropertyValue {
    param(
        [object]$Object,
        [string]$PropertyName
    )

    if (Test-Property -Object $Object -PropertyName $PropertyName) {
        return $Object.PSObject.Properties[$PropertyName].Value
    }

    return $null
}

function Convert-ToComparableText {
    param(
        [object]$Value
    )

    if ($null -eq $Value) {
        return ""
    }

    $text = "$Value"
    $text = $text -replace "^\s+", ""
    $text = $text -replace "\s+$", ""

    return $text
}

# ============================================================
# INITIALIZATION AND LOGGING
# ============================================================

function Initialize-Repository {

    if (-not (Test-Path $ScriptRoot)) {
        New-Item -Path $ScriptRoot -ItemType Directory -Force | Out-Null
    }

    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
    }

    Initialize-MappingFiles
    Import-MappingFiles
}

function Write-ExecutionLog {
    param(
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp`t$Message"

    Add-Content -Path $LogPath -Value $entry
}

function Initialize-MappingFiles {

    if (-not (Test-Path $CategoryMappingPath)) {

        $defaultCategoryMappings = @"
{
    "audit": "Auditing",
    "userrights": "User Rights Assignment",
    "defender": "Microsoft Defender",
    "microsoftdefender": "Microsoft Defender",
    "attack_surface_reduction": "Attack Surface Reduction",
    "asr": "Attack Surface Reduction",
    "firewall": "Firewall",
    "wifi": "Wi-Fi",
    "bitlocker": "BitLocker",
    "browser": "Browser",
    "edge": "Browser",
    "internetexplorer": "Browser",
    "credentialguard": "Credential Guard",
    "deviceguard": "Device Guard",
    "remotedesktop": "Remote Desktop Services",
    "smartscreen": "SmartScreen",
    "explorer": "File Explorer",
    "logon": "Windows Logon",
    "power": "Power Management",
    "connectivity": "Connectivity",
    "devicelock": "Device Lock",
    "passportforwork": "Windows Hello for Business",
    "whfb": "Windows Hello for Business",
    "privacy": "Privacy",
    "windowsai": "Windows AI",
    "windowsinkworkspace": "Windows Ink Workspace",
    "credentialproviders": "Credential Providers",
    "autoplay": "AutoPlay",
    "localpoliciessecurityoptions": "Local Policies Security Options"
}
"@

        Set-Content -Path $CategoryMappingPath -Value $defaultCategoryMappings
    }

    if (-not (Test-Path $FriendlyNameMapPath)) {

        $defaultFriendlyNameMappings = @"
{
    "audit_objectaccess_audithandlemanipulation": "Object Access - Audit Handle Manipulation",
    "audit_objectaccess_auditfilesystem": "Object Access - Audit File System",
    "audit_objectaccess_auditregistry": "Object Access - Audit Registry",
    "audit_logonlogoff_auditlogon": "Logon Logoff - Audit Logon",
    "audit_logonlogoff_auditlogoff": "Logon Logoff - Audit Logoff",
    "audit_accountlogon_auditcredentialvalidation": "Account Logon - Audit Credential Validation",

    "userrights_allowlogonlocally": "Allow Log On Locally",
    "userrights_denylogonlocally": "Deny Log On Locally",
    "userrights_allowlogonthroughremotedesktopservices": "Allow Log On Through Remote Desktop Services",
    "userrights_denylogonthroughremotedesktopservices": "Deny Log On Through Remote Desktop Services",
    "userrights_debugprograms": "Debug Programs",
    "userrights_impersonateaclientafterauthentication": "Impersonate A Client After Authentication",
    "userrights_accessthiscomputerfromthenetwork": "Access This Computer From The Network",
    "userrights_denyaccesstothiscomputerfromthenetwork": "Deny Access To This Computer From The Network",
    "userrights_backupthefilesanddirectories": "Back Up Files And Directories",
    "userrights_restorefilesanddirectories": "Restore Files And Directories",
    "userrights_takeownershipoffilesorotherobjects": "Take Ownership Of Files Or Other Objects",

    "defender_allowrealtimemonitoring": "Allow Real-Time Monitoring",
    "defender_allowcloudprotection": "Allow Cloud Protection",
    "defender_submitunknownsamples": "Submit Unknown Samples",
    "defender_checkforsignaturesbeforerunningscan": "Check For Signatures Before Running Scan",
    "defender_scanremovabledrivesduringfullscan": "Scan Removable Drives During Full Scan",
    "defender_allowbehaviormonitoring": "Allow Behavior Monitoring",
    "defender_allowioavprotection": "Allow IOAV Protection",

    "browser_allowpasswordmanager": "Allow Password Manager",
    "wifi_allowautoconnecttowifisensehotspots": "Allow Auto Connect To Wi-Fi Sense Hotspots"
}
"@

        Set-Content -Path $FriendlyNameMapPath -Value $defaultFriendlyNameMappings
    }

    if (-not (Test-Path $TranslationProfilePath)) {

        $defaultTranslationProfiles = @"
{
    "Audit": {
        "0": "No Auditing",
        "1": "Success",
        "2": "Failure",
        "3": "Success + Failure"
    },
    "EnableDisable": {
        "true": "Enabled",
        "false": "Disabled",
        "1": "Enabled",
        "0": "Disabled",
        "enabled": "Enabled",
        "disabled": "Disabled",
        "enable": "Enabled",
        "disable": "Disabled"
    },
    "BlockAllow": {
        "true": "Blocked",
        "false": "Allowed",
        "1": "Blocked",
        "0": "Allowed",
        "block": "Blocked",
        "blocked": "Blocked",
        "allow": "Allowed",
        "allowed": "Allowed",
        "enabled": "Blocked",
        "disabled": "Allowed"
    },
    "Default": {
        "true": "Enabled",
        "false": "Disabled",
        "1": "Enabled",
        "0": "Disabled"
    }
}
"@

        Set-Content -Path $TranslationProfilePath -Value $defaultTranslationProfiles
    }
}

function Import-MappingFiles {

    try {
        $Global:CategoryMappings =
            Get-Content -Path $CategoryMappingPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop

        $Global:FriendlyNameMappings =
            Get-Content -Path $FriendlyNameMapPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop

        $Global:TranslationProfiles =
            Get-Content -Path $TranslationProfilePath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Failed to load mapping files. Error: $($_.Exception.Message)"
    }
}

# ============================================================
# INPUT AND VALIDATION
# ============================================================

function Get-JsonFilePath {
    param(
        [string]$PromptMessage
    )

    $path = Read-Host $PromptMessage

    if (-not (Test-Path $path)) {
        throw "File not found: $path"
    }

    return $path
}

function Import-StigJson {
    param(
        [string]$Path
    )

    try {
        $content = Get-Content -Path $Path -Raw -ErrorAction Stop
        $json = $content | ConvertFrom-Json -ErrorAction Stop
        return $json
    }
    catch {
        throw "Unable to read or parse JSON file: $Path. Error: $($_.Exception.Message)"
    }
}

function Get-PolicyType {
    param(
        [object]$JsonObject
    )

    $jsonText = $JsonObject | ConvertTo-Json -Depth 100

    if ($jsonText -match "templateFamily" -and $jsonText -match "endpointSecurity") {
        return "EndpointSecurity"
    }

    if ($jsonText -match "settingDefinitionId") {
        return "SettingsCatalog"
    }

    return "Unknown"
}

function Test-SupportedPolicyType {
    param(
        [object]$JsonObject,
        [string]$FilePath
    )

    $policyType = Get-PolicyType -JsonObject $JsonObject

    if ($policyType -eq "SettingsCatalog") {
        return $true
    }

    if ($policyType -eq "EndpointSecurity") {
        throw "Unsupported policy type detected in '$FilePath'. Version 1 supports Intune Settings Catalog exports only. Endpoint Security support may be added in a future update."
    }

    throw "Unsupported or unknown JSON structure detected in '$FilePath'. No supported Settings Catalog settingDefinitionId structure was found."
}

# ============================================================
# CATEGORY AND FRIENDLY NAME TRANSLATION
# ============================================================

function Get-CategoryName {
    param(
        [string]$SettingDefinitionId
    )

    if (Test-Blank -Value $SettingDefinitionId) {
        return "Unknown"
    }

    foreach ($property in $Global:CategoryMappings.PSObject.Properties) {
        $key = $property.Name
        $value = $property.Value

        if ($SettingDefinitionId -match $key) {
            return $value
        }
    }

    return "Unknown"
}

function ConvertTo-FriendlySettingName {
    param(
        [string]$SettingDefinitionId
    )

    if (Test-Blank -Value $SettingDefinitionId) {
        return "Unknown Setting"
    }

    $name = "$SettingDefinitionId"

    $name = $name -replace "device_vendor_msft_policy_config_", ""
    $name = $name -replace "user_vendor_msft_policy_config_", ""
    $name = $name -replace "vendor_msft_policy_config_", ""
    $name = $name -replace "_\d+$", ""

    foreach ($property in $Global:FriendlyNameMappings.PSObject.Properties) {
        if ($name -ieq $property.Name) {
            return $property.Value
        }
    }

    $friendly = $name -replace "_", " "
    $friendly = $friendly -replace "^\s+", ""
    $friendly = $friendly -replace "\s+$", ""

    if ($friendly -eq "") {
        return "Unknown Setting"
    }

    return $friendly
}

function Get-TranslationConfidence {
    param(
        [string]$Category,
        [string]$SettingName
    )

    if ($Category -ne "Unknown") {
        return "Medium"
    }

    if (-not (Test-Blank -Value $SettingName)) {
        return "Low"
    }

  