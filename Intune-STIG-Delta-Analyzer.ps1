<#
.SYNOPSIS
    Settings Catalog STIG Delta Analyzer

.DESCRIPTION
    Compares two Settings Catalog STIG JSON exports and generates
    administrator-friendly delta reports for STIG review.

.VERSION
    1.0

.SUPPORTED
    - Settings Catalog JSON exports

.NOT SUPPORTED IN V1
    - Endpoint Security policy exports
    - Security Baselines
    - Custom OMA-URI policies
    - Compliance policies

.FUTURE ENHANCEMENTS
    - Endpoint Security policy comparison
    - Security Baseline comparison
    - Automated DISA/STIG delta validation

.COMPARISON METHOD
    - Compares settings by settingDefinitionId
    - Displays friendly category and setting names
    - Hides raw Microsoft Graph structure unless troubleshooting mode is enabled
    - Normalizes formatting-only differences before comparison

.OUTPUT
    - Console report with color-coded differences
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
# CONSOLE COLOR OUTPUT FUNCTIONS
# ============================================================

function Write-ColorOutput {
    param(
        [string]$Message,
        [ValidateSet("Green", "Red", "Yellow", "Cyan", "White", "Gray")]
        [string]$Color = "White"
    )
    
    $hostColor = @{
        "Green"  = "Green"
        "Red"    = "Red"
        "Yellow" = "Yellow"
        "Cyan"   = "Cyan"
        "White"  = "White"
        "Gray"   = "Gray"
    }
    
    Write-Host $Message -ForegroundColor $hostColor[$Color]
}

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

function Normalize-ForDisplay {
    param(
        [object]$Value
    )
    
    if ($null -eq $Value) {
        return ""
    }
    
    $text = "$Value"
    # Replace newlines with semicolon separator for readability
    $text = $text -replace "`r`n", "; "
    $text = $text -replace "`n", "; "
    
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
        throw "Unsupported policy type detected in '$FilePath'. Version 1 supports Settings Catalog exports only. Endpoint Security support may be added in a future update."
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

    $categoryUnknown = ($Category -eq "Unknown")
    $settingBlank = (Test-Blank -Value $SettingName)
    
    # High confidence: both category and setting name are known
    if (-not $categoryUnknown -and -not $settingBlank) {
        return "High"
    }

    # Medium confidence: category is known
    if (-not $categoryUnknown) {
        return "Medium"
    }

    # Low confidence: only setting name exists
    if (-not $settingBlank) {
        return "Low"
    }
    
    # None/Unknown: both are unknown/blank
    return "None"
}

function Translate-PolicyValue {
    param(
        [object]$Value,
        [string]$Category,
        [string]$SettingName
    )

    $valueText = Convert-ToComparableText -Value $Value

    if (Test-Blank -Value $valueText) {
        return "Not Configured"
    }

    # Determine which profile to use
    $profile = "Default"

    if ($Category -match "audit|logon|logoff") {
        $profile = "Audit"
    }
    elseif ($SettingName -match "allow|block|blocked|allowed") {
        $profile = "BlockAllow"
    }

    # Try to translate using selected profile
    $profileObj = Get-PropertyValue -Object $Global:TranslationProfiles -PropertyName $profile
    
    if ($null -ne $profileObj) {
        $translated = Get-PropertyValue -Object $profileObj -PropertyName $valueText
        
        if (-not (Test-Blank -Value $translated)) {
            return $translated
        }
    }

    # Fallback to default profile
    $defaultProfile = Get-PropertyValue -Object $Global:TranslationProfiles -PropertyName "Default"
    if ($null -ne $defaultProfile) {
        $translated = Get-PropertyValue -Object $defaultProfile -PropertyName $valueText
        
        if (-not (Test-Blank -Value $translated)) {
            return $translated
        }
    }

    # Return value as-is if no translation found
    return $valueText
}

# ============================================================
# COMPARISON FUNCTIONS
# ============================================================

function Build-SettingsDictionary {
    param(
        [object]$JsonData
    )

    $dict = @{}

    # Handle both single object and array
    $items = @()
    if ($JsonData -is [System.Collections.IEnumerable] -and -not ($JsonData -is [string])) {
        $items = @($JsonData)
    }
    else {
        $items = @($JsonData)
    }

    foreach ($item in $items) {
        if (Test-Property -Object $item -PropertyName "settingDefinitionId") {
            $id = Get-PropertyValue -Object $item -PropertyName "settingDefinitionId"
            
            if (-not (Test-Blank -Value $id)) {
                $dict[$id] = $item
            }
        }
    }

    return $dict
}

function Compare-StigSettings {
    param(
        [hashtable]$PreviousSettings,
        [hashtable]$CurrentSettings
    )

    $results = @{
        "Added"    = @()
        "Removed"  = @()
        "Modified" = @()
    }

    # Find removed and modified settings
    foreach ($id in $PreviousSettings.Keys) {
        if ($CurrentSettings.ContainsKey($id)) {
            # Check if modified
            $prevValue = Get-PropertyValue -Object $PreviousSettings[$id] -PropertyName "value"
            $currValue = Get-PropertyValue -Object $CurrentSettings[$id] -PropertyName "value"

            $prevComparable = Convert-ToComparableText -Value $prevValue
            $currComparable = Convert-ToComparableText -Value $currValue

            if ($prevComparable -ne $currComparable) {
                $results["Modified"] += @{
                    Id = $id
                    Previous = $prevValue
                    Current = $currValue
                }
            }
        }
        else {
            # Setting was removed
            $value = Get-PropertyValue -Object $PreviousSettings[$id] -PropertyName "value"
            $results["Removed"] += @{
                Id = $id
                Value = $value
            }
        }
    }

    # Find added settings
    foreach ($id in $CurrentSettings.Keys) {
        if (-not $PreviousSettings.ContainsKey($id)) {
            $value = Get-PropertyValue -Object $CurrentSettings[$id] -PropertyName "value"
            $results["Added"] += @{
                Id = $id
                Value = $value
            }
        }
    }

    return $results
}

# ============================================================
# REPORT GENERATION FUNCTIONS
# ============================================================

function Export-CsvReport {
    param(
        [hashtable]$ComparisonResults,
        [string]$OutputPath
    )

    $csvData = @()

    # Added settings
    foreach ($item in $ComparisonResults["Added"]) {
        $category = Get-CategoryName -SettingDefinitionId $item.Id
        $settingName = ConvertTo-FriendlySettingName -SettingDefinitionId $item.Id
        $value = Normalize-ForDisplay -Value $item.Value

        $csvData += [PSCustomObject]@{
            Status        = "Added"
            Category      = $category
            Setting       = $settingName
            PreviousValue = ""
            CurrentValue  = $value
        }
    }

    # Removed settings
    foreach ($item in $ComparisonResults["Removed"]) {
        $category = Get-CategoryName -SettingDefinitionId $item.Id
        $settingName = ConvertTo-FriendlySettingName -SettingDefinitionId $item.Id
        $value = Normalize-ForDisplay -Value $item.Value

        $csvData += [PSCustomObject]@{
            Status        = "Removed"
            Category      = $category
            Setting       = $settingName
            PreviousValue = $value
            CurrentValue  = ""
        }
    }

    # Modified settings
    foreach ($item in $ComparisonResults["Modified"]) {
        $category = Get-CategoryName -SettingDefinitionId $item.Id
        $settingName = ConvertTo-FriendlySettingName -SettingDefinitionId $item.Id
        $prevValue = Normalize-ForDisplay -Value $item.Previous
        $currValue = Normalize-ForDisplay -Value $item.Current

        $csvData += [PSCustomObject]@{
            Status        = "Modified"
            Category      = $category
            Setting       = $settingName
            PreviousValue = $prevValue
            CurrentValue  = $currValue
        }
    }

    $csvData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}

function Write-ConsoleReport {
    param(
        [hashtable]$ComparisonResults,
        [string]$PreviousPath,
        [string]$CurrentPath
    )

    $addedCount = $ComparisonResults["Added"].Count
    $removedCount = $ComparisonResults["Removed"].Count
    $modifiedCount = $ComparisonResults["Modified"].Count
    $totalCount = $addedCount + $removedCount + $modifiedCount

    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "STIG DELTA REPORT" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Comparison Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "Previous File: $(Split-Path -Leaf $PreviousPath)"
    Write-Host "Current File:  $(Split-Path -Leaf $CurrentPath)"
    Write-Host ""
    Write-Host "SUMMARY" -ForegroundColor Cyan
    Write-Host "-------"
    Write-ColorOutput "Added Settings:     $addedCount" "Green"
    Write-ColorOutput "Removed Settings:   $removedCount" "Red"
    Write-ColorOutput "Modified Settings:  $modifiedCount" "Yellow"
    Write-Host "Total Differences:  $totalCount"
    Write-Host ""

    # Display Modified
    if ($modifiedCount -gt 0) {
        Write-Host "MODIFIED SETTINGS" -ForegroundColor Yellow
        Write-Host "-----------------"
        
        foreach ($item in $ComparisonResults["Modified"]) {
            $category = Get-CategoryName -SettingDefinitionId $item.Id
            $settingName = ConvertTo-FriendlySettingName -SettingDefinitionId $item.Id
            $prevDisp = Normalize-ForDisplay -Value $item.Previous
            $currDisp = Normalize-ForDisplay -Value $item.Current
            
            $prevTranslated = Translate-PolicyValue -Value $item.Previous -Category $category -SettingName $settingName
            $currTranslated = Translate-PolicyValue -Value $item.Current -Category $category -SettingName $settingName

            Write-Host "$category → $settingName"
            Write-ColorOutput "  Previous: $prevTranslated" "Gray"
            Write-ColorOutput "  Current:  $currTranslated" "Gray"
            Write-Host ""
        }
    }

    # Display Removed
    if ($removedCount -gt 0) {
        Write-Host "REMOVED SETTINGS" -ForegroundColor Red
        Write-Host "----------------"
        
        foreach ($item in $ComparisonResults["Removed"]) {
            $category = Get-CategoryName -SettingDefinitionId $item.Id
            $settingName = ConvertTo-FriendlySettingName -SettingDefinitionId $item.Id
            $value = Translate-PolicyValue -Value $item.Value -Category $category -SettingName $settingName

            Write-ColorOutput "✗ $category → $settingName" "Red"
            Write-ColorOutput "  Value: $value" "Gray"
            Write-Host ""
        }
    }

    # Display Added
    if ($addedCount -gt 0) {
        Write-Host "ADDED SETTINGS" -ForegroundColor Green
        Write-Host "--------------"
        
        foreach ($item in $ComparisonResults["Added"]) {
            $category = Get-CategoryName -SettingDefinitionId $item.Id
            $settingName = ConvertTo-FriendlySettingName -SettingDefinitionId $item.Id
            $value = Translate-PolicyValue -Value $item.Value -Category $category -SettingName $settingName

            Write-ColorOutput "✓ $category → $settingName" "Green"
            Write-ColorOutput "  Value: $value" "Gray"
            Write-Host ""
        }
    }

    Write-Host "========================================================" -ForegroundColor Cyan
}

function Write-LogReport {
    param(
        [hashtable]$ComparisonResults,
        [string]$PreviousPath,
        [string]$CurrentPath
    )

    $logEntry = @"
========================================================
Execution Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Previous STIG File: $PreviousPath
Current STIG File: $CurrentPath
Added Count: $($ComparisonResults["Added"].Count)
Removed Count: $($ComparisonResults["Removed"].Count)
Modified Count: $($ComparisonResults["Modified"].Count)
Details:
"@

    # Added details
    foreach ($item in $ComparisonResults["Added"]) {
        $category = Get-CategoryName -SettingDefinitionId $item.Id
        $value = Normalize-ForDisplay -Value $item.Value
        $logEntry += "`n - Added    | $($item.Id) | Category: $category | Value: $value"
    }

    # Removed details
    foreach ($item in $ComparisonResults["Removed"]) {
        $category = Get-CategoryName -SettingDefinitionId $item.Id
        $value = Normalize-ForDisplay -Value $item.Value
        $logEntry += "`n - Removed  | $($item.Id) | Category: $category | Value: $value"
    }

    # Modified details
    foreach ($item in $ComparisonResults["Modified"]) {
        $category = Get-CategoryName -SettingDefinitionId $item.Id
        $prevValue = Normalize-ForDisplay -Value $item.Previous
        $currValue = Normalize-ForDisplay -Value $item.Current
        $logEntry += "`n - Modified | $($item.Id) | Category: $category | Previous: $prevValue | Current: $currValue"
    }

    $logEntry += "`n========================================================"

    Add-Content -Path $LogPath -Value $logEntry
}

# ============================================================
# MAIN EXECUTION
# ============================================================

function Main {
    try {
        Write-Host ""
        Write-ColorOutput "Settings Catalog STIG Delta Analyzer v1.0" "Cyan"
        Write-Host ""

        # Initialize
        Initialize-Repository

        # Get input files
        $previousPath = Get-JsonFilePath "Enter the path to the previous STIG JSON file (baseline):"
        Write-ColorOutput "✓ Baseline file found: $previousPath" "Green"

        $previousJson = Import-StigJson -Path $previousPath
        Test-SupportedPolicyType -JsonObject $previousJson -FilePath $previousPath

        $currentPath = Get-JsonFilePath "Enter the path to the current STIG JSON file (target):"
        Write-ColorOutput "✓ Current file found: $currentPath" "Green"

        $currentJson = Import-StigJson -Path $currentPath
        Test-SupportedPolicyType -JsonObject $currentJson -FilePath $currentPath

        # Ask about troubleshooting mode
        $troubleResponse = Read-Host "Enable troubleshooting mode for detailed error output? (Y/N)"
        
        if ($troubleResponse -ieq "Y") {
            $script:TroubleshootingMode = "Basic"
        }

        Write-Host ""
        Write-Host "Analyzing differences..." -ForegroundColor Cyan
        Write-Host ""

        # Build dictionaries
        $previousSettings = Build-SettingsDictionary -JsonData $previousJson
        $currentSettings = Build-SettingsDictionary -JsonData $currentJson

        # Compare
        $comparison = Compare-StigSettings -PreviousSettings $previousSettings -CurrentSettings $currentSettings

        # Generate reports
        Write-ConsoleReport -ComparisonResults $comparison -PreviousPath $previousPath -CurrentPath $currentPath

        # Export CSV
        $csvPath = Join-Path $ReportPath "stig_delta_report.csv"
        Export-CsvReport -ComparisonResults $comparison -OutputPath $csvPath
        Write-ColorOutput "Report saved to: $csvPath" "Green"

        # Write log
        Write-LogReport -ComparisonResults $comparison -PreviousPath $previousPath -CurrentPath $currentPath
        Write-ColorOutput "Log updated: $LogPath" "Green"

        Write-Host ""
        Write-ColorOutput "Execution completed successfully." "Green"
        Write-Host ""
    }
    catch {
        Write-ColorOutput "ERROR: $($_.Exception.Message)" "Red"
        
        if ($script:TroubleshootingMode -eq "Basic" -or $script:TroubleshootingMode -eq "Deep") {
            Write-Host "Stack Trace:"
            Write-Host $_.ScriptStackTrace
        }
        
        exit 1
    }
}

# ============================================================
# SCRIPT ENTRY POINT
# ============================================================

Main
