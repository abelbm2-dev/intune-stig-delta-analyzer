$ErrorActionPreference = 'Stop'

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-ErrorAndExit {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    exit 1
}

function Get-ValidatedFilePath {
    param(
        [string]$Prompt,
        [string]$DefaultPath
    )

    while ($true) {
        $inputPath = Read-Host $Prompt
        if ([string]::IsNullOrWhiteSpace($inputPath)) {
            if ([string]::IsNullOrWhiteSpace($DefaultPath)) {
                Write-Warn 'A file path is required.'
                continue
            }
            $inputPath = $DefaultPath
        }

        if (-not (Test-Path -Path $inputPath -PathType Leaf)) {
            Write-Warn "File not found: $inputPath"
            continue
        }

        return (Resolve-Path -Path $inputPath).Path
    }
}

function Read-JsonFile {
    param([string]$Path)

    try {
        $rawContent = Get-Content -Path $Path -Raw
        if ([string]::IsNullOrWhiteSpace($rawContent)) {
            throw 'File content is empty.'
        }

        $jsonObject = ConvertFrom-Json -InputObject $rawContent -ErrorAction Stop
        if ($null -eq $jsonObject) {
            throw 'JSON content was empty after parsing.'
        }

        return $jsonObject
    }
    catch {
        throw "Unable to parse JSON from '$Path': $($_.Exception.Message)"
    }
}

function Normalize-AccountValue {
    param([string]$Value)

    if ($null -eq $Value) {
        return '<empty>'
    }

    $text = [string]$Value
    $text = $text.Trim()
    if ($text -eq '') {
        return '<empty>'
    }

    if ($text -like '*\*') {
        $parts = $text -split '\\'
        $text = $parts[-1]
    }

    $text = $text -replace '^BUILTIN\\', ''
    $text = $text -replace '^NT AUTHORITY\\', ''
    $text = $text -replace '^NT SERVICE\\', ''
    $text = $text -replace '^LOCAL SERVICE$', 'LOCAL SERVICE'

    return $text
}

function Get-FriendlyCategory {
    param([string]$SettingDefinitionId)

    if ($null -eq $SettingDefinitionId) {
        return 'Unknown'
    }

    $lower = $SettingDefinitionId.ToLowerInvariant()

    if ($lower -match 'audit') { return 'Auditing' }
    if ($lower -match 'userrights') { return 'User Rights Assignment' }
    if ($lower -match 'defender') { return 'Microsoft Defender' }
    if ($lower -match 'firewall') { return 'Firewall' }
    if ($lower -match 'wifi') { return 'Wi-Fi' }
    if ($lower -match 'bitlocker') { return 'BitLocker' }
    if ($lower -match 'browser') { return 'Browser' }
    if ($lower -match 'credentialguard') { return 'Credential Guard' }

    return 'Unknown'
}

function Get-FriendlySettingName {
    param([string]$SettingDefinitionId)

    if ([string]::IsNullOrWhiteSpace($SettingDefinitionId)) {
        return 'Unknown'
    }

    $name = $SettingDefinitionId
    $name = $name -replace '^device_vendor_msft_policy_config_', ''
    $name = $name -replace '^user_vendor_msft_policy_config_', ''
    $name = $name -replace '^device_vendor_msft_policy_config_', ''
    $name = $name -replace '^device_', ''

    $tokens = $name -split '_'
    $friendlyTokens = New-Object System.Collections.ArrayList

    foreach ($token in $tokens) {
        if ([string]::IsNullOrWhiteSpace($token)) {
            continue
        }

        $lowerToken = $token.ToLowerInvariant()

        switch ($lowerToken) {
            'allow' { $null = $friendlyTokens.Add('Allow') ; continue }
            'audit' { $null = $friendlyTokens.Add('Audit') ; continue }
            'objectaccess' { $null = $friendlyTokens.Add('Object Access') ; continue }
            'accountmanagement' { $null = $friendlyTokens.Add('Account Management') ; continue }
            'accountlogonlogoff' { $null = $friendlyTokens.Add('Account Logon Logoff') ; continue }
            'detailedtracking' { $null = $friendlyTokens.Add('Detailed Tracking') ; continue }
            'policychange' { $null = $friendlyTokens.Add('Policy Change') ; continue }
            'privilegeuse' { $null = $friendlyTokens.Add('Privilege Use') ; continue }
            'system' { $null = $friendlyTokens.Add('System') ; continue }
            'allowlocallogon' { $null = $friendlyTokens.Add('Allow Log On Locally') ; continue }
            'denyaccessfromnetwork' { $null = $friendlyTokens.Add('Deny Access From Network') ; continue }
            'denylocallogon' { $null = $friendlyTokens.Add('Deny Local Logon') ; continue }
            'denyremotedesktopserviceslogon' { $null = $friendlyTokens.Add('Deny Remote Desktop Services Logon') ; continue }
            'remotedesktopservices' { $null = $friendlyTokens.Add('Remote Desktop Services') ; continue }
            'logon' { $null = $friendlyTokens.Add('Logon') ; continue }
            'locallogon' { $null = $friendlyTokens.Add('Local Logon') ; continue }
            'local' { $null = $friendlyTokens.Add('Local') ; continue }
            'remote' { $null = $friendlyTokens.Add('Remote') ; continue }
            'desktop' { $null = $friendlyTokens.Add('Desktop') ; continue }
            'services' { $null = $friendlyTokens.Add('Services') ; continue }
            'autoconnect' { $null = $friendlyTokens.Add('Auto Connect') ; continue }
            'wifisense' { $null = $friendlyTokens.Add('Wi-Fi Sense') ; continue }
            'hotspots' { $null = $friendlyTokens.Add('Hotspots') ; continue }
            'fileshare' { $null = $friendlyTokens.Add('File Share') ; continue }
            'filesystem' { $null = $friendlyTokens.Add('File System') ; continue }
            'handlemanipulation' { $null = $friendlyTokens.Add('Handle Manipulation') ; continue }
            'otherobjectaccessevents' { $null = $friendlyTokens.Add('Other Object Access Events') ; continue }
            'speciallogon' { $null = $friendlyTokens.Add('Special Logon') ; continue }
            'audithandlemanipulation' { $null = $friendlyTokens.Add('Audit Handle Manipulation') ; continue }
            'auditfileshare' { $null = $friendlyTokens.Add('Audit File Share') ; continue }
            'auditspeciallogon' { $null = $friendlyTokens.Add('Audit Special Logon') ; continue }
            'auditfilesystem' { $null = $friendlyTokens.Add('Audit File System') ; continue }
            'auditotherobjectaccessevents' { $null = $friendlyTokens.Add('Audit Other Object Access Events') ; continue }
            'auditotherlogonlogoffevents' { $null = $friendlyTokens.Add('Audit Other Logon Logoff Events') ; continue }
            'auditsecuritygroupmanagement' { $null = $friendlyTokens.Add('Audit Security Group Management') ; continue }
            'audituseraccountmanagement' { $null = $friendlyTokens.Add('Audit User Account Management') ; continue }
            'auditsecuritysystemextension' { $null = $friendlyTokens.Add('Audit Security System Extension') ; continue }
            'auditmpssvcrulelevelpolicychange' { $null = $friendlyTokens.Add('Audit MPSSVC Rule Level Policy Change') ; continue }
            'auditotherpolicychangeevents' { $null = $friendlyTokens.Add('Audit Other Policy Change Events') ; continue }
            'auditsensitiveprivilegeuse' { $null = $friendlyTokens.Add('Audit Sensitive Privilege Use') ; continue }
            'auditipsecdriver' { $null = $friendlyTokens.Add('Audit IPSec Driver') ; continue }
            'auditothersystemevents' { $null = $friendlyTokens.Add('Audit Other System Events') ; continue }
            'auditsecuritystatechange' { $null = $friendlyTokens.Add('Audit Security State Change') ; continue }
            'auditsystemintegrity' { $null = $friendlyTokens.Add('Audit System Integrity') ; continue }
            'pnpactivity' { $null = $friendlyTokens.Add('PNP Activity') ; continue }
            'processcreation' { $null = $friendlyTokens.Add('Process Creation') ; continue }
            'removable' { $null = $friendlyTokens.Add('Removable') ; continue }
            'storage' { $null = $friendlyTokens.Add('Storage') ; continue }
            default { $null = $friendlyTokens.Add(($token.Substring(0,1).ToUpperInvariant() + $token.Substring(1))) }
        }
    }

    if ($friendlyTokens.Count -eq 0) {
        return 'Unknown'
    }

    return ($friendlyTokens -join ' - ')
}

function Get-LeafValueText {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [bool]) {
        return [string]$Value
    }

    if ($Value -is [pscustomobject]) {
        $valueProperty = $Value.PSObject.Properties['value']
        if ($null -ne $valueProperty -and $null -ne $valueProperty.Value) {
            return Get-LeafValueText -Value $valueProperty.Value
        }
    }

    return $null
}

function Get-FriendlyValueText {
    param(
        [string]$SettingDefinitionId,
        [object]$Value
    )

    if ($null -eq $Value) {
        return '<empty>'
    }

    if ($Value -is [System.Array]) {
        $normalizedValues = New-Object System.Collections.ArrayList
        foreach ($item in $Value) {
            $friendly = Get-FriendlyValueText -SettingDefinitionId $SettingDefinitionId -Value $item
            if ($friendly -ne '<empty>') {
                $null = $normalizedValues.Add($friendly)
            }
        }
        if ($normalizedValues.Count -eq 0) {
            return '<empty>'
        }
        if ($normalizedValues.Count -eq 1) {
            return $normalizedValues[0]
        }
        return ($normalizedValues -join [Environment]::NewLine)
    }

    $leafText = Get-LeafValueText -Value $Value
    if ($null -ne $leafText) {
        $text = [string]$leafText
    }
    else {
        $text = [string]$Value
    }

    $text = $text.Trim()
    if ($text -eq '') {
        return '<empty>'
    }

    if ($text -like 'null') {
        return '<empty>'
    }

    $text = Normalize-AccountValue -Value $text

    if ($text -eq '<empty>') {
        return '<empty>'
    }

    if ($SettingDefinitionId -match 'audit' -and $text -match '^(\d+)$') {
        switch ($matches[1]) {
            '0' { return 'No Auditing' }
            '1' { return 'Success' }
            '2' { return 'Failure' }
            '3' { return 'Success + Failure' }
            default { return $text }
        }
    }

    if ($text -match '_([0-9]+)$') {
        $suffix = $matches[1]
        switch ($suffix) {
            '0' { return 'Disabled' }
            '1' { return 'Enabled' }
            '2' { return 'Not Configured' }
            default { return $text }
        }
    }

    if ($text -match 'device_vendor_msft_policy_config_.*_(0|1|2|3)$') {
        $suffix = $matches[1]
        switch ($suffix) {
            '0' { return 'Disabled' }
            '1' { return 'Enabled' }
            '2' { return 'Not Configured' }
            '3' { return 'Enabled' }
            default { return $text }
        }
    }

    if ($text -match '^(true|false)$') {
        if ($text -eq 'true') {
            return 'Enabled'
        }
        return 'Disabled'
    }

    if ($text -match 'allowautoconnecttowifisensehotspots') {
        return 'Enabled'
    }

    return $text
}

function Get-SettingValues {
    param([object]$SettingInstance)

    if ($null -eq $SettingInstance) {
        return @()
    }

    $simpleCollectionValue = $SettingInstance.PSObject.Properties['simpleSettingCollectionValue']
    if ($null -ne $simpleCollectionValue -and $null -ne $simpleCollectionValue.Value) {
        $values = New-Object System.Collections.ArrayList
        $collection = $simpleCollectionValue.Value
        if ($collection -is [System.Array] -or $collection -is [System.Collections.IEnumerable]) {
            foreach ($item in $collection) {
                if ($null -eq $item) {
                    continue
                }
                $leafValue = Get-LeafValueText -Value $item
                if ($null -ne $leafValue) {
                    $null = $values.Add($leafValue)
                }
            }
        }
        if ($values.Count -gt 0) {
            return @($values)
        }
    }

    $simpleValue = $SettingInstance.PSObject.Properties['simpleSettingValue']
    if ($null -ne $simpleValue -and $null -ne $simpleValue.Value) {
        $value = $simpleValue.Value
        if ($null -ne $value) {
            $leafValue = Get-LeafValueText -Value $value
            if ($null -ne $leafValue) {
                return @($leafValue)
            }
        }
    }

    $choiceValue = $SettingInstance.PSObject.Properties['choiceSettingValue']
    if ($null -ne $choiceValue -and $null -ne $choiceValue.Value) {
        $value = $choiceValue.Value
        if ($null -ne $value) {
            $leafValue = Get-LeafValueText -Value $value
            if ($null -ne $leafValue) {
                return @($leafValue)
            }
        }
    }

    return @()
}

function Get-StigEntries {
    param([object]$JsonObject)

    if ($null -eq $JsonObject) {
        throw 'The JSON object is null.'
    }

    $settingsProperty = $JsonObject.PSObject.Properties.Match('settings')
    if ($settingsProperty.Count -eq 0) {
        throw 'The JSON does not contain a settings array.'
    }

    $settings = $JsonObject.settings
    if ($null -eq $settings) {
        throw 'The settings array is missing or empty.'
    }

    if ($settings -isnot [System.Array]) {
        $settings = @($settings)
    }

    $normalizedEntries = New-Object System.Collections.ArrayList

    foreach ($entry in $settings) {
        if ($null -eq $entry) {
            continue
        }

        $settingInstance = $null
        if ($entry.PSObject.Properties.Match('settingInstance').Count -gt 0) {
            $settingInstance = $entry.settingInstance
        }

        if ($null -eq $settingInstance) {
            continue
        }

        $settingDefinitionId = $null
        $definitionProperty = $settingInstance.PSObject.Properties['settingDefinitionId']
        if ($null -ne $definitionProperty -and $null -ne $definitionProperty.Value) {
            $settingDefinitionId = [string]$definitionProperty.Value
        }

        if ([string]::IsNullOrWhiteSpace($settingDefinitionId)) {
            $idProperty = $entry.PSObject.Properties['id']
            if ($null -ne $idProperty -and $null -ne $idProperty.Value) {
                $settingDefinitionId = [string]$idProperty.Value
            }
        }

        if ([string]::IsNullOrWhiteSpace($settingDefinitionId)) {
            continue
        }

        $values = @(Get-SettingValues -SettingInstance $settingInstance)
        $friendlyValues = New-Object System.Collections.ArrayList
        foreach ($value in $values) {
            if ($null -eq $value) {
                continue
            }
            $friendlyValue = Get-FriendlyValueText -SettingDefinitionId $settingDefinitionId -Value $value
            if ($friendlyValue -ne '<empty>') {
                $null = $friendlyValues.Add($friendlyValue)
            }
        }

        if ($friendlyValues.Count -eq 0) {
            $friendlyValues.Add('<empty>')
        }

        $null = $normalizedEntries.Add([pscustomobject]@{
                SettingDefinitionId = $settingDefinitionId
                Category = Get-FriendlyCategory -SettingDefinitionId $settingDefinitionId
                Setting = Get-FriendlySettingName -SettingDefinitionId $settingDefinitionId
                Values = $friendlyValues.ToArray()
                CompareValues = $friendlyValues.ToArray()
            })
    }

    return $normalizedEntries
}

function Write-CsvReport {
    param(
        [object[]]$Rows,
        [string]$Path
    )

    try {
        if (Test-Path -Path $Path) {
            Remove-Item -Path $Path -Force
        }

        $Rows | Select-Object Status, Category, Setting, PreviousValue, CurrentValue | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        return $Path
    }
    catch {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $directory = Split-Path -Parent $Path
        $fallbackPath = Join-Path -Path $directory -ChildPath ("stig_delta_report_{0}.csv" -f $timestamp)
        $Rows | Select-Object Status, Category, Setting, PreviousValue, CurrentValue | Export-Csv -Path $fallbackPath -NoTypeInformation -Encoding UTF8
        return $fallbackPath
    }
}

function Write-ReportBlock {
    param(
        [string]$Status,
        [object[]]$Items,
        [bool]$TroubleshootingMode
    )

    if ($null -eq $Items -or $Items.Count -eq 0) {
        return
    }

    Write-Host $Status -ForegroundColor Green
    foreach ($item in $Items) {
        Write-Host ''
        Write-Host ("Category: {0}" -f $item.Category)
        Write-Host ("Setting: {0}" -f $item.Setting)
        if ($TroubleshootingMode) {
            Write-Host ("Definition ID: {0}" -f $item.SettingDefinitionId)
        }

        if ($Status -eq 'Modified') {
            Write-Host ("Previous Value: {0}" -f $item.PreviousValue)
            Write-Host ("Current Value: {0}" -f $item.CurrentValue)
        }
        else {
            Write-Host ("Configuration: {0}" -f $item.Configuration)
        }
    }

    Write-Host ''
    Write-Host ('-' * 52)
}

try {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
    if (-not (Test-Path -Path $scriptDirectory)) {
        $null = New-Item -ItemType Directory -Path $scriptDirectory -Force
    }

    $repoFolder = 'C:\Repo\Script_Comparison'
    if (-not (Test-Path -Path $repoFolder)) {
        $null = New-Item -ItemType Directory -Path $repoFolder -Force
    }

    $csvOutputPath = Join-Path -Path $repoFolder -ChildPath 'stig_delta_report.csv'
    $logPath = Join-Path -Path $repoFolder -ChildPath 'stig_comparison.log'

    Write-Info "Script folder: $scriptDirectory"
    Write-Info "Log folder: $repoFolder"
    Write-Host ''

    $baselinePath = Get-ValidatedFilePath -Prompt 'Enter the path to the previous STIG JSON file:' -DefaultPath ''
    $currentPath = Get-ValidatedFilePath -Prompt 'Enter the path to the current STIG JSON file:' -DefaultPath ''

    $troubleshootingMode = $false
    $troubleshootingResponse = Read-Host 'Enable troubleshooting mode? [Y/N]'
    if ($troubleshootingResponse -match '^(y|yes)$') {
        $troubleshootingMode = $true
    }

    Write-Info 'Loading JSON files...'
    $baselineJson = Read-JsonFile -Path $baselinePath
    $currentJson = Read-JsonFile -Path $currentPath

    Write-Info 'Extracting entries...'
    $baselineEntries = @(Get-StigEntries -JsonObject $baselineJson)
    $currentEntries = @(Get-StigEntries -JsonObject $currentJson)

    $baselineMap = @{}
    foreach ($entry in $baselineEntries) {
        if ($null -ne $entry -and -not [string]::IsNullOrWhiteSpace($entry.SettingDefinitionId)) {
            $baselineMap[$entry.SettingDefinitionId] = $entry
        }
    }

    $currentMap = @{}
    foreach ($entry in $currentEntries) {
        if ($null -ne $entry -and -not [string]::IsNullOrWhiteSpace($entry.SettingDefinitionId)) {
            $currentMap[$entry.SettingDefinitionId] = $entry
        }
    }

    $allKeys = @($baselineMap.Keys + $currentMap.Keys | Select-Object -Unique)

    $addedItems = New-Object System.Collections.ArrayList
    $removedItems = New-Object System.Collections.ArrayList
    $modifiedItems = New-Object System.Collections.ArrayList
    $addedCount = 0
    $removedCount = 0
    $modifiedCount = 0

    foreach ($key in $allKeys) {
        $baselineEntry = $null
        $currentEntry = $null

        if ($baselineMap.ContainsKey($key)) {
            $baselineEntry = $baselineMap[$key]
        }

        if ($currentMap.ContainsKey($key)) {
            $currentEntry = $currentMap[$key]
        }

        if ($null -eq $baselineEntry -and $null -ne $currentEntry) {
            $addedCount++
            $item = [pscustomobject]@{
                Status = 'Added'
                Category = $currentEntry.Category
                Setting = $currentEntry.Setting
                SettingDefinitionId = $currentEntry.SettingDefinitionId
                Configuration = ($currentEntry.Values -join [Environment]::NewLine)
            }
            $null = $addedItems.Add($item)
        }
        elseif ($null -ne $baselineEntry -and $null -eq $currentEntry) {
            $removedCount++
            $item = [pscustomobject]@{
                Status = 'Removed'
                Category = $baselineEntry.Category
                Setting = $baselineEntry.Setting
                SettingDefinitionId = $baselineEntry.SettingDefinitionId
                Configuration = ($baselineEntry.Values -join [Environment]::NewLine)
            }
            $null = $removedItems.Add($item)
        }
        elseif ($null -ne $baselineEntry -and $null -ne $currentEntry) {
            $baselineComparable = ($baselineEntry.CompareValues -join "`n")
            $currentComparable = ($currentEntry.CompareValues -join "`n")
            if ($baselineComparable -ne $currentComparable) {
                $modifiedCount++
                $item = [pscustomobject]@{
                    Status = 'Modified'
                    Category = $currentEntry.Category
                    Setting = $currentEntry.Setting
                    SettingDefinitionId = $currentEntry.SettingDefinitionId
                    PreviousValue = ($baselineEntry.Values -join [Environment]::NewLine)
                    CurrentValue = ($currentEntry.Values -join [Environment]::NewLine)
                }
                $null = $modifiedItems.Add($item)
            }
        }
    }

    Write-Host ''
    Write-Host '====================================================' -ForegroundColor Green
    Write-Host 'INTUNE SETTINGS CATALOG DELTA REPORT' -ForegroundColor Green
    Write-Host '====================================================' -ForegroundColor Green
    Write-Host ''

    Write-ReportBlock -Status 'Modified' -Items @($modifiedItems) -TroubleshootingMode $troubleshootingMode
    Write-ReportBlock -Status 'Added' -Items @($addedItems) -TroubleshootingMode $troubleshootingMode
    Write-ReportBlock -Status 'Removed' -Items @($removedItems) -TroubleshootingMode $troubleshootingMode

    Write-Host 'SUMMARY' -ForegroundColor Green
    Write-Host ("Added: {0}" -f $addedCount)
    Write-Host ("Removed: {0}" -f $removedCount)
    Write-Host ("Modified: {0}" -f $modifiedCount)

    $csvRows = New-Object System.Collections.ArrayList
    foreach ($item in @($modifiedItems)) {
        $null = $csvRows.Add([pscustomobject]@{
                Status = $item.Status
                Category = $item.Category
                Setting = $item.Setting
                PreviousValue = $item.PreviousValue
                CurrentValue = $item.CurrentValue
            })
    }
    foreach ($item in @($addedItems)) {
        $null = $csvRows.Add([pscustomobject]@{
                Status = $item.Status
                Category = $item.Category
                Setting = $item.Setting
                PreviousValue = ''
                CurrentValue = $item.Configuration
            })
    }
    foreach ($item in @($removedItems)) {
        $null = $csvRows.Add([pscustomobject]@{
                Status = $item.Status
                Category = $item.Category
                Setting = $item.Setting
                PreviousValue = $item.Configuration
                CurrentValue = ''
            })
    }

    $csvOutputPath = Write-CsvReport -Rows $csvRows -Path $csvOutputPath
    Write-Info "CSV report written to: $csvOutputPath"

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logLines = @(
        '========================================================',
        "Execution Date: $timestamp",
        "Previous STIG File: $baselinePath",
        "Current STIG File: $currentPath",
        "Added Count: $addedCount",
        "Removed Count: $removedCount",
        "Modified Count: $modifiedCount"
    )

    $logLines += 'Details:'
    foreach ($item in @($modifiedItems)) {
        $prev = ($item.PreviousValue -replace "`r?`n", '; ')
        $curr = ($item.CurrentValue -replace "`r?`n", '; ')
        $logLines += (" - Modified | {0} | Previous: {1} | Current: {2}" -f $item.SettingDefinitionId, $prev, $curr)
    }
    foreach ($item in @($addedItems)) {
        $curr = ($item.Configuration -replace "`r?`n", '; ')
        $logLines += (" - Added    | {0} | Current: {1}" -f $item.SettingDefinitionId, $curr)
    }
    foreach ($item in @($removedItems)) {
        $prev = ($item.Configuration -replace "`r?`n", '; ')
        $logLines += (" - Removed  | {0} | Previous: {1}" -f $item.SettingDefinitionId, $prev)
    }

    Add-Content -Path $logPath -Value $logLines
    Write-Info "Log appended to: $logPath"
}
catch {
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $repoFolder = 'C:\Repo\Script_Comparison'
    if (-not (Test-Path -Path $repoFolder)) {
        $null = New-Item -ItemType Directory -Path $repoFolder -Force
    }
    $logPath = Join-Path -Path $repoFolder -ChildPath 'stig_comparison.log'
    $errorLine = "ERROR [$timestamp] $($_.Exception.Message)"
    Add-Content -Path $logPath -Value $errorLine
    Write-ErrorAndExit $_.Exception.Message
}
