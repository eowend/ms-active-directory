<#
.SYNOPSIS
    Active Directory Infrastructure Health Check.
    Version 1.4 - Stability fixes for null exports, trust discovery, event summary syntax and StrictMode count handling.

.DESCRIPTION
    Discovers the Active Directory forest, domains, domain controllers, sites, DNS,
    replication state, SYSVOL/NETLOGON, FSMO roles, critical services, ports,
    recent event logs, password policies, privileged groups, GPO inventory,
    dcdiag output, repadmin output, w32tm output and DFSR migration state.

    The script is read-only.
    It creates C:\ad-health\ and writes all outputs there.

.OUTPUT
    C:\ad-health\ADHealth-yyyyMMdd-HHmmss\
    C:\ad-health\Latest_ADHealthReport.html

.REQUIREMENTS
    Run from an elevated PowerShell session on a domain-joined server.
    RSAT Active Directory PowerShell module is required.
    DnsServer and GroupPolicy modules are optional.

.EXAMPLE
    .\Test-ADInfrastructureHealth.ps1

.EXAMPLE
    .\Test-ADInfrastructureHealth.ps1 -RecentEventHours 168

.EXAMPLE
    .\Test-ADInfrastructureHealth.ps1 -SkipDcDiag -SkipRepAdmin
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = "C:\ad-health",

    [int]$RecentEventHours = 72,

    [int]$ReplicationWarningHours = 24,

    [int]$CommandTimeoutSeconds = 1800,

    [int]$TcpTimeoutMilliseconds = 2500,

    [int]$MaxEventsPerLog = 1000,

    [switch]$SkipDcDiag,

    [switch]$SkipRepAdmin,

    [switch]$SkipDnsDeepChecks
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$Script:StartedAt = Get-Date
$Script:RunStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Script:RunRoot = Join-Path $OutputRoot "ADHealth-$Script:RunStamp"
$Script:RawDir = Join-Path $Script:RunRoot "raw"
$Script:CsvDir = Join-Path $Script:RunRoot "csv"
$Script:JsonDir = Join-Path $Script:RunRoot "json"
$Script:HtmlDir = Join-Path $Script:RunRoot "html"
$Script:LogDir = Join-Path $Script:RunRoot "logs"
$Script:TranscriptPath = Join-Path $Script:LogDir "Transcript-$Script:RunStamp.txt"

$Script:Findings = New-Object System.Collections.Generic.List[object]
$Script:CommandResults = New-Object System.Collections.Generic.List[object]

function Initialize-OutputFolders {
    $folders = @(
        $OutputRoot,
        $Script:RunRoot,
        $Script:RawDir,
        $Script:CsvDir,
        $Script:JsonDir,
        $Script:HtmlDir,
        $Script:LogDir
    )

    foreach ($folder in $folders) {
        if (-not (Test-Path -Path $folder)) {
            New-Item -Path $folder -ItemType Directory -Force | Out-Null
        }
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "OK")][string]$Level = "INFO"
    )

    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line

    $logPath = Join-Path $Script:LogDir "ADHealth-$Script:RunStamp.log"
    Add-Content -Path $logPath -Value $line
}

function Add-Finding {
    param(
        [ValidateSet("Critical", "Warning", "Info", "Pass")][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$EvidenceFile = ""
    )

    $Script:Findings.Add([pscustomobject]@{
        Timestamp    = Get-Date
        Severity     = $Severity
        Category     = $Category
        Target       = $Target
        Message      = $Message
        EvidenceFile = $EvidenceFile
    }) | Out-Null
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ExportItems {
    param(
        [AllowNull()]$Data
    )

    $items = New-Object System.Collections.Generic.List[object]

    if ($null -eq $Data) {
        return @()
    }

    if ($Data -is [string]) {
        $items.Add($Data) | Out-Null
        return $items.ToArray()
    }

    if (($Data -is [System.Collections.IEnumerable]) -and
        (-not ($Data -is [System.Collections.IDictionary])) -and
        (-not ($Data -is [System.Management.Automation.PSCustomObject]))) {

        foreach ($item in $Data) {
            if ($null -ne $item) {
                $items.Add($item) | Out-Null
            }
        }
    }
    else {
        $items.Add($Data) | Out-Null
    }

    return $items.ToArray()
}

function ConvertTo-ExportableValue {
    param(
        [AllowNull()]$Value
    )

    if ($null -eq $Value) {
        return ""
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [datetime]) {
        return $Value.ToString("yyyy-MM-dd HH:mm:ss")
    }

    if (($Value -is [bool]) -or
        ($Value -is [byte]) -or
        ($Value -is [int16]) -or
        ($Value -is [int]) -or
        ($Value -is [long]) -or
        ($Value -is [single]) -or
        ($Value -is [double]) -or
        ($Value -is [decimal])) {
        return $Value
    }

    if ($Value -is [System.Enum]) {
        return $Value.ToString()
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $pairs = New-Object System.Collections.Generic.List[string]
        foreach ($key in $Value.Keys) {
            $pairs.Add(("{0}={1}" -f $key, $Value[$key])) | Out-Null
        }
        return ($pairs.ToArray() -join "; ")
    }

    if (($Value -is [System.Collections.IEnumerable]) -and (-not ($Value -is [string]))) {
        $values = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $Value) {
            if ($null -ne $entry) {
                $values.Add([string]$entry) | Out-Null
            }
        }
        return ($values.ToArray() -join "; ")
    }

    return [string]$Value
}

function ConvertTo-FlatObject {
    param(
        [AllowNull()]$Item
    )

    if ($null -eq $Item) {
        return $null
    }

    if (($Item -is [string]) -or
        ($Item -is [datetime]) -or
        ($Item -is [bool]) -or
        ($Item -is [byte]) -or
        ($Item -is [int16]) -or
        ($Item -is [int]) -or
        ($Item -is [long]) -or
        ($Item -is [single]) -or
        ($Item -is [double]) -or
        ($Item -is [decimal]) -or
        ($Item -is [System.Enum])) {
        return [pscustomobject]@{
            Value = ConvertTo-ExportableValue -Value $Item
        }
    }

    $ordered = [ordered]@{}

    if ($Item -is [System.Collections.IDictionary]) {
        foreach ($key in $Item.Keys) {
            $propertyName = [string]$key
            if ([string]::IsNullOrWhiteSpace($propertyName)) {
                $propertyName = "Key"
            }
            if (-not $ordered.Contains($propertyName)) {
                $ordered[$propertyName] = ConvertTo-ExportableValue -Value $Item[$key]
            }
        }
        return [pscustomobject]$ordered
    }

    $properties = @($Item.PSObject.Properties | Where-Object {
        $_.MemberType -in @("NoteProperty", "Property", "AliasProperty", "ScriptProperty")
    })

    if ($properties.Count -eq 0) {
        return [pscustomobject]@{
            Value = ConvertTo-ExportableValue -Value $Item
        }
    }

    foreach ($property in $properties) {
        $propertyName = $property.Name
        if ([string]::IsNullOrWhiteSpace($propertyName)) {
            continue
        }

        if ($ordered.Contains($propertyName)) {
            continue
        }

        try {
            $ordered[$propertyName] = ConvertTo-ExportableValue -Value $property.Value
        }
        catch {
            $ordered[$propertyName] = "Unable to read property value: $($_.Exception.Message)"
        }
    }

    return [pscustomobject]$ordered
}

function Export-Data {
    param(
        [AllowNull()]$Data,
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$JsonOnly
    )

    $items = @(Get-ExportItems -Data $Data)

    if ($items.Count -eq 0) {
        $emptyPath = Join-Path $Script:CsvDir "$Name.no-data.txt"
        "No data collected for $Name" | Out-File -FilePath $emptyPath -Encoding UTF8
        return $emptyPath
    }

    $flatItems = New-Object System.Collections.Generic.List[object]
    foreach ($item in $items) {
        $flatItem = ConvertTo-FlatObject -Item $item
        if ($null -ne $flatItem) {
            $flatItems.Add($flatItem) | Out-Null
        }
    }

    if ($flatItems.Count -eq 0) {
        $emptyPath = Join-Path $Script:CsvDir "$Name.no-data.txt"
        "No exportable data collected for $Name" | Out-File -FilePath $emptyPath -Encoding UTF8
        return $emptyPath
    }

    $jsonPath = Join-Path $Script:JsonDir "$Name.json"
    $flatItems.ToArray() | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8

    if ($JsonOnly) {
        return $jsonPath
    }

    $csvPath = Join-Path $Script:CsvDir "$Name.csv"
    $flatItems.ToArray() | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    return $csvPath
}

function Save-Text {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $path = Join-Path $Script:RawDir $Name
    $Text | Out-File -FilePath $path -Encoding UTF8
    return $path
}

function Get-ExternalCommandPath {
    param([Parameter(Mandatory = $true)][string]$Name)

    try {
        $command = Get-Command $Name -ErrorAction Stop
        return $command.Source
    }
    catch {
        Add-Finding -Severity "Warning" -Category "Missing Tool" -Target $Name -Message "The command was not found on this server."
        return $null
    }
}

function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$OutputName,
        [int]$TimeoutSeconds = $CommandTimeoutSeconds
    )

    $safeName = $OutputName -replace '[\\/:*?"<>|]', '_'
    $stdoutPath = Join-Path $Script:RawDir "$safeName.txt"
    $stderrPath = Join-Path $Script:RawDir "$safeName.err.txt"

    $started = Get-Date
    Write-Log "Running command: $FilePath $Arguments"

    try {
        $process = Start-Process -FilePath $FilePath `
            -ArgumentList $Arguments `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -NoNewWindow `
            -PassThru

        $completed = $process.WaitForExit($TimeoutSeconds * 1000)

        if (-not $completed) {
            try { $process.Kill() } catch { }
            Add-Finding -Severity "Warning" -Category "Command Timeout" -Target "$FilePath $Arguments" -Message "The command exceeded the timeout of $TimeoutSeconds seconds." -EvidenceFile $stdoutPath
        }

        $ended = Get-Date
        $stderrLength = 0

        if (Test-Path $stderrPath) {
            $stderrLength = (Get-Item $stderrPath).Length
        }

        $result = [pscustomobject]@{
            Command     = $FilePath
            Arguments   = $Arguments
            StartedAt   = $started
            EndedAt     = $ended
            DurationSec = [math]::Round(($ended - $started).TotalSeconds, 2)
            Completed   = $completed
            ExitCode    = $process.ExitCode
            StdOutFile  = $stdoutPath
            StdErrFile  = $stderrPath
            StdErrBytes = $stderrLength
        }

        $Script:CommandResults.Add($result) | Out-Null

        if ($stderrLength -gt 0) {
            Add-Finding -Severity "Info" -Category "Command STDERR" -Target "$FilePath $Arguments" -Message "The command generated STDERR output. Review the .err.txt file." -EvidenceFile $stderrPath
        }

        return $result
    }
    catch {
        Add-Finding -Severity "Warning" -Category "Command Failed" -Target "$FilePath $Arguments" -Message $_.Exception.Message -EvidenceFile $stderrPath

        $result = [pscustomobject]@{
            Command     = $FilePath
            Arguments   = $Arguments
            StartedAt   = $started
            EndedAt     = Get-Date
            DurationSec = 0
            Completed   = $false
            ExitCode    = $null
            StdOutFile  = $stdoutPath
            StdErrFile  = $stderrPath
            StdErrBytes = 0
        }

        $Script:CommandResults.Add($result) | Out-Null
        return $result
    }
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutMilliseconds = $TcpTimeoutMilliseconds
    )

    $client = $null
    $started = Get-Date

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $success = $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)

        if ($success) {
            $client.EndConnect($async)
        }

        return [pscustomobject]@{
            ComputerName         = $ComputerName
            Port                 = $Port
            TcpTestSucceeded     = [bool]$success
            ResponseMilliseconds = [math]::Round(((Get-Date) - $started).TotalMilliseconds, 0)
            Error                = ""
        }
    }
    catch {
        return [pscustomobject]@{
            ComputerName         = $ComputerName
            Port                 = $Port
            TcpTestSucceeded     = $false
            ResponseMilliseconds = [math]::Round(((Get-Date) - $started).TotalMilliseconds, 0)
            Error                = $_.Exception.Message
        }
    }
    finally {
        if ($client) {
            $client.Close()
        }
    }
}

function Get-RecentDcEvents {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][datetime]$StartTime,
        [int]$MaxEvents = 1000
    )

    $logs = @(
        "Directory Service",
        "DNS Server",
        "DFS Replication",
        "System",
        "Application"
    )

    $events = New-Object System.Collections.Generic.List[object]

    foreach ($log in $logs) {
        try {
            $filter = @{
                LogName   = $log
                StartTime = $StartTime
                Level     = @(1, 2, 3)
            }

            $logEvents = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop

            foreach ($event in $logEvents) {
                $events.Add([pscustomobject]@{
                    ComputerName     = $ComputerName
                    LogName          = $event.LogName
                    TimeCreated      = $event.TimeCreated
                    Id               = $event.Id
                    Level            = $event.Level
                    LevelDisplayName = $event.LevelDisplayName
                    ProviderName     = $event.ProviderName
                    Message          = ($event.Message -replace "`r|`n", " ")
                }) | Out-Null
            }
        }
        catch {
            $message = $_.Exception.Message

            if ($message -notmatch "No events were found") {
                Add-Finding -Severity "Info" -Category "Event Log Collection" -Target "$ComputerName / $log" -Message $message
            }
        }
    }

    return $events
}

function Convert-DcDiagFindings {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path $Path)) {
        return @()
    }

    $patterns = @(
        "failed test",
        "error",
        "warning",
        "fatal",
        "unable",
        "could not",
        "can't",
        "cannot",
        "failed"
    )

    $findings = New-Object System.Collections.Generic.List[object]
    $lines = Get-Content -Path $Path -ErrorAction SilentlyContinue

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]

        foreach ($pattern in $patterns) {
            if ($line -match $pattern) {
                $findings.Add([pscustomobject]@{
                    SourceFile = $Path
                    LineNumber = $i + 1
                    Pattern    = $pattern
                    Line       = $line.Trim()
                }) | Out-Null

                break
            }
        }
    }

    return $findings
}

function New-HtmlReport {
    param(
        [Parameter(Mandatory = $true)]$RunInfo,
        [Parameter(Mandatory = $true)]$ForestSummary,
        [Parameter(Mandatory = $true)]$DomainSummary,
        [Parameter(Mandatory = $true)]$DcSummary,
        [Parameter(Mandatory = $true)]$Findings,
        [Parameter(Mandatory = $true)]$CommandResults,
        [Parameter(Mandatory = $true)]$OutputFiles
    )

    $reportPath = Join-Path $Script:HtmlDir "ADHealthReport-$Script:RunStamp.html"

    $criticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $warningCount = @($Findings | Where-Object { $_.Severity -eq "Warning" }).Count
    $infoCount = @($Findings | Where-Object { $_.Severity -eq "Info" }).Count
    $passCount = @($Findings | Where-Object { $_.Severity -eq "Pass" }).Count

    $css = @"
<style>
body {
    font-family: Segoe UI, Arial, sans-serif;
    font-size: 13px;
    color: #222;
    margin: 24px;
}
h1 {
    font-size: 24px;
}
h2 {
    font-size: 18px;
    margin-top: 28px;
    border-bottom: 1px solid #ccc;
    padding-bottom: 4px;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin-top: 10px;
}
th, td {
    border: 1px solid #ddd;
    padding: 6px;
    vertical-align: top;
}
th {
    background: #f2f2f2;
    text-align: left;
}
tr:nth-child(even) {
    background: #fafafa;
}
.badge {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 12px;
    background: #eee;
    margin-right: 6px;
}
</style>
"@

    $runHtml = $RunInfo | ConvertTo-Html -Fragment
    $forestHtml = $ForestSummary | ConvertTo-Html -Fragment
    $domainHtml = $DomainSummary | ConvertTo-Html -Fragment
    $dcHtml = $DcSummary | ConvertTo-Html -Fragment
    $findingsHtml = $Findings | Sort-Object Severity, Category, Target | ConvertTo-Html -Fragment
    $commandsHtml = $CommandResults | ConvertTo-Html -Fragment
    $filesHtml = $OutputFiles | ConvertTo-Html -Fragment

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Active Directory Health Report - $Script:RunStamp</title>
$css
</head>
<body>
<h1>Active Directory Health Report</h1>

<div>
<span class="badge">Critical: $criticalCount</span>
<span class="badge">Warnings: $warningCount</span>
<span class="badge">Info: $infoCount</span>
<span class="badge">Pass: $passCount</span>
</div>

<h2>Run Information</h2>
$runHtml

<h2>Forest Summary</h2>
$forestHtml

<h2>Domain Summary</h2>
$domainHtml

<h2>Domain Controller Summary</h2>
$dcHtml

<h2>Findings</h2>
$findingsHtml

<h2>External Command Results</h2>
$commandsHtml

<h2>Output Files</h2>
$filesHtml

</body>
</html>
"@

    $html | Out-File -FilePath $reportPath -Encoding UTF8

    $latestPath = Join-Path $OutputRoot "Latest_ADHealthReport.html"
    Copy-Item -Path $reportPath -Destination $latestPath -Force

    return $reportPath
}

Initialize-OutputFolders
Start-Transcript -Path $Script:TranscriptPath -Force | Out-Null

try {
    Write-Log "Starting Active Directory health collection. Output folder: $Script:RunRoot"

    if (-not (Test-IsAdministrator)) {
        Add-Finding -Severity "Warning" -Category "Execution Context" -Target $env:COMPUTERNAME -Message "PowerShell is not running elevated. Some tests may fail or return partial data."
        Write-Log "PowerShell is not running elevated." "WARN"
    }

    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name

    $runInfo = [pscustomobject]@{
        StartedAt               = $Script:StartedAt
        RunStamp                = $Script:RunStamp
        ComputerName            = $env:COMPUTERNAME
        UserName                = $currentIdentity
        OutputRoot              = $OutputRoot
        RunRoot                 = $Script:RunRoot
        RecentEventHours        = $RecentEventHours
        ReplicationWarningHours = $ReplicationWarningHours
        CommandTimeoutSeconds   = $CommandTimeoutSeconds
        PowerShellVersion       = $PSVersionTable.PSVersion.ToString()
        Elevated                = Test-IsAdministrator
    }

    Export-Data -Data $runInfo -Name "RunInfo" | Out-Null

    Write-Log "Loading ActiveDirectory module."

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Add-Finding -Severity "Critical" -Category "PowerShell Module" -Target "ActiveDirectory" -Message "The ActiveDirectory PowerShell module could not be loaded. Install RSAT AD DS tools or run from a domain controller. Error: $($_.Exception.Message)"
        throw
    }

    $dnsModuleAvailable = $false

    if (Get-Module -ListAvailable -Name DnsServer) {
        try {
            Import-Module DnsServer -ErrorAction Stop
            $dnsModuleAvailable = $true
            Write-Log "DnsServer module loaded."
        }
        catch {
            Add-Finding -Severity "Info" -Category "PowerShell Module" -Target "DnsServer" -Message "DnsServer module exists but could not be loaded. DNS deep checks will be partial. Error: $($_.Exception.Message)"
        }
    }
    else {
        Add-Finding -Severity "Info" -Category "PowerShell Module" -Target "DnsServer" -Message "DnsServer module was not found. DNS deep checks will be skipped."
    }

    $groupPolicyModuleAvailable = $false

    if (Get-Module -ListAvailable -Name GroupPolicy) {
        try {
            Import-Module GroupPolicy -ErrorAction Stop
            $groupPolicyModuleAvailable = $true
            Write-Log "GroupPolicy module loaded."
        }
        catch {
            Add-Finding -Severity "Info" -Category "PowerShell Module" -Target "GroupPolicy" -Message "GroupPolicy module exists but could not be loaded. GPO inventory will be skipped. Error: $($_.Exception.Message)"
        }
    }

    Write-Log "Discovering forest, domains and configuration naming context."

    $forest = Get-ADForest
    $rootDse = Get-ADRootDSE
    $configNamingContext = $rootDse.ConfigurationNamingContext

    $directoryServiceObject = $null

    try {
        $directoryServiceObject = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configNamingContext" -Properties tombstoneLifetime, msDS-DeletedObjectLifetime
    }
    catch {
        Add-Finding -Severity "Info" -Category "Forest Discovery" -Target "Directory Service Object" -Message $_.Exception.Message
    }

    $forestSummary = [pscustomobject]@{
        Name                       = $forest.Name
        RootDomain                 = $forest.RootDomain
        ForestMode                 = $forest.ForestMode
        SchemaMaster               = $forest.SchemaMaster
        DomainNamingMaster         = $forest.DomainNamingMaster
        GlobalCatalogs             = ($forest.GlobalCatalogs -join "; ")
        Sites                      = ($forest.Sites -join "; ")
        Domains                    = ($forest.Domains -join "; ")
        TombstoneLifetime          = if ($directoryServiceObject) { $directoryServiceObject.tombstoneLifetime } else { $null }
        DeletedObjectLifetime      = if ($directoryServiceObject) { $directoryServiceObject.'msDS-DeletedObjectLifetime' } else { $null }
        ConfigurationNamingContext = $configNamingContext
    }

    Export-Data -Data $forestSummary -Name "ForestSummary" | Out-Null

    $domainObjects = New-Object System.Collections.Generic.List[object]

    foreach ($domainName in $forest.Domains) {
        try {
            $domainObjects.Add((Get-ADDomain -Identity $domainName)) | Out-Null
        }
        catch {
            Add-Finding -Severity "Warning" -Category "Domain Discovery" -Target $domainName -Message $_.Exception.Message
        }
    }

    $domainSummary = foreach ($domain in $domainObjects) {
        [pscustomobject]@{
            DNSRoot              = $domain.DNSRoot
            NetBIOSName          = $domain.NetBIOSName
            DomainMode           = $domain.DomainMode
            PDCEmulator          = $domain.PDCEmulator
            RIDMaster            = $domain.RIDMaster
            InfrastructureMaster = $domain.InfrastructureMaster
            UsersContainer       = $domain.UsersContainer
            ComputersContainer   = $domain.ComputersContainer
            DistinguishedName    = $domain.DistinguishedName
        }
    }

    Export-Data -Data $domainSummary -Name "DomainSummary" | Out-Null

    Write-Log "Discovering domain controllers."

    $domainControllers = New-Object System.Collections.Generic.List[object]

    foreach ($domain in $domainObjects) {
        try {
            $dcs = Get-ADDomainController -Filter * -Server $domain.DNSRoot

            foreach ($dc in $dcs) {
                $domainControllers.Add([pscustomobject]@{
                    Domain               = $domain.DNSRoot
                    Name                 = $dc.Name
                    HostName             = $dc.HostName
                    Site                 = $dc.Site
                    IPv4Address          = $dc.IPv4Address
                    IPv6Address          = $dc.IPv6Address
                    IsGlobalCatalog      = $dc.IsGlobalCatalog
                    IsReadOnly           = $dc.IsReadOnly
                    OperatingSystem      = $dc.OperatingSystem
                    OperationMasterRoles = ($dc.OperationMasterRoles -join "; ")
                    DistinguishedName    = $dc.ComputerObjectDN
                }) | Out-Null
            }
        }
        catch {
            Add-Finding -Severity "Warning" -Category "Domain Controller Discovery" -Target $domain.DNSRoot -Message $_.Exception.Message
        }
    }

    Export-Data -Data $domainControllers -Name "DomainControllers" | Out-Null

    if ($domainControllers.Count -eq 0) {
        Add-Finding -Severity "Critical" -Category "Discovery" -Target $forest.Name -Message "No domain controllers were discovered."
        throw "No domain controllers discovered."
    }

    Write-Log "Collecting sites, subnets, site links, trusts, password policies and GPO inventory."

    $sites = @()
    $subnets = @()
    $siteLinks = @()
    $trusts = @()
    $passwordPolicies = New-Object System.Collections.Generic.List[object]
    $fineGrainedPasswordPolicies = New-Object System.Collections.Generic.List[object]
    $gpoInventory = New-Object System.Collections.Generic.List[object]

    try { $sites = @(Get-ADReplicationSite -Filter * -Properties *) } catch { Add-Finding -Severity "Info" -Category "Sites" -Target "Sites" -Message $_.Exception.Message; $sites = @() }
    try { $subnets = @(Get-ADReplicationSubnet -Filter * -Properties *) } catch { Add-Finding -Severity "Info" -Category "Sites" -Target "Subnets" -Message $_.Exception.Message; $subnets = @() }
    try { $siteLinks = @(Get-ADReplicationSiteLink -Filter * -Properties *) } catch { Add-Finding -Severity "Info" -Category "Sites" -Target "Site Links" -Message $_.Exception.Message; $siteLinks = @() }
    try { $trusts = @(Get-ADTrust -Filter *) } catch { Add-Finding -Severity "Info" -Category "Trusts" -Target "Trusts" -Message $_.Exception.Message; $trusts = @() }

    foreach ($domain in $domainObjects) {
        try {
            $policy = Get-ADDefaultDomainPasswordPolicy -Server $domain.DNSRoot
            $passwordPolicies.Add([pscustomobject]@{
                Domain                  = $domain.DNSRoot
                ComplexityEnabled       = $policy.ComplexityEnabled
                LockoutDuration         = $policy.LockoutDuration
                LockoutObservationWindow = $policy.LockoutObservationWindow
                LockoutThreshold        = $policy.LockoutThreshold
                MaxPasswordAge          = $policy.MaxPasswordAge
                MinPasswordAge          = $policy.MinPasswordAge
                MinPasswordLength       = $policy.MinPasswordLength
                PasswordHistoryCount    = $policy.PasswordHistoryCount
                ReversibleEncryptionEnabled = $policy.ReversibleEncryptionEnabled
            }) | Out-Null
        }
        catch {
            Add-Finding -Severity "Info" -Category "Password Policy" -Target $domain.DNSRoot -Message $_.Exception.Message
        }

        try {
            $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -Server $domain.DNSRoot -Properties *

            foreach ($fgpp in $fgpps) {
                $fineGrainedPasswordPolicies.Add([pscustomobject]@{
                    Domain                    = $domain.DNSRoot
                    Name                      = $fgpp.Name
                    Precedence                = $fgpp.Precedence
                    ComplexityEnabled         = $fgpp.ComplexityEnabled
                    LockoutDuration           = $fgpp.LockoutDuration
                    LockoutObservationWindow  = $fgpp.LockoutObservationWindow
                    LockoutThreshold          = $fgpp.LockoutThreshold
                    MaxPasswordAge            = $fgpp.MaxPasswordAge
                    MinPasswordAge            = $fgpp.MinPasswordAge
                    MinPasswordLength         = $fgpp.MinPasswordLength
                    PasswordHistoryCount      = $fgpp.PasswordHistoryCount
                    ReversibleEncryptionEnabled = $fgpp.ReversibleEncryptionEnabled
                    AppliesTo                 = ($fgpp.AppliesTo -join "; ")
                }) | Out-Null
            }
        }
        catch {
            Add-Finding -Severity "Info" -Category "Fine Grained Password Policy" -Target $domain.DNSRoot -Message $_.Exception.Message
        }

        if ($groupPolicyModuleAvailable) {
            try {
                $domainGpos = Get-GPO -All -Domain $domain.DNSRoot

                foreach ($gpo in $domainGpos) {
                    $gpoInventory.Add([pscustomobject]@{
                        Domain           = $domain.DNSRoot
                        DisplayName      = $gpo.DisplayName
                        Id               = $gpo.Id
                        Owner            = $gpo.Owner
                        CreationTime     = $gpo.CreationTime
                        ModificationTime = $gpo.ModificationTime
                        UserVersion      = $gpo.User.DSVersion
                        ComputerVersion  = $gpo.Computer.DSVersion
                        GpoStatus        = $gpo.GpoStatus
                    }) | Out-Null
                }
            }
            catch {
                Add-Finding -Severity "Info" -Category "GPO Inventory" -Target $domain.DNSRoot -Message $_.Exception.Message
            }
        }
    }

    Export-Data -Data $sites -Name "ADSites" | Out-Null
    Export-Data -Data $subnets -Name "ADSubnets" | Out-Null
    Export-Data -Data $siteLinks -Name "ADSiteLinks" | Out-Null
    Export-Data -Data $trusts -Name "ADTrusts" | Out-Null
    Export-Data -Data $passwordPolicies -Name "DefaultDomainPasswordPolicies" | Out-Null
    Export-Data -Data $fineGrainedPasswordPolicies -Name "FineGrainedPasswordPolicies" | Out-Null
    Export-Data -Data $gpoInventory -Name "GPOInventory" | Out-Null

    Write-Log "Collecting domain controller system, share, service, port and event health."

    $dcSystemInfo = New-Object System.Collections.Generic.List[object]
    $shareTests = New-Object System.Collections.Generic.List[object]
    $serviceHealth = New-Object System.Collections.Generic.List[object]
    $tcpPortHealth = New-Object System.Collections.Generic.List[object]
    $eventHealth = New-Object System.Collections.Generic.List[object]
    $startEventTime = (Get-Date).AddHours(-1 * $RecentEventHours)

    $baseRequiredPorts = @(88, 135, 389, 445, 464, 9389)
    $conditionalPorts = @(53, 636, 3268, 3269, 5722)
    $allPorts = ($baseRequiredPorts + $conditionalPorts) | Sort-Object -Unique

    $serviceNames = @("NTDS", "KDC", "Netlogon", "W32Time", "ADWS", "DNS", "DFSR", "NtFrs", "IsmServ")
    $strictServices = @("NTDS", "KDC", "Netlogon", "W32Time", "ADWS")

    foreach ($dc in $domainControllers) {
        $target = $dc.HostName
        Write-Log "Checking domain controller: $target"

        $pingOk = $false

        try {
            $pingOk = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction Stop
        }
        catch {
            $pingOk = $false
        }

        if (-not $pingOk) {
            Add-Finding -Severity "Warning" -Category "Connectivity" -Target $target -Message "ICMP ping failed or was blocked. TCP tests may still succeed."
        }

        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $target -ErrorAction Stop
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $target -ErrorAction Stop

            $dcSystemInfo.Add([pscustomobject]@{
                Domain                = $dc.Domain
                ComputerName          = $target
                Ping                  = $pingOk
                Manufacturer          = $cs.Manufacturer
                Model                 = $cs.Model
                TotalPhysicalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                Caption               = $os.Caption
                Version               = $os.Version
                BuildNumber           = $os.BuildNumber
                InstallDate           = $os.InstallDate
                LastBootUpTime        = $os.LastBootUpTime
                UptimeDays            = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
                WindowsDirectory      = $os.WindowsDirectory
                SystemDirectory       = $os.SystemDirectory
            }) | Out-Null
        }
        catch {
            $dcSystemInfo.Add([pscustomobject]@{
                Domain                = $dc.Domain
                ComputerName          = $target
                Ping                  = $pingOk
                Manufacturer          = ""
                Model                 = ""
                TotalPhysicalMemoryGB = $null
                Caption               = ""
                Version               = ""
                BuildNumber           = ""
                InstallDate           = $null
                LastBootUpTime        = $null
                UptimeDays            = $null
                WindowsDirectory      = ""
                SystemDirectory       = ""
                Error                 = $_.Exception.Message
            }) | Out-Null

            Add-Finding -Severity "Info" -Category "CIM Collection" -Target $target -Message $_.Exception.Message
        }

        foreach ($share in @("SYSVOL", "NETLOGON")) {
            $unc = "\\$target\$share"
            $exists = $false
            $errorMessage = ""

            try {
                $exists = Test-Path -Path $unc -ErrorAction Stop
            }
            catch {
                $errorMessage = $_.Exception.Message
            }

            $shareTests.Add([pscustomobject]@{
                ComputerName = $target
                Share        = $share
                UNC          = $unc
                Accessible   = $exists
                Error        = $errorMessage
            }) | Out-Null

            if (-not $exists) {
                Add-Finding -Severity "Warning" -Category "SYSVOL/NETLOGON" -Target $unc -Message "The share was not accessible from the server running this script. $errorMessage"
            }
        }

        foreach ($serviceName in $serviceNames) {
            try {
                $svc = Get-Service -ComputerName $target -Name $serviceName -ErrorAction Stop

                $serviceHealth.Add([pscustomobject]@{
                    ComputerName = $target
                    ServiceName  = $serviceName
                    DisplayName  = $svc.DisplayName
                    Status       = $svc.Status
                    StartType    = $svc.StartType
                    Found        = $true
                    Error        = ""
                }) | Out-Null

                if (($strictServices -contains $serviceName) -and ($svc.Status -ne "Running")) {
                    Add-Finding -Severity "Critical" -Category "Service Health" -Target "$target / $serviceName" -Message "Required service is not running. Current status: $($svc.Status)."
                }

                if ((@("DNS", "DFSR", "NtFrs") -contains $serviceName) -and ($svc.Status -eq "Stopped")) {
                    Add-Finding -Severity "Warning" -Category "Service Health" -Target "$target / $serviceName" -Message "Service exists but is stopped. Validate whether this is expected."
                }
            }
            catch {
                $serviceHealth.Add([pscustomobject]@{
                    ComputerName = $target
                    ServiceName  = $serviceName
                    DisplayName  = ""
                    Status       = "NotFoundOrUnavailable"
                    StartType    = ""
                    Found        = $false
                    Error        = $_.Exception.Message
                }) | Out-Null

                if ($strictServices -contains $serviceName) {
                    Add-Finding -Severity "Warning" -Category "Service Health" -Target "$target / $serviceName" -Message "Required service could not be queried or was not found. $($_.Exception.Message)"
                }
            }
        }

        foreach ($port in $allPorts) {
            $portResult = Test-TcpPort -ComputerName $target -Port $port -TimeoutMilliseconds $TcpTimeoutMilliseconds
            $tcpPortHealth.Add($portResult) | Out-Null

            $isRequired = $baseRequiredPorts -contains $port

            if (($port -eq 3268) -and ($dc.IsGlobalCatalog)) {
                $isRequired = $true
            }

            if (($port -eq 53) -and (@($serviceHealth | Where-Object { $_.ComputerName -eq $target -and $_.ServiceName -eq "DNS" -and $_.Status -eq "Running" }).Count -gt 0)) {
                $isRequired = $true
            }

            if (($isRequired) -and (-not $portResult.TcpTestSucceeded)) {
                Add-Finding -Severity "Warning" -Category "TCP Port" -Target "$target`:$port" -Message "Common AD port did not respond from the server running this script. Error: $($portResult.Error)"
            }
        }

        $events = Get-RecentDcEvents -ComputerName $target -StartTime $startEventTime -MaxEvents $MaxEventsPerLog

        foreach ($event in $events) {
            $eventHealth.Add($event) | Out-Null
        }
    }

    Export-Data -Data $dcSystemInfo -Name "DomainControllerSystemInfo" | Out-Null
    Export-Data -Data $shareTests -Name "SysvolNetlogonShareTests" | Out-Null
    Export-Data -Data $serviceHealth -Name "DomainControllerServiceHealth" | Out-Null
    Export-Data -Data $tcpPortHealth -Name "DomainControllerTcpPortHealth" | Out-Null
    Export-Data -Data $eventHealth -Name "RecentDcCriticalWarningErrorEvents" | Out-Null

    $eventSummary = @($eventHealth |
        Group-Object ComputerName, LogName, LevelDisplayName |
        ForEach-Object {
            $parts = $_.Name -split ", "

            [pscustomobject]@{
                ComputerName     = if ($parts.Count -ge 1) { $parts[0] } else { "" }
                LogName          = if ($parts.Count -ge 2) { $parts[1] } else { "" }
                LevelDisplayName = if ($parts.Count -ge 3) { $parts[2] } else { "" }
                Count            = $_.Count
            }
        }
    )

    Export-Data -Data $eventSummary -Name "RecentEventSummary" | Out-Null

    foreach ($row in $eventSummary) {
        if ($row.LevelDisplayName -eq "Error" -and $row.Count -gt 0) {
            Add-Finding -Severity "Info" -Category "Event Logs" -Target "$($row.ComputerName) / $($row.LogName)" -Message "$($row.Count) error events found in the last $RecentEventHours hours. Review event export."
        }
    }

    Write-Log "Collecting replication metadata and failures."

    $replicationPartnerMetadata = New-Object System.Collections.Generic.List[object]
    $replicationFailures = New-Object System.Collections.Generic.List[object]

    foreach ($dc in $domainControllers) {
        $target = $dc.HostName

        try {
            $metadata = Get-ADReplicationPartnerMetadata -Target $target -Scope Server -ErrorAction Stop

            foreach ($item in $metadata) {
                $lastSuccessAgeHours = $null

                if ($item.LastReplicationSuccess) {
                    $lastSuccessAgeHours = [math]::Round(((Get-Date) - $item.LastReplicationSuccess).TotalHours, 2)
                }

                $row = [pscustomobject]@{
                    TargetServer                    = $target
                    Partner                         = $item.Partner
                    Partition                       = $item.Partition
                    PartnerType                     = $item.PartnerType
                    IntersiteTransportType          = $item.IntersiteTransportType
                    LastReplicationAttempt          = $item.LastReplicationAttempt
                    LastReplicationSuccess          = $item.LastReplicationSuccess
                    LastReplicationResult           = $item.LastReplicationResult
                    LastReplicationResultMessage    = $item.LastReplicationResultMessage
                    ConsecutiveReplicationFailures  = $item.ConsecutiveReplicationFailures
                    LastSuccessAgeHours             = $lastSuccessAgeHours
                }

                $replicationPartnerMetadata.Add($row) | Out-Null

                if (($row.LastReplicationResult -ne 0) -or ($row.ConsecutiveReplicationFailures -gt 0)) {
                    Add-Finding -Severity "Critical" -Category "Replication" -Target "$target from $($row.Partner)" -Message "Replication result: $($row.LastReplicationResult). Consecutive failures: $($row.ConsecutiveReplicationFailures). $($row.LastReplicationResultMessage)"
                }
                elseif (($null -ne $lastSuccessAgeHours) -and ($lastSuccessAgeHours -gt $ReplicationWarningHours)) {
                    Add-Finding -Severity "Warning" -Category "Replication" -Target "$target from $($row.Partner)" -Message "Last successful replication is $lastSuccessAgeHours hours old."
                }
            }
        }
        catch {
            Add-Finding -Severity "Warning" -Category "Replication Metadata" -Target $target -Message $_.Exception.Message
        }

        try {
            $failures = Get-ADReplicationFailure -Target $target -Scope Server -ErrorAction Stop

            foreach ($failure in $failures) {
                $replicationFailures.Add([pscustomobject]@{
                    TargetServer     = $target
                    Server           = $failure.Server
                    Partner          = $failure.Partner
                    FirstFailureTime = $failure.FirstFailureTime
                    FailureCount     = $failure.FailureCount
                    FailureType      = $failure.FailureType
                    LastError        = $failure.LastError
                    LastErrorMessage = $failure.LastErrorMessage
                }) | Out-Null

                Add-Finding -Severity "Critical" -Category "Replication Failure" -Target "$target / $($failure.Partner)" -Message "Failure count: $($failure.FailureCount). Last error: $($failure.LastError) $($failure.LastErrorMessage)"
            }
        }
        catch {
            Add-Finding -Severity "Info" -Category "Replication Failure Collection" -Target $target -Message $_.Exception.Message
        }
    }

    Export-Data -Data $replicationPartnerMetadata -Name "ReplicationPartnerMetadata" | Out-Null
    Export-Data -Data $replicationFailures -Name "ReplicationFailures" | Out-Null

    Write-Log "Running DFSR migration state commands when available."

    $dfsrmigPath = Get-ExternalCommandPath -Name "dfsrmig.exe"

    if ($dfsrmigPath) {
        Invoke-ExternalCommand -FilePath $dfsrmigPath -Arguments "/getglobalstate" -OutputName "dfsrmig_getglobalstate" | Out-Null
        Invoke-ExternalCommand -FilePath $dfsrmigPath -Arguments "/getmigrationstate" -OutputName "dfsrmig_getmigrationstate" | Out-Null
    }

    Write-Log "Running time service checks."

    $w32tmPath = Get-ExternalCommandPath -Name "w32tm.exe"

    if ($w32tmPath) {
        foreach ($domain in $domainObjects) {
            Invoke-ExternalCommand -FilePath $w32tmPath -Arguments "/monitor /domain:$($domain.DNSRoot)" -OutputName "w32tm_monitor_$($domain.DNSRoot)" | Out-Null
        }

        foreach ($dc in $domainControllers) {
            Invoke-ExternalCommand -FilePath $w32tmPath -Arguments "/query /computer:$($dc.HostName) /status" -OutputName "w32tm_status_$($dc.HostName)" | Out-Null
        }
    }

    if (-not $SkipRepAdmin) {
        Write-Log "Running repadmin commands."

        $repadminPath = Get-ExternalCommandPath -Name "repadmin.exe"

        if ($repadminPath) {
            Invoke-ExternalCommand -FilePath $repadminPath -Arguments "/replsummary" -OutputName "repadmin_replsummary" | Out-Null
            Invoke-ExternalCommand -FilePath $repadminPath -Arguments "/showrepl * /csv" -OutputName "repadmin_showrepl_all_csv" | Out-Null
            Invoke-ExternalCommand -FilePath $repadminPath -Arguments "/showrepl * /errorsonly" -OutputName "repadmin_showrepl_errorsonly" | Out-Null
            Invoke-ExternalCommand -FilePath $repadminPath -Arguments "/queue *" -OutputName "repadmin_queue_all" | Out-Null
            Invoke-ExternalCommand -FilePath $repadminPath -Arguments "/showutdvec * * /latency" -OutputName "repadmin_showutdvec_latency" | Out-Null
        }
    }
    else {
        Add-Finding -Severity "Info" -Category "Skipped" -Target "repadmin" -Message "repadmin checks were skipped by parameter."
    }

    if (-not $SkipDcDiag) {
        Write-Log "Running dcdiag commands. This can take several minutes in larger environments."

        $dcdiagPath = Get-ExternalCommandPath -Name "dcdiag.exe"

        if ($dcdiagPath) {
            $dcdiagFull = Invoke-ExternalCommand -FilePath $dcdiagPath -Arguments "/e /c /v" -OutputName "dcdiag_enterprise_comprehensive_verbose" -TimeoutSeconds $CommandTimeoutSeconds
            $dcdiagDns = Invoke-ExternalCommand -FilePath $dcdiagPath -Arguments "/e /test:dns /v" -OutputName "dcdiag_enterprise_dns_verbose" -TimeoutSeconds $CommandTimeoutSeconds

            $dcdiagParsed = New-Object System.Collections.Generic.List[object]

            if ($dcdiagFull.StdOutFile) {
                foreach ($item in (Convert-DcDiagFindings -Path $dcdiagFull.StdOutFile)) {
                    $dcdiagParsed.Add($item) | Out-Null
                }
            }

            if ($dcdiagDns.StdOutFile) {
                foreach ($item in (Convert-DcDiagFindings -Path $dcdiagDns.StdOutFile)) {
                    $dcdiagParsed.Add($item) | Out-Null
                }
            }

            Export-Data -Data $dcdiagParsed -Name "DcDiagParsedFindings" | Out-Null

            foreach ($item in ($dcdiagParsed | Select-Object -First 75)) {
                $severity = "Info"

                if ($item.Line -match "failed test|fatal|error") {
                    $severity = "Warning"
                }

                Add-Finding -Severity $severity -Category "DCDIAG Parsed" -Target "Line $($item.LineNumber)" -Message $item.Line -EvidenceFile $item.SourceFile
            }
        }
    }
    else {
        Add-Finding -Severity "Info" -Category "Skipped" -Target "dcdiag" -Message "dcdiag checks were skipped by parameter."
    }

    Write-Log "Collecting DNS configuration and DNS resolution checks."

    $dnsZones = New-Object System.Collections.Generic.List[object]
    $dnsForwarders = New-Object System.Collections.Generic.List[object]
    $dnsScavenging = New-Object System.Collections.Generic.List[object]
    $dnsZoneAging = New-Object System.Collections.Generic.List[object]
    $dnsResolutionTests = New-Object System.Collections.Generic.List[object]

    if (($dnsModuleAvailable) -and (-not $SkipDnsDeepChecks)) {
        foreach ($dc in $domainControllers) {
            $target = $dc.HostName
            $dnsService = @($serviceHealth | Where-Object { $_.ComputerName -eq $target -and $_.ServiceName -eq "DNS" -and $_.Status -eq "Running" })

            if (@($dnsService).Count -eq 0) {
                continue
            }

            try {
                $zones = Get-DnsServerZone -ComputerName $target -ErrorAction Stop

                foreach ($zone in $zones) {
                    $dnsZones.Add([pscustomobject]@{
                        DnsServer           = $target
                        ZoneName            = $zone.ZoneName
                        ZoneType            = $zone.ZoneType
                        IsDsIntegrated      = $zone.IsDsIntegrated
                        IsAutoCreated       = $zone.IsAutoCreated
                        IsReverseLookupZone = $zone.IsReverseLookupZone
                        DynamicUpdate       = $zone.DynamicUpdate
                        ReplicationScope    = $zone.ReplicationScope
                    }) | Out-Null

                    try {
                        $aging = Get-DnsServerZoneAging -ComputerName $target -Name $zone.ZoneName -ErrorAction Stop

                        $dnsZoneAging.Add([pscustomobject]@{
                            DnsServer         = $target
                            ZoneName          = $zone.ZoneName
                            AgingEnabled      = $aging.AgingEnabled
                            RefreshInterval   = $aging.RefreshInterval
                            NoRefreshInterval = $aging.NoRefreshInterval
                            ScavengeServers   = ($aging.ScavengeServers -join "; ")
                        }) | Out-Null
                    }
                    catch {
                        $dnsZoneAging.Add([pscustomobject]@{
                            DnsServer         = $target
                            ZoneName          = $zone.ZoneName
                            AgingEnabled      = $null
                            RefreshInterval   = $null
                            NoRefreshInterval = $null
                            ScavengeServers   = ""
                            Error             = $_.Exception.Message
                        }) | Out-Null
                    }
                }
            }
            catch {
                Add-Finding -Severity "Info" -Category "DNS Zones" -Target $target -Message $_.Exception.Message
            }

            try {
                $forwarders = Get-DnsServerForwarder -ComputerName $target -ErrorAction Stop

                $dnsForwarders.Add([pscustomobject]@{
                    DnsServer        = $target
                    IPAddress        = ($forwarders.IPAddress -join "; ")
                    UseRootHint      = $forwarders.UseRootHint
                    Timeout          = $forwarders.Timeout
                    EnableReordering = $forwarders.EnableReordering
                }) | Out-Null
            }
            catch {
                Add-Finding -Severity "Info" -Category "DNS Forwarders" -Target $target -Message $_.Exception.Message
            }

            try {
                $scavenging = Get-DnsServerScavenging -ComputerName $target -ErrorAction Stop

                $dnsScavenging.Add([pscustomobject]@{
                    DnsServer          = $target
                    ScavengingState    = $scavenging.ScavengingState
                    ScavengingInterval = $scavenging.ScavengingInterval
                    LastScavengeTime   = $scavenging.LastScavengeTime
                }) | Out-Null
            }
            catch {
                Add-Finding -Severity "Info" -Category "DNS Scavenging" -Target $target -Message $_.Exception.Message
            }
        }
    }
    else {
        Add-Finding -Severity "Info" -Category "DNS" -Target "DNS Deep Checks" -Message "DNS deep checks skipped because the DnsServer module is unavailable or SkipDnsDeepChecks was used."
    }

    if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
        foreach ($dnsServer in $domainControllers) {
            $targetDnsServer = $dnsServer.HostName
            $recordsToTest = New-Object System.Collections.Generic.List[object]

            $recordsToTest.Add([pscustomobject]@{ Name = "_ldap._tcp.dc._msdcs.$($forest.RootDomain)"; Type = "SRV"; Scope = "Forest" }) | Out-Null
            $recordsToTest.Add([pscustomobject]@{ Name = "_gc._tcp.$($forest.RootDomain)"; Type = "SRV"; Scope = "Forest" }) | Out-Null

            foreach ($domain in $domainObjects) {
                $recordsToTest.Add([pscustomobject]@{ Name = "_ldap._tcp.$($domain.DNSRoot)"; Type = "SRV"; Scope = $domain.DNSRoot }) | Out-Null
                $recordsToTest.Add([pscustomobject]@{ Name = "_kerberos._tcp.$($domain.DNSRoot)"; Type = "SRV"; Scope = $domain.DNSRoot }) | Out-Null
            }

            foreach ($record in $recordsToTest) {
                try {
                    $answers = Resolve-DnsName -Name $record.Name -Type $record.Type -Server $targetDnsServer -ErrorAction Stop

                    $dnsResolutionTests.Add([pscustomobject]@{
                        DnsServer   = $targetDnsServer
                        QueryName   = $record.Name
                        QueryType   = $record.Type
                        Scope       = $record.Scope
                        Success     = $true
                        AnswerCount = @($answers).Count
                        Error       = ""
                    }) | Out-Null
                }
                catch {
                    $dnsResolutionTests.Add([pscustomobject]@{
                        DnsServer   = $targetDnsServer
                        QueryName   = $record.Name
                        QueryType   = $record.Type
                        Scope       = $record.Scope
                        Success     = $false
                        AnswerCount = 0
                        Error       = $_.Exception.Message
                    }) | Out-Null

                    Add-Finding -Severity "Warning" -Category "DNS Resolution" -Target "$targetDnsServer / $($record.Name)" -Message $_.Exception.Message
                }
            }

            foreach ($dcToResolve in $domainControllers) {
                try {
                    $answers = Resolve-DnsName -Name $dcToResolve.HostName -Type A -Server $targetDnsServer -ErrorAction Stop

                    $dnsResolutionTests.Add([pscustomobject]@{
                        DnsServer   = $targetDnsServer
                        QueryName   = $dcToResolve.HostName
                        QueryType   = "A"
                        Scope       = "DomainControllerARecord"
                        Success     = $true
                        AnswerCount = @($answers).Count
                        Error       = ""
                    }) | Out-Null
                }
                catch {
                    $dnsResolutionTests.Add([pscustomobject]@{
                        DnsServer   = $targetDnsServer
                        QueryName   = $dcToResolve.HostName
                        QueryType   = "A"
                        Scope       = "DomainControllerARecord"
                        Success     = $false
                        AnswerCount = 0
                        Error       = $_.Exception.Message
                    }) | Out-Null

                    Add-Finding -Severity "Warning" -Category "DNS Resolution" -Target "$targetDnsServer / $($dcToResolve.HostName)" -Message $_.Exception.Message
                }
            }
        }
    }
    else {
        Add-Finding -Severity "Info" -Category "DNS Resolution" -Target "Resolve-DnsName" -Message "Resolve-DnsName was not available on this server."
    }

    Export-Data -Data $dnsZones -Name "DnsZones" | Out-Null
    Export-Data -Data $dnsForwarders -Name "DnsForwarders" | Out-Null
    Export-Data -Data $dnsScavenging -Name "DnsScavenging" | Out-Null
    Export-Data -Data $dnsZoneAging -Name "DnsZoneAging" | Out-Null
    Export-Data -Data $dnsResolutionTests -Name "DnsResolutionTests" | Out-Null

    Write-Log "Collecting domain object counts."

    $domainObjectCounts = New-Object System.Collections.Generic.List[object]

    foreach ($domain in $domainObjects) {
        $queries = @(
            @{ Name = "Users"; Filter = 'ObjectClass -eq "user"' },
            @{ Name = "EnabledUsers"; Filter = 'ObjectClass -eq "user" -and Enabled -eq $true' },
            @{ Name = "DisabledUsers"; Filter = 'ObjectClass -eq "user" -and Enabled -eq $false' },
            @{ Name = "Computers"; Filter = 'ObjectClass -eq "computer"' },
            @{ Name = "EnabledComputers"; Filter = 'ObjectClass -eq "computer" -and Enabled -eq $true' },
            @{ Name = "DisabledComputers"; Filter = 'ObjectClass -eq "computer" -and Enabled -eq $false' },
            @{ Name = "Groups"; Filter = 'ObjectClass -eq "group"' }
        )

        foreach ($query in $queries) {
            try {
                $count = (Get-ADObject -Filter $query.Filter -Server $domain.DNSRoot -ResultSetSize $null | Measure-Object).Count

                $domainObjectCounts.Add([pscustomobject]@{
                    Domain = $domain.DNSRoot
                    Type   = $query.Name
                    Count  = $count
                    Error  = ""
                }) | Out-Null
            }
            catch {
                $domainObjectCounts.Add([pscustomobject]@{
                    Domain = $domain.DNSRoot
                    Type   = $query.Name
                    Count  = $null
                    Error  = $_.Exception.Message
                }) | Out-Null
            }
        }
    }

    Export-Data -Data $domainObjectCounts -Name "DomainObjectCounts" | Out-Null

    Write-Log "Collecting privileged group membership summary."

    $privilegedGroupMembership = New-Object System.Collections.Generic.List[object]

    $privilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "DnsAdmins"
    )

    foreach ($domain in $domainObjects) {
        foreach ($groupName in $privilegedGroups) {
            try {
                $group = Get-ADGroup -Identity $groupName -Server $domain.DNSRoot -ErrorAction Stop
                $members = Get-ADGroupMember -Identity $group.DistinguishedName -Server $domain.DNSRoot -Recursive -ErrorAction Stop

                foreach ($member in $members) {
                    $privilegedGroupMembership.Add([pscustomobject]@{
                        Domain                    = $domain.DNSRoot
                        GroupName                 = $groupName
                        MemberName                = $member.Name
                        MemberSamAccountName      = $member.SamAccountName
                        MemberObjectClass         = $member.ObjectClass
                        MemberDistinguishedName   = $member.DistinguishedName
                        Error                     = ""
                    }) | Out-Null
                }
            }
            catch {
                $privilegedGroupMembership.Add([pscustomobject]@{
                    Domain                    = $domain.DNSRoot
                    GroupName                 = $groupName
                    MemberName                = ""
                    MemberSamAccountName      = ""
                    MemberObjectClass         = ""
                    MemberDistinguishedName   = ""
                    Error                     = $_.Exception.Message
                }) | Out-Null
            }
        }
    }

    Export-Data -Data $privilegedGroupMembership -Name "PrivilegedGroupMembership" | Out-Null

    Write-Log "Building domain controller summary."

    $dcSummary = foreach ($dc in $domainControllers) {
        $sysvol = $shareTests | Where-Object { $_.ComputerName -eq $dc.HostName -and $_.Share -eq "SYSVOL" } | Select-Object -First 1
        $netlogon = $shareTests | Where-Object { $_.ComputerName -eq $dc.HostName -and $_.Share -eq "NETLOGON" } | Select-Object -First 1

        $criticalServiceIssues = @($serviceHealth | Where-Object {
            $_.ComputerName -eq $dc.HostName -and
            ($strictServices -contains $_.ServiceName) -and
            $_.Status -ne "Running"
        }).Count

        $tcpIssues = @($tcpPortHealth | Where-Object {
            $_.ComputerName -eq $dc.HostName -and
            $_.TcpTestSucceeded -eq $false -and
            ($baseRequiredPorts -contains $_.Port)
        }).Count

        $replIssues = @($replicationPartnerMetadata | Where-Object {
            $_.TargetServer -eq $dc.HostName -and
            (($_.LastReplicationResult -ne 0) -or ($_.ConsecutiveReplicationFailures -gt 0))
        }).Count

        $eventErrors = @($eventHealth | Where-Object {
            $_.ComputerName -eq $dc.HostName -and
            $_.LevelDisplayName -eq "Error"
        }).Count

        [pscustomobject]@{
            Domain                = $dc.Domain
            Name                  = $dc.Name
            HostName              = $dc.HostName
            Site                  = $dc.Site
            IPv4Address           = $dc.IPv4Address
            IsGlobalCatalog       = $dc.IsGlobalCatalog
            IsReadOnly            = $dc.IsReadOnly
            OperationMasterRoles  = $dc.OperationMasterRoles
            SysvolAccessible      = if ($sysvol) { $sysvol.Accessible } else { $false }
            NetlogonAccessible    = if ($netlogon) { $netlogon.Accessible } else { $false }
            CriticalServiceIssues = $criticalServiceIssues
            RequiredTcpIssues     = $tcpIssues
            ReplicationIssues     = $replIssues
            RecentErrorEvents     = $eventErrors
        }
    }

    Export-Data -Data $dcSummary -Name "DomainControllerSummary" | Out-Null

    Add-Finding -Severity "Pass" -Category "Script" -Target $env:COMPUTERNAME -Message "Active Directory health collection completed. Review the HTML report and CSV files."

    Export-Data -Data $Script:Findings -Name "Findings" | Out-Null
    Export-Data -Data $Script:CommandResults -Name "ExternalCommandResults" | Out-Null

    $outputFiles = Get-ChildItem -Path $Script:RunRoot -Recurse -File | Select-Object FullName, Length, LastWriteTime
    Export-Data -Data $outputFiles -Name "OutputFiles" | Out-Null

    $reportPath = New-HtmlReport -RunInfo $runInfo `
        -ForestSummary $forestSummary `
        -DomainSummary $domainSummary `
        -DcSummary $dcSummary `
        -Findings $Script:Findings `
        -CommandResults $Script:CommandResults `
        -OutputFiles $outputFiles

    Write-Log "Report created: $reportPath" "OK"
    Write-Log "Latest report shortcut: $(Join-Path $OutputRoot 'Latest_ADHealthReport.html')" "OK"
    Write-Log "Active Directory health collection completed." "OK"
}
catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    Add-Finding -Severity "Critical" -Category "Script" -Target $env:COMPUTERNAME -Message $_.Exception.Message

    try {
        Export-Data -Data $Script:Findings -Name "Findings" | Out-Null
        Export-Data -Data $Script:CommandResults -Name "ExternalCommandResults" | Out-Null
    }
    catch { }

    throw
}
finally {
    try {
        Stop-Transcript | Out-Null
    }
    catch { }
}
