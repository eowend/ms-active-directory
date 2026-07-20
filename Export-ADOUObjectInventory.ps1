<#
.SYNOPSIS
    Exports an inventory of all Active Directory objects located under a selected OU.

.DESCRIPTION
    Loads the ActiveDirectory PowerShell module and attempts to install the required
    RSAT component when the module is unavailable.

    The script displays a graphical selector for choosing the parent organizational
    unit. It then retrieves every Active Directory object within the selected scope
    and exports a normalized inventory to a timestamped CSV file.

    By default, the search includes every descendant below the selected OU.

.PARAMETER Server
    Optional domain controller or Active Directory domain name to use.

.PARAMETER SearchScope
    Controls the depth of the search.

    OneLevel:
        Includes only direct child objects.

    Subtree:
        Includes direct children and all descendant objects.

.PARAMETER IncludeSelectedOU
    Includes the selected parent OU itself in the CSV report.

.EXAMPLE
    .\Export-ADOUObjectInventory.ps1

.EXAMPLE
    .\Export-ADOUObjectInventory.ps1 -SearchScope OneLevel

.EXAMPLE
    .\Export-ADOUObjectInventory.ps1 -Server "DC01.contoso.com"

.NOTES
    File Name : Export-ADOUObjectInventory.ps1
    Author    : Juan Ortiz
    Version   : 1.0.0
    Created   : 2026-07-20
    Updated   : 2026-07-20

    Requirements:
      - Windows PowerShell 5.1
      - Access to an Active Directory domain
      - Permission to read the selected OU
      - Administrator rights if RSAT must be installed

.LINK
    https://learn.microsoft.com/powershell/module/activedirectory/get-adobject

.LINK
    https://learn.microsoft.com/powershell/module/activedirectory/get-adorganizationalunit

.LINK
    https://learn.microsoft.com/windows-server/administration/install-remote-server-administration-tools
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [ValidateSet('OneLevel', 'Subtree')]
    [string]$SearchScope = 'Subtree',

    [Parameter(Mandatory = $false)]
    [switch]$IncludeSelectedOU,

    [Parameter(Mandatory = $false, DontShow = $true)]
    [switch]$IsolatedProcess
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Process isolation

if (-not $IsolatedProcess) {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw 'Save the script as a .ps1 file before running it.'
    }

    $powerShellPath = Join-Path `
        -Path $env:SystemRoot `
        -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'

    if (-not (Test-Path -LiteralPath $powerShellPath)) {
        throw "Windows PowerShell was not found at '$powerShellPath'."
    }

    $arguments = @(
        '-NoLogo'
        '-NoProfile'
        '-STA'
        '-ExecutionPolicy'
        'Bypass'
        '-File'
        $PSCommandPath
        '-IsolatedProcess'
        '-SearchScope'
        $SearchScope
    )

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $arguments += @('-Server', $Server)
    }

    if ($IncludeSelectedOU) {
        $arguments += '-IncludeSelectedOU'
    }

    Write-Host 'Starting the Active Directory inventory in a clean PowerShell process...' `
        -ForegroundColor Cyan

    Write-Host "PowerShell engine: $powerShellPath" -ForegroundColor DarkGray
    Write-Host ''

    & $powerShellPath @arguments

    $childExitCode = $LASTEXITCODE

    if ($childExitCode -ne 0) {
        throw "The isolated process ended with exit code $childExitCode."
    }

    return
}

#endregion Process isolation

#region Functions

function Test-IsAdministrator {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    $principal = New-Object `
        System.Security.Principal.WindowsPrincipal($identity)

    return $principal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Import-ActiveDirectoryModule {
    [CmdletBinding()]
    param()

    $module = Get-Module `
        -ListAvailable `
        -Name 'ActiveDirectory' |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $module) {
        Write-Host 'The ActiveDirectory module was not found.' `
            -ForegroundColor Yellow

        if (-not (Test-IsAdministrator)) {
            throw (
                'The ActiveDirectory module is not installed. ' +
                'Run the script as an administrator so RSAT can be installed.'
            )
        }

        $operatingSystem = Get-CimInstance `
            -ClassName Win32_OperatingSystem `
            -ErrorAction Stop

        $isWindowsClient = ([int]$operatingSystem.ProductType -eq 1)

        if ($isWindowsClient) {
            $capabilityName =
                'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'

            $capability = Get-WindowsCapability `
                -Online `
                -Name $capabilityName `
                -ErrorAction Stop

            if ($capability.State -ne 'Installed') {
                Write-Host 'Installing Active Directory RSAT tools...' `
                    -ForegroundColor Cyan

                Add-WindowsCapability `
                    -Online `
                    -Name $capabilityName `
                    -ErrorAction Stop |
                    Out-Null
            }
        }
        else {
            Import-Module ServerManager -ErrorAction Stop

            $feature = Get-WindowsFeature `
                -Name 'RSAT-AD-PowerShell' `
                -ErrorAction Stop

            if (-not $feature.Installed) {
                Write-Host 'Installing RSAT-AD-PowerShell...' `
                    -ForegroundColor Cyan

                $result = Install-WindowsFeature `
                    -Name 'RSAT-AD-PowerShell' `
                    -IncludeAllSubFeature `
                    -ErrorAction Stop

                if (-not $result.Success) {
                    throw 'RSAT-AD-PowerShell could not be installed.'
                }
            }
        }
    }

    Import-Module ActiveDirectory -Force -ErrorAction Stop

    $loadedModule = Get-Module `
        -Name ActiveDirectory |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $loadedModule) {
        throw 'The ActiveDirectory module could not be loaded.'
    }

    Write-Host (
        'Loaded ActiveDirectory module version {0}.' -f
        $loadedModule.Version
    ) -ForegroundColor DarkGray
}

function Select-ParentOU {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$OrganizationalUnits
    )

    $outGridView = Get-Command `
        -Name Out-GridView `
        -ErrorAction SilentlyContinue

    if (-not $outGridView) {
        throw 'Out-GridView is not available on this computer.'
    }

    $selection = $OrganizationalUnits |
        Select-Object `
            Name,
            CanonicalName,
            DistinguishedName,
            Description,
            ProtectedFromAccidentalDeletion |
        Sort-Object CanonicalName |
        Out-GridView `
            -Title 'Select the parent Organizational Unit' `
            -OutputMode Single

    if (-not $selection) {
        throw [System.OperationCanceledException]::new(
            'OU selection was canceled.'
        )
    }

    return $selection
}

function Select-ExportFolder {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Add-Type -AssemblyName System.Windows.Forms

    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog

    $dialog.Description =
        'Select the folder where the Active Directory CSV report will be saved.'

    $dialog.ShowNewFolderButton = $true

    $result = $dialog.ShowDialog()

    if (
        $result -ne [System.Windows.Forms.DialogResult]::OK -or
        [string]::IsNullOrWhiteSpace($dialog.SelectedPath)
    ) {
        throw [System.OperationCanceledException]::new(
            'Export folder selection was canceled.'
        )
    }

    return $dialog.SelectedPath
}

function Get-SafeProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    if ($null -eq $InputObject) {
        return $null
    }

    foreach ($name in $Names) {
        $property = $InputObject.PSObject.Properties[$name]

        if ($null -ne $property -and $null -ne $property.Value) {
            return $property.Value
        }
    }

    return $null
}

function Convert-ToCsvText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) {
        return $Value.ToString('o')
    }

    if (
        $Value -is [System.Collections.IEnumerable] -and
        $Value -isnot [string] -and
        $Value -isnot [byte[]]
    ) {
        return (
            @(
                $Value |
                    ForEach-Object {
                        [string]$_
                    }
            ) -join ';'
        )
    }

    return [string]$Value
}

function Convert-ADFileTime {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $false)]
        [switch]$MaximumMeansNever
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) {
        return $Value.ToString('o')
    }

    $numericValue = 0L

    if (-not [long]::TryParse(
            [string]$Value,
            [ref]$numericValue
        )) {

        return Convert-ToCsvText -Value $Value
    }

    if ($numericValue -le 0) {
        return $null
    }

    if (
        $MaximumMeansNever -and
        $numericValue -ge 9223372036854775807L
    ) {
        return $null
    }

    try {
        return [datetime]::FromFileTimeUtc(
            $numericValue
        ).ToLocalTime().ToString('o')
    }
    catch {
        return [string]$numericValue
    }
}

function Convert-SidToString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Sid
    )

    if ($null -eq $Sid) {
        return $null
    }

    if ($Sid -is [System.Security.Principal.SecurityIdentifier]) {
        return $Sid.Value
    }

    try {
        if ($Sid -is [byte[]]) {
            $securityIdentifier = New-Object `
                System.Security.Principal.SecurityIdentifier($Sid, 0)

            return $securityIdentifier.Value
        }

        return [string]$Sid
    }
    catch {
        return Convert-ToCsvText -Value $Sid
    }
}

function Get-NormalizedObjectClass {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object
    )

    $value = Get-SafeProperty `
        -InputObject $Object `
        -Names @('ObjectClass', 'objectClass')

    if (
        $value -is [System.Collections.IEnumerable] -and
        $value -isnot [string]
    ) {
        $classes = @($value)

        if ($classes.Count -gt 0) {
            return [string]$classes[-1]
        }
    }

    return [string]$value
}

function Get-AccountState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$ObjectClass
    )

    $accountClasses = @(
        'user'
        'computer'
        'msDS-ManagedServiceAccount'
        'msDS-GroupManagedServiceAccount'
    )

    if ($accountClasses -notcontains $ObjectClass) {
        return [pscustomobject]@{
            Enabled = $null
            Status  = 'Not applicable'
        }
    }

    $uacValue = Get-SafeProperty `
        -InputObject $Object `
        -Names @('userAccountControl', 'UserAccountControl')

    if ($null -eq $uacValue) {
        return [pscustomobject]@{
            Enabled = $null
            Status  = 'Unknown'
        }
    }

    $enabled = (([int64]$uacValue -band 2) -eq 0)

    return [pscustomobject]@{
        Enabled = $enabled
        Status  = if ($enabled) {
            'Enabled'
        }
        else {
            'Disabled'
        }
    }
}

function Get-GroupInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$GroupType
    )

    if ($null -eq $GroupType) {
        return [pscustomobject]@{
            Category = $null
            Scope    = $null
        }
    }

    try {
        $signedValue = [int32]$GroupType

        $unsignedValue = [BitConverter]::ToUInt32(
            [BitConverter]::GetBytes($signedValue),
            0
        )

        $category = if (
            ($unsignedValue -band [uint32]2147483648) -ne 0
        ) {
            'Security'
        }
        else {
            'Distribution'
        }

        $scope = if (($unsignedValue -band [uint32]8) -ne 0) {
            'Universal'
        }
        elseif (($unsignedValue -band [uint32]4) -ne 0) {
            'DomainLocal'
        }
        elseif (($unsignedValue -band [uint32]2) -ne 0) {
            'Global'
        }
        elseif (($unsignedValue -band [uint32]1) -ne 0) {
            'BuiltinLocal'
        }
        else {
            'Unknown'
        }

        return [pscustomobject]@{
            Category = $category
            Scope    = $scope
        }
    }
    catch {
        return [pscustomobject]@{
            Category = 'Unknown'
            Scope    = 'Unknown'
        }
    }
}

function Get-SafeFileName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $result = $Value

    foreach (
        $invalidCharacter in
        [System.IO.Path]::GetInvalidFileNameChars()
    ) {
        $result = $result.Replace(
            [string]$invalidCharacter,
            '_'
        )
    }

    $result = ($result -replace '\s+', '_').Trim('_')

    if ([string]::IsNullOrWhiteSpace($result)) {
        return 'SelectedOU'
    }

    return $result
}

#endregion Functions

#region Main execution

try {
    Write-Host 'Starting Active Directory OU inventory...' `
        -ForegroundColor Cyan

    Write-Host "Process ID        : $PID" -ForegroundColor DarkGray
    Write-Host (
        'PowerShell version: {0} ({1})' -f
        $PSVersionTable.PSVersion,
        $PSVersionTable.PSEdition
    ) -ForegroundColor DarkGray

    Import-ActiveDirectoryModule

    $connectionParameters = @{}

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $connectionParameters.Server = $Server
    }

    Write-Host 'Connecting to Active Directory...' `
        -ForegroundColor Cyan

    $domain = Get-ADDomain @connectionParameters

    Write-Host "Connected domain: $($domain.DNSRoot)" `
        -ForegroundColor Green

    $ouParameters = @{
        Filter = '*'
        Properties = @(
            'CanonicalName'
            'Description'
            'ProtectedFromAccidentalDeletion'
        )
    }

    if ($connectionParameters.ContainsKey('Server')) {
        $ouParameters.Server = $connectionParameters.Server
    }

    Write-Host 'Reading organizational units...' `
        -ForegroundColor Cyan

    $organizationalUnits = @(
        Get-ADOrganizationalUnit @ouParameters
    )

    Write-Host (
        'Organizational units returned: {0}' -f
        $organizationalUnits.Count
    ) -ForegroundColor Green

    $selectedOU = Select-ParentOU `
        -OrganizationalUnits $organizationalUnits

    $exportFolder = Select-ExportFolder

    Write-Host ''
    Write-Host (
        'Selected parent OU: {0}' -f
        $selectedOU.CanonicalName
    ) -ForegroundColor Cyan

    Write-Host "Search scope      : $SearchScope" `
        -ForegroundColor Cyan

    Write-Host "Export folder     : $exportFolder" `
        -ForegroundColor Cyan

    $properties = @(
        'accountExpires'
        'adminCount'
        'CanonicalName'
        'company'
        'department'
        'Description'
        'DisplayName'
        'dNSHostName'
        'employeeID'
        'gPLink'
        'gPOptions'
        'groupType'
        'isCriticalSystemObject'
        'lastLogonTimestamp'
        'mail'
        'managedBy'
        'manager'
        'member'
        'memberOf'
        'mobile'
        'objectCategory'
        'objectSid'
        'operatingSystem'
        'operatingSystemVersion'
        'physicalDeliveryOfficeName'
        'ProtectedFromAccidentalDeletion'
        'proxyAddresses'
        'pwdLastSet'
        'sAMAccountName'
        'servicePrincipalName'
        'telephoneNumber'
        'title'
        'userAccountControl'
        'userPrincipalName'
        'whenChanged'
        'whenCreated'
    )

    $objectParameters = @{
        Filter      = '*'
        SearchBase  = $selectedOU.DistinguishedName
        SearchScope = $SearchScope
        Properties  = $properties
    }

    if ($connectionParameters.ContainsKey('Server')) {
        $objectParameters.Server = $connectionParameters.Server
    }

    Write-Host ''
    Write-Host 'Reading Active Directory objects...' `
        -ForegroundColor Cyan

    $objects = @(
        Get-ADObject @objectParameters
    )

    if (-not $IncludeSelectedOU) {
        $objects = @(
            $objects |
                Where-Object {
                    -not [string]::Equals(
                        [string]$_.DistinguishedName,
                        [string]$selectedOU.DistinguishedName,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )
                }
        )
    }

    Write-Host (
        'Objects returned: {0}' -f
        $objects.Count
    ) -ForegroundColor Green

    $rows = New-Object System.Collections.ArrayList
    $timestamp = Get-Date
    $processed = 0

    foreach ($object in $objects) {
        $processed++

        $objectClass = Get-NormalizedObjectClass `
            -Object $object

        $objectName = [string](
            Get-SafeProperty `
                -InputObject $object `
                -Names @('Name', 'name')
        )

        Write-Progress `
            -Activity 'Documenting Active Directory objects' `
            -Status (
                'Processing object {0} of {1}: {2}' -f
                $processed,
                $objects.Count,
                $objectName
            ) `
            -PercentComplete (
                (
                    $processed /
                    [math]::Max($objects.Count, 1)
                ) * 100
            )

        $accountState = Get-AccountState `
            -Object $object `
            -ObjectClass $objectClass

        $groupType = Get-SafeProperty `
            -InputObject $object `
            -Names @('groupType', 'GroupType')

        $groupInformation = Get-GroupInformation `
            -GroupType $groupType

        $members = @(
            Get-SafeProperty `
                -InputObject $object `
                -Names @('member', 'Member')
        )

        $row = [pscustomobject][ordered]@{
            ReportTimestamp = $timestamp.ToString('o')

            DomainDNSRoot = $domain.DNSRoot

            DomainNetBIOSName = $domain.NetBIOSName

            SelectedParentOU =
                $selectedOU.DistinguishedName

            SearchScope = $SearchScope

            ObjectClass = $objectClass

            Name = $objectName

            DisplayName = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('DisplayName', 'displayName')
            )

            SamAccountName = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('SamAccountName', 'sAMAccountName')
            )

            UserPrincipalName = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @(
                        'UserPrincipalName'
                        'userPrincipalName'
                    )
            )

            DistinguishedName = $object.DistinguishedName

            CanonicalName = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('CanonicalName', 'canonicalName')
            )

            ObjectGUID = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('ObjectGUID', 'objectGUID')
            )

            ObjectSID = Convert-SidToString -Sid (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('objectSid', 'ObjectSid', 'SID')
            )

            Created = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('whenCreated', 'Created')
            )

            Modified = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('whenChanged', 'Modified')
            )

            Description = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('Description', 'description')
            )

            ProtectedFromAccidentalDeletion =
                Convert-ToCsvText -Value (
                    Get-SafeProperty `
                        -InputObject $object `
                        -Names @(
                            'ProtectedFromAccidentalDeletion'
                            'protectedFromAccidentalDeletion'
                        )
                )

            IsCriticalSystemObject =
                Convert-ToCsvText -Value (
                    Get-SafeProperty `
                        -InputObject $object `
                        -Names @(
                            'isCriticalSystemObject'
                            'IsCriticalSystemObject'
                        )
                )

            IsEnabled =
                Convert-ToCsvText -Value $accountState.Enabled

            AccountStatus = $accountState.Status

            UserAccountControl =
                Convert-ToCsvText -Value (
                    Get-SafeProperty `
                        -InputObject $object `
                        -Names @(
                            'userAccountControl'
                            'UserAccountControl'
                        )
                )

            LastLogonTimestamp =
                Convert-ADFileTime -Value (
                    Get-SafeProperty `
                        -InputObject $object `
                        -Names @(
                            'lastLogonTimestamp'
                            'LastLogonTimestamp'
                        )
                )

            PasswordLastSet =
                Convert-ADFileTime -Value (
                    Get-SafeProperty `
                        -InputObject $object `
                        -Names @(
                            'pwdLastSet'
                            'PasswordLastSet'
                        )
                )

            AccountExpirationDate =
                Convert-ADFileTime `
                    -Value (
                        Get-SafeProperty `
                            -InputObject $object `
                            -Names @(
                                'accountExpires'
                                'AccountExpirationDate'
                            )
                    ) `
                    -MaximumMeansNever

            Mail = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('mail', 'Mail')
            )

            ProxyAddresses = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @(
                        'proxyAddresses'
                        'ProxyAddresses'
                    )
            )

            Department = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('department', 'Department')
            )

            Title = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('title', 'Title')
            )

            Company = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('company', 'Company')
            )

            Office = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @(
                        'physicalDeliveryOfficeName'
                        'Office'
                    )
            )

            Manager = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('manager', 'Manager')
            )

            ManagedBy = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('managedBy', 'ManagedBy')
            )

            EmployeeID = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('employeeID', 'EmployeeID')
            )

            TelephoneNumber = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @(
                        'telephoneNumber'
                        'OfficePhone'
                    )
            )

            Mobile = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('mobile', 'MobilePhone')
            )

            DNSHostName = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('dNSHostName', 'DNSHostName')
            )

            OperatingSystem = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @(
                        'operatingSystem'
                        'OperatingSystem'
                    )
            )

            OperatingSystemVersion =
                Convert-ToCsvText -Value (
                    Get-SafeProperty `
                        -InputObject $object `
                        -Names @(
                            'operatingSystemVersion'
                            'OperatingSystemVersion'
                        )
                )

            GroupCategory = $groupInformation.Category

            GroupScope = $groupInformation.Scope

            DirectMemberCount = $members.Count

            DirectMembers = Convert-ToCsvText -Value $members

            MemberOf = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('memberOf', 'MemberOf')
            )

            ServicePrincipalNames =
                Convert-ToCsvText -Value (
                    Get-SafeProperty `
                        -InputObject $object `
                        -Names @(
                            'servicePrincipalName'
                            'ServicePrincipalNames'
                        )
                )

            GroupPolicyLinks = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('gPLink', 'GPLink')
            )

            GroupPolicyOptions = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('gPOptions', 'GPOptions')
            )

            AdminCount = Convert-ToCsvText -Value (
                Get-SafeProperty `
                    -InputObject $object `
                    -Names @('adminCount', 'AdminCount')
            )
        }

        [void]$rows.Add($row)
    }

    Write-Progress `
        -Activity 'Documenting Active Directory objects' `
        -Completed

    $safeOUName = Get-SafeFileName `
        -Value $selectedOU.Name

    $fileTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

    $outputPath = Join-Path `
        -Path $exportFolder `
        -ChildPath (
            'ActiveDirectory_OU_ObjectInventory_{0}_{1}.csv' -f
            $safeOUName,
            $fileTimestamp
        )

    $rows |
        Export-Csv `
            -LiteralPath $outputPath `
            -NoTypeInformation `
            -Encoding UTF8 `
            -Force

    $classSummary = @(
        $rows |
            Group-Object ObjectClass |
            Sort-Object -Property @(
                @{
                    Expression = 'Count'
                    Descending = $true
                }
                'Name'
            )
    )

    Write-Host ''
    Write-Host 'Export completed successfully.' `
        -ForegroundColor Green

    Write-Host "CSV report      : $outputPath"
    Write-Host "Objects exported: $($rows.Count)"

    Write-Host ''
    Write-Host 'Objects by class:' -ForegroundColor Cyan

    foreach ($item in $classSummary) {
        Write-Host (
            '  {0,-40} {1,8}' -f
            $item.Name,
            $item.Count
        )
    }
}
catch [System.OperationCanceledException] {
    Write-Host 'Operation canceled. No report was created.' `
        -ForegroundColor Yellow

    exit 0
}
catch {
    Write-Error (
        'The Active Directory export failed: {0}' -f
        $_.Exception.Message
    )

    exit 1
}

#endregion Main execution