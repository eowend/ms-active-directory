<#
.SYNOPSIS
    Exports Active Directory users by selected Search Bases and account status.

.DESCRIPTION
    This script detects the current Active Directory domain automatically,
    loads all Organizational Units from the domain, and presents them in a
    graphical interface with checkboxes.

    The user can select one or more Search Bases, choose an account status
    filter, select an output folder, and generate a timestamped CSV report.

    The account status is calculated directly from userAccountControl.
    This avoids relying only on the Enabled property when bulk exports return
    blank or incomplete values.

.REQUIREMENTS
    - Windows machine joined to the domain or able to query Active Directory
    - RSAT Active Directory PowerShell module
    - Permissions to read users and OUs in Active Directory
    - PowerShell running in an interactive desktop session

.OUTPUT
    Timestamped CSV report containing AD user details.

.EXAMPLE
    .\Export-ADUsers-GUI.ps1

.AUTHOR
    Juan Ortiz (juan.ortiz@toconnect.net)
    To Connect, LLC

.VERSION
    1.0.0
#>

#requires -Modules ActiveDirectory

Set-StrictMode -Version Latest

# =========================
# Load required assemblies
# =========================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# =========================
# Functions
# =========================

function ConvertTo-SafeFileName {
    <#
    .SYNOPSIS
        Converts a string into a safe file name.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $InvalidChars = [System.IO.Path]::GetInvalidFileNameChars()

    foreach ($Char in $InvalidChars) {
        $Value = $Value.Replace($Char, "_")
    }

    return $Value
}

function Get-AccountStatusFromUserAccountControl {
    <#
    .SYNOPSIS
        Calculates AD account status from userAccountControl.

    .DESCRIPTION
        The ACCOUNTDISABLE flag has a decimal value of 2.
        If the bit is present, the account is disabled.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [int]$UserAccountControl
    )

    $IsDisabled = [bool]($UserAccountControl -band 2)

    if ($IsDisabled) {
        return "Disabled"
    }

    return "Enabled"
}

function Get-LdapFilterByStatus {
    <#
    .SYNOPSIS
        Returns the LDAP filter used to query AD users.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("All", "Enabled", "Disabled")]
        [string]$Status
    )

    switch ($Status) {
        "Enabled" {
            return "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        }

        "Disabled" {
            return "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
        }

        "All" {
            return "(&(objectCategory=person)(objectClass=user))"
        }
    }
}

function Get-OrganizationalUnitPath {
    <#
    .SYNOPSIS
        Extracts a readable OU path from a Distinguished Name.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName
    )

    $OuComponents = ($DistinguishedName -split '(?<!\\),') |
        Where-Object { $_ -like "OU=*" } |
        ForEach-Object { $_ -replace "^OU=", "" }

    if ($OuComponents.Count -eq 0) {
        return ""
    }

    [array]::Reverse($OuComponents)

    return ($OuComponents -join " / ")
}

function Show-AdExportForm {
    <#
    .SYNOPSIS
        Shows the GUI used to select Search Bases, status, and output folder.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$DomainDnsName,

        [Parameter(Mandatory = $true)]
        [array]$SearchBases
    )

    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Export Active Directory Users"
    $Form.Size = New-Object System.Drawing.Size(900, 680)
    $Form.StartPosition = "CenterScreen"
    $Form.MaximizeBox = $false

    $LabelDomain = New-Object System.Windows.Forms.Label
    $LabelDomain.Text = "Detected domain: $DomainDnsName"
    $LabelDomain.Location = New-Object System.Drawing.Point(20, 20)
    $LabelDomain.Size = New-Object System.Drawing.Size(830, 25)
    $Form.Controls.Add($LabelDomain)

    $LabelSearchBase = New-Object System.Windows.Forms.Label
    $LabelSearchBase.Text = "Select one or more Search Bases:"
    $LabelSearchBase.Location = New-Object System.Drawing.Point(20, 55)
    $LabelSearchBase.Size = New-Object System.Drawing.Size(300, 25)
    $Form.Controls.Add($LabelSearchBase)

    $CheckedListBox = New-Object System.Windows.Forms.CheckedListBox
    $CheckedListBox.Location = New-Object System.Drawing.Point(20, 85)
    $CheckedListBox.Size = New-Object System.Drawing.Size(840, 340)
    $CheckedListBox.CheckOnClick = $true
    $CheckedListBox.DisplayMember = "DisplayName"

    foreach ($Item in $SearchBases) {
        [void]$CheckedListBox.Items.Add($Item)
    }

    $Form.Controls.Add($CheckedListBox)

    $ButtonSelectAll = New-Object System.Windows.Forms.Button
    $ButtonSelectAll.Text = "Select All"
    $ButtonSelectAll.Location = New-Object System.Drawing.Point(20, 435)
    $ButtonSelectAll.Size = New-Object System.Drawing.Size(120, 30)
    $ButtonSelectAll.Add_Click({
        for ($Index = 0; $Index -lt $CheckedListBox.Items.Count; $Index++) {
            $CheckedListBox.SetItemChecked($Index, $true)
        }
    })
    $Form.Controls.Add($ButtonSelectAll)

    $ButtonClearAll = New-Object System.Windows.Forms.Button
    $ButtonClearAll.Text = "Clear Selection"
    $ButtonClearAll.Location = New-Object System.Drawing.Point(150, 435)
    $ButtonClearAll.Size = New-Object System.Drawing.Size(130, 30)
    $ButtonClearAll.Add_Click({
        for ($Index = 0; $Index -lt $CheckedListBox.Items.Count; $Index++) {
            $CheckedListBox.SetItemChecked($Index, $false)
        }
    })
    $Form.Controls.Add($ButtonClearAll)

    $LabelStatus = New-Object System.Windows.Forms.Label
    $LabelStatus.Text = "Account status:"
    $LabelStatus.Location = New-Object System.Drawing.Point(20, 485)
    $LabelStatus.Size = New-Object System.Drawing.Size(150, 25)
    $Form.Controls.Add($LabelStatus)

    $ComboStatus = New-Object System.Windows.Forms.ComboBox
    $ComboStatus.Location = New-Object System.Drawing.Point(170, 481)
    $ComboStatus.Size = New-Object System.Drawing.Size(180, 25)
    $ComboStatus.DropDownStyle = "DropDownList"
    [void]$ComboStatus.Items.Add("All")
    [void]$ComboStatus.Items.Add("Enabled")
    [void]$ComboStatus.Items.Add("Disabled")
    $ComboStatus.SelectedItem = "All"
    $Form.Controls.Add($ComboStatus)

    $LabelOutput = New-Object System.Windows.Forms.Label
    $LabelOutput.Text = "Report folder:"
    $LabelOutput.Location = New-Object System.Drawing.Point(20, 525)
    $LabelOutput.Size = New-Object System.Drawing.Size(150, 25)
    $Form.Controls.Add($LabelOutput)

    $TextOutput = New-Object System.Windows.Forms.TextBox
    $TextOutput.Location = New-Object System.Drawing.Point(170, 521)
    $TextOutput.Size = New-Object System.Drawing.Size(550, 25)
    $TextOutput.ReadOnly = $true
    $Form.Controls.Add($TextOutput)

    $ButtonBrowse = New-Object System.Windows.Forms.Button
    $ButtonBrowse.Text = "Browse..."
    $ButtonBrowse.Location = New-Object System.Drawing.Point(735, 519)
    $ButtonBrowse.Size = New-Object System.Drawing.Size(125, 30)
    $ButtonBrowse.Add_Click({
        $FolderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderDialog.Description = "Select the folder where reports will be saved"

        if ($FolderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $TextOutput.Text = $FolderDialog.SelectedPath
        }
    })
    $Form.Controls.Add($ButtonBrowse)

    $ButtonRun = New-Object System.Windows.Forms.Button
    $ButtonRun.Text = "Generate Report"
    $ButtonRun.Location = New-Object System.Drawing.Point(610, 575)
    $ButtonRun.Size = New-Object System.Drawing.Size(125, 35)
    $ButtonRun.Add_Click({
        if ($CheckedListBox.CheckedItems.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Select at least one Search Base.",
                "Validation",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null

            return
        }

        if ([string]::IsNullOrWhiteSpace($TextOutput.Text)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Select a report output folder.",
                "Validation",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null

            return
        }

        $Form.Tag = [PSCustomObject]@{
            SelectedSearchBases = @($CheckedListBox.CheckedItems)
            Status              = $ComboStatus.SelectedItem
            OutputDirectory     = $TextOutput.Text
        }

        $Form.Close()
    })
    $Form.Controls.Add($ButtonRun)

    $ButtonCancel = New-Object System.Windows.Forms.Button
    $ButtonCancel.Text = "Cancel"
    $ButtonCancel.Location = New-Object System.Drawing.Point(750, 575)
    $ButtonCancel.Size = New-Object System.Drawing.Size(110, 35)
    $ButtonCancel.Add_Click({
        $Form.Tag = $null
        $Form.Close()
    })
    $Form.Controls.Add($ButtonCancel)

    [void]$Form.ShowDialog()

    return $Form.Tag
}

# =========================
# Main script
# =========================

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Error "The Active Directory PowerShell module could not be loaded. Install RSAT or run this script from a system with AD tools."
    exit 1
}

try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $DomainDn = $Domain.DistinguishedName
    $DomainDnsName = $Domain.DNSRoot
}
catch {
    Write-Error "The current Active Directory domain could not be detected."
    exit 1
}

Write-Host "Detected domain: $DomainDnsName" -ForegroundColor Cyan

try {
    $SearchBases = @()

    $SearchBases += [PSCustomObject]@{
        DisplayName = "Full domain - $DomainDnsName"
        SearchBase  = $DomainDn
    }

    $OrganizationalUnits = Get-ADOrganizationalUnit `
        -Filter * `
        -SearchBase $DomainDn `
        -Properties CanonicalName `
        -ErrorAction Stop |
        Sort-Object CanonicalName

    foreach ($Ou in $OrganizationalUnits) {
        $SearchBases += [PSCustomObject]@{
            DisplayName = $Ou.CanonicalName
            SearchBase  = $Ou.DistinguishedName
        }
    }
}
catch {
    Write-Error "Organizational Units could not be loaded from Active Directory."
    exit 1
}

$UserSelection = Show-AdExportForm `
    -DomainDnsName $DomainDnsName `
    -SearchBases $SearchBases

if ($null -eq $UserSelection) {
    Write-Host "Operation canceled by user." -ForegroundColor Yellow
    exit 0
}

$SelectedSearchBases = $UserSelection.SelectedSearchBases
$Status = $UserSelection.Status
$OutputDirectory = $UserSelection.OutputDirectory

$LdapFilter = Get-LdapFilterByStatus -Status $Status

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$SafeDomainName = ConvertTo-SafeFileName -Value $DomainDnsName
$SafeStatus = ConvertTo-SafeFileName -Value $Status

$OutputFileName = "AD_Users_${SafeDomainName}_${SafeStatus}_${Timestamp}.csv"
$OutputPath = Join-Path -Path $OutputDirectory -ChildPath $OutputFileName

$Results = New-Object System.Collections.Generic.List[object]
$SeenObjectGuids = @{}

foreach ($SearchBaseItem in $SelectedSearchBases) {
    $SearchBase = $SearchBaseItem.SearchBase
    $SearchBaseName = $SearchBaseItem.DisplayName

    Write-Host "Querying Search Base: $SearchBaseName" -ForegroundColor Cyan

    try {
        $Users = Get-ADUser `
            -LDAPFilter $LdapFilter `
            -SearchBase $SearchBase `
            -SearchScope Subtree `
            -Properties `
                DisplayName,
                GivenName,
                Surname,
                Mail,
                UserPrincipalName,
                SamAccountName,
                Enabled,
                userAccountControl,
                whenCreated,
                whenChanged,
                LastLogonDate,
                DistinguishedName,
                ObjectGUID `
            -ErrorAction Stop

        foreach ($User in $Users) {
            $ObjectGuid = $User.ObjectGUID.Guid

            if ($SeenObjectGuids.ContainsKey($ObjectGuid)) {
                continue
            }

            $SeenObjectGuids[$ObjectGuid] = $true

            $CalculatedStatus = Get-AccountStatusFromUserAccountControl `
                -UserAccountControl $User.userAccountControl

            $OuPath = Get-OrganizationalUnitPath `
                -DistinguishedName $User.DistinguishedName

            $Results.Add([PSCustomObject]@{
                Domain              = $DomainDnsName
                DisplayName         = $User.DisplayName
                FirstName           = $User.GivenName
                LastName            = $User.Surname
                SamAccountName      = $User.SamAccountName
                UserPrincipalName   = $User.UserPrincipalName
                Mail                = $User.Mail
                AccountStatus       = $CalculatedStatus
                ADModuleEnabled     = $User.Enabled
                UserAccountControl  = $User.userAccountControl
                WhenCreated         = $User.whenCreated
                WhenChanged         = $User.whenChanged
                LastLogonDate       = $User.LastLogonDate
                OUPath              = $OuPath
                SelectedSearchBase  = $SearchBaseName
                DistinguishedName   = $User.DistinguishedName
                ObjectGUID          = $ObjectGuid
            })
        }
    }
    catch {
        Write-Warning "Search Base could not be queried: $SearchBaseName"
        Write-Warning $_.Exception.Message
    }
}

$SortedResults = $Results |
    Sort-Object SelectedSearchBase, AccountStatus, DisplayName

if ($SortedResults.Count -gt 0) {
    $SortedResults |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    $Headers = @(
        "Domain",
        "DisplayName",
        "FirstName",
        "LastName",
        "SamAccountName",
        "UserPrincipalName",
        "Mail",
        "AccountStatus",
        "ADModuleEnabled",
        "UserAccountControl",
        "WhenCreated",
        "WhenChanged",
        "LastLogonDate",
        "OUPath",
        "SelectedSearchBase",
        "DistinguishedName",
        "ObjectGUID"
    )

    ($Headers -join ",") |
        Set-Content -Path $OutputPath -Encoding UTF8
}

Write-Host ""
Write-Host "Report generated successfully." -ForegroundColor Green
Write-Host "Users exported: $($SortedResults.Count)"
Write-Host "Output file: $OutputPath"

[System.Windows.Forms.MessageBox]::Show(
    "Report generated successfully.`n`nUsers exported: $($SortedResults.Count)`n`n$OutputPath",
    "Export completed",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Information
) | Out-Null