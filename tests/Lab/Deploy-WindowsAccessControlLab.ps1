<#
    .SYNOPSIS
        Deploys the disposable multi-forest AutomatedLab environment that the
        WindowsAccessControl enterprise acceptance suites require.

    .DESCRIPTION
        Defines and installs a Hyper-V lab with three forests, two child
        domains, two replication partners in the fixture domain, an enterprise
        root certification authority, and member servers for SMB share, Task
        Scheduler, and private-key fixtures.

        The domain, machine-name, and trust shape comes from the AutomatedLab
        sample scenario 'Multi-AD Forest with Trusts.ps1' in
        <LabSources>\SampleScripts\Scenarios. tests\Lab\README.md records the
        additions this script makes on top of that baseline and the suite that
        requires each one.

        The lab is disposable. It must never be attached to a production
        network and never holds production data. No credential, key, or
        recovery value is stored in this repository; the operator supplies the
        installation credential at run time.

    .PARAMETER InstallationCredential
        The local and domain administrator credential AutomatedLab uses for
        every machine and domain in the lab.

    .PARAMETER LabName
        The AutomatedLab lab name.

    .PARAMETER VmPath
        The host directory that stores the lab virtual machines.

    .PARAMETER OperatingSystem
        The operating system name that must exist in the AutomatedLab ISO
        inventory.

    .PARAMETER DomainControllerMemoryMB
        Memory for domain controllers and the certification authority.

    .PARAMETER MemberMemoryMB
        Memory for member servers.

    .PARAMETER PowerShell7Uri
        The download location of the PowerShell 7 machine-wide installer. The
        deployment installs it on every machine so the acceptance suites can
        run in both supported PowerShell editions.

    .PARAMETER PesterModulePath
        The Pester 5 module version directory copied to every machine. It
        defaults to the restored Sampler dependency in this repository.

    .PARAMETER RemoveExistingLab
        Removes an existing lab with the same name, including its virtual
        machines and disks, before defining the new one.

    .PARAMETER RemoveLabName
        Removes additional named labs before defining the new one. A predecessor
        lab keeps the machine names, addresses, and host-file entries the new
        lab needs, so it must be removed first.

    .EXAMPLE
        $credential = Get-Credential -UserName Install -Message 'Lab admin'
        .\Deploy-WindowsAccessControlLab.ps1 -InstallationCredential $credential

        Deploys the lab with the default topology.

    .NOTES
        Requires an elevated host session with Hyper-V and AutomatedLab.

    .LINK
        tests/Lab/README.md
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [pscredential]$InstallationCredential,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LabName = 'WindowsAccessControlLab',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$VmPath = 'V:\AutomatedLab-VMs',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OperatingSystem = 'Windows Server 2025 Datacenter (Desktop Experience)',

    [Parameter()]
    [ValidateRange(1024, 65536)]
    [int]$DomainControllerMemoryMB = 4096,

    [Parameter()]
    [ValidateRange(1024, 65536)]
    [int]$MemberMemoryMB = 3072,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PowerShell7Uri = 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.3/PowerShell-7.6.3-win-x64.msi',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PesterModulePath = (Join-Path $PSScriptRoot '..\..\output\RequiredModules\Pester\5.7.1'),

    [Parameter()]
    [switch]$RemoveExistingLab,

    [Parameter()]
    [ValidateNotNull()]
    [string[]]$RemoveLabName = @()
)

$ErrorActionPreference = 'Stop'

Import-Module -Name AutomatedLab -ErrorAction Stop

$rootDomain = 'forest1.net'
$firstChildDomain = "a.$rootDomain"
$secondChildDomain = "b.$rootDomain"
$secondForest = 'forest2.net'
$thirdForest = 'forest3.net'

# Symbolic role -> machine mapping. README.md in this directory and
# docs/domain-lab-inventory.md describe the same topology, so all three must be
# changed together.
$machineDefinitions = @(
    @{ Name = 'F1DC1'; Domain = $rootDomain; Roles = 'RootDC'; Memory = $DomainControllerMemoryMB }
    @{ Name = 'F1DC2'; Domain = $rootDomain; Roles = 'DC'; Memory = $DomainControllerMemoryMB }
    @{ Name = 'F1CA1'; Domain = $rootDomain; Roles = 'CaRoot'; Memory = $DomainControllerMemoryMB }
    @{ Name = 'F1ADC1'; Domain = $firstChildDomain; Roles = 'FirstChildDC'; Memory = $DomainControllerMemoryMB }
    @{ Name = 'F1ADC2'; Domain = $firstChildDomain; Roles = 'DC'; Memory = $DomainControllerMemoryMB }
    @{ Name = 'F1AFile1'; Domain = $firstChildDomain; Roles = 'FileServer'; Memory = $MemberMemoryMB }
    @{ Name = 'F1AFile2'; Domain = $firstChildDomain; Roles = 'FileServer', 'WebServer'; Memory = $MemberMemoryMB }
    @{ Name = 'F1BDC1'; Domain = $secondChildDomain; Roles = 'FirstChildDC'; Memory = $DomainControllerMemoryMB }
    @{ Name = 'F1BFile1'; Domain = $secondChildDomain; Roles = 'FileServer'; Memory = $MemberMemoryMB }
    @{ Name = 'F2DC1'; Domain = $secondForest; Roles = 'RootDC'; Memory = $DomainControllerMemoryMB }
    @{ Name = 'F2File1'; Domain = $secondForest; Roles = 'FileServer'; Memory = $MemberMemoryMB }
    @{ Name = 'F3DC1'; Domain = $thirdForest; Roles = 'RootDC'; Memory = $DomainControllerMemoryMB }
    @{ Name = 'F3File1'; Domain = $thirdForest; Roles = 'FileServer'; Memory = $MemberMemoryMB }
)

$resolvedPesterPath = (Resolve-Path -LiteralPath $PesterModulePath -ErrorAction Stop).ProviderPath
if (-not (Test-Path -LiteralPath (Join-Path $resolvedPesterPath 'Pester.psd1') -PathType Leaf)) {
    throw "PesterModulePath does not contain a Pester module manifest: '$resolvedPesterPath'."
}

$machineNames = $machineDefinitions.Name -join ', '
if (-not $PSCmdlet.ShouldProcess(
        "AutomatedLab lab '$LabName' on this Hyper-V host",
        "Deploy $($machineDefinitions.Count) virtual machines ($machineNames)"
    )) {
    return
}

# A predecessor lab owns the machine names, addresses, and host-file entries, so
# it is removed before an interrupted definition of the new lab.
$labsToRemove = @(
    $RemoveLabName
    if ($RemoveExistingLab) { $LabName }
) | Select-Object -Unique

foreach ($labToRemove in $labsToRemove) {
    if (@(Get-Lab -List) -notcontains $labToRemove) {
        continue
    }
    Write-Verbose "Removing the existing lab '$labToRemove'." -Verbose
    try {
        Import-Lab -Name $labToRemove -NoValidation
        Remove-Lab -Confirm:$false -ErrorAction Stop
    }
    catch {
        # An interrupted definition can reference machines another lab owns, so
        # the leftover definition is discarded rather than left to collide.
        Write-Warning "Removing lab '$labToRemove' reported '$($_.Exception.Message)'. Discarding its definition."
        Remove-Item -LiteralPath (Join-Path $env:ProgramData "AutomatedLab\Labs\$labToRemove") -Recurse -Force -ErrorAction Stop
    }
}

# A switch that outlives its lab keeps a host adapter on the retired subnet
# while the new lab picks the next free one, which silently strands every new
# machine. Only a switch with no virtual machine attached is removed.
foreach ($switchName in @($labsToRemove) + $LabName | Select-Object -Unique) {
    if (-not (Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue)) {
        continue
    }
    $attachedMachines = @(
        Get-VMNetworkAdapter -All |
            Where-Object { $_.SwitchName -eq $switchName -and -not $_.IsManagementOs }
    )
    if ($attachedMachines.Count -gt 0) {
        throw (
            "Refusing to remove virtual switch '$switchName' because " +
            "$($attachedMachines.Count) virtual machines are still attached."
        )
    }
    Write-Verbose "Removing the orphaned virtual switch '$switchName'." -Verbose
    Remove-VMSwitch -Name $switchName -Force -ErrorAction Stop
}

# A failed teardown can leave a host-file entry that points a machine name at a
# retired address, and Install-Lab refuses to redirect it. Each lab owns a named
# section, so a stale entry is cleared from every lab section this run replaces.
foreach ($section in @($labsToRemove) + $LabName | Select-Object -Unique) {
    foreach ($definition in $machineDefinitions) {
        foreach ($hostName in $definition.Name, "$($definition.Name).$($definition.Domain)") {
            $null = Remove-HostEntry -HostName $hostName -Section $section -ErrorAction SilentlyContinue
        }
    }
}

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath $VmPath


$adminUser = $InstallationCredential.UserName
$adminPassword = $InstallationCredential.GetNetworkCredential().Password

foreach ($domain in $rootDomain, $firstChildDomain, $secondChildDomain, $secondForest, $thirdForest) {
    Add-LabDomainDefinition -Name $domain -AdminUser $adminUser -AdminPassword $adminPassword
}

Set-LabInstallationCredential -Username $adminUser -Password $adminPassword

foreach ($definition in $machineDefinitions) {
    Add-LabMachineDefinition `
        -Name $definition.Name `
        -DomainName $definition.Domain `
        -Roles $definition.Roles `
        -OperatingSystem $OperatingSystem `
        -Memory ($definition.Memory * 1MB) `
        -ToolsPath "$labSources\Tools"
}

Install-Lab

$labMachines = Get-LabVM

$installerDirectory = Join-Path $labSources 'SoftwarePackages'
$null = New-Item -Path $installerDirectory -ItemType Directory -Force
$powerShell7Installer = Get-LabInternetFile `
    -Uri $PowerShell7Uri `
    -Path $installerDirectory `
    -PassThru `
    -NoDisplay
$powerShell7InstallerPath = if ($powerShell7Installer.FullName) {
    $powerShell7Installer.FullName
}
else {
    Join-Path $installerDirectory ([uri]$PowerShell7Uri).Segments[-1]
}

Install-LabSoftwarePackage `
    -ComputerName $labMachines `
    -Path $powerShell7InstallerPath `
    -CommandLine '/quiet /norestart ADD_PATH=1' `
    -Timeout 30

foreach ($modulesRoot in 'C:\Program Files\WindowsPowerShell\Modules', 'C:\Program Files\PowerShell\Modules') {
    $destination = Join-Path $modulesRoot 'Pester'
    Invoke-LabCommand `
        -ComputerName $labMachines `
        -ActivityName 'Create the Pester module directory' `
        -ScriptBlock { param($Path) $null = New-Item -Path $Path -ItemType Directory -Force } `
        -ArgumentList $destination `
        -NoDisplay
    Copy-LabFileItem `
        -Path $resolvedPesterPath `
        -ComputerName $labMachines `
        -DestinationFolderPath $destination `
        -Recurse
}

Invoke-LabCommand `
    -ComputerName $labMachines `
    -ActivityName 'Install the Active Directory PowerShell tools' `
    -ScriptBlock {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            $null = Install-WindowsFeature -Name RSAT-AD-PowerShell
        }
    } `
    -NoDisplay

Show-LabDeploymentSummary -Summary
