<#
    .SYNOPSIS
        Runs the WindowsAccessControl domain-lab acceptance inside the lab from
        the Hyper-V host.

    .DESCRIPTION
        The development host is not domain joined, and the module pins Kerberos
        for its LDAP bind, so the enterprise suites cannot run on the host. This
        script copies the built module, the source manifest, and the lab suites
        into the management domain controller, runs the unattended acceptance
        profile there through AutomatedLab, and copies the redacted evidence
        back.

        AutomatedLab uses credential delegation, so the directory calls inside
        the lab session hold a real ticket-granting ticket.

    .PARAMETER LabName
        The AutomatedLab lab to import.

    .PARAMETER ManagementDomainController
        The lab machine that hosts the harness and the directory suites.

    .PARAMETER MemberServer
        The lab machine that hosts the SMB share, Task Scheduler, and private-key
        fixtures.

    .PARAMETER DomainDistinguishedName
        The distinguished name of the fixture domain.

    .PARAMETER RemoteRepositoryPath
        The directory on the management domain controller that receives the
        minimal repository tree.

    .PARAMETER EvidencePath
        The local file that receives the redacted acceptance evidence.

    .PARAMETER CoverageEvidencePath
        The local file that receives the domain-lab JaCoCo code-coverage
        document. It is deliberately outside `output` because the Sampler build
        deletes that tree, and the repository build imports it from here before
        merging.

    .PARAMETER SkipPayload
        Reuses the tree already present on the management domain controller
        instead of copying it again.

    .EXAMPLE
        .\Invoke-WindowsAccessControlLabAcceptance.ps1

        Deploys the current build into the lab and runs all six suites.

    .NOTES
        Requires an elevated host session with the lab installed.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LabName = 'WindowsAccessControlLab',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ManagementDomainController = 'F1ADC1',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$MemberServer = 'F1AFile1',

    [Parameter()]
    [ValidatePattern('^DC=[^,]+(?:,DC=[^,]+)+$')]
    [string]$DomainDistinguishedName = 'DC=a,DC=forest1,DC=net',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RemoteRepositoryPath = 'C:\WacRepo',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EvidencePath = (Join-Path $env:TEMP 'wac-domain-lab-evidence.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CoverageEvidencePath = (Join-Path $PSScriptRoot 'coverage\JaCoCo_coverage_DomainLab.xml'),

    [Parameter()]
    [switch]$SkipPayload
)

$ErrorActionPreference = 'Stop'

Import-Module -Name AutomatedLab -ErrorAction Stop

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).ProviderPath
$builtModule = Get-ChildItem -Path (
    Join-Path $repositoryRoot 'output\module\WindowsAccessControl\*'
) -Directory -ErrorAction Stop |
    Sort-Object -Property { [version]$_.Name } -Descending |
    Select-Object -First 1
if (-not $builtModule) {
    throw 'Build the module before running the lab acceptance.'
}

if (-not $PSCmdlet.ShouldProcess(
        "Lab '$LabName' machines '$ManagementDomainController' and '$MemberServer'",
        'Deploy the current build and run the domain-lab acceptance'
    )) {
    return
}

Import-Lab -Name $LabName -NoValidation

if (-not $SkipPayload) {
    Invoke-LabCommand `
        -ComputerName $ManagementDomainController `
        -ActivityName 'Reset the acceptance payload directory' `
        -ScriptBlock {
            param($Path)

            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
            $null = New-Item -Path (Join-Path $Path 'output') -ItemType Directory -Force
        } `
        -ArgumentList $RemoteRepositoryPath `
        -NoDisplay

    foreach ($item in 'source', 'tests') {
        Copy-LabFileItem `
            -Path (Join-Path $repositoryRoot $item) `
            -ComputerName $ManagementDomainController `
            -DestinationFolderPath $RemoteRepositoryPath `
            -Recurse
    }
    Copy-LabFileItem `
        -Path (Join-Path $repositoryRoot 'output\module') `
        -ComputerName $ManagementDomainController `
        -DestinationFolderPath (Join-Path $RemoteRepositoryPath 'output') `
        -Recurse
}

$remoteEvidencePath = Join-Path $RemoteRepositoryPath 'lab-evidence.json'
$remoteCoveragePath = Join-Path $RemoteRepositoryPath 'lab-coverage.xml'
$acceptanceOutput = Invoke-LabCommand `
    -ComputerName $ManagementDomainController `
    -ActivityName 'WindowsAccessControl domain-lab acceptance' `
    -ScriptBlock {
        param($RepositoryPath, $DomainDn, $Member, $OutputPath, $CoveragePath)

        $starter = Join-Path `
            $RepositoryPath `
            'tests\Lab\Start-WindowsAccessControlDomainLabAcceptance.ps1'
        $output = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -NoProfile `
            -NonInteractive `
            -ExecutionPolicy Bypass `
            -File $starter `
            -RepositoryRoot $RepositoryPath `
            -DomainDistinguishedName $DomainDn `
            -MemberServer $Member `
            -OutputPath $OutputPath `
            -CoverageOutputPath $CoveragePath 2>&1 |
            ForEach-Object { [string]$_ }
        [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output   = $output
        }
    } `
    -ArgumentList $RemoteRepositoryPath, $DomainDistinguishedName, $MemberServer, $remoteEvidencePath, $remoteCoveragePath `
    -PassThru `
    -NoDisplay

$acceptanceOutput.Output | Write-Information -InformationAction Continue
if ($acceptanceOutput.ExitCode -ne 0) {
    throw "The domain-lab acceptance failed with exit code $($acceptanceOutput.ExitCode)."
}

$coverageDirectory = Split-Path -Path $CoverageEvidencePath -Parent
if (-not (Test-Path -LiteralPath $coverageDirectory -PathType Container)) {
    $null = New-Item -Path $coverageDirectory -ItemType Directory -Force
}

$session = New-LabPSSession -ComputerName $ManagementDomainController
try {
    Copy-Item `
        -Path $remoteEvidencePath `
        -Destination $EvidencePath `
        -FromSession $session `
        -Force `
        -ErrorAction Stop
    Copy-Item `
        -Path $remoteCoveragePath `
        -Destination $CoverageEvidencePath `
        -FromSession $session `
        -Force `
        -ErrorAction Stop
}
finally {
    Remove-PSSession $session -ErrorAction SilentlyContinue
}

Write-Information "Evidence written to '$EvidencePath'." -InformationAction Continue
Write-Information "Code coverage written to '$CoverageEvidencePath'." -InformationAction Continue
Get-Content -LiteralPath $EvidencePath -Raw | ConvertFrom-Json
