<#
    .SYNOPSIS
        Starts the WindowsAccessControl domain-lab acceptance inside the lab.

    .DESCRIPTION
        The acceptance runs in its own console process rather than directly in
        the AutomatedLab session. A session runspace has a far smaller script
        call-depth budget than a console host: measured on the fixture domain
        controller, the session allows 165 nested script frames while a child
        console process allows 4694. The directory suites drive deep validation
        chains through worker runspaces and sit close to the session limit even
        without instrumentation, so enabling code coverage there fails them with
        a call-depth overflow rather than with the rejection they assert.

    .PARAMETER RepositoryRoot
        The directory on this machine that holds the minimal repository tree.

    .PARAMETER DomainDistinguishedName
        The distinguished name of the fixture domain.

    .PARAMETER MemberServer
        The lab machine that hosts the SMB share, Task Scheduler, and
        private-key fixtures.

    .PARAMETER OutputPath
        The file that receives the redacted acceptance evidence.

    .PARAMETER CoverageOutputPath
        The file that receives the JaCoCo code-coverage document.

    .NOTES
        Requires an elevated session with directory access.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$RepositoryRoot,

    [Parameter(Mandatory)]
    [ValidatePattern('^DC=[^,]+(?:,DC=[^,]+)+$')]
    [string]$DomainDistinguishedName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$MemberServer,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [string]$CoverageOutputPath
)

$ErrorActionPreference = 'Stop'

try {
    Import-Module (
        Join-Path $RepositoryRoot 'tests\Lab\WindowsAccessControl.DomainLab.psm1'
    ) -Force -ErrorAction Stop

    $null = Initialize-WindowsAccessControlDomainLab `
        -DomainDistinguishedName $DomainDistinguishedName `
        -MemberServer $MemberServer `
        -Confirm:$false

    $acceptanceParameters = @{
        RepositoryRoot          = $RepositoryRoot
        DomainDistinguishedName = $DomainDistinguishedName
        MemberServer            = $MemberServer
        OutputPath              = $OutputPath
        Confirm                 = $false
        InformationAction       = 'Continue'
    }
    if (-not [string]::IsNullOrWhiteSpace($CoverageOutputPath)) {
        $acceptanceParameters['CoverageOutputPath'] = $CoverageOutputPath
    }

    $summary = Invoke-WindowsAccessControlDomainLabAcceptance @acceptanceParameters
    Write-Information (
        'ACCEPTANCE RESULT {0} suites={1}' -f
            $summary.Result,
            @($summary.Suites).Count
    ) -InformationAction Continue
}
catch {
    Write-Information (
        'ACCEPTANCE FAILED {0}' -f $_.Exception.Message
    ) -InformationAction Continue
    Write-Information $_.ScriptStackTrace -InformationAction Continue
    exit 1
}

exit 0
