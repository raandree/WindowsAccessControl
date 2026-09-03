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

    .PARAMETER PowerShellEdition
        The PowerShell editions the acceptance runs in, one complete pass each.
        The suites are cross-edition contracts, so both supported editions are
        exercised by default. The editions run in the order given because they
        share one fixture set.

    .PARAMETER CoverageEdition
        The single edition that arms code coverage, or `None`. Coverage
        instruments every measured command, so arming it in more than one pass
        would multiply the run time without measuring a line the other pass
        cannot reach. It must be one of the requested editions or `None`.

    .PARAMETER EvidencePath
        The local base file name for the redacted acceptance evidence. Each
        edition writes its own file with the edition appended to the base name,
        because one pass cannot describe the other.

    .PARAMETER CoverageEvidencePath
        The local file that receives the domain-lab JaCoCo code-coverage
        document. It is deliberately outside `output` because the Sampler build
        deletes that tree, and the repository build imports it from here before
        merging.

    .PARAMETER SkipPayloadDeployment
        Reuses the tree already present on the management domain controller
        instead of deploying it again. `SkipPayload` and `SkipDeployment` are
        aliases for compatibility and concise interactive use.

    .PARAMETER ModuleSource
        Selects the module the suites load. `Build` loads the tree the Sampler
        build wrote to `output\module`. `Installed` expands the packaged module
        into the machine module path of the management domain controller and
        points every suite at that installed copy, which is what proves the
        package and not only the build output.

    .PARAMETER PackagePath
        The NuGet package an `Installed` run expands. It defaults to the newest
        `WindowsAccessControl.*.nupkg` under `output`, which `build.ps1 -Tasks
        pack` produces.

    .EXAMPLE
        .\Invoke-WindowsAccessControlLabAcceptance.ps1

        Deploys the current build into the lab and runs every suite in both
        supported PowerShell editions.

    .EXAMPLE
        .\Invoke-WindowsAccessControlLabAcceptance.ps1 -PowerShellEdition Core

        Runs only the PowerShell 7 pass and arms no coverage.

    .EXAMPLE
        .\Invoke-WindowsAccessControlLabAcceptance.ps1 -SkipPayloadDeployment -Confirm:$false

        Runs the acceptance against the repository tree already deployed to
        the management domain controller without interactive confirmation.

    .EXAMPLE
        .\Invoke-WindowsAccessControlLabAcceptance.ps1 -ModuleSource Installed -CoverageEdition None

        Installs the packaged module into the machine module path of the
        management domain controller and runs every suite against it.

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
    [ValidateSet('Desktop', 'Core')]
    [string[]]$PowerShellEdition = @('Desktop', 'Core'),

    [Parameter()]
    [ValidateSet('Desktop', 'Core', 'None')]
    [string]$CoverageEdition = 'Desktop',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EvidencePath = (Join-Path $env:TEMP 'wac-domain-lab-evidence.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CoverageEvidencePath = (Join-Path $PSScriptRoot 'coverage\JaCoCo_coverage_DomainLab.xml'),

    [Parameter()]
    [ValidateSet('Build', 'Installed')]
    [string]$ModuleSource = 'Build',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PackagePath,

    [Parameter()]
    [Alias('SkipPayload', 'SkipDeployment')]
    [switch]$SkipPayloadDeployment
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

$editions = @($PowerShellEdition | Select-Object -Unique)
$coverageEditionName = $CoverageEdition
if (-not $PSBoundParameters.ContainsKey('CoverageEdition') -and
    $editions -notcontains $coverageEditionName) {
    $coverageEditionName = $editions[0]
}
if ($coverageEditionName -ne 'None' -and $editions -notcontains $coverageEditionName) {
    throw (
        "CoverageEdition '$coverageEditionName' is not one of the requested editions: " +
        "$($editions -join ', ')."
    )
}

$resolvedPackagePath = $null
if ($ModuleSource -eq 'Installed') {
    # Coverage instruments the built module, so measuring it while the suites
    # load an installed copy would report a green run over an unmeasured module.
    if ($coverageEditionName -ne 'None') {
        throw 'An installed-package run cannot arm code coverage. Pass -CoverageEdition None.'
    }

    $package = if ($PSBoundParameters.ContainsKey('PackagePath')) {
        Get-Item -LiteralPath $PackagePath -ErrorAction Stop
    }
    else {
        Get-ChildItem -Path (Join-Path $repositoryRoot 'output\WindowsAccessControl.*.nupkg') -ErrorAction SilentlyContinue |
            Sort-Object -Property LastWriteTimeUtc -Descending |
            Select-Object -First 1
    }
    if (-not $package) {
        throw 'No WindowsAccessControl package was found under output. Run ".\build.ps1 -Tasks pack" first.'
    }
    $resolvedPackagePath = $package.FullName
}

$resolvedEvidencePath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($EvidencePath)
$evidenceDirectory = Split-Path -Path $resolvedEvidencePath -Parent
$evidenceBaseName = [IO.Path]::GetFileNameWithoutExtension($resolvedEvidencePath)
$evidenceExtension = [IO.Path]::GetExtension($resolvedEvidencePath)
if (-not (Test-Path -LiteralPath $evidenceDirectory -PathType Container)) {
    $null = New-Item -Path $evidenceDirectory -ItemType Directory -Force
}

$shouldProcessAction = if ($SkipPayloadDeployment) {
    "Run the domain-lab acceptance in $($editions -join ' and ')"
}
else {
    "Deploy the current build and run the domain-lab acceptance in $($editions -join ' and ')"
}
if (-not $PSCmdlet.ShouldProcess(
        "Lab '$LabName' machines '$ManagementDomainController' and '$MemberServer'",
        $shouldProcessAction
    )) {
    return
}

Import-Lab -Name $LabName -NoValidation

if (-not $SkipPayloadDeployment) {
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

$installedModuleRoot = ''
if ($ModuleSource -eq 'Installed') {
    $packageDestination = Join-Path $RemoteRepositoryPath 'package'
    Invoke-LabCommand `
        -ComputerName $ManagementDomainController `
        -ActivityName 'Reset the package staging directory' `
        -ScriptBlock {
            param($Path)

            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
            $null = New-Item -Path $Path -ItemType Directory -Force
        } `
        -ArgumentList $packageDestination `
        -NoDisplay

    Copy-LabFileItem `
        -Path $resolvedPackagePath `
        -ComputerName $ManagementDomainController `
        -DestinationFolderPath $packageDestination

    $installedModuleRoot = Invoke-LabCommand `
        -ComputerName $ManagementDomainController `
        -ActivityName 'Install the packaged module into the machine module path' `
        -ScriptBlock {
            param($PackageDirectory)

            $ErrorActionPreference = 'Stop'
            Add-Type -AssemblyName System.IO.Compression.FileSystem

            $package = Get-ChildItem -Path (Join-Path $PackageDirectory '*.nupkg') |
                Sort-Object -Property LastWriteTimeUtc -Descending |
                Select-Object -First 1
            if (-not $package) {
                throw "No package reached '$PackageDirectory'."
            }

            $staging = Join-Path $PackageDirectory 'expanded'
            Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
            [IO.Compression.ZipFile]::ExtractToDirectory($package.FullName, $staging)

            # A NuGet package carries its own manifest tree. An installed module
            # is the payload alone, so the packaging artifacts are dropped
            # rather than shipped into the module path.
            foreach ($artifact in '_rels', 'package', '[Content_Types].xml') {
                Remove-Item -LiteralPath (Join-Path $staging $artifact) -Recurse -Force -ErrorAction SilentlyContinue
            }
            Get-ChildItem -Path (Join-Path $staging '*.nuspec') -ErrorAction SilentlyContinue |
                Remove-Item -Force

            $manifestPath = Join-Path $staging 'WindowsAccessControl.psd1'
            if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
                throw 'The package does not contain a WindowsAccessControl manifest.'
            }
            $version = (Import-PowerShellDataFile -LiteralPath $manifestPath).ModuleVersion

            $installRoot = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\WindowsAccessControl'
            $target = Join-Path $installRoot $version
            Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
            $null = New-Item -Path $target -ItemType Directory -Force
            Copy-Item -Path (Join-Path $staging '*') -Destination $target -Recurse -Force

            $null = Test-ModuleManifest -Path (Join-Path $target 'WindowsAccessControl.psd1')
            $target
        } `
        -ArgumentList $packageDestination `
        -PassThru `
        -NoDisplay

    $installedModuleRoot = [string]$installedModuleRoot
    Write-Information (
        "The packaged module is installed at '$installedModuleRoot'."
    ) -InformationAction Continue
}

$editionResults = [Collections.Generic.List[object]]::new()

foreach ($edition in $editions) {
    $editionKey = $edition.ToLowerInvariant()
    $armCoverage = $edition -eq $coverageEditionName
    $remoteEvidencePath = Join-Path `
        $RemoteRepositoryPath `
        ('lab-evidence-{0}.json' -f $editionKey)
    $remoteCoveragePath = if ($armCoverage) {
        Join-Path $RemoteRepositoryPath 'lab-coverage.xml'
    }
    else {
        ''
    }

    Write-Information (
        '[{0:O}] EDITION START {1} coverage={2}' -f
            [datetime]::UtcNow, $edition, $armCoverage
    ) -InformationAction Continue

    $acceptanceOutput = Invoke-LabCommand `
        -ComputerName $ManagementDomainController `
        -ActivityName "WindowsAccessControl domain-lab acceptance ($edition)" `
        -ScriptBlock {
            param($RepositoryPath, $DomainDn, $Member, $OutputPath, $CoveragePath, $Edition, $ModuleRoot)

            # The suites read this, so it has to be set before the child console
            # process inherits the environment.
            $env:WAC_LAB_MODULE_ROOT = $ModuleRoot

            $executable = if ($Edition -eq 'Core') {
                $resolved = @(
                    Get-Command -Name 'pwsh.exe' -CommandType Application -ErrorAction SilentlyContinue
                ) | Select-Object -First 1
                if ($resolved) {
                    $resolved.Source
                }
                else {
                    Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
                }
            }
            else {
                Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            }
            if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
                throw "The $Edition PowerShell host is not installed on this machine: '$executable'."
            }

            $starter = Join-Path `
                $RepositoryPath `
                'tests\Lab\Start-WindowsAccessControlDomainLabAcceptance.ps1'
            $arguments = @(
                '-NoProfile'
                '-NonInteractive'
                '-ExecutionPolicy', 'Bypass'
                '-File', $starter
                '-RepositoryRoot', $RepositoryPath
                '-DomainDistinguishedName', $DomainDn
                '-MemberServer', $Member
                '-OutputPath', $OutputPath
            )
            if (-not [string]::IsNullOrWhiteSpace($CoveragePath)) {
                $arguments += @('-CoverageOutputPath', $CoveragePath)
            }

            $output = & $executable @arguments 2>&1 |
                ForEach-Object { [string]$_ }
            [pscustomobject]@{
                ExitCode = $LASTEXITCODE
                Output   = $output
            }
        } `
        -ArgumentList $RemoteRepositoryPath, $DomainDistinguishedName, $MemberServer, $remoteEvidencePath, $remoteCoveragePath, $edition, $installedModuleRoot `
        -PassThru `
        -NoDisplay

    $acceptanceOutput.Output | Write-Information -InformationAction Continue
    Write-Information (
        '[{0:O}] EDITION END {1} exit={2}' -f
            [datetime]::UtcNow, $edition, $acceptanceOutput.ExitCode
    ) -InformationAction Continue

    $editionResults.Add([pscustomobject]@{
        Edition            = $edition
        ExitCode           = [int]$acceptanceOutput.ExitCode
        RemoteEvidencePath = $remoteEvidencePath
        RemoteCoveragePath = $remoteCoveragePath
        EvidencePath       = Join-Path `
            $evidenceDirectory `
            ('{0}-{1}{2}' -f $evidenceBaseName, $editionKey, $evidenceExtension)
    })
}

$coverageDirectory = Split-Path -Path $CoverageEvidencePath -Parent
if (-not (Test-Path -LiteralPath $coverageDirectory -PathType Container)) {
    $null = New-Item -Path $coverageDirectory -ItemType Directory -Force
}

# A failed pass still writes its evidence, so every artifact is carried back
# before the run is failed.
$session = New-LabPSSession -ComputerName $ManagementDomainController
try {
    foreach ($editionResult in $editionResults) {
        try {
            Copy-Item `
                -Path $editionResult.RemoteEvidencePath `
                -Destination $editionResult.EvidencePath `
                -FromSession $session `
                -Force `
                -ErrorAction Stop
            Write-Information (
                "Evidence written to '$($editionResult.EvidencePath)'."
            ) -InformationAction Continue
        }
        catch {
            Write-Warning (
                "The $($editionResult.Edition) pass produced no evidence file: $($_.Exception.Message)"
            )
        }

        if ([string]::IsNullOrWhiteSpace($editionResult.RemoteCoveragePath)) {
            continue
        }

        try {
            Copy-Item `
                -Path $editionResult.RemoteCoveragePath `
                -Destination $CoverageEvidencePath `
                -FromSession $session `
                -Force `
                -ErrorAction Stop
            Write-Information (
                "Code coverage written to '$CoverageEvidencePath'."
            ) -InformationAction Continue
        }
        catch {
            Write-Warning (
                "The $($editionResult.Edition) pass produced no coverage document: $($_.Exception.Message)"
            )
        }
    }
}
finally {
    Remove-PSSession $session -ErrorAction SilentlyContinue
}

foreach ($editionResult in $editionResults) {
    if (-not (Test-Path -LiteralPath $editionResult.EvidencePath -PathType Leaf)) {
        continue
    }
    Get-Content -LiteralPath $editionResult.EvidencePath -Raw |
        ConvertFrom-Json |
        Add-Member `
            -NotePropertyName 'PowerShellEdition' `
            -NotePropertyValue $editionResult.Edition `
            -PassThru
}

$failedEditions = @($editionResults | Where-Object { $_.ExitCode -ne 0 })
if ($failedEditions.Count -gt 0) {
    throw (
        'The domain-lab acceptance failed in {0}: {1}.' -f
            (@('one edition', 'both editions')[[int]($failedEditions.Count -gt 1)]),
            (($failedEditions | ForEach-Object { '{0} (exit {1})' -f $_.Edition, $_.ExitCode }) -join ', ')
    )
}
