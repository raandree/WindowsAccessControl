[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(4, 1024)]
    [int]$AceCount = 256,

    [Parameter()]
    [ValidateRange(1, 10000)]
    [int]$OperationCount = 50,

    [Parameter()]
    [ValidateRange(1, 20)]
    [int]$Iterations = 5,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('RightsDisplay', 'RemovedAce', 'CngEquivalence', 'SingleTargetDispatch')]
    [string[]]$Workload = @('RightsDisplay', 'RemovedAce', 'CngEquivalence', 'SingleTargetDispatch'),

    [Parameter()]
    [string]$ModuleManifestPath,

    [Parameter()]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (Get-Module -Name WindowsAccessControl) {
    throw 'Run the benchmark in a fresh PowerShell process without WindowsAccessControl loaded.'
}
if ([string]::IsNullOrWhiteSpace($ModuleManifestPath)) {
    $repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
    $manifest = Get-ChildItem -Path (
        Join-Path $repositoryRoot 'output\module\WindowsAccessControl\*\WindowsAccessControl.psd1'
    ) | Sort-Object -Property { [version]$_.Directory.Name } -Descending | Select-Object -First 1
    if (-not $manifest) {
        throw 'Build the module before running the performance benchmark.'
    }
    $ModuleManifestPath = $manifest.FullName
}

$module = Import-Module -Name $ModuleManifestPath -PassThru -ErrorAction Stop
& {
    param($Module, $AceCount, $OperationCount, $Iterations, $Workload, $OutputPath)

    $original = [System.Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:')
    $reversed = [System.Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:')
    $retained = [System.Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:')
    $trustee = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    for ($aceIndex = 0; $aceIndex -lt $AceCount; $aceIndex++) {
        $ace = [System.Security.AccessControl.CommonAce]::new(
            [System.Security.AccessControl.AceFlags]::None,
            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            $aceIndex + 1,
            $trustee,
            $false,
            $null
        )
        $original.DiscretionaryAcl.InsertAce($aceIndex, $ace)
        $reversed.DiscretionaryAcl.InsertAce(0, $ace)
        if ($aceIndex % 4 -ne 0) {
            $retained.DiscretionaryAcl.InsertAce(0, $ace)
        }
    }
    $originalBytes = [byte[]]::new($original.BinaryLength)
    $original.GetBinaryForm($originalBytes, 0)
    $retainedBytes = [byte[]]::new($retained.BinaryLength)
    $retained.GetBinaryForm($retainedBytes, 0)
    $fixtures = @{
        Original         = $original
        Reversed         = $reversed
        OriginalBytes    = $originalBytes
        RetainedBytes    = $retainedBytes
        RemovedCount     = [int][Math]::Ceiling($AceCount / 4.0)
    }

    $runWorkload = {
        param($Name, $Count, $Fixtures)

        $checksum = [long]0
        switch ($Name) {
            RightsDisplay {
                $rightsTypes = @(
                    [System.Security.AccessControl.FileSystemRights]
                    [System.Security.AccessControl.RegistryRights]
                    [WindowsServiceRights]
                )
                $masks = @(0x001200A9L, 0xE0010000L, 0x80000400L, 0x001F01FFL)
                for ($operation = 0; $operation -lt $Count; $operation++) {
                    $parameters = @{
                        AccessMask = $masks[$operation % $masks.Count]
                        RightsType = $rightsTypes[$operation % $rightsTypes.Count]
                    }
                    $display = ConvertTo-WindowsAccessRightsDisplay @parameters
                    $checksum += $display.Length
                }
            }
            RemovedAce {
                $parameters = @{
                    OriginalSecurityDescriptor = $Fixtures.OriginalBytes
                    SecurityDescriptor         = $Fixtures.RetainedBytes
                }
                for ($operation = 0; $operation -lt $Count; $operation++) {
                    $removed = @(Get-WindowsADRemovedAce @parameters)
                    if ($removed.Count -ne $Fixtures.RemovedCount) {
                        throw 'The ACE difference returned an incorrect removal count.'
                    }
                    $checksum += $removed.Count
                }
            }
            CngEquivalence {
                $parameters = @{ Left = $Fixtures.Original; Right = $Fixtures.Reversed }
                for ($operation = 0; $operation -lt $Count; $operation++) {
                    if (-not (Test-WindowsCngKeyDaclEquivalent @parameters)) {
                        throw 'The reordered DACL must remain equivalent.'
                    }
                    $checksum++
                }
            }
            SingleTargetDispatch {
                $parameters = @{
                    InputObject   = @(1)
                    ScriptBlock   = { param($InputValue) $InputValue }
                    ThrottleLimit = 1
                }
                for ($operation = 0; $operation -lt $Count; $operation++) {
                    $result = @(Invoke-WindowsAccessControlBatch @parameters)
                    if ($result.Count -ne 1 -or $result[0] -ne 1) {
                        throw 'The dispatcher must return its single input.'
                    }
                    $checksum += $result.Count
                }
            }
        }
        $checksum
    }

    $expected = @{}
    foreach ($name in $Workload) {
        $expected[$name] = & $module $runWorkload $name $OperationCount $fixtures
    }
    $runs = [System.Collections.Generic.List[object]]::new()
    for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
        $orderedWorkload = [string[]]$Workload.Clone()
        if ($iteration % 2 -eq 0) {
            [Array]::Reverse($orderedWorkload)
        }
        foreach ($name in $orderedWorkload) {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $checksum = & $module $runWorkload $name $OperationCount $fixtures
            $stopwatch.Stop()
            if ($checksum -ne $expected[$name]) {
                throw "The $name workload returned inconsistent results."
            }
            $runs.Add([pscustomobject][ordered]@{
                Workload            = $name
                Iteration           = $iteration
                OperationCount      = $OperationCount
                ElapsedMilliseconds = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)
                Checksum            = $checksum
            })
        }
    }
    $summary = @(
        foreach ($group in $runs | Group-Object -Property Workload) {
            $elapsed = [double[]]$group.Group.ElapsedMilliseconds
            [Array]::Sort($elapsed)
            $middle = [int][Math]::Floor($elapsed.Count / 2.0)
            $median = if ($elapsed.Count % 2 -eq 0) {
                ($elapsed[$middle - 1] + $elapsed[$middle]) / 2.0
            } else {
                $elapsed[$middle]
            }
            [pscustomobject][ordered]@{
                Workload                  = $group.Name
                MedianElapsedMilliseconds = [Math]::Round($median, 3)
                MinimumElapsedMilliseconds = $elapsed[0]
                MaximumElapsedMilliseconds = $elapsed[$elapsed.Count - 1]
            }
        }
    )
    $benchmark = [pscustomobject][ordered]@{
        SchemaVersion     = 1
        MeasuredUtc       = [DateTime]::UtcNow.ToString('o')
        ModuleVersion     = $module.Version.ToString()
        ModuleSha256      = (Get-FileHash -LiteralPath $module.Path -Algorithm SHA256).Hash
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition = $PSVersionTable.PSEdition
        OperatingSystem   = [Environment]::OSVersion.VersionString
        ProcessorCount    = [Environment]::ProcessorCount
        AceCount          = $AceCount
        OperationCount    = $OperationCount
        Iterations        = $Iterations
        Runs              = $runs.ToArray()
        Summary           = $summary
    }
    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
        $null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($resolvedPath))
        [System.IO.File]::WriteAllText(
            $resolvedPath,
            ($benchmark | ConvertTo-Json -Depth 6),
            [System.Text.UTF8Encoding]::new($false)
        )
    }
    $benchmark
} $module $AceCount $OperationCount $Iterations $Workload $OutputPath
