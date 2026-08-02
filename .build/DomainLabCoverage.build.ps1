param
(
    [Parameter()]
    [System.String]
    $ProjectPath = (property ProjectPath $BuildRoot),

    [Parameter()]
    [System.String]
    $OutputDirectory = (property OutputDirectory (Join-Path $BuildRoot 'output')),

    [Parameter()]
    [System.String]
    $BuiltModuleSubdirectory = (property BuiltModuleSubdirectory ''),

    [Parameter()]
    [System.Management.Automation.SwitchParameter]
    $VersionedOutputDirectory = (property VersionedOutputDirectory $true),

    [Parameter()]
    [System.String]
    $ProjectName = (property ProjectName ''),

    [Parameter()]
    [System.String]
    $PesterOutputFolder = (property PesterOutputFolder 'testResults'),

    [Parameter()]
    [System.String]
    $CodeCoverageThreshold = (property CodeCoverageThreshold ''),

    [Parameter()]
    [System.Collections.Hashtable]
    $BuildInfo = (property BuildInfo @{ })
)

# Synopsis: Import the domain-lab code coverage document so it can be merged with the local run.
task Import_DomainLab_Code_Coverage {
    # Get the values for task variables, see https://github.com/gaelcolas/Sampler?tab=readme-ov-file#build-task-variables.
    . Set-SamplerTaskVariable

    $GetCodeCoverageThresholdParameters = @{
        RuntimeCodeCoverageThreshold = $CodeCoverageThreshold
        BuildInfo                    = $BuildInfo
    }

    $CodeCoverageThreshold = Get-CodeCoverageThreshold @GetCodeCoverageThresholdParameters

    if (-not $CodeCoverageThreshold)
    {
        Write-Build -Color 'DarkGray' -Text 'Code coverage has been disabled, skipping task.'

        return
    }

    $PesterOutputFolder = Get-SamplerAbsolutePath -Path $PesterOutputFolder -RelativeTo $OutputDirectory

    "`tPester Output Folder       = '$PesterOutputFolder'"

    $domainLabCodeCoverageFile = 'tests/Lab/coverage/JaCoCo_coverage_DomainLab.xml'

    if ($BuildInfo.ContainsKey('CodeCoverage') -and $BuildInfo.CodeCoverage.ContainsKey('DomainLabCodeCoverageFile'))
    {
        $domainLabCodeCoverageFile = $BuildInfo.CodeCoverage.DomainLabCodeCoverageFile
    }

    $domainLabCodeCoverageFile = Get-SamplerAbsolutePath -Path $domainLabCodeCoverageFile -RelativeTo $ProjectPath

    "`tDomain-Lab Coverage File   = '$domainLabCodeCoverageFile'"

    $destinationFile = Join-Path -Path $PesterOutputFolder -ChildPath 'JaCoCo_coverage_DomainLab.xml'
    $unusableReason = $null
    $domainLabDocument = $null

    if (-not (Test-Path -Path $domainLabCodeCoverageFile))
    {
        $unusableReason = (
            'No domain-lab code coverage was found. Run ' +
            'tests/Lab/Invoke-WindowsAccessControlLabAcceptance.ps1 to produce it.'
        )
    }
    else
    {
        $localCodeCoverageFile = Get-SamplerCodeCoverageOutputFile -BuildInfo $BuildInfo -PesterOutputFolder $PesterOutputFolder

        if (-not $localCodeCoverageFile -or -not (Test-Path -Path $localCodeCoverageFile))
        {
            throw "The locally measured code coverage file was not found: '$localCodeCoverageFile'."
        }

        try
        {
            [System.Xml.XmlDocument] $localDocument = Get-Content -Path $localCodeCoverageFile -Raw
            [System.Xml.XmlDocument] $domainLabDocument = Get-Content -Path $domainLabCodeCoverageFile -Raw

            Assert-JaCoCoDocumentIdentity -ReferenceDocument $localDocument -Document $domainLabDocument
        }
        catch
        {
            # A document that cannot be read or was measured against another build must not
            # be merged, and must not fail a build that has no way to produce a current one.
            $unusableReason = $_.Exception.Message
        }
    }

    if ($unusableReason)
    {
        Write-Build -Color 'Yellow' -Text (
            $unusableReason + ' The threshold is asserted over the commands the local test ' +
            'profile can execute, and the declared domain-lab-only source files are ' +
            'reported rather than asserted.'
        )

        Set-Content `
            -Path $destinationFile `
            -Value (Get-EmptyJaCoCoDocument -Name 'WindowsAccessControl domain lab (absent)') `
            -Encoding 'ascii' `
            -NoNewline `
            -Force

        return
    }

    $domainLabCount = Get-JaCoCoCommandCount -Document $domainLabDocument

    Write-Build -Color 'Green' -Text (
        'Domain-lab code coverage: {0:0.##} % ({1} of {2} commands).' -f
        $domainLabCount.Percent, $domainLabCount.Executed, $domainLabCount.Analyzed
    )

    Copy-Item -Path $domainLabCodeCoverageFile -Destination $destinationFile -Force
}

# Synopsis: Fails the build if the merged code coverage is under the predefined threshold.
task Assert_Merged_Code_Coverage_Threshold {
    # Get the values for task variables, see https://github.com/gaelcolas/Sampler?tab=readme-ov-file#build-task-variables.
    . Set-SamplerTaskVariable

    $GetCodeCoverageThresholdParameters = @{
        RuntimeCodeCoverageThreshold = $CodeCoverageThreshold
        BuildInfo                    = $BuildInfo
    }

    $CodeCoverageThreshold = Get-CodeCoverageThreshold @GetCodeCoverageThresholdParameters

    if (-not $CodeCoverageThreshold)
    {
        Write-Build -Color 'DarkGray' -Text 'Code coverage has been disabled, skipping task.'

        return
    }

    $PesterOutputFolder = Get-SamplerAbsolutePath -Path $PesterOutputFolder -RelativeTo $OutputDirectory

    $codeCoverageMergedOutputFile = 'CodeCov_Merged.xml'

    if ($BuildInfo.CodeCoverage.CodeCoverageMergedOutputFile)
    {
        $codeCoverageMergedOutputFile = $BuildInfo.CodeCoverage.CodeCoverageMergedOutputFile
    }

    $codeCoverageMergedOutputFile = Get-SamplerAbsolutePath -Path $codeCoverageMergedOutputFile -RelativeTo $PesterOutputFolder

    "`tCode Coverage Threshold    = '$CodeCoverageThreshold'"
    "`tMerged Code Coverage File  = '$codeCoverageMergedOutputFile'"

    if (-not (Test-Path -Path $codeCoverageMergedOutputFile))
    {
        throw "The merged code coverage file was not found: '$codeCoverageMergedOutputFile'."
    }

    if (-not $BuiltModuleRootScriptPath -or -not (Test-Path -Path $BuiltModuleRootScriptPath))
    {
        throw "The built module root script was not found: '$BuiltModuleRootScriptPath'."
    }

    $localCodeCoverageFile = Get-SamplerCodeCoverageOutputFile -BuildInfo $BuildInfo -PesterOutputFolder $PesterOutputFolder

    if (-not $localCodeCoverageFile -or -not (Test-Path -Path $localCodeCoverageFile))
    {
        throw "The locally measured code coverage file was not found: '$localCodeCoverageFile'."
    }

    [System.Xml.XmlDocument] $mergedDocument = Get-Content -Path $codeCoverageMergedOutputFile -Raw
    [System.Xml.XmlDocument] $localDocument = Get-Content -Path $localCodeCoverageFile -Raw

    $merged = Get-JaCoCoCommandCount -Document $mergedDocument

    $domainLabImportedFile = Join-Path -Path $PesterOutputFolder -ChildPath 'JaCoCo_coverage_DomainLab.xml'
    $domainLabMerged = $false

    if (Test-Path -Path $domainLabImportedFile)
    {
        [System.Xml.XmlDocument] $domainLabImported = Get-Content -Path $domainLabImportedFile -Raw

        $domainLabMerged = (Get-JaCoCoCommandCount -Document $domainLabImported).Analyzed -gt 0
    }

    $domainLabOnlySourcePath = @()

    if ($BuildInfo.ContainsKey('CodeCoverage') -and $BuildInfo.CodeCoverage.ContainsKey('DomainLabOnlySourcePath'))
    {
        $domainLabOnlySourcePath = @(
            $BuildInfo.CodeCoverage.DomainLabOnlySourcePath |
                Where-Object -FilterScript { -not [System.String]::IsNullOrWhiteSpace($_) }
        )
    }

    $sourceMap = Get-BuiltModuleSourceMap -Path $BuiltModuleRootScriptPath

    $scoped = Get-JaCoCoScopedCommandCount `
        -Document $mergedDocument `
        -SourceMap $sourceMap `
        -DomainLabOnlySourcePath $domainLabOnlySourcePath

    if ($scoped.UnmatchedPattern.Count -gt 0)
    {
        throw (
            'These declared domain-lab-only source paths match no source file of the built ' +
            "module: $($scoped.UnmatchedPattern -join ', '). Remove a path that no longer " +
            'applies rather than leaving the asserted scope smaller than it looks.'
        )
    }

    # A declaration is only honest while the local run really executes nothing of the file.
    # Measuring it against the merged document instead would accept anything the lab covers.
    $localScoped = Get-JaCoCoScopedCommandCount `
        -Document $localDocument `
        -SourceMap $sourceMap `
        -DomainLabOnlySourcePath $domainLabOnlySourcePath

    $executedDeclaration = @(
        $localScoped.DomainLabOnlySource | Where-Object -FilterScript { $_.Executed -gt 0 }
    )

    if ($executedDeclaration.Count -gt 0)
    {
        $executedDetail = ($executedDeclaration | ForEach-Object -Process {
                '{0} ({1} of {2} commands)' -f $_.SourcePath, $_.Executed, $_.Analyzed
            }) -join ', '

        throw (
            'These source paths are declared domain-lab-only but the local test profile ' +
            "executes them: $executedDetail. Remove them from DomainLabOnlySourcePath so " +
            'their coverage is asserted rather than reported.'
        )
    }

    Write-Build -Color 'White' -Text (
        'Whole-module coverage {0:0.##} % ({1} of {2} commands), reported only. Domain-lab evidence merged: {3}.' -f
        $merged.Percent, $merged.Executed, $merged.Analyzed,
        $(if ($domainLabMerged) { 'yes' } else { 'no' })
    )

    Write-Build -Color 'White' -Text (
        'Domain-lab-only coverage {0:0.##} % ({1} of {2} commands over {3} source files), reported only.' -f
        $scoped.DomainLabOnly.Percent, $scoped.DomainLabOnly.Executed,
        $scoped.DomainLabOnly.Analyzed, $scoped.DomainLabOnlySource.Count
    )

    if ($scoped.Unattributed.Analyzed -gt 0)
    {
        Write-Build -Color 'Yellow' -Text (
            ('{0} measured command(s) could not be attributed to a source file and stay in ' +
                'scope. The coverage document and the built module may describe different builds.') -f
            $scoped.Unattributed.Analyzed
        )
    }

    if ($scoped.InScope.Percent -lt $CodeCoverageThreshold)
    {
        throw (
            ('Code Coverage FAILURE: {0:0.##} % of the {1} commands this test profile can ' +
                'execute is under the threshold of {2:0.##} %.') -f
            $scoped.InScope.Percent, $scoped.InScope.Analyzed, $CodeCoverageThreshold
        )
    }

    Write-Build -Color 'Green' -Text (
        'Code Coverage SUCCESS with value of {0:0.##} % ({1} of {2} commands this test profile can execute, threshold {3:0.##} %)' -f
        $scoped.InScope.Percent, $scoped.InScope.Executed, $scoped.InScope.Analyzed, $CodeCoverageThreshold
    )
}
