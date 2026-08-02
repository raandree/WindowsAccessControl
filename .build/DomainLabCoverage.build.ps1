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

    if (-not (Test-Path -Path $domainLabCodeCoverageFile))
    {
        Write-Build -Color 'Yellow' -Text (
            'No domain-lab code coverage was found. The threshold is asserted over the ' +
            'locally measured commands alone, which cannot execute the Active Directory, ' +
            'certificate private-key, and SMB share families. Run ' +
            'tests/Lab/Invoke-WindowsAccessControlLabAcceptance.ps1 to produce it.'
        )

        Set-Content `
            -Path $destinationFile `
            -Value (Get-EmptyJaCoCoDocument -Name 'WindowsAccessControl domain lab (absent)') `
            -Encoding 'ascii' `
            -NoNewline `
            -Force

        return
    }

    $localCodeCoverageFile = Get-SamplerCodeCoverageOutputFile -BuildInfo $BuildInfo -PesterOutputFolder $PesterOutputFolder

    if (-not $localCodeCoverageFile -or -not (Test-Path -Path $localCodeCoverageFile))
    {
        throw "The locally measured code coverage file was not found: '$localCodeCoverageFile'."
    }

    [System.Xml.XmlDocument] $localDocument = Get-Content -Path $localCodeCoverageFile -Raw
    [System.Xml.XmlDocument] $domainLabDocument = Get-Content -Path $domainLabCodeCoverageFile -Raw

    Assert-JaCoCoDocumentIdentity -ReferenceDocument $localDocument -Document $domainLabDocument

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

    [System.Xml.XmlDocument] $mergedDocument = Get-Content -Path $codeCoverageMergedOutputFile -Raw

    $merged = Get-JaCoCoCommandCount -Document $mergedDocument

    $localCodeCoverageFile = Get-SamplerCodeCoverageOutputFile -BuildInfo $BuildInfo -PesterOutputFolder $PesterOutputFolder

    if ($localCodeCoverageFile -and (Test-Path -Path $localCodeCoverageFile))
    {
        [System.Xml.XmlDocument] $localDocument = Get-Content -Path $localCodeCoverageFile -Raw

        $local = Get-JaCoCoCommandCount -Document $localDocument

        Write-Build -Color 'White' -Text (
            'Locally measured coverage {0:0.##} % ({1} of {2} commands).' -f
            $local.Percent, $local.Executed, $local.Analyzed
        )
    }

    if ($merged.Percent -lt $CodeCoverageThreshold)
    {
        throw (
            'Code Coverage FAILURE: {0:0.##} % of {1} merged commands is under the threshold of {2:0.##} %.' -f
            $merged.Percent, $merged.Analyzed, $CodeCoverageThreshold
        )
    }

    Write-Build -Color 'Green' -Text (
        'Code Coverage SUCCESS with value of {0:0.##} % ({1} of {2} merged commands, threshold {3:0.##} %)' -f
        $merged.Percent, $merged.Executed, $merged.Analyzed, $CodeCoverageThreshold
    )
}
