<#
    .SYNOPSIS
        JaCoCo document helpers shared by the code-coverage build tasks.

    .DESCRIPTION
        Every file in the `.build` folder is dot-sourced into the Invoke-Build
        script scope, so these functions are available to the tasks. They are
        kept out of the task file so they can be unit tested directly.
#>

<#
    .SYNOPSIS
        Returns a valid but empty JaCoCo document.

    .DESCRIPTION
        The merge task needs two documents. When no domain-lab evidence exists
        the second document has to be empty rather than a copy of the first, so
        the merged result stays identical to the locally measured result instead
        of quietly counting the same commands twice.

        The document type declaration is required: Sampler identifies the JaCoCo
        format from it, and merges into the second node of the `report` property.
#>
function Get-EmptyJaCoCoDocument
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    $counters = 'INSTRUCTION', 'LINE', 'METHOD', 'CLASS' |
        ForEach-Object -Process { '<counter type="{0}" missed="0" covered="0"/>' -f $_ }

    return @(
        '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
        '<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">'
        ('<report name="{0}">' -f [System.Security.SecurityElement]::Escape($Name))
        '<sessioninfo id="this" start="0" dump="0"/>'
        ($counters -join '')
        '</report>'
    ) -join ''
}

<#
    .SYNOPSIS
        Returns every measured line of a JaCoCo document keyed by source file.
#>
function Get-JaCoCoLineIndex
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlDocument]
        $Document
    )

    $index = @{ }

    foreach ($package in $Document.report.package)
    {
        foreach ($sourceFile in $package.sourcefile)
        {
            $key = '{0}/{1}' -f $package.name, $sourceFile.name

            if (-not $index.ContainsKey($key))
            {
                $index[$key] = @{ }
            }

            foreach ($line in $sourceFile.line)
            {
                $index[$key][[int] $line.nr] = [PSCustomObject] @{
                    Missed  = [int] $line.mi
                    Covered = [int] $line.ci
                }
            }
        }
    }

    return $index
}

<#
    .SYNOPSIS
        Returns the executed and analyzed command counts of a JaCoCo document.

    .DESCRIPTION
        The counts are summed from the `line` elements rather than read from the
        `counter` elements, because the line elements are the merge unit and are
        therefore authoritative for a merged document.
#>
function Get-JaCoCoCommandCount
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlDocument]
        $Document
    )

    $missed = 0
    $covered = 0

    foreach ($package in $Document.report.package)
    {
        foreach ($sourceFile in $package.sourcefile)
        {
            foreach ($line in $sourceFile.line)
            {
                $missed += [int] $line.mi
                $covered += [int] $line.ci
            }
        }
    }

    $analyzed = $missed + $covered

    return [PSCustomObject] @{
        Analyzed = $analyzed
        Executed = $covered
        Missed   = $missed
        Percent  = if ($analyzed -eq 0) { 0 } else { $covered / $analyzed * 100 }
    }
}

<#
    .SYNOPSIS
        Refuses a document that cannot merge into the reference document.

    .DESCRIPTION
        A merge only combines entries whose package, class, and line identity
        match. Two documents that disagree produce a union of disjoint sets,
        which changes the reported percentage without measuring anything new.
        This asserts that every source file and every line the document measures
        also exists in the reference document.
#>
function Assert-JaCoCoDocumentIdentity
{
    [CmdletBinding()]
    [OutputType([System.Void])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlDocument]
        $ReferenceDocument,

        [Parameter(Mandatory = $true)]
        [System.Xml.XmlDocument]
        $Document
    )

    $referenceIndex = Get-JaCoCoLineIndex -Document $ReferenceDocument
    $index = Get-JaCoCoLineIndex -Document $Document

    $unknownSourceFiles = @(
        $index.Keys | Where-Object -FilterScript { -not $referenceIndex.ContainsKey($_) }
    )

    if ($unknownSourceFiles.Count -gt 0)
    {
        throw (
            'The domain-lab code coverage measures source files the local run does not: ' +
            "$($unknownSourceFiles -join ', '). Rebuild the module and rerun the domain-lab acceptance."
        )
    }

    $unknownLineCount = 0

    foreach ($sourceFileKey in $index.Keys)
    {
        foreach ($lineNumber in $index[$sourceFileKey].Keys)
        {
            if (-not $referenceIndex[$sourceFileKey].ContainsKey($lineNumber))
            {
                $unknownLineCount++
            }
        }
    }

    if ($unknownLineCount -gt 0)
    {
        throw (
            "The domain-lab code coverage measures $unknownLineCount line(s) the local run does not. " +
            'Rebuild the module and rerun the domain-lab acceptance so both runs measure the same file.'
        )
    }
}

<#
    .SYNOPSIS
        Maps every line of the built module to the source file it was merged
        from.

    .DESCRIPTION
        ModuleBuilder merges the source tree into one `.psm1` and brackets each
        file with `#Region '<source path>'` and `#EndRegion '<source path>'`
        comment lines. Coverage measures that merged file, so those comments are
        the only evidence of which source file a measured line belongs to.

        A line outside every region is deliberately left unmapped. The caller
        keeps such a line in scope, so a built module whose regions cannot be
        read measures more rather than less.
#>
function Get-BuiltModuleSourceMap
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path
    )

    $map = @{ }
    $sourcePath = $null
    $lineNumber = 0

    foreach ($line in [System.IO.File]::ReadLines($Path))
    {
        $lineNumber++

        if ($line -cmatch "^#Region\s+'(?<SourcePath>[^']+)'")
        {
            $sourcePath = $Matches['SourcePath'] -replace '^\.[\\/]' -replace '\\', '/'

            continue
        }

        if ($line -cmatch "^#EndRegion\s+'(?<SourcePath>[^']+)'")
        {
            $sourcePath = $null

            continue
        }

        if ($sourcePath)
        {
            $map[$lineNumber] = $sourcePath
        }
    }

    return $map
}

<#
    .SYNOPSIS
        Returns the measured commands of a JaCoCo document per source file.

    .DESCRIPTION
        Every measured line is attributed through the built-module source map.
        A line the map does not know is reported under an empty source path
        rather than dropped, so the counts still add up to the whole document.
#>
function Get-JaCoCoSourceCoverage
{
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlDocument]
        $Document,

        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $SourceMap
    )

    $totals = @{ }

    foreach ($package in $Document.report.package)
    {
        foreach ($sourceFile in $package.sourcefile)
        {
            foreach ($line in $sourceFile.line)
            {
                $sourcePath = [System.String] $SourceMap[[int] $line.nr]

                if (-not $totals.ContainsKey($sourcePath))
                {
                    $totals[$sourcePath] = [PSCustomObject] @{
                        SourcePath = $sourcePath
                        Analyzed   = 0
                        Executed   = 0
                        Missed     = 0
                    }
                }

                $totals[$sourcePath].Missed += [int] $line.mi
                $totals[$sourcePath].Executed += [int] $line.ci
                $totals[$sourcePath].Analyzed += ([int] $line.mi + [int] $line.ci)
            }
        }
    }

    return [PSCustomObject[]] @($totals.Values | Sort-Object -Property 'SourcePath')
}

<#
    .SYNOPSIS
        Splits the measured commands into the surface the running test profile
        can execute and the surface only the domain-lab acceptance executes.

    .DESCRIPTION
        The default Pester profile has no domain controller, no member server,
        and no disposable fixture set, so it structurally cannot execute the
        enterprise families. Asserting one threshold over both surfaces reports
        "insufficiently tested" for code the profile was never able to run.

        Only a source file that matches a declared pattern leaves the asserted
        scope. Everything else, including a line the source map cannot attribute
        and every file added later, stays in scope. `DomainLabOnlySource`
        carries the per-file counts so a caller can refuse a declaration the
        measured run contradicts.
#>
function Get-JaCoCoScopedCommandCount
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlDocument]
        $Document,

        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $SourceMap,

        [Parameter()]
        [AllowEmptyCollection()]
        [System.String[]]
        $DomainLabOnlySourcePath = @()
    )

    $inScopeExecuted = 0
    $inScopeMissed = 0
    $domainLabOnlyExecuted = 0
    $domainLabOnlyMissed = 0
    $unattributedExecuted = 0
    $unattributedMissed = 0
    $matchedPattern = @{ }
    $domainLabOnlySource = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($source in (Get-JaCoCoSourceCoverage -Document $Document -SourceMap $SourceMap))
    {
        if (-not $source.SourcePath)
        {
            $unattributedExecuted += $source.Executed
            $unattributedMissed += $source.Missed
        }

        $pattern = @(
            $DomainLabOnlySourcePath | Where-Object -FilterScript {
                $source.SourcePath -and $source.SourcePath -like $_
            }
        )

        if ($pattern.Count -gt 0)
        {
            foreach ($name in $pattern)
            {
                $matchedPattern[$name] = $true
            }

            $domainLabOnlyExecuted += $source.Executed
            $domainLabOnlyMissed += $source.Missed
            $domainLabOnlySource.Add($source)

            continue
        }

        $inScopeExecuted += $source.Executed
        $inScopeMissed += $source.Missed
    }

    return [PSCustomObject] @{
        InScope             = Get-JaCoCoCountResult -Executed $inScopeExecuted -Missed $inScopeMissed
        DomainLabOnly       = Get-JaCoCoCountResult -Executed $domainLabOnlyExecuted -Missed $domainLabOnlyMissed
        Unattributed        = Get-JaCoCoCountResult -Executed $unattributedExecuted -Missed $unattributedMissed
        DomainLabOnlySource = $domainLabOnlySource.ToArray()
        UnmatchedPattern    = @(
            $DomainLabOnlySourcePath | Where-Object -FilterScript { -not $matchedPattern.ContainsKey($_) }
        )
    }
}

<#
    .SYNOPSIS
        Returns one command-count result from an executed and a missed count.
#>
function Get-JaCoCoCountResult
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Int32]
        $Executed,

        [Parameter(Mandatory = $true)]
        [System.Int32]
        $Missed
    )

    $analyzed = $Executed + $Missed

    return [PSCustomObject] @{
        Analyzed = $analyzed
        Executed = $Executed
        Missed   = $Missed
        Percent  = if ($analyzed -eq 0) { 0 } else { $Executed / $analyzed * 100 }
    }
}
