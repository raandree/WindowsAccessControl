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
