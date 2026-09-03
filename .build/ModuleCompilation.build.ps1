param
(
    [Parameter()]
    [System.String]
    $ProjectName = (property ProjectName '')
)

<#
    .SYNOPSIS
        Fails the build when the test process holds more than one runtime copy
        of a module-defined type.

    .DESCRIPTION
        PowerShell compiles a module file into a dynamic assembly carrying every
        class and enumeration it declares, and caches the compiled script block
        by file path and content. A read that misses that cache compiles the
        file again, and from then on the module's own commands emit the new copy
        while every script-side reference resolves the first one. The symptom is
        a strict type assertion failing with `Expected [X], but got [X]`, which
        is unreadable without this measurement (OI-31).

        The QA suite stops the test files from causing that. This task is what
        covers everything else, including the module's own bounded-batch engine,
        which imports the manifest into a runspace pool in this same process.
#>

# Synopsis: Fails the build if more than one runtime copy of a module-defined type is live.
task Assert_Single_Module_Compilation {
    # One enumeration and one class, so a change to either shape is noticed.
    $probeTypeName = @(
        'WindowsServiceControlManagerRights'
        'WindowsAccessControlNtfsAccessRule'
    )

    if (-not (Get-Module -Name $ProjectName))
    {
        Write-Build -Color 'DarkGray' -Text (
            "'$ProjectName' is not loaded in this process, skipping task."
        )

        return
    }

    $split = @()

    foreach ($typeName in $probeTypeName)
    {
        $definingAssembly = @(
            [System.AppDomain]::CurrentDomain.GetAssemblies() |
                Where-Object { $_.GetType($typeName, $false, $false) } |
                ForEach-Object { $_.FullName }
        )

        if ($definingAssembly.Count -eq 0)
        {
            throw (
                "No loaded assembly defines '$typeName', so this task cannot measure what " +
                'it asserts. Update the probe type names if the module surface changed.'
            )
        }

        Write-Build -Color 'White' -Text (
            "`t{0,-40} {1} runtime copy/copies" -f $typeName, $definingAssembly.Count
        )

        if ($definingAssembly.Count -gt 1)
        {
            $split += "$typeName is defined by $($definingAssembly.Count) assemblies: " +
                ($definingAssembly -join ', ')
        }
    }

    if ($split)
    {
        throw (
            "The module file was read more than once in this process, so every " +
            "module-defined type now exists more than once and no type literal can name " +
            "the copy the module's own commands emit. " + ($split -join ' ')
        )
    }

    Write-Build -Color 'Green' -Text (
        "`tThe module was compiled once in this process."
    )
}
