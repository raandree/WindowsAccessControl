param
(
    [Parameter()]
    [System.String]
    $ProjectName = (property ProjectName '')
)

<#
    .SYNOPSIS
        Fails the build when the test process held more than one runtime copy of
        a module-defined type.

    .DESCRIPTION
        PowerShell compiles a module file into a dynamic assembly carrying every
        class and enumeration it declares, and caches the compiled script block
        by file path and content. A read that misses that cache compiles the
        file again, and from then on the module's own commands emit the new copy
        while every script-side reference resolves the first one. The symptom is
        a strict type assertion failing with `Expected [X], but got [X]`, which
        is unreadable without this measurement (OI-31).

        The QA suite stops the test files from causing that, but it can only see
        the call sites it knows about. This measures the outcome instead.

        It is an exit block rather than a workflow task because a duplicate
        compilation surfaces as a failing type assertion, and a task placed
        after the Pester task is skipped on exactly that run.
#>
Exit-Build {
    # Nothing ran Pester, so there is no test process state to assert over.
    if (-not @(${*}.Tasks | Where-Object { $_.Name -match 'Pester' }))
    {
        return
    }

    if (-not $ProjectName)
    {
        $ProjectName = Get-SamplerProjectName -BuildRoot $BuildRoot
    }

    $module = @(Get-Module -Name $ProjectName)

    if ($module.Count -ne 1)
    {
        throw (
            "The test phase ran but '$ProjectName' is loaded $($module.Count) time(s) in " +
            'this process. Exactly one instance is required, because a second read of the ' +
            'module file compiles a second copy of every type it declares.'
        )
    }

    # Derived from the module's own assembly so a rename cannot silently empty
    # the probe set. The compiler-generated helper types are skipped.
    $probeTypeName = @(
        $module[0].ImplementingAssembly.GetTypes() |
            Where-Object { $_.IsPublic -and $_.Name -notmatch '<' } |
            ForEach-Object { $_.FullName }
    )

    if ($probeTypeName.Count -eq 0)
    {
        throw (
            "'$ProjectName' declares no types this task can probe, so it cannot measure " +
            'what it asserts.'
        )
    }

    $loadedAssembly = [System.AppDomain]::CurrentDomain.GetAssemblies()
    $split = @()

    foreach ($typeName in $probeTypeName)
    {
        $definingAssembly = @(
            foreach ($assembly in $loadedAssembly)
            {
                try
                {
                    if ($assembly.GetType($typeName, $false, $false))
                    {
                        $assembly.FullName
                    }
                }
                catch
                {
                    # An assembly that cannot be reflected over says nothing
                    # about this module and must not fail the build.
                }
            }
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
            'The module file was read more than once in this process, so every ' +
            'module-defined type now exists more than once and no type literal can name ' +
            "the copy the module's own commands emit. " + ($split -join ' ')
        )
    }

    Write-Build -Color 'Green' -Text (
        "`t$ProjectName was compiled once in this process, $($probeTypeName.Count) types probed."
    )
}
