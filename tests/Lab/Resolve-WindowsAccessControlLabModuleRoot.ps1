<#
    .SYNOPSIS
        Resolves the WindowsAccessControl module directory that a lab suite loads.

    .DESCRIPTION
        Every acceptance suite loads the module the repository build produced
        under `output\module`. Setting `WAC_LAB_MODULE_ROOT` to an installed
        module version directory makes every suite load that directory instead,
        which is how the acceptance runs against the installed package rather
        than against the build output tree.

        The variable is validated rather than trusted: a path without a module
        manifest fails here instead of silently falling back to the build
        output, because a silent fallback would report an installed-package run
        that never happened.

    .EXAMPLE
        $moduleRoot = & "$PSScriptRoot\Resolve-WindowsAccessControlLabModuleRoot.ps1"

        Returns the module version directory the suites must import.

    .OUTPUTS
        System.String
#>
[CmdletBinding()]
[OutputType([string])]
param()

$ErrorActionPreference = 'Stop'

if (-not [string]::IsNullOrWhiteSpace($env:WAC_LAB_MODULE_ROOT))
{
    $configuredRoot = $env:WAC_LAB_MODULE_ROOT
    if (-not (Test-Path -LiteralPath (Join-Path $configuredRoot 'WindowsAccessControl.psd1') -PathType Leaf))
    {
        throw "WAC_LAB_MODULE_ROOT does not contain a WindowsAccessControl manifest: '$configuredRoot'."
    }

    return (Resolve-Path -LiteralPath $configuredRoot).ProviderPath
}

$builtModule = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*" -Directory -ErrorAction SilentlyContinue |
    Sort-Object -Property { [version]$_.Name } -Descending |
    Select-Object -First 1
if (-not $builtModule)
{
    throw 'No built WindowsAccessControl module was found under output\module.'
}

$builtModule.FullName
