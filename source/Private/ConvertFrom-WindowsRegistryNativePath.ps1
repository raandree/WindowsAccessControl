function ConvertFrom-WindowsRegistryNativePath {
    <#
        .SYNOPSIS
            Converts a native registry key name to its PowerShell provider path.

        .DESCRIPTION
            Maps the native hive prefixes used by the Windows security APIs to
            their provider equivalents. Returns null for an absent name and for
            any prefix that is not a supported local hive, so an unrecognized
            native form is reported as unresolvable instead of as a path that no
            provider cmdlet can open.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$NativePath
    )

    if ([string]::IsNullOrWhiteSpace($NativePath)) {
        return $null
    }

    $segments = $NativePath -split '\\', 2
    $providerHive = switch ($segments[0].ToUpperInvariant()) {
        'MACHINE' { 'HKLM:' }
        'CURRENT_USER' { 'HKCU:' }
        'CLASSES_ROOT' { 'HKCR:' }
        'USERS' { 'HKU:' }
        default { $null }
    }
    if (-not $providerHive) {
        return $null
    }

    (@($providerHive) + @($segments | Select-Object -Skip 1) |
        Where-Object { $_ }) -join '\'
}
