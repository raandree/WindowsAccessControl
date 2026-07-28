function ConvertTo-WindowsTaskSchedulerPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $normalizedPath = $Path.Trim()
    if (-not $normalizedPath.StartsWith('\') -or
        $normalizedPath.StartsWith('\\') -or
        $normalizedPath.Contains('/') -or
        $normalizedPath.Contains([char]0) -or
        [Management.Automation.WildcardPattern]::ContainsWildcardCharacters(
            $normalizedPath
        ) -or
        ($normalizedPath.Length -gt 1 -and $normalizedPath.EndsWith('\')) -or
        $normalizedPath -match '\\\\') {
        throw [ArgumentException]::new(
            "Task Scheduler path '$Path' is not a canonical local absolute path."
        )
    }

    $segments = @($normalizedPath.TrimStart('\').Split('\'))
    if ($segments -contains '.' -or $segments -contains '..' -or
        @($segments | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
        throw [ArgumentException]::new(
            "Task Scheduler path '$Path' contains an invalid path segment."
        )
    }

    $normalizedPath
}