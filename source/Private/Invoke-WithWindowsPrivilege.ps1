function Invoke-WithWindowsPrivilege {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$ArgumentList = @()
    )

    Initialize-WindowsAccessControlNativeType
    $uniqueNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $leases = [System.Collections.Generic.List[System.IDisposable]]::new()
    $operationError = $null
    $cleanupErrors = [System.Collections.Generic.List[System.Exception]]::new()
    try {
        foreach ($privilegeName in $Name) {
            if ($uniqueNames.Add($privilegeName)) {
                $leases.Add(
                    [WindowsAccessControl.NativeMethods]::AcquirePrivilege($privilegeName)
                )
            }
        }
        & $ScriptBlock @ArgumentList
    } catch {
        $operationError = $_
    } finally {
        for ($index = $leases.Count - 1; $index -ge 0; $index--) {
            try {
                $leases[$index].Dispose()
            } catch {
                $cleanupError = $_
                $cleanupErrors.Add($cleanupError.Exception)
            }
        }
    }

    if ($operationError -and $cleanupErrors.Count -eq 0) {
        $PSCmdlet.ThrowTerminatingError($operationError)
    }
    if ($cleanupErrors.Count -gt 0) {
        $allErrors = [System.Collections.Generic.List[System.Exception]]::new()
        if ($operationError) {
            $allErrors.Add($operationError.Exception)
        }
        $allErrors.AddRange($cleanupErrors)
        throw [System.AggregateException]::new(
            'One or more privilege scopes could not be restored.',
            $allErrors
        )
    }
}
