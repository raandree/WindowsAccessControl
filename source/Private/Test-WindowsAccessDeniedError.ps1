function Test-WindowsAccessDeniedError {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $exception = $ErrorRecord.Exception
    while ($exception) {
        if ($exception -is [System.ComponentModel.Win32Exception] -and
            $exception.NativeErrorCode -eq 5) {
            return $true
        }
        $exception = $exception.InnerException
    }
    $false
}
