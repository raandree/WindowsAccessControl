function Invoke-WithWindowsImpersonation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscredential]$Credential,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$ArgumentList = @()
    )

    Initialize-WindowsAccessControlNativeType
    $tokenHandle = $null
    $operationError = $null
    $cleanupError = $null
    $result = $null
    try {
        $tokenHandle = [WindowsAccessControl.NativeMethods]::LogonUser(
            $Credential.UserName,
            $Credential.Password
        )
        $operationScriptBlock = $ScriptBlock
        $operationArgumentList = $ArgumentList
        $operation = [Func[object]] {
            @(& $operationScriptBlock @operationArgumentList)
        }
        $result = [WindowsAccessControl.NativeMethods]::RunImpersonated(
            $tokenHandle,
            $operation
        )
    } catch {
        $operationError = $_
    } finally {
        if ($null -ne $tokenHandle) {
            try {
                $tokenHandle.Dispose()
            } catch {
                $cleanupError = $_
            }
        }
    }

    if ($operationError -and -not $cleanupError) {
        $PSCmdlet.ThrowTerminatingError($operationError)
    }
    if ($cleanupError) {
        $errors = [System.Collections.Generic.List[System.Exception]]::new()
        if ($operationError) {
            $errors.Add($operationError.Exception)
        }
        $errors.Add($cleanupError.Exception)
        throw [System.AggregateException]::new(
            'The impersonation token could not be released.',
            $errors
        )
    }
    $result
}
