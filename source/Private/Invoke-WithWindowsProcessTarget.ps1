function Invoke-WithWindowsProcessTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [WindowsSecurityDescriptorSection]$Sections,

        [Parameter()]
        [switch]$Write,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [object[]]$ArgumentList = @()
    )

    Initialize-WindowsAccessControlNativeType
    $operation = {
        param($processTarget, $sectionMask, $writeAccess, $action, $actionArguments)

        $ownsHandle = $false
        if ($processTarget.DescriptorSource -eq 'Handle') {
            $processHandle = [IntPtr]$processTarget.Handle
        } else {
            $processHandle = [WindowsAccessControl.NativeMethods]::OpenProcessSecurityHandle(
                [int]$processTarget.ProcessId,
                [long]$processTarget.CreationTimeFileTime,
                [uint32][int]$sectionMask,
                [bool]$writeAccess
            )
            $ownsHandle = $true
        }
        $operationTarget = $processTarget.PSObject.Copy()
        $operationTarget.Handle = $processHandle
        $operationError = $null
        $operationResult = $null
        try {
            $operationResult = & $action $operationTarget @actionArguments
        } catch {
            $operationError = $_
        } finally {
            if ($ownsHandle) {
                try {
                    [WindowsAccessControl.NativeMethods]::CloseProcessSecurityHandle(
                        $processHandle
                    )
                } catch {
                    if ($operationError) {
                        throw [System.AggregateException]::new(
                            'The process operation and handle cleanup both failed.',
                            [System.Exception[]]@(
                                $operationError.Exception
                                $_.Exception
                            )
                        )
                    }
                    throw
                }
            }
        }
        if ($operationError) {
            throw $operationError
        }
        $operationResult
    }

    $arguments = [System.Collections.Generic.List[object]]::new()
    $arguments.Add($Target)
    $arguments.Add($Sections)
    $arguments.Add([bool]$Write)
    $arguments.Add($ScriptBlock)
    $arguments.Add($ArgumentList)
    $operationArguments = $arguments.ToArray()

    $requiredPrivileges = [System.Collections.Generic.List[string]]::new()
    if (($Sections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0) {
        $requiredPrivileges.Add('SeSecurityPrivilege')
    }
    if ($Write -and ($Sections -band (
        [WindowsSecurityDescriptorSection]::Owner -bor
        [WindowsSecurityDescriptorSection]::Group
    )) -ne 0) {
        $privilegeNames = @(Get-WindowsPrivilege).Name
        if ('SeRestorePrivilege' -in $privilegeNames) {
            $requiredPrivileges.Add('SeRestorePrivilege')
        }
    }

    try {
        if ($requiredPrivileges.Count -gt 0) {
            $privilegeParameters = @{
                Name         = $requiredPrivileges.ToArray()
                ScriptBlock  = $operation
                ArgumentList = $operationArguments
            }
            return Invoke-WithWindowsPrivilege @privilegeParameters
        }
        return & $operation @operationArguments
    } catch {
        $operationError = $_
        if ($Target.DescriptorSource -eq 'Handle' -or
            -not (Test-WindowsAccessDeniedError -ErrorRecord $operationError)) {
            throw
        }
        $privilegeNames = @(Get-WindowsPrivilege).Name
        if ('SeDebugPrivilege' -notin $privilegeNames) {
            throw
        }
        if (-not $requiredPrivileges.Contains('SeDebugPrivilege')) {
            $requiredPrivileges.Add('SeDebugPrivilege')
        }
        $privilegeParameters = @{
            Name         = $requiredPrivileges.ToArray()
            ScriptBlock  = $operation
            ArgumentList = $operationArguments
        }
        Invoke-WithWindowsPrivilege @privilegeParameters
    }
}
