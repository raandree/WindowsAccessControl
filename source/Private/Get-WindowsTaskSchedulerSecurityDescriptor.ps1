function Get-WindowsTaskSchedulerSecurityDescriptor {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target
    )

    $result = Invoke-WindowsTaskSchedulerComOperation -Target $Target -Operation {
        param($NativeTarget)

        $sddl = [string]$NativeTarget.GetSecurityDescriptor(4)
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
        if (-not $descriptor.DiscretionaryAcl) {
            throw [InvalidOperationException]::new(
                'Task Scheduler returned a null DACL.'
            )
        }
        $bytes = [byte[]]::new($descriptor.BinaryLength)
        $descriptor.GetBinaryForm($bytes, 0)
        [pscustomobject]@{ Bytes = $bytes }
    }
    Write-Output -InputObject ([byte[]]$result.Bytes) -NoEnumerate
}