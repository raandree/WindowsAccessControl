function Resolve-WindowsProcessTarget {
    [CmdletBinding(DefaultParameterSetName = 'Process')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Process')]
        [ValidateNotNull()]
        [object]$InputObject,

        [Parameter(Mandatory, ParameterSetName = 'Handle')]
        [IntPtr]$Handle
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Handle') {
            if ($Handle -eq [IntPtr]::Zero -or $Handle -eq [IntPtr](-1)) {
                throw [System.ArgumentException]::new(
                    'A valid caller-owned process handle is required.'
                )
            }
            return [pscustomobject]@{
                ObjectType           = 'Process'
                Path                 = 'Handle:0x{0:X}' -f $Handle.ToInt64()
                ProcessId            = $null
                ProcessName          = $null
                CreationTime         = $null
                CreationTimeFileTime = $null
                Handle               = $Handle
                DescriptorSource     = 'Handle'
                CanonicalTarget      = 'ProcessHandle:0x{0:X}' -f $Handle.ToInt64()
            }
        }

        if ($InputObject -is [System.Diagnostics.Process]) {
            if ($InputObject.HasExited) {
                throw [System.InvalidOperationException]::new(
                    "Process $($InputObject.Id) has exited."
                )
            }
            $processId = $InputObject.Id
            $processName = $InputObject.ProcessName
            $creationTime = $InputObject.StartTime.ToUniversalTime()
            $creationTimeFileTime = $InputObject.StartTime.ToFileTimeUtc()
        } elseif ($InputObject.PSObject.Properties['ObjectType'] -and
            [string]$InputObject.ObjectType -eq 'Process') {
            if ($InputObject.PSObject.Properties['Handle'] -and
                [IntPtr]$InputObject.Handle -ne [IntPtr]::Zero) {
                return Resolve-WindowsProcessTarget -Handle ([IntPtr]$InputObject.Handle)
            }
            $processId = [int]$InputObject.ProcessId
            $processName = [string]$InputObject.ProcessName
            $creationTime = $InputObject.CreationTime
            $creationTimeFileTime = [long]$InputObject.CreationTimeFileTime
            if ($processId -le 0 -or $creationTimeFileTime -le 0) {
                throw [System.ArgumentException]::new(
                    'Process module output requires a positive PID and creation identity.'
                )
            }
        } else {
            try {
                $processId = [int]$InputObject
            } catch {
                throw [System.ArgumentException]::new(
                    "Process target '$InputObject' is not a PID, Process object, or module output."
                )
            }
            if ($processId -le 0) {
                throw [System.ArgumentOutOfRangeException]::new('ProcessId')
            }
            $process = Get-Process -Id $processId -ErrorAction Stop
            try {
                $processName = $process.ProcessName
                $creationTime = $process.StartTime.ToUniversalTime()
                $creationTimeFileTime = $process.StartTime.ToFileTimeUtc()
            } finally {
                $process.Dispose()
            }
        }

        [pscustomobject]@{
            ObjectType           = 'Process'
            Path                 = 'PID:{0}' -f $processId
            ProcessId            = $processId
            ProcessName          = $processName
            CreationTime         = $creationTime
            CreationTimeFileTime = $creationTimeFileTime
            Handle               = [IntPtr]::Zero
            DescriptorSource     = 'ProcessId'
            CanonicalTarget      = 'Process:{0}:{1}' -f $processId, $creationTimeFileTime
        }
    }
}
