<#
    .SYNOPSIS
        Manages the exact security descriptor of a running process.

    .DESCRIPTION
        Compares the selected sections of the process security descriptor
        against the desired SDDL and rewrites only those sections. The target is
        pinned by process identifier and creation time, so a reused identifier
        fails closed rather than reaching a different process. Process desired
        state is ephemeral and valid only while that process instance lives.

    .PARAMETER ProcessId
        The identifier of the process whose descriptor is managed.

    .PARAMETER CreationTimeFileTime
        The creation time of the pinned process instance as a file time. It
        distinguishes the intended process from a later one that reused the
        identifier.

    .PARAMETER Sections
        The security descriptor sections this resource owns. Only these sections
        are compared and written.

    .PARAMETER Sddl
        The desired security descriptor for the selected sections, in SDDL form.
        Capture it from Get-ProcessSecurityDescriptor.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlProcessSecurityDescriptor {
    [DscProperty(Key)]
    [uint32]$ProcessId

    [DscProperty(Key)]
    [int64]$CreationTimeFileTime

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlProcessSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily Process `
            -ProcessId $this.ProcessId `
            -CreationTimeFileTime $this.CreationTimeFileTime `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlProcessSecurityDescriptor]::new()
        $currentState.ProcessId = $this.ProcessId
        $currentState.CreationTimeFileTime = $this.CreationTimeFileTime
        $currentState.Sections = $this.Sections
        $currentState.Sddl = $descriptor.Sddl
        $currentState.Reasons = $this.GetReasons($descriptor.Sddl)
        return $currentState
    }

    [bool] Test() {
        return $this.Get().Reasons.Count -eq 0
    }

    [void] Set() {
        Set-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily Process `
            -ProcessId $this.ProcessId `
            -CreationTimeFileTime $this.CreationTimeFileTime `
            -Sections $this.Sections `
            -Sddl $this.Sddl `
            -ErrorAction Stop
    }

    [WindowsAccessControlDscReason[]] GetReasons([string]$CurrentSddl) {
        if (Test-WindowsAccessControlDscSddl `
                -CurrentSddl $CurrentSddl `
                -DesiredSddl $this.Sddl `
                -Sections $this.Sections) {
            return @()
        }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Sddl' -f $this.GetType().Name
        $reason.Phrase = "The selected descriptor for process $($this.ProcessId) differs from the desired SDDL."
        return @($reason)
    }
}
