<#
    .SYNOPSIS
        Manages the exact security descriptor of a Windows service.

    .DESCRIPTION
        Compares the selected sections of the service security descriptor
        against the desired SDDL and rewrites only those sections. The service
        is addressed by its service name on the local node.

    .PARAMETER Name
        The service name, not the display name.

    .PARAMETER Sections
        The security descriptor sections this resource owns. Only these sections
        are compared and written.

    .PARAMETER Sddl
        The desired security descriptor for the selected sections, in SDDL form.
        Capture it from Get-ServiceSecurityDescriptor.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlServiceSecurityDescriptor {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlServiceSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily Service `
            -Target $this.Name `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlServiceSecurityDescriptor]::new()
        $currentState.Name = $this.Name
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
            -ObjectFamily Service `
            -Target $this.Name `
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
        $reason.Phrase = "The selected service descriptor for '$($this.Name)' differs from the desired SDDL."
        return @($reason)
    }
}
