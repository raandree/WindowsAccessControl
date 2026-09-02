<#
    .SYNOPSIS
        Manages the exact security descriptor of the Service Control Manager.

    .DESCRIPTION
        Compares the selected sections of the Service Control Manager security
        descriptor against the desired SDDL and rewrites only those sections.
        The Service Control Manager is a single node-wide object, so declare at
        most one instance of this resource per node.

    .PARAMETER Sections
        The security descriptor sections this resource owns. Only these sections
        are compared and written.

    .PARAMETER Sddl
        The desired security descriptor for the selected sections, in SDDL form.
        Capture it from Get-ServiceSecurityDescriptor -ServiceControlManager.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlServiceControlManagerSecurityDescriptor {
    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlServiceControlManagerSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily ServiceControlManager `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlServiceControlManagerSecurityDescriptor]::new()
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
            -ObjectFamily ServiceControlManager `
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
        $reason.Phrase = 'The selected Service Control Manager descriptor differs from the desired SDDL.'
        return @($reason)
    }
}
