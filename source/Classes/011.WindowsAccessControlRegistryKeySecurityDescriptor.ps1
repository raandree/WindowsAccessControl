<#
    .SYNOPSIS
        Manages the exact security descriptor of a registry key.

    .DESCRIPTION
        Compares the selected sections of the registry key security descriptor
        against the desired SDDL and rewrites only those sections. The registry
        view is part of the resource identity, so the 32-bit and 64-bit views of
        the same path are two separate targets.

    .PARAMETER Path
        The registry key whose security descriptor is managed.

    .PARAMETER RegistryView
        The registry view the key is opened in. It is part of the key identity.

    .PARAMETER Sections
        The security descriptor sections this resource owns. Only these sections
        are compared and written.

    .PARAMETER Sddl
        The desired security descriptor for the selected sections, in SDDL form.
        Capture it from Get-RegistryKeySecurityDescriptor.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlRegistryKeySecurityDescriptor {
    [DscProperty(Key)]
    [string]$Path

    [DscProperty(Key)]
    [WindowsRegistryView]$RegistryView

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlRegistryKeySecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily RegistryKey `
            -Target $this.Path `
            -RegistryView $this.RegistryView `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlRegistryKeySecurityDescriptor]::new()
        $currentState.Path = $this.Path
        $currentState.RegistryView = $this.RegistryView
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
            -ObjectFamily RegistryKey `
            -Target $this.Path `
            -RegistryView $this.RegistryView `
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
        $reason.Phrase = "The selected registry descriptor for '$($this.Path)' differs from the desired SDDL."
        return @($reason)
    }
}
