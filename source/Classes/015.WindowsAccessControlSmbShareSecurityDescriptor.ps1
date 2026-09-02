<#
    .SYNOPSIS
        Manages the exact share DACL of a local SMB share.

    .DESCRIPTION
        Compares the share access control list against the desired SDDL and
        rewrites it. This resource manages the access section only; the file
        system permissions behind the share are a separate target managed by
        WindowsAccessControlNtfsSecurityDescriptor.

    .PARAMETER Name
        The name of the local share whose DACL is managed.

    .PARAMETER Sections
        The security descriptor sections this resource owns. Only the access
        section is supported for a share.

    .PARAMETER Sddl
        The desired share DACL in SDDL form. Capture it from
        Get-SmbShareSecurityDescriptor.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlSmbShareSecurityDescriptor {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections =
        [WindowsSecurityDescriptorSection]::Access

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlSmbShareSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily SmbShare `
            -Target $this.Name `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlSmbShareSecurityDescriptor]::new()
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
            -ObjectFamily SmbShare `
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
        $reason.Phrase = "The share DACL for '$($this.Name)' differs from the desired SDDL."
        return @($reason)
    }
}
