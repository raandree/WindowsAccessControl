<#
    .SYNOPSIS
        Manages the exact security descriptor of a file or directory.

    .DESCRIPTION
        Compares the selected sections of the NTFS security descriptor at Path
        against the desired SDDL and rewrites only those sections. Every section
        the resource does not select is left untouched. System-maintained
        AUTO_INHERITED flags are ignored during comparison, while protection
        flags and every access control entry stay exact.

    .PARAMETER Path
        The file or directory whose security descriptor is managed.

    .PARAMETER Sections
        The security descriptor sections this resource owns. Only these sections
        are compared and written.

    .PARAMETER Sddl
        The desired security descriptor for the selected sections, in SDDL form.
        Capture it from Get-NTFSItemSecurityDescriptor. Prefer a protected DACL
        so parent inheritance cannot add entries after convergence.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlNtfsSecurityDescriptor {
    [DscProperty(Key)]
    [string]$Path

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlNtfsSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily FileSystem `
            -Target $this.Path `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlNtfsSecurityDescriptor]::new()
        $currentState.Path = $this.Path
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
            -ObjectFamily FileSystem `
            -Target $this.Path `
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
        $reason.Phrase = "The selected security descriptor for '$($this.Path)' differs from the desired SDDL."
        return @($reason)
    }
}
