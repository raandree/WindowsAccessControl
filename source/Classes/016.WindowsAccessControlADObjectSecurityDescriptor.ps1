<#
    .SYNOPSIS
        Manages the exact DACL of an Active Directory object.

    .DESCRIPTION
        Compares the directory object's access control list against the desired
        SDDL and rewrites it. The resource takes no credential, so the Local
        Configuration Manager binds LDAP as the node's own identity and a
        compiled configuration never carries directory credentials. Every write
        is confined to AllowedBaseDistinguishedName, so a configuration states
        its own containment boundary.

    .PARAMETER DistinguishedName
        The distinguished name of the directory object whose DACL is managed.

    .PARAMETER Sections
        The security descriptor sections this resource owns. Only the access
        section is supported for a directory object.

    .PARAMETER AllowedBaseDistinguishedName
        The subtree the configuration is allowed to write under. A target
        outside it is refused before anything is written.

    .PARAMETER Sddl
        The desired DACL in SDDL form. Capture it from
        Get-ADObjectSecurityDescriptor.

    .PARAMETER Server
        The domain controller to bind over signed and sealed LDAP. When empty, a
        writable controller is discovered. Pin it when two writes must be
        serialized, because a security descriptor is one replicated attribute
        and the losing write is discarded whole.

    .PARAMETER ObjectGuid
        The immutable identity of the intended object. A distinguished name can
        be reused after a delete and recreate, so when this is set and the name
        now resolves to a different object the resource fails closed.

    .PARAMETER TimeoutSeconds
        The directory operation timeout in seconds.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlADObjectSecurityDescriptor {
    [DscProperty(Key)]
    [string]$DistinguishedName

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections =
        [WindowsSecurityDescriptorSection]::Access

    [DscProperty(Mandatory)]
    [string]$AllowedBaseDistinguishedName

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty()]
    [string]$Server

    [DscProperty()]
    [string]$ObjectGuid

    [DscProperty()]
    [int]$TimeoutSeconds = 10

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlADObjectSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily ADObject `
            -Target $this.DistinguishedName `
            -Server $this.Server `
            -TimeoutSeconds $this.TimeoutSeconds `
            -Sections $this.Sections `
            -ErrorAction Stop
        $this.AssertObjectGuid($descriptor.ObjectGuid)
        $currentState = [WindowsAccessControlADObjectSecurityDescriptor]::new()
        $currentState.DistinguishedName = $this.DistinguishedName
        $currentState.Sections = $this.Sections
        $currentState.AllowedBaseDistinguishedName = $this.AllowedBaseDistinguishedName
        $currentState.Server = $this.Server
        $currentState.ObjectGuid = [string]$descriptor.ObjectGuid
        $currentState.TimeoutSeconds = $this.TimeoutSeconds
        $currentState.Sddl = $descriptor.Sddl
        $currentState.Reasons = $this.GetReasons($descriptor.Sddl)
        return $currentState
    }

    [bool] Test() {
        return $this.Get().Reasons.Count -eq 0
    }

    [void] Set() {
        Set-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily ADObject `
            -Target $this.DistinguishedName `
            -Server $this.Server `
            -AllowedBaseDistinguishedName $this.AllowedBaseDistinguishedName `
            -ObjectGuid $this.ObjectGuid `
            -TimeoutSeconds $this.TimeoutSeconds `
            -Sections $this.Sections `
            -Sddl $this.Sddl `
            -ErrorAction Stop
    }

    # A distinguished name can be reused by a different object after a delete
    # and recreate, so an author may pin the immutable directory identity.
    [void] AssertObjectGuid([object]$ActualObjectGuid) {
        if ([string]::IsNullOrWhiteSpace($this.ObjectGuid)) {
            return
        }
        $expected = [guid]::Empty
        if (-not [guid]::TryParse($this.ObjectGuid, [ref]$expected) -or
            $expected -ne ($ActualObjectGuid -as [guid])) {
            throw "The Active Directory object '$($this.DistinguishedName)' does not have the configured object GUID."
        }
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
        $reason.Phrase = "The directory DACL for '$($this.DistinguishedName)' differs from the desired SDDL."
        return @($reason)
    }
}
