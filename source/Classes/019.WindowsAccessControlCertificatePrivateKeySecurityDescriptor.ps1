<#
    .SYNOPSIS
        Manages the exact DACL of a persisted CNG certificate private key.

    .DESCRIPTION
        Compares the private key's access control list against the desired SDDL
        and rewrites it. The key is addressed by provider, key name, and scope
        rather than by certificate thumbprint, because a renewal that reuses the
        key changes the thumbprint. Private key material is never exported or
        serialized.

    .PARAMETER ProviderName
        The exact expected CNG provider. This increment accepts only Microsoft
        Software Key Storage Provider.

    .PARAMETER KeyName
        The exact persisted CNG key name whose DACL is managed.

    .PARAMETER KeyScope
        Selects the machine or current-user key store.

    .PARAMETER Sections
        The security descriptor sections this resource owns. Only the access
        section is supported for a private key.

    .PARAMETER Sddl
        The desired DACL in SDDL form. Capture it from
        Get-CertificatePrivateKeySecurityDescriptor.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlCertificatePrivateKeySecurityDescriptor {
    [DscProperty(Key)]
    [string]$ProviderName

    [DscProperty(Key)]
    [string]$KeyName

    [DscProperty(Key)]
    [ValidateSet('Machine', 'User')]
    [string]$KeyScope

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections =
        [WindowsSecurityDescriptorSection]::Access

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlCertificatePrivateKeySecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily CertificatePrivateKey `
            -Target $this.KeyName `
            -ProviderName $this.ProviderName `
            -KeyScope $this.KeyScope `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlCertificatePrivateKeySecurityDescriptor]::new()
        $currentState.ProviderName = $this.ProviderName
        $currentState.KeyName = $this.KeyName
        $currentState.KeyScope = $this.KeyScope
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
            -ObjectFamily CertificatePrivateKey `
            -Target $this.KeyName `
            -ProviderName $this.ProviderName `
            -KeyScope $this.KeyScope `
            -Sections $this.Sections `
            -Sddl $this.Sddl `
            -ErrorAction Stop
    }

    [WindowsAccessControlDscReason[]] GetReasons([string]$CurrentSddl) {
        if (Test-WindowsCngKeyDscSddl `
                -CurrentSddl $CurrentSddl `
                -DesiredSddl $this.Sddl) {
            return @()
        }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Sddl' -f $this.GetType().Name
        $reason.Phrase = "The private-key DACL for '$($this.KeyName)' differs from the desired SDDL."
        return @($reason)
    }
}
