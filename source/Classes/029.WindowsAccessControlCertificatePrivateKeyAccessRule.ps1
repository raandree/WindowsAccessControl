<#
    .SYNOPSIS
        Ensures one exact explicit private key access rule is present or absent.

    .DESCRIPTION
        The composite key identifies exactly one explicit access control entry on
        a persisted CNG certificate private key. The key is addressed by
        provider, key name, and scope rather than by certificate thumbprint,
        because a renewal that reuses the key changes the thumbprint. Private key
        material is never exported or serialized.

    .PARAMETER ProviderName
        The exact expected CNG provider. This increment accepts only Microsoft
        Software Key Storage Provider.

    .PARAMETER KeyName
        The exact persisted CNG key name the rule applies to.

    .PARAMETER KeyScope
        Selects the machine or current-user key store.

    .PARAMETER Account
        The principal the rule applies to. An alias is normalized by security
        identifier, so any spelling that resolves to the same principal matches.

    .PARAMETER AccessRights
        The exact crypto key rights the entry grants or denies.

    .PARAMETER AccessControlType
        Whether the entry is an allow or a deny entry.

    .PARAMETER Ensure
        Whether the exact entry must be present or absent. Defaults to Present.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlCertificatePrivateKeyAccessRule {
    [DscProperty(Key)] [string]$ProviderName
    [DscProperty(Key)] [string]$KeyName
    [DscProperty(Key)]
    [ValidateSet('Machine', 'User')]
    [string]$KeyScope
    [DscProperty(Key)] [string]$Account
    [DscProperty(Key)] [WindowsCryptoKeyRights]$AccessRights
    [DscProperty(Key)] [System.Security.AccessControl.AccessControlType]$AccessControlType
    [DscProperty()] [WindowsAccessControlDscEnsure]$Ensure =
        [WindowsAccessControlDscEnsure]::Present
    [DscProperty(NotConfigurable)] [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlCertificatePrivateKeyAccessRule] Get() {
        $present = Get-WindowsAccessControlDscAccessRule `
            -ObjectFamily CertificatePrivateKey -Target $this.KeyName `
            -ProviderName $this.ProviderName -KeyScope $this.KeyScope `
            -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -ErrorAction Stop
        $currentState = [WindowsAccessControlCertificatePrivateKeyAccessRule]::new()
        $currentState.ProviderName = $this.ProviderName
        $currentState.KeyName = $this.KeyName
        $currentState.KeyScope = $this.KeyScope
        $currentState.Account = $this.Account
        $currentState.AccessRights = $this.AccessRights
        $currentState.AccessControlType = $this.AccessControlType
        $currentState.Ensure = if ($present) {
            [WindowsAccessControlDscEnsure]::Present
        } else {
            [WindowsAccessControlDscEnsure]::Absent
        }
        $currentState.Reasons = $this.GetReasons($currentState.Ensure)
        return $currentState
    }

    [bool] Test() { return $this.Get().Reasons.Count -eq 0 }
    [void] Set() {
        Set-WindowsAccessControlDscAccessRule `
            -ObjectFamily CertificatePrivateKey -Target $this.KeyName `
            -ProviderName $this.ProviderName -KeyScope $this.KeyScope `
            -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -Ensure $this.Ensure `
            -ErrorAction Stop
    }
    [WindowsAccessControlDscReason[]] GetReasons([WindowsAccessControlDscEnsure]$Current) {
        if ($Current -eq $this.Ensure) { return @() }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Ensure' -f $this.GetType().Name
        $reason.Phrase = "The exact private-key access rule on '$($this.KeyName)' is $Current but should be $($this.Ensure)."
        return @($reason)
    }
}
