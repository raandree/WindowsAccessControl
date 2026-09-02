<#
    .SYNOPSIS
        Ensures one exact explicit registry key access rule is present or absent.

    .DESCRIPTION
        The composite key identifies exactly one explicit access control entry
        by key path, registry view, account, rights, qualifier, and inheritance
        scope. Absent removes every duplicate of that exact entry without
        purging unrelated rights or the opposite qualifier.

    .PARAMETER Path
        The registry key the rule applies to.

    .PARAMETER RegistryView
        The registry view the key is opened in. It is part of the key identity.

    .PARAMETER Account
        The principal the rule applies to. An alias is normalized by security
        identifier, so any spelling that resolves to the same principal matches.

    .PARAMETER AccessRights
        The exact registry rights the entry grants or denies.

    .PARAMETER AccessControlType
        Whether the entry is an allow or a deny entry.

    .PARAMETER AppliesTo
        The inheritance scope of the entry across the key and its subkeys.

    .PARAMETER Ensure
        Whether the exact entry must be present or absent. Defaults to Present.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlRegistryKeyAccessRule {
    [DscProperty(Key)] [string]$Path
    [DscProperty(Key)] [WindowsRegistryView]$RegistryView
    [DscProperty(Key)] [string]$Account
    [DscProperty(Key)] [System.Security.AccessControl.RegistryRights]$AccessRights
    [DscProperty(Key)] [System.Security.AccessControl.AccessControlType]$AccessControlType
    [DscProperty(Key)]
    [ValidateSet(
        'ThisKeyOnly',
        'ThisKeyAndSubkeys',
        'SubkeysOnly',
        'ThisKeyAndSubkeysOneLevel',
        'SubkeysOnlyOneLevel'
    )]
    [string]$AppliesTo
    [DscProperty()] [WindowsAccessControlDscEnsure]$Ensure =
        [WindowsAccessControlDscEnsure]::Present
    [DscProperty(NotConfigurable)] [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlRegistryKeyAccessRule] Get() {
        $present = Get-WindowsAccessControlDscAccessRule `
            -ObjectFamily RegistryKey -Target $this.Path `
            -RegistryView $this.RegistryView -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -AppliesTo $this.AppliesTo `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlRegistryKeyAccessRule]::new()
        $currentState.Path = $this.Path
        $currentState.RegistryView = $this.RegistryView
        $currentState.Account = $this.Account
        $currentState.AccessRights = $this.AccessRights
        $currentState.AccessControlType = $this.AccessControlType
        $currentState.AppliesTo = $this.AppliesTo
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
            -ObjectFamily RegistryKey -Target $this.Path `
            -RegistryView $this.RegistryView -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -AppliesTo $this.AppliesTo `
            -Ensure $this.Ensure -ErrorAction Stop
    }
    [WindowsAccessControlDscReason[]] GetReasons([WindowsAccessControlDscEnsure]$Current) {
        if ($Current -eq $this.Ensure) { return @() }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Ensure' -f $this.GetType().Name
        $reason.Phrase = "The exact registry access rule on '$($this.Path)' is $Current but should be $($this.Ensure)."
        return @($reason)
    }
}
