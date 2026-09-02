<#
    .SYNOPSIS
        Ensures one exact explicit service access rule is present or absent.

    .DESCRIPTION
        The composite key identifies exactly one explicit access control entry
        on a service by service name, account, rights, and qualifier. Absent
        removes every duplicate of that exact entry without purging unrelated
        rights or the opposite qualifier.

    .PARAMETER Name
        The service name, not the display name.

    .PARAMETER Account
        The principal the rule applies to. An alias is normalized by security
        identifier, so any spelling that resolves to the same principal matches.

    .PARAMETER ServiceRights
        The exact service rights the entry grants or denies.

    .PARAMETER AccessControlType
        Whether the entry is an allow or a deny entry.

    .PARAMETER Ensure
        Whether the exact entry must be present or absent. Defaults to Present.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlServiceAccessRule {
    [DscProperty(Key)] [string]$Name
    [DscProperty(Key)] [string]$Account
    [DscProperty(Key)] [WindowsServiceRights]$ServiceRights
    [DscProperty(Key)] [System.Security.AccessControl.AccessControlType]$AccessControlType
    [DscProperty()] [WindowsAccessControlDscEnsure]$Ensure =
        [WindowsAccessControlDscEnsure]::Present
    [DscProperty(NotConfigurable)] [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlServiceAccessRule] Get() {
        $present = Get-WindowsAccessControlDscAccessRule `
            -ObjectFamily Service -Target $this.Name -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.ServiceRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -ErrorAction Stop
        $currentState = [WindowsAccessControlServiceAccessRule]::new()
        $currentState.Name = $this.Name
        $currentState.Account = $this.Account
        $currentState.ServiceRights = $this.ServiceRights
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
            -ObjectFamily Service -Target $this.Name -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.ServiceRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -Ensure $this.Ensure `
            -ErrorAction Stop
    }
    [WindowsAccessControlDscReason[]] GetReasons([WindowsAccessControlDscEnsure]$Current) {
        if ($Current -eq $this.Ensure) { return @() }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Ensure' -f $this.GetType().Name
        $reason.Phrase = "The exact service access rule on '$($this.Name)' is $Current but should be $($this.Ensure)."
        return @($reason)
    }
}
