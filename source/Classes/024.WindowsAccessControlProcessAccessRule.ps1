<#
    .SYNOPSIS
        Ensures one exact explicit process access rule is present or absent.

    .DESCRIPTION
        The composite key identifies exactly one explicit access control entry on
        a pinned process instance. The target is pinned by process identifier and
        creation time, so a reused identifier fails closed rather than reaching a
        different process. Intended for long-lived process instances; the desired
        state is valid only while that instance lives.

    .PARAMETER ProcessId
        The identifier of the process the rule applies to.

    .PARAMETER CreationTimeFileTime
        The creation time of the pinned process instance as a file time. It
        distinguishes the intended process from a later one that reused the
        identifier.

    .PARAMETER Account
        The principal the rule applies to. An alias is normalized by security
        identifier, so any spelling that resolves to the same principal matches.

    .PARAMETER ProcessRights
        The exact process rights the entry grants or denies.

    .PARAMETER AccessControlType
        Whether the entry is an allow or a deny entry.

    .PARAMETER Ensure
        Whether the exact entry must be present or absent. Defaults to Present.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlProcessAccessRule {
    [DscProperty(Key)] [uint32]$ProcessId
    [DscProperty(Key)] [int64]$CreationTimeFileTime
    [DscProperty(Key)] [string]$Account
    [DscProperty(Key)] [WindowsProcessRights]$ProcessRights
    [DscProperty(Key)] [System.Security.AccessControl.AccessControlType]$AccessControlType
    [DscProperty()] [WindowsAccessControlDscEnsure]$Ensure =
        [WindowsAccessControlDscEnsure]::Present
    [DscProperty(NotConfigurable)] [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlProcessAccessRule] Get() {
        $present = Get-WindowsAccessControlDscAccessRule `
            -ObjectFamily Process -ProcessId $this.ProcessId `
            -CreationTimeFileTime $this.CreationTimeFileTime -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.ProcessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -ErrorAction Stop
        $currentState = [WindowsAccessControlProcessAccessRule]::new()
        $currentState.ProcessId = $this.ProcessId
        $currentState.CreationTimeFileTime = $this.CreationTimeFileTime
        $currentState.Account = $this.Account
        $currentState.ProcessRights = $this.ProcessRights
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
            -ObjectFamily Process -ProcessId $this.ProcessId `
            -CreationTimeFileTime $this.CreationTimeFileTime -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.ProcessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -Ensure $this.Ensure `
            -ErrorAction Stop
    }
    [WindowsAccessControlDscReason[]] GetReasons([WindowsAccessControlDscEnsure]$Current) {
        if ($Current -eq $this.Ensure) { return @() }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Ensure' -f $this.GetType().Name
        $reason.Phrase = "The exact process access rule is $Current but should be $($this.Ensure)."
        return @($reason)
    }
}
