<#
    .SYNOPSIS
        Ensures one exact explicit registered task access rule is present or
        absent.

    .DESCRIPTION
        The composite key identifies exactly one explicit access control entry on
        a registered scheduled task by folder, task name, account, rights, and
        qualifier. Every write is confined to AllowedRootPath.

    .PARAMETER TaskPath
        The task folder that contains the registered task.

    .PARAMETER TaskName
        The name of the registered task the rule applies to.

    .PARAMETER Account
        The principal the rule applies to. An alias is normalized by security
        identifier, so any spelling that resolves to the same principal matches.

    .PARAMETER AccessRights
        The exact scheduled task rights the entry grants or denies.

    .PARAMETER AccessControlType
        Whether the entry is an allow or a deny entry.

    .PARAMETER AllowedRootPath
        The task folder subtree the configuration is allowed to write under. A
        target outside it is refused before anything is written.

    .PARAMETER Ensure
        Whether the exact entry must be present or absent. Defaults to Present.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlScheduledTaskAccessRule {
    [DscProperty(Key)] [string]$TaskPath
    [DscProperty(Key)] [string]$TaskName
    [DscProperty(Key)] [string]$Account
    [DscProperty(Key)] [WindowsScheduledTaskRights]$AccessRights
    [DscProperty(Key)] [System.Security.AccessControl.AccessControlType]$AccessControlType
    [DscProperty(Mandatory)] [string]$AllowedRootPath
    [DscProperty()] [WindowsAccessControlDscEnsure]$Ensure =
        [WindowsAccessControlDscEnsure]::Present
    [DscProperty(NotConfigurable)] [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlScheduledTaskAccessRule] Get() {
        $present = Get-WindowsAccessControlDscAccessRule `
            -ObjectFamily ScheduledTask -Target $this.TaskPath `
            -TaskName $this.TaskName -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -ErrorAction Stop
        $currentState = [WindowsAccessControlScheduledTaskAccessRule]::new()
        $currentState.TaskPath = $this.TaskPath
        $currentState.TaskName = $this.TaskName
        $currentState.Account = $this.Account
        $currentState.AccessRights = $this.AccessRights
        $currentState.AccessControlType = $this.AccessControlType
        $currentState.AllowedRootPath = $this.AllowedRootPath
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
            -ObjectFamily ScheduledTask -Target $this.TaskPath `
            -TaskName $this.TaskName -AllowedRootPath $this.AllowedRootPath `
            -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -Ensure $this.Ensure `
            -ErrorAction Stop
    }
    [WindowsAccessControlDscReason[]] GetReasons([WindowsAccessControlDscEnsure]$Current) {
        if ($Current -eq $this.Ensure) { return @() }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Ensure' -f $this.GetType().Name
        $reason.Phrase = "The exact registered-task access rule on '$($this.TaskPath)\$($this.TaskName)' is $Current but should be $($this.Ensure)."
        return @($reason)
    }
}
