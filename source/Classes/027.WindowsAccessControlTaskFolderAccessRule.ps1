<#
    .SYNOPSIS
        Ensures one exact explicit task folder access rule is present or absent.

    .DESCRIPTION
        The composite key identifies exactly one explicit access control entry on
        a Task Scheduler folder by path, account, rights, qualifier, and
        inheritance scope. Every write is confined to AllowedRootPath.

    .PARAMETER Path
        The task folder the rule applies to.

    .PARAMETER Account
        The principal the rule applies to. An alias is normalized by security
        identifier, so any spelling that resolves to the same principal matches.

    .PARAMETER AccessRights
        The exact task folder rights the entry grants or denies.

    .PARAMETER AccessControlType
        Whether the entry is an allow or a deny entry.

    .PARAMETER AppliesTo
        The inheritance scope of the entry across the folder, its subfolders, and
        the tasks in them.

    .PARAMETER AllowedRootPath
        The task folder subtree the configuration is allowed to write under. A
        target outside it is refused before anything is written.

    .PARAMETER Ensure
        Whether the exact entry must be present or absent. Defaults to Present.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlTaskFolderAccessRule {
    [DscProperty(Key)] [string]$Path
    [DscProperty(Key)] [string]$Account
    [DscProperty(Key)] [WindowsTaskFolderRights]$AccessRights
    [DscProperty(Key)] [System.Security.AccessControl.AccessControlType]$AccessControlType
    [DscProperty(Key)]
    [ValidateSet(
        'ThisFolderOnly',
        'ThisFolderSubfoldersAndTasks',
        'ThisFolderAndSubfolders',
        'ThisFolderAndTasks',
        'SubfoldersAndTasksOnly',
        'SubfoldersOnly',
        'TasksOnly'
    )]
    [string]$AppliesTo
    [DscProperty(Mandatory)] [string]$AllowedRootPath
    [DscProperty()] [WindowsAccessControlDscEnsure]$Ensure =
        [WindowsAccessControlDscEnsure]::Present
    [DscProperty(NotConfigurable)] [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlTaskFolderAccessRule] Get() {
        $present = Get-WindowsAccessControlDscAccessRule `
            -ObjectFamily TaskFolder -Target $this.Path -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -AppliesTo $this.AppliesTo `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlTaskFolderAccessRule]::new()
        $currentState.Path = $this.Path
        $currentState.Account = $this.Account
        $currentState.AccessRights = $this.AccessRights
        $currentState.AccessControlType = $this.AccessControlType
        $currentState.AppliesTo = $this.AppliesTo
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
            -ObjectFamily TaskFolder -Target $this.Path `
            -AllowedRootPath $this.AllowedRootPath -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -AppliesTo $this.AppliesTo `
            -Ensure $this.Ensure -ErrorAction Stop
    }
    [WindowsAccessControlDscReason[]] GetReasons([WindowsAccessControlDscEnsure]$Current) {
        if ($Current -eq $this.Ensure) { return @() }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Ensure' -f $this.GetType().Name
        $reason.Phrase = "The exact task-folder access rule on '$($this.Path)' is $Current but should be $($this.Ensure)."
        return @($reason)
    }
}
