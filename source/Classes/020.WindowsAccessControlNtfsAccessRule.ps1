<#
    .SYNOPSIS
        Ensures one exact explicit NTFS access rule is present or absent.

    .DESCRIPTION
        The composite key identifies exactly one explicit access control entry
        by path, account, rights, qualifier, and inheritance scope. Absent
        removes every duplicate of that exact entry without purging unrelated
        rights or the opposite qualifier. For an allow rule the comparison
        includes the Synchronize bit that .NET adds when it materializes the
        entry. Windows can merge entries that share account, qualifier, and
        scope, so a narrower exact rule cannot coexist with a broader superset
        entry and will stay noncompliant; model the superset explicitly or
        manage the whole list with WindowsAccessControlNtfsSecurityDescriptor.

    .PARAMETER Path
        The file or directory the rule applies to.

    .PARAMETER Account
        The principal the rule applies to. An alias is normalized by security
        identifier, so any spelling that resolves to the same principal matches.

    .PARAMETER AccessRights
        The exact file system rights the entry grants or denies.

    .PARAMETER AccessControlType
        Whether the entry is an allow or a deny entry.

    .PARAMETER AppliesTo
        The inheritance scope of the entry, expressed the way the Windows
        security editor expresses it.

    .PARAMETER Ensure
        Whether the exact entry must be present or absent. Defaults to Present.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlNtfsAccessRule {
    [DscProperty(Key)] [string]$Path
    [DscProperty(Key)] [string]$Account
    [DscProperty(Key)] [System.Security.AccessControl.FileSystemRights]$AccessRights
    [DscProperty(Key)] [System.Security.AccessControl.AccessControlType]$AccessControlType
    [DscProperty(Key)]
    [ValidateSet(
        'ThisFolderOnly',
        'ThisFolderSubfoldersAndFiles',
        'ThisFolderAndSubfolders',
        'ThisFolderAndFiles',
        'SubfoldersAndFilesOnly',
        'SubfoldersOnly',
        'FilesOnly',
        'ThisFolderSubfoldersAndFilesOneLevel',
        'ThisFolderAndSubfoldersOneLevel',
        'ThisFolderAndFilesOneLevel',
        'SubfoldersAndFilesOnlyOneLevel',
        'SubfoldersOnlyOneLevel',
        'FilesOnlyOneLevel'
    )]
    [string]$AppliesTo
    [DscProperty()] [WindowsAccessControlDscEnsure]$Ensure =
        [WindowsAccessControlDscEnsure]::Present
    [DscProperty(NotConfigurable)] [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlNtfsAccessRule] Get() {
        $present = Get-WindowsAccessControlDscAccessRule `
            -ObjectFamily FileSystem -Target $this.Path -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -AppliesTo $this.AppliesTo `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlNtfsAccessRule]::new()
        $currentState.Path = $this.Path
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
            -ObjectFamily FileSystem -Target $this.Path -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -AppliesTo $this.AppliesTo `
            -Ensure $this.Ensure -ErrorAction Stop
    }
    [WindowsAccessControlDscReason[]] GetReasons([WindowsAccessControlDscEnsure]$Current) {
        if ($Current -eq $this.Ensure) { return @() }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Ensure' -f $this.GetType().Name
        $reason.Phrase = "The exact access rule on '$($this.Path)' is $Current but should be $($this.Ensure)."
        return @($reason)
    }
}
