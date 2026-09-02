<#
    .SYNOPSIS
        Manages the exact DACL of a Task Scheduler folder.

    .DESCRIPTION
        Compares the task folder's access control list against the desired SDDL
        and rewrites it. Access control entry order is ignored during
        comparison because the Task Scheduler service canonicalizes it after a
        write, so this resource cannot detect a reordering that moves an allow
        entry ahead of a deny entry. Do not make it the sole drift control for
        an order-sensitive deny entry.

    .PARAMETER Path
        The task folder whose DACL is managed.

    .PARAMETER Sections
        The security descriptor sections this resource owns. Only the access
        section is supported for a task folder.

    .PARAMETER AllowedRootPath
        The task folder subtree the configuration is allowed to write under. A
        target outside it is refused before anything is written.

    .PARAMETER Sddl
        The desired DACL in SDDL form. Capture it from
        Get-TaskFolderSecurityDescriptor.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlTaskFolderSecurityDescriptor {
    [DscProperty(Key)]
    [string]$Path

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections =
        [WindowsSecurityDescriptorSection]::Access

    [DscProperty(Mandatory)]
    [string]$AllowedRootPath

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlTaskFolderSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily TaskFolder `
            -Target $this.Path `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlTaskFolderSecurityDescriptor]::new()
        $currentState.Path = $this.Path
        $currentState.Sections = $this.Sections
        $currentState.AllowedRootPath = $this.AllowedRootPath
        $currentState.Sddl = $descriptor.Sddl
        $currentState.Reasons = $this.GetReasons($descriptor.Sddl)
        return $currentState
    }

    [bool] Test() {
        return $this.Get().Reasons.Count -eq 0
    }

    [void] Set() {
        Set-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily TaskFolder `
            -Target $this.Path `
            -AllowedRootPath $this.AllowedRootPath `
            -Sections $this.Sections `
            -Sddl $this.Sddl `
            -ErrorAction Stop
    }

    [WindowsAccessControlDscReason[]] GetReasons([string]$CurrentSddl) {
        if (Test-WindowsTaskSchedulerDscSddl `
                -CurrentSddl $CurrentSddl `
                -DesiredSddl $this.Sddl) {
            return @()
        }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Sddl' -f $this.GetType().Name
        $reason.Phrase = "The task-folder DACL for '$($this.Path)' differs from the desired SDDL."
        return @($reason)
    }
}
