<#
    .SYNOPSIS
        Manages the exact DACL of a registered scheduled task.

    .DESCRIPTION
        Compares the registered task's access control list against the desired
        SDDL and rewrites it. Access control entry order is ignored during
        comparison because the Task Scheduler service canonicalizes it after a
        write, so this resource cannot detect a reordering that moves an allow
        entry ahead of a deny entry.

    .PARAMETER TaskPath
        The task folder that contains the registered task.

    .PARAMETER TaskName
        The name of the registered task whose DACL is managed.

    .PARAMETER Sections
        The security descriptor sections this resource owns. Only the access
        section is supported for a registered task.

    .PARAMETER AllowedRootPath
        The task folder subtree the configuration is allowed to write under. A
        target outside it is refused before anything is written.

    .PARAMETER Sddl
        The desired DACL in SDDL form. Capture it from
        Get-ScheduledTaskSecurityDescriptor.

    .PARAMETER Reasons
        Returns why the resource is not in the desired state. Not configurable.
#>
[DscResource()]
class WindowsAccessControlScheduledTaskSecurityDescriptor {
    [DscProperty(Key)]
    [string]$TaskPath

    [DscProperty(Key)]
    [string]$TaskName

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections =
        [WindowsSecurityDescriptorSection]::Access

    [DscProperty(Mandatory)]
    [string]$AllowedRootPath

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlScheduledTaskSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily ScheduledTask `
            -Target $this.TaskPath `
            -TaskName $this.TaskName `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlScheduledTaskSecurityDescriptor]::new()
        $currentState.TaskPath = $this.TaskPath
        $currentState.TaskName = $this.TaskName
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
            -ObjectFamily ScheduledTask `
            -Target $this.TaskPath `
            -TaskName $this.TaskName `
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
        $reason.Phrase = "The registered-task DACL for '$($this.TaskPath)\$($this.TaskName)' differs from the desired SDDL."
        return @($reason)
    }
}
