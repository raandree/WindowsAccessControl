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

[DscResource()]
class WindowsAccessControlServiceControlManagerAccessRule {
    [DscProperty(Key)] [string]$Account
    [DscProperty(Key)] [WindowsServiceControlManagerRights]$ControlManagerRights
    [DscProperty(Key)] [System.Security.AccessControl.AccessControlType]$AccessControlType
    [DscProperty()] [WindowsAccessControlDscEnsure]$Ensure =
        [WindowsAccessControlDscEnsure]::Present
    [DscProperty(NotConfigurable)] [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlServiceControlManagerAccessRule] Get() {
        $present = Get-WindowsAccessControlDscAccessRule `
            -ObjectFamily ServiceControlManager -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.ControlManagerRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -ErrorAction Stop
        $currentState = [WindowsAccessControlServiceControlManagerAccessRule]::new()
        $currentState.Account = $this.Account
        $currentState.ControlManagerRights = $this.ControlManagerRights
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
            -ObjectFamily ServiceControlManager -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.ControlManagerRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -Ensure $this.Ensure `
            -ErrorAction Stop
    }
    [WindowsAccessControlDscReason[]] GetReasons([WindowsAccessControlDscEnsure]$Current) {
        if ($Current -eq $this.Ensure) { return @() }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Ensure' -f $this.GetType().Name
        $reason.Phrase = "The exact SCM access rule is $Current but should be $($this.Ensure)."
        return @($reason)
    }
}

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

[DscResource()]
class WindowsAccessControlSmbShareAccessRule {
    [DscProperty(Key)] [string]$Name
    [DscProperty(Key)] [string]$Account
    [DscProperty(Key)] [WindowsSmbShareRights]$AccessRights
    [DscProperty(Key)] [System.Security.AccessControl.AccessControlType]$AccessControlType
    [DscProperty()] [WindowsAccessControlDscEnsure]$Ensure =
        [WindowsAccessControlDscEnsure]::Present
    [DscProperty(NotConfigurable)] [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlSmbShareAccessRule] Get() {
        $present = Get-WindowsAccessControlDscAccessRule `
            -ObjectFamily SmbShare -Target $this.Name -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -ErrorAction Stop
        $currentState = [WindowsAccessControlSmbShareAccessRule]::new()
        $currentState.Name = $this.Name
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
            -ObjectFamily SmbShare -Target $this.Name -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType -Ensure $this.Ensure `
            -ErrorAction Stop
    }
    [WindowsAccessControlDscReason[]] GetReasons([WindowsAccessControlDscEnsure]$Current) {
        if ($Current -eq $this.Ensure) { return @() }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Ensure' -f $this.GetType().Name
        $reason.Phrase = "The exact share access rule on '$($this.Name)' is $Current but should be $($this.Ensure)."
        return @($reason)
    }
}

[DscResource()]
class WindowsAccessControlADObjectAccessRule {
    [DscProperty(Key)] [string]$DistinguishedName
    [DscProperty(Key)] [string]$Account
    [DscProperty(Key)] [WindowsActiveDirectoryRights]$AccessRights
    [DscProperty(Key)] [System.Security.AccessControl.AccessControlType]$AccessControlType
    [DscProperty(Key)] [WindowsActiveDirectoryInheritance]$InheritanceType =
        [WindowsActiveDirectoryInheritance]::None
    [DscProperty(Key)] [string]$ObjectType = ''
    [DscProperty(Key)] [string]$InheritedObjectType = ''
    [DscProperty(Mandatory)] [string]$AllowedBaseDistinguishedName
    [DscProperty()] [string]$Server
    [DscProperty()] [int]$TimeoutSeconds = 10
    [DscProperty()] [WindowsAccessControlDscEnsure]$Ensure =
        [WindowsAccessControlDscEnsure]::Present
    [DscProperty(NotConfigurable)] [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlADObjectAccessRule] Get() {
        $present = Get-WindowsAccessControlDscAccessRule `
            -ObjectFamily ADObject -Target $this.DistinguishedName `
            -Server $this.Server -TimeoutSeconds $this.TimeoutSeconds `
            -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType `
            -InheritanceType $this.InheritanceType `
            -ObjectTypeGuid $this.ParseGuid($this.ObjectType, 'ObjectType') `
            -InheritedObjectTypeGuid $this.ParseGuid(
                $this.InheritedObjectType, 'InheritedObjectType') `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlADObjectAccessRule]::new()
        $currentState.DistinguishedName = $this.DistinguishedName
        $currentState.Account = $this.Account
        $currentState.AccessRights = $this.AccessRights
        $currentState.AccessControlType = $this.AccessControlType
        $currentState.InheritanceType = $this.InheritanceType
        $currentState.ObjectType = $this.ObjectType
        $currentState.InheritedObjectType = $this.InheritedObjectType
        $currentState.AllowedBaseDistinguishedName = $this.AllowedBaseDistinguishedName
        $currentState.Server = $this.Server
        $currentState.TimeoutSeconds = $this.TimeoutSeconds
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
            -ObjectFamily ADObject -Target $this.DistinguishedName `
            -Server $this.Server `
            -AllowedBaseDistinguishedName $this.AllowedBaseDistinguishedName `
            -TimeoutSeconds $this.TimeoutSeconds -Account $this.Account `
            -AccessMask ([uint64]([int64][int]$this.AccessRights -band 0xFFFFFFFFL)) `
            -AccessControlType $this.AccessControlType `
            -InheritanceType $this.InheritanceType `
            -ObjectTypeGuid $this.ParseGuid($this.ObjectType, 'ObjectType') `
            -InheritedObjectTypeGuid $this.ParseGuid(
                $this.InheritedObjectType, 'InheritedObjectType') `
            -Ensure $this.Ensure -ErrorAction Stop
    }
    # An empty key means "no object scope"; anything else must be a real GUID so
    # a typo can never widen the managed ACE to the whole object.
    [guid] ParseGuid([string]$Value, [string]$PropertyName) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return [guid]::Empty }
        $parsed = [guid]::Empty
        if (-not [guid]::TryParse($Value, [ref]$parsed)) {
            throw "$PropertyName must be empty or a GUID."
        }
        return $parsed
    }
    [WindowsAccessControlDscReason[]] GetReasons([WindowsAccessControlDscEnsure]$Current) {
        if ($Current -eq $this.Ensure) { return @() }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Ensure' -f $this.GetType().Name
        $reason.Phrase = "The exact directory access rule on '$($this.DistinguishedName)' is $Current but should be $($this.Ensure)."
        return @($reason)
    }
}

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
