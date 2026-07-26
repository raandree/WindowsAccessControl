[DscResource()]
class WindowsAccessControlNtfsAccessRule {
    [DscProperty(Key)] [string]$Path
    [DscProperty(Key)] [string]$Account
    [DscProperty(Key)] [System.Security.AccessControl.FileSystemRights]$AccessRights
    [DscProperty(Key)] [System.Security.AccessControl.AccessControlType]$AccessControlType
    [DscProperty(Key)] [string]$AppliesTo
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
    [DscProperty(Key)] [string]$AppliesTo
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
