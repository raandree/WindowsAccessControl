[DscResource()]
class WindowsAccessControlNtfsSecurityDescriptor {
    [DscProperty(Key)]
    [string]$Path

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlNtfsSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily FileSystem `
            -Target $this.Path `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlNtfsSecurityDescriptor]::new()
        $currentState.Path = $this.Path
        $currentState.Sections = $this.Sections
        $currentState.Sddl = $descriptor.Sddl
        $currentState.Reasons = $this.GetReasons($descriptor.Sddl)
        return $currentState
    }

    [bool] Test() {
        return $this.Get().Reasons.Count -eq 0
    }

    [void] Set() {
        Set-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily FileSystem `
            -Target $this.Path `
            -Sections $this.Sections `
            -Sddl $this.Sddl `
            -ErrorAction Stop
    }

    [WindowsAccessControlDscReason[]] GetReasons([string]$CurrentSddl) {
        if (Test-WindowsAccessControlDscSddl `
                -CurrentSddl $CurrentSddl `
                -DesiredSddl $this.Sddl `
                -Sections $this.Sections) {
            return @()
        }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Sddl' -f $this.GetType().Name
        $reason.Phrase = "The selected security descriptor for '$($this.Path)' differs from the desired SDDL."
        return @($reason)
    }
}

[DscResource()]
class WindowsAccessControlRegistryKeySecurityDescriptor {
    [DscProperty(Key)]
    [string]$Path

    [DscProperty(Key)]
    [WindowsRegistryView]$RegistryView

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlRegistryKeySecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily RegistryKey `
            -Target $this.Path `
            -RegistryView $this.RegistryView `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlRegistryKeySecurityDescriptor]::new()
        $currentState.Path = $this.Path
        $currentState.RegistryView = $this.RegistryView
        $currentState.Sections = $this.Sections
        $currentState.Sddl = $descriptor.Sddl
        $currentState.Reasons = $this.GetReasons($descriptor.Sddl)
        return $currentState
    }

    [bool] Test() {
        return $this.Get().Reasons.Count -eq 0
    }

    [void] Set() {
        Set-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily RegistryKey `
            -Target $this.Path `
            -RegistryView $this.RegistryView `
            -Sections $this.Sections `
            -Sddl $this.Sddl `
            -ErrorAction Stop
    }

    [WindowsAccessControlDscReason[]] GetReasons([string]$CurrentSddl) {
        if (Test-WindowsAccessControlDscSddl `
                -CurrentSddl $CurrentSddl `
                -DesiredSddl $this.Sddl `
                -Sections $this.Sections) {
            return @()
        }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Sddl' -f $this.GetType().Name
        $reason.Phrase = "The selected registry descriptor for '$($this.Path)' differs from the desired SDDL."
        return @($reason)
    }
}

[DscResource()]
class WindowsAccessControlServiceSecurityDescriptor {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlServiceSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily Service `
            -Target $this.Name `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlServiceSecurityDescriptor]::new()
        $currentState.Name = $this.Name
        $currentState.Sections = $this.Sections
        $currentState.Sddl = $descriptor.Sddl
        $currentState.Reasons = $this.GetReasons($descriptor.Sddl)
        return $currentState
    }

    [bool] Test() {
        return $this.Get().Reasons.Count -eq 0
    }

    [void] Set() {
        Set-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily Service `
            -Target $this.Name `
            -Sections $this.Sections `
            -Sddl $this.Sddl `
            -ErrorAction Stop
    }

    [WindowsAccessControlDscReason[]] GetReasons([string]$CurrentSddl) {
        if (Test-WindowsAccessControlDscSddl `
                -CurrentSddl $CurrentSddl `
                -DesiredSddl $this.Sddl `
                -Sections $this.Sections) {
            return @()
        }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Sddl' -f $this.GetType().Name
        $reason.Phrase = "The selected service descriptor for '$($this.Name)' differs from the desired SDDL."
        return @($reason)
    }
}

[DscResource()]
class WindowsAccessControlServiceControlManagerSecurityDescriptor {
    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlServiceControlManagerSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily ServiceControlManager `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlServiceControlManagerSecurityDescriptor]::new()
        $currentState.Sections = $this.Sections
        $currentState.Sddl = $descriptor.Sddl
        $currentState.Reasons = $this.GetReasons($descriptor.Sddl)
        return $currentState
    }

    [bool] Test() {
        return $this.Get().Reasons.Count -eq 0
    }

    [void] Set() {
        Set-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily ServiceControlManager `
            -Sections $this.Sections `
            -Sddl $this.Sddl `
            -ErrorAction Stop
    }

    [WindowsAccessControlDscReason[]] GetReasons([string]$CurrentSddl) {
        if (Test-WindowsAccessControlDscSddl `
                -CurrentSddl $CurrentSddl `
                -DesiredSddl $this.Sddl `
                -Sections $this.Sections) {
            return @()
        }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Sddl' -f $this.GetType().Name
        $reason.Phrase = 'The selected Service Control Manager descriptor differs from the desired SDDL.'
        return @($reason)
    }
}

[DscResource()]
class WindowsAccessControlProcessSecurityDescriptor {
    [DscProperty(Key)]
    [uint32]$ProcessId

    [DscProperty(Key)]
    [int64]$CreationTimeFileTime

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlProcessSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily Process `
            -ProcessId $this.ProcessId `
            -CreationTimeFileTime $this.CreationTimeFileTime `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlProcessSecurityDescriptor]::new()
        $currentState.ProcessId = $this.ProcessId
        $currentState.CreationTimeFileTime = $this.CreationTimeFileTime
        $currentState.Sections = $this.Sections
        $currentState.Sddl = $descriptor.Sddl
        $currentState.Reasons = $this.GetReasons($descriptor.Sddl)
        return $currentState
    }

    [bool] Test() {
        return $this.Get().Reasons.Count -eq 0
    }

    [void] Set() {
        Set-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily Process `
            -ProcessId $this.ProcessId `
            -CreationTimeFileTime $this.CreationTimeFileTime `
            -Sections $this.Sections `
            -Sddl $this.Sddl `
            -ErrorAction Stop
    }

    [WindowsAccessControlDscReason[]] GetReasons([string]$CurrentSddl) {
        if (Test-WindowsAccessControlDscSddl `
                -CurrentSddl $CurrentSddl `
                -DesiredSddl $this.Sddl `
                -Sections $this.Sections) {
            return @()
        }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Sddl' -f $this.GetType().Name
        $reason.Phrase = "The selected descriptor for process $($this.ProcessId) differs from the desired SDDL."
        return @($reason)
    }
}
