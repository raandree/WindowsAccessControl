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

[DscResource()]
class WindowsAccessControlSmbShareSecurityDescriptor {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections =
        [WindowsSecurityDescriptorSection]::Access

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlSmbShareSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily SmbShare `
            -Target $this.Name `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlSmbShareSecurityDescriptor]::new()
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
            -ObjectFamily SmbShare `
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
        $reason.Phrase = "The share DACL for '$($this.Name)' differs from the desired SDDL."
        return @($reason)
    }
}

[DscResource()]
class WindowsAccessControlADObjectSecurityDescriptor {
    [DscProperty(Key)]
    [string]$DistinguishedName

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections =
        [WindowsSecurityDescriptorSection]::Access

    [DscProperty(Mandatory)]
    [string]$AllowedBaseDistinguishedName

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty()]
    [string]$Server

    [DscProperty()]
    [string]$ObjectGuid

    [DscProperty()]
    [int]$TimeoutSeconds = 10

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlADObjectSecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily ADObject `
            -Target $this.DistinguishedName `
            -Server $this.Server `
            -TimeoutSeconds $this.TimeoutSeconds `
            -Sections $this.Sections `
            -ErrorAction Stop
        $this.AssertObjectGuid($descriptor.ObjectGuid)
        $currentState = [WindowsAccessControlADObjectSecurityDescriptor]::new()
        $currentState.DistinguishedName = $this.DistinguishedName
        $currentState.Sections = $this.Sections
        $currentState.AllowedBaseDistinguishedName = $this.AllowedBaseDistinguishedName
        $currentState.Server = $this.Server
        $currentState.ObjectGuid = [string]$descriptor.ObjectGuid
        $currentState.TimeoutSeconds = $this.TimeoutSeconds
        $currentState.Sddl = $descriptor.Sddl
        $currentState.Reasons = $this.GetReasons($descriptor.Sddl)
        return $currentState
    }

    [bool] Test() {
        return $this.Get().Reasons.Count -eq 0
    }

    [void] Set() {
        Set-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily ADObject `
            -Target $this.DistinguishedName `
            -Server $this.Server `
            -AllowedBaseDistinguishedName $this.AllowedBaseDistinguishedName `
            -ObjectGuid $this.ObjectGuid `
            -TimeoutSeconds $this.TimeoutSeconds `
            -Sections $this.Sections `
            -Sddl $this.Sddl `
            -ErrorAction Stop
    }

    # A distinguished name can be reused by a different object after a delete
    # and recreate, so an author may pin the immutable directory identity.
    [void] AssertObjectGuid([object]$ActualObjectGuid) {
        if ([string]::IsNullOrWhiteSpace($this.ObjectGuid)) {
            return
        }
        $expected = [guid]::Empty
        if (-not [guid]::TryParse($this.ObjectGuid, [ref]$expected) -or
            $expected -ne ($ActualObjectGuid -as [guid])) {
            throw "The Active Directory object '$($this.DistinguishedName)' does not have the configured object GUID."
        }
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
        $reason.Phrase = "The directory DACL for '$($this.DistinguishedName)' differs from the desired SDDL."
        return @($reason)
    }
}

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

[DscResource()]
class WindowsAccessControlCertificatePrivateKeySecurityDescriptor {
    [DscProperty(Key)]
    [string]$ProviderName

    [DscProperty(Key)]
    [string]$KeyName

    [DscProperty(Key)]
    [ValidateSet('Machine', 'User')]
    [string]$KeyScope

    [DscProperty(Key)]
    [WindowsSecurityDescriptorSection]$Sections =
        [WindowsSecurityDescriptorSection]::Access

    [DscProperty(Mandatory)]
    [string]$Sddl

    [DscProperty(NotConfigurable)]
    [WindowsAccessControlDscReason[]]$Reasons

    [WindowsAccessControlCertificatePrivateKeySecurityDescriptor] Get() {
        $descriptor = Get-WindowsAccessControlDscSecurityDescriptor `
            -ObjectFamily CertificatePrivateKey `
            -Target $this.KeyName `
            -ProviderName $this.ProviderName `
            -KeyScope $this.KeyScope `
            -Sections $this.Sections `
            -ErrorAction Stop
        $currentState = [WindowsAccessControlCertificatePrivateKeySecurityDescriptor]::new()
        $currentState.ProviderName = $this.ProviderName
        $currentState.KeyName = $this.KeyName
        $currentState.KeyScope = $this.KeyScope
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
            -ObjectFamily CertificatePrivateKey `
            -Target $this.KeyName `
            -ProviderName $this.ProviderName `
            -KeyScope $this.KeyScope `
            -Sections $this.Sections `
            -Sddl $this.Sddl `
            -ErrorAction Stop
    }

    [WindowsAccessControlDscReason[]] GetReasons([string]$CurrentSddl) {
        if (Test-WindowsCngKeyDscSddl `
                -CurrentSddl $CurrentSddl `
                -DesiredSddl $this.Sddl) {
            return @()
        }
        $reason = [WindowsAccessControlDscReason]::new()
        $reason.Code = '{0}:{0}:Sddl' -f $this.GetType().Name
        $reason.Phrase = "The private-key DACL for '$($this.KeyName)' differs from the desired SDDL."
        return @($reason)
    }
}
