# Cross-cutting ShouldProcess and WhatIf contract (FR-17).
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Mutator WhatIf safety' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:sourceFile = Join-Path -Path $TestDrive -ChildPath 'source.txt'
        $script:targetFile = Join-Path -Path $TestDrive -ChildPath 'target.txt'
        Set-Content -LiteralPath $script:sourceFile -Value 'source'
        Set-Content -LiteralPath $script:targetFile -Value 'target'
        Mock -ModuleName WindowsAccessControl -CommandName Invoke-NTFSSecurityDescriptorPersistence
        Mock -ModuleName WindowsAccessControl -CommandName Set-WindowsNamedSecurityDescriptor
        Mock -ModuleName WindowsAccessControl -CommandName Set-WindowsServiceTargetSecurityDescriptor
        Mock -ModuleName WindowsAccessControl -CommandName Set-WindowsProcessTargetSecurityDescriptor
        Mock -ModuleName WindowsAccessControl -CommandName Invoke-WindowsProcessAclRuleMutation
    }

    It 'Should expose WhatIf on every state-changing command' {
        $mutators = @(
            'Add-NTFSAccessRule'
            'Set-NTFSAccessRule'
            'Remove-NTFSAccessRule'
            'Clear-NTFSAccessRule'
            'Add-NTFSAuditRule'
            'Set-NTFSAuditRule'
            'Remove-NTFSAuditRule'
            'Clear-NTFSAuditRule'
            'Set-NTFSItemOwner'
            'Enable-NTFSItemInheritance'
            'Disable-NTFSItemInheritance'
            'Copy-NTFSItemSecurityDescriptor'
            'Backup-NTFSItemSecurityDescriptor'
            'Backup-WindowsSecurityDescriptor'
            'Restore-NTFSItemSecurityDescriptor'
            'Restore-WindowsSecurityDescriptor'
            'Enable-WindowsPrivilege'
            'Disable-WindowsPrivilege'
            'Add-RegistryKeyAccessRule'
            'Set-RegistryKeyAccessRule'
            'Remove-RegistryKeyAccessRule'
            'Clear-RegistryKeyAccessRule'
            'Add-RegistryKeyAuditRule'
            'Set-RegistryKeyAuditRule'
            'Remove-RegistryKeyAuditRule'
            'Clear-RegistryKeyAuditRule'
            'Set-RegistryKeySecurityDescriptor'
            'Enable-RegistryKeyInheritance'
            'Disable-RegistryKeyInheritance'
            'Add-ServiceAccessRule'
            'Set-ServiceAccessRule'
            'Remove-ServiceAccessRule'
            'Clear-ServiceAccessRule'
            'Add-ServiceAuditRule'
            'Set-ServiceAuditRule'
            'Remove-ServiceAuditRule'
            'Clear-ServiceAuditRule'
            'Set-ServiceSecurityDescriptor'
            'Add-SmbShareAccessRule'
            'Remove-SmbShareAccessRule'
            'Set-SmbShareSecurityDescriptor'
            'Set-TaskFolderSecurityDescriptor'
            'Set-ScheduledTaskSecurityDescriptor'
            'Add-ADObjectAccessRule'
            'Remove-ADObjectAccessRule'
            'Set-ADObjectSecurityDescriptor'
            'Add-ProcessAccessRule'
            'Set-ProcessAccessRule'
            'Remove-ProcessAccessRule'
            'Clear-ProcessAccessRule'
            'Add-ProcessAuditRule'
            'Set-ProcessAuditRule'
            'Remove-ProcessAuditRule'
            'Clear-ProcessAuditRule'
            'Set-ProcessSecurityDescriptor'
        )

        foreach ($commandName in $mutators) {
            (Get-Command -Name $commandName).Parameters.ContainsKey('WhatIf') |
                Should -BeTrue -Because "$commandName changes system state"
        }
    }

    It 'Should not persist an added access rule under WhatIf' {
        Add-NTFSAccessRule -LiteralPath $script:targetFile `
            -Account 'S-1-1-0' -AccessRights Read -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not persist a replacement access rule under WhatIf' {
        Set-NTFSAccessRule -LiteralPath $script:targetFile `
            -Account 'S-1-1-0' -AccessRights Read -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not purge access rules under WhatIf' {
        Remove-NTFSAccessRule -LiteralPath $script:targetFile `
            -Account 'S-1-1-0' -RemovalMode All -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not clear access rules under WhatIf' {
        Clear-NTFSAccessRule -LiteralPath $script:targetFile -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not persist an added audit rule under WhatIf' {
        Add-NTFSAuditRule -LiteralPath $script:targetFile `
            -Account 'S-1-1-0' -AccessRights Read -AuditFlags Failure -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not persist a replacement audit rule under WhatIf' {
        Set-NTFSAuditRule -LiteralPath $script:targetFile `
            -Account 'S-1-1-0' -AccessRights Read -AuditFlags Failure -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not purge audit rules under WhatIf' {
        Remove-NTFSAuditRule -LiteralPath $script:targetFile `
            -Account 'S-1-1-0' -RemovalMode All -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not clear audit rules under WhatIf' {
        Clear-NTFSAuditRule -LiteralPath $script:targetFile -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not set an owner under WhatIf' {
        Set-NTFSItemOwner -LiteralPath $script:targetFile `
            -Account $script:currentSid -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not enable inheritance under WhatIf' {
        Enable-NTFSItemInheritance -LiteralPath $script:targetFile -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not disable inheritance under WhatIf' {
        Disable-NTFSItemInheritance -LiteralPath $script:targetFile -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not copy descriptor sections under WhatIf' {
        Copy-NTFSItemSecurityDescriptor -SourceLiteralPath $script:sourceFile `
            -LiteralPath $script:targetFile -Sections Access -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not restore descriptor sections under WhatIf' {
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'restore-whatif.json'
        Backup-NTFSItemSecurityDescriptor -LiteralPath $script:targetFile `
            -DestinationPath $backupPath -Sections Access

        Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -WhatIf
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not create or overwrite a backup under WhatIf' {
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'backup-whatif.json'
        Set-Content -LiteralPath $backupPath -Value 'original backup'

        Backup-NTFSItemSecurityDescriptor -LiteralPath $script:targetFile `
            -DestinationPath $backupPath -Force -WhatIf

        Get-Content -LiteralPath $backupPath -Raw | Should -Match '^original backup'
    }

    It 'Should not create or overwrite a unified backup under WhatIf' {
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'unified-backup-whatif.json'
        Set-Content -LiteralPath $backupPath -Value 'original backup'
        $descriptor = Get-NTFSItemSecurityDescriptor `
            -LiteralPath $script:targetFile `
            -Sections Access

        $descriptor | Backup-WindowsSecurityDescriptor `
            -DestinationPath $backupPath `
            -Force `
            -WhatIf

        Get-Content -LiteralPath $backupPath -Raw | Should -Match '^original backup'
    }

    It 'Should not restore a unified descriptor under WhatIf' {
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'unified-restore-whatif.json'
        Get-NTFSItemSecurityDescriptor `
            -LiteralPath $script:targetFile `
            -Sections Access |
            Backup-WindowsSecurityDescriptor -DestinationPath $backupPath

        Restore-WindowsSecurityDescriptor -BackupPath $backupPath -WhatIf

        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not enable a token privilege under WhatIf' {
        $wasEnabled = Test-WindowsPrivilege -Name 'SeChangeNotifyPrivilege'
        Enable-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' -WhatIf
        Test-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' | Should -Be $wasEnabled
    }

    It 'Should not disable a token privilege under WhatIf' {
        $wasEnabled = Test-WindowsPrivilege -Name 'SeChangeNotifyPrivilege'
        Disable-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' -WhatIf
        Test-WindowsPrivilege -Name 'SeChangeNotifyPrivilege' | Should -Be $wasEnabled
    }

    It 'Should not persist registry descriptor changes under WhatIf' {
        $path = 'HKCU:\Software\WindowsAccessControlWhatIf'
        $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $accessAce = [System.Security.AccessControl.CommonAce]::new(
            [System.Security.AccessControl.AceFlags]::None,
            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            1,
            $sid,
            $false,
            $null
        )
        $auditAce = [System.Security.AccessControl.CommonAce]::new(
            [System.Security.AccessControl.AceFlags]::FailedAccess,
            [System.Security.AccessControl.AceQualifier]::SystemAudit,
            1,
            $sid,
            $false,
            $null
        )
        $accessRule = [pscustomobject]@{
            Path         = $path
            RegistryView = 'Default'
            NativeAce    = $accessAce
            SID          = $sid.Value
        }
        $accessRule.PSObject.TypeNames.Insert(
            0,
            'WindowsAccessControl.RegistryKeyAccessRule'
        )
        $auditRule = [pscustomobject]@{
            Path         = $path
            RegistryView = 'Default'
            NativeAce    = $auditAce
            SID          = $sid.Value
        }
        $auditRule.PSObject.TypeNames.Insert(
            0,
            'WindowsAccessControl.RegistryKeyAuditRule'
        )

        Add-RegistryKeyAccessRule -Path $path -Account $sid -AccessRights ReadKey -WhatIf
        Set-RegistryKeyAccessRule -Path $path -Account $sid -AccessRights ReadKey -WhatIf
        Remove-RegistryKeyAccessRule -InputObject $accessRule -WhatIf
        Clear-RegistryKeyAccessRule -Path $path -Account $sid -WhatIf
        Add-RegistryKeyAuditRule -Path $path -Account $sid -AccessRights ReadKey `
            -AuditFlags Failure -WhatIf
        Set-RegistryKeyAuditRule -Path $path -Account $sid -AccessRights ReadKey `
            -AuditFlags Failure -WhatIf
        Remove-RegistryKeyAuditRule -InputObject $auditRule -WhatIf
        Clear-RegistryKeyAuditRule -Path $path -Account $sid -WhatIf
        Set-RegistryKeySecurityDescriptor -Path $path -Sddl 'D:(A;;KR;;;WD)' `
            -Sections Access -WhatIf
        Enable-RegistryKeyInheritance -Path $path -Section All -WhatIf
        Disable-RegistryKeyInheritance -Path $path -Section All -WhatIf

        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Set-WindowsNamedSecurityDescriptor -Times 0 -Exactly
    }

    It 'Should not persist service descriptor changes under WhatIf' {
        $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $accessAce = [System.Security.AccessControl.CommonAce]::new(
            [System.Security.AccessControl.AceFlags]::None,
            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            4,
            $sid,
            $false,
            $null
        )
        $auditAce = [System.Security.AccessControl.CommonAce]::new(
            [System.Security.AccessControl.AceFlags]::FailedAccess,
            [System.Security.AccessControl.AceQualifier]::SystemAudit,
            16,
            $sid,
            $false,
            $null
        )
        $accessRule = [pscustomobject]@{
            ObjectType  = 'Service'
            ServiceName = 'WacWhatIf'
            NativeAce   = $accessAce
            SID         = $sid.Value
        }
        $accessRule.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.ServiceAccessRule')
        $auditRule = [pscustomobject]@{
            ObjectType  = 'Service'
            ServiceName = 'WacWhatIf'
            NativeAce   = $auditAce
            SID         = $sid.Value
        }
        $auditRule.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.ServiceAuditRule')

        Add-ServiceAccessRule -Name WacWhatIf -Account $sid `
            -ServiceRights QueryStatus -WhatIf
        Set-ServiceAccessRule -Name WacWhatIf -Account $sid `
            -ServiceRights QueryStatus -WhatIf
        Remove-ServiceAccessRule -InputObject $accessRule -WhatIf
        Clear-ServiceAccessRule -Name WacWhatIf -Account $sid -WhatIf
        Add-ServiceAuditRule -Name WacWhatIf -Account $sid `
            -ServiceRights Start -AuditFlags Failure -WhatIf
        Set-ServiceAuditRule -Name WacWhatIf -Account $sid `
            -ServiceRights Start -AuditFlags Failure -WhatIf
        Remove-ServiceAuditRule -InputObject $auditRule -WhatIf
        Clear-ServiceAuditRule -Name WacWhatIf -Account $sid -WhatIf
        Set-ServiceSecurityDescriptor -Name WacWhatIf `
            -Sddl 'D:(A;;CC;;;WD)' -Sections Access -WhatIf
        Add-ServiceAccessRule -ServiceControlManager -Account $sid `
            -ControlManagerRights Connect -WhatIf
        Set-ServiceAccessRule -ServiceControlManager -Account $sid `
            -ControlManagerRights Connect -WhatIf
        Clear-ServiceAccessRule -ServiceControlManager -Account $sid -WhatIf
        Add-ServiceAuditRule -ServiceControlManager -Account $sid `
            -ControlManagerRights Connect -AuditFlags Failure -WhatIf
        Set-ServiceAuditRule -ServiceControlManager -Account $sid `
            -ControlManagerRights Connect -AuditFlags Failure -WhatIf
        Clear-ServiceAuditRule -ServiceControlManager -Account $sid -WhatIf
        Set-ServiceSecurityDescriptor -ServiceControlManager `
            -Sddl 'D:(A;;CC;;;WD)' -Sections Access -WhatIf

        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Set-WindowsServiceTargetSecurityDescriptor -Times 0 -Exactly
    }

    It 'Should not persist process descriptor changes under WhatIf' {
        $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $creationTime = (Get-Process -Id $PID).StartTime.ToFileTimeUtc()
        $target = [pscustomobject]@{
            ObjectType           = 'Process'
            ProcessId            = $PID
            ProcessName          = 'pwsh'
            CreationTimeFileTime = $creationTime
            Handle               = [IntPtr]::Zero
        }
        $accessAce = [System.Security.AccessControl.CommonAce]::new(
            [System.Security.AccessControl.AceFlags]::None,
            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            4096,
            $sid,
            $false,
            $null
        )
        $accessRule = $target.PSObject.Copy()
        $accessRule | Add-Member NativeAce $accessAce
        $accessRule | Add-Member SID $sid.Value
        $accessRule.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.ProcessAccessRule')
        $auditAce = [System.Security.AccessControl.CommonAce]::new(
            [System.Security.AccessControl.AceFlags]::FailedAccess,
            [System.Security.AccessControl.AceQualifier]::SystemAudit,
            1,
            $sid,
            $false,
            $null
        )
        $auditRule = $target.PSObject.Copy()
        $auditRule | Add-Member NativeAce $auditAce
        $auditRule | Add-Member SID $sid.Value
        $auditRule.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.ProcessAuditRule')

        Add-ProcessAccessRule -ProcessId $PID -Account $sid `
            -ProcessRights QueryLimitedInformation -WhatIf
        Set-ProcessAccessRule -ProcessId $PID -Account $sid `
            -ProcessRights QueryLimitedInformation -WhatIf
        Remove-ProcessAccessRule -InputObject $accessRule -WhatIf
        Clear-ProcessAccessRule -ProcessId $PID -Account $sid -WhatIf
        Add-ProcessAuditRule -ProcessId $PID -Account $sid `
            -ProcessRights Terminate -AuditFlags Failure -WhatIf
        Set-ProcessAuditRule -ProcessId $PID -Account $sid `
            -ProcessRights Terminate -AuditFlags Failure -WhatIf
        Remove-ProcessAuditRule -InputObject $auditRule -WhatIf
        Clear-ProcessAuditRule -ProcessId $PID -Account $sid -WhatIf
        Set-ProcessSecurityDescriptor -ProcessId $PID `
            -Sddl 'D:(A;;GR;;;WD)' -Sections Access -WhatIf
        Add-ProcessAccessRule -Handle ([IntPtr]1) -Account $sid `
            -ProcessRights QueryLimitedInformation -WhatIf
        Set-ProcessSecurityDescriptor -Handle ([IntPtr]1) `
            -Sddl 'D:(A;;GR;;;WD)' -Sections Access -WhatIf

        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Invoke-WindowsProcessAclRuleMutation -Times 0 -Exactly
        Should -Invoke -ModuleName WindowsAccessControl `
            -CommandName Set-WindowsProcessTargetSecurityDescriptor -Times 0 -Exactly
    }
}
