# Cross-cutting ShouldProcess and WhatIf contract (FR-17).
BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Mutator WhatIf safety' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:sourceFile = Join-Path -Path $TestDrive -ChildPath 'source.txt'
        $script:targetFile = Join-Path -Path $TestDrive -ChildPath 'target.txt'
        Set-Content -LiteralPath $script:sourceFile -Value 'source'
        Set-Content -LiteralPath $script:targetFile -Value 'target'
        Mock -ModuleName NTFSPermission -CommandName Invoke-NTFSSecurityDescriptorPersistence
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
            'Restore-NTFSItemSecurityDescriptor'
            'Enable-NTFSPrivilege'
            'Disable-NTFSPrivilege'
        )

        foreach ($commandName in $mutators) {
            (Get-Command -Name $commandName).Parameters.ContainsKey('WhatIf') |
                Should -BeTrue -Because "$commandName changes system state"
        }
    }

    It 'Should not persist an added access rule under WhatIf' {
        Add-NTFSAccessRule -LiteralPath $script:targetFile `
            -Account 'S-1-1-0' -AccessRights Read -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not persist a replacement access rule under WhatIf' {
        Set-NTFSAccessRule -LiteralPath $script:targetFile `
            -Account 'S-1-1-0' -AccessRights Read -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not purge access rules under WhatIf' {
        Remove-NTFSAccessRule -LiteralPath $script:targetFile `
            -Account 'S-1-1-0' -RemovalMode All -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not clear access rules under WhatIf' {
        Clear-NTFSAccessRule -LiteralPath $script:targetFile -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not persist an added audit rule under WhatIf' {
        Add-NTFSAuditRule -LiteralPath $script:targetFile `
            -Account 'S-1-1-0' -AccessRights Read -AuditFlags Failure -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not persist a replacement audit rule under WhatIf' {
        Set-NTFSAuditRule -LiteralPath $script:targetFile `
            -Account 'S-1-1-0' -AccessRights Read -AuditFlags Failure -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not purge audit rules under WhatIf' {
        Remove-NTFSAuditRule -LiteralPath $script:targetFile `
            -Account 'S-1-1-0' -RemovalMode All -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not clear audit rules under WhatIf' {
        Clear-NTFSAuditRule -LiteralPath $script:targetFile -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not set an owner under WhatIf' {
        Set-NTFSItemOwner -LiteralPath $script:targetFile `
            -Account $script:currentSid -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not enable inheritance under WhatIf' {
        Enable-NTFSItemInheritance -LiteralPath $script:targetFile -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not disable inheritance under WhatIf' {
        Disable-NTFSItemInheritance -LiteralPath $script:targetFile -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not copy descriptor sections under WhatIf' {
        Copy-NTFSItemSecurityDescriptor -SourceLiteralPath $script:sourceFile `
            -LiteralPath $script:targetFile -Sections Access -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not restore descriptor sections under WhatIf' {
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'restore-whatif.json'
        Backup-NTFSItemSecurityDescriptor -LiteralPath $script:targetFile `
            -DestinationPath $backupPath -Sections Access

        Restore-NTFSItemSecurityDescriptor -BackupPath $backupPath -WhatIf
        Should -Invoke -ModuleName NTFSPermission `
            -CommandName Invoke-NTFSSecurityDescriptorPersistence -Times 0 -Exactly
    }

    It 'Should not create or overwrite a backup under WhatIf' {
        $backupPath = Join-Path -Path $TestDrive -ChildPath 'backup-whatif.json'
        Set-Content -LiteralPath $backupPath -Value 'original backup'

        Backup-NTFSItemSecurityDescriptor -LiteralPath $script:targetFile `
            -DestinationPath $backupPath -Force -WhatIf

        Get-Content -LiteralPath $backupPath -Raw | Should -Match '^original backup'
    }

    It 'Should not enable a token privilege under WhatIf' {
        $wasEnabled = Test-NTFSPrivilege -Name 'SeChangeNotifyPrivilege'
        Enable-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' -WhatIf
        Test-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' | Should -Be $wasEnabled
    }

    It 'Should not disable a token privilege under WhatIf' {
        $wasEnabled = Test-NTFSPrivilege -Name 'SeChangeNotifyPrivilege'
        Disable-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' -WhatIf
        Test-NTFSPrivilege -Name 'SeChangeNotifyPrivilege' | Should -Be $wasEnabled
    }
}
