BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop

    $script:testId = [guid]::NewGuid().ToString('N')
    $script:parentPath = "HKCU:\Software\WindowsAccessControlRegistryTest\$script:testId"
    $script:keyPath = Join-Path $script:parentPath 'Target'
    $script:childPath = Join-Path $script:keyPath 'Child'
    $script:currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $script:testSid = 'S-1-1-0'

    $null = New-Item -Path $script:childPath -Force -ErrorAction Stop
}

AfterAll {
    Remove-Item -LiteralPath $script:parentPath -Recurse -Force -ErrorAction SilentlyContinue
    $root = 'HKCU:\Software\WindowsAccessControlRegistryTest'
    if (Test-Path -LiteralPath $root -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $root).Count -eq 0) {
            Remove-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Registry key security descriptors' -Tag 'Integration', 'WindowsOnly' {
    It 'Get-RegistryKeySecurityDescriptor should accept provider pipeline input' {
        $result = Get-Item -LiteralPath $script:keyPath | Get-RegistryKeySecurityDescriptor

        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.RegistryKeySecurityDescriptor'
        $result.ObjectType | Should -Be 'RegistryKey'
        $result.Path | Should -Be $script:keyPath
        $result.NativePath | Should -Match '^CURRENT_USER\\'
        $result.Sddl | Should -Match '^O:'
        $result.BinarySecurityDescriptor.Length | Should -BeGreaterThan 0
    }

    It 'Get-RegistryKeySecurityDescriptor should deduplicate batches and record metrics' {
        $before = Get-WindowsAccessControlMetric `
            -CommandName 'Get-RegistryKeySecurityDescriptor' `
            -ObjectFamily 'RegistryKey'
        $beforeOperations = if ($before) { $before.OperationCount } else { 0 }
        $beforeTargets = if ($before) { $before.TargetCount } else { 0 }
        $beforeSuccesses = if ($before) { $before.SuccessCount } else { 0 }

        $result = @(Get-RegistryKeySecurityDescriptor `
            -Path @($script:keyPath, $script:keyPath, $script:childPath) `
            -Sections Access `
            -ThrottleLimit 2)
        $after = Get-WindowsAccessControlMetric `
            -CommandName 'Get-RegistryKeySecurityDescriptor' `
            -ObjectFamily 'RegistryKey'

        $result | Should -HaveCount 2
        @($result.CanonicalTarget | Sort-Object -Unique) | Should -HaveCount 2
        $after.OperationCount - $beforeOperations | Should -Be 1
        $after.TargetCount - $beforeTargets | Should -Be 2
        $after.SuccessCount - $beforeSuccesses | Should -Be 2
        $after.FailureCount | Should -Be 0
    }

    It 'Set-RegistryKeySecurityDescriptor should round-trip a selected DACL' {
        $before = Get-RegistryKeySecurityDescriptor -Path $script:keyPath -Sections Access

        Set-RegistryKeySecurityDescriptor -Path $script:keyPath -Sddl $before.Sddl `
            -Sections Access -Confirm:$false

        $after = Get-RegistryKeySecurityDescriptor -Path $script:keyPath -Sections Access
        $after.Sddl | Should -BeExactly $before.Sddl
        {
            Set-RegistryKeySecurityDescriptor -Path $script:keyPath `
                -Sddl 'D:(A;;KR;;;WD)' -Sections Audit -Confirm:$false
        } | Should -Throw -ExpectedMessage '*SACL*'
    }

    It 'Set-RegistryKeySecurityDescriptor should honor WhatIf' {
        $before = Get-RegistryKeySecurityDescriptor -Path $script:keyPath -Sections Access

        Set-RegistryKeySecurityDescriptor -Path $script:keyPath -Sddl 'D:(A;;KA;;;WD)' `
            -Sections Access -WhatIf

        (Get-RegistryKeySecurityDescriptor -Path $script:keyPath -Sections Access).Sddl |
            Should -BeExactly $before.Sddl
    }

    It 'Registry view selection should remain explicit and local' {
        $default = Get-RegistryKeySecurityDescriptor -Path $script:keyPath
        $view32 = Get-RegistryKeySecurityDescriptor -Path $script:keyPath -RegistryView Registry32
        $view64 = Get-RegistryKeySecurityDescriptor -Path $script:keyPath -RegistryView Registry64
        $forwardSlashPath = $script:keyPath.Replace('\', '/')
        $forwardSlash = Get-RegistryKeySecurityDescriptor -Path $forwardSlashPath `
            -Sections Access

        $default.RegistryView | Should -Be 'Default'
        $view32.RegistryView | Should -Be 'Registry32'
        $view64.RegistryView | Should -Be 'Registry64'
        $forwardSlash.Path | Should -Be $script:keyPath
        { Get-RegistryKeySecurityDescriptor -Path '\\server\MACHINE\Software' } |
            Should -Throw -ExpectedMessage '*remote*'
    }

    It 'RegistryKey objects marked as remote should be rejected' {
        $key = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::CurrentUser,
            [Microsoft.Win32.RegistryView]::Default
        )
        $bindingFlags = [Reflection.BindingFlags]'Instance,NonPublic'
        $remoteField = @('_remoteKey', 'remoteKey', 'm_remoteKey') |
            ForEach-Object { $key.GetType().GetField($_, $bindingFlags) } |
            Where-Object { $_ } |
            Select-Object -First 1
        $remoteField | Should -Not -BeNullOrEmpty
        $wasRemote = $remoteField.GetValue($key)
        try {
            $remoteField.SetValue($key, $true)

            { $key | Get-RegistryKeySecurityDescriptor -Sections Access } |
                Should -Throw -ExpectedMessage '*remote*'
        } finally {
            $remoteField.SetValue($key, $wasRemote)
            $key.Dispose()
        }
    }
}

Describe 'Registry key access rules' -Tag 'Integration', 'WindowsOnly' {
    BeforeEach {
        Clear-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -Confirm:$false -ErrorAction SilentlyContinue
    }

    It 'Add-RegistryKeyAccessRule and Get-RegistryKeyAccessRule should persist a typed rule' {
        Add-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights ReadKey -AppliesTo ThisKeyAndSubkeys -Confirm:$false

        $result = Get-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited

        $result | Should -HaveCount 1
        $result.AccessControlType | Should -Be 'Allow'
        $result.AccessMask | Should -BeOfType ([uint64])
        ($result.AccessMask -band [int][System.Security.AccessControl.RegistryRights]::ReadKey) |
            Should -Be ([int][System.Security.AccessControl.RegistryRights]::ReadKey)
        $result.AppliesTo | Should -Be 'ThisKeyAndSubkeys'

        $identity = Resolve-WindowsIdentity -Identity $script:testSid
        Get-RegistryKeyAccessRule -Path $script:keyPath -Account $identity `
            -ExcludeInherited | Should -HaveCount 1
    }

    It 'Set-RegistryKeyAccessRule should replace matching access rights' {
        Add-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights ReadKey -Confirm:$false

        Set-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights SetValue -Confirm:$false

        $result = Get-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited
        $result | Should -HaveCount 1
        ($result.AccessMask -band [int][System.Security.AccessControl.RegistryRights]::SetValue) |
            Should -Be ([int][System.Security.AccessControl.RegistryRights]::SetValue)
        ($result.AccessMask -band [int][System.Security.AccessControl.RegistryRights]::QueryValues) |
            Should -Be 0
    }

    It 'Remove-RegistryKeyAccessRule should remove an exact pipeline rule' {
        Add-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights ReadKey -Confirm:$false
        $rule = Get-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited

        $rule | Remove-RegistryKeyAccessRule -Confirm:$false

        Get-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited | Should -BeNullOrEmpty
    }

    It 'Clear-RegistryKeyAccessRule should remove selected explicit account rules' {
        Add-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights ReadKey -Confirm:$false

        Clear-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -Confirm:$false

        Get-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited | Should -BeNullOrEmpty
    }

    It 'Add-RegistryKeyAccessRule should persist a rule that differs only by inheritance scope' {
        Add-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights ReadKey -AppliesTo ThisKeyOnly -Confirm:$false

        $added = @(Add-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights ReadKey -AppliesTo ThisKeyAndSubkeys -Confirm:$false -PassThru)

        $result = @(Get-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited)
        $result | Should -HaveCount 2
        @($result.AppliesTo) | Should -Contain 'ThisKeyOnly'
        @($result.AppliesTo) | Should -Contain 'ThisKeyAndSubkeys'
        $added | Should -HaveCount 2
    }

    It 'Add-RegistryKeyAccessRule should still suppress an identical rule' {
        Add-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights ReadKey -AppliesTo ThisKeyAndSubkeys -Confirm:$false
        Add-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights ReadKey -AppliesTo ThisKeyAndSubkeys -Confirm:$false

        @(Get-RegistryKeyAccessRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited) | Should -HaveCount 1
    }
}

Describe 'Registry key audit rules' -Tag 'Integration', 'WindowsOnly', 'RequiresElevation' {
    BeforeEach {
        Clear-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -Confirm:$false -ErrorAction SilentlyContinue
    }

    It 'Add-RegistryKeyAuditRule and Get-RegistryKeyAuditRule should persist a SACL rule' {
        Add-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights SetValue -AuditFlags Failure -Confirm:$false

        $result = Get-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited

        $result | Should -HaveCount 1
        $result.AuditFlags | Should -Be 'Failure'
        {
            Add-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
                -AccessRights SetValue -AuditFlags None -Confirm:$false
        } | Should -Throw
        {
            Set-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
                -AccessRights SetValue -AuditFlags None -Confirm:$false
        } | Should -Throw
    }

    It 'Set-RegistryKeyAuditRule should replace matching audit rights' {
        Add-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights QueryValues -AuditFlags Failure -Confirm:$false

        Set-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights SetValue -AuditFlags Failure -Confirm:$false

        $result = Get-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited
        $result | Should -HaveCount 1
        ($result.AccessMask -band [int][System.Security.AccessControl.RegistryRights]::SetValue) |
            Should -Be ([int][System.Security.AccessControl.RegistryRights]::SetValue)
    }

    It 'Set-RegistryKeyAuditRule should preserve opposite audit flags' {
        Add-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights QueryValues -AuditFlags Success -Confirm:$false
        Add-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights QueryValues -AuditFlags Failure -Confirm:$false

        Set-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights SetValue -AuditFlags Failure -Confirm:$false

        $rules = @(Get-RegistryKeyAuditRule -Path $script:keyPath `
            -Account $script:testSid -ExcludeInherited)
        $rules | Should -HaveCount 2
        ($rules | Where-Object AuditFlags -EQ Success).AccessRights |
            Should -Be ([System.Security.AccessControl.RegistryRights]::QueryValues)
        ($rules | Where-Object AuditFlags -EQ Failure).AccessRights |
            Should -Be ([System.Security.AccessControl.RegistryRights]::SetValue)
    }

    It 'Remove-RegistryKeyAuditRule should remove an exact pipeline rule' {
        Add-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights SetValue -AuditFlags Failure -Confirm:$false
        $rule = Get-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited

        $rule | Remove-RegistryKeyAuditRule -Confirm:$false

        Get-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited | Should -BeNullOrEmpty
    }

    It 'Add-RegistryKeyAuditRule should persist a rule that differs only by inheritance scope' {
        Add-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights SetValue -AuditFlags Failure -AppliesTo ThisKeyOnly -Confirm:$false
        Add-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights SetValue -AuditFlags Failure -AppliesTo ThisKeyAndSubkeys `
            -Confirm:$false

        $result = @(Get-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited)

        $result | Should -HaveCount 2
        @($result.AppliesTo) | Should -Contain 'ThisKeyOnly'
        @($result.AppliesTo) | Should -Contain 'ThisKeyAndSubkeys'
    }

    It 'Clear-RegistryKeyAuditRule should remove selected explicit account rules' {
        Add-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -AccessRights SetValue -AuditFlags Failure -Confirm:$false

        Clear-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -Confirm:$false

        Get-RegistryKeyAuditRule -Path $script:keyPath -Account $script:testSid `
            -ExcludeInherited | Should -BeNullOrEmpty
    }

    It 'Clear-RegistryKeyAuditRule should preserve an absent SACL when nothing matches' {
        $path = Join-Path $script:parentPath 'AbsentSacl'
        $null = New-Item -Path $path -Force
        try {
            $before = Get-RegistryKeySecurityDescriptor -Path $path -Sections Audit
            $before.NativeDescriptor.SystemAcl | Should -BeNullOrEmpty

            Clear-RegistryKeyAuditRule -Path $path -Account $script:testSid `
                -Confirm:$false

            $after = Get-RegistryKeySecurityDescriptor -Path $path -Sections Audit
            $after.NativeDescriptor.SystemAcl | Should -BeNullOrEmpty
            $after.Sddl | Should -BeExactly $before.Sddl
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Registry key inheritance' -Tag 'Integration', 'WindowsOnly', 'RequiresElevation' {
    It 'Disable-RegistryKeyInheritance and Enable-RegistryKeyInheritance should converge both ACLs' {
        Disable-RegistryKeyInheritance -Path $script:keyPath -Section All `
            -PreserveInherited $true -Confirm:$false

        $disabled = Get-RegistryKeyInheritance -Path $script:keyPath -Section All
        $disabled.AccessInheritanceEnabled | Should -BeFalse
        $disabled.AuditInheritanceEnabled | Should -BeFalse

        Enable-RegistryKeyInheritance -Path $script:keyPath -Section All -Confirm:$false

        $enabled = Get-RegistryKeyInheritance -Path $script:keyPath -Section All
        $enabled.AccessInheritanceEnabled | Should -BeTrue
        $enabled.AuditInheritanceEnabled | Should -BeTrue
    }
}
