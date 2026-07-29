BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'In-memory NTFS descriptor editing' -Tag 'Integration', 'WindowsOnly' {
    It 'Should stage an access rule in memory and persist it only with Set' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'edit.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9001'

        $descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections Access
        $edited = $descriptor | Add-NTFSAccessRule -Account $stagedSid -AccessRights Read

        Get-NTFSAccessRule -LiteralPath $testFile -Account $stagedSid -ExcludeInherited |
            Should -BeNullOrEmpty

        $edited | Set-NTFSItemSecurityDescriptor

        $persisted = @(Get-NTFSAccessRule -LiteralPath $testFile -Account $stagedSid -ExcludeInherited)
        $persisted | Should -HaveCount 1
        $persisted[0].AccessRights | Should -Match 'Read'
    }

    It 'Should not persist a staged edit under WhatIf' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'whatif.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9002'

        $descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections Access
        $edited = $descriptor | Add-NTFSAccessRule -Account $stagedSid -AccessRights Read
        $edited | Set-NTFSItemSecurityDescriptor -WhatIf

        Get-NTFSAccessRule -LiteralPath $testFile -Account $stagedSid -ExcludeInherited |
            Should -BeNullOrEmpty
    }

    It 'Should return the edited descriptor from Set with PassThru' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'passthru.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9003'

        $result = Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections Access |
            Add-NTFSAccessRule -Account $stagedSid -AccessRights Read |
            Set-NTFSItemSecurityDescriptor -PassThru

        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.SecurityDescriptor'
        $result.Path | Should -Be $testFile
    }

    It 'Should add and persist one rule through a bounded editing scope' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'bounded-edit.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9004'

        $result = Edit-NTFSItemSecurityDescriptor `
            -LiteralPath $testFile `
            -Sections Access `
            -ScriptBlock {
                param($descriptor, $sid)
                $descriptor | Add-NTFSAccessRule `
                    -Account $sid `
                    -AccessRights Read | Out-Null
            } `
            -ArgumentList $stagedSid `
            -PassThru `
            -Confirm:$false

        $result.PSObject.TypeNames |
            Should -Contain 'WindowsAccessControl.SecurityDescriptor'
        $persisted = @(
            Get-NTFSAccessRule `
                -LiteralPath $testFile `
                -Account $stagedSid `
                -ExcludeInherited
        )
        $persisted | Should -HaveCount 1
        $persisted[0].AccessRights | Should -Match 'Read'
    }

    It 'Should leave the target unchanged when the bounded callback fails' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'bounded-failure.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $before = (Get-Acl -LiteralPath $testFile).Sddl

        {
            Edit-NTFSItemSecurityDescriptor `
                -LiteralPath $testFile `
                -Sections Access `
                -ScriptBlock { throw 'Expected bounded edit failure.' } `
                -Confirm:$false `
                -ErrorAction Stop
        } | Should -Throw -ExpectedMessage '*Expected bounded edit failure*'

        (Get-Acl -LiteralPath $testFile).Sddl | Should -BeExactly $before
    }

    It 'Should edit multiple targets deterministically without sharing a callback across runspaces' {
        $testFiles = @(
            Join-Path -Path $TestDrive -ChildPath 'bounded-one.txt'
            Join-Path -Path $TestDrive -ChildPath 'bounded-two.txt'
        )
        $testFiles | ForEach-Object {
            Set-Content -LiteralPath $_ -Value 'test'
        }
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9005'

        Edit-NTFSItemSecurityDescriptor `
            -LiteralPath $testFiles `
            -Sections Access `
            -ScriptBlock {
                param($descriptor, $sid)
                $descriptor | Add-NTFSAccessRule `
                    -Account $sid `
                    -AccessRights Read | Out-Null
            } `
            -ArgumentList $stagedSid `
            -ThrottleLimit 8 `
            -Confirm:$false

        foreach ($testFile in $testFiles) {
            @(
                Get-NTFSAccessRule `
                    -LiteralPath $testFile `
                    -Account $stagedSid `
                    -ExcludeInherited
            ) | Should -HaveCount 1
        }
    }

    It 'Should persist several staged access edits with one write' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'multi-edit.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $keptSid = 'S-1-5-21-1111111111-2222222222-3333333333-9006'
        $replacedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9007'

        Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections Access |
            Add-NTFSAccessRule -Account $keptSid -AccessRights Read |
            Add-NTFSAccessRule -Account $replacedSid -AccessRights Read |
            Set-NTFSAccessRule -Account $replacedSid -AccessRights Modify |
            Set-NTFSItemSecurityDescriptor

        @(Get-NTFSAccessRule -LiteralPath $testFile -Account $keptSid -ExcludeInherited) |
            Should -HaveCount 1
        $replaced = @(
            Get-NTFSAccessRule -LiteralPath $testFile -Account $replacedSid -ExcludeInherited
        )
        $replaced | Should -HaveCount 1
        $replaced[0].AccessRights | Should -Match 'Modify'
    }

    It 'Should remove a staged access rule through a bounded editing scope' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'bounded-remove.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9008'
        Add-NTFSAccessRule `
            -LiteralPath $testFile `
            -Account $stagedSid `
            -AccessRights Read `
            -Confirm:$false

        Edit-NTFSItemSecurityDescriptor `
            -LiteralPath $testFile `
            -Sections Access `
            -ScriptBlock {
                param($descriptor, $sid)
                $descriptor | Remove-NTFSAccessRule `
                    -Account $sid `
                    -RemovalMode All | Out-Null
            } `
            -ArgumentList $stagedSid `
            -Confirm:$false

        Get-NTFSAccessRule -LiteralPath $testFile -Account $stagedSid -ExcludeInherited |
            Should -BeNullOrEmpty
    }

    It 'Should persist descriptor-staged inheritance protection' {
        $testDirectory = Join-Path -Path $TestDrive -ChildPath 'bounded-inheritance'
        $null = New-Item -Path $testDirectory -ItemType Directory

        Edit-NTFSItemSecurityDescriptor `
            -LiteralPath $testDirectory `
            -Sections Access `
            -ScriptBlock {
                param($descriptor)
                $descriptor | Disable-NTFSItemInheritance `
                    -Section Access `
                    -PreserveInherited $true | Out-Null
            } `
            -Confirm:$false

        (Get-NTFSItemInheritance -LiteralPath $testDirectory).AccessInheritanceEnabled |
            Should -BeFalse
    }

    It 'Should reject staging a section the descriptor did not load' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'section-guard.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $before = (Get-Acl -LiteralPath $testFile).Sddl

        {
            Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections Owner |
                Add-NTFSAccessRule `
                    -Account 'S-1-1-0' `
                    -AccessRights Read `
                    -ErrorAction Stop
        } | Should -Throw -ExpectedMessage '*without the Access section*'

        (Get-Acl -LiteralPath $testFile).Sddl | Should -BeExactly $before
    }

    It 'Should reject a stale descriptor when RequireUnchanged is set' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'stale.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $staleSid = 'S-1-5-21-1111111111-2222222222-3333333333-9009'
        $concurrentSid = 'S-1-5-21-1111111111-2222222222-3333333333-9010'

        $descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections Access |
            Add-NTFSAccessRule -Account $staleSid -AccessRights Read

        Add-NTFSAccessRule `
            -LiteralPath $testFile `
            -Account $concurrentSid `
            -AccessRights Read `
            -Confirm:$false

        {
            $descriptor | Set-NTFSItemSecurityDescriptor `
                -RequireUnchanged `
                -ErrorAction Stop
        } | Should -Throw -ExpectedMessage '*changed after they were read*'

        Get-NTFSAccessRule -LiteralPath $testFile -Account $staleSid -ExcludeInherited |
            Should -BeNullOrEmpty
        @(Get-NTFSAccessRule -LiteralPath $testFile -Account $concurrentSid -ExcludeInherited) |
            Should -HaveCount 1
    }

    It 'Should persist an unchanged descriptor when RequireUnchanged is set' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'fresh.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9011'

        Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections Access |
            Add-NTFSAccessRule -Account $stagedSid -AccessRights Read |
            Set-NTFSItemSecurityDescriptor -RequireUnchanged

        @(Get-NTFSAccessRule -LiteralPath $testFile -Account $stagedSid -ExcludeInherited) |
            Should -HaveCount 1
    }

    It 'Should persist an Access and Audit descriptor on an item without a SACL' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'no-sacl.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9012'

        $descriptor = Get-NTFSItemSecurityDescriptor `
            -LiteralPath $testFile `
            -Sections Access, Audit
        $descriptor.NativeSecurity.GetAuditRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        ) | Should -BeNullOrEmpty

        {
            $descriptor |
                Add-NTFSAccessRule -Account $stagedSid -AccessRights Read |
                Set-NTFSItemSecurityDescriptor -ErrorAction Stop
        } | Should -Not -Throw

        @(Get-NTFSAccessRule -LiteralPath $testFile -Account $stagedSid -ExcludeInherited) |
            Should -HaveCount 1
    }

    It 'Should stage an edit without changing the descriptor projection source of truth' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'projection.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $stagedSid = 'S-1-5-21-1111111111-2222222222-3333333333-9013'

        $descriptor = Get-NTFSItemSecurityDescriptor -LiteralPath $testFile -Sections Access |
            Add-NTFSAccessRule -Account $stagedSid -AccessRights Read

        $descriptor.Sddl | Should -Match ([regex]::Escape($stagedSid))
        $descriptor.Sddl | Should -BeExactly $descriptor.NativeSecurity.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::Access
        )
    }
}
