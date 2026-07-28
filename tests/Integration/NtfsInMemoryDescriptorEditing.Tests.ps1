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
}
