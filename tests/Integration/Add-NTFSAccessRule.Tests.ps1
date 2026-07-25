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

Describe 'Add-NTFSAccessRule' -Tag 'Integration', 'WindowsOnly' {
    It 'Should add and return an explicit access rule from file pipeline input' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'pipeline-input.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        $addedRule = Get-Item -LiteralPath $testFile |
            Add-NTFSAccessRule -Account $script:currentSid -AccessRights Read -PassThru

        $storedRule = Get-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -ExcludeInherited

        $addedRule.PSObject.TypeNames | Should -Contain 'NTFSPermission.AccessRule'
        $addedRule.Path | Should -Be (Get-Item -LiteralPath $testFile).FullName
        $addedRule.SID | Should -Be $script:currentSid
        ($storedRule.AccessRights -band [System.Security.AccessControl.FileSystemRights]::Read) |
            Should -Be ([System.Security.AccessControl.FileSystemRights]::Read)
        $storedRule.IsInherited | Should -BeFalse
    }

    It 'Should not persist a rule when WhatIf is used' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'what-if.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        Add-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -AccessRights Write -WhatIf

        Get-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -ExcludeInherited |
            Should -BeNullOrEmpty
    }

    It 'Should preserve owner and group sections during a DACL change' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'preserve-sections.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $sections = (
            [System.Security.AccessControl.AccessControlSections]::Owner -bor
            [System.Security.AccessControl.AccessControlSections]::Group
        )
        $before = (Get-Acl -LiteralPath $testFile).GetSecurityDescriptorSddlForm($sections)

        Add-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -AccessRights Read

        $after = (Get-Acl -LiteralPath $testFile).GetSecurityDescriptorSddlForm($sections)
        $after | Should -BeExactly $before
    }
}