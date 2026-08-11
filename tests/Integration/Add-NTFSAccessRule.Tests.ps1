# Multi-account, pipeline, and section-preservation evidence (FR-3, FR-15, NFR-3, NFR-6).
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

Describe 'Add-NTFSAccessRule' -Tag 'Integration', 'WindowsOnly' {
    It 'Should bind a hexadecimal literal mask the enumeration cannot name' {
        # A hexadecimal literal is the one form the engine converts before the
        # rights transformation attribute runs. The same value written as a
        # variable or a decimal literal always bound, which is why this defect
        # survived the tests that already covered unnameable masks.
        $testFile = Join-Path -Path $TestDrive -ChildPath 'hex-literal-mask.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        { Add-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -AccessRights 0x10000000 -WhatIf } |
            Should -Not -Throw
    }

    It 'Should still refuse an unknown rights name' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'unknown-rights-name.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        { Add-NTFSAccessRule -LiteralPath $testFile -Account 'S-1-1-0' -AccessRights 'NotARight' -WhatIf } |
            Should -Throw -ExpectedMessage '*NotARight*FileSystemRights*'
    }

    It 'Should add and return an explicit access rule from file pipeline input' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'pipeline-input.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        $addedRule = Get-Item -LiteralPath $testFile |
            Add-NTFSAccessRule -Account $script:currentSid -AccessRights Read -PassThru

        $storedRule = Get-NTFSAccessRule -LiteralPath $testFile -Account $script:currentSid -ExcludeInherited

        $addedRule.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.AccessRule'
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

    It 'Should add access rules for multiple accounts with one descriptor write' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'multiple-accounts.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $accounts = @(
            'S-1-5-21-4242424242-4242424242-4242424242-4242'
            'S-1-5-21-4242424242-4242424242-4242424242-4243'
        )
        $addParameters = @{
            LiteralPath = $testFile
            Account     = $accounts
            AccessRights = 'Read'
            PassThru    = $true
        }

        $addedRules = @(Add-NTFSAccessRule @addParameters)
        $storedRules = @(Get-NTFSAccessRule -LiteralPath $testFile -ExcludeInherited |
            Where-Object SID -In $accounts)

        $addedRules | Should -HaveCount 2
        $storedRules | Should -HaveCount 2
        foreach ($account in $accounts) {
            $addedRules.SID | Should -Contain $account
        }
    }

    It 'Should add one access rule for duplicate account inputs' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'duplicate-accounts.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        $account = 'S-1-5-21-4242424242-4242424242-4242424242-4244'
        $addParameters = @{
            LiteralPath  = $testFile
            Account      = @($account, $account)
            AccessRights = 'Read'
            PassThru     = $true
        }
        $getParameters = @{
            LiteralPath     = $testFile
            Account         = $account
            ExcludeInherited = $true
        }

        $addedRules = @(Add-NTFSAccessRule @addParameters)
        $storedRules = @(Get-NTFSAccessRule @getParameters)

        $addedRules | Should -HaveCount 1
        $storedRules | Should -HaveCount 1
    }
}
