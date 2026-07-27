BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-NTFSAccessRule orphan handling' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:testFile = Join-Path -Path $TestDrive -ChildPath 'orphaned.txt'
        Set-Content -LiteralPath $script:testFile -Value 'test'
        $script:orphanSid = 'S-1-5-21-1111111111-2222222222-3333333333-4444'
        $script:testSecurity = [System.Security.AccessControl.FileSecurity]::new()
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($script:orphanSid),
            [System.Security.AccessControl.FileSystemRights]::Read,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $script:testSecurity.AddAccessRule($rule)
        Mock -ModuleName WindowsAccessControl -CommandName Get-Acl -MockWith {
            $script:testSecurity
        }
    }

    It 'Should return an unresolvable SID without aborting enumeration' {
        $result = Get-NTFSAccessRule -LiteralPath $script:testFile -Orphaned

        $result | Should -HaveCount 1
        $result.SID | Should -Be $script:orphanSid
        $result.Account | Should -BeNullOrEmpty
        $result.IsOrphaned | Should -BeTrue
    }

    It 'Should ignore non-standard ACEs that are absent from managed access rules' {
        $rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $script:testSecurity.GetSecurityDescriptorBinaryForm(),
            0
        )
        $rawAcl = [System.Security.AccessControl.RawAcl]::new(
            [byte]4,
            $rawDescriptor.DiscretionaryAcl.Count + 1
        )
        $objectAce = [System.Security.AccessControl.ObjectAce]::new(
            [System.Security.AccessControl.AceFlags]::None,
            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            1,
            [System.Security.Principal.SecurityIdentifier]::new($script:orphanSid),
            [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
            [guid]::NewGuid(),
            [guid]::Empty,
            $false,
            $null
        )
        $rawAcl.InsertAce(0, $objectAce)
        for ($aceIndex = 0; $aceIndex -lt $rawDescriptor.DiscretionaryAcl.Count; $aceIndex++) {
            $rawAcl.InsertAce($aceIndex + 1, $rawDescriptor.DiscretionaryAcl[$aceIndex])
        }
        $rawDescriptor.DiscretionaryAcl = $rawAcl
        $binaryDescriptor = [byte[]]::new($rawDescriptor.BinaryLength)
        $rawDescriptor.GetBinaryForm($binaryDescriptor, 0)
        $script:testSecurity.SetSecurityDescriptorBinaryForm(
            $binaryDescriptor,
            [System.Security.AccessControl.AccessControlSections]::Access
        )

        $result = Get-NTFSAccessRule -LiteralPath $script:testFile -Orphaned

        $result | Should -HaveCount 1
        $result.SID | Should -Be $script:orphanSid
    }

    It 'Should not resolve provenance when inherited rules are excluded' {
        $rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $script:testSecurity.GetSecurityDescriptorBinaryForm(),
            0
        )
        $rawAcl = [System.Security.AccessControl.RawAcl]::new(
            [byte]4,
            $rawDescriptor.DiscretionaryAcl.Count + 1
        )
        for ($aceIndex = 0; $aceIndex -lt $rawDescriptor.DiscretionaryAcl.Count; $aceIndex++) {
            $rawAcl.InsertAce($aceIndex, $rawDescriptor.DiscretionaryAcl[$aceIndex])
        }
        $rawAcl.InsertAce(
            $rawAcl.Count,
            [System.Security.AccessControl.CommonAce]::new(
                [System.Security.AccessControl.AceFlags]::Inherited,
                [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                1,
                [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                $false,
                $null
            )
        )
        $rawDescriptor.DiscretionaryAcl = $rawAcl
        $binaryDescriptor = [byte[]]::new($rawDescriptor.BinaryLength)
        $rawDescriptor.GetBinaryForm($binaryDescriptor, 0)
        $script:testSecurity.SetSecurityDescriptorBinaryForm(
            $binaryDescriptor,
            [System.Security.AccessControl.AccessControlSections]::Access
        )
        Mock -ModuleName WindowsAccessControl -CommandName Get-Acl -MockWith {
            Remove-Item -LiteralPath $script:testFile -Force
            $script:testSecurity
        }

        $result = Get-NTFSAccessRule `
            -LiteralPath $script:testFile `
            -ExcludeInherited `
            -Orphaned

        $result | Should -HaveCount 1
        ($null -eq $result.InheritedFrom) | Should -BeTrue
    }
}
