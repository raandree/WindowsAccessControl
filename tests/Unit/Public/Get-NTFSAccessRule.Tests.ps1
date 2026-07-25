BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\NTFSPermission\*\NTFSPermission.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'NTFSPermission' -Force -ErrorAction SilentlyContinue
}

Describe 'Get-NTFSAccessRule orphan handling' -Tag 'Unit', 'WindowsOnly' {
    BeforeEach {
        $script:testFile = Join-Path -Path $TestDrive -ChildPath 'orphaned.txt'
        Set-Content -LiteralPath $script:testFile -Value 'test'
        $script:orphanSid = 'S-1-5-21-1111111111-2222222222-3333333333-4444'
        $security = [System.Security.AccessControl.FileSecurity]::new()
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($script:orphanSid),
            [System.Security.AccessControl.FileSystemRights]::Read,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $security.AddAccessRule($rule)
        Mock -ModuleName NTFSPermission -CommandName Get-Acl -MockWith { $security }
    }

    It 'Should return an unresolvable SID without aborting enumeration' {
        $result = Get-NTFSAccessRule -LiteralPath $script:testFile -Orphaned

        $result | Should -HaveCount 1
        $result.SID | Should -Be $script:orphanSid
        $result.Account | Should -BeNullOrEmpty
        $result.IsOrphaned | Should -BeTrue
    }
}