BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'Resolve-WindowsIdentity' -Tag 'Unit', 'WindowsOnly' {
    It 'Should resolve a well-known SID and preserve its SID value' {
        $result = Resolve-WindowsIdentity -Identity 'S-1-1-0'

        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.Identity'
        $result.SID | Should -Be 'S-1-1-0'
        $result.IsResolved | Should -BeTrue
        $result.Account | Should -Not -BeNullOrEmpty
    }

    It 'Should accept its own identity output through the pipeline' {
        $original = Resolve-WindowsIdentity -Identity 'S-1-1-0'

        $result = $original | Resolve-WindowsIdentity

        $result.SID | Should -Be 'S-1-1-0'
        $result.IdentityReference | Should -BeOfType (
            [System.Security.Principal.SecurityIdentifier]
        )
    }

    It 'Should accept SID and IdentityReference properties from pipeline objects' {
        $sidObject = [pscustomobject]@{ SID = 'S-1-1-0' }
        $identityObject = [pscustomobject]@{
            IdentityReference = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        }

        $results = @($sidObject, $identityObject) | Resolve-WindowsIdentity

        $results.SID | Should -Be @('S-1-1-0', 'S-1-5-18')
    }

    It 'Should preserve an orphaned but valid SID' {
        $orphanSid = 'S-1-5-21-111111111-222222222-333333333-424242'

        $result = Resolve-WindowsIdentity -Identity $orphanSid

        $result.SID | Should -Be $orphanSid
        $result.IsResolved | Should -BeFalse
        $result.Account | Should -BeNullOrEmpty
    }
}
