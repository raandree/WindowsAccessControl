BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1

    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'WindowsAccessControl' -Force -ErrorAction SilentlyContinue
}

Describe 'Resolve-WindowsIdentity' -Tag 'Unit', 'WindowsOnly' {
    It 'Should resolve a well-known SID and preserve its SID value' {
        $result = Resolve-WindowsIdentity -Identity 'S-1-1-0'

        $result.PSObject.TypeNames | Should -Contain 'WindowsAccessControl.Identity'
        $result.SID | Should -Be 'S-1-1-0'
        $result.IsResolved | Should -BeTrue
        $result.Account | Should -Not -BeNullOrEmpty
    }
}