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

Describe 'Set-NTFSItemOwner' -Tag 'Integration', 'WindowsOnly' {
    It 'Should set the owner from file pipeline input and return it' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'set-owner.txt'
        Set-Content -LiteralPath $testFile -Value 'test'

        $result = Get-Item -LiteralPath $testFile |
            Set-NTFSItemOwner -Account $script:currentSid -PassThru -Confirm:$false

        $result.SID | Should -Be $script:currentSid
        (Get-NTFSItemOwner -LiteralPath $testFile).SID | Should -Be $script:currentSid
    }
}