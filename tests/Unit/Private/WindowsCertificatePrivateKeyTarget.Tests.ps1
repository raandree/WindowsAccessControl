BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    $script:module = Get-Module WindowsAccessControl
}

AfterAll {
    Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
}

Describe 'Certificate private-key canonical identity' -Tag 'Unit', 'WindowsOnly' {
    It 'Should hash length-bounded provider identity without embedding raw names' {
        $first = & $script:module {
            Get-WindowsCertificatePrivateKeyCanonicalTarget `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -UniqueName 'container:one' `
                -KeyScope Machine
        }
        $second = & $script:module {
            Get-WindowsCertificatePrivateKeyCanonicalTarget `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -UniqueName 'container:two' `
                -KeyScope Machine
        }

        $first | Should -Match '^CertificatePrivateKey:Cng:Machine:[0-9A-F]{64}$'
        $first | Should -Not -Match 'Microsoft|container'
        $first | Should -Not -BeExactly $second
    }
}