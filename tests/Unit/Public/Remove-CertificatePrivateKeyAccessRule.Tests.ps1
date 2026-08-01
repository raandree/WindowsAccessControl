. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Remove-CertificatePrivateKeyAccessRule' `
    -RequiredParameters @(
        'Certificate'
        'ProviderName'
        'KeyName'
        'Account'
        'AccessRights'
        'AccessControlType'
        'ConcurrencyToken'
    ) `
    -SupportsShouldProcess $true `
    -SupportsTargetArrays $false

Describe 'Remove-CertificatePrivateKeyAccessRule behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
    }

    It 'Should request the mutation boundary so the canonical write lock is taken' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            Mock Invoke-WithWindowsCertificatePrivateKeyTarget { }

            $certificate | Remove-CertificatePrivateKeyAccessRule `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyName 'TestKey' `
                -Account 'S-1-5-32-545' `
                -AccessRights Read `
                -Confirm:$false

            Should -Invoke Invoke-WithWindowsCertificatePrivateKeyTarget `
                -Times 1 `
                -Exactly `
                -ParameterFilter { $ForMutation }
        }
    }

    It 'Should pass the requested mask so removal stays exact' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            $script:requestedMask = $null
            Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                $script:requestedMask = $ArgumentList[2]
            }

            $certificate | Remove-CertificatePrivateKeyAccessRule `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyName 'TestKey' `
                -Account 'S-1-5-32-545' `
                -AccessRights Read `
                -Confirm:$false

            $script:requestedMask | Should -Be 0x00120089
        }
    }
}
