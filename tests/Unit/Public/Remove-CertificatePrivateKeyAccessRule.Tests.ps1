. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Remove-CertificatePrivateKeyAccessRule' `
    -RequiredParameters @(
        'Certificate'
        'ProviderName'
        'KeyName'
        'KeyScope'
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

    It 'Should warn when the request matches no rule so a revocation cannot report a false success' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            $ephemeralKey = [Security.Cryptography.CngKey]::Create(
                [Security.Cryptography.CngAlgorithm]::Rsa
            )
            try {
                $stored = [Security.AccessControl.RawSecurityDescriptor]::new(
                    'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)'
                )
                $storedBytes = [byte[]]::new($stored.BinaryLength)
                $stored.GetBinaryForm($storedBytes, 0)
                Mock Get-WindowsCngKeySecurityDescriptor { , $storedBytes }
                Mock Set-WindowsCngKeySecurityDescriptor { , $SecurityDescriptor }
                Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                    $target = [pscustomobject]@{
                        CanonicalTarget = 'CertificatePrivateKey:Cng:Machine:0'
                    }
                    & $Operation $target $ephemeralKey @ArgumentList
                }

                $certificate | Remove-CertificatePrivateKeyAccessRule `
                    -ProviderName 'Microsoft Software Key Storage Provider' `
                    -KeyName 'TestKey' `
                    -Account 'S-1-5-32-545' `
                    -AccessRights Read `
                    -Confirm:$false `
                    -WarningVariable removalWarning `
                    -WarningAction SilentlyContinue

                @($removalWarning) | Should -Not -BeNullOrEmpty
                [string]$removalWarning | Should -BeLike '*matched the requested*'
            }
            finally {
                $ephemeralKey.Dispose()
            }
        }
    }

    It 'Should name only the accounts a partial removal left unchanged' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            $ephemeralKey = [Security.Cryptography.CngKey]::Create(
                [Security.Cryptography.CngAlgorithm]::Rsa
            )
            try {
                # Users holds exactly Read and is removed; Guests holds full
                # control, so an exact Read removal leaves it untouched.
                $stored = [Security.AccessControl.RawSecurityDescriptor]::new(
                    'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)(A;;FA;;;BG)'
                )
                $storedBytes = [byte[]]::new($stored.BinaryLength)
                $stored.GetBinaryForm($storedBytes, 0)
                Mock Get-WindowsCngKeySecurityDescriptor { , $storedBytes }
                Mock Set-WindowsCngKeySecurityDescriptor { , $SecurityDescriptor }
                Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                    $target = [pscustomobject]@{
                        CanonicalTarget = 'CertificatePrivateKey:Cng:Machine:0'
                    }
                    & $Operation $target $ephemeralKey @ArgumentList
                }

                $certificate | Remove-CertificatePrivateKeyAccessRule `
                    -ProviderName 'Microsoft Software Key Storage Provider' `
                    -KeyName 'TestKey' `
                    -Account 'S-1-5-32-545', 'S-1-5-32-546' `
                    -AccessRights Read `
                    -Confirm:$false `
                    -WarningVariable removalWarning `
                    -WarningAction SilentlyContinue

                [string]$removalWarning | Should -BeLike '*S-1-5-32-546*' -Because 'the unmatched account must be named'
                [string]$removalWarning | Should -Not -BeLike '*S-1-5-32-545*' -Because 'the matched account was removed'
            }
            finally {
                $ephemeralKey.Dispose()
            }
        }
    }

    It 'Should derive a concurrency token from its own read when the caller supplies none' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            $ephemeralKey = [Security.Cryptography.CngKey]::Create(
                [Security.Cryptography.CngAlgorithm]::Rsa
            )
            try {
                $stored = [Security.AccessControl.RawSecurityDescriptor]::new(
                    'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)'
                )
                $storedBytes = [byte[]]::new($stored.BinaryLength)
                $stored.GetBinaryForm($storedBytes, 0)
                $script:observedToken = $null
                Mock Get-WindowsCngKeySecurityDescriptor { , $storedBytes }
                Mock Set-WindowsCngKeySecurityDescriptor {
                    $script:observedToken = $ExpectedConcurrencyToken
                    , $SecurityDescriptor
                }
                Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                    $target = [pscustomobject]@{
                        CanonicalTarget = 'CertificatePrivateKey:Cng:Machine:0'
                    }
                    & $Operation $target $ephemeralKey @ArgumentList
                }

                $certificate | Remove-CertificatePrivateKeyAccessRule `
                    -ProviderName 'Microsoft Software Key Storage Provider' `
                    -KeyName 'TestKey' `
                    -Account 'S-1-5-32-545' `
                    -AccessRights Read `
                    -Confirm:$false

                $expected = Get-WindowsSecurityDescriptorConcurrencyToken -Sddl (
                    $stored.GetSddlForm(
                        [Security.AccessControl.AccessControlSections]::Access
                    )
                )
                $script:observedToken | Should -BeExactly $expected
            }
            finally {
                $ephemeralKey.Dispose()
            }
        }
    }
}
