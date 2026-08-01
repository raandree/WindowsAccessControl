. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Add-CertificatePrivateKeyAccessRule' `
    -RequiredParameters @(
        'Certificate'
        'ProviderName'
        'KeyName'
        'Account'
        'AccessRights'
        'ConcurrencyToken'
        'PassThru'
    ) `
    -SupportsShouldProcess $true `
    -SupportsTargetArrays $false

Describe 'Add-CertificatePrivateKeyAccessRule behavior' -Tag 'Unit', 'WindowsOnly' {
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

            $certificate | Add-CertificatePrivateKeyAccessRule `
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

    It 'Should deduplicate repeated accounts before staging the candidate' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            $script:stagedIdentities = $null
            Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                $script:stagedIdentities = $ArgumentList[1]
            }

            $certificate | Add-CertificatePrivateKeyAccessRule `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyName 'TestKey' `
                -Account 'S-1-5-32-545', 'S-1-5-32-545', 'S-1-5-18' `
                -AccessRights Read `
                -Confirm:$false

            @($script:stagedIdentities).Count | Should -Be 2
        }
    }

    It 'Should not expose a way to add a deny rule' {
        $command = Get-Command Add-CertificatePrivateKeyAccessRule -Module WindowsAccessControl

        $command.Parameters.ContainsKey('AccessControlType') | Should -BeFalse
    }

    It 'Should stage the caller concurrency token only when it is supplied' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            $script:stagedToken = 'unset'
            Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                $script:stagedToken = $ArgumentList[3]
            }

            $certificate | Add-CertificatePrivateKeyAccessRule `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyName 'TestKey' `
                -Account 'S-1-5-32-545' `
                -AccessRights Read `
                -Confirm:$false
            $script:stagedToken | Should -BeNullOrEmpty

            $certificate | Add-CertificatePrivateKeyAccessRule `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyName 'TestKey' `
                -Account 'S-1-5-32-545' `
                -AccessRights Read `
                -ConcurrencyToken 'ABC123' `
                -Confirm:$false
            $script:stagedToken | Should -BeExactly 'ABC123'
        }
    }

    It 'Should pass the certificate through so the binding gate can compare keys' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            $script:bindingCertificate = $null
            Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                $script:bindingCertificate = $ArgumentList[4]
            }

            $certificate | Add-CertificatePrivateKeyAccessRule `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyName 'TestKey' `
                -Account 'S-1-5-32-545' `
                -AccessRights Read `
                -Confirm:$false

            $script:bindingCertificate | Should -Be $certificate
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
                    'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
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

                $certificate | Add-CertificatePrivateKeyAccessRule `
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
