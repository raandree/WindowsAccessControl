. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Set-CertificatePrivateKeySecurityDescriptor' `
    -RequiredParameters @(
        'Certificate'
        'ProviderName'
        'KeyName'
        'KeyScope'
        'Sddl'
        'ConcurrencyToken'
        'ExpectedCanonicalTarget'
        'PassThru'
    ) `
    -SupportsShouldProcess $true `
    -SupportsTargetArrays $false

Describe 'Set-CertificatePrivateKeySecurityDescriptor behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    }

    It 'Should request the mutation boundary so the canonical write lock is taken' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            Mock Invoke-WithWindowsCertificatePrivateKeyTarget { }

            $certificate | Set-CertificatePrivateKeySecurityDescriptor `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyName 'TestKey' `
                -Sddl 'D:P(A;;FA;;;SY)(A;;FA;;;BA)' `
                -Confirm:$false

            Should -Invoke Invoke-WithWindowsCertificatePrivateKeyTarget `
                -Times 1 `
                -Exactly `
                -ParameterFilter { $ForMutation }
        }
    }

    It 'Should pin the resolved key to the expected canonical identity' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            Mock Invoke-WithWindowsCertificatePrivateKeyTarget { }

            $certificate | Set-CertificatePrivateKeySecurityDescriptor `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyName 'TestKey' `
                -Sddl 'D:P(A;;FA;;;SY)(A;;FA;;;BA)' `
                -ExpectedCanonicalTarget 'CertificatePrivateKey:Cng:Machine:0' `
                -Confirm:$false

            Should -Invoke Invoke-WithWindowsCertificatePrivateKeyTarget `
                -Times 1 `
                -Exactly `
                -ParameterFilter {
                    $ExpectedCanonicalTarget -ceq 'CertificatePrivateKey:Cng:Machine:0'
                }
        }
    }

    It 'Should drop a caller owner and group because only the access section is written' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            $ephemeralKey = [Security.Cryptography.CngKey]::Create(
                [Security.Cryptography.CngAlgorithm]::Rsa
            )
            try {
                $current = [Security.AccessControl.RawSecurityDescriptor]::new(
                    'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
                )
                $currentBytes = [byte[]]::new($current.BinaryLength)
                $current.GetBinaryForm($currentBytes, 0)
                $script:writtenSddl = $null
                Mock Get-WindowsCngKeySecurityDescriptor { , $currentBytes }
                Mock Set-WindowsCngKeySecurityDescriptor {
                    $written = [Security.AccessControl.RawSecurityDescriptor]::new(
                        $SecurityDescriptor,
                        0
                    )
                    $script:writtenSddl = $written.GetSddlForm('All')
                    , $SecurityDescriptor
                }
                Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                    $target = [pscustomobject]@{
                        CanonicalTarget = 'CertificatePrivateKey:Cng:Machine:0'
                    }
                    & $Operation $target $ephemeralKey @ArgumentList
                }

                $certificate | Set-CertificatePrivateKeySecurityDescriptor `
                    -ProviderName 'Microsoft Software Key Storage Provider' `
                    -KeyName 'TestKey' `
                    -Sddl 'O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)' `
                    -Confirm:$false

                $script:writtenSddl | Should -Not -BeLike '*O:*'
                $script:writtenSddl | Should -Not -BeLike '*G:*'
                $script:writtenSddl | Should -BeLike '*BU*'

                # A SACL in the caller's SDDL must not survive into the binary
                # form either: the provider is written with the access section
                # alone and audit policy is outside this contract.
                $certificate | Set-CertificatePrivateKeySecurityDescriptor `
                    -ProviderName 'Microsoft Software Key Storage Provider' `
                    -KeyName 'TestKey' `
                    -Sddl 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)S:P(AU;SA;FA;;;WD)' `
                    -Confirm:$false

                $script:writtenSddl | Should -Not -BeLike '*S:*'
                $script:writtenSddl | Should -BeLike '*BU*'

                {
                    $certificate | Set-CertificatePrivateKeySecurityDescriptor `
                        -ProviderName 'Microsoft Software Key Storage Provider' `
                        -KeyName 'TestKey' `
                        -Sddl 'O:BAG:SY' `
                        -Confirm:$false
                } | Should -Throw -ExpectedMessage '*non-null DACL*'
            }
            finally {
                $ephemeralKey.Dispose()
            }
        }
    }
}
