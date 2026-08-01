. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Get-CertificatePrivateKeyAccessRule' `
    -RequiredParameters @('Certificate', 'ProviderName', 'KeyName', 'Account') `
    -SupportsShouldProcess $false `
    -SupportsTargetArrays $false

Describe 'Get-CertificatePrivateKeyAccessRule behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
    }

    It 'Should read the key without requesting the mutation boundary' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            Mock Invoke-WithWindowsCertificatePrivateKeyTarget { }

            $null = $certificate | Get-CertificatePrivateKeyAccessRule `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyName 'TestKey'

            Should -Invoke Invoke-WithWindowsCertificatePrivateKeyTarget `
                -Times 1 `
                -Exactly `
                -ParameterFilter { -not $ForMutation }
        }
    }

    It 'Should emit typed rules with the effective mask and the raw stored mask' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            $ephemeralKey = [Security.Cryptography.CngKey]::Create(
                [Security.Cryptography.CngAlgorithm]::Rsa
            )
            try {
                $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
                    'D:P(A;;0x80120089;;;BU)'
                )
                $descriptorBytes = [byte[]]::new($descriptor.BinaryLength)
                $descriptor.GetBinaryForm($descriptorBytes, 0)
                Mock Get-WindowsCngKeySecurityDescriptor { , $descriptorBytes }
                Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                    $target = [pscustomobject]@{
                        ObjectType            = 'CertificatePrivateKey'
                        Path                  = 'ABC'
                        ProviderName          = 'Microsoft Software Key Storage Provider'
                        KeyName               = 'TestKey'
                        KeyScope              = 'Machine'
                        CertificateThumbprint = 'ABC'
                        CanonicalTarget       = 'CertificatePrivateKey:Cng:Machine:0'
                    }
                    & $Operation $target $ephemeralKey @ArgumentList
                }

                $rules = @(
                    $certificate | Get-CertificatePrivateKeyAccessRule `
                        -ProviderName 'Microsoft Software Key Storage Provider' `
                        -KeyName 'TestKey'
                )

                $rules.Count | Should -Be 1
                $rules[0].SID | Should -BeExactly 'S-1-5-32-545'
                $rules[0].AccessMask | Should -Be 0x80120089L
                $rules[0].EffectiveAccessMask | Should -Be 0x00120089L
                [string]$rules[0].AccessRights | Should -BeExactly 'Read'
                $rules[0].PSObject.TypeNames |
                    Should -Contain 'WindowsAccessControl.CertificatePrivateKeyAccessRule'
            }
            finally {
                $ephemeralKey.Dispose()
            }
        }
    }
}
