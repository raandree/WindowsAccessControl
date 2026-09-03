BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    $script:module = Get-Module WindowsAccessControl
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

Describe 'Certificate private-key public identity' -Tag 'Unit', 'WindowsOnly' {
    It 'Should read the same public identity from a key and a certificate over it' {
        InModuleScope WindowsAccessControl {
            $rsa = [Security.Cryptography.RSACng]::new(2048)
            $other = [Security.Cryptography.RSACng]::new(2048)
            try {
                $certificate = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    'CN=WacUnitKeyIdentity',
                    $rsa,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.RSASignaturePadding]::Pkcs1
                ).CreateSelfSigned(
                    [datetimeoffset]::UtcNow.AddMinutes(-5),
                    [datetimeoffset]::UtcNow.AddMinutes(5))
                try {
                    $fromKey = Get-WindowsRsaPublicKeyIdentity -Key $rsa.Key
                    $fromCertificate = Get-WindowsRsaPublicKeyIdentity `
                        -Certificate $certificate
                    $fromOtherKey = Get-WindowsRsaPublicKeyIdentity -Key $other.Key

                    $fromKey | Should -Match '^RSA:[0-9A-F]+:[0-9A-F]+$'
                    $fromKey | Should -BeExactly $fromCertificate
                    $fromKey | Should -Not -BeExactly $fromOtherKey
                }
                finally {
                    $certificate.Dispose()
                }
            }
            finally {
                $rsa.Dispose()
                $other.Dispose()
            }
        }
    }

    It 'Should report no identity for a certificate that is not RSA' {
        InModuleScope WindowsAccessControl {
            $ecdsa = [Security.Cryptography.ECDsa]::Create(
                [Security.Cryptography.ECCurve+NamedCurves]::nistP256
            )
            try {
                $certificate = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    'CN=WacUnitEcdsa',
                    $ecdsa,
                    [Security.Cryptography.HashAlgorithmName]::SHA256
                ).CreateSelfSigned(
                    [datetimeoffset]::UtcNow.AddMinutes(-5),
                    [datetimeoffset]::UtcNow.AddMinutes(5))
                try {
                    $identity = Get-WindowsRsaPublicKeyIdentity -Certificate $certificate

                    $identity | Should -BeNullOrEmpty
                }
                finally {
                    $certificate.Dispose()
                }
            }
            finally {
                $ecdsa.Dispose()
            }
        }
    }

    It 'Should key the binding gate on the key rather than on a certificate' {
        InModuleScope WindowsAccessControl {
            $rsa = [Security.Cryptography.RSACng]::new(2048)
            $unrelated = [Security.Cryptography.RSACng]::new(2048)
            try {
                $bound = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    'CN=WacUnitBound',
                    $rsa,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.RSASignaturePadding]::Pkcs1
                ).CreateSelfSigned(
                    [datetimeoffset]::UtcNow.AddMinutes(-5),
                    [datetimeoffset]::UtcNow.AddMinutes(5))
                try {
                    Mock Get-WindowsMachineCertificateStoreName { 'MY' }
                    Mock Get-WindowsMachineStoreCertificate { }
                    Mock Get-WindowsServiceStoreCertificate {
                        [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                            $bound.RawData
                        )
                    }
                    Mock Get-WindowsBoundCertificateThumbprint {
                        [pscustomobject]@{
                            Binding    = 'RemoteDesktop'
                            Thumbprint = $bound.Thumbprint.ToUpperInvariant()
                            Detail     = 'Win32_TSGeneralSetting'
                        }
                    }

                    $matched = @(Get-WindowsCertificateCriticalBinding -Key $rsa.Key)
                    $unmatched = @(
                        Get-WindowsCertificateCriticalBinding -Key $unrelated.Key
                    )

                    $matched.Count | Should -Be 1
                    $matched[0].Binding | Should -BeExactly 'RemoteDesktop'
                    $unmatched.Count | Should -Be 0
                }
                finally {
                    $bound.Dispose()
                }
            }
            finally {
                $rsa.Dispose()
                $unrelated.Dispose()
            }
        }
    }
}

Describe 'Certificate private-key target resolution' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $script:persistedKeyName = 'WacUnitKey-{0}' -f [guid]::NewGuid().ToString('N')
        $script:persistedKey = $null
        try {
            $creationParameters =
                [Security.Cryptography.CngKeyCreationParameters]::new()
            $creationParameters.Provider =
                [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
            $creationParameters.ExportPolicy =
                [Security.Cryptography.CngExportPolicies]::None
            $script:persistedKey = [Security.Cryptography.CngKey]::Create(
                [Security.Cryptography.CngAlgorithm]::Rsa,
                $script:persistedKeyName,
                $creationParameters
            )
        }
        catch {
            $script:persistedKey = $null
        }
    }

    AfterAll {
        if ($script:persistedKey) {
            $script:persistedKey.Delete()
        }
    }

    It 'Should resolve a persisted key by provider, key name, and key scope' {
        if (-not $script:persistedKey) {
            Set-ItResult -Skipped -Because 'a disposable current-user CNG key could not be created'
            return
        }

        $target = & $script:module {
            param($KeyName)
            Invoke-WithWindowsCertificatePrivateKeyTarget `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyName $KeyName `
                -KeyScope User `
                -Operation { param($Target) $Target }
        } $script:persistedKeyName

        $target.ObjectType | Should -BeExactly 'CertificatePrivateKey'
        $target.KeyName | Should -BeExactly $script:persistedKeyName
        $target.KeyScope | Should -BeExactly 'User'
        $target.Server | Should -BeExactly ([Environment]::MachineName)
        $target.CertificateThumbprint | Should -BeNullOrEmpty
        $target.CanonicalTarget |
            Should -Match '^CertificatePrivateKey:Cng:User:[0-9A-F]{64}$'
    }

    It 'Should refuse to answer from the other key store' {
        if (-not $script:persistedKey) {
            Set-ItResult -Skipped -Because 'a disposable current-user CNG key could not be created'
            return
        }

        {
            & $script:module {
                param($KeyName)
                Invoke-WithWindowsCertificatePrivateKeyTarget `
                    -ProviderName 'Microsoft Software Key Storage Provider' `
                    -KeyName $KeyName `
                    -KeyScope Machine `
                    -Operation { param($Target) $Target }
            } $script:persistedKeyName
        } | Should -Throw '*could not be opened*'
    }

    It 'Should refuse a key-addressed target in an unsupported provider' {
        {
            & $script:module {
                Invoke-WithWindowsCertificatePrivateKeyTarget `
                    -ProviderName 'Microsoft Smart Card Key Storage Provider' `
                    -KeyName 'WacUnitMissingKey' `
                    -KeyScope Machine `
                    -Operation { param($Target) $Target }
            }
        } | Should -Throw '*not admitted*'
    }

    It 'Should refuse a key that no longer has the expected canonical identity' {
        if (-not $script:persistedKey) {
            Set-ItResult -Skipped -Because 'a disposable current-user CNG key could not be created'
            return
        }

        # A delete and recreate under the same key name produces a different
        # container, which is exactly what this pin rejects.
        {
            & $script:module {
                param($KeyName)
                Invoke-WithWindowsCertificatePrivateKeyTarget `
                    -ProviderName 'Microsoft Software Key Storage Provider' `
                    -KeyName $KeyName `
                    -KeyScope User `
                    -ExpectedCanonicalTarget (
                        'CertificatePrivateKey:Cng:User:' + ('FFFFFFFF' * 8)
                    ) `
                    -Operation { param($Target) $Target }
            } $script:persistedKeyName
        } | Should -Throw '*no longer has the expected canonical identity*'
    }
}