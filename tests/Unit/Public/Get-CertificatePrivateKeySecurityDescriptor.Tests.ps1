. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Get-CertificatePrivateKeySecurityDescriptor' `
    -RequiredParameters @('Certificate', 'ProviderName', 'KeyName', 'KeyScope') `
    -SupportsShouldProcess $false `
    -SupportsTargetArrays $false

Describe 'Get-CertificatePrivateKeySecurityDescriptor behavior' `
    -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
    }

    It 'Should delegate one exact certificate, provider, and key identity' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            $script:expected = [pscustomobject]@{
                ObjectType = 'CertificatePrivateKey'
                ProviderName = 'Microsoft Software Key Storage Provider'
                KeyName = 'TestKey'
                KeyScope = 'Machine'
                Sddl = 'D:(A;;FA;;;SY)'
            }
            $script:expected.PSObject.TypeNames.Insert(
                0,
                'WindowsAccessControl.CertificatePrivateKeySecurityDescriptor'
            )
            Mock Invoke-WithWindowsCertificatePrivateKeyTarget {
                $script:expected
            }

            $result = $certificate | Get-CertificatePrivateKeySecurityDescriptor `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyName 'TestKey'

            $result | Should -Be $script:expected
            $result.PSObject.TypeNames |
                Should -Contain 'WindowsAccessControl.CertificatePrivateKeySecurityDescriptor'
            Should -Invoke Invoke-WithWindowsCertificatePrivateKeyTarget `
                -Times 1 `
                -Exactly `
                -ParameterFilter {
                    $Certificate -eq $certificate -and
                        $ProviderName -ceq 'Microsoft Software Key Storage Provider' -and
                        $KeyName -ceq 'TestKey'
                }
        }
    }

    It 'Should reject an unsupported provider before key access' {
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()

        {
            $certificate | Get-CertificatePrivateKeySecurityDescriptor `
                -ProviderName 'Microsoft Platform Crypto Provider' `
                -KeyName 'TestKey'
        } | Should -Throw -ExpectedMessage '*Only persisted RSA keys*'
    }

    It 'Should reject a certificate without a private key' {
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()

        {
            $certificate | Get-CertificatePrivateKeySecurityDescriptor `
                -ProviderName 'Microsoft Software Key Storage Provider' `
                -KeyName 'TestKey'
        } | Should -Throw -ExpectedMessage '*does not have an accessible private key*'
    }

    It 'Should reject an ephemeral RSACng certificate key' {
        $rsa = [Security.Cryptography.RSACng]::new(2048)
        $certificate = $null
        try {
            $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Ephemeral CNG Unit Test',
                $rsa,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $certificate = $request.CreateSelfSigned(
                [datetimeoffset]::UtcNow.AddMinutes(-1),
                [datetimeoffset]::UtcNow.AddHours(1)
            )

            {
                $certificate | Get-CertificatePrivateKeySecurityDescriptor `
                    -ProviderName 'Microsoft Software Key Storage Provider' `
                    -KeyName 'NotPersisted'
            } | Should -Throw -ExpectedMessage '*Ephemeral or unstable*'
        }
        finally {
            if ($certificate) {
                $certificate.Dispose()
            }
            $rsa.Dispose()
        }
    }
}