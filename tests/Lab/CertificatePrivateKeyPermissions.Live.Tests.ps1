[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseUsingScopeModifierInNewRunspaces',
    '',
    Justification = 'Remote parameters are supplied explicitly through Invoke-Command ArgumentList.'
)]
param()

BeforeAll {
    if ([string]::IsNullOrWhiteSpace($env:WAC_DOMAIN_LAB_MEMBER)) {
        throw 'WAC_DOMAIN_LAB_MEMBER must identify the disposable member server.'
    }

    $script:session = New-PSSession `
        -ComputerName $env:WAC_DOMAIN_LAB_MEMBER `
        -Authentication Kerberos `
        -ErrorAction Stop
    $script:remoteModulePath = 'C:\WindowsAccessControlLab\ModuleUnderTest'
    Invoke-Command -Session $script:session -ArgumentList $script:remoteModulePath -ScriptBlock {
        param($ModulePath)

        Remove-Item -LiteralPath $ModulePath -Recurse -Force -ErrorAction SilentlyContinue
        $null = New-Item -Path $ModulePath -ItemType Directory -Force
    }
    $moduleSource = Get-ChildItem -Path "$PSScriptRoot\..\..\output\module\WindowsAccessControl\*" |
        Sort-Object -Property { [version]$_.Name } -Descending |
        Select-Object -First 1
    Copy-Item `
        -Path (Join-Path $moduleSource.FullName '*') `
        -Destination $script:remoteModulePath `
        -ToSession $script:session `
        -Recurse `
        -Force `
        -ErrorAction Stop
    $script:remoteManifest = Join-Path $script:remoteModulePath 'WindowsAccessControl.psd1'
}

AfterAll {
    if ($script:session) {
        Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:remoteModulePath `
            -ScriptBlock {
                param($ModulePath)

                Remove-Module WindowsAccessControl -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $ModulePath -Recurse -Force -ErrorAction SilentlyContinue
            } `
            -ErrorAction SilentlyContinue
        Remove-PSSession $script:session
    }
}

Describe 'Certificate private-key DACL inspection' `
    -Tag 'DomainLab', 'WindowsOnly', 'RequiresElevation' {
    It 'Should read the exact non-exportable software CNG key without disposing the certificate' {
        $result = Invoke-Command `
            -Session $script:session `
            -ArgumentList $script:remoteManifest `
            -ScriptBlock {
                param($Manifest)

                Import-Module $Manifest -Force -ErrorAction Stop
                $certificate = @(
                    Get-ChildItem Cert:\LocalMachine\My |
                        Where-Object {
                            $_.Subject -ceq 'CN=WindowsAccessControl Lab Key' -and
                            $_.FriendlyName -ceq 'WindowsAccessControl Lab Key'
                        }
                )
                if ($certificate.Count -ne 1) {
                    throw "Expected one disposable CNG certificate, found $($certificate.Count)."
                }
                $privateKey = $null
                try {
                    $privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
                        GetRSAPrivateKey($certificate[0])
                    $providerName = $privateKey.Key.Provider.Provider
                    $keyName = $privateKey.Key.KeyName
                }
                finally {
                    if ($privateKey) {
                        $privateKey.Dispose()
                    }
                }

                $descriptor = $certificate[0] |
                    Get-CertificatePrivateKeySecurityDescriptor `
                        -ProviderName $providerName `
                        -KeyName $keyName
                $certificateStillUsable = -not [string]::IsNullOrWhiteSpace(
                    $certificate[0].Thumbprint
                )
                [pscustomobject]@{
                    Descriptor = $descriptor
                    ProviderName = $providerName
                    KeyName = $keyName
                    CertificateStillUsable = $certificateStillUsable
                }
            }

        $descriptor = $result.Descriptor
        $descriptor.PSObject.TypeNames | Should -Contain (
            'Deserialized.WindowsAccessControl.CertificatePrivateKeySecurityDescriptor'
        )
        $descriptor.ProviderName | Should -BeExactly $result.ProviderName
        $descriptor.KeyName | Should -BeExactly $result.KeyName
        $descriptor.KeyScope | Should -BeExactly 'Machine'
        $descriptor.CanonicalTarget |
            Should -Match '^CertificatePrivateKey:Cng:Machine:[0-9A-F]{64}$'
        $descriptor.Sddl | Should -Match '^D:'
        $descriptor.BinarySecurityDescriptor.Count | Should -BeGreaterThan 0
        $descriptor.PSObject.Properties.Name | Should -Not -Contain 'PrivateKey'
        $result.CertificateStillUsable | Should -BeTrue
    }
}