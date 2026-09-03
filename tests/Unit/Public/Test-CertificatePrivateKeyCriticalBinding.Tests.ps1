. "$PSScriptRoot\EnterpriseCommandContract.ps1"

Register-EnterpriseCommandContract `
    -Name 'Test-CertificatePrivateKeyCriticalBinding' `
    -RequiredParameters @('Certificate') `
    -SupportsShouldProcess $false `
    -SupportsTargetArrays $false

Describe 'Test-CertificatePrivateKeyCriticalBinding behavior' -Tag 'Unit', 'WindowsOnly' {
    BeforeAll {
        $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
            Sort-Object -Property { [version]$_.Directory.Name } -Descending |
            Select-Object -First 1
        Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
    }

    It 'Should require a certificate rather than a thumbprint so the key is compared' {
        $command = Get-Command Test-CertificatePrivateKeyCriticalBinding -Module WindowsAccessControl

        $command.Parameters.ContainsKey('Thumbprint') | Should -BeFalse
        $command.Parameters['Certificate'].ParameterType.FullName |
            Should -BeExactly 'System.Security.Cryptography.X509Certificates.X509Certificate2'
    }

    It 'Should emit one typed record per binding that shares the private key' {
        InModuleScope WindowsAccessControl {
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
            Mock Get-WindowsCertificateCriticalBinding {
                [pscustomobject]@{
                    Binding    = 'RemoteDesktop'
                    Thumbprint = '0123456789ABCDEF0123456789ABCDEF01234567'
                    Detail     = 'bound'
                }
                [pscustomobject]@{
                    Binding    = 'HttpSys'
                    Thumbprint = 'FEDCBA9876543210FEDCBA9876543210FEDCBA98'
                    Detail     = 'bound'
                }
            }

            $result = @(Test-CertificatePrivateKeyCriticalBinding -Certificate $certificate)

            $result.Count | Should -Be 2
            $result[0].Binding | Should -BeExactly 'RemoteDesktop'
            $result[0].PSObject.TypeNames |
                Should -Contain 'WindowsAccessControl.CertificateCriticalBinding'
            Should -Invoke Get-WindowsCertificateCriticalBinding `
                -Times 1 `
                -Exactly `
                -ParameterFilter { $Certificate -eq $certificate }
        }
    }
}
