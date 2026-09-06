BeforeAll {
    $moduleManifest = Get-ChildItem -Path "$PSScriptRoot\..\..\..\output\module\WindowsAccessControl\*\WindowsAccessControl.psd1" |
        Sort-Object -Property { [version]$_.Directory.Name } -Descending |
        Select-Object -First 1
    Import-Module -Name $moduleManifest.FullName -ErrorAction Stop
}

Describe 'Get-WindowsBoundCertificateThumbprint' -Tag 'Unit', 'WindowsOnly' {
    It 'Should report normalized HTTP.sys, WinRM, and Remote Desktop bindings' {
        InModuleScope WindowsAccessControl {
            $httpThumbprint = '0123456789abcdef0123456789abcdef01234567'
            $winRmThumbprint = '89abcdef0123456789abcdef0123456789abcdef'
            $remoteDesktopThumbprint = 'fedcba9876543210fedcba9876543210fedcba98'

            Mock -CommandName 'netsh.exe' {
                "Certificate Hash : $httpThumbprint"
            }
            Mock Join-Path { 'netsh.exe' } -ParameterFilter {
                $Path -eq $env:SystemRoot -and
                    $ChildPath -eq 'System32\netsh.exe'
            }
            Mock Get-Service {
                [pscustomobject]@{ Status = 'Running' }
            } -ParameterFilter { $Name -eq 'WinRM' }
            Mock Get-ChildItem {
                [pscustomobject]@{
                    PSPath = 'WSMan:\localhost\Listener\Listener_1'
                }
            } -ParameterFilter { $Path -eq 'WSMan:\localhost\Listener' }
            Mock Get-ChildItem {
                [pscustomobject]@{
                    Name  = 'CertificateThumbprint'
                    Value = $winRmThumbprint.ToLowerInvariant()
                }
            } -ParameterFilter {
                $Path -eq 'WSMan:\localhost\Listener\Listener_1'
            }
            Mock Get-CimInstance {
                [pscustomobject]@{
                    SSLCertificateSHA1Hash = $remoteDesktopThumbprint
                    TerminalName           = 'RDP-Tcp'
                }
            } -ParameterFilter { $ClassName -eq 'Win32_TSGeneralSetting' }
            Mock Get-CimInstance {
                [pscustomobject]@{ ProductType = 1 }
            } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
            $previousExitCode = $global:LASTEXITCODE
            try {
                $global:LASTEXITCODE = 0

                $result = @(Get-WindowsBoundCertificateThumbprint)

                $result.Binding | Should -Be @('HttpSys', 'WinRm', 'RemoteDesktop')
                $result.Thumbprint | Should -Be @(
                    $httpThumbprint.ToUpperInvariant()
                    $winRmThumbprint.ToUpperInvariant()
                    $remoteDesktopThumbprint.ToUpperInvariant()
                )
                ($result | Where-Object Binding -EQ 'RemoteDesktop').Detail |
                    Should -Match 'RDP-Tcp'
            }
            finally {
                $global:LASTEXITCODE = $previousExitCode
            }
        }
    }
}
