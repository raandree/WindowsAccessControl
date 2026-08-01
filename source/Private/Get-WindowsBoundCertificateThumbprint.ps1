function Get-WindowsBoundCertificateThumbprint {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # HTTP.sys owns every Internet Information Services, WinRM HTTPS, and
    # self-hosted TLS binding. The label text is localized, so a hash is matched
    # by shape rather than by parsing a named field. A netsh failure throws so
    # the gate fails closed.
    $netshPath = Join-Path $env:SystemRoot 'System32\netsh.exe'
    $netshOutput = & $netshPath http show sslcert 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw [InvalidOperationException]::new(
            "Unable to enumerate HTTP.sys certificate bindings; 'netsh http show sslcert' returned exit code $LASTEXITCODE."
        )
    }
    foreach ($match in [regex]::Matches(
            (@($netshOutput) -join "`n"),
            '(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])'
        )) {
        [pscustomobject]@{
            Binding    = 'HttpSys'
            Thumbprint = $match.Value.ToUpperInvariant()
            Detail     = 'An HTTP.sys TLS endpoint (Internet Information Services, WinRM HTTPS, or a self-hosted listener) uses this key.'
        }
    }

    # A stopped WinRM service cannot serve a listener, so only a genuine
    # not-installed or stopped service skips the probe. Any other failure throws.
    $winRmService = $null
    try {
        $winRmService = Get-Service -Name WinRM -ErrorAction Stop
    }
    catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        $winRmService = $null
    }
    if ($winRmService -and $winRmService.Status -eq 'Running') {
        foreach ($listener in Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop) {
            $settings = Get-ChildItem -Path $listener.PSPath -ErrorAction Stop
            $thumbprint = [string](
                $settings | Where-Object Name -EQ 'CertificateThumbprint'
            ).Value
            $thumbprint = ($thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
            if ($thumbprint.Length -eq 40) {
                [pscustomobject]@{
                    Binding    = 'WinRm'
                    Thumbprint = $thumbprint
                    Detail     = 'A WinRM HTTPS listener uses this key.'
                }
            }
        }
    }

    foreach ($setting in @(
            Get-CimInstance `
                -Namespace 'root/cimv2/TerminalServices' `
                -ClassName 'Win32_TSGeneralSetting' `
                -ErrorAction Stop
        )) {
        $thumbprint = (([string]$setting.SSLCertificateSHA1Hash) -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        if ($thumbprint.Length -eq 40) {
            [pscustomobject]@{
                Binding    = 'RemoteDesktop'
                Thumbprint = $thumbprint
                Detail     = "The Remote Desktop listener '$($setting.TerminalName)' uses this key."
            }
        }
    }

    # Active Directory Domain Services selects an LDAPS certificate itself, so
    # every server-authentication certificate on a domain controller counts.
    if ((Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType -eq 2) {
        foreach ($storeName in 'NTDS\My', 'My') {
            foreach ($certificate in @(
                    Get-WindowsMachineStoreCertificate -StoreName $storeName -Required
                )) {
                if (Test-WindowsCertificateServerAuthentication -Certificate $certificate) {
                    [pscustomobject]@{
                        Binding    = 'DirectoryServices'
                        Thumbprint = $certificate.Thumbprint.ToUpperInvariant()
                        Detail     = "A server-authentication certificate in '$storeName' on a domain controller can serve LDAPS with this key."
                    }
                }
            }
        }
    }
}
