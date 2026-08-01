function Get-WindowsCertificateCriticalBinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    # The write target is the private key, not the certificate. A renewal that
    # reuses the key produces a second certificate over the same key, so a
    # thumbprint comparison alone would miss a live binding. Every bound
    # thumbprint is therefore resolved to its certificate and compared by public
    # key, which identifies the private key without opening a key handle.
    $storeNames = 'My', 'WebHosting', 'Remote Desktop', 'NTDS\My'
    $machineCertificates = @{}
    foreach ($storeName in $storeNames) {
        foreach ($stored in @(Get-WindowsMachineStoreCertificate -StoreName $storeName)) {
            $thumbprint = $stored.Thumbprint.ToUpperInvariant()
            if (-not $machineCertificates.ContainsKey($thumbprint)) {
                $machineCertificates[$thumbprint] = $stored
            }
        }
    }

    foreach ($binding in @(Get-WindowsBoundCertificateThumbprint)) {
        if (-not $machineCertificates.ContainsKey($binding.Thumbprint)) {
            throw [InvalidOperationException]::new(
                (
                    "Certificate '$($binding.Thumbprint)' serves the $($binding.Binding) binding but was " +
                    "not found in any local machine store ($($storeNames -join ', ')), so its private key " +
                    'cannot be compared with the write target.'
                )
            )
        }
        if (Test-WindowsCertificateSharesPrivateKey `
                -Left $Certificate `
                -Right $machineCertificates[$binding.Thumbprint]) {
            [pscustomobject]@{
                Binding    = $binding.Binding
                Thumbprint = $binding.Thumbprint
                Detail     = $binding.Detail
            }
        }
    }
}
