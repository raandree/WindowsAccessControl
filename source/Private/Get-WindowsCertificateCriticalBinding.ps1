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
    $bindings = @(Get-WindowsBoundCertificateThumbprint)
    if ($bindings.Count -eq 0) {
        return
    }

    $wanted = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($binding in $bindings) {
        $null = $wanted.Add($binding.Thumbprint)
    }

    # Only the bound thumbprints are retained. Materializing every certificate
    # in every store would hold hundreds of handles open on each write. This
    # helper takes ownership of every certificate handed to it, so only pass
    # certificates a producer created for this call.
    $resolved = @{}
    function Select-WantedCertificate {
        # Not named after the outer $Certificate parameter, which is the write
        # target: PowerShell variable names are case-insensitive and a shadowed
        # name in this family has already caused one defect.
        param([object[]]$Candidate)

        foreach ($stored in $Candidate) {
            $thumbprint = $stored.Thumbprint.ToUpperInvariant()
            if ($wanted.Contains($thumbprint) -and -not $resolved.ContainsKey($thumbprint)) {
                $resolved[$thumbprint] = $stored
                continue
            }
            $stored.Dispose()
        }
    }

    try {
        # A domain controller can hold its LDAPS certificate in the NTDS service
        # store, which the local machine store location cannot address. The probe
        # is one native call that fails immediately when the store is absent, so
        # it is cheaper than asking the operating system for its product type.
        Select-WantedCertificate -Candidate @(
            Get-WindowsServiceStoreCertificate -ServiceName 'NTDS' -StoreName 'MY'
        )
        foreach ($storeName in @(Get-WindowsMachineCertificateStoreName)) {
            if ($resolved.Count -eq $wanted.Count) {
                break
            }
            Select-WantedCertificate -Candidate @(
                Get-WindowsMachineStoreCertificate -StoreName $storeName
            )
        }

        foreach ($binding in $bindings) {
            if (-not $resolved.ContainsKey($binding.Thumbprint)) {
                throw [InvalidOperationException]::new(
                    (
                        "Certificate '$($binding.Thumbprint)' serves the $($binding.Binding) binding but was " +
                        'not found in any local machine certificate store or in the NTDS service store, so ' +
                        'its private key cannot be compared with the write target. Remove the stale binding ' +
                        'or restore the certificate.'
                    )
                )
            }
            if (Test-WindowsCertificateSharesPrivateKey `
                    -Left $Certificate `
                    -Right $resolved[$binding.Thumbprint]) {
                [pscustomobject]@{
                    Binding    = $binding.Binding
                    Thumbprint = $binding.Thumbprint
                    Detail     = $binding.Detail
                }
            }
        }
    }
    finally {
        foreach ($stored in $resolved.Values) {
            $stored.Dispose()
        }
    }
}
