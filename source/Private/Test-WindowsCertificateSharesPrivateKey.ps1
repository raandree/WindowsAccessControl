function Test-WindowsCertificateSharesPrivateKey {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Left,

        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Right
    )

    if ($Left.Thumbprint -ceq $Right.Thumbprint) {
        return $true
    }

    # Certificate renewal with key reuse produces a second certificate over the
    # same private key. Two certificates share a private key exactly when they
    # carry the same public key, and that comparison needs no key handle.
    if ($Left.PublicKey.Oid.Value -cne $Right.PublicKey.Oid.Value) {
        return $false
    }
    foreach ($pair in @(
            @{ L = $Left.PublicKey.EncodedKeyValue.RawData; R = $Right.PublicKey.EncodedKeyValue.RawData }
            @{ L = $Left.PublicKey.EncodedParameters.RawData; R = $Right.PublicKey.EncodedParameters.RawData }
        )) {
        # PowerShell variable names are case-insensitive, so these cannot be
        # named after the typed $Left and $Right parameters.
        $leftBytes = [byte[]]$pair.L
        $rightBytes = [byte[]]$pair.R
        if ($leftBytes.Length -ne $rightBytes.Length) {
            return $false
        }
        for ($index = 0; $index -lt $leftBytes.Length; $index++) {
            if ($leftBytes[$index] -ne $rightBytes[$index]) {
                return $false
            }
        }
    }
    $true
}
