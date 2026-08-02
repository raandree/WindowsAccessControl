function Get-WindowsRsaPublicKeyIdentity {
    <#
        .SYNOPSIS
            Returns a comparable RSA public-key identity for a key or certificate.

        .DESCRIPTION
            The critical-binding gate is keyed on the private key, so a write
            that is addressed by provider and key name has no certificate to
            compare with. Two certificates share a private key exactly when they
            carry the same public key, and a persisted CNG key exposes the same
            public key without opening or exporting private material. Both
            sources are normalized to one string so the comparison cannot differ
            between the two ways of addressing the same key.

            A certificate that does not carry an RSA public key returns nothing,
            because this module writes only RSA private keys and a key of another
            algorithm can never be the same key.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Certificate')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory, ParameterSetName = 'Key')]
        [Security.Cryptography.CngKey]$Key
    )

    # Leading zero bytes are not significant in a big-endian integer, and the
    # two sources pad differently, so they are removed before comparison.
    function ConvertTo-WindowsRsaHexToken {
        param([byte[]]$Value)

        if ($null -eq $Value -or $Value.Length -eq 0) {
            return [string]::Empty
        }
        $offset = 0
        while ($offset -lt $Value.Length - 1 -and $Value[$offset] -eq 0) {
            $offset++
        }
        -join @(
            $Value[$offset..($Value.Length - 1)] | ForEach-Object { $_.ToString('X2') }
        )
    }

    if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
        $publicKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
            GetRSAPublicKey($Certificate)
        if ($null -eq $publicKey) {
            return
        }
        try {
            $parameters = $publicKey.ExportParameters($false)
        }
        finally {
            $publicKey.Dispose()
        }
        return 'RSA:{0}:{1}' -f
            (ConvertTo-WindowsRsaHexToken -Value $parameters.Modulus),
            (ConvertTo-WindowsRsaHexToken -Value $parameters.Exponent)
    }

    # A gate input that cannot be read must throw. Returning nothing here would
    # turn an unreadable public key into "no binding uses this key".
    try {
        $blob = $Key.Export(
            [Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob
        )
    }
    catch {
        throw [InvalidOperationException]::new(
            (
                "The public key of CNG key '$($Key.KeyName)' could not be read, so a critical " +
                'binding on that key cannot be ruled out.'
            ),
            $_.Exception
        )
    }
    # BCRYPT_RSAKEY_BLOB is six little-endian 32-bit header values followed by
    # the big-endian public exponent and modulus.
    if ($null -eq $blob -or $blob.Length -lt 24 -or
        [BitConverter]::ToUInt32($blob, 0) -ne 0x31415352) {
        throw [InvalidOperationException]::new(
            (
                "CNG key '$($Key.KeyName)' did not export an RSA public key blob, so a critical " +
                'binding on that key cannot be ruled out.'
            )
        )
    }
    $exponentLength = [BitConverter]::ToUInt32($blob, 8)
    $modulusLength = [BitConverter]::ToUInt32($blob, 12)
    if ($exponentLength -eq 0 -or $modulusLength -eq 0 -or
        24L + $exponentLength + $modulusLength -gt $blob.Length) {
        throw [InvalidOperationException]::new(
            (
                "CNG key '$($Key.KeyName)' exported a malformed RSA public key blob, so a " +
                'critical binding on that key cannot be ruled out.'
            )
        )
    }
    $exponent = [byte[]]::new([int]$exponentLength)
    [Array]::Copy($blob, 24, $exponent, 0, [int]$exponentLength)
    $modulus = [byte[]]::new([int]$modulusLength)
    [Array]::Copy($blob, 24 + [int]$exponentLength, $modulus, 0, [int]$modulusLength)
    'RSA:{0}:{1}' -f
        (ConvertTo-WindowsRsaHexToken -Value $modulus),
        (ConvertTo-WindowsRsaHexToken -Value $exponent)
}
