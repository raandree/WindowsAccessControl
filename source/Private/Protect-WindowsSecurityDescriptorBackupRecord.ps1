function Protect-WindowsSecurityDescriptorBackupRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [psobject]$Record,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $now = [DateTime]::UtcNow
    if ($now -lt $Certificate.NotBefore.ToUniversalTime() -or
        $now -gt $Certificate.NotAfter.ToUniversalTime()) {
        throw [System.Security.Cryptography.CryptographicException]::new(
            'The signing certificate is not currently valid.'
        )
    }
    if (-not $Certificate.HasPrivateKey) {
        throw [System.Security.Cryptography.CryptographicException]::new(
            'The signing certificate does not contain a private key.'
        )
    }

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey(
        $Certificate
    )
    if (-not $rsa) {
        throw [System.Security.Cryptography.CryptographicException]::new(
            'The signing certificate does not contain a supported RSA private key.'
        )
    }
    try {
        $hash = Get-WindowsSecurityDescriptorRecordHash -Record $Record
        $signature = $rsa.SignHash(
            $hash,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
    } finally {
        $rsa.Dispose()
    }

    $Record.Integrity = [pscustomobject][ordered]@{
        Algorithm             = 'SHA256'
        Digest               = [string]$Record.Integrity.Digest
        SignatureAlgorithm   = 'RSASSA-PKCS1-v1_5-SHA256'
        CertificateThumbprint = $Certificate.Thumbprint.Replace(' ', '').ToUpperInvariant()
        Signature             = [Convert]::ToBase64String($signature)
    }
    $Record
}
