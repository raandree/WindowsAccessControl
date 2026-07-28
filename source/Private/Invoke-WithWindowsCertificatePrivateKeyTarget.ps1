function Invoke-WithWindowsCertificatePrivateKeyTarget {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProviderName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyName,

        [Parameter(Mandatory)]
        [scriptblock]$Operation
    )

    $supportedProvider = 'Microsoft Software Key Storage Provider'
    if ($ProviderName -cne $supportedProvider) {
        throw [NotSupportedException]::new(
            "Only persisted RSA keys in '$supportedProvider' are supported by this read-only increment."
        )
    }
    if (-not $Certificate.HasPrivateKey) {
        throw [InvalidOperationException]::new(
            'The supplied certificate does not have an accessible private key.'
        )
    }

    $rsa = $null
    try {
        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
            GetRSAPrivateKey($Certificate)
        if ($null -eq $rsa -or
            $rsa.GetType().FullName -cne 'System.Security.Cryptography.RSACng') {
            throw [NotSupportedException]::new(
                'The supplied certificate does not select a supported CNG RSA private key.'
            )
        }
        $key = $rsa.Key
        if ($key.IsEphemeral -or [string]::IsNullOrWhiteSpace($key.UniqueName)) {
            throw [NotSupportedException]::new(
                'Ephemeral or unstable CNG private-key identities are not supported.'
            )
        }
        if ([string]$key.Provider.Provider -cne $ProviderName -or
            [string]$key.KeyName -cne $KeyName) {
            throw [InvalidOperationException]::new(
                'The certificate private key does not match the expected provider and key name.'
            )
        }

        $keyScope = if ($key.IsMachineKey) { 'Machine' } else { 'User' }
        $canonicalTarget = Get-WindowsCertificatePrivateKeyCanonicalTarget `
            -ProviderName $ProviderName `
            -UniqueName $key.UniqueName `
            -KeyScope $keyScope
        $thumbprint = ([string]$Certificate.Thumbprint).
            Replace(' ', '').ToUpperInvariant()
        $target = [pscustomobject]@{
            ObjectType            = 'CertificatePrivateKey'
            Path                  = $thumbprint
            ProviderName          = $ProviderName
            KeyName               = $key.KeyName
            UniqueName            = $key.UniqueName
            KeyScope              = $keyScope
            CertificateThumbprint = $thumbprint
            CanonicalTarget       = $canonicalTarget
            DescriptorSource      = 'CngKey'
        }

        & $Operation $target $key
    }
    finally {
        if ($null -ne $rsa) {
            $rsa.Dispose()
        }
    }
}