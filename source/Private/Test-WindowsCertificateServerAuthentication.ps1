function Test-WindowsCertificateServerAuthentication {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $serverAuthentication = '1.3.6.1.5.5.7.3.1'
    $sawEnhancedKeyUsage = $false
    foreach ($extension in $Certificate.Extensions) {
        $enhancedKeyUsage = $extension -as
            [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
        if (-not $enhancedKeyUsage) {
            continue
        }
        $sawEnhancedKeyUsage = $true
        foreach ($usage in $enhancedKeyUsage.EnhancedKeyUsages) {
            if ($usage.Value -ceq $serverAuthentication) {
                return $true
            }
        }
    }

    # A certificate without an enhanced key usage extension is valid for every
    # purpose, so it can still serve LDAPS.
    -not $sawEnhancedKeyUsage
}
