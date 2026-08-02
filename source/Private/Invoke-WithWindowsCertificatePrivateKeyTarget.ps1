function Invoke-WithWindowsCertificatePrivateKeyTarget {
    <#
        .SYNOPSIS
            Resolves one persisted CNG private key and runs an operation on it.

        .DESCRIPTION
            A key can be addressed through an exact caller-owned certificate or,
            when no certificate is available, through its provider, persisted key
            name, and key scope. Both forms resolve the same canonical identity
            and pass through the same gates; only the selector differs. The
            certificate thumbprint is never a selector, because a renewal that
            reuses the key changes the thumbprint while the key stays the same.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Certificate')]
    [OutputType([object])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProviderName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyName,

        [Parameter(Mandatory, ParameterSetName = 'Key')]
        [ValidateSet('Machine', 'User')]
        [string]$KeyScope,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedCanonicalTarget,

        [Parameter(Mandatory)]
        [scriptblock]$Operation,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$ArgumentList = @(),

        [Parameter()]
        [switch]$ForMutation
    )

    Assert-WindowsCngKeyProviderSupport -ProviderName $ProviderName

    $rsa = $null
    $openedKey = $null
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
            if (-not $Certificate.HasPrivateKey) {
                throw [InvalidOperationException]::new(
                    'The supplied certificate does not have an accessible private key.'
                )
            }
            $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
                GetRSAPrivateKey($Certificate)
            if ($null -eq $rsa -or
                $rsa.GetType().FullName -cne 'System.Security.Cryptography.RSACng') {
                throw [NotSupportedException]::new(
                    'The supplied certificate does not select a supported CNG RSA private key.'
                )
            }
            $key = $rsa.Key
        }
        else {
            $openOptions = if ($KeyScope -eq 'Machine') {
                [Security.Cryptography.CngKeyOpenOptions]::MachineKey
            }
            else {
                [Security.Cryptography.CngKeyOpenOptions]::None
            }
            try {
                $openedKey = [Security.Cryptography.CngKey]::Open(
                    $KeyName,
                    [Security.Cryptography.CngProvider]::new($ProviderName),
                    $openOptions
                )
            }
            catch {
                throw [InvalidOperationException]::new(
                    (
                        "The persisted $KeyScope CNG key '$KeyName' could not be opened in " +
                        "provider '$ProviderName'."
                    ),
                    $_.Exception
                )
            }
            $key = $openedKey
            if ([string]$key.AlgorithmGroup.AlgorithmGroup -cne 'RSA') {
                throw [NotSupportedException]::new(
                    "The persisted CNG key '$KeyName' is not an RSA key."
                )
            }
            if (($KeyScope -eq 'Machine') -ne [bool]$key.IsMachineKey) {
                throw [InvalidOperationException]::new(
                    "The persisted CNG key '$KeyName' does not have the expected $KeyScope key scope."
                )
            }
        }

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

        $resolvedKeyScope = if ($key.IsMachineKey) { 'Machine' } else { 'User' }
        $canonicalTarget = Get-WindowsCertificatePrivateKeyCanonicalTarget `
            -ProviderName $ProviderName `
            -UniqueName $key.UniqueName `
            -KeyScope $resolvedKeyScope
        # A caller that resolved this key earlier can pin the identity it saw.
        # The check runs while this handle is open and the handle serves the
        # whole operation, so a key deleted and recreated under the same name
        # between the two resolutions is rejected rather than written to.
        if ($PSBoundParameters.ContainsKey('ExpectedCanonicalTarget') -and
            $canonicalTarget -cne $ExpectedCanonicalTarget) {
            throw [InvalidOperationException]::new(
                (
                    "The persisted CNG key '$KeyName' in '$ProviderName' no longer has the " +
                    'expected canonical identity, so it is not the key that was resolved earlier.'
                )
            )
        }
        $thumbprint = if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
            ([string]$Certificate.Thumbprint).Replace(' ', '').ToUpperInvariant()
        }
        else {
            $null
        }
        # The canonical identity hashes the provider's per-machine container
        # name, so every target reports the owning computer and a portability
        # record built from it cannot be replayed on another machine.
        $target = [pscustomobject]@{
            ObjectType            = 'CertificatePrivateKey'
            Path                  = $thumbprint
            Server                = [Environment]::MachineName
            ProviderName          = $ProviderName
            KeyName               = $key.KeyName
            UniqueName            = $key.UniqueName
            KeyScope              = $resolvedKeyScope
            CertificateThumbprint = $thumbprint
            CanonicalTarget       = $canonicalTarget
            DescriptorSource      = 'CngKey'
        }

        if (-not $ForMutation) {
            return (& $Operation $target $key @ArgumentList)
        }

        # Serialize concurrent writers on the canonical key identity exactly as
        # the bounded dispatcher does for every path-addressed family.
        $targetLock = Get-WindowsAccessControlTargetLock -CanonicalTarget $canonicalTarget
        $lockAcquired = $false
        try {
            $targetLock.Semaphore.Wait()
            $lockAcquired = $true
            & $Operation $target $key @ArgumentList
        }
        finally {
            if ($lockAcquired) {
                $null = $targetLock.Semaphore.Release()
            }
            Unlock-WindowsAccessControlTargetLock -TargetLock $targetLock
        }
    }
    finally {
        if ($null -ne $rsa) {
            $rsa.Dispose()
        }
        if ($null -ne $openedKey) {
            $openedKey.Dispose()
        }
    }
}