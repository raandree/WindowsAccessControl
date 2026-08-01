function Set-CertificatePrivateKeySecurityDescriptor {
    <#
    .SYNOPSIS
        Sets the exact DACL of a supported certificate private key.
    .DESCRIPTION
        Persists one caller-supplied DACL on the persisted CNG key under a
        canonical write lock. This is the explicit escape hatch for a complete
        desired-state descriptor. It still enforces the software-only provider,
        the critical-binding refusal, the plain-ACE and no-new-deny rules, and
        the SYSTEM, Administrators, and service-grant preservation gates, and it
        rolls the key back exactly when the write cannot be verified.

        Only the access section is written. The owner and group of the key are
        never read or changed, so an owner or group in Sddl is ignored rather
        than applied.
    .PARAMETER Certificate
        An exact X509Certificate2 object with the private key to change. The
        command does not dispose the caller-owned certificate.
    .PARAMETER ProviderName
        The exact expected CNG provider.
    .PARAMETER KeyName
        The exact expected persisted CNG key name.
    .PARAMETER Sddl
        The complete desired DACL in SDDL form.
    .PARAMETER ConcurrencyToken
        The ConcurrencyToken of an earlier
        Get-CertificatePrivateKeySecurityDescriptor result. The write is rejected
        when the stored DACL changed after that read.
    .PARAMETER PassThru
        Returns the stored private-key descriptor after persistence.
    .EXAMPLE
        $certificate = Get-Item 'Cert:\LocalMachine\My\0123456789ABCDEF'
        Set-CertificatePrivateKeySecurityDescriptor -Certificate $certificate `
            -ProviderName 'Microsoft Software Key Storage Provider' `
            -KeyName 'WorkloadKey' -Sddl 'D:P(A;;FA;;;SY)(A;;FA;;;BA)' -WhatIf

        Previews replacing the private-key DACL with the exact desired state.
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
    .OUTPUTS
        None
        WindowsAccessControl.CertificatePrivateKeySecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProviderName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Sddl,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ConcurrencyToken,

        [Parameter()]
        [switch]$PassThru
    )

    process {
        $operation = {
            param($Target, $Key, $Cmdlet, $DesiredSddl, $Token, $BindingCertificate)

            if (-not $Cmdlet.ShouldProcess(
                    $Target.CanonicalTarget,
                    'Set certificate private-key DACL'
                )) {
                return
            }
            $candidate = [Security.AccessControl.RawSecurityDescriptor]::new($DesiredSddl)
            if (-not $candidate.DiscretionaryAcl) {
                throw [ArgumentException]::new(
                    'Sddl must contain a non-null DACL; a null DACL grants unrestricted access.'
                )
            }
            # The provider is read and written with DACL_SECURITY_INFORMATION
            # only, so a caller-supplied owner or group is dropped here rather
            # than silently carried into the write.
            $candidate.Owner = $null
            $candidate.Group = $null
            $candidateBytes = [byte[]]::new($candidate.BinaryLength)
            $candidate.GetBinaryForm($candidateBytes, 0)
            $setParameters = @{
                Target             = $Target
                Certificate        = $BindingCertificate
                Key                = $Key
                SecurityDescriptor = $candidateBytes
            }
            if ($null -ne $Token) {
                $setParameters['ExpectedConcurrencyToken'] = $Token
            }
            $null = Set-WindowsCngKeySecurityDescriptor @setParameters
        }
        $expectedToken = if ($PSBoundParameters.ContainsKey('ConcurrencyToken')) {
            $ConcurrencyToken
        }
        else {
            $null
        }
        Invoke-WithWindowsCertificatePrivateKeyTarget `
            -Certificate $Certificate `
            -ProviderName $ProviderName `
            -KeyName $KeyName `
            -Operation $operation `
            -ArgumentList @(
                $PSCmdlet
                $Sddl
                $expectedToken
                $Certificate
            ) `
            -ForMutation

        if ($PassThru -and -not $WhatIfPreference) {
            Get-CertificatePrivateKeySecurityDescriptor `
                -Certificate $Certificate `
                -ProviderName $ProviderName `
                -KeyName $KeyName
        }
    }
}
