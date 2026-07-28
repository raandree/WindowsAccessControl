function Get-CertificatePrivateKeySecurityDescriptor {
    <#
    .SYNOPSIS
        Gets the DACL descriptor for a supported certificate private key.
    .DESCRIPTION
        Uses an exact caller-owned X.509 certificate plus expected CNG provider
        and key name to inspect a persisted RSA private-key DACL. The first
        increment is read-only and supports only the Microsoft Software Key
        Storage Provider. It never exports or serializes private-key material.
    .PARAMETER Certificate
        An exact X509Certificate2 object with the private key to inspect. The
        command does not dispose the caller-owned certificate.
    .PARAMETER ProviderName
        The exact expected CNG provider. This increment accepts only Microsoft
        Software Key Storage Provider.
    .PARAMETER KeyName
        The exact expected persisted CNG key name. The command verifies it
        against the key selected by Certificate before reading the descriptor.
    .EXAMPLE
        $certificate = Get-Item 'Cert:\LocalMachine\My\0123456789ABCDEF'
        Get-CertificatePrivateKeySecurityDescriptor `
            -Certificate $certificate `
            -ProviderName 'Microsoft Software Key Storage Provider' `
            -KeyName 'WorkloadKey'

        Gets only the DACL descriptor for the exact supported CNG key.
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
    .OUTPUTS
        WindowsAccessControl.CertificatePrivateKeySecurityDescriptor
    #>
    [CmdletBinding()]
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
        [string]$KeyName
    )

    process {
        $operation = {
            param($Target, $Key)

            $descriptor = Get-WindowsCngKeySecurityDescriptor -Key $Key
            ConvertTo-WindowsSecurityDescriptorObject `
                -Target $Target `
                -Sections Access `
                -SecurityDescriptor $descriptor `
                -TypeName (
                    'WindowsAccessControl.CertificatePrivateKeySecurityDescriptor'
                )
        }
        Invoke-WithWindowsCertificatePrivateKeyTarget `
            -Certificate $Certificate `
            -ProviderName $ProviderName `
            -KeyName $KeyName `
            -Operation $operation
    }
}