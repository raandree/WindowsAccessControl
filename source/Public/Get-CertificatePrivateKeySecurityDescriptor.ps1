function Get-CertificatePrivateKeySecurityDescriptor {
    <#
    .SYNOPSIS
        Gets the DACL descriptor for a supported certificate private key.
    .DESCRIPTION
        Inspects a persisted RSA private-key DACL in the Microsoft Software Key
        Storage Provider. The key is addressed either through an exact
        caller-owned X.509 certificate plus the expected CNG provider and key
        name, or, when no certificate is available, through the provider, key
        name, and key scope alone. It never exports or serializes private-key
        material.
    .PARAMETER Certificate
        An exact X509Certificate2 object with the private key to inspect. The
        command does not dispose the caller-owned certificate.
    .PARAMETER ProviderName
        The exact expected CNG provider. This increment accepts only Microsoft
        Software Key Storage Provider.
    .PARAMETER KeyName
        The exact expected persisted CNG key name. The command verifies it
        against the key selected by Certificate before reading the descriptor.
    .PARAMETER KeyScope
        Selects the machine or current-user key store when the key is addressed
        without a certificate.
    .EXAMPLE
        $certificate = Get-Item 'Cert:\LocalMachine\My\0123456789ABCDEF'
        Get-CertificatePrivateKeySecurityDescriptor `
            -Certificate $certificate `
            -ProviderName 'Microsoft Software Key Storage Provider' `
            -KeyName 'WorkloadKey'

        Gets only the DACL descriptor for the exact supported CNG key.
    .EXAMPLE
        Get-CertificatePrivateKeySecurityDescriptor `
            -ProviderName 'Microsoft Software Key Storage Provider' `
            -KeyName 'WorkloadKey' `
            -KeyScope Machine

        Gets the same descriptor without a certificate, which is how a
        portability record and a desired-state resource address the key.
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
    .OUTPUTS
        WindowsAccessControl.CertificatePrivateKeySecurityDescriptor
    #>
    [CmdletBinding(DefaultParameterSetName = 'Certificate')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Certificate')]
        [ValidateNotNull()]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProviderName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyName,

        [Parameter(Mandatory, ParameterSetName = 'Key')]
        [ValidateSet('Machine', 'User')]
        [string]$KeyScope
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
        $targetParameters = New-WindowsCertificatePrivateKeyTargetParameter `
            -ParameterSetName $PSCmdlet.ParameterSetName `
            -Certificate $Certificate `
            -ProviderName $ProviderName `
            -KeyName $KeyName `
            -KeyScope $KeyScope
        Invoke-WithWindowsCertificatePrivateKeyTarget `
            @targetParameters `
            -Operation $operation
    }
}