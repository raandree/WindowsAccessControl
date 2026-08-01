function Test-CertificatePrivateKeyCriticalBinding {
    <#
    .SYNOPSIS
        Reports the critical service bindings that use a certificate's private key.
    .DESCRIPTION
        Enumerates every certificate currently bound to an HTTP.sys TLS
        endpoint, a WinRM HTTPS listener, a Remote Desktop listener, or eligible
        for Active Directory LDAPS, and reports the bindings whose certificate
        shares a private key with the supplied certificate.

        The comparison is by public key, not by thumbprint, because a renewal
        that reuses the key produces a second certificate over the same private
        key. The private-key mutation commands refuse to write while any binding
        is reported, so this command explains a refusal without changing state.
    .PARAMETER Certificate
        The certificate whose private key is inspected.
    .EXAMPLE
        $certificate = Get-Item 'Cert:\LocalMachine\My\0123456789ABCDEF'
        Test-CertificatePrivateKeyCriticalBinding -Certificate $certificate

        Reports every critical binding that currently uses the same private key.
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
    .OUTPUTS
        WindowsAccessControl.CertificateCriticalBinding
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    process {
        foreach ($binding in @(
                Get-WindowsCertificateCriticalBinding -Certificate $Certificate
            )) {
            $result = [pscustomobject]@{
                Certificate = ([string]$Certificate.Thumbprint).ToUpperInvariant()
                Binding     = $binding.Binding
                Thumbprint  = $binding.Thumbprint
                Detail      = $binding.Detail
            }
            $result.PSObject.TypeNames.Insert(
                0,
                'WindowsAccessControl.CertificateCriticalBinding'
            )
            $result
        }
    }
}
