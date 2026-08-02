function Get-CertificatePrivateKeyAccessRule {
    <#
    .SYNOPSIS
        Gets typed access rules from a supported certificate private-key DACL.
    .DESCRIPTION
        Reads the persisted private-key DACL and emits typed rules. The key is
        addressed either through an exact caller-owned X.509 certificate plus the
        expected CNG provider and key name, or, when no certificate is available,
        through the provider, key name, and key scope alone. The provider must be
        the Microsoft Software Key Storage Provider and must report a
        software-only implementation.
    .PARAMETER Certificate
        An exact X509Certificate2 object with the private key to inspect. The
        command does not dispose the caller-owned certificate.
    .PARAMETER ProviderName
        The exact expected CNG provider.
    .PARAMETER KeyName
        The exact expected persisted CNG key name.
    .PARAMETER KeyScope
        Selects the machine or current-user key store when the key is addressed
        without a certificate.
    .PARAMETER Account
        Filters results by account names, SIDs, identity references, or module identities.
    .EXAMPLE
        $certificate = Get-Item 'Cert:\LocalMachine\My\0123456789ABCDEF'
        Get-CertificatePrivateKeyAccessRule -Certificate $certificate `
            -ProviderName 'Microsoft Software Key Storage Provider' `
            -KeyName 'WorkloadKey'

        Gets every typed access rule on the exact supported CNG key.
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
    .OUTPUTS
        WindowsAccessControl.CertificatePrivateKeyAccessRule
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
        [string]$KeyScope,

        [Parameter()]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account
    )

    begin {
        $accountSids = @(
            foreach ($accountValue in $Account) {
                (Resolve-WindowsIdentityReference -Identity $accountValue).Value
            }
        )
    }
    process {
        $operation = {
            param($Target, $Key, $FilterSids)

            $descriptorBytes = Get-WindowsCngKeySecurityDescriptor -Key $Key
            $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
                $descriptorBytes,
                0
            )
            if (-not $descriptor.DiscretionaryAcl) {
                return
            }
            foreach ($ace in $descriptor.DiscretionaryAcl) {
                $qualifiedAce = $ace -as [Security.AccessControl.QualifiedAce]
                if (-not $qualifiedAce) {
                    continue
                }
                if ($FilterSids.Count -gt 0 -and
                    $qualifiedAce.SecurityIdentifier.Value -notin $FilterSids) {
                    continue
                }
                ConvertTo-WindowsCngKeyAccessRuleObject `
                    -Ace $ace `
                    -Target $Target `
                    -TypeName 'WindowsAccessControl.CertificatePrivateKeyAccessRule'
            }
        }
        $targetParameters = New-WindowsCertificatePrivateKeyTargetParameter `
            -ParameterSetName $PSCmdlet.ParameterSetName `
            -Certificate $Certificate `
            -ProviderName $ProviderName `
            -KeyName $KeyName `
            -KeyScope $KeyScope
        Invoke-WithWindowsCertificatePrivateKeyTarget `
            @targetParameters `
            -Operation $operation `
            -ArgumentList @(, $accountSids)
    }
}
