function Remove-CertificatePrivateKeyAccessRule {
    <#
    .SYNOPSIS
        Removes exact typed access rules from a certificate private-key DACL.
    .DESCRIPTION
        Removes only explicit ACEs whose account, qualifier, and effective
        rights match the request, then persists the result once under a
        canonical write lock. Removing an existing deny rule is supported.
        The write is refused when the provider is not a software-only key
        storage provider, when the same private key serves a critical binding,
        or when the result would remove SYSTEM, Administrators, or an existing
        service grant.
    .PARAMETER Certificate
        An exact X509Certificate2 object with the private key to change. The
        command does not dispose the caller-owned certificate.
    .PARAMETER ProviderName
        The exact expected CNG provider.
    .PARAMETER KeyName
        The exact expected persisted CNG key name.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER AccessRights
        The exact private-key rights to remove.
    .PARAMETER AccessControlType
        Removes an Allow rule by default or an existing Deny rule.
    .PARAMETER ConcurrencyToken
        The ConcurrencyToken of an earlier
        Get-CertificatePrivateKeySecurityDescriptor result. The write is rejected
        when the stored DACL changed after that read.
    .EXAMPLE
        $certificate = Get-Item 'Cert:\LocalMachine\My\0123456789ABCDEF'
        Remove-CertificatePrivateKeyAccessRule -Certificate $certificate `
            -ProviderName 'Microsoft Software Key Storage Provider' `
            -KeyName 'WorkloadKey' -Account 'CONTOSO\WebService' -AccessRights Read

        Removes the exact read grant and leaves every other rule intact.
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
    .OUTPUTS
        None
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([void])]
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
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,

        [Parameter(Mandatory)]
        [WindowsCryptoKeyRights]$AccessRights,

        [Parameter()]
        [Security.AccessControl.AccessControlType]$AccessControlType =
            [Security.AccessControl.AccessControlType]::Allow,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ConcurrencyToken
    )

    begin {
        $seen = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        $identities = @(
            foreach ($accountValue in $Account) {
                $sid = Resolve-WindowsIdentityReference -Identity $accountValue
                if ($seen.Add($sid.Value)) { $sid }
            }
        )
    }
    process {
        $operation = {
            param($Target, $Key, $Cmdlet, $Identities, $Rights, $RuleType, $Token, $BindingCertificate)

            if (-not $Cmdlet.ShouldProcess(
                    $Target.CanonicalTarget,
                    "Remove exact $RuleType certificate private-key access rules"
                )) {
                return
            }
            $currentBytes = Get-WindowsCngKeySecurityDescriptor -Key $Key
            $candidateBytes = Invoke-WindowsCngKeyAclRuleMutation `
                -SecurityDescriptor $currentBytes `
                -Operation Remove `
                -SecurityIdentifier $Identities `
                -AccessMask $Rights `
                -AccessControlType $RuleType
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
                (, $identities)
                ([long][int]$AccessRights -band 0xFFFFFFFFL)
                $AccessControlType
                $expectedToken
                $Certificate
            ) `
            -ForMutation
    }
}
