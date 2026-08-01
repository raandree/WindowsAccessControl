function Add-CertificatePrivateKeyAccessRule {
    <#
    .SYNOPSIS
        Adds typed allow rules to a supported certificate private-key DACL.
    .DESCRIPTION
        Resolves and deduplicates every account, stages the requested allow ACEs
        on the current private-key DACL, and persists the result once under a
        canonical write lock. The write is refused when the provider is not a
        software-only key storage provider, when the same private key serves a
        critical binding, when the candidate contains an ACE that is not a plain
        allow or deny, or when the result would remove SYSTEM, Administrators, or
        an existing service grant.

        Only allow rules can be added. A deny ACE naming a group that contains
        SYSTEM or Administrators would lock the key with no per-account check
        able to detect it, so a new deny ACE is rejected at the write boundary.
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
        Private-key rights to add, such as Read or FullControl.
    .PARAMETER ConcurrencyToken
        The ConcurrencyToken of an earlier
        Get-CertificatePrivateKeySecurityDescriptor result. The write is rejected
        when the stored DACL changed after that read.
    .PARAMETER PassThru
        Returns the stored explicit private-key access rules after persistence.
    .EXAMPLE
        $certificate = Get-Item 'Cert:\LocalMachine\My\0123456789ABCDEF'
        Add-CertificatePrivateKeyAccessRule -Certificate $certificate `
            -ProviderName 'Microsoft Software Key Storage Provider' `
            -KeyName 'WorkloadKey' -Account 'CONTOSO\WebService' -AccessRights Read

        Grants the workload identity read access to the private key.
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
    .OUTPUTS
        None
        WindowsAccessControl.CertificatePrivateKeyAccessRule
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
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,

        [Parameter(Mandatory)]
        [WindowsCryptoKeyRights]$AccessRights,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ConcurrencyToken,

        [Parameter()]
        [switch]$PassThru
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
            param($Target, $Key, $Cmdlet, $Identities, $Rights, $Token, $BindingCertificate)

            if (-not $Cmdlet.ShouldProcess(
                    $Target.CanonicalTarget,
                    'Add Allow certificate private-key access rules'
                )) {
                return
            }
            $currentBytes = Get-WindowsCngKeySecurityDescriptor -Key $Key
            $candidateBytes = Invoke-WindowsCngKeyAclRuleMutation `
                -SecurityDescriptor $currentBytes `
                -Operation Add `
                -SecurityIdentifier $Identities `
                -AccessMask $Rights
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
        $requestedMask = [long][int]$AccessRights -band 0xFFFFFFFFL
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
                $requestedMask
                $expectedToken
                $Certificate
            ) `
            -ForMutation

        if ($PassThru -and -not $WhatIfPreference) {
            $expectedMask = ConvertTo-WindowsCryptoKeyEffectiveMask -AccessMask $requestedMask
            Get-CertificatePrivateKeyAccessRule `
                -Certificate $Certificate `
                -ProviderName $ProviderName `
                -KeyName $KeyName `
                -Account $identities.Value |
                Where-Object {
                    -not $_.IsInherited -and
                    $_.AccessControlType -eq
                        [Security.AccessControl.AccessControlType]::Allow -and
                    [long]$_.EffectiveAccessMask -eq $expectedMask
                }
        }
    }
}
