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
            $current = [Security.AccessControl.RawSecurityDescriptor]::new($currentBytes, 0)
            $candidate = [Security.AccessControl.RawSecurityDescriptor]::new($candidateBytes, 0)
            # Rights are matched exactly, so removing Read from an account that
            # holds FullControl matches nothing. Counting ACEs would miss a
            # request where one account matched and another did not, which is
            # the more convincing false success of the two.
            $remainingKeys = [Collections.Generic.List[string]]@(
                ConvertTo-WindowsCngKeyAceKey -Acl $candidate.DiscretionaryAcl
            )
            $removedIdentities = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
            foreach ($aceKey in @(
                    ConvertTo-WindowsCngKeyAceKey -Acl $current.DiscretionaryAcl
                )) {
                $matchIndex = $remainingKeys.IndexOf($aceKey)
                if ($matchIndex -ge 0) {
                    $remainingKeys.RemoveAt($matchIndex)
                    continue
                }
                # A custom ACE is keyed by its bytes rather than by an identity,
                # so only a key that starts with a security identifier can be
                # attributed to an account.
                $identity = ($aceKey -split '\|')[0]
                if ($identity -like 'S-1-*') {
                    $null = $removedIdentities.Add($identity)
                }
            }
            $unmatched = @(
                $Identities.Value | Where-Object { -not $removedIdentities.Contains($_) }
            )
            if ($unmatched.Count -gt 0) {
                Write-Warning (
                    "No private-key access rule on '$($Target.CanonicalTarget)' matched the " +
                    "requested $RuleType rights for $($unmatched -join ', '); rights are " +
                    'matched exactly, so an account that holds different rights is unchanged.'
                )
            }
            $setParameters = @{
                Target             = $Target
                Certificate        = $BindingCertificate
                Key                = $Key
                SecurityDescriptor = $candidateBytes
            }
            # Without a caller token this read-modify-write would overwrite a
            # change another process made after the read above.
            $setParameters['ExpectedConcurrencyToken'] = if ($null -ne $Token) {
                $Token
            }
            else {
                Get-WindowsSecurityDescriptorConcurrencyToken -Sddl (
                    $current.GetSddlForm(
                        [Security.AccessControl.AccessControlSections]::Access
                    )
                )
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
