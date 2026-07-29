function Write-WindowsTaskSchedulerDenyAceWarning {
    <#
        Warns about deny ACEs the fail-closed service gate allows but that an
        operator rarely intends: a new deny that removes WRITE_DAC or
        WRITE_OWNER from a broad service-token identity makes the target
        unmanageable without ownership, and a pre-existing service-hostile deny
        is invisible during the very operation used to remove it.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'The function only writes to the warning stream.'
    )]
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$CurrentDescriptor,

        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$CandidateDescriptor,

        [Parameter()]
        [Collections.Generic.HashSet[string]]$ServiceTokenSid
    )

    $serviceTokenSids = if ($ServiceTokenSid) {
        $ServiceTokenSid
    }
    else {
        Get-WindowsTaskSchedulerServiceTokenSid
    }
    $currentDenyAces = Get-WindowsTaskSchedulerDenyAceIdentity `
        -SecurityDescriptor $CurrentDescriptor
    $manageabilityMask = 0x000C0000

    foreach ($ace in $CandidateDescriptor.DiscretionaryAcl) {
        $knownAce = $ace -as [Security.AccessControl.KnownAce]
        $qualifiedAce = $ace -as [Security.AccessControl.QualifiedAce]
        if (-not $knownAce -or -not $qualifiedAce -or
            $qualifiedAce.AceQualifier -ne
                [Security.AccessControl.AceQualifier]::AccessDenied -or
            -not $serviceTokenSids.Contains($knownAce.SecurityIdentifier.Value)) {
            continue
        }
        $bytes = [byte[]]::new($ace.BinaryLength)
        $ace.GetBinaryForm($bytes, 0)
        $isPreExisting = $currentDenyAces.Contains([Convert]::ToBase64String($bytes))
        $effectiveMask = ConvertTo-WindowsTaskSchedulerEffectiveMask `
            -AccessMask $knownAce.AccessMask
        if ($isPreExisting) {
            if (($effectiveMask -band 0x001201BF) -ne 0) {
                Write-Warning -Message (
                    'The target already denies {0} access mask 0x{1:X8}, which can prevent the Task Scheduler service from reading or running its tasks. This write does not change that ACE.' -f
                        $knownAce.SecurityIdentifier.Value, $effectiveMask
                )
            }
            continue
        }
        if (($effectiveMask -band $manageabilityMask) -ne 0) {
            Write-Warning -Message (
                'The candidate denies {0} permission to change the DACL or owner. Recovering from this ACE requires ownership of the target.' -f
                    $knownAce.SecurityIdentifier.Value
            )
        }
    }
}
