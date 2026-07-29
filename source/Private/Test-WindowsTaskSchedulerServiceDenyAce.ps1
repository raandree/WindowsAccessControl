function Test-WindowsTaskSchedulerServiceDenyAce {
    <#
        Returns true when the candidate DACL introduces a deny ACE that could
        remove the Task Scheduler service token's required access. The required
        mask is the documented read, write, and execute file access the service
        needs to read, update, and run a task. A deny ACE the target already
        carries is exempt so an affected target stays manageable.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
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
        if ($currentDenyAces.Contains([Convert]::ToBase64String($bytes))) {
            continue
        }
        $effectiveMask = ConvertTo-WindowsTaskSchedulerEffectiveMask `
            -AccessMask $knownAce.AccessMask
        if (($effectiveMask -band 0x001201BF) -ne 0) {
            return $true
        }
    }
    $false
}
