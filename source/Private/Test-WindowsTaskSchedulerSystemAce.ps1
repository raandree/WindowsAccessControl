function Test-WindowsTaskSchedulerSystemAce {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$CurrentDescriptor,

        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$CandidateDescriptor
    )

    $systemSid = 'S-1-5-18'
    # Without a current DACL neither Local System preservation nor an exact
    # rollback can be verified, so a missing or null DACL fails closed. A DACL
    # that merely lacks a Local System ACE has nothing to preserve.
    if (-not $CurrentDescriptor.DiscretionaryAcl) {
        return $false
    }
    $getAceIdentity = {
        param($Ace)

        $knownAce = $Ace -as [Security.AccessControl.KnownAce]
        if (-not $knownAce -or $knownAce.SecurityIdentifier.Value -ne $systemSid) {
            return
        }
        $bytes = [byte[]]::new($Ace.BinaryLength)
        $Ace.GetBinaryForm($bytes, 0)
        [Convert]::ToBase64String($bytes)
    }
    $currentSystemAces = [Collections.Generic.HashSet[string]]::new(
        [string[]]@(
            foreach ($ace in $CurrentDescriptor.DiscretionaryAcl) {
                & $getAceIdentity $ace
            }
        ),
        [StringComparer]::Ordinal
    )
    $candidateSystemAces = [Collections.Generic.HashSet[string]]::new(
        [string[]]@(
            foreach ($ace in $CandidateDescriptor.DiscretionaryAcl) {
                & $getAceIdentity $ace
            }
        ),
        [StringComparer]::Ordinal
    )
    foreach ($ace in $CandidateDescriptor.DiscretionaryAcl) {
        $knownAce = $ace -as [Security.AccessControl.KnownAce]
        $qualifiedAce = $ace -as [Security.AccessControl.QualifiedAce]
        if ($knownAce -and $qualifiedAce -and
            $knownAce.SecurityIdentifier.Value -eq $systemSid -and
            $qualifiedAce.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessDenied) {
            return $false
        }
    }
    foreach ($currentSystemAce in $currentSystemAces) {
        if (-not $candidateSystemAces.Contains($currentSystemAce)) {
            return $false
        }
    }
    $true
}