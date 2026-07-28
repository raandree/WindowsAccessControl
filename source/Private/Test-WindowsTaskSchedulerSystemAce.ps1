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
    $currentSystemAces = @(
        foreach ($ace in $CurrentDescriptor.DiscretionaryAcl) {
            & $getAceIdentity $ace
        }
    )
    $candidateSystemAces = @(
        foreach ($ace in $CandidateDescriptor.DiscretionaryAcl) {
            & $getAceIdentity $ace
        }
    )
    if ($currentSystemAces.Count -eq 0) {
        return $false
    }
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
        if ($candidateSystemAces -notcontains $currentSystemAce) {
            return $false
        }
    }
    $true
}