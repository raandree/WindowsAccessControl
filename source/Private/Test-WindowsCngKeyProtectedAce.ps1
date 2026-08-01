function Test-WindowsCngKeyProtectedAce {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$CurrentDescriptor,

        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$CandidateDescriptor
    )

    $localSystem = 'S-1-5-18'
    $administrators = 'S-1-5-32-544'
    $fullControl = [long][WindowsCryptoKeyRights]::FullControl

    $candidateGrants = @{}
    $candidateDenies = @{}
    foreach ($ace in @($CandidateDescriptor.DiscretionaryAcl)) {
        $knownAce = $ace -as [Security.AccessControl.KnownAce]
        if (-not $knownAce) {
            continue
        }
        # An inherit-only ACE never applies to the object itself.
        if (([int]$ace.AceFlags -band
                [int][Security.AccessControl.AceFlags]::InheritOnly) -ne 0) {
            continue
        }
        $sid = $knownAce.SecurityIdentifier.Value
        $mask = ConvertTo-WindowsCryptoKeyEffectiveMask -AccessMask ([long]$knownAce.AccessMask)
        # The ACE type, not the qualifier, decides whether an ACE grants
        # unconditionally. A callback ACE parses with an AccessAllowed qualifier
        # but grants nothing when its condition is false, so it must never
        # satisfy a required grant while it must still count as a deny.
        if ($ace.AceType -eq [Security.AccessControl.AceType]::AccessAllowed) {
            $candidateGrants[$sid] = ([long]$candidateGrants[$sid]) -bor $mask
            continue
        }
        $candidateDenies[$sid] = ([long]$candidateDenies[$sid]) -bor $mask
    }

    foreach ($requiredSid in $localSystem, $administrators) {
        $granted = [long]$candidateGrants[$requiredSid]
        if (($granted -band $fullControl) -ne $fullControl) {
            return [pscustomobject]@{
                IsAllowed = $false
                Reason    = "The candidate private-key DACL must grant full control to '$requiredSid'."
            }
        }
        if ([long]$candidateDenies[$requiredSid] -ne 0) {
            return [pscustomobject]@{
                IsAllowed = $false
                Reason    = "The candidate private-key DACL must not deny any access to '$requiredSid'."
            }
        }
    }

    foreach ($ace in @($CurrentDescriptor.DiscretionaryAcl)) {
        $knownAce = $ace -as [Security.AccessControl.KnownAce]
        if (-not $knownAce -or
            $ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed) {
            continue
        }
        $sid = $knownAce.SecurityIdentifier.Value
        if (-not (Test-WindowsCngKeyServiceIdentity -SecurityIdentifier $sid)) {
            continue
        }
        $required = ConvertTo-WindowsCryptoKeyEffectiveMask -AccessMask ([long]$knownAce.AccessMask)
        $granted = [long]$candidateGrants[$sid]
        if (($granted -band $required) -ne $required) {
            return [pscustomobject]@{
                IsAllowed = $false
                Reason    = "The candidate private-key DACL removes access that service identity '$sid' currently holds."
            }
        }
        if (([long]$candidateDenies[$sid] -band $required) -ne 0) {
            return [pscustomobject]@{
                IsAllowed = $false
                Reason    = "The candidate private-key DACL denies access that service identity '$sid' currently holds."
            }
        }
    }

    [pscustomobject]@{
        IsAllowed = $true
        Reason    = $null
    }
}
