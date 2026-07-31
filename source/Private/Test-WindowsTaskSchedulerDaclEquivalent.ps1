function Test-WindowsTaskSchedulerDaclEquivalent {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$Left,

        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$Right
    )

    if (-not $Left.DiscretionaryAcl -or -not $Right.DiscretionaryAcl) {
        return $false
    }
    $controlMask = [int][Security.AccessControl.ControlFlags]::DiscretionaryAclPresent -bor
        [int][Security.AccessControl.ControlFlags]::DiscretionaryAclProtected -bor
        [int][Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInheritRequired
    if (([int]$Left.ControlFlags -band $controlMask) -ne
        ([int]$Right.ControlFlags -band $controlMask) -or
        $Left.DiscretionaryAcl.Revision -ne $Right.DiscretionaryAcl.Revision -or
        $Left.DiscretionaryAcl.Count -ne $Right.DiscretionaryAcl.Count) {
        return $false
    }

    $getSortedAceIdentities = {
        param([Security.AccessControl.RawAcl]$Acl)

        $identities = [string[]]@(
            foreach ($ace in $Acl) {
                $bytes = [byte[]]::new($ace.BinaryLength)
                $ace.GetBinaryForm($bytes, 0)
                [Convert]::ToBase64String($bytes)
            }
        )
        # Ordinal ordering keeps the multiset comparison independent of culture.
        [Array]::Sort($identities, [StringComparer]::Ordinal)
        $identities
    }
    $leftAces = @(& $getSortedAceIdentities $Left.DiscretionaryAcl)
    $rightAces = @(& $getSortedAceIdentities $Right.DiscretionaryAcl)
    for ($index = 0; $index -lt $leftAces.Count; $index++) {
        if ($leftAces[$index] -cne $rightAces[$index]) {
            return $false
        }
    }
    $true
}