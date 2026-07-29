function Get-WindowsTaskSchedulerDenyAceIdentity {
    [CmdletBinding()]
    [OutputType([Collections.Generic.HashSet[string]])]
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor
    )

    # Base64 is case-significant, so an ordinal set avoids a fail-open match.
    $identities = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($ace in $SecurityDescriptor.DiscretionaryAcl) {
        $knownAce = $ace -as [Security.AccessControl.KnownAce]
        $qualifiedAce = $ace -as [Security.AccessControl.QualifiedAce]
        if (-not $knownAce -or -not $qualifiedAce -or
            $qualifiedAce.AceQualifier -ne
                [Security.AccessControl.AceQualifier]::AccessDenied) {
            continue
        }
        $bytes = [byte[]]::new($ace.BinaryLength)
        $ace.GetBinaryForm($bytes, 0)
        $null = $identities.Add([Convert]::ToBase64String($bytes))
    }
    , $identities
}
