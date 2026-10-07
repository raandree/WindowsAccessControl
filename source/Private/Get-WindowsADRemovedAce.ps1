function Get-WindowsADRemovedAce {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseLiteralInitializerForHashtable',
        '',
        Justification = 'Binary ACE identities require an ordinal comparer; a literal hashtable is case-insensitive.'
    )]
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.GenericAce])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$OriginalSecurityDescriptor,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor
    )

    $originalAcl = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $OriginalSecurityDescriptor,
        0
    ).DiscretionaryAcl
    if (-not $originalAcl) {
        return
    }
    $currentAcl = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $SecurityDescriptor,
        0
    ).DiscretionaryAcl

    # Multiset difference, so a duplicated ACE is reported once per removed copy.
    $retained = [System.Collections.Hashtable]::new(
        [System.StringComparer]::Ordinal
    )
    if ($currentAcl) {
        foreach ($ace in $currentAcl) {
            $bytes = [byte[]]::new($ace.BinaryLength)
            $ace.GetBinaryForm($bytes, 0)
            $identity = [Convert]::ToBase64String($bytes)
            $remainingCount = [int]$retained[$identity]
            $retained[$identity] = $remainingCount + 1
        }
    }
    foreach ($ace in $originalAcl) {
        $bytes = [byte[]]::new($ace.BinaryLength)
        $ace.GetBinaryForm($bytes, 0)
        $identity = [Convert]::ToBase64String($bytes)
        $remainingCount = [int]$retained[$identity]
        if ($remainingCount -gt 0) {
            $retained[$identity] = $remainingCount - 1
            continue
        }
        $ace
    }
}
