function Test-WindowsCngKeyDaclEquivalent {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [Security.AccessControl.RawSecurityDescriptor]$Left,

        [Parameter(Mandatory)]
        [AllowNull()]
        [Security.AccessControl.RawSecurityDescriptor]$Right,

        [Parameter()]
        [switch]$Ordered
    )

    if ($null -eq $Left -or $null -eq $Right) {
        return $false
    }
    # A null DACL grants everyone everything and an empty DACL grants nobody
    # anything, yet both yield zero ACE keys. Callers reject a null DACL before
    # reaching here, but a security-critical predicate must not rely on that.
    if (($null -eq $Left.DiscretionaryAcl) -ne ($null -eq $Right.DiscretionaryAcl)) {
        return $false
    }
    $leftProtected = ([int]$Left.ControlFlags -band
        [int][Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0
    $rightProtected = ([int]$Right.ControlFlags -band
        [int][Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0
    if ($leftProtected -ne $rightProtected) {
        return $false
    }

    $leftKeys = [string[]]@(ConvertTo-WindowsCngKeyAceKey -Acl $Left.DiscretionaryAcl)
    $rightKeys = [string[]]@(ConvertTo-WindowsCngKeyAceKey -Acl $Right.DiscretionaryAcl)
    if ($leftKeys.Count -ne $rightKeys.Count) {
        return $false
    }
    # Verification after a write compares the multiset, because the provider
    # decides the stored order. A caller asking whether a candidate is already
    # the desired state must compare the sequence, because ACE order changes
    # which rule wins. Typed arrays keep a one-ACE DACL from collapsing to a
    # string and comparing character by character.
    if (-not $Ordered) {
        [Array]::Sort($leftKeys, [StringComparer]::Ordinal)
        [Array]::Sort($rightKeys, [StringComparer]::Ordinal)
    }
    for ($index = 0; $index -lt $leftKeys.Count; $index++) {
        if ($leftKeys[$index] -cne $rightKeys[$index]) {
            return $false
        }
    }
    $true
}
