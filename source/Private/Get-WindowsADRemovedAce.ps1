function Get-WindowsADRemovedAce {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.GenericAce])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$OriginalSecurityDescriptor,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor
    )

    $getAceBytes = {
        param([System.Security.AccessControl.GenericAce]$Ace)

        $bytes = [byte[]]::new($Ace.BinaryLength)
        $Ace.GetBinaryForm($bytes, 0)
        [Convert]::ToBase64String($bytes)
    }

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
    $retained = [System.Collections.Generic.List[string]]::new()
    if ($currentAcl) {
        foreach ($ace in $currentAcl) {
            $retained.Add((& $getAceBytes $ace))
        }
    }
    foreach ($ace in $originalAcl) {
        $index = $retained.IndexOf((& $getAceBytes $ace))
        if ($index -ge 0) {
            $retained.RemoveAt($index)
            continue
        }
        $ace
    }
}
