function ConvertTo-WindowsCngKeyAceKey {
    [CmdletBinding(DefaultParameterSetName = 'Acl')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Acl')]
        [AllowNull()]
        [Security.AccessControl.RawAcl]$Acl,

        [Parameter(Mandatory, ParameterSetName = 'Ace')]
        [Security.AccessControl.GenericAce]$Ace
    )

    $aces = if ($PSCmdlet.ParameterSetName -eq 'Ace') {
        , $Ace
    }
    elseif ($null -eq $Acl) {
        @()
    }
    else {
        @($Acl)
    }

    foreach ($currentAce in $aces) {
        $knownAce = $currentAce -as [Security.AccessControl.KnownAce]
        if (-not $knownAce) {
            # A custom ACE carries no parsed identity, so it gets a key over its
            # exact bytes that can never compare equal to a parsed ACE.
            $bytes = [byte[]]::new($currentAce.BinaryLength)
            $currentAce.GetBinaryForm($bytes, 0)
            'CUSTOM|{0:X2}|{1:X2}|{2}' -f
                ([int]$currentAce.AceType),
                ([int]$currentAce.AceFlags),
                (Get-WindowsCngKeyByteDigest -Bytes $bytes)
            continue
        }
        $effectiveMask = ConvertTo-WindowsCryptoKeyEffectiveMask `
            -AccessMask ([long]$knownAce.AccessMask)
        # AceType separates a callback or object ACE from the plain ACE that
        # shares its qualifier, and the opaque digest separates two conditional
        # ACEs whose conditions differ.
        $opaque = 'NONE'
        $commonAce = $currentAce -as [Security.AccessControl.CommonAce]
        if ($commonAce -and $commonAce.OpaqueLength -gt 0) {
            $opaque = Get-WindowsCngKeyByteDigest -Bytes $commonAce.GetOpaque()
        }
        $objectScope = 'NONE'
        $objectAce = $currentAce -as [Security.AccessControl.ObjectAce]
        if ($objectAce) {
            $objectScope = '{0}|{1}|{2}' -f
                ([int]$objectAce.ObjectAceFlags),
                $objectAce.ObjectAceType,
                $objectAce.InheritedObjectAceType
        }
        '{0}|{1:X2}|{2:X8}|{3:X2}|{4}|{5}' -f
            $knownAce.SecurityIdentifier.Value,
            ([int]$currentAce.AceType),
            $effectiveMask,
            ([int]$currentAce.AceFlags),
            $opaque,
            $objectScope
    }
}
