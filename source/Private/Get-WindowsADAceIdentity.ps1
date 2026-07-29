function Get-WindowsADAceIdentity {
    <#
        .SYNOPSIS
            Builds the comparable identity of one directory access-control entry.

        .DESCRIPTION
            Returns the security identifier, unsigned access mask, qualifier,
            and both object GUIDs of an ACE as one string. Inheritance and
            propagation flags are excluded because Windows rewrites them while
            an ACE propagates from an ancestor to a descendant.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.QualifiedAce]$Ace
    )

    $objectAce = $Ace -as [System.Security.AccessControl.ObjectAce]
    $objectType = [guid]::Empty
    $inheritedObjectType = [guid]::Empty
    if ($objectAce) {
        if (($objectAce.ObjectAceFlags -band
                [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent)) {
            $objectType = $objectAce.ObjectAceType
        }
        if (($objectAce.ObjectAceFlags -band
                [System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent)) {
            $inheritedObjectType = $objectAce.InheritedObjectAceType
        }
    }

    '{0}|{1}|{2}|{3}|{4}' -f
        $Ace.SecurityIdentifier.Value,
        ([int64]$Ace.AccessMask -band 0xFFFFFFFFL),
        ([int]$Ace.AceQualifier),
        $objectType.ToString('N'),
        $inheritedObjectType.ToString('N')
}
