function ConvertTo-WindowsADAccessRuleObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.GenericAce]$Ace,

        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$InheritedFrom,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary]$SchemaGuidName
    )

    $qualifiedAce = $Ace -as [System.Security.AccessControl.QualifiedAce]
    $knownAce = $Ace -as [System.Security.AccessControl.KnownAce]
    if (-not $qualifiedAce -or -not $knownAce -or
        $qualifiedAce.AceQualifier -notin @(
            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            [System.Security.AccessControl.AceQualifier]::AccessDenied
        )) {
        return
    }
    $account = $null
    $isOrphaned = $false
    try {
        $account = $qualifiedAce.SecurityIdentifier.Translate(
            [System.Security.Principal.NTAccount]
        ).Value
    }
    catch [System.Security.Principal.IdentityNotMappedException] {
        $isOrphaned = $true
    }
    $objectAce = $Ace -as [System.Security.AccessControl.ObjectAce]
    $objectTypeGuid = if ($objectAce -and
        ($objectAce.ObjectAceFlags -band
            [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent)) {
        $objectAce.ObjectAceType
    }
    else { [guid]::Empty }
    $inheritedObjectTypeGuid = if ($objectAce -and
        ($objectAce.ObjectAceFlags -band
            [System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent)) {
        $objectAce.InheritedObjectAceType
    }
    else { [guid]::Empty }
    $inheritanceMask = [int]$Ace.AceFlags -band (
        [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
        [int][System.Security.AccessControl.AceFlags]::InheritOnly -bor
        [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit
    )
    $inheritanceType = switch ($inheritanceMask) {
        0 { [WindowsActiveDirectoryInheritance]::None }
        2 { [WindowsActiveDirectoryInheritance]::All }
        10 { [WindowsActiveDirectoryInheritance]::Descendents }
        6 { [WindowsActiveDirectoryInheritance]::SelfAndChildren }
        14 { [WindowsActiveDirectoryInheritance]::Children }
        default { [WindowsActiveDirectoryInheritance]::None }
    }
    $isInherited = ([int]$Ace.AceFlags -band
        [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0
    $result = [pscustomobject]@{
        ObjectType = 'ADObject'
        Server = $Target.Server
        DistinguishedName = $Target.DistinguishedName
        ObjectGuid = $Target.ObjectGuid
        CanonicalTarget = $Target.CanonicalTarget
        Account = $account
        SID = $qualifiedAce.SecurityIdentifier.Value
        IsOrphaned = $isOrphaned
        AccessMask = [uint64]([int64]$knownAce.AccessMask -band 0xFFFFFFFFL)
        AccessRights = [System.Enum]::ToObject(
            [WindowsActiveDirectoryRights],
            $knownAce.AccessMask
        )
        AccessControlType = if ($qualifiedAce.AceQualifier -eq
            [System.Security.AccessControl.AceQualifier]::AccessDenied) {
            [System.Security.AccessControl.AccessControlType]::Deny
        }
        else {
            [System.Security.AccessControl.AccessControlType]::Allow
        }
        InheritanceType = $inheritanceType
        IsInherited = $isInherited
        InheritedFrom = if ($isInherited -and -not [string]::IsNullOrEmpty($InheritedFrom)) {
            $InheritedFrom
        }
        else { $null }
        ObjectTypeGuid = $objectTypeGuid
        ObjectTypeName = Get-WindowsADSchemaGuidDisplayName `
            -Guid $objectTypeGuid -SchemaGuidName $SchemaGuidName
        InheritedObjectTypeGuid = $inheritedObjectTypeGuid
        InheritedObjectTypeName = Get-WindowsADSchemaGuidDisplayName `
            -Guid $inheritedObjectTypeGuid -SchemaGuidName $SchemaGuidName
        IdentityReference = $qualifiedAce.SecurityIdentifier
        NativeAce = $Ace
    }
    $result.PSObject.TypeNames.Insert(0, 'WindowsAccessControl.ADObjectAccessRule')
    $result.PSObject.TypeNames.Add('WindowsAccessControl.Rule')
    $result
}
