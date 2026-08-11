function ConvertTo-WindowsADSchemaDefaultRuleObject {
    <#
        .SYNOPSIS
            Converts one schema default access control entry into an object.

        .DESCRIPTION
            Emits the template entry a class carries in its
            defaultSecurityDescriptor. The result is deliberately not a
            path-bound rule: it describes what Active Directory applies when it
            creates an object of the class, not the current state of any object,
            so it carries no target identity and cannot be piped into a mutator.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.GenericAce]$Ace,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ObjectClass,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Server,

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
    try {
        $account = $qualifiedAce.SecurityIdentifier.Translate(
            [System.Security.Principal.NTAccount]
        ).Value
    }
    catch [System.Security.Principal.IdentityNotMappedException] {
        $account = $null
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
    $result = [pscustomobject]@{
        ObjectType = 'ADSchemaDefault'
        Server = $Server
        ObjectClass = $ObjectClass
        Account = $account
        SID = $qualifiedAce.SecurityIdentifier.Value
        AccessMask = [uint64]([int64]$knownAce.AccessMask -band 0xFFFFFFFFL)
        AccessRights = [System.Enum]::ToObject(
            [WindowsActiveDirectoryRights],
            $knownAce.AccessMask
        )
        AccessRightsDisplay = ConvertTo-WindowsAccessRightsDisplay `
            -AccessMask ([int64]$knownAce.AccessMask -band 0xFFFFFFFFL) `
            -RightsType ([WindowsActiveDirectoryRights])
        AccessControlType = if ($qualifiedAce.AceQualifier -eq
            [System.Security.AccessControl.AceQualifier]::AccessDenied) {
            [System.Security.AccessControl.AccessControlType]::Deny
        }
        else {
            [System.Security.AccessControl.AccessControlType]::Allow
        }
        InheritanceType = $inheritanceType
        ObjectTypeGuid = $objectTypeGuid
        ObjectTypeName = Get-WindowsADSchemaGuidDisplayName `
            -Guid $objectTypeGuid -SchemaGuidName $SchemaGuidName
        InheritedObjectTypeGuid = $inheritedObjectTypeGuid
        InheritedObjectTypeName = Get-WindowsADSchemaGuidDisplayName `
            -Guid $inheritedObjectTypeGuid -SchemaGuidName $SchemaGuidName
        IdentityReference = $qualifiedAce.SecurityIdentifier
        NativeAce = $Ace
    }
    $result.PSObject.TypeNames.Insert(
        0, 'WindowsAccessControl.ADSchemaDefaultAccessRule'
    )
    $result
}
