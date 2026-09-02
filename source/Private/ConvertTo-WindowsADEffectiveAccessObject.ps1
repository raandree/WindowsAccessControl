function ConvertTo-WindowsADEffectiveAccessObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter(Mandatory)]
        [pscustomobject]$Record,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Account
    )

    $writableAttribute = @($Record.WritableAttribute | Sort-Object)
    $creatableChildClass = @($Record.CreatableChildClass | Sort-Object)
    $result = [pscustomobject]@{
        ObjectType = 'ADObject'
        Server = $Target.Server
        DistinguishedName = $Target.DistinguishedName
        ObjectGuid = $Target.ObjectGuid
        CanonicalTarget = $Target.CanonicalTarget
        Account = $Account
        WritableAttribute = $writableAttribute
        WritableAttributeCount = $writableAttribute.Count
        CreatableChildClass = $creatableChildClass
        CreatableChildClassCount = $creatableChildClass.Count
        SDRightsEffective = [int]$Record.SDRightsEffective
        # sDRightsEffective carries the OWNER, GROUP, DACL, and SACL bits of
        # SECURITY_INFORMATION, which are the values of this enum.
        WritableDescriptorSection = [WindowsSecurityDescriptorSection](
            [int]$Record.SDRightsEffective
        )
        AuthorizationContext = 'DomainControllerCallerScoped'
    }
    $result.PSObject.TypeNames.Insert(
        0,
        'WindowsAccessControl.ADObjectCallerEffectiveAccess'
    )
    $result
}
