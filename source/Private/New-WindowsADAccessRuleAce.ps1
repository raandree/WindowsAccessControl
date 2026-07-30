function New-WindowsADAccessRuleAce {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This function constructs an in-memory ACE and changes no target state.'
    )]
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.CommonAce])]
    [OutputType([System.Security.AccessControl.ObjectAce])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$SecurityIdentifier,

        [Parameter(Mandatory)]
        [int]$AccessMask,

        [Parameter()]
        [System.Security.AccessControl.AccessControlType]$AccessControlType =
            [System.Security.AccessControl.AccessControlType]::Allow,

        [Parameter()]
        [WindowsActiveDirectoryInheritance]$InheritanceType =
            [WindowsActiveDirectoryInheritance]::None,

        [Parameter()]
        [guid]$ObjectType = [guid]::Empty,

        [Parameter()]
        [guid]$InheritedObjectType = [guid]::Empty
    )

    $aceFlags = ConvertTo-WindowsADAceFlag -InheritanceType $InheritanceType
    $qualifier = if ($AccessControlType -eq
        [System.Security.AccessControl.AccessControlType]::Deny) {
        [System.Security.AccessControl.AceQualifier]::AccessDenied
    }
    else {
        [System.Security.AccessControl.AceQualifier]::AccessAllowed
    }
    $objectAceFlags = [System.Security.AccessControl.ObjectAceFlags]::None
    if ($ObjectType -ne [guid]::Empty) {
        $objectAceFlags = $objectAceFlags -bor
            [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent
    }
    if ($InheritedObjectType -ne [guid]::Empty) {
        $objectAceFlags = $objectAceFlags -bor
            [System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent
    }
    if ($objectAceFlags -ne [System.Security.AccessControl.ObjectAceFlags]::None) {
        return [System.Security.AccessControl.ObjectAce]::new(
            $aceFlags,
            $qualifier,
            $AccessMask,
            $SecurityIdentifier,
            $objectAceFlags,
            $ObjectType,
            $InheritedObjectType,
            $false,
            $null
        )
    }
    [System.Security.AccessControl.CommonAce]::new(
        $aceFlags,
        $qualifier,
        $AccessMask,
        $SecurityIdentifier,
        $false,
        $null
    )
}
