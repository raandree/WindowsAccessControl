function Invoke-WindowsADAccessRuleMutation {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [ValidateSet('Add', 'Remove')]
        [string]$Operation,

        [Parameter()]
        [System.Security.Principal.SecurityIdentifier]$SecurityIdentifier,

        [Parameter()]
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
        [guid]$InheritedObjectType = [guid]::Empty,

        [Parameter()]
        [System.Security.AccessControl.GenericAce]$NativeAce
    )

    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $SecurityDescriptor,
        0
    )
    $acl = $descriptor.DiscretionaryAcl
    if (-not $acl) {
        throw 'The Active Directory security descriptor contains a null DACL.'
    }

    $getAceBytes = {
        param([System.Security.AccessControl.GenericAce]$Ace)

        $bytes = [byte[]]::new($Ace.BinaryLength)
        $Ace.GetBinaryForm($bytes, 0)
        [Convert]::ToBase64String($bytes)
    }

    if ($Operation -eq 'Remove') {
        if (-not $NativeAce) {
            throw 'NativeAce is required for exact Active Directory rule removal.'
        }
        $expected = & $getAceBytes $NativeAce
        for ($index = $acl.Count - 1; $index -ge 0; $index--) {
            if ((& $getAceBytes $acl[$index]) -ceq $expected) {
                if (([int]$acl[$index].AceFlags -band
                    [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0) {
                    throw 'Inherited Active Directory access rules cannot be removed directly.'
                }
                $acl.RemoveAce($index)
                break
            }
        }
    }
    else {
        if (-not $SecurityIdentifier) {
            throw 'SecurityIdentifier is required for Active Directory rule addition.'
        }
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
        $newAce = if ($objectAceFlags -ne
            [System.Security.AccessControl.ObjectAceFlags]::None) {
            [System.Security.AccessControl.ObjectAce]::new(
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
        else {
            [System.Security.AccessControl.CommonAce]::new(
                $aceFlags,
                $qualifier,
                $AccessMask,
                $SecurityIdentifier,
                $false,
                $null
            )
        }
        $expected = & $getAceBytes $newAce
        $duplicate = @(
            $acl | Where-Object { (& $getAceBytes $_) -ceq $expected }
        ).Count -gt 0
        if (-not $duplicate) {
            $insertIndex = $acl.Count
            for ($index = 0; $index -lt $acl.Count; $index++) {
                $existingAce = $acl[$index]
                $existingQualified = $existingAce -as (
                    [System.Security.AccessControl.QualifiedAce]
                )
                $isInherited = ([int]$existingAce.AceFlags -band
                    [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0
                if ($isInherited -or
                    ($qualifier -eq
                        [System.Security.AccessControl.AceQualifier]::AccessDenied -and
                        $existingQualified -and
                        $existingQualified.AceQualifier -eq
                            [System.Security.AccessControl.AceQualifier]::AccessAllowed)) {
                    $insertIndex = $index
                    break
                }
            }
            $acl.InsertAce($insertIndex, $newAce)
        }
    }

    $result = [byte[]]::new($descriptor.BinaryLength)
    $descriptor.GetBinaryForm($result, 0)
    $result
}
