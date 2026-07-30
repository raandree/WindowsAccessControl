function Invoke-WindowsADAccessRuleMutation {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [ValidateSet('Add', 'Set', 'Remove', 'RemoveRights', 'Clear')]
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

    # An ACE shares a rule scope only when its qualifier, account, and both object
    # GUIDs match, so an object ACE is never folded into a common ACE.
    $testScopeMatch = {
        param(
            [System.Security.AccessControl.GenericAce]$Ace,
            $Qualifier,
            $Sid,
            $ScopeObjectType,
            $ScopeInheritedObjectType
        )

        $qualifiedAce = $Ace -as [System.Security.AccessControl.QualifiedAce]
        $knownAce = $Ace -as [System.Security.AccessControl.KnownAce]
        if (-not $qualifiedAce -or -not $knownAce) {
            return $false
        }
        if (([int]$Ace.AceFlags -band
            [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0) {
            return $false
        }
        if ($qualifiedAce.AceQualifier -ne $Qualifier -or
            $qualifiedAce.SecurityIdentifier -ne $Sid) {
            return $false
        }
        $aceObjectType = [guid]::Empty
        $aceInheritedObjectType = [guid]::Empty
        $objectAce = $Ace -as [System.Security.AccessControl.ObjectAce]
        if ($objectAce) {
            if (([int]$objectAce.ObjectAceFlags -band
                [int][System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent) -ne 0) {
                $aceObjectType = $objectAce.ObjectAceType
            }
            if (([int]$objectAce.ObjectAceFlags -band
                [int][System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent) -ne 0) {
                $aceInheritedObjectType = $objectAce.InheritedObjectAceType
            }
        }
        $aceObjectType -eq $ScopeObjectType -and
            $aceInheritedObjectType -eq $ScopeInheritedObjectType
    }

    $qualifier = if ($AccessControlType -eq
        [System.Security.AccessControl.AccessControlType]::Deny) {
        [System.Security.AccessControl.AceQualifier]::AccessDenied
    }
    else {
        [System.Security.AccessControl.AceQualifier]::AccessAllowed
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
    elseif ($Operation -eq 'Clear') {
        for ($index = $acl.Count - 1; $index -ge 0; $index--) {
            $ace = $acl[$index]
            $qualifiedAce = $ace -as [System.Security.AccessControl.QualifiedAce]
            if (-not $qualifiedAce -or
                ([int]$ace.AceFlags -band
                    [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0) {
                continue
            }
            if ($SecurityIdentifier -and
                $qualifiedAce.SecurityIdentifier -ne $SecurityIdentifier) {
                continue
            }
            $acl.RemoveAce($index)
        }
    }
    elseif ($Operation -eq 'RemoveRights') {
        if (-not $SecurityIdentifier) {
            throw 'SecurityIdentifier is required for Active Directory rights removal.'
        }
        # Active Directory stores GENERIC_* bits verbatim and maps them at access
        # check time, so expand a stored generic bit before subtracting any of the
        # specific rights it confers. Subtracting from the raw bit would silently
        # retain the grant.
        $genericMap = [ordered]@{
            0x10000000L = [long][WindowsActiveDirectoryRights]::GenericAll
            0x40000000L = [long][WindowsActiveDirectoryRights]::GenericWrite
            0x80000000L = [long][WindowsActiveDirectoryRights]::GenericRead
            0x20000000L = [long][WindowsActiveDirectoryRights]::GenericExecute
        }
        $requestedMask = [long]$AccessMask -band 0xFFFFFFFFL
        for ($index = $acl.Count - 1; $index -ge 0; $index--) {
            $isMatch = & $testScopeMatch `
                $acl[$index] $qualifier $SecurityIdentifier $ObjectType $InheritedObjectType
            if (-not $isMatch) {
                continue
            }
            $stored = [long]$acl[$index].AccessMask -band 0xFFFFFFFFL
            foreach ($genericBit in $genericMap.Keys) {
                if (($stored -band $genericBit) -ne 0 -and
                    ($requestedMask -band $genericMap[$genericBit]) -ne 0) {
                    $stored = ($stored -band (-bnot $genericBit)) -bor $genericMap[$genericBit]
                }
            }
            $remaining = ($stored -band (-bnot $requestedMask)) -band 0xFFFFFFFFL
            if ($remaining -eq 0) {
                $acl.RemoveAce($index)
            }
            else {
                $acl[$index].AccessMask = [BitConverter]::ToInt32(
                    [BitConverter]::GetBytes([uint32]$remaining),
                    0
                )
            }
        }
    }
    else {
        if (-not $SecurityIdentifier) {
            throw 'SecurityIdentifier is required for Active Directory rule addition.'
        }
        if ($Operation -eq 'Set') {
            for ($index = $acl.Count - 1; $index -ge 0; $index--) {
                $isMatch = & $testScopeMatch `
                    $acl[$index] $qualifier $SecurityIdentifier $ObjectType $InheritedObjectType
                if ($isMatch) {
                    $acl.RemoveAce($index)
                }
            }
        }
        $newAce = New-WindowsADAccessRuleAce `
            -SecurityIdentifier $SecurityIdentifier `
            -AccessMask $AccessMask `
            -AccessControlType $AccessControlType `
            -InheritanceType $InheritanceType `
            -ObjectType $ObjectType `
            -InheritedObjectType $InheritedObjectType
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
