function Set-WindowsAclProtection {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This private helper mutates only an in-memory descriptor.'
    )]
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [ValidateSet('Access', 'Audit', 'All')]
        [string]$Section,

        [Parameter(Mandatory)]
        [bool]$Protected,

        [Parameter()]
        [bool]$PreserveInherited = $true,

        [Parameter()]
        [switch]$RemoveExplicitRules
    )

    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $SecurityDescriptor,
        0
    )
    $controlFlagMask = [int]$descriptor.ControlFlags
    $aclDefinitions = @()
    if ($Section -in @('Access', 'All')) {
        $aclDefinitions += [pscustomobject]@{
            PropertyName  = 'DiscretionaryAcl'
            ProtectedFlag = [int][System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
            PresentFlag   = [int][System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent
        }
    }
    if ($Section -in @('Audit', 'All')) {
        $aclDefinitions += [pscustomobject]@{
            PropertyName  = 'SystemAcl'
            ProtectedFlag = [int][System.Security.AccessControl.ControlFlags]::SystemAclProtected
            PresentFlag   = [int][System.Security.AccessControl.ControlFlags]::SystemAclPresent
        }
    }

    foreach ($definition in $aclDefinitions) {
        $acl = $descriptor.($definition.PropertyName)
        if (-not $acl) {
            if ($definition.PropertyName -eq 'DiscretionaryAcl') {
                throw 'The security descriptor does not contain a non-null access ACL.'
            }
            $acl = [System.Security.AccessControl.RawAcl]::new(
                [System.Security.AccessControl.GenericAcl]::AclRevision,
                0
            )
            $controlFlagMask = $controlFlagMask -bor $definition.PresentFlag
        }
        $newAcl = [System.Security.AccessControl.RawAcl]::new($acl.Revision, $acl.Count)
        for ($index = 0; $index -lt $acl.Count; $index++) {
            $ace = $acl[$index]
            $isInherited = ([int]$ace.AceFlags -band (
                [int][System.Security.AccessControl.AceFlags]::Inherited
            )) -ne 0
            if ($Protected -and $isInherited -and -not $PreserveInherited) {
                continue
            }
            if (-not $Protected -and $RemoveExplicitRules -and -not $isInherited) {
                continue
            }
            $aceBytes = [byte[]]::new($ace.BinaryLength)
            $ace.GetBinaryForm($aceBytes, 0)
            $clonedAce = [System.Security.AccessControl.GenericAce]::CreateFromBinaryForm(
                $aceBytes,
                0
            )
            if ($Protected -and $isInherited -and $PreserveInherited) {
                $clonedAce.AceFlags = [System.Security.AccessControl.AceFlags](
                    [int]$clonedAce.AceFlags -band
                        (-bnot [int][System.Security.AccessControl.AceFlags]::Inherited)
                )
            }
            $newAcl.InsertAce($newAcl.Count, $clonedAce)
        }
        $descriptor.($definition.PropertyName) = $newAcl
        if ($Protected) {
            $controlFlagMask = $controlFlagMask -bor $definition.ProtectedFlag
        } else {
            $controlFlagMask = $controlFlagMask -band (-bnot $definition.ProtectedFlag)
        }
    }
    $descriptor.SetFlags(
        [System.Security.AccessControl.ControlFlags]$controlFlagMask
    )
    $result = [byte[]]::new($descriptor.BinaryLength)
    $descriptor.GetBinaryForm($result, 0)
    $result
}
