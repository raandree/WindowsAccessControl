function Assert-WindowsADManageableDacl {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter()]
        [byte[]]$CurrentSecurityDescriptor
    )

    $testManageable = {
        param([byte[]]$Candidate)

        $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            $Candidate,
            0
        )
        $acl = $descriptor.DiscretionaryAcl
        if (-not $acl) {
            throw 'The Active Directory security descriptor contains a null DACL.'
        }

        # WindowsActiveDirectoryRights.GenericAll already contains WriteDacl, so the
        # two specific bits plus the native GENERIC_ALL bit cover every manage grant
        # without matching an ACE that only carries a low-order specific right.
        # WriteOwner counts because its holder can take ownership and then rewrite
        # the DACL.
        $manageMask =
            [int][WindowsActiveDirectoryRights]::WriteDacl -bor
            [int][WindowsActiveDirectoryRights]::WriteOwner -bor
            0x10000000
        $inheritOnly = [int][System.Security.AccessControl.AceFlags]::InheritOnly
        $denied = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )

        # The DACL read from nTSecurityDescriptor already contains inherited ACEs, and
        # a canonical directory DACL orders deny before allow, so one ordered pass is
        # enough to find a principal that still holds WRITE_DAC on the object itself.
        foreach ($ace in $acl) {
            $qualifiedAce = $ace -as [System.Security.AccessControl.QualifiedAce]
            $knownAce = $ace -as [System.Security.AccessControl.KnownAce]
            if (-not $qualifiedAce -or -not $knownAce) {
                continue
            }
            if (([int]$ace.AceFlags -band $inheritOnly) -ne 0) {
                continue
            }
            # An object-scoped ACE grants its rights over a property set or extended
            # right, not over the object's own DACL, so it is not manage authority.
            $objectAce = $ace -as [System.Security.AccessControl.ObjectAce]
            if ($objectAce -and
                ([int]$objectAce.ObjectAceFlags -band
                    [int][System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent) -ne 0) {
                continue
            }
            if (([int]$knownAce.AccessMask -band $manageMask) -eq 0) {
                continue
            }
            $sid = $qualifiedAce.SecurityIdentifier.Value
            if ($qualifiedAce.AceQualifier -eq
                [System.Security.AccessControl.AceQualifier]::AccessDenied) {
                $null = $denied.Add($sid)
                continue
            }
            if ($qualifiedAce.AceQualifier -eq
                [System.Security.AccessControl.AceQualifier]::AccessAllowed -and
                -not $denied.Contains($sid)) {
                return $true
            }
        }
        $false
    }

    if (& $testManageable $SecurityDescriptor) {
        return
    }
    # Do not attribute a pre-existing condition to this request. A current
    # descriptor that cannot even be evaluated is treated the same way.
    if ($CurrentSecurityDescriptor) {
        $currentIsManageable = try {
            & $testManageable $CurrentSecurityDescriptor
        }
        catch {
            $false
        }
        if (-not $currentIsManageable) {
            Write-Warning (
                "The DACL for $Target already grants no principal WriteDacl or " +
                'WriteOwner. This request does not change that.'
            )
            return
        }
    }

    throw ("The requested DACL for $Target would leave no principal with " +
        'WriteDacl or WriteOwner on the object, so only its owner could manage ' +
        'it. This is a lockout guard for the common case, not a proof of ' +
        'recoverability. Use Set-ADObjectSecurityDescriptor to apply such a ' +
        'descriptor explicitly.')
}
