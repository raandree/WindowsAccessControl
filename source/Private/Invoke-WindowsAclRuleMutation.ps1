function Invoke-WindowsAclRuleMutation {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [ValidateSet('Access', 'Audit')]
        [string]$RuleType,

        [Parameter(Mandatory)]
        [ValidateSet('Add', 'Set', 'Remove', 'Clear')]
        [string]$Operation,

        [Parameter()]
        [System.Security.Principal.SecurityIdentifier]$SecurityIdentifier,

        [Parameter()]
        [int]$AccessMask,

        [Parameter()]
        [System.Security.AccessControl.AccessControlType]$AccessControlType =
            [System.Security.AccessControl.AccessControlType]::Allow,

        [Parameter()]
        [System.Security.AccessControl.AceFlags]$AceFlags =
            [System.Security.AccessControl.AceFlags]::None,

        [Parameter()]
        [System.Security.AccessControl.GenericAce]$NativeAce
    )

    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $SecurityDescriptor,
        0
    )
    if ($RuleType -eq 'Audit') {
        $acl = $descriptor.SystemAcl
    } else {
        $acl = $descriptor.DiscretionaryAcl
    }
    if (-not $acl) {
        if ($RuleType -eq 'Access') {
            throw 'The security descriptor does not contain a non-null access ACL.'
        }
        if ($Operation -in @('Clear', 'Remove')) {
            return $SecurityDescriptor
        }
        $acl = [System.Security.AccessControl.RawAcl]::new(
            [System.Security.AccessControl.GenericAcl]::AclRevision,
            0
        )
        $descriptor.SystemAcl = $acl
        $descriptor.SetFlags(
            [System.Security.AccessControl.ControlFlags](
                [int]$descriptor.ControlFlags -bor
                    [int][System.Security.AccessControl.ControlFlags]::SystemAclPresent
            )
        )
    }

    $qualifier = if ($RuleType -eq 'Audit') {
        [System.Security.AccessControl.AceQualifier]::SystemAudit
    } elseif ($AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
        [System.Security.AccessControl.AceQualifier]::AccessDenied
    } else {
        [System.Security.AccessControl.AceQualifier]::AccessAllowed
    }
    $auditAceFlagMask =
        [int][System.Security.AccessControl.AceFlags]::SuccessfulAccess -bor
        [int][System.Security.AccessControl.AceFlags]::FailedAccess

    $testRuleMatch = {
        param(
            $ace,
            $exact,
            $matchRuleType,
            $matchQualifier,
            $matchSecurityIdentifier,
            $matchAccessMask,
            $matchAceFlags,
            $matchAuditAceFlagMask
        )

        $qualifiedAce = $ace -as [System.Security.AccessControl.QualifiedAce]
        $knownAce = $ace -as [System.Security.AccessControl.KnownAce]
        if (-not $qualifiedAce -or -not $knownAce -or
            ([int]$ace.AceFlags -band
                [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0 -or
            $qualifiedAce.AceQualifier -ne $matchQualifier -or
            $qualifiedAce.SecurityIdentifier -ne $matchSecurityIdentifier) {
            return $false
        }
        if ($matchRuleType -eq 'Audit' -and
            ([int]$ace.AceFlags -band $matchAuditAceFlagMask) -ne
                ([int]$matchAceFlags -band $matchAuditAceFlagMask)) {
            return $false
        }
        if (-not $exact) {
            return $true
        }
        if ($knownAce.AccessMask -ne $matchAccessMask) {
            return $false
        }
        $true
    }
    $matchArguments = @(
        $RuleType
        $qualifier
        $SecurityIdentifier
        $AccessMask
        $AceFlags
        $auditAceFlagMask
    )

    if ($Operation -eq 'Clear') {
        for ($index = $acl.Count - 1; $index -ge 0; $index--) {
            $ace = $acl[$index]
            $qualifiedAce = $ace -as [System.Security.AccessControl.QualifiedAce]
            if (-not $qualifiedAce -or
                ([int]$ace.AceFlags -band
                    [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0) {
                continue
            }
            $isAuditAce = $qualifiedAce.AceQualifier -eq (
                [System.Security.AccessControl.AceQualifier]::SystemAudit
            )
            if (($RuleType -eq 'Audit') -ne $isAuditAce) {
                continue
            }
            if ($SecurityIdentifier -and
                $qualifiedAce.SecurityIdentifier -ne $SecurityIdentifier) {
                continue
            }
            $acl.RemoveAce($index)
        }
    } elseif ($Operation -eq 'Remove') {
        if ($NativeAce) {
            $qualifiedNativeAce = $NativeAce -as [System.Security.AccessControl.QualifiedAce]
            $knownNativeAce = $NativeAce -as [System.Security.AccessControl.KnownAce]
            if (-not $qualifiedNativeAce -or -not $knownNativeAce) {
                throw 'NativeAce must be a qualified known ACE.'
            }
            $SecurityIdentifier = $qualifiedNativeAce.SecurityIdentifier
            $AccessMask = $knownNativeAce.AccessMask
            $qualifier = $qualifiedNativeAce.AceQualifier
            $AceFlags = $NativeAce.AceFlags
            $testNativeAceMatch = {
                param($ace, $matchQualifier, $matchSecurityIdentifier, $matchAccessMask, $matchAceFlags)

                $qualifiedAce = $ace -as [System.Security.AccessControl.QualifiedAce]
                $knownAce = $ace -as [System.Security.AccessControl.KnownAce]
                $qualifiedAce -and $knownAce -and
                    ([int]$ace.AceFlags -band
                        [int][System.Security.AccessControl.AceFlags]::Inherited) -eq 0 -and
                    $qualifiedAce.AceQualifier -eq $matchQualifier -and
                    $qualifiedAce.SecurityIdentifier -eq $matchSecurityIdentifier -and
                    $knownAce.AccessMask -eq $matchAccessMask -and
                    $ace.AceFlags -eq $matchAceFlags
            }
        }
        for ($index = $acl.Count - 1; $index -ge 0; $index--) {
            $isMatch = if ($NativeAce) {
                $nativeMatchArguments = @(
                    $qualifier
                    $SecurityIdentifier
                    $AccessMask
                    $AceFlags
                )
                & $testNativeAceMatch $acl[$index] @nativeMatchArguments
            } else {
                & $testRuleMatch $acl[$index] $true @matchArguments
            }
            if ($isMatch) {
                $acl.RemoveAce($index)
                break
            }
        }
    } else {
        if (-not $SecurityIdentifier) {
            throw 'SecurityIdentifier is required for Add and Set operations.'
        }
        if ($Operation -eq 'Set') {
            for ($index = $acl.Count - 1; $index -ge 0; $index--) {
                if (& $testRuleMatch $acl[$index] $false @matchArguments) {
                    $acl.RemoveAce($index)
                }
            }
        }

        $newAce = [System.Security.AccessControl.CommonAce]::new(
            $AceFlags,
            $qualifier,
            $AccessMask,
            $SecurityIdentifier,
            $false,
            $null
        )
        $duplicate = $false
        for ($index = 0; $index -lt $acl.Count; $index++) {
            if (& $testRuleMatch $acl[$index] $true @matchArguments) {
                $duplicate = $true
                break
            }
        }
        if (-not $duplicate) {
            $insertIndex = $acl.Count
            for ($index = 0; $index -lt $acl.Count; $index++) {
                $existingAce = $acl[$index]
                $existingQualified = $existingAce -as [System.Security.AccessControl.QualifiedAce]
                $isInherited = ([int]$existingAce.AceFlags -band (
                    [int][System.Security.AccessControl.AceFlags]::Inherited
                )) -ne 0
                if ($isInherited -or
                    ($RuleType -eq 'Access' -and
                    $qualifier -eq [System.Security.AccessControl.AceQualifier]::AccessDenied -and
                    $existingQualified -and
                    $existingQualified.AceQualifier -eq (
                        [System.Security.AccessControl.AceQualifier]::AccessAllowed
                    ))) {
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
