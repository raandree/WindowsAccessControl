function Invoke-WindowsCngKeyAclRuleMutation {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [ValidateSet('Add', 'Remove')]
        [string]$Operation,

        [Parameter()]
        [Security.Principal.SecurityIdentifier[]]$SecurityIdentifier,

        [Parameter()]
        [long]$AccessMask,

        [Parameter()]
        [Security.AccessControl.AccessControlType]$AccessControlType =
            [Security.AccessControl.AccessControlType]::Allow
    )

    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($SecurityDescriptor, 0)
    $acl = $descriptor.DiscretionaryAcl
    if (-not $acl) {
        throw [InvalidOperationException]::new(
            'The private-key security descriptor does not contain a non-null access ACL.'
        )
    }
    $qualifier = if ($AccessControlType -eq
        [Security.AccessControl.AccessControlType]::Deny) {
        [Security.AccessControl.AceQualifier]::AccessDenied
    }
    else {
        [Security.AccessControl.AceQualifier]::AccessAllowed
    }

    if ($Operation -eq 'Add') {
        $requested = ConvertTo-WindowsCryptoKeyEffectiveMask -AccessMask $AccessMask
        foreach ($sid in $SecurityIdentifier) {
            $alreadyPresent = $false
            foreach ($ace in $acl) {
                $qualifiedAce = $ace -as [Security.AccessControl.QualifiedAce]
                if (-not $qualifiedAce -or
                    ([int]$ace.AceFlags -band
                        [int][Security.AccessControl.AceFlags]::Inherited) -ne 0 -or
                    $qualifiedAce.AceQualifier -ne $qualifier -or
                    $qualifiedAce.SecurityIdentifier -ne $sid) {
                    continue
                }
                $existing = ConvertTo-WindowsCryptoKeyEffectiveMask `
                    -AccessMask ([long]$qualifiedAce.AccessMask)
                if ($existing -eq $requested) {
                    $alreadyPresent = $true
                    break
                }
            }
            if ($alreadyPresent) {
                continue
            }
            # A deny ACE must precede every allow ACE so the provider stores a
            # canonical DACL.
            $insertIndex = if ($qualifier -eq
                [Security.AccessControl.AceQualifier]::AccessDenied) {
                0
            }
            else {
                $acl.Count
            }
            $acl.InsertAce(
                $insertIndex,
                [Security.AccessControl.CommonAce]::new(
                    [Security.AccessControl.AceFlags]::None,
                    $qualifier,
                    # A generic mask such as GENERIC_READ exceeds Int32, so the
                    # unsigned value is reinterpreted rather than cast.
                    [BitConverter]::ToInt32(
                        [BitConverter]::GetBytes([uint32]($AccessMask -band 0xFFFFFFFFL)),
                        0
                    ),
                    $sid,
                    $false,
                    $null
                )
            )
        }
    }
    else {
        $removeIndexes = [Collections.Generic.List[int]]::new()
        for ($index = 0; $index -lt $acl.Count; $index++) {
            $ace = $acl[$index]
            $qualifiedAce = $ace -as [Security.AccessControl.QualifiedAce]
            if (-not $qualifiedAce -or
                ([int]$ace.AceFlags -band
                    [int][Security.AccessControl.AceFlags]::Inherited) -ne 0) {
                continue
            }
            if ($qualifiedAce.AceQualifier -ne $qualifier -or
                $qualifiedAce.SecurityIdentifier -notin $SecurityIdentifier) {
                continue
            }
            $existing = ConvertTo-WindowsCryptoKeyEffectiveMask `
                -AccessMask ([long]$qualifiedAce.AccessMask)
            $requested = ConvertTo-WindowsCryptoKeyEffectiveMask -AccessMask $AccessMask
            if ($existing -eq $requested) {
                $removeIndexes.Add($index)
            }
        }
        for ($index = $removeIndexes.Count - 1; $index -ge 0; $index--) {
            $acl.RemoveAce($removeIndexes[$index])
        }
    }

    $bytes = [byte[]]::new($descriptor.BinaryLength)
    $descriptor.GetBinaryForm($bytes, 0)
    Write-Output -InputObject $bytes -NoEnumerate
}
