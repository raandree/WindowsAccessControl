function Get-WindowsADObjectInheritanceSource {
    <#
        .SYNOPSIS
            Resolves the ancestor object of every inherited DACL ACE.

        .DESCRIPTION
            Returns one entry per DACL ACE, in ACL order, so callers can align
            results by ACE index. An entry is empty for an explicit ACE and for
            an inherited ACE whose origin cannot be identified. An empty result
            means no inherited ACE is present at all.

            Windows exposes GetInheritanceSourceW for directory objects, but
            that call locates its own domain controller and cannot honor the
            server and credential this connection is already bound to. The
            ancestor chain is therefore walked over the same signed and sealed
            connection, and each inherited ACE is matched to the nearest
            ancestor that holds an equivalent explicit inheritable ACE.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedName,

        [Parameter(Mandatory)]
        [byte[]]$SecurityDescriptor,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$NamingContext
    )

    $inheritedFlag = [int][System.Security.AccessControl.AceFlags]::Inherited
    $containerFlag = [int][System.Security.AccessControl.AceFlags]::ContainerInherit
    $noPropagateFlag = [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit

    $acl = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $SecurityDescriptor,
        0
    ).DiscretionaryAcl
    if (-not $acl -or $acl.Count -eq 0) {
        return , [string[]]@()
    }
    $inheritedIndexes = @(
        for ($index = 0; $index -lt $acl.Count; $index++) {
            if (([int]$acl[$index].AceFlags -band $inheritedFlag) -ne 0) {
                $index
            }
        }
    )
    if ($inheritedIndexes.Count -eq 0) {
        return , [string[]]@()
    }

    $ancestorNames = [System.Collections.Generic.List[string]]::new()
    $currentName = $DistinguishedName
    while (-not $currentName.Equals($NamingContext, [StringComparison]::OrdinalIgnoreCase)) {
        $parentName = Get-WindowsADParentDistinguishedName -DistinguishedName $currentName
        if ([string]::IsNullOrEmpty($parentName)) {
            break
        }
        $ancestorNames.Add($parentName)
        $currentName = $parentName
    }

    $ancestors = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($ancestorName in $ancestorNames) {
        try {
            $record = Get-WindowsADObjectRecord `
                -Connection $Connection `
                -DistinguishedName $ancestorName `
                -IncludeSecurityDescriptor
            $ancestorDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                $record.SecurityDescriptor,
                0
            )
            $ancestorAcl = $ancestorDescriptor.DiscretionaryAcl
        }
        catch {
            # An ancestor the caller cannot read truncates the walk. Reporting
            # a more distant ancestor would name the wrong origin.
            Write-Verbose "Cannot read the Active Directory ancestor '$ancestorName': $($_.Exception.Message) Inheritance sources beyond it are not reported."
            break
        }
        $entries = @(
            if ($ancestorAcl) {
                foreach ($candidate in $ancestorAcl) {
                    $qualified = $candidate -as [System.Security.AccessControl.QualifiedAce]
                    if ($qualified) {
                        [pscustomobject]@{
                            Key = Get-WindowsADAceIdentity -Ace $qualified
                            Flags = [int]$qualified.AceFlags
                        }
                    }
                    else {
                        [pscustomobject]@{ Key = $null; Flags = 0 }
                    }
                }
            }
        )
        $ancestors.Add([pscustomobject]@{
                DistinguishedName = $record.DistinguishedName
                Entries = $entries
                Consumed = [bool[]]::new($entries.Count)
            })
        $isProtected = ([int]$ancestorDescriptor.ControlFlags -band
            [int][System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0
        if ($isProtected) {
            # Nothing above a protected DACL can propagate through it.
            break
        }
    }

    $sources = [string[]]::new($acl.Count)
    foreach ($index in $inheritedIndexes) {
        $ace = $acl[$index] -as [System.Security.AccessControl.QualifiedAce]
        if (-not $ace) {
            continue
        }
        $key = Get-WindowsADAceIdentity -Ace $ace
        # Windows clears ContainerInherit on a propagated copy only when the
        # originating ACE stopped propagation with NoPropagateInherit.
        $keepsPropagating = ([int]$ace.AceFlags -band $containerFlag) -ne 0
        for ($level = 0; $level -lt $ancestors.Count; $level++) {
            $ancestor = $ancestors[$level]
            $matchedIndex = -1
            for ($entryIndex = 0; $entryIndex -lt $ancestor.Entries.Count; $entryIndex++) {
                $entry = $ancestor.Entries[$entryIndex]
                if ($ancestor.Consumed[$entryIndex] -or -not $entry.Key) {
                    continue
                }
                if (($entry.Flags -band $containerFlag) -eq 0 -or
                    ($entry.Flags -band $inheritedFlag) -ne 0) {
                    continue
                }
                $stopsPropagating = ($entry.Flags -band $noPropagateFlag) -ne 0
                if ($keepsPropagating -eq $stopsPropagating) {
                    continue
                }
                # NoPropagateInherit stops an ACE one level below its container.
                if ($level -gt 0 -and $stopsPropagating) {
                    continue
                }
                if ($entry.Key -ne $key) {
                    continue
                }
                $matchedIndex = $entryIndex
                break
            }
            if ($matchedIndex -ge 0) {
                $ancestor.Consumed[$matchedIndex] = $true
                $sources[$index] = $ancestor.DistinguishedName
                break
            }
        }
    }

    , [string[]]$sources
}
