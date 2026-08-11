function Select-WindowsADNonDefaultAccessRule {
    <#
        .SYNOPSIS
            Removes the rules a schema class template already accounts for.

        .DESCRIPTION
            Returns every rule that the structural class default does not
            positively explain. An explicit rule is removed only when a template
            entry equals it on trustee, access mask, access control type,
            inheritance type, and both object type GUIDs. Everything else is
            returned, because hiding an entry an operator added makes a live
            grant invisible while showing a redundant one is only noise.

            A template entry naming a creator placeholder is dropped from the
            baseline. Active Directory replaces it with the creating principal,
            and nothing on the created object separates that from a grant an
            operator made to the same principal.

            An inherited rule is never a candidate: it came from an ancestor
            rather than from this object's class default.

            The decision is a pure function over two collections so the cases in
            ADR 0033 are provable without a domain controller.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Rule,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$SchemaDefault
    )

    # CREATOR OWNER, CREATOR GROUP, and their server variants. OWNER RIGHTS
    # (S-1-3-4) is a real trustee and is deliberately absent.
    $creatorPlaceholder = @('S-1-3-0', 'S-1-3-1', 'S-1-3-2', 'S-1-3-3')
    $getEntryKey = {
        param($Entry)

        ([string]$Entry.SID) + '|' +
        ([uint64]$Entry.AccessMask).ToString() + '|' +
        ([string]$Entry.AccessControlType) + '|' +
        ([string]$Entry.InheritanceType) + '|' +
        ([guid]$Entry.ObjectTypeGuid).ToString('N') + '|' +
        ([guid]$Entry.InheritedObjectTypeGuid).ToString('N')
    }
    $defaultKeys = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($template in $SchemaDefault) {
        if ($null -eq $template -or [string]$template.SID -in $creatorPlaceholder) {
            continue
        }
        $null = $defaultKeys.Add((& $getEntryKey $template))
    }
    foreach ($candidate in $Rule) {
        if ($null -eq $candidate) {
            continue
        }
        if ($candidate.IsInherited -or
            -not $defaultKeys.Contains((& $getEntryKey $candidate))) {
            $candidate
        }
    }
}
