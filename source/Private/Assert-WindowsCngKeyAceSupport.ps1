function Assert-WindowsCngKeyAceSupport {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$CurrentDescriptor,

        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$CandidateDescriptor
    )

    $plainTypes = @(
        [Security.AccessControl.AceType]::AccessAllowed
        [Security.AccessControl.AceType]::AccessDenied
    )

    $currentDenies = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($ace in @($CurrentDescriptor.DiscretionaryAcl)) {
        if ($ace.AceType -ne [Security.AccessControl.AceType]::AccessDenied) {
            continue
        }
        $currentDenies.Add((ConvertTo-WindowsCngKeyAceKey -Ace $ace)) | Out-Null
    }

    foreach ($ace in @($CandidateDescriptor.DiscretionaryAcl)) {
        if ($ace.AceType -notin $plainTypes) {
            throw [NotSupportedException]::new(
                (
                    "The candidate private-key DACL contains an ACE of type '$($ace.AceType)'. " +
                    'Only plain allow and deny ACEs are supported, because a callback, ' +
                    'conditional, or object ACE cannot be verified after the write.'
                )
            )
        }
        if ($ace.AceType -ne [Security.AccessControl.AceType]::AccessDenied) {
            continue
        }
        # A new deny ACE is the one change that can lock every recovery identity
        # out of the key through a containing group, which no per-SID grant check
        # can detect. An existing deny stays so a caller can still reassert or
        # remove it.
        if (-not $currentDenies.Contains((ConvertTo-WindowsCngKeyAceKey -Ace $ace))) {
            throw [NotSupportedException]::new(
                (
                    'The candidate private-key DACL adds a deny ACE. A deny ACE naming a group ' +
                    'that contains SYSTEM or Administrators would lock the key, so only deny ' +
                    'ACEs that already exist on the key are accepted.'
                )
            )
        }
    }
}
