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
    $currentAceKeys = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($ace in @($CurrentDescriptor.DiscretionaryAcl)) {
        $aceKey = ConvertTo-WindowsCngKeyAceKey -Ace $ace
        $currentAceKeys.Add($aceKey) | Out-Null
        if ($ace.AceType -ne [Security.AccessControl.AceType]::AccessDenied) {
            continue
        }
        $currentDenies.Add($aceKey) | Out-Null
    }

    foreach ($ace in @($CandidateDescriptor.DiscretionaryAcl)) {
        if ($ace.AceType -notin $plainTypes) {
            # The ACE can come from the stored DACL rather than from the caller,
            # for example when a desired-state pass reasserts a key that already
            # carries a conditional ACE. Naming the source makes the refusal
            # actionable instead of blaming the request.
            if ($currentAceKeys.Contains((ConvertTo-WindowsCngKeyAceKey -Ace $ace))) {
                throw [NotSupportedException]::new(
                    (
                        "The stored private-key DACL already contains an ACE of type " +
                        "'$($ace.AceType)', which cannot be verified after a write. Remove that " +
                        'ACE before managing this key.'
                    )
                )
            }
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
