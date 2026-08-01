function Get-WindowsMachineCertificateStoreName {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    # A binding can name any local machine store, so a fixed list would leave a
    # bound thumbprint unresolvable and turn the critical-binding gate into a
    # machine-wide write denial. Every store that exists is discovered instead.
    # These are the three registry roots the local machine store location is
    # composed from. The .NET registry API is used rather than the HKLM PSDrive,
    # which is not present in every runspace, and it reports an absent key as a
    # null handle instead of an exception type a caller has to guess.
    $roots = @(
        'SOFTWARE\Microsoft\SystemCertificates'
        'SOFTWARE\Policies\Microsoft\SystemCertificates'
        'SOFTWARE\Microsoft\EnterpriseCertificates'
    )
    # A binding names one of these in practice, so probing them first lets a
    # caller stop before it opens every remaining store.
    $preferred = 'My', 'WebHosting', 'Remote Desktop'
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $discovered = [Collections.Generic.List[string]]::new()
    foreach ($root in $roots) {
        $key = $null
        try {
            try {
                $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($root)
            }
            catch {
                # A root that exists but cannot be read would silently narrow
                # the search and send a caller to fix a healthy certificate.
                throw [InvalidOperationException]::new(
                    (
                        "The local machine certificate store root '$root' could not be read, " +
                        "so a bound certificate cannot be resolved: $($_.Exception.Message)"
                    )
                )
            }
            if ($null -eq $key) {
                continue
            }
            foreach ($name in $key.GetSubKeyNames()) {
                if ($seen.Add($name)) {
                    $discovered.Add($name)
                }
            }
        }
        finally {
            if ($key) {
                $key.Dispose()
            }
        }
    }
    if ($discovered.Count -eq 0) {
        throw [InvalidOperationException]::new(
            (
                'No local machine certificate store could be enumerated under ' +
                "$($roots -join ', '), so a bound certificate cannot be resolved."
            )
        )
    }

    foreach ($name in $preferred) {
        if ($seen.Contains($name)) {
            $name
        }
    }
    foreach ($name in $discovered) {
        if ($name -notin $preferred) {
            $name
        }
    }
}
