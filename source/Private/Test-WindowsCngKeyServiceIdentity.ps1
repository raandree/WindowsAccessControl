function Test-WindowsCngKeyServiceIdentity {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SecurityIdentifier
    )

    # LOCAL SERVICE, NETWORK SERVICE, per-service SIDs (NT SERVICE\*), and IIS
    # application-pool SIDs identify a running workload that may already depend
    # on this key. Removing such a grant can stop a service that this module
    # cannot see.
    switch -Regex ($SecurityIdentifier) {
        '^S-1-5-19$' { return $true }
        '^S-1-5-20$' { return $true }
        '^S-1-5-80-' { return $true }
        '^S-1-5-82-' { return $true }
        default { return $false }
    }
}
