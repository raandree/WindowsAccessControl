function Get-WindowsTaskSchedulerServiceTokenSid {
    <#
        Returns the identities whose ACEs can affect the Task Scheduler service
        token. The set is the live LocalSystem token group membership captured
        for the Schedule service plus NT SERVICE\ALL SERVICES, and it is a
        best-effort static list: a different Windows SKU or build can carry
        additional groups.
    #>
    [CmdletBinding()]
    [OutputType([Collections.Generic.HashSet[string]])]
    param()

    $serviceTokenSids = [Collections.Generic.HashSet[string]]::new(
        [string[]]@(
            'S-1-5-18'
            'S-1-1-0'
            'S-1-2-0'
            'S-1-2-1'
            'S-1-5-6'
            'S-1-5-11'
            'S-1-5-15'
            'S-1-5-32-544'
            'S-1-5-32-545'
            'S-1-5-32-554'
            'S-1-5-80-0'
        ),
        [StringComparer]::OrdinalIgnoreCase
    )
    try {
        $scheduleSid = [Security.Principal.NTAccount]::new('NT SERVICE\Schedule').Translate(
            [Security.Principal.SecurityIdentifier]
        )
        $null = $serviceTokenSids.Add($scheduleSid.Value)
    }
    catch [Security.Principal.IdentityNotMappedException] {
        Write-Verbose -Message 'The NT SERVICE\Schedule identity could not be resolved; using the well-known service-token SIDs only.'
    }
    , $serviceTokenSids
}
