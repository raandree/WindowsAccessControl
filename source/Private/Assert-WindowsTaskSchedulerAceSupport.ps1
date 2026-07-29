function Assert-WindowsTaskSchedulerAceSupport {
    <#
        Task Scheduler stores object and compound ACEs verbatim but the store
        then normalizes the DACL revision from 2 to 4, so an exact-persistence
        check reports a false mismatch and rolls the write back. Those ACE
        types also carry no Task Scheduler meaning, so reject them explicitly
        instead of writing a descriptor the adapter cannot verify.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor
    )

    foreach ($ace in $SecurityDescriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce]) {
            throw [NotSupportedException]::new(
                "Task Scheduler DACLs support only common ACEs; '$($ace.GetType().Name)' entries are rejected because the store normalizes the ACL revision and the write cannot be verified."
            )
        }
    }
}
