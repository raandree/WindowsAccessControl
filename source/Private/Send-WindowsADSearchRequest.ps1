function Send-WindowsADSearchRequest {
    <#
        Sends one LDAP search over a bound connection and returns its response.
        A request for an object that does not exist fails with
        ItemNotFoundException. Get-WindowsADObjectRecord, Get-WindowsADRootDse,
        and Get-WindowsADEffectiveAccessRecord reach the directory only through
        this function, so unit tests can supply a response without a domain
        controller.
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.Protocols.SearchResponse])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.SearchRequest]$Request
    )

    # The catch stays beside the native call: once the exception leaves a
    # function, PowerShell reports it as MethodInvocationException and the
    # result code below is no longer reachable through $_.Exception.
    try {
        [System.DirectoryServices.Protocols.SearchResponse](
            $Connection.SendRequest($Request)
        )
    }
    catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        if ($_.Exception.Response.ResultCode -eq
            [System.DirectoryServices.Protocols.ResultCode]::NoSuchObject) {
            throw [System.Management.Automation.ItemNotFoundException]::new(
                "Active Directory object was not found: '$($Request.DistinguishedName)'."
            )
        }
        throw
    }
}
