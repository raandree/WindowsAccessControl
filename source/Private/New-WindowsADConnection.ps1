function New-WindowsADConnection {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This function constructs an in-memory LDAP connection and changes no target state.'
    )]
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.Protocols.LdapConnection])]
    param(
        [Parameter(Mandatory)]
        [string]$Server,

        [Parameter()]
        [pscredential]$Credential,

        [Parameter(Mandatory)]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds
    )

    Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
    $serverName = Resolve-WindowsADServerName -Server $Server
    $identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new(
        $serverName,
        389,
        $true,
        $false
    )
    $connection = if ($Credential) {
        [System.DirectoryServices.Protocols.LdapConnection]::new(
            $identifier,
            $Credential.GetNetworkCredential(),
            [System.DirectoryServices.Protocols.AuthType]::Kerberos
        )
    }
    else {
        [System.DirectoryServices.Protocols.LdapConnection]::new($identifier)
    }
    try {
        $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Kerberos
        $connection.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $connection.SessionOptions.ProtocolVersion = 3
        $connection.SessionOptions.ReferralChasing =
            [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
        $connection.SessionOptions.Signing = $true
        $connection.SessionOptions.Sealing = $true
        $connection.Bind()
        $connection
    }
    catch {
        $connection.Dispose()
        throw
    }
}
