function Resolve-WindowsADServerName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Server
    )

    $serverName = $Server.Trim().TrimEnd('.')
    $parsedAddress = $null
    if ($serverName -notmatch '\.' -or
        [Uri]::CheckHostName($serverName) -ne [UriHostNameType]::Dns -or
        [Net.IPAddress]::TryParse($serverName, [ref]$parsedAddress) -or
        $serverName -in @('localhost', $env:COMPUTERNAME) -or
        $serverName -match '[:/\\]') {
        throw [System.ArgumentException]::new(
            "Server must be an explicit DNS domain-controller name: '$Server'."
        )
    }
    $serverName.ToLowerInvariant()
}
