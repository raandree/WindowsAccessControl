function Resolve-WindowsADServer {
    <#
        .SYNOPSIS
            Returns the domain controller that serves one Active Directory command.

        .DESCRIPTION
            Validates an explicit DNS domain-controller name, or locates one
            writable domain controller in the current computer's domain when no
            name is supplied. The caller pins the returned name for every target
            in the invocation so one consistency point is used throughout.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Server
    )

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        return Resolve-WindowsADServerName -Server $Server
    }

    Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
    $domain = $null
    $controller = $null
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $controller = $domain.FindDomainController(
            [System.DirectoryServices.ActiveDirectory.LocatorOptions]::WriteableRequired
        )
        $discoveredName = $controller.Name
    }
    catch {
        throw [System.InvalidOperationException]::new(
            'Cannot locate a writable domain controller for the current computer domain. Supply an explicit Server name.',
            $_.Exception
        )
    }
    finally {
        if ($controller) { $controller.Dispose() }
        if ($domain) { $domain.Dispose() }
    }

    $resolvedName = Resolve-WindowsADServerName -Server $discoveredName
    Write-Verbose "Using discovered writable domain controller '$resolvedName'."
    $resolvedName
}
