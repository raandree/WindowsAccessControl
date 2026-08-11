function Resolve-WindowsADObjectTypeGuid {
    <#
        .SYNOPSIS
            Resolves object type parameter values to directory GUIDs.

        .DESCRIPTION
            Returns the empty GUID for an omitted value and the parsed value
            when the caller already supplied a GUID. Any other value is looked
            up over one bound connection as the lDAPDisplayName or common name
            of a schema class or attribute, or as the display name or common
            name of a control access right, which covers property sets,
            validated writes, and extended rights.

            A name that matches nothing, that matches more than one GUID, or
            that cannot be looked up because no server was supplied throws. The
            empty GUID widens an entry scoped to one object or property into
            one that applies to every object and every property, so an
            unresolved name must never fall back to it.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$ObjectType,

        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$InheritedObjectType,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [pscredential]$Credential,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10
    )

    $requested = [ordered]@{
        ObjectType = $ObjectType
        InheritedObjectType = $InheritedObjectType
    }
    $resolved = [ordered]@{}
    $pending = [ordered]@{}
    foreach ($parameterName in $requested.Keys) {
        $text = if ($null -eq $requested[$parameterName]) {
            ''
        }
        else {
            $requested[$parameterName].Trim()
        }
        $parsed = [guid]::Empty
        if ($text.Length -eq 0 -or [guid]::TryParse($text, [ref]$parsed)) {
            $resolved[$parameterName] = $parsed
            continue
        }
        $pending[$parameterName] = $text
    }
    if ($pending.Count -eq 0) {
        return [pscustomobject]$resolved
    }
    if ([string]::IsNullOrWhiteSpace($Server)) {
        throw "Resolving '$($pending.Values -join "', '")' to an Active Directory GUID requires a domain controller. Supply Server, or supply the GUID instead of the name."
    }

    $connection = New-WindowsADConnection `
        -Server (Resolve-WindowsADServerName -Server $Server) `
        -Credential $Credential `
        -TimeoutSeconds $TimeoutSeconds
    try {
        $rootDse = Get-WindowsADRootDse -Connection $connection
        foreach ($parameterName in @($pending.Keys)) {
            $resolved[$parameterName] = Find-WindowsADObjectTypeGuid `
                -Connection $connection `
                -SchemaNamingContext $rootDse.SchemaNamingContext `
                -ConfigurationNamingContext $rootDse.ConfigurationNamingContext `
                -Name $pending[$parameterName] `
                -ParameterName $parameterName
        }
    }
    finally {
        $connection.Dispose()
    }
    [pscustomobject]$resolved
}
