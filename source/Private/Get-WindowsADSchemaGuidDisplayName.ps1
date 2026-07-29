function Get-WindowsADSchemaGuidDisplayName {
    <#
        .SYNOPSIS
            Returns the resolved name of one directory ACE GUID.

        .DESCRIPTION
            Returns null for an empty GUID and for a GUID that no schema or
            control-access lookup resolved, so an unresolved value never hides
            the GUID that the rule object still reports.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [guid]$Guid,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary]$SchemaGuidName
    )

    if ($Guid -eq [guid]::Empty -or -not $SchemaGuidName) {
        return $null
    }
    $key = $Guid.ToString('D').ToLowerInvariant()
    if (-not $SchemaGuidName.Contains($key)) {
        return $null
    }
    $name = [string]$SchemaGuidName[$key]
    if ([string]::IsNullOrEmpty($name)) {
        return $null
    }
    $name
}
