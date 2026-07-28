function ConvertFrom-WindowsADAttributeValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Value
    )

    if ($Value -is [byte[]]) {
        [Text.Encoding]::UTF8.GetString([byte[]]$Value)
    }
    else {
        [string]$Value
    }
}
