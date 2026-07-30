function Get-WindowsSecurityDescriptorRecordHash {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [psobject]$Record
    )

    $stream = [System.IO.MemoryStream]::new()
    try {
        $writer = [System.IO.BinaryWriter]::new(
            $stream,
            [System.Text.UTF8Encoding]::new($false),
            $true
        )
        try {
            $recordVersion = [int]$Record.RecordVersion
            $writer.Write('WindowsAccessControl.SecurityDescriptorBackupRecord')
            $writer.Write($recordVersion)
            # Version 1 keeps its original field set so existing local-family
            # backups still validate; version 2 additionally binds the explicit
            # server authority and immutable enterprise target identity.
            $hashedProperties = @(
                'ObjectFamily'
                'Target'
                'Path'
                'CanonicalTarget'
                'ItemType'
                'RegistryView'
                'ProcessId'
                'CreationTimeFileTime'
                'Sddl'
            )
            if ($recordVersion -ge 2) {
                $hashedProperties += @(
                    'Server'
                    'ShareName'
                    'DistinguishedName'
                    'ObjectGuid'
                    'DomainNamingContext'
                )
            }
            foreach ($propertyName in $hashedProperties) {
                $property = $Record.PSObject.Properties[$propertyName]
                $propertyValue = if ($property -and $null -ne $property.Value) {
                    if ($propertyName -in @('ProcessId', 'CreationTimeFileTime')) {
                        ([long]$property.Value).ToString(
                            [System.Globalization.CultureInfo]::InvariantCulture
                        )
                    } else {
                        [string]$property.Value
                    }
                } else {
                    [string]::Empty
                }
                $writer.Write($propertyValue)
            }
            $writer.Write([int]$Record.Sections)
            $writer.Flush()
        } finally {
            $writer.Dispose()
        }

        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hash = $sha256.ComputeHash($stream.ToArray())
            ,$hash
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}
