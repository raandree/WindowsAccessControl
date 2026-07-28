function Resolve-WindowsADObjectTarget {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Server,

        [Parameter(Mandatory)]
        [string]$DistinguishedName,

        [Parameter()]
        [string]$AllowedBaseDistinguishedName,

        [Parameter()]
        [pscredential]$Credential,

        [Parameter(Mandatory)]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds,

        [Parameter()]
        [switch]$ForWrite,

        [Parameter()]
        [guid]$ExpectedObjectGuid = [guid]::Empty
    )

    $serverName = Resolve-WindowsADServerName -Server $Server
    $connection = New-WindowsADConnection `
        -Server $serverName `
        -Credential $Credential `
        -TimeoutSeconds $TimeoutSeconds
    try {
        $rootDse = Get-WindowsADRootDse -Connection $connection
        if (-not (Test-WindowsADDistinguishedNameWithinBase `
                -DistinguishedName $DistinguishedName `
                -BaseDistinguishedName $rootDse.DefaultNamingContext)) {
            throw 'Active Directory targets must be in the default domain naming context.'
        }
        if (Test-WindowsADExcludedPartition `
                -DistinguishedName $DistinguishedName `
                -RootDse $rootDse) {
            throw 'Active Directory targets in the configuration or schema partition are not supported.'
        }
        $record = Get-WindowsADObjectRecord `
            -Connection $connection `
            -DistinguishedName $DistinguishedName `
            -IncludeSecurityDescriptor
        if ($ExpectedObjectGuid -ne [guid]::Empty -and
            $record.ObjectGuid -ne $ExpectedObjectGuid) {
            throw 'The Active Directory object GUID no longer matches the path-bound target.'
        }

        if ($ForWrite) {
            if ([string]::IsNullOrWhiteSpace($AllowedBaseDistinguishedName)) {
                throw 'AllowedBaseDistinguishedName is required for Active Directory writes.'
            }
            if (-not (Test-WindowsADDistinguishedNameWithinBase `
                    -DistinguishedName $AllowedBaseDistinguishedName `
                    -BaseDistinguishedName $rootDse.DefaultNamingContext)) {
                throw 'The allowed Active Directory base must be in the default domain partition.'
            }
            $baseRecord = Get-WindowsADObjectRecord `
                -Connection $connection `
                -DistinguishedName $AllowedBaseDistinguishedName
            if ('organizationalUnit' -notin $baseRecord.ObjectClasses) {
                throw 'AllowedBaseDistinguishedName must resolve to an organizational unit.'
            }
            if (-not (Test-WindowsADDistinguishedNameWithinBase `
                    -DistinguishedName $record.DistinguishedName `
                    -BaseDistinguishedName $baseRecord.DistinguishedName)) {
                throw 'The Active Directory target is outside the allowed organizational unit.'
            }
            if (Test-WindowsADProtectedTarget -Record $record -RootDse $rootDse) {
                throw 'The selected Active Directory object is protected from mutation.'
            }
        }

        [pscustomobject]@{
            ObjectType = 'ADObject'
            Path = $record.DistinguishedName
            Server = $serverName
            DistinguishedName = $record.DistinguishedName
            ObjectGuid = $record.ObjectGuid
            ObjectClasses = $record.ObjectClasses
            BinarySecurityDescriptor = $record.SecurityDescriptor
            CanonicalTarget = 'ADObject:{0}:{1}' -f (
                $serverName.ToUpperInvariant()
            ), $record.ObjectGuid.ToString('D').ToUpperInvariant()
        }
    }
    finally {
        $connection.Dispose()
    }
}
