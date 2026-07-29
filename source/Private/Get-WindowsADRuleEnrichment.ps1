function Get-WindowsADRuleEnrichment {
    <#
        .SYNOPSIS
            Resolves inheritance sources and GUID names for directory rules.

        .DESCRIPTION
            Returns the ACL-aligned inheritance sources and the GUID name map
            used to enrich directory access rules. Either lookup can fail after
            the object descriptor is already in hand, so a failure degrades the
            affected enrichment through a non-terminating error instead of
            discarding a successful descriptor read.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [Parameter()]
        [AllowEmptyCollection()]
        [System.Security.AccessControl.GenericAce[]]$Ace = @(),

        [Parameter()]
        [switch]$SkipInheritanceSource
    )

    $inheritanceSources = [string[]]@()
    if (-not $SkipInheritanceSource) {
        try {
            $inheritanceSources = Get-WindowsADObjectInheritanceSource `
                -Connection $Connection `
                -DistinguishedName $Target.DistinguishedName `
                -SecurityDescriptor $Target.BinarySecurityDescriptor `
                -NamingContext $Target.DefaultNamingContext
        }
        catch {
            $inheritanceSources = [string[]]@()
            Write-Error `
                -Message "Cannot resolve inheritance sources for '$($Target.DistinguishedName)': $($_.Exception.Message) Access rules are reported without an inheritance source." `
                -Category ReadError `
                -TargetObject $Target.DistinguishedName
        }
    }

    $ruleGuids = @(
        foreach ($value in $Ace) {
            $objectAce = $value -as [System.Security.AccessControl.ObjectAce]
            if (-not $objectAce) { continue }
            if ($objectAce.ObjectAceFlags -band
                [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent) {
                $objectAce.ObjectAceType
            }
            if ($objectAce.ObjectAceFlags -band
                [System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent) {
                $objectAce.InheritedObjectAceType
            }
        }
    )
    $schemaGuidName = $null
    if ($ruleGuids.Count -gt 0) {
        try {
            $schemaGuidName = Resolve-WindowsADSchemaGuidName `
                -Connection $Connection `
                -SchemaNamingContext $Target.SchemaNamingContext `
                -ConfigurationNamingContext $Target.ConfigurationNamingContext `
                -Guid $ruleGuids
        }
        catch {
            $schemaGuidName = $null
            Write-Error `
                -Message "Cannot resolve directory schema names for '$($Target.DistinguishedName)': $($_.Exception.Message) Access rules are reported with object GUIDs only." `
                -Category ReadError `
                -TargetObject $Target.DistinguishedName
        }
    }

    [pscustomobject]@{
        InheritanceSource = $inheritanceSources
        SchemaGuidName = $schemaGuidName
    }
}
