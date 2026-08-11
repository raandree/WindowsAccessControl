function Get-ADObjectAccessRule {
    <#
    .SYNOPSIS
        Gets typed access rules from Active Directory object DACLs.
    .DESCRIPTION
        Reads object DACLs over signed and sealed LDAP and preserves common or
        object-specific ACE masks, inheritance, GUIDs, and immutable targets.
        Inherited rules expose InheritedFrom with the ancestor object that holds
        the originating explicit ACE, and object GUIDs are additionally reported
        as resolved schema, property-set, or extended-right names.
    .PARAMETER Server
        The explicit DNS name of the final writable domain controller. When it
        is omitted, one writable domain controller is located in the current
        computer's domain and pinned for the whole command.
    .PARAMETER DistinguishedName
        One or more distinguished names to query.
    .PARAMETER Credential
        An optional credential used only for the direct LDAP bind to Server.
    .PARAMETER Account
        Filters results by account names, SIDs, identity references, or module identities.
    .PARAMETER ExcludeInherited
        Excludes inherited access rules.
    .PARAMETER ExcludeExplicit
        Excludes explicit access rules.
    .PARAMETER ExcludeSchemaDefault
        Excludes every explicit rule that the target's structural class already
        grants through its defaultSecurityDescriptor, leaving the entries an
        operator added. A rule is excluded only when a template entry equals it
        on account, access mask, access control type, inheritance, and both
        object type GUIDs; anything the comparison cannot decide is reported.
        Inherited rules, and the entries a template placeholder such as CREATOR
        OWNER became, are never excluded.
    .PARAMETER TimeoutSeconds
        Sets the LDAP request timeout from 1 through 300 seconds.
    .PARAMETER ThrottleLimit
        Limits concurrently processed immutable object targets from 1 through 64.
    .EXAMPLE
        Get-ADObjectAccessRule -Server dc01.example.test -DistinguishedName $dn -Account Everyone

        Gets Everyone access rules from the selected directory object.
    .EXAMPLE
        Get-ADObjectAccessRule -DistinguishedName $dn -ExcludeExplicit

        Gets inherited rules, with their source object and resolved GUID names,
        through an automatically located writable domain controller.
    .EXAMPLE
        Get-ADObjectAccessRule -DistinguishedName $dn -ExcludeInherited -ExcludeSchemaDefault

        Gets the explicit rules the object's class default does not already
        grant, which is the delegation an operator configured.
    .INPUTS
        System.String
    .OUTPUTS
        WindowsAccessControl.ADObjectAccessRule
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string]$Server,
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Path')]
        [object[]]$DistinguishedName,
        [Parameter()]
        [pscredential]$Credential,
        [Parameter()]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,
        [Parameter()]
        [switch]$ExcludeInherited,
        [Parameter()]
        [switch]$ExcludeExplicit,
        [Parameter()]
        [switch]$ExcludeSchemaDefault,
        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10,
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount))
    )

    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            if (-not $pinnedServer) {
                $pinnedServer = Resolve-WindowsADServer -Server $Server
            }
            $PSBoundParameters['Server'] = $pinnedServer
            Invoke-WindowsADCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Server $pinnedServer `
                -DistinguishedName $DistinguishedName `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds `
                -ThrottleLimit $ThrottleLimit
            return
        }
        $accountSids = @(
            foreach ($accountValue in $Account) {
                (Resolve-WindowsIdentityReference -Identity $accountValue).Value
            }
        )
        $connection = New-WindowsADConnection `
            -Server $Server `
            -Credential $Credential `
            -TimeoutSeconds $TimeoutSeconds
        $schemaDefaultByClass = @{}
        $rootDse = $null
        $domainSidPair = $null
        try {
            foreach ($dnValue in $DistinguishedName) {
                $target = Resolve-WindowsADObjectTarget `
                    -Server $Server `
                    -DistinguishedName ([string]$dnValue) `
                    -Credential $Credential `
                    -TimeoutSeconds $TimeoutSeconds `
                    -Connection $connection
                $acl = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                    $target.BinarySecurityDescriptor,
                    0
                ).DiscretionaryAcl
                if (-not $acl) {
                    continue
                }
                $selectedIndexes = @(
                    for ($index = 0; $index -lt $acl.Count; $index++) {
                        $qualified = $acl[$index] -as [System.Security.AccessControl.QualifiedAce]
                        if (-not $qualified) { continue }
                        $isInherited = ([int]$acl[$index].AceFlags -band
                            [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0
                        if (($ExcludeInherited -and $isInherited) -or
                            ($ExcludeExplicit -and -not $isInherited) -or
                            ($accountSids.Count -gt 0 -and
                                $qualified.SecurityIdentifier.Value -notin $accountSids)) {
                            continue
                        }
                        $index
                    }
                )
                if ($selectedIndexes.Count -eq 0) {
                    continue
                }
                $enrichment = Get-WindowsADRuleEnrichment `
                    -Connection $connection `
                    -Target $target `
                    -Ace @(foreach ($index in $selectedIndexes) { $acl[$index] }) `
                    -SkipInheritanceSource:$ExcludeInherited

                $rules = foreach ($index in $selectedIndexes) {
                    $inheritedFrom = if ($index -lt $enrichment.InheritanceSource.Count) {
                        $enrichment.InheritanceSource[$index]
                    }
                    else { $null }
                    ConvertTo-WindowsADAccessRuleObject `
                        -Ace $acl[$index] `
                        -Target $target `
                        -InheritedFrom $inheritedFrom `
                        -SchemaGuidName $enrichment.SchemaGuidName
                }
                if ($ExcludeSchemaDefault) {
                    # Active Directory returns objectClass from top down to the
                    # structural class, which is the only template it applies.
                    $structuralClass = @($target.ObjectClasses)[-1]
                    if (-not $schemaDefaultByClass.ContainsKey($structuralClass)) {
                        if (-not $rootDse) {
                            $rootDse = Get-WindowsADRootDse -Connection $connection
                            $domainSidPair = Get-WindowsADDomainSidPair `
                                -Connection $connection `
                                -RootDse $rootDse `
                                -Server $Server `
                                -Credential $Credential `
                                -TimeoutSeconds $TimeoutSeconds
                        }
                        $schemaDefaultByClass[$structuralClass] = @(
                            Get-WindowsADSchemaDefaultRule `
                                -Connection $connection `
                                -Server $Server `
                                -ObjectClass $structuralClass `
                                -RootDse $rootDse `
                                -DomainSid $domainSidPair.DomainSid `
                                -RootDomainSid $domainSidPair.RootDomainSid
                        )
                    }
                    $rules = Select-WindowsADNonDefaultAccessRule `
                        -Rule @($rules) `
                        -SchemaDefault $schemaDefaultByClass[$structuralClass]
                }
                $rules
            }
        }
        finally {
            $connection.Dispose()
        }
    }
}
