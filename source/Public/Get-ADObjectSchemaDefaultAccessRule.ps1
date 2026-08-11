function Get-ADObjectSchemaDefaultAccessRule {
    <#
    .SYNOPSIS
        Returns the default access rules a schema class applies to new objects.
    .DESCRIPTION
        Reads defaultSecurityDescriptor from one or more classSchema objects and
        returns the access control entries Active Directory itself applies when
        it creates an object of that class. The result is the baseline an
        explicit rule has to be compared against: without it, every default
        entry looks like operator configuration.

        The stored descriptor is SDDL that names domain-relative aliases such as
        DA and EA. Those are expanded against the SID of the domain the selected
        controller serves, and against the forest root domain SID where the
        alias is forest wide, rather than against the calling computer's own
        domain. A machine that is not domain joined cannot resolve them at all,
        so the expansion is what makes the read work from any host.

        The output is not path bound. It describes a template rather than the
        current state of any object and therefore cannot be piped into a rule
        mutator.
    .PARAMETER Server
        The explicit DNS name of the domain controller to read. When it is
        omitted, one writable domain controller is located in the current
        computer's domain and pinned for the whole command.
    .PARAMETER ObjectClass
        One or more schema class names, given as the lDAPDisplayName or the
        common name.
    .PARAMETER Credential
        An optional credential used only for the direct LDAP bind to Server.
    .PARAMETER TimeoutSeconds
        Sets the LDAP request timeout from 1 through 300 seconds.
    .EXAMPLE
        Get-ADObjectSchemaDefaultAccessRule -Server dc01.example.test -ObjectClass user

        Returns the entries Active Directory applies to every new user object.
    .EXAMPLE
        Get-ADObjectAccessRule -Server dc01.example.test -DistinguishedName $dn -ExcludeInherited |
            Where-Object SID -notin (Get-ADObjectSchemaDefaultAccessRule -Server dc01.example.test -ObjectClass user).SID

        Narrows explicit entries to the accounts the schema default does not
        already grant.
    .INPUTS
        System.String
    .OUTPUTS
        WindowsAccessControl.ADSchemaDefaultAccessRule
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string]$Server,
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Class')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ObjectClass,
        [Parameter()]
        [pscredential]$Credential,
        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10
    )

    begin {
        $pinnedServer = Resolve-WindowsADServer -Server $Server
        $connection = New-WindowsADConnection `
            -Server $pinnedServer `
            -Credential $Credential `
            -TimeoutSeconds $TimeoutSeconds
        $rootDse = Get-WindowsADRootDse -Connection $connection
        $domainSid = Get-WindowsADNamingContextSid `
            -Connection $connection `
            -NamingContext $rootDse.DefaultNamingContext
        if (-not $domainSid) {
            $connection.Dispose()
            throw "Cannot read the domain SID of '$($rootDse.DefaultNamingContext)' from '$pinnedServer'. Schema default rules cannot be expanded without it."
        }
        $rootDomainSid = if ($rootDse.RootDomainNamingContext -and
            $rootDse.RootDomainNamingContext -ne $rootDse.DefaultNamingContext) {
            Get-WindowsADNamingContextSid `
                -Connection $connection `
                -NamingContext $rootDse.RootDomainNamingContext
        }
        else { $domainSid }
    }
    process {
        foreach ($className in $ObjectClass) {
            $escaped = ConvertTo-WindowsADLdapFilterValue -Value $className
            $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
                $rootDse.SchemaNamingContext,
                '(&(objectClass=classSchema)(|(lDAPDisplayName={0})(cn={0})))' -f $escaped,
                [System.DirectoryServices.Protocols.SearchScope]::OneLevel,
                [string[]]@('lDAPDisplayName', 'defaultSecurityDescriptor')
            )
            $response = [System.DirectoryServices.Protocols.SearchResponse](
                $connection.SendRequest($request)
            )
            if ($response.Entries.Count -ne 1) {
                Write-Error `
                    -Message "Object class '$className' did not resolve to exactly one schema class on '$pinnedServer'." `
                    -Category ObjectNotFound `
                    -TargetObject $className
                continue
            }
            $entry = $response.Entries[0]
            $resolvedName = ConvertFrom-WindowsADAttributeValue `
                -Value $entry.Attributes['lDAPDisplayName'][0]
            if (-not $entry.Attributes.Contains('defaultSecurityDescriptor')) {
                Write-Verbose "Object class '$resolvedName' carries no defaultSecurityDescriptor."
                continue
            }
            $sddl = ConvertFrom-WindowsADAttributeValue `
                -Value $entry.Attributes['defaultSecurityDescriptor'][0]
            $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                (ConvertTo-WindowsADAbsoluteSddl `
                    -Sddl $sddl `
                    -DomainSid $domainSid `
                    -RootDomainSid $rootDomainSid)
            )
            $acl = $descriptor.DiscretionaryAcl
            if (-not $acl) {
                continue
            }
            $ruleGuids = @(
                foreach ($value in $acl) {
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
                        -Connection $connection `
                        -SchemaNamingContext $rootDse.SchemaNamingContext `
                        -ConfigurationNamingContext $rootDse.ConfigurationNamingContext `
                        -Guid $ruleGuids
                }
                catch {
                    $schemaGuidName = $null
                    Write-Error `
                        -Message "Cannot resolve directory schema names for '$resolvedName': $($_.Exception.Message) Rules are reported with object GUIDs only." `
                        -Category ReadError `
                        -TargetObject $resolvedName
                }
            }
            foreach ($ace in $acl) {
                ConvertTo-WindowsADSchemaDefaultRuleObject `
                    -Ace $ace `
                    -ObjectClass $resolvedName `
                    -Server $pinnedServer `
                    -SchemaGuidName $schemaGuidName
            }
        }
    }
    end {
        $connection.Dispose()
    }
}
