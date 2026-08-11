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
        try {
            $rootDse = Get-WindowsADRootDse -Connection $connection
            $domainSidPair = Get-WindowsADDomainSidPair `
                -Connection $connection `
                -RootDse $rootDse `
                -Server $pinnedServer `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds
        }
        catch {
            $connection.Dispose()
            throw
        }
    }
    process {
        foreach ($className in $ObjectClass) {
            Get-WindowsADSchemaDefaultRule `
                -Connection $connection `
                -Server $pinnedServer `
                -ObjectClass $className `
                -RootDse $rootDse `
                -DomainSid $domainSidPair.DomainSid `
                -RootDomainSid $domainSidPair.RootDomainSid
        }
    }
    end {
        $connection.Dispose()
    }
}
