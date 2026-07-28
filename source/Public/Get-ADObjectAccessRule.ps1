function Get-ADObjectAccessRule {
    <#
    .SYNOPSIS
        Gets typed access rules from Active Directory object DACLs.
    .DESCRIPTION
        Reads object DACLs over signed and sealed LDAP and preserves common or
        object-specific ACE masks, inheritance, GUIDs, and immutable targets.
    .PARAMETER Server
        The explicit DNS name of the final writable domain controller.
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
    .PARAMETER TimeoutSeconds
        Sets the LDAP request timeout from 1 through 300 seconds.
    .PARAMETER ThrottleLimit
        Limits concurrently processed immutable object targets from 1 through 64.
    .EXAMPLE
        Get-ADObjectAccessRule -Server dc01.example.test -DistinguishedName $dn -Account Everyone

        Gets Everyone access rules from the selected directory object.
    .INPUTS
        System.String
    .OUTPUTS
        WindowsAccessControl.ADObjectAccessRule
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
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
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10,
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount))
    )

    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsADCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Server $Server `
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
        foreach ($dnValue in $DistinguishedName) {
            $target = Resolve-WindowsADObjectTarget `
                -Server $Server `
                -DistinguishedName ([string]$dnValue) `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds
            $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                $target.BinarySecurityDescriptor,
                0
            )
            for ($index = 0; $index -lt $descriptor.DiscretionaryAcl.Count; $index++) {
                $ace = $descriptor.DiscretionaryAcl[$index]
                $qualified = $ace -as [System.Security.AccessControl.QualifiedAce]
                if (-not $qualified) { continue }
                $isInherited = ([int]$ace.AceFlags -band
                    [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0
                if (($ExcludeInherited -and $isInherited) -or
                    ($ExcludeExplicit -and -not $isInherited) -or
                    ($accountSids.Count -gt 0 -and
                        $qualified.SecurityIdentifier.Value -notin $accountSids)) {
                    continue
                }
                ConvertTo-WindowsADAccessRuleObject -Ace $ace -Target $target
            }
        }
    }
}
