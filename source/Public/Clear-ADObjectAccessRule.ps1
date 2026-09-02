function Clear-ADObjectAccessRule {
    <#
    .SYNOPSIS
        Removes explicit access rules from bounded Active Directory object DACLs.
    .DESCRIPTION
        Removes every explicit ACE from the selected object DACLs, or only the
        explicit ACEs of the selected accounts, and leaves inherited ACEs
        untouched. Both allow and deny rules are removed, so removing a deny can
        increase effective access; the command warns when that happens. The write
        is rejected when the result would leave no principal able to manage the
        object.
    .PARAMETER Server
        The explicit DNS name of the final writable domain controller. When it
        is omitted, one writable domain controller is located in the current
        computer's domain and pinned for the whole command.
    .PARAMETER DistinguishedName
        One or more distinguished names to modify.
    .PARAMETER AllowedBaseDistinguishedName
        The organizational unit that bounds every permitted mutation.
    .PARAMETER Credential
        An optional credential used only for the direct LDAP bind to Server.
    .PARAMETER Account
        Restricts removal to these account names, SIDs, identity references, or
        module identities. All explicit rules are removed when it is omitted.
    .PARAMETER TimeoutSeconds
        Sets the LDAP request timeout from 1 through 300 seconds.
    .PARAMETER ThrottleLimit
        Limits concurrently processed immutable object targets from 1 through 64.
    .PARAMETER PassThru
        Returns the removed explicit access rules after persistence.
    .EXAMPLE
        Clear-ADObjectAccessRule -Server dc01.example.test -DistinguishedName $dn -AllowedBaseDistinguishedName $ou -Account $sid -WhatIf

        Previews removing every explicit ACE for one account inside the allowed OU.
    .EXAMPLE
        Clear-ADObjectAccessRule -DistinguishedName $dn -AllowedBaseDistinguishedName $ou -WhatIf

        Previews removing every explicit ACE from the object, including ACEs
        for accounts not named in this command. Inherited ACEs and the guard
        against leaving no principal able to manage the object still apply.
    .EXAMPLE
        Clear-ADObjectAccessRule -DistinguishedName $dn -AllowedBaseDistinguishedName $ou -Account 'CONTOSO\FormerContractors', 'CONTOSO\Legacy' -Confirm:$false -PassThru

        Removes every explicit ACE for two accounts and returns what was
        removed, including any deny rule.
    .INPUTS
        System.String
    .OUTPUTS
        None
        WindowsAccessControl.ADObjectAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string]$Server,
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Path')]
        [object[]]$DistinguishedName,
        [Parameter(Mandatory)]
        [string]$AllowedBaseDistinguishedName,
        [Parameter()]
        [pscredential]$Credential,
        [Parameter()]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,
        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10,
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),
        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $seen = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $identities = @(
            foreach ($accountValue in $Account) {
                $sid = Resolve-WindowsIdentityReference -Identity $accountValue
                if ($seen.Add($sid.Value)) { $sid }
            }
        )
    }
    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Assert-WindowsADDistinguishedNameInput -DistinguishedName $DistinguishedName
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
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact High
            return
        }
        foreach ($dnValue in $DistinguishedName) {
            $target = Resolve-WindowsADObjectTarget `
                -Server $Server `
                -DistinguishedName ([string]$dnValue) `
                -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                -Credential $Credential `
                -TimeoutSeconds $TimeoutSeconds `
                -ForWrite
            $accountLabel = if ($identities.Count -gt 0) {
                $identities.Value -join ', '
            }
            else { 'all accounts' }
            $descriptor = $target.BinarySecurityDescriptor
            if ($identities.Count -eq 0) {
                $descriptor = Invoke-WindowsADAccessRuleMutation `
                    -SecurityDescriptor $descriptor `
                    -Operation Clear
            }
            else {
                foreach ($sid in $identities) {
                    $descriptor = Invoke-WindowsADAccessRuleMutation `
                        -SecurityDescriptor $descriptor `
                        -Operation Clear `
                        -SecurityIdentifier $sid
                }
            }
            # Disclose a deny removal in the description so it is visible under
            # WhatIf and before a confirmation prompt is answered.
            $denyCount = @(
                Get-WindowsADRemovedAce `
                    -OriginalSecurityDescriptor $target.BinarySecurityDescriptor `
                    -SecurityDescriptor $descriptor |
                    Where-Object {
                        ($_ -as [System.Security.AccessControl.QualifiedAce]).AceQualifier -eq
                            [System.Security.AccessControl.AceQualifier]::AccessDenied
                    }
            ).Count
            $action = "Clear explicit Active Directory access rules for $accountLabel"
            if ($denyCount -gt 0) {
                $action += " including $denyCount explicit deny rule(s), which can increase effective access"
            }
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, $action)) {
                $removed = if ($PassThru) {
                    @(Get-WindowsADRemovedAccessRule `
                        -Target $target `
                        -OriginalSecurityDescriptor $target.BinarySecurityDescriptor `
                        -SecurityDescriptor $descriptor)
                }
                Set-WindowsADObjectSecurityDescriptor `
                    -Target $target `
                    -AllowedBaseDistinguishedName $AllowedBaseDistinguishedName `
                    -Credential $Credential `
                    -TimeoutSeconds $TimeoutSeconds `
                    -SecurityDescriptor $descriptor `
                    -ExpectedSecurityDescriptor $target.BinarySecurityDescriptor `
                    -RequireManageableDacl
                if ($denyCount -gt 0) {
                    Write-Warning (
                        "Clearing $($target.CanonicalTarget) removed $denyCount " +
                        'explicit deny rule(s), which can increase effective access.'
                    )
                }
                if ($PassThru) {
                    foreach ($rule in $removed) { $rule }
                }
            }
        }
    }
}
