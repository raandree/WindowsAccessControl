function Add-SmbShareAccessRule {
    <#
    .SYNOPSIS
        Adds typed access rules to local SMB share DACLs.
    .DESCRIPTION
        Resolves and deduplicates every account before adding exact share ACEs
        and persists each target DACL once without touching backing NTFS ACLs.
    .PARAMETER Name
        One or more unqualified local SMB share names.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER AccessRights
        Share rights to add: Read, Change, or Full.
    .PARAMETER AccessControlType
        Adds an Allow rule by default or an explicit Deny rule.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical share targets from 1 through 64.
    .PARAMETER PassThru
        Returns the stored explicit share access rules after persistence.
    .EXAMPLE
        Add-SmbShareAccessRule -Name 'Data$' -Account Everyone -AccessRights Read -WhatIf

        Previews adding an Everyone read rule to the local Data share.
    .INPUTS
        System.String
    .OUTPUTS
        None
        WindowsAccessControl.SmbShareAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('ShareName')]
        [object[]]$Name,

        [Parameter(Mandatory)]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,

        [Parameter(Mandatory)]
        [WindowsSmbShareRights]$AccessRights,

        [Parameter()]
        [System.Security.AccessControl.AccessControlType]$AccessControlType =
            [System.Security.AccessControl.AccessControlType]::Allow,

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
            Invoke-WindowsSmbShareCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Name $Name `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact Medium
            return
        }
        foreach ($nameValue in $Name) {
            $target = Resolve-WindowsSmbShareTarget -Name $nameValue
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Add $AccessControlType SMB share access rules")) {
                $null = Invoke-WindowsSmbShareAclRuleMutation `
                    -Target $target `
                    -Operation Add `
                    -SecurityIdentifier $identities `
                    -AccessMask ([int]$AccessRights) `
                    -AccessControlType $AccessControlType
                if ($PassThru) {
                    Get-SmbShareAccessRule `
                        -Name $target.ShareName `
                        -Account $identities.Value `
                        -ExcludeInherited `
                        -ThrottleLimit 1 |
                        Where-Object {
                            [int]$_.AccessRights -eq [int]$AccessRights -and
                            $_.AccessControlType -eq $AccessControlType
                        }
                }
            }
        }
    }
}
