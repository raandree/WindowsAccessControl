function Add-ScheduledTaskAccessRule {
    <#
    .SYNOPSIS
        Adds typed access rules to contained local registered tasks.
    .DESCRIPTION
        Resolves and deduplicates every account before adding exact task ACEs
        and persisting each target DACL once. The parent folder must be inside
        AllowedRootPath, outside the root and Microsoft system tree, and the
        result must preserve the Task Scheduler service token's access.
    .PARAMETER TaskPath
        One or more absolute local Task Scheduler parent-folder paths.
    .PARAMETER TaskName
        The exact leaf name of the registered task in each supplied folder.
    .PARAMETER AllowedRootPath
        The explicit non-system folder boundary containing every write target.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER AccessRights
        Registered-task rights to add, such as Read, ReadAndRun, or Modify.
    .PARAMETER AccessControlType
        Adds an Allow rule by default or an explicit Deny rule.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical task targets from 1 to 64.
    .PARAMETER PassThru
        Returns the stored explicit task access rules after persistence.
    .EXAMPLE
        Add-ScheduledTaskAccessRule -TaskPath '\Operations' -TaskName 'Cleanup' `
            -AllowedRootPath '\Operations' -Account 'CONTOSO\Operators' `
            -AccessRights ReadAndRun -WhatIf

        Previews granting read-and-run access on the contained Cleanup task.
    .INPUTS
        System.String
    .OUTPUTS
        None
        WindowsAccessControl.ScheduledTaskAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [object[]]$TaskPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AllowedRootPath,

        [Parameter(Mandatory)]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,

        [Parameter(Mandatory)]
        [WindowsScheduledTaskRights]$AccessRights,

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
            Invoke-WindowsTaskSchedulerCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $TaskPath `
                -PathParameterName TaskPath `
                -TaskName $TaskName `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact High
            return
        }
        foreach ($pathValue in $TaskPath) {
            $target = Resolve-WindowsTaskSchedulerTarget `
                -Path ([string]$pathValue) `
                -TaskName $TaskName `
                -ForWrite `
                -AllowedRootPath $AllowedRootPath
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Add $AccessControlType registered-task access rules")) {
                $null = Invoke-WindowsTaskSchedulerAclRuleMutation `
                    -Target $target `
                    -Operation Add `
                    -SecurityIdentifier $identities `
                    -AccessMask ([int]$AccessRights) `
                    -AccessControlType $AccessControlType
                if ($PassThru) {
                    Get-ScheduledTaskAccessRule `
                        -TaskPath $target.TaskPath `
                        -TaskName $target.TaskName `
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
