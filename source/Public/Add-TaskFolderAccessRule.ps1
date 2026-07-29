function Add-TaskFolderAccessRule {
    <#
    .SYNOPSIS
        Adds typed access rules to contained local Task Scheduler folders.
    .DESCRIPTION
        Resolves and deduplicates every account before adding exact folder ACEs
        and persisting each target DACL once. The target must be inside
        AllowedRootPath, outside the root and Microsoft system tree, and the
        result must preserve the Task Scheduler service token's access.
    .PARAMETER Path
        One or more absolute local Task Scheduler folder paths.
    .PARAMETER AllowedRootPath
        The explicit non-system folder boundary containing every write target.
    .PARAMETER Account
        One or more account names, SIDs, identity references, or module identities.
    .PARAMETER AccessRights
        Task folder rights to add, such as Read, ReadAndTraverse, or CreateTask.
    .PARAMETER AccessControlType
        Adds an Allow rule by default or an explicit Deny rule.
    .PARAMETER AppliesTo
        Controls whether the ACE applies to this folder, subfolders, or tasks.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical folder targets from 1 to 64.
    .PARAMETER PassThru
        Returns the stored explicit folder access rules after persistence.
    .EXAMPLE
        Add-TaskFolderAccessRule -Path '\Operations' -AllowedRootPath '\Operations' `
            -Account 'CONTOSO\Operators' -AccessRights ReadAndTraverse -WhatIf

        Previews adding a contained read-and-traverse rule to the Operations folder.
    .INPUTS
        System.String
    .OUTPUTS
        None
        WindowsAccessControl.TaskFolderAccessRule
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('TaskPath')]
        [object[]]$Path,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AllowedRootPath,

        [Parameter(Mandatory)]
        [Alias('IdentityReference', 'ID')]
        [object[]]$Account,

        [Parameter(Mandatory)]
        [WindowsTaskFolderRights]$AccessRights,

        [Parameter()]
        [System.Security.AccessControl.AccessControlType]$AccessControlType =
            [System.Security.AccessControl.AccessControlType]::Allow,

        [Parameter()]
        [ValidateSet(
            'ThisFolderOnly',
            'ThisFolderSubfoldersAndTasks',
            'ThisFolderAndSubfolders',
            'ThisFolderAndTasks',
            'SubfoldersAndTasksOnly',
            'SubfoldersOnly',
            'TasksOnly'
        )]
        [string]$AppliesTo = 'ThisFolderOnly',

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
        $aceFlags = ConvertTo-WindowsTaskSchedulerAceFlag -AppliesTo $AppliesTo
    }
    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsTaskSchedulerCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Path $Path `
                -PathParameterName Path `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact High
            return
        }
        foreach ($pathValue in $Path) {
            $target = Resolve-WindowsTaskSchedulerTarget `
                -Path ([string]$pathValue) `
                -ForWrite `
                -AllowedRootPath $AllowedRootPath
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Add $AccessControlType Task Scheduler folder access rules")) {
                $null = Invoke-WindowsTaskSchedulerAclRuleMutation `
                    -Target $target `
                    -Operation Add `
                    -SecurityIdentifier $identities `
                    -AccessMask ([int]$AccessRights) `
                    -AccessControlType $AccessControlType `
                    -AceFlags $aceFlags
                if ($PassThru) {
                    Get-TaskFolderAccessRule `
                        -Path $target.TaskPath `
                        -Account $identities.Value `
                        -ExcludeInherited `
                        -ThrottleLimit 1 |
                        Where-Object {
                            [int]$_.AccessRights -eq [int]$AccessRights -and
                            $_.AccessControlType -eq $AccessControlType -and
                            $_.AppliesTo -eq $AppliesTo
                        }
                }
            }
        }
    }
}
