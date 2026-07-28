function Set-ScheduledTaskSecurityDescriptor {
    <#
    .SYNOPSIS
        Sets DACL descriptors on contained local registered tasks.
    .DESCRIPTION
        Persists only the DACL through the local Task Scheduler COM API with
        TASK_DONT_ADD_PRINCIPAL_ACE. The target must be inside AllowedRootPath,
        and the candidate must preserve every current SYSTEM ACE.
    .PARAMETER TaskPath
        One or more absolute local Task Scheduler parent-folder paths.
    .PARAMETER TaskName
        The exact leaf name of the registered task in each supplied folder.
    .PARAMETER AllowedRootPath
        The explicit non-system folder boundary containing every write target.
    .PARAMETER Sddl
        A valid SDDL document containing a non-null DACL.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical task targets from 1 to 64.
    .PARAMETER PassThru
        Returns the verified DACL descriptor after persistence.
    .EXAMPLE
        Set-ScheduledTaskSecurityDescriptor -TaskPath '\Operations' `
            -TaskName 'Cleanup' -AllowedRootPath '\Operations' `
            -Sddl $sddl -WhatIf

        Previews a contained local task DACL write.
    .INPUTS
        System.String
    .OUTPUTS
        None
        WindowsAccessControl.ScheduledTaskSecurityDescriptor
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
        [ValidateNotNullOrEmpty()]
        [string]$Sddl,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount)),

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $rawDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
        if (-not $rawDescriptor.DiscretionaryAcl) {
            throw 'The supplied SDDL does not contain a non-null DACL.'
        }
        $descriptorBytes = [byte[]]::new($rawDescriptor.BinaryLength)
        $rawDescriptor.GetBinaryForm($descriptorBytes, 0)
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
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, 'Set registered-task DACL')) {
                $stored = Set-WindowsTaskSchedulerSecurityDescriptor `
                    -Target $target `
                    -SecurityDescriptor $descriptorBytes
                if ($PassThru) {
                    ConvertTo-WindowsSecurityDescriptorObject `
                        -Target $target `
                        -Sections Access `
                        -SecurityDescriptor $stored `
                        -TypeName 'WindowsAccessControl.ScheduledTaskSecurityDescriptor'
                }
            }
        }
    }
}