function Set-TaskFolderSecurityDescriptor {
    <#
    .SYNOPSIS
        Sets DACL descriptors on contained local Task Scheduler folders.
    .DESCRIPTION
        Persists only the DACL through the local Task Scheduler COM API. The
        target must be inside AllowedRootPath, outside the root and Microsoft
        system tree, and the candidate must preserve every current SYSTEM ACE.
    .PARAMETER Path
        One or more absolute local Task Scheduler folder paths.
    .PARAMETER AllowedRootPath
        The explicit non-system folder boundary containing every write target.
    .PARAMETER Sddl
        A valid SDDL document containing a non-null DACL.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical folder targets from 1 to 64.
    .PARAMETER PassThru
        Returns the verified DACL descriptor after persistence.
    .EXAMPLE
        Set-TaskFolderSecurityDescriptor -Path '\Operations' `
            -AllowedRootPath '\Operations' -Sddl $sddl -WhatIf

        Previews a contained local task-folder DACL write.
    .INPUTS
        System.String
    .OUTPUTS
        None
        WindowsAccessControl.TaskFolderSecurityDescriptor
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
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, 'Set Task Scheduler folder DACL')) {
                $stored = Set-WindowsTaskSchedulerSecurityDescriptor `
                    -Target $target `
                    -SecurityDescriptor $descriptorBytes
                if ($PassThru) {
                    ConvertTo-WindowsSecurityDescriptorObject `
                        -Target $target `
                        -Sections Access `
                        -SecurityDescriptor $stored `
                        -TypeName 'WindowsAccessControl.TaskFolderSecurityDescriptor'
                }
            }
        }
    }
}