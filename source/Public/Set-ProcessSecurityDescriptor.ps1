function Set-ProcessSecurityDescriptor {
    <#
    .SYNOPSIS
        Sets selected security descriptor sections on pinned live processes.
    .DESCRIPTION
        Parses SDDL as data, opens PID targets once with a verified creation
        identity, and persists only selected sections to that process instance.
    .PARAMETER InputObject
        One or more PIDs, Process objects, or process objects emitted by this module.
    .PARAMETER Handle
        One or more caller-owned process handles that the module never closes.
    .PARAMETER Sddl
        A structurally valid SDDL document containing every selected section.
    .PARAMETER Sections
        Selects the descriptor sections to persist from the SDDL document.
    .PARAMETER ThrottleLimit
        Limits concurrently processed pinned targets. One requests
        deterministic sequential execution.
    .PARAMETER PassThru
        Returns the stored selected descriptor sections after persistence.
    .EXAMPLE
        Set-ProcessSecurityDescriptor -ProcessId $PID -Sddl 'D:(A;;GR;;;WD)' -Sections Access -WhatIf

        Previews replacing only the current process DACL.
    .INPUTS
        System.Int32
        System.Diagnostics.Process
        WindowsAccessControl.ProcessSecurityDescriptor
    .OUTPUTS
        None
        WindowsAccessControl.ProcessSecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Process')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Process')]
        [Alias('Process', 'Id', 'ProcessId')]
        [object[]]$InputObject,
        [Parameter(Mandatory, ParameterSetName = 'Handle')]
        [IntPtr[]]$Handle,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Sddl,
        [Parameter()]
        [WindowsSecurityDescriptorSection]$Sections =
            [WindowsSecurityDescriptorSection]::All,
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(
            1,
            [Math]::Min(8, [Environment]::ProcessorCount)
        ),
        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
        if (($Sections -band [WindowsSecurityDescriptorSection]::Access) -ne 0 -and
            -not $rawDescriptor.DiscretionaryAcl) {
            throw 'The supplied SDDL does not contain a non-null DACL.'
        }
        $systemAclPresent = ([int]$rawDescriptor.ControlFlags -band
            [int][System.Security.AccessControl.ControlFlags]::SystemAclPresent) -ne 0
        if (($Sections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0 -and
            -not $systemAclPresent) {
            throw 'The supplied SDDL does not contain a SACL.'
        }
        $descriptorBytes = [byte[]]::new($rawDescriptor.BinaryLength)
        $rawDescriptor.GetBinaryForm($descriptorBytes, 0)
    }
    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsProcessCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -InputObject $InputObject `
                -Handle $Handle `
                -ThrottleLimit $ThrottleLimit `
                -SerializeByCanonicalTarget `
                -ConfirmationImpact High
            return
        }
        $targets = if ($PSCmdlet.ParameterSetName -eq 'Handle') {
            @($Handle | ForEach-Object { Resolve-WindowsProcessTarget -Handle $_ })
        } else {
            @($InputObject | Resolve-WindowsProcessTarget)
        }
        foreach ($target in $targets) {
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Set $Sections process security")) {
                $setParameters = @{
                    Target             = $target
                    Sections           = $Sections
                    SecurityDescriptor = $descriptorBytes
                }
                Set-WindowsProcessTargetSecurityDescriptor @setParameters
                if ($PassThru) {
                    $resultParameters = @{ Sections = $Sections }
                    if ($target.DescriptorSource -eq 'Handle') {
                        $resultParameters.Handle = $target.Handle
                    } else {
                        $resultParameters.InputObject = $target
                    }
                    Get-ProcessSecurityDescriptor @resultParameters
                }
            }
        }
    }
}
