function Get-ProcessSecurityDescriptor {
    <#
    .SYNOPSIS
        Gets selected security descriptor sections from pinned live processes.
    .DESCRIPTION
        Resolves a PID, Process object, module output, or caller-owned handle,
        pins PID targets by creation FILETIME, and returns portable descriptor data.
    .PARAMETER InputObject
        One or more PIDs, Process objects, or process objects emitted by this module.
    .PARAMETER Handle
        One or more caller-owned process handles that the module never closes.
    .PARAMETER Sections
        Selects owner, group, access, audit, or any combination to retrieve.
    .EXAMPLE
        Get-Process -Id $PID | Get-ProcessSecurityDescriptor -Sections Access

        Gets the current process DACL through a pinned Process pipeline object.
    .INPUTS
        System.Int32
        System.Diagnostics.Process
        WindowsAccessControl.ProcessSecurityDescriptor
    .OUTPUTS
        WindowsAccessControl.ProcessSecurityDescriptor
    #>
    [CmdletBinding(DefaultParameterSetName = 'Process')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Process')]
        [Alias('Process', 'Id', 'ProcessId')]
        [object[]]$InputObject,

        [Parameter(Mandatory, ParameterSetName = 'Handle')]
        [IntPtr[]]$Handle,

        [Parameter()]
        [WindowsSecurityDescriptorSection]$Sections =
            [WindowsSecurityDescriptorSection]::All
    )

    process {
        $targets = if ($PSCmdlet.ParameterSetName -eq 'Handle') {
            @($Handle | ForEach-Object { Resolve-WindowsProcessTarget -Handle $_ })
        } else {
            @($InputObject | Resolve-WindowsProcessTarget)
        }
        foreach ($target in $targets) {
            $getParameters = @{
                Target   = $target
                Sections = $Sections
            }
            $descriptor = Get-WindowsProcessTargetSecurityDescriptor @getParameters
            $conversionParameters = @{
                Target             = $target
                Sections           = $Sections
                SecurityDescriptor = $descriptor
                TypeName           = 'WindowsAccessControl.ProcessSecurityDescriptor'
            }
            ConvertTo-WindowsSecurityDescriptorObject @conversionParameters
        }
    }
}
