function Get-ServiceSecurityDescriptor {
    <#
    .SYNOPSIS
        Gets selected security descriptor sections from local services or the SCM.
    .DESCRIPTION
        Reads owner, group, DACL, or SACL sections from local named services or
        the explicit local Service Control Manager target and returns portable SDDL.
    .PARAMETER Name
        One or more local service names, ServiceController objects, or module outputs.
    .PARAMETER ServiceControlManager
        Selects the local Service Control Manager instead of a named service.
    .PARAMETER Sections
        Selects owner, group, access, audit, or any combination to retrieve.
    .PARAMETER ThrottleLimit
        Limits concurrently processed canonical targets. One requests
        deterministic sequential execution.
    .EXAMPLE
        Get-Service BITS | Get-ServiceSecurityDescriptor -Sections Access

        Gets the BITS service DACL through a ServiceController pipeline object.
    .INPUTS
        System.String
        System.ServiceProcess.ServiceController
    .OUTPUTS
        WindowsAccessControl.ServiceSecurityDescriptor
        WindowsAccessControl.ServiceControlManagerSecurityDescriptor
    #>
    [CmdletBinding(DefaultParameterSetName = 'Service')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Service')]
        [Alias('ServiceName')]
        [object[]]$Name,

        [Parameter(Mandatory, ParameterSetName = 'ServiceControlManager')]
        [switch]$ServiceControlManager,

        [Parameter()]
        [WindowsSecurityDescriptorSection]$Sections =
            [WindowsSecurityDescriptorSection]::All,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount))
    )

    process {
        if (-not $script:WindowsAccessControlBatchWorker.Value) {
            Invoke-WindowsServiceCommandBatch `
                -CommandName $MyInvocation.MyCommand.Name `
                -BoundParameters $PSBoundParameters `
                -Name $Name `
                -ServiceControlManager:$ServiceControlManager `
                -ThrottleLimit $ThrottleLimit
            return
        }
        $targets = if ($ServiceControlManager) {
            @(Resolve-WindowsServiceTarget -ServiceControlManager)
        } else {
            @($Name | Resolve-WindowsServiceTarget)
        }
        foreach ($target in $targets) {
            $descriptorParameters = @{
                Target   = $target
                Sections = $Sections
            }
            $descriptor = Get-WindowsServiceTargetSecurityDescriptor @descriptorParameters
            $conversionParameters = @{
                Target             = $target
                Sections           = $Sections
                SecurityDescriptor = $descriptor
                TypeName           = 'WindowsAccessControl.{0}SecurityDescriptor' -f $target.ObjectType
            }
            ConvertTo-WindowsSecurityDescriptorObject @conversionParameters
        }
    }
}
