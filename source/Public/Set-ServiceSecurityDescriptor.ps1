function Set-ServiceSecurityDescriptor {
    <#
    .SYNOPSIS
        Sets selected security descriptor sections on local services or the SCM.
    .DESCRIPTION
        Parses SDDL as data and persists only selected sections to local named
        services or the explicit local Service Control Manager target.
    .PARAMETER Name
        One or more local service names, ServiceController objects, or module outputs.
    .PARAMETER ServiceControlManager
        Selects the local Service Control Manager instead of a named service.
    .PARAMETER Sddl
        A structurally valid SDDL document containing every selected section.
    .PARAMETER Sections
        Selects the descriptor sections to persist from the SDDL document.
    .PARAMETER PassThru
        Returns the stored selected descriptor sections after persistence.
    .EXAMPLE
        Set-ServiceSecurityDescriptor -Name BITS -Sddl 'D:(A;;CC;;;WD)' -Sections Access -WhatIf

        Previews replacing only the BITS service DACL.
    .INPUTS
        System.String
        System.ServiceProcess.ServiceController
    .OUTPUTS
        None
        WindowsAccessControl.ServiceSecurityDescriptor
        WindowsAccessControl.ServiceControlManagerSecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Service')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Service')]
        [Alias('ServiceName')]
        [object[]]$Name,

        [Parameter(Mandatory, ParameterSetName = 'ServiceControlManager')]
        [switch]$ServiceControlManager,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Sddl,

        [Parameter()]
        [WindowsSecurityDescriptorSection]$Sections =
            [WindowsSecurityDescriptorSection]::All,

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
        $targets = if ($ServiceControlManager) {
            @(Resolve-WindowsServiceTarget -ServiceControlManager)
        } else {
            @($Name | Resolve-WindowsServiceTarget)
        }
        foreach ($target in $targets) {
            if ($PSCmdlet.ShouldProcess($target.CanonicalTarget, "Set $Sections service security")) {
                $getParameters = @{
                    Target   = $target
                    Sections = $Sections
                }
                $currentDescriptor = Get-WindowsServiceTargetSecurityDescriptor @getParameters
                $setParameters = @{
                    Target                    = $target
                    Sections                  = $Sections
                    SecurityDescriptor        = $descriptorBytes
                    CurrentSecurityDescriptor = $currentDescriptor
                }
                Set-WindowsServiceTargetSecurityDescriptor @setParameters
                if ($PassThru) {
                    $resultParameters = @{
                        Sections = $Sections
                    }
                    if ($target.ObjectType -eq 'ServiceControlManager') {
                        $resultParameters.ServiceControlManager = $true
                    } else {
                        $resultParameters.Name = $target.ServiceName
                    }
                    Get-ServiceSecurityDescriptor @resultParameters
                }
            }
        }
    }
}
