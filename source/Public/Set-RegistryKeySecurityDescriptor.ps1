function Set-RegistryKeySecurityDescriptor {
    <#
    .SYNOPSIS
        Sets selected security descriptor sections on local registry keys.
    .DESCRIPTION
        Parses SDDL as data and persists only the selected owner, group, DACL,
        or SACL sections to local registry keys while honoring PowerShell
        confirmation and preview semantics.
    .PARAMETER Path
        One or more local registry key paths or RegistryKey objects supplied
        directly or through the pipeline.
    .PARAMETER Sddl
        A structurally valid SDDL document containing every selected section.
    .PARAMETER RegistryView
        Selects the default, 32-bit, or 64-bit registry view explicitly.
    .PARAMETER Sections
        Selects the descriptor sections to persist from the SDDL document.
    .PARAMETER PassThru
        Returns the updated selected descriptor sections after persistence.
    .EXAMPLE
        Set-RegistryKeySecurityDescriptor -Path HKCU:\Software -Sddl 'D:(A;;KR;;;WD)' -Sections Access -WhatIf

        Previews replacing only the Software key DACL.
    .INPUTS
        System.String
        Microsoft.Win32.RegistryKey
    .OUTPUTS
        None
        WindowsAccessControl.RegistryKeySecurityDescriptor
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('PSPath')]
        [object[]]$Path,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Sddl,

        [Parameter()]
        [WindowsRegistryView]$RegistryView = [WindowsRegistryView]::Default,

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
        if (($Sections -band [WindowsSecurityDescriptorSection]::Audit) -ne 0 -and
            -not $rawDescriptor.SystemAcl) {
            throw 'The supplied SDDL does not contain a SACL.'
        }
        $managedSections = ConvertTo-WindowsAccessControlSection -Sections $Sections
        $requestedSddl = $rawDescriptor.GetSddlForm($managedSections)
        $descriptorBytes = [byte[]]::new($rawDescriptor.BinaryLength)
        $rawDescriptor.GetBinaryForm($descriptorBytes, 0)
    }

    process {
        foreach ($pathValue in $Path) {
            $target = Resolve-RegistryKeyTarget -Path $pathValue -RegistryView $RegistryView
            if ($PSCmdlet.ShouldProcess($target.Path, "Set $Sections registry security")) {
                $getDescriptorParameters = @{
                    NativePath       = $target.NativePath
                    NativeObjectType = $target.NativeObjectType
                    Sections         = $Sections
                }
                $currentBytes = Get-WindowsNamedSecurityDescriptor @getDescriptorParameters
                $currentDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                    $currentBytes,
                    0
                )
                if ($currentDescriptor.GetSddlForm($managedSections) -cne $requestedSddl) {
                    $setParameters = @{
                        NativePath         = $target.NativePath
                        NativeObjectType   = $target.NativeObjectType
                        Sections           = $Sections
                        SecurityDescriptor = $descriptorBytes
                        CurrentSecurityDescriptor = $currentBytes
                    }
                    Set-WindowsNamedSecurityDescriptor @setParameters
                }
                if ($PassThru) {
                    $getResultParameters = @{
                        Path         = $target.Path
                        RegistryView = $RegistryView
                        Sections     = $Sections
                    }
                    Get-RegistryKeySecurityDescriptor @getResultParameters
                }
            }
        }
    }
}
